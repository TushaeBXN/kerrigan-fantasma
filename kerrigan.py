#!/usr/bin/env python3
"""
Kerrigan-Fantasma — main entry point

Modes:
  kerrigan.py                          — interactive chat
  kerrigan.py "query"                  — single query
  kerrigan.py --evolve "target"        — run evolutionary fuzzing loop
  kerrigan.py --evolve "target" --iterations 5 --fuzz-inputs 100

Pipeline (chat mode):
  Query → Creep (context) → Abathur (route) → Model → Overmind (gate) → Creep (store)

Pipeline (evolve mode):
  LLM generates harness → Compiler → Fuzzer → Triage → LLM mutates → repeat
"""

import sys
import argparse
from router.abathur import Abathur
from verifier.overmind import Overmind
from memory.creep import Creep

abathur = Abathur()
overmind = Overmind()
creep = Creep()


def run_evolve(target: str, iterations: int, n_fuzz: int, model: str, secure: bool = False):
    """Launch the evolutionary fuzzing loop."""
    from loop.evolution import EvolutionaryLoop

    loop = EvolutionaryLoop(
        model=model,
        n_fuzz=n_fuzz,
        max_retries=3,
        creep=creep,
    )

    if secure:
        from loop.secure_runner import SecureEvolutionaryLoop, ResourceConfig
        print("[SecureRunner] Wrapping loop with defense-in-depth sandbox...")
        secure_loop = SecureEvolutionaryLoop(
            loop,
            cfg=ResourceConfig(cpu_seconds=30, memory_mb=512, timeout_seconds=60),
        )
        session = secure_loop.run(target, iterations=iterations)
    else:
        session = loop.run(target, iterations=iterations)

    # Surface high-exploitability findings back through Overmind
    high = [r for r in session.all_crashes if r.exploitability == "high"]
    if high:
        print(f"\n[Overmind] Reviewing {len(high)} high-exploitability finding(s)...")
        for r in high:
            _, verdict = overmind.gate(r.to_llm_prompt(), query=target)
            flag = "APPROVED" if verdict.passed else "FLAGGED"
            print(f"  {flag}: {r.summary()}")
    return session


def ask(query: str, context: dict = None, show_routing: bool = True, show_verdict: bool = True) -> str:
    context = context or {}

    # Step 1: Creep injects relevant prior knowledge
    prior_context = creep.build_context(query)
    enriched_query = f"{prior_context}{query}" if prior_context else query
    if prior_context and show_routing:
        print(f"[Creep] {creep.count()} memories | injecting {len(prior_context.splitlines())-1} relevant findings\n")

    # Step 2: Abathur decides which expert handles this
    decision = abathur.route(query)
    if show_routing:
        print(decision.reasoning)
        print()

    # Step 3: Query the chosen model
    import ollama
    print(f"[Kerrigan] Querying {decision.model}...\n")
    response = ollama.chat(
        model=decision.model,
        messages=[{"role": "user", "content": enriched_query}]
    )
    raw_output = response["message"]["content"]

    # Step 4: Overmind gates the output
    gated_output, verdict = overmind.gate(raw_output, query=query, context=context)

    if show_verdict and not verdict.passed:
        print(f"[Overmind] BLOCKED — {verdict.reason}\n")
        return gated_output

    # Step 5: Store response in Creep for future sessions
    if verdict.passed:
        creep.tag_response(query, raw_output, decision.expert)

    # Step 6: Abathur learns from outcome
    abathur.learn(decision.expert, success=verdict.passed)

    return gated_output


def chat_loop():
    print("=" * 60)
    print("  KERRIGAN-FANTASMA  |  Queen of Blades Security LLM")
    print("=" * 60)
    print("  Commands: /exit  /routing off  /routing on  /history  /memory  /evolve <target>")
    print("=" * 60)
    print()

    show_routing = True
    context = {}

    while True:
        try:
            query = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Kerrigan] Returning to the Swarm.")
            break

        if not query:
            continue

        if query == "/exit":
            print("[Kerrigan] Returning to the Swarm.")
            break
        elif query == "/routing off":
            show_routing = False
            print("[Abathur] Routing display disabled.\n")
            continue
        elif query == "/routing on":
            show_routing = True
            print("[Abathur] Routing display enabled.\n")
            continue
        elif query == "/history":
            if not abathur.history:
                print("No history yet.\n")
            else:
                for i, h in enumerate(abathur.history[-10:], 1):
                    print(f"  {i}. [{h['expert']}] {h['query']}")
                print()
            continue
        elif query == "/memory":
            count = creep.count()
            print(f"[Creep] {count} finding(s) stored across sessions.")
            if count > 0:
                recent = creep.recall("security vulnerability exploit", n=3)
                for f in recent:
                    print(f"  [{f['expert']}] {f['content'][:120]}...")
            print()
            continue
        elif query.startswith("/evolve "):
            target = query[8:].strip()
            if not target:
                print("[Kerrigan] Usage: /evolve <target description>\n")
                continue
            iters  = int(input("  Iterations [3]: ").strip() or 3)
            n_fuzz = int(input("  Fuzz inputs [50]: ").strip() or 50)
            run_evolve(target, iterations=iters, n_fuzz=n_fuzz, model="kerrigan-fantasma")
            continue
        elif query.startswith("/auth "):
            target = query[6:].strip()
            context.setdefault("authorized_targets", []).append(target)
            print(f"[Overmind] Authorized target added: {target}\n")
            continue

        result = ask(query, context=context, show_routing=show_routing)
        print(result)
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Kerrigan-Fantasma Security LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 kerrigan.py                              # interactive chat
  python3 kerrigan.py "explain heap overflow"      # single query
  python3 kerrigan.py --evolve "HTTP parser"       # evolve + fuzz
  python3 kerrigan.py --evolve "DNS parser" --iterations 5 --fuzz-inputs 200
        """,
    )
    parser.add_argument("query",            nargs="?",          help="Single chat query")
    parser.add_argument("--no-routing",     action="store_true",help="Hide Abathur routing output")
    parser.add_argument("--evolve",         metavar="TARGET",   help="Run evolutionary fuzzing loop on TARGET")
    parser.add_argument("--iterations",     type=int, default=3,help="Evolution iterations (default: 3)")
    parser.add_argument("--fuzz-inputs",    type=int, default=100, help="Mutations per iteration (default: 100)")
    parser.add_argument("--model",          default="kerrigan-fantasma", help="Ollama model to use")
    parser.add_argument("--secure",         action="store_true", help="Enable defense-in-depth sandbox (resource limits + Docker if available)")
    args = parser.parse_args()

    if args.evolve:
        run_evolve(args.evolve, iterations=args.iterations,
                   n_fuzz=args.fuzz_inputs, model=args.model, secure=args.secure)
    elif args.query:
        result = ask(args.query, show_routing=not args.no_routing)
        print(result)
    else:
        chat_loop()
