#!/usr/bin/env python3
"""
Kerrigan-Fantasma — main entry point
Query → Creep (context) → Abathur (route) → Model (respond) → Overmind (gate) → Creep (store) → Output
"""

import sys
import argparse
from router.abathur import Abathur
from verifier.overmind import Overmind
from memory.creep import Creep

abathur = Abathur()
overmind = Overmind()
creep = Creep()


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
    print("  Commands: /exit  /routing off  /routing on  /history  /memory")
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
        elif query.startswith("/auth "):
            target = query[6:].strip()
            context.setdefault("authorized_targets", []).append(target)
            print(f"[Overmind] Authorized target added: {target}\n")
            continue

        result = ask(query, context=context, show_routing=show_routing)
        print(result)
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kerrigan-Fantasma Security LLM")
    parser.add_argument("query", nargs="?", help="Single query (non-interactive)")
    parser.add_argument("--no-routing", action="store_true", help="Hide routing output")
    args = parser.parse_args()

    if args.query:
        result = ask(args.query, show_routing=not args.no_routing)
        print(result)
    else:
        chat_loop()
