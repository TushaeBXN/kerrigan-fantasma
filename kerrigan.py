#!/usr/bin/env python3
"""
Kerrigan-Fantasma — main entry point
Query → Abathur (route) → Model (respond) → Overmind (gate) → Output
"""

import sys
import argparse
from router.abathur import Abathur
from verifier.overmind import Overmind

abathur = Abathur()
overmind = Overmind()


def ask(query: str, context: dict = None, show_routing: bool = True, show_verdict: bool = True) -> str:
    context = context or {}

    # Step 1: Abathur decides which expert handles this
    decision = abathur.route(query)
    if show_routing:
        print(decision.reasoning)
        print()

    # Step 2: Query the chosen model
    import ollama
    print(f"[Kerrigan] Querying {decision.model}...\n")
    response = ollama.chat(
        model=decision.model,
        messages=[{"role": "user", "content": query}]
    )
    raw_output = response["message"]["content"]

    # Step 3: Overmind gates the output
    gated_output, verdict = overmind.gate(raw_output, query=query, context=context)

    if show_verdict and not verdict.passed:
        print(f"[Overmind] BLOCKED — {verdict.reason}\n")
        return gated_output

    # Step 4: Feedback loop — let Abathur learn
    # (auto-mark as win if Overmind passed; user can override)
    abathur.learn(decision.expert, success=verdict.passed)

    return gated_output


def chat_loop():
    print("=" * 60)
    print("  KERRIGAN-FANTASMA  |  Queen of Blades Security LLM")
    print("=" * 60)
    print("  Commands: /exit  /routing off  /routing on  /history")
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
