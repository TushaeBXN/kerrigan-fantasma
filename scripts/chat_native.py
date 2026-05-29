#!/usr/bin/env python3
"""
Chat with the native Kerrigan Core architecture.
Loads a checkpoint and generates text — no Ollama, no external model.
"""

import sys
import argparse
from pathlib import Path
from contextlib import nullcontext

import torch
import torch.nn.functional as F

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.model import KerriganCore, KerriganConfig
from verifier.overmind import Overmind

# ── Generation ─────────────────────────────────────────────────────────────────

def generate(
    model: KerriganCore,
    prompt_ids: list[int],
    max_new_tokens: int,
    temperature: float,
    top_k: int,
    device: str,
) -> list[int]:
    model.eval()
    ids = torch.tensor([prompt_ids], dtype=torch.long, device=device)

    with torch.no_grad():
        for _ in range(max_new_tokens):
            # Truncate to max_seq_len
            ids_cond = ids[:, -model.cfg.max_seq_len:]

            logits, _ = model(ids_cond, return_loop_count=True)
            logits = logits[:, -1, :]  # last token only

            if temperature == 0.0:
                next_id = logits.argmax(dim=-1, keepdim=True)
            else:
                logits = logits / temperature
                if top_k > 0:
                    v, _ = torch.topk(logits, min(top_k, logits.size(-1)))
                    logits[logits < v[:, [-1]]] = float("-inf")
                probs = F.softmax(logits, dim=-1)
                next_id = torch.multinomial(probs, num_samples=1)

            ids = torch.cat([ids, next_id], dim=1)

    return ids[0].tolist()


# ── Tokenizer (must match training) ───────────────────────────────────────────

class CharTokenizer:
    def __init__(self):
        chars = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "0123456789 \n\t.,!?;:'\"-_()[]{}/<>@#$%^&*+=\\|`~")
        self.stoi = {c: i+1 for i, c in enumerate(chars)}
        self.itos = {i: c for c, i in self.stoi.items()}
        self.vocab_size = len(self.stoi) + 1

    def encode(self, text: str) -> list[int]:
        return [self.stoi.get(c, 0) for c in text]

    def decode(self, ids: list[int]) -> str:
        return "".join(self.itos.get(i, "") for i in ids)


# ── Load checkpoint ────────────────────────────────────────────────────────────

def load_model(checkpoint_path: str, device: str = "cpu"):
    ckpt = torch.load(checkpoint_path, map_location=device)
    cfg: KerriganConfig = ckpt["config"]
    cfg.device = device
    cfg.dtype = torch.float32

    model = KerriganCore(cfg).to(device)
    model.load_state_dict(ckpt["model"])

    tier = ckpt.get("tier", "unknown")
    step = ckpt.get("step", 0)
    loss = ckpt.get("loss", 0.0)
    return model, cfg, tier, step, loss


# ── Chat loop ──────────────────────────────────────────────────────────────────

def chat(checkpoint_path: str, max_new_tokens: int, temperature: float, top_k: int):
    device = "cpu"
    tokenizer = CharTokenizer()
    overmind = Overmind()

    print(f"\n[Kerrigan] Loading checkpoint: {checkpoint_path}")
    model, cfg, tier, step, loss = load_model(checkpoint_path, device)

    print(f"[Kerrigan] {model.num_parameters():,} parameters | "
          f"tier={tier} | step={step} | loss={loss:.4f}")
    print(f"[Kerrigan] max_loops={cfg.max_loops} | "
          f"hidden={cfg.hidden_size} | experts={cfg.num_experts}")
    print()
    print("=" * 60)
    print("  KERRIGAN CORE — Native Architecture Chat")
    print("  (early checkpoint — expect imperfect output)")
    print("  /exit to quit | /loops to toggle loop count display")
    print("=" * 60)
    print()

    show_loops = True

    while True:
        try:
            prompt = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Kerrigan] Returning to the Swarm.")
            break

        if not prompt:
            continue
        if prompt == "/exit":
            print("[Kerrigan] Returning to the Swarm.")
            break
        if prompt == "/loops":
            show_loops = not show_loops
            print(f"[Kerrigan] Loop display {'on' if show_loops else 'off'}\n")
            continue

        prompt_ids = tokenizer.encode(prompt)
        if not prompt_ids:
            continue

        # Count loops on the prompt pass
        with torch.no_grad():
            ids_t = torch.tensor([prompt_ids[-cfg.max_seq_len:]], dtype=torch.long)
            _, loops = model(ids_t, return_loop_count=True)

        if show_loops:
            print(f"[ACT] {loops} loop(s) to process prompt\n")

        output_ids = generate(
            model, prompt_ids, max_new_tokens, temperature, top_k, device
        )
        new_ids = output_ids[len(prompt_ids):]
        response = tokenizer.decode(new_ids)

        # Gate through Overmind
        gated, verdict = overmind.gate(response, query=prompt)
        if not verdict.passed:
            print(f"[Overmind] BLOCKED — {verdict.reason}\n")
            continue

        print(f"\n{gated}\n")
        if verdict.warnings:
            for w in verdict.warnings:
                print(f"  ⚠ {w}")
            print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chat with native Kerrigan Core")
    parser.add_argument(
        "--checkpoint",
        default="checkpoints/kerrigan_smoke/final.pt",
        help="Path to checkpoint file",
    )
    parser.add_argument("--max-tokens", type=int, default=200)
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--top-k", type=int, default=40)
    args = parser.parse_args()

    if not Path(args.checkpoint).exists():
        print(f"[Error] Checkpoint not found: {args.checkpoint}")
        print("Run training first: python3 scripts/train.py --tier smoke")
        sys.exit(1)

    chat(args.checkpoint, args.max_tokens, args.temperature, args.top_k)
