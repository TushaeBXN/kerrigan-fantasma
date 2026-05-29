#!/usr/bin/env python3
"""
Kerrigan-Fantasma training script.
Tiers (same pattern as Anthos):
  smoke         — 100 steps, tiny data, verify architecture works
  proof         — 1k steps, small data, verify loss drops
  sft           — full supervised fine-tune on security corpus
  instruct      — instruction tuning (Q&A format)

Local (Mac): smoke/proof only, float32, num_workers=0
RunPod     : sft/instruct, bfloat16, num_workers=4
"""

import os
import sys
import math
import time
import argparse
from contextlib import nullcontext
from pathlib import Path

import torch
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.model import KerriganCore, KerriganConfig

# ── Tier configs ───────────────────────────────────────────────────────────────

TIERS = {
    "smoke": dict(
        max_steps=100,
        batch_size=2,
        seq_len=128,
        lr=1e-3,
        eval_every=25,
        save_every=100,
        hidden_size=256,
        num_prelude_layers=1,
        num_coda_layers=1,
        max_loops=4,
        num_experts=4,
        description="Verify forward/backward pass works locally",
    ),
    "proof": dict(
        max_steps=1000,
        batch_size=4,
        seq_len=256,
        lr=3e-4,
        eval_every=100,
        save_every=500,
        hidden_size=512,
        num_prelude_layers=2,
        num_coda_layers=2,
        max_loops=8,
        num_experts=8,
        description="Verify loss drops consistently",
    ),
    "sft": dict(
        max_steps=50_000,
        batch_size=16,
        seq_len=2048,
        lr=1e-4,
        eval_every=500,
        save_every=2000,
        hidden_size=2048,
        num_prelude_layers=4,
        num_coda_layers=2,
        max_loops=16,
        num_experts=64,
        description="Full security corpus supervised fine-tune (RunPod)",
    ),
    "instruct": dict(
        max_steps=10_000,
        batch_size=8,
        seq_len=2048,
        lr=5e-5,
        eval_every=200,
        save_every=1000,
        hidden_size=2048,
        num_prelude_layers=4,
        num_coda_layers=2,
        max_loops=16,
        num_experts=64,
        description="Instruction tuning on Q&A pairs (RunPod)",
    ),
}

# ── Tokenizer (character-level for smoke/proof; swap for BPE in sft) ──────────

class CharTokenizer:
    """Minimal character tokenizer for smoke/proof tiers."""
    def __init__(self):
        chars = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                     "0123456789 \n\t.,!?;:'\"-_()[]{}/<>@#$%^&*+=\\|`~")
        self.stoi = {c: i+1 for i, c in enumerate(chars)}  # 0 = pad
        self.itos = {i: c for c, i in self.stoi.items()}
        self.vocab_size = len(self.stoi) + 1

    def encode(self, text: str) -> list[int]:
        return [self.stoi.get(c, 0) for c in text]

    def decode(self, ids: list[int]) -> str:
        return "".join(self.itos.get(i, "") for i in ids)


# ── Dataset ────────────────────────────────────────────────────────────────────

class TextDataset(Dataset):
    def __init__(self, tokens: list[int], seq_len: int):
        self.tokens = tokens
        self.seq_len = seq_len

    def __len__(self):
        return max(1, len(self.tokens) - self.seq_len - 1)

    def __getitem__(self, idx):
        chunk = self.tokens[idx : idx + self.seq_len + 1]
        # Pad if too short
        if len(chunk) < self.seq_len + 1:
            chunk = chunk + [0] * (self.seq_len + 1 - len(chunk))
        x = torch.tensor(chunk[:-1], dtype=torch.long)
        y = torch.tensor(chunk[1:],  dtype=torch.long)
        return x, y


def make_smoke_data(tokenizer: CharTokenizer, seq_len: int, n: int = 2000) -> TextDataset:
    """Generate synthetic security-flavored text for smoke/proof."""
    snippets = [
        "heap overflow exploit tcache poisoning arbitrary write rip control",
        "rop chain gadget ret2libc stack pivot pop rdi ret system binsh",
        "spectre flush reload cache timing side channel memory leak kernel",
        "uefi firmware smm handler vulnerability arbitrary code execution ring0",
        "use after free dangling pointer double free glibc malloc chunk",
        "privilege escalation kernel exploit cve lpe arbitrary write root",
        "yara rule malware detection signature pe header entropy packer",
        "buffer overflow stack canary bypass aslr pie nx ret2plt got",
    ]
    text = (" ".join(snippets) * (n // len(snippets) + 1))[:n * 10]
    tokens = tokenizer.encode(text)
    return TextDataset(tokens, seq_len)


# ── Training loop ──────────────────────────────────────────────────────────────

def train(tier: str, data_path: str = None, checkpoint_dir: str = None, resume: str = None):
    cfg_overrides = TIERS[tier]
    print(f"\n{'='*60}")
    print(f"  Kerrigan-Fantasma Training — Tier: {tier.upper()}")
    print(f"  {cfg_overrides['description']}")
    print(f"{'='*60}\n")

    # Device setup (Mac-safe)
    device = "cpu"
    dtype  = torch.float32
    ctx    = nullcontext()
    print(f"[Setup] device={device} dtype={dtype}")

    # Tokenizer
    tokenizer = CharTokenizer()
    vocab_size = tokenizer.vocab_size

    # Model config
    cfg = KerriganConfig(
        vocab_size=vocab_size,
        hidden_size=cfg_overrides["hidden_size"],
        intermediate_size=cfg_overrides["hidden_size"] * 4,
        num_heads=max(1, cfg_overrides["hidden_size"] // 64),
        head_dim=64,
        num_prelude_layers=cfg_overrides["num_prelude_layers"],
        num_coda_layers=cfg_overrides["num_coda_layers"],
        max_loops=cfg_overrides["max_loops"],
        num_experts=cfg_overrides["num_experts"],
        top_k_experts=2,
        lora_rank=8,
        device=device,
        dtype=dtype,
    )

    model = KerriganCore.from_config(cfg)
    print(f"[Model] {model.num_parameters():,} parameters")

    # Checkpoint dir
    ckpt_dir = Path(checkpoint_dir or f"checkpoints/kerrigan_{tier}")
    ckpt_dir.mkdir(parents=True, exist_ok=True)

    # Resume from checkpoint
    step_start = 0
    if resume and Path(resume).exists():
        ckpt = torch.load(resume, map_location=device)
        model.load_state_dict(ckpt["model"])
        step_start = ckpt.get("step", 0)
        print(f"[Resume] Loaded checkpoint at step {step_start}")

    # Dataset
    seq_len = cfg_overrides["seq_len"]
    if data_path and Path(data_path).exists():
        text = Path(data_path).read_text()
        tokens = tokenizer.encode(text)
        dataset = TextDataset(tokens, seq_len)
        print(f"[Data] Loaded {len(tokens):,} tokens from {data_path}")
    else:
        dataset = make_smoke_data(tokenizer, seq_len)
        print(f"[Data] Using synthetic security text ({len(dataset)} samples)")

    loader = DataLoader(dataset, batch_size=cfg_overrides["batch_size"],
                        shuffle=True, num_workers=0, drop_last=True)

    # Optimizer — cosine LR schedule
    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg_overrides["lr"],
                                   betas=(0.9, 0.95), weight_decay=0.1)

    max_steps = cfg_overrides["max_steps"]
    def lr_schedule(step):
        warmup = min(100, max_steps // 10)
        if step < warmup:
            return step / warmup
        progress = (step - warmup) / (max_steps - warmup)
        return 0.1 + 0.9 * 0.5 * (1 + math.cos(math.pi * progress))

    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_schedule)

    # ── Train ──
    model.train()
    step = step_start
    data_iter = iter(loader)
    best_loss = float("inf")
    t0 = time.time()

    print(f"\n[Train] Starting at step {step}, max {max_steps}\n")

    while step < max_steps:
        try:
            x, y = next(data_iter)
        except StopIteration:
            data_iter = iter(loader)
            x, y = next(data_iter)

        x, y = x.to(device), y.to(device)

        with ctx:
            logits, loops = model(x, return_loop_count=True)
            loss = F.cross_entropy(
                logits.view(-1, vocab_size),
                y.view(-1),
                ignore_index=0,
            )

        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        scheduler.step()
        step += 1

        if step % cfg_overrides["eval_every"] == 0 or step == 1:
            elapsed = time.time() - t0
            lr_now = scheduler.get_last_lr()[0]
            print(f"  step {step:>6} | loss {loss.item():.4f} | "
                  f"loops {loops} | lr {lr_now:.2e} | {elapsed:.1f}s")
            t0 = time.time()

            if loss.item() < best_loss:
                best_loss = loss.item()

        if step % cfg_overrides["save_every"] == 0:
            ckpt_path = ckpt_dir / f"step_{step:06d}.pt"
            torch.save({
                "model": model.state_dict(),
                "config": cfg,
                "step": step,
                "loss": loss.item(),
                "tier": tier,
            }, ckpt_path)
            print(f"  [Saved] {ckpt_path}")

    # Final save
    final_path = ckpt_dir / "final.pt"
    torch.save({
        "model": model.state_dict(),
        "config": cfg,
        "step": step,
        "loss": loss.item(),
        "tier": tier,
    }, final_path)
    print(f"\n[Done] Best loss: {best_loss:.4f} | Saved to {final_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Kerrigan-Fantasma")
    parser.add_argument("--tier", choices=list(TIERS.keys()), default="smoke")
    parser.add_argument("--data", default=None, help="Path to training text file")
    parser.add_argument("--checkpoint-dir", default=None)
    parser.add_argument("--resume", default=None, help="Path to checkpoint to resume from")
    args = parser.parse_args()

    train(args.tier, args.data, args.checkpoint_dir, args.resume)
