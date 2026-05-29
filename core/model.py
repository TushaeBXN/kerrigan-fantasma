"""
Kerrigan Core — Recurrent-Depth Transformer
Architecture: Prelude → [Recurrent Block × N loops] → Coda
Each loop evolves the same hidden state through the same weights.
ACT (Adaptive Computation Time) lets the model halt early when confident.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Optional


@dataclass
class KerriganConfig:
    vocab_size: int = 32000
    hidden_size: int = 512          # small for local dev; scale to 2048 for 3B
    intermediate_size: int = 2048   # 4× hidden
    num_heads: int = 8
    head_dim: int = 64              # hidden_size // num_heads
    num_prelude_layers: int = 2
    num_coda_layers: int = 2
    max_loops: int = 8              # max recurrent iterations
    act_threshold: float = 0.01     # halt when state change < this
    max_seq_len: int = 2048
    dropout: float = 0.1
    # MoE
    num_experts: int = 8
    top_k_experts: int = 2
    # LoRA per loop
    lora_rank: int = 8
    lora_alpha: float = 16.0
    # Device
    device: str = "cpu"
    dtype: torch.dtype = torch.float32


# ── Attention ──────────────────────────────────────────────────────────────────

class MultiHeadAttention(nn.Module):
    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.num_heads = cfg.num_heads
        self.head_dim = cfg.head_dim
        self.scale = cfg.head_dim ** -0.5

        d = cfg.hidden_size
        self.q = nn.Linear(d, d, bias=False)
        self.k = nn.Linear(d, d, bias=False)
        self.v = nn.Linear(d, d, bias=False)
        self.out = nn.Linear(d, d, bias=False)
        self.drop = nn.Dropout(cfg.dropout)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        B, T, D = x.shape
        H, Dh = self.num_heads, self.head_dim

        q = self.q(x).view(B, T, H, Dh).transpose(1, 2)
        k = self.k(x).view(B, T, H, Dh).transpose(1, 2)
        v = self.v(x).view(B, T, H, Dh).transpose(1, 2)

        attn = (q @ k.transpose(-2, -1)) * self.scale
        if mask is not None:
            attn = attn.masked_fill(mask == 0, float("-inf"))
        attn = F.softmax(attn, dim=-1)
        attn = self.drop(attn)

        out = (attn @ v).transpose(1, 2).contiguous().view(B, T, D)
        return self.out(out)


# ── Mixture of Experts ─────────────────────────────────────────────────────────

class Expert(nn.Module):
    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.gate = nn.Linear(cfg.hidden_size, cfg.intermediate_size, bias=False)
        self.up   = nn.Linear(cfg.hidden_size, cfg.intermediate_size, bias=False)
        self.down = nn.Linear(cfg.intermediate_size, cfg.hidden_size, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.down(F.silu(self.gate(x)) * self.up(x))


class MoELayer(nn.Module):
    """Sparse Mixture of Experts — top-k routing."""

    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.num_experts = cfg.num_experts
        self.top_k = cfg.top_k_experts
        self.router = nn.Linear(cfg.hidden_size, cfg.num_experts, bias=False)
        self.experts = nn.ModuleList([Expert(cfg) for _ in range(cfg.num_experts)])

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, T, D = x.shape
        flat = x.view(-1, D)                          # (B*T, D)

        logits = self.router(flat)                    # (B*T, E)
        weights, indices = torch.topk(logits, self.top_k, dim=-1)
        weights = F.softmax(weights, dim=-1)          # (B*T, k)

        out = torch.zeros_like(flat)
        for k in range(self.top_k):
            expert_idx = indices[:, k]               # (B*T,)
            weight     = weights[:, k].unsqueeze(-1) # (B*T, 1)
            for e in range(self.num_experts):
                mask = (expert_idx == e)
                if mask.any():
                    out[mask] += weight[mask] * self.experts[e](flat[mask])

        return out.view(B, T, D)


# ── Loop LoRA adapter ──────────────────────────────────────────────────────────

class LoRAAdapter(nn.Module):
    """Per-loop low-rank adaptation — each loop can specialize."""

    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        r = cfg.lora_rank
        d = cfg.hidden_size
        scale = cfg.lora_alpha / r
        self.A = nn.Linear(d, r, bias=False)
        self.B = nn.Linear(r, d, bias=False)
        nn.init.kaiming_uniform_(self.A.weight)
        nn.init.zeros_(self.B.weight)
        self.scale = scale

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.scale * self.B(self.A(x))


# ── RMSNorm (compatible with PyTorch 2.2.2) ────────────────────────────────────

class RMSNorm(nn.Module):
    def __init__(self, dim: int, eps: float = 1e-6):
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        rms = x.pow(2).mean(-1, keepdim=True).add(self.eps).rsqrt()
        return x * rms * self.weight


# ── Transformer block ──────────────────────────────────────────────────────────

class TransformerBlock(nn.Module):
    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.norm1 = RMSNorm(cfg.hidden_size)
        self.attn  = MultiHeadAttention(cfg)
        self.norm2 = RMSNorm(cfg.hidden_size)
        self.moe   = MoELayer(cfg)
        self.drop  = nn.Dropout(cfg.dropout)

    def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
        x = x + self.drop(self.attn(self.norm1(x), mask))
        x = x + self.drop(self.moe(self.norm2(x)))
        return x


# ── Adaptive Computation Time ──────────────────────────────────────────────────

class ACTHalting(nn.Module):
    """
    Learns a halting probability at each loop.
    Stops when cumulative halt prob exceeds threshold.
    """

    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.halt_linear = nn.Linear(cfg.hidden_size, 1)
        self.threshold = cfg.act_threshold

    def halting_prob(self, x: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(self.halt_linear(x)).squeeze(-1)  # (B, T)

    def should_halt(self, x: torch.Tensor, cumulative_halt: torch.Tensor) -> tuple[bool, torch.Tensor]:
        p = self.halting_prob(x)
        cumulative_halt = cumulative_halt + p
        halt = (cumulative_halt >= 1.0 - self.threshold).all().item()
        return halt, cumulative_halt


# ── Kerrigan Core ──────────────────────────────────────────────────────────────

class KerriganCore(nn.Module):
    """
    Recurrent-Depth Transformer.
    
    Prelude:   N standard transformer blocks (encode input once)
    Recurrent: 1 block looped up to max_loops times (evolving thought)
    Coda:      N standard transformer blocks (refine final state)
    
    Each loop applies a LoRA adapter so the same weights can specialize
    per iteration without parameter growth.
    """

    def __init__(self, cfg: KerriganConfig):
        super().__init__()
        self.cfg = cfg

        self.embed    = nn.Embedding(cfg.vocab_size, cfg.hidden_size)
        self.pos_embed = nn.Embedding(cfg.max_seq_len, cfg.hidden_size)
        self.drop     = nn.Dropout(cfg.dropout)

        # Prelude: initial encoding (runs once)
        self.prelude = nn.ModuleList([
            TransformerBlock(cfg) for _ in range(cfg.num_prelude_layers)
        ])

        # Recurrent block: looped up to max_loops times
        self.recurrent_block = TransformerBlock(cfg)

        # Per-loop LoRA adapters: each iteration can specialize
        self.loop_adapters = nn.ModuleList([
            LoRAAdapter(cfg) for _ in range(cfg.max_loops)
        ])

        # ACT: model learns when to halt
        self.act = ACTHalting(cfg)

        # Coda: final refinement
        self.coda = nn.ModuleList([
            TransformerBlock(cfg) for _ in range(cfg.num_coda_layers)
        ])

        self.norm   = RMSNorm(cfg.hidden_size)
        self.lm_head = nn.Linear(cfg.hidden_size, cfg.vocab_size, bias=False)

        # Weight tying
        self.lm_head.weight = self.embed.weight

        self.apply(self._init_weights)

    def _init_weights(self, module):
        if isinstance(module, nn.Linear):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)

    def forward(
        self,
        input_ids: torch.Tensor,
        mask: Optional[torch.Tensor] = None,
        return_loop_count: bool = False,
    ):
        B, T = input_ids.shape
        pos = torch.arange(T, device=input_ids.device).unsqueeze(0)

        x = self.drop(self.embed(input_ids) + self.pos_embed(pos))

        # Causal mask
        if mask is None:
            mask = torch.tril(torch.ones(T, T, device=x.device)).unsqueeze(0).unsqueeze(0)

        # ── Prelude ──
        for block in self.prelude:
            x = block(x, mask)

        # Freeze the encoded input so it can be re-injected each loop
        e_frozen = x.detach()

        # ── Recurrent loops ──
        cumulative_halt = torch.zeros(B, T, device=x.device)
        loops_taken = 0

        for t in range(self.cfg.max_loops):
            # Loop-specific LoRA adaptation
            x = self.loop_adapters[t](x)

            # Re-inject frozen encoding (prevents catastrophic forgetting)
            x = x + 0.1 * e_frozen

            # Recurrent block
            x = self.recurrent_block(x, mask)

            loops_taken = t + 1

            # ACT: check if model wants to halt
            should_halt, cumulative_halt = self.act.should_halt(x, cumulative_halt)
            if should_halt and t >= 1:  # always do at least 2 loops
                break

        # ── Coda ──
        for block in self.coda:
            x = block(x, mask)

        x = self.norm(x)
        logits = self.lm_head(x)

        if return_loop_count:
            return logits, loops_taken
        return logits

    def num_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters())

    @classmethod
    def from_config(cls, cfg: KerriganConfig) -> "KerriganCore":
        return cls(cfg).to(cfg.device)
