import re
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import ollama


@dataclass
class ExpertProfile:
    name: str
    model: str
    keywords: list[str]
    description: str


@dataclass
class RouteDecision:
    expert: str
    model: str
    reasoning: str
    confidence: float
    indicators: list[str]


class Abathur:
    """
    Routes queries to the optimal expert model.
    Tracks success/failure to evolve routing strategy over time.
    """

    EXPERTS: list[ExpertProfile] = [
        ExpertProfile(
            name="kerrigan-core",
            model="kerrigan-fantasma",
            keywords=["exploit", "rop", "shellcode", "buffer overflow", "heap", "uaf",
                      "use after free", "kernel", "privilege escalation", "pwn",
                      "spectre", "meltdown", "rowhammer", "side channel", "cache timing",
                      "dma", "firmware", "uefi", "smm", "trustzone",
                      "vulnerability", "cve", "attack", "bypass", "injection",
                      "overflow", "memory corruption", "zero day", "payload",
                      "reverse shell", "c2", "malware", "rootkit", "backdoor",
                      "http parser", "dns parser", "fuzzing", "harness",
                      "security", "penetration", "red team", "blue team",
                      "hardware", "cpu", "cache", "memory", "register"],
            description="Hardware/software exploit research and vulnerability analysis"
        ),
        ExpertProfile(
            name="code-general",
            model="deepseek-coder:6.7b",
            keywords=["write code", "implement", "function", "script",
                      "regex", "algorithm", "debug", "fix", "refactor",
                      "syntax", "compile error", "build", "class", "method"],
            description="General code generation and debugging"
        ),
        ExpertProfile(
            name="reasoning",
            model="llama3.2:3b",
            keywords=["explain", "what is", "how does", "why", "overview",
                      "difference between", "compare", "summarize"],
            description="Explanation and conceptual reasoning"
        ),
        ExpertProfile(
            name="analysis",
            model="mistral-small",
            keywords=["analyze", "review", "audit", "assess", "evaluate",
                      "malware", "sample", "binary", "yara", "sigma", "forensic",
                      "incident", "threat", "ioc"],
            description="Deep analysis, malware, forensics, threat intel"
        ),
    ]

    def __init__(self):
        self.evolution: dict[str, dict] = defaultdict(lambda: {"wins": 0, "losses": 0})
        self.history: list[dict] = []

    # Security keywords that should always boost kerrigan-core even in explanation queries
    SECURITY_OVERRIDE = {
        "spectre", "meltdown", "rowhammer", "buffer overflow", "heap overflow",
        "stack overflow", "use after free", "rop chain", "shellcode", "exploit",
        "vulnerability", "cve", "zero day", "privilege escalation", "kernel exploit",
        "side channel", "cache timing", "firmware", "uefi", "trustzone",
        "memory corruption", "overflow", "fuzzing", "malware", "rootkit",
    }

    def _score_expert(self, query: str, expert: ExpertProfile) -> tuple[float, list[str]]:
        q = query.lower()
        matched = [kw for kw in expert.keywords if kw in q]

        # Base score: match count weighted by keyword list size
        base_score = len(matched) * (1.0 / max(len(expert.keywords) ** 0.5, 1))

        # Security override: any security concept instantly boosts kerrigan-core
        # This ensures security questions beat generic "explain/what is" routing
        security_boost = 0.0
        if expert.name == "kerrigan-core":
            security_hits = [kw for kw in self.SECURITY_OVERRIDE if kw in q]
            if security_hits:
                security_boost = 0.4 * len(security_hits)
                matched = list(set(matched + security_hits))

        stats = self.evolution[expert.name]
        total = stats["wins"] + stats["losses"]
        win_rate = stats["wins"] / total if total > 0 else 0.5
        score = (base_score * 0.75) + (win_rate * 0.25) + security_boost
        return score, matched

    def route(self, query: str) -> RouteDecision:
        scores: list[tuple[float, list[str], ExpertProfile]] = []

        for expert in self.EXPERTS:
            score, indicators = self._score_expert(query, expert)
            scores.append((score, indicators, expert))

        scores.sort(key=lambda x: x[0], reverse=True)
        best_score, best_indicators, best_expert = scores[0]

        # Fall back to kerrigan-core for security queries with no keyword match
        if best_score == 0:
            best_expert = self.EXPERTS[0]
            best_indicators = []
            best_score = 0.3

        reasoning = (
            f"[Abathur Analysis]\n"
            f"  Query indicators: {best_indicators or ['(none matched)']}\n"
            f"  Top candidates:\n"
        )
        for score, indicators, expert in scores[:3]:
            stats = self.evolution[expert.name]
            total = stats["wins"] + stats["losses"]
            wr = f"{stats['wins']}/{total}" if total > 0 else "no history"
            reasoning += f"    {expert.name}: score={score:.2f}, wins={wr}\n"
        reasoning += f"  → Routing to: {best_expert.name} ({best_expert.model})"

        decision = RouteDecision(
            expert=best_expert.name,
            model=best_expert.model,
            reasoning=reasoning,
            confidence=best_score,
            indicators=best_indicators,
        )
        self.history.append({"query": query[:80], "expert": best_expert.name})
        return decision

    def learn(self, expert_name: str, success: bool):
        key = "wins" if success else "losses"
        self.evolution[expert_name][key] += 1

    def ask(self, query: str, show_routing: bool = True) -> str:
        decision = self.route(query)

        if show_routing:
            print(decision.reasoning)
            print()

        response = ollama.chat(
            model=decision.model,
            messages=[{"role": "user", "content": query}]
        )
        return response["message"]["content"]
