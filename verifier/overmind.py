import re
import ast
import subprocess
from dataclasses import dataclass


@dataclass
class Verdict:
    passed: bool
    reason: str
    warnings: list[str]
    category: str


DANGEROUS_PATTERNS = [
    (r"(?i)(msfvenom|metasploit payload)", "live payload generator reference"),
    (r"curl\s+\S+\s*\|\s*(ba)?sh", "curl-pipe-to-shell"),
    (r"(?i)nc\s+-e\s+/bin/(ba)?sh", "netcat reverse shell"),
    (r"python\s+-c\s+['\"]import socket", "inline socket reverse shell"),
    (r"(?i)(add-?user|useradd)\s+.*&&.*passwd", "live account creation chain"),
]

LIVE_TARGET_PATTERNS = [
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",           # raw IPv4
    r"(?i)\b(prod|production|live)\b.{0,20}(server|host|target|box)",
]

EDUCATIONAL_MARKERS = [
    "educational", "example", "demonstration", "lab", "ctf",
    "proof of concept", "poc", "sandbox", "test environment",
]


class Overmind:
    """
    Verifies all Kerrigan-Fantasma output before delivery.
    Blocks live weaponization, flags warnings, approves clean responses.
    """

    def verify(self, output: str, query: str = "", context: dict | None = None) -> Verdict:
        context = context or {}
        warnings: list[str] = []

        # Pass 1: hard blocks
        for pattern, label in DANGEROUS_PATTERNS:
            if re.search(pattern, output):
                is_educational = any(m in output.lower() for m in EDUCATIONAL_MARKERS)
                if not is_educational:
                    return Verdict(
                        passed=False,
                        reason=f"Overmind blocked: {label}",
                        warnings=[],
                        category="hard_block",
                    )
                warnings.append(f"Dangerous pattern present but marked educational: {label}")

        # Pass 2: live target check
        authorized = context.get("authorized_targets", [])
        for pattern in LIVE_TARGET_PATTERNS:
            matches = re.findall(pattern, output)
            for match in matches:
                match_str = match if isinstance(match, str) else " ".join(match)
                if not any(t in match_str for t in authorized):
                    warnings.append(f"Possible live target reference: '{match_str[:40]}'")

        # Pass 3: code safety check
        code_blocks = re.findall(r"```(?:python)?\n(.*?)```", output, re.DOTALL)
        for block in code_blocks:
            result = self._check_code(block)
            if result:
                warnings.append(f"Code warning: {result}")

        # Pass 4: authorization check
        needs_auth = any(kw in output.lower() for kw in [
            "target system", "victim", "compromised host", "owned box"
        ])
        if needs_auth and not context.get("authorized"):
            warnings.append("Output references target systems — ensure you have authorization")

        passed = True
        reason = "Overmind approves"
        if warnings:
            reason = f"Overmind approves with {len(warnings)} warning(s)"

        return Verdict(passed=passed, reason=reason, warnings=warnings, category="approved")

    def _check_code(self, code: str) -> str | None:
        """Light AST check for obviously unsafe patterns in Python code blocks."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return None  # not Python, skip

        unsafe_calls = {"eval", "exec", "compile", "__import__"}
        unsafe_attrs = {"system", "popen", "Popen"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
                if name in unsafe_calls:
                    return f"unsafe call: {name}()"
                if name in unsafe_attrs:
                    return f"shell execution: {name}()"
        return None

    def gate(self, output: str, query: str = "", context: dict | None = None) -> tuple[str, Verdict]:
        """
        Main entry point. Returns (filtered_output, verdict).
        Appends warnings to output if any.
        """
        verdict = self.verify(output, query, context)

        if not verdict.passed:
            blocked_msg = (
                f"\n[OVERMIND] {verdict.reason}\n"
                "Response blocked. Rephrase with explicit educational/lab context."
            )
            return blocked_msg, verdict

        result = output
        if verdict.warnings:
            result += "\n\n---\n[OVERMIND WARNINGS]\n"
            for w in verdict.warnings:
                result += f"  ⚠ {w}\n"

        return result, verdict
