"""
CrashTriageEngine — deduplicates and classifies crashes.

On macOS (no ASan): parses UBSan messages + exit signals.
On Linux (ASan):    parses full ASan stack traces.

Dedup key: hash(crash_type + ubsan_message + function_hint)
All unique crashes stored in Creep for cross-session memory.
"""

import re
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum


class CrashType(str, Enum):
    STACK_OVERFLOW    = "stack_overflow"
    HEAP_OVERFLOW     = "heap_overflow"
    USE_AFTER_FREE    = "use_after_free"
    NULL_DEREF        = "null_deref"
    INTEGER_OVERFLOW  = "integer_overflow"
    OUT_OF_BOUNDS     = "out_of_bounds"
    FORMAT_STRING     = "format_string"
    ABORT             = "abort"
    SEGFAULT          = "segfault"
    UBSAN             = "ubsan_generic"
    UNKNOWN           = "unknown"


EXPLOITABILITY = {
    CrashType.STACK_OVERFLOW:   "high",
    CrashType.HEAP_OVERFLOW:    "high",
    CrashType.USE_AFTER_FREE:   "high",
    CrashType.FORMAT_STRING:    "high",
    CrashType.OUT_OF_BOUNDS:    "medium",
    CrashType.NULL_DEREF:       "low",
    CrashType.INTEGER_OVERFLOW: "medium",
    CrashType.ABORT:            "low",
    CrashType.SEGFAULT:         "medium",
    CrashType.UBSAN:            "medium",
    CrashType.UNKNOWN:          "unknown",
}

# UBSan / ASan output patterns → crash type
PATTERNS = [
    (CrashType.HEAP_OVERFLOW,   r"heap-buffer-overflow|heap buffer overflow"),
    (CrashType.STACK_OVERFLOW,  r"stack-buffer-overflow|stack buffer overflow|stack-overflow"),
    (CrashType.USE_AFTER_FREE,  r"heap-use-after-free|use.after.free"),
    (CrashType.NULL_DEREF,      r"null pointer dereference|SEGV on unknown address 0x000000000000"),
    (CrashType.INTEGER_OVERFLOW,r"integer overflow|signed integer overflow|unsigned integer overflow"),
    (CrashType.OUT_OF_BOUNDS,   r"out of bounds|index \d+ out of bounds"),
    (CrashType.FORMAT_STRING,   r"format.string|%n in format"),
    (CrashType.ABORT,           r"Aborted|abort()"),
    (CrashType.SEGFAULT,        r"Segmentation fault|SIGSEGV"),
    (CrashType.UBSAN,           r"runtime error:"),
]

# Exit code → signal name
EXIT_SIGNALS = {
    -4:  "SIGILL",
    -6:  "SIGABRT",
    -11: "SIGSEGV",
    134: "SIGABRT",
    139: "SIGSEGV",
    132: "SIGILL",
}


@dataclass
class CrashReport:
    crash_id:       str
    crash_type:     CrashType
    exploitability: str
    exit_code:      int
    signal:         str
    raw_output:     str
    ubsan_message:  str
    input_sample:   bytes
    binary_path:    str
    timestamp:      float = field(default_factory=time.time)
    is_unique:      bool = True

    def to_llm_prompt(self) -> str:
        """Format crash for LLM analysis."""
        return (
            f"Crash Report\n"
            f"  Type         : {self.crash_type.value}\n"
            f"  Exploitability: {self.exploitability}\n"
            f"  Signal       : {self.signal} (exit {self.exit_code})\n"
            f"  UBSan message: {self.ubsan_message or '(none)'}\n"
            f"  Input (hex)  : {self.input_sample[:32].hex()}{'...' if len(self.input_sample)>32 else ''}\n"
            f"  Raw output   : {self.raw_output[:500]}\n"
        )

    def summary(self) -> str:
        return (
            f"[{self.crash_type.value}] exploit={self.exploitability} "
            f"signal={self.signal} id={self.crash_id}"
        )


class CrashTriageEngine:
    """
    Receives (exit_code, stderr, input_bytes) tuples.
    Classifies, deduplicates, and stores unique crashes in Creep.
    """

    def __init__(self, creep=None):
        self._seen: dict[str, CrashReport] = {}   # crash_id → report
        self._creep = creep                         # optional Creep memory

    # ── Classification ─────────────────────────────────────────────────────────

    def _classify(self, stderr: str, exit_code: int) -> CrashType:
        text = stderr.lower()
        for crash_type, pattern in PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return crash_type
        # macOS SIP suppresses UBSan stderr — classify by signal alone
        # SIGILL (-4/132) from UBSan instrumentation = memory corruption
        # Use input size as a heuristic: large input + SIGILL = overflow
        if exit_code in EXIT_SIGNALS:
            if exit_code in (-11, 139): return CrashType.SEGFAULT
            if exit_code in (-6, 134):  return CrashType.ABORT
            if exit_code in (-4, 132):  return CrashType.STACK_OVERFLOW  # UBSan fired
        if exit_code != 0:
            return CrashType.UNKNOWN
        return CrashType.UNKNOWN

    def _extract_ubsan_message(self, stderr: str) -> str:
        """Pull the first UBSan runtime error line."""
        for line in stderr.splitlines():
            if "runtime error:" in line:
                # Strip file path prefix — keep only the error text
                match = re.search(r"runtime error:\s*(.+)", line)
                return match.group(1).strip() if match else line.strip()
        # ASan summary line
        match = re.search(r"(heap-buffer-overflow|stack-buffer-overflow|"
                           r"heap-use-after-free|null-pointer-dereference)", stderr)
        return match.group(1) if match else ""

    def _crash_id(self, crash_type: CrashType, ubsan_msg: str,
                  exit_code: int) -> str:
        """
        Stable dedup key.
        Strip memory addresses so the same bug hashes identically
        across runs with different ASLR layouts.
        """
        clean_msg = re.sub(r"0x[0-9a-f]+", "0xADDR", ubsan_msg.lower())
        clean_msg = re.sub(r"\bline \d+\b", "line N", clean_msg)
        raw = f"{crash_type.value}:{clean_msg}:{exit_code}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    # ── Public API ─────────────────────────────────────────────────────────────

    def process(
        self,
        exit_code: int,
        stderr: str,
        stdout: str,
        input_bytes: bytes,
        binary_path: str,
    ) -> CrashReport | None:
        """
        Process one execution result.
        Returns CrashReport if it's a crash, None if clean run.
        Sets report.is_unique=False if we've seen this crash before.
        """
        if exit_code == 0:
            return None

        crash_type  = self._classify(stderr, exit_code)
        ubsan_msg   = self._extract_ubsan_message(stderr)
        signal      = EXIT_SIGNALS.get(exit_code, f"exit({exit_code})")
        crash_id    = self._crash_id(crash_type, ubsan_msg, exit_code)

        report = CrashReport(
            crash_id       = crash_id,
            crash_type     = crash_type,
            exploitability = EXPLOITABILITY[crash_type],
            exit_code      = exit_code,
            signal         = signal,
            raw_output     = (stderr + stdout)[:2000],
            ubsan_message  = ubsan_msg,
            input_sample   = input_bytes[:64],
            binary_path    = binary_path,
            is_unique      = crash_id not in self._seen,
        )

        if report.is_unique:
            self._seen[crash_id] = report
            self._store_in_creep(report)

        return report

    def unique_reports(self) -> list[CrashReport]:
        return list(self._seen.values())

    def stats(self) -> dict:
        reports = self.unique_reports()
        by_type = {}
        for r in reports:
            by_type[r.crash_type.value] = by_type.get(r.crash_type.value, 0) + 1
        return {
            "total_unique": len(reports),
            "high_exploitability": sum(1 for r in reports if r.exploitability == "high"),
            "by_type": by_type,
        }

    def _store_in_creep(self, report: CrashReport):
        if self._creep is None:
            return
        try:
            from memory.creep import Finding
            import time
            finding = Finding(
                content=(
                    f"Crash: {report.crash_type.value} | "
                    f"exploit={report.exploitability} | "
                    f"signal={report.signal} | "
                    f"ubsan={report.ubsan_message}"
                ),
                query=f"crash analysis {report.crash_type.value}",
                expert="evolutionary-loop",
                tags=["crash", report.crash_type.value, report.exploitability],
                timestamp=report.timestamp,
            )
            self._creep.absorb(finding)
        except Exception:
            pass  # Creep is optional — don't break the loop if it fails
