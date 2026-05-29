"""
ClosedLoopCompiler — compiles LLM-generated C harnesses with ASan/UBSan.
Captures all compiler output and raises structured errors the LLM can act on.
"""

import re
import os
import subprocess
import tempfile
import hashlib
from dataclasses import dataclass, field
from pathlib import Path


COMPILER   = "clang"

# ASan is blocked by SIP/AMFI on macOS Sequoia with OpenCore (legacy Mac).
# On Linux/RunPod: use full ASan + UBSan.
# On Mac locally: UBSan only — still catches integer overflows, OOB, null deref.
import platform
_IS_LINUX = platform.system() == "Linux"

ASAN_FLAGS = (
    [
        "-fsanitize=address,undefined",
        "-fno-omit-frame-pointer",
        "-fno-optimize-sibling-calls",
        "-g",
        "-O1",
    ]
    if _IS_LINUX else
    [
        "-fsanitize=undefined",    # UBSan works on macOS
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
    ]
)

EXTRA_FLAGS = ["-Wall", "-Wextra", "-Wno-unused-parameter"]

BUILD_DIR = Path(__file__).parent.parent / "data" / "harnesses"
BUILD_DIR.mkdir(parents=True, exist_ok=True)


# ── Errors ─────────────────────────────────────────────────────────────────────

@dataclass
class CompilationError(Exception):
    stderr: str
    code: str
    returncode: int

    def __str__(self):
        return f"CompilationError (rc={self.returncode}):\n{self.stderr}"

    def summary(self) -> str:
        """Extract just the error lines for the LLM — strip noise."""
        lines = self.stderr.splitlines()
        errors = [l for l in lines if "error:" in l or "warning:" in l]
        return "\n".join(errors[:20])  # cap at 20 lines


@dataclass
class CompiledHarness:
    binary_path: Path
    source_path: Path
    source_hash: str
    compiler_warnings: list[str] = field(default_factory=list)

    def __str__(self):
        return f"CompiledHarness({self.binary_path.name}, warnings={len(self.compiler_warnings)})"


# ── Compiler ───────────────────────────────────────────────────────────────────

class ClosedLoopCompiler:
    """
    Compiles C code strings into instrumented binaries.
    All output is captured so the LLM can see exactly what went wrong.
    """

    def __init__(self, build_dir: Path = BUILD_DIR, asan: bool = True):
        self.build_dir = Path(build_dir)
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.asan = asan
        self.compile_history: list[dict] = []

    def compile(self, code: str, name: str = "harness") -> CompiledHarness:
        """
        Compile a C code string into a binary.
        Raises CompilationError with full stderr if it fails.
        Returns CompiledHarness on success.
        """
        # Stable filename from content hash
        code_hash = hashlib.md5(code.encode()).hexdigest()[:8]
        src_path = self.build_dir / f"{name}_{code_hash}.c"
        bin_path = self.build_dir / f"{name}_{code_hash}.bin"

        # Write source
        src_path.write_text(code)

        # Build command
        cmd = [COMPILER]
        if self.asan:
            cmd.extend(ASAN_FLAGS)
        cmd.extend(EXTRA_FLAGS)
        cmd.extend([str(src_path), "-o", str(bin_path)])

        # Compile
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        stderr = result.stderr.strip()
        self.compile_history.append({
            "name": name,
            "hash": code_hash,
            "returncode": result.returncode,
            "stderr_lines": len(stderr.splitlines()),
        })

        if result.returncode != 0:
            raise CompilationError(
                stderr=stderr,
                code=code,
                returncode=result.returncode,
            )

        # Extract warnings from successful compile
        warnings = [
            l for l in stderr.splitlines()
            if "warning:" in l
        ]

        return CompiledHarness(
            binary_path=bin_path,
            source_path=src_path,
            source_hash=code_hash,
            compiler_warnings=warnings,
        )

    def compile_with_retry(
        self,
        code: str,
        fix_fn,          # callable(code, error) -> fixed_code
        name: str = "harness",
        max_retries: int = 3,
    ) -> CompiledHarness:
        """
        Compile with automatic LLM-driven retry on failure.
        fix_fn is called with (broken_code, error_summary) → fixed code.
        """
        current_code = code
        last_error = None

        for attempt in range(max_retries + 1):
            try:
                harness = self.compile(current_code, name=f"{name}_attempt{attempt}")
                if attempt > 0:
                    print(f"[Compiler] Fixed after {attempt} attempt(s)")
                return harness

            except CompilationError as e:
                last_error = e
                if attempt == max_retries:
                    break

                print(f"[Compiler] Attempt {attempt+1} failed — asking LLM to fix")
                print(f"  Errors: {e.summary()[:200]}")
                current_code = fix_fn(current_code, e.summary())

        raise CompilationError(
            stderr=f"Failed after {max_retries} retries.\n{last_error.stderr}",
            code=current_code,
            returncode=-1,
        )

    def cleanup_old_binaries(self, keep: int = 10):
        """Keep only the N most recent binaries to save disk space."""
        bins = sorted(self.build_dir.glob("*.bin"), key=os.path.getmtime)
        for old in bins[:-keep]:
            old.unlink(missing_ok=True)
            old.with_suffix(".c").unlink(missing_ok=True)
