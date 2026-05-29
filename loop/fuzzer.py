"""
MutationFuzzer — generates mutated inputs to find crashes.
No external dependencies. Works identically on Mac and Linux.

Strategies:
  - Boundary values (0, MAX_INT, -1, empty, huge)
  - Bit flips
  - Byte insertions / deletions
  - Interesting integers injected at random offsets
  - Format string sequences
  - Long repetitions (triggers length checks)
  - Known-bad patterns (null bytes, non-printable, unicode bombs)
"""

import os
import random
import struct
import subprocess
from pathlib import Path
from dataclasses import dataclass


# ── Interesting values ─────────────────────────────────────────────────────────

INTERESTING_8  = [0, 1, 0x7f, 0x80, 0xff, 0xfe]
INTERESTING_16 = [0, 1, 0x7fff, 0x8000, 0xffff, 0xfffe, 100, 1000]
INTERESTING_32 = [0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe,
                  0x10000, 0x1000, 100, 1000, 65536]

FORMAT_STRINGS = [
    b"%s%s%s%s%s%s%s%s",
    b"%x%x%x%x%x%x%x%x",
    b"%n%n%n%n",
    b"%.99999s",
    b"%1000000d",
    b"AAAA%08x.%08x.%08x",
]

LONG_STRINGS = [
    b"A" * n for n in [16, 32, 64, 128, 256, 512, 1024, 4096, 65536]
]

SPECIAL_BYTES = [
    b"\x00",                    # null terminator
    b"\xff\xfe",                # BOM
    b"\x00" * 8,                # null block
    b"\x41" * 256,              # overflow bait
    b"../../../etc/passwd",     # path traversal
    b"%s" * 20,                 # format string
    b"\n" * 100,                # newline flood
]


@dataclass
class FuzzResult:
    input_data: bytes
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def crashed(self) -> bool:
        return self.exit_code != 0 or self.timed_out


class MutationFuzzer:
    """
    Generates and executes mutated inputs against a compiled binary.
    Returns all crashing inputs for the triage engine.
    """

    def __init__(self, timeout_sec: float = 3.0, seed: int = None):
        self.timeout = timeout_sec
        self.rng = random.Random(seed)

    # ── Mutation strategies ────────────────────────────────────────────────────

    def _bit_flip(self, data: bytes, n_flips: int = 1) -> bytes:
        buf = bytearray(data)
        if not buf:
            return data
        for _ in range(n_flips):
            pos = self.rng.randrange(len(buf))
            bit = 1 << self.rng.randrange(8)
            buf[pos] ^= bit
        return bytes(buf)

    def _byte_insert(self, data: bytes) -> bytes:
        buf = bytearray(data)
        pos = self.rng.randrange(len(buf) + 1)
        val = self.rng.randint(0, 255)
        buf.insert(pos, val)
        return bytes(buf)

    def _byte_delete(self, data: bytes) -> bytes:
        if len(data) <= 1:
            return data
        buf = bytearray(data)
        pos = self.rng.randrange(len(buf))
        del buf[pos]
        return bytes(buf)

    def _inject_interesting(self, data: bytes) -> bytes:
        buf = bytearray(data)
        if not buf:
            return data
        pos = self.rng.randrange(len(buf))
        choice = self.rng.choice([8, 16, 32])
        if choice == 8:
            val = struct.pack("B", self.rng.choice(INTERESTING_8))
        elif choice == 16:
            val = struct.pack("<H", self.rng.choice(INTERESTING_16))
        else:
            val = struct.pack("<I", self.rng.choice(INTERESTING_32))
        buf[pos:pos+len(val)] = val
        return bytes(buf)

    def _splice(self, a: bytes, b: bytes) -> bytes:
        """Combine two inputs at a random split point."""
        if not a or not b:
            return a or b
        split = self.rng.randrange(len(a))
        return a[:split] + b[self.rng.randrange(len(b)):]

    def generate_mutations(self, seed: bytes, n: int = 50) -> list[bytes]:
        """Generate n mutations from a seed input."""
        if not seed:
            seed = b"A"

        corpus = [seed]
        mutations = []

        # Add known interesting inputs
        mutations.extend(LONG_STRINGS[:4])
        mutations.extend(FORMAT_STRINGS[:3])
        mutations.extend(SPECIAL_BYTES[:4])

        # Mutation-based
        strategies = [
            lambda d: self._bit_flip(d, 1),
            lambda d: self._bit_flip(d, 4),
            lambda d: self._byte_insert(d),
            lambda d: self._byte_delete(d),
            lambda d: self._inject_interesting(d),
            lambda d: d * self.rng.randint(2, 10),        # repetition
            lambda d: d + bytes([0] * self.rng.randint(1, 64)),  # null append
            lambda d: bytes([self.rng.randint(0, 255) for _ in range(len(d))]),  # random
        ]

        while len(mutations) < n:
            base = self.rng.choice(corpus)
            strategy = self.rng.choice(strategies)
            try:
                mutant = strategy(base)
                mutations.append(mutant)
                # Occasionally add mutant back into corpus (coverage-guided-like)
                if self.rng.random() < 0.1:
                    corpus.append(mutant)
            except Exception:
                mutations.append(base)

        return mutations[:n]

    # ── Execution ──────────────────────────────────────────────────────────────

    def run_one(self, binary_path: Path, input_data: bytes) -> FuzzResult:
        """Execute binary with input via stdin. Return result."""
        try:
            result = subprocess.run(
                [str(binary_path)],
                input=input_data,
                capture_output=True,
                timeout=self.timeout,
            )
            return FuzzResult(
                input_data=input_data,
                exit_code=result.returncode,
                stdout=result.stdout.decode("utf-8", errors="replace"),
                stderr=result.stderr.decode("utf-8", errors="replace"),
            )
        except subprocess.TimeoutExpired:
            return FuzzResult(
                input_data=input_data,
                exit_code=-1,
                stdout="",
                stderr="[timeout]",
                timed_out=True,
            )
        except Exception as e:
            return FuzzResult(
                input_data=input_data,
                exit_code=-1,
                stdout="",
                stderr=str(e),
            )

    def fuzz(
        self,
        binary_path: Path,
        seed: bytes = b"A",
        n_inputs: int = 100,
        on_crash=None,
    ) -> list[FuzzResult]:
        """
        Fuzz a binary with n_inputs mutations of seed.
        Calls on_crash(result) for each crash if provided.
        Returns all crashing results.
        """
        mutations = self.generate_mutations(seed, n=n_inputs)
        crashes = []
        clean = 0

        for i, inp in enumerate(mutations):
            result = self.run_one(binary_path, inp)
            if result.crashed:
                crashes.append(result)
                if on_crash:
                    on_crash(result)
            else:
                clean += 1

        print(f"  [Fuzzer] {n_inputs} inputs → {len(crashes)} crashes, "
              f"{clean} clean ({binary_path.name})")
        return crashes
