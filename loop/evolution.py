"""
EvolutionaryLoop — the closed feedback loop.

LLM generates harness → Compiler instruments it → Fuzzer mutates inputs
→ Triage deduplicates crashes → LLM analyzes + mutates harness → repeat.

Uses Ollama (kerrigan-fantasma model) for all LLM calls.
Falls back gracefully if Ollama is unavailable.
"""

import re
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import ollama

from loop.compiler  import ClosedLoopCompiler, CompilationError
from loop.fuzzer    import MutationFuzzer
from loop.triage    import CrashTriageEngine, CrashReport


DEFAULT_MODEL = "kerrigan-fantasma"
FALLBACK_MODEL = "deepseek-coder:6.7b"

LOGS_DIR = Path(__file__).parent.parent / "data" / "evolution_logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)


# ── LLM interface ──────────────────────────────────────────────────────────────

class KerriganLLM:
    def __init__(self, model: str = DEFAULT_MODEL):
        # Verify model is available, fall back if needed
        try:
            models = [m.model for m in ollama.list().models]
            self.model = model if model in models else FALLBACK_MODEL
        except Exception:
            self.model = FALLBACK_MODEL
        print(f"[LLM] Using model: {self.model}")

    def _ask(self, prompt: str, temperature: float = 0.3) -> str:
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": temperature},
            )
            return resp["message"]["content"]
        except Exception as e:
            return f"// LLM error: {e}"

    def _extract_c_code(self, text: str) -> str:
        """Pull C code out of markdown code blocks or raw text."""
        # Try fenced block first
        match = re.search(r"```(?:c|C)?\n(.*?)```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        # Heuristic: if it looks like C, return it directly
        if "#include" in text or "int main" in text:
            return text.strip()
        return text.strip()

    def generate_harness(self, target: str) -> str:
        prompt = f"""Write a C program that parses untrusted input from stdin.
Requirements:
- Include a function: void parse_input(char *data, size_t len)
- Read from stdin into a fixed-size buffer
- Add at least two of: buffer copy, integer arithmetic, pointer arithmetic
- Keep it under 60 lines
- Return ONLY the C code, no explanation

Target: {target}"""
        return self._extract_c_code(self._ask(prompt, temperature=0.4))

    def fix_compilation(self, code: str, error: str) -> str:
        prompt = f"""Fix this C code that failed to compile.
Compiler errors:
{error}

Code:
```c
{code}
```
Return ONLY the corrected C code."""
        return self._extract_c_code(self._ask(prompt, temperature=0.2))

    def analyze_crash(self, report: CrashReport) -> str:
        prompt = f"""Analyze this crash report from a C fuzzing session:

{report.to_llm_prompt()}

Answer concisely:
1. Root cause (1 sentence)
2. Vulnerability class (e.g. CWE-121)
3. How to trigger it reliably
4. Fix recommendation"""
        return self._ask(prompt, temperature=0.2)

    def mutate_harness(self, code: str, crash_reports: list[CrashReport]) -> str:
        crash_summary = "\n".join(
            f"- {r.crash_type.value} (exploit={r.exploitability}): {r.ubsan_message}"
            for r in crash_reports[:5]
        )
        prompt = f"""You are evolving a C fuzzing harness. Current crashes found:
{crash_summary}

Current harness:
```c
{code}
```

Mutate the harness to:
1. Keep the existing vulnerability surfaces
2. Add one NEW vulnerability class not yet found
3. Stay under 80 lines

Return ONLY the C code."""
        return self._extract_c_code(self._ask(prompt, temperature=0.5))

    def expand_harness(self, code: str) -> str:
        """Called when no crashes found — add more attack surface."""
        prompt = f"""This C fuzzing harness found no crashes after mutation fuzzing.
Add more vulnerability surfaces (heap allocation, string operations, integer math).

Current code:
```c
{code}
```
Return ONLY the updated C code."""
        return self._extract_c_code(self._ask(prompt, temperature=0.5))


# ── Evolution loop ─────────────────────────────────────────────────────────────

@dataclass
class IterationResult:
    iteration:     int
    code:          str
    compiled:      bool
    crashes_found: int
    unique_new:    int
    error:         str = ""
    duration_sec:  float = 0.0


@dataclass
class EvolutionSession:
    target:       str
    iterations:   list[IterationResult] = field(default_factory=list)
    all_crashes:  list[CrashReport]     = field(default_factory=list)
    start_time:   float                 = field(default_factory=time.time)

    def summary(self) -> str:
        total   = len(self.all_crashes)
        unique  = len({r.crash_id for r in self.all_crashes})
        high    = sum(1 for r in self.all_crashes if r.exploitability == "high")
        elapsed = time.time() - self.start_time
        return (
            f"Session: {self.target[:60]}\n"
            f"  Iterations  : {len(self.iterations)}\n"
            f"  Total crashes: {total} ({unique} unique)\n"
            f"  High exploit : {high}\n"
            f"  Duration     : {elapsed:.1f}s"
        )


class EvolutionaryLoop:
    def __init__(
        self,
        model:       str   = DEFAULT_MODEL,
        n_fuzz:      int   = 100,
        max_retries: int   = 3,
        creep=None,
    ):
        self.llm      = KerriganLLM(model)
        self.compiler = ClosedLoopCompiler()
        self.fuzzer   = MutationFuzzer(timeout_sec=3.0)
        self.triage   = CrashTriageEngine(creep=creep)
        self.n_fuzz   = n_fuzz
        self.max_retries = max_retries

    def run(self, target: str, iterations: int = 5) -> EvolutionSession:
        session = EvolutionSession(target=target)
        log_path = LOGS_DIR / f"session_{int(time.time())}.jsonl"

        def log(obj: dict):
            with log_path.open("a") as f:
                f.write(json.dumps(obj) + "\n")

        print(f"\n{'='*60}")
        print(f"  EVOLUTIONARY LOOP")
        print(f"  Target   : {target}")
        print(f"  Iterations: {iterations} | Fuzz inputs: {self.n_fuzz}")
        print(f"  Log      : {log_path.name}")
        print(f"{'='*60}\n")

        # Iteration 0: generate initial harness
        print("[Iter 0] Generating initial harness...")
        code = self.llm.generate_harness(target)
        log({"iteration": 0, "event": "generate", "code_len": len(code)})

        for i in range(1, iterations + 1):
            t0 = time.time()
            print(f"\n[Iter {i}/{iterations}] ─────────────────────────────")

            # ── Compile ──────────────────────────────────────────────────────
            harness = None
            compile_attempts = 0
            current_code = code

            for attempt in range(self.max_retries):
                try:
                    harness = self.compiler.compile(current_code, name=f"harness_i{i}")
                    compile_attempts = attempt + 1
                    print(f"  Compiled   : OK (attempt {compile_attempts}, "
                          f"warnings={len(harness.compiler_warnings)})")
                    break
                except CompilationError as e:
                    print(f"  Compile err (attempt {attempt+1}): {e.summary()[:100]}")
                    log({"iteration": i, "event": "compile_error",
                         "attempt": attempt+1, "error": e.summary()[:200]})
                    current_code = self.llm.fix_compilation(current_code, e.summary())

            if harness is None:
                result = IterationResult(
                    iteration=i, code=current_code, compiled=False,
                    crashes_found=0, unique_new=0,
                    error="compile failed after retries",
                    duration_sec=time.time()-t0,
                )
                session.iterations.append(result)
                log({"iteration": i, "event": "skip_no_compile"})
                continue

            # ── Fuzz ─────────────────────────────────────────────────────────
            seed = b"Hello\x00World\n"
            crash_results = self.fuzzer.fuzz(harness.binary_path, seed=seed,
                                              n_inputs=self.n_fuzz)

            # ── Triage ───────────────────────────────────────────────────────
            new_unique = []
            for cr in crash_results:
                report = self.triage.process(
                    exit_code=cr.exit_code,
                    stderr=cr.stderr,
                    stdout=cr.stdout,
                    input_bytes=cr.input_data,
                    binary_path=str(harness.binary_path),
                )
                if report and report.is_unique:
                    new_unique.append(report)
                    session.all_crashes.append(report)
                    print(f"  NEW CRASH  : {report.summary()}")
                    log({"iteration": i, "event": "new_crash",
                         "crash_id": report.crash_id,
                         "type": report.crash_type.value,
                         "exploit": report.exploitability})

            stats = self.triage.stats()
            print(f"  Triage     : {len(crash_results)} crashes → "
                  f"{len(new_unique)} new unique | "
                  f"total unique={stats['total_unique']}")

            # ── LLM analysis of new crashes ───────────────────────────────────
            for report in new_unique[:2]:  # analyze max 2 per iteration
                analysis = self.llm.analyze_crash(report)
                print(f"\n  [Analysis] {report.crash_type.value}:")
                for line in analysis.splitlines()[:4]:
                    print(f"    {line}")
                log({"iteration": i, "event": "analysis",
                     "crash_id": report.crash_id, "analysis": analysis[:500]})

            # ── Evolve code for next iteration ────────────────────────────────
            unique_reports = self.triage.unique_reports()
            if unique_reports:
                print(f"\n  [Evolve] Mutating harness based on {len(unique_reports)} crash(es)...")
                code = self.llm.mutate_harness(current_code, unique_reports)
            else:
                print(f"\n  [Evolve] No crashes — expanding attack surface...")
                code = self.llm.expand_harness(current_code)

            result = IterationResult(
                iteration=i,
                code=current_code,
                compiled=True,
                crashes_found=len(crash_results),
                unique_new=len(new_unique),
                duration_sec=time.time()-t0,
            )
            session.iterations.append(result)
            log({"iteration": i, "event": "complete",
                 "crashes": len(crash_results), "new_unique": len(new_unique),
                 "duration": result.duration_sec})

        # ── Session summary ───────────────────────────────────────────────────
        print(f"\n{'='*60}")
        print(session.summary())
        print(f"{'='*60}")
        log({"event": "session_end", "summary": session.summary()})

        self.compiler.cleanup_old_binaries(keep=20)
        return session
