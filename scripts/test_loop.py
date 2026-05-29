"""
Test the full evolutionary loop with a known-vulnerable harness.
Uses a hardcoded harness so we don't need the LLM for the test —
but the triage and fuzzer are fully live.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from loop.compiler import ClosedLoopCompiler, CompilationError
from loop.fuzzer   import MutationFuzzer
from loop.triage   import CrashTriageEngine

VULNERABLE_HARNESS = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void parse_input(char *data, size_t len) {
    char stack_buf[32];
    char *heap_buf = malloc(16);

    // Vulnerability 1: no bounds check on stack copy
    memcpy(stack_buf, data, len);

    // Vulnerability 2: no bounds check on heap copy
    memcpy(heap_buf, data, len);

    free(heap_buf);
}

int main() {
    char input[4096] = {0};
    size_t n = fread(input, 1, sizeof(input)-1, stdin);
    if (n > 0) parse_input(input, n);
    return 0;
}
"""

compiler = ClosedLoopCompiler()
fuzzer   = MutationFuzzer(timeout_sec=2.0, seed=42)
triage   = CrashTriageEngine()

print("=== Step 1: Compile vulnerable harness ===")
harness = compiler.compile(VULNERABLE_HARNESS, name="vuln_test")
print(f"  {harness}")

print("\n=== Step 2: Fuzz with 80 mutations ===")
crashes = fuzzer.fuzz(harness.binary_path, seed=b"Hello", n_inputs=80)

print("\n=== Step 3: Triage crashes ===")
for cr in crashes:
    report = triage.process(
        exit_code=cr.exit_code,
        stderr=cr.stderr,
        stdout=cr.stdout,
        input_bytes=cr.input_data,
        binary_path=str(harness.binary_path),
    )
    if report and report.is_unique:
        print(f"  UNIQUE: {report.summary()}")

print("\n=== Stats ===")
stats = triage.stats()
print(f"  Total unique crashes : {stats['total_unique']}")
print(f"  High exploitability  : {stats['high_exploitability']}")
print(f"  By type              : {stats['by_type']}")

print("\n=== LLM-ready report (first crash) ===")
reports = triage.unique_reports()
if reports:
    print(reports[0].to_llm_prompt())
