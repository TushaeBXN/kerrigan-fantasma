import sys
sys.path.insert(0, "/Users/dadsmacpro/Desktop/kerrigan-fantasma")
from loop.compiler import ClosedLoopCompiler, CompilationError
import subprocess

compiler = ClosedLoopCompiler()

# ── Test 1: clean compile ──────────────────────────────────────────────────────
print("=== Test 1: Clean compile ===")
clean_code = """
#include <stdio.h>
#include <string.h>
void parse_input(char *data, size_t len) {
    char buf[64];
    if (len < 64) strncpy(buf, data, len);
}
int main() {
    parse_input("hello", 5);
    printf("OK\\n");
    return 0;
}
"""
harness = compiler.compile(clean_code, name="clean")
print(f"  Result : {harness}")
print(f"  Binary : {harness.binary_path}")
print(f"  Warnings: {len(harness.compiler_warnings)}")

# ── Test 2: compilation error ──────────────────────────────────────────────────
print("\n=== Test 2: Compilation error ===")
bad_code = """
#include <stdio.h>
int main() {
    int x = "this is not an int"  // missing semicolon, wrong type
    return 0;
}
"""
try:
    compiler.compile(bad_code, name="bad")
except CompilationError as e:
    print(f"  Caught CompilationError (expected)")
    print(f"  Summary: {e.summary()[:150]}")

# ── Test 3: real overflow — compiles fine, crashes at runtime with ASan ────────
print("\n=== Test 3: Stack overflow (compiles, ASan catches at runtime) ===")
overflow_code = """
#include <stdio.h>
#include <string.h>
void parse_input(char *data) {
    char buf[16];
    strcpy(buf, data);   // classic overflow — no bounds check
}
int main() {
    parse_input("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}
"""
harness = compiler.compile(overflow_code, name="overflow")
print(f"  Compiled: {harness}")
result = subprocess.run(
    [str(harness.binary_path)],
    capture_output=True, text=True, timeout=5
)
print(f"  Exit code : {result.returncode}")
print(f"  ASan output (first 3 lines):")
for line in result.stderr.splitlines()[:3]:
    print(f"    {line}")

# ── Test 4: heap overflow — ASan catches reliably ─────────────────────────────
print("\n=== Test 4: Heap overflow (ASan catches reliably) ===")
heap_overflow = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void parse_input(char *data, size_t len) {
    char *buf = malloc(16);
    memcpy(buf, data, len);   // heap overflow when len > 16
    free(buf);
}
int main() {
    char input[64];
    memset(input, 'A', 64);
    parse_input(input, 64);   // write 64 bytes into 16-byte heap alloc
    return 0;
}
"""
harness = compiler.compile(heap_overflow, name="heap_overflow")
result = subprocess.run(
    [str(harness.binary_path)],
    capture_output=True, text=True, timeout=5
)
print(f"  Exit code : {result.returncode}")
asan_lines = [l for l in result.stderr.splitlines() if l.strip()]
for line in asan_lines[:5]:
    print(f"    {line}")
