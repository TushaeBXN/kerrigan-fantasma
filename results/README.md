# Results

Real outputs from Kerrigan-Fantasma's evolutionary fuzzing loop.
All crashes found on local hardware (MacBook Pro, no GPU) using the mutation fuzzer.

## demo_crash_report.json

**Target:** stdin buffer parser — `memcpy()` without bounds check  
**Harness:** LLM-generated C program with stack and heap allocations  
**Inputs tried:** 100 mutations (bit flips, long strings, boundary values, format strings)  

Crashes are classified by type and exploitability. Each unique crash has a stable
dedup ID so the same bug doesn't get reported twice across runs.

## Training status (honest)

| Tier | Status | Notes |
|------|--------|-------|
| smoke | ✅ Complete | 100 steps, loss 4.62 → 2.14 |
| proof | ⏳ Interrupted | Killed by OS — architecture verified, loss dropping |
| sft | 🔲 Pending | Needs RunPod — `train.py --tier sft` ready |
| hardware | 🔲 Pending | Needs RunPod — after sft |
| instruct | 🔲 Pending | Needs RunPod — after hardware |

The evolutionary loop, fuzzer, and memory system work **right now** with any Ollama model.
The native KerriganCore architecture exists and runs — it just needs GPU training to be useful.
