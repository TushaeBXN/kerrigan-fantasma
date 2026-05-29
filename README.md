# Kerrigan-Fantasma

A custom security LLM built from scratch — custom architecture, custom training pipeline, autonomous fuzzing loop. Built to reason across the hardware-software boundary, write and attack its own code, and get better every run.

> Named after Kerrigan (evolves through adversity, ultimate adaptive weapon) + Fantasma (ghost — elusive, operating in shadows).

## Current Status

| Layer | Status |
|-------|--------|
| Custom RDT architecture (`core/model.py`) | ✅ Built and runs |
| Evolutionary fuzzing loop | ✅ Working — finds real crashes today |
| Mutation fuzzer | ✅ Working — no external deps |
| Creep memory (ChromaDB) | ✅ Working — persists across sessions |
| Overmind safety verifier | ✅ Working |
| Training pipeline (5 tiers) | ✅ Scripts ready |
| Data pipeline (12 languages, kernel, firmware, CVEs) | ✅ Scripts ready |
| smoke training (100 steps) | ✅ Complete — loss 4.62 → 2.14 |
| sft / hardware / instruct training | 🔲 Pending GPU (RunPod) |
| **Current inference backbone** | **Ollama + deepseek-coder:6.7b** |

The fuzzer, compiler, memory, and safety systems work right now with any Ollama model.
The native KerriganCore runs — it needs GPU training hours to replace the Ollama backbone.

---

## What it can do

### Autonomous Vulnerability Research
- Writes its own C exploit harnesses targeting a description you give it
- Fuzzes them with thousands of mutated inputs (bit flips, boundary values, format strings, long strings)
- Finds crashes, classifies them (stack overflow, heap overflow, use-after-free, etc.)
- Analyzes each crash and rewrites the harness to find more — in a loop
- Every crash feeds into persistent memory so future sessions build on past findings

### Hardware-Software Reasoning
- Understands CPU microarchitecture: Spectre, Meltdown, Rowhammer, cache side channels
- Reads and reasons about Linux kernel source, UEFI firmware, TrustZone, SMM handlers
- Knows hardware attack surfaces: DMA, PCIe, Thunderbolt, fault injection, power analysis
- Trained on RISC-V ISA spec, ARM architecture docs, x86 memory maps
- Crosses the boundary: can reason from assembly → OS → application → network in one response

### Code Across All Layers
- **Systems**: C, C++, Rust, Assembly (x86-64, ARM64, RISC-V)
- **Applications**: Python, Go, JavaScript, Java
- **Hardware**: Verilog, VHDL, SystemVerilog
- **Shell/infra**: Bash, scripting
- Understands how code compiles to machine instructions, how the CPU executes it, and where it breaks

### Security Knowledge
- CVE analysis across hardware and software
- Exploit technique library: ROP chains, heap exploitation, kernel exploits, firmware attacks
- Defensive tooling: YARA rules, Sigma detection, memory forensics, hardening
- Reads and interprets ASan/UBSan crash output, stack traces, and sanitizer reports
- Trained on Project Zero research, arxiv cs.CR papers, Exploit-DB entries

### Memory That Grows
- Every session stores findings in a persistent vector database (ChromaDB)
- Future queries automatically retrieve relevant prior findings
- The more you use it, the more it knows about your specific targets

---

## Architecture

This is a **Recurrent-Depth Transformer (RDT)** — not a standard transformer.

```
Input → Prelude (encode once) → [Recurrent Block × N loops] → Coda → Output
                                         ↑________________________↓
                                   same weights, evolving state
```

The model decides how many loops it needs (Adaptive Computation Time). Simple questions: 2-3 loops. Hardware-software reasoning chains: up to 16 loops. It thinks before it answers.

Inside each loop:
- **Multi-head attention** over the full context
- **Mixture of Experts** FFN (64 experts, top-2 routing) — each expert specializes
- **Per-loop LoRA adapters** — each iteration can specialize without growing parameters
- **Frozen encoding re-injection** — prevents forgetting the original question

| Component | Role |
|-----------|------|
| **Kerrigan Core** | Custom RDT — the actual trained model |
| **Abathur** | Routes queries to the optimal expert, evolves from feedback |
| **Overmind** | Safety gate — blocks live weaponization, flags dangerous output |
| **Creep** | ChromaDB vector memory — persists and retrieves findings across sessions |
| **ClosedLoopCompiler** | Compiles LLM-generated C with ASan/UBSan instrumentation |
| **MutationFuzzer** | Generates thousands of mutated inputs, zero external dependencies |
| **CrashTriageEngine** | Deduplicates crashes, classifies by type and exploitability |
| **EvolutionaryLoop** | Wires it all together — the autonomous research loop |

---

## Setup

```bash
./setup.sh
```

Requires: Ollama, Python 3.10+, clang, ~10GB disk.

---

## Usage

```bash
# Interactive chat
python3 kerrigan.py

# Single query
python3 kerrigan.py "Explain tcache poisoning in glibc 2.31"

# Autonomous fuzzing loop
python3 kerrigan.py --evolve "HTTP request parser"
python3 kerrigan.py --evolve "DNS response handler" --iterations 5 --fuzz-inputs 200

# Use a specific model
python3 kerrigan.py --evolve "JPEG parser" --model deepseek-coder:6.7b
```

### Chat commands

| Command | Action |
|---------|--------|
| `/evolve <target>` | Launch evolutionary fuzzing loop interactively |
| `/routing on/off` | Toggle Abathur routing display |
| `/history` | Last 10 routed queries |
| `/memory` | Show Creep memory stats and recent findings |
| `/auth <ip>` | Whitelist a target IP (suppresses Overmind warnings) |
| `/exit` | Quit |

---

## Training

Kerrigan Core is trained in stages, each building on the last:

```
smoke → proof → sft → hardware → instruct
```

| Tier | Steps | Where | Data |
|------|-------|-------|------|
| `smoke` | 100 | Mac | Synthetic — verify architecture |
| `proof` | 1,000 | Mac | Security text — verify loss drops |
| `sft` | 50,000 | RunPod | Combined corpus: code + hw + security |
| `hardware` | 20,000 | RunPod | Kernel + firmware + CPU specs (fine-tune) |
| `instruct` | 10,000 | RunPod | Q&A pairs: Spectre, ROP, UEFI, TrustZone, etc. |

### Training data sources

| Source | What |
|--------|------|
| The Stack (HuggingFace) | C, C++, Rust, Assembly, Python, Go, JS, Java, Verilog, VHDL, SystemVerilog |
| Linux kernel | security/, arch/x86, arch/arm64, drivers/, mm/, net/ |
| EDK2/UEFI | Firmware source: DXE core, SMM core, SecurityPkg |
| Hardware specs | RISC-V ISA manual, ARM CMSIS, x86 memory map, PCIe |
| OpenSSL | Crypto implementation source |
| NVD CVEs | 500+ CVEs across memory corruption, hardware, firmware, kernel |
| Exploit-DB | Exploit titles, types, platforms |
| arxiv cs.CR | Security research papers: side channels, firmware, kernel exploits |
| Project Zero | Full blog post text |

```bash
# Build the full corpus
python3 scripts/prepare_data.py --sources all --stack 200 --cves 500

# Train (RunPod)
python3 scripts/train.py --tier sft      --data data/corpus/combined.txt
python3 scripts/train.py --tier hardware --data data/corpus/hardware.txt --resume checkpoints/kerrigan_sft/final.pt
python3 scripts/train.py --tier instruct --data data/corpus/combined.txt --resume checkpoints/kerrigan_hardware/final.pt
```

---

## Project layout

```
kerrigan-fantasma/
├── kerrigan.py              ← main entry point (chat + evolve)
├── setup.sh                 ← one-time setup
├── core/
│   └── model.py             ← KerriganCore RDT architecture
├── router/
│   └── abathur.py           ← expert routing + evolution tracking
├── verifier/
│   └── overmind.py          ← output safety gating
├── memory/
│   └── creep.py             ← ChromaDB vector memory
├── loop/
│   ├── compiler.py          ← ClosedLoopCompiler (ASan/UBSan)
│   ├── fuzzer.py            ← MutationFuzzer (no external deps)
│   ├── triage.py            ← CrashTriageEngine
│   └── evolution.py         ← EvolutionaryLoop
├── scripts/
│   ├── train.py             ← training (smoke/proof/sft/hardware/instruct)
│   ├── chat_native.py       ← chat with trained checkpoint directly
│   └── prepare_data.py      ← build training corpus from all sources
└── config/
    └── Modelfile            ← Ollama system prompt (fallback)
```

---

## Safety

Overmind gates every output before it reaches you:
- **Hard block**: curl-pipe-to-shell, netcat reverse shells, live payload generators, msfvenom
- **Warning**: raw IPs, `eval()`/`exec()` in generated code, references to live targets
- Educational context (`[EDUCATIONAL]`, "lab", "CTF", "demonstration") bypasses hard blocks but always warns
- All evolutionary loop harnesses run in isolated subprocesses with timeouts
