# Kerrigan-Fantasma

A local, hardware-aware security LLM. Query → route → respond → verify → remember.

```
Query → Creep (context) → Abathur (route) → Model → Overmind (gate) → Creep (store) → Output
```

## Components

| Component | Role |
|-----------|------|
| **Kerrigan Core** | Security-tuned `deepseek-coder:6.7b` via Ollama |
| **Abathur** | Routes queries to the optimal expert model |
| **Overmind** | Gates every output — blocks live weaponization |
| **Creep** | ChromaDB vector memory, persists across sessions |

## Setup

```bash
./setup.sh
```

Requires: Ollama, Python 3.10+, ~10GB disk for models.

## Usage

```bash
# Interactive chat
python3 kerrigan.py

# Single query
python3 kerrigan.py "Explain tcache poisoning"

# Hide routing output
python3 kerrigan.py "What is a ROP chain?" --no-routing
```

## Chat commands

| Command | Action |
|---------|--------|
| `/routing on/off` | Toggle Abathur routing display |
| `/history` | Last 10 routed queries |
| `/memory` | Show Creep memory stats and recent findings |
| `/auth <ip>` | Whitelist a target IP (suppresses Overmind warnings) |
| `/exit` | Quit |

## Expert routing

| Query type | Model |
|------------|-------|
| exploit / rop / shellcode / firmware / cache timing | `kerrigan-fantasma` |
| write code / implement / debug / parse | `deepseek-coder:6.7b` |
| explain / what is / how does / compare | `llama3.2:3b` |
| analyze / malware / forensic / yara / sigma | `mistral-small` |

Abathur evolves routing weights based on Overmind pass/fail outcomes.

## Project layout

```
kerrigan-fantasma/
├── kerrigan.py        ← main entry point
├── setup.sh           ← one-time setup
├── config/
│   └── Modelfile      ← kerrigan-fantasma system prompt
├── router/
│   └── abathur.py     ← expert routing + evolution tracking
├── verifier/
│   └── overmind.py    ← output safety gating
├── memory/
│   └── creep.py       ← ChromaDB vector memory
└── data/
    └── creep_db/      ← persistent memory store (gitignored)
```

## Overmind safety rules

- **Hard block**: curl-pipe-to-shell, netcat reverse shells, live payload generators
- **Warning**: raw IPs, `eval()`/`exec()` in generated code, target system references
- Educational context (`[EDUCATIONAL]`, "demonstration", "lab", "CTF") bypasses hard blocks but always warns

## Adding a new expert

1. Pull the model: `ollama pull <model>`
2. Add an `ExpertProfile` entry in `router/abathur.py`
3. Done — Abathur will route to it automatically
