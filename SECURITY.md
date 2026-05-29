# Security Policy

## Supported Versions

This project is under active development. Security fixes apply to the latest commit on `main`.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately to: **brian.thomas.t@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours. If the issue is confirmed, a fix will be prioritized and you will be credited in the release notes (unless you prefer to remain anonymous).

## Scope

In scope:
- Overmind safety bypass — any input that causes Kerrigan to produce live weaponized output
- SecureHarnessRunner escape — any harness that escapes the sandbox and executes on the host
- Prompt injection via Creep memory — malicious content stored in ChromaDB that alters behavior
- Dependency vulnerabilities (torch, chromadb, ollama client)

Out of scope:
- The generated harnesses themselves crashing (that is the intended behavior)
- Social engineering the LLM into producing educational security content
- Theoretical attacks requiring physical access

## Security Design

Kerrigan-Fantasma uses defense-in-depth:

1. **Overmind** — AST-level output gating, blocks live shellcode patterns
2. **SecureHarnessRunner** — 7-layer input validation, rlimits, Docker isolation
3. **Sandboxed execution** — no network, no capabilities, read-only filesystem
4. **Intent** — built for authorized security research, not production attack tooling

## Intended Use

This tool is for **authorized security research and education only**.
Never point the evolutionary fuzzing loop at systems you do not own or have explicit permission to test.
