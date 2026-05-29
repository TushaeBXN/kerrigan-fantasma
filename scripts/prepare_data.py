#!/usr/bin/env python3
"""
Kerrigan-Fantasma data preparation.

Sources (all public, no auth required):
  1. NVD CVE descriptions       — NIST public API
  2. Exploit-DB                 — public CSV + raw exploit text
  3. CTFtime writeups index     — public HTML
  4. Project Zero blog          — public RSS
  5. Local files                — any .txt/.md you drop in data/raw/

Output: data/kerrigan_corpus.txt  (plain text, one document per blank line)
        data/kerrigan_instruct.jsonl  (Q&A pairs for instruct tier)
"""

import re
import sys
import json
import time
import random
import argparse
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from xml.etree import ElementTree

# Legacy Mac: create unverified SSL context for public research sources
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Paths ──────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).parent.parent
RAW_DIR  = ROOT / "data" / "raw"
OUT_TEXT = ROOT / "data" / "kerrigan_corpus.txt"
OUT_INST = ROOT / "data" / "kerrigan_instruct.jsonl"
RAW_DIR.mkdir(parents=True, exist_ok=True)

# ── HTTP helper ────────────────────────────────────────────────────────────────

HEADERS = {"User-Agent": "Mozilla/5.0 (research/kerrigan-fantasma)"}

def fetch(url: str, retries: int = 3, delay: float = 1.5) -> str | None:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=15, context=_SSL_CTX) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
            else:
                print(f"  [WARN] Failed: {url} — {e}")
    return None


def strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ── Source 1: NVD CVE API ─────────────────────────────────────────────────────

def fetch_nvd_cves(max_cves: int = 500) -> list[str]:
    """Pull CVE descriptions from NIST NVD public API (no key needed for basic use)."""
    print(f"\n[NVD] Fetching up to {max_cves} CVEs...")
    docs = []
    results_per_page = 100

    for start in range(0, max_cves, results_per_page):
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage={results_per_page}&startIndex={start}"
            f"&keywordSearch=exploit+vulnerability"
        )
        raw = fetch(url)
        if not raw:
            break

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            break

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            en_desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            if len(en_desc) > 80:
                docs.append(f"CVE: {cve_id}\n{en_desc}")

        print(f"  [{len(docs)} CVEs collected]")
        time.sleep(1.0)  # NVD rate limit: 5 req/30s without key

        if len(docs) >= max_cves:
            break

    print(f"[NVD] Done — {len(docs)} CVE descriptions")
    return docs


# ── Source 2: Exploit-DB CSV ──────────────────────────────────────────────────

def fetch_exploitdb(max_entries: int = 300) -> list[str]:
    """
    Exploit-DB publishes a CSV index. We pull titles + types as training signal.
    Full exploit text requires individual page fetches — we do a sample.
    """
    print(f"\n[ExploitDB] Fetching index CSV...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    raw = fetch(url)
    if not raw:
        print("  [WARN] ExploitDB CSV unavailable")
        return []

    docs = []
    lines = raw.strip().split("\n")[1:]  # skip header
    random.shuffle(lines)

    for line in lines[:max_entries]:
        parts = line.split(",")
        if len(parts) < 5:
            continue
        eid    = parts[0].strip().strip('"')
        desc   = parts[2].strip().strip('"')
        etype  = parts[5].strip().strip('"') if len(parts) > 5 else ""
        eplatform = parts[6].strip().strip('"') if len(parts) > 6 else ""
        if desc and len(desc) > 20:
            docs.append(
                f"Exploit: {desc}\nType: {etype} | Platform: {eplatform}\n"
                f"Source: Exploit-DB #{eid}"
            )

    print(f"[ExploitDB] Done — {len(docs)} exploit entries")
    return docs


# ── Source 3: Project Zero blog (RSS) ─────────────────────────────────────────

def fetch_project_zero() -> list[str]:
    print(f"\n[ProjectZero] Fetching blog RSS...")
    url = "https://googleprojectzero.blogspot.com/feeds/posts/default"
    raw = fetch(url)
    if not raw:
        print("  [WARN] Project Zero RSS unavailable")
        return []

    docs = []
    try:
        root = ElementTree.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("atom:entry", ns):
            title = entry.findtext("atom:title", "", ns)
            content_el = entry.find("atom:content", ns)
            if content_el is None:
                content_el = entry.find("atom:summary", ns)
            if content_el is not None and content_el.text:
                text = strip_html(content_el.text)
                if len(text) > 200:
                    docs.append(f"[Project Zero Research]\nTitle: {title}\n\n{text[:3000]}")
    except ElementTree.ParseError as e:
        print(f"  [WARN] RSS parse error: {e}")

    print(f"[ProjectZero] Done — {len(docs)} posts")
    return docs


# ── Source 4: Local raw files ──────────────────────────────────────────────────

def load_local_files() -> list[str]:
    """Load any .txt or .md files dropped in data/raw/."""
    docs = []
    for path in RAW_DIR.glob("**/*"):
        if path.suffix in (".txt", ".md") and path.is_file():
            text = path.read_text(errors="ignore").strip()
            if len(text) > 100:
                docs.append(f"[Local: {path.name}]\n\n{text}")
                print(f"  Loaded {path.name} ({len(text):,} chars)")
    if docs:
        print(f"[Local] {len(docs)} file(s) loaded from data/raw/")
    return docs


# ── Instruct pairs generator ───────────────────────────────────────────────────

INSTRUCT_TEMPLATES = [
    ("What is {concept}?", "Explain {concept} including how it works and its security implications."),
    ("How does {concept} work?", "Provide a technical explanation of {concept}."),
    ("What are the defenses against {concept}?", "List and explain mitigations for {concept}."),
    ("Give an example of {concept}.", "Describe a concrete scenario involving {concept}."),
]

SECURITY_CONCEPTS = [
    "heap overflow", "stack buffer overflow", "use after free",
    "ROP chain", "ret2libc", "ASLR bypass", "stack canary",
    "Spectre", "Meltdown", "Rowhammer", "cache side channel",
    "UEFI vulnerability", "SMM exploit", "TrustZone bypass",
    "tcache poisoning", "house of force", "format string vulnerability",
    "type confusion", "integer overflow", "race condition",
    "privilege escalation", "kernel exploit", "LPE",
    "DMA attack", "PCIe exploit", "Thunderbolt vulnerability",
    "YARA rule", "Sigma rule", "memory forensics",
    "shellcode injection", "NOP sled", "egg hunting",
]

def generate_instruct_pairs(cve_docs: list[str]) -> list[dict]:
    pairs = []

    # Template-based pairs from concepts
    for concept in SECURITY_CONCEPTS:
        tmpl = random.choice(INSTRUCT_TEMPLATES)
        q = tmpl[0].format(concept=concept)
        instruction = tmpl[1].format(concept=concept)
        pairs.append({
            "instruction": q,
            "context": instruction,
            "response": f"[Kerrigan] Analyzing {concept}...",  # placeholder until trained
        })

    # CVE-based Q&A
    for doc in cve_docs[:100]:
        lines = doc.split("\n")
        cve_id = lines[0].replace("CVE: ", "").strip() if lines else ""
        desc   = lines[1].strip() if len(lines) > 1 else ""
        if cve_id and desc:
            pairs.append({
                "instruction": f"Explain the vulnerability described in {cve_id}.",
                "context": desc,
                "response": f"[Kerrigan] {desc}",
            })

    print(f"[Instruct] Generated {len(pairs)} Q&A pairs")
    return pairs


# ── Main ───────────────────────────────────────────────────────────────────────

def prepare(sources: list[str], max_cves: int, max_exploits: int):
    all_docs: list[str] = []

    if "nvd" in sources:
        all_docs.extend(fetch_nvd_cves(max_cves))

    if "exploitdb" in sources:
        all_docs.extend(fetch_exploitdb(max_exploits))

    if "projectzero" in sources:
        all_docs.extend(fetch_project_zero())

    if "local" in sources:
        all_docs.extend(load_local_files())

    if not all_docs:
        print("\n[WARN] No documents collected. Check network or add files to data/raw/")
        return

    # Shuffle and write corpus
    random.shuffle(all_docs)
    corpus = "\n\n".join(all_docs)
    OUT_TEXT.write_text(corpus)
    print(f"\n[Corpus] {len(all_docs)} documents | {len(corpus):,} chars → {OUT_TEXT}")

    # Write instruct pairs
    cve_docs = [d for d in all_docs if d.startswith("CVE:")]
    pairs = generate_instruct_pairs(cve_docs)
    with OUT_INST.open("w") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"[Instruct] {len(pairs)} pairs → {OUT_INST}")

    print("\n[Done] Ready to train:")
    print(f"  python3 scripts/train.py --tier sft --data {OUT_TEXT}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare Kerrigan-Fantasma training data")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["nvd", "exploitdb", "projectzero", "local", "all"],
        default=["all"],
        help="Data sources to pull from",
    )
    parser.add_argument("--max-cves",     type=int, default=500)
    parser.add_argument("--max-exploits", type=int, default=300)
    args = parser.parse_args()

    sources = (
        ["nvd", "exploitdb", "projectzero", "local"]
        if "all" in args.sources
        else args.sources
    )

    prepare(sources, args.max_cves, args.max_exploits)
