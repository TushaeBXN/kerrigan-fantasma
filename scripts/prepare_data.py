#!/usr/bin/env python3
"""
Kerrigan-Fantasma data preparation — full corpus build.

Sources:
  CODE        — The Stack (HuggingFace): C, C++, Rust, Assembly, Python,
                Go, JavaScript, Java, Verilog, VHDL, SystemVerilog
  KERNEL      — Linux kernel source (security/, drivers/, arch/)
  FIRMWARE    — EDK2/UEFI source (GitHub)
  HARDWARE    — RISC-V ISA spec, ARM/Intel public docs (text)
  SECURITY    — NVD CVEs, Exploit-DB full text, Project Zero, arxiv cs.CR
  CTF         — CTFtime writeup index
  CRYPTO      — OpenSSL + mbedTLS source
  LOCAL       — Any .txt/.c/.cpp/.rs/.py/.md in data/raw/

Output:
  data/corpus/code.txt          — all programming languages
  data/corpus/hardware.txt      — hw specs, kernel, firmware
  data/corpus/security.txt      — CVEs, exploits, research
  data/corpus/combined.txt      — everything merged + shuffled
  data/kerrigan_instruct.jsonl  — Q&A pairs for instruct tier
"""

import re, sys, json, time, random, ssl, argparse, hashlib, subprocess
import urllib.request, urllib.error
from pathlib import Path
from xml.etree import ElementTree

ROOT        = Path(__file__).parent.parent
CORPUS_DIR  = ROOT / "data" / "corpus"
RAW_DIR     = ROOT / "data" / "raw"
OUT_INST    = ROOT / "data" / "kerrigan_instruct.jsonl"
CORPUS_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE

HEADERS = {"User-Agent": "Mozilla/5.0 (research/kerrigan-fantasma)"}

# ── HTTP util ──────────────────────────────────────────────────────────────────

def fetch(url: str, retries=3, delay=1.5) -> str | None:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=20, context=_SSL) as r:
                return r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
            else:
                print(f"  [WARN] {url[:60]} — {e}")
    return None

def strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def dedup(docs: list[str]) -> list[str]:
    seen, out = set(), []
    for d in docs:
        h = hashlib.md5(d[:200].encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            out.append(d)
    return out

# ── SOURCE 1: The Stack via HuggingFace (code) ────────────────────────────────

LANGUAGES = [
    ("c",               500),
    ("cpp",             500),
    ("rust",            400),
    ("assembly",        300),
    ("python",          500),
    ("go",              300),
    ("javascript",      300),
    ("java",            300),
    ("verilog",         200),
    ("vhdl",            150),
    ("systemverilog",   150),
    ("shell",           200),
]

def fetch_the_stack(max_per_lang: int = 200) -> list[str]:
    """
    Pull code from The Stack (HuggingFace bigcode/the-stack-smol).
    Uses streaming so it never downloads the full dataset.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("  [WARN] datasets not installed — skipping The Stack")
        return []

    docs = []
    print(f"\n[TheStack] Pulling code samples...")

    for lang, limit in LANGUAGES:
        actual_limit = min(max_per_lang, limit)
        try:
            ds = load_dataset(
                "bigcode/the-stack-smol",
                data_dir=f"data/{lang}",
                split="train",
                streaming=True,
                trust_remote_code=True,
            )
            count = 0
            for sample in ds:
                content = sample.get("content", "")
                if len(content) > 200 and len(content) < 8000:
                    docs.append(f"[Language: {lang}]\n{content[:4000]}")
                    count += 1
                    if count >= actual_limit:
                        break
            print(f"  {lang:<20} {count} samples")
        except Exception as e:
            print(f"  {lang:<20} SKIP ({e.__class__.__name__})")

    print(f"[TheStack] {len(docs)} total code samples")
    return docs

# ── SOURCE 2: Linux kernel (security-relevant subsystems) ─────────────────────

KERNEL_SUBSYSTEMS = [
    "security",        # LSM, SELinux, AppArmor
    "arch/x86",        # x86 low-level, syscalls, interrupts
    "arch/arm64",      # ARM64 architecture
    "drivers/char",    # character devices (attack surface)
    "net/core",        # networking core
    "mm",              # memory management
    "kernel",          # core kernel
]

def fetch_linux_kernel(max_files: int = 300) -> list[str]:
    """
    Pull Linux kernel .c/.h files via GitHub API (no clone needed).
    Targets security-relevant subsystems.
    """
    print(f"\n[LinuxKernel] Fetching source files...")
    docs = []
    base = "https://api.github.com/repos/torvalds/linux/contents"

    def get_files(path: str, depth: int = 0) -> list[str]:
        if depth > 2 or len(docs) >= max_files:
            return []
        raw = fetch(f"{base}/{path}")
        if not raw:
            return []
        try:
            items = json.loads(raw)
        except Exception:
            return []
        files = []
        for item in items:
            if len(docs) >= max_files:
                break
            if item["type"] == "file" and item["name"].endswith((".c", ".h")):
                files.append(item["download_url"])
            elif item["type"] == "dir" and depth < 2:
                files.extend(get_files(item["path"], depth + 1))
        return files

    for subsystem in KERNEL_SUBSYSTEMS:
        if len(docs) >= max_files:
            break
        urls = get_files(subsystem)
        for url in urls[:max_files // len(KERNEL_SUBSYSTEMS)]:
            if len(docs) >= max_files:
                break
            content = fetch(url)
            if content and len(content) > 100:
                fname = url.split("/")[-1]
                docs.append(f"[Linux kernel: {subsystem}/{fname}]\n{content[:6000]}")
        print(f"  {subsystem:<25} {len(docs)} total so far")
        time.sleep(0.5)  # GitHub rate limit

    print(f"[LinuxKernel] {len(docs)} source files")
    return docs

# ── SOURCE 3: EDK2 / UEFI firmware source ─────────────────────────────────────

EDK2_PATHS = [
    "MdeModulePkg/Core/Dxe",
    "MdeModulePkg/Core/PiSmmCore",
    "OvmfPkg",
    "SecurityPkg",
    "MdePkg/Library",
]

def fetch_edk2(max_files: int = 100) -> list[str]:
    print(f"\n[EDK2/UEFI] Fetching firmware source...")
    docs = []
    base = "https://api.github.com/repos/tianocore/edk2/contents"

    for path in EDK2_PATHS:
        if len(docs) >= max_files:
            break
        raw = fetch(f"{base}/{path}")
        if not raw:
            continue
        try:
            items = json.loads(raw)
        except Exception:
            continue
        for item in items:
            if len(docs) >= max_files:
                break
            if item["type"] == "file" and item["name"].endswith(".c"):
                content = fetch(item["download_url"])
                if content and len(content) > 200:
                    docs.append(f"[UEFI/EDK2: {path}/{item['name']}]\n{content[:5000]}")
        time.sleep(0.3)

    print(f"[EDK2/UEFI] {len(docs)} firmware files")
    return docs

# ── SOURCE 4: Hardware specs (public text) ────────────────────────────────────

HW_SPECS = [
    # RISC-V ISA spec — public GitHub
    ("https://raw.githubusercontent.com/riscv/riscv-isa-manual/main/src/intro.adoc",
     "RISC-V ISA: Introduction"),
    ("https://raw.githubusercontent.com/riscv/riscv-isa-manual/main/src/rv32.adoc",
     "RISC-V ISA: RV32I Base Integer"),
    ("https://raw.githubusercontent.com/riscv/riscv-privileged/main/src/intro.adoc",
     "RISC-V Privileged: Introduction"),
    # ARM Cortex-M docs (public)
    ("https://raw.githubusercontent.com/ARM-software/CMSIS_6/main/CMSIS/Core/Include/core_cm4.h",
     "ARM Cortex-M4 CMSIS Core"),
    # x86 reference (OSDev wiki — plain text)
    ("https://wiki.osdev.org/X86_memory_map",
     "x86 Memory Map"),
    # PCIe overview
    ("https://raw.githubusercontent.com/enjoy-digital/litepcie/master/README",
     "PCIe Overview"),
]

def fetch_hw_specs() -> list[str]:
    print(f"\n[HWSpecs] Fetching hardware specifications...")
    docs = []
    for url, label in HW_SPECS:
        content = fetch(url)
        if content and len(content) > 200:
            docs.append(f"[Hardware Spec: {label}]\n{content[:8000]}")
            print(f"  OK: {label}")
        else:
            print(f"  SKIP: {label}")
        time.sleep(0.3)
    print(f"[HWSpecs] {len(docs)} spec documents")
    return docs

# ── SOURCE 5: Crypto library source (OpenSSL) ─────────────────────────────────

OPENSSL_FILES = [
    "ssl/ssl_lib.c", "ssl/tls13_enc.c", "ssl/record/tls_record.c",
    "crypto/aes/aes_core.c", "crypto/rsa/rsa_ossl.c",
    "crypto/ec/ec_key.c", "crypto/evp/evp_enc.c",
]

def fetch_openssl(max_files: int = 20) -> list[str]:
    print(f"\n[OpenSSL] Fetching crypto source...")
    docs = []
    base = "https://raw.githubusercontent.com/openssl/openssl/master"
    for fpath in OPENSSL_FILES[:max_files]:
        content = fetch(f"{base}/{fpath}")
        if content and len(content) > 200:
            docs.append(f"[OpenSSL: {fpath}]\n{content[:6000]}")
    print(f"[OpenSSL] {len(docs)} files")
    return docs

# ── SOURCE 6: NVD CVEs (security) ─────────────────────────────────────────────

def fetch_nvd_cves(max_cves: int = 500) -> list[str]:
    print(f"\n[NVD] Fetching CVEs (max={max_cves})...")
    docs = []
    keywords = ["memory corruption", "buffer overflow", "use after free",
                "privilege escalation", "firmware", "kernel exploit",
                "hardware vulnerability", "side channel"]

    for kw in keywords:
        if len(docs) >= max_cves:
            break
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?resultsPerPage=100&startIndex=0"
            f"&keywordSearch={urllib.parse.quote(kw)}"
        )
        raw = fetch(url)
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            if len(en) > 80:
                docs.append(f"CVE: {cve_id}\nKeyword: {kw}\n{en}")
        print(f"  '{kw}': {len(docs)} total")
        time.sleep(1.2)

    docs = dedup(docs)
    print(f"[NVD] {len(docs)} unique CVEs")
    return docs

# need urllib.parse for the above
import urllib.parse

# ── SOURCE 7: Exploit-DB full text ────────────────────────────────────────────

def fetch_exploitdb(max_entries: int = 200) -> list[str]:
    print(f"\n[ExploitDB] Fetching exploit entries...")
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    raw = fetch(url)
    if not raw:
        return []

    docs = []
    lines = raw.strip().split("\n")[1:]
    random.shuffle(lines)

    for line in lines[:max_entries * 2]:
        parts = line.split(",")
        if len(parts) < 5:
            continue
        eid    = parts[0].strip().strip('"')
        desc   = parts[2].strip().strip('"')
        etype  = parts[5].strip().strip('"') if len(parts) > 5 else ""
        eplatf = parts[6].strip().strip('"') if len(parts) > 6 else ""
        if len(desc) > 20:
            docs.append(f"Exploit-DB #{eid}\nTitle: {desc}\nType: {etype} | Platform: {eplatf}")
            if len(docs) >= max_entries:
                break

    print(f"[ExploitDB] {len(docs)} entries")
    return docs

# ── SOURCE 8: arxiv cs.CR (security research papers) ─────────────────────────

def fetch_arxiv_security(max_papers: int = 100) -> list[str]:
    print(f"\n[arxiv] Fetching cs.CR security papers...")
    queries = [
        "hardware+vulnerability+exploit",
        "memory+corruption+exploitation",
        "side+channel+attack+cache",
        "firmware+security+vulnerability",
        "kernel+exploit+privilege+escalation",
    ]
    docs = []

    for q in queries:
        if len(docs) >= max_papers:
            break
        url = (
            f"https://export.arxiv.org/api/query"
            f"?search_query=cat:cs.CR+AND+{q}"
            f"&max_results=20&sortBy=submittedDate&sortOrder=descending"
        )
        raw = fetch(url)
        if not raw:
            continue
        try:
            root = ElementTree.fromstring(raw)
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.findall("atom:entry", ns):
                title   = entry.findtext("atom:title", "", ns).strip()
                summary = entry.findtext("atom:summary", "", ns).strip()
                if len(summary) > 100:
                    docs.append(f"[Security Research]\nTitle: {title}\n\n{summary[:2000]}")
        except Exception as e:
            print(f"  WARN: {e}")
        time.sleep(0.5)

    docs = dedup(docs)
    print(f"[arxiv] {len(docs)} papers")
    return docs

# ── SOURCE 9: Project Zero blog ───────────────────────────────────────────────

def fetch_project_zero() -> list[str]:
    print(f"\n[ProjectZero] Fetching blog posts...")
    url = "https://googleprojectzero.blogspot.com/feeds/posts/default"
    raw = fetch(url)
    if not raw:
        return []
    docs = []
    try:
        root = ElementTree.fromstring(raw)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.findall("atom:entry", ns):
            title = entry.findtext("atom:title", "", ns)
            el = entry.find("atom:content", ns) or entry.find("atom:summary", ns)
            if el is not None and el.text:
                text = strip_html(el.text)
                if len(text) > 200:
                    docs.append(f"[Project Zero]\nTitle: {title}\n\n{text[:4000]}")
    except Exception:
        pass
    print(f"[ProjectZero] {len(docs)} posts")
    return docs

# ── SOURCE 10: Local files ────────────────────────────────────────────────────

def load_local() -> list[str]:
    docs = []
    exts = (".txt", ".md", ".c", ".cpp", ".rs", ".py", ".go", ".v", ".sv")
    for path in RAW_DIR.glob("**/*"):
        if path.suffix in exts and path.is_file():
            text = path.read_text(errors="ignore").strip()
            if len(text) > 100:
                docs.append(f"[Local: {path.name}]\n\n{text}")
                print(f"  Loaded: {path.name} ({len(text):,} chars)")
    if docs:
        print(f"[Local] {len(docs)} files")
    return docs

# ── Instruct pair generation ───────────────────────────────────────────────────

HW_SW_CONCEPTS = [
    # Hardware attacks
    "Spectre variant 1 bounds check bypass",
    "Meltdown kernel memory leak via speculative execution",
    "Rowhammer bit flip DRAM attack",
    "cache side channel Prime+Probe attack",
    "Flush+Reload cache timing attack",
    "DMA attack via PCIe device",
    "Thunderbolt DMA exploit",
    "fault injection glitching attack",
    "power analysis side channel",
    # Hardware-software boundary
    "UEFI SMM handler vulnerability",
    "TrustZone secure world exploit",
    "hypervisor escape attack",
    "CPU microcode vulnerability",
    "branch predictor manipulation",
    "CPU register state leakage",
    # Kernel/firmware
    "Linux kernel use-after-free",
    "Windows kernel pool overflow",
    "driver privilege escalation",
    "ARM TrustZone memory isolation bypass",
    "IOMMU bypass DMA attack",
    # Code exploitation
    "heap feng shui exploitation technique",
    "tcache poisoning glibc 2.31",
    "ROP chain stack pivot technique",
    "ret2libc ASLR bypass",
    "format string arbitrary write",
    "type confusion C++ vtable exploit",
    "integer overflow to heap overflow",
    "race condition TOCTOU exploit",
    # Languages + security
    "Rust memory safety vs C buffer overflow",
    "unsafe Rust code vulnerability",
    "Go slice bounds check bypass",
    "JavaScript JIT spray technique",
    "Java deserialization exploit",
    "Verilog timing vulnerability RTL",
    "SystemVerilog formal verification security",
    # Defenses
    "Control Flow Integrity CFI bypass",
    "Address Space Layout Randomization ASLR",
    "stack canary bypass techniques",
    "Data Execution Prevention DEP NX bypass",
    "Pointer Authentication Code PAC ARM",
    "Memory Tagging Extension MTE ARM",
    "Shadow Stack Intel CET",
]

TEMPLATES = [
    ("Explain {concept} technically.",
     "Provide a deep technical explanation of {concept} including the mechanism, affected systems, and real-world impact."),
    ("How does {concept} work at the hardware level?",
     "Describe the hardware and microarchitectural mechanisms behind {concept}."),
    ("Write a proof-of-concept demonstrating {concept}.",
     "Provide educational pseudocode or C code demonstrating {concept} in a lab environment."),
    ("What are the defenses against {concept}?",
     "List hardware and software mitigations for {concept} with implementation details."),
    ("How does {concept} cross the hardware-software boundary?",
     "Explain how {concept} exploits the interaction between hardware behavior and software assumptions."),
]

def generate_instruct_pairs(cve_docs: list[str]) -> list[dict]:
    pairs = []
    for concept in HW_SW_CONCEPTS:
        tmpl = random.choice(TEMPLATES)
        pairs.append({
            "instruction": tmpl[0].format(concept=concept),
            "context":     tmpl[1].format(concept=concept),
            "domain":      "hardware_software_security",
        })
    for doc in cve_docs[:200]:
        lines = doc.split("\n")
        cve_id = lines[0].replace("CVE: ", "").strip()
        desc   = lines[2].strip() if len(lines) > 2 else ""
        if cve_id and len(desc) > 50:
            pairs.append({
                "instruction": f"Analyze the vulnerability in {cve_id}.",
                "context":     desc,
                "domain":      "cve_analysis",
            })
    random.shuffle(pairs)
    print(f"[Instruct] {len(pairs)} Q&A pairs")
    return pairs

# ── Write corpus files ─────────────────────────────────────────────────────────

def write_corpus(name: str, docs: list[str]) -> Path:
    if not docs:
        return None
    path = CORPUS_DIR / f"{name}.txt"
    random.shuffle(docs)
    path.write_text("\n\n".join(docs))
    size_mb = path.stat().st_size / 1_000_000
    print(f"  → {path.name}: {len(docs)} docs | {size_mb:.1f} MB")
    return path

# ── Main ───────────────────────────────────────────────────────────────────────

ALL_SOURCES = ["code", "kernel", "firmware", "hardware", "security", "crypto", "local"]

def prepare(sources: list[str], limits: dict):
    code_docs, hw_docs, sec_docs = [], [], []

    if "code" in sources:
        code_docs.extend(fetch_the_stack(limits.get("stack", 100)))

    if "kernel" in sources:
        hw_docs.extend(fetch_linux_kernel(limits.get("kernel", 200)))

    if "firmware" in sources:
        hw_docs.extend(fetch_edk2(limits.get("firmware", 80)))

    if "hardware" in sources:
        hw_docs.extend(fetch_hw_specs())

    if "crypto" in sources:
        code_docs.extend(fetch_openssl(limits.get("openssl", 15)))

    if "security" in sources:
        cves = fetch_nvd_cves(limits.get("cves", 500))
        sec_docs.extend(cves)
        sec_docs.extend(fetch_exploitdb(limits.get("exploits", 200)))
        sec_docs.extend(fetch_arxiv_security(limits.get("arxiv", 80)))
        sec_docs.extend(fetch_project_zero())

    if "local" in sources:
        local = load_local()
        code_docs.extend(local)

    # Dedup each bucket
    code_docs = dedup(code_docs)
    hw_docs   = dedup(hw_docs)
    sec_docs  = dedup(sec_docs)

    print(f"\n{'='*50}")
    print(f"  CODE     : {len(code_docs)} docs")
    print(f"  HARDWARE : {len(hw_docs)} docs")
    print(f"  SECURITY : {len(sec_docs)} docs")
    print(f"{'='*50}\n")

    write_corpus("code",     code_docs)
    write_corpus("hardware", hw_docs)
    write_corpus("security", sec_docs)

    # Combined corpus — all three merged
    all_docs = code_docs + hw_docs + sec_docs
    random.shuffle(all_docs)
    combined_path = write_corpus("combined", all_docs)

    # Instruct pairs
    cve_docs = [d for d in sec_docs if d.startswith("CVE:")]
    pairs = generate_instruct_pairs(cve_docs)
    with OUT_INST.open("w") as f:
        for p in pairs:
            f.write(json.dumps(p) + "\n")
    print(f"[Instruct] → {OUT_INST.name}: {len(pairs)} pairs")

    print(f"\n[Done] Training data ready.")
    print(f"  Pretraining : python3 scripts/train.py --tier sft      --data {CORPUS_DIR}/combined.txt")
    print(f"  HW focused  : python3 scripts/train.py --tier hardware --data {CORPUS_DIR}/hardware.txt")
    print(f"  Instruct    : python3 scripts/train.py --tier instruct --data {CORPUS_DIR}/combined.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Kerrigan-Fantasma training corpus")
    parser.add_argument("--sources", nargs="+",
                        choices=ALL_SOURCES + ["all"], default=["all"])
    parser.add_argument("--stack",    type=int, default=100,  help="Code samples per language")
    parser.add_argument("--kernel",   type=int, default=200,  help="Linux kernel files")
    parser.add_argument("--firmware", type=int, default=80,   help="EDK2 files")
    parser.add_argument("--cves",     type=int, default=500,  help="NVD CVEs")
    parser.add_argument("--exploits", type=int, default=200,  help="Exploit-DB entries")
    parser.add_argument("--arxiv",    type=int, default=80,   help="arxiv papers")
    parser.add_argument("--openssl",  type=int, default=15,   help="OpenSSL source files")
    args = parser.parse_args()

    sources = ALL_SOURCES if "all" in args.sources else args.sources
    limits  = {
        "stack":    args.stack,
        "kernel":   args.kernel,
        "firmware": args.firmware,
        "cves":     args.cves,
        "exploits": args.exploits,
        "arxiv":    args.arxiv,
        "openssl":  args.openssl,
    }
    prepare(sources, limits)
