"""
Creep — shared knowledge memory system.
Stores findings, retrieves relevant context before each query,
and spreads knowledge across the swarm.
Persists to disk across sessions.
"""

import json
import hashlib
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional
import chromadb
from chromadb.utils import embedding_functions


CREEP_DIR = Path(__file__).parent.parent / "data" / "creep_db"
CREEP_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = CREEP_DIR / "findings.jsonl"


@dataclass
class Finding:
    content: str
    query: str
    expert: str
    tags: list[str]
    timestamp: float
    id: str = ""

    def __post_init__(self):
        if not self.id:
            raw = f"{self.query}{self.timestamp}"
            self.id = hashlib.md5(raw.encode()).hexdigest()[:12]


class Creep:
    """
    Persistent vector memory. Each finding is stored with its embedding
    so future queries can retrieve relevant prior knowledge.
    """

    def __init__(self):
        self._client = chromadb.PersistentClient(path=str(CREEP_DIR))
        self._embed_fn = embedding_functions.DefaultEmbeddingFunction()
        self._collection = self._client.get_or_create_collection(
            name="kerrigan_creep",
            embedding_function=self._embed_fn,
            metadata={"hnsw:space": "cosine"},
        )

    def absorb(self, finding: Finding) -> str:
        """Store a new finding. Returns its ID."""
        self._collection.add(
            ids=[finding.id],
            documents=[finding.content],
            metadatas=[{
                "query": finding.query[:200],
                "expert": finding.expert,
                "tags": ",".join(finding.tags),
                "timestamp": finding.timestamp,
            }],
        )
        # Also append to JSONL log for human readability
        with LOG_FILE.open("a") as f:
            f.write(json.dumps(asdict(finding)) + "\n")

        return finding.id

    def recall(self, query: str, n: int = 3) -> list[dict]:
        """
        Retrieve the n most relevant past findings for a query.
        Returns list of {content, expert, tags, similarity}.
        """
        count = self._collection.count()
        if count == 0:
            return []

        results = self._collection.query(
            query_texts=[query],
            n_results=min(n, count),
            include=["documents", "metadatas", "distances"],
        )

        findings = []
        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results["distances"][0]

        for doc, meta, dist in zip(docs, metas, distances):
            similarity = 1 - dist  # cosine distance → similarity
            if similarity > 0.3:   # threshold — skip weak matches
                findings.append({
                    "content": doc,
                    "expert": meta["expert"],
                    "tags": meta["tags"].split(",") if meta["tags"] else [],
                    "similarity": round(similarity, 3),
                })

        return findings

    def build_context(self, query: str) -> str:
        """
        Returns a context block to prepend to the query if relevant
        prior knowledge exists.
        """
        findings = self.recall(query)
        if not findings:
            return ""

        lines = ["[Creep Memory — relevant prior findings]"]
        for f in findings:
            lines.append(f"  [{f['expert']}] (similarity={f['similarity']}) {f['content'][:300]}")
        lines.append("")
        return "\n".join(lines)

    def count(self) -> int:
        return self._collection.count()

    def tag_response(self, query: str, response: str, expert: str) -> Finding:
        """Auto-tag a response and absorb it into the Creep."""
        tags = self._extract_tags(query + " " + response)
        finding = Finding(
            content=response[:1000],  # store first 1000 chars
            query=query[:200],
            expert=expert,
            tags=tags,
            timestamp=time.time(),
        )
        self.absorb(finding)
        return finding

    def _extract_tags(self, text: str) -> list[str]:
        text_lower = text.lower()
        tag_map = {
            "rop": ["rop", "return oriented"],
            "heap": ["heap overflow", "heap spray", "use after free", "uaf"],
            "kernel": ["kernel exploit", "privilege escalation", "lpe"],
            "firmware": ["uefi", "smm", "firmware", "trustzone"],
            "cache": ["cache timing", "spectre", "flush+reload", "prime+probe"],
            "malware": ["malware", "shellcode", "payload", "c2", "beacon"],
            "forensics": ["forensic", "volatility", "memory dump", "artifact"],
            "yara": ["yara", "sigma", "detection rule"],
        }
        found = []
        for tag, keywords in tag_map.items():
            if any(kw in text_lower for kw in keywords):
                found.append(tag)
        return found
