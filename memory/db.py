"""
Kerrigan-Fantasma MySQL Backend
Writes all sessions, crashes, memories, instruct pairs, and corpus
metadata to kerrigan_db so you can query and browse in Querious.

Tables created automatically on first connect:
  sessions       — every evolution loop run
  crashes        — every crash found (type, exploitability, input, signal)
  memories       — everything Creep has learned across sessions
  instruct_pairs — Q&A training pairs
  corpus_sources — what data was pulled for training
"""

import json
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional
import mysql.connector
from mysql.connector import Error


# ── Connection ─────────────────────────────────────────────────────────────────

class KerriganDB:
    """
    MySQL backend for Kerrigan-Fantasma.
    All methods are safe to call even if MySQL is unavailable —
    they log a warning and continue rather than crashing the main loop.
    """

    def __init__(
        self,
        host:     str = "127.0.0.1",
        port:     int = 3306,
        user:     str = "root",
        password: str = "",
        database: str = "kerrigan_db",
    ):
        self.config = dict(host=host, port=port, user=user,
                           password=password, database=database)
        self._conn = None
        self._connect()
        if self._conn:
            self._create_tables()

    def _connect(self):
        try:
            self._conn = mysql.connector.connect(**self.config)
            print(f"[KerriganDB] Connected to MySQL — {self.config['database']} @ {self.config['host']}")
        except Error as e:
            print(f"[KerriganDB] MySQL unavailable — running without database: {e}")
            self._conn = None

    def _cursor(self):
        try:
            if self._conn and not self._conn.is_connected():
                self._conn.reconnect(attempts=3, delay=1)
            return self._conn.cursor()
        except Exception:
            return None

    def _exec(self, sql: str, values: tuple = None, many: bool = False) -> bool:
        cur = self._cursor()
        if not cur:
            return False
        try:
            if many and values:
                cur.executemany(sql, values)
            elif values:
                cur.execute(sql, values)
            else:
                cur.execute(sql)
            self._conn.commit()
            return True
        except Error as e:
            print(f"[KerriganDB] Query error: {e}")
            return False
        finally:
            cur.close()

    # ── Schema ─────────────────────────────────────────────────────────────────

    def _create_tables(self):
        tables = [
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                session_id    VARCHAR(32)  UNIQUE NOT NULL,
                target        TEXT         NOT NULL,
                iterations    INT          DEFAULT 0,
                total_crashes INT          DEFAULT 0,
                unique_crashes INT         DEFAULT 0,
                high_exploit  INT          DEFAULT 0,
                duration_sec  FLOAT        DEFAULT 0,
                started_at    DATETIME     NOT NULL,
                completed_at  DATETIME,
                status        VARCHAR(20)  DEFAULT 'running',
                INDEX idx_started (started_at)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS crashes (
                id            INT AUTO_INCREMENT PRIMARY KEY,
                crash_id      VARCHAR(32)  NOT NULL,
                session_id    VARCHAR(32),
                crash_type    VARCHAR(50)  NOT NULL,
                exploitability VARCHAR(20) NOT NULL,
                crash_signal  VARCHAR(20),
                exit_code     INT,
                input_hex     TEXT,
                input_len     INT,
                ubsan_message TEXT,
                binary_name   VARCHAR(255),
                raw_output    TEXT,
                found_at      DATETIME     NOT NULL,
                UNIQUE KEY unique_crash (crash_id),
                INDEX idx_type (crash_type),
                INDEX idx_exploit (exploitability),
                INDEX idx_session (session_id),
                INDEX idx_found (found_at)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS memories (
                id         INT AUTO_INCREMENT PRIMARY KEY,
                memory_id  VARCHAR(32)  UNIQUE NOT NULL,
                content    TEXT         NOT NULL,
                query      TEXT,
                expert     VARCHAR(50),
                tags       VARCHAR(255),
                created_at DATETIME     NOT NULL,
                INDEX idx_expert (expert),
                INDEX idx_created (created_at),
                FULLTEXT idx_content (content)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS instruct_pairs (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                pair_id     VARCHAR(32)  UNIQUE NOT NULL,
                instruction TEXT         NOT NULL,
                context     TEXT,
                response    TEXT,
                domain      VARCHAR(100),
                created_at  DATETIME     NOT NULL,
                INDEX idx_domain (domain),
                FULLTEXT idx_instruction (instruction)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS corpus_sources (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                source_name VARCHAR(100) NOT NULL,
                doc_count   INT          DEFAULT 0,
                size_bytes  BIGINT       DEFAULT 0,
                pulled_at   DATETIME     NOT NULL,
                corpus_file VARCHAR(255),
                INDEX idx_source (source_name),
                INDEX idx_pulled (pulled_at)
            )
            """,
        ]
        for sql in tables:
            self._exec(sql)
        print("[KerriganDB] Schema ready — 5 tables")

    # ── Sessions ───────────────────────────────────────────────────────────────

    def start_session(self, target: str) -> str:
        session_id = hashlib.md5(f"{target}{time.time()}".encode()).hexdigest()[:16]
        self._exec(
            """INSERT INTO sessions (session_id, target, started_at, status)
               VALUES (%s, %s, %s, 'running')
               ON DUPLICATE KEY UPDATE status='running'""",
            (session_id, target[:500], datetime.now()),
        )
        return session_id

    def complete_session(self, session_id: str, iterations: int,
                         total_crashes: int, unique_crashes: int,
                         high_exploit: int, duration_sec: float):
        self._exec(
            """UPDATE sessions SET
               iterations=%s, total_crashes=%s, unique_crashes=%s,
               high_exploit=%s, duration_sec=%s,
               completed_at=%s, status='completed'
               WHERE session_id=%s""",
            (iterations, total_crashes, unique_crashes,
             high_exploit, duration_sec, datetime.now(), session_id),
        )

    # ── Crashes ────────────────────────────────────────────────────────────────

    def log_crash(self, report, session_id: str = None):
        """Log a CrashReport from loop/triage.py to MySQL."""
        self._exec(
            """INSERT INTO crashes
               (crash_id, session_id, crash_type, exploitability, crash_signal,
                exit_code, input_hex, input_len, ubsan_message, binary_name,
                raw_output, found_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON DUPLICATE KEY UPDATE session_id=VALUES(session_id)""",
            (
                report.crash_id,
                session_id,
                report.crash_type.value,
                report.exploitability,
                report.signal,
                report.exit_code,
                report.input_sample.hex(),
                len(report.input_sample),
                report.ubsan_message or "",
                report.binary_path,
                (report.raw_output or "")[:4000],
                datetime.fromtimestamp(report.timestamp),
            ),
        )

    # ── Memories ───────────────────────────────────────────────────────────────

    def log_memory(self, finding):
        """Log a Creep Finding to MySQL."""
        self._exec(
            """INSERT INTO memories
               (memory_id, content, query, expert, tags, created_at)
               VALUES (%s,%s,%s,%s,%s,%s)
               ON DUPLICATE KEY UPDATE content=VALUES(content)""",
            (
                finding.id,
                finding.content[:4000],
                (finding.query or "")[:500],
                finding.expert,
                ",".join(finding.tags),
                datetime.fromtimestamp(finding.timestamp),
            ),
        )

    # ── Instruct pairs ─────────────────────────────────────────────────────────

    def log_instruct_pairs(self, pairs: list[dict]):
        """Bulk-insert instruct Q&A pairs."""
        rows = []
        for p in pairs:
            pair_id = hashlib.md5(p.get("instruction","").encode()).hexdigest()[:16]
            rows.append((
                pair_id,
                p.get("instruction","")[:1000],
                p.get("context","")[:2000],
                p.get("response","")[:2000],
                p.get("domain",""),
                datetime.now(),
            ))
        if rows:
            self._exec(
                """INSERT INTO instruct_pairs
                   (pair_id, instruction, context, response, domain, created_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON DUPLICATE KEY UPDATE instruction=VALUES(instruction)""",
                rows, many=True,
            )
            print(f"[KerriganDB] Logged {len(rows)} instruct pairs")

    # ── Corpus sources ─────────────────────────────────────────────────────────

    def log_corpus_source(self, source_name: str, doc_count: int,
                          corpus_file: str = ""):
        size = Path(corpus_file).stat().st_size if corpus_file and Path(corpus_file).exists() else 0
        self._exec(
            """INSERT INTO corpus_sources
               (source_name, doc_count, size_bytes, pulled_at, corpus_file)
               VALUES (%s,%s,%s,%s,%s)""",
            (source_name, doc_count, size, datetime.now(), corpus_file),
        )

    # ── Quick stats ────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        cur = self._cursor()
        if not cur:
            return {}
        out = {}
        try:
            for table in ("sessions", "crashes", "memories", "instruct_pairs"):
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                out[table] = cur.fetchone()[0]
            cur.execute(
                "SELECT crash_type, COUNT(*) as n FROM crashes "
                "GROUP BY crash_type ORDER BY n DESC"
            )
            out["crashes_by_type"] = {r[0]: r[1] for r in cur.fetchall()}
            cur.execute(
                "SELECT exploitability, COUNT(*) as n FROM crashes "
                "GROUP BY exploitability"
            )
            out["crashes_by_exploit"] = {r[0]: r[1] for r in cur.fetchall()}
        finally:
            cur.close()
        return out

    def close(self):
        if self._conn and self._conn.is_connected():
            self._conn.close()
