"""
LUMENCHAIN — Data layer

SQLite is used so this platform runs with zero external setup (unzip and
run). For a real multi-analyst deployment, swap this for PostgreSQL —
the schema below is plain SQL and translates directly; only the
connection string in `Database.__init__` needs to change.
"""

import sqlite3
import json
import threading
from pathlib import Path

DB_PATH = Path(__file__).parent / "lumenchain.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at REAL NOT NULL,
    status TEXT DEFAULT 'open'
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    source TEXT NOT NULL,
    event_time REAL NOT NULL,
    raw_log TEXT NOT NULL,
    ingested_at REAL NOT NULL,
    block_index INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    log_id INTEGER NOT NULL,
    event_time REAL NOT NULL,
    category TEXT NOT NULL,
    technique TEXT,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    description TEXT NOT NULL,
    detector TEXT NOT NULL,
    FOREIGN KEY(log_id) REFERENCES logs(id)
);

CREATE TABLE IF NOT EXISTS blockchain_ledger (
    idx INTEGER NOT NULL,
    case_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    log_hash TEXT NOT NULL,
    prev_block_hash TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    metadata TEXT,
    PRIMARY KEY (case_id, idx)
);
"""


class Database:
    def __init__(self, path=DB_PATH):
        self.path = str(path)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)

    # ---------- cases ----------
    def create_case(self, case_id, name, created_at):
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO cases (case_id, name, created_at) VALUES (?, ?, ?)",
                (case_id, name, created_at),
            )

    def get_case(self, case_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
            return dict(row) if row else None

    def list_cases(self):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    # ---------- logs ----------
    def insert_log(self, case_id, source, event_time, raw_log: dict, ingested_at, block_index=None):
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO logs (case_id, source, event_time, raw_log, ingested_at, block_index) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, source, event_time, json.dumps(raw_log), ingested_at, block_index),
            )
            return cur.lastrowid

    def get_logs(self, case_id=None):
        with self._connect() as conn:
            if case_id:
                rows = conn.execute(
                    "SELECT * FROM logs WHERE case_id=? ORDER BY event_time ASC", (case_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM logs ORDER BY event_time ASC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["raw_log"] = json.loads(d["raw_log"])
                out.append(d)
            return out

    def get_log_by_id(self, log_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM logs WHERE id=?", (log_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["raw_log"] = json.loads(d["raw_log"])
            return d

    # ---------- alerts ----------
    def insert_alert(self, case_id, log_id, event_time, category, technique, severity, confidence, description, detector):
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO alerts (case_id, log_id, event_time, category, technique, severity, confidence, description, detector) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, log_id, event_time, category, technique, severity, confidence, description, detector),
            )
            return cur.lastrowid

    def get_alerts(self, case_id=None):
        with self._connect() as conn:
            if case_id:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE case_id=? ORDER BY event_time ASC", (case_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM alerts ORDER BY event_time ASC").fetchall()
            return [dict(r) for r in rows]

    # ---------- blockchain ledger ----------
    def get_last_block(self):
        with self._connect() as conn:
	    if case_id:
		row = conn.execute(
		    "SELECT * FROM blockchain_ledger WHERE case_id=? ORDER BY idx DESC LIMIT 1",
		    (case_id,),
		).fetchone()
	    else:
                row = conn.execute(
                    "SELECT * FROM blockchain_ledger ORDER BY idx DESC LIMIT 1"
                ).fetchone()
            return dict(row) if row else None

    def insert_block(self, block: dict):
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO blockchain_ledger (idx, case_id, timestamp, log_hash, prev_block_hash, block_hash, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    block["index"], block["case_id"], block["timestamp"], block["log_hash"],
                    block["prev_block_hash"], block["block_hash"], json.dumps(block.get("metadata", {})),
                ),
            )

    def get_all_blocks(self, case_id=None):
        with self._connect() as conn:
            if case_id:
                rows = conn.execute(
                    "SELECT * FROM blockchain_ledger WHERE case_id=? ORDER BY idx ASC", (case_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM blockchain_ledger ORDER BY idx ASC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["index"] = d.pop("idx")
                d["metadata"] = json.loads(d["metadata"]) if d["metadata"] else {}
                out.append(d)
            return out

    def get_block(self, case_id, index):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM blockchain_ledger WHERE case_id=? AND idx=?", (case_id, index)
            ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["index"] = d.pop("idx")
            return d

    def reset(self):
        """Wipes all data. Used only for demo/testing convenience."""
        with self._lock, self._connect() as conn:
            conn.executescript(
                "DELETE FROM logs; DELETE FROM alerts; DELETE FROM blockchain_ledger; DELETE FROM cases;"
            )
