"""SQLite persistence for runs, flow events, classifications, and contracts."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

from .aggregator import AggregatedFlow
from .parser import FlowEvent


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    window_start TEXT,
    window_end TEXT,
    status TEXT NOT NULL DEFAULT 'in_progress'
);

CREATE TABLE IF NOT EXISTS flow_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts TEXT,
    sgt INTEGER,
    dgt INTEGER,
    protocol TEXT,
    src_port TEXT,
    dst_port TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    hits INTEGER,
    sgacl_name TEXT,
    observed_action TEXT
);

CREATE TABLE IF NOT EXISTS flow_classifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    sgt INTEGER, dgt INTEGER, protocol TEXT,
    src_port TEXT, dst_port TEXT,
    category TEXT NOT NULL,
    rationale TEXT,
    total_hits INTEGER
);

CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    src_sgt INTEGER, dst_sgt INTEGER,
    src_sgt_name TEXT, dst_sgt_name TEXT,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contract_aces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    protocol TEXT, src_port TEXT, dst_port TEXT,
    action TEXT NOT NULL,
    source_category TEXT
);
"""


def init_db(path: str | Path) -> None:
    with _connect(path) as conn:
        conn.executescript(SCHEMA)


@contextmanager
def _connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def create_run(path: str | Path, source_type: str, start: datetime | None, end: datetime | None) -> int:
    with _connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO runs (started_at, source_type, window_start, window_end) VALUES (?, ?, ?, ?)",
            (
                datetime.utcnow().isoformat(),
                source_type,
                start.isoformat() if start else None,
                end.isoformat() if end else None,
            ),
        )
        return int(cur.lastrowid)


def set_run_status(path: str | Path, run_id: int, status: str) -> None:
    with _connect(path) as conn:
        conn.execute("UPDATE runs SET status = ? WHERE id = ?", (status, run_id))


def insert_flow_events(path: str | Path, run_id: int, events: Iterable[FlowEvent]) -> int:
    rows = [
        (
            run_id,
            e.ts.isoformat() if e.ts else None,
            e.sgt, e.dgt, e.protocol, e.src_port, e.dst_port,
            e.src_ip, e.dst_ip, e.hits, e.sgacl_name, e.observed_action,
        )
        for e in events
    ]
    if not rows:
        return 0
    with _connect(path) as conn:
        conn.executemany(
            "INSERT INTO flow_events (run_id, ts, sgt, dgt, protocol, src_port, dst_port, "
            "src_ip, dst_ip, hits, sgacl_name, observed_action) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def insert_classifications(
    path: str | Path,
    run_id: int,
    classified: list[tuple[AggregatedFlow, str, str]],
) -> None:
    rows = [
        (
            run_id, flow.key.sgt, flow.key.dgt, flow.key.protocol,
            flow.key.src_port, flow.key.dst_port,
            category, rationale, flow.total_hits,
        )
        for flow, category, rationale in classified
    ]
    if not rows:
        return
    with _connect(path) as conn:
        conn.executemany(
            "INSERT INTO flow_classifications (run_id, sgt, dgt, protocol, src_port, dst_port, "
            "category, rationale, total_hits) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )


def insert_contracts(path: str | Path, run_id: int, contracts: list[dict]) -> None:
    with _connect(path) as conn:
        for contract in contracts:
            cur = conn.execute(
                "INSERT INTO contracts (run_id, src_sgt, dst_sgt, src_sgt_name, dst_sgt_name, name) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    contract["src_sgt"], contract["dst_sgt"],
                    contract["src_sgt_name"], contract["dst_sgt_name"],
                    contract["name"],
                ),
            )
            contract_id = cur.lastrowid
            ace_rows = [
                (contract_id, ace["protocol"], ace["src_port"], ace["dst_port"],
                 ace["action"], ace.get("source_category"))
                for ace in contract["aces"]
            ]
            if ace_rows:
                conn.executemany(
                    "INSERT INTO contract_aces (contract_id, protocol, src_port, dst_port, "
                    "action, source_category) VALUES (?, ?, ?, ?, ?, ?)",
                    ace_rows,
                )


def list_runs(path: str | Path) -> list[dict]:
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, started_at, source_type, window_start, window_end, status "
            "FROM runs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def load_contracts(path: str | Path, run_id: int) -> list[dict]:
    with _connect(path) as conn:
        conn.row_factory = sqlite3.Row
        contracts = conn.execute(
            "SELECT * FROM contracts WHERE run_id = ? ORDER BY src_sgt, dst_sgt",
            (run_id,),
        ).fetchall()
        result = []
        for c in contracts:
            aces = conn.execute(
                "SELECT * FROM contract_aces WHERE contract_id = ?", (c["id"],)
            ).fetchall()
            result.append({**dict(c), "aces": [dict(a) for a in aces]})
        return result
