"""Persistência de scans e findings.

Usa ``sqlite3`` da stdlib (default) mantendo a interface desacoplada do banco
(Repository Pattern, CLAUDE.md §6/§9): trocar por Postgres significa fornecer
outra implementação de :class:`FindingStore`, sem tocar em domínio/aplicação.

Nota: o schema `Finding` é o contrato; aqui apenas serializamos/deserializamos.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from .schema import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement TEXT NOT NULL,
    profile TEXT NOT NULL,
    targets TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL,
    UNIQUE(scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


class FindingStore:
    def __init__(self, db_path: str | Path = "vulnforge.db") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def create_scan(self, engagement: str, profile: str, targets: list[str]) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans(engagement, profile, targets, started_at) VALUES (?,?,?,?)",
            (engagement, profile, json.dumps(targets), datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()
        assert cur.lastrowid is not None  # garantido após INSERT bem-sucedido
        return int(cur.lastrowid)

    def finish_scan(self, scan_id: int) -> None:
        self._conn.execute(
            "UPDATE scans SET finished_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), scan_id),
        )
        self._conn.commit()

    def add_findings(self, scan_id: int, findings: Iterable[Finding]) -> int:
        n = 0
        for f in findings:
            # INSERT OR IGNORE respeita o UNIQUE(scan_id, fingerprint): dedup
            # em nível de persistência como segunda barreira além do dedup lógico.
            self._conn.execute(
                "INSERT OR IGNORE INTO findings(scan_id, fingerprint, severity, data) "
                "VALUES (?,?,?,?)",
                (scan_id, f.fingerprint, f.severity.value, f.model_dump_json()),
            )
            n += 1
        self._conn.commit()
        return n

    def get_findings(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT data FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def get_scan(self, scan_id: int) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
