"""SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable

from kernel_hunter.models import Finding, ScanRun


SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analyzer TEXT NOT NULL,
    kernel_tree TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    message TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    subsystem TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    rationale TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    source TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_fingerprint TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    evidence TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_fingerprint) REFERENCES findings(fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(file);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
"""


class FindingStore:
    """SQLite-backed finding store."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def add_scan_run(self, run: ScanRun) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO scan_runs
            (analyzer, kernel_tree, status, started_at, finished_at, message, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.analyzer,
                str(run.kernel_tree),
                run.status,
                run.started_at.isoformat(),
                run.finished_at.isoformat() if run.finished_at else None,
                run.message,
                json.dumps(run.metadata, sort_keys=True),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def upsert_findings(self, findings: Iterable[Finding]) -> int:
        count = 0
        for finding in findings:
            now = datetime.now(UTC).isoformat()
            self.connection.execute(
                """
                INSERT INTO findings
                (fingerprint, title, category, severity, confidence, subsystem, file, line,
                 evidence, rationale, recommendation, source, analyzer, metadata,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    confidence=max(confidence, excluded.confidence),
                    severity=excluded.severity,
                    metadata=excluded.metadata,
                    updated_at=excluded.updated_at
                """,
                (
                    finding.fingerprint,
                    finding.title,
                    finding.category,
                    str(finding.severity),
                    finding.confidence,
                    finding.subsystem,
                    finding.file,
                    finding.line,
                    finding.evidence,
                    finding.rationale,
                    finding.recommendation,
                    finding.source,
                    finding.analyzer,
                    json.dumps(finding.metadata, sort_keys=True),
                    finding.created_at.isoformat(),
                    now,
                ),
            )
            self.connection.execute(
                """
                INSERT INTO evidence
                (finding_fingerprint, analyzer, evidence, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (finding.fingerprint, finding.analyzer, finding.evidence, now),
            )
            count += 1
        self.connection.commit()
        return count

    def list_findings(self, min_confidence: int = 0, limit: int | None = None) -> list[Finding]:
        query = "SELECT * FROM findings WHERE confidence >= ? ORDER BY confidence DESC, file, line"
        params: list[object] = [min_confidence]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
        rows = self.connection.execute(query, params).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            title=row["title"],
            category=row["category"],
            severity=row["severity"],
            confidence=row["confidence"],
            subsystem=row["subsystem"],
            file=row["file"],
            line=row["line"],
            evidence=row["evidence"],
            rationale=row["rationale"],
            recommendation=row["recommendation"],
            source=row["source"],
            analyzer=row["analyzer"],
            fingerprint=row["fingerprint"],
            metadata=json.loads(row["metadata"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )
