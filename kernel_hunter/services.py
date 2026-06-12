"""Application services shared by CLI and TUI."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kernel_hunter.analyzers.base import Analyzer, AnalyzerError
from kernel_hunter.analyzers.history import HistoryAnalyzer
from kernel_hunter.analyzers.resource_lifetime import ResourceLifetimeAnalyzer
from kernel_hunter.analyzers.smatch import SmatchAnalyzer
from kernel_hunter.models import AnalyzerResult, Finding, ScanRun
from kernel_hunter.scorers.confidence import boost_agreement
from kernel_hunter.storage.sqlite import FindingStore


def persist_result(result: AnalyzerResult, kernel_tree: Path, db_path: Path) -> int:
    """Persist analyzer result and return finding count."""

    store = FindingStore(db_path)
    try:
        store.add_scan_run(
            ScanRun(
                analyzer=result.analyzer,
                kernel_tree=kernel_tree,
                finished_at=datetime.now(UTC),
                metadata=result.metadata,
                message="; ".join(result.warnings) if result.warnings else None,
            )
        )
        findings = boost_agreement(result.findings)
        return store.upsert_findings(findings)
    finally:
        store.close()


def run_and_persist(
    analyzer: Analyzer,
    kernel_tree: Path,
    db_path: Path,
    subsystem: str | None = None,
) -> tuple[AnalyzerResult, int]:
    """Run one analyzer and persist its findings."""

    result = analyzer.run(kernel_tree, subsystem)
    stored = persist_result(result, kernel_tree, db_path)
    return result, stored


def run_first_slice(
    kernel_tree: Path,
    db_path: Path,
    subsystem: str | None = None,
    smatch_log: Path | None = None,
    jobs: int = 1,
) -> tuple[list[Finding], list[str]]:
    """Run the first-slice analyzers and return findings plus warnings."""

    analyzers: list[Analyzer] = [
        HistoryAnalyzer(),
        SmatchAnalyzer(log_file=smatch_log, jobs=jobs),
        ResourceLifetimeAnalyzer(require_tree_sitter=True),
    ]
    findings: list[Finding] = []
    warnings: list[str] = []
    for analyzer in analyzers:
        try:
            result, _stored = run_and_persist(analyzer, kernel_tree, db_path, subsystem)
        except AnalyzerError as exc:
            warnings.append(f"{analyzer.name}: {exc}")
            continue
        findings.extend(result.findings)
        warnings.extend(result.warnings)
    return boost_agreement(findings), warnings


def list_stored_findings(
    db_path: Path,
    min_confidence: int = 0,
    limit: int | None = None,
) -> list[Finding]:
    """Load findings from storage."""

    store = FindingStore(db_path)
    try:
        return store.list_findings(min_confidence=min_confidence, limit=limit)
    finally:
        store.close()
