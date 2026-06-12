from pathlib import Path

from kernel_hunter.models import Finding, Severity
from kernel_hunter.storage.sqlite import FindingStore


def make_finding(confidence: int = 80) -> Finding:
    return Finding(
        title="Potential NULL dereference",
        category="null_dereference",
        severity=Severity.HIGH,
        confidence=confidence,
        subsystem="drivers/foo",
        file="drivers/foo/bar.c",
        line=42,
        evidence="foo->bar",
        rationale="test rationale",
        recommendation="test recommendation",
        source="smatch",
        analyzer="smatch",
    )


def test_fingerprint_is_stable() -> None:
    first = make_finding()
    second = make_finding()
    assert first.fingerprint == second.fingerprint


def test_sqlite_dedupes_findings(tmp_path: Path) -> None:
    store = FindingStore(tmp_path / "findings.sqlite")
    try:
        store.upsert_findings([make_finding(70), make_finding(90)])
        findings = store.list_findings(min_confidence=0)
    finally:
        store.close()
    assert len(findings) == 1
    assert findings[0].confidence == 90
