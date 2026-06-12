"""Confidence scoring."""

from __future__ import annotations

from collections import defaultdict

from kernel_hunter.models import Finding


SOURCE_WEIGHTS: dict[str, int] = {
    "smatch": 40,
    "sparse": 30,
    "coccinelle": 25,
    "history": 20,
    "resource_lifetime": 15,
}


def cap_confidence(value: int) -> int:
    """Clamp confidence to 0..100."""

    return max(0, min(100, value))


def apply_source_floor(finding: Finding, source: str, evidence_bonus: int = 0) -> Finding:
    """Raise confidence to at least the source baseline plus evidence bonus."""

    baseline = SOURCE_WEIGHTS.get(source, 10)
    finding.confidence = cap_confidence(max(finding.confidence, baseline + evidence_bonus))
    return finding


def boost_agreement(findings: list[Finding]) -> list[Finding]:
    """Boost confidence when multiple analyzers report the same file and nearby line."""

    buckets: dict[tuple[str, str, int], set[str]] = defaultdict(set)
    for finding in findings:
        buckets[(finding.category, finding.file, finding.line // 10)].add(finding.analyzer)

    boosted: list[Finding] = []
    for finding in findings:
        analyzers = buckets[(finding.category, finding.file, finding.line // 10)]
        if len(analyzers) > 1:
            finding.confidence = cap_confidence(finding.confidence + 20)
            finding.metadata["agreement_analyzers"] = sorted(analyzers)
        boosted.append(finding)
    return boosted
