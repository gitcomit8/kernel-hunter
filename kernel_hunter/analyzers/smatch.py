"""Smatch integration and parser."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from kernel_hunter.analyzers.base import Analyzer, AnalyzerError
from kernel_hunter.models import AnalyzerResult, Finding, Severity
from kernel_hunter.scorers.confidence import apply_source_floor
from kernel_hunter.utils.kernel import infer_subsystem


SMATCH_RE = re.compile(
    r"^(?P<file>[^:\n]+):(?P<line>\d+)(?::(?P<column>\d+))?\s+(?P<level>[^:]+):\s*(?P<message>.+)$"
)


class SmatchAnalyzer(Analyzer):
    """Run or parse Smatch output."""

    name = "smatch"

    def __init__(self, log_file: Path | None = None, jobs: int = 1) -> None:
        self.log_file = log_file
        self.jobs = jobs

    def run(self, kernel_tree: Path, subsystem: str | None = None) -> AnalyzerResult:
        if self.log_file:
            output = self.log_file.read_text(encoding="utf-8", errors="replace")
            return AnalyzerResult(analyzer=self.name, findings=parse_smatch_output(output))

        if shutil.which("smatch") is None:
            raise AnalyzerError(
                "Smatch is not installed or not on PATH. Install smatch or pass --log-file."
            )

        target = [subsystem] if subsystem else []
        command = ["make", f"-j{self.jobs}", "CHECK=smatch", "C=2", *target]
        completed = subprocess.run(
            command,
            cwd=kernel_tree,
            check=False,
            text=True,
            capture_output=True,
        )
        output = "\n".join([completed.stdout, completed.stderr])
        findings = parse_smatch_output(output)
        warnings = []
        if completed.returncode != 0 and not findings:
            warnings.append(f"Smatch command exited with {completed.returncode} and no findings.")
        return AnalyzerResult(
            analyzer=self.name,
            findings=findings,
            warnings=warnings,
            metadata={"returncode": completed.returncode, "command": command},
        )


def parse_smatch_output(output: str) -> list[Finding]:
    """Parse Smatch output into findings."""

    findings: list[Finding] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        match = SMATCH_RE.match(raw_line.strip())
        if not match:
            continue
        file_path = match.group("file")
        line = int(match.group("line"))
        message = match.group("message").strip()
        title, category, severity, bonus = classify_smatch_message(message)
        finding = Finding(
            title=title,
            category=category,
            severity=severity,
            confidence=0,
            subsystem=infer_subsystem(file_path),
            file=file_path,
            line=line,
            evidence=raw_line.strip(),
            rationale=f"Smatch reported: {message}",
            recommendation=recommendation_for_category(category),
            source="smatch",
            analyzer="smatch",
            metadata={"raw_level": match.group("level").strip(), "message": message},
        )
        apply_source_floor(finding, "smatch", bonus)
        if finding.fingerprint not in seen:
            findings.append(finding)
            seen.add(finding.fingerprint or "")
    return findings


def classify_smatch_message(message: str) -> tuple[str, str, Severity, int]:
    """Classify a Smatch diagnostic."""

    lowered = message.lower()
    if "null" in lowered and ("dereference" in lowered or "deref" in lowered):
        return "Potential NULL dereference", "null_dereference", Severity.HIGH, 42
    if "use after free" in lowered or "uaf" in lowered:
        return "Potential use-after-free", "use_after_free", Severity.CRITICAL, 48
    if "uninitialized" in lowered:
        return "Potential uninitialized variable use", "uninitialized_variable", Severity.HIGH, 36
    if "unchecked" in lowered and ("return" in lowered or "retval" in lowered):
        return "Unchecked return value", "unchecked_return", Severity.MEDIUM, 32
    if "refcount" in lowered or "kref" in lowered:
        return "Potential refcount issue", "refcount", Severity.HIGH, 38
    return "Smatch warning", "smatch_warning", Severity.MEDIUM, 18


def recommendation_for_category(category: str) -> str:
    """Return a suggested investigation for a Smatch category."""

    recommendations = {
        "null_dereference": "Verify the pointer is checked on all paths before dereference.",
        "use_after_free": "Audit object lifetime and confirm no dereference occurs after release.",
        "uninitialized_variable": "Check whether all control-flow paths initialize the value.",
        "unchecked_return": "Check whether the return value must gate later resource use or cleanup.",
        "refcount": "Audit get/put symmetry and error paths around the reported object.",
    }
    return recommendations.get(category, "Inspect the warning and surrounding control flow.")
