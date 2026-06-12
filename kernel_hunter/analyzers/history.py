"""Local git history mining."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from kernel_hunter.analyzers.base import Analyzer, AnalyzerError
from kernel_hunter.models import AnalyzerResult, Finding, Severity
from kernel_hunter.scorers.confidence import apply_source_floor
from kernel_hunter.utils.kernel import infer_subsystem


BUG_TERMS = {
    "fixes": "fix_reference",
    "bug": "bug",
    "race": "race",
    "overflow": "integer_overflow",
    "null": "null_dereference",
    "refcount": "refcount",
    "uaf": "use_after_free",
    "use-after-free": "use_after_free",
    "deadlock": "deadlock",
}

HUNK_RE = re.compile(r"^@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@(?P<context>.*)$")


@dataclass(frozen=True)
class FixCommit:
    commit: str
    subject: str
    category: str


class HistoryAnalyzer(Analyzer):
    """Mine local git history for patch opportunities."""

    name = "history"

    def __init__(self, since: str | None = None, max_commits: int = 250) -> None:
        self.since = since
        self.max_commits = max_commits

    def run(self, kernel_tree: Path, subsystem: str | None = None) -> AnalyzerResult:
        if not (kernel_tree / ".git").exists():
            raise AnalyzerError(f"Kernel tree is not a git repository: {kernel_tree}")
        commits = find_fix_commits(kernel_tree, self.since, self.max_commits, subsystem)
        findings: list[Finding] = []
        for commit in commits:
            findings.extend(find_similar_code(kernel_tree, commit, subsystem))
        return AnalyzerResult(
            analyzer=self.name,
            findings=findings,
            metadata={"fix_commits": len(commits), "max_commits": self.max_commits},
        )


def find_fix_commits(
    kernel_tree: Path,
    since: str | None,
    max_commits: int,
    subsystem: str | None,
) -> list[FixCommit]:
    """Return likely bug-fix commits from local git history."""

    args = [
        "git",
        "log",
        f"--max-count={max_commits}",
        "--format=%H%x00%s%x00%b%x1e",
    ]
    if since:
        args.append(f"{since}..HEAD")
    if subsystem:
        args.extend(["--", subsystem])
    completed = subprocess.run(args, cwd=kernel_tree, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise AnalyzerError(completed.stderr.strip() or "git log failed")

    commits: list[FixCommit] = []
    for record in completed.stdout.strip("\x1e\n").split("\x1e"):
        if not record.strip():
            continue
        parts = record.strip().split("\x00", 2)
        if len(parts) != 3:
            continue
        commit_hash, subject, body = parts
        category = classify_commit_message(f"{subject}\n{body}")
        if category:
            commits.append(FixCommit(commit_hash, subject.strip(), category))
    return commits


def classify_commit_message(message: str) -> str | None:
    """Classify a commit message into a bug category."""

    lowered = message.lower()
    for term, category in BUG_TERMS.items():
        if term in lowered:
            return category
    return None


def find_similar_code(
    kernel_tree: Path,
    commit: FixCommit,
    subsystem: str | None,
) -> list[Finding]:
    """Generate leads from files touched by a fix commit."""

    show = subprocess.run(
        ["git", "show", "--format=", "--unified=0", "--no-ext-diff", commit.commit],
        cwd=kernel_tree,
        check=False,
        text=True,
        capture_output=True,
    )
    if show.returncode != 0:
        return []

    findings: list[Finding] = []
    current_file: str | None = None
    current_line = 1
    for line in show.stdout.splitlines():
        if line.startswith("+++ b/"):
            current_file = line.removeprefix("+++ b/")
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            current_line = int(hunk.group("new"))
            continue
        if current_file is None or not current_file.endswith((".c", ".h")):
            continue
        if subsystem and not current_file.startswith(subsystem.rstrip("/") + "/"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added = line[1:].strip()
            if not is_interesting_added_line(added):
                current_line += 1
                continue
            finding = Finding(
                title=f"History-derived {commit.category.replace('_', ' ')} patch lead",
                category=commit.category,
                severity=severity_for_category(commit.category),
                confidence=0,
                subsystem=infer_subsystem(current_file),
                file=current_file,
                line=max(current_line, 1),
                evidence=added,
                rationale=(
                    f"Commit {commit.commit[:12]} ('{commit.subject}') fixed a related pattern "
                    "in this area. Similar nearby code may need the same audit."
                ),
                recommendation=(
                    "Compare the fixed hunk with adjacent call sites and check whether the same "
                    "precondition, cleanup, or lifetime rule is missing."
                ),
                source="history",
                analyzer="history",
                metadata={"commit": commit.commit, "subject": commit.subject},
            )
            apply_source_floor(finding, "history", 18)
            findings.append(finding)
            current_line += 1
        elif not line.startswith("-"):
            current_line += 1
    return findings


def is_interesting_added_line(line: str) -> bool:
    """Return true for added lines likely to represent a fix pattern."""

    if not line or line.startswith(("*", "//", "/*")):
        return False
    tokens = (
        "if",
        "return",
        "goto",
        "put_",
        "_put",
        "free",
        "unlock",
        "refcount",
        "kref",
        "IS_ERR",
        "PTR_ERR",
        "check_",
    )
    return any(token in line for token in tokens)


def severity_for_category(category: str) -> Severity:
    """Map history category to severity."""

    if category in {"use_after_free", "race", "deadlock", "integer_overflow"}:
        return Severity.HIGH
    if category in {"null_dereference", "refcount"}:
        return Severity.MEDIUM
    return Severity.LOW
