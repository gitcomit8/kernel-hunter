from pathlib import Path

from kernel_hunter.models import Finding
from kernel_hunter.reports.render import render_json, render_markdown


def test_reports_write_files(tmp_path: Path) -> None:
    finding = Finding(
        title="Unchecked return value",
        category="unchecked_return",
        severity="medium",
        confidence=72,
        subsystem="drivers/foo",
        file="drivers/foo/bar.c",
        line=7,
        evidence="ret = foo();",
        rationale="Smatch reported an unchecked return.",
        recommendation="Audit the return value.",
        source="smatch",
        analyzer="smatch",
    )
    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"
    render_json([finding], json_path)
    render_markdown([finding], md_path)
    assert "unchecked_return" in json_path.read_text(encoding="utf-8")
    assert "Suggested Investigation" in md_path.read_text(encoding="utf-8")
