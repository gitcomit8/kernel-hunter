"""Report renderers."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.table import Table

from kernel_hunter.models import Finding


def render_terminal(findings: list[Finding], console: Console | None = None) -> None:
    """Render findings to the terminal."""

    target = console or Console()
    table = Table(title="Kernel Hunter Findings")
    table.add_column("Confidence", justify="right")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Location")
    table.add_column("Title")
    for finding in findings:
        table.add_row(
            str(finding.confidence),
            str(finding.severity),
            finding.category,
            f"{finding.file}:{finding.line}",
            finding.title,
        )
    target.print(table)


def render_json(findings: list[Finding], output: Path) -> None:
    """Render JSON report."""

    output.parent.mkdir(parents=True, exist_ok=True)
    payload = [finding.model_dump(mode="json") for finding in findings]
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def render_markdown(findings: list[Finding], output: Path) -> None:
    """Render Markdown report."""

    output.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Kernel Hunter Findings", ""]
    for finding in findings:
        lines.extend(
            [
                f"## [{finding.confidence}] {finding.title}",
                "",
                f"- **Category:** {finding.category}",
                f"- **Severity:** {finding.severity}",
                f"- **Location:** `{finding.file}:{finding.line}`",
                f"- **Subsystem:** `{finding.subsystem}`",
                "",
                "### Evidence",
                "",
                "```",
                finding.evidence,
                "```",
                "",
                "### Rationale",
                "",
                finding.rationale,
                "",
                "### Suggested Investigation",
                "",
                finding.recommendation,
                "",
            ]
        )
    output.write_text("\n".join(lines), encoding="utf-8")


def render_html(findings: list[Finding], output: Path, template_dir: Path | None = None) -> None:
    """Render HTML report."""

    output.parent.mkdir(parents=True, exist_ok=True)
    templates = template_dir or Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(templates),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    output.write_text(template.render(findings=findings), encoding="utf-8")
