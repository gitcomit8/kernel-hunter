"""Primary Textual application for Kernel Hunter."""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, Static

from kernel_hunter.analyzers.base import AnalyzerError
from kernel_hunter.analyzers.history import HistoryAnalyzer
from kernel_hunter.analyzers.resource_lifetime import ResourceLifetimeAnalyzer
from kernel_hunter.analyzers.smatch import SmatchAnalyzer
from kernel_hunter.models import Finding
from kernel_hunter.reports.render import render_html, render_json, render_markdown
from kernel_hunter.services import list_stored_findings, run_and_persist, run_first_slice
from kernel_hunter.utils.config import load_config, resolve_db_path, resolve_kernel_tree


class KernelHunterTui(App[None]):
    """Interactive Kernel Hunter workflow."""

    TITLE = "Kernel Hunter"
    SUB_TITLE = "Linux kernel patch opportunity discovery"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_findings", "Refresh"),
        ("h", "run_history", "History"),
        ("s", "run_smatch", "Smatch"),
        ("l", "run_lifetime", "Lifetime"),
        ("a", "run_all", "All"),
    ]

    CSS = """
    Screen {
        layout: vertical;
    }

    #body {
        height: 1fr;
    }

    #controls {
        width: 42;
        min-width: 38;
        padding: 1;
        border: solid $accent;
    }

    #main {
        width: 1fr;
        padding: 1;
    }

    Input {
        margin-bottom: 1;
    }

    Button {
        width: 100%;
        margin-bottom: 1;
    }

    #status {
        min-height: 5;
        border: solid $panel;
        padding: 1;
        margin-top: 1;
    }

    #details {
        height: 12;
        border: solid $panel;
        padding: 1;
        margin-top: 1;
    }

    DataTable {
        height: 1fr;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._findings: list[Finding] = []

    def compose(self) -> ComposeResult:
        cfg = load_config()
        yield Header(show_clock=True)
        with Horizontal(id="body"):
            with Vertical(id="controls"):
                yield Label("Kernel tree")
                yield Input(
                    value=str(cfg.kernel_tree or ""),
                    placeholder="/path/to/linux",
                    id="kernel_tree",
                )
                yield Label("SQLite database")
                yield Input(value=str(cfg.database), id="db_path")
                yield Label("Subsystem")
                yield Input(placeholder="drivers/platform/x86", id="subsystem")
                yield Label("Smatch log")
                yield Input(placeholder="Optional saved smatch.log", id="smatch_log")
                yield Label("Min confidence")
                yield Input(value=str(cfg.min_confidence), id="min_confidence")
                yield Label("Report output")
                yield Input(value="reports/kernel-hunter.html", id="report_output")
                yield Button("Run All First-Slice Analyzers", id="run_all", variant="primary")
                yield Button("Mine Git History", id="run_history")
                yield Button("Run Smatch / Parse Log", id="run_smatch")
                yield Button("Run Resource Lifetime", id="run_lifetime")
                yield Button("Refresh Findings", id="refresh")
                yield Button("Export HTML Report", id="report_html")
                yield Button("Export Markdown Report", id="report_markdown")
                yield Button("Export JSON Report", id="report_json")
                yield Button("Planned Web Mining", id="planned")
            with Vertical(id="main"):
                yield Static("Findings", id="heading")
                yield DataTable(id="findings")
                yield Static("Select a finding to view evidence and suggested investigation.", id="details")
                yield Static("Ready.", id="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.cursor_type = "row"
        table.add_columns("Score", "Severity", "Category", "Location", "Title")
        self.action_refresh_findings()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        actions: dict[str, Callable[[], None]] = {
            "run_all": self.action_run_all,
            "run_history": self.action_run_history,
            "run_smatch": self.action_run_smatch,
            "run_lifetime": self.action_run_lifetime,
            "refresh": self.action_refresh_findings,
            "report_html": lambda: self.export_report("html"),
            "report_markdown": lambda: self.export_report("markdown"),
            "report_json": lambda: self.export_report("json"),
            "planned": self.show_planned,
        }
        if button_id in actions:
            actions[button_id]()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.cursor_row is None or event.cursor_row >= len(self._findings):
            return
        finding = self._findings[event.cursor_row]
        self.query_one("#details", Static).update(
            "\n".join(
                [
                    f"[{finding.confidence}] {finding.title}",
                    f"{finding.file}:{finding.line} · {finding.category} · {finding.severity}",
                    "",
                    f"Evidence: {finding.evidence}",
                    f"Rationale: {finding.rationale}",
                    f"Suggested investigation: {finding.recommendation}",
                ]
            )
        )

    def action_run_all(self) -> None:
        try:
            self.run_all_worker(
                self.kernel_tree(),
                self.db_path(),
                self.subsystem(),
                self.optional_path("smatch_log"),
            )
        except Exception as exc:
            self.set_status(f"Could not start scan: {exc}", error=True)

    def action_run_history(self) -> None:
        self.start_single_analyzer("history")

    def action_run_smatch(self) -> None:
        self.start_single_analyzer("smatch")

    def action_run_lifetime(self) -> None:
        self.start_single_analyzer("resource_lifetime")

    def start_single_analyzer(self, analyzer_name: str) -> None:
        try:
            self.run_single_analyzer_worker(
                analyzer_name,
                self.kernel_tree(),
                self.db_path(),
                self.subsystem(),
                self.optional_path("smatch_log"),
            )
        except Exception as exc:
            self.set_status(f"Could not start {analyzer_name}: {exc}", error=True)

    def action_refresh_findings(self) -> None:
        try:
            db_path = self.db_path()
            min_confidence = self.min_confidence()
            self._findings = list_stored_findings(db_path, min_confidence=min_confidence, limit=500)
        except Exception as exc:
            self.set_status(f"Could not load findings: {exc}", error=True)
            return
        self.populate_findings()
        self.set_status(f"Loaded {len(self._findings)} finding(s).")

    @work(thread=True)
    def run_all_worker(
        self,
        kernel_tree: Path,
        db_path: Path,
        subsystem: str | None,
        smatch_log: Path | None,
    ) -> None:
        self.call_from_thread(self.set_status, "Running all first-slice analyzers...")
        try:
            findings, warnings = run_first_slice(
                kernel_tree,
                db_path,
                subsystem,
                smatch_log,
            )
        except Exception as exc:
            self.call_from_thread(self.set_status, f"Scan failed: {exc}", True)
            return
        message = f"Scan complete: {len(findings)} finding(s)."
        if warnings:
            message += "\nWarnings:\n" + "\n".join(warnings)
        self.call_from_thread(self.set_status, message)
        self.call_from_thread(self.action_refresh_findings)

    @work(thread=True)
    def run_single_analyzer_worker(
        self,
        analyzer_name: str,
        kernel_tree: Path,
        db_path: Path,
        subsystem: str | None,
        smatch_log: Path | None,
    ) -> None:
        self.call_from_thread(self.set_status, f"Running {analyzer_name}...")
        try:
            if analyzer_name == "history":
                analyzer = HistoryAnalyzer()
            elif analyzer_name == "smatch":
                analyzer = SmatchAnalyzer(log_file=smatch_log)
            elif analyzer_name == "resource_lifetime":
                analyzer = ResourceLifetimeAnalyzer(require_tree_sitter=True)
            else:
                raise ValueError(f"Unknown analyzer: {analyzer_name}")
            result, stored = run_and_persist(
                analyzer,
                kernel_tree,
                db_path,
                subsystem,
            )
        except AnalyzerError as exc:
            self.call_from_thread(self.set_status, str(exc), True)
            return
        except Exception as exc:
            self.call_from_thread(self.set_status, f"{analyzer_name} failed: {exc}", True)
            return
        warning_text = "\n".join(result.warnings)
        self.call_from_thread(
            self.set_status,
            f"{analyzer_name} complete: {len(result.findings)} finding(s), {stored} stored."
            + (f"\n{warning_text}" if warning_text else ""),
        )
        self.call_from_thread(self.action_refresh_findings)

    def populate_findings(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear(columns=False)
        for finding in self._findings:
            table.add_row(
                str(finding.confidence),
                str(finding.severity),
                finding.category,
                f"{finding.file}:{finding.line}",
                finding.title,
            )

    def export_report(self, report_type: str) -> None:
        try:
            output = Path(self.query_one("#report_output", Input).value).expanduser()
            findings = list_stored_findings(self.db_path(), min_confidence=self.min_confidence())
            if report_type == "html":
                render_html(findings, output)
            elif report_type == "markdown":
                render_markdown(findings, output)
            elif report_type == "json":
                render_json(findings, output)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
        except Exception as exc:
            self.set_status(f"Report failed: {exc}", error=True)
            return
        self.set_status(f"Wrote {report_type} report to {output}")

    def show_planned(self) -> None:
        self.set_status(
            "Planned modules: Lore/Patchwork/CVE/Syzkaller mining, Sparse, Coccinelle, "
            "attack surface, locking, refcount, integer overflow, and PM runtime analyzers."
        )

    def kernel_tree(self) -> Path:
        value = self.query_one("#kernel_tree", Input).value.strip()
        cfg = load_config()
        return resolve_kernel_tree(Path(value) if value else None, cfg)

    def db_path(self) -> Path:
        value = self.query_one("#db_path", Input).value.strip()
        cfg = load_config()
        return resolve_db_path(Path(value) if value else None, cfg)

    def subsystem(self) -> str | None:
        value = self.query_one("#subsystem", Input).value.strip()
        return value or None

    def min_confidence(self) -> int:
        raw = self.query_one("#min_confidence", Input).value.strip()
        if not raw:
            return 0
        value = int(raw)
        if value < 0 or value > 100:
            raise ValueError("Min confidence must be between 0 and 100.")
        return value

    def optional_path(self, input_id: str) -> Path | None:
        value = self.query_one(f"#{input_id}", Input).value.strip()
        return Path(value).expanduser() if value else None

    def set_status(self, message: str, error: bool = False) -> None:
        prefix = "ERROR: " if error else ""
        self.query_one("#status", Static).update(prefix + message)
        if error:
            self.notify(message, severity="error")
        else:
            self.notify(message)
