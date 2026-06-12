"""Typer CLI for Kernel Hunter."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from kernel_hunter.analyzers.base import AnalyzerError
from kernel_hunter.analyzers.history import HistoryAnalyzer
from kernel_hunter.analyzers.resource_lifetime import ResourceLifetimeAnalyzer
from kernel_hunter.analyzers.smatch import SmatchAnalyzer
from kernel_hunter.models import AnalyzerResult
from kernel_hunter.reports.render import render_html, render_json, render_markdown, render_terminal
from kernel_hunter.storage.sqlite import FindingStore
from kernel_hunter.tui.app import KernelHunterTui
from kernel_hunter.services import persist_result, run_first_slice
from kernel_hunter.utils.config import load_config, resolve_db_path, resolve_kernel_tree
from kernel_hunter.utils.logging import configure_logging


console = Console()
app = typer.Typer(help="Linux kernel bug and patch opportunity discovery framework.")
scan_app = typer.Typer(help="Run analyzers.")
mine_app = typer.Typer(help="Mine external or local signal.")
report_app = typer.Typer(help="Generate reports.")
app.add_typer(scan_app, name="scan")
app.add_typer(mine_app, name="mine")
app.add_typer(report_app, name="report")


KernelTreeOption = Annotated[Path | None, typer.Option("--kernel-tree", help="Linux kernel tree")]
DbOption = Annotated[Path | None, typer.Option("--db", help="SQLite findings database")]
ConfigOption = Annotated[Path | None, typer.Option("--config", help="Optional config TOML")]


def run_analyzer(result: AnalyzerResult, kernel_tree: Path, db_path: Path) -> None:
    """Persist and print an analyzer result."""

    count = persist_result(result, kernel_tree, db_path)
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    console.print(f"[green]stored {count} finding(s)[/green] from {result.analyzer}")
    render_terminal(result.findings, console)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Configure global CLI behavior."""

    configure_logging(verbose)
    if ctx.invoked_subcommand is None:
        KernelHunterTui().run()
        raise typer.Exit()


@scan_app.command("smatch")
def scan_smatch(
    kernel_tree: KernelTreeOption = None,
    db: DbOption = None,
    config: ConfigOption = None,
    log_file: Annotated[Path | None, typer.Option("--log-file", help="Parse saved Smatch log")] = None,
    subsystem: Annotated[str | None, typer.Option("--subsystem", help="Kernel subsystem path")] = None,
    jobs: Annotated[int, typer.Option("--jobs", "-j", min=1)] = 1,
) -> None:
    """Run or parse Smatch diagnostics."""

    cfg = load_config(config)
    tree = resolve_kernel_tree(kernel_tree, cfg)
    db_path = resolve_db_path(db, cfg)
    try:
        result = SmatchAnalyzer(log_file=log_file, jobs=jobs).run(tree, subsystem)
    except AnalyzerError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_analyzer(result, tree, db_path)


@scan_app.command("resource-lifetime")
def scan_resource_lifetime(
    kernel_tree: KernelTreeOption = None,
    db: DbOption = None,
    config: ConfigOption = None,
    subsystem: Annotated[str | None, typer.Option("--subsystem", help="Kernel subsystem path")] = None,
) -> None:
    """Run resource lifetime analysis."""

    cfg = load_config(config)
    tree = resolve_kernel_tree(kernel_tree, cfg)
    db_path = resolve_db_path(db, cfg)
    try:
        result = ResourceLifetimeAnalyzer(require_tree_sitter=True).run(tree, subsystem)
    except AnalyzerError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_analyzer(result, tree, db_path)


@scan_app.command("all")
def scan_all(
    kernel_tree: KernelTreeOption = None,
    db: DbOption = None,
    config: ConfigOption = None,
    subsystem: Annotated[str | None, typer.Option("--subsystem", help="Kernel subsystem path")] = None,
    smatch_log: Annotated[Path | None, typer.Option("--smatch-log", help="Parse saved Smatch log")] = None,
) -> None:
    """Run first-slice analyzers."""

    cfg = load_config(config)
    tree = resolve_kernel_tree(kernel_tree, cfg)
    db_path = resolve_db_path(db, cfg)
    all_findings, warnings = run_first_slice(tree, db_path, subsystem, smatch_log)
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    console.print(f"[green]completed scan; {len(all_findings)} finding(s)[/green]")
    render_terminal(all_findings, console)


@scan_app.command("subsystem")
def scan_subsystem(
    subsystem: str,
    kernel_tree: KernelTreeOption = None,
    db: DbOption = None,
    config: ConfigOption = None,
) -> None:
    """Scan a specific subsystem with first-slice analyzers."""

    scan_all(kernel_tree=kernel_tree, db=db, config=config, subsystem=subsystem, smatch_log=None)


@mine_app.command("history")
def mine_history(
    kernel_tree: KernelTreeOption = None,
    db: DbOption = None,
    config: ConfigOption = None,
    subsystem: Annotated[str | None, typer.Option("--subsystem", help="Kernel subsystem path")] = None,
    since: Annotated[str | None, typer.Option("--since", help="Git revision range start")] = None,
    max_commits: Annotated[int, typer.Option("--max-commits", min=1)] = 250,
) -> None:
    """Mine local git history for patch opportunities."""

    cfg = load_config(config)
    tree = resolve_kernel_tree(kernel_tree, cfg)
    db_path = resolve_db_path(db, cfg)
    try:
        result = HistoryAnalyzer(since=since, max_commits=max_commits).run(tree, subsystem)
    except AnalyzerError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run_analyzer(result, tree, db_path)


@app.command("findings")
def findings(
    db: DbOption = None,
    config: ConfigOption = None,
    min_confidence: Annotated[int, typer.Option("--min-confidence", min=0, max=100)] = 70,
    limit: Annotated[int | None, typer.Option("--limit", min=1)] = None,
) -> None:
    """List stored findings."""

    cfg = load_config(config)
    store = FindingStore(resolve_db_path(db, cfg))
    try:
        render_terminal(store.list_findings(min_confidence=min_confidence, limit=limit), console)
    finally:
        store.close()


@report_app.command("json")
def report_json(
    output: Annotated[Path, typer.Option("--output", "-o")],
    db: DbOption = None,
    config: ConfigOption = None,
    min_confidence: Annotated[int, typer.Option("--min-confidence", min=0, max=100)] = 0,
) -> None:
    """Generate a JSON report."""

    cfg = load_config(config)
    store = FindingStore(resolve_db_path(db, cfg))
    try:
        render_json(store.list_findings(min_confidence), output)
    finally:
        store.close()


@report_app.command("markdown")
def report_markdown(
    output: Annotated[Path, typer.Option("--output", "-o")],
    db: DbOption = None,
    config: ConfigOption = None,
    min_confidence: Annotated[int, typer.Option("--min-confidence", min=0, max=100)] = 0,
) -> None:
    """Generate a Markdown report."""

    cfg = load_config(config)
    store = FindingStore(resolve_db_path(db, cfg))
    try:
        render_markdown(store.list_findings(min_confidence), output)
    finally:
        store.close()


@report_app.command("html")
def report_html(
    output: Annotated[Path, typer.Option("--output", "-o")],
    db: DbOption = None,
    config: ConfigOption = None,
    min_confidence: Annotated[int, typer.Option("--min-confidence", min=0, max=100)] = 0,
) -> None:
    """Generate an HTML report."""

    cfg = load_config(config)
    store = FindingStore(resolve_db_path(db, cfg))
    try:
        render_html(store.list_findings(min_confidence), output)
    finally:
        store.close()


@app.command("menu")
def menu() -> None:
    """Launch the Textual TUI."""

    KernelHunterTui().run()


@app.command("tui")
def tui() -> None:
    """Launch the Textual TUI."""

    KernelHunterTui().run()
