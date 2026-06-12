"""Textual menu UI."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Footer, Header, Static


class KernelHunterTui(App[None]):
    """Menu-driven Kernel Hunter interface."""

    CSS = """
    Screen { padding: 1 2; }
    #intro { margin: 1 0; }
    Button { width: 42; margin: 1 0; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Vertical(
            Static("Kernel Hunter", id="intro"),
            Static("Use the CLI commands below from a shell for this first slice:"),
            Button("Mine local git history", id="history"),
            Button("Run Smatch or parse Smatch log", id="smatch"),
            Button("Run resource lifetime analysis", id="resource"),
            Button("List findings", id="findings"),
            Button("Generate reports", id="reports"),
            Button("Planned: Lore / Patchwork / CVE mining", id="planned"),
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        messages = {
            "history": "Run: kh mine history --kernel-tree /path/to/linux",
            "smatch": "Run: kh scan smatch --kernel-tree /path/to/linux or --log-file smatch.log",
            "resource": "Run: kh scan resource-lifetime --kernel-tree /path/to/linux",
            "findings": "Run: kh findings --min-confidence 70",
            "reports": "Run: kh report html --output report.html",
            "planned": "Network mining is documented for a later slice and intentionally disabled now.",
        }
        self.notify(messages.get(event.button.id or "", "Unknown action"))
