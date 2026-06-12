"""Explicit extension-point analyzers for future modules."""

from __future__ import annotations

from pathlib import Path

from kernel_hunter.analyzers.base import Analyzer
from kernel_hunter.models import AnalyzerResult


class PlannedAnalyzer(Analyzer):
    """Analyzer placeholder that reports planned behavior clearly."""

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    def run(self, kernel_tree: Path, subsystem: str | None = None) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.name,
            findings=[],
            warnings=[f"{self.name} is planned but not implemented in the first slice."],
            metadata={"description": self.description, "kernel_tree": str(kernel_tree)},
        )
