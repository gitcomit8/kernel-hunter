"""Analyzer base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from kernel_hunter.models import AnalyzerResult


class AnalyzerError(RuntimeError):
    """Raised for analyzer execution failures."""


class Analyzer(ABC):
    """Analyzer interface."""

    name: str

    @abstractmethod
    def run(self, kernel_tree: Path, subsystem: str | None = None) -> AnalyzerResult:
        """Run analyzer against a kernel tree."""
