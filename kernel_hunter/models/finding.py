"""Structured finding models."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(StrEnum):
    """Kernel Hunter severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A normalized, actionable kernel finding."""

    model_config = ConfigDict(use_enum_values=True)

    title: str
    category: str
    severity: Severity = Severity.MEDIUM
    confidence: int = Field(ge=0, le=100)
    subsystem: str
    file: str
    line: int = Field(ge=1)
    evidence: str
    rationale: str
    recommendation: str
    source: str
    analyzer: str
    fingerprint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("file")
    @classmethod
    def normalize_file(cls, value: str) -> str:
        return value.replace("\\", "/").lstrip("./")

    @model_validator(mode="after")
    def assign_fingerprint(self) -> Finding:
        if self.fingerprint is None:
            basis = "|".join(
                [
                    self.source,
                    self.category,
                    self.file,
                    str(self.line),
                    self.title,
                    self.evidence.strip(),
                ]
            )
            self.fingerprint = hashlib.sha256(basis.encode("utf-8")).hexdigest()
        return self


class ScanRun(BaseModel):
    """Metadata for a scan or mining run."""

    analyzer: str
    kernel_tree: Path
    status: str = "completed"
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    message: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalyzerResult(BaseModel):
    """Analyzer output before persistence."""

    analyzer: str
    findings: list[Finding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
