"""Configuration loading."""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


class KernelHunterConfig(BaseModel):
    """Runtime configuration."""

    kernel_tree: Path | None = None
    database: Path = Path(".kernel-hunter/findings.sqlite")
    jobs: int = 1
    min_confidence: int = Field(default=70, ge=0, le=100)


def load_config(path: Path | None = None) -> KernelHunterConfig:
    """Load optional TOML config."""

    config_path = path or Path("kernel-hunter.toml")
    if not config_path.exists():
        return KernelHunterConfig()
    data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    section = data.get("kernel_hunter", data)
    return KernelHunterConfig.model_validate(section)


def resolve_kernel_tree(kernel_tree: Path | None, config: KernelHunterConfig) -> Path:
    """Resolve and validate the kernel tree path."""

    resolved = kernel_tree or config.kernel_tree
    if resolved is None:
        raise ValueError("A Linux kernel tree path is required. Pass --kernel-tree PATH.")
    path = resolved.expanduser().resolve()
    if not path.exists() or not path.is_dir():
        raise ValueError(f"Kernel tree does not exist or is not a directory: {path}")
    return path


def resolve_db_path(db: Path | None, config: KernelHunterConfig) -> Path:
    """Resolve the SQLite database path."""

    return (db or config.database).expanduser()
