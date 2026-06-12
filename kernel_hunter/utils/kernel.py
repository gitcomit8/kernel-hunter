"""Kernel tree helpers."""

from __future__ import annotations

from pathlib import Path


def infer_subsystem(file_path: str | Path) -> str:
    """Infer a kernel subsystem from a relative source path."""

    parts = Path(str(file_path)).parts
    if not parts:
        return "unknown"
    if parts[0] in {"drivers", "fs", "net", "kernel", "mm", "arch", "sound", "crypto"}:
        return "/".join(parts[:2]) if len(parts) > 1 else parts[0]
    return parts[0]


def iter_c_files(kernel_tree: Path, subsystem: str | None = None) -> list[Path]:
    """Return C files under a kernel tree or subsystem."""

    root = kernel_tree / subsystem if subsystem else kernel_tree
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.c") if path.is_file())
