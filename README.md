# Kernel Hunter

Kernel Hunter is a Linux kernel bug and patch opportunity discovery framework.
It prioritizes high-confidence findings over high-volume text matching.

The first implementation slice focuses on:

- local git-history mining for upstreamable patch leads
- Smatch output parsing and optional Smatch execution
- resource lifetime imbalance analysis
- structured SQLite storage
- terminal, JSON, Markdown, and HTML reports
- a Typer CLI plus a Textual menu entrypoint

## Install

```bash
python3 -m pip install -e '.[dev,c]'
```

Resource lifetime scans require tree-sitter support:

```bash
python3 -m pip install tree-sitter tree-sitter-c
```

Smatch scans require Smatch on `PATH`, or a saved log via `--log-file`.

## Quickstart

```bash
kh mine history --kernel-tree /path/to/linux --subsystem drivers/platform/x86
kh scan smatch --kernel-tree /path/to/linux --log-file smatch.log
kh scan resource-lifetime --kernel-tree /path/to/linux --subsystem drivers/platform/x86
kh findings --min-confidence 70
kh report markdown --output reports/findings.md
kh menu
```

## Configuration

Optional `kernel-hunter.toml`:

```toml
[kernel_hunter]
kernel_tree = "/path/to/linux"
database = ".kernel-hunter/findings.sqlite"
jobs = 8
min_confidence = 70
```

CLI flags override config values.
