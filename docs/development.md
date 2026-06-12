# Development

Run tests:

```bash
python3 -m pytest
```

Run linting and typing when dependencies are installed:

```bash
ruff check .
mypy kernel_hunter
```

Analyzer implementations should return `AnalyzerResult` and normalized
`Finding` objects. They should not write reports directly.

The Textual app is the primary user interface. Keep orchestration code in
`kernel_hunter.services` so the TUI and scriptable CLI commands share behavior.
