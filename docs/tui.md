# TUI

Launch Kernel Hunter with:

```bash
kh
```

or:

```bash
kh tui
```

The TUI is the primary workflow:

- configure the kernel tree, database, subsystem, Smatch log, and confidence threshold
- run all first-slice analyzers or run history, Smatch, and resource lifetime individually
- inspect stored findings in a sortable table
- select a finding to view evidence, rationale, and suggested investigation
- export HTML, Markdown, or JSON reports

The CLI remains available for automation and CI.
