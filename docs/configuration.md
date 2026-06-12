# Configuration

Kernel Hunter accepts an optional `kernel-hunter.toml`.

```toml
[kernel_hunter]
kernel_tree = "/path/to/linux"
database = ".kernel-hunter/findings.sqlite"
jobs = 8
min_confidence = 70
```

Commands that scan or mine require a Linux kernel tree, either through
`--kernel-tree` or config. The explicit flag is recommended for repeatable patch
workflows.
