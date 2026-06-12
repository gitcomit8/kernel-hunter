# Analyzers

## Smatch

`kh scan smatch` runs Smatch through `make CHECK=smatch C=2` when Smatch is
available. It can also parse a saved log with `--log-file`, which is useful for
CI artifacts and offline triage.

## Git History

`kh mine history` analyzes local git history in the supplied kernel tree. It
classifies likely fix commits, inspects their diffs, and emits patch leads near
interesting fix lines.

## Resource Lifetime

`kh scan resource-lifetime` tracks acquisition/release pairs inside C functions.
The command requires `tree-sitter` and `tree-sitter-c`; the internal parser used
by tests is intentionally conservative.

## Planned Modules

Sparse, Coccinelle, CVE mining, Syzkaller, Lore/Patchwork, attack surface,
integer overflow, locking, refcount, and PM runtime analyzers are planned
extension points after the first high-signal slice.
