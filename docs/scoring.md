# Confidence Scoring

Kernel Hunter uses a 0-100 confidence score. The first slice applies source
baselines and evidence bonuses:

- Smatch: up to 40 baseline, higher for NULL dereference, UAF, refcount, and uninitialized warnings.
- Git history: up to 20 baseline, higher when the changed line looks like a concrete fix pattern.
- Resource lifetime: up to 15 baseline, higher when function-local control flow shows likely error paths.
- Analyzer agreement: +20 when multiple analyzers report the same category in the same nearby file range.

Scores are capped at 100. The goal is to rank findings for upstream patch work,
not to claim proof of a bug.
