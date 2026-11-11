# Working rules for this repository

- Research workspace, private. Publish nothing without the owner's approval.
- Commits are authored by the repository owner only. No co-author trailers.
- Commit incrementally; every code commit comes with tests that were run.
- Never write "proved" or "secure" on the basis of passing tests.
- Every number in `reports/` and `research/` must come from a file in `data/`
  or from a test. Regenerate with the scripts in `tools/`; do not hand-edit.
- Every in-scope fault is classified benign / covered / bypass / unknown.
  Unknown is never counted as safe. No silent exclusions.
- `src/cafq/checker.py` is the trusted base: standard library only, no imports
  from the analyzer. A test enforces this.
- The mandatory regression `D(X) = delta` (zero challenge entropy) lives in
  `tests/test_discrepancy.py` and `tests/test_cafq_soundness.py`. Keep it.
- Third-party material (e.g. the DFAR replication package) is not copied into
  the repository. Record its hash and cite file paths.
- Prior-art entries state how each fact was obtained: read in full, abstract
  only, or not accessed.

## Commands

```
python -m pytest                       # full suite, ~1 min
python -m pytest tests/test_field.py   # exhaustive GF(2^8)
python tools/run_benchmarks.py
```
