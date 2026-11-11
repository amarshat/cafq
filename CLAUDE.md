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
- `src/cafq/structural_checker.py` is trusted too: standard library plus
  `cafq.checker` only. It derives class membership itself; certificates must
  not carry class fields that it relies on.
- `src/cafq/analyzer.py` + `checker.py` are the preserved per-fault BASELINE.
  Do not change their behaviour or the fault model to improve a comparison.
  Any refactor must leave certificates byte-identical.
- A structural shortcut is only valid at fault-linear sites (taint check).
  The counterexample circuits `square_check` and `nonlinear_trap` guard this.
- A class certificate is a statement about detection conditional on a wrong
  output. Never describe it as security or observation equivalence.
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
python tools/run_structural_benchmarks.py   # A / A' / B / C comparison, ~8 min
python tools/two_fault_study.py             # ~70 s
python tools/compiled_kernel_study.py       # needs gcc, clang, unicorn; ~1 min
```
