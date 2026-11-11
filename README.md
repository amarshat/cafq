# CAFQ — Algebraic Rejection under test and Certified Algebraic Fault Quotients

**Research-only. Private. Nothing here is a proven cryptographic construction,
a standards-conformant KEM, or production code.**

Two tracks, from the work package of 10 Nov 2026:

1. **Algebraic Rejection (H-AR)** — a comparison-free decapsulation rule that
   feeds a polynomial discrepancy into the KDF. Treated as a hypothesis to
   falsify. **Result: refuted as specified** (see `reports/phase1_toy_findings.md`).
2. **CAFQ** — a certifying algorithm that classifies every single fault in a
   small arithmetic IR as benign / covered / bypass / unknown, attaches a
   checkable algebraic witness, and groups covered faults into classes that
   provably share a detection bound. **Result: sound on the toy IR, with a
   measured reduction over exact fault collapsing; novelty not established**
   (see `reports/phase2_cafq_results.md`).

Start with `reports/final_research_assessment.md`.

## Layout

| Path | Content |
|---|---|
| `reports/` | Phase 0/1/2 reports and the go/no-go assessment |
| `research/` | Novelty matrix, threat model, counterexamples, proof obligations, decision log |
| `specs/` | Field and discrepancy, CAFQ semantics and theorems, certificate format, KEM games |
| `src/toy/` | GF(2^8), discrepancy, toy FO / H-AR / DFAR KEM, fault hooks, attacks |
| `src/cafq/` | IR, circuits, analyzer (untrusted), checker (trusted, stdlib only) |
| `tests/` | 139 tests: exhaustive field and challenge checks, attacks, brute-force soundness, certificate tampering |
| `tools/` | Report, manifest and benchmark generators |
| `data/` | Generated matrices, benchmarks, certificates, test transcripts |

## Reproduce

```
pip install pytest==9.2.0          # only dependency; Python 3.13.18 was used
python -m pytest                   # about 1 minute
python tools/phase1_report.py      # regenerates data/phase1_fault_matrix.md
python tools/run_benchmarks.py     # regenerates data/phase2_benchmarks.{json,md}
python tools/fault_site_manifest.py polymul_karatsuba2
```

## Claims discipline

"Exhaustive" always names the exact domain. "Proved" is used only for the
short theorems in `specs/cafq_semantics.md`, whose proofs are written out and
whose instances are brute-force checked; they are not machine-checked.
Everything else is "observed", "hypothesised", "refuted" or "blocked".
