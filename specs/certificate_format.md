# Certificate format, version 0.1

One JSON object per in-scope fault, plus one for the fault-free program
(`site_id = "fault-free"`). Stored by `tools/fault_site_manifest.py` under
`data/certificates/<program>.json` together with the program and the checker
report. All values are produced by execution.

| Field | Meaning |
|---|---|
| `version` | `"0.1"` |
| `program_sha256` | SHA-256 of the canonical JSON of the program (sorted keys, no spaces) |
| `ir_or_isa` | `"toy-ir-v1"` |
| `compiler_and_flags` | `"not-applicable"` (no compilation at this level) |
| `fault_model` | `single-dynamic-instruction-{skip,zero,bitflip}` or `fault-free` |
| `observation_model` | `"output-registers-and-detection-status"` |
| `challenge_model` | `fresh-hidden-uniform-GF<q>` |
| `site_id` | `<kind>@<instruction index>[.b<bit>]` |
| `fault` | `{kind, site, bit}` or `null` |
| `region` | Region tag of the instruction (`data`, `diff`, `check`, `marshal`) |
| `classification` | `benign`, `covered`, `bypass`, `unknown` |
| `wrong_output_possible` | `false` if `W ≡ 0`; `true` otherwise; `null` for benign |
| `discrepancy_polynomial` | Reduced `g_f` as `[[coeff, [[var, exp], …]], …]`, or `null` |
| `discrepancy_polynomial_text` | Human-readable form of the same |
| `degree_bound` | Certified maximum number of challenges (out of `q`) for which a wrong result is undetected, for any state. Equals the exact count when `quotient.exact_roots` is set |
| `preconditions` | Always `[]` in v0.1: every claim holds for all states |
| `witness` | `{type: linear, degrees, matrix}`, `{type: unit, degrees, lambda}`, `{type: bypass-point, point}`, or `{type: wrongness-identically-zero}` |
| `quotient` | `{shift_k, u, h, h_text, exact_roots, naive_degree}` for covered faults with `W ≢ 0` |
| `class_keys` | Class identifier at levels `L1..L4` |
| `flags` | `status_changed`, `status_depends_on_state` |
| `reason` | Free text for bypass / unknown |
| `proof_artifact` | `<certificate file>#<site_id>` |
| `checker_result` | `pass`, `fail`, `not-checked` |

## Checker obligations

See `specs/cafq_semantics.md` §7 and the module docstring of
`src/cafq/checker.py`. A certificate set is accepted only if every
certificate passes, the manifest is complete with no extras or duplicates,
and every class at every level is sound.

## Not in v0.1

Preconditions on states, multi-fault certificates, ISA-level sites, compiler
metadata, and any claim about ineffective-fault leakage.
