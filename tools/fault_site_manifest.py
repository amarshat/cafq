#!/usr/bin/env python3
"""Write the full certificate set and site-coverage manifest for one circuit.

    python tools/fault_site_manifest.py polymul_karatsuba2
    python tools/fault_site_manifest.py ar_discrepancy 4

Outputs data/certificates/<program>.json (program, every certificate, checker
report) and prints the manifest. Every in-scope fault appears exactly once;
the checker independently confirms that.
"""
import json
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from cafq import circuits  # noqa: E402
from cafq.pipeline import certify  # noqa: E402


def manifest(analysis) -> dict:
    rows = Counter()
    for c in analysis.certificates:
        if c["fault"] is None:
            continue
        cls = c["classification"]
        if cls == "covered" and c["wrong_output_possible"] is False:
            cls = "covered(no wrong output; status may change)"
        rows[(c["region"], c["fault"]["kind"], cls)] += 1
    return {"|".join(k): v for k, v in sorted(rows.items())}


def main(argv):
    name, args = argv[0], [int(a) for a in argv[1:]]
    prog = circuits.ALL_BUILDERS[name](*args)
    analysis, report = certify(prog)
    outdir = ROOT / "data" / "certificates"
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{prog.name}.json"
    rel = str(path.relative_to(ROOT))
    for c in analysis.certificates:
        c["proof_artifact"] = f"{rel}#{c['site_id']}"
    doc = {
        "program": prog.to_json(), "program_sha256": prog.sha256(),
        "fault_kinds": ["skip", "zero", "bitflip"],
        "counts": analysis.counts(), "manifest": manifest(analysis),
        "checker": {"ok": report["ok"], "errors": report["errors"],
                    "counts": report["counts"],
                    "in_scope_faults": report["in_scope_faults"]},
        "certificates": analysis.certificates,
    }
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"{prog.name}  sha256={prog.sha256()}")
    print(f"in-scope faults: {report['in_scope_faults']}  checker ok: {report['ok']}")
    for k, v in doc["manifest"].items():
        print(f"  {v:5d}  {k}")
    print(f"wrote {rel}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
