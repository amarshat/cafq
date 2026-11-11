"""Glue: analyze -> serialise -> independent check -> annotate."""
from __future__ import annotations

import json

from . import checker
from .analyzer import Analysis, analyze
from .ir import FAULT_KINDS, Program


def certify(prog: Program, kinds=FAULT_KINDS, seed: int = 0) -> tuple[Analysis, dict]:
    """Run the analyzer, pass everything through JSON (so the checker sees
    only serialised data), run the checker and record its verdicts."""
    analysis = analyze(prog, kinds, seed)
    wire_prog = json.loads(json.dumps(prog.to_json()))
    wire_certs = json.loads(json.dumps(analysis.certificates))
    report = checker.check(wire_prog, wire_certs, kinds)
    for cert in analysis.certificates:
        verdict = report["results"].get(cert["site_id"], "fail: not checked")
        cert["checker_result"] = "pass" if verdict == "pass" else "fail"
    return analysis, report
