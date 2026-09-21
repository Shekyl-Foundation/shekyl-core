# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# DRS-E2 register extractor (RD-Q6): the CSR-3a register as JSON, for the
# Rust grader in `shekyl-chain-ingest::grader`.
#
# The register is prose (`CONSENSUS_STORE_RECONCILIATION.md` §5.4.1); the
# grader takes typed states. This script is the one place the two meet, and
# it performs NO parsing of its own: it imports `check_conformance_coverage`
# — the gate CI already runs over the same two documents — and serializes
# what that gate derived. So the E2 denominator is the gate's, never a
# figure hand-copied into a fixture (RD-Q6; `drs_artifact.py`'s discipline:
# the artifact carries its schema version and refuses a wrong one).
#
# Output (`--out PATH`, or stdout):
#
#   {
#     "schema_version": "shekyl_e2_register_v1",
#     "rows": [{"id": "CEN-A1", "state": "CHECKED-CONFORMANT"}, ...],   # recorded, sorted by id
#     "unrecorded_ratified": ["CEN-..", ...]                            # ratified, no record = UNREVIEWED by absence
#   }
#
# Exit 2 when the gate itself would refuse the documents (a register the
# gate cannot read is not one this script may summarize); 0 otherwise.
# `--selftest` re-derives the tally from the emitted JSON and checks it
# against the gate's, so the serialization cannot drift from the parse.

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_conformance_coverage as gate  # noqa: E402

SCHEMA = "shekyl_e2_register_v1"


def derive() -> dict | None:
    failures: list[str] = []
    census_lines = gate.read(gate.CENSUS, failures)
    register_lines = gate.read(gate.REGISTER, failures)
    if census_lines is None or register_lines is None:
        for f in failures:
            print(f, file=sys.stderr)
        return None
    ratified = gate.census_ratified(census_lines, failures)
    recorded, states = gate.register_recorded(register_lines, failures)
    gate.check_tally("\n".join(register_lines), states, failures)
    if failures:
        for f in failures:
            print(f, file=sys.stderr)
        return None
    rows = [{"id": rid, "state": states[rid]} for rid in sorted(recorded)]
    return {
        "schema_version": SCHEMA,
        "rows": rows,
        "unrecorded_ratified": sorted(ratified - recorded),
    }


def main(argv: list[str]) -> int:
    doc = derive()
    if doc is None:
        print("export_conformance_register: the coverage gate refuses the documents", file=sys.stderr)
        return 2
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    out = None
    for i, a in enumerate(argv):
        if a == "--out" and i + 1 < len(argv):
            out = argv[i + 1]
    if out:
        Path(out).write_text(text, encoding="utf-8")
        tally = Counter(r["state"] for r in doc["rows"])
        print(
            f"export_conformance_register: {len(doc['rows'])} rows "
            f"({', '.join(f'{tally[s]} {s}' for s in gate.STATES)}), "
            f"{len(doc['unrecorded_ratified'])} ratified without record → {out}"
        )
    else:
        sys.stdout.write(text)
    return 0


def _selftest() -> int:
    doc = derive()
    if doc is None:
        print("selftest: derive() refused", file=sys.stderr)
        return 1
    failures: list[str] = []
    if doc["schema_version"] != SCHEMA:
        failures.append("schema_version drifted")
    ids = [r["id"] for r in doc["rows"]]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        failures.append("rows are not sorted and unique by id")
    bad_states = {r["state"] for r in doc["rows"]} - set(gate.STATES)
    if bad_states:
        failures.append(f"states outside the vocabulary: {sorted(bad_states)}")
    # The serialized tally is the gate's tally.
    reg_failures: list[str] = []
    register_lines = gate.read(gate.REGISTER, reg_failures)
    _, states = gate.register_recorded(register_lines, reg_failures)
    if Counter(r["state"] for r in doc["rows"]) != Counter(states.values()):
        failures.append("emitted tally differs from the gate's derived tally")
    if not doc["rows"]:
        failures.append("no rows: the register parsed to nothing (rule 47)")
    if failures:
        for f in failures:
            print(f"selftest: {f}", file=sys.stderr)
        return 1
    print(f"export_conformance_register selftest: {len(doc['rows'])} rows, tally equals the gate's")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit(main(sys.argv[1:]))
