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
#
# Two checks keep the emitted JSON honest, neither of which re-runs this
# script's own derivation as its oracle:
#
# - `--selftest` serializes the document to text and parses THAT back,
#   asserting the shape the Rust grader reads (`grader::Register`): the
#   schema id, sorted unique ids, states inside the gate's vocabulary,
#   and at least one row (rule 47).
# - `--check-fixture PATH` diffs the emitted text against the committed
#   copy the Rust grader's tests parse (`rust/shekyl-chain-ingest/
#   fixtures/conformance_register.json`), so a key rename on either side
#   goes red in CI, not at the end of a replay. Regenerate the fixture
#   with `--out` when the register changes.

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
    text = render(doc)
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


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# The keys `grader::Register` / `RegisterRow` deserialize. A rename on
# either side must fail here and in `--check-fixture`, never in a replay.
REGISTER_KEYS = {"schema_version", "rows", "unrecorded_ratified"}
ROW_KEYS = {"id", "state"}


def _selftest() -> int:
    doc = derive()
    if doc is None:
        print("selftest: derive() refused", file=sys.stderr)
        return 1
    # The oracle is the serialized text, parsed back — what the grader reads.
    emitted = json.loads(render(doc))
    failures: list[str] = []
    if set(emitted) != REGISTER_KEYS:
        failures.append(f"top-level keys {sorted(emitted)} are not {sorted(REGISTER_KEYS)}")
    if emitted.get("schema_version") != SCHEMA:
        failures.append("schema_version drifted")
    rows = emitted.get("rows", [])
    if not rows:
        failures.append("no rows: the register parsed to nothing (rule 47)")
    bad_rows = [r for r in rows if set(r) != ROW_KEYS]
    if bad_rows:
        failures.append(f"row keys drifted: {bad_rows[0]}")
    ids = [r.get("id") for r in rows]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        failures.append("rows are not sorted and unique by id")
    bad_ids = [i for i in ids if not isinstance(i, str) or not i.startswith("CEN-")]
    if bad_ids:
        failures.append(f"ids outside the census's namespace: {bad_ids[:3]}")
    bad_states = {r.get("state") for r in rows} - set(gate.STATES)
    if bad_states:
        failures.append(f"states outside the vocabulary: {sorted(map(str, bad_states))}")
    unrecorded = emitted.get("unrecorded_ratified", [])
    if unrecorded != sorted(unrecorded) or set(unrecorded) & set(ids):
        failures.append("unrecorded_ratified is not sorted, or names a recorded row")
    if failures:
        for f in failures:
            print(f"selftest: {f}", file=sys.stderr)
        return 1
    print(f"export_conformance_register selftest: {len(rows)} rows in the grader's shape")
    return 0


def _check_fixture(path: str) -> int:
    doc = derive()
    if doc is None:
        print("check-fixture: derive() refused", file=sys.stderr)
        return 1
    committed = Path(path)
    if not committed.is_file():
        print(f"check-fixture: {path} is missing — the gate's subject does not exist", file=sys.stderr)
        return 1
    if committed.read_text(encoding="utf-8") != render(doc):
        print(
            f"check-fixture: {path} differs from the register the extractor derives now;\n"
            f"  regenerate it: python3 scripts/ci/export_conformance_register.py --out {path}",
            file=sys.stderr,
        )
        return 1
    print(f"export_conformance_register check-fixture: {path} matches ({len(doc['rows'])} rows)")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    if "--check-fixture" in sys.argv:
        i = sys.argv.index("--check-fixture")
        if i + 1 >= len(sys.argv):
            print("--check-fixture needs a path", file=sys.stderr)
            sys.exit(2)
        sys.exit(_check_fixture(sys.argv[i + 1]))
    sys.exit(main(sys.argv[1:]))
