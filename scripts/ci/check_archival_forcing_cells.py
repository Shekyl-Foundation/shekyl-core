#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Gate the AFC-1 forcing register (docs/design/archival_forcing_cells.tsv).

Four legs, each able to fail:

  1. SHAPE      — every data row has 5 fields and a known `half`.
  2. DENOMINATOR— the table set equals the X(LMDB_ARCHIVAL_...) X-macro's,
                  as a set difference in BOTH directions, and each table
                  carries exactly two cells (apply + revert).
  3. DISPOSITION— every cell is FORCED-BY:<event> or EXCLUDED:<reason>.
  4. ANCHORS    — every `site` line still contains the symbol its row names.

Leg 4 is the reason this file exists. The register's whole value is that its
citations resolve; line anchors drift with every edit to db_lmdb.cpp, and a
register of stale anchors is worse than no register because it reads as
checked. Absence of a signal here is first evidence the subject moved
(rule 47), so leg 2 asserts the X-macro was actually found rather than
treating an empty parse as agreement.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TSV = ROOT / "docs/design/archival_forcing_cells.tsv"
XMACRO_SRC = ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp"
SOURCES = {
    "db_lmdb.cpp": ROOT / "src/blockchain_db/lmdb/db_lmdb.cpp",
    "blockchain_db.cpp": ROOT / "src/blockchain_db/blockchain_db.cpp",
    "blockchain.cpp": ROOT / "src/cryptonote_core/blockchain.cpp",
}
HALVES = ("apply", "revert")


def fail(msg):
    print(f"FAIL: {msg}")
    return 1


def main():
    errors = 0

    if not TSV.exists():
        return fail(f"{TSV.relative_to(ROOT)} is missing")

    rows = []
    for raw in TSV.read_text().splitlines():
        if not raw or raw.startswith("#") or raw.startswith("table\t"):
            continue
        rows.append(raw.split("\t"))

    # Leg 1 — shape.
    for r in rows:
        if len(r) != 5:
            errors += fail(f"row has {len(r)} fields, expected 5: {r[:2]}")
        elif r[1] not in HALVES:
            errors += fail(f"unknown half {r[1]!r} on {r[0]}")
    if errors:
        return errors

    # Leg 2 — denominator against the X-macro, both directions.
    xm = set(
        re.findall(r'X\(LMDB_ARCHIVAL_[A-Z_]+,\s*"([a-z_]+)"', XMACRO_SRC.read_text())
    )
    if not xm:
        return fail(
            "found no X(LMDB_ARCHIVAL_...) entries — the macro moved or was "
            "renamed. This is a broken run, not agreement (rule 47)."
        )
    listed = {r[0] for r in rows}
    for missing in sorted(xm - listed):
        errors += fail(f"table {missing} is in the X-macro but has no register row")
    for extra in sorted(listed - xm):
        errors += fail(f"table {extra} is in the register but not in the X-macro")

    for t in sorted(listed):
        halves = sorted(r[1] for r in rows if r[0] == t)
        if halves != sorted(HALVES):
            errors += fail(f"table {t} has halves {halves}, expected apply+revert")

    # Leg 3 — disposition vocabulary.
    for r in rows:
        if not (r[2].startswith("FORCED-BY:") or r[2].startswith("EXCLUDED:")):
            errors += fail(f"{r[0]}/{r[1]}: disposition {r[2]!r} is neither FORCED-BY nor EXCLUDED")

    # Leg 4 — anchors still contain the symbol their row names.
    cache = {k: v.read_text().splitlines() for k, v in SOURCES.items() if v.exists()}
    for r in rows:
        table, half, _, site, note = r
        m = re.match(r"([\w.]+):(\d+)$", site)
        if not m:
            errors += fail(f"{table}/{half}: site {site!r} is not <file>:<line>")
            continue
        fname, lineno = m.group(1), int(m.group(2))
        if fname not in cache:
            errors += fail(f"{table}/{half}: unknown source file {fname}")
            continue
        lines = cache[fname]
        if not (1 <= lineno <= len(lines)):
            errors += fail(f"{table}/{half}: {site} is past end of file ({len(lines)} lines)")
            continue
        text = lines[lineno - 1]
        syms = [w for w in re.findall(r"[a-z_]{8,}", note) if w != "archival"]
        if table not in text and not any(s in text for s in syms):
            errors += fail(
                f"{table}/{half}: anchor {site} no longer contains its symbol — "
                f"line reads: {text.strip()[:80]!r}"
            )

    if errors:
        print(f"\n{errors} problem(s) in the AFC-1 forcing register.")
        return 1

    excluded = sum(1 for r in rows if r[2].startswith("EXCLUDED:"))
    print(
        f"OK: AFC-1 register — {len(rows)} cells over {len(listed)} tables "
        f"({len(rows) - excluded} FORCED-BY, {excluded} EXCLUDED); "
        f"table set matches the X-macro; all anchors resolve."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
