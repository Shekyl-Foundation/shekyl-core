#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Gate the AFC-1 forcing register (docs/design/archival_forcing_cells.tsv).

Four legs, each able to fail:

  1. SHAPE      — every data row has 6 fields and a known `half`.
  2. DENOMINATOR— the table set equals the X(LMDB_ARCHIVAL_...) X-macro's,
                  as a set difference in BOTH directions, with duplicate
                  macro entries rejected, and each table carries exactly two
                  cells (apply + revert).
  3. DISPOSITION— every cell is FORCED-BY:<event> or EXCLUDED:<reason>, each
                  with a NON-EMPTY event or reason after the prefix.
  4. ANCHORS    — every `site` line still contains its row's `symbol`.

Leg 4 is the reason this file exists. The register's whole value is that its
citations resolve; line anchors drift with every edit to db_lmdb.cpp, and a
register of stale anchors is worse than no register because it reads as
checked.

`symbol` is a dedicated typed column precisely so this leg cannot be
satisfied by accident. The first version of this gate matched any 8+
character lowercase word taken from the free-text `note`, and the
`archival_attestation_witness` row passed on the generic word "template"
appearing in a comment — a citation that resolved to prose, not to code,
while reading as checked. Matching prose is a defect generator: the note is
edited for readability and the check silently follows it. The column is the
invariant; the note is commentary.

Absence of a signal is first evidence the subject moved (rule 47), so leg 2
asserts the macro was actually found rather than treating an empty parse as
agreement.
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
        if len(r) != 6:
            errors += fail(f"row has {len(r)} fields, expected 6: {r[:2]}")
        elif r[1] not in HALVES:
            errors += fail(f"unknown half {r[1]!r} on {r[0]}")
    if errors:
        return errors

    # Leg 2 — denominator against the X-macro, both directions.
    #
    # Extraction is deliberately IDENTICAL to check_lmdb_schema_coverage.py's:
    # scoped to the SHEKYL_LMDB_TABLES macro body, digits allowed in the table
    # name, closing paren required. Two gates pinning "the same" set with
    # independently written parsers is how they agree by construction today and
    # diverge silently later. A looser parser here (no digits) would MISS a
    # future table like `archival_r2_market`; it would then be absent from both
    # sides of the set difference, and this gate would go GREEN over a table
    # nothing covers -- §7.1.1's own hazard reappearing through its fix.
    text = XMACRO_SRC.read_text()
    body = re.search(r"^#define SHEKYL_LMDB_TABLES\(X\)(.*?)^\s*$", text, re.S | re.M)
    if not body:
        return fail(
            "SHEKYL_LMDB_TABLES macro not found in db_lmdb.cpp — it moved or "
            "was renamed. This is a broken run, not agreement (rule 47)."
        )
    macro_names = [
        t
        for t in re.findall(r'X\([A-Z0-9_]+,\s*"([a-z0-9_]+)"\)', body.group(1))
        if t.startswith("archival_")
    ]
    # Parse to a LIST first: collapsing straight into a set would hide a
    # duplicated X() entry, and both the set difference and the per-table
    # half count would stay green over a macro that names a table twice.
    for name in sorted({n for n in macro_names if macro_names.count(n) > 1}):
        errors += fail(f"SHEKYL_LMDB_TABLES names {name} more than once")
    xm = set(macro_names)
    if not xm:
        return fail(
            "found no archival_* entries in SHEKYL_LMDB_TABLES — the naming "
            "changed. This is a broken run, not agreement (rule 47)."
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

    # Leg 3 — disposition vocabulary, and a non-empty payload after it.
    # A bare "FORCED-BY:" would otherwise satisfy the prefix while naming no
    # event, which is an unresolved cell wearing a resolved cell's label.
    for r in rows:
        for prefix in ("FORCED-BY:", "EXCLUDED:"):
            if r[2].startswith(prefix):
                if not r[2][len(prefix):].strip():
                    errors += fail(
                        f"{r[0]}/{r[1]}: disposition {r[2]!r} names no "
                        f"{'event' if prefix == 'FORCED-BY:' else 'reason'}"
                    )
                break
        else:
            errors += fail(f"{r[0]}/{r[1]}: disposition {r[2]!r} is neither FORCED-BY nor EXCLUDED")

    # Leg 4 — anchors still contain the symbol their row names.
    cache = {k: v.read_text().splitlines() for k, v in SOURCES.items() if v.exists()}
    for r in rows:
        table, half, _, site, symbol, _note = r
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
        if not symbol.strip():
            errors += fail(f"{table}/{half}: empty symbol column")
            continue
        text = lines[lineno - 1]
        if symbol not in text:
            errors += fail(
                f"{table}/{half}: anchor {site} no longer contains {symbol!r} — "
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
