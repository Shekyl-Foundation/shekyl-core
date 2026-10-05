#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Hold DAEMON_REDB_STORE.md §7.5 (the DRS-E6 surface partition) to the
# consensus rule census it claims to be derived from.
#
# §7.5 says which census rows arrive in Rust with a store surface (E1…E5) and
# which have no surface and are DRS-E6's own work. The tables there are a dated
# snapshot of a derivation over CONSENSUS_RULE_CENSUS.md §4: the flag column
# (C/P), the bucket column (b), and whether a row's `site(s)` cell cites a file
# under `src/blockchain_db/`. The census moves — a row is re-bucketed, gains or
# loses a store citation, a new row is minted — and every such move changes
# the schedule §7.5 states and the denominators its completeness gate divides
# by. Nothing else re-reads the tables, so this gate does: it re-derives every
# figure from the census and fails on any difference, printing the derivation.
#
# What is checked (all of it against the census, none of it against prose):
#
#   table 1 — rows by flag × surface × bucket, and the totals;
#   table 2 — the live (bucket ≠ 3) surface-bound consensus rows, by id and
#             bucket: exactly that set, no more, no fewer;
#   table 3 — the surface-free consensus rows per census subsystem, by bucket,
#             and exactly the subsystems that have any;
#   the derived-totals sentence (`= E = **B bound + F free**`);
#   every `N of M live|enforced consensus rows` phrase in the DRS doc;
#   the bound/free regex, quoted verbatim in §7.5 so the doc and this gate
#   cannot disagree about what "surface-bound" means.
#
# Rule 47: the gate asserts its own subject. An empty census, a §4 table whose
# header lacks the columns the derivation reads (every table's own header —
# §4.J carries three under one heading), a header in either document not
# followed by its GFM delimiter row of the same width (Markdown renders no
# table, so the rows under it are not on the page — rule 94 §7), a §4 row
# whose id cell is not a well-formed `CEN-` id or that is too short for its
# header, a census with zero bound rows, an unterminated code fence in either
# document (it would hide the rest of the file from the parse), a DRS doc with
# no §7.5 or with a table missing, a table-2 row that names no increment —
# each is a missing subject and a failure, never a vacuous pass. `--selftest`
# proves each refusal fires and reports how many did.
#
# Rule 46: the verdict is the process exit code; nothing here pipes it.

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _census import (  # noqa: E402
    BOUND_RE_TEXT,
    FLAGS,
    H2,
    ROW_ID,
    Refused,
    Row,
    parse_census,
    require_delimiter,
    row_cells,
    unfenced,
)

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CENSUS = REPO / "docs" / "design" / "CONSENSUS_RULE_CENSUS.md"
DEFAULT_DOC = REPO / "docs" / "design" / "DAEMON_REDB_STORE.md"

# Census parsing — `Row`, `Refused`, `parse_census`, the bound regex and the
# GFM table-shape helpers — is `_census.py`, shared with
# `check_chain_rules_coverage.py` so the two gates divide by one denominator.

DOC_SECTION_START = re.compile(r"^### 7\.5\b")
DOC_SECTION_END = re.compile(r"^(### |## )")  # a #### stays inside §7.5

TABLE1_HEADER = ["flag", "surface", "b1", "b2", "b3", "b4", "total"]
TABLE2_HEADER = ["row", "b", "store site (per census)", "arrives with"]
TABLE3_HEADER = ["subsystem", "b1", "b2", "b4", "total"]  # + a free-text column

# Table 2's `arrives with` cell names the increment a live surface-bound row
# ports with: `**E<n> S-<SURFACE>**` (the surface's increment) or
# `**E<n> increment <k>**` (a mechanism increment such as E1's 2.5). Which
# increment is a ruling the doc owns and the gate does not second-guess; that
# the cell names one is the subject — a live row that "arrives nowhere" is the
# hole the table exists to close.
ARRIVES_RE = re.compile(r"\*\*E\d+ (?:S-[A-Z][A-Z0-9-]*|increment \d+(?:\.\d+)?)\*\*")

TOTALS_RE = re.compile(
    r"\(bucket ≠ 3\) = (\d+) = \*\*(\d+) bound \+ (\d+) free\*\*"
)
# The two headline phrases, in the one shape the gate reads. A restatement in
# another shape is not gated, so the doc uses these and only these.
N_OF_M_RE = re.compile(r"\b(\d+) of (\d+) (?:live|enforced) consensus rows\b")
BOUND_OF_ALL_RE = re.compile(r"\b(\d+) of (\d+) census rows\b")
SUBSYSTEM_TOKEN = re.compile(r"^\**(4\.[A-Z])\b")
# The decision log records what was true at a dated entry; its figures are
# records-was and stay when the census moves (rule 95). Everything else in
# the doc asserts the present and is scanned.
DECISION_LOG = re.compile(r"^## 15\. ")


@dataclass(frozen=True)
class Derived:
    table1: dict[tuple[str, str], list[int]]  # (flag, surface) -> [b1..b4]
    live_bound: dict[str, int]  # row id -> bucket (consensus, bucket != 3, bound)
    free_by_subsystem: dict[str, list[int]]  # subsystem -> [b1, b2, b4]
    enforced: int
    bound_enforced: int
    free_enforced: int


def derive(rows: list[Row]) -> Derived:
    table1 = {(f, s): [0, 0, 0, 0] for f in FLAGS for s in ("bound", "free")}
    for r in rows:
        table1[(r.flag, "bound" if r.bound else "free")][r.bucket - 1] += 1
    consensus_live = [r for r in rows if r.flag == "C" and r.bucket != 3]
    live_bound = {r.id: r.bucket for r in consensus_live if r.bound}
    free: dict[str, list[int]] = {}
    for r in consensus_live:
        if r.bound:
            continue
        slot = free.setdefault(r.subsystem, [0, 0, 0])
        slot[{1: 0, 2: 1, 4: 2}[r.bucket]] += 1
    return Derived(
        table1=table1,
        live_bound=live_bound,
        free_by_subsystem=free,
        enforced=len(consensus_live),
        bound_enforced=len(live_bound),
        free_enforced=len(consensus_live) - len(live_bound),
    )


# --------------------------------------------------------------------------
# DRS doc side
# --------------------------------------------------------------------------


def section_7_5(text: str) -> tuple[list[str], int]:
    """The lines of §7.5 and the 1-based line number where it starts."""
    lines, fenced = unfenced(text, "DRS doc")
    start = None
    for n, line in enumerate(lines):
        if n not in fenced and DOC_SECTION_START.match(line):
            start = n
            break
    if start is None:
        raise Refused("DRS doc: no `### 7.5` section — subject missing")
    body: list[str] = []
    for n in range(start + 1, len(lines)):
        if n not in fenced and DOC_SECTION_END.match(lines[n]):
            break
        body.append("" if n in fenced else lines[n])
    return body, start + 1


def live_text(text: str) -> str:
    """The DRS doc with fenced code and the §15 decision log removed."""
    lines, fenced = unfenced(text, "DRS doc")
    out: list[str] = []
    in_log = False
    for n, line in enumerate(lines):
        if n in fenced:
            continue
        if DECISION_LOG.match(line):
            in_log = True
        elif in_log and H2.match(line):
            in_log = False
        if not in_log:
            out.append(line)
    return "\n".join(out)


def find_table(body: list[str], header: list[str], label: str) -> list[list[str]]:
    """Rows of the first table in `body` whose header starts with `header`.

    The header must be followed by its GFM delimiter row, or the "table" is a
    paragraph and its rows are not a subject. Past the delimiter every `|`
    line is a data row; a second separator-looking line is a malformed row
    and fails the table's checks rather than being skipped.
    """
    want = [h.lower() for h in header]
    where = f"DRS §7.5 {label}"
    i = 0
    while i < len(body):
        line = body[i]
        if line.startswith("|"):
            cells = row_cells(line)
            if [c.lower() for c in cells[: len(want)]] == want:
                require_delimiter(body, i, len(cells), where)
                rows: list[list[str]] = []
                j = i + 2
                while j < len(body) and body[j].startswith("|"):
                    rows.append(row_cells(body[j]))
                    j += 1
                if not rows:
                    raise Refused(f"{where}: header present but no rows")
                return rows
        i += 1
    raise Refused(f"{where}: no table with header {header!r} — subject missing")


def _int(cell: str, where: str) -> int:
    t = cell.strip().strip("*")
    if not re.fullmatch(r"\d+", t):
        raise Refused(f"{where}: {cell!r} is not an integer")
    return int(t)


def check_table1(body: list[str], d: Derived, errors: list[str]) -> None:
    rows = find_table(body, TABLE1_HEADER, "table 1")
    seen: set[tuple[str, str]] = set()
    for cells in rows:
        if len(cells) < 7:
            errors.append(f"table 1: row {cells!r} has fewer than 7 cells")
            continue
        key = (cells[0].strip("*"), cells[1].strip("*"))
        if key not in d.table1:
            errors.append(f"table 1: unknown (flag, surface) {key!r}")
            continue
        if key in seen:
            errors.append(f"table 1: {key[0]}/{key[1]} listed twice")
        seen.add(key)
        got = [_int(c, f"table 1 {key}") for c in cells[2:6]]
        total = _int(cells[6], f"table 1 {key} total")
        want = d.table1[key]
        if got != want or total != sum(want):
            errors.append(
                f"table 1 {key[0]}/{key[1]}: doc says b1..b4={got} total={total}, "
                f"census derives {want} total={sum(want)}"
            )
    missing = set(d.table1) - seen
    if missing:
        errors.append(f"table 1: rows missing for {sorted(missing)}")


def check_table2(body: list[str], d: Derived, errors: list[str]) -> None:
    rows = find_table(body, TABLE2_HEADER, "table 2")
    doc: dict[str, int] = {}
    for cells in rows:
        if len(cells) < 4:
            errors.append(f"table 2: row {cells!r} has fewer than 4 cells")
            continue
        m = ROW_ID.match(cells[0])
        if not m:
            errors.append(f"table 2: first cell {cells[0]!r} is not a CEN- id")
            continue
        rid = m.group(1)
        if rid in doc:
            errors.append(f"table 2: {rid} listed twice")
        doc[rid] = _int(cells[1], f"table 2 {rid} b")
        if not ARRIVES_RE.search(cells[3]):
            errors.append(
                f"table 2 {rid}: `arrives with` {cells[3]!r} names no increment "
                "(`**E<n> S-<SURFACE>**` or `**E<n> increment <k>**`) — a live "
                "surface-bound row arrives somewhere"
            )
    extra = sorted(set(doc) - set(d.live_bound))
    missing = sorted(set(d.live_bound) - set(doc))
    if extra:
        errors.append(
            f"table 2 lists rows the census does not derive as live (bucket ≠ 3) "
            f"surface-bound consensus rows: {extra}"
        )
    if missing:
        errors.append(f"table 2 is missing live surface-bound consensus rows: {missing}")
    for rid in sorted(set(doc) & set(d.live_bound)):
        if doc[rid] != d.live_bound[rid]:
            errors.append(
                f"table 2 {rid}: doc bucket {doc[rid]}, census bucket {d.live_bound[rid]}"
            )


def check_table3(body: list[str], d: Derived, errors: list[str]) -> None:
    rows = find_table(body, TABLE3_HEADER, "table 3")
    doc: dict[str, list[int]] = {}
    for cells in rows:
        if len(cells) < 5:
            errors.append(f"table 3: row {cells!r} has fewer than 5 cells")
            continue
        m = SUBSYSTEM_TOKEN.match(cells[0])
        if not m:
            errors.append(f"table 3: subsystem cell {cells[0]!r} does not start with `4.X`")
            continue
        sub = m.group(1)
        if sub in doc:
            errors.append(f"table 3: {sub} listed twice")
        counts = [_int(c, f"table 3 {sub}") for c in cells[1:4]]
        total = _int(cells[4], f"table 3 {sub} total")
        if total != sum(counts):
            errors.append(f"table 3 {sub}: total {total} ≠ b1+b2+b4 = {sum(counts)}")
        doc[sub] = counts
    extra = sorted(set(doc) - set(d.free_by_subsystem))
    missing = sorted(set(d.free_by_subsystem) - set(doc))
    if extra:
        errors.append(f"table 3 lists subsystems with no surface-free consensus rows: {extra}")
    if missing:
        errors.append(f"table 3 is missing subsystems that have surface-free rows: {missing}")
    for sub in sorted(set(doc) & set(d.free_by_subsystem)):
        if doc[sub] != d.free_by_subsystem[sub]:
            errors.append(
                f"table 3 {sub}: doc [b1,b2,b4]={doc[sub]}, census derives "
                f"{d.free_by_subsystem[sub]}"
            )
    doc_total = sum(sum(v) for v in doc.values())
    if doc_total != d.free_enforced:
        errors.append(f"table 3 sums to {doc_total}; census derives {d.free_enforced} free rows")


def check_prose(body: list[str], full_text: str, d: Derived, errors: list[str]) -> None:
    joined = "\n".join(body)
    if f"`{BOUND_RE_TEXT}`" not in joined:
        errors.append(
            f"§7.5 does not quote the bound regex verbatim: expected the code span "
            f"`{BOUND_RE_TEXT}` — the doc and the gate would then define "
            "'surface-bound' differently"
        )
    totals = TOTALS_RE.findall(joined)
    if not totals:
        errors.append(
            "§7.5 lacks the derived-totals sentence `(bucket ≠ 3) = E = **B bound + F free**`"
        )
    for e, b, f in totals:
        got = (int(e), int(b), int(f))
        want = (d.enforced, d.bound_enforced, d.free_enforced)
        if got != want:
            errors.append(f"derived-totals sentence says {got}, census derives {want}")
    live = live_text(full_text)
    phrases = N_OF_M_RE.findall(live)
    if not phrases:
        errors.append(
            "DRS doc carries no `N of M live|enforced consensus rows` phrase outside "
            "the decision log — the headline figure is unstated or restated in a "
            "shape this gate cannot read"
        )
    for n, m in phrases:
        if (int(n), int(m)) != (d.free_enforced, d.enforced):
            errors.append(
                f"phrase `{n} of {m} … consensus rows` disagrees with the census "
                f"({d.free_enforced} of {d.enforced})"
            )
    bound_all = sum(sum(v) for (_f, s), v in d.table1.items() if s == "bound")
    total_all = sum(sum(v) for v in d.table1.values())
    bound_phrases = BOUND_OF_ALL_RE.findall(live)
    if not bound_phrases:
        errors.append("DRS doc carries no `N of M census rows` (bound of all) phrase")
    for n, m in bound_phrases:
        if (int(n), int(m)) != (bound_all, total_all):
            errors.append(
                f"phrase `{n} of {m} census rows` disagrees with the census "
                f"({bound_all} of {total_all} cite a store file)"
            )


def check(census_text: str, doc_text: str) -> list[str]:
    """All mismatches between §7.5 and the census; empty when they agree."""
    rows = parse_census(census_text)
    d = derive(rows)
    body, _start = section_7_5(doc_text)
    errors: list[str] = []
    check_table1(body, d, errors)
    check_table2(body, d, errors)
    check_table3(body, d, errors)
    check_prose(body, doc_text, d, errors)
    return errors


def describe(census_text: str) -> str:
    rows = parse_census(census_text)
    d = derive(rows)
    out = [
        f"census rows: {len(rows)}; consensus enforced (bucket ≠ 3): {d.enforced} "
        f"= {d.bound_enforced} bound + {d.free_enforced} free",
        "table 1 (flag, surface): b1 b2 b3 b4",
    ]
    for key, v in sorted(d.table1.items()):
        out.append(f"  {key[0]} {key[1]:5}: {v}")
    out.append("live bound consensus rows: " + ", ".join(sorted(d.live_bound)))
    for sub, v in sorted(d.free_by_subsystem.items()):
        out.append(f"  free {sub}: b1={v[0]} b2={v[1]} b4={v[2]}")
    return "\n".join(out)


# --------------------------------------------------------------------------
# self-test: every refusal must fire on the input built to trip it
# --------------------------------------------------------------------------

_CENSUS_OK = """\
# census

## 4. Rows

### 4.A Acceptance topology

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-A1 | parent exists | `src/cryptonote_core/blockchain.cpp:10` | C | 1 | x | y | z |
| CEN-A2 | height | `blockchain.cpp:20` | C | 2 | x | y | z |
| CEN-A3 | policy thing | `tx_pool.cpp:5` | P | 1 | x | y | z |

### 4.L Storage layer

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-L1 | key image unique | `src/blockchain_db/lmdb/db_lmdb.cpp:1432` | C | 2 | x | y | z |
| CEN-L2 | parent at h-1 | `src/blockchain_db/blockchain_db.cpp:600` | C | 3 | x | y | z |
| **CEN-L3** | bucket-4 belt | `db_lmdb.cpp:700` | C | 4 | x | y | z |

## 5. Dead surfaces

| id | rule | site(s) | C/P | b | class | evidence | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CEN-Z9 | not in §4 | `src/blockchain_db/x.cpp` | C | 1 | x | y | z |
"""

_DOC_OK = """\
# DRS

**Banner: 2 of 4 live consensus rows have no storage surface.**

## 7. Work

### 7.5 DRS-E6 — the partition

Only 3 of 6 census rows name a store file. Derived. A row is **surface-bound**
when its `site(s)` cell matches `blockchain_db|db_lmdb|src/blockchain_db|lmdb/`.

**Table 1**

| flag | surface | b1 | b2 | b3 | b4 | total |
| --- | --- | --- | --- | --- | --- | --- |
| C | bound | 0 | 1 | 1 | 1 | 3 |
| C | free | 1 | 1 | 0 | 0 | 2 |
| P | bound | 0 | 0 | 0 | 0 | 0 |
| P | free | 1 | 0 | 0 | 0 | 1 |

Consensus **enforced** (bucket ≠ 3) = 4 = **2 bound + 2 free**.

**Table 2**

| row | b | store site (per census) | arrives with |
| --- | --- | --- | --- |
| CEN-L1 | 2 | `spent_keys` | **E1 S-CHAIN-W** — belt `SI-1` |
| CEN-L3 | 4 | belt | mechanism **E1 increment 2.5**; semantics **E4 S-ARCH** |

**Table 3**

| subsystem | b1 | b2 | b4 | total | proposed slice / dependency note |
| --- | --- | --- | --- | --- | --- |
| 4.A Acceptance topology | 1 | 1 | 0 | 2 | slice 1 |

#### 7.5.3 Gate

Still inside §7.5.

### 7.6 Next

Outside.

## 15. Decision log

| date | entry |
| --- | --- |
| 2026-01-01 | at that pin, 1 of 3 live consensus rows were free and 1 of 5 census rows cited a store file — records-was, never re-derived |
"""


# A census subsection carrying two tables (§4.J's shape). The second table's
# header re-orders the read columns; a parser that inherited the first table's
# indices would read `C` as the site and `4` as the flag.
_CENSUS_TWO_TABLES = _CENSUS_OK.replace(
    "| **CEN-L3** | bucket-4 belt | `db_lmdb.cpp:700` | C | 4 | x | y | z |\n",
    "\n"
    "Second table, same subsection.\n"
    "\n"
    "| id | rule | C/P | b | site(s) | class | evidence | notes |\n"
    "| --- | --- | --- | --- | --- | --- | --- | --- |\n"
    "| **CEN-L3** | bucket-4 belt | C | 4 | `db_lmdb.cpp:700` | x | y | z |\n",
)


class _Probe:
    """Runs the self-test cases and counts the refusals that fired.

    The count is reported, not hard-coded, so the diagnostic cannot say
    "27 refusals" over 24 cases.
    """

    def __init__(self) -> None:
        self.refusals = 0

    @staticmethod
    def ok(census: str, doc: str, name: str) -> None:
        errs = check(census, doc)
        if errs:
            raise SystemExit(f"selftest {name}: expected clean, got:\n  " + "\n  ".join(errs))

    def refusal(self, census: str, doc: str, needle: str, name: str) -> None:
        try:
            errs = check(census, doc)
        except Refused as e:
            errs = [str(e)]
        if not any(needle in e for e in errs):
            raise SystemExit(
                f"selftest {name}: expected a refusal mentioning {needle!r}, got:\n  "
                + ("\n  ".join(errs) if errs else "(clean)")
            )
        self.refusals += 1


def selftest() -> None:
    p = _Probe()
    p.ok(_CENSUS_OK, _DOC_OK, "consistent pair")
    p.ok(_CENSUS_TWO_TABLES, _DOC_OK, "second table under one subsection read against its own header")

    # census moves: bucket, citation, new row
    moved = _CENSUS_OK.replace("| CEN-A2 | height | `blockchain.cpp:20` | C | 2 |", "| CEN-A2 | height | `blockchain.cpp:20` | C | 1 |")
    p.refusal(moved, _DOC_OK, "table 1 C/free", "row re-bucketed")
    p.refusal(moved, _DOC_OK, "table 3 4.A", "row re-bucketed (table 3)")
    cited = _CENSUS_OK.replace("`blockchain.cpp:20` | C | 2 |", "`src/blockchain_db/db.cpp:20` | C | 2 |")
    p.refusal(cited, _DOC_OK, "table 2 is missing", "row gains a store citation")
    p.refusal(cited, _DOC_OK, "2 of 4", "headline phrase goes stale")
    retired = _CENSUS_OK.replace("`db_lmdb.cpp:700` | C | 4 |", "`db_lmdb.cpp:700` | C | 3 |")
    p.refusal(retired, _DOC_OK, "not derive as live", "bound row retires to bucket 3")
    minted = _CENSUS_OK.replace(
        "| CEN-A3 | policy thing | `tx_pool.cpp:5` | P | 1 | x | y | z |\n",
        "| CEN-A3 | policy thing | `tx_pool.cpp:5` | P | 1 | x | y | z |\n"
        "| CEN-A4 | new | `blockchain.cpp:30` | C | 4 | x | y | z |\n",
    )
    p.refusal(minted, _DOC_OK, "table 3 4.A", "new surface-free row minted")
    # a row after the blank line that ends a table is a header-less table, not a row
    p.refusal(
        _CENSUS_OK.replace(
            "### 4.L Storage layer",
            "| CEN-A4 | new | `blockchain.cpp:30` | C | 4 | x | y | z |\n\n### 4.L Storage layer",
        ),
        _DOC_OK,
        "lacks a column",
        "a stray row outside any table is not read as a rule",
    )

    # doc drifts
    l3_row = "| CEN-L3 | 4 | belt | mechanism **E1 increment 2.5**; semantics **E4 S-ARCH** |\n"
    p.refusal(_CENSUS_OK, _DOC_OK.replace(l3_row, ""), "missing live surface-bound", "table 2 drops a row")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("| CEN-L1 | 2 |", "| CEN-L1 | 1 |"), "table 2 CEN-L1", "table 2 wrong bucket")
    # a live row must arrive at a named increment, not "later" and not nowhere
    p.refusal(_CENSUS_OK, _DOC_OK.replace(l3_row, "| CEN-L3 | 4 | belt | later, once R8b-3 names it |\n"), "names no increment", "table 2 row arrives nowhere")
    p.refusal(_CENSUS_OK, _DOC_OK.replace(l3_row, "| CEN-L3 | 4 | belt | E1 |\n"), "names no increment", "table 2 increment not in the token grammar")
    p.refusal(_CENSUS_OK, _DOC_OK.replace(l3_row, "| CEN-L3 | 4 |\n"), "fewer than 4 cells", "table 2 truncated row")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("| 4.A Acceptance topology | 1 | 1 | 0 | 2 | slice 1 |", "| 4.A Acceptance topology | 1 | 1 |"), "fewer than 5 cells", "table 3 truncated row")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("| 4.A Acceptance topology | 1 | 1 | 0 | 2 |", "| 4.A Acceptance topology | 2 | 0 | 0 | 2 |"), "table 3 4.A", "table 3 wrong split")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("= 4 = **2 bound + 2 free**", "= 4 = **3 bound + 1 free**"), "derived-totals", "totals sentence stale")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("`blockchain_db|db_lmdb|src/blockchain_db|lmdb/`", "`blockchain_db`"), "quote the bound regex", "regex not quoted")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("2 of 4 live", "3 of 4 live"), "disagrees with the census", "phrase disagrees")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("Only 3 of 6 census rows", "Only 4 of 6 census rows"), "cite a store file", "bound-of-all phrase disagrees")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("Only 3 of 6 census rows", "Only three census rows"), "no `N of M census rows`", "bound-of-all phrase absent")
    # the decision log's stale figures are records-was and are NOT read as live
    p.ok(_CENSUS_OK, _DOC_OK.replace("1 of 3 live consensus rows", "9 of 9 live consensus rows"), "decision log excluded")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("## 15. Decision log", "## 14. Not the log"), "disagrees with the census", "the same figures outside the log are read")

    # subjects missing
    p.refusal(_CENSUS_OK, _DOC_OK.replace("### 7.5", "### 7.9"), "no `### 7.5`", "no §7.5")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("| flag | surface |", "| flg | surface |"), "table 1", "table 1 header missing")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("2 of 4 live consensus rows", "two of four"), "no `N of M", "headline phrase absent")
    p.refusal("# census\n\n## 4. Rows\n\n### 4.A x\n\ntext\n\n## 5. y\n", _DOC_OK, "no §4 rows tables", "empty census")
    unbound = _CENSUS_OK.replace("src/blockchain_db/lmdb/db_lmdb.cpp:1432", "x.cpp").replace("src/blockchain_db/blockchain_db.cpp:600", "y.cpp").replace("db_lmdb.cpp:700", "z.cpp")
    p.refusal(unbound, _DOC_OK, "zero rows match", "no bound rows")
    p.refusal(_CENSUS_OK.replace("| id | rule | site(s) | C/P | b |", "| id | rule | where | C/P | b |"), _DOC_OK, "lacks a column", "census header changed")
    p.refusal(_CENSUS_OK.replace("| C | 2 | x | y | z |\n| CEN-A3", "| X | 2 | x | y | z |\n| CEN-A3"), _DOC_OK, "not one of", "flag vocabulary")
    p.refusal(_CENSUS_OK.replace("| CEN-A3 | policy thing |", "| CEN-A1 | policy thing |"), _DOC_OK, "duplicate row ids", "duplicate id")
    p.refusal(_CENSUS_OK.replace("| CEN-A2 | height |", "| CEN-A2 (see note) | height |"), _DOC_OK, "is not a `CEN-` row id", "malformed id is refused, not dropped")
    p.refusal(_CENSUS_OK.replace("| CEN-A3 | policy thing | `tx_pool.cpp:5` | P | 1 | x | y | z |", "| CEN-A3 | policy thing | `tx_pool.cpp:5` |"), _DOC_OK, "fewer than", "truncated row")
    # each table under a subsection is read against its OWN header
    p.refusal(_CENSUS_TWO_TABLES.replace("| id | rule | C/P | b | site(s) |", "| id | rule | C/P | bucket | site(s) |"), _DOC_OK, "lacks a column", "second table's header is checked, not inherited")
    # an unterminated fence hides everything after it: refused at every entry
    p.refusal(_CENSUS_OK.replace("### 4.L Storage layer", "```\n### 4.L Storage layer"), _DOC_OK, "code fence is left open", "open fence in the census")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("**Table 2**", "```\n**Table 2**"), "code fence is left open", "open fence in the DRS doc")
    p.refusal(_CENSUS_OK, _DOC_OK.replace("| C | free | 1 | 1 | 0 | 0 | 2 |\n", "| C | free | 1 | 1 | 0 | 0 | 2 |\n| C | free | 1 | 1 | 0 | 0 | 2 |\n"), "listed twice", "table 1 duplicate row")

    # a header is a table only with its GFM delimiter row directly beneath, of the
    # same width — otherwise Markdown renders a paragraph and the rows are not on
    # the page. Both documents, and a second separator-looking line is data.
    t2_delim = "| row | b | store site (per census) | arrives with |\n| --- | --- | --- | --- |\n"
    p.refusal(_CENSUS_OK, _DOC_OK.replace(t2_delim, "| row | b | store site (per census) | arrives with |\n"), "not followed by a GFM delimiter", "DRS table header without its delimiter row")
    p.refusal(_CENSUS_OK, _DOC_OK.replace(t2_delim, "| row | b | store site (per census) | arrives with |\n| --- | --- | --- |\n"), "delimiter row has 3 cells", "DRS delimiter row narrower than its header")
    p.refusal(_CENSUS_OK, _DOC_OK.replace(t2_delim, "| row | b | store site (per census) | arrives with |\n\n| --- | --- | --- | --- |\n"), "not followed by a GFM delimiter", "DRS delimiter row not directly beneath the header")
    p.refusal(_CENSUS_OK.replace("| --- | --- | --- | --- | --- | --- | --- | --- |\n| CEN-L1", "| CEN-L1"), _DOC_OK, "not followed by a GFM delimiter", "census table header without its delimiter row")
    p.refusal(_CENSUS_OK.replace("| --- | --- | --- | --- | --- | --- | --- | --- |\n| CEN-L1", "| --- | --- | --- | --- | --- | --- | --- |\n| CEN-L1"), _DOC_OK, "delimiter row has 7 cells", "census delimiter row narrower than its header")
    p.refusal(_CENSUS_OK.replace("| CEN-A2 | height |", "| --- | --- | --- | --- | --- | --- | --- | --- |\n| CEN-A2 | height |"), _DOC_OK, "is not a `CEN-` row id", "a second separator-looking line is a data row, refused not skipped")

    # §5's bound row must not leak into the §4 derivation
    leaked = _CENSUS_OK.replace("## 5. Dead surfaces", "### 4.Z Leak")
    p.refusal(leaked, _DOC_OK, "table 2 is missing", "a §4 row outside the doc's tables is caught")

    print(f"check_drs_e6_partition selftest: {p.refusals} refusals fire, consistent pairs pass")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--census", type=Path, default=DEFAULT_CENSUS)
    ap.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    ap.add_argument("--describe", action="store_true", help="print the derivation and exit 0")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        selftest()
        return 0
    for p in (args.census, args.doc):
        if not p.is_file():
            print(f"check_drs_e6_partition: missing input {p}", file=sys.stderr)
            return 2
    census_text = args.census.read_text(encoding="utf-8")
    doc_text = args.doc.read_text(encoding="utf-8")
    try:
        if args.describe:
            print(describe(census_text))
            return 0
        errors = check(census_text, doc_text)
    except Refused as e:
        print(f"check_drs_e6_partition: {e}", file=sys.stderr)
        return 2
    if errors:
        print(
            f"check_drs_e6_partition: {args.doc.relative_to(REPO) if args.doc.is_relative_to(REPO) else args.doc} "
            f"§7.5 disagrees with {args.census.name} in {len(errors)} place(s):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print("\nderivation:\n" + describe(census_text), file=sys.stderr)
        return 1
    print("check_drs_e6_partition: §7.5 tables agree with the census")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
