#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""No new bare-`u64` block height on the daemon-store and archival surface.

# Why this gate exists

A block **index** and a block **count** are both `u64` and differ by one
everywhere they meet. `HEIGHT_SEMANTICS.md` §3.1 ruled the remedy in
September 2026 — C2: inland Rust never carries a block-axis quantity as a
bare `u64`; C3: it is `BlockHeight`, `ChainCount` or `BlockCount`; C7: never
a bare identifier `height` — and `shekyl_types::block_axis` is the type pair,
with mixing refused at compile time. Phases 2a–2f then retyped the wallet
side and declared the inland remainder "C2-complete".

It was complete over its census. The daemon store and the archival
settlement schedule were in that census nowhere, and the DRS-E4 lane then
produced three one-apart defects on that surface in three days, each found
by a test and not by a reader (`DRS_E4_ARCHIVAL_WRITER.md` `ARW-Q16`: the
close height in commit 2, the coinbase term in commit 3, the slash-log key
in commit 6 / `ARW-26`). Commit 4 had defended the class with a *name*,
`Transition::count()`; the name held in its crate and not across the call
into the store, where `height: u64` arrived. A name defends the crate it is
in; a type defends the call. C2 was review-borne, and a review-borne rule
whose campaign reads *complete* is one nobody re-checks. This gate is what
re-checks.

# What it asserts

Over every `.rs` file in the crates in `SCOPE` (production and test code
alike — a test helper that takes `height: u64` is inland too, and once the
production signature is typed the test cannot pass it a bare integer
anyway), every line that binds a height-named identifier to a bare `u64`:

  * a parameter, field or binding `…height…: u64` (also `Option<u64>`,
    `Vec<u64>`, `Range<u64>`, `RangeInclusive<u64>`), or
  * a function named `…height…` returning `u64` (also wrapped in `Option`
    or `Result`) on the same line as its parameter list,

is a **hit**. Every hit must be recorded **exactly** — path, occurrence
count, trimmed line text — in `inland_height_u64_grandfather.txt`, and
every record must still describe a hit:

  1. A hit with no record, or more occurrences than recorded, is a new
     instance: red. Type it (`BlockHeight` / `ChainCount` / `BlockCount`,
     decoding once at the wire or FFI edge per C1/C8), do not record it.
  2. A record with fewer occurrences than it says, or none, is a burn-down
     that was not locked in: red, with the instruction to lower or delete
     the entry. Editing a recorded line — a rename, a retype — moves it off
     its record, so touching a grandfathered site means typing it.
  3. The list's total is bounded by `GRANDFATHER_CEILING`, a constant in
     this file that only goes down: a list above it is refused, and a list
     more than `GRANDFATHER_SLACK` below it demands the ceiling be lowered.
     Adding a row is therefore a two-place edit, both visible in review.

The gate asserts its own subject (rule 47): every `SCOPE` crate must exist
and contain Rust source, or the gate cannot ask its question and exits 2;
and `--selftest` plants each hit shape and each non-hit on synthetic text
and each failure class on a synthetic record, so an empty list over a
typed tree — Phase 2g complete — is a steady state the gate keeps, not a
vacuous pass.

# What it does not see, stated so nobody reads silence as coverage

  * A **count-named** operand (`Transition::count() -> u64`, `prev_height +
    1`) — counts of blocks share their names with counts of everything
    else, so the count side of the class stays review-borne until Phase 2g
    types `ChainCount` through the surface.
  * A height bound under another name (`h_open: u64`, `tip: u64`, `at:
    u64`), a return type on the line after its parameter list, a tuple or
    generic position (`(u64, BlockInfo)`), or a `u64` that *is* a height
    only in the C++ it mirrors.
  * A grandfathered line **moved within its file** with its text intact
    (re-ordered fields, a helper relocated) — a record is `(path, text,
    count)` and carries no line number, so the move is invisible here and
    the touched-site law above is review-borne for it. Deliberate: a
    line-numbered record would be invalidated by every unrelated edit
    above it, and a list re-recorded on every edit is one nobody reads;
    text identity is what lets the list only burn down.
  * Anything outside `SCOPE`. The wallet side carries the campaign's own
    `RK-` and C1 raw rulings and is not this gate's subject; widening is
    Phase 2g's call, taken by adding a crate and its records.

Exit 0: clean. Exit 1: a finding. Exit 2: the question could not be asked.
`--print-records` writes the current hits in the record format, for the
commit that lowers the list; it does not write the file.
"""

from __future__ import annotations

import os
import re
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST = os.path.join(ROOT, "rust")
GRANDFATHER = os.path.join(
    ROOT, "scripts", "ci", "inland_height_u64_grandfather.txt"
)

# The daemon-store and archival surface `HEIGHT_SEMANTICS.md` §3.5 Phase 2g
# names. Each is asserted to exist and to contain Rust source.
SCOPE = (
    "shekyl-archival-retention",
    "shekyl-chain-ingest",
    "shekyl-chain-rules",
    "shekyl-chain-store",
    "shekyl-types",
)

# The list's length ratchet. Lower it as sites are typed; it is not raised.
# History: 174 at the gate's birth (2026-10-01, DRS-E4, `ARW-Q16` (c) as
# ruled: landed grandfathered so the forty-first instance is CI's finding);
# 172 at E4 commit 8 (2026-10-02: `record_archival_epoch` / `write_slashes`
# take the connecting `BlockHeight`, `ARW-Q17`); 170 at E4 commit 10d
# (2026-10-02: the serve-credit C++ mirror `serve_credit_decisions.rs`
# deleted with its two sites — not typed, gone); 167 at E4 commit 12
# (2026-10-02: `ShardClose::ClosedAt` and `shard_age_milli` take
# `BlockHeight` — the merge with `dev`'s SHT-Q2 close operand surfaced the
# sites as this gate's first red on a merged tree, and they were typed, not
# recorded); 166 at E6 slice 8 PR-a review (2026-10-05: the levered chain's
# next-block height is `BlockHeight`, and `scenario_archival_tests.rs`'s
# local `first_spending_height() -> u64` moved to `archival_driver` as
# `BlockHeight`); 161 at slice 6 row 6 (2026-10-07: the pipeline reorg
# test's hand-built fork, and its `fork_spend` closure, replaced by
# `reorg` over real spends — the site is gone, not typed).
GRANDFATHER_CEILING = 161
# How far the ceiling may sit above the list before the gate demands it be
# lowered. Small enough that a burn-down is locked in within a few sites.
GRANDFATHER_SLACK = 5

_WRAP = r"(?:(?:Option|Vec|Range|RangeInclusive|Result)\s*<\s*)?"
_IDENT = r"[A-Za-z0-9_]*height[A-Za-z0-9_]*"
BIND_RE = re.compile(r"\b" + _IDENT + r"\s*:\s*" + _WRAP + r"u64\b")
RET_RE = re.compile(
    r"\bfn\s+" + _IDENT + r"\s*(?:<[^>]*>)?\s*\([^)]*\)\s*->\s*" + _WRAP + r"u64\b"
)

Hit = tuple[str, str]  # (relative path, trimmed line)


class GateError(Exception):
    """The gate could not ask its question (exit 2)."""


def is_hit(line: str) -> bool:
    return bool(BIND_RE.search(line) or RET_RE.search(line))


def scan_text(relpath: str, text: str) -> Counter:
    hits: Counter = Counter()
    for line in text.splitlines():
        if is_hit(line):
            hits[(relpath, line.strip())] += 1
    return hits


def scan_tree(rust_root: str, scope: tuple[str, ...]) -> Counter:
    hits: Counter = Counter()
    for crate in scope:
        crate_dir = os.path.join(rust_root, crate)
        if not os.path.isdir(crate_dir):
            raise GateError(f"SCOPE crate `{crate}` is not a directory under rust/")
        seen_rs = False
        for dirpath, dirnames, filenames in os.walk(crate_dir):
            dirnames[:] = [d for d in dirnames if d != "target"]
            for name in filenames:
                if not name.endswith(".rs"):
                    continue
                seen_rs = True
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, os.path.dirname(rust_root))
                with open(full, encoding="utf-8") as fh:
                    hits.update(scan_text(rel, fh.read()))
        if not seen_rs:
            raise GateError(f"SCOPE crate `{crate}` contains no Rust source")
    return hits


def parse_records(text: str) -> Counter:
    """`path<TAB>count<TAB>line` per record; `#` comments and blanks skipped."""
    records: Counter = Counter()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[1].isdigit() or int(parts[1]) < 1:
            raise GateError(
                f"grandfather record {lineno}: expected `path<TAB>count<TAB>line`, got {line!r}"
            )
        key = (parts[0], parts[2].strip())
        if key in records:
            raise GateError(f"grandfather record {lineno}: duplicate record for {key!r}")
        records[key] = int(parts[1])
    return records


def format_records(hits: Counter) -> str:
    return "".join(
        f"{path}\t{count}\t{text}\n" for (path, text), count in sorted(hits.items())
    )


def compare(hits: Counter, records: Counter, ceiling: int, slack: int) -> list[str]:
    failures: list[str] = []
    for key in sorted(set(hits) | set(records)):
        path, text = key
        have, recorded = hits.get(key, 0), records.get(key, 0)
        if have > recorded:
            what = "unrecorded" if recorded == 0 else f"{have} occurrences, {recorded} recorded"
            failures.append(
                f"{path}: new bare-u64 height ({what}): `{text}` — type it "
                f"(BlockHeight / ChainCount / BlockCount, HEIGHT_SEMANTICS.md §3.1 C2/C3/C7); "
                f"do not add a record"
            )
        elif have < recorded:
            action = "delete the record" if have == 0 else f"lower its count to {have}"
            failures.append(
                f"{path}: grandfathered site no longer matches its record "
                f"({have} of {recorded} remain): `{text}` — {action} and lower "
                f"GRANDFATHER_CEILING to lock the burn-down in"
            )
    total = sum(records.values())
    if total > ceiling:
        failures.append(
            f"grandfather list totals {total}, above GRANDFATHER_CEILING {ceiling} — "
            f"the list only shrinks; type the new site instead"
        )
    elif total < ceiling - slack:
        failures.append(
            f"grandfather list totals {total}, more than {slack} below "
            f"GRANDFATHER_CEILING {ceiling} — lower the ceiling to lock the burn-down in"
        )
    return failures


def selftest() -> int:
    problems: list[str] = []

    def expect(cond: bool, what: str) -> None:
        if not cond:
            problems.append(what)

    for line in (
        "    height: u64,",
        "fn write_slashes(&self, height: u64, delta: &ArchivalDelta) -> Result<(), StoreError> {",
        "    pub freeze_height: u64,",
        "        current_block_height: Option<u64>,",
        "    pub processed_height_range: Range<u64>,",
        "    heights: Vec<u64>,",
        "    pub fn height_hint(&self) -> Option<u64> {",
        "pub const fn slash_deadline_height(self, epoch: u64) -> u64 {",
        "fn first_height_of(&self, e: u64) -> Result<u64, ReadFault> {",
    ):
        expect(is_hit(line), f"hit shape not matched: {line!r}")
    for line in (
        "    height: BlockHeight,",
        "    pub fn height(&self) -> BlockHeight {",
        "    weight: u64,",
        "    pub fn height_class(&self) -> HeightClass<'_> {",
        "let count = ChainCount::from_raw(raw);",
        "    fn to_raw(self) -> u64 {",
    ):
        expect(not is_hit(line), f"non-hit matched: {line!r}")

    tree = Counter({("rust/x/src/a.rs", "height: u64,"): 2, ("rust/x/src/b.rs", "fn h_height() -> u64 {"): 1})
    exact = tree.copy()
    expect(compare(tree, exact, ceiling=3, slack=5) == [], "exact records should be green")
    expect(
        any("unrecorded" in f for f in compare(tree, Counter({("rust/x/src/a.rs", "height: u64,"): 2}), 3, 5)),
        "an unrecorded hit must be red",
    )
    expect(
        any("occurrences" in f for f in compare(tree, Counter({**exact, ("rust/x/src/a.rs", "height: u64,"): 1}), 3, 5)),
        "more occurrences than recorded must be red",
    )
    expect(
        any("delete the record" in f for f in compare(tree, Counter({**exact, ("rust/x/src/c.rs", "h_height: u64"): 1}), 4, 5)),
        "a record with no site must be red",
    )
    expect(
        any("lower its count" in f for f in compare(tree, Counter({**exact, ("rust/x/src/a.rs", "height: u64,"): 3}), 4, 5)),
        "a record above its site count must be red",
    )
    expect(
        any("above GRANDFATHER_CEILING" in f for f in compare(tree, exact, ceiling=2, slack=5)),
        "a list above the ceiling must be red",
    )
    expect(
        any("lower the ceiling" in f for f in compare(tree, exact, ceiling=20, slack=5)),
        "a ceiling far above the list must be red",
    )
    expect(compare(Counter(), Counter(), ceiling=0, slack=5) == [], "empty list over a typed tree is the steady state")

    try:
        parse_records("rust/x/src/a.rs\t0\theight: u64,\n")
        problems.append("a zero-count record must be refused")
    except GateError:
        pass
    try:
        parse_records("rust/x/src/a.rs\t1\theight: u64,\nrust/x/src/a.rs\t1\theight: u64,\n")
        problems.append("a duplicate record must be refused")
    except GateError:
        pass
    rt = parse_records("# comment\n\n" + format_records(tree))
    expect(rt == tree, "record format must round-trip")

    if problems:
        for p in problems:
            print(f"SELFTEST FAIL: {p}", file=sys.stderr)
        return 1
    print("inland height u64 selftest: hit shapes, non-hits and each failure class behave")
    return 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    try:
        hits = scan_tree(RUST, SCOPE)
        if "--print-records" in argv:
            sys.stdout.write(format_records(hits))
            return 0
        if not os.path.isfile(GRANDFATHER):
            raise GateError(f"grandfather list missing: {GRANDFATHER}")
        with open(GRANDFATHER, encoding="utf-8") as fh:
            records = parse_records(fh.read())
    except GateError as e:
        print(f"inland height u64: cannot ask the question: {e}", file=sys.stderr)
        return 2
    failures = compare(hits, records, GRANDFATHER_CEILING, GRANDFATHER_SLACK)
    if failures:
        print(
            f"inland height u64: {len(failures)} finding(s) on the Phase 2g surface "
            f"(HEIGHT_SEMANTICS.md §3.1 C2/C7; DRS_E4_ARCHIVAL_WRITER.md ARW-Q16):",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"inland height u64: {sum(hits.values())} grandfathered bare-u64 height sites "
        f"across {len(SCOPE)} crates, none new (ceiling {GRANDFATHER_CEILING}); "
        f"count-named operands are not this gate's subject"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
