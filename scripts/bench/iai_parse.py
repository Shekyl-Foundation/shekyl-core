#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""Parse gungraun's stdout into iai entries for `capture_rust_baseline.sh`.

The capture runs each registered row's gungraun bench and writes a
`==== <crate>::<bench> ====` marker before its stdout. Within a section:

    <bench_binary>::<group>::<function> <run_id>:<args>
      Instructions:    <n>|...
      L1 Hits:         <n>|...
      ...

A measurement the parser does not read is a gate that cannot fail
(rule 50): the row is captured, the envelope never holds it, and the
benchmark comment reports nothing. So the parse refuses three shapes
instead of dropping them:

- a function header its header pattern does not read (a
  `#[library_benchmark]` with no `#[bench::...]` case prints no run id);
- a registered row whose section yields no entry;
- a registered row with no section at all.

Run its tests: `python3 scripts/bench/test_iai_parse.py`.
"""

from __future__ import annotations

import re

SECTION_RE = re.compile(
    r"^==== (?P<crate>[\w-]+)::(?P<bench>[\w_]+) ====$", re.MULTILINE)
HEADER_RE = re.compile(
    r"^(?P<bin>[A-Za-z_][\w]*)::(?P<group>[A-Za-z_][\w]*)::"
    r"(?P<function>[A-Za-z_][\w]*)\s+(?P<run_id>[^:\s]+):(?P<setup>.+)$")
# Anything shaped like a function header, read or not.
HEADER_SHAPE_RE = re.compile(
    r"^[A-Za-z_]\w*::[A-Za-z_]\w*::[A-Za-z_]\w*(\s|$)")
METRIC_RE = re.compile(
    r"^\s{2}(?P<name>[A-Za-z][A-Za-z0-9+ ]*?):\s+(?P<value>\d+)\|")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

METRIC_KEYS = {
    "Instructions": "instructions",
    "L1 Hits": "l1_hits",
    "LL Hits": "ll_hits",
    "RAM Hits": "ram_hits",
    "Total read+write": "total_read_write",
    "Estimated Cycles": "estimated_cycles",
}


class CaptureError(Exception):
    """The capture holds a measurement the parse would drop."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


def rows_from_benches(benches: list[str]) -> list[tuple[str, str]]:
    """`(crate, iai_bench)` for each `crate:criterion:iai[:features]`
    row of the capture's `BENCHES` array."""
    rows = []
    for row in benches:
        row = row.strip()
        if not row:
            continue
        fields = row.split(":")
        rows.append((fields[0], fields[2]))
    return rows


def parse(text: str, rows: list[tuple[str, str]]) -> list[dict]:
    """Every entry in `text`, or `CaptureError` naming each measurement
    the parse would otherwise drop."""
    text = ANSI_RE.sub("", text)
    starts = [(m.start(), m.group("crate"), m.group("bench"))
              for m in SECTION_RE.finditer(text)]
    starts.append((len(text), None, None))
    entries: list[dict] = []
    per_section: dict[tuple[str, str], int] = {}
    problems: list[str] = []
    for i in range(len(starts) - 1):
        body_start, crate, bench = starts[i]
        body = text[body_start:starts[i + 1][0]]
        found = 0
        current = None
        for line in body.splitlines():
            hm = HEADER_RE.match(line)
            if hm is not None:
                if current is not None:
                    entries.append(current)
                found += 1
                current = {
                    "crate": crate,
                    "bench_target": bench,
                    "bin": hm.group("bin"),
                    "group": hm.group("group"),
                    "function": hm.group("function"),
                    "run_id": hm.group("run_id"),
                    "setup": hm.group("setup").strip(),
                    "metrics": {},
                }
                continue
            if HEADER_SHAPE_RE.match(line) is not None:
                problems.append(
                    f"{crate}::{bench}: a function header the parse does "
                    f"not read (no `<run_id>:<args>`; give the bench a "
                    f"`#[bench::<id>(...)]` case): {line.strip()!r}")
                if current is not None:
                    entries.append(current)
                current = None
                continue
            mm = METRIC_RE.match(line)
            if mm is not None and current is not None:
                key = METRIC_KEYS.get(mm.group("name").strip())
                if key is not None:
                    current["metrics"][key] = int(mm.group("value"))
        if current is not None:
            entries.append(current)
        key = (crate, bench)
        per_section[key] = per_section.get(key, 0) + found
    for crate, bench in rows:
        if (crate, bench) not in per_section:
            problems.append(
                f"{crate}::{bench}: registered, but the capture has no "
                f"section for it")
        elif per_section[(crate, bench)] == 0:
            problems.append(
                f"{crate}::{bench}: registered, but its section yields no "
                f"entry")
    if problems:
        raise CaptureError(problems)
    return entries
