#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Rewrite every citation of a vacated rule number to its successor.

The data is `.cursor/rules/vacated-numbers.tsv`: each vacated number, its old
file stem, and either the rule's new stem (renumbered) or the record that
keeps its text (retired). This script is the one-time mechanical sweep that
moves the tree's citations; `scripts/ci/check_vacated_rule_numbers.py` is the
gate that then holds the tree, with its own, broader detector.

A rewrite keeps each citation resolvable without changing what it says. With
NN a renumbered rule, MM its new number and R the record of a retired one:

  rule NN, Rule NN's, rules 05/NN, rule-NN -> rule MM, Rule MM's, rules 05/MM, rule-MM
  `NN-slug.mdc`, .cursor/rules/NN-slug.mdc -> `MM-slug.mdc`, .cursor/rules/MM-slug.mdc
  [`NN`](.cursor/rules/NN-slug.mdc)        -> [`MM`](.cursor/rules/MM-slug.mdc)
  a retired rule's citation                -> `R` (the record's name)
  a retired rule's path                    -> R's path, written the way the
                                              citation was (repository-root
                                              or relative to the citing file)

A citation may break across a line, behind a comment or quote prefix (`///`,
`//!`, `//`, `#`, `*`, `>`). The number is matched whole (no digit on either
side), so a rewritten 125 is never matched again: the sweep is idempotent.

Usage:
  sweep_rule_citations.py            report what would change, exit 1 if anything would
  sweep_rule_citations.py --write    rewrite the files
  sweep_rule_citations.py --report   also print every rewrite, file:line: old -> new
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass

DATA = ".cursor/rules/vacated-numbers.tsv"

# Paths the sweep never rewrites, each with its reason. They are the only
# files that must name the vacated numbers: the data, the gate that reads it,
# and this script.
EXCLUDED = {
    DATA: "the data file: it names every vacated number by definition",
    "scripts/ci/check_vacated_rule_numbers.py": "the gate: its detector and selftest fixtures plant each vacated citation",
    "scripts/rules/sweep_rule_citations.py": "this script: its docstring shows each rewrite",
}


@dataclass(frozen=True)
class Vacated:
    number: str
    old: str
    status: str
    repo: str
    successor: str

    @property
    def new_number(self) -> str:
        return self.successor.split("-", 1)[0]

    @property
    def record_stem(self) -> str:
        return os.path.splitext(os.path.basename(self.successor))[0]


def load(root: str) -> dict[str, Vacated]:
    rows: dict[str, Vacated] = {}
    with open(os.path.join(root, DATA), encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or line.startswith("number\t"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                raise SystemExit(f"{DATA}: malformed row: {line!r}")
            v = Vacated(*parts)
            if v.status not in ("renumbered", "retired"):
                raise SystemExit(f"{DATA}: unknown status {v.status!r}")
            rows[v.number] = v
    if not rows:
        raise SystemExit(f"{DATA}: no rows; a sweep over nothing would pass having done nothing")
    return rows


# Whitespace inside a citation: spaces, or a line break followed by an
# optional comment or quote prefix.
GAP = r"(?:[ \t]+|[ \t]*\n[ \t]*(?:(?:///|//!|//|#|\*|>|--)[ \t]*)?)"
NUM = r"(?<![\d.])\d{2}(?![\d])"
LISTSEP = rf"(?:[ \t]*(?:/|,|&|–|—)[ \t]*(?:\n[ \t]*(?:(?:///|//!|//|#|\*|>|--)[ \t]*)?)?|{GAP}(?:and|or){GAP}|,{GAP}(?:and|or){GAP})"
CITE = re.compile(rf"(?P<pre>[ \t]*)\b(?P<word>rules?)(?P<gap>{GAP}|-)(?P<list>{NUM}(?:{LISTSEP}{NUM})*)", re.IGNORECASE)


def tracked_text_files(root: str) -> list[str]:
    out = subprocess.run(
        ["git", "-C", root, "grep", "-I", "-l", "-e", ""],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    return [f for f in out if f]


def record_path(v: Vacated, citing: str, prefix: str) -> str:
    """Where the record is, written the way the citation was written."""
    if prefix.startswith(("./", "../")):
        return os.path.relpath(v.successor, os.path.dirname(citing) or ".")
    if ".cursor/rules/" in prefix:
        return v.successor
    return os.path.basename(v.successor)


def sweep_text(path: str, text: str, vac: dict[str, Vacated]) -> tuple[str, list[tuple[int, str, str]]]:
    edits: list[tuple[int, str, str]] = []

    def note(m: re.Match, new: str) -> str:
        if new != m.group(0):
            edits.append((text.count("\n", 0, m.start()) + 1, m.group(0), new))
        return new

    olds = "|".join(re.escape(v.old) for v in vac.values())

    # 1. Link text that is the bare number, linking to the old file.
    link = re.compile(rf"\[(?P<q>`?)(?P<n>\d{{2}})(?P=q)\]\((?P<pre>[^)\s]*?)(?P<old>{olds})(?P<ext>\.mdc)?\)")

    def r_link(m: re.Match) -> str:
        v = next(x for x in vac.values() if x.old == m.group("old"))
        if m.group("n") != v.number:
            return m.group(0)
        if v.status == "renumbered":
            return note(m, f"[{m.group('q')}{v.new_number}{m.group('q')}]({m.group('pre')}{v.successor}{m.group('ext') or ''})")
        return note(m, f"[{m.group('q')}{v.record_stem}{m.group('q')}]({record_path(v, path, m.group('pre') or '.')})")

    text = link.sub(r_link, text)

    # 2. The old file stem, bare or in a path, with or without .mdc.
    stem = re.compile(rf"(?P<pre>(?:\.\.?/)*(?:\.cursor/rules/)?)\b(?P<old>{olds})\b(?P<ext>\.mdc)?")

    def r_stem(m: re.Match) -> str:
        v = next(x for x in vac.values() if x.old == m.group("old"))
        if v.status == "renumbered":
            return note(m, f"{m.group('pre')}{v.successor}{m.group('ext') or ''}")
        pre = m.group("pre")
        if pre or m.group("ext"):
            return note(m, record_path(v, path, pre))
        return note(m, v.record_stem)

    text = stem.sub(r_stem, text)

    # 3. rule NN, rules NN/MM, rules NN and MM, across a line break too.
    def r_cite(m: re.Match) -> str:
        lst = m.group("list")
        nums = re.findall(NUM, lst)
        if not any(n in vac for n in nums):
            return m.group(0)
        retired = [n for n in nums if n in vac and vac[n].status == "retired"]

        def r_num(nm: re.Match) -> str:
            n = nm.group(0)
            if n not in vac:
                return n
            v = vac[n]
            return v.new_number if v.status == "renumbered" else f"`{v.record_stem}`"

        new_list = re.sub(NUM, r_num, lst)
        pre, gap = m.group("pre"), m.group("gap")
        if len(retired) == len(nums):
            # Every number in it is retired: the record names replace the
            # citation. A line break inside it stays where it was, and the
            # space before the dropped word goes with it.
            if "\n" in gap:
                return note(m, gap[gap.index("\n"):] + new_list)
            return note(m, pre + new_list)
        return note(m, f"{pre}{m.group('word')}{gap}{new_list}")

    text = CITE.sub(r_cite, text)
    return text, edits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    vac = load(a.root)
    print("excluded (never rewritten):")
    for p, why in EXCLUDED.items():
        print(f"  {p}: {why}")
    total = 0
    files = 0
    per_top: dict[str, int] = {}
    for rel in tracked_text_files(a.root):
        if rel in EXCLUDED:
            continue
        full = os.path.join(a.root, rel)
        try:
            with open(full, encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            continue
        new, edits = sweep_text(rel, text, vac)
        if not edits:
            continue
        files += 1
        total += len(edits)
        top = rel.split("/")[0] if "/" in rel else "(root)"
        per_top[top] = per_top.get(top, 0) + len(edits)
        if a.report:
            for line, old, rep in edits:
                print(f"{rel}:{line}: {old!r} -> {rep!r}")
        if a.write:
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(new)
    print(f"{total} citations in {files} files" + (" rewritten" if a.write else " to rewrite"))
    for top, n in sorted(per_top.items(), key=lambda kv: -kv[1]):
        print(f"  {top}: {n}")
    return 0 if (a.write or total == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
