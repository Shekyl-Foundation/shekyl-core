#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A vacated rule number is never cited, and never reused.

`.cursor/rules/vacated-numbers.tsv` lists every rule number that has been
vacated: renumbered into a repository's own series, or retired with a record
that keeps its text. Ruled 2026-11-19 (Round 0 §7) and 2026-11-27. A citation
of a vacated number points at nothing, or, once the number is reused, at the
wrong rule; this gate fails on any.

It fails on, in every tracked text file but the data file itself:

  - a rule file in `.cursor/rules/` whose number is vacated (reuse);
  - "rule NN", "rules NN/MM", "rules NN and MM", "rule-NN", "rule #NN",
    including across a line break behind a comment or quote prefix, when
    any listed number is vacated (a parenthesis is not a separator: "the
    maturity rule (60/10)" counts blocks, not rules);
  - a vacated rule's old file stem, with or without `.mdc` or a path;
  - any `.cursor/rules/NN-…` path whose number is vacated, whatever the slug;
  - a link into `.cursor/rules/` whose bare-number text is vacated or names a
    different number than the file it links to.

The detector is this file's own, broader than the sweep's
(`scripts/rules/sweep_rule_citations.py`), so the sweep cannot vouch for
itself. The selftest builds every form from the data file and requires the
detector to find each, then runs the whole gate end to end on scratch
repositories (clean, one citation, one reused number); no vacated number is
written in this file.

Usage:
  check_vacated_rule_numbers.py              check the tracked tree
  check_vacated_rule_numbers.py --selftest   plant each form and require a failure
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

DATA = ".cursor/rules/vacated-numbers.tsv"
MIN_TRACKED_TEXT_FILES = 50


def load(root: str) -> list[dict[str, str]]:
    path = os.path.join(root, DATA)
    if not os.path.isfile(path):
        raise SystemExit(f"FAIL: {DATA} is missing; the gate has no subject")
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or line.startswith("number\t"):
                continue
            n, old, status, repo, succ = line.split("\t")
            if not re.fullmatch(r"\d{2}", n) or not old.startswith(n + "-"):
                raise SystemExit(f"FAIL: {DATA}: malformed row {line!r}")
            if status not in ("renumbered", "retired"):
                raise SystemExit(f"FAIL: {DATA}: unknown status in {line!r}")
            rows.append(dict(number=n, old=old, status=status, repo=repo, successor=succ))
    if not rows:
        raise SystemExit(f"FAIL: {DATA} lists no number; the gate would pass having checked nothing")
    return rows


def detector(rows: list[dict[str, str]]):
    nums = {r["number"] for r in rows}
    olds = "|".join(re.escape(r["old"]) for r in rows)
    sep = r"(?:[ \t]*(?:-|#)?[ \t]*|[ \t]*\n[ \t]*(?:(?:///|//!|//|#|\*|>|--)[ \t]*)?)"
    num = r"(?<![\d.])(\d{2})(?!\d)"
    listsep = r"(?:\s*[^\w\s]{1,2}\s*|\s+(?:and|or|to)\s+|,\s*(?:and|or)\s+)"
    cite = re.compile(rf"\brules?{sep}{num}((?:{listsep}\d{{2}}(?!\d))*)", re.I)
    stem = re.compile(rf"\b({olds})\b")
    path = re.compile(r"\.cursor/rules/(\d{2})-[\w-]+")
    link = re.compile(r"\[`?(\d{2,3})`?\]\([^)\s]*?\.cursor/rules/(\d{2,3})-[\w-]+(?:\.mdc)?\)")

    def scan(text: str):
        for m in cite.finditer(text):
            listed = [m.group(1)] + re.findall(r"(?<!\d)\d{2}(?!\d)", m.group(2) or "")
            bad = [n for n in listed if n in nums]
            if bad:
                yield m.start(), f"cites vacated rule {', '.join(bad)}: {m.group(0)!r}"
        for m in stem.finditer(text):
            yield m.start(), f"names vacated rule file {m.group(1)!r}"
        for m in path.finditer(text):
            if m.group(1) in nums:
                yield m.start(), f"path into a vacated rule number: {m.group(0)!r}"
        for m in link.finditer(text):
            if m.group(1) in nums or m.group(1) != m.group(2):
                yield m.start(), f"link text {m.group(1)!r} for rule file {m.group(2)!r}"

    return scan


def tracked_text_files(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "grep", "-I", "-l", "-e", ""],
                         capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\n") if f]


def candidates(root: str, rows: list[dict[str, str]]) -> list[str]:
    """Tracked text files that could hold a citation: they say "rule" or name
    a rule path or an old stem. git grep is the coarse, fast filter; the
    detector decides."""
    pats = ["rule", ".cursor/rules/"] + [r["old"] for r in rows]
    args = ["git", "-C", root, "grep", "-I", "-l", "-i", "-F"]
    for p in pats:
        args += ["-e", p]
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode not in (0, 1):
        raise SystemExit(f"FAIL: git grep exited {r.returncode}: {r.stderr.strip()}")
    return [f for f in r.stdout.split("\n") if f]


def reused(root: str, nums: set[str]) -> list[str]:
    out = []
    rules_dir = os.path.join(root, ".cursor/rules")
    if os.path.isdir(rules_dir):
        for f in sorted(os.listdir(rules_dir)):
            m = re.match(r"(\d+)-", f)
            if m and m.group(1) in nums:
                out.append(f".cursor/rules/{f}: reuses vacated number {m.group(1)}")
    return out


def check(root: str) -> int:
    rows = load(root)
    nums = {r["number"] for r in rows}
    scan = detector(rows)
    files = tracked_text_files(root)
    if len(files) < MIN_TRACKED_TEXT_FILES and not os.environ.get("VACATED_SELFTEST"):
        print(f"FAIL: only {len(files)} tracked text files; expected at least {MIN_TRACKED_TEXT_FILES}")
        return 1
    failures = reused(root, nums)
    for rel in candidates(root, rows):
        if rel == DATA:
            continue
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as fh:
                text = fh.read()
        except UnicodeDecodeError:
            continue
        for pos, why in scan(text):
            failures.append(f"{rel}:{text.count(chr(10), 0, pos) + 1}: {why}")
    if failures:
        print("FAIL: vacated rule numbers are cited (see .cursor/rules/vacated-numbers.tsv):")
        for f in failures:
            print("  " + f)
        print("Fix: rewrite each to its successor (scripts/rules/sweep_rule_citations.py --write).")
        return 1
    print(f"OK: no citation of the {len(nums)} vacated rule numbers in {len(files)} tracked text files.")
    return 0


def plants(rows: list[dict[str, str]]) -> list[tuple[str, str, str]]:
    """(name, file, content) for every citation form, built from the data."""
    out = []
    for r in rows:
        n, old = r["number"], r["old"]
        out += [
            (f"rule {n}", "doc.md", f"see rule {n} for this\n"),
            (f"Rule {n}'s", "doc.md", f"Rule {n}'s scope\n"),
            (f"rules 05/{n}", "doc.md", f"rules 05/{n} both apply\n"),
            (f"rules 05 and {n}", "doc.md", f"rules 05 and {n} both apply\n"),
            (f"rule-{n}", "doc.md", f"the rule-{n} floor\n"),
            (f"rule\\n/// {n}", "lib.rs", f"/// this is held by rule\n/// {n}, always\n"),
            (f"stem {old}", "doc.md", f"`{old}.mdc`\n"),
            (f"path .cursor/rules/{n}-x", "doc.md", f"(.cursor/rules/{n}-anything-else.mdc)\n"),
            (f"link [{n}]", "doc.md", f"[`{n}`](.cursor/rules/{old}.mdc)\n"),
            (f"reuse {n}", f".cursor/rules/{n}-reused.mdc", "---\ndescription: x\n---\n"),
        ]
    return out


def selftest(root: str) -> int:
    rows = load(root)
    nums = {r["number"] for r in rows}
    scan = detector(rows)
    with open(os.path.join(root, DATA), encoding="utf-8") as fh:
        data = fh.read()
    ok = True
    count = 0
    for name, rel, body in plants(rows):
        count += 1
        hit = bool(reused_name(rel, nums)) or any(True for _ in scan(body))
        if not hit:
            print(f"SELFTEST FAIL: planted {name!r} in {rel} was not detected")
            ok = False
    clean = "rule 05 and rules 15/16; RULE_20 is a record name; 2026-11-27; the maturity rule (60/10)\n"
    if any(True for _ in scan(clean)):
        print("SELFTEST FAIL: the clean text was flagged")
        ok = False
    print(f"selftest: {count} planted citations detected in-process: {'all' if ok else 'NOT ALL'}")

    def run(tree: dict[str, str]) -> int:
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            for rel, body in {DATA: data, **tree}.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(body)
            subprocess.run(["git", "-C", d, "add", "-A"], check=True)
            env = dict(os.environ, VACATED_SELFTEST="1")
            return subprocess.run([sys.executable, __file__, "--root", d],
                                  capture_output=True, text=True, env=env).returncode

    if run({"doc.md": clean}) != 0:
        print("SELFTEST FAIL: a clean tree was refused end to end")
        ok = False
    first = rows[0]
    for name, tree in (("a citation", {"doc.md": f"see rule {first['number']}\n"}),
                       ("a reused number", {f".cursor/rules/{first['number']}-reused.mdc": "x\n"})):
        if run(tree) == 0:
            print(f"SELFTEST FAIL: {name} passed end to end")
            ok = False
    print(f"selftest: end to end, clean passes and a planted citation and a reuse fail: {'yes' if ok else 'NO'}")
    return 0 if ok else 1


def reused_name(rel: str, nums: set[str]) -> bool:
    m = re.match(r"\.cursor/rules/(\d+)-", rel)
    return bool(m and m.group(1) in nums)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    return selftest(a.root) if a.selftest else check(a.root)


if __name__ == "__main__":
    sys.exit(main())
