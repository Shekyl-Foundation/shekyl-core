#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Rewrite every citation of a vacated rule number to its successor.

The data is `.cursor/rules/vacated-numbers.tsv`: each vacated number, its old
file stem, and either the rule's new stem (renumbered) or the record that
keeps its text (retired). This script is the mechanical sweep.
`scripts/ci/check_vacated_rule_numbers.py` is the gate that then holds the
tree. The two do not share a module: the gate is copied verbatim into the
other repositories and stays one file. `--selftest` loads the gate as an
oracle and rewrites every citation form the gate plants.

A rewrite keeps each citation resolvable. With NN a renumbered rule, MM its
new number and R the record of a retired one:

  rule NN, Rule NN's, rule #NN, rule-NN     -> rule MM, Rule MM's, rule #MM, rule-MM
  rules 05/NN, rules 05 and NN, rules 05 to NN
                                            -> rules 05/MM, rules 05 and MM, rules 05 to MM
  rules (NN gloss; 05 other)                -> rules (MM gloss; 05 other)
                                               (two or more "number subject"
                                               items; one number in
                                               parentheses is a quantity
                                               or a count and stays)
  `NN-slug.mdc`, .cursor/rules/NN-slug.mdc  -> `MM-slug.mdc`, .cursor/rules/MM-slug.mdc
  .cursor/rules/NN-anything.mdc             -> .cursor/rules/MM-slug.mdc
                                               (the number is the citation;
                                               the successor is that rule's file)
  [`NN`](NN-slug.mdc)                       -> [`MM`](MM-slug.mdc)
  [`NN`](MM-slug.mdc)                       -> [`MM`](MM-slug.mdc)
                                               (the path already names the
                                               successor; only the label moves)
  a retired rule's citation                 -> `R` (the record's name)
  a retired rule's path                     -> R's path, written the way the
                                               citation was (repository-root
                                               or relative to the citing file)

A citation may break across a line, behind a comment or quote prefix (`///`,
`//!`, `//`, `#`, `*`, `>`). A number is matched whole (no digit or dot on
the left, no digit on the right), and a rule link is parsed as a path rather
than searched for an old stem. A successor path such as `MM-slug` therefore
has nothing a second pass can match: the sweep is idempotent. A block ratio
written `rule (60/10)` is not a citation.

Usage:
  sweep_rule_citations.py              report what would change, exit 1 if anything would
  sweep_rule_citations.py --write      rewrite the files
  sweep_rule_citations.py --report     also print every rewrite, file:line: old -> new
  sweep_rule_citations.py --selftest   rewrite the gate's planted forms and require them stable
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

# An estate rule number is two digits. A file in a repository series is two
# or three (estate 00-99, core 101-199, GUI 201-299, prism 901-999). The
# lookarounds make the prose match a whole number, so a successor is not a
# second match. The gate carries the same widths and does not import this
# file; --selftest is what keeps the two honest.
ESTATE_NUMBER = r"(?<![\d.])\d{2}(?!\d)"
SERIES_NUMBER = r"\d{2,3}"

# A citation may break across a line behind a comment or quote prefix.
COMMENT_PREFIX = r"(?:///|//!|//|#|\*|>|--)"
LINE_BREAK = rf"[ \t]*\n[ \t]*(?:{COMMENT_PREFIX}[ \t]*)?"
GAP = rf"(?:[ \t]+|{LINE_BREAK})"
# "rule #NN" and "rule-NN". A number glued on, "ruleNN", is one token.
MARK = r"[ \t]*[#-][ \t]*"
PUNCT = r"[^\w\s]{1,2}"
LISTSEP = rf"(?:[ \t]*{PUNCT}[ \t]*(?:{LINE_BREAK})?|{GAP}(?:and|or|to){GAP}|,{GAP}(?:and|or){GAP})"
CITE = re.compile(
    rf"(?P<pre>[ \t]*)\b(?P<word>rules?)(?P<gap>{GAP}|{MARK})(?P<list>{ESTATE_NUMBER}(?:{LISTSEP}{ESTATE_NUMBER})*)",
    re.IGNORECASE,
)
# "rules (NN subject; MM subject)". An item is a whole number at the opening
# parenthesis, a comma, or a semicolon, and the next word is its subject.
# A list is two or more items. One number in parentheses is a quantity or a
# count ("rule (NN minutes)", "Rules (NN, plain data)", "rules (…; NN at
# close)"), and a slash after a number is a ratio, so none of those is a list.
GLOSS_LIST_FLOOR = 2
GLOSS = re.compile(r"\brules?\s*\((?P<inner>[^)]*)\)", re.IGNORECASE)
GLOSS_ITEM = re.compile(
    rf"(?P<lead>(?:^|[,;])\s*)(?P<n>{ESTATE_NUMBER})(?=\s+[A-Za-z])"
)
RULE_FILE = re.compile(rf"^({SERIES_NUMBER}-[\w-]+?)(\.mdc)?$")
LINK = re.compile(rf"\[(?P<q>`?)(?P<n>\d{{2}})(?P=q)\]\((?P<url>[^)\s]+)\)")


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


@dataclass(frozen=True)
class RuleLink:
    """A markdown link whose target is a rule file.

    prefix is the directory part and includes its trailing slash, or is empty
    when the link is a bare file name. stem is that final segment's
    ``NNN-slug`` name, taken from the start of the segment, so a successor
    ``142-…`` is never read as a vacated ``42-…``. ext is ``.mdc`` or empty.
    suffix is a ``#fragment`` or ``?query`` kept verbatim, marker included.
    """

    prefix: str
    stem: str
    ext: str
    suffix: str

    @property
    def url(self) -> str:
        return f"{self.prefix}{self.stem}{self.ext}{self.suffix}"


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
            if v.number in rows:
                raise SystemExit(f"{DATA}: duplicate number {v.number}")
            rows[v.number] = v
    if not rows:
        raise SystemExit(f"{DATA}: no rows; a sweep over nothing would pass having done nothing")
    return rows


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


def successor_token(v: Vacated) -> str:
    """The prose that replaces a vacated number: the new number, or the record's name."""
    if v.status == "renumbered":
        return v.new_number
    return f"`{v.record_stem}`"


def parse_rule_link(url: str) -> RuleLink | None:
    """The rule file a link target names, or None when it does not name one.

    The stem is the whole final path segment. A search for an old stem inside
    the segment would take ``42-…`` out of a successor ``142-…`` and write a
    fourth digit back.
    """
    cut = len(url)
    for mark in "#?":
        at = url.find(mark)
        if at != -1 and at < cut:
            cut = at
    path, suffix = url[:cut], url[cut:]
    slash = path.rfind("/")
    prefix, base = (path[: slash + 1], path[slash + 1 :]) if slash >= 0 else ("", path)
    matched = RULE_FILE.fullmatch(base)
    if matched is None:
        return None
    return RuleLink(prefix, matched.group(1), matched.group(2) or "", suffix)


def rewritten_link(
    link: RuleLink, label: str, by_old: dict[str, Vacated], vac: dict[str, Vacated], citing: str,
) -> tuple[str, str] | None:
    """(new label, new url), or None when this link is not a vacated citation.

    A retired rule's record is a different document, so a fragment of the old
    rule file is not carried over. A renumbered rule is the same document, so
    its fragment stays. A path that already is the successor is returned
    unchanged; only a stale label moves.
    """
    row = by_old.get(link.stem)
    if row is not None and label == row.number:
        if row.status == "renumbered":
            return row.new_number, RuleLink(link.prefix, row.successor, link.ext, link.suffix).url
        return row.record_stem, record_path(row, citing, link.prefix or ".")
    named = vac.get(label)
    if named is not None and named.status == "renumbered" and link.stem == named.successor:
        return named.new_number, link.url
    return None


def sweep_text(path: str, text: str, vac: dict[str, Vacated]) -> tuple[str, list[tuple[int, str, str]]]:
    edits: list[tuple[int, str, str]] = []
    by_old = {v.old: v for v in vac.values()}

    def note(m: re.Match, new: str) -> str:
        if new != m.group(0):
            edits.append((text.count("\n", 0, m.start()) + 1, m.group(0), new))
        return new

    def r_link(m: re.Match) -> str:
        parsed = parse_rule_link(m.group("url"))
        if parsed is None:
            return m.group(0)
        moved = rewritten_link(parsed, m.group("n"), by_old, vac, path)
        if moved is None:
            return m.group(0)
        label, url = moved
        return note(m, f"[{m.group('q')}{label}{m.group('q')}]({url})")

    text = LINK.sub(r_link, text)

    # .cursor/rules/NN-… with a vacated number, whatever the slug. The number
    # is the citation; the only file it can name now is that row's successor.
    # The final segment starts at the slash, so a successor 1NN-… is not read
    # as NN-….
    vacated_path = re.compile(
        rf"(?P<pre>(?:\.\.?/)*\.cursor/rules/)(?P<n>{ESTATE_NUMBER})-(?P<slug>[\w-]+)(?P<ext>\.mdc)?"
    )

    def r_path(m: re.Match) -> str:
        row = vac.get(m.group("n"))
        if row is None:
            return m.group(0)
        if row.status == "renumbered":
            return note(m, f"{m.group('pre')}{row.successor}{m.group('ext') or ''}")
        return note(m, record_path(row, path, m.group("pre")))

    text = vacated_path.sub(r_path, text)

    # The old file stem, bare or in a path, with or without .mdc. The boundary
    # is a word boundary, so the stem does not match inside a successor that
    # merely ends in the same digits.
    olds = "|".join(re.escape(v.old) for v in vac.values())
    stem = re.compile(rf"(?P<pre>(?:\.\.?/)*(?:\.cursor/rules/)?)\b(?P<old>{olds})\b(?P<ext>\.mdc)?")

    def r_stem(m: re.Match) -> str:
        row = by_old[m.group("old")]
        if row.status == "renumbered":
            return note(m, f"{m.group('pre')}{row.successor}{m.group('ext') or ''}")
        pre = m.group("pre")
        if pre or m.group("ext"):
            return note(m, record_path(row, path, pre))
        return note(m, row.record_stem)

    text = stem.sub(r_stem, text)

    def r_cite(m: re.Match) -> str:
        listed = m.group("list")
        numbers = re.findall(ESTATE_NUMBER, listed)
        if not any(n in vac for n in numbers):
            return m.group(0)
        retired = [n for n in numbers if n in vac and vac[n].status == "retired"]

        def r_num(nm: re.Match) -> str:
            row = vac.get(nm.group(0))
            return successor_token(row) if row is not None else nm.group(0)

        new_list = re.sub(ESTATE_NUMBER, r_num, listed)
        pre, gap = m.group("pre"), m.group("gap")
        if len(retired) == len(numbers):
            # Every number in it is retired: the record names replace the
            # citation. A line break inside it stays where it was, and the
            # space before the dropped word goes with it.
            if "\n" in gap:
                return note(m, gap[gap.index("\n"):] + new_list)
            return note(m, pre + new_list)
        return note(m, f"{pre}{m.group('word')}{gap}{new_list}")

    text = CITE.sub(r_cite, text)

    def r_gloss(m: re.Match) -> str:
        def r_item(im: re.Match) -> str:
            row = vac.get(im.group("n"))
            if row is None:
                return im.group(0)
            return im.group("lead") + successor_token(row)

        inner = m.group("inner")
        if len(list(GLOSS_ITEM.finditer(inner))) < GLOSS_LIST_FLOOR:
            return m.group(0)
        new_inner = GLOSS_ITEM.sub(r_item, inner)
        if new_inner == inner:
            return m.group(0)
        full = m.group(0)
        start = m.start("inner") - m.start()
        end = m.end("inner") - m.start()
        return note(m, full[:start] + new_inner + full[end:])

    text = GLOSS.sub(r_gloss, text)
    return text, edits


def load_gate(root: str):
    """The vacated-number gate, used by --selftest as an independent oracle.

    Production rewriting does not import it. Assigning the module before
    exec is what lets a dataclass in the loaded file finish defining itself.
    """
    import importlib.util

    path = os.path.join(root, "scripts", "ci", "check_vacated_rule_numbers.py")
    name = "shekyl_check_vacated_rule_numbers"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"SELFTEST FAIL: cannot load the gate at {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def selftest(root: str) -> int:
    gate = load_gate(root)
    rows = gate.load(root)
    vac = load(root)
    if {r["number"] for r in rows} != set(vac):
        print("SELFTEST FAIL: the sweep and the gate read different vacated numbers")
        return 1
    if not any(v.status == "renumbered" for v in vac.values()):
        print("SELFTEST FAIL: no renumbered row; the successor-path case would not run")
        return 1
    if not any(v.status == "retired" for v in vac.values()):
        print("SELFTEST FAIL: no retired row; the record-path case would not run")
        return 1
    scan = gate.detector(rows)
    planted = gate.plants(rows)
    citations = [(name, rel, body) for name, rel, body in planted if not rel.startswith(".cursor/rules/")]
    if not citations:
        print("SELFTEST FAIL: the gate planted no citation; the sweep would pass having rewritten nothing")
        return 1
    ok = True

    def stable(name: str, rel: str, body: str, require_edit: bool) -> str:
        nonlocal ok
        new, edits = sweep_text(rel, body, vac)
        if require_edit and not edits:
            print(f"SELFTEST FAIL: {name!r} was not rewritten")
            ok = False
        left = [why for _, why in scan(new)]
        if left:
            print(f"SELFTEST FAIL: {name!r} still flagged after rewrite: {left[0]}")
            ok = False
        again, edits2 = sweep_text(rel, new, vac)
        if again != new or edits2:
            print(f"SELFTEST FAIL: {name!r} changed on a second pass: {again!r}")
            ok = False
        return new

    for name, rel, body in citations:
        if not any(True for _ in scan(body)):
            print(f"SELFTEST FAIL: the gate did not flag {name!r}, so the sweep is not its rewriter")
            ok = False
            continue
        stable(name, rel, body, True)

    for row in vac.values():
        for prefix in ("", ".cursor/rules/"):
            for suffix in ("", "#h", "?q=1"):
                old_url = f"{prefix}{row.old}.mdc{suffix}"
                old = f"[`{row.number}`]({old_url})"
                if row.status == "renumbered":
                    want = f"[`{row.new_number}`]({prefix}{row.successor}.mdc{suffix})"
                else:
                    want = f"[`{row.record_stem}`]({record_path(row, 'doc.md', prefix or '.')})"
                got = stable(f"link {old_url}", "doc.md", old, True)
                if got != want:
                    print(f"SELFTEST FAIL: {old!r} became {got!r}, want {want!r}")
                    ok = False
                if row.status != "renumbered":
                    continue
                stale_url = f"{prefix}{row.successor}.mdc{suffix}"
                stale = f"[`{row.number}`]({stale_url})"
                if f"1{row.successor}" in stale:
                    print(f"SELFTEST FAIL: fixture itself corrupted {stale!r}")
                    ok = False
                got = stable(f"stale label {stale_url}", "doc.md", stale, True)
                want = f"[`{row.new_number}`]({stale_url})"
                if got != want or f"1{row.successor}" in got:
                    print(f"SELFTEST FAIL: {stale!r} became {got!r}, want {want!r}")
                    ok = False
        if row.status == "renumbered":
            decimal = f"rule {row.number}.4"
            got = stable(decimal, "doc.md", decimal, True)
            if got != f"rule {row.new_number}.4":
                print(f"SELFTEST FAIL: {decimal!r} became {got!r}")
                ok = False
            held = f"see rule {row.new_number} for this"
            got, edits = sweep_text("doc.md", held, vac)
            if got != held or edits or any(True for _ in scan(held)):
                print(f"SELFTEST FAIL: a successor citation moved or was flagged: {got!r}")
                ok = False

    # 60/10 counts blocks. 10 is vacated; a detector that treats the ratio as
    # a citation flags this file, because the gate scans it.
    sample = next(iter(vac.values()))
    held_parens = (
        "the maturity rule (60/10)",
        f"the revert rule ({sample.number} minutes)",
        f"Rules ({sample.number}, plain data)",
        f"rules (**05** live; {sample.number} at close)",
    )
    for held in held_parens:
        got, edits = sweep_text("doc.md", held, vac)
        if got != held or edits or any(True for _ in scan(held)):
            print(f"SELFTEST FAIL: a quantity or a count moved or was flagged: {held!r} -> {got!r}")
            ok = False
    if ok:
        print(f"selftest: {len(planted)} forms planted by the gate; {len(citations)} citations rewrite once and stay put")
    else:
        print("selftest: FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest(a.root)
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
