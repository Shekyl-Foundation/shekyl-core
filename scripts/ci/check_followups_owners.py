#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# FOLLOWUPS Owner: resolution gate — a deferral's owner must resolve.
#
# Rule 22 requires a deferral to be "tagged and scheduled". Six deferrals in
# September 2026 named "the E2 lane" as their owner while no such lane existed
# in any form — no plan doc, no branch, no PR (DRS_E2_REPLAY_DRIVER.md RD-F3).
# Each row was individually legitimate; in aggregate they were an unchosen
# queue, and nothing could see it because "owner" was prose. This gate makes
# the owner a checked cell.
#
# THE RULE. Every top-level work item in docs/FOLLOWUPS.md carries an
#     - Owner: <target>
# sub-bullet beside `Target:`, and <target> must RESOLVE to something that
# outlives its landing:
#   * a live plan document — a path under docs/design/ that exists (a
#     completed/ path is not live: the work it owned is done, and a row still
#     pointing at it has an owner who left), or
#   * a registered identifier family — a token such as `RD-Q4`, `SI-10`,
#     `DRS-E2` whose family prefix appears in IMPLEMENTATION_INDEX.md §2 (read
#     through the prefix gate's own reader, so the two gates cannot disagree
#     about what the registry holds).
# A PR number may be cited alongside (and often should be) but is NOT an
# owner on its own: PRs merge and close, and a row whose only owner is a
# merged PR is a row nobody owns — the shape this gate exists to catch. The
# direction memo of 2026-09-19 listed "an open PR" among resolvable owners;
# this gate narrows that on rule-22 grounds (a carrier must outlive its
# landing) and says so here so the choice is reviewable, not silent.
#
# GRANDFATHER. Rows that predate the cell are listed BY EXACT HEADING in
# scripts/ci/followups_owner_grandfather.txt (the shape #786's GOVERNED_OWNERS
# took). The gate asserts every listed heading still exists (a row that is
# gone must leave the list — red when the item is gone, rule 47's second leg)
# and that the list never grows. A grandfathered row gains an Owner: by
# leaving the list; the list is a burn-down, not a permanent exemption.
#
# SUBJECT (rule 47). Refuses to pass when FOLLOWUPS.md is missing or has no
# rows, when the index registry parses empty, or when NO row carries an
# Owner: (a gate over a cell nobody writes has no subject).
#
# --selftest exercises: a doc owner resolves; a family owner resolves; a
# completed/ path is refused; a prose owner ("the E2 lane") is refused; a
# PR-only owner is refused; a grandfathered row missing its heading is
# refused; a row neither grandfathered nor owned is refused.
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FOLLOWUPS = os.path.join(ROOT, "docs", "FOLLOWUPS.md")
GRANDFATHER = os.path.join(ROOT, "scripts", "ci", "followups_owner_grandfather.txt")
DESIGN_DIR = os.path.join(ROOT, "docs", "design")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_index_prefix_uniqueness import family_prefix, registry_rows  # noqa: E402

ENTRY_RE = re.compile(r"^- \*\*(.+?)\*\*")
OWNER_RE = re.compile(r"^\s+-\s*Owner:\s*(.+?)\s*$")
TARGET_RE = re.compile(r"^\s+-\s*Target:")
# A path into docs/design (absolute-from-root, or relative from docs/ as
# FOLLOWUPS links are written).
DOC_PATH_RE = re.compile(r"(?:docs/)?(?:design/)([A-Za-z0-9_./-]+\.md)")
COMPLETED_RE = re.compile(r"(?:docs/)?completed/[A-Za-z0-9_./-]+\.md")
# A family token: letters, optional digits, optional -letters, then digits or
# a range. `RD-Q4`, `SI-10`, `DRS-E2`, `CEN-D4`.
TOKEN_RE = re.compile(r"\b([A-Z][A-Za-z]*\d*(?:-[A-Z][A-Za-z]*)?)-?(\d+)\b")
PR_RE = re.compile(r"(?:PR\s*)?#\d+")


class GateError(Exception):
    """The gate could not ask its question (exit 2)."""


def parse_items(text: str) -> list[dict]:
    """Top-level items with their heading, Owner: value and line number."""
    items: list[dict] = []
    current: dict | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        m = ENTRY_RE.match(line)
        if m:
            current = {"heading": m.group(1).strip(), "line": lineno, "owner": None, "target": False}
            items.append(current)
            continue
        if current is None:
            continue
        if line.startswith("- ") or line.startswith("## "):
            current = None
            continue
        om = OWNER_RE.match(line)
        if om:
            current["owner"] = om.group(1)
        elif TARGET_RE.match(line):
            current["target"] = True
    return items


def registry_prefixes(rows: list[str]) -> set[str]:
    out: set[str] = set()
    for cell in rows:
        for part in re.split(r"\s*/\s*|,\s*", cell):
            p = family_prefix(part)
            if p:
                out.add(p)
    return out


def resolves(owner: str, prefixes: set[str], design_dir: str) -> tuple[bool, str]:
    """Whether an Owner: value names something that outlives its landing."""
    if COMPLETED_RE.search(owner) and not DOC_PATH_RE.search(owner):
        return False, "points only at docs/completed/ — that work is done; the row's owner left"
    for m in DOC_PATH_RE.finditer(owner):
        rel = m.group(1)
        if os.path.isfile(os.path.join(design_dir, rel)):
            return True, f"live doc design/{rel}"
        return False, f"design/{rel} does not exist"
    for m in TOKEN_RE.finditer(owner):
        pref = family_prefix(m.group(1) + m.group(2))
        if pref and pref in prefixes:
            return True, f"family {pref}"
    if PR_RE.search(owner):
        return False, "a PR number is not an owner on its own (PRs merge and close); name the doc or family it lands in"
    return False, "names neither a live docs/design/ document nor a registered identifier family"


def check(text: str, grandfather: list[str], prefixes: set[str], design_dir: str) -> list[str]:
    items = parse_items(text)
    if not items:
        raise GateError("subject absent: FOLLOWUPS has no `- **…**` items")
    if not prefixes:
        raise GateError("subject absent: IMPLEMENTATION_INDEX §2 registry parsed no family prefixes")
    headings = {it["heading"] for it in items}
    findings: list[str] = []
    listed = set()
    for g in grandfather:
        if g in listed:
            findings.append(f"grandfather list repeats a heading: {g[:70]!r}")
        listed.add(g)
        if g not in headings:
            findings.append(
                f"grandfathered heading no longer exists — remove it from the list: {g[:70]!r}"
            )
    owned = 0
    for it in items:
        if it["owner"] is None:
            if it["heading"] in listed:
                continue
            findings.append(
                f"FOLLOWUPS.md:{it['line']}: no `Owner:` and not grandfathered: {it['heading'][:70]!r}"
            )
            continue
        owned += 1
        if it["heading"] in listed:
            findings.append(
                f"FOLLOWUPS.md:{it['line']}: carries Owner: but is still grandfathered — remove it from the list"
            )
        ok, why = resolves(it["owner"], prefixes, design_dir)
        if not ok:
            findings.append(
                f"FOLLOWUPS.md:{it['line']}: Owner {it['owner'][:60]!r} does not resolve: {why}"
            )
    if owned == 0:
        raise GateError("subject absent: no FOLLOWUPS row carries an `Owner:` — nothing for this gate to check")
    return findings


def load_grandfather(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise GateError(f"grandfather list missing: {path}")
    with open(path, encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip() and not ln.startswith("#")]


def main() -> int:
    if not os.path.isfile(FOLLOWUPS):
        print("followups owners: docs/FOLLOWUPS.md is missing", file=sys.stderr)
        return 2
    rows = registry_rows()
    if rows is None:
        print("followups owners: IMPLEMENTATION_INDEX.md is missing", file=sys.stderr)
        return 2
    try:
        with open(FOLLOWUPS, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        findings = check(text, load_grandfather(GRANDFATHER), registry_prefixes(rows), DESIGN_DIR)
    except GateError as e:
        print(f"followups owners: {e}", file=sys.stderr)
        return 2
    if findings:
        print("FAIL: FOLLOWUPS owner resolution:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    items = parse_items(text)
    owned = sum(1 for it in items if it["owner"] is not None)
    print(
        f"followups owners: {len(items)} items, {owned} carry Owner: (all resolve), "
        f"{len(items) - owned} grandfathered (burn-down list, never grows)"
    )
    return 0


def selftest() -> int:
    import tempfile

    prefixes = {"RD-Q", "SI", "DRS"}
    with tempfile.TemporaryDirectory() as d:
        design = os.path.join(d, "design")
        os.makedirs(design)
        with open(os.path.join(design, "LIVE.md"), "w", encoding="utf-8") as fh:
            fh.write("# live\n")

        def run(text: str, gf: list[str]) -> list[str]:
            return check(text, gf, prefixes, design)

        doc_owner = "- **A**\n  - Target: pre-genesis\n  - Owner: [`LIVE.md`](design/LIVE.md) §4\n"
        fam_owner = "- **B**\n  - Target: pre-genesis\n  - Owner: the RD-Q4 lane\n"
        assert run(doc_owner + fam_owner, []) == [], "doc and family owners resolve"

        bad = [
            ("- **C**\n  - Target: pre-genesis\n  - Owner: the E2 lane\n", "names neither"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: PR #788\n", "not an owner on its own"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: [`X.md`](completed/X.md)\n", "docs/completed/"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: design/MISSING.md\n", "does not exist"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: the ZZ-Q1 lane\n", "names neither"),
        ]
        for text, needle in bad:
            out = run(doc_owner + text, [])
            assert out and needle in out[0], (text, out)

        # Neither owned nor grandfathered → refused; grandfathered → passes.
        bare = "- **D**\n  - Target: pre-genesis\n"
        out = run(doc_owner + bare, [])
        assert out and "not grandfathered" in out[0], out
        assert run(doc_owner + bare, ["D"]) == []
        # A grandfathered heading that is gone → refused (red when the item is gone).
        out = run(doc_owner, ["GONE"])
        assert out and "no longer exists" in out[0], out
        # Owned AND grandfathered → the list must burn down.
        out = run(doc_owner, ["A"])
        assert out and "still grandfathered" in out[0], out
        # Subject assertions.
        for text, gf in [("", []), (bare, ["D"])]:
            try:
                run(text, gf)
            except GateError:
                pass
            else:
                raise AssertionError(f"subject assertion did not fire for {text!r}")
        try:
            check(doc_owner, [], set(), design)
        except GateError:
            pass
        else:
            raise AssertionError("empty registry must be a missing subject")
    print("followups owners selftest: 12 cases OK")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
