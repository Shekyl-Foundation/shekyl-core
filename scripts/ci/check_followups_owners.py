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
# gone must leave the list — red when the item is gone, rule 47's second leg).
#
# "NEVER GROWS" IS A RATCHET, NOT A COMMENT. GRANDFATHER_CEILING below bounds
# the list's length; a list longer than the ceiling is refused, so adding a
# row to the exemption file cannot pass the live gate without ALSO raising a
# constant in this script — a diff to the gate itself, reviewed as one, with
# its reason in the commit (the shape check_redb_schema_key_types.py's floor
# and the GUI's file-size ratchet take). The ceiling must also be LOWERED as
# rows burn down: a ceiling more than GRANDFATHER_SLACK above the list is
# refused, so the win is locked in rather than left as headroom for the next
# addition. The one legitimate raise is a merge that lands rows written before
# this gate existed (PR #804 did exactly that: 338 → 340 at the merge with
# #792); it is legitimate because it is visible.
#
# SUBJECT (rule 47). Refuses to pass when FOLLOWUPS.md is missing or has no
# rows, when the index registry parses empty, or when NO row carries an
# Owner: (a gate over a cell nobody writes has no subject).
#
# --selftest exercises: a doc owner resolves; a family owner resolves (`RD-Q4`,
# `SI-10`, and `DRS-E2` against a wildcard `DRS` row); a completed/ path is
# refused; a traversal (`design/../completed/`) is refused;
# a prose owner ("the E2 lane") is refused; a PR-only owner is refused; a
# grandfathered row missing its heading is refused; a row neither
# grandfathered nor owned is refused; the ratchet refuses a list above the
# ceiling and a ceiling too far above the list.
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FOLLOWUPS = os.path.join(ROOT, "docs", "FOLLOWUPS.md")
GRANDFATHER = os.path.join(ROOT, "scripts", "ci", "followups_owner_grandfather.txt")
DESIGN_DIR = os.path.join(ROOT, "docs", "design")

# The grandfather list's length ratchet. Lower it as rows gain owners; raise
# it only at a merge that lands rows predating the gate, and say so in the
# commit. History: 338 at the gate's birth (2026-09-20); 340 at the merge
# with #792/#800 (three pre-gate rows: two new, one re-titled).
GRANDFATHER_CEILING = 331
# How far the ceiling may sit above the list before the gate demands it be
# lowered. Small enough that a burn-down is locked in within a few rows.
GRANDFATHER_SLACK = 5

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


def under_design(rel: str, design_dir: str) -> bool:
    """True iff `design/<rel>` exists AND its canonical path lies beneath
    `design_dir`. A `..` component (`design/../completed/X.md`) matches the
    path regex and would otherwise resolve to a completed document through
    the front door this gate closes; the canonical check refuses it."""
    if any(part in {"..", ""} for part in rel.split("/")):
        return False
    base = os.path.realpath(design_dir)
    target = os.path.realpath(os.path.join(design_dir, rel))
    return target.startswith(base + os.sep) and os.path.isfile(target)


def token_prefixes(token: str) -> list[str]:
    """The family prefixes a token such as `SI-10`, `RD-Q4` or `DRS-E2` may
    resolve under, finest first.

    The token is handed to `family_prefix` WHOLE — `SI-10` derives `SI`;
    gluing the regex groups back together made `SI10`, which derives `SI10`
    and matches nothing (Bugbot on #804). And a registry row may be coarser
    than the token: `**DRS-***` registers `DRS`, while `DRS-E2` derives
    `DRS-E`, so the token's head before its first hyphen or digit is tried
    too. Finest first, so `RD-Q4` reports `RD-Q`, not `RD`, when both exist.
    """
    out: list[str] = []
    fine = family_prefix(token)
    if fine:
        out.append(fine)
    head = re.match(r"[A-Z][A-Za-z]*", token)
    if head and head.group(0) not in out:
        out.append(head.group(0))
    return out


def resolves(owner: str, prefixes: set[str], design_dir: str) -> tuple[bool, str]:
    """Whether an Owner: value names something that outlives its landing."""
    if COMPLETED_RE.search(owner) and not DOC_PATH_RE.search(owner):
        return False, "points only at docs/completed/ — that work is done; the row's owner left"
    for m in DOC_PATH_RE.finditer(owner):
        rel = m.group(1)
        if under_design(rel, design_dir):
            return True, f"live doc design/{rel}"
        return False, f"design/{rel} is not a live document under docs/design/ (missing, or a path that escapes the directory)"
    for m in TOKEN_RE.finditer(owner):
        for pref in token_prefixes(m.group(0)):
            if pref in prefixes:
                return True, f"family {pref}"
    if PR_RE.search(owner):
        return False, "a PR number is not an owner on its own (PRs merge and close); name the doc or family it lands in"
    return False, "names neither a live docs/design/ document nor a registered identifier family"


def check(
    text: str,
    grandfather: list[str],
    prefixes: set[str],
    design_dir: str,
    ceiling: int = GRANDFATHER_CEILING,
    slack: int = GRANDFATHER_SLACK,
) -> list[str]:
    items = parse_items(text)
    if not items:
        raise GateError("subject absent: FOLLOWUPS has no `- **…**` items")
    if not prefixes:
        raise GateError("subject absent: IMPLEMENTATION_INDEX §2 registry parsed no family prefixes")
    headings = {it["heading"] for it in items}
    findings: list[str] = []
    if len(grandfather) > ceiling:
        findings.append(
            f"grandfather list has {len(grandfather)} headings, above GRANDFATHER_CEILING = {ceiling}: "
            "the list only burns down. Give the new row an Owner:, or — only at a merge landing "
            "rows written before this gate — raise the ceiling in this script and say why."
        )
    elif ceiling - len(grandfather) > slack:
        findings.append(
            f"GRANDFATHER_CEILING = {ceiling} sits {ceiling - len(grandfather)} above the list's "
            f"{len(grandfather)} headings (slack {slack}): lower the ceiling to lock the burn-down in."
        )
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
            # The ratchet is exercised on its own below; here the ceiling
            # tracks the list so the other legs are tested in isolation.
            return check(text, gf, prefixes, design, ceiling=len(gf), slack=GRANDFATHER_SLACK)

        doc_owner = "- **A**\n  - Target: pre-genesis\n  - Owner: [`LIVE.md`](design/LIVE.md) §4\n"
        fam_owner = "- **B**\n  - Target: pre-genesis\n  - Owner: the RD-Q4 lane\n"
        assert run(doc_owner + fam_owner, []) == [], "doc and family owners resolve"
        # A hyphen-then-digits token (`SI-10`) and a token finer than its
        # wildcard registry row (`DRS-E2` against `DRS`) both resolve.
        si_owner = "- **S**\n  - Target: pre-genesis\n  - Owner: SI-10 (the store-invariant register)\n"
        drs_owner = "- **D**\n  - Target: pre-genesis\n  - Owner: DRS-E2\n"
        assert run(doc_owner + si_owner + drs_owner, []) == [], "SI-10 and DRS-E2 resolve"
        assert token_prefixes("SI-10") == ["SI"], token_prefixes("SI-10")
        assert token_prefixes("DRS-E2") == ["DRS-E", "DRS"], token_prefixes("DRS-E2")

        bad = [
            ("- **C**\n  - Target: pre-genesis\n  - Owner: the E2 lane\n", "names neither"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: PR #788\n", "not an owner on its own"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: [`X.md`](completed/X.md)\n", "docs/completed/"),
            ("- **C**\n  - Target: pre-genesis\n  - Owner: design/MISSING.md\n", "not a live document"),
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
        # Traversal: `design/../completed/X.md` matches the path regex; the
        # canonical check refuses it even though the file exists.
        completed = os.path.join(d, "completed")
        os.makedirs(completed)
        with open(os.path.join(completed, "DONE.md"), "w", encoding="utf-8") as fh:
            fh.write("# done\n")
        out = run(doc_owner + "- **T**\n  - Target: pre-genesis\n  - Owner: design/../completed/DONE.md\n", [])
        assert out and "escapes the directory" in out[0], out
        # The ratchet: a list above the ceiling is refused; a ceiling too far
        # above the list is refused; a ceiling within slack passes.
        rows = "".join(f"- **G{i}**\n  - Target: pre-genesis\n" for i in range(4))
        gf4 = [f"G{i}" for i in range(4)]
        out = check(doc_owner + rows, gf4, prefixes, design, ceiling=3, slack=5)
        assert out and "above GRANDFATHER_CEILING" in out[0], out
        out = check(doc_owner + rows, gf4, prefixes, design, ceiling=20, slack=5)
        assert out and "lower the ceiling" in out[0], out
        assert check(doc_owner + rows, gf4, prefixes, design, ceiling=6, slack=5) == []
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
    print("followups owners selftest: 18 cases OK")
    return 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
