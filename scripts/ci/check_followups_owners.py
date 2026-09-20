# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# FOLLOWUPS Owner: gate — a deferral's owner must resolve (DRS-E2, RD-F4).
#
# Six items were once routed to "owner: the E2 lane" — a lane that existed in
# no document, branch or PR — and sat there as an unchosen queue (rule 22)
# until the lane was opened to repair it. This gate is the repair's
# generalisation: every work item in docs/FOLLOWUPS.md carries an `Owner:`
# sub-bullet beside its `Target:`, and the owner RESOLVES to one of exactly
# three things that exist:
#
#   - a LIVE design doc — a markdown link into docs/design/ (docs/completed/
#     is a closed record and cannot own open work; a doc that does not exist
#     owns nothing);
#   - an OPEN pull request — `PR #NNN`; a merged or closed PR is a landing,
#     and the row it owned is either done (remove it) or re-pointed;
#   - an index §2 identifier family — `XX-`, resolved through
#     check_index_prefix_uniqueness.py's own registry reader, so this gate and
#     the prefix gate cannot disagree about which families exist.
#
# Same family as `held_by_cxx` asserting its holder exists: a name that
# nothing checks becomes a place to park work, and the parking is invisible
# because nothing ever contradicts it.
#
# GRANDFATHER (shrink-only, exact hit). Owners were prose when this gate was
# written ("owner **the X lane**"), so the rows that predate the convention
# are listed by exact title in followups_owner_grandfather.txt. The check is
# set equality in both directions: a row without `Owner:` whose title is not
# listed is red (new debt), and a listed title with no matching row is red
# (burned down — delete the line, so the list only ever records what is still
# owed). When the list empties the file must be deleted and this comment
# updated; a grandfather with nothing left to cover is a hiding place.
#
# PR resolution needs the network (`gh pr view`). In CI it runs; locally,
# `--offline` names the PR-owned rows it could not verify and passes the rest.
# Never pass `--offline` in CI — an owner that is only ever assumed open is
# the queue this gate exists to refuse.
#
# Instance of 47-gate-subject-assertion.mdc: a missing FOLLOWUPS.md, a file
# with no work items, a missing index, or a grandfather file that exists but
# is empty are each a missing subject (exit 2), never a pass.

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Callable

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FOLLOWUPS = os.path.join(ROOT, "docs", "FOLLOWUPS.md")
DESIGN_DIR = os.path.join(ROOT, "docs", "design")
GRANDFATHER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "followups_owner_grandfather.txt"
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_followups_targets import ITEM_RE, TARGET_RE  # noqa: E402
from check_index_prefix_uniqueness import family_prefix, registry_rows  # noqa: E402

# One item grammar with the Target: gate (its ITEM_RE / TARGET_RE), so the two
# gates count the same population — a row one of them cannot see is a row
# nobody checks. The title used for the exact-hit grandfather is the bold
# lead when the row has one, else the whole first line.
TITLE_RE = re.compile(r"^- (?:~~)?\*\*(?P<title>.+?)\*\*")
SUB_RE = re.compile(r"^\s+-\s*(?P<key>Target|Owner):\s*(?P<value>.*?)\s*$")
# A note may follow the reference after an em dash; the reference itself is
# one of the three forms, nothing else.
NOTE_SPLIT_RE = re.compile(r"\s+—\s+")
DOC_RE = re.compile(r"^\[`?(?P<label>[^`\]]+)`?\]\((?P<path>[^)\s]+)\)(?:\s+§\S+)?$")
PR_RE = re.compile(r"^PR #(?P<number>\d+)$")
# The family as the prefix gate names it (`STX`, `SP-T`, `Q12-D`), written
# with or without the trailing dash of its tokens: `STX-`.
FAMILY_RE = re.compile(r"^\*{0,2}(?P<token>[A-Za-z]+\d*(?:-[A-Za-z]+)?)-?\*{0,2}$")


class Item:
    """One top-level FOLLOWUPS work item: its title, line, and sub-bullets."""

    def __init__(self, line_no: int, title: str) -> None:
        self.line_no = line_no
        self.title = title
        self.owners: list[tuple[int, str]] = []

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Item({self.line_no}, {self.title[:40]!r}, owners={self.owners})"


def parse_items(lines: list[str]) -> list[Item]:
    """Top-level `- **title**` items and the `Owner:` sub-bullets under each."""
    items: list[Item] = []
    current: Item | None = None
    for n, line in enumerate(lines, start=1):
        if ITEM_RE.match(line) and not TARGET_RE.match(line):
            t = TITLE_RE.match(line)
            title = t.group("title") if t else line[2:].strip()
            current = Item(n, title)
            items.append(current)
            continue
        if line.startswith("#"):
            current = None
            continue
        s = SUB_RE.match(line)
        if s and current is not None and s.group("key") == "Owner":
            current.owners.append((n, s.group("value")))
    return items


class Resolver:
    """Resolves one `Owner:` value; the network leg is injectable for tests."""

    def __init__(
        self,
        families: frozenset[str],
        design_dir: str,
        pr_state: Callable[[int], str | None] | None,
    ) -> None:
        self.families = families
        self.design_dir = design_dir
        self.pr_state = pr_state
        self.unverified_prs: list[int] = []

    def resolve(self, value: str) -> str | None:
        """None when the owner resolves; otherwise the reason it does not."""
        ref = NOTE_SPLIT_RE.split(value, maxsplit=1)[0].strip()
        if not ref:
            return "empty Owner:"
        m = DOC_RE.match(ref)
        if m:
            return self._resolve_doc(m.group("path"))
        m = PR_RE.match(ref)
        if m:
            return self._resolve_pr(int(m.group("number")))
        m = FAMILY_RE.match(ref)
        if m:
            pref = family_prefix(m.group("token"))
            if pref in self.families:
                return None
            return f"family {m.group('token')!r} is not an index §2 registry row"
        return (
            f"{ref!r} is none of: a docs/design link, `PR #NNN`, "
            "or an index §2 family token like `STX-`"
        )

    def _resolve_doc(self, path: str) -> str | None:
        # Links in FOLLOWUPS are relative to docs/.
        target = os.path.normpath(os.path.join(ROOT, "docs", path.split("#", 1)[0]))
        design = os.path.normpath(self.design_dir)
        if not target.startswith(design + os.sep):
            return f"{path!r} is not under docs/design/ (a closed record cannot own open work)"
        if not os.path.isfile(target):
            return f"{path!r} does not exist"
        return None

    def _resolve_pr(self, number: int) -> str | None:
        if self.pr_state is None:
            self.unverified_prs.append(number)
            return None
        state = self.pr_state(number)
        if state is None:
            return f"PR #{number} could not be looked up"
        if state != "OPEN":
            return f"PR #{number} is {state} — the owner landed; remove or re-point the row"
        return None


def gh_pr_state(number: int) -> str | None:
    """`gh pr view` state, or None when gh cannot answer."""
    if shutil.which("gh") is None:
        return None
    try:
        out = subprocess.run(
            ["gh", "pr", "view", str(number), "--json", "state"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout).get("state")
    except json.JSONDecodeError:
        return None


def read_grandfather(path: str) -> frozenset[str] | None:
    """Titles still owed an Owner:, or None when there is no list."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as fh:
        titles = [ln.rstrip("\n") for ln in fh if ln.strip() and not ln.startswith("#")]
    return frozenset(titles)


def check(
    items: list[Item],
    grandfather: frozenset[str] | None,
    resolver: Resolver,
) -> list[str]:
    """Every failure, as `path:line: reason` strings."""
    bad: list[str] = []
    unowned: set[str] = set()
    for it in items:
        if not it.owners:
            unowned.add(it.title)
            continue
        if len(it.owners) > 1:
            bad.append(f"docs/FOLLOWUPS.md:{it.line_no}: item has {len(it.owners)} Owner: lines")
            continue
        line_no, value = it.owners[0]
        why = resolver.resolve(value)
        if why is not None:
            bad.append(f"docs/FOLLOWUPS.md:{line_no}: Owner: does not resolve — {why}")
    listed = grandfather or frozenset()
    for title in sorted(unowned - listed):
        bad.append(
            f"docs/FOLLOWUPS.md: item without Owner: and not grandfathered: "
            f"{title[:80]!r}"
        )
    for title in sorted(listed - unowned):
        bad.append(
            f"{os.path.relpath(GRANDFATHER, ROOT)}: listed title has no matching "
            f"unowned row (burned down — delete the line): {title[:80]!r}"
        )
    return bad


def _flag_value(argv: list[str], flag: str, default: str) -> str:
    """`--flag=path` — lets a harness point the gate at a copy of its inputs
    so an observed-red run never edits the tree."""
    for a in argv:
        if a.startswith(flag + "="):
            return os.path.abspath(a.split("=", 1)[1])
    return default


def main(argv: list[str]) -> int:
    global GRANDFATHER
    offline = "--offline" in argv
    followups = _flag_value(argv, "--followups", FOLLOWUPS)
    GRANDFATHER = _flag_value(argv, "--grandfather", GRANDFATHER)
    if not os.path.isfile(followups):
        print("followups owners: docs/FOLLOWUPS.md is missing", file=sys.stderr)
        return 2
    rows = registry_rows()
    if rows is None:
        print("followups owners: IMPLEMENTATION_INDEX.md is missing", file=sys.stderr)
        return 2
    families = frozenset(p for p in (family_prefix(c) for c in rows) if p)
    if not families:
        print("followups owners: the index §2 registry parsed to no families", file=sys.stderr)
        return 2
    with open(followups, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    items = parse_items(lines)
    if not items:
        print("followups owners: no work items found", file=sys.stderr)
        return 2
    grandfather = read_grandfather(GRANDFATHER)
    if grandfather is not None and not grandfather:
        print(
            f"followups owners: {os.path.relpath(GRANDFATHER, ROOT)} exists but lists "
            "nothing — delete it (a grandfather with nothing to cover is a hiding place)",
            file=sys.stderr,
        )
        return 2
    resolver = Resolver(families, DESIGN_DIR, None if offline else gh_pr_state)
    bad = check(items, grandfather, resolver)
    if bad:
        for b in bad:
            print(b)
        print(f"\n{len(bad)} FOLLOWUPS Owner: failure(s).", file=sys.stderr)
        return 1
    owned = sum(1 for it in items if it.owners)
    grandfathered = len(items) - owned
    note = ""
    if resolver.unverified_prs:
        note = (
            f"; --offline: PR-owned rows NOT verified open: "
            f"{sorted(set(resolver.unverified_prs))}"
        )
    print(
        f"followups owners: {len(items)} items — {owned} owned and resolving, "
        f"{grandfathered} grandfathered by exact title ({len(families)} families){note}"
    )
    return 0


def _selftest() -> int:
    """Every leg in both directions: it fires, and it stays silent."""
    import tempfile

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        design = os.path.join(tmp, "docs", "design")
        completed = os.path.join(tmp, "docs", "completed")
        os.makedirs(design)
        os.makedirs(completed)
        open(os.path.join(design, "LIVE.md"), "w").close()
        open(os.path.join(completed, "DONE.md"), "w").close()
        global ROOT
        saved_root = ROOT
        ROOT = tmp
        try:
            states = {1: "OPEN", 2: "MERGED", 3: "CLOSED"}
            online = Resolver(
                frozenset({"STX", "SP-T"}), design, lambda n: states.get(n)
            )
            offline = Resolver(frozenset({"STX"}), design, None)
            owner_cases = [
                ("live doc", online, "[`LIVE.md`](design/LIVE.md)", True),
                ("live doc with section", online, "[`LIVE.md`](design/LIVE.md) §3", True),
                ("live doc with note", online, "[`LIVE.md`](design/LIVE.md) — after PR B", True),
                ("completed doc", online, "[`DONE.md`](completed/DONE.md)", False),
                ("missing doc", online, "[`NOPE.md`](design/NOPE.md)", False),
                ("open PR", online, "PR #1", True),
                ("merged PR", online, "PR #2", False),
                ("closed PR", online, "PR #3", False),
                ("unknown PR", online, "PR #9", False),
                ("known family", online, "STX-", True),
                ("known family, bold", online, "**STX-**", True),
                ("known infix family", online, "SP-T", True),
                ("unknown family", online, "ZZZ-", False),
                ("prose owner", online, "the DRS-E2 lane", False),
                ("empty", online, "", False),
                ("offline PR passes, recorded", offline, "PR #77", True),
            ]
            for name, res, value, must_pass in owner_cases:
                got = res.resolve(value) is None
                if got != must_pass:
                    failures.append(
                        f"selftest owner {name!r}: expected resolve={must_pass}, "
                        f"got {got} ({res.resolve(value)})"
                    )
            if offline.unverified_prs != [77]:
                failures.append(f"selftest: offline did not record PR 77: {offline.unverified_prs}")

            def items_of(text: str) -> list[Item]:
                return parse_items(text.splitlines(keepends=True))

            owned = "- **Owned row.** body\n  - Target: pre-genesis\n  - Owner: STX-\n"
            unowned = "- **Old row.** body\n  - Target: pre-genesis\n"
            twice = (
                "- **Twice.** body\n  - Target: pre-genesis\n  - Owner: STX-\n  - Owner: STX-\n"
            )
            struck = "- ~~**Done row**~~ — DONE\n  - Target: pre-genesis\n  - Owner: STX-\n"
            gf = frozenset({"Old row."})
            set_cases = [
                ("owned resolves", owned, frozenset(), False),
                ("grandfathered exact", unowned, gf, False),
                ("new unowned row", unowned + "- **New row.** x\n  - Target: V4\n", gf, True),
                ("burned down but still listed", owned, gf, True),
                ("two Owner: lines", twice, frozenset(), True),
                ("struck-through row is an item and its Owner: counts", struck, frozenset(), False),
                ("no grandfather file, all owned", owned, None, False),
            ]
            for name, text, g, must_fire in set_cases:
                bad = check(items_of(text), g, online)
                if bool(bad) != must_fire:
                    failures.append(
                        f"selftest set {name!r}: expected fire={must_fire}, got {bad}"
                    )
        finally:
            ROOT = saved_root
    if failures:
        for f in failures:
            print(f, file=sys.stderr)
        return 1
    print("followups owners selftest: 16 owner cases + 7 set cases, both directions exercised")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    sys.exit(main(sys.argv[1:]))
