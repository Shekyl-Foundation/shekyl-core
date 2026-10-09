#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Self-test for check_dial_path_freeze.py: each verdict the gate can give is
# bitten in a synthetic repository, so a gate that stopped reading bodies
# would be caught here before it passed a real edit. Named for the property
# each case holds.

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_dial_path_freeze.py"
LIST = "scripts/ci/dial_path_freeze.tsv"
BRIEF = "docs/design/P2P_3_SLICE_3_DIALER_BRIEF.md"
INL = "src/p2p/net_node.inl"
ZONE = "src/p2p/zone_server.h"

ALPHA = """  template<class t>
  bool node_server<t>::alpha(int n)
  {
    // a brace in a comment { does not count
    MERROR("a brace in a string { does not count either");
    if (n > 0) { return true; }
    return false;
  }
"""

IDLE = """  template<class t>
  bool node_server<t>::idle_worker()
  {
    m_a.do_call(boost::bind(&node_server<t>::alpha, this));
    m_b.do_call(boost::bind(&node_server<t>::beta, this));
    return true;
  }
"""

BETA = """  template<class t>
  bool node_server<t>::beta()
  {
    return true;
  }
"""

ZONE_TEXT = """struct zone_server
{
  open_outcome open(const address& a, context& out)
  {
    return open_outcome::ok;
  }
};
"""

LIST_TEXT = (
    "# frozen\n"
    f"body\t{INL}\tnode_server<t>::alpha(\n"
    f"body\t{ZONE}\topen_outcome open(\n"
    f"calls\t{INL}\tnode_server<t>::idle_worker(\talpha\n"
)


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t",
            "PATH": "/usr/bin:/bin",
        },
    )


def write(repo: Path, rel: str, text: str | None) -> None:
    path = repo / rel
    if text is None:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def repo_with(
    base: dict[str, str | None], head: dict[str, str | None]
) -> Path:
    repo = Path(tempfile.mkdtemp(prefix="freeze-"))
    git(repo, "init", "-q", "-b", "main")
    for rel, text in base.items():
        write(repo, rel, text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base", "--allow-empty")
    for rel, text in head.items():
        write(repo, rel, text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "head", "--allow-empty")
    return repo


def gate(repo: Path) -> tuple[int, str]:
    done = subprocess.run(
        [sys.executable, str(GATE), "--repo", str(repo), "--base", "HEAD~1", "--head", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, done.stdout + done.stderr


BASE = {INL: ALPHA + IDLE + BETA, ZONE: ZONE_TEXT, LIST: LIST_TEXT, BRIEF: "# brief\n"}

CASES: list[tuple[str, dict[str, str | None], int, str]] = [
    (
        "an untouched tree passes with every row unchanged",
        {},
        0,
        "3 rows judged, 0 failed",
    ),
    (
        "a body edit inside a frozen function fails and shows the diff",
        {INL: ALPHA.replace("return false;", "return !!n;") + IDLE + BETA},
        1,
        "alpha: body changed",
    ),
    (
        "a comment edit inside a frozen body is a body change",
        {INL: ALPHA.replace("does not count\n", "does not count at all\n") + IDLE + BETA},
        1,
        "alpha: body changed",
    ),
    (
        "deleting a frozen function passes",
        {INL: IDLE + BETA},
        0,
        "alpha: deleted",
    ),
    (
        "deleting the whole file passes every row in it",
        {INL: None},
        0,
        "alpha: deleted",
    ),
    (
        "a frozen function elsewhere in the file is still found and judged",
        {INL: BETA + IDLE + ALPHA},
        0,
        "alpha: unchanged",
    ),
    (
        "editing an unfrozen function in the same file passes",
        {INL: ALPHA + IDLE + BETA.replace("return true;", "return false;")},
        0,
        "3 rows judged, 0 failed",
    ),
    (
        "editing a frozen call line fails",
        {INL: ALPHA + IDLE.replace("::alpha, this", "::alpha, this, 1") + BETA},
        1,
        "the frozen call lines changed",
    ),
    (
        "deleting the frozen call line passes while the enclosing function stays",
        {INL: ALPHA + IDLE.replace("    m_a.do_call(boost::bind(&node_server<t>::alpha, this));\n", "") + BETA},
        0,
        "calls deleted",
    ),
    (
        "editing an unfrozen call line in the enclosing function passes",
        {INL: ALPHA + IDLE.replace("::beta, this", "::beta, this, 2") + BETA},
        0,
        "inside idle_worker: unchanged",
    ),
    (
        "a header-defined frozen body is judged like an .inl one",
        {ZONE: ZONE_TEXT.replace("open_outcome::ok", "open_outcome::fail")},
        1,
        "open: body changed",
    ),
    (
        "a row the base does not have fails rather than being skipped",
        {LIST: LIST_TEXT + f"body\t{INL}\tnode_server<t>::gamma(\n"},
        1,
        "gamma: not found at base (rule 47)",
    ),
    (
        "removing a row while its function is present fails without a ruling",
        {LIST: LIST_TEXT.replace(f"body\t{INL}\tnode_server<t>::alpha(\n", "")},
        1,
        "row removed while the function is still present",
    ),
    (
        "removing a row with a dated ruling by Rick in the brief passes and is reported",
        {
            LIST: LIST_TEXT.replace(f"body\t{INL}\tnode_server<t>::alpha(\n", ""),
            BRIEF: "# brief\n\n**Ruling 2026-10-09 (Rick).** `alpha` is unfrozen: reason.\n",
        },
        0,
        "unfrozen by ruling",
    ),
    (
        "removing a row whose function is also deleted passes",
        {
            LIST: LIST_TEXT.replace(f"body\t{INL}\tnode_server<t>::alpha(\n", ""),
            INL: IDLE + BETA,
        },
        0,
        "row retired, function deleted",
    ),
    (
        "an empty list at base is the discharged freeze",
        {},
        0,
        "freeze is discharged",
    ),
]


def main() -> int:
    failures = 0
    for name, head, want_rc, want_text in CASES:
        base = dict(BASE)
        if name.startswith("an empty list"):
            base[LIST] = "# nothing left\n"
        repo = repo_with(base, head)
        rc, out = gate(repo)
        ok = rc == want_rc and want_text in out
        print(("ok   " if ok else "FAIL ") + name)
        if not ok:
            failures += 1
            print(f"  want rc={want_rc} containing {want_text!r}; got rc={rc}\n{out}")

    # The list introduced by the change itself: read at head, judged against
    # the base bodies, so the gate passes its own first PR.
    repo = repo_with({INL: ALPHA + IDLE + BETA, ZONE: ZONE_TEXT, BRIEF: "#\n"}, {LIST: LIST_TEXT})
    rc, out = gate(repo)
    ok = rc == 0 and "introduced by this change" in out and "3 rows judged, 0 failed" in out
    print(("ok   " if ok else "FAIL ") + "a list introduced at head is judged against base bodies")
    if not ok:
        failures += 1
        print(out)

    # No list anywhere: the gate has no subject and says so.
    repo = repo_with({INL: ALPHA}, {})
    rc, out = gate(repo)
    ok = rc == 2 and "no subject" in out
    print(("ok   " if ok else "FAIL ") + "a missing list is a configuration failure, not a pass")
    if not ok:
        failures += 1
        print(out)

    print(f"{failures} failing case(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
