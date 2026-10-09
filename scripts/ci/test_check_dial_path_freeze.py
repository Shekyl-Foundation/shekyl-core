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
HDR = "src/p2p/net_node.h"
ZONE = "src/p2p/zone_server.h"

ALPHA = """  template<class t>
  bool node_server<t>::alpha(int n)
  {
    // a brace in a comment { does not count
    MERROR("a brace in a string { does not count either");
    if (n > 1'000) { return true;
    }
    const int tail = n * 2;
    return tail > 0;
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

# Declarations, as net_node.h holds them. `alpha` is declared here, so a
# deletion that leaves the declaration behind is not a deletion.
HDR_TEXT = """struct node_server
{
  // the dial path
  bool alpha(int n);
  bool idle_worker();
  bool beta();
};
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
    f"shrink\t{INL}\n"
    f"shrink\t{HDR}\n"
    f"body\t{INL}\tnode_server<t>::alpha(\n"
    f"body\t{ZONE}\topen_outcome open(\n"
    f"calls\t{INL}\tnode_server<t>::idle_worker(\talpha\n"
)

INL_TEXT = ALPHA + IDLE + BETA
BRIEF_TEXT = "# brief\n"
ALPHA_ROW = f"body\t{INL}\tnode_server<t>::alpha(\n"
UNFREEZE_ALPHA = "**UNFREEZE (Rick, 2026-10-09):** node_server<t>::alpha( — the reason.\n"
UNFREEZE_INL = f"**UNFREEZE (Rick, 2026-10-09):** {INL} — the reason.\n"


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


def repo_with(base: dict[str, str | None], head: dict[str, str | None]) -> Path:
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


BASE: dict[str, str | None] = {
    INL: INL_TEXT,
    HDR: HDR_TEXT,
    ZONE: ZONE_TEXT,
    LIST: LIST_TEXT,
    BRIEF: BRIEF_TEXT,
}

# alpha gone everywhere: definition, declaration, and the call in idle_worker.
WITHOUT_ALPHA = {
    INL: IDLE.replace("    m_a.do_call(boost::bind(&node_server<t>::alpha, this));\n", "") + BETA,
    HDR: HDR_TEXT.replace("  bool alpha(int n);\n", ""),
}

CASES: list[tuple[str, dict[str, str | None], int, str]] = [
    (
        "an untouched tree passes with every row unchanged",
        {},
        0,
        "5 rows judged, 0 failed",
    ),
    (
        "a body edit inside a frozen function fails and shows the diff",
        {INL: ALPHA.replace("return tail > 0;", "return tail >= 0;") + IDLE + BETA},
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
        "an edit after a digit separator is still inside the body",
        {INL: ALPHA.replace("const int tail = n * 2;", "const int tail = n * 3;") + IDLE + BETA},
        1,
        "alpha: body changed",
    ),
    (
        "deleting a frozen function, its declaration and its call passes",
        WITHOUT_ALPHA,
        0,
        "alpha: deleted",
    ),
    (
        "deleting the definition but leaving the declaration is not a deletion",
        {INL: WITHOUT_ALPHA[INL]},
        1,
        "renamed or re-signed, not deleted",
    ),
    (
        "renaming a frozen function fails: the body survives under another name",
        {
            INL: INL_TEXT.replace("alpha", "gamma"),
            HDR: HDR_TEXT.replace("alpha", "gamma"),
        },
        1,
        "body survives under another signature",
    ),
    (
        "re-signing a frozen function fails: the anchor is gone, the name is not",
        {INL: INL_TEXT.replace("node_server<t>::alpha(int n)", "node_server<t>::alpha (int n)")},
        1,
        "renamed or re-signed, not deleted",
    ),
    (
        "deleting every frozen file passes every row in them",
        {INL: None, HDR: None, ZONE: None},
        0,
        "5 rows judged, 0 failed",
    ),
    (
        "a frozen function elsewhere in the file is still found and judged",
        {INL: BETA + IDLE + ALPHA},
        0,
        "alpha: unchanged",
    ),
    (
        "editing an unfrozen function without growing the file passes",
        {INL: ALPHA + IDLE + BETA.replace("return true;", "return false;")},
        0,
        "5 rows judged, 0 failed",
    ),
    (
        "editing a frozen call line fails",
        {INL: ALPHA + IDLE.replace("::alpha, this", "::alpha, this, 1") + BETA},
        1,
        "the frozen call lines changed",
    ),
    (
        "deleting the call while the callee is still present is not a deletion",
        {INL: ALPHA + IDLE.replace("    m_a.do_call(boost::bind(&node_server<t>::alpha, this));\n", "") + BETA},
        1,
        "the calls are gone but `alpha` is still named",
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
        "a word that is only a string literal elsewhere does not keep a deleted function alive",
        {ZONE: ZONE_TEXT.replace(
            "  open_outcome open(const address& a, context& out)\n  {\n    return open_outcome::ok;\n  }\n",
            '  const char* note = "open";\n',
        )},
        0,
        "open: deleted",
    ),
    (
        "a row the base does not have fails rather than being skipped",
        {LIST: LIST_TEXT + f"body\t{INL}\tnode_server<t>::delta(\n"},
        1,
        "delta: not found at base (rule 47)",
    ),
    (
        "removing a row while its function is present fails without an UNFREEZE line",
        {LIST: LIST_TEXT.replace(ALPHA_ROW, "")},
        1,
        "row removed while the function is still present",
    ),
    (
        "removing a row with a new UNFREEZE line naming the full anchor passes",
        {LIST: LIST_TEXT.replace(ALPHA_ROW, ""), BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_ALPHA},
        0,
        "row retired under an UNFREEZE line",
    ),
    (
        "a body change under a new UNFREEZE line naming the full anchor passes",
        {INL: ALPHA.replace("return tail > 0;", "return tail >= 0;") + IDLE + BETA, BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_ALPHA},
        0,
        "changed under an UNFREEZE line",
    ),
    (
        "an UNFREEZE line naming only the bare name is not read",
        {
            LIST: LIST_TEXT.replace(ALPHA_ROW, ""),
            BRIEF: BRIEF_TEXT + "\n**UNFREEZE (Rick, 2026-10-09):** alpha — the reason.\n",
        },
        1,
        "row removed while the function is still present",
    ),
    (
        "the old loose form, a name beside Rick and a date, is not read",
        {
            LIST: LIST_TEXT.replace(ALPHA_ROW, ""),
            BRIEF: BRIEF_TEXT + "\n**Ruling 2026-10-09 (Rick).** `alpha` is unfrozen: reason.\n",
        },
        1,
        "row removed while the function is still present",
    ),
    (
        "removing a row whose function is also deleted passes",
        {LIST: LIST_TEXT.replace(ALPHA_ROW, ""), **WITHOUT_ALPHA},
        0,
        "row retired, function deleted",
    ),
    (
        "growing a shrink-only file by one code line fails",
        {INL: INL_TEXT + "  int extra_code_line;\n"},
        1,
        "non-blank, non-comment lines. src/p2p/net_node.inl is shrink-only",
    ),
    (
        "a net shrink with lines added passes",
        {INL: ALPHA + IDLE + "  int one_added_line;\n"},
        0,
        "net_node.inl: shrink-only: ",
    ),
    (
        "a comment-only addition passes",
        {INL: INL_TEXT + "  // a note\n  /* and a block\n     comment */\n"},
        0,
        "net_node.inl: shrink-only: ",
    ),
    (
        "deleting comments does not buy room: code lines are what is counted",
        {HDR: HDR_TEXT.replace("  // the dial path\n", "  bool extra();\n")},
        1,
        "net_node.h is shrink-only",
    ),
    (
        "growth under a new UNFREEZE line naming the file passes",
        {INL: INL_TEXT + "  int extra_code_line;\n", BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_INL},
        0,
        "under an UNFREEZE line naming the file",
    ),
    (
        "an UNFREEZE line that was already at base does not count",
        {INL: INL_TEXT + "  int extra_code_line;\n"},
        1,
        "already present at base, not counted",
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
        if name.startswith("an UNFREEZE line that was already at base"):
            base[BRIEF] = BRIEF_TEXT + "\n" + UNFREEZE_INL
        repo = repo_with(base, head)
        rc, out = gate(repo)
        ok = rc == want_rc and want_text in out
        print(("ok   " if ok else "FAIL ") + name)
        if not ok:
            failures += 1
            print(f"  want rc={want_rc} containing {want_text!r}; got rc={rc}\n{out}")

    # The list introduced by the change itself: read at head, judged against
    # the base bodies, so the gate passes its own first PR.
    repo = repo_with({INL: INL_TEXT, HDR: HDR_TEXT, ZONE: ZONE_TEXT, BRIEF: BRIEF_TEXT}, {LIST: LIST_TEXT})
    rc, out = gate(repo)
    ok = rc == 0 and "introduced by this change" in out and "5 rows judged, 0 failed" in out
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
