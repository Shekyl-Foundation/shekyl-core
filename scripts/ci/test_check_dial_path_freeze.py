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
NOTIFY = "src/cryptonote_protocol/levin_notify.cpp"

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

# `open` is an ordinary word: the file system handle below uses it too, and
# a log string names it. The row's witness is `open_outcome`.
ZONE_TEXT = """struct open_outcome { bool ok; };
struct zone_server
{
  open_outcome open(const address& a, context& out)
  {
    MINFO("seam open refused");
    return open_outcome{true};
  }
  void load() { src_file.open(path); }
};
"""
ZONE_WITHOUT_OPEN = """struct zone_server
{
  void load() { src_file.open(path); }
};
"""

NOTIFY_TEXT = """void notify::flush()
{
  // the relay timing
  schedule.flush();
}
void notify::stem(const tx& t)
{
  const auto plan = relay.plan(t);
  write(plan.target, t.bytes);
}
void notify::fluff(const tx& t)
{
  for (auto& peer : peers) write(peer, t.bytes);
  pool.set_relayed(t.id);
}
"""
NOTIFY_FLUSH = NOTIFY_TEXT[: NOTIFY_TEXT.index("void notify::stem")]
NOTIFY_REST = NOTIFY_TEXT[NOTIFY_TEXT.index("void notify::stem") :]
MOVED = "src/cryptonote_protocol/relay_notify.cpp"
MOVED_TOO = "src/cryptonote_protocol/relay_fluff.cpp"
PADDING = "".join(f"void notify::pad_{i}() {{ counters[{i}] += {i} * 7; }}\n" for i in range(40))

SHRINK_ROWS = f"shrink\t{INL}\nshrink\t{HDR}\nshrink\t{NOTIFY}\n"
FUNCTION_ROWS = (
    f"body\t{INL}\tnode_server<t>::alpha(\n"
    f"body\t{ZONE}\topen_outcome open(\topen_outcome\n"
    f"calls\t{INL}\tnode_server<t>::idle_worker(\talpha\n"
)
LIST_TEXT = "# frozen\n" + SHRINK_ROWS + FUNCTION_ROWS

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
    NOTIFY: NOTIFY_TEXT,
    LIST: LIST_TEXT,
    BRIEF: BRIEF_TEXT,
}
ROWS = 6

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
        f"{ROWS} rows judged, 0 failed",
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
        "moving a frozen function to another file fails: the definition moved, not deleted",
        {
            INL: IDLE + BETA,
            "src/p2p/dial_helpers.inl": ALPHA,
            HDR: HDR_TEXT.replace("  bool alpha(int n);\n", ""),
        },
        1,
        "the definition moved to src/p2p/dial_helpers.inl, not deleted",
    ),
    (
        "re-signing a frozen function fails: the anchor is gone, the name is not",
        {INL: INL_TEXT.replace("node_server<t>::alpha(int n)", "node_server<t>::alpha (int n)")},
        1,
        "renamed or re-signed, not deleted",
    ),
    (
        "deleting every frozen file passes every row in them",
        {INL: None, HDR: None, ZONE: None, NOTIFY: None},
        0,
        f"{ROWS} rows judged, 0 failed",
    ),
    (
        "a frozen function moved within the file is still found; the move adds lines",
        {INL: BETA + IDLE + ALPHA},
        1,
        "alpha: unchanged",
    ),
    (
        "an in-place edit with an equal line count is an added code line",
        {INL: ALPHA + IDLE + BETA.replace("return true;", "return false;")},
        1,
        "1 code line(s) added",
    ),
    (
        "swapping logic for a call into Rust fails without an UNFREEZE line",
        {INL: ALPHA + IDLE + BETA.replace("return true;", "return shekyl_beta();")},
        1,
        "net_node.inl takes deletions only",
    ),
    (
        "swapping logic for a call into Rust passes under an UNFREEZE line naming the file",
        {
            INL: ALPHA + IDLE + BETA.replace("return true;", "return shekyl_beta();"),
            BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_INL,
        },
        0,
        "added under an UNFREEZE line naming the file",
    ),
    (
        "a pure deletion passes",
        {INL: ALPHA + IDLE},
        0,
        "net_node.inl: shrink-only: ",
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
        "editing an unfrozen call line leaves the calls row unchanged and adds a code line",
        {INL: ALPHA + IDLE.replace("::beta, this", "::beta, this, 2") + BETA},
        1,
        "inside idle_worker: unchanged",
    ),
    (
        "a header-defined frozen body is judged like an .inl one",
        {ZONE: ZONE_TEXT.replace("open_outcome{true}", "open_outcome{false}")},
        1,
        "open: body changed",
    ),
    (
        "with a witness, the bare word surviving as a file handle and a log string does not block the deletion",
        {ZONE: ZONE_WITHOUT_OPEN},
        0,
        "open: deleted",
    ),
    (
        "with a witness, the witness surviving blocks the deletion",
        {ZONE: "struct open_outcome { bool ok; };\n" + ZONE_WITHOUT_OPEN},
        1,
        "`open_outcome` is still named",
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
        "a body change under an UNFREEZE line naming the anchor still adds a code line to the file",
        {INL: ALPHA.replace("return tail > 0;", "return tail >= 0;") + IDLE + BETA, BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_ALPHA},
        1,
        "changed under an UNFREEZE line",
    ),
    (
        "a body change under UNFREEZE lines naming the anchor and the file passes",
        {
            INL: ALPHA.replace("return tail > 0;", "return tail >= 0;") + IDLE + BETA,
            BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_ALPHA + UNFREEZE_INL,
        },
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
        "1 code line(s) added",
    ),
    (
        "a net shrink that still adds a code line fails",
        {INL: ALPHA + IDLE + "  int one_added_line;\n"},
        1,
        "net_node.inl takes deletions only",
    ),
    (
        "a comment-only addition passes",
        {INL: INL_TEXT + "  // a note\n  /* and a block\n     comment */\n"},
        0,
        "net_node.inl: shrink-only: ",
    ),
    (
        "editing a comment in a shrink file is not an added code line",
        {HDR: HDR_TEXT.replace("  // the dial path\n", "  // the dial path, frozen until the cutover\n")},
        0,
        "net_node.h: shrink-only: 6 -> 6 code lines, none added",
    ),
    (
        "deleting comments does not buy room: code lines are what is counted",
        {HDR: HDR_TEXT.replace("  // the dial path\n", "  bool extra();\n")},
        1,
        "net_node.h takes deletions only",
    ),
    (
        "levin_notify.cpp is held to the same rule",
        {NOTIFY: NOTIFY_TEXT.replace("schedule.flush();", "schedule.flush_now();")},
        1,
        "levin_notify.cpp takes deletions only",
    ),
    (
        "growth under a new UNFREEZE line naming the file passes",
        {INL: INL_TEXT + "  int extra_code_line;\n", BRIEF: BRIEF_TEXT + "\n" + UNFREEZE_INL},
        0,
        "under an UNFREEZE line naming the file",
    ),
    (
        "a real deletion of a shrink file passes",
        {NOTIFY: None},
        0,
        "levin_notify.cpp: shrink-only: file deleted",
    ),
    (
        "a plain rename of a shrink file fails: renamed, not deleted",
        {NOTIFY: None, MOVED: NOTIFY_TEXT},
        1,
        "renamed, not deleted (R100 src/cryptonote_protocol/relay_notify.cpp)",
    ),
    (
        "a rename with edits fails: renamed, not deleted",
        {NOTIFY: None, MOVED: NOTIFY_TEXT.replace("schedule.flush();", "schedule.flush_now();")},
        1,
        "renamed, not deleted",
    ),
    (
        "a split into two files fails: the code survives under src/",
        # The larger half is padded with new code, so git's byte similarity
        # stays under its rename threshold and this is the survival check's
        # own verdict, not git's.
        {NOTIFY: None, MOVED: NOTIFY_FLUSH, MOVED_TOO: NOTIFY_REST + PADDING},
        1,
        "renamed or split, not deleted",
    ),
    (
        "the cutover shape passes: every function deleted, the shrink rows kept",
        {**WITHOUT_ALPHA, ZONE: ZONE_WITHOUT_OPEN, LIST: "# frozen\n" + SHRINK_ROWS},
        0,
        "row retired, function deleted",
    ),
    (
        "a shrink row removed while its file exists fails",
        {LIST: LIST_TEXT.replace(f"shrink\t{INL}\n", "")},
        1,
        "row removed while the file is still present",
    ),
    (
        "after the cutover the function freeze is discharged and the shrink rows still judge",
        {INL: IDLE + BETA + "  int grown;\n"},
        1,
        "function freeze is discharged",
    ),
    (
        "an UNFREEZE line that was already at base does not count",
        {INL: INL_TEXT + "  int extra_code_line;\n"},
        1,
        "already present at base, not counted",
    ),
    (
        "an empty list at base is nothing frozen",
        {},
        0,
        "nothing is frozen",
    ),
]


def main() -> int:
    failures = 0
    for name, head, want_rc, want_text in CASES:
        base = dict(BASE)
        if name.startswith("an empty list"):
            base[LIST] = "# nothing left\n"
        if name.startswith("after the cutover"):
            base[LIST] = "# frozen\n" + SHRINK_ROWS
            base[INL] = IDLE + BETA
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
    repo = repo_with(
        {INL: INL_TEXT, HDR: HDR_TEXT, ZONE: ZONE_TEXT, NOTIFY: NOTIFY_TEXT, BRIEF: BRIEF_TEXT},
        {LIST: LIST_TEXT},
    )
    rc, out = gate(repo)
    ok = rc == 0 and "introduced by this change" in out and f"{ROWS} rows judged, 0 failed" in out
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
