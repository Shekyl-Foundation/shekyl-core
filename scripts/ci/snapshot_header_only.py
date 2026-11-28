#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Which changed schema snapshots changed only their generated header.

A `.snap` file is a generated header, a leading run of lines that begin with
`#`, followed by the body, the format itself. A change confined to the header
(a reworded comment, a renumbered rule citation) moves no byte of any
encoding, so it owes no version bump. The schema-snapshot gate
(`.github/workflows/schema-snapshot.yml`, enforce-version-bump) drops the
files this script prints from the list its version checks read. Ruled
2026-11-27.

Only the leading run of `#` lines is the header. A `#` line after the first
body line is body, so a change to it still demands the bump; and because a
`#` line inside a body would read as a comment to anyone looking at the file,
the gate refuses any snapshot at the head that has one, and names it.

A snapshot added or deleted is never header-only.

Usage:
  snapshot_header_only.py --base REV --head REV FILE...
      Print each FILE that is a `.snap` at both revisions with the same
      body. Exit 1, naming the files, if any `.snap` tracked at REV --head
      has a `#` line after its first body line.
  snapshot_header_only.py --selftest
      Build scratch repositories and require each verdict.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile


def split(text: str) -> tuple[list[str], list[str]]:
    """(header, body): the leading run of `#` lines, and the rest."""
    lines = text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    return lines[:i], lines[i:]


def late_hash_lines(text: str) -> list[int]:
    """1-based numbers of the `#` lines that follow the first body line."""
    header, body = split(text)
    return [len(header) + k + 1 for k, line in enumerate(body) if line.startswith("#")]


def show(root: str, rev: str, path: str) -> str | None:
    r = subprocess.run(["git", "-C", root, "show", f"{rev}:{path}"], capture_output=True)
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8")


def snaps_at(root: str, rev: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-tree", "-r", "--name-only", rev],
                         capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\n") if f.endswith(".snap")]


def run(root: str, base: str, head: str, files: list[str]) -> int:
    refused = []
    for path in snaps_at(root, head):
        late = late_hash_lines(show(root, head, path) or "")
        if late:
            refused.append(f"{path}: a # line after the body began, at line {', '.join(map(str, late))}")
    if refused:
        for r in refused:
            print(f"::error file={r.split(':', 1)[0]}::{r}", file=sys.stderr)
        print("FAIL: a snapshot's # lines are its generated header and come first; a # line "
              "inside the body cannot be told from a comment. Fix the generator.", file=sys.stderr)
        return 1
    for path in files:
        if not path.endswith(".snap"):
            continue
        a, b = show(root, base, path), show(root, head, path)
        if a is not None and b is not None and split(a)[1] == split(b)[1]:
            print(path)
    return 0


def selftest() -> int:
    me = os.path.abspath(__file__)
    header = "# generated snapshot (rule 142). Do not edit by hand.\n# regenerate: UPDATE_SNAPSHOTS=1 ...\n"
    body = "codec = x\nfixed_width = 8\n"

    def verdict(before: dict[str, str], after: dict[str, str]) -> tuple[int, list[str]]:
        with tempfile.TemporaryDirectory() as d:
            def commit(tree: dict[str, str]) -> str:
                for f in os.listdir(d):
                    if f != ".git":
                        os.remove(os.path.join(d, f))
                for rel, text in tree.items():
                    with open(os.path.join(d, rel), "w", encoding="utf-8") as fh:
                        fh.write(text)
                subprocess.run(["git", "-C", d, "add", "-A"], check=True)
                subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit",
                                "-q", "--allow-empty", "-m", "x"], check=True)
                return subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True,
                                      text=True, check=True).stdout.strip()

            subprocess.run(["git", "init", "-q", d], check=True)
            base, head = commit(before), commit(after)
            files = sorted(set(before) | set(after))
            r = subprocess.run([sys.executable, me, "--root", d, "--base", base, "--head", head, *files],
                               capture_output=True, text=True)
            return r.returncode, [f for f in r.stdout.split("\n") if f]

    renumbered = header.replace("142", "242")
    cases = [
        ("the header reworded: header-only",
         {"a.snap": header + body}, {"a.snap": renumbered + body}, (0, ["a.snap"])),
        ("a body line changed: owes the bump",
         {"a.snap": header + body}, {"a.snap": header + body.replace("8", "9")}, (0, [])),
        ("header and body changed: owes the bump",
         {"a.snap": header + body}, {"a.snap": renumbered + body.replace("8", "9")}, (0, [])),
        ("a snapshot added: owes the bump",
         {"b.txt": "x\n"}, {"b.txt": "x\n", "a.snap": header + body}, (0, [])),
        ("a snapshot deleted: owes the bump",
         {"a.snap": header + body, "b.txt": "x\n"}, {"b.txt": "x\n"}, (0, [])),
        ("a header-only change to a file that is not a snapshot: not listed",
         {"a.txt": header + body}, {"a.txt": renumbered + body}, (0, [])),
        # The negative test the ruling asks for: a body line that begins with
        # `#` and changes. Stripping every `#` line would call it header-only;
        # the leading run alone keeps it in the body, and the gate refuses it.
        ("a # line in the body changed: refused, never header-only",
         {"a.snap": header + body}, {"a.snap": header + body + "# 1\n"}, (1, [])),
        ("a # line in the body at the head, the change elsewhere: refused",
         {"a.snap": header + body, "c.snap": header + body},
         {"a.snap": renumbered + body, "c.snap": header + "codec = y\n# kept\n"}, (1, [])),
    ]
    ok = True
    # The comparison itself, refusal aside: a changed `#` line after the
    # first body line is a body change.
    mid_a, mid_b = header + "codec = x\n# a\nfixed_width = 8\n", header + "codec = x\n# b\nfixed_width = 8\n"
    passed = split(mid_a)[1] != split(mid_b)[1]
    ok &= passed
    print(f"selftest: a changed # line inside the body compares as a body change: "
          f"{'as required' if passed else 'WRONG'}")
    for name, before, after, want in cases:
        got = verdict(before, after)
        passed = got == want
        ok &= passed
        print(f"selftest: {name}: {'as required' if passed else f'WRONG (got {got}, want {want})'}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--base")
    ap.add_argument("--head")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.base or not a.head:
        ap.error("--base and --head are required")
    return run(a.root, a.base, a.head, a.files)


if __name__ == "__main__":
    sys.exit(main())
