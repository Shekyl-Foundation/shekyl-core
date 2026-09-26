#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Pinned-anchor gate: a `file:line` citation must resolve in the tree it is
# PINNED to, not in the working tree the author happened to have open.
#
# THE DEFECT THIS EXISTS FOR. PR #812's rows cite `dev` at a stated SHA. Five
# anchors in one block were derived from the author's working tree instead,
# where that PR's own edits shift `src/p2p/net_node.inl` by +10 lines. The
# SUBSTANCE was right every time and the line numbers were not, which is the
# worst shape: a reviewer who spot-checks one anchor against the working tree
# sees agreement, and a reader at the pin sees `return;` where the row promised
# a network-id check. A row whose falsifier points at the wrong line is a row
# the next reader cannot run.
#
# Three separate sets of bad anchors reached a peer session from this lane
# before this gate existed. Each time the reviewer caught it by reading; that
# is not a mechanism.
#
# THE RULE. A document that states a pin ("verified at `dev` `<sha>`", or
# "anchors pinned to `dev` `<sha>`") has every `path:line` citation in it
# checked against `git show <sha>:<path>`. A citation whose line is past EOF at
# the pin, or whose pinned content is blank, is refused.
#
# SUBJECT (rule 47). Refuses when no document states a pin, or when a stated
# pin is not a resolvable object — an empty population is a missing subject.
#
# --selftest exercises: a citation that resolves; one past EOF; one landing on
# a blank line; a doc with no pin (skipped); an unresolvable pin (refused).
from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PIN_RE = re.compile(r"(?:pinned to|verified at)\s+`?dev`?\s+`([0-9a-f]{7,40})`", re.I)
CITE_RE = re.compile(r"`?((?:src|contrib|rust|tests|scripts)/[A-Za-z0-9_./-]+\.(?:inl|cpp|h|hpp|rs|py|sh))`?[)\]`]*\s*:\s*(\d+)")


class GateError(Exception):
    """The gate could not ask its question (exit 2)."""


def blob(sha: str, path: str) -> list[str] | None:
    r = subprocess.run(["git", "-C", ROOT, "show", f"{sha}:{path}"],
                       capture_output=True, text=True)
    return None if r.returncode else r.stdout.splitlines()


def check_text(text: str, label: str, resolver) -> list[str]:
    """Each pin governs the region from where it is stated until the NEXT pin.

    A document may state several pins -- a round document pinned at its own SHA
    can carry a later section re-pinned after `dev` moved. Applying the first
    pin to every citation makes a borrowed citation inherit the lender's pin,
    which is the very defect this gate exists to catch, one level up.
    """
    pins = list(PIN_RE.finditer(text))
    if not pins:
        return []
    fails = []
    for i, m in enumerate(pins):
        sha = m.group(1)
        end = pins[i + 1].start() if i + 1 < len(pins) else len(text)
        region = text[m.start():end]
        fails += _check_region(region, label, sha, resolver)
    return fails


def _check_region(text: str, label: str, sha: str, resolver) -> list[str]:
    lines = resolver(sha)
    if lines is None:
        raise GateError(f"{label}: stated pin {sha} does not resolve")
    fails = []
    for cm in CITE_RE.finditer(text):
        path, ln = cm.group(1), int(cm.group(2))
        body = lines(path)
        if body is None:
            continue  # path absent at the pin: a different gate's question
        if ln > len(body):
            fails.append(f"{label}: {path}:{ln} is past EOF at pin {sha} ({len(body)} lines)")
        elif not body[ln - 1].strip():
            fails.append(f"{label}: {path}:{ln} is a BLANK line at pin {sha}")
    return fails


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    docs = []
    for base, _, names in os.walk(os.path.join(ROOT, "docs")):
        for n in names:
            if n.endswith(".md"):
                docs.append(os.path.join(base, n))
    if not docs:
        print("FAIL: no documents found — missing subject (rule 47)")
        return 2
    pinned, fails = 0, []
    for d in docs:
        text = open(d, encoding="utf-8", errors="replace").read()
        if not PIN_RE.search(text):
            continue
        pinned += 1
        rel = os.path.relpath(d, ROOT)
        cache: dict[str, list[str] | None] = {}

        def resolver(sha, _cache=cache):
            def get(path):
                if path not in _cache:
                    _cache[path] = blob(sha, path)
                return _cache[path]
            return get
        try:
            fails += check_text(text, rel, resolver)
        except GateError as e:
            print(f"FAIL: {e}")
            return 2
    if pinned == 0:
        print("FAIL: no document states a pin — missing subject (rule 47)")
        return 2
    if fails:
        print("FAIL: pinned anchors that do not resolve at their stated pin:")
        for f in fails:
            print("  " + f)
        return 1
    print(f"pinned anchors: all citations resolve in {pinned} pinned document(s)")
    return 0


def selftest() -> int:
    def mk(files):
        def resolver(_sha):
            def get(path):
                return files.get(path)
            return get
        return resolver
    ok = "verified at `dev` `059aca264`\nsee `src/p2p/net_node.inl`:2\n"
    eof = "verified at `dev` `059aca264`\nsee `src/p2p/net_node.inl`:99\n"
    blank = "verified at `dev` `059aca264`\nsee `src/p2p/net_node.inl`:3\n"
    nopin = "see `src/p2p/net_node.inl`:99\n"
    files = {"src/p2p/net_node.inl": ["a", "b", "   "]}
    cases = [
        (ok, 0, "a resolving citation passes"),
        (eof, 1, "past EOF is refused"),
        (blank, 1, "a blank pinned line is refused"),
        (nopin, 0, "a doc with no pin is skipped"),
    ]
    for text, want, why in cases:
        got = len(check_text(text, "t", mk(files)))
        got = 1 if got else 0
        if got != want:
            print(f"SELFTEST FAIL: {why}")
            return 1
    try:
        check_text(ok, "t", lambda _sha: (_ for _ in ()).throw(GateError("x")))
    except GateError:
        pass
    print("selftest: 5 cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
