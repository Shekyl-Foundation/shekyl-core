# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Release-archive docs gate: every host's release archive carries the user
# guide, and none carries the repository README. The README is written for
# someone building from source; the person who opens a binary archive needs
# the guide to running what is in it (alpha.11 bug hunt A10: the shipped
# README named flags that do not exist and said no packages exist, beside the
# packages).
#
# What an archive carries beside the binaries is `dist.files` in
# rust/xtask/matrix.toml, and each gitian descriptor stages it with
# `cargo xtask dist`. So the gate reads the matrix's rows, and holds every
# descriptor to that staging line with no `cp` of its own into bin/. Instance
# of 47-gate-subject-assertion.mdc: it fails if a descriptor or a host's row
# is missing, or a row carries no docs at all, rather than passing over
# nothing.
#
# Usage: check_release_archive_docs.py [--selftest]

from __future__ import annotations

import os
import re
import sys
import tomllib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GITIAN = os.path.join(ROOT, "contrib", "gitian")
MATRIX = os.path.join(ROOT, "rust", "xtask", "matrix.toml")
DESCRIPTORS = ("linux", "freebsd", "osx", "win")
RELEASE_HOSTS = 6
SHIPPED = "docs/USER_GUIDE.md"
REFUSED = "README.md"
STAGE = re.compile(r"^\s*\(cd \.\./rust && cargo xtask dist --host \$\{i\} --out \.\./build/bin\)\s*$", re.M)
# A `cp` whose last argument is the archive's bin directory.
COPY = re.compile(r"^\s*cp\s+(?P<sources>.+?)\s+bin/?\s*$", re.M)


def check_descriptor(rel: str, text: str) -> list[str]:
    problems = []
    if not STAGE.search(text):
        problems.append(f"{rel}: no `cargo xtask dist` line; the gate cannot see what the archive ships")
    for match in COPY.finditer(text):
        problems.append(f"{rel}: copies {match.group('sources')} into bin/ outside the matrix")
    return problems


def check_matrix(text: str) -> list[str]:
    hosts = [h for h in tomllib.loads(text).get("host", []) if "dist" in h]
    if len(hosts) != RELEASE_HOSTS:
        return [f"rust/xtask/matrix.toml: {len(hosts)} release hosts, not {RELEASE_HOSTS}"]
    problems = []
    for host in hosts:
        sources = [row[0] for row in host["dist"]["files"]]
        if SHIPPED not in sources:
            problems.append(f"host {host['name']}: the archive does not ship {SHIPPED}")
        if REFUSED in sources:
            problems.append(f"host {host['name']}: the archive ships the repository README ({REFUSED})")
    return problems


def check(name: str) -> list[str]:
    path = os.path.join(GITIAN, f"gitian-{name}.yml")
    rel = os.path.relpath(path, ROOT)
    if not os.path.isfile(path):
        return [f"{rel}: missing; the gate has no descriptor to read"]
    with open(path, encoding="utf-8") as fh:
        return check_descriptor(rel, fh.read())


def selftest() -> int:
    with open(MATRIX, encoding="utf-8") as fh:
        matrix = fh.read()
    line = "    (cd ../rust && cargo xtask dist --host ${i} --out ../build/bin)\n"
    cases = [
        ("the committed matrix is clean", check_matrix(matrix) == []),
        ("a descriptor that stages through the xtask is clean", check_descriptor("d", line) == []),
        ("a descriptor with no staging line is refused", bool(check_descriptor("d", "make\n"))),
        ("a cp of the README into bin is refused", bool(check_descriptor("d", line + "    cp ../README.md bin\n"))),
        ("a host that drops the guide is refused",
         bool(check_matrix(matrix.replace('["docs/USER_GUIDE.md", "USER_GUIDE.md", "644"],\n', "", 1)))),
        ("a host that ships the README is refused",
         bool(check_matrix(matrix.replace('["LICENSE", "LICENSE", "644"],', '["README.md", "README.md", "644"],', 1)))),
        ("a missing host row is refused",
         bool(check_matrix(matrix.replace('name = "x86_64-unknown-freebsd"\ntriple = "x86_64-unknown-freebsd"\nbinaries = ["shekyld", "shekyl-cli", "shekyl-wallet-rpc", "shekyl-rpc-tunnel"]\n\n[host.dist]',
                                          'name = "x86_64-unknown-freebsd"\ntriple = "x86_64-unknown-freebsd"\nbinaries = ["shekyld", "shekyl-cli", "shekyl-wallet-rpc", "shekyl-rpc-tunnel"]\n\n[host.unused]', 1)))),
    ]
    failures = 0
    for label, ok in cases:
        print(f"{'ok  ' if ok else 'FAIL'} {label}")
        failures += 0 if ok else 1
    print("selftest: " + ("passed" if failures == 0 else f"{failures} failure(s)"))
    return 1 if failures else 0


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    with open(MATRIX, encoding="utf-8") as fh:
        problems = check_matrix(fh.read())
    problems += [p for name in DESCRIPTORS for p in check(name)]
    if problems:
        for p in problems:
            print(p)
        print(f"\n{len(problems)} release-archive docs problem(s).", file=sys.stderr)
        return 1
    print(f"release-archive docs: {len(DESCRIPTORS)} descriptors ship {SHIPPED}, none the repository README")
    return 0


if __name__ == "__main__":
    sys.exit(main())
