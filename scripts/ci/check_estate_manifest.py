#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The estate rules are one text, held in shekyl-core and copied verbatim.

`.cursor/rules/ESTATE_MANIFEST` lists every estate file with its sha256: the
rules whose frontmatter says `scope: estate`, the vacated-number list, and the
three gates a consumer runs over its copies (this script, the scope gate and
the vacated-number gate). shekyl-core holds the manifest to its files; the
GUI and prism hold their copies to shekyl-core `dev`'s manifest (ruled
2026-11-19, Round 0 §7.2, and 2026-11-27: consumers check on pull requests
that touch `.cursor/rules/` and daily). The fix for any failure in a consumer
is to copy the file again from shekyl-core, never to edit the copy.

Usage:
  check_estate_manifest.py                       shekyl-core: the manifest matches the files
  check_estate_manifest.py --write               shekyl-core: rewrite the manifest
  check_estate_manifest.py --against FILE        a consumer: its copies match FILE
                                                 (shekyl-core dev's manifest)
  check_estate_manifest.py --selftest            plant a one-byte drift and more; require failures
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

RULES = ".cursor/rules"
MANIFEST = f"{RULES}/ESTATE_MANIFEST"
ALSO = (
    f"{RULES}/vacated-numbers.tsv",
    "scripts/ci/check_estate_manifest.py",
    "scripts/ci/check_rule_scope.py",
    "scripts/ci/check_vacated_rule_numbers.py",
)
HEADER = (
    "# The estate files, canonical in shekyl-core, copied verbatim into\n"
    "# shekyl-gui-wallet and shekyl-prism. sha256 and path, one per line.\n"
    "# Generated: scripts/ci/check_estate_manifest.py --write. Never edit by hand.\n"
)


def sha256(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def estate_rules(root: str) -> list[str]:
    out = []
    d = os.path.join(root, RULES)
    for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not name.endswith((".mdc", ".md")):
            continue
        with open(os.path.join(d, name), encoding="utf-8") as fh:
            head = fh.read(4096)
        end = head.find("\n---\n", 4)
        if head.startswith("---\n") and end > 0 and re.search(r"^scope:\s*estate\s*$", head[4:end], re.M):
            out.append(f"{RULES}/{name}")
    return out


def render(root: str) -> str:
    paths = estate_rules(root) + [p for p in ALSO]
    lines = [f"{sha256(os.path.join(root, p))}  {p}" for p in sorted(paths)]
    return HEADER + "\n".join(lines) + "\n"


def parse(text: str) -> dict[str, str]:
    rows = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        digest, path = line.split("  ", 1)
        rows[path] = digest
    return rows


def check_core(root: str, write: bool) -> int:
    rules = estate_rules(root)
    if len(rules) < 5:
        print(f"FAIL: {len(rules)} estate rules found under {RULES}; the manifest would describe nothing")
        return 1
    for p in ALSO:
        if not os.path.isfile(os.path.join(root, p)):
            print(f"FAIL: {p} is missing")
            return 1
    want = render(root)
    path = os.path.join(root, MANIFEST)
    if write:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(want)
        print(f"wrote {MANIFEST}: {len(parse(want))} files")
        return 0
    have = open(path, encoding="utf-8").read() if os.path.isfile(path) else ""
    if have != want:
        a, b = parse(have), parse(want)
        print(f"FAIL: {MANIFEST} does not match the estate files:")
        for p in sorted(set(a) | set(b)):
            if a.get(p) != b.get(p):
                print(f"  {p}: manifest {a.get(p, 'absent')[:12]}, file {b.get(p, 'absent')[:12]}")
        print("Fix: scripts/ci/check_estate_manifest.py --write, in the same commit as the estate edit.")
        return 1
    print(f"OK: {MANIFEST} matches the {len(parse(want))} estate files.")
    return 0


def check_consumer(root: str, against: str) -> int:
    with open(against, encoding="utf-8") as fh:
        want = parse(fh.read())
    if len(want) < 5:
        print(f"FAIL: {against} lists {len(want)} files; not shekyl-core's estate manifest")
        return 1
    fails = []
    for p, digest in sorted(want.items()):
        full = os.path.join(root, p)
        if not os.path.isfile(full):
            fails.append(f"{p}: missing here")
        elif sha256(full) != digest:
            fails.append(f"{p}: differs from shekyl-core dev")
    for p in estate_rules(root):
        if p not in want:
            fails.append(f"{p}: says scope: estate but shekyl-core has no such estate file")
    if fails:
        print("FAIL: the estate copies drifted from shekyl-core dev:")
        for f in fails:
            print("  " + f)
        print("Fix: copy each file again from shekyl-core dev; never edit an estate copy here.")
        return 1
    print(f"OK: all {len(want)} estate files match shekyl-core dev.")
    return 0


def selftest(root: str) -> int:
    ok = True
    me = os.path.abspath(__file__)

    def run(d: str, *args: str) -> int:
        return subprocess.run([sys.executable, me, "--root", d, *args], capture_output=True, text=True).returncode

    with tempfile.TemporaryDirectory() as t:
        core, cons = os.path.join(t, "core"), os.path.join(t, "cons")
        for d in (core, cons):
            os.makedirs(os.path.join(d, RULES))
            os.makedirs(os.path.join(d, "scripts/ci"))
        for i in range(6):
            body = f"---\ndescription: d\nalwaysApply: true\nscope: estate\nrepos: [core, gui, prism]\n---\n# rule {i}\n"
            open(os.path.join(core, RULES, f"0{i}-r.mdc"), "w").write(body)
        open(os.path.join(core, RULES, "106-core-only.mdc"), "w").write("---\ndescription: d\nscope: core\n---\n")
        for p in ALSO:
            open(os.path.join(core, p), "w").write(f"stand-in for {p}\n")
        steps = []
        steps.append(("core: no manifest", run(core) != 0))
        run(core, "--write")
        steps.append(("core: manifest written, clean", run(core) == 0))
        with open(os.path.join(core, RULES, "03-r.mdc"), "a") as fh:
            fh.write("x")
        steps.append(("core: estate edited without --write", run(core) != 0))
        run(core, "--write")
        man = os.path.join(t, "manifest")
        shutil.copy(os.path.join(core, MANIFEST), man)
        for p in parse(open(man).read()):
            shutil.copy(os.path.join(core, p), os.path.join(cons, p))
        steps.append(("consumer: exact copies", run(cons, "--against", man) == 0))
        target = os.path.join(cons, RULES, "02-r.mdc")
        data = bytearray(open(target, "rb").read())
        data[-2] ^= 0x01
        open(target, "wb").write(bytes(data))
        steps.append(("consumer: one-byte edit in a copy", run(cons, "--against", man) != 0))
        shutil.copy(os.path.join(core, RULES, "02-r.mdc"), target)
        os.remove(os.path.join(cons, RULES, "04-r.mdc"))
        steps.append(("consumer: a copy missing", run(cons, "--against", man) != 0))
        shutil.copy(os.path.join(core, RULES, "04-r.mdc"), os.path.join(cons, RULES, "04-r.mdc"))
        open(os.path.join(cons, RULES, "07-stray.mdc"), "w").write(
            "---\ndescription: d\nalwaysApply: true\nscope: estate\nrepos: [gui]\n---\n")
        steps.append(("consumer: an estate file core does not have", run(cons, "--against", man) != 0))
    for name, passed in steps:
        print(f"selftest: {name}: {'as required' if passed else 'WRONG'}")
        ok &= passed
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--against")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest(a.root)
    if a.against:
        return check_consumer(a.root, a.against)
    return check_core(a.root, a.write)


if __name__ == "__main__":
    sys.exit(main())
