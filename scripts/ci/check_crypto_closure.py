#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every lock holds the crypto closure at the versions its record reviewed.

# What is held

`rust/.cargo/crypto-closure.toml` records every registry package on a
proving, signing, wiping, RNG or seed path, with the version core's test
vectors, KATs and constant-time harness ran against and a one-line reason.
A lock that carries one of those packages on the same compatibility line
(`1.x`, `0.y`, `0.0.z`) at any other version fails, naming the lock, the
package and both versions. A `cargo update` that moves a held package is
therefore red until the record moves with it, in a reviewed change.

A different compatibility line of the same name is not the recorded
package: `rand` 0.10 under the shard rasterizer is not `rand` 0.8 under the
prover, and is not held.

# Modes

  (default)      lockfile-only. Checks `rust/Cargo.lock` and every
                 `rust/*/fuzz/Cargo.lock`, or the locks named with
                 `--lock` (the GUI wallet's, from its own workflows).
                 No cargo, no compile.
  --complete     the record is the closure, no more and no less. Runs
                 `cargo metadata --locked` on the workspace and on every fuzz
                 crate, walks normal edges from the record's `roots` (a
                 registry package of that name that a local crate depends on
                 through a normal edge) and compares the set with the
                 record's packages. A proc-macro is recorded (a derive writes
                 wipe and curve code) and its compiler toolchain is not
                 walked. A package the walk finds and the record lacks, or
                 the reverse, fails, naming it.
  --print-closure   the walk's result, one `name version` per line, for
                 writing a record change.
  --selftest     the lock check and the record parser on planted inputs,
                 including one held package bumped in one lock.

`--record PATH` reads another record (the GUI's workflows pass core's).
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import tomllib

RECORD = "rust/.cargo/crypto-closure.toml"
WORKSPACE_MANIFEST = "rust/Cargo.toml"
WORKSPACE_LOCK = "rust/Cargo.lock"
FUZZ_LOCKS = "rust/*/fuzz/Cargo.lock"


def compat_line(version: str) -> str:
    """Cargo's compatibility line: `1.x` -> "1", `0.y` -> "0.y", `0.0.z`."""
    core = version.split("+", 1)[0].split("-", 1)[0].split(".")
    if core[0] != "0":
        return core[0]
    if len(core) > 1 and core[1] != "0":
        return "0." + core[1]
    return "0.0." + (core[2] if len(core) > 2 else "0")


def parse_record(text: str) -> tuple[list[str], dict[str, dict[str, str]]]:
    """(roots, {name: {version: reason}}). Raises ValueError on a bad record."""
    data = tomllib.loads(text)
    roots = data.get("roots")
    if not isinstance(roots, list) or not roots or not all(isinstance(r, str) for r in roots):
        raise ValueError("`roots` must be a non-empty list of crate names")
    held: dict[str, dict[str, str]] = {}
    entries = data.get("package")
    if not isinstance(entries, list) or not entries:
        raise ValueError("the record holds no [[package]] entry")
    for i, entry in enumerate(entries):
        name, version, reason = entry.get("name"), entry.get("version"), entry.get("reason")
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(reason, str)):
            raise ValueError(f"[[package]] #{i + 1}: name, version and reason are all required strings")
        if not reason.strip():
            raise ValueError(f"{name} {version}: the reason is empty")
        lines = held.setdefault(name, {})
        if any(compat_line(v) == compat_line(version) for v in lines):
            raise ValueError(f"{name}: two entries on the {compat_line(version)} line")
        lines[version] = reason
    return roots, held


def lock_packages(text: str) -> dict[str, set[str]]:
    """{name: {version}} for the registry packages of a Cargo.lock."""
    out: dict[str, set[str]] = {}
    for p in tomllib.loads(text).get("package", []):
        if str(p.get("source", "")).startswith("registry+"):
            out.setdefault(p["name"], set()).add(p["version"])
    return out


def check_lock(label: str, lock: dict[str, set[str]], held: dict[str, dict[str, str]]) -> list[str]:
    errors = []
    for name, versions in sorted(held.items()):
        by_line = {compat_line(v): v for v in versions}
        for got in sorted(lock.get(name, ())):
            want = by_line.get(compat_line(got))
            if want is not None and got != want:
                errors.append(f"{label}: {name} is {got}; the crypto-closure record holds {want}")
    return errors


def run_locks(record_path: str, locks: list[str]) -> int:
    _, held = parse_record(open(record_path, encoding="utf-8").read())
    if not locks:
        locks = [WORKSPACE_LOCK] + sorted(glob.glob(FUZZ_LOCKS))
        # Rule 47: the subject exists. The workspace lock and ten fuzz locks
        # are what this check is for; a glob that matched nothing would pass.
        if len(locks) < 2:
            print(f"crypto closure: no fuzz lock matched {FUZZ_LOCKS}")
            return 1
    errors: list[str] = []
    checked = 0
    for path in locks:
        pkgs = lock_packages(open(path, encoding="utf-8").read())
        if not pkgs:
            errors.append(f"{path}: no registry package parsed")
            continue
        found = sum(1 for n in held if n in pkgs)
        if path == WORKSPACE_LOCK and found != len(held):
            missing = sorted(n for n in held if n not in pkgs)
            errors.append(f"{path}: the record holds packages the workspace lock lacks: {', '.join(missing)}")
        errors += check_lock(path, pkgs, held)
        checked += 1
    for e in errors:
        print(e)
    if errors:
        print(f"crypto closure: {len(errors)} difference(s) from {record_path}")
        return 1
    print(f"crypto closure: {checked} lock(s) agree with {record_path} "
          f"({sum(len(v) for v in held.values())} held packages)")
    return 0


def closure_of(metadata: dict, roots: set[str]) -> set[tuple[str, str]]:
    pk = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}

    def normal(dep: dict) -> bool:
        return any(k.get("kind") is None for k in dep["dep_kinds"])

    def local(pid: str) -> bool:
        return pk[pid]["source"] is None

    def proc_macro(pid: str) -> bool:
        return any("proc-macro" in t["kind"] for t in pk[pid]["targets"])

    todo = [
        d["pkg"]
        for nid, node in nodes.items() if local(nid)
        for d in node["deps"]
        if normal(d) and not local(d["pkg"]) and pk[d["pkg"]]["name"] in roots
    ]
    seen: set[str] = set()
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if proc_macro(pid):
            continue
        todo += [d["pkg"] for d in nodes[pid]["deps"] if normal(d)]
    return {(pk[i]["name"], pk[i]["version"]) for i in seen if not local(i)}


def walk(roots: set[str]) -> set[tuple[str, str]]:
    manifests = [WORKSPACE_MANIFEST] + sorted(glob.glob("rust/*/fuzz/Cargo.toml"))
    found: set[tuple[str, str]] = set()
    for manifest in manifests:
        out = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--manifest-path", manifest],
            capture_output=True, text=True, check=False,
        )
        if out.returncode != 0:
            raise RuntimeError(f"cargo metadata --manifest-path {manifest} failed:\n{out.stderr}")
        found |= closure_of(json.loads(out.stdout), roots)
    return found


def run_complete(record_path: str) -> int:
    roots, held = parse_record(open(record_path, encoding="utf-8").read())
    found = walk(set(roots))
    if not found:
        print("crypto closure: the walk found nothing; the roots name no dependency")
        return 1
    recorded = {(n, v) for n, vs in held.items() for v in vs}
    errors = [f"in the closure, not in the record: {n} {v}" for n, v in sorted(found - recorded)]
    errors += [f"in the record, not in the closure: {n} {v}" for n, v in sorted(recorded - found)]
    for e in errors:
        print(e)
    if errors:
        print(f"crypto closure: the record and the closure differ ({len(errors)}); "
              "a record change is a reviewed change (rules 17, 30, 35)")
        return 1
    print(f"crypto closure: the record is the closure ({len(found)} packages from {len(roots)} roots)")
    return 0


def selftest() -> int:
    record = (
        'roots = ["zeroize"]\n'
        '[[package]]\nname = "zeroize"\nversion = "1.8.2"\nreason = "wipes"\n'
        '[[package]]\nname = "rand"\nversion = "0.8.6"\nreason = "rng"\n'
    )
    _, held = parse_record(record)

    def lock(*pkgs: tuple[str, str]) -> dict[str, set[str]]:
        text = "".join(
            f'[[package]]\nname = "{n}"\nversion = "{v}"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            for n, v in pkgs
        )
        return lock_packages(text)

    cases = [
        ("agreeing lock passes", lock(("zeroize", "1.8.2"), ("rand", "0.8.6")), 0),
        ("one held package bumped fails", lock(("zeroize", "1.9.2"), ("rand", "0.8.6")), 1),
        ("a held package stepped down fails", lock(("zeroize", "1.8.2"), ("rand", "0.8.5")), 1),
        ("another compat line is not held", lock(("zeroize", "1.8.2"), ("rand", "0.8.6"), ("rand", "0.10.4")), 0),
        ("an absent package is not a difference", lock(("rand", "0.8.6")), 0),
    ]
    failed = 0
    for name, pkgs, want in cases:
        got = len(check_lock("planted", pkgs, held))
        if got != want:
            print(f"selftest FAIL: {name}: {got} difference(s), expected {want}")
            failed += 1
        else:
            print(f"selftest ok: {name}")
    bumped = check_lock("planted", lock(("zeroize", "1.9.2")), held)
    if bumped != ["planted: zeroize is 1.9.2; the crypto-closure record holds 1.8.2"]:
        print(f"selftest FAIL: the message names lock, package and both versions: {bumped}")
        failed += 1
    for name, bad in [
        ("no roots", '[[package]]\nname = "a"\nversion = "1.0.0"\nreason = "r"\n'),
        ("empty reason", 'roots = ["a"]\n[[package]]\nname = "a"\nversion = "1.0.0"\nreason = " "\n'),
        ("two entries on one line", 'roots = ["a"]\n[[package]]\nname = "a"\nversion = "1.0.0"\nreason = "r"\n'
                                    '[[package]]\nname = "a"\nversion = "1.2.0"\nreason = "r"\n'),
        ("no packages", 'roots = ["a"]\n'),
    ]:
        try:
            parse_record(bad)
        except ValueError:
            print(f"selftest ok: the parser refuses {name}")
        else:
            print(f"selftest FAIL: the parser accepted {name}")
            failed += 1
    for v, line in [("1.8.2", "1"), ("0.8.6", "0.8"), ("0.0.3", "0.0.3"), ("1.2.1+spec-1.1.0", "1")]:
        if compat_line(v) != line:
            print(f"selftest FAIL: compat_line({v}) = {compat_line(v)}, expected {line}")
            failed += 1
    print("selftest:", "FAIL" if failed else "ok")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    record = RECORD
    locks: list[str] = []
    mode = "locks"
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--record":
            record = argv[i + 1]
            i += 1
        elif a == "--lock":
            locks.append(argv[i + 1])
            i += 1
        elif a in ("--complete", "--selftest", "--print-closure"):
            mode = a[2:]
        else:
            print(f"unknown argument: {a}")
            return 2
        i += 1
    if mode == "selftest":
        return selftest()
    if not os.path.exists(record):
        print(f"crypto closure: no record at {record}")
        return 1
    if mode == "complete":
        return run_complete(record)
    if mode == "print-closure":
        roots, _ = parse_record(open(record, encoding="utf-8").read())
        for n, v in sorted(walk(set(roots))):
            print(n, v)
        return 0
    return run_locks(record, locks)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
