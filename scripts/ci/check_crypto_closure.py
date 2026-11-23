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

The source is held too. An entry with a `source` (a pinned fork) must come
from exactly that source in every lock, and an entry without one must come
from crates.io, so neither a `[patch]` of a held crate nor a fork at another
revision passes unseen.

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
import re
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


def record_sources(text: str) -> dict[tuple[str, str], str]:
    """{(name, version): source} for the record's pinned forks.

    Raises ValueError on a source that is not a git revision pinned in full.
    """
    out: dict[tuple[str, str], str] = {}
    for entry in tomllib.loads(text).get("package", []):
        source = entry.get("source")
        if source is None:
            continue
        pinned = re.fullmatch(r"git\+https://[^?#]+\?rev=([0-9a-f]{40})#([0-9a-f]{40})", str(source))
        if not pinned or pinned.group(1) != pinned.group(2):
            raise ValueError(f"{entry.get('name')}: source must be a git URL pinned to one full revision")
        out[(entry["name"], entry["version"])] = source
    return out


def lock_packages(text: str) -> dict[str, set[str]]:
    """{name: {version}} for the registry and git packages of a Cargo.lock."""
    out: dict[str, set[str]] = {}
    for p in tomllib.loads(text).get("package", []):
        if str(p.get("source", "")).startswith(("registry+", "git+")):
            out.setdefault(p["name"], set()).add(p["version"])
    return out


def check_sources(label: str, text: str, held: dict[str, dict[str, str]],
                  sources: dict[tuple[str, str], str]) -> list[str]:
    """Each held package a lock takes from anywhere but the recorded source."""
    errors = []
    for p in tomllib.loads(text).get("package", []):
        name, version, got = p["name"], p["version"], str(p.get("source", ""))
        if not got or version not in held.get(name, {}):
            continue
        want = sources.get((name, version))
        if want is None:
            if not got.startswith("registry+"):
                errors.append(f"{label}: {name} {version} comes from {got}; "
                              "the crypto-closure record holds it from crates.io")
        elif got != want:
            errors.append(f"{label}: {name} {version} comes from {got}; "
                          f"the crypto-closure record holds {want}")
    return errors


def check_lock(label: str, lock: dict[str, set[str]], held: dict[str, dict[str, str]]) -> list[str]:
    """Each held package a lock carries on a held line, at another version.

    A held package may be absent from a lock (a fuzz crate links part of
    the closure), but a lock that carries none of them on a held line
    compared nothing, and agreeing with it would be absence of signal read
    as agreement (rule 47): it fails, naming the lock.
    """
    errors = []
    compared = 0
    for name, versions in sorted(held.items()):
        by_line = {compat_line(v): v for v in versions}
        for got in sorted(lock.get(name, ())):
            want = by_line.get(compat_line(got))
            if want is None:
                continue
            compared += 1
            if got != want:
                errors.append(f"{label}: {name} is {got}; the crypto-closure record holds {want}")
    if compared == 0:
        errors.append(f"{label}: carries none of the record's packages on a held line, "
                      "so nothing was compared; it is not a lock this record governs")
    return errors


def run_locks(record_path: str, locks: list[str]) -> int:
    record_text = open(record_path, encoding="utf-8").read()
    _, held = parse_record(record_text)
    sources = record_sources(record_text)
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
        lock_text = open(path, encoding="utf-8").read()
        pkgs = lock_packages(lock_text)
        if not pkgs:
            errors.append(f"{path}: no registry package parsed")
            continue
        found = sum(1 for n in held if n in pkgs)
        if path == WORKSPACE_LOCK and found != len(held):
            missing = sorted(n for n in held if n not in pkgs)
            errors.append(f"{path}: the record holds packages the workspace lock lacks: {', '.join(missing)}")
        errors += check_lock(path, pkgs, held)
        errors += check_sources(path, lock_text, held, sources)
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

    def normal_or_build(dep: dict) -> bool:
        # A held crate's build script chooses what compiles (curve25519-dalek's
        # picks its backend and word size through rustc_version), so its build
        # dependencies are on the path too.
        return any(k.get("kind") in (None, "build") for k in dep["dep_kinds"])

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
        todo += [d["pkg"] for d in nodes[pid]["deps"] if normal_or_build(d)]
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


def complete_errors(found: set[tuple[str, str]], held: dict[str, dict[str, str]]) -> list[str]:
    """Each package the walk found and the record lacks, and the reverse."""
    recorded = {(n, v) for n, vs in held.items() for v in vs}
    errors = [f"in the closure, not in the record: {n} {v}" for n, v in sorted(found - recorded)]
    errors += [f"in the record, not in the closure: {n} {v}" for n, v in sorted(recorded - found)]
    return errors


def run_complete(record_path: str) -> int:
    roots, held = parse_record(open(record_path, encoding="utf-8").read())
    found = walk(set(roots))
    if not found:
        print("crypto closure: the walk found nothing; the roots name no dependency")
        return 1
    errors = complete_errors(found, held)
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
        ("a lock with no held package fails", lock(("tokio", "1.54.1")), 1),
        ("a lock with a held name only on another line fails", lock(("rand", "0.10.4")), 1),
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
    # The walk, on a planted resolve: local crate `app` -> root `dalek`;
    # `dalek` has a build dependency `rustcv` (which depends on `semverx`)
    # and a derive `derivex` (whose compiler toolchain `synx` is not walked);
    # `app` also has a dev-only edge to `devonly`, which is not a root path.
    def pkg(name: str, *, local: bool = False, proc: bool = False) -> dict:
        return {"id": name, "name": name, "version": "1.0.0",
                "source": None if local else "registry+https://github.com/rust-lang/crates.io-index",
                "targets": [{"kind": ["proc-macro" if proc else "lib"]}]}

    def edge(to: str, kind: str | None) -> dict:
        return {"pkg": to, "dep_kinds": [{"kind": kind, "target": None}]}

    planted = {
        "packages": [pkg("app", local=True), pkg("dalek"), pkg("rustcv"), pkg("semverx"),
                     pkg("derivex", proc=True), pkg("synx"), pkg("devonly")],
        "resolve": {"nodes": [
            {"id": "app", "deps": [edge("dalek", None), edge("devonly", "dev")]},
            {"id": "dalek", "deps": [edge("rustcv", "build"), edge("derivex", None)]},
            {"id": "rustcv", "deps": [edge("semverx", None)]},
            {"id": "semverx", "deps": []},
            {"id": "derivex", "deps": [edge("synx", None)]},
            {"id": "synx", "deps": []},
            {"id": "devonly", "deps": []},
        ]},
    }
    walked = closure_of(planted, {"dalek"})
    want = {(n, "1.0.0") for n in ("dalek", "rustcv", "semverx", "derivex")}
    if walked != want:
        print(f"selftest FAIL: the walk follows normal and build edges, not a derive's "
              f"toolchain or a dev edge: {sorted(walked)}")
        failed += 1
    else:
        print("selftest ok: the walk follows a held crate's build dependencies")
    _, short = parse_record(
        'roots = ["dalek"]\n'
        + "".join(f'[[package]]\nname = "{n}"\nversion = "1.0.0"\nreason = "r"\n'
                  for n in ("dalek", "semverx", "derivex")))
    missing = complete_errors(walked, short)
    if missing != ["in the closure, not in the record: rustcv 1.0.0"]:
        print(f"selftest FAIL: a held crate's build dependency missing from the record "
              f"must fail, naming it: {missing}")
        failed += 1
    else:
        print("selftest ok: a held crate's build dependency missing from the record fails")
    # The source is held: a pinned fork at its revision passes; the registry
    # copy, another revision, or a git source for an unpinned package fails.
    rev_a, rev_b = "a" * 40, "b" * 40
    fork = f"git+https://example.invalid/f?rev={rev_a}#{rev_a}"
    other = f"git+https://example.invalid/f?rev={rev_b}#{rev_b}"
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    pinned_record = (
        'roots = ["f"]\n'
        f'[[package]]\nname = "f"\nversion = "0.5.0"\nsource = "{fork}"\nreason = "fork"\n'
        '[[package]]\nname = "g"\nversion = "1.0.0"\nreason = "plain"\n'
    )
    _, pin_held = parse_record(pinned_record)
    pins = record_sources(pinned_record)

    def entry(name: str, version: str, source: str) -> str:
        return f'[[package]]\nname = "{name}"\nversion = "{version}"\nsource = "{source}"\n'

    for name, text, want in [
        ("a fork at its pinned revision passes", entry("f", "0.5.0", fork) + entry("g", "1.0.0", registry), 0),
        ("the registry copy of a pinned fork fails", entry("f", "0.5.0", registry), 1),
        ("a pinned fork at another revision fails", entry("f", "0.5.0", other), 1),
        ("a git source for a package held from crates.io fails", entry("g", "1.0.0", fork), 1),
    ]:
        got = len(check_sources("planted", text, pin_held, pins))
        if got != want:
            print(f"selftest FAIL: {name}: {got} difference(s), expected {want}")
            failed += 1
        else:
            print(f"selftest ok: {name}")
    if lock_packages(entry("f", "0.5.0", fork)) != {"f": {"0.5.0"}}:
        print("selftest FAIL: a git package must reach the version check")
        failed += 1
    else:
        print("selftest ok: a git package reaches the version check")
    for bad in ("git+https://example.invalid/f?branch=main#" + rev_a,
                f"git+https://example.invalid/f?rev={rev_a}#{rev_b}",
                f"git+https://example.invalid/f?rev=abc#abc"):
        try:
            record_sources(f'[[package]]\nname = "f"\nversion = "1.0.0"\nsource = "{bad}"\nreason = "r"\n')
        except ValueError:
            print("selftest ok: the parser refuses a source not pinned to one full revision")
        else:
            print(f"selftest FAIL: the parser accepted {bad}")
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
