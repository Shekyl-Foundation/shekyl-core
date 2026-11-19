#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Every doc link in the workspace resolves.

# The policy

The docs are written for the maintainers who read the source, not for a
published API, so they document private items too and may link to them.
What they may not do is link to a name that does not exist: a link is a
claim about the code, and a renamed, deleted or test-only item leaves a
claim nobody checks. The gate documents every lib crate in the workspace
with private items included (`--document-private-items`), and fails on any
rustdoc warning (`-D warnings`) except `rustdoc::private_intra_doc_links`,
which is the lint that forbids linking a private item.

# Coverage

Every lib crate in the workspace is documented except those in
`EXCLUDED`, each with its reason. A crate that lands joins the gate the day
it lands; there is no list to add it to.

Rule 47: cargo reports a doc artifact for each crate it documented, fresh or
rebuilt. The gate fails when a crate it expected has none, since that crate
was graded by nothing.

# Use

    check_rustdoc.py                     the workspace, from rust/
    check_rustdoc.py --package NAME ...  only these crates (the Windows job
                                         documents `shekyl-win-sec` this way)
    check_rustdoc.py --selftest          the policy's own cases, on fixtures

The selftest runs rustdoc with these same flags over small fixture crates:
a missing name must fail in a public doc and in a private one, a link to a
private item and a clean crate must pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST = os.path.join(ROOT, "rust")

# Every rustdoc warning fails, except a link to a private item: these docs
# are for maintainers, and private items are documented.
RUSTDOCFLAGS = ["-D", "warnings", "-A", "rustdoc::private_intra_doc_links"]
DOC_ARGS = ["--locked", "--no-deps", "--lib", "--document-private-items"]

EXCLUDED = {
    # `cfg(windows)`: on Linux it compiles to nothing, so documenting it here
    # would grade an empty crate and pass forever. build.yml's Windows job
    # runs this gate on it (`--package shekyl-win-sec`), where its docs exist.
    "shekyl-win-sec": "cfg(windows); gated on the Windows job in build.yml",
}


def lib_crates() -> dict[str, str]:
    """Package name to lib target name, for every workspace member with a lib."""
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
            cwd=RUST,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    members = set(meta["workspace_members"])
    out = {}
    for package in meta["packages"]:
        if package["id"] not in members:
            continue
        for target in package["targets"]:
            if "lib" in target["kind"] or "proc-macro" in target["kind"] or "rlib" in target["kind"]:
                out[package["name"]] = target["name"].replace("-", "_")
                break
    return out


def run_gate(packages: list[str]) -> int:
    crates = lib_crates()
    for name in EXCLUDED:
        if name not in crates:
            print(f"::error::{name} is excluded but is not a workspace lib crate; drop it from EXCLUDED")
            return 1
    if packages:
        unknown = [p for p in packages if p not in crates]
        if unknown:
            print(f"::error::not workspace lib crates: {', '.join(unknown)}")
            return 1
        expected = {p: crates[p] for p in packages}
        selection = [arg for p in packages for arg in ("-p", p)]
    else:
        expected = {p: lib for p, lib in crates.items() if p not in EXCLUDED}
        selection = ["--workspace"] + [arg for p in sorted(EXCLUDED) for arg in ("--exclude", p)]
    env = dict(os.environ, RUSTDOCFLAGS=" ".join(RUSTDOCFLAGS))
    proc = subprocess.Popen(
        ["cargo", "doc", *DOC_ARGS, *selection, "--message-format=json"],
        cwd=RUST,
        env=env,
        stdout=subprocess.PIPE,
        text=True,
    )
    documented = set()
    findings = 0
    assert proc.stdout is not None
    for line in proc.stdout:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("reason") == "compiler-message":
            rendered = message["message"].get("rendered")
            if rendered:
                sys.stdout.write(rendered)
            if message["message"]["level"] == "error":
                findings += 1
        elif message.get("reason") == "compiler-artifact":
            lib = message["target"]["name"].replace("-", "_")
            if any(f.endswith(os.path.join("doc", lib, "index.html")) for f in message["filenames"]):
                documented.add(lib)
    status = proc.wait()
    missing = sorted(p for p, lib in expected.items() if lib not in documented)
    if status != 0:
        print(f"::error::rustdoc failed ({findings} errors above): every doc link must resolve")
        return 1
    if missing:
        print(f"::error::cargo documented no artifact for {', '.join(missing)}; the gate graded nothing there")
        return 1
    print(f"rustdoc: {len(expected)} crates documented with private items, every link resolves")
    return 0


FIXTURES = {
    "a missing name in a public doc": (
        "/// Points at [`Nowhere`].\npub fn shown() {}\n",
        False,
    ),
    "a missing name in a private doc": (
        "/// Points at [`Nowhere`].\nfn hidden() {}\npub fn shown() { hidden() }\n",
        False,
    ),
    "a missing name in a private module's doc": (
        "mod inner {\n    //! Points at [`Nowhere`].\n    pub(crate) fn f() {}\n}\npub fn shown() { inner::f() }\n",
        False,
    ),
    "a public doc linking a private item": (
        "/// Calls [`hidden`].\npub fn shown() { hidden() }\nfn hidden() {}\n",
        True,
    ),
    "a private doc linking a private item": (
        "/// Calls [`other`].\nfn hidden() { other() }\nfn other() {}\npub fn shown() { hidden() }\n",
        True,
    ),
    "a clean crate": (
        "/// Plain.\npub fn shown() {}\n",
        True,
    ),
}


def selftest() -> int:
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, (source, should_pass) in FIXTURES.items():
            src = os.path.join(tmp, "fixture.rs")
            with open(src, "w", encoding="utf-8") as handle:
                handle.write("//! Fixture.\n" + source)
            # rustdoc from rust/, so rust-toolchain.toml picks the same
            # toolchain the gate's cargo doc uses.
            proc = subprocess.run(
                ["rustdoc", "--edition", "2021", "--crate-type", "lib", "--crate-name", "fixture",
                 "--document-private-items", *RUSTDOCFLAGS, "-o", os.path.join(tmp, "doc"), src],
                cwd=RUST,
                capture_output=True,
                text=True,
            )
            # A fixture that must fail must fail on its missing name, not on
            # some other error (a rustdoc that did not run fails too).
            if should_pass:
                ok = proc.returncode == 0
            else:
                ok = proc.returncode != 0 and "unresolved link to `Nowhere`" in proc.stderr
            if not ok:
                want = "pass" if should_pass else "fail on `Nowhere`"
                print(f"selftest FAIL: {label}: rustdoc exited {proc.returncode}, want {want}\n{proc.stderr}")
                failed = 1
    if not failed:
        print(f"selftest: {len(FIXTURES)} cases")
    return failed


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    packages = [argv[i + 1] for i, a in enumerate(argv) if a == "--package" and i + 1 < len(argv)]
    return run_gate(packages)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
