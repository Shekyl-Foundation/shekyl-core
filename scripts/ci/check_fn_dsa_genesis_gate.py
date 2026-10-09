#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# No genesis on a pre-standard FN-DSA.
#
# WHY. The receipt and the witness carrier signature are Ed25519 +
# FN-DSA-1024 (hybrid scheme byte 3; ARCHIVAL_SERVE_CREDIT_SPEC.md §6.2). FIPS
# 206 is not final, and the `fn-dsa` crate says of itself that keys and
# signatures made with a pre-1.0 version may stop verifying under a later
# one. A testnet can take that: a version bump is a flag day. A genesis chain
# cannot — a bond record would carry a receipt key no later node could use.
# The ruling (spec §11, 2026-10-07) is that genesis waits for a 1.0 crate.
#
# WHAT IT CHECKS, on every run:
#
#   1. all five packages (`fn-dsa` and its four sub-crates) are in the lock.
#      Absence is a failure, not a pass: a gate over a dependency that is no
#      longer there has nothing to say (47-gate-subject-assertion). When the
#      scheme is removed, this script is deleted with it;
#   2. the five are locked at ONE version. The wrapper depends on each
#      sub-crate by caret, so a lock that let one move is a different
#      implementation from the one the vectors pin;
#   3. `shekyl-crypto-pq`'s manifest pins each of the five exact (`=X`), at
#      the locked version.
#
# WHAT IT REFUSES, for a genesis release only: a locked version below 1.0.0.
# A genesis release is any tag that is not a recognised pre-release —
# RELEASE_PROMOTION.md reserves the first such tag for the genesis mainnet
# release. The test is on the pre-release shape, so a tag this script does
# not recognise is refused and not waved through. The tag comes
# from `--release-tag`, or from GITHUB_REF_NAME when GITHUB_REF_TYPE is `tag`.
# With no tag the script reports what a genesis build would be told and
# passes, so a pull request sees the standing state without being blocked by
# a condition that is not its own.
#
# Exit status is the verdict; nothing here is decided through a pipe
# (46-shell-gate-exits).

import argparse
import os
import re
import sys

PACKAGES = ("fn-dsa", "fn-dsa-comm", "fn-dsa-kgen", "fn-dsa-sign", "fn-dsa-vrfy")
LOCK = "rust/Cargo.lock"
MANIFEST = "rust/shekyl-crypto-pq/Cargo.toml"

# The pre-release shapes this repository cuts (RELEASE_PROMOTION.md §3):
# `v3.1.0-alpha.9`, `v3.0.0-RC1`, `v3.0.0-beta`. Every other tag is a genesis
# release as far as this gate is concerned — `v3.0.0`, and equally `V3.0.0`,
# `v3.0`, `v3.0.0+mainnet` or `mainnet-3.0.0`. An oddly named rehearsal tag
# is refused until it is re-cut with a suffix; that is the direction a gate
# whose job is to keep mainnet off a pre-standard crate has to fail in.
# `gitian.yml` carries the same expression for a tree that predates this
# script; the two change together.
PRERELEASE_TAG = re.compile(r"^v?\d+\.\d+\.\d+-(alpha|beta|rc)(\.?\d+)*$", re.IGNORECASE)
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def locked_versions(lock_text):
    """`name -> [versions]` for the five packages, from a Cargo.lock."""
    found = {name: [] for name in PACKAGES}
    for block in lock_text.split("[[package]]"):
        name = re.search(r'^name = "([^"]+)"$', block, re.M)
        version = re.search(r'^version = "([^"]+)"$', block, re.M)
        if name and version and name.group(1) in found:
            found[name.group(1)].append(version.group(1))
    return found


def manifest_pins(manifest_text):
    """`name -> requirement string` for the five, from a Cargo.toml."""
    pins = {}
    for name in PACKAGES:
        simple = re.search(
            r'^%s\s*=\s*"([^"]+)"\s*$' % re.escape(name), manifest_text, re.M
        )
        table = re.search(
            r'^%s\s*=\s*\{[^}]*\bversion\s*=\s*"([^"]+)"' % re.escape(name),
            manifest_text,
            re.M,
        )
        hit = simple or table
        if hit:
            pins[name] = hit.group(1)
    return pins


def is_genesis_tag(tag):
    return bool(tag) and not PRERELEASE_TAG.match(tag)


def judge(lock_text, manifest_text, tag):
    """Return `(problems, notes)`. Empty `problems` is a pass."""
    problems, notes = [], []
    locked = locked_versions(lock_text)

    missing = [name for name in PACKAGES if not locked[name]]
    if missing:
        problems.append(
            "not in %s: %s. The gate's subject is absent; if scheme 3 was "
            "removed, delete this script with it" % (LOCK, ", ".join(missing))
        )
        return problems, notes
    doubled = [name for name in PACKAGES if len(locked[name]) > 1]
    if doubled:
        problems.append(
            "locked at more than one version: %s"
            % ", ".join("%s %s" % (n, locked[n]) for n in doubled)
        )
        return problems, notes

    versions = {name: locked[name][0] for name in PACKAGES}
    if len(set(versions.values())) != 1:
        problems.append(
            "the five packages are not at one version: %s"
            % ", ".join("%s %s" % kv for kv in sorted(versions.items()))
        )
    version = versions["fn-dsa"]

    pins = manifest_pins(manifest_text)
    for name in PACKAGES:
        want = "=" + versions[name]
        got = pins.get(name)
        if got is None:
            problems.append("%s does not name %s" % (MANIFEST, name))
        elif got != want:
            problems.append(
                '%s pins %s as "%s"; the lock has %s, so the pin must be "%s"'
                % (MANIFEST, name, got, versions[name], want)
            )

    parsed = SEMVER.match(version)
    if not parsed:
        problems.append("cannot read %r as a version" % version)
        return problems, notes
    pre_standard = int(parsed.group(1)) < 1

    if is_genesis_tag(tag):
        if pre_standard:
            problems.append(
                "tag %s is not a recognised pre-release (-alpha.N, -beta, "
                "-RCn), so it is a genesis release, and "
                "fn-dsa is locked at %s. A pre-1.0 fn-dsa is pre-standard: "
                "its keys and signatures are not stable. Genesis waits for "
                "1.0 (ARCHIVAL_SERVE_CREDIT_SPEC.md §11)" % (tag, version)
            )
        else:
            notes.append("tag %s: fn-dsa %s is a standard release" % (tag, version))
    elif pre_standard:
        notes.append(
            "fn-dsa is locked at %s, pre-standard. This passes for %s; a "
            "genesis release (any tag that is not a recognised pre-release) would be "
            "refused" % (version, "tag %s" % tag if tag else "an untagged build")
        )
    else:
        notes.append("fn-dsa is locked at %s" % version)
    return problems, notes


def lock_with(versions):
    return "".join(
        '[[package]]\nname = "%s"\nversion = "%s"\n\n' % (name, version)
        for name, version in versions.items()
    )


def manifest_with(pins):
    return "".join('%s = "%s"\n' % (name, pin) for name, pin in pins.items())


def selftest():
    """Every verdict the gate can give, on constructed inputs."""
    def case(label, expect_pass, versions, pins, tag):
        problems, _ = judge(lock_with(versions), manifest_with(pins), tag)
        passed = not problems
        if passed != expect_pass:
            print(
                "selftest FAILED: %s — expected %s, got %s %s"
                % (label, "pass" if expect_pass else "refusal",
                   "pass" if passed else "refusal", problems),
                file=sys.stderr,
            )
            return False
        return True

    old = {name: "0.4.0" for name in PACKAGES}
    new = {name: "1.0.0" for name in PACKAGES}
    exact = lambda v: {name: "=" + v[name] for name in PACKAGES}  # noqa: E731
    without = lambda d, k: {n: v for n, v in d.items() if n != k}  # noqa: E731

    ok = True
    ok &= case("pre-1.0, no tag", True, old, exact(old), None)
    ok &= case("pre-1.0, pre-release tag", True, old, exact(old), "v3.1.0-alpha.9")
    ok &= case("pre-1.0, RC tag", True, old, exact(old), "v3.0.0-RC1")
    ok &= case("pre-1.0, genesis tag", False, old, exact(old), "v3.0.0")
    ok &= case("1.0, genesis tag", True, new, exact(new), "v3.0.0")
    ok &= case("a sub-crate missing from the lock", False,
               without(old, "fn-dsa-sign"), exact(old), None)
    ok &= case("nothing in the lock", False, {}, exact(old), None)
    drifted = dict(old, **{"fn-dsa-vrfy": "0.4.1"})
    ok &= case("one sub-crate moved", False, drifted, exact(drifted), None)
    caret = dict(exact(old), **{"fn-dsa-kgen": "0.4"})
    ok &= case("a caret pin", False, old, caret, None)
    ok &= case("a pin missing from the manifest", False,
               old, without(exact(old), "fn-dsa-comm"), None)
    stale = dict(exact(old), **{"fn-dsa": "=0.3.0"})
    ok &= case("a pin that is not the locked version", False, old, stale, None)
    # A table-form requirement is read like the string form.
    table = 'fn-dsa = { version = "=0.4.0", default-features = false }\n' + "".join(
        '%s = "=0.4.0"\n' % name for name in PACKAGES[1:]
    )
    problems, _ = judge(lock_with(old), table, None)
    if problems:
        print("selftest FAILED: table-form pin — %s" % problems, file=sys.stderr)
        ok = False
    for tag, genesis in (
        ("v3.0.0", True), ("v10.2.33", True), ("3.0.0", True),
        # The pre-release shapes the repository cuts.
        ("v3.1.0-alpha.9", False), ("v3.0.0-RC1", False), ("v3.0.0-RC14", False),
        ("v3.0.0-rc.1", False), ("v3.0.0-beta", False), ("3.1.0-alpha.10", False),
        # Unrecognised shapes are genesis: the gate fails closed.
        ("V3.0.0", True), ("v3.0", True), ("v3.0.0+mainnet", True),
        ("mainnet-3.0.0", True), ("core-v3.1.0", True), ("v3.0.0-final", True),
        ("v3.0.0-rc.1+build", True), ("v3.0.0-alphabet", True), ("genesis", True),
        # No tag at all is an untagged build, not a release.
        ("", False), (None, False),
    ):
        if is_genesis_tag(tag) != genesis:
            print("selftest FAILED: is_genesis_tag(%r)" % (tag,), file=sys.stderr)
            ok = False
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-tag", help="the tag being released")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        if selftest():
            print("fn-dsa genesis gate self-test: OK")
            return 0
        return 1

    tag = args.release_tag
    if tag is None and os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ.get("GITHUB_REF_NAME")

    try:
        with open(LOCK, encoding="utf-8") as f:
            lock_text = f.read()
        with open(MANIFEST, encoding="utf-8") as f:
            manifest_text = f.read()
    except OSError as error:
        print("fn-dsa genesis gate: cannot read its inputs: %s" % error, file=sys.stderr)
        return 1

    problems, notes = judge(lock_text, manifest_text, tag)
    for note in notes:
        print("fn-dsa genesis gate: %s" % note)
    if problems:
        for problem in problems:
            print("FAIL: %s" % problem, file=sys.stderr)
        return 1
    print("fn-dsa genesis gate: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
