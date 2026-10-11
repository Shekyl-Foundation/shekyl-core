#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# `shekyl-noise`'s `test-support` feature exposes raw session keys and lets a
# caller set a record nonce. It exists so that a handshake's tests can pin the
# key schedule from another crate (docs/design/RPC_CHANNEL.md section 10,
# RT-O16). It must never be on in a build that ships.
#
# WHY A GATE AND NOT A COMMENT. A Cargo feature is on for a whole build if
# anything in that build asks for it. One line in one manifest, written to
# make a test compile, would put `ck_and_k()` in the daemon. A sentence beside
# the feature does not stop that (rule 47: a gate asserts its own subject).
#
# WHAT IS CHECKED, in rust/:
#   1. The crate exists and declares the feature, and its `default` features
#      do not include it.
#   2. Every manifest that asks for the feature asks for it under
#      [dev-dependencies] only. A dev-dependency is built for that crate's own
#      tests, benches and examples, and for nothing that depends on it.
#   3. No [workspace.dependencies] entry asks for it: that would hand it to
#      every member that inherits the entry, whatever table they use.
#   4. No crate's own [features] table forwards it (`shekyl-noise/test-support`
#      or the `?` form). A forwarded feature is on whenever someone enables
#      the forwarding one, and nothing here could see who does.
#
# This is the mechanism of check_clatter_not_in_production.py: the manifests
# are read as data, and the gate's own failure cases are exercised by
# --selftest.
#
# SUBJECT. If the crate or the feature is gone, this gate has nothing to check
# and says so by failing: delete the gate with the feature, do not leave it
# passing over nothing.
#
# Usage:  check_noise_test_support.py            # check the tree
#         check_noise_test_support.py --selftest # bite each failure

import pathlib
import sys
import tempfile
import tomllib

CRATE = "shekyl-noise"
FEATURE = "test-support"
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
FORWARDS = (f"{CRATE}/{FEATURE}", f"{CRATE}?/{FEATURE}")


def _tables(manifest):
    """Yield (table_name, table) for every dependency table of a manifest,
    target-specific ones included, and the workspace's shared table."""
    for name in DEP_TABLES:
        if isinstance(manifest.get(name), dict):
            yield name, manifest[name]
    for target in (manifest.get("target") or {}).values():
        if isinstance(target, dict):
            for name in DEP_TABLES:
                if isinstance(target.get(name), dict):
                    yield name, target[name]
    workspace = manifest.get("workspace") or {}
    if isinstance(workspace.get("dependencies"), dict):
        yield "workspace.dependencies", workspace["dependencies"]


def _asks_for_feature(key, spec):
    """Whether a dependency entry is the crate, by key or by rename, with the
    feature turned on."""
    if not isinstance(spec, dict):
        return False
    if key != CRATE and spec.get("package") != CRATE:
        return False
    return FEATURE in (spec.get("features") or [])


def check(rust_dir):
    problems = []
    rust_dir = pathlib.Path(rust_dir)
    manifests = sorted(p for p in rust_dir.rglob("Cargo.toml") if "target" not in p.parts)
    if not manifests:
        return [f"no Cargo.toml under {rust_dir}: nothing was read"], 0

    declared = False
    dev_sites = 0
    for path in manifests:
        rel = path.relative_to(rust_dir)
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
        package = (manifest.get("package") or {}).get("name")
        features = manifest.get("features") or {}

        if package == CRATE:
            if FEATURE in features:
                declared = True
            if FEATURE in (features.get("default") or []):
                problems.append(
                    f"{rel}: {CRATE}'s default features include {FEATURE}. It would be on "
                    "in every build that does not turn defaults off.")

        for name, members in features.items():
            if not isinstance(members, list):
                continue
            for member in members:
                if member in FORWARDS:
                    problems.append(
                        f"{rel}: feature {name!r} forwards {member}. Whoever enables "
                        f"{name!r} turns raw-key access on, in whatever build they are in. "
                        f"Ask for {FEATURE} directly, under [dev-dependencies].")

        for table_name, table in _tables(manifest):
            for key, spec in table.items():
                if not _asks_for_feature(key, spec):
                    continue
                if table_name == "dev-dependencies":
                    dev_sites += 1
                    continue
                problems.append(
                    f"{rel}: [{table_name}] turns on {CRATE}'s {FEATURE}. That feature "
                    "exposes raw session keys; it may be asked for under "
                    "[dev-dependencies] only.")

    if not declared:
        problems.append(
            f"{CRATE} does not declare a {FEATURE} feature (or the crate is gone): this "
            "gate has no subject. If the feature was removed on purpose, remove this gate "
            "with it.")
    return problems, dev_sites


# --- self-test ---------------------------------------------------------------

_NOISE = f"""[package]
name = "{CRATE}"
[features]
{FEATURE} = []
"""
_USER = f"""[package]
name = "shekyl-user"
[dependencies]
{CRATE} = {{ path = "../{CRATE}" }}
[dev-dependencies]
{CRATE} = {{ path = "../{CRATE}", features = ["{FEATURE}"] }}
"""
_ROOT = """[workspace]
members = ["shekyl-noise", "shekyl-user"]
"""


def _tree(root, noise=_NOISE, user=_USER, top=_ROOT):
    for name, text in ((CRATE, noise), ("shekyl-user", user)):
        if text is None:
            continue
        (root / name).mkdir(parents=True)
        (root / name / "Cargo.toml").write_text(text, encoding="utf-8")
    if top is not None:
        (root / "Cargo.toml").write_text(top, encoding="utf-8")


def selftest():
    normal = f'{CRATE} = {{ path = "../{CRATE}" }}\n[dev-dependencies]'
    cases = [
        ("the intended shape passes", {}, 0),
        ("a normal dependency turns the feature on",
         {"user": _USER.replace(
             normal, f'{CRATE} = {{ path = "../{CRATE}", features = ["{FEATURE}"] }}\n[dev-dependencies]')}, 1),
        ("a build dependency turns it on",
         {"user": _USER + f'[build-dependencies]\n{CRATE} = {{ path = "../{CRATE}", features = ["{FEATURE}"] }}\n'}, 1),
        ("a target-specific normal dependency turns it on",
         {"user": _USER + f'[target."cfg(unix)".dependencies]\n{CRATE} = {{ path = "../{CRATE}", features = ["{FEATURE}"] }}\n'}, 1),
        ("a renamed normal dependency turns it on",
         {"user": _USER.replace(
             normal, f'noise = {{ package = "{CRATE}", path = "../{CRATE}", features = ["{FEATURE}"] }}\n[dev-dependencies]')}, 1),
        ("the workspace's shared entry turns it on",
         {"top": _ROOT + f'[workspace.dependencies]\n{CRATE} = {{ path = "{CRATE}", features = ["{FEATURE}"] }}\n'}, 1),
        ("a crate's own feature forwards it",
         {"user": _USER + f'[features]\nkeys = ["{CRATE}/{FEATURE}"]\n'}, 1),
        ("a crate's own feature forwards it with the optional form",
         {"user": _USER + f'[features]\nkeys = ["{CRATE}?/{FEATURE}"]\n'}, 1),
        ("the crate's defaults include it",
         {"noise": _NOISE + f'default = ["{FEATURE}"]\n'}, 1),
        ("a target-specific dev dependency is still a dev dependency",
         {"user": _USER + f'[target."cfg(unix)".dev-dependencies]\n{CRATE} = {{ path = "../{CRATE}", features = ["{FEATURE}"] }}\n'}, 0),
        ("the feature is gone: no subject",
         {"noise": f'[package]\nname = "{CRATE}"\n',
          "user": f'[package]\nname = "shekyl-user"\n[dependencies]\n{CRATE} = {{ path = "../{CRATE}" }}\n'}, 1),
        ("the crate is gone: no subject", {"noise": None}, 1),
    ]
    failed = 0
    for label, overrides, want in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _tree(root, **overrides)
            problems, _sites = check(root)
            got = 1 if problems else 0
        if got == want:
            print(f"ok   {label}")
        else:
            failed += 1
            print(f"FAIL {label}: wanted {'a refusal' if want else 'a pass'}", file=sys.stderr)
    print(f"{failed} failing case(s)")
    return 1 if failed else 0


def main():
    if "--selftest" in sys.argv[1:]:
        return selftest()
    rust_dir = pathlib.Path(__file__).resolve().parents[2] / "rust"
    problems, dev_sites = check(rust_dir)
    if problems:
        print("noise test-support gate: FAIL", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    print(f"noise test-support gate: PASS ({CRATE}'s {FEATURE} is asked for by "
          f"{dev_sites} dev-dependency entr{'y' if dev_sites == 1 else 'ies'} and nothing else)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
