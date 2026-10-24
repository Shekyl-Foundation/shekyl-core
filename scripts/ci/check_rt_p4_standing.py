#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""RT-P4's standing check (RPC_CHANNEL.md §9 RT-P4, §13 RT-W9; RT-O22).

RT-P4 measured that `fips203`'s ML-KEM-768 decapsulation time does not
depend on the ciphertext, on two machines, each built one way. A change to
the toolchain, the pinned crate or the code-generation settings changes the
code that result is about, without touching the harness. This gate reads
every source of those settings and compares them with what each run was
built with (`docs/benchmarks/rt_p4_attestation.toml`).

The sources:

1. `rust/rust-toolchain.toml`: the `[toolchain] channel`.
2. `rust/Cargo.lock`: the `fips203` version and checksum.
3. `rust/Cargo.toml`: `[profile.release]`, as written.
4. `rust/.cargo/config.toml`: each target's `rustflags`.
5. `cmake/BuildRust.cmake`: the cargo flags, the `-C` flags and the
   environment the C++ build gives cargo.
6. `contrib/gitian/gitian-*.yml`: the toolchain each release build installs,
   and anything else that reaches rustc.

It fails two ways:

- **On anything it does not recognise**, in any source: a profile key, a
  config table or rustflag, a cargo flag, an environment variable, a rustup
  option. It cannot tell whether such a thing changes the generated code,
  so it does not guess. The fix is a reviewed change to this file.
- **On a recognised setting that differs from a run's attestation**, for
  that run's target. The message names the device and the command to run.
  The attestation is updated with the new run's record, never on its own.

Exit 0 when nothing differs; 1 naming each failure; 2 when a subject cannot
be read (rule 47: a gate asserts its own subject).
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ATTESTATION = "docs/benchmarks/rt_p4_attestation.toml"
TOOLCHAIN = "rust/rust-toolchain.toml"
LOCK = "rust/Cargo.lock"
MANIFEST = "rust/Cargo.toml"
CARGO_CONFIG = "rust/.cargo/config.toml"
BUILD_RUST = "cmake/BuildRust.cmake"
GITIAN_GLOB = "contrib/gitian/gitian-*.yml"
HARNESS = "rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs"

PINNED_CRATE = "fips203"

# Every key Cargo documents for a profile. A key outside this set (or a
# nested table such as `package` or `build-override`) is unrecognised.
PROFILE_KEYS = {
    "opt-level", "debug", "split-debuginfo", "strip", "debug-assertions",
    "overflow-checks", "lto", "panic", "incremental", "codegen-units", "rpath",
}

# The `-C` values a target's rustflags may carry. `+crt-static` selects the
# static C runtime on MSVC (rust/.cargo/config.toml).
KNOWN_RUSTFLAGS = {"target-feature=+crt-static"}

# What cmake/BuildRust.cmake gives cargo today, each read at its use.
# The environment: compilers and flags for the C compiled inside crates,
# the cross linker, the macOS deployment floor and SDK, and (cross builds
# only) a target's RUSTFLAGS, which the `-C` check below holds to
# `link-arg=` values. The bare names are the ones it clears.
KNOWN_BUILD_ENV = {
    "AR", "AR_<T>", "CC", "CC_<T>", "CFLAGS", "CFLAGS_<T>", "CXX",
    "CXXFLAGS", "LDFLAGS", "NM", "RANLIB", "CARGO_TARGET_<T>_LINKER",
    "CARGO_TARGET_<T>_RUSTFLAGS", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT",
}
# Cargo's flags, and `--sysroot`, which is a C flag in a forwarded string.
KNOWN_BUILD_FLAGS = {
    "--features", "--locked", "--release", "--sysroot", "--target",
    "--target-dir",
}
# `-C` values: link arguments only. They change the link, not the code.
KNOWN_BUILD_C_PREFIXES = ("link-arg=",)

# rustup-init options the gitian descriptors use.
KNOWN_RUSTUP_INIT = {"-y", "--profile", "minimal", "--default-toolchain"}
# Names that would reach rustc or cargo from a descriptor.
GITIAN_FORBIDDEN = re.compile(
    r"\b(RUSTFLAGS|RUSTDOCFLAGS|CARGO_[A-Z0-9_]+|RUSTC[A-Z_]*)\b|cargo\s+\+|(?<![\w-])-C\s*[a-z-]+="
)


class Unreadable(Exception):
    """A subject the gate needs is missing or unparseable."""


# ── Reading the sources ─────────────────────────────────────────────────────


def read_toolchain(text: str) -> tuple[str, list[str]]:
    data = tomllib.loads(text)
    problems = []
    for key in data:
        if key != "toolchain":
            problems.append(f"{TOOLCHAIN}: table [{key}]")
    table = data.get("toolchain", {})
    for key in table:
        if key != "channel":
            problems.append(f"{TOOLCHAIN}: [toolchain] {key}")
    channel = table.get("channel")
    if not isinstance(channel, str):
        raise Unreadable(f"{TOOLCHAIN} names no [toolchain] channel")
    return channel, problems


def read_pinned_crate(text: str) -> tuple[str, str]:
    data = tomllib.loads(text)
    found = [p for p in data.get("package", []) if p.get("name") == PINNED_CRATE]
    if len(found) != 1:
        raise Unreadable(f"{LOCK} has {len(found)} {PINNED_CRATE} entries, expected one")
    entry = found[0]
    if "version" not in entry or "checksum" not in entry:
        raise Unreadable(f"{LOCK}: {PINNED_CRATE} has no version or checksum")
    return entry["version"], entry["checksum"]


def read_release_profile(text: str) -> tuple[dict, list[str]]:
    data = tomllib.loads(text)
    release = data.get("profile", {}).get("release")
    if release is None:
        raise Unreadable(f"{MANIFEST} has no [profile.release]")
    problems = [
        f"{MANIFEST}: [profile.release] {key}"
        for key in release
        if key not in PROFILE_KEYS or isinstance(release[key], dict)
    ]
    return release, problems


def split_rustflags(flags: list) -> tuple[list[str], list[str]]:
    """The `-C` values of a rustflags list, and anything that is not one."""
    values, other = [], []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag == "-C" and i + 1 < len(flags):
            values.append(flags[i + 1])
            i += 2
            continue
        if isinstance(flag, str) and flag.startswith("-C") and len(flag) > 2:
            values.append(flag[2:])
        else:
            other.append(str(flag))
        i += 1
    return values, other


def read_cargo_config(text: str) -> tuple[dict[str, list[str]], list[str]]:
    data = tomllib.loads(text)
    problems = []
    rustflags: dict[str, list[str]] = {}
    for key in data:
        if key != "target":
            problems.append(f"{CARGO_CONFIG}: table [{key}]")
    for triple, table in data.get("target", {}).items():
        if triple.startswith("cfg("):
            problems.append(f"{CARGO_CONFIG}: [target.'{triple}']")
            continue
        for key in table:
            if key != "rustflags":
                problems.append(f"{CARGO_CONFIG}: [target.{triple}] {key}")
        values, other = split_rustflags(table.get("rustflags", []))
        for value in values:
            if value not in KNOWN_RUSTFLAGS:
                problems.append(f"{CARGO_CONFIG}: [target.{triple}] rustflag -C {value}")
        for flag in other:
            problems.append(f"{CARGO_CONFIG}: [target.{triple}] rustflag {flag}")
        rustflags[triple] = ["-C " + v for v in values]
    return rustflags, problems


def cmake_code(text: str) -> str:
    return "\n".join(re.sub(r"#.*$", "", line) for line in text.splitlines())


def read_build_rust(text: str) -> list[str]:
    code = cmake_code(text)
    problems = []
    for value in re.findall(r'-C\s*([^\s"\)]+)', code):
        if not value.startswith(KNOWN_BUILD_C_PREFIXES):
            problems.append(f"{BUILD_RUST}: -C {value}")
    for raw in re.findall(r'"([A-Z][A-Z0-9_]*(?:\$\{[^}]+\}[A-Z0-9_]*)*)=', code):
        name = re.sub(r"\$\{[^}]+\}", "<T>", raw)
        if name not in KNOWN_BUILD_ENV:
            problems.append(f"{BUILD_RUST}: environment {name}")
    for flag in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", code):
        if flag not in KNOWN_BUILD_FLAGS:
            problems.append(f"{BUILD_RUST}: flag {flag}")
    if re.search(r"(?<![\w-])-Z|\+nightly|\bCARGO_ENCODED_RUSTFLAGS\b|\bCARGO_PROFILE_", code):
        problems.append(f"{BUILD_RUST}: an unstable flag or a profile set by environment")
    return sorted(set(problems))


def read_gitian(name: str, text: str, channel: str) -> tuple[list[str], list[str]]:
    """Unrecognised things, and toolchains that differ from the pinned one."""
    problems, differs = [], []
    lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    installs = 0
    for line in lines:
        m = GITIAN_FORBIDDEN.search(line)
        if m:
            problems.append(f"{name}: {m.group(0).strip()}")
        install = re.match(r"\s*sh\s+\S*rustup-init\.sh\b(.*)$", line)
        if install:
            installs += 1
            args = install.group(1).split()
            for arg in args:
                if arg not in KNOWN_RUSTUP_INIT and not re.fullmatch(r"\d+\.\d+\.\d+", arg):
                    problems.append(f"{name}: rustup-init {arg}")
            m = re.search(r"--default-toolchain\s+(\S+)", line)
            if not m:
                problems.append(f"{name}: rustup-init without --default-toolchain")
            elif m.group(1) != channel:
                differs.append(f"{name} installs {m.group(1)}, {TOOLCHAIN} pins {channel}")
        for m in re.finditer(r"\brustup\s+([a-z-]+)(?:\s+([a-z-]+))?", line):
            if (m.group(1), m.group(2)) != ("target", "add"):
                problems.append(f"{name}: rustup {m.group(1)} {m.group(2) or ''}".rstrip())
    if installs != 1:
        problems.append(f"{name}: {installs} rustup-init installs, expected one")
    return problems, differs


# ── The comparison ──────────────────────────────────────────────────────────


def shipped_for(target: str, sources: dict) -> dict:
    return {
        "toolchain": sources["toolchain"],
        "fips203": sources["fips203"][0],
        "fips203_checksum": sources["fips203"][1],
        "rustflags": sources["rustflags"].get(target, []),
        "profile_release": sources["profile"],
    }


def normalise_rustflags(flags: list) -> list[str]:
    values, other = split_rustflags(flags)
    return ["-C " + v for v in values] + other


def drift(run: dict, shipped: dict) -> list[str]:
    out = []
    for field in ("toolchain", "fips203", "fips203_checksum", "rustflags", "profile_release"):
        attested = run.get(field)
        now = shipped[field]
        if field == "rustflags":
            attested = normalise_rustflags(attested or [])
        if attested != now:
            out.append(f"{field}: attested {attested!r}, shipped {now!r}")
    return out


def rerun_message(run: dict) -> str:
    return (
        f"  Re-run RT-P4 on {run['device']} under the registered lines in {run['record']}:\n"
        f"    cargo build --release --locked -p shekyl-rpc-channel --example rt_p4_decaps_timing\n"
        f"  on the device itself ({run['target']}), from a fresh clone of the commit that ships,\n"
        f"  run the harness ({HARNESS}) as that record registers, record the run,\n"
        f"  and set this entry of {ATTESTATION} to the new run's settings in the same change."
    )


def check(texts: dict[str, str], gitian: dict[str, str]) -> tuple[list[str], list[str]]:
    """(unrecognised, drift) over the given source texts."""
    unrecognised: list[str] = []
    channel, problems = read_toolchain(texts[TOOLCHAIN])
    unrecognised += problems
    crate = read_pinned_crate(texts[LOCK])
    profile, problems = read_release_profile(texts[MANIFEST])
    unrecognised += problems
    rustflags, problems = read_cargo_config(texts[CARGO_CONFIG])
    unrecognised += problems
    unrecognised += read_build_rust(texts[BUILD_RUST])
    if not gitian:
        raise Unreadable(f"no gitian descriptors match {GITIAN_GLOB}")
    differs: list[str] = []
    for name, text in sorted(gitian.items()):
        problems, d = read_gitian(name, text, channel)
        unrecognised += problems
        differs += d

    attestation = tomllib.loads(texts[ATTESTATION])
    runs = attestation.get("run", [])
    if not runs:
        raise Unreadable(f"{ATTESTATION} attests no run")
    sources = {"toolchain": channel, "fips203": crate, "rustflags": rustflags, "profile": profile}
    drifts: list[str] = []
    if differs:
        drifts.append(
            "SHIPPED TOOLCHAIN SPLIT: a release build installs a toolchain other than the pinned one\n"
            + "\n".join(f"  {d}" for d in differs)
            + "\n  The bump policy in rust/rust-toolchain.toml moves them together; RT-P4 then re-runs."
        )
    for run in runs:
        for field in ("device", "record", "commit", "target"):
            if not run.get(field):
                raise Unreadable(f"{ATTESTATION}: a run has no {field}")
        found = drift(run, shipped_for(run["target"], sources))
        if found:
            drifts.append(
                f"RT-P4 ATTESTATION DRIFT for {run['device']} ({run['target']}; "
                f"{run['record']} at {run['commit']}):\n"
                + "\n".join(f"  {f}" for f in found)
                + "\n" + rerun_message(run)
            )
    return sorted(set(unrecognised)), drifts


# ── Running it ──────────────────────────────────────────────────────────────


def read_tree(root: Path) -> tuple[dict[str, str], dict[str, str]]:
    texts = {}
    for path in (ATTESTATION, TOOLCHAIN, LOCK, MANIFEST, CARGO_CONFIG, BUILD_RUST):
        p = root / path
        if not p.is_file():
            raise Unreadable(f"{path} is missing")
        texts[path] = p.read_text()
    gitian = {str(p.relative_to(root)): p.read_text() for p in sorted(root.glob(GITIAN_GLOB))}
    attestation = tomllib.loads(texts[ATTESTATION])
    for run in attestation.get("run", []):
        if not (root / run.get("record", "")).is_file():
            raise Unreadable(f"{ATTESTATION}: record {run.get('record')!r} does not exist")
    if not (root / HARNESS).is_file():
        raise Unreadable(f"the harness {HARNESS} is missing")
    return texts, gitian


def report(unrecognised: list[str], drifts: list[str]) -> int:
    for item in unrecognised:
        print(f"UNRECOGNISED {item}", file=sys.stderr)
    if unrecognised:
        print(
            "  The standing check cannot tell whether that changes the code RT-P4 measured.\n"
            "  Teach scripts/ci/check_rt_p4_standing.py what it is in a reviewed change;\n"
            "  if it changes the generated code, RT-P4 is re-run on every attested device.",
            file=sys.stderr,
        )
    for item in drifts:
        print(item, file=sys.stderr)
    return 1 if unrecognised or drifts else 0


SELFTEST_TOOLCHAIN = '[toolchain]\nchannel = "1.94.0"\n'
SELFTEST_LOCK = (
    '[[package]]\nname = "fips203"\nversion = "0.4.3"\n'
    'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "c8bd"\n'
)
SELFTEST_MANIFEST = '[profile.release]\npanic = "abort"\noverflow-checks = true\n'
SELFTEST_CONFIG = '[target.x86_64-pc-windows-msvc]\nrustflags = ["-C", "target-feature=+crt-static"]\n'
SELFTEST_BUILD = (
    'set(RUST_BUILD_FLAG "--release")\n'
    '# a comment with --anything and -C opt-level=3 is ignored\n'
    'list(APPEND _rust_env_clear "CARGO_TARGET_${_upper_triple}_LINKER=${CMAKE_C_COMPILER}")\n'
    'string(APPEND _rust_link_args " -C link-arg=${_flag}")\n'
    '${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}\n'
)
SELFTEST_GITIAN = (
    "  sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.94.0\n"
    "  rustup target add x86_64-pc-windows-gnu\n"
)
SELFTEST_ATTESTATION = """
[[run]]
device = "floor"
record = "r.md"
commit = "abc"
target = "aarch64-unknown-linux-gnu"
toolchain = "1.94.0"
fips203 = "0.4.3"
fips203_checksum = "c8bd"
rustflags = []
[run.profile_release]
panic = "abort"
overflow-checks = true

[[run]]
device = "laptop"
record = "r.md"
commit = "abc"
target = "x86_64-pc-windows-msvc"
toolchain = "1.94.0"
fips203 = "0.4.3"
fips203_checksum = "c8bd"
rustflags = ["-C", "target-feature=+crt-static"]
[run.profile_release]
panic = "abort"
overflow-checks = true
"""


def selftest() -> int:
    base = {
        ATTESTATION: SELFTEST_ATTESTATION,
        TOOLCHAIN: SELFTEST_TOOLCHAIN,
        LOCK: SELFTEST_LOCK,
        MANIFEST: SELFTEST_MANIFEST,
        CARGO_CONFIG: SELFTEST_CONFIG,
        BUILD_RUST: SELFTEST_BUILD,
    }
    gitian = {"gitian-win.yml": SELFTEST_GITIAN}

    def run(edit_path: str | None, old: str = "", new: str = "", g: dict | None = None):
        texts = dict(base)
        if edit_path:
            assert old in texts[edit_path], (edit_path, old)
            texts[edit_path] = texts[edit_path].replace(old, new)
        return check(texts, g if g is not None else gitian)

    # (name, edit, expected kind, a phrase the failure must carry)
    cases = [
        ("toolchain bumped", (TOOLCHAIN, '"1.94.0"', '"1.95.0"'), "drift", "toolchain: attested '1.94.0'"),
        ("toolchain gains a key", (TOOLCHAIN, 'channel', 'components = []\nchannel'), "unrecognised", "[toolchain] components"),
        ("crate bumped", (LOCK, '"0.4.3"', '"0.4.4"'), "drift", "fips203: attested '0.4.3'"),
        ("crate checksum", (LOCK, '"c8bd"', '"ffff"'), "drift", "fips203_checksum"),
        ("profile value", (MANIFEST, 'overflow-checks = true', 'overflow-checks = false'), "drift", "profile_release"),
        ("profile known key added", (MANIFEST, 'panic', 'opt-level = 2\npanic'), "drift", "profile_release"),
        ("profile unknown key", (MANIFEST, 'panic', 'trim-paths = true\npanic'), "unrecognised", "[profile.release] trim-paths"),
        ("profile nested table", (MANIFEST, 'overflow-checks = true\n', 'overflow-checks = true\n[profile.release.package.fips203]\nopt-level = 1\n'), "unrecognised", "[profile.release] package"),
        ("rustflag removed", (CARGO_CONFIG, '"-C", "target-feature=+crt-static"', ''), "drift", "rustflags: attested"),
        ("rustflag unknown", (CARGO_CONFIG, '"target-feature=+crt-static"', '"target-cpu=native"'), "unrecognised", "rustflag -C target-cpu=native"),
        ("config unknown table", (CARGO_CONFIG, '[target.', '[build]\njobs = 1\n[target.'), "unrecognised", "table [build]"),
        ("config cfg target", (CARGO_CONFIG, '[target.x86_64-pc-windows-msvc]', "[target.'cfg(windows)']"), "unrecognised", "cfg(windows)"),
        ("build rust codegen -C", (BUILD_RUST, 'link-arg=${_flag}', 'opt-level=3'), "unrecognised", "-C opt-level=3"),
        ("build rust env", (BUILD_RUST, 'CARGO_TARGET_${_upper_triple}_LINKER', 'RUSTFLAGS'), "unrecognised", "environment RUSTFLAGS"),
        ("build rust flag", (BUILD_RUST, '--locked', '--locked --config profile.release.lto=true'), "unrecognised", "flag --config"),
        ("build rust -Z", (BUILD_RUST, '--locked', '--locked -Zbuild-std'), "unrecognised", "unstable flag"),
    ]
    failures = 0
    unrecognised, drifts = run(None)
    if unrecognised or drifts:
        print(f"selftest: the clean case failed: {unrecognised} {drifts}", file=sys.stderr)
        failures += 1
    for name, (path, old, new), kind, phrase in cases:
        unrecognised, drifts = run(path, old, new)
        # An unrecognised key inside a compared table is reported as drift
        # too; what matters is that it is named as unrecognised. A drift
        # case must not also be called unrecognised.
        bucket = unrecognised if kind == "unrecognised" else drifts
        if not any(phrase in item for item in bucket) or (kind == "drift" and unrecognised):
            print(f"selftest: '{name}' did not fail as {kind} carrying {phrase!r}: "
                  f"unrecognised={unrecognised} drift={drifts}", file=sys.stderr)
            failures += 1
    gitian_cases = [
        ("gitian toolchain split", SELFTEST_GITIAN.replace("1.94.0", "1.95.0"), "drift", "installs 1.95.0"),
        ("gitian RUSTFLAGS", SELFTEST_GITIAN + '  export RUSTFLAGS="-C target-cpu=native"\n', "unrecognised", "RUSTFLAGS"),
        ("gitian rustup option", SELFTEST_GITIAN.replace("--profile minimal", "--profile default"), "unrecognised", "rustup-init default"),
        ("gitian rustup command", SELFTEST_GITIAN + "  rustup default nightly\n", "unrecognised", "rustup default nightly"),
        ("gitian no install", "  rustup target add x86_64-pc-windows-gnu\n", "unrecognised", "0 rustup-init installs"),
    ]
    for name, text, kind, phrase in gitian_cases:
        unrecognised, drifts = run(None, g={"gitian-win.yml": text})
        bucket = unrecognised if kind == "unrecognised" else drifts
        if not any(phrase in item for item in bucket):
            print(f"selftest: '{name}' did not fail as {kind} carrying {phrase!r}: "
                  f"unrecognised={unrecognised} drift={drifts}", file=sys.stderr)
            failures += 1
    # The drift message says what to run.
    _, drifts = run(TOOLCHAIN, '"1.94.0"', '"1.95.0"')
    run_drifts = [d for d in drifts if d.startswith("RT-P4 ATTESTATION DRIFT")]
    if len(run_drifts) != 2 or not all(
        "cargo build --release --locked -p shekyl-rpc-channel --example rt_p4_decaps_timing" in d
        for d in run_drifts
    ):
        print("selftest: a drift message does not say what to run", file=sys.stderr)
        failures += 1
    total = 1 + len(cases) + len(gitian_cases) + 1
    if failures:
        print(f"selftest: {failures} of {total} cases failed", file=sys.stderr)
        return 1
    print(f"selftest: {total} cases OK")
    return 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if argv[1:]:
        print("usage: check_rt_p4_standing.py [--selftest]", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[2]
    try:
        texts, gitian = read_tree(root)
        unrecognised, drifts = check(texts, gitian)
    except (Unreadable, tomllib.TOMLDecodeError) as error:
        print(f"RT-P4 standing check: cannot read its subject: {error}", file=sys.stderr)
        return 2
    code = report(unrecognised, drifts)
    attestation = tomllib.loads(texts[ATTESTATION])
    print(
        f"RT-P4 standing check: {len(attestation['run'])} attested runs, "
        f"{len(gitian)} release descriptors; " + ("FAIL" if code else "PASS")
    )
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
