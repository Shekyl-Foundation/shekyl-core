#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""RT-P4's standing check (RPC_CHANNEL.md §9 RT-P4, §13 RT-W9; RT-O22).

The check reads the sources that decide the code RT-P4 measured, and
compares them with `docs/benchmarks/rt_p4_attestation.toml`.

Sources:

1. `rust/rust-toolchain.toml`: the `[toolchain] channel`.
2. `rust/Cargo.lock`: the decapsulation closure of `fips203`.
3. `rust/Cargo.toml`: `[profile.release]`, the recognised keys only.
4. `rust/.cargo/config.toml`: each target's `rustflags`.
5. `cmake/BuildRust.cmake`: cargo invocations, `-C` tokens, environment.
6. `contrib/gitian/gitian-*.yml`: the toolchain each release build
   installs. A descriptor builds through make. A cargo or rustc
   command, a `RUSTUP_*` variable, or a `+` toolchain selector is
   unrecognised. `.cargo` on `PATH` and make's `-C` are the build.

Three findings. An unrecognised key is not by itself a re-run. Drift
is only a recognised setting that changed. The two meet when one edit
does both, such as replacing a known rustflag with an unknown one:
the recognised snapshot changed, and the new flag has no account here.

- **unrecognised** — a key, token or flag this file has no account of.
  The fix is a reviewed change here, and a re-run only when that
  change alters the generated code.
- **invalid** — an attestation entry outside its basis's key set, a
  broken evidence pin, or a rustflags target that is neither a run nor
  an `[[unmeasured]]` row. The scan continues with the other entries.
  A schema-invalid entry is not also a drift of that entry.
- **drift** — a recognised setting that differs from the attestation.
  The message names the device and what to run.

Exit 0 when nothing differs; 1 naming each finding; 2 when a subject
cannot be read (rule 47: a gate asserts its own subject). A missing
field on one entry is invalid, not unreadable: the file was read.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
import sys
import tomllib

ATTESTATION = "docs/benchmarks/rt_p4_attestation.toml"
TOOLCHAIN = "rust/rust-toolchain.toml"
LOCK = "rust/Cargo.lock"
MANIFEST = "rust/Cargo.toml"
CARGO_CONFIG = "rust/.cargo/config.toml"
BUILD_RUST = "cmake/BuildRust.cmake"
GITIAN_GLOB = "contrib/gitian/gitian-*.yml"
HARNESS = "rust/shekyl-rpc-channel/examples/rt_p4_decaps_timing.rs"

CLOSURE_ROOT = "fips203"

# Every key Cargo documents for a profile. A key outside this set, or a
# nested table, is unrecognised in Cargo.toml and invalid in an entry.
PROFILE_KEYS = frozenset({
    "opt-level", "debug", "split-debuginfo", "strip", "debug-assertions",
    "overflow-checks", "lto", "panic", "incremental", "codegen-units", "rpath",
})

# The one `-C` value a target's rustflags may carry. `+crt-static` selects
# the static C runtime on MSVC (rust/.cargo/config.toml).
KNOWN_RUSTFLAGS = frozenset({"target-feature=+crt-static"})

# What cmake/BuildRust.cmake gives cargo, each read at its use.
# Compilers and flags for the C compiled inside crates, the cross linker,
# the macOS deployment floor and SDK, and (cross builds only) a target's
# RUSTFLAGS, which the `-C` check holds to `link-arg=`. The bare names are
# the ones it clears.
KNOWN_BUILD_ENV = frozenset({
    "AR", "AR_<T>", "CC", "CC_<T>", "CFLAGS", "CFLAGS_<T>", "CXX",
    "CXXFLAGS", "LDFLAGS", "NM", "RANLIB", "CARGO_TARGET_<T>_LINKER",
    "CARGO_TARGET_<T>_RUSTFLAGS", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT",
})
KNOWN_BUILD_FLAGS = frozenset({
    "--features", "--locked", "--release", "--sysroot", "--target",
    "--target-dir",
})
# After `build --locked`, the only tokens a cargo invocation may carry.
CARGO_TAIL = frozenset({
    "${RUST_BUILD_FLAG}",
    "${RUST_TARGET_FLAG}",
    "${_measurement_features}",
    "${_shekyl_rust_bin_pkg_args}",
})
CARGO_END = frozenset({
    "WORKING_DIRECTORY", "DEPENDS", "COMMENT", "VERBATIM", ")", "COMMAND", "OUTPUT",
})

# The decapsulation image is the lock-file closure of fips203 with three
# cuts. Each cut is a crate that is not object code on the measured path
# (the committed disassembly is fips203, subtle, keccak, sha3, zeroize):
#
# - Leaves are pinned and not expanded. `rand_core`'s only edge is
#   `getrandom`, fips203's `default-rng` feature; decapsulation takes no
#   RNG, and following it reaches the wasm graph. `cpufeatures`'s edge is
#   `libc`, FFI declarations; the detection logic is in cpufeatures.
# - A `*_derive` crate is a leaf for the same reason: the macro is part of
#   the build of the image, its host crates (syn, quote, proc-macro2) are not.
# - `version_check` is generic-array's build script. It is neither pinned
#   nor expanded.
CLOSURE_LEAVES = frozenset({"rand_core", "cpufeatures"})
CLOSURE_NOT_IMAGE = frozenset({"version_check"})

# rustup-init options the gitian descriptors use. `minimal` is the value
# of `--profile`, allowlisted as its own token because the descriptor's
# install line is a fixed spelling.
KNOWN_RUSTUP_INIT = frozenset({"-y", "--profile", "minimal", "--default-toolchain"})
# A descriptor installs the toolchain and builds through make. A cargo or
# rustc command, a rustup/cargo/rustc environment variable, or a `+`
# toolchain selector would reach the compiler another way. `.cargo` is the
# toolchain directory on PATH; make's `-C` changes directory. Neither is a
# compiler invocation, so neither is a signal here. The cmake scan holds
# every rustc `-C` to `link-arg=`.
GITIAN_FORBIDDEN = re.compile(
    r"\b(?:RUSTFLAGS|RUSTDOCFLAGS|RUSTUP_[A-Z0-9_]+|CARGO_[A-Z0-9_]+|RUSTC[A-Z_]*)\b"
    r"|(?<!\.)\b(?:cargo|rustc)\b"
    r"|(?<![\w+])\+(?:nightly|stable|beta|\d+\.\d+(?:\.\d+)?)"
)

TIMING_FIELDS = frozenset({
    "device", "basis", "record", "commit", "target",
    "toolchain", "rustflags", "profile_release",
})
DISASSEMBLY_FIELDS = TIMING_FIELDS | frozenset({
    "identical_to_record", "identical_to_commit", "comparison", "comparison_sha256",
})
BASIS_FIELDS = {"timing": TIMING_FIELDS, "disassembly": DISASSEMBLY_FIELDS}
CRATE_FIELDS = frozenset({"version", "checksum"})
UNMEASURED_FIELDS = frozenset({"target", "reason"})
ATTESTATION_KEYS = frozenset({"run", "crates", "unmeasured"})

ENV_NAME = re.compile(r"^([A-Z][A-Z0-9_]*(?:\$\{[^}]+\}[A-Z0-9_]*)*)=")
FLAG_NAME = re.compile(r"^(--[a-z][a-z0-9-]*)")
SELECTOR = re.compile(r"^\+(?:nightly|stable|beta|\d+\.\d+(?:\.\d+)?)$")
PACKAGE_ARG = re.compile(r"^shekyl-[a-z0-9-]+$|^\$\{[^}]+\}$")
# A CMake bracket comment (`#[[ ... ]]`, or with `=` between the brackets)
# hides every token inside it from a line-comment strip. `#` `[` followed
# by anything else is an ordinary token: `#[cfg(test)]` in a comment is
# not one of these. When one is present the scan cannot see the cargo
# invocations, so the file is unreadable (rule 47) rather than a finding
# list that would hide whatever the brackets contain.
CMAKE_BRACKET_COMMENT = re.compile(r"#\[=*\[")


class Unreadable(Exception):
    """A subject the gate needs is missing or unparseable."""


@dataclass(frozen=True)
class CratePin:
    version: str
    checksum: str

    def text(self) -> str:
        return f"version {self.version} checksum {self.checksum}"


@dataclass(frozen=True)
class Findings:
    unrecognised: tuple[str, ...]
    invalid: tuple[str, ...]
    drift: tuple[str, ...]

    def failed(self) -> bool:
        return bool(self.unrecognised or self.invalid or self.drift)


# ── Reading the sources ─────────────────────────────────────────────────────


def read_toolchain(text: str) -> tuple[str, list[str]]:
    data = tomllib.loads(text)
    problems = [f"{TOOLCHAIN}: table [{key}]" for key in data if key != "toolchain"]
    table = data.get("toolchain", {})
    problems += [f"{TOOLCHAIN}: [toolchain] {key}" for key in table if key != "channel"]
    channel = table.get("channel")
    if not isinstance(channel, str):
        raise Unreadable(f"{TOOLCHAIN} names no [toolchain] channel")
    return channel, problems


def _resolve_dep(spec: str, by_name: dict[str, list[dict]]) -> dict:
    parts = spec.split()
    name = parts[0]
    version = parts[1] if len(parts) >= 2 and not parts[1].startswith("(") else None
    found = by_name.get(name, [])
    if version is None:
        if len(found) != 1:
            raise Unreadable(
                f"{LOCK}: dependency {spec!r} matches {len(found)} versions"
            )
        return found[0]
    match = [pkg for pkg in found if pkg.get("version") == version]
    if len(match) != 1:
        raise Unreadable(f"{LOCK}: dependency {spec!r} matches {len(match)} packages")
    return match[0]


def crate_closure(packages: list[dict]) -> dict[str, CratePin]:
    """fips203 and every crate in the decapsulation image, keyed by name.

    Leaves are pinned and not expanded. `CLOSURE_NOT_IMAGE` and the
    dependencies of a `*_derive` crate are not part of the image.
    """
    by_name: dict[str, list[dict]] = {}
    for pkg in packages:
        by_name.setdefault(pkg.get("name", ""), []).append(pkg)
    root = by_name.get(CLOSURE_ROOT, [])
    if len(root) != 1:
        raise Unreadable(f"{LOCK} has {len(root)} {CLOSURE_ROOT} entries, expected one")

    pins: dict[str, CratePin] = {}
    pending = [root[0]]
    seen: set[tuple[str, str]] = set()
    while pending:
        pkg = pending.pop()
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise Unreadable(f"{LOCK}: a package in the {CLOSURE_ROOT} closure has no name")
        identity = (name, version)
        if identity in seen:
            continue
        seen.add(identity)
        if name in CLOSURE_NOT_IMAGE:
            continue
        checksum = pkg.get("checksum")
        if not isinstance(checksum, str):
            raise Unreadable(f"{LOCK}: {name} {version} has no checksum")
        pin = CratePin(version, checksum)
        previous = pins.get(name)
        if previous is not None and previous != pin:
            raise Unreadable(f"{LOCK}: the closure reaches two versions of {name}")
        pins[name] = pin
        if name in CLOSURE_LEAVES or name.endswith("_derive"):
            continue
        for spec in pkg.get("dependencies", []):
            if isinstance(spec, str):
                pending.append(_resolve_dep(spec, by_name))
    if CLOSURE_ROOT not in pins:
        raise Unreadable(f"{LOCK}: the closure does not contain {CLOSURE_ROOT}")
    return pins


def read_release_profile(text: str) -> tuple[dict, list[str]]:
    """Recognised `[profile.release]` keys, and the keys that are not.

    The snapshot omits what it does not recognise, so an unknown key is
    not also a difference against the attestation.
    """
    data = tomllib.loads(text)
    release = data.get("profile", {}).get("release")
    if not isinstance(release, dict):
        raise Unreadable(f"{MANIFEST} has no [profile.release]")
    snapshot = {}
    problems = []
    for key, value in release.items():
        if key not in PROFILE_KEYS or isinstance(value, dict):
            problems.append(f"{MANIFEST}: [profile.release] {key}")
        else:
            snapshot[key] = value
    return snapshot, problems


def split_rustflags(flags: list) -> tuple[list[str], list[str]]:
    """The `-C` values of a rustflags list, and anything that is not one."""
    values, other = [], []
    index = 0
    while index < len(flags):
        flag = flags[index]
        if flag == "-C" and index + 1 < len(flags):
            values.append(flags[index + 1])
            index += 2
            continue
        if isinstance(flag, str) and flag.startswith("-C") and len(flag) > 2:
            values.append(flag[2:])
        else:
            other.append(str(flag))
        index += 1
    return values, other


def recognised_rustflags(flags: list) -> tuple[list[str], list[str]]:
    """Normalised known `-C` flags, and the flags that are not known."""
    values, other = split_rustflags(flags)
    kept, problems = [], []
    for value in values:
        if value in KNOWN_RUSTFLAGS:
            kept.append("-C " + value)
        else:
            problems.append(f"rustflag -C {value}")
    problems += [f"rustflag {flag}" for flag in other]
    return kept, problems


def read_cargo_config(text: str) -> tuple[dict[str, list[str] | None], list[str]]:
    """rustflags per target. `None` means the value was not a list.

    A `None` entry is unrecognised and is not compared. Unknown `-C`
    values are omitted from the list that is compared.
    """
    data = tomllib.loads(text)
    problems = [f"{CARGO_CONFIG}: table [{key}]" for key in data if key != "target"]
    rustflags: dict[str, list[str] | None] = {}
    for triple, table in data.get("target", {}).items():
        if triple.startswith("cfg("):
            problems.append(f"{CARGO_CONFIG}: [target.'{triple}']")
            continue
        if not isinstance(table, dict):
            problems.append(f"{CARGO_CONFIG}: [target.{triple}]")
            rustflags[triple] = None
            continue
        for key in table:
            if key != "rustflags":
                problems.append(f"{CARGO_CONFIG}: [target.{triple}] {key}")
        raw = table.get("rustflags", [])
        if not isinstance(raw, list):
            problems.append(f"{CARGO_CONFIG}: [target.{triple}] rustflags is not a list")
            rustflags[triple] = None
            continue
        kept, flag_problems = recognised_rustflags(raw)
        problems += [f"{CARGO_CONFIG}: [target.{triple}] {item}" for item in flag_problems]
        rustflags[triple] = kept
    return rustflags, problems


def strip_cmake_comments(text: str) -> str:
    """CMake `#` comments, leaving quoted strings intact."""
    out = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" and end + 1 < length else 1
            out.append(text[index:end + 1] if end < length else text[index:])
            index = end + 1 if end < length else length
            continue
        if text[index] == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def cmake_tokens(code: str) -> list[tuple[str, bool]]:
    """`(text, quoted)` tokens. A quoted `${CARGO_EXECUTABLE}` is a mention."""
    tokens: list[tuple[str, bool]] = []
    index = 0
    length = len(code)
    while index < length:
        char = code[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == '"':
            end = index + 1
            buf: list[str] = []
            while end < length and code[end] != '"':
                if code[end] == "\\" and end + 1 < length:
                    buf.append(code[end + 1])
                    end += 2
                    continue
                buf.append(code[end])
                end += 1
            tokens.extend((word, True) for word in "".join(buf).split())
            index = end + 1 if end < length else length
            continue
        if char in "()":
            tokens.append((char, False))
            index += 1
            continue
        end = index
        while end < length and code[end] not in " \t\r\n\"()":
            end += 1
        tokens.append((code[index:end], False))
        index = end
    return tokens


def _normalise_env(name: str) -> str:
    return re.sub(r"\$\{[^}]+\}", "<T>", name)


def invocation_problems(tokens: list[tuple[str, bool]], start: int) -> list[str]:
    rest = []
    for tok, _quoted in tokens[start + 1:]:
        if tok in CARGO_END:
            break
        rest.append(tok)
    if rest[:2] != ["build", "--locked"]:
        return [f"{BUILD_RUST}: cargo invocation is not build --locked"]
    problems = []
    index = 2
    while index < len(rest):
        tok = rest[index]
        if tok in CARGO_TAIL:
            index += 1
            continue
        if (
            tok == "-p"
            and index + 1 < len(rest)
            and PACKAGE_ARG.fullmatch(rest[index + 1])
        ):
            index += 2
            continue
        problems.append(f"{BUILD_RUST}: cargo argument {tok}")
        index += 1
    return problems


def read_build_rust(text: str) -> list[str]:
    """Unrecognised codegen tokens. Zero cargo invocations is unreadable.

    `-C` is a token: the next token, or the same token's suffix, must
    start with `link-arg=`. An environment write is a `NAME=` token,
    quoted or not, or `set(ENV{NAME}`. Both must name `KNOWN_BUILD_ENV`.
    """
    if CMAKE_BRACKET_COMMENT.search(text):
        raise Unreadable(
            f"{BUILD_RUST}: bracket comment; the cargo invocations cannot be read"
        )
    tokens = cmake_tokens(strip_cmake_comments(text))
    problems = []
    invocations = 0
    for index, (tok, quoted) in enumerate(tokens):
        if tok == "${CARGO_EXECUTABLE}" and not quoted:
            invocations += 1
            problems.extend(invocation_problems(tokens, index))
        if tok == "-C":
            value = tokens[index + 1][0] if index + 1 < len(tokens) else ""
            if not value.startswith("link-arg="):
                problems.append(f"{BUILD_RUST}: -C {value}")
        elif tok.startswith("-C") and not tok[2:].startswith("link-arg="):
            problems.append(f"{BUILD_RUST}: -C {tok[2:]}")
        flag = FLAG_NAME.match(tok)
        if flag and flag.group(1) not in KNOWN_BUILD_FLAGS:
            problems.append(f"{BUILD_RUST}: flag {flag.group(1)}")
        env = ENV_NAME.match(tok)
        if env:
            name = _normalise_env(env.group(1))
            if name not in KNOWN_BUILD_ENV:
                problems.append(f"{BUILD_RUST}: environment {name}")
        if tok == "set" and not quoted:
            written = _env_write(tokens, index)
            if written:
                problems.append(f"{BUILD_RUST}: environment {written}")
        if tok.startswith("-Z"):
            problems.append(f"{BUILD_RUST}: an unstable flag or a profile set by environment")
        if "CARGO_ENCODED_RUSTFLAGS" in tok or "CARGO_PROFILE_" in tok:
            problems.append(f"{BUILD_RUST}: an unstable flag or a profile set by environment")
        if SELECTOR.fullmatch(tok):
            problems.append(f"{BUILD_RUST}: toolchain selector {tok}")
    if invocations == 0:
        raise Unreadable(f"{BUILD_RUST} invokes no cargo")
    return sorted(set(problems))


def _env_write(tokens: list[tuple[str, bool]], index: int) -> str | None:
    """The name of a `set(ENV{NAME}` write that is not a known variable."""
    if index + 2 >= len(tokens) or tokens[index + 1][0] != "(":
        return None
    match = re.fullmatch(r"ENV\{([A-Za-z_][A-Za-z0-9_]*)\}", tokens[index + 2][0])
    if match and match.group(1) not in KNOWN_BUILD_ENV:
        return match.group(1)
    return None


def read_gitian(name: str, text: str, channel: str) -> tuple[list[str], list[str]]:
    """Unrecognised things, and toolchains that differ from the pinned one."""
    problems, differs = [], []
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    installs = 0
    for line in lines:
        match = GITIAN_FORBIDDEN.search(line)
        if match:
            problems.append(f"{name}: {match.group(0).strip()}")
        install = re.match(r"\s*sh\s+\S*rustup-init\.sh\b(.*)$", line)
        if install:
            installs += 1
            for arg in install.group(1).split():
                if arg not in KNOWN_RUSTUP_INIT and not re.fullmatch(r"\d+\.\d+\.\d+", arg):
                    problems.append(f"{name}: rustup-init {arg}")
            chosen = re.search(r"--default-toolchain\s+(\S+)", line)
            if not chosen:
                problems.append(f"{name}: rustup-init without --default-toolchain")
            elif chosen.group(1) != channel:
                differs.append(f"{name} installs {chosen.group(1)}, {TOOLCHAIN} pins {channel}")
        for command in re.finditer(r"\brustup\s+([a-z-]+)(?:\s+([a-z-]+))?", line):
            if (command.group(1), command.group(2)) != ("target", "add"):
                problems.append(
                    f"{name}: rustup {command.group(1)} {command.group(2) or ''}".rstrip()
                )
    if installs != 1:
        problems.append(f"{name}: {installs} rustup-init installs, expected one")
    return problems, differs


# ── The comparison ──────────────────────────────────────────────────────────


def shipped_rustflags(target: str, rustflags: dict[str, list[str] | None]) -> list[str] | None:
    return rustflags.get(target, [])


def setting_drift(run: dict, toolchain: str, profile: dict, rustflags: dict) -> list[str]:
    """Differences of recognised settings. The caller has checked the schema."""
    shipped_flags = shipped_rustflags(run["target"], rustflags)
    if shipped_flags is None:
        return []
    attested_flags, _problems = recognised_rustflags(run["rustflags"])
    pairs = (
        ("toolchain", run["toolchain"], toolchain),
        ("rustflags", attested_flags, shipped_flags),
        ("profile_release", run["profile_release"], profile),
    )
    return [
        f"{field}: attested {attested!r}, shipped {shipped!r}"
        for field, attested, shipped in pairs
        if attested != shipped
    ]


def closure_lines(attested: dict[str, CratePin], shipped: dict[str, CratePin]) -> list[str]:
    lines = []
    for name in sorted(set(attested) | set(shipped)):
        have = attested.get(name)
        now = shipped.get(name)
        if have != now:
            attested_text = have.text() if have else "absent"
            shipped_text = now.text() if now else "absent"
            lines.append(f"  {name}: attested {attested_text}, shipped {shipped_text}")
    return lines


def rerun_message(run: dict) -> str:
    return (
        f"  Build the harness on {run['device']} ({run['target']}) from a fresh clone of the commit\n"
        f"  that ships:\n"
        f"    cargo build --release --locked -p shekyl-rpc-channel --example rt_p4_decaps_timing\n"
        f"  Then one of:\n"
        f"  - if its decapsulation code is identical, by disassembly, to the attested run's, commit\n"
        f"    the comparison and replace this entry with a `disassembly` entry naming it;\n"
        f"  - otherwise re-run RT-P4 there ({HARNESS}) under the pass line ruled 2026-10-25\n"
        f"    (invalid-vs-invalid differing only in the decrypted message; valid-vs-invalid reported\n"
        f"    as information), record it, and replace this entry with a `timing` entry for it.\n"
        f"  Either way, the change that replaces the entry commits its evidence."
    )


def run_name(run: dict) -> str:
    return f"{run.get('device', '?')} ({run.get('target', '?')})"


def schema_problems(run: dict) -> list[str]:
    """Keys and types. Evidence files are a separate check."""
    name = run_name(run)
    basis = run.get("basis")
    fields = BASIS_FIELDS.get(basis)
    if fields is None:
        return [f"{name}: unknown basis {basis!r} (expected 'timing' or 'disassembly')"]
    problems = [f"{name}: unknown key {key}" for key in run if key not in fields]
    problems += [f"{name}: no {key}" for key in sorted(fields - set(run))]
    profile = run.get("profile_release")
    if isinstance(profile, dict):
        for key, value in profile.items():
            if key not in PROFILE_KEYS or isinstance(value, dict):
                problems.append(f"{name}: profile_release {key}")
    elif "profile_release" in fields and "profile_release" in run:
        problems.append(f"{name}: profile_release is not a table")
    flags = run.get("rustflags")
    if isinstance(flags, list):
        _kept, flag_problems = recognised_rustflags(flags)
        problems += [f"{name}: {item}" for item in flag_problems]
    elif "rustflags" in run:
        problems.append(f"{name}: rustflags is not a list")
    return problems


def evidence_problems(run: dict, present: dict[str, bytes]) -> list[str]:
    name = run_name(run)
    problems = []

    def need(field: str) -> None:
        path = run.get(field)
        if not isinstance(path, str) or not path:
            problems.append(f"{name}: no {field}")
        elif path not in present:
            problems.append(f"{name}: {field} {path!r} does not exist")

    if run["basis"] == "timing":
        need("record")
        return problems
    for field in ("record", "identical_to_record", "comparison"):
        need(field)
    comparison = run.get("comparison")
    if isinstance(comparison, str) and comparison in present:
        digest = hashlib.sha256(present[comparison]).hexdigest()
        if digest != run.get("comparison_sha256"):
            problems.append(
                f"{name}: comparison {comparison!r} has SHA-256 {digest}, "
                f"the entry says {run.get('comparison_sha256')!r}"
            )
    return problems


def parse_crates(table: dict) -> tuple[dict[str, CratePin], list[str]]:
    pins = {}
    problems = []
    for name, entry in table.items():
        if not isinstance(entry, dict):
            problems.append(f"{ATTESTATION}: crates.{name} is not a table")
            continue
        unknown = [key for key in entry if key not in CRATE_FIELDS]
        problems += [f"{ATTESTATION}: crates.{name} unknown key {key}" for key in unknown]
        missing = [key for key in CRATE_FIELDS if not isinstance(entry.get(key), str)]
        problems += [f"{ATTESTATION}: crates.{name} no {key}" for key in missing]
        if not unknown and not missing:
            pins[name] = CratePin(entry["version"], entry["checksum"])
    return pins, problems


def parse_unmeasured(rows: object) -> tuple[list[dict], list[str]]:
    if rows is None:
        return [], []
    if not isinstance(rows, list):
        return [], [f"{ATTESTATION}: unmeasured is not a list"]
    kept, problems = [], []
    for row in rows:
        if not isinstance(row, dict):
            problems.append(f"{ATTESTATION}: an unmeasured row is not a table")
            continue
        problems += [
            f"{ATTESTATION}: unmeasured unknown key {key}"
            for key in row if key not in UNMEASURED_FIELDS
        ]
        target = row.get("target")
        reason = row.get("reason")
        if not isinstance(target, str) or not target:
            problems.append(f"{ATTESTATION}: an unmeasured row has no target")
        if not isinstance(reason, str) or not reason:
            problems.append(f"{ATTESTATION}: unmeasured target {target!r} has no reason")
        if isinstance(target, str) and target and isinstance(reason, str) and reason:
            if set(row) <= UNMEASURED_FIELDS:
                kept.append(row)
    return kept, problems


def account_rustflags(rustflags: dict, runs: list[dict], unmeasured: list[dict]) -> list[str]:
    """Every target that carries rustflags is a run or an explicit allow."""
    flagged = {target for target, flags in rustflags.items() if flags}
    run_targets = {
        run.get("target") for run in runs if isinstance(run.get("target"), str)
    }
    allowed = {row["target"] for row in unmeasured}
    problems = [
        f"{CARGO_CONFIG}: [target.{target}] carries rustflags and is neither a run "
        f"nor an unmeasured target"
        for target in sorted(flagged - run_targets - allowed)
    ]
    problems += [
        f"{ATTESTATION}: unmeasured target {target} carries no rustflags"
        for target in sorted(allowed - flagged)
    ]
    problems += [
        f"{ATTESTATION}: unmeasured target {target} is already a run"
        for target in sorted(allowed & run_targets)
    ]
    return problems


def check(
    texts: dict[str, str], gitian: dict[str, str], present: dict[str, bytes]
) -> Findings:
    """Findings over the given source texts.

    `present` maps each repository path an attestation entry names to its
    bytes; a path missing from it does not exist.
    """
    unrecognised: list[str] = []
    channel, problems = read_toolchain(texts[TOOLCHAIN])
    unrecognised += problems
    shipped_crates = crate_closure(tomllib.loads(texts[LOCK]).get("package", []))
    profile, problems = read_release_profile(texts[MANIFEST])
    unrecognised += problems
    rustflags, problems = read_cargo_config(texts[CARGO_CONFIG])
    unrecognised += problems
    unrecognised += read_build_rust(texts[BUILD_RUST])
    if not gitian:
        raise Unreadable(f"no gitian descriptors match {GITIAN_GLOB}")
    differs: list[str] = []
    for name, text in sorted(gitian.items()):
        problems, drift_lines = read_gitian(name, text, channel)
        unrecognised += problems
        differs += drift_lines

    attestation = tomllib.loads(texts[ATTESTATION])
    invalid = [f"{ATTESTATION}: unknown key {key}" for key in attestation if key not in ATTESTATION_KEYS]
    runs = attestation.get("run", [])
    if not isinstance(runs, list) or not runs:
        raise Unreadable(f"{ATTESTATION} attests no run")
    raw_crates = attestation.get("crates")
    if not isinstance(raw_crates, dict) or not raw_crates:
        raise Unreadable(f"{ATTESTATION} attests no crate closure")
    attested_crates, crate_invalid = parse_crates(raw_crates)
    invalid += crate_invalid
    unmeasured, unmeasured_invalid = parse_unmeasured(attestation.get("unmeasured"))
    invalid += unmeasured_invalid
    invalid += account_rustflags(rustflags, runs, unmeasured)

    drifts: list[str] = []
    if differs:
        drifts.append(
            "SHIPPED TOOLCHAIN SPLIT: a release build installs a toolchain other than the pinned one\n"
            + "\n".join(f"  {item}" for item in differs)
            + "\n  The bump policy in rust/rust-toolchain.toml moves them together; RT-P4 then re-runs."
        )
    if not crate_invalid:
        lines = closure_lines(attested_crates, shipped_crates)
        if lines:
            reruns = "\n".join(rerun_message(run) for run in runs if run.get("device") and run.get("target"))
            drifts.append(
                "RT-P4 CRATE CLOSURE DRIFT:\n"
                + "\n".join(lines)
                + "\n  The decapsulation image those runs measured has changed.\n"
                + reruns
            )
    for run in runs:
        broken = schema_problems(run)
        if broken:
            invalid.append(
                "RT-P4 ATTESTATION ENTRY INVALID:\n" + "\n".join(f"  {item}" for item in broken)
            )
            continue
        evidence = evidence_problems(run, present)
        if evidence:
            invalid.append(
                "RT-P4 ATTESTATION ENTRY INVALID:\n" + "\n".join(f"  {item}" for item in evidence)
            )
        found = setting_drift(run, channel, profile, rustflags)
        if found:
            drifts.append(
                f"RT-P4 ATTESTATION DRIFT for {run['device']} ({run['target']}; "
                f"{run['record']} at {run['commit']}):\n"
                + "\n".join(f"  {item}" for item in found)
                + "\n" + rerun_message(run)
            )
    return Findings(tuple(sorted(set(unrecognised))), tuple(invalid), tuple(drifts))


# ── Running it ──────────────────────────────────────────────────────────────


def named_paths(run: dict) -> list[str]:
    return [
        run[field]
        for field in ("record", "identical_to_record", "comparison")
        if isinstance(run.get(field), str)
    ]


def read_tree(root: Path) -> tuple[dict[str, str], dict[str, str], dict[str, bytes]]:
    texts = {}
    for path in (ATTESTATION, TOOLCHAIN, LOCK, MANIFEST, CARGO_CONFIG, BUILD_RUST):
        file = root / path
        if not file.is_file():
            raise Unreadable(f"{path} is missing")
        texts[path] = file.read_text()
    gitian = {str(path.relative_to(root)): path.read_text() for path in sorted(root.glob(GITIAN_GLOB))}
    attestation = tomllib.loads(texts[ATTESTATION])
    present = {
        path: (root / path).read_bytes()
        for run in attestation.get("run", [])
        for path in named_paths(run)
        if (root / path).is_file()
    }
    if not (root / HARNESS).is_file():
        raise Unreadable(f"the harness {HARNESS} is missing")
    return texts, gitian, present


def report(findings: Findings) -> int:
    for item in findings.unrecognised:
        print(f"UNRECOGNISED {item}", file=sys.stderr)
    if findings.unrecognised:
        print(
            "  The standing check cannot tell whether that changes the code RT-P4 measured.\n"
            "  Teach scripts/ci/check_rt_p4_standing.py what it is in a reviewed change;\n"
            "  if it changes the generated code, RT-P4 is re-run on every attested device.",
            file=sys.stderr,
        )
    for item in findings.invalid:
        print(item, file=sys.stderr)
    for item in findings.drift:
        print(item, file=sys.stderr)
    return 1 if findings.failed() else 0


SELFTEST_TOOLCHAIN = '[toolchain]\nchannel = "1.94.0"\n'
SELFTEST_LOCK = """
[[package]]
name = "fips203"
version = "0.4.3"
checksum = "chk-fips203"
dependencies = ["sha3", "subtle", "rand_core 0.6.4", "zeroize"]

[[package]]
name = "sha3"
version = "0.10.8"
checksum = "chk-sha3"
dependencies = ["keccak", "digest"]

[[package]]
name = "digest"
version = "0.10.7"
checksum = "chk-digest"
dependencies = ["generic-array 0.14.9"]

[[package]]
name = "generic-array"
version = "0.14.9"
checksum = "chk-ga"
dependencies = ["typenum", "version_check"]

[[package]]
name = "typenum"
version = "1.20.0"
checksum = "chk-ty"

[[package]]
name = "version_check"
version = "0.9.5"
checksum = "chk-vc"

[[package]]
name = "keccak"
version = "0.1.6"
checksum = "chk-keccak"
dependencies = ["cpufeatures"]

[[package]]
name = "cpufeatures"
version = "0.2.17"
checksum = "chk-cpu"
dependencies = ["libc"]

[[package]]
name = "libc"
version = "0.2.1"
checksum = "chk-libc"

[[package]]
name = "subtle"
version = "2.6.1"
checksum = "chk-subtle"

[[package]]
name = "rand_core"
version = "0.6.4"
checksum = "chk-rand"
dependencies = ["getrandom"]

[[package]]
name = "getrandom"
version = "0.2.17"
checksum = "chk-gr"

[[package]]
name = "zeroize"
version = "1.8.2"
checksum = "chk-zero"
dependencies = ["zeroize_derive"]

[[package]]
name = "zeroize_derive"
version = "1.4.3"
checksum = "chk-derive"
dependencies = ["syn"]

[[package]]
name = "syn"
version = "2.0.117"
checksum = "chk-syn"
"""
SELFTEST_MANIFEST = '[profile.release]\npanic = "abort"\noverflow-checks = true\n'
SELFTEST_CONFIG = """
[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]

[target.aarch64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
"""
SELFTEST_BUILD = (
    'set(RUST_BUILD_FLAG "--release")\n'
    '# a comment with --anything and -C opt-level=3 is ignored\n'
    'list(APPEND _rust_env_clear "CARGO_TARGET_${_upper_triple}_LINKER=${CMAKE_C_COMPILER}")\n'
    'string(APPEND _rust_link_args " -C link-arg=${_flag}")\n'
    '${CARGO_EXECUTABLE} build --locked ${RUST_BUILD_FLAG} ${RUST_TARGET_FLAG}\n'
)
SELFTEST_GITIAN = (
    "  sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain 1.94.0\n"
    '  export PATH="$HOME/.cargo/bin:$PATH"\n'
    "  rustup target add x86_64-pc-windows-gnu\n"
    "  make ${MAKEOPTS} -C ${BASEPREFIX} HOST=x\n"
)
SELFTEST_CRATES = """
[crates.cpufeatures]
version = "0.2.17"
checksum = "chk-cpu"

[crates.digest]
version = "0.10.7"
checksum = "chk-digest"

[crates.fips203]
version = "0.4.3"
checksum = "chk-fips203"

[crates.generic-array]
version = "0.14.9"
checksum = "chk-ga"

[crates.keccak]
version = "0.1.6"
checksum = "chk-keccak"

[crates.rand_core]
version = "0.6.4"
checksum = "chk-rand"

[crates.sha3]
version = "0.10.8"
checksum = "chk-sha3"

[crates.subtle]
version = "2.6.1"
checksum = "chk-subtle"

[crates.typenum]
version = "1.20.0"
checksum = "chk-ty"

[crates.zeroize]
version = "1.8.2"
checksum = "chk-zero"

[crates.zeroize_derive]
version = "1.4.3"
checksum = "chk-derive"
"""
SELFTEST_ATTESTATION = SELFTEST_CRATES + """
[[unmeasured]]
target = "aarch64-pc-windows-msvc"
reason = "no aarch64 Windows run"

[[run]]
device = "floor"
basis = "timing"
record = "r.md"
commit = "abc"
target = "aarch64-unknown-linux-gnu"
toolchain = "1.94.0"
rustflags = []
[run.profile_release]
panic = "abort"
overflow-checks = true

[[run]]
device = "laptop"
basis = "disassembly"
record = "r2.md"
commit = "def"
identical_to_record = "r.md"
identical_to_commit = "abc"
comparison = "cmp.txt"
comparison_sha256 = "40c19a67b22b8a67dd05388dd8026ac860367d904510639672eeef85c47139ea"
target = "x86_64-pc-windows-msvc"
toolchain = "1.94.0"
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
    files = {"r.md": b"", "r2.md": b"", "cmp.txt": b"the comparison\n"}

    def run(edit_path: str | None, old: str = "", new: str = "", g=None, present=None) -> Findings:
        texts = dict(base)
        if edit_path:
            assert old in texts[edit_path], (edit_path, old)
            texts[edit_path] = texts[edit_path].replace(old, new, 1)
        return check(texts, g if g is not None else gitian, present if present is not None else files)

    # (name, edit, kind, phrase). clean: every channel empty.
    cases = [
        ("toolchain bumped", (TOOLCHAIN, '"1.94.0"', '"1.95.0"'), "drift", "toolchain: attested '1.94.0'"),
        ("toolchain gains a key", (TOOLCHAIN, "channel", "components = []\nchannel"), "unrecognised", "[toolchain] components"),
        ("crate bumped", (LOCK, '"0.4.3"', '"0.4.4"'), "drift", "fips203: attested version 0.4.3"),
        ("crate checksum", (LOCK, '"chk-fips203"', '"chk-ffff"'), "drift", "checksum chk-ffff"),
        ("sha3 bumped", (LOCK, '"0.10.8"', '"0.10.9"'), "drift", "sha3: attested version 0.10.8"),
        ("derive bumped", (LOCK, '"chk-derive"', '"chk-derive2"'), "drift", "zeroize_derive:"),
        ("closure gains a crate", (LOCK, 'dependencies = ["cpufeatures"]', 'dependencies = ["cpufeatures", "tiny"]\n\n[[package]]\nname = "tiny"\nversion = "1.0.0"\nchecksum = "chk-tiny"'), "drift", "tiny: attested absent"),
        ("syn is not the image", (LOCK, '"chk-syn"', '"chk-syn2"'), "clean", ""),
        ("getrandom is not the image", (LOCK, '"chk-gr"', '"chk-gr2"'), "clean", ""),
        ("libc is not the image", (LOCK, '"chk-libc"', '"chk-libc2"'), "clean", ""),
        ("version_check is not the image", (LOCK, '"chk-vc"', '"chk-vc2"'), "clean", ""),
        ("profile value", (MANIFEST, "overflow-checks = true", "overflow-checks = false"), "drift", "profile_release"),
        ("profile known key added", (MANIFEST, "panic", "opt-level = 2\npanic"), "drift", "profile_release"),
        ("profile unknown key", (MANIFEST, "panic", "trim-paths = true\npanic"), "unrecognised", "[profile.release] trim-paths"),
        ("profile nested table", (MANIFEST, "overflow-checks = true\n", "overflow-checks = true\n[profile.release.package.fips203]\nopt-level = 1\n"), "unrecognised", "[profile.release] package"),
        ("rustflag removed", (CARGO_CONFIG, '"-C", "target-feature=+crt-static"', ""), "drift", "rustflags: attested"),
        ("rustflag unknown added", (CARGO_CONFIG, '"-C", "target-feature=+crt-static"', '"-C", "target-feature=+crt-static", "-C", "target-cpu=native"'), "unrecognised", "rustflag -C target-cpu=native"),
        ("config unknown table", (CARGO_CONFIG, "[target.", "[build]\njobs = 1\n[target."), "unrecognised", "table [build]"),
        ("config cfg target", (CARGO_CONFIG, "[target.x86_64-pc-windows-msvc]", "[target.'cfg(windows)']\nrustflags = [\"-C\", \"target-feature=+crt-static\"]\n[target.x86_64-pc-windows-msvc]"), "unrecognised", "cfg(windows)"),
        ("crate entry loses its checksum", (ATTESTATION, 'checksum = "chk-fips203"\n', ""), "invalid", "crates.fips203 no checksum"),
        ("unknown attestation key", (ATTESTATION, "[[unmeasured]]", "note = true\n[[unmeasured]]"), "invalid", "unknown key note"),
        ("unmeasured row removed", (ATTESTATION, '[[unmeasured]]\ntarget = "aarch64-pc-windows-msvc"\nreason = "no aarch64 Windows run"\n\n', ""), "invalid", "neither a run nor an unmeasured target"),
        ("unmeasured target is stale", (ATTESTATION, '"aarch64-pc-windows-msvc"', '"riscv64-unknown-linux-gnu"'), "invalid", "carries no rustflags"),
        ("build rust codegen -C", (BUILD_RUST, "link-arg=${_flag}", "opt-level=3"), "unrecognised", "-C opt-level=3"),
        ("build rust split -C", (BUILD_RUST, "${CARGO_EXECUTABLE}", 'set(X "-C" "target-cpu=native")\n${CARGO_EXECUTABLE}'), "unrecognised", "-C target-cpu=native"),
        ("build rust env", (BUILD_RUST, "CARGO_TARGET_${_upper_triple}_LINKER", "RUSTFLAGS"), "unrecognised", "environment RUSTFLAGS"),
        ("build rust unquoted env", (BUILD_RUST, "${CARGO_EXECUTABLE}", "list(APPEND _rust_env_clear RUSTFLAGS=-g)\n${CARGO_EXECUTABLE}"), "unrecognised", "environment RUSTFLAGS"),
        ("build rust set ENV", (BUILD_RUST, "${CARGO_EXECUTABLE}", 'set(ENV{CARGO_INCREMENTAL} "0")\n${CARGO_EXECUTABLE}'), "unrecognised", "environment CARGO_INCREMENTAL"),
        ("build rust flag", (BUILD_RUST, "--locked", "--locked --config profile.release.lto=true"), "unrecognised", "flag --config"),
        ("build rust -Z", (BUILD_RUST, "--locked", "--locked -Zbuild-std"), "unrecognised", "unstable flag"),
        ("build rust toolchain selector", (BUILD_RUST, "${CARGO_EXECUTABLE} build", "${CARGO_EXECUTABLE} +1.95.0 build"), "unrecognised", "toolchain selector +1.95.0"),
        ("build rust subcommand", (BUILD_RUST, "${CARGO_EXECUTABLE} build --locked", "${CARGO_EXECUTABLE} rustc --"), "unrecognised", "not build --locked"),
        ("unknown basis", (ATTESTATION, 'basis = "timing"', 'basis = "vibes"'), "invalid", "unknown basis 'vibes'"),
        ("timing entry, no basis", (ATTESTATION, 'basis = "timing"\n', ""), "invalid", "unknown basis None"),
        ("unknown run key", (ATTESTATION, 'device = "floor"\n', 'device = "floor"\nlto = true\n'), "invalid", "unknown key lto"),
        ("missing target", (ATTESTATION, 'target = "aarch64-unknown-linux-gnu"\n', ""), "invalid", "no target"),
        ("comparison hash differs", (ATTESTATION, 'comparison_sha256 = "', 'comparison_sha256 = "0'), "invalid", "has SHA-256"),
        ("comparison not named", (ATTESTATION, 'comparison = "cmp.txt"\n', ""), "invalid", "no comparison"),
        ("no identical_to_commit", (ATTESTATION, 'identical_to_commit = "abc"\n', ""), "invalid", "no identical_to_commit"),
    ]
    failures = 0

    def expect(name: str, findings: Findings, kind: str, phrase: str) -> None:
        nonlocal failures
        channels = {
            "unrecognised": findings.unrecognised,
            "invalid": findings.invalid,
            "drift": findings.drift,
        }
        if kind == "clean":
            if findings.failed():
                print(f"selftest: '{name}' was not clean: {findings}", file=sys.stderr)
                failures += 1
            return
        bucket = channels[kind]
        others = [item for key, items in channels.items() if key != kind for item in items]
        if not any(phrase in item for item in bucket) or others:
            print(
                f"selftest: '{name}' did not fail as {kind} only, carrying {phrase!r}: "
                f"unrecognised={findings.unrecognised} invalid={findings.invalid} drift={findings.drift}",
                file=sys.stderr,
            )
            failures += 1

    try:
        clean = run(None)
    except Unreadable as error:
        print(f"selftest: the clean case raised {error}", file=sys.stderr)
        return 1
    expect("clean", clean, "clean", "")
    for name, (path, old, new), kind, phrase in cases:
        try:
            expect(name, run(path, old, new), kind, phrase)
        except Unreadable as error:
            print(f"selftest: '{name}' raised {error}", file=sys.stderr)
            failures += 1
    # The other device is still judged when one entry has no target.
    try:
        missing_target = run(ATTESTATION, 'target = "aarch64-unknown-linux-gnu"\n', "")
    except Unreadable as error:
        print(f"selftest: a missing target aborted the scan: {error}", file=sys.stderr)
        failures += 1
        missing_target = None
    if missing_target is not None and any("laptop" in item and "INVALID" in item for item in missing_target.invalid):
        print("selftest: a missing target marked the other entry invalid", file=sys.stderr)
        failures += 1
    for name, missing, phrase in [
        ("timing record missing", "r.md", "record 'r.md' does not exist"),
        ("comparison missing", "cmp.txt", "comparison 'cmp.txt' does not exist"),
    ]:
        try:
            findings = run(None, present={key: value for key, value in files.items() if key != missing})
        except Unreadable as error:
            print(f"selftest: '{name}' raised {error}", file=sys.stderr)
            failures += 1
            continue
        expect(name, findings, "invalid", phrase)
    gitian_cases = [
        ("gitian toolchain split", SELFTEST_GITIAN.replace("1.94.0", "1.95.0"), "drift", "installs 1.95.0"),
        ("gitian RUSTFLAGS", SELFTEST_GITIAN + '  export RUSTFLAGS="-C target-cpu=native"\n', "unrecognised", "RUSTFLAGS"),
        ("gitian RUSTUP_TOOLCHAIN", SELFTEST_GITIAN + "  export RUSTUP_TOOLCHAIN=1.95.0\n", "unrecognised", "RUSTUP_TOOLCHAIN"),
        ("gitian cargo command", SELFTEST_GITIAN + "  cargo build --release --config profile.release.opt-level=0\n", "unrecognised", "cargo"),
        ("gitian rustup option", SELFTEST_GITIAN.replace("--profile minimal", "--profile default"), "unrecognised", "rustup-init default"),
        ("gitian rustup command", SELFTEST_GITIAN + "  rustup default nightly\n", "unrecognised", "rustup default nightly"),
        ("gitian rustc command", SELFTEST_GITIAN + "  rustc -C opt-level=3\n", "unrecognised", "rustc"),
        ("gitian no install", "  rustup target add x86_64-pc-windows-gnu\n", "unrecognised", "0 rustup-init installs"),
    ]
    for name, text, kind, phrase in gitian_cases:
        try:
            expect(name, run(None, g={"gitian-win.yml": text}), kind, phrase)
        except Unreadable as error:
            print(f"selftest: '{name}' raised {error}", file=sys.stderr)
            failures += 1
    try:
        empty = dict(base)
        marker = "[[unmeasured]]"
        empty[ATTESTATION] = marker + SELFTEST_ATTESTATION.split(marker, 1)[1]
        check(empty, gitian, files)
        print("selftest: an empty crate closure was readable", file=sys.stderr)
        failures += 1
    except Unreadable as error:
        if "no crate closure" not in str(error):
            print(f"selftest: an empty crate closure raised {error}", file=sys.stderr)
            failures += 1
    try:
        run(BUILD_RUST, "${CARGO_EXECUTABLE}", "#[[\n${CARGO_EXECUTABLE}")
        print("selftest: a bracket comment was readable", file=sys.stderr)
        failures += 1
    except Unreadable as error:
        if "bracket comment" not in str(error):
            print(f"selftest: a bracket comment raised {error}", file=sys.stderr)
            failures += 1
    # Replacing a known flag drops it from the snapshot and adds an unknown
    # one. Those are two facts: the recognised rustflags drifted, and the
    # new flag is unrecognised. An unknown flag added beside a known one
    # stays unrecognised only; that case is in the list above.
    replaced = run(
        CARGO_CONFIG,
        '"-C", "target-feature=+crt-static"',
        '"-C", "target-cpu=native"',
    )
    if (
        replaced.invalid
        or not any("target-cpu=native" in item for item in replaced.unrecognised)
        or not any(item.startswith("RT-P4 ATTESTATION DRIFT") and "rustflags:" in item for item in replaced.drift)
    ):
        print(
            "selftest: replacing a known rustflag was not unrecognised and drift: "
            f"unrecognised={replaced.unrecognised} invalid={replaced.invalid} drift={replaced.drift}",
            file=sys.stderr,
        )
        failures += 1
    toolchain = run(TOOLCHAIN, '"1.94.0"', '"1.95.0"')
    run_drifts = [item for item in toolchain.drift if item.startswith("RT-P4 ATTESTATION DRIFT")]
    if len(run_drifts) != 2 or not all(
        "cargo build --release --locked -p shekyl-rpc-channel --example rt_p4_decaps_timing" in item
        and "disassembly" in item
        for item in run_drifts
    ):
        print("selftest: a drift message does not say what to run", file=sys.stderr)
        failures += 1
    total = (
        1  # the clean fixture
        + len(cases)
        + len(gitian_cases)
        + 1  # a missing target does not abort the other run
        + 2  # a missing evidence file
        + 1  # an empty crate closure is unreadable
        + 1  # a bracket comment is unreadable
        + 1  # replacing a known rustflag is unrecognised and drift
        + 1  # a drift says what to run
    )
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
        texts, gitian, present = read_tree(root)
        findings = check(texts, gitian, present)
    except (Unreadable, tomllib.TOMLDecodeError) as error:
        print(f"RT-P4 standing check: cannot read its subject: {error}", file=sys.stderr)
        return 2
    code = report(findings)
    attestation = tomllib.loads(texts[ATTESTATION])
    print(
        f"RT-P4 standing check: {len(attestation['run'])} attested runs, "
        f"{len(attestation['crates'])} decapsulation crates, "
        f"{len(gitian)} release descriptors; " + ("FAIL" if code else "PASS")
    )
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
