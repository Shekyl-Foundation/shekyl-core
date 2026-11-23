#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The release matrix, `rust/xtask/matrix.toml`, read once for every gate.

`cargo xtask` builds the shipped binaries from that file and adds nothing of
its own: every variable and argument a release cargo build is given is a
value in it (rust/xtask/src/plan.rs substitutes the placeholders and runs
cargo). So a gate that holds what a release build is given reads it here:

- the shipped roots: every host's `binaries`;
- the features a release passes: none (`cargo_args` and the hosts name
  none; `--features` comes only from `[measurement]`, under the xtask's
  measurement flag);
- each host's invocations: the `[build]` variables, then the host's, and
  the cargo arguments.

The reading is strict: a table or key this file has no account of is an
error, as the xtask's own reading is (`matrix.rs`), so a setting cannot sit
in the file unread by either.

Usage: release_matrix.py --selftest
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "rust" / "xtask" / "matrix.toml"
XTASK_SRC = REPO / "rust" / "xtask" / "src"

TOP_KEYS = {"build", "version", "measurement", "host"}
BUILD_KEYS = {
    "toolchain_file", "cargo_args", "target_dir", "profile_dir", "env", "unset",
    "refused", "refused_values",
}
HOST_KEYS = {"name", "triple", "binaries", "macos_minimum", "macos_minimum_depends", "dist", "native"}
DIST_KEYS = {"target", "env", "binary_mode", "files"}
NATIVE_KEYS = {"target", "env"}
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
PLACEHOLDERS = {
    "prefix", "cc", "ar", "target_dir", "version_full", "release_name", "is_release",
    "macos_minimum", "macos_minimum_depends",
}


class MatrixError(ValueError):
    """The file is missing, unparseable, or holds what nothing reads."""


@dataclass(frozen=True)
class Invocation:
    """One cargo run: the host, its mode, the variables and the arguments."""

    host: str
    triple: str
    mode: str  # "dist" or "native"
    env: tuple[tuple[str, str], ...]
    args: tuple[str, ...]


@dataclass(frozen=True)
class Matrix:
    raw: dict
    invocations: tuple[Invocation, ...]
    roots: tuple[str, ...]
    measurement_features: tuple[str, ...]
    refused: tuple[str, ...]


def _keys(where: str, table: dict, allowed: set[str], required: set[str] | None = None) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise MatrixError(f"{where}: {sorted(unknown)} not a key anything reads")
    missing = (allowed if required is None else required) - set(table)
    if missing:
        raise MatrixError(f"{where}: missing {sorted(missing)}")


def _pairs(where: str, value) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list) or not all(
        isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) for x in p) for p in value
    ):
        raise MatrixError(f"{where}: not a list of [name, value] pairs")
    for _, v in value:
        for key in PLACEHOLDER.findall(v):
            if key not in PLACEHOLDERS and not key.startswith("which:"):
                raise MatrixError(f"{where}: {{{key}}} is not a placeholder the xtask fills")
    return tuple((n, v) for n, v in value)


def parse(text: str) -> Matrix:
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as why:
        raise MatrixError(f"not TOML: {why}") from None
    _keys("the file", raw, TOP_KEYS)
    build = raw["build"]
    _keys("[build]", build, BUILD_KEYS)
    base_env = _pairs("[build] env", build["env"])
    cargo_args = tuple(build["cargo_args"])
    measurement = raw["measurement"]
    _keys("[measurement]", measurement, {"features", "warning"})

    invocations = []
    roots: set[str] = set()
    for i, host in enumerate(raw["host"]):
        _keys(f"[[host]] {i}", host, HOST_KEYS, {"name", "triple", "binaries"})
        name, triple, binaries = host["name"], host["triple"], host["binaries"]
        roots.update(binaries)
        for mode, allowed in (("dist", DIST_KEYS), ("native", NATIVE_KEYS)):
            if mode not in host:
                continue
            table = host[mode]
            _keys(f"host {name}.{mode}", table, allowed)
            env = base_env + _pairs(f"host {name}.{mode} env", table["env"])
            args = ["cargo", *cargo_args]
            if table["target"]:
                args += ["--target", triple]
            for b in binaries:
                args += ["-p", b]
            invocations.append(Invocation(name, triple, mode, env, tuple(args)))
        if "dist" not in host and "native" not in host:
            raise MatrixError(f"host {name}: neither dist nor native")
    return Matrix(
        raw=raw,
        invocations=tuple(invocations),
        roots=tuple(sorted(roots)),
        measurement_features=tuple(measurement["features"]),
        refused=tuple(build["refused"]),
    )


def load(path: Path = MATRIX) -> Matrix:
    if not path.is_file():
        raise MatrixError(f"{path} is missing")
    return parse(path.read_text(encoding="utf-8"))


def selftest() -> int:
    failures = 0

    def expect(label: str, ok: bool) -> None:
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {label}")
        failures += 0 if ok else 1

    def refused(text: str) -> bool:
        try:
            parse(text)
        except MatrixError:
            return True
        return False

    text = MATRIX.read_text(encoding="utf-8")
    m = parse(text)
    expect("the committed matrix reads", bool(m.invocations))
    expect("shekyld is a root", "shekyld" in m.roots)
    expect("no release invocation names --features", all("--features" not in i.args for i in m.invocations))
    expect("an unknown key in [build] is refused", refused(text.replace("[build]\n", "[build]\nopt_level = 3\n", 1)))
    expect(
        "an unknown placeholder is refused",
        refused(text.replace('["CARGO_TARGET_DIR", "{target_dir}"]', '["CARGO_TARGET_DIR", "{home}"]', 1)),
    )
    print("selftest: " + ("passed" if failures == 0 else f"{failures} failure(s)"))
    return 1 if failures else 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        sys.exit(selftest())
    print(__doc__, file=sys.stderr)
    sys.exit(2)
