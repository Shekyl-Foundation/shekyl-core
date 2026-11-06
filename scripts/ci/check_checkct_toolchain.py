#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# A toolchain bump re-measures the constant-time harness (CA-1).
#
# The cargo-checkct verdicts in docs/formal/checkct/results/ are statements
# about one compiler: on 2026-10-24 the same crypto-bigint 0.5.5 source was
# branchless on x86_64 under one LLVM and branched under another. So the
# verdicts are only as current as the toolchain they were made for, and
# this gate makes that checkable: docs/formal/checkct/results/measured.toml
# names the shipped channel the latest measurement covers, and this script
# fails when rust/rust-toolchain.toml names a different one.
#
# The fix for a red is never to edit measured.toml alone: re-run the
# harness (docs/formal/checkct/README.md), commit the new results/<date>/
# tables, and update measured.toml in the same PR as the bump.
#
# The dynamic crate (docs/formal/checkct/dynamic/rust-toolchain.toml) pins
# the same channel, so a device row is built with what ships; it is checked
# here too. Rule 47: every file must exist and carry one channel; a missing
# subject is red, not green. `--selftest` exercises every arm.
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLCHAIN = ROOT / "rust/rust-toolchain.toml"
MEASURED = ROOT / "docs/formal/checkct/results/measured.toml"
# The dynamic (dudect-style) crate pins the shipped toolchain too, so a
# device row is for the binary the wallet ships; it must move with the bump.
DYNAMIC = ROOT / "docs/formal/checkct/dynamic/rust-toolchain.toml"

CHANNEL_RE = re.compile(r'^channel\s*=\s*"([^"]+)"\s*$', re.M)
MEASURED_RE = re.compile(r'^rust_toolchain_channel\s*=\s*"([^"]+)"\s*$', re.M)


def read_channel(path: Path, pattern: re.Pattern, what: str) -> str:
    if not path.is_file():
        raise SystemExit(f"FAIL: {what} missing: {path}")
    found = pattern.findall(path.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise SystemExit(f"FAIL: {what} must name exactly one channel, found {len(found)}: {path}")
    return found[0]


def check(toolchain: Path, measured: Path, dynamic: Path) -> str:
    shipped = read_channel(toolchain, CHANNEL_RE, "rust-toolchain.toml")
    covered = read_channel(measured, MEASURED_RE, "checkct measured.toml")
    pinned = read_channel(dynamic, CHANNEL_RE, "checkct dynamic/rust-toolchain.toml")
    if shipped != covered:
        raise SystemExit(
            f"FAIL: rust-toolchain.toml is {shipped} but the constant-time harness was last "
            f"measured for {covered}. Re-run docs/formal/checkct (README), commit the new "
            f"results/<date>/ tables, and set rust_toolchain_channel in {measured} "
            f"in the same PR."
        )
    if shipped != pinned:
        raise SystemExit(
            f"FAIL: rust-toolchain.toml is {shipped} but the dynamic harness crate pins {pinned} "
            f"({dynamic}); a device row must be built with the shipped toolchain."
        )
    return f"OK: constant-time harness measured for, and its dynamic crate pinned to, the shipped toolchain {shipped}"


def selftest() -> None:
    cases = [
        ("match", 'channel = "1.94.0"\n', 'rust_toolchain_channel = "1.94.0"\n', 'channel = "1.94.0"\n', True),
        ("bump", 'channel = "1.95.0"\n', 'rust_toolchain_channel = "1.94.0"\n', 'channel = "1.95.0"\n', False),
        ("no measured channel", 'channel = "1.94.0"\n', "measured_on = \"2026-10-24\"\n", 'channel = "1.94.0"\n', False),
        ("two channels", 'channel = "1.94.0"\nchannel = "1.95.0"\n', 'rust_toolchain_channel = "1.94.0"\n', 'channel = "1.94.0"\n', False),
        ("missing measured", 'channel = "1.94.0"\n', None, 'channel = "1.94.0"\n', False),
        ("dynamic pin drifted", 'channel = "1.94.0"\n', 'rust_toolchain_channel = "1.94.0"\n', 'channel = "1.93.0"\n', False),
        ("missing dynamic pin", 'channel = "1.94.0"\n', 'rust_toolchain_channel = "1.94.0"\n', None, False),
    ]
    for name, tc, me, dy, want_ok in cases:
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "rust-toolchain.toml"
            t.write_text(tc, encoding="utf-8")
            m = Path(d) / "measured.toml"
            if me is not None:
                m.write_text(me, encoding="utf-8")
            dyn = Path(d) / "dynamic-rust-toolchain.toml"
            if dy is not None:
                dyn.write_text(dy, encoding="utf-8")
            try:
                check(t, m, dyn)
                ok = True
            except SystemExit:
                ok = False
        if ok != want_ok:
            raise SystemExit(f"selftest FAIL: case '{name}' expected {'pass' if want_ok else 'fail'}")
    # The live files are the subject: both must parse, whatever they say.
    read_channel(TOOLCHAIN, CHANNEL_RE, "rust-toolchain.toml")
    read_channel(MEASURED, MEASURED_RE, "checkct measured.toml")
    read_channel(DYNAMIC, CHANNEL_RE, "checkct dynamic/rust-toolchain.toml")
    print(f"selftest OK: {len(cases)} cases")


def main() -> None:
    if "--selftest" in sys.argv[1:]:
        selftest()
        return
    print(check(TOOLCHAIN, MEASURED, DYNAMIC))


if __name__ == "__main__":
    main()
