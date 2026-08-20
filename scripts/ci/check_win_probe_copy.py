#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

"""GATE 0 for the Windows probe suite: the WP-D9 copy must not be stale.

`shekyl-engine-core` carries TLS (`ring`), so its Windows disk probe cannot be
cross-compiled from a Linux box and the probe suite holds a copy of it. A suite
that exercises a STALE copy measures nothing — the same defect class as a grep
gate that passes because its path vanished, which this repo has now hit six
times. So the copy is compared before anything runs.

Python rather than PowerShell on purpose: this is the part of the runner whose
logic is load-bearing, and it is the part that can be executed and tested on
the development box. `windows_probe.ps1` calls it rather than reimplementing
it, so there is one comparison and it is the tested one.

Runs on Linux and Windows alike. Exit 0 = in sync, 2 = drifted or unfindable.
"""

from __future__ import annotations

import io
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
REAL = REPO / "rust/shekyl-engine-core/src/engine/stake_engine/serving/disk.rs"
COPY = REPO / "rust/shekyl-win-sec/tests/probes.rs"

# The Windows arm, from its `#[cfg(windows)]` attribute to the closing brace at
# column 0.
#
# The attribute is REQUIRED in the shipping file, and that is not cosmetic:
# `disk.rs` defines `free_bytes_available` TWICE — once per platform — so a
# pattern anchored on the function name alone matches the Unix arm first and
# silently compares the wrong implementation. The first version of this gate
# did exactly that, and only the length mismatch in its own failure output
# revealed it. A gate whose selector can match the wrong subject is the same
# class of defect as a gate whose path can vanish.
_FN_WINDOWS = re.compile(
    r"#\[cfg\(windows\)\]\s*\n"
    r"fn free_bytes_available\(path: &Path\) -> std::io::Result<u64> \{"
    r".*?\n\}",
    re.S,
)

# The copy lives in a file that is `#![cfg(windows)]` wholesale, so it carries
# no per-item attribute. Matched separately rather than by making the attribute
# optional — optional would re-admit the Unix arm.
_FN_COPY = re.compile(
    r"fn free_bytes_available\(path: &std::path::Path\) -> std::io::Result<u64> \{"
    r".*?\n\}",
    re.S,
)


def extract(path: pathlib.Path, pattern: re.Pattern[str]) -> str | None:
    """The Windows implementation, normalised for comparison.

    Normalisation covers exactly three differences that are licensed:
      * the `#[cfg(windows)]` attribute (the copy's whole file is cfg'd),
      * the `std::path::` qualifier (import scope differs),
      * all whitespace (formatting is not the subject; the CALL is).

    Anything else — a changed out-param, a different function, a dropped
    error branch — survives normalisation and fails the gate, which is the
    point.
    """
    if not path.is_file():
        return None
    text = io.open(path, encoding="utf-8").read()
    m = pattern.search(text)
    if not m:
        return None
    body = m.group(0)
    body = body.replace("#[cfg(windows)]", "")
    body = body.replace("std::path::Path", "Path")
    return re.sub(r"\s+", "", body)


def main() -> int:
    real = extract(REAL, _FN_WINDOWS)
    copy = extract(COPY, _FN_COPY)

    if real is None:
        print(f"GATE 0 FAIL: no `free_bytes_available` found in {REAL.relative_to(REPO)}")
        print("  Either WP-D9 moved or the gate's anchor is wrong. Both need a human.")
        return 2
    if copy is None:
        print(f"GATE 0 FAIL: no `free_bytes_available` found in {COPY.relative_to(REPO)}")
        print("  P-8 has nothing to test, so a green suite would be misleading.")
        return 2

    if real != copy:
        print("GATE 0 FAIL: the probe copy has DIVERGED from shekyl-engine-core.")
        print(f"  ships:  {REAL.relative_to(REPO)}")
        print(f"  probes: {COPY.relative_to(REPO)}")
        print("  P-8 would be testing code that no longer ships. Re-sync the copy.")
        print(f"  (normalised lengths: {len(real)} vs {len(copy)})")
        return 2

    print("GATE 0 OK: the WP-D9 probe copy is identical to what ships.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
