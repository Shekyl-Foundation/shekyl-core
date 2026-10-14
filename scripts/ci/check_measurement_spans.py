#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""Assert that the measurement spans never reach a release build.

# Why this gate exists

Rick's ruling of 2026-10-14: the cold-first-contact measurement needs the
Tor dial and gap deadlines lifted to 120 s, so the distribution is read
uncensored by the deadlines it is meant to derive. That is a compile-time
feature on `shekyl-transport-layer` (`measurement-spans`), built only for
the measurement binary, never a runtime option. A node built with it keeps
a silent Tor peer for two minutes instead of seconds. Nothing in the
compiler notices if a release path turns it on; this gate does.

# What it asserts

  1. **Subject** — the feature exists in `shekyl-transport-layer`'s feature
     map, `spans.rs` switches on it, and `cmake/BuildRust.cmake` declares
     the `SHEKYL_MEASUREMENT_SPANS` option default `OFF` and passes the
     feature only under it. Without this the other limbs pass vacuously
     (rule 47).
  2. **No Cargo edge** — no dependency edge of any kind, and no feature of
     any workspace package (`default` included), enables it. The only way
     in is the CMake option, on the command line of a measurement build.
  3. **No release path** — no workflow, release or packaging script turns
     the option on or names the feature: `.github/`, `contrib/`,
     `scripts/` (this gate excepted), `Makefile`, `CMakeLists.txt`,
     `cmake/` outside the one guarded line.

`--selftest` runs limbs 2 and 3 against synthetic inputs, one red case
each, so the gate shows it can fail.
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
OWNER = "shekyl-transport-layer"
FEATURE = "measurement-spans"
OPTION = "SHEKYL_MEASUREMENT_SPANS"
SELF = pathlib.Path(__file__).resolve()
SCANNED = [".github", "contrib", "scripts", "Makefile", "CMakeLists.txt", "cmake"]


def edge_enablers(metadata):
    """Every (package, how) in the workspace graph that turns the feature on."""
    found = []
    for pkg in metadata["packages"]:
        for dep in pkg.get("dependencies", []):
            if dep["name"] == OWNER and FEATURE in dep.get("features", []):
                found.append((pkg["name"], f"{dep.get('kind') or 'normal'} edge"))
        for name, enables in pkg.get("features", {}).items():
            for item in enables:
                if item in (f"{OWNER}/{FEATURE}", f"{OWNER}?/{FEATURE}") or (
                    pkg["name"] == OWNER and item == FEATURE
                ):
                    found.append((pkg["name"], f"its feature `{name}`"))
    return found


def release_mentions(files):
    """(path, line number, text) for every mention outside the guarded line."""
    hits = []
    for path, text in files:
        for n, line in enumerate(text.splitlines(), 1):
            if FEATURE in line or re.search(rf"-D\s*{OPTION}\s*=\s*(ON|1|TRUE|YES)", line, re.I):
                if path.endswith("BuildRust.cmake") and guarded(line):
                    continue
                if path.endswith("BuildRust.cmake") and line.lstrip().startswith("#"):
                    continue
                hits.append((path, n, line.strip()))
    return hits


def guarded(line):
    return f"--features {OWNER}/{FEATURE}" in line and "set(" in line


def scanned_files():
    out = []
    for entry in SCANNED:
        base = ROOT / entry
        paths = [base] if base.is_file() else sorted(p for p in base.rglob("*") if p.is_file())
        for p in paths:
            if p.resolve() == SELF:
                continue
            try:
                out.append((str(p.relative_to(ROOT)), p.read_text(encoding="utf-8")))
            except (UnicodeDecodeError, OSError):
                continue
    return out


def subject(metadata, fail):
    owner = next((p for p in metadata["packages"] if p["name"] == OWNER), None)
    if owner is None or FEATURE not in owner.get("features", {}):
        fail(f"{OWNER} does not declare the `{FEATURE}` feature")
    spans = (ROOT / "rust" / OWNER / "src" / "spans.rs").read_text(encoding="utf-8")
    if f'feature = "{FEATURE}"' not in spans:
        fail(f"spans.rs does not switch on `{FEATURE}`")
    cmake = (ROOT / "cmake" / "BuildRust.cmake").read_text(encoding="utf-8")
    if not re.search(rf'option\(\s*{OPTION}\s+"[^"]*"\s+OFF\s*\)', cmake):
        fail(f"cmake/BuildRust.cmake does not declare option {OPTION} default OFF")
    if not any(guarded(line) for line in cmake.splitlines()):
        fail(f"cmake/BuildRust.cmake does not pass the feature under {OPTION}")
    if not re.search(rf"if\(\s*{OPTION}\s*\)", cmake):
        fail(f"cmake/BuildRust.cmake does not guard the feature with if({OPTION})")


def run(metadata, files):
    errors = []
    subject(metadata, errors.append)
    for pkg, how in edge_enablers(metadata):
        errors.append(f"{pkg} enables {OWNER}/{FEATURE} through {how}")
    for path, n, text in release_mentions(files):
        errors.append(f"{path}:{n} names the measurement build: {text}")
    return errors


def selftest():
    meta = {
        "packages": [
            {"name": OWNER, "features": {FEATURE: [], "default": []}, "dependencies": []},
            {"name": "shekyl-ffi", "features": {}, "dependencies": [{"name": OWNER, "features": [], "kind": None}]},
        ]
    }
    assert edge_enablers(meta) == [], "clean graph"
    meta["packages"][1]["dependencies"][0]["features"] = [FEATURE]
    assert edge_enablers(meta), "a normal edge enabling the feature is red"
    meta["packages"][1]["dependencies"][0]["features"] = []
    meta["packages"][0]["features"]["default"] = [FEATURE]
    assert edge_enablers(meta), "the owner's default enabling it is red"
    assert release_mentions([("x.yml", "cmake -B b -DSHEKYL_MEASUREMENT_SPANS=ON")]), "a workflow turning it on is red"
    assert release_mentions([("x.sh", f"cargo build --features {OWNER}/{FEATURE}")]), "a script naming it is red"
    assert not release_mentions(
        [("cmake/BuildRust.cmake", f"    set(_measurement --features {OWNER}/{FEATURE})")]
    ), "the guarded line is allowed"
    print("check_measurement_spans selftest: ok")


def main():
    if "--selftest" in sys.argv:
        selftest()
        return 0
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=ROOT / "rust",
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    errors = run(json.loads(out), scanned_files())
    if errors:
        print("FAIL: the measurement spans can reach a release build:")
        for e in errors:
            print(f"  {e}")
        return 1
    print(f"ok: {OWNER}/{FEATURE} is reachable only through {OPTION} (default OFF)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
