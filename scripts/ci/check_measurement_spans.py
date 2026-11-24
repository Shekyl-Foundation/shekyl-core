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
a silent Tor peer for two minutes instead of seconds. Two more crates own a
feature of the same name for the same build: `shekyl-clearnet` (the step 7
message-size tap) and `shekyl-relay` (transaction ids on the relay's debug
lines, which a shipped node's log must not carry: beside a batch's session
they name the transactions it originated and their first stem hop).
Nothing in the compiler notices if a release path turns one on; this gate
does.

# What it asserts

  1. **Subject** — each owner in `OWNERS` declares the feature and its
     named source file switches on it. `rust/xtask/matrix.toml`'s
     `[measurement] features` names every owner's feature and nothing else,
     no release `cargo_args` passes a `--features` that names one, no
     host environment carries the name (`release_matrix.py` reads both),
     and the xtask adds the table's features only under its
     `--measurement-spans` flag: the flag is parsed in `main.rs`, and
     `plan.rs` is the one source that reads `measurement.features`.
     Without this limb the others pass vacuously (rule 47).
  2. **No Cargo edge** — no dependency edge of any kind, and no feature of
     any workspace package (`default` included), enables any owner's. The
     only way in is the xtask's flag, on the command line of a measurement
     build.
  3. **No release path** — no workflow, release or packaging script passes
     the flag or names the feature: `.github/`, `contrib/`, `scripts/`
     (this gate excepted).

`--selftest` runs limbs 1 to 3 against synthetic inputs, one red case
each, so the gate shows it can fail.
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import release_matrix  # noqa: E402

FEATURE = "measurement-spans"
# Every crate that owns the feature, with the source file that switches on
# it: the Tor gap, the clearnet message-size tap, the relay's transaction
# ids on its debug lines. Each is the gate's subject (rule 47).
OWNERS = {
    "shekyl-transport-layer": "src/spans.rs",
    "shekyl-clearnet": "src/sizes.rs",
    "shekyl-relay": "src/stem_watch.rs",
}
FLAG = "--measurement-spans"
SELF = pathlib.Path(__file__).resolve()
SCANNED = [".github", "contrib", "scripts"]
XTASK = ROOT / "rust" / "xtask" / "src"


def edge_enablers(metadata):
    """Every (package, owner, how) in the workspace graph that turns an
    owner's feature on."""
    found = []
    for pkg in metadata["packages"]:
        for dep in pkg.get("dependencies", []):
            if dep["name"] in OWNERS and FEATURE in dep.get("features", []):
                found.append((pkg["name"], dep["name"], f"{dep.get('kind') or 'normal'} edge"))
        for name, enables in pkg.get("features", {}).items():
            for item in enables:
                for owner in OWNERS:
                    if item in (f"{owner}/{FEATURE}", f"{owner}?/{FEATURE}") or (
                        pkg["name"] == owner and item == FEATURE
                    ):
                        found.append((pkg["name"], owner, f"its feature `{name}`"))
    return found


def release_mentions(files):
    """(path, line number, text) for every line naming the feature or the flag."""
    hits = []
    for path, text in files:
        for n, line in enumerate(text.splitlines(), 1):
            if FEATURE in line:
                hits.append((path, n, line.strip()))
    return hits


def matrix_problems(text):
    """The matrix holds every owner's feature in [measurement] and nowhere else."""
    try:
        matrix = release_matrix.parse(text)
    except release_matrix.MatrixError as why:
        return [f"rust/xtask/matrix.toml: {why}"]
    problems = []
    wanted = sorted(f"{owner}/{FEATURE}" for owner in OWNERS)
    if sorted(matrix.measurement_features) != wanted:
        problems.append(
            f"[measurement] features are {sorted(matrix.measurement_features)}, not {wanted}"
        )
    for arg in matrix.raw["build"]["cargo_args"]:
        if isinstance(arg, str) and FEATURE in arg:
            problems.append(f"[build] cargo_args passes {arg}")
    for invocation in matrix.invocations:
        for name, value in invocation.env:
            if FEATURE in value:
                problems.append(f"host {invocation.host} ({invocation.mode}) sets {name}={value}")
    return problems


def xtask_problems(sources):
    """The flag is parsed, and only plan.rs reads the features."""
    problems = []
    code = {name: re.sub(r"(?s)#\[cfg\(test\)\].*", "", text) for name, text in sources.items()}
    if not any(f'"{FLAG}" =>' in text for text in code.values()):
        problems.append(f"rust/xtask/src parses no {FLAG}")
    readers = sorted(name for name, text in code.items() if "measurement.features" in text)
    if readers != ["plan.rs"]:
        problems.append(f"measurement.features is read in {readers or 'no file'}, not plan.rs alone")
    return problems


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
    for name, switch in OWNERS.items():
        owner = next((p for p in metadata["packages"] if p["name"] == name), None)
        if owner is None or FEATURE not in owner.get("features", {}):
            fail(f"{name} does not declare the `{FEATURE}` feature")
        source = (ROOT / "rust" / name / switch).read_text(encoding="utf-8")
        if f'feature = "{FEATURE}"' not in source:
            fail(f"{name}'s {switch} does not switch on `{FEATURE}`")
    for problem in matrix_problems(release_matrix.MATRIX.read_text(encoding="utf-8")):
        fail(problem)
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(XTASK.glob("*.rs"))}
    for problem in xtask_problems(sources):
        fail(problem)


def run(metadata, files):
    errors = []
    subject(metadata, errors.append)
    for pkg, owner, how in edge_enablers(metadata):
        errors.append(f"{pkg} enables {owner}/{FEATURE} through {how}")
    for path, n, text in release_mentions(files):
        errors.append(f"{path}:{n} names the measurement build: {text}")
    return errors


def selftest():
    for owner in OWNERS:
        meta = {
            "packages": [
                {"name": owner, "features": {FEATURE: [], "default": []}, "dependencies": []},
                {"name": "shekyld", "features": {}, "dependencies": [{"name": owner, "features": [], "kind": None}]},
            ]
        }
        assert edge_enablers(meta) == [], f"clean graph ({owner})"
        meta["packages"][1]["dependencies"][0]["features"] = [FEATURE]
        assert edge_enablers(meta), f"a normal edge enabling {owner}'s feature is red"
        meta["packages"][1]["dependencies"][0]["features"] = []
        meta["packages"][0]["features"]["default"] = [FEATURE]
        assert edge_enablers(meta), f"{owner}'s default enabling it is red"
        assert release_mentions([("x.sh", f"cargo build --features {owner}/{FEATURE}")]), f"a script naming {owner}'s is red"
    assert release_mentions([("x.yml", "cargo xtask dist --host h --measurement-spans")]), "a workflow passing the flag is red"
    committed = release_matrix.MATRIX.read_text(encoding="utf-8")
    assert matrix_problems(committed) == [], matrix_problems(committed)
    planted = committed.replace(
        'cargo_args = ["build", "--locked", "--release"]',
        'cargo_args = ["build", "--locked", "--release", "--features", "shekyl-relay/measurement-spans"]',
        1,
    )
    assert matrix_problems(planted), "a feature outside [measurement] is red"
    dropped = committed.replace('    "shekyl-relay/measurement-spans",\n', "", 1)
    assert matrix_problems(dropped), "an owner missing from [measurement] is red"
    sources = {p.name: p.read_text(encoding="utf-8") for p in sorted(XTASK.glob("*.rs"))}
    assert xtask_problems(sources) == [], xtask_problems(sources)
    leaked = dict(sources, **{"main.rs": "fn f(m: &M) { m.measurement.features.len(); }\n" + sources["main.rs"]})
    assert xtask_problems(leaked), "a second reader of the features is red"
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
    names = ", ".join(f"{owner}/{FEATURE}" for owner in OWNERS)
    print(f"ok: {names} are reachable only through cargo xtask {FLAG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
