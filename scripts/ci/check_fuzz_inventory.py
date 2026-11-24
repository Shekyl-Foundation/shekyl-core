#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The fuzz harness inventory, derived from the tree (the CI lane's fuzz
# brief, Part A, ruled 2026-11-12 and amended 2026-11-15).
#
# A fuzz crate is `rust/<crate>/fuzz/Cargo.toml`: its own workspace, outside
# the main one, so nothing else compiles it. This gate reads every one and
# holds:
#
#   - each `[[bin]]` names a file under `fuzz_targets/`, and each file there
#     is a `[[bin]]`;
#   - the crate's `Cargo.lock` is tracked, and every package it shares with
#     the workspace's `rust/Cargo.lock` is at a version the workspace locks:
#     a fuzzer exercises the dependency versions that ship, and `cargo audit`
#     (which reads only the workspace lockfile) sees every one of them;
#   - the compile workflow builds its matrix from this script
#     (`--matrix`), so a fuzz crate cannot exist without being compiled;
#   - every `seeds/<name>/` directory in a fuzz crate is named for one of
#     its targets (a seed directory whose target was renamed seeds
#     nothing);
#   - every target of the weekly long run (`WEEKLY`) exists, and the
#     fuzz workflow reads the run it owes from this script (`--plan`),
#     so a target cannot exist without being run;
#   - that workflow declares exactly the two crons this script plans
#     (`NIGHTLY_CRON`, `WEEKLY_CRON`). The planner is the one place a
#     cron becomes the nightly run or the weekly run.
#
# Modes:
#   (none)        the check; exit 0, 1 on a finding, 2 when the question
#                 cannot be asked (no fuzz crate found: rule 47).
#   --matrix      the crates a change reaches, as a JSON list for the
#                 workflow's matrix (below).
#   --targets nightly|weekly [<crate>/<target>]
#                 the targets the nightly fuzz job runs (every one) or the
#                 weekly long run's, as a JSON list of `<crate>/<target>`;
#                 naming one target narrows the list to it (refused, exit
#                 2, when it is not in the list).
#   --plan [nightly|weekly [<crate>/<target>]] [--emit]
#                 the run this event owes: the target lists, the crates to
#                 build, and the seconds. With no run named, `FUZZ_SCHEDULE`
#                 (a cron) wins and otherwise `FUZZ_PLAN` (a dispatch) is
#                 `nightly` or `weekly`; `FUZZ_TARGET` narrows it. `--emit`
#                 appends that plan, plus `FUZZ_BRANCH` and `FUZZ_COMMIT`,
#                 to `GITHUB_OUTPUT` for the fuzz workflow.
#   --floors      the coverage floors (`FLOORS`, below): every target has
#                 exactly one row, every row names a target, its tolerance
#                 is the one its two runs' spread gives (`tolerance`,
#                 below), and a floor or a second coverage that moved since
#                 the parent commit moved with the run that measured it.
#                 The recorded commit may be corrected on its own. The
#                 per-PR compile workflow runs it; the nightly does not, so
#                 a branch dispatch can measure a new target's first floor.
#   --regenerate  rewrite every fuzz crate's `Cargo.lock` from the
#                 workspace's: copy it in, then `cargo update --workspace
#                 --offline` re-resolves the fuzz crate's own entries only,
#                 so a package the two share keeps the workspace's version.
#   --selftest    the check on planted trees.
#
# The merge-ready label calls `on_merge`: the head merged with the newest
# base, then this check on that tree. `merge_selftest` plants the trial,
# and `merge_ready.py --selftest` runs it. This module does not import
# the label, and neither call is a mode of this script.
#
# --matrix reads `RUST_TESTS` (change_scope.py's `rust_tests`: `all`, `none`
# or the members a change reaches through the reverse closure) and the file
# `CHANGED_FILE` names (the changed paths, one per line; unset, none). A
# file, not the paths themselves in the environment: Linux refuses to start
# a program one of whose environment strings passes 128 KiB, and a release
# pull request's diff against `main` lists over 200 KiB of paths (#1474's
# fuzz scope step exited 126 before Python ran). A fuzz crate is in the matrix
# when any crate it depends on by path is in `rust_tests`, when its own
# files changed, or when the change touches what every harness builds
# against (the workspace lockfile, the toolchain pin, this script, the
# workflow).

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/fuzz-harness.yml"
# The environment variable naming the file of changed paths `--matrix` reads.
CHANGED_FILE = "CHANGED_FILE"
# The fuzz lanes. Their own workflow, so nightly.yml keeps one cron.
FUZZ_WORKFLOW = ".github/workflows/fuzz-nightly.yml"
# Twelve hours from nightly.yml's 03:00 cron, and off the hour, where
# GitHub's start delay is worst. Sunday's weekly run is after the nightly
# fuzz and before 03:00. The workflow declares these and no others.
NIGHTLY_CRON = "17 15 * * *"
WEEKLY_CRON = "17 19 * * 0"
# How long a leg of each run fuzzes. The workflow's hang bound is the
# runner's own slack around this, not a second copy of it.
NIGHTLY_SECONDS = 300
WEEKLY_SECONDS = 1800
# The weekly long run, thirty minutes each (ruled 2026-11-15): the parsers
# that take bytes from anyone before anything about the sender is known,
# and the target five minutes cannot exercise. The Noise handshake's
# reader is the responder reading an unknown initiator's first message;
# transaction and block decode are the wire parsers; KEM decapsulation
# reads a ciphertext an output carries. The Bulletproofs+ round trip
# proves and verifies once per input, a few thousand executions in five
# minutes.
WEEKLY = (
    "shekyl-crypto-pq/fuzz_kem_decapsulate",
    "shekyl-p2p-transport/fuzz_read_message1",
    "shekyl-tx-builder/fuzz_bp_plus_masks",
    "shekyl-wire/fuzz_block_parse",
    "shekyl-wire/fuzz_tx_parse",
)
WORKSPACE_LOCK = "rust/Cargo.lock"
# What `on_merge` checks out of the trial merge: this check's subjects, and
# nothing else. `merge_selftest` holds the three named files in this tuple,
# so a hand-listed path cannot drift away from what the check reads (rule 47).
MERGE_PATHS = (
    f"/{WORKSPACE_LOCK}",
    "/rust/*/fuzz/Cargo.toml",
    "/rust/*/fuzz/Cargo.lock",
    f"/{WORKFLOW}",
    f"/{FUZZ_WORKFLOW}",
)
# Each git step of the trial. The whole of it took 5.9 s on #1489 and #1497.
MERGE_STEP_SECONDS = 90
# Each target's coverage floor (ruled 2026-11-15): the final `cov:` of one
# seeded nightly run, which `fuzz_run.py` holds every later run to. The
# file's own header says how a floor is set and moved.
FLOORS = "scripts/ci/fuzz_coverage_floors.tsv"
FULL_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# The coverage tolerance (ruled 2026-11-16): a run whose final coverage is
# under this percentage of its target's floor is red. A target whose two
# floor runs differ by more than SPREAD_LIMIT percent gets its own, wider
# tolerance (`tolerance`).
DEFAULT_TOLERANCE = 90
SPREAD_LIMIT = 5
CRON_RE = re.compile(r'^\s*-\s*cron:\s*"([^"]+)"', re.MULTILINE)
# A change to any of these reaches every harness.
EVERY_HARNESS = (
    WORKSPACE_LOCK,
    "rust/rust-toolchain.toml",
    "rust/Cargo.toml",
    WORKFLOW,
    "scripts/ci/check_fuzz_inventory.py",
    "scripts/ci/test_check_fuzz_inventory.py",
)


class GateError(Exception):
    """The question could not be asked (exit 2)."""


def tracked(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=False
    )
    if out.returncode != 0:
        raise GateError(f"git ls-files failed: {out.stderr.strip()}")
    return out.stdout.splitlines()


def fuzz_crates(files: list[str]) -> list[str]:
    """`<crate>` for every tracked `rust/<crate>/fuzz/Cargo.toml`, sorted."""
    found = sorted(
        m.group(1)
        for f in files
        if (m := re.fullmatch(r"rust/([^/]+)/fuzz/Cargo\.toml", f))
    )
    if not found:
        raise GateError("no rust/<crate>/fuzz/Cargo.toml is tracked — missing subject (rule 47)")
    return found


def locked(lock_text: str) -> dict[str, set[str]]:
    """Registry and git packages of a lockfile: name -> versions. Path
    packages (no `source`) are the tree's own and are not compared."""
    data = tomllib.loads(lock_text)
    out: dict[str, set[str]] = {}
    for package in data.get("package", []):
        if "source" in package:
            out.setdefault(package["name"], set()).add(package["version"])
    return out


def path_deps(root: Path, crate: str, manifest: dict) -> set[str]:
    """The package names the fuzz crate depends on by path."""
    names: set[str] = set()
    base = root / "rust" / crate / "fuzz"
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dep in manifest.get(table, {}).values():
            if isinstance(dep, dict) and "path" in dep:
                dep_manifest = (base / dep["path"] / "Cargo.toml").resolve()
                try:
                    names.add(tomllib.loads(dep_manifest.read_text())["package"]["name"])
                except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
                    raise GateError(f"rust/{crate}/fuzz: path dependency {dep['path']}: {exc}") from exc
    return names


def targets(root: Path, files: list[str] | None = None) -> list[str]:
    """Every fuzz target, as `<crate>/<target>`, sorted."""
    files = tracked(root) if files is None else files
    out = []
    for crate in fuzz_crates(files):
        manifest = tomllib.loads((root / "rust" / crate / "fuzz" / "Cargo.toml").read_text())
        out.extend(f"{crate}/{entry.get('name')}" for entry in manifest.get("bin", []))
    return sorted(out)


def fuzz_workflow_findings(text: str) -> list[str]:
    """The fuzz workflow declares exactly the crons the planner runs, and
    reads the run from this script."""
    fails = []
    if "check_fuzz_inventory.py --plan" not in text:
        fails.append(
            f"{FUZZ_WORKFLOW} does not read its run from `check_fuzz_inventory.py --plan`, "
            "so a target can exist that it does not run"
        )
    declared = set(CRON_RE.findall(text))
    wanted = {NIGHTLY_CRON, WEEKLY_CRON}
    fails.extend(
        f"{FUZZ_WORKFLOW} declares the cron {cron!r}, which the planner does not run"
        for cron in sorted(declared - wanted)
    )
    fails.extend(
        f"{FUZZ_WORKFLOW} does not declare the cron {cron!r} the planner runs"
        for cron in sorted(wanted - declared)
    )
    return fails


def check(root: Path, weekly: tuple[str, ...] = WEEKLY) -> tuple[list[str], list[str], int]:
    """Findings, the crates, and the number of targets."""
    files = tracked(root)
    file_set = set(files)
    crates = fuzz_crates(files)
    lock_path = root / WORKSPACE_LOCK
    if not lock_path.is_file():
        raise GateError(f"{WORKSPACE_LOCK} is missing — missing subject (rule 47)")
    workspace = locked(lock_path.read_text())
    fails: list[str] = []
    n_targets = 0
    for crate in crates:
        base = f"rust/{crate}/fuzz"
        manifest = tomllib.loads((root / base / "Cargo.toml").read_text())
        bins = manifest.get("bin", [])
        named = set()
        for entry in bins:
            path = f"{base}/{entry.get('path', '')}"
            named.add(path)
            if path not in file_set:
                fails.append(f"{base}: [[bin]] {entry.get('name')!r} names {path}, which is not a tracked file")
        on_disk = {f for f in files if f.startswith(f"{base}/fuzz_targets/") and f.endswith(".rs")}
        fails.extend(
            f"{base}: {f} is a fuzz target no [[bin]] names, so nothing builds it"
            for f in sorted(on_disk - named)
        )
        if not bins:
            fails.append(f"{base}: no [[bin]] target")
        n_targets += len(bins)
        bin_names = {entry.get("name") for entry in bins}
        seed_dirs = sorted(
            {
                m.group(1)
                for f in files
                if (m := re.fullmatch(re.escape(base) + r"/seeds/([^/]+)/.+", f))
            }
        )
        fails.extend(
            f"{base}/seeds/{name}/ is named for no target of this crate, so it seeds nothing"
            for name in seed_dirs
            if name not in bin_names
        )
        lock = f"{base}/Cargo.lock"
        if lock not in file_set:
            fails.append(
                f"{base}: Cargo.lock is not tracked. `--locked` is the point: commit the "
                "lockfile `--regenerate` writes"
            )
            continue
        own = locked((root / lock).read_text())
        for name, versions in sorted(own.items()):
            if name not in workspace:
                continue
            for version in sorted(versions - workspace[name]):
                fails.append(
                    f"{lock}: {name} {version}, where {WORKSPACE_LOCK} locks "
                    f"{', '.join(sorted(workspace[name]))}. Regenerate it "
                    "(scripts/ci/check_fuzz_inventory.py --regenerate)"
                )
    every = set(targets(root, files))
    fails.extend(
        f"the weekly long run names {name}, which is not a fuzz target"
        for name in weekly
        if name not in every
    )
    fuzz_workflow = root / FUZZ_WORKFLOW
    if not fuzz_workflow.is_file():
        fails.append(f"{FUZZ_WORKFLOW} is missing: nothing runs the fuzz targets")
    else:
        fails.extend(fuzz_workflow_findings(fuzz_workflow.read_text()))
    workflow = root / WORKFLOW
    if not workflow.is_file():
        fails.append(f"{WORKFLOW} is missing: nothing compiles the fuzz crates")
    else:
        workflow_text = workflow.read_text()
        if "check_fuzz_inventory.py --matrix" not in workflow_text:
            fails.append(
                f"{WORKFLOW} does not build its matrix from `check_fuzz_inventory.py --matrix`, "
                "so a fuzz crate can exist that it does not compile"
            )
        elif f"{CHANGED_FILE}=" not in workflow_text or 'CHANGED="' in workflow_text:
            fails.append(
                f"{WORKFLOW} does not hand `--matrix` its changed paths in the file `{CHANGED_FILE}` "
                "names: paths in the environment stop the step at 128 KiB, before the script runs"
            )
        if "check_fuzz_inventory.py --floors" not in workflow_text:
            fails.append(
                f"{WORKFLOW} does not check the coverage floors (`check_fuzz_inventory.py --floors`), "
                "so a target can run with no floor, or a floor can move unmeasured"
            )
    return fails, crates, n_targets


@dataclass(frozen=True)
class Floor:
    """One row of `FLOORS`: the floor, the run and commit that measured it,
    a second run's coverage of the same target, and the tolerance the two
    give."""

    cov: int
    run: str
    commit: str
    second_cov: int
    second_run: str
    tolerance: int


def tolerance(cov: int, second_cov: int) -> int | None:
    """The percentage of the floor a run must reach, from the spread of the
    two runs that measured it: |a - b| over the larger. Up to SPREAD_LIMIT
    percent it is DEFAULT_TOLERANCE, whose margin (100 - 90 = 10 points) is
    twice that limit. Over it, the margin is twice the spread rounded up to
    a whole percent, the same ratio, so the default and a measured tolerance
    meet at the limit. None when the spread leaves no floor (a margin of
    100 points or more)."""
    larger, gap = max(cov, second_cov), abs(cov - second_cov)
    if 100 * gap <= SPREAD_LIMIT * larger:
        return DEFAULT_TOLERANCE
    spread = -(-100 * gap // larger)  # rounded up
    margin = 2 * spread
    return 100 - margin if margin < 100 else None


def parse_floors(text: str) -> tuple[dict[str, Floor], list[str]]:
    """`target -> Floor`, and what does not parse."""
    rows: dict[str, Floor] = {}
    fails: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        where = f"{FLOORS}:{number}"
        if len(fields) != 7:
            fails.append(
                f"{where}: {len(fields)} fields, not the seven "
                "`target  cov  run  commit  second_cov  second_run  tolerance`"
            )
            continue
        target, cov, run_id, commit, second_cov, second_run, given = fields
        if not cov.isdigit() or int(cov) == 0:
            fails.append(f"{where}: {target}'s floor {cov!r} is not a positive count of edges")
            continue
        if not run_id.isdigit():
            fails.append(f"{where}: {target}'s run {run_id!r} is not a workflow run id")
            continue
        if not FULL_COMMIT_RE.fullmatch(commit):
            fails.append(f"{where}: {target}'s commit {commit!r} is not a full 40-character commit id")
            continue
        if not second_cov.isdigit() or int(second_cov) == 0:
            fails.append(f"{where}: {target}'s second coverage {second_cov!r} is not a positive count of edges")
            continue
        if not second_run.isdigit() or second_run == run_id:
            fails.append(f"{where}: {target}'s second run {second_run!r} is not a second workflow run id")
            continue
        wanted = tolerance(int(cov), int(second_cov))
        if wanted is None:
            fails.append(
                f"{where}: {target}'s runs reached cov {cov} and {second_cov}, too far apart to hold a floor"
            )
            continue
        if given != str(wanted):
            fails.append(
                f"{where}: {target}'s tolerance is {given!r}, and its runs (cov {cov} and {second_cov}) "
                f"give {wanted}"
            )
            continue
        if target in rows:
            fails.append(f"{where}: {target} has a second row")
            continue
        rows[target] = Floor(int(cov), run_id, commit, int(second_cov), second_run, wanted)
    return rows, fails


def floors(root: Path) -> dict[str, Floor]:
    """The floors, or GateError when the file is missing or does not parse."""
    path = root / FLOORS
    if not path.is_file():
        raise GateError(f"{FLOORS} is missing — missing subject (rule 47)")
    rows, fails = parse_floors(path.read_text())
    if fails:
        raise GateError("; ".join(fails))
    return rows


def floor_findings(root: Path) -> list[str]:
    """`--floors`: every target has one row, and no floor moved unmeasured."""
    path = root / FLOORS
    if not path.is_file():
        raise GateError(f"{FLOORS} is missing — missing subject (rule 47)")
    rows, fails = parse_floors(path.read_text())
    every = set(targets(root))
    if not every:
        raise GateError("no fuzz target found — missing subject (rule 47)")
    fails.extend(
        f"{FLOORS}: {name} has no coverage floor. Dispatch the nightly `fuzz` job on the branch for "
        "it and record the run's `cov:` with that run's id and commit"
        for name in sorted(every - set(rows))
    )
    fails.extend(f"{FLOORS}: {name} is not a fuzz target" for name in sorted(set(rows) - every))
    parent = subprocess.run(
        ["git", "-C", str(root), "show", f"HEAD^1:{FLOORS}"], capture_output=True, text=True, check=False
    )
    if parent.returncode == 0:
        before, _ = parse_floors(parent.stdout)
        for name, row in sorted(rows.items()):
            was = before.get(name)
            if was and was.cov != row.cov and was.run == row.run:
                fails.append(
                    f"{FLOORS}: {name}'s floor moved {was.cov} -> {row.cov} with the run "
                    "unchanged: a floor moves only with the run that measured it"
                )
            if was and was.second_cov != row.second_cov and was.second_run == row.second_run:
                fails.append(
                    f"{FLOORS}: {name}'s second coverage moved {was.second_cov} -> {row.second_cov} with "
                    "its run unchanged: the tolerance moves only with the run that measured it"
                )
    else:
        print(f"note: no {FLOORS} at HEAD^1, so no floor is compared with a parent")
    return fails


def run_floors(root: Path) -> int:
    try:
        fails = floor_findings(root)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2
    if fails:
        print("FAIL: the coverage floors disagree with the tree:")
        for finding in fails:
            print("  " + finding)
        return 1
    print(f"fuzz coverage floors: one per target, {len(floors(root))} rows")
    return 0


def matrix(root: Path, rust_tests: str, changed: list[str]) -> list[str]:
    files = tracked(root)
    crates = fuzz_crates(files)
    if rust_tests == "all" or any(path in EVERY_HARNESS for path in changed):
        return crates
    reached = set(rust_tests.split()) if rust_tests != "none" else set()
    out = []
    for crate in crates:
        base = f"rust/{crate}/fuzz/"
        manifest = tomllib.loads((root / base / "Cargo.toml").read_text())
        if path_deps(root, crate, manifest) & reached or any(p.startswith(base) for p in changed):
            out.append(crate)
    return out


def regenerate(root: Path) -> int:
    for crate in fuzz_crates(tracked(root)):
        base = root / "rust" / crate / "fuzz"
        shutil.copyfile(root / WORKSPACE_LOCK, base / "Cargo.lock")
        done = subprocess.run(
            ["cargo", "update", "--workspace", "--offline"],
            cwd=base,
            capture_output=True,
            text=True,
            check=False,
        )
        if done.returncode != 0:
            print(f"{crate}: cargo update failed:\n{done.stderr}", file=sys.stderr)
            return 1
        print(f"{crate}: Cargo.lock regenerated from {WORKSPACE_LOCK}")
    return 0


def resolve_plan(schedule: str, requested: str) -> str:
    """Which run this event owes. A schedule is the run. A dispatch names one."""
    if schedule == NIGHTLY_CRON:
        return "nightly"
    if schedule == WEEKLY_CRON:
        return "weekly"
    if schedule:
        raise GateError(f"the schedule {schedule!r} is not a fuzz run")
    if requested in ("nightly", "weekly"):
        return requested
    raise GateError("a dispatch names its plan, nightly or weekly")


def build_plan(root: Path, which: str, only: str | None = None, weekly: tuple[str, ...] = WEEKLY) -> dict:
    """The lists a fuzz run owes: the targets, the crates to build, the seconds."""
    if which == "nightly":
        nightly = listed(root, "nightly", only, weekly)
        weekly_targets: list[str] = []
    elif which == "weekly":
        nightly = []
        weekly_targets = listed(root, "weekly", only, weekly)
    else:
        raise GateError(f"a fuzz plan is nightly or weekly, not {which!r}")
    crates = sorted({name.partition("/")[0] for name in (nightly or weekly_targets)})
    return {
        "nightly": nightly,
        "weekly": weekly_targets,
        "crates": crates,
        "nightly_seconds": NIGHTLY_SECONDS,
        "weekly_seconds": WEEKLY_SECONDS,
    }


def emit_plan(plan: dict, branch: str, commit: str, out: Path) -> None:
    """Append the plan the workflow's later jobs read. One line per key."""
    if not branch or not commit:
        raise GateError("a plan emit needs the branch and the commit")
    lines = {
        "nightly": json.dumps(plan["nightly"]),
        "weekly": json.dumps(plan["weekly"]),
        "crates": json.dumps(plan["crates"]),
        "nightly_seconds": str(plan["nightly_seconds"]),
        "weekly_seconds": str(plan["weekly_seconds"]),
        "commit": commit,
        "branches": json.dumps([branch]),
    }
    with out.open("a") as handle:
        for key, value in lines.items():
            handle.write(f"{key}={value}\n")


def listed(root: Path, which: str, only: str | None, weekly: tuple[str, ...] = WEEKLY) -> list[str]:
    """`--targets`: every target, or the weekly run's, narrowed to `only`."""
    every = targets(root)
    if which == "nightly":
        out = every
    elif which == "weekly":
        out = [name for name in weekly if name in every]
    else:
        raise GateError(f"--targets takes nightly or weekly, not {which!r}")
    if only is not None:
        if only not in out:
            raise GateError(f"{only} is not one of the {which} fuzz targets")
        out = [only]
    return out


def run(root: Path, weekly: tuple[str, ...] = WEEKLY) -> int:
    try:
        fails, crates, n_targets = check(root, weekly)
    except GateError as exc:
        print(f"FAIL: {exc}")
        return 2
    if fails:
        print("FAIL: the fuzz harness inventory disagrees with the tree:")
        for finding in fails:
            print("  " + finding)
        return 1
    print(
        f"fuzz inventory: {len(crates)} fuzz crates, {n_targets} targets, every [[bin]] a file "
        f"and every file a [[bin]], every lockfile at the workspace's versions, "
        f"{len(weekly)} weekly targets"
    )
    return 0


def changed_paths(path: str | None) -> list[str]:
    """The changed paths in the file `path` names, one per line; none when
    no file is named (a push or a dispatch, which compiles every harness).
    A named file that cannot be read is an error, not an empty change."""
    if not path:
        return []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"{CHANGED_FILE}={path} cannot be read: {exc}") from exc
    return [line for line in text.splitlines() if line]


def merge_reasons(returncode: int, output: str, base: str, dev: str) -> list[str]:
    """Why this check's exit refuses the label: its findings, each its own
    reason. Any exit but 0 or 1 is a check that could not run."""
    if returncode == 0:
        return []
    where = f"this head merged with `{base}` at {dev[:10]}"
    if returncode != 1:
        return [f"the fuzz inventory could not be checked on {where} (exit {returncode})"]
    findings = [line.strip() for line in output.splitlines() if line.startswith("  ")]
    return [f"the fuzz inventory fails on {where}: {finding}" for finding in findings] or [
        f"the fuzz inventory fails on {where}"
    ]


def on_merge(url: str, base: str, head: str) -> list[str]:
    """Why the label cannot stand once `head` is merged with the newest
    `base`: it does not merge, or this check fails there. Empty when both
    hold. A check that cannot run refuses, with why: a skipped gate reads
    as a passed one.

    A fresh partial clone with no file contents, a merge of trees alone, and
    a checkout of `MERGE_PATHS`. This file is copied into the trial, because
    the check reads the tree it sits in, so a pull request cannot change the
    check either."""
    script = str(Path(__file__).resolve())
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        with tempfile.TemporaryDirectory(prefix="fuzz-inventory-merge-") as held:
            tree = os.path.join(held, "tree")

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", *args],
                    cwd=tree,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=MERGE_STEP_SECONDS,
                ).stdout.strip()

            os.mkdir(tree)
            git("init", "-q")
            git("remote", "add", "origin", url)
            git("config", "extensions.partialClone", "origin")
            git("config", "remote.origin.promisor", "true")
            git("config", "remote.origin.partialclonefilter", "blob:none")
            git(
                "fetch", "-q", "--filter=blob:none", "--no-tags", "origin",
                f"+refs/heads/{base}:refs/trial/base", head,
            )
            dev = git("rev-parse", "refs/trial/base")
            merged = subprocess.run(
                ["git", "merge-tree", "--write-tree", dev, head],
                cwd=tree, env=env, capture_output=True, text=True, timeout=MERGE_STEP_SECONDS,
            )
            if merged.returncode == 1:
                return [f"this head does not merge with `{base}` at {dev[:10]}"]
            if merged.returncode != 0:
                raise subprocess.CalledProcessError(
                    merged.returncode, "git merge-tree", stderr=merged.stderr
                )
            commit = git(
                "-c", "user.name=fuzz-inventory", "-c", "user.email=fuzz-inventory@invalid",
                "commit-tree", merged.stdout.split()[0], "-p", dev, "-p", head,
                "-m", "the trial merge",
            )
            git("sparse-checkout", "set", "--no-cone", *MERGE_PATHS)
            git("checkout", "-q", "--detach", commit)
            placed = os.path.join(tree, "scripts", "ci", Path(__file__).name)
            os.makedirs(os.path.dirname(placed), exist_ok=True)
            shutil.copyfile(script, placed)
            checked = subprocess.run(
                [sys.executable, placed],
                cwd=tree, env=env, capture_output=True, text=True, timeout=MERGE_STEP_SECONDS,
            )
            return merge_reasons(checked.returncode, checked.stdout, base, dev)
    except (OSError, subprocess.SubprocessError) as error:
        said = (getattr(error, "stderr", "") or str(error)).strip().splitlines()
        detail = said[-1][:160] if said else error
        return [f"the fuzz inventory could not be checked against `{base}`: {detail}"]


# The planted trial's lock versions. The workspace and every fuzz lock that
# already exists move together; a lock left behind is the finding.
_MERGE_V1 = "1.0.0"
_MERGE_V2 = "1.0.1"
_MERGE_STALE = "9.9.9"


def _merge_lock(version: str) -> str:
    """A lockfile whose one sourced package is `serde` at `version`."""
    return (
        "version = 4\n\n[[package]]\n"
        'name = "serde"\n'
        f'version = "{version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )


def _merge_manifest(crate: str, bins: tuple[str, ...]) -> str:
    body = "".join(
        f'[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"\n\n' for name in bins
    )
    return f'[package]\nname = "{crate}-fuzz"\nversion = "0.0.0"\nedition = "2021"\n\n{body}[workspace]\n'


def _merge_workflows() -> tuple[tuple[str, str], ...]:
    """The two workflows, saying what this check requires them to say."""
    harness = (
        "jobs:\n  scope:\n    steps:\n"
        f'      - run: {CHANGED_FILE}="$changed_file" '
        "python3 scripts/ci/check_fuzz_inventory.py --matrix\n"
        "      - run: python3 scripts/ci/check_fuzz_inventory.py --floors\n"
    )
    nightly = (
        "on:\n  schedule:\n"
        f'    - cron: "{NIGHTLY_CRON}"\n'
        f'    - cron: "{WEEKLY_CRON}"\n'
        "jobs:\n  fuzz-targets:\n    steps:\n"
        "      - run: python3 scripts/ci/check_fuzz_inventory.py --plan\n"
    )
    return ((WORKFLOW, harness), (FUZZ_WORKFLOW, nightly))


def _weekly_by_crate() -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for name in WEEKLY:
        crate, target = name.split("/", 1)
        grouped.setdefault(crate, []).append(target)
    return {crate: tuple(names) for crate, names in grouped.items()}


def _crate_files(crate: str, bins: tuple[str, ...], version: str) -> list[tuple[str, str]]:
    base = f"rust/{crate}/fuzz"
    files = [
        (f"{base}/Cargo.toml", _merge_manifest(crate, bins)),
        (f"{base}/Cargo.lock", _merge_lock(version)),
    ]
    files.extend((f"{base}/fuzz_targets/{name}.rs", "fn main() {}\n") for name in bins)
    return files


def merge_selftest() -> list[str]:
    """The trial merge on throwaway repositories, in the shape of #1489 and
    #1497: a pull request adds a fuzz lockfile while `dev` moves the
    workspace lock under it, and each is green alone. The trial runs this
    script."""
    problems: list[str] = []
    for path in (WORKSPACE_LOCK, WORKFLOW, FUZZ_WORKFLOW):
        if f"/{path}" not in MERGE_PATHS:
            problems.append(f"MERGE_PATHS lacks {path}, which the inventory reads")
    with tempfile.TemporaryDirectory(prefix="fuzz-inventory-merge-selftest-") as held:
        origin = os.path.join(held, "origin")
        os.mkdir(origin)
        identity = (
            "-c", "user.name=t", "-c", "user.email=t@invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
        )

        def g(*args: str) -> str:
            return subprocess.run(
                ["git", *identity, *args], cwd=origin, check=True, capture_output=True, text=True,
            ).stdout.strip()

        def put(path: str, text: str) -> None:
            full = os.path.join(origin, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as handle:
                handle.write(text)

        def commit(*files: tuple[str, str]) -> str:
            for path, text in files:
                put(path, text)
            g("add", "-A")
            g("commit", "-q", "-m", "x")
            return g("rev-parse", "HEAD")

        g("init", "-q", "-b", "dev")
        g("config", "uploadpack.allowFilter", "true")
        g("config", "uploadpack.allowAnySHA1InWant", "true")
        root_files = [("rust/Cargo.lock", _merge_lock(_MERGE_V1)), *_merge_workflows()]
        for crate, bins in _weekly_by_crate().items():
            root_files.extend(_crate_files(crate, bins, _MERGE_V1))
        root = commit(*root_files)
        branches: dict[str, str] = {}
        planted = {
            "adds-a-lock": _crate_files("shekyl-stale", ("fuzz_stale",), _MERGE_STALE),
            "adds-it-right": _crate_files("shekyl-extra", ("fuzz_extra",), _MERGE_V2),
            "no-fuzz": [("docs.md", "text\n")],
            "conflicts": [("rust/Cargo.lock", _merge_lock("9.0.0"))],
        }
        for name, files in planted.items():
            g("checkout", "-q", "-b", name, root)
            branches[name] = commit(*files)
        g("checkout", "-q", "dev")
        moved = [("rust/Cargo.lock", _merge_lock(_MERGE_V2))]
        moved.extend(
            (f"rust/{crate}/fuzz/Cargo.lock", _merge_lock(_MERGE_V2))
            for crate in _weekly_by_crate()
        )
        commit(*moved)
        url = f"file://{origin}"
        got = on_merge(url, "dev", branches["adds-a-lock"])
        stale = f"serde {_MERGE_STALE}"
        agreed = f"locks {_MERGE_V2}"
        if len(got) != 1 or stale not in got[0] or agreed not in got[0]:
            problems.append(f"inventory on the merge, a lock the base moved under: {got}")
        got = on_merge(url, "dev", branches["conflicts"])
        if len(got) != 1 or "does not merge" not in got[0]:
            problems.append(f"inventory on the merge, a head that does not merge: {got}")
        for label, name in (
            ("a lockfile at the merged version", "adds-it-right"),
            ("no fuzz change", "no-fuzz"),
        ):
            got = on_merge(url, "dev", branches[name])
            if got:
                problems.append(f"inventory on the merge, {label}: {got}")
        for label, args in (
            ("a head the remote does not have", (url, "dev", "0" * 39 + "1")),
            ("a base the remote does not have", (url, "no-such-branch", branches["no-fuzz"])),
        ):
            got = on_merge(*args)
            if len(got) != 1 or "could not be checked" not in got[0]:
                problems.append(f"inventory on the merge, {label}: {got}")
    for label, args, want in (
        ("a clean exit", (0, "", "dev", "d" * 40), 0),
        ("two findings", (1, "FAIL: x\n  a: stale\n  b: stale\n", "dev", "d" * 40), 2),
        ("a failure with no finding named", (1, "FAIL: x\n", "dev", "d" * 40), 1),
        ("a check that could not run", (2, "FAIL: x\n", "dev", "d" * 40), 1),
    ):
        got_reasons = merge_reasons(*args)
        if len(got_reasons) != want:
            problems.append(f"merge_reasons, {label}: {got_reasons}")
    if "could not be checked" not in merge_reasons(2, "", "dev", "d" * 40)[0]:
        problems.append("merge_reasons: an exit of 2 is not named as a check that could not run")
    return problems


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        import test_check_fuzz_inventory  # noqa: PLC0415

        return test_check_fuzz_inventory.selftest()
    if args == ["--matrix"]:
        try:
            changed = changed_paths(os.environ.get(CHANGED_FILE))
            print(json.dumps(matrix(ROOT, os.environ.get("RUST_TESTS", "all"), changed)))
        except GateError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        return 0
    if args[:1] == ["--targets"] and len(args) in (2, 3):
        try:
            print(json.dumps(listed(ROOT, args[1], args[2] if len(args) == 3 else None)))
        except GateError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        return 0
    if args[:1] == ["--plan"]:
        emit = "--emit" in args[1:]
        rest = [arg for arg in args[1:] if arg != "--emit"]
        try:
            if not rest:
                which = resolve_plan(os.environ.get("FUZZ_SCHEDULE", ""), os.environ.get("FUZZ_PLAN", ""))
                only = os.environ.get("FUZZ_TARGET") or None
            elif rest[0] in ("nightly", "weekly") and len(rest) in (1, 2):
                which = rest[0]
                only = rest[1] if len(rest) == 2 else None
            else:
                raise GateError(f"--plan takes nightly or weekly, not {' '.join(rest)!r}")
            planned = build_plan(ROOT, which, only)
            if emit:
                output = os.environ.get("GITHUB_OUTPUT", "")
                if not output:
                    raise GateError("--emit needs GITHUB_OUTPUT")
                emit_plan(
                    planned,
                    os.environ.get("FUZZ_BRANCH", ""),
                    os.environ.get("FUZZ_COMMIT", ""),
                    Path(output),
                )
            else:
                print(json.dumps(planned))
        except GateError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 2
        return 0
    if args == ["--regenerate"]:
        return regenerate(ROOT)
    if args == ["--floors"]:
        return run_floors(ROOT)
    if args:
        print(
            f"usage: {sys.argv[0]} [--matrix | --targets nightly|weekly [<crate>/<target>] "
            "| --plan [nightly|weekly [<crate>/<target>]] [--emit] "
            "| --floors | --regenerate | --selftest]",
            file=sys.stderr,
        )
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
