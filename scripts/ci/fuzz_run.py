#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Build a fuzz crate's targets once, run one target for a fixed time, and
# judge the run (the CI lane's fuzz brief, Part B, ruled 2026-11-15). The
# fuzz workflow's `fuzz-build` legs build, one per crate, and its `fuzz`
# and `fuzz-weekly` legs run, one per target
# (`.github/workflows/fuzz-nightly.yml`).
#
#   fuzz_run.py --build <crate> <bin-dir>
#   fuzz_run.py <crate>/<target> <seconds> <corpus-dir> <stats-file> <binary>
#   fuzz_run.py --summary <stats-dir>
#   fuzz_run.py --selftest
#
# `--build` is `cargo +<toolchain> fuzz build --target
# x86_64-unknown-linux-gnu` in `rust/<crate>`, which builds every target of
# the crate with the address sanitizer, then copies each target's binary
# into `<bin-dir>`. The toolchain is `FUZZ_TOOLCHAIN` (the workflow pins it
# once). The triple is explicit: a cargo-fuzz built for musl would
# otherwise build the harness for musl, where the address sanitizer is
# refused. The build is red when it fails, when a target's binary is not
# where cargo-fuzz writes it (rule 47), or when it rewrote the crate's
# committed `fuzz/Cargo.lock`: cargo-fuzz takes no `--locked`, so the
# lockfile is compared after the build instead (Part A holds it to the
# workspace's versions).
#
# A run executes the built binary as `cargo fuzz run` would: with
# `ASAN_OPTIONS` carrying `detect_odr_violation=0`, and `-artifact_prefix=`
# `rust/<crate>/fuzz/artifacts/<target>/`, then `-max_total_time=<seconds>`,
# the corpus directory and `<seeds>`, the crate's committed
# `fuzz/seeds/<target>/` when there is one: libFuzzer reads it and writes
# nothing there, so new inputs land in the corpus directory alone.
#
# A run is green only when it proves it fuzzed. The verdict, in this order,
# so a red says what went wrong first:
#
#   1. a crash: libFuzzer wrote an input under `fuzz/artifacts/<target>/`.
#      The workflow uploads that directory; the input is the reproduction.
#      A `slow-unit-*` file there is not one: libFuzzer writes it for an
#      input that ran past `-report_slow_units` (10 s) and then carries on,
#      so it is a figure about speed, which rule 4 already judges.
#   2. the run failed some other way (a sanitizer abort with no input
#      written): the exit status is not zero.
#   3. no final `Done <n> runs` line: the fuzzer never reported finishing.
#   4. fewer than FLOOR executions: a harness that ran, but too slowly to
#      have fuzzed anything (a green job with zero executions is the
#      failure this run exists to remove).
#   5. an empty corpus directory after the run.
#   6. no coverage floor recorded for the target, or a final coverage that
#      misses its floor (`scripts/ci/fuzz_coverage.py`). The floor is the
#      target's row in `scripts/ci/fuzz_coverage_floors.tsv`: the final
#      `cov:` of a seeded nightly run, and the tolerance the two runs that
#      measured it give (90, or wider when they differ by more than 5
#      percent). That row records what one binary reached. Whether this
#      binary stopped reaching its own code is a second question. Under
#      the tolerance, the run is still green only when the crate's own
#      sources are unchanged since the floor's commit and coverage meets
#      the codegen allowance (the default tolerance minus one spread-limit);
#      the verdict names the fuzz-lock packages that moved. A deeper drop,
#      any drop after those sources changed, or a subject that cannot be
#      read, is red. A harness that stops at a length check runs millions
#      of inputs over a handful of edges: rules 4 and 5 pass it, and this
#      one does not, because that drop is past the allowance. A target
#      with no row is red with its coverage reported, which is how its
#      first floor is measured. The floor itself moves only in a reviewed
#      commit that names the run that measured it
#      (`check_fuzz_inventory.py --floors`).
#
# The stats line also carries the run's final coverage (the `cov:` of
# libFuzzer's `DONE` line) and how many corpus inputs the run started from
# (the restored cache: zero is a cold start).
#
# `--summary` is the `fuzz-summary` job: it reads every leg's stats line
# under `<stats-dir>` (one artifact directory per leg), writes one table to
# the run's summary, and fails when a leg the target lists named left no
# line (it died before its run: rule 47) or when any leg was red. The
# lists are `NIGHTLY` (run for 300 s) and `WEEKLY` (1800 s), as JSON, the
# outputs of the `fuzz-targets` job.
#
# The run's output is written to a log file and judged from that file, not
# through a pipe (rule 46). The stats file gets one JSON line (target,
# executions, seconds, corpus size, verdict) for the run's summary table,
# and the step summary gets the same as a line a person reads.

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_fuzz_inventory  # noqa: E402
import fuzz_coverage  # noqa: E402

from check_fuzz_inventory import NIGHTLY_SECONDS, WEEKLY_SECONDS  # noqa: E402

# The execution floor (ruled 2026-11-15): at least this many executions in
# the run's time, or the job is red.
FLOOR = 1000
TRIPLE = "x86_64-unknown-linux-gnu"
DONE_RE = re.compile(r"^Done (\d+) runs in (\d+) second", re.MULTILINE)
# libFuzzer's last status line, `#<n>\tDONE   cov: <edges> ft: ...`.
COV_RE = re.compile(r"^#\d+\s+DONE\s+cov: (\d+)", re.MULTILINE)
# What the run started from: `INFO: <n> files found in <corpus-dir>`.
FOUND_RE = re.compile(r"^INFO:\s+(\d+) files found in (.+)$", re.MULTILINE)
# What `cargo fuzz run` sets for an address-sanitized target (cargo-fuzz
# 0.13.1, `project.rs`), merged into any options already set.
ASAN_DEFAULT = "detect_odr_violation=0"


@dataclass(frozen=True)
class Outcome:
    """What a run left behind, as the verdict reads it."""

    exit_code: int
    log: str
    crash_inputs: tuple[str, ...]
    corpus_files: int


# libFuzzer's artifact prefixes for an input it stopped on: a crash, a leak,
# a per-input timeout, an out-of-memory. `slow-unit-` is the one it writes
# and runs on past.
SLOW_UNIT_PREFIX = "slow-unit-"


def failure_inputs(names: list[str]) -> tuple[str, ...]:
    """The artifact files that are a failing input: every one but a slow unit."""
    return tuple(sorted(n for n in names if not Path(n).name.startswith(SLOW_UNIT_PREFIX)))


@dataclass(frozen=True)
class Verdict:
    green: bool
    says: str
    executions: int | None
    cov: int | None


def final_cov(log: str) -> int | None:
    """The `cov:` of libFuzzer's last `DONE` line, or None."""
    found = COV_RE.findall(log)
    return int(found[-1]) if found else None


def restored(log: str, corpus: Path) -> int | None:
    """How many inputs libFuzzer found in the corpus directory at start."""
    for count, where in FOUND_RE.findall(log):
        if Path(where.strip()) == corpus:
            return int(count)
    return None


def judge(
    outcome: Outcome,
    cov_floor: tuple[int, int] | None,
    floor: int = FLOOR,
    *,
    subject: fuzz_coverage.SubjectDelta | None = None,
    commit: str | None = None,
) -> Verdict:
    """The run's verdict (the header's order). `cov_floor` is the target's
    recorded coverage floor and its tolerance (a percentage), or None when
    it has none. `subject` is the crate since `commit`; omitted, a miss
    under the tolerance has no codegen allowance."""
    done = DONE_RE.findall(outcome.log)
    executions = int(done[-1][0]) if done else None
    cov = final_cov(outcome.log)
    if outcome.crash_inputs:
        return Verdict(
            False,
            f"crash: libFuzzer wrote {', '.join(outcome.crash_inputs)} (uploaded as the run's artifact)",
            executions,
            cov,
        )
    if outcome.exit_code != 0:
        return Verdict(False, f"the run failed with exit status {outcome.exit_code} and wrote no input", executions, cov)
    if executions is None:
        return Verdict(False, "the fuzzer printed no final `Done <n> runs` line", None, cov)
    if executions < floor:
        return Verdict(False, f"{executions} executions, under the floor of {floor}", executions, cov)
    if outcome.corpus_files == 0:
        return Verdict(False, "the corpus directory is empty after the run", executions, cov)
    if cov is None:
        return Verdict(False, "libFuzzer printed no final `DONE ... cov:` line", executions, None)
    if cov_floor is None:
        return Verdict(
            False,
            f"no coverage floor recorded: this run reached cov {cov}. Record it, with this run's id and "
            "commit, in scripts/ci/fuzz_coverage_floors.tsv",
            executions,
            cov,
        )
    edges, percent = cov_floor
    decision = fuzz_coverage.decide(cov, edges, percent, subject)
    if isinstance(decision, fuzz_coverage.Held):
        return Verdict(
            True,
            f"{executions} executions, cov {cov} (floor {edges} at {percent}%), {outcome.corpus_files} corpus inputs",
            executions,
            cov,
        )
    if isinstance(decision, fuzz_coverage.CodegenDrift):
        return Verdict(
            True,
            f"{executions} executions, cov {cov} (floor {edges} at {percent}%), {outcome.corpus_files} corpus inputs: "
            + fuzz_coverage.drift_says(decision, commit),
            executions,
            cov,
        )
    return Verdict(False, fuzz_coverage.shortfall_says(decision, commit), executions, cov)


def slash_as_underscore(part: str) -> str:
    """`/` is not an artifact-name character. The reporter applies the same map."""
    return part.replace("/", "_")


def build_artifact(branch: str, crate: str) -> str:
    """The artifact of one crate's built binaries, shared by every lane."""
    return f"fuzz-bin-{slash_as_underscore(branch)}-{crate}"


def leg_names(lane: str, branch: str, target: str) -> dict[str, str]:
    """Names for one leg.

    The red-issue reporter rebuilds `crash` as
    `fuzz-crash-<lane>-<branch>-<target>`, with each `/` read as `_`.
    `cache` has no lane, so the weekly run continues the nightly corpus.
    """
    crate, _, binary = target.partition("/")
    safe_branch = slash_as_underscore(branch)
    safe_target = slash_as_underscore(target)
    stamp = f"{lane}-{safe_branch}-{safe_target}"
    return {
        "crate": crate,
        "bin": binary,
        "binaries": build_artifact(branch, crate),
        "safe": stamp,
        "cache": f"fuzz-corpus-{safe_branch}-{safe_target}",
        "crash": f"fuzz-crash-{stamp}",
        "stats": f"fuzz-stats-{stamp}",
    }


def every_target() -> list[str]:
    """Every fuzz target, as `<crate>/<target>`, from the inventory."""
    return check_fuzz_inventory.targets(ROOT)


def binaries(crate: str) -> list[str]:
    """The crate's fuzz targets, by binary name."""
    return [name.partition("/")[2] for name in every_target() if name.partition("/")[0] == crate]


def build(crate: str, out: Path) -> int:
    """`--build`: every target of the crate, built once, copied to `out`."""
    fuzz_dir = ROOT / "rust" / crate / "fuzz"
    if not (fuzz_dir / "Cargo.toml").is_file():
        print(f"FAIL: {crate} has no fuzz crate (rust/{crate}/fuzz/Cargo.toml) — missing subject (rule 47)")
        return 2
    names = binaries(crate)
    if not names:
        print(f"FAIL: the inventory lists no target of {crate} — missing subject (rule 47)")
        return 2
    toolchain = os.environ.get("FUZZ_TOOLCHAIN", "")
    if not toolchain:
        print("FAIL: FUZZ_TOOLCHAIN is not set: the workflow pins the fuzzing toolchain")
        return 2
    command = ["cargo", f"+{toolchain}", "fuzz", "build", "--target", TRIPLE]
    print("+ " + " ".join(command), flush=True)
    done = subprocess.run(command, cwd=fuzz_dir.parent, check=False)
    if done.returncode != 0:
        print(f"FAIL: {crate}: cargo fuzz build exited {done.returncode}")
        return 1
    lock = f"rust/{crate}/fuzz/Cargo.lock"
    diff = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", "--", lock], check=False)
    if diff.returncode == 1:
        print(f"FAIL: {crate}: the build rewrote the crate's committed {lock}")
        return 1
    if diff.returncode != 0:
        print(f"FAIL: git diff on {lock} exited {diff.returncode}")
        return 2
    built = fuzz_dir / "target" / TRIPLE / "release"
    out.mkdir(parents=True, exist_ok=True)
    missing = [name for name in names if not (built / name).is_file()]
    if missing:
        print(f"FAIL: {crate}: the build wrote no binary for {', '.join(missing)} under {built} (rule 47)")
        return 1
    for name in names:
        shutil.copy2(built / name, out / name)
    print(f"ok: {crate}: {len(names)} targets built: {', '.join(names)}")
    return 0


def run(name: str, seconds: int, corpus: Path, stats: Path, binary: Path) -> int:
    crate, _, target = name.partition("/")
    fuzz_dir = ROOT / "rust" / crate / "fuzz"
    if not target or not (fuzz_dir / "fuzz_targets" / f"{target}.rs").is_file():
        print(f"FAIL: {name} is not a fuzz target (rust/<crate>/fuzz/fuzz_targets/<target>.rs) — missing subject (rule 47)")
        return 2
    # The run's working directory is the crate's fuzz directory, so a
    # relative path is resolved first.
    binary = binary.resolve()
    if not binary.is_file():
        print(f"FAIL: {name}: no built binary at {binary}; its crate's fuzz-build leg says why — missing subject (rule 47)")
        return 2
    try:
        row = check_fuzz_inventory.floors(ROOT).get(name)
    except check_fuzz_inventory.GateError as exc:
        print(f"FAIL: the coverage floors cannot be read: {exc}")
        return 2
    cov_floor = (row.cov, row.tolerance) if row else None
    floor_commit = row.commit if row else None
    # An artifact download does not keep the executable bit.
    binary.chmod(binary.stat().st_mode | 0o111)
    corpus = corpus.resolve()
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts = fuzz_dir / "artifacts" / target
    artifacts.mkdir(parents=True, exist_ok=True)
    command = [str(binary), f"-artifact_prefix={artifacts}/", f"-max_total_time={seconds}", str(corpus)]
    seeds = fuzz_dir / "seeds" / target
    if seeds.is_dir():
        command.append(str(seeds))
    asan = os.environ.get("ASAN_OPTIONS", "")
    env = dict(os.environ, ASAN_OPTIONS=f"{asan}:{ASAN_DEFAULT}" if asan else ASAN_DEFAULT)
    print("+ " + " ".join(command), flush=True)
    log_path = stats.with_suffix(".log")
    with log_path.open("w") as log:
        done = subprocess.run(command, cwd=fuzz_dir, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
    log_text = log_path.read_text(errors="replace")
    print(log_text, flush=True)
    outcome = Outcome(
        exit_code=done.returncode,
        log=log_text,
        crash_inputs=failure_inputs([str(p.relative_to(ROOT)) for p in artifacts.glob("*") if p.is_file()]),
        corpus_files=sum(1 for p in corpus.iterdir() if p.is_file()),
    )
    # After the run. Only a miss under the spread line asks what the crate
    # did: a run that meets its tolerance does not need the floor commit,
    # and a shallow checkout does not fetch it. A git failure is an unknown
    # subject, which takes no codegen allowance, and it must not discard a
    # run that already fuzzed.
    reached_cov = final_cov(log_text)
    subject = None
    if (
        floor_commit
        and reached_cov is not None
        and cov_floor is not None
        and not fuzz_coverage.meets(reached_cov, cov_floor[0], cov_floor[1])
    ):
        subject = fuzz_coverage.subject_delta(ROOT, floor_commit, crate)
    verdict = judge(outcome, cov_floor, subject=subject, commit=floor_commit)
    record = {
        "target": name,
        "seconds": seconds,
        "executions": verdict.executions,
        "cov": verdict.cov,
        "floor": cov_floor[0] if cov_floor else None,
        "tolerance": cov_floor[1] if cov_floor else None,
        "restored": restored(log_text, corpus),
        "corpus": outcome.corpus_files,
        "seeded": seeds.is_dir(),
        "green": verdict.green,
        "says": verdict.says,
    }
    stats.write_text(json.dumps(record) + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            mark = "green" if verdict.green else "RED"
            out.write(f"**{name}** ({seconds} s): {mark}, {verdict.says}\n")
    print(("ok: " if verdict.green else "FAIL: ") + f"{name}: {verdict.says}")
    return 0 if verdict.green else 1


def tabulate(records: list[dict], nightly: list[str], weekly: list[str]) -> tuple[list[str], list[str]]:
    """The summary's table rows, and its findings."""
    expected = [(name, NIGHTLY_SECONDS) for name in nightly] + [(name, WEEKLY_SECONDS) for name in weekly]
    seen = {(r.get("target"), r.get("seconds")): r for r in records}
    rows = [
        "| Target | Seconds | Executions | Cov | Floor | Restored | Corpus | Seeded | Verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    findings = []
    for name, seconds in expected:
        record = seen.get((name, seconds))
        if record is None:
            rows.append(f"| {name} | {seconds} | | | | | | | RED: no figures (the leg died before its run) |")
            findings.append(f"{name} ({seconds} s) uploaded no figures")
            continue
        mark = "green" if record.get("green") else "RED"
        shown = ["" if record.get(key) is None else str(record.get(key)) for key in ("executions", "cov", "floor", "restored")]
        if record.get("floor") is not None and record.get("tolerance") is not None:
            shown[2] = f"{record['floor']} ({record['tolerance']}%)"
        rows.append(
            f"| {name} | {seconds} | {' | '.join(shown)} | {record.get('corpus')} "
            f"| {'yes' if record.get('seeded') else 'no'} | {mark}: {record.get('says')} |"
        )
        if not record.get("green"):
            findings.append(f"{name} ({seconds} s): {record.get('says')}")
    findings.extend(
        f"{name} ({seconds} s) reported, but no list named it"
        for (name, seconds) in sorted(seen, key=str)
        if (name, seconds) not in expected
    )
    return rows, findings


def summary(stats_dir: Path) -> int:
    try:
        nightly = json.loads(os.environ.get("NIGHTLY") or "[]")
        weekly = json.loads(os.environ.get("WEEKLY") or "[]")
    except json.JSONDecodeError as exc:
        print(f"FAIL: the target lists are not JSON: {exc}")
        return 2
    if not nightly and not weekly:
        print("FAIL: both target lists are empty — missing subject (rule 47)")
        return 2
    records = []
    if stats_dir.is_dir():
        for path in sorted(stats_dir.rglob("stats.json")):
            records.extend(json.loads(line) for line in path.read_text().splitlines() if line.strip())
    rows, findings = tabulate(records, nightly, weekly)
    table = "\n".join(rows) + "\n"
    print(table)
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if out:
        with open(out, "a") as handle:
            handle.write(f"### Fuzz runs: {len(nightly)} nightly, {len(weekly)} weekly\n\n{table}")
    if findings:
        print("FAIL:")
        for finding in findings:
            print("  " + finding)
        return 1
    print(f"ok: {len(nightly) + len(weekly)} legs, every one green")
    return 0


def selftest() -> int:
    done = "#52816\tDONE   cov: 1201 ft: 2583 corp: 24/88b\nDone 52816 runs in 21 second(s)\n"
    slow = "Done 412 runs in 300 second(s)\n"
    crashed = "==1234==ERROR: libFuzzer: deadly signal\nTest unit written to fuzz/artifacts/t/crash-ab\n"
    base = Outcome(exit_code=0, log=done, crash_inputs=(), corpus_files=24)
    # A harness that dies at its length check: the first nightly dispatch's
    # fuzz_read_message1, 80,666,212 executions at a flat cov 137 where the
    # seeded harness reaches 182. Planted here with a non-empty corpus, so
    # the coverage rule alone has to catch it.
    length_check = "#80666212\tDONE   cov: 137 ft: 138 corp: 1/1b\nDone 80666212 runs in 301 second(s)\n"
    at = lambda cov: f"#9000\tDONE   cov: {cov} ft: 1\nDone 9000 runs in 300 second(s)\n"  # noqa: E731
    cases = [
        ("a run that fuzzed", base, (1201, 90), True, "52816 executions, cov 1201 (floor 1201 at 90%)"),
        (
            "a crash, even one that came before the floor",
            Outcome(1, crashed, ("rust/a/fuzz/artifacts/t/crash-ab",), 3),
            (1201, 90),
            False,
            "crash: libFuzzer wrote rust/a/fuzz/artifacts/t/crash-ab",
        ),
        ("a sanitizer abort with no input", Outcome(1, "==1==ERROR: AddressSanitizer\n", (), 0), (1201, 90), False, "exit status 1"),
        ("no final line", Outcome(0, "INFO: Seed: 1\n", (), 2), (1201, 90), False, "no final `Done <n> runs`"),
        ("under the floor", Outcome(0, slow, (), 5), (1201, 90), False, "412 executions, under the floor of 1000"),
        ("an empty corpus", Outcome(0, done, (), 0), (1201, 90), False, "corpus directory is empty"),
        (
            "a harness that dies at its length check",
            Outcome(0, length_check, (), 1),
            (182, 90),
            False,
            "cov 137, under 90% of its floor of 182",
        ),
        ("exactly the tolerance", Outcome(0, at(1350), (), 9), (1500, 90), True, "cov 1350 (floor 1500 at 90%)"),
        ("one edge under the tolerance", Outcome(0, at(1349), (), 9), (1500, 90), False, "cov 1349, under 90%"),
        ("a target's own, wider tolerance", Outcome(0, at(1200), (), 9), (1500, 80), True, "cov 1200 (floor 1500 at 80%)"),
        ("one edge under a target's own", Outcome(0, at(1199), (), 9), (1500, 80), False, "cov 1199, under 80%"),
        ("a target with no floor reports its coverage", base, None, False, "no coverage floor recorded: this run reached cov 1201"),
        (
            "a Done line with no DONE status line",
            Outcome(0, "Done 52816 runs in 21 second(s)\n", (), 3),
            (1201, 90),
            False,
            "no final `DONE ... cov:` line",
        ),
    ]
    failures = []
    for why, outcome, cov_floor, green, says in cases:
        verdict = judge(outcome, cov_floor)
        if verdict.green != green or says not in verdict.says:
            failures.append(f"{why}: wanted green={green} saying {says!r}, got {verdict}")
    # The coverage decision, through the verdict a nightly log actually prints.
    # Dropping `subject` here grants no allowance, which the unknown-subject
    # case holds; granting it whenever the crate is unchanged greens the
    # length-check case.
    unchanged = fuzz_coverage.SubjectDelta(False, ("zeroize 1.8.2 -> 1.9.2",))
    changed_sources = fuzz_coverage.SubjectDelta(True, ())
    quiet_lock = fuzz_coverage.SubjectDelta(False, ())
    floor_commit = "298205388b5baf413b15e5cc056f67ef5de48ce4"
    reached = lambda cov: Outcome(0, at(cov), (), 9)  # noqa: E731
    coverage_cases = [
        (
            "an unchanged crate inside the codegen allowance",
            reached(880),
            (1000, 90),
            unchanged,
            True,
            ("codegen drift", "zeroize 1.8.2 -> 1.9.2"),
        ),
        (
            "an unchanged crate past the codegen allowance",
            reached(700),
            (1000, 90),
            unchanged,
            False,
            ("past the codegen allowance", "cov 700, under 90% of its floor of 1000"),
        ),
        (
            "sources changed, inside the codegen band",
            reached(880),
            (1000, 90),
            changed_sources,
            False,
            ("sources changed", "cov 880, under 90% of its floor of 1000"),
        ),
        (
            "a subject that was not read",
            reached(880),
            (1000, 90),
            None,
            False,
            ("not shown unchanged", "cov 880, under 90% of its floor of 1000"),
        ),
        (
            "the length-check harness, sources unchanged",
            Outcome(0, length_check, (), 1),
            (182, 90),
            unchanged,
            False,
            ("cov 137, under 90% of its floor of 182", "past the codegen allowance"),
        ),
        (
            "a wider tolerance is not widened again",
            reached(1199),
            (1500, 80),
            unchanged,
            False,
            ("cov 1199, under 80%", "past the codegen allowance"),
        ),
        (
            "an unchanged crate whose lock did not move",
            reached(880),
            (1000, 90),
            quiet_lock,
            True,
            ("codegen drift", "no fuzz-lock package version changed"),
        ),
    ]
    for why, outcome, cov_floor, subject, green, says in coverage_cases:
        verdict = judge(outcome, cov_floor, subject=subject, commit=floor_commit)
        missing = [needle for needle in says if needle not in verdict.says]
        if verdict.green != green or missing:
            failures.append(f"{why}: wanted green={green} saying {says!r}, got {verdict}")
    # A slow unit is not a failing input; every other artifact is.
    for why, names, want in [
        ("a slow unit alone", ["a/slow-unit-3f"], ()),
        ("a crash beside a slow unit", ["a/slow-unit-3f", "a/crash-ab"], ("a/crash-ab",)),
        ("a per-input timeout", ["a/timeout-9c"], ("a/timeout-9c",)),
        ("a leak and an out-of-memory", ["a/oom-1", "a/leak-2"], ("a/leak-2", "a/oom-1")),
    ]:
        if failure_inputs(names) != want:
            failures.append(f"artifacts, {why}: wanted {want}, got {failure_inputs(names)}")
    # The figures the stats line carries, read from libFuzzer's own lines.
    log = (
        "INFO:        3 files found in /t/corpus\nINFO:        1 files found in /t/seeds\n"
        "#2\tINITED cov: 133 ft: 134 corp: 1/1216b\n#9\tNEW    cov: 140 ft: 150\n"
        "#41706716\tDONE   cov: 182 ft: 302 corp: 14/15809b\nDone 41706716 runs in 301 second(s)\n"
    )
    for why, got, want in [
        ("the final coverage is the DONE line's", final_cov(log), 182),
        ("no DONE line, no coverage", final_cov("#2\tINITED cov: 133\n"), None),
        ("the restored count is the corpus directory's, not the seeds'", restored(log, Path("/t/corpus")), 3),
        ("no line for the directory, no count", restored(log, Path("/t/other")), None),
    ]:
        if got != want:
            failures.append(f"{why}: wanted {want}, got {got}")
    # The run itself refuses a target that does not exist, and a target with
    # no built binary, before running anything.
    with tempfile.TemporaryDirectory() as raw, redirect_stdout(io.StringIO()):
        code = run("shekyl-none/fuzz_none", 1, Path(raw) / "corpus", Path(raw) / "stats.json", Path(raw) / "bin")
        if code != 2:
            failures.append(f"an unknown target: wanted exit 2, got {code}")
        some = next(iter(every_target()), None)
        if some is None:
            failures.append("the inventory lists no target to plant a missing binary under")
        else:
            code = run(some, 1, Path(raw) / "corpus", Path(raw) / "stats.json", Path(raw) / "no-such-binary")
            if code != 2:
                failures.append(f"a target with no built binary: wanted exit 2, got {code}")
        code = build("shekyl-none", Path(raw) / "bin")
        if code != 2:
            failures.append(f"building a crate with no fuzz crate: wanted exit 2, got {code}")
    green = {"target": "a/x", "seconds": 300, "executions": 5000, "corpus": 3, "seeded": False, "green": True, "says": "ok"}
    weekly_green = dict(green, seconds=1800)
    red = dict(green, target="a/y", green=False, says="crash: libFuzzer wrote f")
    tables = [
        ("every leg green", [green, weekly_green], ["a/x"], ["a/x"], []),
        ("a leg with no figures", [green], ["a/x", "a/y"], [], ["a/y (300 s) uploaded no figures"]),
        ("a red leg", [green, red], ["a/x", "a/y"], [], ["a/y (300 s): crash"]),
        ("the weekly leg missing beside its nightly twin", [green], ["a/x"], ["a/x"], ["a/x (1800 s) uploaded no figures"]),
        ("a leg no list named", [green, red], ["a/x"], [], ["a/y (300 s) reported, but no list named it"]),
    ]
    for why, records, nightly, weekly, want in tables:
        _, got = tabulate(records, nightly, weekly)
        if len(got) != len(want) or any(w not in g for w, g in zip(want, got)):
            failures.append(f"summary, {why}: wanted {want}, got {got}")
    names = leg_names("fuzz", "ci/fuzz-nightly-runs", "shekyl-wire/fuzz_tx_parse")
    want_names = {
        "crate": "shekyl-wire",
        "bin": "fuzz_tx_parse",
        "binaries": "fuzz-bin-ci_fuzz-nightly-runs-shekyl-wire",
        "safe": "fuzz-ci_fuzz-nightly-runs-shekyl-wire_fuzz_tx_parse",
        "cache": "fuzz-corpus-ci_fuzz-nightly-runs-shekyl-wire_fuzz_tx_parse",
        "crash": "fuzz-crash-fuzz-ci_fuzz-nightly-runs-shekyl-wire_fuzz_tx_parse",
        "stats": "fuzz-stats-fuzz-ci_fuzz-nightly-runs-shekyl-wire_fuzz_tx_parse",
    }
    if names != want_names:
        failures.append(f"leg names: wanted {want_names}, got {names}")
    if names["binaries"] != build_artifact("ci/fuzz-nightly-runs", "shekyl-wire"):
        failures.append("the leg's binary artifact is not the build's")
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"fuzz run selftest: {len(cases) + len(coverage_cases) + 4 + 4 + 3 + len(tables) + 2} cases pass")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if len(args) == 2 and args[0] == "--summary":
        return summary(Path(args[1]))
    if len(args) == 3 and args[0] == "--build":
        return build(args[1], Path(args[2]))
    if len(args) == 4 and args[0] == "--names":
        for key, value in leg_names(args[1], args[2], args[3]).items():
            print(f"{key}={value}")
        return 0
    if len(args) == 3 and args[0] == "--build-name":
        print(build_artifact(args[1], args[2]))
        return 0
    if len(args) != 5 or not args[1].isdigit():
        print(
            f"usage: {sys.argv[0]} <crate>/<target> <seconds> <corpus-dir> <stats-file> <binary> "
            "| --build <crate> <bin-dir> | --build-name <branch> <crate> "
            "| --names <lane> <branch> <crate>/<target> | --summary <stats-dir> | --selftest",
            file=sys.stderr,
        )
        return 2
    return run(args[0], int(args[1]), Path(args[2]), Path(args[3]), Path(args[4]))


if __name__ == "__main__":
    sys.exit(main())
