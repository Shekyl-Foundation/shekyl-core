#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Run one fuzz target for a fixed time, and judge the run (the CI lane's
# fuzz brief, Part B, ruled 2026-11-15). The nightly workflow's `fuzz` and
# `fuzz-weekly` legs call it once each.
#
#   fuzz_run.py <crate>/<target> <seconds> <corpus-dir> <stats-file>
#   fuzz_run.py --summary <stats-dir>
#   fuzz_run.py --selftest
#
# The run is `cargo +<toolchain> fuzz run <target> --target
# x86_64-unknown-linux-gnu <corpus-dir> [<seeds>] -- -max_total_time=<seconds>`
# in `rust/<crate>`. The toolchain is `FUZZ_TOOLCHAIN` (the workflow pins
# it once). `<seeds>` is the crate's committed `fuzz/seeds/<target>/` when
# there is one: libFuzzer reads it and writes nothing there, so new inputs
# land in the corpus directory alone. The triple is explicit: a cargo-fuzz
# built for musl would otherwise build the harness for musl, where the
# address sanitizer is refused.
#
# A run is green only when it proves it fuzzed. The verdict, in this order,
# so a red says what went wrong first:
#
#   1. a crash: libFuzzer wrote an input under `fuzz/artifacts/<target>/`.
#      The workflow uploads that directory; the input is the reproduction.
#   2. the run failed some other way (a build error, a sanitizer abort with
#      no input written): the exit status is not zero.
#   3. no final `Done <n> runs` line: the fuzzer never reported finishing.
#   4. fewer than FLOOR executions: a harness that ran, but too slowly to
#      have fuzzed anything (a green job with zero executions is the
#      failure this run exists to remove).
#   5. an empty corpus directory after the run.
#   6. the run rewrote the crate's committed `fuzz/Cargo.lock`: cargo-fuzz
#      takes no `--locked`, so the lockfile is compared after the run
#      instead (Part A holds it to the workspace's versions).
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
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The execution floor (ruled 2026-11-15): at least this many executions in
# the run's time, or the job is red.
FLOOR = 1000
TRIPLE = "x86_64-unknown-linux-gnu"
DONE_RE = re.compile(r"^Done (\d+) runs in (\d+) second", re.MULTILINE)


@dataclass(frozen=True)
class Outcome:
    """What a run left behind, as the verdict reads it."""

    exit_code: int
    log: str
    crash_inputs: tuple[str, ...]
    corpus_files: int
    lock_changed: bool


@dataclass(frozen=True)
class Verdict:
    green: bool
    says: str
    executions: int | None


def judge(outcome: Outcome, floor: int = FLOOR) -> Verdict:
    """The run's verdict (the header's order)."""
    done = DONE_RE.findall(outcome.log)
    executions = int(done[-1][0]) if done else None
    if outcome.crash_inputs:
        return Verdict(
            False,
            f"crash: libFuzzer wrote {', '.join(outcome.crash_inputs)} (uploaded as the run's artifact)",
            executions,
        )
    if outcome.exit_code != 0:
        return Verdict(False, f"the run failed with exit status {outcome.exit_code} and wrote no input", executions)
    if executions is None:
        return Verdict(False, "the fuzzer printed no final `Done <n> runs` line", None)
    if executions < floor:
        return Verdict(False, f"{executions} executions, under the floor of {floor}", executions)
    if outcome.corpus_files == 0:
        return Verdict(False, "the corpus directory is empty after the run", executions)
    if outcome.lock_changed:
        return Verdict(False, "the run rewrote the crate's committed fuzz/Cargo.lock", executions)
    return Verdict(True, f"{executions} executions, {outcome.corpus_files} corpus inputs", executions)


def run(name: str, seconds: int, corpus: Path, stats: Path) -> int:
    crate, _, target = name.partition("/")
    crate_dir = ROOT / "rust" / crate
    fuzz_dir = crate_dir / "fuzz"
    if not target or not (fuzz_dir / "fuzz_targets" / f"{target}.rs").is_file():
        print(f"FAIL: {name} is not a fuzz target (rust/<crate>/fuzz/fuzz_targets/<target>.rs) — missing subject (rule 47)")
        return 2
    toolchain = os.environ.get("FUZZ_TOOLCHAIN", "")
    if not toolchain:
        print("FAIL: FUZZ_TOOLCHAIN is not set: the workflow pins the fuzzing toolchain")
        return 2
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts = fuzz_dir / "artifacts" / target
    command = [
        "cargo", f"+{toolchain}", "fuzz", "run", target, "--target", TRIPLE, str(corpus),
    ]
    seeds = fuzz_dir / "seeds" / target
    if seeds.is_dir():
        command.append(str(seeds))
    command += ["--", f"-max_total_time={seconds}"]
    print("+ " + " ".join(command), flush=True)
    log_path = stats.with_suffix(".log")
    with log_path.open("w") as log:
        done = subprocess.run(command, cwd=crate_dir, stdout=log, stderr=subprocess.STDOUT, check=False)
    log_text = log_path.read_text(errors="replace")
    print(log_text, flush=True)
    lock = f"rust/{crate}/fuzz/Cargo.lock"
    diff = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", "--", lock], check=False)
    if diff.returncode not in (0, 1):
        print(f"FAIL: git diff on {lock} exited {diff.returncode}")
        return 2
    outcome = Outcome(
        exit_code=done.returncode,
        log=log_text,
        crash_inputs=tuple(sorted(str(p.relative_to(ROOT)) for p in artifacts.glob("*") if p.is_file()))
        if artifacts.is_dir()
        else (),
        corpus_files=sum(1 for p in corpus.iterdir() if p.is_file()),
        lock_changed=diff.returncode == 1,
    )
    verdict = judge(outcome)
    record = {
        "target": name,
        "seconds": seconds,
        "executions": verdict.executions,
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


NIGHTLY_SECONDS = 300
WEEKLY_SECONDS = 1800


def tabulate(records: list[dict], nightly: list[str], weekly: list[str]) -> tuple[list[str], list[str]]:
    """The summary's table rows, and its findings."""
    expected = [(name, NIGHTLY_SECONDS) for name in nightly] + [(name, WEEKLY_SECONDS) for name in weekly]
    seen = {(r.get("target"), r.get("seconds")): r for r in records}
    rows = ["| Target | Seconds | Executions | Corpus | Seeded | Verdict |", "| --- | ---: | ---: | ---: | --- | --- |"]
    findings = []
    for name, seconds in expected:
        record = seen.get((name, seconds))
        if record is None:
            rows.append(f"| {name} | {seconds} | | | | RED: no figures (the leg died before its run) |")
            findings.append(f"{name} ({seconds} s) uploaded no figures")
            continue
        executions = record.get("executions")
        mark = "green" if record.get("green") else "RED"
        rows.append(
            f"| {name} | {seconds} | {executions if executions is not None else ''} | {record.get('corpus')} "
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
    base = Outcome(exit_code=0, log=done, crash_inputs=(), corpus_files=24, lock_changed=False)
    cases = [
        ("a run that fuzzed", base, True, "52816 executions"),
        (
            "a crash, even one that came before the floor",
            Outcome(1, crashed, ("rust/a/fuzz/artifacts/t/crash-ab",), 3, False),
            False,
            "crash: libFuzzer wrote rust/a/fuzz/artifacts/t/crash-ab",
        ),
        ("a failed build", Outcome(101, "error[E0308]: mismatched types\n", (), 0, False), False, "exit status 101"),
        ("no final line", Outcome(0, "INFO: Seed: 1\n", (), 2, False), False, "no final `Done <n> runs`"),
        ("under the floor", Outcome(0, slow, (), 5, False), False, "412 executions, under the floor of 1000"),
        ("an empty corpus", Outcome(0, done, (), 0, False), False, "corpus directory is empty"),
        ("a rewritten lockfile", Outcome(0, done, (), 24, True), False, "rewrote the crate's committed"),
    ]
    failures = []
    for why, outcome, green, says in cases:
        verdict = judge(outcome)
        if verdict.green != green or says not in verdict.says:
            failures.append(f"{why}: wanted green={green} saying {says!r}, got {verdict}")
    # The run itself refuses a target that does not exist, before running
    # anything.
    with tempfile.TemporaryDirectory() as raw, redirect_stdout(io.StringIO()):
        code = run("shekyl-none/fuzz_none", 1, Path(raw) / "corpus", Path(raw) / "stats.json")
        if code != 2:
            failures.append(f"an unknown target: wanted exit 2, got {code}")
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
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"fuzz run selftest: {len(cases) + 1 + len(tables)} cases pass")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if len(args) == 2 and args[0] == "--summary":
        return summary(Path(args[1]))
    if len(args) != 4 or not args[1].isdigit():
        print(
            f"usage: {sys.argv[0]} <crate>/<target> <seconds> <corpus-dir> <stats-file> "
            "| --summary <stats-dir> | --selftest",
            file=sys.stderr,
        )
        return 2
    return run(args[0], int(args[1]), Path(args[2]), Path(args[3]))


if __name__ == "__main__":
    sys.exit(main())
