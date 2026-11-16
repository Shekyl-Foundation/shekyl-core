#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Build a fuzz crate's targets once, run one target for a fixed time, and
# judge the run (the CI lane's fuzz brief, Part B, ruled 2026-11-15). The
# nightly workflow's `fuzz-build` legs build, one per crate, and its `fuzz`
# and `fuzz-weekly` legs run, one per target.
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
#   2. the run failed some other way (a sanitizer abort with no input
#      written): the exit status is not zero.
#   3. no final `Done <n> runs` line: the fuzzer never reported finishing.
#   4. fewer than FLOOR executions: a harness that ran, but too slowly to
#      have fuzzed anything (a green job with zero executions is the
#      failure this run exists to remove).
#   5. an empty corpus directory after the run.
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


def judge(outcome: Outcome, floor: int = FLOOR) -> Verdict:
    """The run's verdict (the header's order)."""
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
    return Verdict(True, f"{executions} executions, {outcome.corpus_files} corpus inputs", executions, cov)


def every_target() -> list[str]:
    """Every fuzz target, as `<crate>/<target>`, from the inventory."""
    import check_fuzz_inventory  # noqa: PLC0415

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
        crash_inputs=tuple(sorted(str(p.relative_to(ROOT)) for p in artifacts.glob("*") if p.is_file())),
        corpus_files=sum(1 for p in corpus.iterdir() if p.is_file()),
    )
    verdict = judge(outcome)
    record = {
        "target": name,
        "seconds": seconds,
        "executions": verdict.executions,
        "cov": verdict.cov,
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


NIGHTLY_SECONDS = 300
WEEKLY_SECONDS = 1800


def tabulate(records: list[dict], nightly: list[str], weekly: list[str]) -> tuple[list[str], list[str]]:
    """The summary's table rows, and its findings."""
    expected = [(name, NIGHTLY_SECONDS) for name in nightly] + [(name, WEEKLY_SECONDS) for name in weekly]
    seen = {(r.get("target"), r.get("seconds")): r for r in records}
    rows = [
        "| Target | Seconds | Executions | Cov | Restored | Corpus | Seeded | Verdict |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    findings = []
    for name, seconds in expected:
        record = seen.get((name, seconds))
        if record is None:
            rows.append(f"| {name} | {seconds} | | | | | | RED: no figures (the leg died before its run) |")
            findings.append(f"{name} ({seconds} s) uploaded no figures")
            continue
        mark = "green" if record.get("green") else "RED"
        shown = ["" if record.get(key) is None else str(record.get(key)) for key in ("executions", "cov", "restored")]
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
    cases = [
        ("a run that fuzzed", base, True, "52816 executions"),
        (
            "a crash, even one that came before the floor",
            Outcome(1, crashed, ("rust/a/fuzz/artifacts/t/crash-ab",), 3),
            False,
            "crash: libFuzzer wrote rust/a/fuzz/artifacts/t/crash-ab",
        ),
        ("a sanitizer abort with no input", Outcome(1, "==1==ERROR: AddressSanitizer\n", (), 0), False, "exit status 1"),
        ("no final line", Outcome(0, "INFO: Seed: 1\n", (), 2), False, "no final `Done <n> runs`"),
        ("under the floor", Outcome(0, slow, (), 5), False, "412 executions, under the floor of 1000"),
        ("an empty corpus", Outcome(0, done, (), 0), False, "corpus directory is empty"),
    ]
    failures = []
    for why, outcome, green, says in cases:
        verdict = judge(outcome)
        if verdict.green != green or says not in verdict.says:
            failures.append(f"{why}: wanted green={green} saying {says!r}, got {verdict}")
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
    if failures:
        print("SELFTEST FAIL:")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"fuzz run selftest: {len(cases) + 4 + 3 + len(tables)} cases pass")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if len(args) == 2 and args[0] == "--summary":
        return summary(Path(args[1]))
    if len(args) == 3 and args[0] == "--build":
        return build(args[1], Path(args[2]))
    if len(args) != 5 or not args[1].isdigit():
        print(
            f"usage: {sys.argv[0]} <crate>/<target> <seconds> <corpus-dir> <stats-file> <binary> "
            "| --build <crate> <bin-dir> | --summary <stats-dir> | --selftest",
            file=sys.stderr,
        )
        return 2
    return run(args[0], int(args[1]), Path(args[2]), Path(args[3]), Path(args[4]))


if __name__ == "__main__":
    sys.exit(main())
