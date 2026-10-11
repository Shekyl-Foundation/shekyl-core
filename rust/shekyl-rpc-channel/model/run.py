#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Execute the hybridXK model (model.py) and fail if a pinned verdict moves.
# One query is one ProVerif process, each under its own time and memory cap.
#
# Run:  python3 run.py              # every row; exit 1 on any unexpected verdict
#       python3 run.py --list       # the table, without running
#       python3 run.py --keep DIR   # also leave the generated .pv files in DIR
#       python3 run.py --jobs N     # rows in parallel (default: up to 4)
#       python3 run.py --only NAME  # one variant's rows, for working on the model
#
# ONE ProVerif version, here and in CI. The verdicts are pinned to it; this
# script reads the version of the proverif it finds and refuses any other.
# Install that version with docs/formal/proverif/install_proverif.sh.

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

from model import BROKEN, LIB, VARIANTS, Expectation, Query, Variant, source

PROVERIF_VERSION = "2.05"

# One row (a variant and one query) is one ProVerif process. A row that
# outlives this is reported as a failure, never skipped: a property nobody
# waited for is not a property that holds.
VARIANT_TIMEOUT_SECONDS = 60 * 60

# ...and one that outgrows this is stopped by the operating system, which
# ProVerif reports as a failure. Without a cap a runaway search takes the
# machine with it; the first version of this model reached 17 GiB in one
# process before it was stopped by hand.
_KIBIBYTE = 1024
_MEBIBYTE = _KIBIBYTE * _KIBIBYTE
_GIBIBYTE = _MEBIBYTE * _KIBIBYTE
VARIANT_MEMORY_BYTES = 6 * _GIBIBYTE

# A row whose peak comes within this fraction of the cap still passes, and is
# called out: it is the row the next change to the model will push over. The
# peak is resident memory and the cap is on address space, which is a little
# larger, so the warning errs early.
MEMORY_WARN_FRACTION = 0.90

# How often a worker reaps its child. A timeout is noticed at most this late.
REAP_POLL_SECONDS = 0.2

# The most rows this runner starts at once when the caller does not say.
# Each row may hold the address-space cap, so the ceiling is a memory
# budget, not a guess at how many cores help. CI passes `--jobs 2`: two
# caps fit a hosted runner, and four would not.
DEFAULT_PARALLEL_ROWS = 4

_INSTALL = "docs/formal/proverif/install_proverif.sh"


@dataclasses.dataclass(frozen=True)
class RowOutcome:
    """What one ProVerif process did: the pinned verdict, and what came back.

    `returncode` is None when the row was killed for outliving
    `VARIANT_TIMEOUT_SECONDS`. `peak_mib` is 0 in that case: the child was
    killed before its usage was read.
    """

    name: str
    query: str
    want: Expectation
    returncode: int | None
    output: str
    seconds: float
    peak_mib: int


def proverif_version(binary: str) -> str | None:
    """The version token from `proverif -help`, captured whole before it is matched."""
    out = subprocess.run([binary, "-help"], capture_output=True, text=True)
    match = re.search(r"Proverif (\d+\.\d+[\w.]*)", out.stdout + out.stderr)
    return match.group(1).rstrip(".") if match else None


def verdicts(output: str) -> list[str]:
    """ProVerif's RESULT lines, in order, as holds / attack / replay-only / unknown.

    When an injective query fails, ProVerif adds a second, parenthesised line
    for the same query saying whether the non-injective form fails too
    ("even ...") or holds ("but ..."). It is not another query. "but" means
    the only attack is a replay, which no expectation here accepts: an
    expected attack is one on the correspondence itself.
    """
    found: list[str] = []
    for line in output.splitlines():
        if not line.startswith("RESULT"):
            continue
        if line.startswith("RESULT ("):
            if found and not line.startswith("RESULT (even "):
                found[-1] = "replay-only"
            continue
        if "cannot be proved" in line:
            found.append("unknown")
        elif line.rstrip().endswith("is true."):
            found.append("holds")
        elif line.rstrip().endswith("is false."):
            found.append("attack")
        else:
            found.append("unknown")
    return found


# The cap is applied by a shell that sets its own limit and then becomes
# ProVerif. Rows are launched from worker threads, and a `preexec_fn` runs
# Python between fork and exec, where a lock another thread held at the fork
# is held for ever: the child can hang before ProVerif starts, and before the
# deadline loop is watching it.

# Primitives, then the break constants. The same order NNhfs uses for these
# two files, and the order the forward-secrecy query was re-proved against.
_LIBRARIES = (LIB, BROKEN)

_CAPPED = 'ulimit -v "$1" && exec "$2" -lib "$3" -lib "$4" "$5"'


def _capped_command(binary: str, path: pathlib.Path) -> list[str]:
    noise, broken = _LIBRARIES
    return [
        "/bin/sh",
        "-c",
        _CAPPED,
        "sh",
        str(VARIANT_MEMORY_BYTES // _KIBIBYTE),
        binary,
        str(noise),
        str(broken),
        str(path),
    ]


def _report_as_done(results):
    for result in results:
        state = "timed out" if result.returncode is None else f"exit {result.returncode}"
        print(
            f"..   {result.name}: {result.query}: finished, {state}, "
            f"{result.seconds:.0f} s, peak {result.peak_mib} MiB",
            flush=True,
        )
        yield result


def _print_list(variants: tuple[Variant, ...]) -> None:
    for variant in variants:
        breaks = ", ".join(sorted(item.value for item in variant.breaks)) or "none"
        edits = ", ".join(sorted(item.value for item in variant.edits)) or "none"
        print(
            f"{variant.name} breaks={breaks} edits={edits} "
            f"publish_client={variant.publish_client} "
            f"leak_daemon_later={variant.leak_daemon_later} "
            f"replicate={variant.replicate} hint={variant.hint}"
        )
        for query, want in variant.expect:
            print(f"    {query.value}: {want.value}")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the hybridXK ProVerif model.")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--keep", type=pathlib.Path)
    parser.add_argument(
        "--jobs", type=int, default=min(os.cpu_count() or 1, DEFAULT_PARALLEL_ROWS)
    )
    parser.add_argument("--only")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    variants = [variant for variant in VARIANTS if args.only in (None, variant.name)]
    if args.only and not variants:
        print(f"no variant is named {args.only!r}", file=sys.stderr)
        return 2
    if args.list:
        _print_list(tuple(variants))
        return 0

    binary = shutil.which("proverif")
    if binary is None:
        print(
            f"proverif is not on PATH: the model was not run. Install it with {_INSTALL}",
            file=sys.stderr,
        )
        return 2
    version = proverif_version(binary)
    if version != PROVERIF_VERSION:
        print(
            f"proverif is version {version!r}; the verdicts are pinned to "
            f"{PROVERIF_VERSION!r}. Install that version with {_INSTALL}, "
            "or re-derive every verdict and move the pin.",
            file=sys.stderr,
        )
        return 2
    for library in _LIBRARIES:
        if not library.is_file():
            print(f"{library} is missing: the shared library was not loaded", file=sys.stderr)
            return 2

    if args.keep is not None:
        args.keep.mkdir(parents=True, exist_ok=True)

    def run_row(row: tuple[Variant, Query], work: pathlib.Path) -> RowOutcome:
        variant, query = row
        path = work / f"{variant.name}.{query.value}.pv"
        path.write_text(source(variant, (query,)), encoding="utf-8")
        started = time.monotonic()
        want = variant.expectation(query)
        # Output goes to a file, not a pipe, so the child can be reaped with
        # wait4 and its own peak memory read: the cap is only a good cap if
        # somebody can see how close each row runs to it.
        with open(work / f"{variant.name}.{query.value}.out", "w+", encoding="utf-8") as sink:
            child = subprocess.Popen(
                _capped_command(binary, path), stdout=sink, stderr=subprocess.STDOUT
            )
            deadline = started + VARIANT_TIMEOUT_SECONDS
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    break
                if time.monotonic() > deadline:
                    child.kill()
                    os.wait4(child.pid, 0)
                    return RowOutcome(
                        variant.name,
                        query.value,
                        want,
                        None,
                        "",
                        time.monotonic() - started,
                        0,
                    )
                time.sleep(REAP_POLL_SECONDS)
            child.returncode = os.waitstatus_to_exitcode(status)
            sink.seek(0)
            output = sink.read()
        return RowOutcome(
            variant.name,
            query.value,
            want,
            child.returncode,
            output,
            time.monotonic() - started,
            # ru_maxrss is kibibytes on Linux, the only host the installer accepts.
            usage.ru_maxrss // _KIBIBYTE,
        )

    rows = [(variant, query) for variant in variants for query, _want in variant.expect]
    failures = 0
    checked = 0
    near_cap = []
    warn_mib = MEMORY_WARN_FRACTION * VARIANT_MEMORY_BYTES / _MEBIBYTE
    with tempfile.TemporaryDirectory() as tmp:
        work = args.keep or pathlib.Path(tmp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            pending = [pool.submit(run_row, row, work) for row in rows]
            results = (future.result() for future in concurrent.futures.as_completed(pending))
            # Reported as each row finishes: the slow ones take minutes, and
            # a silent job looks like a hung one.
            results = list(_report_as_done(results))
        order = {(variant.name, query.value): index for index, (variant, query) in enumerate(rows)}
        results.sort(key=lambda item: order[(item.name, item.query)])
        for outcome in results:
            if outcome.returncode is None:
                failures += 1
                print(
                    f"FAIL {outcome.name}: {outcome.query}: "
                    f"no verdict within {VARIANT_TIMEOUT_SECONDS} s",
                    file=sys.stderr,
                )
                continue
            if outcome.peak_mib > warn_mib:
                near_cap.append((outcome.name, outcome.query, outcome.peak_mib))
            got = verdicts(outcome.output)
            if outcome.returncode != 0 or len(got) != 1:
                failures += 1
                print(
                    f"FAIL {outcome.name}: {outcome.query}: proverif exit {outcome.returncode}, "
                    f"{len(got)} verdict(s) for one query",
                    file=sys.stderr,
                )
                for line in outcome.output.strip().splitlines()[-6:]:
                    print("     " + line, file=sys.stderr)
                continue
            verdict = got[0]
            # A reachability query is "event(...)": ProVerif reports "is false"
            # when the event happened, which this runner calls reachable.
            ok = (
                verdict == "attack"
                if outcome.want is Expectation.REACHABLE
                else verdict == outcome.want.value
            )
            checked += 1
            if ok:
                print(
                    f"ok   {outcome.name}: {outcome.query} -> {outcome.want.value}  "
                    f"({outcome.seconds:.0f} s, peak {outcome.peak_mib} MiB)"
                )
            else:
                failures += 1
                print(
                    f"FAIL {outcome.name}: {outcome.query} expected {outcome.want.value}, "
                    f"ProVerif says {verdict}",
                    file=sys.stderr,
                )
    if checked == 0:
        print("no verdict was checked: the model did not run", file=sys.stderr)
        return 2
    cap_mib = VARIANT_MEMORY_BYTES // _MEBIBYTE
    for name, query, peak_mib in near_cap:
        print(
            f"WARN {name}: {query}: peak {peak_mib} MiB is over "
            f"{MEMORY_WARN_FRACTION:.0%} of the {cap_mib} MiB cap",
            file=sys.stderr,
        )
        # GitHub Actions shows this on the run's summary page.
        print(
            f"::warning title=RT-P7 model near its memory cap::{name}: {query} peaked at "
            f"{peak_mib} MiB of {cap_mib} MiB"
        )
    print(
        f"{checked} verdict(s) checked, {failures} unexpected, "
        f"{len(near_cap)} within {1 - MEMORY_WARN_FRACTION:.0%} of the memory cap"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
