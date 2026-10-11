#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Execute the NNhfs variants and fail if a pinned verdict moves.
# The pattern, the claims, and the generated files live in model.py.
# This is PWD-T1's handshake, not the RPC slice RT-W8.
#
# Run:  python3 run.py                 # every variant; exit 1 on a drift
#       python3 run.py --list          # the claims and the rows that flip them
#       python3 run.py --jobs N        # variants in parallel (default: up to 4)
#       python3 run.py --only NAME
#       python3 run.py --write-variants

from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
import time

from model import (
    CLAIMS,
    LIB,
    VARIANTS,
    Claim,
    Row,
    Verdict,
    check_claims,
    check_variants,
    rows_of,
    write_variants,
    _labels,
)

PROVERIF_VERSION = "2.05"
VARIANT_TIMEOUT_SECONDS = 20 * 60
VARIANT_MEMORY_BYTES = 4 * 1024**3

RESULT = re.compile(r"^RESULT (.*) (is true|is false|cannot be proved)\.?\s*$")
RESULT_WORD = {"is true": Verdict.HOLDS, "is false": Verdict.FAILS}


def proverif_binary() -> str:
    exe = os.environ.get("PROVERIF", "proverif")
    try:
        out = subprocess.run([exe, "-help"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        sys.exit("run.py: no proverif on PATH (set PROVERIF=...); install with ../install_proverif.sh")
    banner = (out.stdout + out.stderr).splitlines()[0] if (out.stdout + out.stderr) else ""
    # The banner is "Proverif <version>. Cryptographic protocol verifier, ...".
    # The whole version token is compared, so 2.05pl1 is not 2.05.
    found = re.match(r"^Proverif (\S+)\. ", banner)
    if not found or found.group(1) != PROVERIF_VERSION:
        sys.exit(f"run.py: pinned to ProVerif {PROVERIF_VERSION}, found: {banner!r}")
    return exe


def proverif_command(exe: str, model_path: str) -> list[str]:
    """Cap the child with prlimit. A preexec_fn would fork from a worker
    thread, which can deadlock before exec."""
    prlimit = shutil.which("prlimit")
    if prlimit is None:
        sys.exit("run.py: prlimit is required (util-linux) to cap each variant")
    return [prlimit, f"--as={VARIANT_MEMORY_BYTES}", "--", exe, "-lib", str(LIB), model_path]


def run_variant(exe: str, row: Row) -> tuple[str, dict[str, Verdict], str | None, float]:
    started = time.monotonic()
    try:
        proc = subprocess.run(
            proverif_command(exe, str(VARIANTS / f"{row.name}.pv")),
            capture_output=True,
            text=True,
            timeout=VARIANT_TIMEOUT_SECONDS,
        )
        out = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return row.name, {}, f"timed out after {VARIANT_TIMEOUT_SECONDS}s", time.monotonic() - started
    results: list[Verdict] = []
    unproved = False
    for line in out.splitlines():
        matched = RESULT.match(line.strip())
        if not matched:
            continue
        verdict = RESULT_WORD.get(matched.group(2))
        if verdict is None:
            unproved = True
            break
        results.append(verdict)
    # A verifier that printed its results and then died has not finished.
    if rc != 0:
        return row.name, {}, f"proverif exited {rc}:\n{out[-3000:]}", time.monotonic() - started
    if unproved:
        return row.name, {}, f"a query cannot be proved:\n{out[-3000:]}", time.monotonic() - started
    if len(results) != len(row.expects):
        return (
            row.name,
            {},
            f"{len(results)} RESULT lines for {len(row.expects)} queries:\n{out[-3000:]}",
            time.monotonic() - started,
        )
    got = dict(zip((name for name, _ in row.expects), results))
    return row.name, got, None, time.monotonic() - started


def _print_list(claims: tuple[Claim, ...]) -> None:
    for claim in claims:
        row = claim.row
        print(
            f"{row.name:32} {_labels(row.edits):22} {_labels(row.breaks):8} "
            + " ".join(f"{name}={verdict.value}" for name, verdict in row.expects)
        )
        falsifier = claim.falsifier
        if falsifier is None:
            print(f"{'':32} stated non-property")
            continue
        print(
            f"  {falsifier.name:30} flips it  {_labels(falsifier.edits):22} {_labels(falsifier.breaks):8} "
            + " ".join(f"{name}={verdict.value}" for name, verdict in falsifier.expects)
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    ap.add_argument("--only")
    ap.add_argument("--write-variants", action="store_true")
    args = ap.parse_args()

    check_claims(CLAIMS)
    rows = rows_of(CLAIMS)
    if args.write_variants:
        write_variants(rows)
        print(f"wrote {len(rows)} variants in {VARIANTS}")
        return 0
    if args.only:
        rows = [row for row in rows if row.name == args.only]
        if not rows:
            sys.exit(f"run.py: no variant named {args.only}")
    if args.list:
        _print_list(CLAIMS)
        return 0

    # The whole committed set is the subject, including when --only runs one.
    stale = check_variants(rows_of(CLAIMS))
    if stale:
        print(f"run.py: {stale}", file=sys.stderr)
        return 1

    exe = proverif_binary()
    failed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for name, got, err, secs in pool.map(lambda row: run_variant(exe, row), rows):
            if err:
                failed = True
                print(f"FAIL  {name:32} {secs:6.1f}s  {err}")
                continue
            expected = dict(next(row.expects for row in rows_of(CLAIMS) if row.name == name))
            bad = {
                query: (got[query].value, verdict.value)
                for query, verdict in expected.items()
                if got.get(query) is not verdict
            }
            if bad:
                failed = True
                detail = "; ".join(
                    f"{query}: got {have}, expected {want}" for query, (have, want) in bad.items()
                )
                print(f"FAIL  {name:32} {secs:6.1f}s  {detail}")
            else:
                summary = ", ".join(f"{query}={verdict.value}" for query, verdict in got.items())
                print(f"ok    {name:32} {secs:6.1f}s  {summary}")
    if failed:
        print(
            "run.py: a verdict changed. A property that moved is a design change; "
            "a falsifier that no longer flips is a model error.",
            file=sys.stderr,
        )
        return 1
    print(f"run.py: {len(rows)} variants, every verdict as pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
