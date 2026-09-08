#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_matrix_job_gating.py — a job whose NAME is interpolated must not carry
# a job-level `if:`.
#
# THE DEFECT THIS EXISTS FOR. A job-level `if:` is evaluated BEFORE the matrix
# expands. A skipped matrix job therefore has no `matrix.*` context to
# interpolate its name from, and cannot emit check runs under the per-leg names
# — `Ubuntu 22.04` and `Ubuntu 24.04` in this repo. Those are REQUIRED contexts,
# so branch protection keeps waiting for reports nobody will make: a required
# check that CANNOT PASS. That is a hard deadlock, and it is silent in review
# because the workflow file reads correctly and the gating looks uniform with
# the literal-named jobs beside it.
#
# The correct shape for such a job is to run and gate its WORK at the step
# level, so the legs exist and report while doing nothing expensive.
#
# Literal-named jobs are unaffected: a skipped job with a literal name reports
# under that name, which protection accepts — the shape codeql.yml's
# analyze-cpp / analyze-python already rely on for two other required contexts.
#
# Run `--selftest` to prove the check can fail; CI runs it before the scan.

import glob
import io
import os
import re
import sys

import yaml

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(REPO, ".github", "workflows", "*.yml")

INTERPOLATED = re.compile(r"\$\{\{")

# The defect is only real when the per-leg names are REQUIRED contexts: nothing
# waits on a name protection does not require, so skipping such a job blocks
# nobody. This script cannot query branch protection, so accepted cases are
# enumerated here with the reason, and an unlisted one fails.
#
# Keyed on (workflow file, job id) — not on the name, which is interpolated and
# therefore not a stable key.
ALLOWED = {
    ("randomx-v2-differential.yml", "runtime-modes"):
        "scheduled differential lane; its per-leg names are cron-prefixed and "
        "are not required contexts, so a skipped job blocks no merge",
    ("randomx-v2-differential.yml", "rotating"):
        "scheduled rotating lane; same basis as runtime-modes above",
}


def offenders(doc, where):
    """Jobs with an interpolated name AND a job-level `if:`."""
    out = []
    for jid, job in (doc.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        name = str(job.get("name", ""))
        if INTERPOLATED.search(name) and "if" in job:
            if (where, jid) in ALLOWED:
                continue
            out.append("%s: job `%s` has an interpolated name (%s) AND a "
                       "job-level `if:` — a skipped matrix job cannot emit its "
                       "per-leg check names. Gate its steps instead, or add it "
                       "to ALLOWED with the reason its names are not required."
                       % (where, jid, name))
    return out


def stale_allowlist(seen):
    """An allowlist row matching nothing is a stated reason about code that is
    gone; it stops describing the tree and starts excusing it."""
    return ["ALLOWED has a row matching nothing: %s / %s" % k
            for k in sorted(ALLOWED) if k not in seen]


FIXTURE_BAD = """
jobs:
  build-ubuntu:
    name: ${{ matrix.name }}
    if: needs.changes.outputs.docs_only != 'true'
    strategy:
      matrix:
        include:
          - name: Ubuntu 22.04
    steps:
      - run: true
"""

FIXTURE_OK = """
jobs:
  build-ubuntu:
    name: ${{ matrix.name }}
    strategy:
      matrix:
        include:
          - name: Ubuntu 22.04
    steps:
      - run: true
        if: needs.changes.outputs.docs_only != 'true'
  build-macos:
    name: 'macOS (brew)'
    if: needs.changes.outputs.docs_only != 'true'
    steps:
      - run: true
"""


def selftest():
    bad = offenders(yaml.safe_load(FIXTURE_BAD), "fixture")
    if len(bad) != 1:
        print("SELFTEST FAIL: bad fixture yielded %d offender(s), want 1" % len(bad))
        return 1
    ok = offenders(yaml.safe_load(FIXTURE_OK), "fixture")
    if ok:
        print("SELFTEST FAIL: good fixture yielded %d offender(s), want 0 — the "
              "check is flagging step-level gating or literal-named job gating, "
              "both of which are correct" % len(ok))
        return 1
    print("SELFTEST PASS: flags an interpolated-name job with a job-level `if:`, "
          "and not step-level gating or a literal-named job")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    rc = selftest()
    if rc:
        return rc

    files = sorted(glob.glob(WORKFLOWS))
    if not files:
        print("FATAL: no workflow files found — the scan path is wrong.")
        return 2

    problems = []
    scanned = 0
    seen = set()
    for path in files:
        try:
            doc = yaml.safe_load(io.open(path, encoding="utf-8").read())
        except Exception as exc:
            print("FATAL: %s does not parse: %s" % (os.path.basename(path), exc))
            return 2
        if not isinstance(doc, dict):
            continue
        scanned += 1
        base = os.path.basename(path)
        for jid, job in (doc.get("jobs") or {}).items():
            if isinstance(job, dict) and INTERPOLATED.search(str(job.get("name", ""))) \
               and "if" in job and (base, jid) in ALLOWED:
                seen.add((base, jid))
        problems.extend(offenders(doc, base))

    problems.extend(stale_allowlist(seen))

    if problems:
        print("FAIL: %d job(s) gate a matrix-named job at the job level:" % len(problems))
        for p in problems:
            print("  " + p)
        return 1

    print("matrix job gating: %d workflow files, no unlisted interpolated-name "
          "job carries a job-level `if:` (%d allowlisted)" % (scanned, len(ALLOWED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
