#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Regression tests for `scripts/bench/compare.py`.
#
# Scope: lock down the iai-callgrind comparator's verdict routing
# against the corruption shapes the bench-baseline branch can ship,
# so future edits to the threshold logic don't accidentally
# re-introduce the +inf% / divide-by-zero failure modes, and so the
# `baseline_zero` anomaly bucket stays distinct from the legitimate
# "new in PR" / "missing in PR" buckets.
#
# Run: `python3 scripts/bench/test_compare.py` (no test runner needed;
# stdlib unittest invoked directly).

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Any


SCRIPT_PATH = pathlib.Path(__file__).resolve().parent / "compare.py"


def _envelope(iai_entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "shekyl_rust_v0",
        "captured_on": {
            "git_rev": "abc123def456",
            "git_dirty": "clean",
            "cpu_model": "test",
            "kernel": "test",
            "rustc_version": "test",
        },
        "iai_callgrind": iai_entries,
        "criterion": [],
    }


def _iai(
    crate: str,
    bench: str,
    group: str,
    fn: str,
    run: str,
    instructions: int,
) -> dict[str, Any]:
    return {
        "crate": crate,
        "bench_target": bench,
        "group": group,
        "function": fn,
        "run_id": run,
        "metrics": {
            "instructions": instructions,
            "estimated_cycles": instructions,
        },
    }


def _run_compare(baseline: dict[str, Any], pr: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    with tempfile.TemporaryDirectory() as d:
        bp = pathlib.Path(d) / "baseline.json"
        pp = pathlib.Path(d) / "pr.json"
        # Explicit utf-8: pathlib defaults to locale encoding, which
        # surprises on Windows runners and on minimal C-locale CI
        # images.
        bp.write_text(json.dumps(baseline), encoding="utf-8")
        pp.write_text(json.dumps(pr), encoding="utf-8")
        # Hard timeout so a future bug in `compare.py` (e.g., a
        # change that accidentally reads from stdin) cannot stall
        # the test job indefinitely. 30s is generous — a cold
        # Python startup plus this comparator's purely-in-memory
        # routing has historically completed in <100ms.
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--baseline", str(bp), "--pr", str(pp)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(
                f"compare.py exceeded 30s timeout: {exc}. "
                "If a legitimate change makes the comparator slower, "
                "raise the timeout deliberately rather than removing it."
            ) from exc
        report = json.loads(proc.stdout) if proc.stdout else {}
        return proc.returncode, report


class CompareTest(unittest.TestCase):
    def test_baseline_zero_routes_to_baseline_zero_bucket(self) -> None:
        # The actual failure shape observed on PR #34: the
        # bench-baseline branch's `baseline.iai.snapshot` recorded
        # `instructions=0` for six `hot_path_bench_ledger_postcard_*`
        # entries that the prior nine baselines had measured at ~4.4M
        # / 44M / 444M instructions. Cause is unknown (under
        # investigation on
        # `chore/investigate-bench-baseline-flake-2026-05-09`); what
        # the comparator must guarantee is that the entries route to
        # the distinct `baseline_zero` bucket — informational, not
        # gating, with the PR-side value preserved for diagnosis —
        # rather than emitting `+inf% fail` (the pre-fix behavior)
        # OR being silently absorbed into `added_in_pr` (which would
        # mislabel the anomaly as "new in PR" and hide the signal
        # from reviewers).
        base = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "ledger_iai",
                    "ledger",
                    "hot_path_bench_ledger_postcard_serialize",
                    "with_setup_0",
                    0,
                ),
                _iai(
                    "shekyl-engine-state",
                    "ledger_iai",
                    "ledger",
                    "hot_path_bench_ledger_postcard_serialize",
                    "with_setup_1",
                    0,
                ),
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    57_531,
                ),
            ]
        )
        pr = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "ledger_iai",
                    "ledger",
                    "hot_path_bench_ledger_postcard_serialize",
                    "with_setup_0",
                    4_453_844,
                ),
                _iai(
                    "shekyl-engine-state",
                    "ledger_iai",
                    "ledger",
                    "hot_path_bench_ledger_postcard_serialize",
                    "with_setup_1",
                    44_641_084,
                ),
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    57_931,
                ),
            ]
        )

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 0)
        s = report["summary"]
        self.assertEqual(s["fail"], 0)
        self.assertFalse(s["has_fail"])

        # The two baseline=0 entries route to the distinct bucket.
        self.assertEqual(len(s["baseline_zero"]), 2)
        # The bucket carries diagnostic info (full_id + class + pr
        # value) so the renderer can surface the anomaly with the
        # PR-side measurement, not just the ID.
        ids = {e["full_id"] for e in s["baseline_zero"]}
        self.assertIn(
            "shekyl-engine-state/ledger_iai/ledger/"
            "hot_path_bench_ledger_postcard_serialize/with_setup_0",
            ids,
        )
        for entry in s["baseline_zero"]:
            self.assertEqual(entry["class"], "hot_path_bench")
            self.assertGreater(entry["pr"], 0)

        # The baseline=0 entries are NOT in `added_in_pr` — that
        # bucket is reserved for entries genuinely new on the PR
        # side. Mislabeling baseline anomalies as "new" would hide
        # the signal from reviewers, which is the failure mode the
        # distinct bucket exists to prevent.
        self.assertEqual(len(s["added_in_pr"]), 0)

        # The valid-baseline entry still gates normally as `ok`.
        self.assertEqual(len(report["entries"]), 1)
        self.assertEqual(report["entries"][0]["verdict"], "ok")

    def test_real_regression_still_fails(self) -> None:
        # Regression guard: the baseline-anomaly accommodation must
        # not silence real regressions. A hot_path entry with valid
        # baseline and PR > +15% must still trip `fail`.
        base = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    57_531,
                ),
            ]
        )
        pr = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    80_000,  # +39%
                ),
            ]
        )

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        s = report["summary"]
        self.assertEqual(s["fail"], 1)
        self.assertTrue(s["has_fail"])
        self.assertEqual(report["entries"][0]["verdict"], "fail")

    def test_both_zero_stays_ok(self) -> None:
        # Preserve prior behavior for the `pr_val == 0` branch: if
        # both sides report zero, the entry resolves to a 0% delta
        # `ok` rather than getting routed to baseline_zero (no real
        # measurement on either side, but no spurious flag either).
        # Distinct from the baseline-anomaly case where pr > 0 — a
        # both-zero observation is informationally a no-op rather
        # than a measurement-of-something-against-no-baseline.
        base = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    0,
                ),
            ]
        )
        pr = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    0,
                ),
            ]
        )

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 0)
        self.assertEqual(report["summary"]["fail"], 0)
        self.assertEqual(len(report["summary"]["baseline_zero"]), 0)
        self.assertEqual(len(report["entries"]), 1)
        self.assertEqual(report["entries"][0]["verdict"], "ok")
        self.assertEqual(report["entries"][0]["delta_pct"], 0.0)

    def test_added_in_pr_distinct_from_baseline_zero(self) -> None:
        # An entry that exists only on the PR side (genuinely new
        # bench) routes to `added_in_pr`, NOT `baseline_zero`. The
        # distinction matters: `added_in_pr` says "this bench did
        # not exist on dev"; `baseline_zero` says "this bench
        # existed on dev but the captured measurement is anomalous."
        # Conflating them buries diagnostic signal.
        base = _envelope([])  # no baseline entries at all
        pr = _envelope(
            [
                _iai(
                    "shekyl-engine-state",
                    "balance_iai",
                    "balance",
                    "hot_path_bench_balance_compute",
                    "with_setup_0",
                    57_931,
                ),
            ]
        )

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 0)
        s = report["summary"]
        self.assertEqual(len(s["added_in_pr"]), 1)
        self.assertEqual(len(s["baseline_zero"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
