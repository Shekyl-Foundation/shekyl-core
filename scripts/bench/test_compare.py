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
import os
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

        # `total` and `gated_total` reflect "entries that produced a
        # gate verdict" (= ok + warn + fail), NOT "gross entries
        # compared." When `baseline_zero` is non-empty, this means
        # `total < len(baseline) entries` — that's the intended
        # semantics and the headline phrase "X gated entries" in
        # `post_comment.py` reflects it. Pin the relationship so a
        # future renderer change can't silently confuse the two.
        self.assertEqual(s["total"], 1)
        self.assertEqual(s["gated_total"], 1)
        self.assertEqual(s["gated_total"], s["ok"] + s["warn"] + s["fail"])

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


    def _relay(self, crate: str, instructions: int) -> dict[str, Any]:
        return _iai(
            crate,
            "relay_admission_verify_iai",
            "relay_admission_verify_group",
            "crypto_bench_relay_admission_verify",
            "modal",
            instructions,
        )

    def test_a_crate_move_is_compared_not_missing(self) -> None:
        # The same bench under another crate is a move: compared under
        # the normal thresholds, neither missing nor added.
        base = _envelope([self._relay("shekyl-ffi", 358_680_540)])
        pr = _envelope([self._relay("shekyl-chain-rules", 358_987_738)])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 0)
        s = report["summary"]
        self.assertEqual(s["missing_in_pr"], [])
        self.assertEqual(s["added_in_pr"], [])
        self.assertEqual(len(s["moved"]), 1)
        self.assertTrue(s["moved"][0]["from"].startswith("shekyl-ffi/"))
        self.assertTrue(s["moved"][0]["to"].startswith("shekyl-chain-rules/"))
        entry = report["entries"][0]
        self.assertEqual(entry["verdict"], "ok")
        self.assertEqual(entry["moved_from"], s["moved"][0]["from"])

    def test_a_move_that_changes_the_workload_still_fails(self) -> None:
        base = _envelope([self._relay("shekyl-ffi", 358_680_540)])
        pr = _envelope([self._relay("shekyl-chain-rules", 200_000_000)])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        self.assertEqual(report["entries"][0]["verdict"], "fail")

    def test_a_deleted_bench_with_no_successor_is_still_missing(self) -> None:
        base = _envelope([self._relay("shekyl-ffi", 358_680_540)])
        pr = _envelope([])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        self.assertEqual(len(report["summary"]["missing_in_pr"]), 1)
        self.assertEqual(report["summary"]["moved"], [])

    def test_an_ambiguous_move_is_not_paired(self) -> None:
        # Two candidates for one missing bench: no pairing, so the old
        # id stays missing and both new ids stay added.
        base = _envelope([self._relay("shekyl-ffi", 358_680_540)])
        pr = _envelope(
            [
                self._relay("shekyl-chain-rules", 358_987_738),
                self._relay("shekyl-mempool", 358_987_738),
            ]
        )

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        s = report["summary"]
        self.assertEqual(len(s["missing_in_pr"]), 1)
        self.assertEqual(len(s["added_in_pr"]), 2)
        self.assertEqual(s["moved"], [])



class ScopedCaptureTests(unittest.TestCase):
    """A capture scoped to the rows a change can reach (`captured_rows`)."""

    def _row(self, crate: str, bench: str, instructions: int) -> dict[str, Any]:
        return _iai(crate, bench, f"{bench}_group", "crypto_bench_x", "cell", instructions)

    def _scoped(self, entries: list[dict[str, Any]], rows: Any) -> dict[str, Any]:
        envelope = _envelope(entries)
        envelope["captured_rows"] = rows
        return envelope

    def test_a_row_the_capture_did_not_run_is_out_of_scope_not_missing(self) -> None:
        base = _envelope(
            [self._row("crate-a", "a_iai", 1_000), self._row("crate-b", "b_iai", 2_000)]
        )
        pr = self._scoped([self._row("crate-a", "a_iai", 1_000)], ["crate-a::a_iai"])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 0)
        s = report["summary"]
        self.assertEqual(s["missing_in_pr"], [])
        self.assertEqual(len(s["out_of_scope"]), 1)
        self.assertTrue(s["out_of_scope"][0].startswith("crate-b/b_iai/"))
        self.assertEqual(s["captured_rows"], ["crate-a::a_iai"])
        self.assertEqual(s["gated_total"], 1)

    def test_a_function_missing_from_a_row_the_capture_ran_still_fails(self) -> None:
        # The row was captured and one of its functions is gone: a deleted
        # bench, in scope.
        base = _envelope(
            [
                self._row("crate-a", "a_iai", 1_000),
                _iai("crate-a", "a_iai", "a_iai_group", "crypto_bench_y", "cell", 5_000),
            ]
        )
        pr = self._scoped([self._row("crate-a", "a_iai", 1_000)], ["crate-a::a_iai"])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        self.assertEqual(len(report["summary"]["missing_in_pr"]), 1)
        self.assertEqual(report["summary"]["out_of_scope"], [])

    def test_a_scoped_capture_still_gates_the_rows_it_ran(self) -> None:
        base = _envelope(
            [self._row("crate-a", "a_iai", 1_000), self._row("crate-b", "b_iai", 2_000)]
        )
        pr = self._scoped([self._row("crate-a", "a_iai", 2_000)], ["crate-a::a_iai"])

        rc, report = _run_compare(base, pr)
        self.assertEqual(rc, 1)
        self.assertEqual(report["summary"]["fail"], 1)

    def test_an_unscoped_capture_reads_every_absent_row_as_missing(self) -> None:
        # No `captured_rows` key is the envelope every capture wrote before
        # scoping; `all` is the push to dev's. Both mean the whole set.
        base = _envelope(
            [self._row("crate-a", "a_iai", 1_000), self._row("crate-b", "b_iai", 2_000)]
        )
        for pr in (
            _envelope([self._row("crate-a", "a_iai", 1_000)]),
            self._scoped([self._row("crate-a", "a_iai", 1_000)], "all"),
        ):
            rc, report = _run_compare(base, pr)
            self.assertEqual(rc, 1)
            self.assertEqual(len(report["summary"]["missing_in_pr"]), 1)
            self.assertEqual(report["summary"]["out_of_scope"], [])

    def test_a_malformed_scope_is_an_input_error(self) -> None:
        base = _envelope([self._row("crate-a", "a_iai", 1_000)])
        pr = self._scoped([self._row("crate-a", "a_iai", 1_000)], "crate-a::a_iai")
        # In process: the subprocess helper reads a report, and an input
        # error writes none.
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import compare  # noqa: PLC0415

        with self.assertRaises(SystemExit):
            compare.compare(base, pr)


def _import_compare():
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import compare  # noqa: PLC0415

    return compare


class DriftLogTest(unittest.TestCase):
    """The log names the row that makes the run red.

    A deleted bench is not an entry. A renderer that walks `entries`
    alone stays green on this test the moment the missing id leaves
    the log.
    """

    def test_format_delta_pct_is_a_signed_percentage(self) -> None:
        compare = _import_compare()
        self.assertEqual(compare.format_delta_pct(0.051), "+5.10%")
        self.assertEqual(compare.format_delta_pct(-0.051), "-5.10%")
        self.assertEqual(compare.format_delta_pct(0), "+0.00%")
        self.assertEqual(compare.format_delta_pct(1 / 3), "+33.33%")

    def test_the_pull_request_comment_uses_that_percentage(self) -> None:
        compare = _import_compare()
        import post_comment  # noqa: PLC0415

        self.assertIs(post_comment.format_delta_pct, compare.format_delta_pct)

    def test_the_log_names_a_missing_row_ahead_of_an_ok_row(self) -> None:
        compare = _import_compare()
        base = _envelope(
            [
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000),
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_quiet", "r", 1000),
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_gone", "r", 1000),
            ]
        )
        pr = _envelope(
            [
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1200),
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_quiet", "r", 1000),
            ]
        )
        report = compare.compare(base, pr)
        log = compare.render_log(report)
        gone = report["summary"]["missing_in_pr"][0]
        by_verdict = {entry["verdict"]: entry["full_id"] for entry in report["entries"]}
        self.assertLess(log.index(gone), log.index(by_verdict["fail"]))
        self.assertLess(log.index(by_verdict["fail"]), log.index(by_verdict["ok"]))
        self.assertIn("+20.00%", log)
        annotation = compare.alarm_annotation(report, "dev baseline", "the earlier capture")
        self.assertIsNotNone(annotation)
        assert annotation is not None
        self.assertIn(gone, annotation)
        self.assertIn(by_verdict["fail"], annotation)
        self.assertNotIn(by_verdict["ok"], annotation)
        self.assertIn("dev baseline", annotation)
        self.assertIn("the earlier capture", annotation)

    def test_a_warn_names_no_error(self) -> None:
        compare = _import_compare()
        base = _envelope(
            [_iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000)]
        )
        pr = _envelope(
            [_iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1060)]
        )
        report = compare.compare(base, pr)
        self.assertEqual(report["entries"][0]["verdict"], "warn")
        self.assertIsNone(
            compare.alarm_annotation(report, "dev baseline", "the earlier capture")
        )

    def test_a_fail_that_names_nothing_is_an_error(self) -> None:
        compare = _import_compare()
        report = {
            "summary": {
                "has_fail": True,
                "missing_in_pr": [],
                "added_in_pr": [],
                "baseline_zero": [],
            },
            "entries": [],
        }
        with self.assertRaises(SystemExit):
            compare.alarm_annotation(report, "dev baseline", "the earlier capture")


class DriftReportScriptTest(unittest.TestCase):
    def _run(self, baseline: dict[str, Any], pr: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        script = pathlib.Path(__file__).resolve().parent / "drift_report.sh"
        self.assertTrue(os.access(script, os.X_OK), f"{script} is not executable")
        with tempfile.TemporaryDirectory() as d:
            directory = pathlib.Path(d)
            earlier = directory / "earlier.json"
            later = directory / "later.json"
            earlier.write_text(json.dumps(baseline), encoding="utf-8")
            later.write_text(json.dumps(pr), encoding="utf-8")
            return subprocess.run(
                [str(script), "dev baseline", str(earlier), str(later), "the earlier capture"],
                capture_output=True,
                text=True,
                timeout=30,
            )

    def test_a_removed_row_is_named_and_red(self) -> None:
        base = _envelope(
            [
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000),
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_gone", "r", 1000),
            ]
        )
        pr = _envelope(
            [_iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000)]
        )
        proc = self._run(base, pr)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("crypto_bench_gone", proc.stdout)
        self.assertIn("::error::dev baseline:", proc.stdout)
        self.assertIn("missing ", proc.stdout)
        self.assertIn("the earlier capture", proc.stdout)

    def test_an_added_row_is_clean(self) -> None:
        base = _envelope(
            [_iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000)]
        )
        pr = _envelope(
            [
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_keep", "r", 1000),
                _iai("shekyl-crypto-pq", "t", "g", "crypto_bench_new", "r", 1000),
            ]
        )
        proc = self._run(base, pr)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("::error::", proc.stdout)
        self.assertIn("crypto_bench_new", proc.stdout)

    def test_a_missing_envelope_is_an_input_error(self) -> None:
        script = pathlib.Path(__file__).resolve().parent / "drift_report.sh"
        proc = subprocess.run(
            [str(script), "dev baseline", "/tmp/does-not-exist-drift.json", "/tmp/neither-does-this.json", "earlier"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("::error::", proc.stdout)


class OriginBranchTest(unittest.TestCase):
    """Exit 2 from ls-remote is absence. Any other failure is not."""

    def _script(self) -> pathlib.Path:
        script = pathlib.Path(__file__).resolve().parent / "origin_branch.sh"
        self.assertTrue(os.access(script, os.X_OK), f"{script} is not executable")
        return script

    def test_no_branch_is_absent_and_a_branch_is_present(self) -> None:
        script = self._script()
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            bare = root / "origin.git"
            work = root / "work"
            subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
            subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
            subprocess.run(
                ["git", "-C", str(work), "config", "user.email", "test@example.com"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(work), "config", "user.name", "origin-branch test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(work), "remote", "add", "origin", str(bare)],
                check=True,
            )
            absent = subprocess.run(
                [str(script), str(work), "bench-baseline"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(absent.returncode, 0, absent.stderr)
            self.assertEqual(absent.stdout, "absent\n")

            subprocess.run(
                ["git", "-C", str(work), "commit", "--allow-empty", "-m", "seed"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(work), "push", "origin", "HEAD:bench-baseline"],
                check=True,
                capture_output=True,
                text=True,
            )
            present = subprocess.run(
                [str(script), str(work), "bench-baseline"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(present.returncode, 0, present.stderr)
            self.assertEqual(present.stdout, "present\n")

    def test_a_failed_lookup_is_not_absent(self) -> None:
        script = self._script()
        with tempfile.TemporaryDirectory() as d:
            work = pathlib.Path(d) / "work"
            subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
            proc = subprocess.run(
                [str(script), str(work), "bench-baseline"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotIn("absent", proc.stdout)
            self.assertIn("::error::", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
