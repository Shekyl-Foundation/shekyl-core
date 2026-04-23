#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Compare two `shekyl_rust_v0` envelopes (PR vs baseline) and route
# each iai-callgrind entry through the threshold table from
# `docs/MID_REWIRE_HARDENING.md` §3.3 / `docs/benchmarks/README.md`.
#
# Output on stdout is a JSON report with the shape:
#
#     {
#       "schema_version": "shekyl_rust_v0_compare_v1",
#       "baseline_git_rev": "...",
#       "pr_git_rev": "...",
#       "entries": [
#         {
#           "full_id": "<crate>/<bench_target>/<group>/<function>/<run_id>",
#           "class": "crypto_bench" | "hot_path_bench" | "unrouted",
#           "metric": "instructions",
#           "baseline": 12064698,
#           "pr": 12064698,
#           "delta_pct": 0.0,
#           "verdict": "ok" | "warn" | "fail"
#         },
#         ...
#       ],
#       "criterion_entries": [...],
#       "summary": {
#         "total": 15,
#         "ok": 15, "warn": 0, "fail": 0,
#         "has_fail": false,
#         "has_warn": false,
#         "unrouted": []
#       }
#     }
#
# Exit code:
#   0 — no fails. warn entries are reported but do not exit nonzero.
#   1 — at least one fail. CI uses this as the gate.
#   2 — input error (bad JSON, missing file, schema mismatch).
#
# The script is deliberately self-contained (only stdlib) so the CI
# workflow can `python3 scripts/bench/compare.py ...` without an
# install step.
#
# Scope per §3.3 implementation notes: **iai-callgrind only**.
# Criterion wall-clock entries are passed through as informational
# rows (no threshold, verdict always "info") so the PR comment can
# still show them, but they do not trip the gate. The Tier-2 upgrade
# that moves criterion onto a dedicated runner and enables it as a
# gate is tracked in §6.1.

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


SCHEMA_VERSION_IN = "shekyl_rust_v0"
SCHEMA_VERSION_OUT = "shekyl_rust_v0_compare_v1"

# Threshold table — see `docs/MID_REWIRE_HARDENING.md` §3.3, §4.1. The
# thresholds are intentionally round-numbered and percentage-of-
# baseline (not raw instruction counts) so the rule is the same across
# benches with wildly different absolute counts.
#
# `crypto_bench_*`  : bidirectional  (±5% warn, ±15% fail).
#                     Speed-ups are suspicious too: a curve25519
#                     short-circuit, an ML-DSA-65 rejection-loop
#                     shortcut, or an Argon2id parameter drop all
#                     manifest as large negative deltas on a
#                     `crypto_bench_*` line.
# `hot_path_bench_*`: slowdown-only (+5% warn, +15% fail).
#                     Faster is unambiguously better for postcard
#                     serde, balance compute, scanner bookkeeping.
CRYPTO_WARN = 0.05
CRYPTO_FAIL = 0.15
HOT_PATH_WARN = 0.05
HOT_PATH_FAIL = 0.15

# The iai-callgrind metric the gate runs on. "instructions" is the
# most stable Tier-1 counter across kernel versions / valgrind patch
# releases; the other counters are kept in the envelope for human
# triage of a tripped gate but are not themselves gated.
GATE_METRIC = "instructions"


def classify(function_name: str) -> str:
    """Route a bench function name to its threshold class.

    The naming convention is enforced at bench-commit time (see
    manifest §2-§5): every iai bench function starts with exactly
    one of `crypto_bench_` or `hot_path_bench_`. Anything else is
    an un-routed bench and lands in the `unrouted` list for human
    review.
    """
    if function_name.startswith("crypto_bench_"):
        return "crypto_bench"
    if function_name.startswith("hot_path_bench_"):
        return "hot_path_bench"
    return "unrouted"


def verdict_for(cls: str, delta_pct: float) -> str:
    if cls == "crypto_bench":
        abs_d = abs(delta_pct)
        if abs_d >= CRYPTO_FAIL:
            return "fail"
        if abs_d >= CRYPTO_WARN:
            return "warn"
        return "ok"
    if cls == "hot_path_bench":
        # Slowdown-only: speed-ups are always OK.
        if delta_pct >= HOT_PATH_FAIL:
            return "fail"
        if delta_pct >= HOT_PATH_WARN:
            return "warn"
        return "ok"
    return "unrouted"


def _iai_full_id(entry: dict[str, Any]) -> str:
    # A single iai-callgrind library_benchmark can produce multiple
    # entries (one per `#[bench]` attribute / `args(...)` row), so
    # the `run_id` + `function` + `group` + `bench_target` + `crate`
    # tuple is what uniquely identifies a measurement across runs.
    return "/".join(
        [
            entry["crate"],
            entry["bench_target"],
            entry["group"],
            entry["function"],
            entry["run_id"],
        ]
    )


def _criterion_full_id(entry: dict[str, Any]) -> str:
    return entry["full_id"]


def load_envelope(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        env = json.load(f)
    if env.get("schema_version") != SCHEMA_VERSION_IN:
        raise SystemExit(
            f"[compare] {path}: expected schema_version={SCHEMA_VERSION_IN!r}, "
            f"got {env.get('schema_version')!r}"
        )
    return env


def compare(baseline: dict[str, Any], pr: dict[str, Any]) -> dict[str, Any]:
    base_iai = {_iai_full_id(e): e for e in baseline.get("iai_callgrind", [])}
    pr_iai = {_iai_full_id(e): e for e in pr.get("iai_callgrind", [])}

    base_crit = {_criterion_full_id(e): e for e in baseline.get("criterion", [])}
    pr_crit = {_criterion_full_id(e): e for e in pr.get("criterion", [])}

    iai_entries: list[dict[str, Any]] = []
    unrouted: list[str] = []
    missing_in_pr: list[str] = []
    added_in_pr: list[str] = []

    for full_id in sorted(set(base_iai) | set(pr_iai)):
        b = base_iai.get(full_id)
        p = pr_iai.get(full_id)
        if b is None:
            added_in_pr.append(full_id)
            continue
        if p is None:
            missing_in_pr.append(full_id)
            continue

        func = b["function"]
        cls = classify(func)
        if cls == "unrouted":
            unrouted.append(full_id)

        base_val = b["metrics"][GATE_METRIC]
        pr_val = p["metrics"][GATE_METRIC]
        # 0-instruction benches (theoretical; we have none) would
        # divide by zero; guard it so the comparator cannot crash on
        # a future schema where an empty-input bench lands.
        if base_val == 0:
            delta_pct = 0.0 if pr_val == 0 else float("inf")
        else:
            delta_pct = (pr_val - base_val) / base_val

        iai_entries.append(
            {
                "full_id": full_id,
                "class": cls,
                "metric": GATE_METRIC,
                "baseline": base_val,
                "pr": pr_val,
                "delta_pct": delta_pct,
                "verdict": verdict_for(cls, delta_pct),
            }
        )

    # Criterion passthrough — informational only, no threshold. The
    # median_ns swing is what humans read; mean_ns is included for
    # completeness. Entries that exist in only one side are flagged
    # with a `missing` verdict so the PR comment can surface them.
    criterion_entries: list[dict[str, Any]] = []
    for full_id in sorted(set(base_crit) | set(pr_crit)):
        b = base_crit.get(full_id)
        p = pr_crit.get(full_id)
        if b is None:
            criterion_entries.append(
                {
                    "full_id": full_id,
                    "verdict": "added",
                    "pr_median_ns": p["median_ns"],
                    "pr_mean_ns": p["mean_ns"],
                }
            )
            continue
        if p is None:
            criterion_entries.append(
                {
                    "full_id": full_id,
                    "verdict": "missing",
                    "baseline_median_ns": b["median_ns"],
                    "baseline_mean_ns": b["mean_ns"],
                }
            )
            continue
        base_med = b["median_ns"]
        pr_med = p["median_ns"]
        delta = (pr_med - base_med) / base_med if base_med else 0.0
        criterion_entries.append(
            {
                "full_id": full_id,
                "verdict": "info",
                "baseline_median_ns": base_med,
                "pr_median_ns": pr_med,
                "delta_pct": delta,
            }
        )

    counts = {
        "total": len(iai_entries),
        "ok": sum(1 for e in iai_entries if e["verdict"] == "ok"),
        "warn": sum(1 for e in iai_entries if e["verdict"] == "warn"),
        "fail": sum(1 for e in iai_entries if e["verdict"] == "fail"),
        "unrouted": unrouted,
        "missing_in_pr": missing_in_pr,
        "added_in_pr": added_in_pr,
    }
    counts["has_fail"] = counts["fail"] > 0 or bool(missing_in_pr)
    counts["has_warn"] = counts["warn"] > 0

    return {
        "schema_version": SCHEMA_VERSION_OUT,
        "baseline_git_rev": baseline["captured_on"]["git_rev"],
        "baseline_git_dirty": baseline["captured_on"].get("git_dirty", "unknown"),
        "pr_git_rev": pr["captured_on"]["git_rev"],
        "pr_git_dirty": pr["captured_on"].get("git_dirty", "unknown"),
        "baseline_host": {
            "cpu_model": baseline["captured_on"].get("cpu_model"),
            "kernel": baseline["captured_on"].get("kernel"),
            "rustc_version": baseline["captured_on"].get("rustc_version"),
        },
        "pr_host": {
            "cpu_model": pr["captured_on"].get("cpu_model"),
            "kernel": pr["captured_on"].get("kernel"),
            "rustc_version": pr["captured_on"].get("rustc_version"),
        },
        "entries": iai_entries,
        "criterion_entries": criterion_entries,
        "summary": counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Compare two shekyl_rust_v0 envelopes and route each "
            "iai-callgrind entry through the §3.3 threshold table."
        ),
    )
    ap.add_argument(
        "--baseline",
        required=True,
        help="Path to the baseline shekyl_rust_v0.json (bench-baseline/baseline.json in CI).",
    )
    ap.add_argument(
        "--pr",
        required=True,
        help="Path to the PR-side shekyl_rust_v0.json (captured on the same runner).",
    )
    ap.add_argument(
        "--out",
        default="-",
        help='Write the JSON report here. "-" (default) writes to stdout.',
    )
    args = ap.parse_args()

    try:
        baseline = load_envelope(args.baseline)
        pr = load_envelope(args.pr)
    except FileNotFoundError as e:
        print(f"[compare] missing input: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"[compare] invalid JSON: {e}", file=sys.stderr)
        return 2

    report = compare(baseline, pr)
    out_text = json.dumps(report, indent=2, sort_keys=False)
    if args.out == "-":
        print(out_text)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text + "\n")

    # Concise stderr summary so humans tailing CI logs get the TL;DR
    # without having to parse the JSON.
    s = report["summary"]
    print(
        f"[compare] {s['total']} iai entries: "
        f"{s['ok']} ok, {s['warn']} warn, {s['fail']} fail"
        + (f", {len(s['unrouted'])} unrouted" if s["unrouted"] else "")
        + (
            f", {len(s['missing_in_pr'])} missing in PR"
            if s["missing_in_pr"]
            else ""
        )
        + (f", {len(s['added_in_pr'])} added in PR" if s["added_in_pr"] else ""),
        file=sys.stderr,
    )

    return 1 if s["has_fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
