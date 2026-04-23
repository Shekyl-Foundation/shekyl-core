#!/usr/bin/env python3
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Render a `shekyl_rust_v0_compare_v1` report (from `compare.py`) as
# a Markdown PR comment, and upsert it on the PR so re-runs replace
# the previous comment instead of stacking.
#
# The comment is deliberately compact: four sections —
#   1. TL;DR status line ("benchmarks: ok" | "warn" | "fail").
#   2. iai-callgrind delta table (gated metric: instructions).
#   3. criterion informational table (median_ns delta, no gate).
#   4. Provenance footer (baseline git_rev + host, PR git_rev + host,
#      samply-profile link placeholder).
#
# Upsert keying: the comment's first line is a stable marker —
# `<!-- shekyl-benchmarks-comment -->` — so the CI workflow can
# locate and edit an existing comment with a single `gh api`
# listing call.
#
# Usage (local render only):
#   python3 scripts/bench/post_comment.py \\
#     --report /tmp/report.json --out /tmp/comment.md
#
# Usage (CI, full upsert):
#   python3 scripts/bench/post_comment.py \\
#     --report /tmp/report.json \\
#     --repo $GITHUB_REPOSITORY --pr $PR_NUMBER \\
#     --profile-artifact-url "${PROFILE_URL:-}"
#
# The CI variant requires `gh` on PATH and a `GITHUB_TOKEN` with
# `pull-requests: write` permission in the calling workflow step.

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any


MARKER = "<!-- shekyl-benchmarks-comment -->"


def _fmt_pct(delta: float) -> str:
    # Show at most one decimal and always include the sign, because
    # "0.0%" reads very differently from "+0.0%" on a delta column.
    sign = "+" if delta >= 0 else ""
    return f"{sign}{delta * 100:.2f}%"


def _fmt_verdict_badge(verdict: str) -> str:
    return {
        "ok": "ok",
        "warn": "WARN",
        "fail": "**FAIL**",
        "unrouted": "(unrouted)",
        "info": "info",
        "added": "added",
        "missing": "**missing**",
    }.get(verdict, verdict)


def _fmt_host_line(host: dict[str, Any]) -> str:
    parts = []
    if host.get("cpu_model"):
        parts.append(host["cpu_model"].strip())
    if host.get("kernel"):
        # Shorten: first two space-separated tokens of `uname -srvmo`
        # are enough to identify the distro/kernel family.
        tokens = host["kernel"].split()
        parts.append(" ".join(tokens[:2]))
    if host.get("rustc_version"):
        parts.append(host["rustc_version"].split(" (")[0])
    return " / ".join(parts) if parts else "unknown host"


def render(report: dict[str, Any], profile_artifact_url: str | None) -> str:
    summary = report["summary"]

    if summary["has_fail"]:
        status_icon = "FAIL"
    elif summary["has_warn"]:
        status_icon = "WARN"
    else:
        status_icon = "OK"

    lines: list[str] = []
    lines.append(MARKER)
    lines.append(f"## shekyl benchmarks — `{status_icon}`")
    lines.append("")
    lines.append(
        f"- **iai-callgrind (gated, metric: `instructions`):** "
        f"{summary['total']} entries — "
        f"{summary['ok']} ok / {summary['warn']} warn / "
        f"{summary['fail']} fail"
    )

    if summary["missing_in_pr"]:
        lines.append(
            f"- **Missing in PR (treated as `fail`):** "
            f"{len(summary['missing_in_pr'])} entries — see table."
        )
    if summary["added_in_pr"]:
        lines.append(
            f"- **New in PR (informational):** "
            f"{len(summary['added_in_pr'])} entries — see table."
        )
    if summary["unrouted"]:
        lines.append(
            f"- **Unrouted (name does not start with `crypto_bench_` "
            f"or `hot_path_bench_`):** {len(summary['unrouted'])} entries — "
            f"review and rename."
        )

    lines.append("")
    lines.append(
        "> Threshold table: `crypto_bench_*` ±5% warn / ±15% fail "
        "(bidirectional); `hot_path_bench_*` +5% warn / +15% fail "
        "(slowdown-only). See "
        "[`docs/MID_REWIRE_HARDENING.md`](../../blob/dev/docs/MID_REWIRE_HARDENING.md) "
        "§3.3 and "
        "[`docs/benchmarks/README.md`](../../blob/dev/docs/benchmarks/README.md) "
        "for the full rules."
    )
    lines.append("")

    # Main iai table
    lines.append("### iai-callgrind (gated)")
    lines.append("")
    lines.append("| Verdict | Benchmark | Class | Baseline | PR | Δ |")
    lines.append("|---|---|---|---:|---:|---:|")

    # Sort: fails first (most urgent), then warns, then ok — within each
    # bucket, by absolute delta descending so the biggest swings are
    # near the top of the bucket.
    def _sort_key(e: dict[str, Any]) -> tuple[int, float]:
        rank = {"fail": 0, "warn": 1, "unrouted": 2, "ok": 3}.get(
            e["verdict"], 4
        )
        return (rank, -abs(e["delta_pct"]))

    for e in sorted(report["entries"], key=_sort_key):
        lines.append(
            f"| {_fmt_verdict_badge(e['verdict'])} "
            f"| `{e['full_id']}` "
            f"| {e['class']} "
            f"| {e['baseline']:,} "
            f"| {e['pr']:,} "
            f"| {_fmt_pct(e['delta_pct'])} |"
        )

    for fid in summary["missing_in_pr"]:
        lines.append(
            f"| {_fmt_verdict_badge('missing')} | `{fid}` | "
            f"(not in PR) | — | — | — |"
        )
    for fid in summary["added_in_pr"]:
        lines.append(
            f"| {_fmt_verdict_badge('added')} | `{fid}` | "
            f"(new) | — | — | — |"
        )

    lines.append("")

    # Criterion informational section
    crit = report.get("criterion_entries", [])
    if crit:
        lines.append("### criterion (informational, not gated)")
        lines.append("")
        lines.append("| Benchmark | Baseline median | PR median | Δ |")
        lines.append("|---|---:|---:|---:|")
        # Sort by absolute delta descending; entries without a delta
        # (added / missing) go to the bottom.
        def _csort(e: dict[str, Any]) -> tuple[int, float]:
            if e["verdict"] == "info":
                return (0, -abs(e.get("delta_pct", 0.0)))
            return (1, 0.0)

        for e in sorted(crit, key=_csort):
            if e["verdict"] == "info":
                bm = e["baseline_median_ns"]
                pm = e["pr_median_ns"]
                lines.append(
                    f"| `{e['full_id']}` "
                    f"| {bm / 1_000:.2f} µs "
                    f"| {pm / 1_000:.2f} µs "
                    f"| {_fmt_pct(e['delta_pct'])} |"
                )
            elif e["verdict"] == "added":
                lines.append(
                    f"| `{e['full_id']}` | — | {e['pr_median_ns'] / 1_000:.2f} µs "
                    f"| **added** |"
                )
            elif e["verdict"] == "missing":
                lines.append(
                    f"| `{e['full_id']}` | {e['baseline_median_ns'] / 1_000:.2f} µs "
                    f"| — | **missing** |"
                )
        lines.append("")
        lines.append(
            "_Criterion wall-clock numbers drift with CPU frequency "
            "scaling, thermal throttling, and runner-load noise — "
            "treat Δ as a hint, not a signal. The Tier-2 upgrade that "
            "makes these gate-worthy (dedicated runner + pinned CPU) "
            "is tracked in `docs/MID_REWIRE_HARDENING.md` §6.1._"
        )
        lines.append("")

    # Profile-on-fail link
    if profile_artifact_url:
        lines.append(
            f"**samply profile on fail:** [{profile_artifact_url}]"
            f"({profile_artifact_url})"
        )
        lines.append("")

    # Provenance footer
    lines.append("### Provenance")
    lines.append("")
    lines.append(
        f"- **Baseline:** `{report['baseline_git_rev']}` "
        f"({report.get('baseline_git_dirty', 'unknown')})  \n"
        f"  Host: {_fmt_host_line(report['baseline_host'])}"
    )
    lines.append(
        f"- **PR head:** `{report['pr_git_rev']}` "
        f"({report.get('pr_git_dirty', 'unknown')})  \n"
        f"  Host: {_fmt_host_line(report['pr_host'])}"
    )

    return "\n".join(lines) + "\n"


def find_existing_comment(repo: str, pr: int) -> int | None:
    """Return comment id of a prior benchmarks comment on this PR, or None."""
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/issues/{pr}/comments", "--paginate"],
        check=True,
        capture_output=True,
        text=True,
    )
    comments = json.loads(result.stdout)
    for c in comments:
        body = c.get("body") or ""
        if body.startswith(MARKER):
            return c["id"]
    return None


def upsert_comment(repo: str, pr: int, body: str) -> None:
    existing = find_existing_comment(repo, pr)
    # `gh api` with -f reads raw values; use --input for bodies so we
    # do not have to escape newlines/backticks.
    payload = json.dumps({"body": body})
    if existing is None:
        subprocess.run(
            [
                "gh",
                "api",
                "--method",
                "POST",
                f"repos/{repo}/issues/{pr}/comments",
                "--input",
                "-",
            ],
            input=payload,
            check=True,
            text=True,
        )
        print(f"[post_comment] created new comment on {repo}#{pr}", file=sys.stderr)
    else:
        subprocess.run(
            [
                "gh",
                "api",
                "--method",
                "PATCH",
                f"repos/{repo}/issues/comments/{existing}",
                "--input",
                "-",
            ],
            input=payload,
            check=True,
            text=True,
        )
        print(
            f"[post_comment] updated comment {existing} on {repo}#{pr}",
            file=sys.stderr,
        )


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Render a benchmarks compare report as a Markdown PR comment "
            "and upsert it on the PR."
        ),
    )
    ap.add_argument("--report", required=True, help="Path to compare.py JSON output.")
    ap.add_argument(
        "--out",
        default=None,
        help="Write rendered Markdown to this file (optional; implies no posting).",
    )
    ap.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="owner/name (defaults to $GITHUB_REPOSITORY).",
    )
    ap.add_argument(
        "--pr",
        type=int,
        default=None,
        help="PR number. If omitted and --out is not given, prints Markdown to stdout.",
    )
    ap.add_argument(
        "--profile-artifact-url",
        default=None,
        help="Optional samply profile artifact URL, inserted into the comment.",
    )
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8") as f:
        report = json.load(f)

    if report.get("schema_version") != "shekyl_rust_v0_compare_v1":
        print(
            f"[post_comment] unexpected schema_version "
            f"{report.get('schema_version')!r}",
            file=sys.stderr,
        )
        return 2

    body = render(report, args.profile_artifact_url)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"[post_comment] wrote {args.out}", file=sys.stderr)

    if args.pr is not None:
        if not args.repo:
            print(
                "[post_comment] --pr requires --repo (or $GITHUB_REPOSITORY).",
                file=sys.stderr,
            )
            return 2
        upsert_comment(args.repo, args.pr, body)
    elif args.out is None:
        # No --out, no --pr: just dump the rendered Markdown so a
        # human running the script locally sees something useful.
        sys.stdout.write(body)

    return 0


if __name__ == "__main__":
    sys.exit(main())
