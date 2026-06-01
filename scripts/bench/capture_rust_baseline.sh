#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Capture the Rust wallet-state benchmark baseline on the current machine.
# Intended to run on a reference machine with consistent toolchain, quiet
# background workload, and stable CPU frequency scaling.
#
# Outputs (all overwritten atomically at the end):
#   docs/benchmarks/shekyl_rust_v0.json           structured envelope
#   docs/benchmarks/shekyl_rust_v0.iai.snapshot   raw iai-callgrind stdout
#
# This script is run by humans, not CI. The CI workflow (commit 3.3)
# runs a similar capture path optimized for per-PR comparison; this
# one is the authoritative rolling-baseline source and is the sibling
# of `capture_cpp_baseline.sh`.
#
# Requires:
#   - rustup-managed toolchain (see rust-toolchain.toml)
#   - valgrind (>= 3.22 recommended) on PATH
#   - iai-callgrind-runner on PATH (cargo install iai-callgrind-runner)
#   - python3 (for JSON assembly; jq-only would be painful given the
#     iai-callgrind stdout parse)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUST_ROOT="${REPO_ROOT}/rust"

OUT_JSON="${OUT_JSON:-${REPO_ROOT}/docs/benchmarks/shekyl_rust_v0.json}"
OUT_IAI_SNAP="${OUT_IAI_SNAP:-${REPO_ROOT}/docs/benchmarks/shekyl_rust_v0.iai.snapshot}"

echo "[capture_rust_baseline] repo root    : ${REPO_ROOT}"
echo "[capture_rust_baseline] rust root    : ${RUST_ROOT}"
echo "[capture_rust_baseline] json output  : ${OUT_JSON}"
echo "[capture_rust_baseline] iai snapshot : ${OUT_IAI_SNAP}"

# ---- preflight -------------------------------------------------------------

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[capture_rust_baseline] ERROR: missing required tool: $1" >&2
    exit 1
  fi
}
need cargo
need valgrind
need iai-callgrind-runner
need python3

# ---- benches: crate : criterion-target : iai-callgrind-target [: features] -
#
# Row format is `:`-delimited:
#
#   <crate> : <criterion-bench> : <iai-bench> [ : <cargo-features> ]
#
# The optional fourth field is a comma-separated list of cargo
# features to enable for both `cargo bench` invocations of that row;
# leave it empty (or omit the trailing colon) when no features are
# required. This lets bench targets gated on `required-features` (e.g.
# `bench-internals`-only fixtures that need access to otherwise
# `pub(crate)` state-injection helpers) participate in the rolling
# baseline without expanding production visibility.
#
# Order matters only for human readability in the JSON envelope and
# the iai snapshot; the script treats each row as self-contained.
#
# The first five rows are the original mid-rewire-hardening pass
# (`docs/MID_REWIRE_HARDENING.md` §3.2 / §3.3); the trailing
# `engine_trait_bench_*` rows are the V3 engine trait spec §3.3.1
# measurement gate, added by Stage 0 PR-2 per
# `docs/design/STAGE_0_HARNESS.md` §4.6. Stage 1 per-trait PRs append
# their own rows here as each deferred bench is introduced.

BENCHES=(
  "shekyl-engine-state:ledger:ledger_iai"
  "shekyl-engine-state:balance:balance_iai"
  "shekyl-engine-file:open:open_iai"
  "shekyl-scanner:scan_block:scan_block_iai"
  "shekyl-tx-builder:transfer_e2e:transfer_e2e_iai"
  "shekyl-engine-core:engine_trait_bench_ledger_synced_height:engine_trait_bench_ledger_synced_height_iai"
  "shekyl-engine-core:engine_trait_bench_ledger_balance:engine_trait_bench_ledger_balance_iai:bench-internals"
  # Stage 2 §5.3 B9. The dispatch row's criterion target carries all
  # three IDs (baseline_claim_mine / actor_claim_mine /
  # actor_claim_not_mine); its iai sibling measures the deterministic
  # crypto baseline only (the actor `ask` paths are criterion-only by
  # design — a cross-thread async round-trip has no deterministic
  # Callgrind signal). The merge-path row is a full criterion+iai pair
  # (the 6-i projection is synchronous + runtime-free).
  "shekyl-engine-core:engine_trait_bench_key_dispatch:engine_trait_bench_key_dispatch_baseline_iai:bench-internals"
  "shekyl-engine-core:engine_trait_bench_key_merge_projection:engine_trait_bench_key_merge_projection_iai:bench-internals"
)

# Clean criterion output so the envelope reflects this run only.
# iai-callgrind output is regenerated on every run; no cleanup needed.
rm -rf "${RUST_ROOT}/target/criterion"

# ---- criterion runs (wall-clock, Tier-2) -----------------------------------

for row in "${BENCHES[@]}"; do
  IFS=':' read -r CRATE CRIT_BENCH IAI_BENCH FEATURES <<<"${row}"
  FEATURE_ARGS=()
  if [[ -n "${FEATURES:-}" ]]; then
    FEATURE_ARGS=(--features "${FEATURES}")
  fi
  echo
  echo "[capture_rust_baseline] criterion : ${CRATE}::${CRIT_BENCH}${FEATURES:+ (features=${FEATURES})}"
  (
    cd "${RUST_ROOT}"
    cargo bench -p "${CRATE}" "${FEATURE_ARGS[@]}" --bench "${CRIT_BENCH}" -- --noplot
  )
done

# ---- iai-callgrind runs (instruction counts, Tier-1) -----------------------

IAI_STDOUT_TMP="$(mktemp)"
trap 'rm -f "${IAI_STDOUT_TMP}"' EXIT

for row in "${BENCHES[@]}"; do
  IFS=':' read -r CRATE CRIT_BENCH IAI_BENCH FEATURES <<<"${row}"
  FEATURE_ARGS=()
  if [[ -n "${FEATURES:-}" ]]; then
    FEATURE_ARGS=(--features "${FEATURES}")
  fi
  echo
  echo "[capture_rust_baseline] iai       : ${CRATE}::${IAI_BENCH}${FEATURES:+ (features=${FEATURES})}"
  {
    printf '\n==== %s::%s ====\n' "${CRATE}" "${IAI_BENCH}"
    (
      cd "${RUST_ROOT}"
      # iai-callgrind colors its output. Disabling via env keeps the
      # snapshot and the parser input plain-text.
      IAI_CALLGRIND_COLOR=never \
        cargo bench -p "${CRATE}" "${FEATURE_ARGS[@]}" --bench "${IAI_BENCH}"
    )
  } | tee -a "${IAI_STDOUT_TMP}"
done

# ---- host manifest ---------------------------------------------------------

GIT_REV="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
GIT_DIRTY="$(git -C "${REPO_ROOT}" diff --quiet 2>/dev/null && echo 'clean' || echo 'dirty')"
KERNEL="$(uname -srvmo)"
CPU_MODEL="$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo 'unknown')"
RUSTC_VER="$(rustc --version 2>/dev/null || echo 'unknown')"
CARGO_VER="$(cargo --version 2>/dev/null || echo 'unknown')"
VALGRIND_VER="$(valgrind --version 2>/dev/null || echo 'unknown')"
# `iai-callgrind-runner --version` exits 1 when the lib-side version is
# not embedded as a protocol handshake (see iai-callgrind CLI entry), so
# we use `cargo install --list` as the authoritative source for the
# installed runner version. Fall back to the runner's own error line
# (which does spell out its version) and finally to "unknown".
IAI_RUNNER_VER="$(cargo install --list 2>/dev/null \
    | awk '/^iai-callgrind-runner / {sub(/:$/, "", $2); print $2; exit}')"
if [[ -z "${IAI_RUNNER_VER}" ]]; then
    IAI_RUNNER_VER="$(iai-callgrind-runner --version 2>&1 \
        | sed -n 's/.*iai-callgrind-runner (\([^)]*\)).*/\1/p' \
        | head -n1)"
fi
IAI_RUNNER_VER="${IAI_RUNNER_VER:-unknown}"

# Commit the raw iai snapshot before JSON assembly so a downstream
# failure still leaves a useful text artifact on disk.
mkdir -p "$(dirname "${OUT_IAI_SNAP}")"
cp "${IAI_STDOUT_TMP}" "${OUT_IAI_SNAP}"
echo
echo "[capture_rust_baseline] wrote ${OUT_IAI_SNAP}"

# ---- JSON envelope (python3) -----------------------------------------------

export RUST_ROOT IAI_STDOUT_TMP OUT_JSON \
  GIT_REV GIT_DIRTY KERNEL CPU_MODEL \
  RUSTC_VER CARGO_VER VALGRIND_VER IAI_RUNNER_VER

python3 - <<'PY'
import json
import os
import pathlib
import re
import sys

rust_root = pathlib.Path(os.environ["RUST_ROOT"])
iai_stdout_path = pathlib.Path(os.environ["IAI_STDOUT_TMP"])
out_json = pathlib.Path(os.environ["OUT_JSON"])

# ── 1. Collect criterion estimates from target/criterion/ ──────────────────
#
# Structure (for grouped benches): target/criterion/<group>/<params>/new/
#                                  ├─ benchmark.json   # group_id, value_str, throughput
#                                  └─ estimates.json   # mean/median/std_dev
# For ungrouped benches with a function_id and no value_str, the path is
# target/criterion/<group>/<function_id>/new/ etc.

criterion_root = rust_root / "target" / "criterion"
criterion_entries = []
if criterion_root.exists():
    for benchmark_json in sorted(criterion_root.rglob("new/benchmark.json")):
        estimates_json = benchmark_json.with_name("estimates.json")
        if not estimates_json.exists():
            continue
        try:
            meta = json.loads(benchmark_json.read_text())
            est = json.loads(estimates_json.read_text())
        except json.JSONDecodeError as exc:
            print(f"[capture_rust_baseline] warning: skipping "
                  f"{benchmark_json}: {exc}", file=sys.stderr)
            continue
        entry = {
            "group_id": meta.get("group_id"),
            "function_id": meta.get("function_id"),
            "value_str": meta.get("value_str"),
            "full_id": meta.get("full_id"),
            "throughput": meta.get("throughput"),
            "mean_ns": est.get("mean", {}).get("point_estimate"),
            "median_ns": est.get("median", {}).get("point_estimate"),
            "std_dev_ns": est.get("std_dev", {}).get("point_estimate"),
            "median_abs_dev_ns":
                est.get("median_abs_dev", {}).get("point_estimate"),
        }
        criterion_entries.append(entry)

# ── 2. Parse iai-callgrind stdout ─────────────────────────────────────────
#
# Sections are separated by our own `==== <crate>::<bench> ====` markers
# so we know which crate owns each iai entry. Within a section:
#
#   <bench_binary>::<group>::<function> <run_id>:<setup>
#     Instructions:    <n>|...
#     L1 Hits:         <n>|...
#     LL Hits:         <n>|...
#     RAM Hits:        <n>|...
#     Total read+write:<n>|...
#     Estimated Cycles:<n>|...

iai_text = iai_stdout_path.read_text(errors="replace")
# Defensive ANSI strip: even with IAI_CALLGRIND_COLOR=never, nothing on
# PATH should be coloring; this keeps the parser robust.
iai_text = re.sub(r"\x1b\[[0-9;]*m", "", iai_text)

section_marker = re.compile(
    r"^==== (?P<crate>[\w-]+)::(?P<bench>[\w_]+) ====$", re.MULTILINE)
header_re = re.compile(
    r"^(?P<bin>[A-Za-z_][\w]*)::(?P<group>[A-Za-z_][\w]*)::"
    r"(?P<function>[A-Za-z_][\w]*)\s+(?P<run_id>[^:\s]+):(?P<setup>.+)$")
metric_re = re.compile(
    r"^\s{2}(?P<name>[A-Za-z][A-Za-z0-9+ ]*?):\s+(?P<value>\d+)\|")

metric_key_map = {
    "Instructions": "instructions",
    "L1 Hits": "l1_hits",
    "LL Hits": "ll_hits",
    "RAM Hits": "ram_hits",
    "Total read+write": "total_read_write",
    "Estimated Cycles": "estimated_cycles",
}

iai_entries = []

# Slice the text into (crate, bench, section_body) tuples.
section_starts = [(m.start(), m.group("crate"), m.group("bench"))
                  for m in section_marker.finditer(iai_text)]
section_starts.append((len(iai_text), None, None))
for i in range(len(section_starts) - 1):
    body_start, crate, bench = section_starts[i]
    body_end = section_starts[i + 1][0]
    body = iai_text[body_start:body_end]
    current = None
    for line in body.splitlines():
        hm = header_re.match(line)
        if hm is not None:
            if current is not None:
                iai_entries.append(current)
            current = {
                "crate": crate,
                "bench_target": bench,
                "bin": hm.group("bin"),
                "group": hm.group("group"),
                "function": hm.group("function"),
                "run_id": hm.group("run_id"),
                "setup": hm.group("setup").strip(),
                "metrics": {},
            }
            continue
        mm = metric_re.match(line)
        if mm is not None and current is not None:
            key = metric_key_map.get(mm.group("name").strip())
            if key is not None:
                current["metrics"][key] = int(mm.group("value"))
    if current is not None:
        iai_entries.append(current)

# ── 3. Producer-side capture guard ────────────────────────────────────────
#
# Reject captures with `instructions == 0` rows before they are
# written to the canonical `shekyl_rust_v0.json` path. Such rows have
# been observed (2026-05-09; see
# `docs/investigation/2026-05-09-bench-baseline-flake.md`) on
# GitHub-hosted ubuntu-latest runners with no causal code change and
# iai-callgrind's own run summary reporting "N without regressions".
# Root cause is unknown; what is known is that committing the
# resulting envelope to the `bench-baseline` branch persists the
# corruption across every subsequent PR's compare run, and that
# rerunning the workflow typically succeeds.
#
# The guard runs after `iai_entries` is fully assembled and BEFORE
# the canonical OUT_JSON is written, so a flaked capture leaves the
# previous (good) bench-baseline content untouched. The raw stdout
# snapshot at OUT_IAI_SNAP was already written above and is
# preserved as evidence regardless.
#
# A diagnostic side-file is written at OUT_JSON + ".flake.json" so
# investigators can `git fetch` the artifact / inspect locally
# without re-running the harness. The flake side-file is
# deliberately not the canonical OUT_JSON path because the rest of
# the pipeline (artifact upload, bench-baseline push, compare.py)
# treats OUT_JSON as authoritative; emitting the bad data there
# would defeat the guard.
#
# Bypass: set `SHEKYL_BENCH_ALLOW_ZERO=1` to skip the check (intended
# only for local debugging of the capture-zero phenomenon itself).
# CI workflows must not set this.

zero_entries = [
    e for e in iai_entries
    if e.get("metrics", {}).get("instructions", -1) == 0
]
allow_zero = os.environ.get("SHEKYL_BENCH_ALLOW_ZERO", "") == "1"

if zero_entries and not allow_zero:
    flake_path = pathlib.Path(str(out_json) + ".flake.json")
    flake_envelope = {
        "schema_version": "shekyl_rust_v0",
        "captured_on": {
            "git_rev": os.environ["GIT_REV"],
            "git_dirty": os.environ["GIT_DIRTY"],
            "kernel": os.environ["KERNEL"],
            "cpu_model": os.environ["CPU_MODEL"],
            "rustc_version": os.environ["RUSTC_VER"],
            "cargo_version": os.environ["CARGO_VER"],
            "valgrind_version": os.environ["VALGRIND_VER"],
            "iai_callgrind_runner_version": os.environ["IAI_RUNNER_VER"],
        },
        "criterion": criterion_entries,
        "iai_callgrind": iai_entries,
        "flake": {
            "kind": "instructions_zero",
            "zero_count": len(zero_entries),
            "zero_entries": [
                {
                    "crate": e.get("crate"),
                    "bench_target": e.get("bench_target"),
                    "group": e.get("group"),
                    "function": e.get("function"),
                    "run_id": e.get("run_id"),
                }
                for e in zero_entries
            ],
        },
    }
    flake_path.parent.mkdir(parents=True, exist_ok=True)
    flake_path.write_text(json.dumps(flake_envelope, indent=2) + "\n",
                          encoding="utf-8")

    print(
        f"[capture_rust_baseline] REJECTED: {len(zero_entries)} of "
        f"{len(iai_entries)} iai entries reported instructions=0",
        file=sys.stderr,
    )
    for e in zero_entries:
        print(
            f"[capture_rust_baseline]   zero: "
            f"{e.get('crate')}/{e.get('bench_target')}/"
            f"{e.get('group')}/{e.get('function')}/{e.get('run_id')}",
            file=sys.stderr,
        )
    print(
        f"[capture_rust_baseline] canonical {out_json.name} NOT written; "
        f"diagnostic envelope at {flake_path}",
        file=sys.stderr,
    )
    print(
        "[capture_rust_baseline] this is a known transient capture "
        "anomaly; rerun the workflow to retry. Investigation: "
        "docs/investigation/2026-05-09-bench-baseline-flake.md",
        file=sys.stderr,
    )
    sys.exit(2)

if zero_entries and allow_zero:
    print(
        f"[capture_rust_baseline] WARNING: {len(zero_entries)} iai "
        f"entries reported instructions=0; SHEKYL_BENCH_ALLOW_ZERO=1 "
        f"is set, proceeding anyway (CI must not set this)",
        file=sys.stderr,
    )

# ── 4. Envelope ───────────────────────────────────────────────────────────

envelope = {
    "schema_version": "shekyl_rust_v0",
    "captured_on": {
        "git_rev": os.environ["GIT_REV"],
        "git_dirty": os.environ["GIT_DIRTY"],
        "kernel": os.environ["KERNEL"],
        "cpu_model": os.environ["CPU_MODEL"],
        "rustc_version": os.environ["RUSTC_VER"],
        "cargo_version": os.environ["CARGO_VER"],
        "valgrind_version": os.environ["VALGRIND_VER"],
        "iai_callgrind_runner_version": os.environ["IAI_RUNNER_VER"],
    },
    "criterion": criterion_entries,
    "iai_callgrind": iai_entries,
}

out_json.parent.mkdir(parents=True, exist_ok=True)
out_json.write_text(json.dumps(envelope, indent=2) + "\n",
                    encoding="utf-8")
print(f"[capture_rust_baseline] wrote {out_json}")
print(f"[capture_rust_baseline]   criterion entries: {len(criterion_entries)}")
print(f"[capture_rust_baseline]   iai entries      : {len(iai_entries)}")
PY

echo
echo "[capture_rust_baseline] done. Review the numbers, then commit the"
echo "[capture_rust_baseline] JSON + snapshot as a follow-up to the harness"
echo "[capture_rust_baseline] commit. Do not commit baselines captured on"
echo "[capture_rust_baseline] a laptop running other workloads; they are"
echo "[capture_rust_baseline] misleading."
