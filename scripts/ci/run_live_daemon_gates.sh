#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Armed #[ignore]d regtest_e2e gates against a live shekyld.
#
# Invoked from .github/workflows/build.yml after the daemon is built. The
# script locates the repo from its own path, so SHEKYLD_BIN resolves inside
# the job container (where github.workspace is the host path, not this tree).
#
# A gate belongs on ARMED only once it has been OBSERVED FAILING for the
# reason it exists. `cargo test --exact` on a moved name exits 0 with
# "0 passed", so a rename would otherwise turn a gate off silently.
#
# Enumeration is `cargo test -- --list --ignored`, the runner's own answer.
# A grep over source counts `#[ignore]` written in doc comments too
# (21 lines, 17 attributes) and would silently disagree with the runner.
#
# The accounting is the load-bearing ratchet: every ignored test is on
# exactly one of the three lists below (ARMED, ARMED_SLOW, DECIDED_DARK),
# so the undecided set is empty by construction.
#
# The work splits, and the split is deliberate. The per-name existence checks
# catch a gate RENAMED OR DELETED -- naming it, and saying the gate is now
# off. The identity catches one ADDED that nobody decided. Because every
# ignored test is named by one of the lists, a deletion always trips a name
# check BEFORE the arithmetic, so the identity fires in the "too many"
# direction only and its message is written for that case. Verified by
# biting it: deleting an armed gate reports the name, not a count mismatch.
#
# Two lanes share this script (GATE_LANE, default "pr"):
#   pr    — ARMED, per-PR in build.yml (each gate <= ~3.5 min, measured
#           2026-09-08 local Release; sum ~20 min).
#   slow  — ARMED_SLOW, the nightly live-daemon workflow (depth-3 spend
#           780 s + emission claim 1122 s measured 2026-09-08 local
#           Release — too heavy per-PR, still consensus gates).
# Both lanes name-check ALL lists, so a rename is caught in every run.
#
# PR #660 ruled against a cost tier on the grounds that a nightly tier
# without a route by which a human sees its reds joins a silence. That
# named criterion is met here: nightly-live-daemon-slow.yml opens (or
# comments on) a tracking issue on failure, so a slow-lane red is pushed
# at a human rather than waiting to be noticed. If that notification step
# is ever removed, the split loses its justification and the slow pair
# moves back to ARMED.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

export SHEKYLD_BIN="${SHEKYLD_BIN:-$REPO_ROOT/build/bin/shekyld}"
test -x "$SHEKYLD_BIN" || {
  echo "FATAL: no shekyld at $SHEKYLD_BIN" >&2
  exit 1
}

cd rust

ignored="$(mktemp)"
gate_log="$(mktemp)"
trap 'rm -f "$ignored" "$gate_log"' EXIT

# Redirected, not piped: a pipeline's status is the last command's, so
# `| tee` would swallow cargo's verdict.
cargo test -p shekyl-engine-core --lib -- --list --ignored >"$ignored" 2>&1

# `grep -c` exits 1 on zero matches, which `set -e` would turn into a
# bare abort with no message — and zero matches is exactly the case this
# must report, not die on (rule 47: assert your own subject).
# Checked FIRST: if the enumeration is empty every name below looks
# renamed, and the gate would blame seventeen tests for one broken command.
regtest_ignored=$(grep -c '^engine::regtest_e2e::.*: test$' "$ignored" || true)
[ "${regtest_ignored:-0}" -gt 0 ] || {
  echo "FATAL: enumerated no regtest_e2e ignored tests — the module moved or the enumeration broke" >&2
  exit 1
}

# Declared once. The lane loop iterates one list and the undecided count is
# derived from all three, so they cannot drift.
#
# Every armed gate carries its red observation (the date it was seen failing
# for its own reason — a doc'd historical red or a 2026-09-08 sabotage run
# that inverted the gate's subject assertion and watched it panic there):
#   restricted_listener / ported_console / ported_p2p / native_handlers /
#     e2e_fcmp_spend_accepted_by_daemon — pre-existing (armed 2026-09-07;
#     the north-star also failed red in CI 2026-09-08, PR #656).
#   regtest_daemon_spawns_and_mines_to_wallet_address — sabotage 2026-09-08.
#   e2e_get_curve_tree_path_returns_valid_path — historical red: 404 on the
#     Axum transport before the route registration (its doc comment).
#   e2e_refresh_scans_coinbase_balance — historical red: RpcError::
#     InvalidNode("invalid block") before the shekyl-wire parse migration.
#   e2e_trim_curve_tree_restores_grow_root — sabotage 2026-09-08.
#   e2e_staker_bond_post_accepted_and_applied — historical red: the PR-4a
#     daemon-gap tripwire pinned the unimplemented-arm Malformed refusal.
#   e2e_drain_wire_shape_matches_a_real_transfer — sabotage 2026-09-08.
#   e2e_release_accepted_and_connected — sabotage 2026-09-08 (as
#     e2e_unbond_accepted_and_connected, pre Unbond→Release rename).
#   e2e_unstake_collect_retire_composed_arc — sabotage 2026-09-08.
#   e2e_arm3_phantom_slot_collected_at_open — sabotage 2026-09-08.
#   e2e_fcmp_spend_over_depth3_tree (slow) — historical red: CurveTreeIngest
#     root mismatch pre-fix, confirmed 2026-06-27 (its doc comment).
#   e2e_emission_claim_accepted_and_applied (slow) — sabotage 2026-09-08.
ARMED=(
  engine::regtest_e2e::restricted_listener_applies_request_caps_through_the_ffi_bridge
  engine::regtest_e2e::ported_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::ported_p2p_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::native_handlers_apply_their_own_request_caps
  engine::regtest_e2e::e2e_fcmp_spend_accepted_by_daemon
  engine::regtest_e2e::regtest_daemon_spawns_and_mines_to_wallet_address
  engine::regtest_e2e::e2e_get_curve_tree_path_returns_valid_path
  engine::regtest_e2e::e2e_refresh_scans_coinbase_balance
  engine::regtest_e2e::e2e_trim_curve_tree_restores_grow_root
  engine::regtest_e2e::e2e_staker_bond_post_accepted_and_applied
  engine::regtest_e2e::e2e_drain_wire_shape_matches_a_real_transfer
  engine::regtest_e2e::e2e_release_accepted_and_connected
  engine::regtest_e2e::e2e_unstake_collect_retire_composed_arc
  engine::regtest_e2e::e2e_arm3_phantom_slot_collected_at_open
)

# Consensus gates too heavy for the per-PR lane (13 + 19 min measured):
# the nightly live-daemon workflow runs these with GATE_LANE=slow.
ARMED_SLOW=(
  engine::regtest_e2e::e2e_fcmp_spend_over_depth3_tree
  engine::regtest_e2e::e2e_emission_claim_accepted_and_applied
)

# Deliberately never run here, with the reason recorded (rule 23: a decided
# disposition leaves a grep surface). Removing or renaming one fails the
# name-check below, so the decision cannot rot silently.
#   generate_ct2_tier_b_fixture — fixture regenerator, not a pass/fail
#     proposition; run manually when the CT-2 Tier-B scenarios change.
DECIDED_DARK=(
  engine::regtest_e2e::generate_ct2_tier_b_fixture
)

for a in "${ARMED[@]}" "${ARMED_SLOW[@]}" "${DECIDED_DARK[@]}"; do
  grep -qx "$a: test" "$ignored" || {
    echo "FATAL: listed gate '$a' names no ignored test — it was renamed or deleted, and its disposition is now dangling" >&2
    exit 1
  }
done

# A name REPEATED inside one list — or appearing on two lists — is the hole
# the identity cannot see: the count below sums list LENGTHS, so a duplicate
# inflates the total by one and a genuinely undecided gate balances against
# it and stays dark. Confirmed by biting it (PR #660) — an extra ARMED line
# plus one new #[ignore]d test passed every check and ran the loop.
#
# Rejected rather than de-duplicated. Silently collapsing the repeat would
# fix the arithmetic and keep the defect: a duplicated ARMED entry also runs
# its gate twice, and on this step that is minutes of CI spent re-proving one
# result; a name on two run lanes is run twice across lanes the same way.
# The name is the thing to delete, so the message says so.
repeated=$(printf '%s\n' "${ARMED[@]}" "${ARMED_SLOW[@]}" "${DECIDED_DARK[@]}" | sort | uniq -d)
[ -z "$repeated" ] || {
  echo "FATAL: repeated across ARMED/ARMED_SLOW/DECIDED_DARK: $(printf '%s' "$repeated" | tr '\n' ' ')" >&2
  echo "A repeat inflates the accounting by one and lets an undecided gate balance against it; delete the duplicate line." >&2
  exit 1
}

# THE DARK SET MAY NOT GROW SILENTLY, and the ratchet is an identity rather
# than a pinned number: every ignored test is armed, scheduled slow, or
# decided dark, so the undecided set is EMPTY by construction.
#
# The two sides come from INDEPENDENT sources — the left from the runner's
# `--list --ignored`, the right from the lists declared above — so this can
# fail when they disagree. A baseline computed as `regtest_ignored - ARMED`
# could not: its expected value would be written by the thing it audits.
#
# It sums list LENGTHS, which equals the number of distinct names only
# because the repeat check above rejects duplicates. That check is
# load-bearing for this arithmetic, not housekeeping.
accounted=$(( ${#ARMED[@]} + ${#ARMED_SLOW[@]} + ${#DECIDED_DARK[@]} ))
if [ "$regtest_ignored" -ne "$accounted" ]; then
  echo "FATAL: $regtest_ignored ignored regtest_e2e tests, but ${#ARMED[@]} armed + ${#ARMED_SLOW[@]} slow + ${#DECIDED_DARK[@]} dark = $accounted." >&2
  echo "A new #[ignore]d test must be armed (observe it red first), added to ARMED_SLOW, or decided dark with its reason recorded here." >&2
  exit 1
fi

GATE_LANE="${GATE_LANE:-pr}"
case "$GATE_LANE" in
  pr) LANE_GATES=("${ARMED[@]}") ;;
  slow) LANE_GATES=("${ARMED_SLOW[@]}") ;;
  *)
    echo "FATAL: unknown GATE_LANE '$GATE_LANE' (expected 'pr' or 'slow')" >&2
    exit 1
    ;;
esac

for t in "${LANE_GATES[@]}"; do
  set +e
  cargo test -p shekyl-engine-core --lib "$t" \
    -- --ignored --exact --nocapture >"$gate_log" 2>&1
  status=$?
  set -e
  cat "$gate_log"
  if [ "$status" -ne 0 ]; then
    echo "FATAL: $t failed" >&2
    exit "$status"
  fi
  grep -qE '^test result: ok\. 1 passed' "$gate_log" || {
    echo "FATAL: $t selected no test — the filter or the name moved" >&2
    exit 1
  }
done
