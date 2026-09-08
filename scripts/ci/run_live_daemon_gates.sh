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
# The accounting is the load-bearing ratchet: every ignored test is either
# ARMED or EXEMPT, so the undecided set is empty by construction.
#
# The work splits, and the split is deliberate. The per-name existence checks
# catch a gate RENAMED OR DELETED -- naming it, and saying the gate is now
# off. The identity catches one ADDED that nobody decided. Because every
# ignored test is named by one of the lists, a deletion always trips a name
# check BEFORE the arithmetic, so the identity fires in the "too many"
# direction only and its message is written for that case. Verified by
# biting it: deleting an armed gate reports the name, not a count mismatch.
#
# All of them run per-PR. There is deliberately no second membership
# splitting them by cost: these gates ARE the money and privacy surface, so
# the split would have excused the ones most worth running. A nightly tier
# would also need a route by which a human sees its reds, and `nightly.yml`
# already runs with no `if: failure` and no notification — a tier added
# without that route joins a silence, it does not get watched.

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

# Declared once. The loop iterates it and the accounting is derived from it,
# so the two cannot drift. Every name here was OBSERVED RED before it was
# added: its driver mutated so the property the gate guards is false, the
# gate watched fail, then restored. Arming without that puts a gate in the
# coverage slot while it checks nothing, which is worse than leaving it dark.
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
  engine::regtest_e2e::e2e_unbond_accepted_and_connected
  engine::regtest_e2e::e2e_drain_wire_shape_matches_a_real_transfer
  engine::regtest_e2e::e2e_staker_bond_post_accepted_and_applied
  engine::regtest_e2e::e2e_unstake_collect_retire_composed_arc
  engine::regtest_e2e::e2e_arm3_phantom_slot_collected_at_open
  engine::regtest_e2e::e2e_emission_claim_accepted_and_applied
  engine::regtest_e2e::e2e_fcmp_spend_over_depth3_tree
)

# EXEMPT: an #[ignore]d test with NO verification job — nothing it could be
# observed failing FOR. `generate_ct2_tier_b_fixture` regenerates a fixture;
# it asserts no property, so arming it would add runtime and no coverage.
# Declared rather than left implied, because "not armed" and "nothing to arm"
# are different states and only one of them is a gap.
EXEMPT=(
  engine::regtest_e2e::generate_ct2_tier_b_fixture
)

for a in "${ARMED[@]}"; do
  grep -qx "$a: test" "$ignored" || {
    echo "FATAL: armed gate '$a' names no ignored test — it was renamed or deleted, and this gate is now off" >&2
    exit 1
  }
done

# An exemption that outlived its test is not harmless: it keeps the identity
# below balancing by one, which would let one genuinely undecided gate hide
# behind it. Says what to do, because the fix is deletion, not renaming.
for e in "${EXEMPT[@]}"; do
  grep -qx "$e: test" "$ignored" || {
    echo "FATAL: exempt entry '$e' names no ignored test — the exemption outlived its test; delete the entry" >&2
    exit 1
  }
done

# A name in both lists would be run and simultaneously declared to have
# nothing to run, and the identity below would still balance — so it is
# checked here rather than inferred from the count.
for a in "${ARMED[@]}"; do
  for e in "${EXEMPT[@]}"; do
    [ "$a" != "$e" ] || {
      echo "FATAL: '$a' is both ARMED and EXEMPT — it cannot be both run and excused" >&2
      exit 1
    }
  done
done

# THE DARK SET MAY NOT GROW SILENTLY, and the ratchet is now an identity
# rather than a pinned number: every ignored test is either armed or exempt,
# so the undecided set is EMPTY by construction.
#
# The two sides come from INDEPENDENT sources — the left from the runner's
# `--list --ignored`, the right from the lists declared above — so this can
# fail when they disagree. A baseline computed as `regtest_ignored - ARMED`
# could not: its expected value would be written by the thing it audits.
accounted=$(( ${#ARMED[@]} + ${#EXEMPT[@]} ))
if [ "$regtest_ignored" -ne "$accounted" ]; then
  echo "FATAL: $regtest_ignored ignored regtest_e2e tests, but ${#ARMED[@]} armed + ${#EXEMPT[@]} exempt = $accounted." >&2
  echo "A new #[ignore]d test must be armed (observe it red first) or exempted (no verification job)." >&2
  exit 1
fi

for t in "${ARMED[@]}"; do
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
