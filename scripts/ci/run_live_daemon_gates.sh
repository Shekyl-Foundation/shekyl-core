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
#           780 s measured 2026-09-08 local Release, and the two slice-7
#           gates — too heavy per-PR, still consensus gates; four bonded
#           walks since the DRS-X flip, two of which close and price an
#           archival shard with real spends before they stake). The
#           emission-claim walk is DECIDED_DARK: its serve-credit lever
#           went with the C++ chain.
# Both lanes name-check ALL lists, so a rename is caught in every run.
#
# PR #660 ruled against a cost tier on the grounds that a nightly tier
# without a route by which a human sees its reds joins a silence. That
# named criterion is met here: nightly-live-daemon-slow.yml opens (or
# comments on) a tracking issue on failure, so a slow-lane red is pushed
# at a human rather than waiting to be noticed. If that notification step
# is ever removed, the split loses its justification and the slow gates
# move back to ARMED.

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
#   e2e_fcmp_spend_reorg_restores_pool_and_fee — sabotage 2026-09-23:
#     fee-delta expected value dropped `+ txn_fee`; panicked at the mined
#     sum (8455500000) against the pre-mine sum (0).
#   regtest_daemon_spawns_and_mines_to_wallet_address — sabotage 2026-09-08.
#   e2e_refresh_scans_coinbase_balance — historical red: RpcError::
#     InvalidNode("invalid block") before the shekyl-wire parse migration.
#   e2e_trim_curve_tree_restores_grow_root — sabotage 2026-09-08.
#   e2e_arm3_phantom_slot_collected_at_open — sabotage 2026-09-08.
#     Stays armed: it persists a bond locally and never broadcasts one.
#   jsonrpc_we_carries_handler_status_through_the_result_envelope — the
#     result-envelope leg split out of restricted_listener_* by PR #782;
#     sabotage 2026-09-18 (envelope pointer inverted, panicked there).
#   get_output_histogram_stays_unrouted — PR #782's deletion falsifier
#     (SOK-Q3): red by construction on any tree that routes the method
#     (dev at 8494f2a27 does); sabotage 2026-09-18 (expected message
#     inverted, panicked there).
#   restricted_listener_is_withheld_status_and_capped_by_native_handlers — the
#     gate armed 2026-09-07 as restricted_listener_applies_request_caps_
#     through_the_ffi_bridge, renamed in RK-5c commit 4 when its last leg
#     (/get_info) went native and it stopped saying anything about the
#     bridge. Sabotage 2026-10-10, daemon rebuilt: the listener's posture
#     mapped to full disclosure for every caller; panicked at "each listener
#     must say which it is".
#   get_info_console_commands_answer_on_the_in_process_arm — RK-5c commit
#     4: status, diff, version and print_pool_stats on the daemon's own
#     console. Sabotage 2026-10-10, daemon rebuilt: `diff` cut off from the
#     native method; panicked at "the in-process diff must name the live
#     tip" after `status` had passed.
#   restricted_listener_hides_a_transaction_this_node_has_not_broadcast —
#     the origin guard anchored on include_sensitive (RK-5c commit 1), two
#     daemons. Sabotage 2026-10-09, twice, each rebuilding the daemon:
#     dispatch_json passing nullptr for the origin panicked naming the three
#     bridged pool routes and not the native one; the native
#     /get_transactions handler passing `true` for the flag panicked naming
#     that route alone. ~77 s measured, local Release daemon.
#   a_dialing_node_hands_its_tip_to_the_peer_it_dials — DX-Q2 item 5 (the
#     design review's M2): a restarted node's first outbound handshake
#     carries the tip it read from its store. Two daemons, one restart.
#     Red check seen 2026-10-29 (the flip's owner, local debug build) with
#     the tip forwarder disabled in shekyl-node: "the restarted A never
#     handed B its tip: after 90s: fresh incoming connections on B: []
#     (wanted one at height Some(21))", 114 s. Green 35 s measured
#     2026-10-29, local debug build.
ARMED=(
  engine::regtest_e2e::origin::restricted_listener_is_withheld_status_and_capped_by_native_handlers
  engine::regtest_e2e::ported_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::ported_p2p_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::native_handlers_apply_their_own_request_caps
  engine::regtest_e2e::e2e_fcmp_spend_accepted_by_daemon
  engine::regtest_e2e::e2e_fcmp_spend_reorg_restores_pool_and_fee
  engine::regtest_e2e::regtest_daemon_spawns_and_mines_to_wallet_address
  engine::regtest_e2e::a_stops_last_line_reaches_the_log_file
  engine::regtest_e2e::e2e_refresh_scans_coinbase_balance
  engine::regtest_e2e::e2e_trim_curve_tree_restores_grow_root
  engine::regtest_e2e::e2e_arm3_phantom_slot_collected_at_open
  engine::regtest_e2e::jsonrpc_we_carries_handler_status_through_the_result_envelope
  engine::regtest_e2e::get_output_histogram_stays_unrouted
  engine::regtest_e2e::origin::restricted_listener_hides_a_transaction_this_node_has_not_broadcast
  engine::regtest_e2e::origin::restricted_listener_names_a_transaction_this_node_shows
  engine::regtest_e2e::origin::get_info_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::the_armed_switch_on_testnet_serves_two_levers_and_knows_no_third
  engine::regtest_e2e::a_dialing_node_hands_its_tip_to_the_peer_it_dials
)

# Consensus gates too heavy for the per-PR lane (depth-3 spend, 13 min
# measured 2026-09-08; the two slice-7 gates ~5 min each in a debug build,
# fifty spends apiece). The nightly live-daemon workflow runs these with
# GATE_LANE=slow. The four bonded walks joined on 2026-10-29, when the Rust
# daemon first admitted a kind-5 JoinMarket (the DRS-X flip), each
# observed green on that daemon before it moved here:
#   e2e_staker_bond_post_accepted_and_applied — the production stake entry
#     (a complete-tree bond: mine + fund + discover + stake + submit +
#     confirm), 264 s.
#   e2e_drain_wire_shape_matches_a_real_transfer — the drain wire shape
#     over a complete-tree bond, 165 s.
#   The two market-bond walks stake a compact join onto shard 0, which
#     CEN-J15 admits only once the shard is closed, final and priced by a
#     slash pass. Each opens with `close_shard_through_the_daemon` from
#     the staker wallet it then stakes from: 289 real wallet spends
#     (10 579 B of archival good apiece, sixteen a block) close the shard,
#     `reorg_cap` blocks make it final, the wallet's P-scan covers the
#     fill ahead of the retention prune, and the chain is mined through
#     the pass that prices it — the daemon's `get_archival_shard_coverage`
#     is the exit, never arithmetic. That fill is most of each walk's
#     time (the box's block pace, 1–3 s, sets the rest), and why they are
#     here rather than per-PR. Observed red on the flip binary 2026-10-29
#     before the fill existed, each at its first stake (the pool door's
#     J15 refusal), and green with it, local debug build:
#     e2e_release_accepted_and_connected — 1 385 s (SEB 32, cap 8).
#     e2e_unstake_collect_retire_composed_arc — 1 348 s (SEB 8, cap 2;
#       the 248-block claim window included).
#   The relay embargo's two live walks (RX-1, Rick 2026-10-29), each
#   waiting out the origin's 1,148 s retry, so slow lane, not PR lane:
#     origin::an_origin_with_no_alternate_fluffs_at_its_first_fire_and_is_mined
#       — origin and sink: the first fire has no alternate and fluffs (W3b);
#       broadcast at 1 148.6 s, mined, 1 230 s, 2026-10-30. Red before the
#       embargo landed: the origin held its transaction in stem past 600 s
#       (2026-10-29).
#     origin::an_origin_whose_successor_drops_re_stems_to_its_alternate_and_never_fluffs
#       — the origin and three simulated Levin peers (regtest_e2e_peer.rs):
#       two take its stem slots and swallow stems, one dials in and fluffs
#       the transaction back. Re-stem to the alternate at 1 148.0 s, disarmed
#       by the return, no fluff through a second interval, mined; 2 497 s,
#       2026-10-30. No daemon option drops stems (Rick, 2026-10-29: the
#       adversary belongs in the test).
ARMED_SLOW=(
  engine::regtest_e2e::e2e_fcmp_spend_over_depth3_tree
  engine::regtest_e2e::e2e_cxx_template_fills_to_its_median
  engine::regtest_e2e::e2e_a_rust_block_at_the_consensus_bound_is_judged_by_the_cxx
  engine::regtest_e2e::e2e_staker_bond_post_accepted_and_applied
  engine::regtest_e2e::e2e_drain_wire_shape_matches_a_real_transfer
  engine::regtest_e2e::e2e_release_accepted_and_connected
  engine::regtest_e2e::e2e_unstake_collect_retire_composed_arc
  engine::regtest_e2e::origin::an_origin_with_no_alternate_fluffs_at_its_first_fire_and_is_mined
  engine::regtest_e2e::origin::an_origin_whose_successor_drops_re_stems_to_its_alternate_and_never_fluffs
)

# Deliberately never run here, with the reason recorded (rule 23: a decided
# disposition leaves a grep surface). Removing or renaming one fails the
# name-check below, so the decision cannot rot silently.
#   generate_ct2_tier_b_fixture — fixture regenerator, not a pass/fail
#     proposition; run manually when the CT-2 Tier-B scenarios change.
#   rt_p5::rt_p5_dry_run, rt_p5::rt_p5_registered_run — RT-P5's sizes
#     part, a registered measurement
#     (docs/benchmarks/rt_p5_rpc_message_sizes_20261017.md), not a
#     pass/fail proposition: each writes its trace under RT_P5_OUT and is
#     run by hand when the registration says. The parser they rely on is
#     covered by ordinary unit tests in the same module.
#   e2e_emission_claim_accepted_and_applied — the third market-bond walk.
#     Dark because serve credit's production path goes live at SO-D12 4b
#     (Rick, 2026-10-29: no inject lever; test the production path). Its
#     CEN-J15 darkness is gone: on the flip binary it fills and prices
#     shard 0, the market bond is admitted and confirmed, and the join
#     epoch is read back (SEB 128, cap 16), green; its A2 leg calls the
#     `inject_archival_serve_credit` lever DX-Q3 deleted with the C++
#     chain. 4b re-subjects A2 to the bundle path and arms it, in the
#     live-Tor lane (FOLLOWUPS: the emission regtest walk). Prior reds:
#     sabotage 2026-09-08 (was ARMED_SLOW).
DECIDED_DARK=(
  engine::regtest_e2e::generate_ct2_tier_b_fixture
  engine::regtest_e2e::rt_p5::rt_p5_dry_run
  engine::regtest_e2e::rt_p5::rt_p5_registered_run
  engine::regtest_e2e::e2e_emission_claim_accepted_and_applied
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

# The armed gates that live outside regtest_e2e, as `<test binary>:<name>`
# in shekyl-levin's integration tests. Same ratchet, per binary: every
# ignored test the binary lists is on this list, and every name here is
# listed, so a rename or a new ignored test fails here rather than going
# dark. PR lane only: each is a short live run.
#
#   refused_inbound — the refused-inbound gate (DAEMON_CONFIG_CUTOVER.md
#     §5.2; Rick, 2026-10-14): the daemon under a lowered soft descriptor
#     limit derives its inbound ceiling and refuses the peer past it.
#     Observed red 2026-10-15 by filling one short of the ceiling: the
#     extra peer was admitted and the test panicked at "must be refused".
#     Unix only (PWD-B1: Windows has no per-process descriptor limit); this
#     script runs on Linux.
#   socks_credentials — the SOCKS username and password ride the dial
#     (DAEMON_CONFIG_CUTOVER.md DC-Q7; Rick, 2026-10-17): a daemon behind a
#     SOCKS5 proxy that takes only RFC 1929 presents the configured pair on
#     the clearnet and the operator-Tor dial, and a refused pair is named by
#     its rows while the daemon keeps running. Observed red 2026-10-17 with
#     both dials forced to no-auth: all three timed out with the proxy
#     seeing only method 0x00. Unix only (the configuration file's mode).
ARMED_LEVIN=(
  refused_inbound:the_inbound_ceiling_derived_from_the_descriptor_limit_refuses_the_next_peer
  socks_credentials:the_clearnet_dial_presents_its_pair_and_tunnels_through_the_proxy
  socks_credentials:a_refused_pair_names_its_rows_and_the_daemon_keeps_running
  socks_credentials:the_operator_tor_dial_presents_its_pair
)

for entry in "${ARMED_LEVIN[@]}"; do
  binary="${entry%%:*}"
  name="${entry#*:}"
  cargo test -p shekyl-levin --test "$binary" -- --list --ignored >"$ignored" 2>&1
  listed=$(grep -c ': test$' "$ignored" || true)
  [ "${listed:-0}" -gt 0 ] || {
    echo "FATAL: shekyl-levin --test $binary lists no ignored test — the binary moved or the enumeration broke" >&2
    exit 1
  }
  grep -qx "$name: test" "$ignored" || {
    echo "FATAL: listed gate '$entry' names no ignored test — it was renamed or deleted" >&2
    exit 1
  }
  armed_here=$(printf '%s\n' "${ARMED_LEVIN[@]}" | grep -c "^$binary:" || true)
  if [ "$listed" -ne "$armed_here" ]; then
    echo "FATAL: shekyl-levin --test $binary lists $listed ignored test(s), but $armed_here are armed here." >&2
    echo "A new #[ignore]d test in that binary must be armed (observe it red first) or moved." >&2
    exit 1
  fi
done

if [ "$GATE_LANE" = pr ]; then
  for entry in "${ARMED_LEVIN[@]}"; do
    binary="${entry%%:*}"
    name="${entry#*:}"
    set +e
    cargo test -p shekyl-levin --test "$binary" "$name" \
      -- --ignored --exact --nocapture >"$gate_log" 2>&1
    status=$?
    set -e
    cat "$gate_log"
    if [ "$status" -ne 0 ]; then
      echo "FATAL: $entry failed" >&2
      exit "$status"
    fi
    grep -qE '^test result: ok\. 1 passed' "$gate_log" || {
      echo "FATAL: $entry selected no test — the filter or the name moved" >&2
      exit 1
    }
  done
fi
