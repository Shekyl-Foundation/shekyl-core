// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

//! The carrier's derived numbers, checked against the facts they derive from.
//!
//! [`carrier::WINDOW_BYTES`] and [`carrier::MAX_FRAGMENTS`] are constants in
//! `shekyl-relay-privacy`, whose default build depends only on
//! `shekyl-draw-rng`. The size facts live in `shekyl-tx-weight`,
//! `shekyl-levin`, and `shekyl-fcmp`, which that default build does not link,
//! so neither constant can be *computed* where it lives. This file is where
//! they are **enforced** instead,
//! and enforcement is the stronger form: a proof-size change reds a test that
//! names the constant, where a computed value would absorb the change and
//! silently move the window.
//!
//! **Nothing here is a literal the assertions could agree with by
//! construction.** Transaction sizes come from `predict_size_and_weight` (the
//! predictor pinned to `Transaction::write` by
//! `predict_weight_matches_wire_weight`), the envelope comes from building a
//! real `NOTIFY_NEW_TRANSACTIONS` with `notify`, the packet ceiling is levin's
//! own `DEFAULT_MAX_PACKET_SIZE`, and the design stem load is the chain's
//! full-reward zone and block time.
//!
//! **Why this file exists at all.** The sizes it replaces — 8395 B "modal" and
//! 16651 B "max admissible" — were asserted flatly, with no derivation, and
//! were wrong by 1.55x and 5.9x. Nothing could go red, because nothing
//! connected them to a transaction. That is the gap this closes.

use shekyl_fcmp::MAX_INPUTS;
use shekyl_levin::{notify, NewTransactions, PortableMap as _, NOTIFY_NEW_TRANSACTIONS};
use shekyl_relay_privacy::params::{carrier, inherited};
use shekyl_tx_weight::{
    predict_size_and_weight, InputCount, OutputCount, MAX_OUTPUTS, MAX_TREE_DEPTH,
};

/// Wire bytes of the `NOTIFY_NEW_TRANSACTIONS` carrying one transaction of
/// this shape — transaction *and* envelope, which is what a window must hold.
///
/// The fee is `u64::MAX` so the varint that carries it is at its widest: the
/// window is a bound, and a bound taken at a plausible fee would be one a
/// large fee could cross.
fn message_bytes(n_in: usize, n_out: usize, depth: u8) -> usize {
    let (tx_bytes, _) = predict_size_and_weight(
        InputCount::clamped(n_in),
        OutputCount::clamped(n_out),
        depth,
        u64::MAX,
    );
    let msg = NewTransactions {
        txs: vec![vec![0u8; tx_bytes]],
        padding: Vec::new(),
        dandelionpp_fluff: false,
    };
    notify(NOTIFY_NEW_TRANSACTIONS, &msg.store().expect("store")).len()
}

/// The window holds the modal transaction whole at EVERY tree depth.
///
/// What edit reds this: shrinking `carrier::WINDOW_BYTES`, or any change that
/// grows a 1-in/2-out transaction (an FCMP++ proof-size change, a new
/// `tx_extra` field, a wider PQC auth) past the margin.
///
/// Depth is `MAX_TREE_DEPTH`, not the genesis depth, and that is the point of
/// the test rather than an incidental choice: at genesis depth the modal
/// transaction fits with room to spare, so a genesis-depth assertion would stay
/// green while the fragment count flipped from 1 to 2 as the curve tree
/// deepened — a hop that doubles on a chain-state threshold, which is the
/// timing-observable drift a fixed window exists to prevent.
#[test]
fn the_window_holds_the_modal_transaction_at_max_tree_depth() {
    let needed = message_bytes(1, 2, MAX_TREE_DEPTH);
    assert!(
        needed <= carrier::WINDOW_BYTES,
        "the modal transaction at MAX_TREE_DEPTH needs {needed} B of window \
         (transaction + NOTIFY_NEW_TRANSACTIONS envelope) but \
         carrier::WINDOW_BYTES is {}; at n > 1 the carrier hop gains a whole \
         cadence per extra fragment",
        carrier::WINDOW_BYTES,
    );
}

/// The fragment cap is `ceil(S_max / WINDOW_BYTES)`, not slack under the
/// epoch ceiling.
///
/// A one-sided `needs <= MAX_FRAGMENTS` is the same class of defect this
/// file exists to remove: the inherited 20 sat in `[ceil, epoch-ceiling]`
/// and would still go green. The derivation is the ceiling of the structural
/// max over the window; equality is what makes 20 unable to hide.
///
/// What edit reds this: raising or lowering `carrier::MAX_FRAGMENTS` without
/// a matching window or wire-size change, shrinking the window, or raising
/// `MAX_INPUTS` / `MAX_OUTPUTS` / `MAX_TREE_DEPTH`.
#[test]
fn the_fragment_cap_is_ceil_of_the_structural_max_over_the_window() {
    let structural_max = message_bytes(MAX_INPUTS, MAX_OUTPUTS, MAX_TREE_DEPTH);
    let needs = structural_max.div_ceil(carrier::WINDOW_BYTES);
    assert_eq!(
        u32::try_from(needs).expect("fragment count is small"),
        carrier::MAX_FRAGMENTS,
        "the largest admissible message is {structural_max} B, which needs \
         {needs} windows of {} B; carrier::MAX_FRAGMENTS is {} — the cap is \
         ceil(S_max / WINDOW_BYTES), not slack under the epoch ceiling",
        carrier::WINDOW_BYTES,
        carrier::MAX_FRAGMENTS,
    );
}

/// The cap stays under levin's packet limit.
///
/// The epoch is not a ceiling on the cap any more: under the memoryless
/// cadence no epoch length guarantees a run finishes, and the epoch tail
/// (`EPOCH_TAIL_WINDOWS`, sized from the cap) lets every run that starts
/// before a boundary finish on its own peer whatever the epoch's length.
///
/// What edit reds this: raising `carrier::MAX_FRAGMENTS` or the window past
/// what one levin packet carries.
#[test]
fn the_cap_stays_under_the_packet_limit() {
    // The guard `levin_notify.cpp` used to carry as a static_assert over two
    // C++ #defines, moved here with the constants it guards — which is what
    // that comment's own FOLLOWUP asked for.
    let widest = u64::from(carrier::MAX_FRAGMENTS) * carrier::WINDOW_BYTES as u64;
    assert!(
        widest <= shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
        "a full-size fragmented message is {widest} B, over levin's \
         {} B packet limit — most nodes would reject this fragment setting",
        shekyl_levin::DEFAULT_MAX_PACKET_SIZE,
    );
}

/// The cover budget is why the window is the modal shape and the cap carries
/// the tail — a one-sided `needed <= WINDOW_BYTES` cannot say so.
///
/// The figure is [`carrier::PER_NODE_BUDGET_BYTES_PER_SEC`] (`CVR-R5`) and
/// is not written here. The cadence is derived from it, so the window at that
/// cadence spends the budget exactly (a compile-time assert beside the
/// constants); this test states the node rate in bytes, which the
/// compile-time form cannot report when it fails. The load-bearing half is
/// the negative control below.
///
/// Byte rates here are binary (`KiB/s` = 1024 B/s).
///
/// What edit reds this: a structural-max shrink that would make a whole-tx
/// window legal, at which point the two-constant split itself is owed a
/// re-read.
#[test]
fn the_window_at_the_budgeted_cadence_spends_the_budget() {
    // Every channel a node runs: `NOISE_CHANNELS`, one per stem slot, whatever
    // connectors carry them. The mean cadence is the denominator.
    let channels = inherited::NOISE_CHANNELS as u64;
    let mean_ms = u64::from(carrier::MEAN_CADENCE_MS);
    let ceiling = u64::from(carrier::PER_NODE_BUDGET_BYTES_PER_SEC);

    // Cross-multiplied, not divided. `a / b <= c` floors, so a breach smaller
    // than 1 B/s satisfies it while the true average sits over the ceiling.
    // The B/s figures below are computed for the DIAGNOSTIC only — a reader of
    // a failure wants bytes per second, but the decision must not round.
    let node_bytes = (carrier::WINDOW_BYTES as u64) * channels * 1_000;
    assert!(
        node_bytes <= ceiling * mean_ms,
        "WINDOW_BYTES {} across {channels} channels at a {mean_ms} ms mean \
         cadence is {} B/s, over the {ceiling} B/s per-node budget",
        carrier::WINDOW_BYTES,
        node_bytes / mean_ms,
    );

    let structural_max = message_bytes(MAX_INPUTS, MAX_OUTPUTS, MAX_TREE_DEPTH);
    let whole_tx_bytes = (structural_max as u64) * channels * 1_000;
    assert!(
        whole_tx_bytes > ceiling * mean_ms,
        "a window sized for the structural max ({structural_max} B) is {} B/s \
         at the budgeted cadence, which should breach the per-node budget — that \
         breach is why MAX_FRAGMENTS exists",
        whole_tx_bytes / mean_ms,
    );
}

/// Every populated verify-cost cell carries the message size its shape really
/// produces.
///
/// `VerifyCell::msg_bytes` is what `f_ms` computes the node-crypto term from,
/// and it is pinned in a crate that cannot reach the wire model — so this is
/// the only place the pin can be checked against the thing it claims to
/// describe. Without it, `msg_bytes` is exactly the ungrounded literal this
/// whole change exists to remove, one field along.
///
/// What edit reds this: changing any cell's `msg_bytes`, or a proof-size /
/// envelope change that moves a shape's real size.
#[test]
fn every_verify_cell_carries_its_shapes_real_message_size() {
    use shekyl_relay_privacy::verify_cost::SPEC_VERIFY_COST;

    let mut checked = 0;
    let mut moved = Vec::new();
    for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
        let real = message_bytes(n_in, 2, u8::try_from(depth).expect("table depth is small"));
        if usize::try_from(cell.msg_bytes).expect("pinned size is small") != real {
            moved.push(format!(
                "verify-cost cell ({n_in}, {depth}) pins {} B but the shape really \
                 produces {real} B",
                cell.msg_bytes
            ));
        }
        checked += 1;
    }
    // Every moved cell in one report: a wire change moves them together, and
    // f_ms derives its node-crypto term from each pin.
    assert!(moved.is_empty(), "{}", moved.join("\n"));
    assert_eq!(checked, 4, "the in-tree surface is the four §85.3 pins");
}

/// The node's channels are its stem slots, and a channel's rate is the
/// budget's share.
///
/// The node rate counts `NOISE_CHANNELS` and no network term: cover runs per
/// channel on whichever covered session holds the slot (`CVR-R3`), so a
/// second network adds no channel. The memoryless cadence has no shortest
/// gap, so no peak rate is stated; a connection is sized against the
/// channel's mean rate.
///
/// What edit reds this: a budget, window or channel-count change that
/// moves the channel rate off the figure the documents quote.
#[test]
fn a_channel_carries_its_share_of_the_budget() {
    assert_eq!(
        carrier::PER_CHANNEL_BYTES_PER_SEC,
        4_096,
        "COVER_TRAFFIC_RESTORATION.md quotes the per-connection cover rate"
    );
    assert_eq!(
        u64::from(carrier::PER_CHANNEL_BYTES_PER_SEC) * inherited::NOISE_CHANNELS as u64,
        u64::from(carrier::PER_NODE_BUDGET_BYTES_PER_SEC),
        "the channels spend the node's budget, no more and no less"
    );
    assert_eq!(
        carrier::MEAN_CADENCE_MS,
        5_000,
        "channels x window / budget"
    );
}

/// A channel carries the design stem load (`CVR-R5`): it sends windows
/// faster than the chain can confirm transactions at its design capacity,
/// so a node relaying every transaction through one channel does not fall
/// behind.
///
/// Counted in windows, not bytes. Every transaction takes at least one
/// whole window, so the load is transactions per second: the penalty-free
/// block weight (`MIN_BLOCK_WEIGHT`, the full-reward zone) over the
/// lightest admissible transaction's weight (one input, the two outputs
/// CEN-I1 requires, at the shallowest tree depth), per block time
/// (`T_SECONDS`). Weight, because the block bound counts weight and a
/// transaction weighs at least its size.
///
/// What edit reds this: a slower cadence, a larger full-reward zone, a
/// shorter block time, or a lighter transaction shape.
#[test]
// The float figures are the failure message's only; the decision is integer.
#[allow(clippy::cast_precision_loss)]
fn a_channel_outruns_the_design_stem_load() {
    let lightest = (1..=MAX_TREE_DEPTH)
        .map(|depth| {
            predict_size_and_weight(InputCount::clamped(1), OutputCount::clamped(2), depth, 0).1
        })
        .min()
        .expect("depths");
    let block_weight = shekyl_wire::transaction::MIN_BLOCK_WEIGHT as u64;
    let block_secs = shekyl_difficulty::T_SECONDS;
    // Transactions per second at capacity: block_weight / lightest / block_secs.
    // Windows per second per channel: 1000 / MEAN_CADENCE_MS. Cross-multiplied.
    let load = block_weight * u64::from(carrier::MEAN_CADENCE_MS);
    let carried = (lightest as u64) * block_secs * 1_000;
    assert!(
        carried > load,
        "a channel sends one window per {} ms; the design load is {} transactions \
         of {lightest} weight per {block_secs} s block, {:.3} per second against \
         {:.3} windows per second",
        carrier::MEAN_CADENCE_MS,
        block_weight / lightest as u64,
        block_weight as f64 / lightest as f64 / block_secs as f64,
        1_000.0 / f64::from(carrier::MEAN_CADENCE_MS),
    );
}
