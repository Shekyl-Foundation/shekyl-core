// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.

//! The carrier's two derived sizes, checked against the facts they derive from.
//!
//! [`carrier::WINDOW_BYTES`] and [`carrier::MAX_FRAGMENTS`] are constants in a
//! crate whose default build is deliberately dependency-free, so neither can be
//! *computed* where it lives. This file is where they are **enforced** instead,
//! and enforcement is the stronger form: a proof-size change reds a test that
//! names the constant, where a computed value would absorb the change and
//! silently move the window.
//!
//! **Nothing here is a literal the assertions could agree with by
//! construction.** Transaction sizes come from `predict_size_and_weight` (the
//! predictor pinned to `Transaction::write` by
//! `predict_weight_matches_wire_weight`), the envelope comes from building a
//! real `NOTIFY_NEW_TRANSACTIONS` with `notify`, and the two ceilings come from
//! `noise_windows_in_epoch` and levin's own `DEFAULT_MAX_PACKET_SIZE`.
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

/// The Dandelion++ epoch the carrier is provisioned against, in seconds.
///
/// Not a constant in `inherited`: the epoch is a runtime argument
/// (`min_epoch_secs`), so mirroring it would be the dead-mirror class Q-11
/// Unit 0 deleted. Named here because the ceiling assertion needs a value.
const PROVISIONED_EPOCH_SECS: u32 = 300;

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

/// Both ceilings above the cap, asserted against the constants that set them.
///
/// Neither binds at the derived cap, which is the finding rather than a
/// formality: the inherited 20 sat exactly ON the epoch ceiling, so the
/// relationship read as a derivation when it was a coincidence.
///
/// What edit reds this: raising `carrier::MAX_FRAGMENTS` past the epoch's
/// window budget, or slowing the noise cadence without lowering the cap.
#[test]
fn the_cap_stays_under_both_ceilings() {
    let affords = inherited::noise_windows_in_epoch(PROVISIONED_EPOCH_SECS);
    assert!(
        carrier::MAX_FRAGMENTS <= affords,
        "a {PROVISIONED_EPOCH_SECS} s epoch affords {affords} windows at the \
         slowest cadence but the cap is {}; the remainder of a full-size \
         message is discarded at every epoch roll (CV-1)",
        carrier::MAX_FRAGMENTS,
    );

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

/// Axis 2's 8 KiB/s ceiling is why the window is the modal shape and the
/// cap carries the tail — a one-sided `needed <= WINDOW_BYTES` cannot say so.
///
/// Byte rates here are binary (`KiB/s` = 1024 B/s), matching
/// `COVER_TRAFFIC_RESTORATION.md` §1.7. The fastest cadence is
/// `NOISE_MIN_DELAY_SECS`; a window that fits the structural max whole at
/// that cadence is the size the ceiling forbade.
///
/// What edit reds this: enlarging `WINDOW_BYTES` past the ceiling, slowing
/// the cadence without shrinking the window, or a structural-max shrink that
/// would make a whole-tx window legal (at which point the two-constant split
/// itself is owed a re-read).
#[test]
fn the_window_at_the_fastest_cadence_stays_under_the_bandwidth_ceiling() {
    const CEILING_BYTES_PER_SEC: u64 = 8 * 1024;

    let window_rate =
        (carrier::WINDOW_BYTES as u64).div_ceil(u64::from(inherited::NOISE_MIN_DELAY_SECS));
    assert!(
        window_rate <= CEILING_BYTES_PER_SEC,
        "WINDOW_BYTES {} at the fastest cadence ({} s) is {window_rate} B/s, \
         over the pre-registered 8 KiB/s ceiling — that ceiling is why the \
         window is not the structural max",
        carrier::WINDOW_BYTES,
        inherited::NOISE_MIN_DELAY_SECS,
    );

    let structural_max = message_bytes(MAX_INPUTS, MAX_OUTPUTS, MAX_TREE_DEPTH);
    let whole_tx_rate =
        (structural_max as u64).div_ceil(u64::from(inherited::NOISE_MIN_DELAY_SECS));
    assert!(
        whole_tx_rate > CEILING_BYTES_PER_SEC,
        "a window sized for the structural max ({structural_max} B) at the \
         fastest cadence is {whole_tx_rate} B/s, which should breach the \
         8 KiB/s ceiling — that breach is why MAX_FRAGMENTS exists"
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
    for (n_in, depth, cell) in SPEC_VERIFY_COST.populated() {
        let real = message_bytes(n_in, 2, u8::try_from(depth).expect("table depth is small"));
        assert_eq!(
            usize::try_from(cell.msg_bytes).expect("pinned size is small"),
            real,
            "verify-cost cell ({n_in}, {depth}) pins {} B but the shape really \
             produces {real} B; f_ms derives its node-crypto term from the pin",
            cell.msg_bytes,
        );
        checked += 1;
    }
    assert_eq!(checked, 4, "the in-tree surface is the four §85.3 pins");
}
