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

/// The fragment cap carries the LARGEST admissible transaction.
///
/// This is the cap's actual job, and the one nothing checked: `MAX_FRAGMENTS`
/// was inherited at 20 — set equal to the epoch ceiling below, never derived
/// against a transaction. A cap under this bound means the biggest admissible
/// transaction is discarded by CV-1 and never arrives.
///
/// What edit reds this: lowering `carrier::MAX_FRAGMENTS`, shrinking the
/// window, or raising `MAX_INPUTS` / `MAX_OUTPUTS` / `MAX_TREE_DEPTH`.
#[test]
fn the_fragment_cap_carries_the_largest_admissible_transaction() {
    let structural_max = message_bytes(8, MAX_OUTPUTS, MAX_TREE_DEPTH);
    let needs = structural_max.div_ceil(carrier::WINDOW_BYTES);
    assert!(
        u32::try_from(needs).expect("fragment count is small") <= carrier::MAX_FRAGMENTS,
        "the largest admissible message is {structural_max} B, which needs \
         {needs} windows of {} B, but carrier::MAX_FRAGMENTS is {} — a \
         transaction over the cap is discarded, not fragmented",
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
