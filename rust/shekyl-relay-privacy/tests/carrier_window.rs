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

/// Where every hop sits on the embargo's resonance grid.
///
/// # The mechanism
///
/// `resonance_clearance_ms` documents it: `derive_embargo` accumulates
/// `div_ceil(h * hop + F, tick)` over the stem-length sum, and when `hop` is
/// near a multiple of `tick` every term steps at once. At `tick = 250` ms that
/// is **+12 s of embargo for a 1 ms hop change** at hop 251/501/751/1001,
/// against +4-5 s elsewhere.
///
/// # A record, not a gate — and the finding it carries
///
/// Nothing in the design picks a hop for its clearance, so a threshold here
/// would be another self-invented bar. What this prevents is a hop moving onto
/// a resonance silently.
///
/// | hop | value | clear of next resonance |
/// | --- | --- | --- |
/// | clearnet modal | 175.4 ms | 75.6 ms (43.1 %) |
/// | **SHIPPED anon modal** (interim 1625) | **1750.4 ms** | **0.6 ms (0.03 %)** |
/// | SHIPPED anon 8-input | 2028.5 ms | 222.5 ms (11.0 %) |
/// | §94 candidate anon modal | 716.0 ms | 35.0 ms (4.9 %) |
/// | **§94 candidate anon 8-input** | **994.1 ms** | **6.9 ms (0.7 %)** |
///
/// **The shipped interim hop is sitting on a resonance** — 0.6 ms clear, so one
/// further millisecond moves its embargo 499 -> 510 s. It is inert today
/// (§89.8.4 arms no anonymity embargo), which is the only reason this is a
/// record rather than a defect.
///
/// **The shape-dependence question is concrete, not hypothetical.** `hop`
/// includes `f_ms(n_in, depth)`, so shapes land at different clearances: at the
/// §94 candidate the two genesis shapes differ by 4.2 points, the 8-input one
/// 0.7 % clear. A re-measurement could put one shape on a resonance and another
/// off it, making the embargo discontinuous **across transaction shapes**.
/// Whether that is observable is §89.3's disclosure question one axis over, and
/// it is noted there rather than ruled here.
///
/// What edit reds this: any change to a transit assumption, a verify-cost cell,
/// or `DEFAULT_EMBARGO_TICK_MILLIS`.
#[test]
fn the_hops_clearance_of_the_resonance_grid_is_recorded() {
    use shekyl_relay_privacy::derive::resonance_clearance_ms;
    use shekyl_relay_privacy::schedule::DEFAULT_EMBARGO_TICK_MILLIS;
    use shekyl_relay_privacy::verify_cost::{
        ADOPTED_TRANSIT_ASSUMPTION_MS, ANON_ZONE_TRANSIT_ASSUMPTION_MS, GENESIS_TREE_DEPTH,
        SPEC_VERIFY_COST,
    };

    // The §94 round's candidate anonymity transit. A local literal ON PURPOSE:
    // it is BANKED, NOT ADOPTED — the flood-suite re-baseline is its
    // prerequisite — so there is no tree constant to read. When it lands this
    // becomes a read and the band below is re-derived with it.
    const CANDIDATE_ANON_TRANSIT_MS: f64 = 590.6;

    let f1 = SPEC_VERIFY_COST
        .f_ms(1, GENESIS_TREE_DEPTH)
        .expect("populated");
    let f8 = SPEC_VERIFY_COST
        .f_ms(8, GENESIS_TREE_DEPTH)
        .expect("populated");

    for (label, hop, lo, hi) in [
        (
            "clearnet modal",
            ADOPTED_TRANSIT_ASSUMPTION_MS + f1,
            75.0,
            76.5,
        ),
        (
            "SHIPPED anon modal",
            ANON_ZONE_TRANSIT_ASSUMPTION_MS + f1,
            0.0,
            1.5,
        ),
        (
            "SHIPPED anon 8-input",
            ANON_ZONE_TRANSIT_ASSUMPTION_MS + f8,
            222.0,
            223.5,
        ),
        (
            "candidate anon modal",
            CANDIDATE_ANON_TRANSIT_MS + f1,
            34.0,
            36.0,
        ),
        (
            "candidate anon 8-input",
            CANDIDATE_ANON_TRANSIT_MS + f8,
            6.0,
            8.0,
        ),
    ] {
        let clear = resonance_clearance_ms(hop, DEFAULT_EMBARGO_TICK_MILLIS);
        assert!(
            (lo..hi).contains(&clear),
            "{label}: hop {hop:.1} ms is {clear:.1} ms clear of the next embargo \
             resonance, outside the recorded {lo}..{hi} ms band — a hop moved \
             onto or off a resonance, where derive_embargo steps ~12 s for a \
             1 ms input change"
        );
    }
}
