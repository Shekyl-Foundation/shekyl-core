// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Release-cooldown gate for `Unbond` and `HoldingsUpdate`-drop (gate-4 §4.3/§4.4;
//! `PHASE_2B_FSM_RETOOL.md` P2B-8 Q1/Q2).
//!
//! The cooldown anchor is a persona's **last-served settlement epoch**, and it is
//! *derived*, never stored (P2B-8 Q1/Q2 — "derive from the landed source of truth,
//! don't add a mutable field"). The serve-credit table is keyed
//! `P_id ‖ BE64(shard) ‖ BE64(epoch)` (a big-endian composite,
//! `serve_credit_decisions::serve_credit_key_be`), so its byte-sort *is*
//! `(P_id, shard, epoch)` ascending; shard `s`'s last-served epoch is therefore the
//! max `E` carrying a bit — a single reverse-cursor seek over the `P_id ‖ BE64(shard)`
//! prefix. That LMDB cursor I/O stays C++-side (the standing schema exception); the
//! derived per-shard maxima arrive here as data, and this module owns the
//! decisions on top: the whole-record anchor (max over shards, for `Unbond`), the
//! cooldown predicate, and the slash-settlement predicate.
//!
//! ## The guarantee (ratified 2026-07-12, maintainer)
//!
//! Together the two predicates ([`release_cooldown_elapsed`] and
//! [`slashes_settled_through`]) guarantee: **at `Unbond` legality, every settlement
//! epoch up to and including the record's last-served anchor has passed its slash
//! deadline and been processed by the deterministic slash scheduler** — any
//! held-but-unserved failure at or before the last serve has already been slashed
//! on still-bonded collateral. Epochs *after* the last serve (at most the cooldown
//! window, unserved by definition, earning nothing) are **exit-forgiven by
//! construction**: slashability ends at the `Unbond` connect, and the refund is
//! never clawed back. The epoch-distance predicate alone is not sufficient — the
//! connect dispatch runs *before* the per-block slash fold
//! (`BlockchainDB::add_block` ordering), so in the first block past the anchor
//! epoch's slash deadline an `Unbond` would exit the record ahead of the fold that
//! settles the anchor epoch; [`slashes_settled_through`] closes exactly that
//! one-block race by requiring the scheduler's settled watermark to have reached
//! the anchor before the release verifies.

use crate::bond_floor::RELEASE_COOLDOWN_EPOCHS;
use crate::constants::effective_settlement_epoch_blocks;

/// The whole-record last-served settlement epoch: the max over the record's current
/// shards of each shard's last-served epoch (P2B-8 Q2 — the `Unbond` cooldown
/// anchor). `None` when the persona has never served any shard.
///
/// `per_shard_served` carries the reverse-cursor maximum of each **served** shard;
/// never-served shards are omitted by the caller (they carry no serve-credit bit, so
/// they cannot lower the max). An empty slice therefore means the persona has never
/// served, folding to `None`.
#[must_use]
pub fn whole_record_last_served(per_shard_served: &[u64]) -> Option<u64> {
    per_shard_served.iter().copied().max()
}

/// Whether the release cooldown has elapsed at `current_settlement_epoch`, given the
/// derived `last_served_epoch` anchor (gate-4 §4.3: the cooldown is the grace window
/// *past* the last served epoch — sized so every epoch up to the anchor reaches its
/// slash deadline before the release can verify).
///
/// Elapsed iff `current_settlement_epoch >= last_served_epoch + RELEASE_COOLDOWN_EPOCHS`.
/// `RELEASE_COOLDOWN_EPOCHS` covers the challenge-resolution window by construction
/// (`ARCHIVAL_TIMING_CONSTANTS.md` §2.2 L16 pin: `RELEASE_COOLDOWN_EPOCHS · SEB >
/// CHALLENGE_RESOLUTION_BLOCKS`). A persona that never served (`None`) has earned
/// nothing whose settlement the exit could outrun — every epoch it held without
/// serving either was already slashed at its deadline while bonded or falls in the
/// exit-forgiven tail (module docs) — so the cooldown is vacuously elapsed.
///
/// This predicate is necessary but not sufficient on its own; pair it with
/// [`slashes_settled_through`] (see the module docs for the combined guarantee and
/// the one-block connect-ordering race the second predicate closes).
#[must_use]
pub fn release_cooldown_elapsed(
    last_served_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> bool {
    match last_served_epoch {
        None => true,
        // `checked_add` keeps the documented predicate exactly: if the boundary epoch
        // `last + RELEASE_COOLDOWN_EPOCHS` overflows `u64` it is unreachable, so the
        // cooldown is reported not-elapsed (fail-closed) rather than saturating to a
        // false "elapsed" that would let an `Unbond` dodge the slashing window.
        Some(last) => match last.checked_add(RELEASE_COOLDOWN_EPOCHS) {
            Some(boundary) => current_settlement_epoch >= boundary,
            None => false,
        },
    }
}

/// The earliest block height at which [`release_cooldown_elapsed`] verifies for the
/// given anchor — `H_cd(P)` in the F-D4 derivation
/// (`ARCHIVAL_EXIT_STANDOFF_FD4_WINDOW.md` §1.1), the **F-D6 anchor**: derived from
/// the named consts `RELEASE_COOLDOWN_EPOCHS × SETTLEMENT_EPOCH_BLOCKS`, never a
/// hardcoded `20_000`. This function is that derivation's single home: any consumer
/// scheduling against the release boundary anchors on the same arithmetic the
/// consensus predicate enforces. (The original exit-standoff consumer — the wallet's
/// `draw_exit_gap` scheduling — was deleted with the F-D4 exit mechanism at Gate-6
/// §12.9 decision 5; this anchor predates the audit and stands on its own
/// anti-drift/slashability grounds, named out-of-scope by the same decision.)
///
/// The cooldown elapses at the first height of epoch
/// `last_served_epoch + RELEASE_COOLDOWN_EPOCHS`, i.e.
/// `(last_served_epoch + RELEASE_COOLDOWN_EPOCHS) × SEB` (`SEB` is
/// [`effective_settlement_epoch_blocks`] — the genesis pin, or the fakechain-only
/// regtest override, matching `settlement_epoch_at_height`). A never-served anchor
/// (`None`) is vacuously elapsed from genesis (`Some(0)`, mirroring the predicate).
/// `None` on overflow: the boundary epoch is unreachable, exactly the predicate's
/// fail-closed arm — the two functions cannot disagree at the boundary.
#[must_use]
pub fn release_cooldown_anchor_height(last_served_epoch: Option<u64>) -> Option<u64> {
    match last_served_epoch {
        None => Some(0),
        Some(last) => last
            .checked_add(RELEASE_COOLDOWN_EPOCHS)
            .and_then(|boundary_epoch| {
                boundary_epoch.checked_mul(effective_settlement_epoch_blocks())
            }),
    }
}

/// Whether the deterministic slash scheduler has settled every settlement epoch up
/// to and including the record's last-served anchor.
///
/// `last_settled_slash_epoch` is the scheduler's monotone watermark (the LMDB
/// `archival_last_slash_epoch` scalar): `Some(S)` means every epoch `<= S` has been
/// scanned at its slash deadline; `None` means no epoch has been settled yet.
///
/// Settled iff the anchor is `None` (never served — nothing the exit could outrun
/// beyond the exit-forgiven tail) or `watermark >= anchor`. Without this predicate,
/// an `Unbond` in the exact first block past the anchor epoch's slash deadline
/// connects *before* that block's slash fold (`add_transaction` precedes
/// `process_archival_slash_at_height` in `BlockchainDB::add_block`) and exits the
/// record ahead of the fold that would have slashed a held-but-unserved shard at
/// the anchor epoch — the one-block race the module docs name.
#[must_use]
pub fn slashes_settled_through(
    last_settled_slash_epoch: Option<u64>,
    last_served_epoch: Option<u64>,
) -> bool {
    match last_served_epoch {
        None => true,
        Some(anchor) => match last_settled_slash_epoch {
            Some(watermark) => watermark >= anchor,
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `RELEASE_COOLDOWN_EPOCHS` is generated from config (genesis value 2); the tests
    // read the constant rather than the literal so a re-pin re-derives them.
    const COOLDOWN: u64 = RELEASE_COOLDOWN_EPOCHS;

    #[test]
    fn genesis_cooldown_is_two_epochs() {
        // Guards the config-generated value against silent drift.
        assert_eq!(RELEASE_COOLDOWN_EPOCHS, 2);
    }

    #[test]
    fn whole_record_last_served_is_max_over_served_shards() {
        assert_eq!(whole_record_last_served(&[4, 9, 7]), Some(9));
    }

    #[test]
    fn whole_record_last_served_ignores_omitted_never_served_shards() {
        // Never-served shards are omitted by the caller, so the fold sees only the
        // served maxima and cannot be lowered by a shard that never served.
        assert_eq!(whole_record_last_served(&[9, 3]), Some(9));
    }

    #[test]
    fn whole_record_last_served_none_when_never_served() {
        // Empty slice = the persona has served no shard at all.
        assert_eq!(whole_record_last_served(&[]), None);
    }

    #[test]
    fn cooldown_elapsed_at_the_boundary_epoch() {
        // Anchor E: earliest Unbond epoch is E + COOLDOWN (inclusive).
        let e = 100;
        assert!(release_cooldown_elapsed(Some(e), e + COOLDOWN));
    }

    #[test]
    fn cooldown_not_elapsed_one_epoch_before_the_boundary() {
        let e = 100;
        assert!(!release_cooldown_elapsed(Some(e), e + COOLDOWN - 1));
        assert!(!release_cooldown_elapsed(Some(e), e)); // same epoch as last serve
    }

    #[test]
    fn cooldown_elapsed_well_past_the_boundary() {
        assert!(release_cooldown_elapsed(Some(100), 1_000));
    }

    #[test]
    fn never_served_cooldown_is_vacuously_elapsed() {
        assert!(release_cooldown_elapsed(None, 0));
    }

    #[test]
    fn settled_through_requires_watermark_at_or_past_the_anchor() {
        // The one-block race: anchor L, watermark L-1 (epoch L's deadline block has
        // not folded yet) must reject; watermark L (and beyond) accepts.
        let anchor = Some(100);
        assert!(!slashes_settled_through(Some(99), anchor));
        assert!(slashes_settled_through(Some(100), anchor));
        assert!(slashes_settled_through(Some(101), anchor));
    }

    #[test]
    fn settled_through_rejects_before_any_epoch_settles() {
        // A served record with no scheduler watermark yet: the anchor epoch cannot
        // have settled, so the release must wait (fail-closed).
        assert!(!slashes_settled_through(None, Some(0)));
    }

    #[test]
    fn settled_through_vacuous_for_never_served() {
        // Never served: no anchor to settle through, with or without a watermark.
        assert!(slashes_settled_through(None, None));
        assert!(slashes_settled_through(Some(7), None));
    }

    #[test]
    fn anchor_height_derives_from_named_consts() {
        use crate::constants::SETTLEMENT_EPOCH_BLOCKS;
        // Precondition, made executable: the unit-test environment runs
        // unarmed, so the effective SEB the anchor multiplies by IS the
        // genesis pin. If a future harness arms the fakechain override,
        // this fails loudly here instead of desynchronizing the
        // expectations below.
        assert_eq!(effective_settlement_epoch_blocks(), SETTLEMENT_EPOCH_BLOCKS);
        // F-D6: the anchor is the product of named consts. At genesis values
        // (COOLDOWN = 2, SEB = 10_000) this is the 20_000 that previously
        // lived only as a doc-comment integer — now derived. The literal is
        // deliberate: a genesis tripwire against silent config drift, the
        // same shape as genesis_cooldown_is_two_epochs.
        assert_eq!(
            release_cooldown_anchor_height(Some(0)),
            Some(RELEASE_COOLDOWN_EPOCHS * SETTLEMENT_EPOCH_BLOCKS)
        );
        assert_eq!(release_cooldown_anchor_height(Some(0)), Some(20_000));
        assert_eq!(
            release_cooldown_anchor_height(Some(7)),
            Some((7 + RELEASE_COOLDOWN_EPOCHS) * SETTLEMENT_EPOCH_BLOCKS)
        );
    }

    #[test]
    fn anchor_height_is_the_predicate_boundary_exactly() {
        use crate::consensus_state::settlement_epoch_at_height;
        // The derivation and the consensus predicate must agree at the
        // boundary: the anchor height is the FIRST height at which the
        // cooldown verifies, and the height before it must not.
        for last in [0u64, 1, 7, 100, 12_345] {
            let h = release_cooldown_anchor_height(Some(last)).expect("no overflow here");
            assert!(
                release_cooldown_elapsed(Some(last), settlement_epoch_at_height(h)),
                "cooldown must be elapsed at the derived anchor height {h} (last {last})"
            );
            assert!(
                !release_cooldown_elapsed(Some(last), settlement_epoch_at_height(h - 1)),
                "cooldown must NOT be elapsed one block before the anchor {h} (last {last})"
            );
        }
    }

    #[test]
    fn anchor_height_vacuous_for_never_served() {
        // Never served: the predicate is vacuously elapsed, so the earliest
        // verifying height is genesis.
        assert_eq!(release_cooldown_anchor_height(None), Some(0));
    }

    #[test]
    fn anchor_height_fails_closed_on_overflow() {
        // Mirrors cooldown_not_elapsed_when_boundary_overflows_u64: an
        // unreachable boundary epoch yields no anchor height, never a
        // saturated false one.
        assert_eq!(release_cooldown_anchor_height(Some(u64::MAX)), None);
    }

    #[test]
    fn cooldown_not_elapsed_when_boundary_overflows_u64() {
        // A last-served anchor so high that `last + RELEASE_COOLDOWN_EPOCHS` overflows
        // u64 has an unreachable boundary epoch: report not-elapsed (fail-closed), never
        // a saturated false "elapsed".
        assert!(!release_cooldown_elapsed(Some(u64::MAX), u64::MAX));
        assert!(!release_cooldown_elapsed(Some(u64::MAX - 1), u64::MAX));
    }
}
