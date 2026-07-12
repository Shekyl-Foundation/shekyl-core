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
//! derived per-shard maxima arrive here as data, and this module owns the two
//! decisions on top: the whole-record anchor (max over shards, for `Unbond`) and the
//! cooldown predicate.

use crate::bond_floor::RELEASE_COOLDOWN_EPOCHS;

/// The whole-record last-served settlement epoch: the max over the record's current
/// shards of each shard's last-served epoch (P2B-8 Q2 — the `Unbond` cooldown
/// anchor). `None` when the persona has never served any shard.
///
/// `per_shard_last_served` carries one entry per current shard: the reverse-cursor
/// maximum for that shard, or `None` if the shard has never carried a serve-credit
/// bit. A never-served shard contributes `None` and cannot lower the max.
#[must_use]
pub fn whole_record_last_served(per_shard_last_served: &[Option<u64>]) -> Option<u64> {
    per_shard_last_served.iter().copied().flatten().max()
}

/// Whether the release cooldown has elapsed at `current_settlement_epoch`, given the
/// derived `last_served_epoch` anchor (gate-4 §4.3: the cooldown is the grace window
/// *past* the last served epoch, so no pending challenge can still slash after `P`
/// stopped serving).
///
/// Elapsed iff `current_settlement_epoch >= last_served_epoch + RELEASE_COOLDOWN_EPOCHS`.
/// `RELEASE_COOLDOWN_EPOCHS` covers the challenge-resolution window by construction
/// (`ARCHIVAL_TIMING_CONSTANTS.md` §2.2 L16 pin: `RELEASE_COOLDOWN_EPOCHS · SEB >
/// CHALLENGE_RESOLUTION_BLOCKS`). A persona that never served (`None`) has no pending
/// challenge that could still slash, so the cooldown is vacuously elapsed.
#[must_use]
pub fn release_cooldown_elapsed(
    last_served_epoch: Option<u64>,
    current_settlement_epoch: u64,
) -> bool {
    match last_served_epoch {
        None => true,
        Some(last) => current_settlement_epoch >= last.saturating_add(RELEASE_COOLDOWN_EPOCHS),
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
        assert_eq!(
            whole_record_last_served(&[Some(4), Some(9), Some(7)]),
            Some(9)
        );
    }

    #[test]
    fn whole_record_last_served_skips_never_served_shards() {
        // A never-served shard (`None`) must not lower the max.
        assert_eq!(whole_record_last_served(&[Some(9), None, Some(3)]), Some(9));
    }

    #[test]
    fn whole_record_last_served_none_when_never_served() {
        assert_eq!(whole_record_last_served(&[None, None]), None);
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
    fn cooldown_saturates_near_u64_max_without_overflow() {
        // A last-served anchor near u64::MAX must not panic on the add; it simply
        // never reaches the (unreachable) boundary.
        assert!(!release_cooldown_elapsed(Some(u64::MAX - 1), u64::MAX - 1));
        assert!(release_cooldown_elapsed(Some(u64::MAX), u64::MAX));
    }
}
