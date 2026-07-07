// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Windowed `ClaimedEpochSet` dedup semantics (`REWARD_EMISSION_LEG.md` §6.3,
//! encoding pinned 2026-06-11; window maintenance folded into the dedup
//! helper per the v4-schema review round, 2026-06-12).
//!
//! The set itself is stored as an inline field on the C++ `ArchivalBondValue`
//! LMDB codec (`src/blockchain_db/shekyl_types.h`, v4) — a strictly
//! increasing list of absolute settlement-epoch indices. The *semantics* of
//! mutating it are consensus rules and live here only, mirroring the
//! `good_through` split: C++ stores bytes, Rust decides
//! (`20-rust-vs-cpp-policy.mdc`; coarse-call FFI discipline). The FFI wrapper
//! lands with its first caller, the emission vin's connect path.
//!
//! Window maintenance is part of [`claimed_epochs_check_and_set`], not a
//! separate sweep:
//! entries below `current_settled_epoch − W` are pruned on insert. The prune
//! is safe by construction — a pruned epoch is unclaimable under the
//! `MAX_CLAIM_AGE_W` rule (§6.6), and `ARCHIVAL_REORG_DEPTH_BLOCKS` (720) is
//! far smaller than `SETTLEMENT_EPOCH_BLOCKS` (10_000), so no processable
//! reorg can resurrect the claimability of a pruned entry; its dedup state is
//! dead weight. An insert-only set would have a continuously-claiming honest
//! `P` overflow the entry cap at roughly epoch `W + slack` (~15 months in).

use crate::MAX_CLAIM_AGE_W;

/// Entry cap on the at-rest set: claim window `W` plus reorg slack.
///
/// §6.3 pins the cap at 32; the const assertion below keeps the derived form
/// honest against the pin if `max_claim_age_w` ever moves in
/// `config/consensus_constants.json`. The cap is unreachable through
/// [`claimed_epochs_check_and_set`] (a pruned, windowed set holds at most
/// `W` entries); it bounds what an untrusted at-rest decode will accept.
pub const MAX_CLAIMED_EPOCH_ENTRIES: u64 = MAX_CLAIM_AGE_W + 6;

const _: () = assert!(
    MAX_CLAIMED_EPOCH_ENTRIES == 32,
    "REWARD_EMISSION_LEG.md §6.3 pins the claimed-epoch cap at 32 \
     (W = 26 + 6 reorg slack); revisit the pin if max_claim_age_w moves"
);

/// Rejection reasons for [`claimed_epochs_check_and_set`]; the set is not
/// mutated on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimedEpochsError {
    /// `epoch >= current_settled_epoch`: only closed settlement epochs are
    /// claimable (the §4.5 lagged read cites `Σwork(E)` stored at the close
    /// of `E`).
    NotSettled,
    /// `epoch < current_settled_epoch − W`: forfeited under the
    /// `MAX_CLAIM_AGE_W` rule (§6.6).
    Expired,
}

/// True when `epoch` is already recorded in the strictly increasing `set`.
#[must_use]
pub fn claimed_epochs_contains(set: &[u64], epoch: u64) -> bool {
    set.binary_search(&epoch).is_ok()
}

/// The oldest still-claimable settlement epoch — `current_settled_epoch − W`
/// (`MAX_CLAIM_AGE_W`). An epoch strictly below this floor has fallen out of the
/// reward-claim window.
///
/// **Single source of the claim-window boundary.** The claim check
/// ([`claimed_epochs_check_and_set`]) and 2d-1's persona-retirement predicate both
/// compute the boundary through this one function, so it cannot drift or go
/// off-by-one between consumers — a retire boundary even one epoch shorter than the
/// claim window would wipe a persona that can still claim (stuck funds).
#[must_use]
pub fn claim_window_floor(current_settled_epoch: u64) -> u64 {
    current_settled_epoch.saturating_sub(MAX_CLAIM_AGE_W)
}

/// True when `epoch` has fallen below the claim window and can no longer be
/// claimed (`epoch < `[`claim_window_floor`]`(current_settled_epoch)`) — the
/// literal `Expired` boundary the claim check enforces. `current_settled_epoch`
/// must be a **finalized** settled epoch (the in-progress epoch is not settled).
#[must_use]
pub fn epoch_is_claim_expired(epoch: u64, current_settled_epoch: u64) -> bool {
    epoch < claim_window_floor(current_settled_epoch)
}

/// Record `epoch` as claimed at `current_settled_epoch`, maintaining the
/// window.
///
/// On a claimable `epoch` (closed and within the `W` window) this prunes
/// entries below `current_settled_epoch − W`, then returns `Ok(false)` if
/// `epoch` was already claimed (dedup hit — the caller rejects the vin) or
/// inserts it in order and returns `Ok(true)`. On an unclaimable `epoch` the
/// set is left untouched and the reason is returned.
///
/// `set` must be strictly increasing on entry (the at-rest invariant the
/// codec enforces); the function preserves that invariant along with the
/// span bound `back − front ≤ W`.
pub fn claimed_epochs_check_and_set(
    set: &mut Vec<u64>,
    epoch: u64,
    current_settled_epoch: u64,
) -> Result<bool, ClaimedEpochsError> {
    if epoch >= current_settled_epoch {
        return Err(ClaimedEpochsError::NotSettled);
    }
    // The expired boundary is [`epoch_is_claim_expired`] — the *same* predicate the
    // 2d-1 persona-retirement witness calls, so the two cannot drift (both resolve
    // through this one definition, not parallel inline copies).
    if epoch_is_claim_expired(epoch, current_settled_epoch) {
        return Err(ClaimedEpochsError::Expired);
    }

    // Prune entries that have themselves fallen below the window floor.
    let window_floor = claim_window_floor(current_settled_epoch);
    set.retain(|&e| e >= window_floor);

    match set.binary_search(&epoch) {
        Ok(_) => Ok(false),
        Err(pos) => {
            set.insert(pos, epoch);
            // Unreachable through this path: the post-prune window holds at
            // most W distinct epochs, and the cap is W + 6.
            debug_assert!(set.len() as u64 <= MAX_CLAIMED_EPOCH_ENTRIES);
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_new_epoch_and_dedups_repeat() {
        let mut set = Vec::new();
        assert_eq!(claimed_epochs_check_and_set(&mut set, 10, 12), Ok(true));
        assert_eq!(claimed_epochs_check_and_set(&mut set, 10, 12), Ok(false));
        assert_eq!(set, vec![10]);
    }

    #[test]
    fn out_of_order_insert_keeps_sorted() {
        let mut set = Vec::new();
        assert_eq!(claimed_epochs_check_and_set(&mut set, 11, 13), Ok(true));
        assert_eq!(claimed_epochs_check_and_set(&mut set, 9, 13), Ok(true));
        assert_eq!(claimed_epochs_check_and_set(&mut set, 10, 13), Ok(true));
        assert_eq!(set, vec![9, 10, 11]);
    }

    #[test]
    fn rejects_unsettled_epochs_without_mutation() {
        let mut set = vec![5];
        assert_eq!(
            claimed_epochs_check_and_set(&mut set, 12, 12),
            Err(ClaimedEpochsError::NotSettled)
        );
        assert_eq!(
            claimed_epochs_check_and_set(&mut set, 13, 12),
            Err(ClaimedEpochsError::NotSettled)
        );
        assert_eq!(set, vec![5]);
    }

    #[test]
    fn rejects_expired_epochs_without_mutation() {
        let current = MAX_CLAIM_AGE_W + 10;
        let mut set = vec![current - 1];
        assert_eq!(
            claimed_epochs_check_and_set(&mut set, 9, current),
            Err(ClaimedEpochsError::Expired)
        );
        assert_eq!(set, vec![current - 1]);
        // Window edge: `current − W` is the oldest claimable epoch.
        assert_eq!(
            claimed_epochs_check_and_set(&mut set, 10, current),
            Ok(true)
        );
    }

    #[test]
    fn prune_on_insert_drops_entries_below_window() {
        // Claims at epochs 1..=3 recorded early, then a claim far later:
        // the stale entries fall out as part of the insert.
        let mut set = Vec::new();
        for e in 1..=3 {
            assert_eq!(claimed_epochs_check_and_set(&mut set, e, e + 1), Ok(true));
        }
        let current = MAX_CLAIM_AGE_W + 30;
        assert_eq!(
            claimed_epochs_check_and_set(&mut set, current - 1, current),
            Ok(true)
        );
        assert_eq!(set, vec![current - 1]);
    }

    #[test]
    fn honest_continuous_claimer_never_overflows() {
        // The review-round liveness case: one claim per settlement epoch,
        // indefinitely. Insert-only semantics would overflow the entry cap
        // at ~epoch 33; the windowed helper must hold the set at ≤ W entries
        // with the span bound intact, forever.
        let mut set = Vec::new();
        for current in 1..=200u64 {
            assert_eq!(
                claimed_epochs_check_and_set(&mut set, current - 1, current),
                Ok(true),
                "honest claim rejected at epoch {current}"
            );
            assert!(set.len() as u64 <= MAX_CLAIM_AGE_W + 1);
            assert!(set.len() as u64 <= MAX_CLAIMED_EPOCH_ENTRIES);
            assert!(set.windows(2).all(|w| w[0] < w[1]));
            if let (Some(first), Some(last)) = (set.first(), set.last()) {
                assert!(last - first <= MAX_CLAIM_AGE_W);
            }
        }
    }

    #[test]
    fn contains_matches_membership() {
        let set = vec![3, 7, 9];
        assert!(claimed_epochs_contains(&set, 7));
        assert!(!claimed_epochs_contains(&set, 8));
        assert!(!claimed_epochs_contains(&[], 0));
    }
}
