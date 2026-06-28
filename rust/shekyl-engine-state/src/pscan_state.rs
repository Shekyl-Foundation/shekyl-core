// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SP-5 (PR-B) — [`PScanState`]: the durable, `P`-isolated scan state.
//!
//! The one durable artifact of the archival-persona scan: the scan frontier
//! ([`PScanCursor`], SP-2) **and** the per-settlement-epoch confirmed funding
//! accruals (SP-4), sealed together. The engine layer wraps this in the
//! StakingBlock-class envelope (AEAD + `atomic_write_file`) to a `P`-isolated
//! file, distinct from the principal wallet ledger
//! (`docs/design/ARCHIVAL_BOND_2D1_PSCAN_PLAN.md` §6 SP-2/SP-4).
//!
//! ## One atomic file ⇒ the SP-2 write-discipline for free
//!
//! Cursor and accruals live in **one** [`PScanState`] sealed atomically. So the
//! cursor can never seal past the accruals it was computed with: a crash leaves
//! the *whole* prior state or the *whole* next one, never a torn `(cursor,
//! accruals)` pair. On resume, `P` re-scans from the sealed `synced_height`
//! forward and the per-epoch accrual recompute is idempotent (SP-4), so the
//! redundant re-scan changes nothing. There is no second durable frontier and no
//! cross-record commit ordering to get wrong — the file's atomicity *is* the
//! discipline (Design B).
//!
//! ## Finality lives in the cursor, not the accruals type
//!
//! An `accruals` entry is **ownership-confirmed** (it is summed only from outputs
//! that passed the full scan) *and* **finality-confirmed** — but only the first
//! is type-carried. Finality is the SP-2 cursor invariant: an epoch is finalized
//! into `accruals` only once the cursor has advanced past it behind the reorg
//! horizon. So `PScanState`'s soundness is exactly the cursor discipline's.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockHeight, SettlementEpoch};
use shekyl_units::AtomicUnits;

use crate::error::WalletLedgerError;
use crate::pscan_cursor::PScanCursor;

/// Schema version of the durable P-scan state. V3.0 ships version `1`. Any field
/// addition / removal / renaming bumps this; loads that see a different version
/// **refuse rather than migrate** (the `StakingBlock` precedent). Distinct from
/// the inner [`PScanCursor`]'s own version (nested, like the wallet ledger over
/// its sub-blocks).
pub const PSCAN_STATE_VERSION: u32 = 1;

/// `P`'s durable scan state (SP-5): the [`PScanCursor`] frontier plus the
/// per-epoch confirmed funding accruals, the unit the engine seals to the
/// `P`-isolated file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PScanState {
    /// Per-state schema version — [`PSCAN_STATE_VERSION`] on construction,
    /// version-gated on load.
    version: u32,
    /// The single authoritative durable scan frontier (SP-2).
    cursor: PScanCursor,
    /// Per settlement-epoch confirmed funding totals, finalized once an epoch is
    /// finality-sealed behind the cursor (SP-4 idempotent recompute). Keyed by
    /// [`SettlementEpoch`] — not a bare `u64` — and `BTreeMap`-ordered, so the
    /// postcard encoding is canonical (sorted) without the producer sorting.
    accruals: BTreeMap<SettlementEpoch, AtomicUnits>,
}

impl PScanState {
    /// A fresh state at genesis: pre-scan cursor, no accruals.
    pub fn genesis() -> Self {
        Self {
            version: PSCAN_STATE_VERSION,
            cursor: PScanCursor::genesis(),
            accruals: BTreeMap::new(),
        }
    }

    /// A state pinned to `cursor` with the given per-epoch `accruals`, stamped
    /// with the current version. The caller (the SP-5 scan task) owns the
    /// invariant that `accruals` covers exactly the epochs finalized behind
    /// `cursor`.
    pub fn new(cursor: PScanCursor, accruals: BTreeMap<SettlementEpoch, AtomicUnits>) -> Self {
        Self {
            version: PSCAN_STATE_VERSION,
            cursor,
            accruals,
        }
    }

    /// The scan frontier cursor.
    pub fn cursor(&self) -> &PScanCursor {
        &self.cursor
    }

    /// The frontier height (`cursor.synced_height()`).
    pub fn synced_height(&self) -> BlockHeight {
        self.cursor.synced_height()
    }

    /// The on-state schema version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The per-epoch confirmed funding accruals.
    pub fn accruals(&self) -> &BTreeMap<SettlementEpoch, AtomicUnits> {
        &self.accruals
    }

    /// The finalized confirmed inflow for `epoch`, or [`AtomicUnits::ZERO`] if no
    /// funding was confirmed in it.
    pub fn accrual_for(&self, epoch: SettlementEpoch) -> AtomicUnits {
        self.accruals
            .get(&epoch)
            .copied()
            .unwrap_or(AtomicUnits::ZERO)
    }

    /// The total confirmed inflow across all finalized epochs — the signal
    /// `C_min` sizing consumes. `None` on a `u64` overflow (fail closed; never
    /// wrap a money total).
    pub fn total_accrued(&self) -> Option<AtomicUnits> {
        AtomicUnits::checked_sum(self.accruals.values().copied())
    }

    /// Serialize to postcard bytes (the inner half of the seal; the engine layer
    /// applies the AEAD + atomic write to the `P`-isolated file).
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from [`Self::to_postcard_bytes`] output. **Refuses a version
    /// mismatch** on the outer state version; the inner [`PScanCursor`] applies
    /// its own version gate on access via its constructors.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let state: Self = postcard::from_bytes(bytes)?;
        state.check_version()?;
        state.cursor.check_version()?;
        Ok(state)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed so a future composite loader can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.version != PSCAN_STATE_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "pscan_state",
                file: self.version,
                binary: PSCAN_STATE_VERSION,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accruals(pairs: &[(u64, u64)]) -> BTreeMap<SettlementEpoch, AtomicUnits> {
        pairs
            .iter()
            .map(|&(e, a)| (SettlementEpoch::from_raw(e), AtomicUnits::from_raw(a)))
            .collect()
    }

    #[test]
    fn round_trips_cursor_and_accruals() {
        let state = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(40_000)),
            accruals(&[(2, 100), (3, 250)]),
        );
        let bytes = state.to_postcard_bytes().expect("serialize");
        let back = PScanState::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, state);
        assert_eq!(back.synced_height(), BlockHeight::from_raw(40_000));
        assert_eq!(
            back.accrual_for(SettlementEpoch::from_raw(3)),
            AtomicUnits::from_raw(250)
        );
    }

    #[test]
    fn genesis_is_empty_at_height_zero() {
        let state = PScanState::genesis();
        assert_eq!(state.synced_height(), BlockHeight::ZERO);
        assert!(state.accruals().is_empty());
        assert_eq!(state.total_accrued(), Some(AtomicUnits::ZERO));
    }

    #[test]
    fn accrual_for_a_missing_epoch_is_zero() {
        let state = PScanState::new(PScanCursor::genesis(), accruals(&[(5, 9)]));
        assert_eq!(
            state.accrual_for(SettlementEpoch::from_raw(4)),
            AtomicUnits::ZERO
        );
        assert_eq!(
            state.accrual_for(SettlementEpoch::from_raw(5)),
            AtomicUnits::from_raw(9)
        );
    }

    #[test]
    fn total_accrued_sums_all_epochs() {
        let state = PScanState::new(
            PScanCursor::genesis(),
            accruals(&[(1, 10), (2, 20), (3, 30)]),
        );
        assert_eq!(state.total_accrued(), Some(AtomicUnits::from_raw(60)));
    }

    #[test]
    fn total_accrued_fails_closed_on_overflow() {
        let state = PScanState::new(PScanCursor::genesis(), accruals(&[(1, u64::MAX), (2, 1)]));
        assert_eq!(state.total_accrued(), None, "must not wrap a money total");
    }

    #[test]
    fn rejects_a_state_version_mismatch_on_load() {
        // A wrong-version state, serialized through the real path (the test child
        // module can reach the private fields).
        let wrong = PScanState {
            version: PSCAN_STATE_VERSION + 1,
            cursor: PScanCursor::genesis(),
            accruals: BTreeMap::new(),
        };
        let forged = wrong
            .to_postcard_bytes()
            .expect("serialize wrong-version state");
        match PScanState::from_postcard_bytes(&forged) {
            Err(WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            }) => {
                assert_eq!(block, "pscan_state");
                assert_eq!(file, PSCAN_STATE_VERSION + 1);
                assert_eq!(binary, PSCAN_STATE_VERSION);
            }
            other => panic!("expected state version rejection, got {other:?}"),
        }
    }
}
