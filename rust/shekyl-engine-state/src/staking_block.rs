// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Staking block — archival-firewall persona bookkeeping.
//!
//! Fifth `.wallet`-side ledger block (after [`LedgerBlock`],
//! [`BookkeepingBlock`], [`TxMetaBlock`], and [`SyncStateBlock`]). It
//! carries the small, **public**, chain-reconciled state the engine
//! needs to drive the archival staking firewall across restarts:
//!
//! * `staking_enabled` — whether this wallet participates in archival
//!   staking. Gates the eager persona derivation at `assemble()`: a
//!   non-staker derives and holds nothing.
//! * `p_slot` — the **persona slot cursor**: the active archival
//!   persona index. Rotation is sequential (`p_slot' = p_slot + 1`,
//!   per `ARCHIVAL_FIREWALL_GATE6.md` §9.2). See "Why a monotone
//!   cursor" below — this value is a *reconciled hint*, not a trusted
//!   counter.
//! * `bonded_slots` — the **per-persona live-bond record**: the slot
//!   indices believed to hold an on-chain bond (`posted`) or a built,
//!   pending-broadcast bond (`consumer_held`). It lets `assemble()`
//!   reconstruct the "derive-forward" set — `{live-bonded slots} ∪
//!   {current ..= current+k}` — after a reopen so a persona that was
//!   rotated past but still holds a bond stays reachable for
//!   unbonding. See "Why a hint, not a source of truth" below.
//!
//! # Why this lives in `WalletLedger` (not `SettingsBlock`/`WalletPrefs`)
//!
//! "Which of my personas hold on-chain bonds" is the wallet's
//! reconciled view of its own chain state — the same *kind* of state
//! as the output/balance set in [`BookkeepingBlock`], reconciled the
//! same way (scan → reconcile → rewrite). It is ledger-shaped state
//! and belongs with the ledger. `p_slot`/`staking_enabled` are more
//! config-shaped but are **funds-load-bearing config** — lose them and
//! the engine stops deriving the personas that hold bonds — so they
//! want the sealed, integrity-protected region-2 tier regardless.
//! `WalletPrefs` (advisory tier, tamper-resets to defaults) would
//! silently drop funds-load-bearing state; `SettingsBlock`
//! (region-2 metadata) is not loaded by the Rust engine's
//! `assemble()` path and is read by the C++/wallet2 surface, which has
//! no use for staking state. `WalletLedger` is the correct tier, the
//! correct semantic home, and keeps staking entirely inside the Rust
//! domain with its own [`STAKING_BLOCK_VERSION`].
//!
//! # Why a hint, not a source of truth
//!
//! Persona persistence is **persist-before-use**: the staking record
//! commits durably *before* the persona signs a bond. A crash in that
//! window can leave a `bonded_slots` entry with no corresponding
//! on-chain (or pending) bond — a *phantom*. If the engine trusted
//! `bonded_slots` as authoritative it would derive that slot forever,
//! every open, for nothing. So `bonded_slots` is a **derive-time hint
//! reconciled against actual bond state** (scan posted + consumer-held
//! bonds, drop slots with no real bond, rewrite the block). The
//! reconciliation needs persona scanning (which needs the personas
//! derived first), so it is **2d-era** work, not done here. What this
//! block freezes is the *correctability*: a flat `Vec<u32>` with these
//! documented semantics lets 2d garbage-collect orphans **without a
//! second [`STAKING_BLOCK_VERSION`] bump**. No aggregator invariant
//! treats `bonded_slots` as truth — adding one would contradict the
//! hint semantics.
//!
//! # Why a monotone cursor
//!
//! Region-2 sealing provides confidentiality and integrity but not
//! necessarily *anti-rollback*: a sealed blob can be replaced with an
//! older, still-validly-sealed one. Combined with the persist-before-use
//! window where `p_slot` can briefly lag actual on-chain usage, a stale
//! or rolled-back cursor would re-activate a slot already rotated past
//! — and **re-using a retired persona links its activities**, defeating
//! the unlinkability the rotation exists to provide. This is a privacy
//! property, not only a funds one. [`StakingBlock::monotone_current_slot`]
//! enforces the fix: `current = max(persisted p_slot, highest_bonded_slot_seen + 1)`,
//! so the active slot can never sit at or below a slot with observed
//! activity. The scan heals a reverted cursor, so the design tolerates
//! the one tier property (anti-rollback) region 2 does not guarantee.
//!
//! # Wire format
//!
//! Postcard-serialized inside [`WalletLedger`], sealed by the same
//! AEAD seal and written by the same crash-atomic, durable
//! `atomic_write_file` path (`tmp → fsync → rename → fsync(parent)`)
//! as every other ledger block — so a persisted record is a durable,
//! crash-atomic commit. Small, schema-narrow, fully `PartialEq` — no
//! secrets live here (slot indices and flags are public), so the test
//! matrix asserts strict value equality after round-trip.
//!
//! [`LedgerBlock`]: crate::ledger_block::LedgerBlock
//! [`BookkeepingBlock`]: crate::bookkeeping_block::BookkeepingBlock
//! [`TxMetaBlock`]: crate::tx_meta_block::TxMetaBlock
//! [`SyncStateBlock`]: crate::sync_state_block::SyncStateBlock
//! [`WalletLedger`]: crate::wallet_ledger::WalletLedger

use serde::{Deserialize, Serialize};

use crate::error::WalletLedgerError;

/// Schema version of the staking block. V3.0 ships version `1`.
/// Any field addition / removal / renaming bumps this; loads that see
/// a different version refuse rather than migrate.
pub const STAKING_BLOCK_VERSION: u32 = 1;

/// Archival-firewall persona bookkeeping. See module docs for scope,
/// versioning, the hint-not-truth `bonded_slots` semantics, and the
/// monotone-cursor rule on `p_slot`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct StakingBlock {
    /// Per-block schema version. Always [`STAKING_BLOCK_VERSION`] on
    /// construction; rejected on load if it does not match.
    pub block_version: u32,

    /// Whether this wallet participates in archival staking. Gates the
    /// eager persona derivation at `assemble()`.
    #[serde(default)]
    pub staking_enabled: bool,

    /// Active persona slot cursor. A reconciled hint, never trusted on
    /// its own — see [`Self::monotone_current_slot`].
    #[serde(default)]
    pub p_slot: u32,

    /// Slots believed to hold a live bond (posted or consumer-held).
    /// A reconcilable hint, not a source of truth: 2d reconciliation
    /// scans actual bond state and rewrites this set, dropping phantoms.
    #[serde(default)]
    pub bonded_slots: Vec<u32>,
}

impl Default for StakingBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl StakingBlock {
    /// Fresh, empty staking block pinned to the current version:
    /// staking disabled, cursor at slot 0, no bonded slots.
    pub fn empty() -> Self {
        Self {
            block_version: STAKING_BLOCK_VERSION,
            staking_enabled: false,
            p_slot: 0,
            bonded_slots: Vec::new(),
        }
    }

    /// Construct a staking block with explicit fields, pinning the
    /// current version.
    pub fn new(staking_enabled: bool, p_slot: u32, bonded_slots: Vec<u32>) -> Self {
        Self {
            block_version: STAKING_BLOCK_VERSION,
            staking_enabled,
            p_slot,
            bonded_slots,
        }
    }

    /// The reconciled active slot: `max(p_slot, highest_bonded_slot_seen + 1)`.
    ///
    /// `highest_bonded_slot_seen` is the highest slot index for which
    /// the caller has observed *real* on-chain (or pending) activity —
    /// chain evidence in the 2d full-scan path, or the persisted
    /// [`Self::bonded_slots`] hint before that (see
    /// [`Self::monotone_current_slot_from_record`]). Passing `None`
    /// (no observed activity) returns the persisted cursor unchanged.
    ///
    /// This is the monotone-forward guard: the returned slot can never
    /// sit at or below a slot with observed activity, so a stale or
    /// rolled-back persisted cursor cannot re-activate a retired
    /// persona and link its activities. `saturating_add` keeps the
    /// `u32::MAX` edge total rather than wrapping into a low slot.
    pub fn monotone_current_slot(&self, highest_bonded_slot_seen: Option<u32>) -> u32 {
        match highest_bonded_slot_seen {
            Some(highest) => self.p_slot.max(highest.saturating_add(1)),
            None => self.p_slot,
        }
    }

    /// [`Self::monotone_current_slot`] using the persisted
    /// [`Self::bonded_slots`] hint as the activity evidence. This is
    /// the self-heal available at open *before* a full chain scan: the
    /// cursor is pulled forward past any persisted bonded slot. The 2d
    /// scan path supplies stronger (chain-observed) evidence when it
    /// lands.
    pub fn monotone_current_slot_from_record(&self) -> u32 {
        self.monotone_current_slot(self.bonded_slots.iter().copied().max())
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`]. Refuses any version mismatch.
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        let block: Self = postcard::from_bytes(bytes)?;
        block.check_version()?;
        Ok(block)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so [`WalletLedger`](crate::wallet_ledger::WalletLedger)
    /// can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        if self.block_version != STAKING_BLOCK_VERSION {
            return Err(WalletLedgerError::UnsupportedBlockVersion {
                block: "staking",
                file: self.block_version,
                binary: STAKING_BLOCK_VERSION,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn populated() -> StakingBlock {
        StakingBlock {
            block_version: STAKING_BLOCK_VERSION,
            staking_enabled: true,
            p_slot: 7,
            bonded_slots: vec![2, 3, 5],
        }
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = StakingBlock::empty();
        assert_eq!(b.block_version, STAKING_BLOCK_VERSION);
        assert!(!b.staking_enabled);
        assert_eq!(b.p_slot, 0);
        assert!(b.bonded_slots.is_empty());
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = StakingBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_roundtrips_value_equality() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = StakingBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    #[test]
    fn populated_block_is_byte_stable() {
        let b = populated();
        let bytes1 = b.to_postcard_bytes().expect("serialize1");
        let back = StakingBlock::from_postcard_bytes(&bytes1).expect("deserialize");
        let bytes2 = back.to_postcard_bytes().expect("serialize2");
        assert_eq!(bytes1, bytes2, "postcard encoding must be byte-stable");
    }

    #[test]
    fn mismatched_block_version_is_refused() {
        let mut b = StakingBlock::empty();
        b.block_version = 999;
        let bytes = b.to_postcard_bytes().expect("serialize");
        match StakingBlock::from_postcard_bytes(&bytes).unwrap_err() {
            WalletLedgerError::UnsupportedBlockVersion {
                block,
                file,
                binary,
            } => {
                assert_eq!(block, "staking");
                assert_eq!(file, 999);
                assert_eq!(binary, STAKING_BLOCK_VERSION);
            }
            other => panic!("expected UnsupportedBlockVersion, got {other:?}"),
        }
    }

    #[test]
    fn truncated_postcard_input_is_refused() {
        let b = populated();
        let bytes = b.to_postcard_bytes().expect("serialize");
        let chopped = &bytes[..bytes.len() / 2];
        let is_postcard = matches!(
            StakingBlock::from_postcard_bytes(chopped).unwrap_err(),
            WalletLedgerError::Postcard(_),
        );
        assert!(is_postcard, "truncated input must hit the postcard branch");
    }

    #[test]
    fn monotone_cursor_with_no_evidence_returns_persisted() {
        let b = StakingBlock::new(true, 5, vec![]);
        assert_eq!(b.monotone_current_slot(None), 5);
        assert_eq!(b.monotone_current_slot_from_record(), 5);
    }

    #[test]
    fn monotone_cursor_pulls_forward_past_observed_activity() {
        // Persisted cursor is stale (rolled back to 2) but slot 4 is
        // bonded on-chain: the cursor must jump to 5, never re-activate 4.
        let b = StakingBlock::new(true, 2, vec![]);
        assert_eq!(b.monotone_current_slot(Some(4)), 5);
    }

    #[test]
    fn monotone_cursor_keeps_persisted_when_ahead() {
        // Persisted cursor already ahead of observed activity: keep it.
        let b = StakingBlock::new(true, 9, vec![]);
        assert_eq!(b.monotone_current_slot(Some(4)), 9);
    }

    #[test]
    fn monotone_cursor_from_record_uses_highest_bonded_slot() {
        // bonded_slots hint {2,3,5}: highest is 5, so current >= 6 even
        // if the persisted cursor lagged behind.
        let b = StakingBlock::new(true, 3, vec![2, 3, 5]);
        assert_eq!(b.monotone_current_slot_from_record(), 6);
    }

    #[test]
    fn monotone_cursor_saturates_at_u32_max() {
        // A bonded slot at u32::MAX must not wrap to 0.
        let b = StakingBlock::new(true, 0, vec![u32::MAX]);
        assert_eq!(b.monotone_current_slot_from_record(), u32::MAX);
    }

    proptest! {
        #[test]
        fn populated_block_round_trip_proptest(
            enabled in any::<bool>(),
            p_slot in any::<u32>(),
            bonded in proptest::collection::vec(any::<u32>(), 0..8),
        ) {
            let b = StakingBlock {
                block_version: STAKING_BLOCK_VERSION,
                staking_enabled: enabled,
                p_slot,
                bonded_slots: bonded,
            };
            let bytes = b.to_postcard_bytes().expect("serialize");
            let back = StakingBlock::from_postcard_bytes(&bytes).expect("deserialize");
            prop_assert_eq!(&back, &b);
            let bytes2 = back.to_postcard_bytes().expect("serialize2");
            prop_assert_eq!(bytes, bytes2);
        }

        #[test]
        fn monotone_cursor_never_below_observed(
            p_slot in any::<u32>(),
            highest in any::<u32>(),
        ) {
            let b = StakingBlock::new(true, p_slot, vec![]);
            let current = b.monotone_current_slot(Some(highest));
            // Never re-activates an observed slot, and never below the
            // persisted cursor.
            prop_assert!(current >= p_slot);
            prop_assert!(current > highest || highest == u32::MAX);
        }

        #[test]
        fn any_wrong_version_is_refused(bad in any::<u32>().prop_filter(
            "must differ from current version",
            |v| *v != STAKING_BLOCK_VERSION,
        )) {
            let mut b = StakingBlock::empty();
            b.block_version = bad;
            let bytes = b.to_postcard_bytes().expect("serialize");
            let err = StakingBlock::from_postcard_bytes(&bytes).unwrap_err();
            let is_version_err = matches!(
                err,
                WalletLedgerError::UnsupportedBlockVersion { .. }
            );
            prop_assert!(is_version_err, "expected UnsupportedBlockVersion");
        }
    }
}
