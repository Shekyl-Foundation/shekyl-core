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
//! * `persona_id_cache` — the bond watch's **probe-id cache**: public
//!   persona canonical ids for the probe window, derived once while the
//!   seed is transiently in scope at open and cached so every later open
//!   (and the credential-less `rescan_blockchain`) has candidates without
//!   re-paying the PQ keygen. See the field docs.
//! * `bond_sightings` — chain-observed bond posts from the principal
//!   scan's bond watch (slot → first sighted height): the durable bridge
//!   that keeps a probe-adopted bond safe from the phantom GC until the
//!   P-scan's own evidence covers it, and the first-stake resume guard's
//!   already-staked witness. See the field docs.
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

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use shekyl_types::{BlockHeight, PCanonicalId};

use crate::error::WalletLedgerError;

/// Schema version of the staking block. V3.0 ships version `2`
/// (`1` + the bond-watch probe-id cache and sighting rows).
/// Any field addition / removal / renaming bumps this; loads that see
/// a different version refuse rather than migrate.
pub const STAKING_BLOCK_VERSION: u32 = 2;

/// Archival-firewall persona bookkeeping. See module docs for scope,
/// versioning, the hint-not-truth `bonded_slots` semantics, and the
/// monotone-cursor rule on `p_slot`.
///
/// `Debug` is hand-written: `persona_id_cache` and `bond_sightings` are
/// persona-history-class rows (slot ↔ id / slot ↔ height associations), the
/// same no-clear-`Debug` discipline as `BondPostRecord` in the pscan state.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
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

    /// The bond-watch **probe-id cache**: persona canonical ids for the
    /// probe window `{bonded_slots} ∪ {cursor ..= cursor + W}`, keyed by
    /// slot. Ids are a deterministic pure function of `(seed, network,
    /// format, slot)` and never invalidate, so they are derived **once**
    /// (at the first open whose seed-in-scope window covers the slot) and
    /// cached here; every later open loads the map instead of paying the
    /// per-slot PQ keygen — that is what makes the principal scan's
    /// unconditional bond watch free at the rule-76 device floor. Public
    /// identifiers by function (`P` is public; the firewall protects only
    /// the `P`↔principal edge), but the slot↔id *association* is
    /// persona history — hence the redacted `Debug` and the AEAD seal.
    /// `BTreeMap` keeps serialization order canonical (two wallets in the
    /// same logical state produce identical bytes).
    #[serde(default)]
    pub persona_id_cache: BTreeMap<u32, PCanonicalId>,

    /// Chain-observed bond-post **sightings** from the principal scan's
    /// bond watch: slot → height of the first sighted `Input::BondPost`
    /// carrying that slot's canonical id. Written at refresh/rescan merge
    /// when a watched id is observed on-chain (the adoption that makes a
    /// restored persona derivable again); consumed by the open-time
    /// reconcile — arm #3 evaluates a sighted slot with the height-gated
    /// verdict (`reconcile(id, sighting_height)`), so a P-scan seal whose
    /// coverage predates the sighting reads `OutsideCovered` and cannot
    /// GC a real probe-adopted bond as phantom — and by the first-stake
    /// W2 resume guard (a sighted slot is already-staked). A row is
    /// pruned once the P-scan's own evidence carries the match
    /// (`Present`), which supersedes it.
    #[serde(default)]
    pub bond_sightings: BTreeMap<u32, BlockHeight>,
}

impl std::fmt::Debug for StakingBlock {
    /// Redacts `persona_id_cache` and `bond_sightings` — slot↔id and
    /// slot↔height rows are `P`'s history, kept off any log / error /
    /// `{:?}` path (the `BondPostRecord` discipline). The scalar fields
    /// stay rendered: they are the same slot ordinals the reconcile arms
    /// already log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StakingBlock")
            .field("block_version", &self.block_version)
            .field("staking_enabled", &self.staking_enabled)
            .field("p_slot", &self.p_slot)
            .field("bonded_slots", &self.bonded_slots)
            .field("persona_id_cache", &"<redacted persona-history>")
            .field("bond_sightings", &"<redacted persona-history>")
            .finish()
    }
}

impl Default for StakingBlock {
    fn default() -> Self {
        Self::empty()
    }
}

impl StakingBlock {
    /// Fresh, empty staking block pinned to the current version:
    /// staking disabled, cursor at slot 0, no bonded slots, empty
    /// probe cache, no sightings.
    pub fn empty() -> Self {
        Self {
            block_version: STAKING_BLOCK_VERSION,
            staking_enabled: false,
            p_slot: 0,
            bonded_slots: Vec::new(),
            persona_id_cache: BTreeMap::new(),
            bond_sightings: BTreeMap::new(),
        }
    }

    /// Construct a staking block with explicit scalar fields, pinning the
    /// current version. The probe cache and sightings start empty (they
    /// are scan-derived state, filled by the open path and the merge).
    pub fn new(staking_enabled: bool, p_slot: u32, bonded_slots: Vec<u32>) -> Self {
        Self {
            block_version: STAKING_BLOCK_VERSION,
            staking_enabled,
            p_slot,
            bonded_slots,
            persona_id_cache: BTreeMap::new(),
            bond_sightings: BTreeMap::new(),
        }
    }

    /// Record a bond-post sighting for `slot`, keeping the **first**
    /// sighted height if one is already recorded (the sighting's consumer
    /// — arm #3's height-gated verdict — needs the earliest height whose
    /// coverage proves or refutes the bond; a later duplicate must not
    /// advance the evidence bar). Returns `true` if this call inserted
    /// the row.
    pub fn record_first_sighting(&mut self, slot: u32, height: BlockHeight) -> bool {
        match self.bond_sightings.entry(slot) {
            std::collections::btree_map::Entry::Vacant(v) => {
                v.insert(height);
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
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
    ///
    /// `Some(highest)` is the chain-fed form (SA-R-6's scan-derivable
    /// half): a sealed blob has confidentiality and integrity, but not
    /// anti-rollback, so a stored counter alone can reset and re-offer a
    /// slot with on-chain activity. [`Self::monotone_current_slot_from_record`]
    /// is the hint-fed feed for the record's own bonded set.
    ///
    /// # Known limit — the guarantee degenerates at `u32::MAX`
    ///
    /// `saturating_add` stops the wrap to slot 0, but it makes `u32::MAX` a
    /// **fixed point**: once `u32::MAX` has been used, this still returns
    /// `u32::MAX`, so the value it reports as "current" is a slot the wallet
    /// already bound. Nothing here represents *slot-space exhaustion*, and the
    /// binding gate does not refuse it — so at that single point the SA-R-6
    /// no-reuse guarantee does not hold.
    ///
    /// Unreached by construction: slots are handed out one per bond, densely
    /// from 0 (`monotone_selection_is_dense_no_gap_reachable`), and every bond
    /// is an on-chain transaction — so occupying this state costs ~4.3 billion
    /// sequential bonds. Representing exhaustion and refusing at the binding
    /// gate is filed in `FOLLOWUPS.md`; **reopen immediately** if any path ever
    /// makes a high slot index reachable other than by sequential binding.
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

    /// The Model-D derive-forward set:
    /// `{bonded_slots} ∪ {cursor ..= cursor + lookahead}`, where `cursor`
    /// is [`Self::monotone_current_slot_from_record`].
    ///
    /// `checked_add` drops the `u32::MAX` tail rather than wrapping to
    /// slot 0 (which would re-derive a moved-past persona — the
    /// unlinkability break the monotone cursor exists to prevent).
    pub fn derive_forward_slots(&self, lookahead: u32) -> BTreeSet<u32> {
        let cursor = self.monotone_current_slot_from_record();
        let mut slots: BTreeSet<u32> = self.bonded_slots.iter().copied().collect();
        for offset in 0..=lookahead {
            if let Some(slot) = cursor.checked_add(offset) {
                slots.insert(slot);
            }
        }
        slots
    }

    /// Serialize to postcard bytes.
    pub fn to_postcard_bytes(&self) -> Result<Vec<u8>, WalletLedgerError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Deserialize from postcard bytes produced by
    /// [`Self::to_postcard_bytes`].
    /// **Refuses a version mismatch before decoding the body**, so a blob
    /// written by another schema version reports its version rather than
    /// surfacing as a codec error (see [`crate::version_gate`]).
    pub fn from_postcard_bytes(bytes: &[u8]) -> Result<Self, WalletLedgerError> {
        // Version first, body second — see [`crate::version_gate`]: postcard
        // carries no framing, so a stale blob decoded under the current
        // declaration fails as corruption before any post-decode check can
        // name the version. The gate reads only the leading varint.
        crate::version_gate::gate_leading_version(bytes, "staking", STAKING_BLOCK_VERSION)?;
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Version gate. Called automatically by [`Self::from_postcard_bytes`];
    /// exposed publicly so [`WalletLedger`](crate::wallet_ledger::WalletLedger)
    /// can fan out the same check.
    pub fn check_version(&self) -> Result<(), WalletLedgerError> {
        crate::version_gate::gate_version(self.block_version, "staking", STAKING_BLOCK_VERSION)
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
            persona_id_cache: BTreeMap::from([
                (2, PCanonicalId::from_bytes([0x22; 32])),
                (3, PCanonicalId::from_bytes([0x33; 32])),
                (5, PCanonicalId::from_bytes([0x55; 32])),
            ]),
            bond_sightings: BTreeMap::from([(3, BlockHeight::from_raw(987_654_321))]),
        }
    }

    #[test]
    fn empty_block_roundtrips_and_pins_version() {
        let b = StakingBlock::empty();
        assert_eq!(b.block_version, STAKING_BLOCK_VERSION);
        assert!(!b.staking_enabled);
        assert_eq!(b.p_slot, 0);
        assert!(b.bonded_slots.is_empty());
        assert!(b.persona_id_cache.is_empty());
        assert!(b.bond_sightings.is_empty());
        let bytes = b.to_postcard_bytes().expect("serialize");
        let back = StakingBlock::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, b);
    }

    /// The `Debug` impl must never render the persona-history rows — no id
    /// byte and no slot↔height pair may reach a log via `{:?}`. Scalars
    /// stay visible (same class the reconcile arms already log).
    #[test]
    fn debug_redacts_persona_history_rows() {
        let b = populated();
        let rendered = format!("{b:?}");
        assert!(
            rendered.contains("<redacted persona-history>"),
            "{rendered}"
        );
        // No byte of any cached id (0x22... etc. render as "34, 34" or hex)
        // and no sighting height may appear.
        assert!(!rendered.contains("34, 34"), "{rendered}");
        assert!(!rendered.contains("2222"), "{rendered}");
        assert!(!rendered.contains("987654321"), "{rendered}");
        // Scalars stay legible.
        assert!(rendered.contains("p_slot: 7"), "{rendered}");
    }

    /// `record_first_sighting` keeps the earliest height: a later duplicate
    /// must not advance the evidence bar arm #3's height-gated verdict
    /// reads from.
    #[test]
    fn first_sighting_wins_and_duplicates_are_ignored() {
        let mut b = StakingBlock::empty();
        assert!(b.record_first_sighting(4, BlockHeight::from_raw(100)));
        assert!(!b.record_first_sighting(4, BlockHeight::from_raw(200)));
        assert_eq!(b.bond_sightings.get(&4), Some(&BlockHeight::from_raw(100)));
        // A different slot inserts independently.
        assert!(b.record_first_sighting(5, BlockHeight::from_raw(200)));
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
        // The asserted property is NO WRAP: a bonded slot at u32::MAX must not
        // send the cursor back to 0, where it would re-offer slot 0 and hand
        // the operator a persona they rotated past 4 billion bonds ago.
        let b = StakingBlock::new(true, 0, vec![u32::MAX]);
        assert_ne!(
            b.monotone_current_slot_from_record(),
            0,
            "saturation must never wrap the cursor to a low slot"
        );

        // Deliberately NOT asserted as correct: the returned value is u32::MAX,
        // which is itself the bonded slot — i.e. at this one fixed point the
        // cursor names a USED slot, and SA-R-6 no-reuse does not hold. That is
        // a known, unreached limit (see `monotone_current_slot`'s docs and the
        // FOLLOWUPS entry), not a property. Pinned here only so the saturation
        // value is visible; an edit that made this refuse instead would be a
        // FIX, and this line is the one to delete.
        assert_eq!(
            b.monotone_current_slot_from_record(),
            u32::MAX,
            "current saturation behaviour — a limit, not a guarantee"
        );
    }

    #[test]
    fn derive_forward_slots_is_bonded_union_monotone_lookahead() {
        // cursor = max(4, 3+1) = 4; set = {1,3} ∪ {4,5,6} for lookahead=2.
        let b = StakingBlock::new(true, 4, vec![1, 3]);
        assert_eq!(
            b.derive_forward_slots(2).into_iter().collect::<Vec<_>>(),
            vec![1, 3, 4, 5, 6]
        );
    }

    /// Density invariant on the **allocation sequence**: the slots this
    /// wallet ever selects are `0, 1, 2, …` with no skip. That — not the
    /// live `bonded_slots` hint — is what the deferred from-seed
    /// reconstruction's "terminate at the first empty slot" rule rests on:
    /// the probe reads *on-chain history*, and it may stop at the first
    /// unused slot only if allocation never left a hole behind it.
    ///
    /// The live hint is explicitly **not** contiguous and must not be
    /// asserted to be: SP-R0 arms #2 and #3 delete rows from it (retired and
    /// phantom slots), so it is a GC'd view, not the allocation record. The
    /// second half of this test is the load-bearing part — it shows the
    /// sequence stays dense *despite* that GC, because `p_slot` carries the
    /// high-water mark independently of the hint. Drop the `p_slot` term
    /// from [`StakingBlock::monotone_current_slot`] and this fails.
    ///
    /// This bites against a sparse selection edit (a future `+k` rotation);
    /// it does NOT cover the chain-fed raise itself (that lives with the
    /// scan-evidence consumer).
    #[test]
    fn monotone_selection_is_dense_no_gap_reachable() {
        let mut st = StakingBlock::empty();
        let mut ever_selected = Vec::new();
        for expected in 0..64u32 {
            let slot = st.monotone_current_slot_from_record();
            assert_eq!(
                slot, expected,
                "selection must be dense (contiguous), never skip a slot"
            );
            ever_selected.push(slot);
            st.bonded_slots.push(slot);
            st.p_slot = st.monotone_current_slot_from_record();
        }
        assert_eq!(
            ever_selected,
            (0..64).collect::<Vec<u32>>(),
            "the allocation sequence is a gap-free contiguous prefix"
        );

        // Now GC the hint the way arms #2/#3 do — drop every row but one,
        // including the highest. Allocation must not rewind or skip: the
        // next slot is still 64, so the from-seed probe's termination rule
        // survives a hint that no longer lists the history.
        st.bonded_slots.retain(|s| *s == 7);
        assert_eq!(
            st.monotone_current_slot_from_record(),
            64,
            "hint GC must not rewind the cursor onto an already-used slot"
        );
    }

    proptest! {
        #[test]
        fn populated_block_round_trip_proptest(
            enabled in any::<bool>(),
            p_slot in any::<u32>(),
            bonded in proptest::collection::vec(any::<u32>(), 0..8),
            cache in proptest::collection::btree_map(any::<u32>(), any::<[u8; 32]>(), 0..8),
            sightings in proptest::collection::btree_map(any::<u32>(), any::<u64>(), 0..8),
        ) {
            let b = StakingBlock {
                block_version: STAKING_BLOCK_VERSION,
                staking_enabled: enabled,
                p_slot,
                bonded_slots: bonded,
                persona_id_cache: cache
                    .into_iter()
                    .map(|(k, v)| (k, PCanonicalId::from_bytes(v)))
                    .collect(),
                bond_sightings: sightings
                    .into_iter()
                    .map(|(k, v)| (k, BlockHeight::from_raw(v)))
                    .collect(),
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
