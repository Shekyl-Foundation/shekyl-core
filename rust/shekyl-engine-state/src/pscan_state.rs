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
use shekyl_types::{BlockHeight, GlobalOutputIndex, PCanonicalId, PSlot, SettlementEpoch, TxHash};
use shekyl_units::AtomicUnits;

use crate::error::WalletLedgerError;
use crate::pscan_cursor::PScanCursor;

/// Schema version of the durable P-scan state. **v6** domain-newtypes the
/// residual raw fields on [`PFundingOutputRecord`] (`p_slot` → [`PSlot`],
/// `tx_hash` → [`TxHash`], `gindex` → [`GlobalOutputIndex`] — FOLLOWUPS
/// WI-2 orchestrator carrier; postcard-transparent, fail-closed on mismatch);
/// **v5** adds the
/// [`MintLineageOutput`] `lineage` field and the `spendable_height` field on
/// [`PFundingOutputRecord`] (GF-4b backing-lineage ladder + sweep
/// spendability filter, `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3/§3.6 — one
/// bump covers both); **v4** added
/// the durable `funding_outputs` (WI-2 D-A1, `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.1
/// — the per-output funding-discovery records bond assembly selects from); **v3**
/// added the durable `bond_post_matches` (SP-6 reconcile evidence); **v2** tracked
/// the nested [`PScanCursor`] gaining its verified-frontier `frontier_hash`. Any
/// field addition / removal / renaming bumps this; loads that see a different
/// version **refuse rather than migrate** (the `StakingBlock` precedent). No
/// migration at any step: pre-genesis, a version mismatch means re-scan (rule 15).
/// Distinct from the inner [`PScanCursor`]'s own version (nested, like the wallet
/// ledger over its sub-blocks).
pub const PSCAN_STATE_VERSION: u32 = 6;

/// The GF-4b mint-lineage ladder for a `P`-owned funding output — the
/// scan-provenance classification (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3;
/// ladder: `ARCHIVAL_FIREWALL_GATE6.md` §2.4 GF-4b), most→least safe as an
/// emission backing output. The emission vin reveals the backing output's
/// `pqc_pk` in cleartext, deterministically identifying that one output and
/// its creating tx; the ladder classifies what that identification newly
/// reveals.
///
/// **Classification is structural and fails toward the forbidden rung:**
/// anything not structurally proven rung 1/2 at the scan seam classifies
/// [`ExternalTransfer`](Self::ExternalTransfer). A misclassification in that
/// direction can only *exclude* a safe output from backing eligibility, never
/// admit an unsafe one.
///
/// **There is no miner/coinbase rung.** `P` is a shard-serving persona only;
/// mining is conducted under the principal (adding capability to `P` adds
/// identification surface — owner ruling, `ARCHIVAL_GF4B_BACKING_LINEAGE.md`
/// §3.3). A coinbase output recovered by `P`'s scanner is an anomaly (wallet
/// bug or adversarial tag — `P`'s hybrid pubkey is on-chain in the bond
/// post), and it classifies [`ExternalTransfer`](Self::ExternalTransfer)
/// structurally: a coinbase tx carries only `Input::Gen`, never a `BondPost`
/// input.
///
/// Consensus is lineage-blind (`REWARD_EMISSION_VIN_PLAN.md` §8.0.3 —
/// unenforceable by construction), so this wallet-side type is the **only**
/// enforcement layer; the `BackingSet` pre-join type consumes it.
///
/// Plain derived `Debug`: a rung tag alone is not a row of `P`'s funding
/// history — the records carrying it stay redacted wholesale.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub enum MintLineageOutput {
    /// Rung 1 — recovered from a transaction carrying `P`'s own
    /// `txin_archival_reward_emission`. Constructed by C-1's emission-vin
    /// scan arm (`shekyl-engine-core`'s `run_dual_extractor` rung-1
    /// pre-pass), which is bound to the fail-toward-forbidden rule as its
    /// acceptance criterion (GF4b-4, `ARCHIVAL_GF4B_BACKING_LINEAGE.md`
    /// §5 residue item 2): only a structurally-proven own emission vin —
    /// blob parsed exactly by the archival-retention reader, derived
    /// `p_canonical_id` ours, carrying-tx hash present — lifts an output
    /// here; every non-own case stays
    /// [`ExternalTransfer`](Self::ExternalTransfer).
    EmissionReward,
    /// Rung 2 — recovered from a transaction carrying a `BondPost` input whose
    /// `p_canonical_id` is the recovered output's **own** persona: bond-post
    /// change. The creating tx is already `P`-public and its backward lineage
    /// is FCMP++-hidden — the bond post is itself one churn hop.
    BondPostChange,
    /// Rung 3 — everything else: raw pre-bond-post principal funding, the
    /// **forbidden** backing rung (its reveal newly identifies the funding tx
    /// and its timing — funding-height → off-chain-principal correlation).
    /// The GF-4b sweep makes this rung structurally empty post-bond; the
    /// `BackingSet` constructor makes it unrepresentable as backing.
    ExternalTransfer,
}

/// A persisted archival bond-post match (SP-6 reconcile evidence): an on-chain
/// bond-post whose `p_canonical_id` is one of `P`'s personas. The **durable, sealed
/// twin** of the engine-core extractor's transform-shaped `BondPostMatch` (rule 18):
/// `P` accumulates these as it scans so the reconcile set survives restart — the
/// cursor never re-scans below its frontier, so a match seen in an earlier run would
/// otherwise be unavailable when 2d-2 SP-R0 corroborates an `Unbond` at retire time
/// (`MAX_CLAIM_AGE_W` epochs after it was observed). All fields are public: a
/// bond-post and its id are on-chain — but **correlated and co-located off-chain is
/// the leak** the firewall exists to prevent, so this type follows the persona-key
/// no-clear-`Debug` discipline (see the `Debug` impl), not the looser treatment a
/// public amount-delta gets.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct BondPostRecord {
    /// Height of the block carrying the post.
    pub height: BlockHeight,
    /// The matched persona's canonical id (a public on-chain pseudonym handle).
    pub p_canonical_id: PCanonicalId,
    /// Wire post-kind byte (`0` = JoinMarket; otherwise the `Other` tag).
    pub post_kind: u8,
}

impl std::fmt::Debug for BondPostRecord {
    /// **Redacted on purpose.** The `(p_canonical_id, height, post_kind)` tuple is a
    /// row of `P`'s bond-post history — the persona-activity ledger the firewall keeps
    /// off-disk-in-the-clear. A derived `Debug` would leak it through any log / error /
    /// `{:?}` path that the public amount-deltas and epochs never trigger, so we never
    /// render the contents. This is the same discipline the persona keys carry.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BondPostRecord(<redacted persona-history>)")
    }
}

/// A persisted `P`-owned funding output (WI-2 D-A1,
/// `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §3.1): the **public identity** of one output
/// the P-scan recovered for a bonded persona — everything bond assembly needs to
/// select, path-prove, and re-derive spend secrets for the output **without a
/// targeted network fetch** (a per-output fetch at assemble time is a
/// probe-shaped correlation leak; the scan records identity while the block is
/// in hand as cover).
///
/// **No derived secrets** — `y` / `z` / `k_amount` / `combined_shared_secret`
/// drop in the scan's offload closure exactly as before (rule 16, the M3d
/// `TransferDetails` discipline). The spend bundle is re-derived at assemble
/// time inside the StakeEngine actor from `(ciphertext, index_in_transaction)`
/// and the persona's resident keys.
///
/// Every field is public on-chain data plus the recovered cleartext `amount`;
/// but the *set* ties amounts to persona slots — `P`'s funding history, the
/// same class as [`BondPostRecord`] — so it carries the same redacted-`Debug`
/// discipline.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
pub struct PFundingOutputRecord {
    /// The owning persona's slot ordinal (selects the re-derivation keys).
    pub p_slot: PSlot,
    /// Hash of the transaction carrying the output.
    pub tx_hash: TxHash,
    /// The output's index within its transaction — the KEM derivation index
    /// the spend-bundle re-derivation consumes.
    pub index_in_transaction: u64,
    /// The global (chain-wide) output index — the curve-tree leaf position
    /// (`AssembleInput::gindex`).
    pub gindex: GlobalOutputIndex,
    /// The on-chain output key `O` (compressed Edwards bytes).
    pub output_key: [u8; 32],
    /// The on-chain amount commitment point `C` (compressed Edwards bytes) —
    /// the *point*, never the opened `(mask, amount)` pair (the mask is a
    /// derived secret and is re-derived at assemble time).
    pub commitment: [u8; 32],
    /// X25519 half of the output's hybrid KEM ciphertext (public, on-chain).
    pub ciphertext_x25519: [u8; 32],
    /// ML-KEM-768 half of the output's hybrid KEM ciphertext (public, on-chain).
    pub ciphertext_ml_kem: Vec<u8>,
    /// The recovered cleartext amount.
    pub amount: AtomicUnits,
    /// Height of the block carrying the output.
    pub height: BlockHeight,
    /// The settlement epoch `height` falls in.
    pub epoch: SettlementEpoch,
    /// GF-4b mint-lineage rung, classified at the scan seam
    /// (`ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.3). Persisted so the C-1
    /// backing-eligibility gate (`BackingSet`) survives restart.
    pub lineage: MintLineageOutput,
    /// The height at which this output's leaf is present in the curve tree
    /// and the output becomes spendable — **literally** the shared
    /// [`crate::transfer::eligible_height`] result, stored at the scan seam
    /// (GF4b-6, `ARCHIVAL_GF4B_BACKING_LINEAGE.md` §3.6). The GF-4b sweep
    /// excludes records above its reference height: consuming an unspendable
    /// output would deny bonding until maturity (the leaf is absent from the
    /// tree, so no membership path exists), whether it arrived by ordinary
    /// fresh funding (+`SPENDABLE_AGE`) or an adversarial coinbase-to-`P`
    /// (+60 via the consensus-enforced `unlock_time` shape).
    pub spendable_height: BlockHeight,
}

impl std::fmt::Debug for PFundingOutputRecord {
    /// **Redacted on purpose** — a row of `P`'s funding history (persona slot,
    /// amount, placement). Same discipline as [`BondPostRecord`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PFundingOutputRecord(<redacted funding-history>)")
    }
}

/// `P`'s durable scan state (SP-5): the [`PScanCursor`] frontier, the per-epoch
/// confirmed funding accruals, and the accumulated bond-post matches — the unit the
/// engine seals to the `P`-isolated file.
///
/// `Debug` is **hand-written** (not derived) so it redacts `bond_post_matches` — even a
/// derived `Debug` that renders each [`BondPostRecord`] as `<redacted>` would still leak
/// the **match count** + structure (`P`'s persona-activity *volume*) through any `{:?}` /
/// log path, and the persisted state is the form most likely to hit one (a deserialize
/// error). The other fields render normally — `bond_post_matches` is the high-bar field
/// (see the field doc + the redacting `BondPostRecord::Debug`).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, postcard_schema::Schema)]
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
    /// Confirmed-but-retire-pending personas: [`PCanonicalId`] → the settlement
    /// epoch its `Unbond` was confirmed in (2d-1 DQ8).
    ///
    /// The **sole durable record** that a persona is unbonded: the `Unbond` block
    /// is behind the cursor and never re-scanned, and the StakeEngine union wipe is
    /// not durable until SP-6 (the persona re-derives on restart with no notion of
    /// "unbonded"). So this entry is what **re-triggers** the retire on each
    /// restart — it is kept until SP-6 durably removes the persona, **not** dropped
    /// when the retire fires (dropping it would let the re-derived persona regrow
    /// the union permanently). Public content (the id is a public on-chain
    /// pseudonym handle), bounded by `P`'s own unbonded-persona count (not
    /// adversary-controllable).
    pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
    /// Matched archival bond-posts (`p_canonical_id` ∈ `P`'s personas) accumulated
    /// across the scan — the **reconcile evidence** SP-6 binds to the verified
    /// `covered` range (the engine-core `PReconcileSet`). Durable for the same reason
    /// `pending_unbonds` is: the cursor never re-scans below its frontier, so a match
    /// from an earlier run must persist to be available when SP-R0 corroborates a
    /// terminal post at retire time. Ordered by scan (height); public and bounded by
    /// `P`'s own posting.
    bond_post_matches: Vec<BondPostRecord>,
    /// Per-output funding-discovery records (WI-2 D-A1) — the `P`-local output
    /// set bond assembly selects funding from (the "steady-state funding-output
    /// discovery" reader of `ARCHIVAL_BOND_PR2_CHAIN.md` §3.6 reader (a)).
    /// Ordered by scan (height, then gindex); everything behind the same
    /// finality horizon as `accruals` (an entry exists iff its epoch delta was
    /// ingested), and per-epoch sums of these records equal the `accruals`
    /// entries by construction. Bounded by `P`'s own funding inflow.
    funding_outputs: Vec<PFundingOutputRecord>,
}

impl std::fmt::Debug for PScanState {
    /// Renders every field except `bond_post_matches`, which is redacted to a constant
    /// placeholder (not even its length): it is `P`'s persona-activity history and its
    /// *count* alone is behavioral metadata the firewall keeps off-log. See the type
    /// docs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PScanState")
            .field("version", &self.version)
            .field("cursor", &self.cursor)
            .field("accruals", &self.accruals)
            .field("pending_unbonds", &self.pending_unbonds)
            .field("bond_post_matches", &"<redacted persona-history>")
            .field("funding_outputs", &"<redacted funding-history>")
            .finish()
    }
}

impl PScanState {
    /// A fresh state at genesis: pre-scan cursor, no accruals, no pending unbonds, no
    /// matches, no funding outputs.
    pub fn genesis() -> Self {
        Self {
            version: PSCAN_STATE_VERSION,
            cursor: PScanCursor::genesis(),
            accruals: BTreeMap::new(),
            pending_unbonds: BTreeMap::new(),
            bond_post_matches: Vec::new(),
            funding_outputs: Vec::new(),
        }
    }

    /// A state pinned to `cursor` with the given per-epoch `accruals`,
    /// `pending_unbonds`, `bond_post_matches`, and `funding_outputs`, stamped with
    /// the current version. The caller (the SP-5 scan task) owns the invariants that
    /// `accruals` covers exactly the epochs finalized behind `cursor`,
    /// `pending_unbonds` holds every persona whose `Unbond` was confirmed but not
    /// yet durably retired (SP-6), `bond_post_matches` holds every bond-post matched
    /// in `[0, cursor.synced_height)` (the reconcile evidence — complete because the
    /// scan is exhaustive over that verified range), and `funding_outputs` holds
    /// every recovered funding output over the same range (per-epoch sums equal the
    /// `accruals` entries).
    pub fn new(
        cursor: PScanCursor,
        accruals: BTreeMap<SettlementEpoch, AtomicUnits>,
        pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
        bond_post_matches: Vec<BondPostRecord>,
        funding_outputs: Vec<PFundingOutputRecord>,
    ) -> Self {
        Self {
            version: PSCAN_STATE_VERSION,
            cursor,
            accruals,
            pending_unbonds,
            bond_post_matches,
            funding_outputs,
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

    /// The confirmed-but-retire-pending personas (`p_canonical_id` → confirmed
    /// `Unbond` epoch) — the durable record that survives restart and re-triggers
    /// the DQ8 retire.
    pub fn pending_unbonds(&self) -> &BTreeMap<PCanonicalId, SettlementEpoch> {
        &self.pending_unbonds
    }

    /// The accumulated bond-post matches — the SP-6 reconcile evidence, complete over
    /// `[0, synced_height)` (the exhaustively-scanned verified range).
    pub fn bond_post_matches(&self) -> &[BondPostRecord] {
        &self.bond_post_matches
    }

    /// The per-output funding-discovery records (WI-2 D-A1) — the `P`-local
    /// output set bond assembly selects from, complete over `[0, synced_height)`.
    pub fn funding_outputs(&self) -> &[PFundingOutputRecord] {
        &self.funding_outputs
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

    fn pending(pairs: &[(u8, u64)]) -> BTreeMap<PCanonicalId, SettlementEpoch> {
        pairs
            .iter()
            .map(|&(id, e)| {
                (
                    PCanonicalId::from_bytes([id; 32]),
                    SettlementEpoch::from_raw(e),
                )
            })
            .collect()
    }

    fn bond_posts(rows: &[(u64, u8, u8)]) -> Vec<BondPostRecord> {
        rows.iter()
            .map(|&(height, id, post_kind)| BondPostRecord {
                height: BlockHeight::from_raw(height),
                p_canonical_id: PCanonicalId::from_bytes([id; 32]),
                post_kind,
            })
            .collect()
    }

    fn funding_output(slot: u32, gindex: u64, amount: u64, height: u64) -> PFundingOutputRecord {
        PFundingOutputRecord {
            p_slot: PSlot::from_raw(slot),
            tx_hash: TxHash::from_bytes([0xA1; 32]),
            index_in_transaction: 1,
            gindex: GlobalOutputIndex::from_raw(gindex),
            output_key: [0xB2; 32],
            commitment: [0xC3; 32],
            ciphertext_x25519: [0xD4; 32],
            ciphertext_ml_kem: vec![0xE5; 8],
            amount: AtomicUnits::from_raw(amount),
            height: BlockHeight::from_raw(height),
            epoch: SettlementEpoch::from_raw(2),
            lineage: MintLineageOutput::ExternalTransfer,
            spendable_height: crate::transfer::eligible_height(
                BlockHeight::from_raw(height),
                shekyl_types::Timelock::None,
            ),
        }
    }

    #[test]
    fn round_trips_cursor_accruals_pending_matches_and_funding() {
        let state = PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(40_000), [0x9C; 32]),
            accruals(&[(2, 100), (3, 250)]),
            pending(&[(0xAB, 7)]),
            bond_posts(&[(12_345, 0xAB, 0), (39_000, 0xCD, 2)]),
            vec![funding_output(3, 77, 100, 12_400)],
        );
        let bytes = state.to_postcard_bytes().expect("serialize");
        let back = PScanState::from_postcard_bytes(&bytes).expect("deserialize");
        assert_eq!(back, state);
        assert_eq!(back.synced_height(), BlockHeight::from_raw(40_000));
        assert_eq!(
            back.cursor().frontier_hash(),
            [0x9C; 32],
            "the verified-frontier anchor round-trips through the state seal"
        );
        assert_eq!(
            back.accrual_for(SettlementEpoch::from_raw(3)),
            AtomicUnits::from_raw(250)
        );
        assert_eq!(
            back.pending_unbonds()
                .get(&PCanonicalId::from_bytes([0xAB; 32])),
            Some(&SettlementEpoch::from_raw(7)),
            "pending unbonds round-trip through the seal"
        );
        assert_eq!(
            back.bond_post_matches(),
            bond_posts(&[(12_345, 0xAB, 0), (39_000, 0xCD, 2)]).as_slice(),
            "the bond-post reconcile evidence round-trips through the seal"
        );
        assert_eq!(
            back.funding_outputs(),
            &[funding_output(3, 77, 100, 12_400)],
            "the funding-output discovery records round-trip through the seal"
        );
    }

    #[test]
    fn funding_output_record_debug_is_redacted() {
        let rendered = format!("{:?}", funding_output(3, 77, 4_242, 12_400));
        assert!(
            rendered.contains("redacted"),
            "Debug must redact the funding-history row: {rendered}"
        );
        assert!(
            !rendered.contains("4242") && !rendered.contains("12400") && !rendered.contains("77"),
            "neither amount, height, nor gindex may appear: {rendered}"
        );
    }

    #[test]
    fn pscan_state_debug_redacts_funding_outputs_including_count() {
        let state = PScanState::new(
            PScanCursor::genesis(),
            accruals(&[]),
            pending(&[]),
            bond_posts(&[]),
            vec![
                funding_output(3, 77, 100, 12_400),
                funding_output(3, 78, 200, 12_401),
            ],
        );
        let rendered = format!("{state:?}");
        assert!(
            rendered.contains("<redacted funding-history>"),
            "funding outputs must be redacted in the state's Debug: {rendered}"
        );
        assert!(
            !rendered.contains("PFundingOutputRecord") && !rendered.contains("12400"),
            "neither contents nor per-entry structure (the count) may appear: {rendered}"
        );
    }

    #[test]
    fn bond_post_record_debug_is_redacted() {
        let rendered = format!("{:?}", bond_posts(&[(123_456, 0xAB, 2)])[0]);
        assert!(
            rendered.contains("redacted"),
            "Debug must redact the persona-history row: {rendered}"
        );
        assert!(
            !rendered.contains("123456") && !rendered.contains("171"),
            "neither the height nor the id byte may appear: {rendered}"
        );
    }

    #[test]
    fn pscan_state_debug_redacts_bond_post_matches_including_count() {
        let state = PScanState::new(
            PScanCursor::genesis(),
            accruals(&[]),
            pending(&[]),
            bond_posts(&[(123_456, 0xAB, 2), (789_012, 0xCD, 0)]),
            vec![],
        );
        let rendered = format!("{state:?}");
        assert!(
            rendered.contains("<redacted"),
            "matches must be redacted in the state's Debug: {rendered}"
        );
        // No contents and — critically — no per-entry structure, so the match *count*
        // (behavioral metadata) does not leak either.
        assert!(
            !rendered.contains("123456") && !rendered.contains("BondPostRecord"),
            "neither contents nor per-entry structure (the count) may appear: {rendered}"
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
        let state = PScanState::new(
            PScanCursor::genesis(),
            accruals(&[(5, 9)]),
            pending(&[]),
            bond_posts(&[]),
            vec![],
        );
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
            pending(&[]),
            bond_posts(&[]),
            vec![],
        );
        assert_eq!(state.total_accrued(), Some(AtomicUnits::from_raw(60)));
    }

    #[test]
    fn total_accrued_fails_closed_on_overflow() {
        let state = PScanState::new(
            PScanCursor::genesis(),
            accruals(&[(1, u64::MAX), (2, 1)]),
            pending(&[]),
            bond_posts(&[]),
            vec![],
        );
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
            pending_unbonds: BTreeMap::new(),
            bond_post_matches: Vec::new(),
            funding_outputs: Vec::new(),
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
