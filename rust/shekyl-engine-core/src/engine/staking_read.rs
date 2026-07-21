// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Read-only staked-balance / staked-output aggregation (WI-RPC-1).
//!
//! One authoritative Engine read helper the wallet-RPC staking queries
//! project from. Aggregates exclusively from the **authoritative** durable
//! records — the sealed [`PScanState`] (funding outputs, bond-post reconcile
//! evidence, pending unbonds, retired ledger) and the sealed
//! [`PendingPostBlock`] (in-flight bond posts) — **never** from
//! `StakingBlock::bonded_slots`, which is a hint, not truth
//! (`shekyl-engine-state/src/staking_block.rs`). The only `StakingBlock`
//! field consumed is `staking_enabled`, which that type documents as the
//! authoritative re-derivation gate.
//!
//! # Read-only, fail-closed
//!
//! Everything here takes `&self` and mutates nothing. A corrupt or
//! version-mismatched seal is an error, never an empty view (a staker must
//! not be shown a zero staked balance over a bad seal); money sums use
//! checked arithmetic and fail closed on overflow.
//!
//! # Semantics (WI-RPC-1 DECISION default)
//!
//! Three fields, never conflated:
//!
//! - **`bonded_principal_confirmed`** — Σ [`ARCHIVAL_BOND_FLOOR_ATOMIC`] over
//!   distinct personas with a confirmed JoinMarket bond post
//!   ([`PScanState::bond_post_matches`], `post_kind == 0`) that are neither
//!   pending-unbond nor retired. The bond principal is the consensus bond
//!   floor by construction (the WI-2 assemble path bonds exactly the floor).
//! - **`bonded_principal_pending`** — the same floor over in-flight posts in
//!   the sealed [`PendingPostBlock`] (Pending or Dispatched) **whose bond has
//!   not yet been observed confirmed on-chain**. A post that has confirmed is
//!   kept in the block only transiently (the removal-ordering contract's
//!   phantom-GC bridge); it is counted as confirmed, never as both — the two
//!   principal legs are disjoint across the whole reconcile window.
//! - **`rewards_received_unspent`** — Σ amount over **unspent** `P`-funding
//!   outputs whose mint lineage is
//!   [`MintLineageOutput::EmissionReward`]. This is *received* reward money
//!   still sitting in `P`-owned outputs — **not** "accrued but unclaimed"
//!   rewards, which require a daemon claimable-epoch query and are a separate
//!   design item (see `docs/FOLLOWUPS.md`).

use std::collections::BTreeSet;

use shekyl_engine_file::WalletFileError;
use shekyl_engine_state::pscan_state::{MintLineageOutput, PScanState};
use shekyl_engine_state::{PendingPostBlock, WalletLedgerError};
use shekyl_types::{BlockHeight, GlobalOutputIndex, PCanonicalId, PSlot};
use shekyl_units::AtomicUnits;

use crate::consensus_constants::ARCHIVAL_BOND_FLOOR_ATOMIC;

use super::local_ledger::LocalLedger;
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Staked-balance breakdown (WI-RPC-1 DECISION default). See the module docs
/// for the field semantics; the three components are deliberately never
/// summed into one number here — conflation is the projection layer's choice
/// to make explicitly, not this type's default.
///
/// Amounts alone (no persona/placement pairing) are the same public class as
/// the wallet's liquid balance, so this type keeps its derived `Debug`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakedBalance {
    /// Bond principal locked under confirmed live bonds.
    pub bonded_principal_confirmed: AtomicUnits,
    /// Bond principal committed by in-flight (sealed, unconfirmed) posts.
    pub bonded_principal_pending: AtomicUnits,
    /// Emission-reward money received and still unspent in `P`-owned outputs.
    pub rewards_received_unspent: AtomicUnits,
}

impl StakedBalance {
    /// The all-zero balance of a wallet with no staking history.
    pub const ZERO: Self = Self {
        bonded_principal_confirmed: AtomicUnits::ZERO,
        bonded_principal_pending: AtomicUnits::ZERO,
        rewards_received_unspent: AtomicUnits::ZERO,
    };
}

/// One staked (P-owned, unspent) funding output, projected from the
/// authoritative [`PScanState::funding_outputs`] record.
///
/// Carries the public identity subset a balance UI needs — no output keys,
/// no ciphertexts, no derived secrets. The *set* still ties amounts to
/// persona slots (`P`'s funding history), so the type carries the same
/// redacted-`Debug` discipline as its source record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StakedOutput {
    /// The global (chain-wide) output index.
    pub gindex: GlobalOutputIndex,
    /// The recovered cleartext amount.
    pub amount: AtomicUnits,
    /// The owning persona's slot ordinal.
    pub p_slot: PSlot,
    /// The height at which the output becomes spendable (its curve-tree
    /// eligibility height — the source record's `spendable_height`).
    pub unlock_height: BlockHeight,
    /// Whether the output is finality-confirmed. Always `true` at V3.0: the
    /// P-scan records outputs only behind the reorg/finality horizon, so an
    /// unconfirmed row cannot exist in the authoritative set. The field is
    /// part of the spec'd wire shape; it becomes load-bearing if a
    /// tip-following staking scan ever lands.
    pub confirmed: bool,
}

impl std::fmt::Debug for StakedOutput {
    /// **Redacted on purpose** — a row of `P`'s funding history (slot,
    /// amount, placement); same discipline as
    /// [`PFundingOutputRecord`](shekyl_engine_state::pscan_state::PFundingOutputRecord).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StakedOutput(<redacted funding-history>)")
    }
}

/// The aggregate staking read view: everything the wallet-RPC staking
/// queries (`get_staked_balance` / `get_staked_outputs` / `staking_info`)
/// project from, computed in one pass over the authoritative records.
#[derive(Clone, PartialEq, Eq)]
pub struct StakingReadView {
    /// Whether staking is enabled for this wallet (the `StakingBlock` gate —
    /// the one field of that block that is authoritative).
    pub staking_enabled: bool,
    /// The staked-balance breakdown.
    pub balance: StakedBalance,
    /// The unspent `P`-owned funding outputs, in scan order.
    pub outputs: Vec<StakedOutput>,
    /// The P-scan's sealed frontier height (`None` when the wallet has never
    /// scanned as `P` — a non-staker, or a staker before its first sweep).
    pub pscan_synced_height: Option<BlockHeight>,
}

impl std::fmt::Debug for StakingReadView {
    /// Redacts the output rows (contents *and* count — the count alone is
    /// `P`-activity volume); the balance totals render like any balance.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StakingReadView")
            .field("staking_enabled", &self.staking_enabled)
            .field("balance", &self.balance)
            .field("outputs", &"<redacted funding-history>")
            .field("pscan_synced_height", &self.pscan_synced_height)
            .finish()
    }
}

/// Why the staking read view could not be produced. Fail-closed by design:
/// a bad seal surfaces here rather than reading as "nothing staked."
#[derive(Debug, thiserror::Error)]
pub enum StakingReadError {
    /// The `.wallet.pscan` / `.wallet.pending` seal could not be opened
    /// (envelope, I/O, swap-refusal).
    #[error("staking read: sealed file: {0}")]
    File(#[from] WalletFileError),
    /// A sealed body failed to decode (corrupt bytes or a fail-closed
    /// schema-version refusal).
    #[error("staking read: sealed state codec: {0}")]
    Codec(#[from] WalletLedgerError),
    /// A money sum overflowed `u64`. Never wrap a money total.
    #[error("staking read: balance arithmetic overflowed")]
    Overflow,
}

/// Compute the [`StakedBalance`] from the authoritative records. Pure —
/// separated from the sealed-file plumbing so the semantics are unit-testable
/// against constructed states (including the pin-2 hint-divergence KAT).
pub(crate) fn staked_balance_from_records(
    pscan: Option<&PScanState>,
    pending: Option<&PendingPostBlock>,
) -> Result<StakedBalance, StakingReadError> {
    // Distinct personas with a confirmed JoinMarket bond post (`post_kind == 0`)
    // observed on-chain. This is the single source both principal legs derive
    // from: the live subset (below) is the confirmed principal, and membership
    // here is exactly what disqualifies an in-flight post from the *pending*
    // principal. A pending post whose bond has confirmed is kept in the sealed
    // `PendingPostBlock` only transiently — the removal-ordering contract holds
    // its record live as the phantom-`bonded_slots` GC bridge until the
    // match-bearing pscan seal is durable (`pending_post_block.rs`) — so
    // counting it as pending *and* confirmed would report one physical bond as
    // both for the whole reconcile window (2× the floor to a UI summing them).
    let confirmed_bonds: BTreeSet<PCanonicalId> = match pscan {
        None => BTreeSet::new(),
        Some(state) => state
            .bond_post_matches()
            .iter()
            .filter(|m| m.post_kind == 0)
            .map(|m| m.p_canonical_id)
            .collect(),
    };

    let bonded_principal_confirmed = match pscan {
        None => AtomicUnits::ZERO,
        Some(state) => {
            // The live-bond set: confirmed personas that are neither
            // pending-unbond nor durably retired — the set the SP-6 reconcile
            // evidence supports.
            let mut live = confirmed_bonds.clone();
            for unbonded in state.pending_unbonds().keys() {
                live.remove(unbonded);
            }
            for retired in state.retired_records() {
                live.remove(&retired.p_canonical_id);
            }
            principal_for_bond_count(live.len())?
        }
    };

    let bonded_principal_pending = match pending {
        None => AtomicUnits::ZERO,
        Some(block) => {
            // Only posts whose bond has not yet been observed confirmed
            // on-chain. A post whose persona is already in `confirmed_bonds`
            // is counted as confirmed (or excluded there as unbonding/retired)
            // and must not be re-counted here — key on the raw match set, not
            // the live set, so a bond that confirmed *and* is already
            // unbonding is excluded from pending too.
            let count = block
                .posts()
                .iter()
                .filter(|post| !confirmed_bonds.contains(&post.persona))
                .count();
            principal_for_bond_count(count)?
        }
    };

    let rewards_received_unspent = match pscan {
        None => AtomicUnits::ZERO,
        Some(state) => AtomicUnits::checked_sum(
            state
                .funding_outputs()
                .iter()
                .filter(|o| o.lineage == MintLineageOutput::EmissionReward)
                .map(|o| o.amount),
        )
        .ok_or(StakingReadError::Overflow)?,
    };

    Ok(StakedBalance {
        bonded_principal_confirmed,
        bonded_principal_pending,
        rewards_received_unspent,
    })
}

/// `count × ARCHIVAL_BOND_FLOOR_ATOMIC`, checked. The bond principal per
/// post is the consensus bond floor by construction (the WI-2 assemble path
/// bonds exactly the floor); a count large enough to overflow is corrupt
/// state and fails closed.
fn principal_for_bond_count(count: usize) -> Result<AtomicUnits, StakingReadError> {
    let count = u64::try_from(count).map_err(|_| StakingReadError::Overflow)?;
    ARCHIVAL_BOND_FLOOR_ATOMIC
        .checked_mul(count)
        .map(AtomicUnits::from_raw)
        .ok_or(StakingReadError::Overflow)
}

/// Project the unspent funding outputs. `PScanState::funding_outputs` is
/// already the *unspent* set (SP-R0 arm #1 prunes a record when its spend is
/// observed), recorded behind the finality horizon (hence `confirmed: true`).
fn staked_outputs_from_state(state: &PScanState) -> Vec<StakedOutput> {
    state
        .funding_outputs()
        .iter()
        .map(|o| StakedOutput {
            gindex: o.gindex,
            amount: o.amount,
            p_slot: o.p_slot,
            unlock_height: o.spendable_height,
            confirmed: true,
        })
        .collect()
}

// `F = WalletFile` specialization: the sealed `.wallet.pscan` /
// `.wallet.pending` files are a concrete `WalletFile` concern (the same seam-b
// rationale as `start_pscan`, `pscan/start.rs`); `L = LocalLedger` for the
// `staking_enabled` read (same specialization as `Engine::ledger`).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P, shekyl_engine_file::WalletFile>
{
    /// Compute the authoritative [`StakingReadView`] — staked balance,
    /// unspent staked outputs, staking-enabled flag, and P-scan frontier.
    ///
    /// **Read-only**: takes a brief ledger read guard for `staking_enabled`,
    /// then opens the two sealed sibling files (`.wallet.pscan`,
    /// `.wallet.pending`) without mutating either. An absent seal is the
    /// ordinary non-staker / never-scanned case and reads as empty; a corrupt
    /// or version-mismatched seal **fails closed** as
    /// [`StakingReadError`] — the caller must not render "nothing staked"
    /// over a bad seal.
    ///
    /// Small synchronous file I/O (the same class as
    /// [`WalletFile::open_pscan_state`]'s other callers); async callers on a
    /// multi-threaded runtime should treat it like the other sealed-file
    /// opens.
    ///
    /// # Errors
    ///
    /// [`StakingReadError`] on seal-open failure, codec/version refusal, or
    /// money-sum overflow.
    pub fn staking_read_view(&self) -> Result<StakingReadView, StakingReadError> {
        let staking_enabled = self.ledger.read().ledger.staking.staking_enabled;

        // No key copy: the region-2 wrap key is borrowed straight from its
        // owner for the two seal opens (same shape as `pscan/start.rs`'s
        // `with_persistence_read`).
        let wrap_key = self.state_wrap_key().as_bytes();
        let pscan = match self.persistence.open_pscan_state(wrap_key)? {
            Some(body) => Some(PScanState::from_postcard_bytes(&body)?),
            None => None,
        };
        let pending = match self.persistence.open_pending_posts(wrap_key)? {
            Some(body) => Some(PendingPostBlock::from_postcard_bytes(&body)?),
            None => None,
        };

        let balance = staked_balance_from_records(pscan.as_ref(), pending.as_ref())?;
        let outputs = pscan
            .as_ref()
            .map(staked_outputs_from_state)
            .unwrap_or_default();
        let pscan_synced_height = pscan.as_ref().map(PScanState::synced_height);

        Ok(StakingReadView {
            staking_enabled,
            balance,
            outputs,
            pscan_synced_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::{
        BondPostRecord, PFundingOutputRecord, RetiredPersonaRecord,
    };
    use shekyl_engine_state::{PendingBondPost, PendingPostState};
    use shekyl_types::{PCanonicalId, SettlementEpoch, TxHash};

    fn persona(b: u8) -> PCanonicalId {
        PCanonicalId::from_bytes([b; 32])
    }

    fn bond_match(id: u8, kind: u8) -> BondPostRecord {
        BondPostRecord {
            height: BlockHeight::from_raw(1_000),
            p_canonical_id: persona(id),
            post_kind: kind,
        }
    }

    fn funding(
        slot: u32,
        gindex: u64,
        amount: u64,
        lineage: MintLineageOutput,
    ) -> PFundingOutputRecord {
        PFundingOutputRecord {
            p_slot: PSlot::from_raw(slot),
            tx_hash: TxHash::from_bytes([0xA1; 32]),
            index_in_transaction: 0,
            gindex: GlobalOutputIndex::from_raw(gindex),
            output_key: [0; 32],
            commitment: [0; 32],
            ciphertext_x25519: [0; 32],
            ciphertext_ml_kem: Vec::new(),
            amount: AtomicUnits::from_raw(amount),
            height: BlockHeight::from_raw(2_000),
            epoch: SettlementEpoch::from_raw(1),
            lineage,
            spendable_height: BlockHeight::from_raw(2_010),
        }
    }

    fn state(
        matches: Vec<BondPostRecord>,
        pending_unbonds: BTreeMap<PCanonicalId, SettlementEpoch>,
        retired: Vec<RetiredPersonaRecord>,
        outputs: Vec<PFundingOutputRecord>,
    ) -> PScanState {
        PScanState::new(
            PScanCursor::at(BlockHeight::from_raw(5_000), [0x11; 32]),
            BTreeMap::new(),
            pending_unbonds,
            matches,
            outputs,
            retired,
        )
    }

    fn pending_post(id: u8) -> PendingBondPost {
        PendingBondPost {
            p_slot: PSlot::from_raw(0),
            persona: persona(id),
            tx_bytes: vec![0xAB; 4],
            bond_post_offset_blocks: 0,
            anchor_t0: BlockHeight::from_raw(1),
            funding_gindexes: Vec::new(),
            state: PendingPostState::Pending,
        }
    }

    /// Empty wallet (no seals): zeros and empty output list.
    #[test]
    fn no_records_reads_as_all_zero() {
        let b = staked_balance_from_records(None, None).expect("balance");
        assert_eq!(b, StakedBalance::ZERO);
    }

    /// Confirmed principal counts distinct live JoinMarket personas ×
    /// the bond floor: non-JoinMarket kinds, pending unbonds, retired
    /// personas, and duplicate matches for one persona are all excluded.
    #[test]
    fn confirmed_principal_counts_distinct_live_joinmarket_bonds() {
        let mut unbonds = BTreeMap::new();
        unbonds.insert(persona(3), SettlementEpoch::from_raw(9));
        let retired = vec![RetiredPersonaRecord {
            p_slot: PSlot::from_raw(4),
            p_canonical_id: persona(4),
            unbond_epoch: SettlementEpoch::from_raw(1),
            retired_epoch: SettlementEpoch::from_raw(2),
        }];
        let s = state(
            vec![
                bond_match(1, 0), // live
                bond_match(1, 0), // duplicate of live — counted once
                bond_match(2, 2), // non-JoinMarket kind — excluded
                bond_match(3, 0), // pending unbond — excluded
                bond_match(4, 0), // retired — excluded
            ],
            unbonds,
            retired,
            Vec::new(),
        );
        let b = staked_balance_from_records(Some(&s), None).expect("balance");
        assert_eq!(
            b.bonded_principal_confirmed,
            AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC),
            "exactly one live persona × the bond floor"
        );
    }

    /// Pending principal is the in-flight post count × the bond floor,
    /// regardless of Pending vs. Dispatched.
    #[test]
    fn pending_principal_counts_inflight_posts() {
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(pending_post(1)));
        assert!(block.push_post(pending_post(2)));
        let b = staked_balance_from_records(None, Some(&block)).expect("balance");
        assert_eq!(
            b.bonded_principal_pending,
            AtomicUnits::from_raw(2 * ARCHIVAL_BOND_FLOOR_ATOMIC)
        );
        assert_eq!(b.bonded_principal_confirmed, AtomicUnits::ZERO);
    }

    /// Reconcile-window disjointness: a bond whose post has confirmed on-chain
    /// (a `post_kind == 0` match in the pscan seal) but whose `PendingPostBlock`
    /// record is still live (the removal-ordering GC bridge) is counted as
    /// confirmed **only** — never in both legs. A distinct persona with an
    /// in-flight post but no match yet still counts as pending.
    #[test]
    fn confirmed_bond_not_double_counted_as_pending() {
        // pscan: persona 1's bond has confirmed on-chain.
        let s = state(
            vec![bond_match(1, 0)],
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
        );
        // pending block: persona 1's record is still live (GC bridge) and
        // persona 2 has a genuinely unconfirmed in-flight post.
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(pending_post(1)));
        assert!(block.push_post(pending_post(2)));

        let b = staked_balance_from_records(Some(&s), Some(&block)).expect("balance");
        let floor = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
        assert_eq!(
            b.bonded_principal_confirmed, floor,
            "persona 1 counts once, as confirmed"
        );
        assert_eq!(
            b.bonded_principal_pending, floor,
            "only persona 2 (no match yet) is pending; persona 1 is not re-counted"
        );
    }

    /// A bond that has confirmed **and** entered pending-unbond within the
    /// reconcile window is excluded from pending (keyed on the raw match set,
    /// not the live set) — it counts in neither leg, not as phantom pending.
    #[test]
    fn confirmed_then_unbonding_post_is_not_pending() {
        let mut unbonds = BTreeMap::new();
        unbonds.insert(persona(1), SettlementEpoch::from_raw(9));
        let s = state(vec![bond_match(1, 0)], unbonds, Vec::new(), Vec::new());
        let mut block = PendingPostBlock::empty();
        assert!(block.push_post(pending_post(1)));

        let b = staked_balance_from_records(Some(&s), Some(&block)).expect("balance");
        assert_eq!(
            b.bonded_principal_confirmed,
            AtomicUnits::ZERO,
            "confirmed-but-unbonding is excluded from confirmed"
        );
        assert_eq!(
            b.bonded_principal_pending,
            AtomicUnits::ZERO,
            "and its still-live post is not counted as pending"
        );
    }

    /// Rewards-received-unspent sums exactly the EmissionReward-lineage
    /// unspent outputs — never bond-post change or external funding.
    #[test]
    fn rewards_received_unspent_sums_only_emission_lineage() {
        let s = state(
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            vec![
                funding(0, 10, 111, MintLineageOutput::EmissionReward),
                funding(0, 11, 222, MintLineageOutput::EmissionReward),
                funding(0, 12, 400, MintLineageOutput::BondPostChange),
                funding(0, 13, 800, MintLineageOutput::ExternalTransfer),
            ],
        );
        let b = staked_balance_from_records(Some(&s), None).expect("balance");
        assert_eq!(b.rewards_received_unspent, AtomicUnits::from_raw(333));
    }

    /// WI-RPC-1 pin 2 (hint-not-truth): when the `StakingBlock::bonded_slots`
    /// hint diverges from the authoritative reconcile evidence — e.g. phantom
    /// slots left by a crash in the persist-before-use window — the staked
    /// reads report the authoritative value, never the hint.
    ///
    /// This bites against any future change that routes `bonded_slots` (or a
    /// count derived from it) into the balance aggregation; it does NOT cover
    /// the `staking_enabled` gate (the one `StakingBlock` field that *is*
    /// authoritative and is read by `staking_read_view` directly).
    #[test]
    fn hint_divergence_reads_authoritative_not_bonded_slots() {
        use shekyl_engine_state::staking_block::StakingBlock;

        // Hint claims three live-bonded slots…
        let hint = StakingBlock::new(true, 3, vec![0, 1, 2]);
        assert_eq!(hint.bonded_slots.len(), 3);

        // …but the authoritative evidence supports exactly one live bond.
        let s = state(
            vec![bond_match(1, 0)],
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
        );
        let b = staked_balance_from_records(Some(&s), None).expect("balance");

        let authoritative = AtomicUnits::from_raw(ARCHIVAL_BOND_FLOOR_ATOMIC);
        let hint_derived =
            AtomicUnits::from_raw(hint.bonded_slots.len() as u64 * ARCHIVAL_BOND_FLOOR_ATOMIC);
        assert_eq!(b.bonded_principal_confirmed, authoritative);
        assert_ne!(
            b.bonded_principal_confirmed, hint_derived,
            "divergence fixture degenerate: hint and authoritative agree"
        );
    }

    /// Money sums fail closed on overflow, never wrap.
    #[test]
    fn overflow_fails_closed() {
        let s = state(
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            vec![
                funding(0, 10, u64::MAX, MintLineageOutput::EmissionReward),
                funding(0, 11, 1, MintLineageOutput::EmissionReward),
            ],
        );
        assert!(matches!(
            staked_balance_from_records(Some(&s), None),
            Err(StakingReadError::Overflow)
        ));
    }

    /// The staked-output projection carries the public identity subset and
    /// redacts its `Debug` (funding-history discipline).
    #[test]
    fn staked_output_projection_and_debug_redaction() {
        let s = state(
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
            vec![funding(7, 42, 999, MintLineageOutput::ExternalTransfer)],
        );
        let outs = staked_outputs_from_state(&s);
        assert_eq!(outs.len(), 1);
        let o = outs[0];
        assert_eq!(o.gindex, GlobalOutputIndex::from_raw(42));
        assert_eq!(o.amount, AtomicUnits::from_raw(999));
        assert_eq!(o.p_slot, PSlot::from_raw(7));
        assert_eq!(o.unlock_height, BlockHeight::from_raw(2_010));
        assert!(o.confirmed);

        let rendered = format!("{o:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains("999") && !rendered.contains("42"),
            "neither amount nor gindex may render: {rendered}"
        );

        let view = StakingReadView {
            staking_enabled: true,
            balance: StakedBalance::ZERO,
            outputs: outs,
            pscan_synced_height: Some(BlockHeight::from_raw(5_000)),
        };
        let rendered = format!("{view:?}");
        assert!(
            rendered.contains("<redacted funding-history>") && !rendered.contains("StakedOutput"),
            "the view must redact output contents and count: {rendered}"
        );
    }
}
