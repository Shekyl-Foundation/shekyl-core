// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The [`SubmitStateShim`] seam and its fact types
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.2 / §4).
//!
//! The shim is the **named reversion boundary** (rule 21): production
//! implements it over the C++ FFI shims (§4.1–§4.3); the race suite
//! implements it as a deterministic mock (§10 item 2); the eventual Rust
//! mempool implements it natively. Facts are plain data — the shim fetches,
//! the engine decides. Zero verdict logic lives behind this trait.

use shekyl_archival_retention::{BadInterval, HoldingsDescriptor, HoldingsKind, LastServedScan};
use shekyl_types::{BlockHash, BlockHeight, ChainCount, TxHash};

use crate::submit::certificate::VerificationCertificate;

/// Per-key-image conflict descriptor from the snapshot / re-check
/// (§4.1: `none | own_txid | other`).
///
/// `OwnTx` means the pool's spender of this key image *is* the submitted
/// txid (an identity fact, paired with `in_pool`); `Other` means a
/// different transaction consumes the input — the only arm that can ever
/// classify as `DoubleSpendConflict`, and only from Phase-D fresh facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyImageConflict {
    /// No pool- or chain-level spender for this key image.
    Free,
    /// The spender is the submitted transaction itself (identity, not conflict).
    OwnTx,
    /// A different transaction consumes this key image.
    Other,
}

/// Facts about the submitted reference block, present iff the daemon knows
/// the block **by hash** (§3.1 item 4: the reference is pinned by hash; a
/// block hash commits to its prefix chain, so hash-canonicality within the
/// age window ⇒ root-canonicality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceFacts {
    /// Height of the reference block on the main chain.
    pub height: BlockHeight,
    /// Curve-tree root at that height.
    pub root: [u8; 32],
    /// Current curve-tree depth in the consensus/LMDB convention
    /// (`curve_trees_tree_depth` = layer count − 1) — the row-K10 upper
    /// bound for the wire `tree_depth`. The verifier reconstructs its
    /// layer count as `wire tree_depth + 1`, exactly as the C++ caller
    /// does (`blockchain.cpp:4119`).
    pub tree_depth: u8,
}

/// The Phase-B POD fact snapshot (§3.1 Phase B / §4.1), taken under one
/// short pool→blockchain lock scope. Also the shape of Phase-D **fresh
/// facts** when the commit races.
///
/// `reference: None` means the reference-block hash is unknown to this
/// daemon (not found on the main chain) — at Phase C that is
/// `ReferenceNotFound`; at a Phase-D re-check on a reference that *was*
/// found at B it is a reorg, classified `StaleRoot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitFacts {
    /// The submitted txid is pool-resident at the `all` relay category, so
    /// the daemon's own Dandelion++-embargoed `local`-state insertions are
    /// visible — the §3.1 identity-category pin; a `legacy`-category fact
    /// would make the F31 resubmit probe fault at the insert tail instead
    /// of returning `AlreadyInPool`. This is the *internal* presence truth
    /// (duplicate-safety + owner disclosure); what a foreign caller is told
    /// is gated on [`in_pool_broadcast`](Self::in_pool_broadcast).
    pub in_pool: bool,
    /// The submitted txid is pool-resident at the `legacy` (broadcast-visible)
    /// relay category — presence that carries no Dandelion++ embargo secret
    /// because the tx has already fluffed. The engine discloses only this
    /// narrower fact to a foreign caller (restricted/public endpoint), so
    /// `POST /submit_transaction` cannot be probed as a stem-presence oracle:
    /// an embargoed self-tx (`in_pool && !in_pool_broadcast`) is concealed
    /// from foreigners exactly as the inherited identity check concealed it.
    /// The C++ side asks `relay_category::broadcasted`.
    pub in_pool_broadcast: bool,
    /// `Some(height)` iff the submitted txid is in the main chain,
    /// confirmed at `height` — the F40 confirming-block height, read under
    /// the same lock scope as the membership fact so the pair cannot be
    /// racy (§3.1 Phase B / §4.1). It rides the fact snapshot, so the
    /// Phase-D `Raced(fresh)` reclassification carries it for free.
    pub in_chain: Option<BlockHeight>,
    /// Conflict descriptor per submitted key image, in submission order.
    pub key_image_conflicts: Vec<KeyImageConflict>,
    /// Reference-block facts, iff the hash is known to the daemon.
    pub reference: Option<ReferenceFacts>,
    /// Dynamic per-byte fee floor parameter (moves every block — F34).
    pub fee_per_byte: u64,
    /// Fee quantization mask (`get_fee_quantization_mask`, always ≥ 1).
    pub fee_quantization_mask: u64,
    /// Transaction weight limit (compile-time constant on Shekyl:
    /// `min_block_weight / 2 − COINBASE_BLOB_RESERVED_SIZE` = 149 400; §3.1).
    pub weight_limit: u64,
    /// Chain block **count** (`m_db->height()`), the consensus basis for
    /// the ref-age window arithmetic. Typed [`ChainCount`], not
    /// [`BlockHeight`]: C++ overloads "height" for this value, and holding
    /// a count in the height type is one `<=` away from an off-by-one
    /// (the emission-claim spendability anchor bug, claim-builder PR-3
    /// review). The ref-age comparison consumes the raw count deliberately
    /// — that is the consensus shape (`blockchain.cpp:3745-3765`).
    pub chain_height: ChainCount,
    /// An archival bond record exists for the submitted bond-post's
    /// `p_canonical_id` (`get_archival_bond_hybrid_pubkey` probe, read under
    /// the same lock scope as the other facts).
    ///
    /// **Kind-agnostic, and deliberately so.** Both arms read this one bit,
    /// in opposite directions — §8.7.1 BP3 requires the record *absent*,
    /// §8.7.1.1 UB2 requires it *present* — and it is the only archival
    /// fact the **commit** shim re-gathers, because Phase D re-collects the
    /// POD and not the variable-size bundles. Restricting it to JoinMarket
    /// would leave UB2 with no Phase-D re-check at all.
    ///
    /// `Some(exists)` iff a [`BondProbe`] ran, either variant; `None` for
    /// every non-bond-post shape. A `None` on a bond-post is a shim
    /// contract violation, surfaced by the engine as
    /// [`crate::submit::EngineFault::ShimContract`] before the verifier
    /// runs — never a guessed fact. On the Phase-D `Raced(fresh)` leg the
    /// commit shim re-probes from the reparsed blob, so a record **appearing**
    /// during Phase C classifies `DoubleSpendConflict` for JoinMarket. The
    /// debit arm does **not** use this bit as its race predicate: an exit
    /// preserves the row, so presence never changes for it — see
    /// [`bond_record_bonded_total`](Self::bond_record_bonded_total), which is
    /// the fact that does move.
    ///
    /// For an Unbond the same presence also rides
    /// [`unbond`](Self::unbond)`.record`, from a second DB read under the
    /// same lock scope: this bit is *presence*, the bundle is *contents*.
    /// The shim pins the two against each other rather than trusting
    /// either — a disagreement is storage inconsistency, and reading past
    /// it would verify an Unbond against half a record.
    pub bond_record_exists: Option<bool>,
    /// The probed record's bonded total; `Some` iff a [`BondProbe::Unbond`]
    /// ran and the record exists.
    ///
    /// **This is the fact the debit arm re-checks at Phase D, and presence is
    /// not a substitute for it.** `apply_archival_unbond` rewrites the row
    /// with `bonded_total_atomic == 0` rather than deleting it, so an exited
    /// persona still probes as *present*. A competing Unbond connecting
    /// during Phase C moves the balance, never the row — a re-check keyed on
    /// presence could not observe the exit it exists to catch.
    ///
    /// Phase C required `bond_debit == record_bonded_total`, so the engine's
    /// race test is this value against the submitted vin's own debit: gone,
    /// or no longer equal, and the bytes can no longer connect.
    pub bond_record_bonded_total: Option<u64>,
    /// §8.7.1.1 rows UB2/UB3/UB4/UB6/UB7: the Unbond debit arm's fact
    /// bundle. `Some` iff the snapshot ran [`BondProbe::Unbond`]; a `None`
    /// on an Unbond submission is a shim contract violation, pre-checked
    /// by the engine exactly as the emission bundle is.
    pub unbond: Option<UnbondFacts>,
    /// §8.7.2 rows E6/E7: the emission-arm fact bundle — the claimant's
    /// pre-block bond record and one frozen as-of-`E` snapshot per claimed
    /// epoch. `Some` iff the snapshot was asked to probe (the engine passes
    /// the vin-derived `(P_canonical_id, epochs)` for an
    /// [`SubmitTxKind::Emission`] submission only); a `None` on an emission
    /// submission is a shim contract violation, pre-checked by the engine.
    ///
    /// [`SubmitTxKind::Emission`]: crate::submit::SubmitTxKind::Emission
    pub emission: Option<EmissionFacts>,
    /// §8.7.2 row E6's Phase-D re-check bit: the claim slot moved — the
    /// claimant bond record is gone **or** a claimed epoch now overlaps the
    /// record's `claimed_settlement_epochs` (a competing claim connected
    /// during Phase C). Fact-shaped like the key-image descriptors: the
    /// C++ shim computes the predicate from the reparsed blob under the
    /// Phase-D lock; **Rust classifies** it (`DoubleSpendConflict`).
    /// `Some` iff an emission probe ran on this snapshot.
    pub emission_claim_conflict: Option<bool>,
}

/// Which archival-bond probe the Phase-B snapshot should run — and, by
/// construction, which fact it fills.
///
/// The two bond-post arms ask *opposite* questions of the same table:
/// JoinMarket wants the record **absent** (row BP3) and needs nothing but
/// that bit; Unbond wants it **present** and needs its contents as verify
/// operands (§8.7.1.1). Modelling that as one enum rather than two optional
/// parameters makes "both probes ran" unrepresentable, so no caller can
/// leave a stale bit beside a fresh bundle.
///
/// The 32-byte payload is the vin's claimed `p_canonical_id`, keyed exactly
/// as the C++ oracle probes it (`blockchain.cpp`
/// `check_archival_bond_post_input`); the claim is independently pinned to
/// the pubkey by the verifier's BP2 leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondProbe<'a> {
    /// JoinMarket (row BP3) — the record must be **absent**; the presence
    /// bit in [`SubmitFacts::bond_record_exists`] is the whole answer.
    Join(&'a [u8; 32]),
    /// Unbond (§8.7.1.1) — the record must be **present**, so the same
    /// presence bit is joined by [`SubmitFacts::unbond`] carrying the
    /// record's contents as verify operands.
    Unbond(&'a [u8; 32]),
}

impl BondProbe<'_> {
    /// The `p_canonical_id` this probe is keyed on, whichever arm it is.
    pub fn p_canonical_id(&self) -> &[u8; 32] {
        match self {
            Self::Join(id) | Self::Unbond(id) => id,
        }
    }
}

/// §8.7.1.1 Unbond-arm facts, owned POD marshaled by the snapshot shim
/// under the **same** lock scope as every other fact — a record read before
/// a block, paired with a watermark read after it, describes a state the
/// chain never occupied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbondFacts {
    /// Row UB2: the record being debited. `None` = no record for this
    /// `p_canonical_id`, and the *time* of that observation decides the
    /// verdict — absent at Phase B is `Malformed` (these bytes can never
    /// connect), absent at a Phase-D re-check after being present at B is
    /// a competing debit that connected during Phase C, which is
    /// `DoubleSpendConflict`.
    pub record: Option<UnbondRecordFacts>,
    /// Row UB6: the slash scheduler's settled-epoch watermark; `None` =
    /// nothing settled yet.
    ///
    /// **This is the only place the C++ `u64::MAX` storage sentinel is
    /// normalised** (`get_archival_last_slash_epoch`'s initial value, never
    /// a settled epoch). The shim edge owns it so no second normalisation
    /// can be added downstream and disagree about what "unset" means.
    pub last_settled_slash_epoch: Option<u64>,
}

/// The debited record's verify operands (row UB2's payload).
///
/// Fields are private and the only constructor is [`new`](Self::new),
/// because one of the invariants cannot be re-checked later without
/// re-deriving the thing it guards: see [`LastServedScanMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbondRecordFacts {
    bonded_total_atomic: u64,
    bad_interval_count: usize,
    bond_spend_pk: Vec<u8>,
    holdings_kind: HoldingsKind,
    per_shard_last_served: Vec<u64>,
}

/// The gather ran the wrong last-served accessor for this record's holdings
/// kind (row UB4).
///
/// A dedicated error rather than a bool because **the wrong gather fails
/// permissively**: a `CompleteTree` record stores no shard list, so the
/// held-shards accessor returns an empty slice, which folds to "never
/// served", which makes the release cooldown *elapse* for a record that has
/// been serving. A permissive failure that reaches a verdict is worse than
/// no fact at all, so the mismatch is made unconstructable instead of
/// checked somewhere downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastServedScanMismatch {
    /// The accessor the gather reported running.
    pub gathered: LastServedScan,
    /// The accessor this record's holdings kind selects.
    pub expected: LastServedScan,
}

impl UnbondRecordFacts {
    /// Build the record facts, pinning the gather's reported accessor
    /// against the one `holdings_kind` selects.
    ///
    /// `gathered_scan` is what the shim says it ran; it is consumed by the
    /// pin and deliberately **not** stored, so no later reader can consult
    /// a scan discriminant instead of the holdings kind.
    ///
    /// # Errors
    ///
    /// [`LastServedScanMismatch`] when the two disagree — a shim contract
    /// violation, never a fact to fold.
    pub fn new(
        bonded_total_atomic: u64,
        bad_interval_count: usize,
        bond_spend_pk: Vec<u8>,
        holdings_kind: HoldingsKind,
        gathered_scan: LastServedScan,
        per_shard_last_served: Vec<u64>,
    ) -> Result<Self, LastServedScanMismatch> {
        let expected = holdings_kind.last_served_scan();
        if gathered_scan != expected {
            return Err(LastServedScanMismatch {
                gathered: gathered_scan,
                expected,
            });
        }
        Ok(Self {
            bonded_total_atomic,
            bad_interval_count,
            bond_spend_pk,
            holdings_kind,
            per_shard_last_served,
        })
    }

    /// The record's current bonded total — an Unbond debit must remove all
    /// of it (row UB9), and a zero total is `NothingToUnbond`.
    pub fn bonded_total_atomic(&self) -> u64 {
        self.bonded_total_atomic
    }

    /// Row UB7: entries in the record's bad-interval log. A full log makes
    /// the transaction unconnectable, so it is unverifiable.
    pub fn bad_interval_count(&self) -> usize {
        self.bad_interval_count
    }

    /// Row UB3: the record's **committed** debit authorizer, exactly as
    /// stored. Any non-canonical length — empty included — means the record
    /// authorizes no debit at all; the pin fails closed rather than falling
    /// back to the identity key.
    pub fn bond_spend_pk(&self) -> &[u8] {
        &self.bond_spend_pk
    }

    /// The record's holdings kind — the authority for which last-served
    /// gather is correct.
    pub fn holdings_kind(&self) -> HoldingsKind {
        self.holdings_kind
    }

    /// Row UB4: per-shard last-served epochs from the accessor this
    /// record's kind selects. Never-served shards are omitted, so an empty
    /// slice is the legitimate "record exists, nothing served" case.
    pub fn per_shard_last_served(&self) -> &[u64] {
        &self.per_shard_last_served
    }
}

/// §8.7.2 emission-arm facts (rows E6 + E7), owned POD marshaled by the
/// snapshot shim under the same lock scope as every other fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionFacts {
    /// E6: the claimant's pre-block bond record; `None` = no record
    /// (the claims battery rejects — `BondMissing` → the claim-slot
    /// conflict classification).
    pub bond: Option<EmissionBondFacts>,
    /// E7: one frozen as-of-`E` snapshot per claimed epoch, claim order
    /// (alignment is re-checked by `emission_vin_verify_claims`).
    pub snapshots: Vec<EmissionEpochSnapshotFacts>,
}

/// E6: the claimant bond record's verify operands
/// (`ClaimantBondRecord`'s owned twin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionBondFacts {
    /// `E_join` — the step-2 `E ≥ E_join + 1` operand.
    pub join_settlement_epoch: u64,
    /// The record's holdings descriptor (step 2 demands equality with the
    /// vin's).
    pub holdings: HoldingsDescriptor,
    /// The record's claimed-epoch set — step 3's read-only dedup operand.
    pub claimed_settlement_epochs: Vec<u64>,
}

/// E7: one frozen as-of-`E` gather snapshot
/// (`ShekylArchivalEmissionEpochSnapshot`'s owned twin; the verifier
/// borrows these into `EpochCloseInputs::verify_view`, the single-sourced
/// view constructor the C++ oracle's FFI shim also uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionEpochSnapshotFacts {
    /// A frozen `budget(E)` row exists — absent means the epoch never
    /// closed (or was pruned): `Malformed` (§8.7.2 row E7).
    pub has_budget_row: bool,
    pub settlement_epoch: u64,
    /// The close-processing height `(E+1)·SEB` (shard-age operand).
    pub close_block_height: u64,
    /// Persisted finalized `Σwork(E)` milli — the stored denominator.
    pub sigma_work_milli: u64,
    /// Persisted frozen `budget(E)` atomic.
    pub budget_atomic: u64,
    /// Claimant `P`'s index into `bonds`, `None` when `P` has no
    /// serve-credit row in `E`.
    pub claimant_bond_idx: Option<usize>,
    /// The frozen bond rows (`EpochCloseBond`'s owned twin).
    pub bonds: Vec<EmissionCloseBondFacts>,
    /// The frozen shard registry rows.
    pub shards: Vec<EmissionShardFacts>,
    /// The frozen serve-credit pairs, as indices into `bonds`/`shards`.
    pub credit_pairs: Vec<EmissionCreditPairFacts>,
}

/// One frozen bond row (owned `EpochCloseBond`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionCloseBondFacts {
    pub join_settlement_epoch: u64,
    pub is_foundation_complete_tree: bool,
    pub bad_intervals: Vec<BadInterval>,
}

/// One frozen shard registry row (owned `EpochCloseShard` — mirrored
/// because the retention type carries no `Eq`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionShardFacts {
    pub shard_id: u64,
    pub has_segment: bool,
    pub freeze_height: u64,
}

/// One frozen serve-credit pair (owned `CreditPair` mirror).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmissionCreditPairFacts {
    pub bond_idx: usize,
    pub shard_idx: usize,
}

/// The snapshot shim failed internally (§3.4: DB exception, marshalling
/// fault, fee-parameter derivation failure). **Never a verdict** — the
/// engine surfaces it as [`crate::submit::EngineFault::SnapshotFault`]
/// (HTTP 5xx at the transport). Payload-free by design: the C++ side has
/// already logged the specifics where an operator can correlate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimFault;

/// Meta fields the commit shim needs for the existing `add_tx` insert tail
/// (§4.2): everything else in `txpool_tx_meta_t` is derived C++-side from
/// the blob and the certificate facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxMeta {
    /// Consensus transaction weight (serialized size + Bp+ clawback).
    pub weight: u64,
    /// Transaction fee (`Ct::Fcmp` fee field).
    pub fee: u64,
}

/// Outcome of the Phase-D check-and-commit (§3.2 / §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Every re-checked premise held; the tx is in the pool (attested via
    /// the certificate) and survived the post-insert `prune()` membership
    /// check (F23). `Accepted ⇒ in pool at commit-check time`.
    Committed,
    /// A mutable premise moved between the Phase-B snapshot and the commit
    /// lock. Carries the fresh facts (boxed: the emission fact bundle makes
    /// the snapshot the enum's dominant variant); **Rust classifies**,
    /// most-terminal-first (§3.1) — the shim never chooses a verdict.
    Raced(Box<SubmitFacts>),
    /// The insert tail succeeded but the tail's `prune()` evicted the tx
    /// under pool pressure (F23 / defect 0.7) — classified
    /// `Rejected{FeeTooLow}` (pool-pressure variant).
    PrunedOnInsert,
    /// Internal inconsistency (§3.4: release-mode txid divergence between
    /// the engine hash and C++ `get_transaction_hash` over the same blob,
    /// or a marshalling fault). Never a verdict: surfaced as a loud
    /// transport-level error so a daemon defect is not converted into a
    /// wallet rebuild.
    InternalFault,
}

/// The engine's seam to pool/blockchain state (§3.2). See the module docs
/// for the reversion shape.
pub trait SubmitStateShim {
    /// Phase B: one short pool→blockchain lock scope, reads only (§4.1).
    ///
    /// `bond_probe` is `Some` for a bond-post submission and names which
    /// archival-bond question to ask. The outputs are **not** mutually
    /// exclusive, and an alternate implementor that treats them that way
    /// will fault the engine:
    ///
    /// - **Both variants must fill [`SubmitFacts::bond_record_exists`]** —
    ///   it is the kind-agnostic presence bit, required for every bond-post
    ///   and re-read at Phase D by both arms.
    /// - [`BondProbe::Unbond`] must **additionally** fill
    ///   [`SubmitFacts::unbond`] (the record's contents, for Phase C) and
    ///   [`SubmitFacts::bond_record_bonded_total`] (the balance, for the
    ///   Phase-D re-check that presence cannot express).
    ///
    /// `None` skips the probe entirely.
    ///
    /// `Err(ShimFault)` is the shim's internal-failure arm (DB exception,
    /// marshalling fault) — never a verdict input.
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
        bond_probe: Option<BondProbe<'_>>,
        emission_probe: Option<(&[u8; 32], &[u64])>,
    ) -> Result<SubmitFacts, ShimFault>;

    /// Phase D: one short pool→blockchain lock scope — release-mode txid
    /// check first, then the §3.1 re-check list (identity, key images,
    /// hash-anchored reference + age window, root compare, `check_fee`
    /// re-gate against fresh params), then the existing `add_tx` insert
    /// tail with certificate-gated `fcmp_verified` attestation (§3.5) and
    /// the post-prune membership check (§4.2).
    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome;

    /// Post-commit relay nudge into the existing
    /// `relay_transactions(local)` dispatch (§4.3). Fire and forget: the
    /// nudge is latency; the Dandelion++ embargo + periodic loop are the
    /// guarantee (§5.2).
    fn relay(&self, txid: &TxHash);
}

// Forwarding impl: one shim instance shared across transport workers (and
// across the engine + a test's assertion handle) is the normal ownership
// shape; without this, every out-of-crate implementor hits the orphan rule
// wrapping its mock in `Arc`.
impl<T: SubmitStateShim + ?Sized> SubmitStateShim for std::sync::Arc<T> {
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
        bond_probe: Option<BondProbe<'_>>,
        emission_probe: Option<(&[u8; 32], &[u64])>,
    ) -> Result<SubmitFacts, ShimFault> {
        (**self).snapshot_facts(
            txid,
            key_images,
            reference_block,
            bond_probe,
            emission_probe,
        )
    }

    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        meta: &TxMeta,
        cert: &VerificationCertificate,
        expected: &SubmitFacts,
    ) -> CommitOutcome {
        (**self).commit(blob, txid, meta, cert, expected)
    }

    fn relay(&self, txid: &TxHash) {
        (**self).relay(txid)
    }
}
