// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`RustPoolShim`]: the submit engine's seam over the Rust pool — CEN-M9,
//! the planned reversion (`DAEMON_SUBMIT_VERDICT.md` §11: "`SubmitStateShim`
//! over C++ FFI | The Rust mempool lands | Swap the trait impl; engine,
//! contract, wallet untouched"), **prepared, not routed** (DRS-E5 PR-b b3).
//! Production constructs [`FfiSubmitShim`](super::FfiSubmitShim) until the
//! DRS-X flip routes this one.
//!
//! # Facts are the chain's and the pool's, read once
//!
//! [`SubmitStateShim::snapshot_facts`] reads one committed snapshot of the
//! chain ([`ChainSource`]) and the pool, as the C++ shim's single lock scope
//! does, and fills every fact the contract names — the identity facts from
//! the pool (`in_pool` is held, `in_pool_broadcast` is public: the embargo
//! concealment §3.1 pins), the confirming height, the key-image classes,
//! the reference, the fee and weight parameters, and the archival bundles.
//! The archival facts are gathered by the validator's own functions
//! ([`shekyl_chain_rules::release_last_served`],
//! [`shekyl_chain_rules::emission_epoch_facts`]), so the engine is handed
//! what the block path reads, never a second gather.
//!
//! # The commit is the door
//!
//! [`SubmitStateShim::commit`] reparses the bytes, checks the txid, and
//! offers the transaction to [`Pool::admit`] — the validator's whole
//! judgement at `TxSlot::Lone`. It does **not** admit on the certificate:
//! the one-validator condition (`E5-Q2`) outranks the reversion's "engine
//! untouched" wording, so the engine's Phase C becomes a verification the
//! door repeats. What that costs and how the swap retires it is the DX
//! round's (`DRS_E5_POOL_ALT_PRUNE.md` §9). The door's answers map onto the
//! contract's outcomes:
//!
//! - admitted → [`CommitOutcome::Committed`];
//! - already held or mined, or refused by the chain-bound half (a spent
//!   image, a moved reference) → [`CommitOutcome::Raced`] with fresh facts
//!   for the engine to classify;
//! - refused by CEN-M3, the relay floor → [`CommitOutcome::PrunedOnInsert`],
//!   which the engine classifies `FeeTooLow` — the engine's fee gate reads
//!   the same window by the same predicate (`fee_floor_window`), so the two
//!   agree; and a full pool holding nothing it
//!   would give up for the transaction (CEN-M10's rising minimum), the C++
//!   insert-tail prune's answer;
//! - anything else — a refusal on the bytes, or by M4/M5, after the engine's
//!   own Phase A–C passed it, or a fault — is
//!   [`CommitOutcome::InternalFault`]: two judgements of one transaction
//!   disagreed, which is a daemon defect, never a verdict.
//!
//! [`CommitOutcome::JoinMarketUnsupported`] is the C++ commit's: the Rust
//! pool holds a JoinMarket like any post.
//!
//! [`SubmitStateShim::relay`] does nothing here: at the flip the relay's
//! driver takes what the pool holds unpublished, and a nudge from the
//! engine is that driver's to wire.

use std::sync::Mutex;

use shekyl_archival_retention::{
    cold_authority_pin, BondPostKind as RetentionBondPostKind, HoldingsDescriptor,
    HoldingsKindScan, ShardSet,
};
use shekyl_chain_rules::{
    emission_epoch_facts, relay_floor_at, relay_floor_window, release_last_served, AdmissionPolicy,
    AtHeight, ChainView, EmissionEpochSnapshot, HeaderView, PolicyRow, RuleSet, Tip,
};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView};
use shekyl_mempool::{stateless, Admission, Arrival, Judged, Pool};
use shekyl_types::archival::{BondRecord, Holdings, MAX_BOND_BAD_INTERVALS};
use shekyl_types::{
    BlockHash, BlockHeight, ChainCount, PCanonicalId, SettlementEpoch, TxHash, UnixSeconds,
};

use crate::submit::certificate::VerificationCertificate;
use crate::submit::facts::{
    BondProbe, CommitOutcome, EmissionBondFacts, EmissionCloseBondFacts, EmissionCreditPairFacts,
    EmissionEpochSnapshotFacts, EmissionFacts, EmissionShardFacts, KeyImageConflict,
    ReferenceFacts, ReleaseFacts, ReleaseRecordFacts, ShimFault, SubmitFacts, SubmitStateShim,
    TxMeta,
};
use crate::submit::phase_a::parse_submission;

/// One committed snapshot of the chain and the rule set in force at the
/// height the next block connects at — what the shim reads, as one
/// unit. The DRS-X flip implements it over the writer's store.
pub trait ChainSource {
    /// Run `f` over one snapshot and the rule set in force at its
    /// connecting height.
    ///
    /// # Errors
    ///
    /// [`ShimFault`] when no snapshot can be begun.
    fn read<R>(&self, f: impl FnOnce(&ReadSnapshot<'_>, &RuleSet) -> R) -> Result<R, ShimFault>;
}

/// The submit engine's seam over the Rust pool (module docs).
pub struct RustPoolShim<C> {
    chain: C,
    pool: Mutex<Pool>,
    policy: AdmissionPolicy,
    clock: fn() -> UnixSeconds,
}

impl<C> core::fmt::Debug for RustPoolShim<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RustPoolShim").finish_non_exhaustive()
    }
}

impl<C: ChainSource> RustPoolShim<C> {
    /// The shim over `chain` and `pool`, admitting under `policy`, with
    /// `clock` the wall clock an admission is stamped by.
    #[must_use]
    pub fn new(chain: C, pool: Pool, policy: AdmissionPolicy, clock: fn() -> UnixSeconds) -> Self {
        Self {
            chain,
            pool: Mutex::new(pool),
            policy,
            clock,
        }
    }

    /// The relay's fluff event for `txid`, through the shim's lock
    /// ([`Pool::fluffed`]): the relay driver's entry point at the flip.
    /// `Ok(false)` when the pool does not hold it.
    ///
    /// # Errors
    ///
    /// [`ShimFault`] when the lock is poisoned or the pool file faults.
    pub fn fluffed(&self, txid: &TxHash) -> Result<bool, ShimFault> {
        let mut pool = self.pool.lock().map_err(|_| ShimFault)?;
        pool.fluffed(txid).map_err(|_| ShimFault)
    }

    /// Read the pool under the shim's lock.
    ///
    /// # Errors
    ///
    /// [`ShimFault`] when the lock is poisoned.
    pub fn with_pool<R>(&self, f: impl FnOnce(&Pool) -> R) -> Result<R, ShimFault> {
        let pool = self.pool.lock().map_err(|_| ShimFault)?;
        Ok(f(&pool))
    }
}

/// The C++ `classify_key_image` over the pool and the chain: spent on the
/// chain is another's; spent in the pool by another transaction is
/// another's (own when the submission itself is pooled, as the C++
/// answers) — embargoed while that transaction is unpublished, which the
/// engine discloses to the owner tier alone; spent in the pool only by the
/// submission itself counts once it is public — before that the image reads
/// free, so the snapshot discloses no embargoed spend.
fn classify(
    view: &SnapshotView<'_>,
    pool: &Pool,
    txid: &TxHash,
    in_pool: bool,
    key_image: &[u8; 32],
) -> Result<KeyImageConflict, ShimFault> {
    let image = shekyl_types::KeyImage::from_bytes(*key_image);
    if view.has_key_image(&image).map_err(|_| ShimFault)? {
        return Ok(KeyImageConflict::Other);
    }
    let (spent, public) = match pool.key_images().spender(&image) {
        None => (false, true),
        Some(spender) if spender != *txid => {
            (true, pool.record(&spender).is_some_and(|r| r.public))
        }
        Some(_) => (pool.record(txid).is_some_and(|r| r.public), true),
    };
    Ok(match (spent, in_pool, public) {
        (false, _, _) => KeyImageConflict::Free,
        (true, true, _) => KeyImageConflict::OwnTx,
        (true, false, true) => KeyImageConflict::Other,
        (true, false, false) => KeyImageConflict::Embargoed,
    })
}

/// The §8.7.1.1 Release bundle (`fill_release_facts_locked`): the record,
/// the slash watermark, and the last-served slice unless a work gate that
/// precedes the cooldown already decides — the txid known, the debit pin
/// failing, nothing to release, a debit that is not the whole balance, a
/// full interval log. The slice is the validator's
/// ([`release_last_served`]).
fn release_facts(
    view: &SnapshotView<'_>,
    persona: &PCanonicalId,
    auth_pubkey: &[u8],
    bond_debit: u64,
    identity_known: bool,
) -> Result<ReleaseFacts, ShimFault> {
    let fault = |_| ShimFault;
    let record = view.bond_record(persona).map_err(fault)?;
    let last_settled_slash_epoch = view
        .last_settled_slash_epoch()
        .map_err(fault)?
        .map(SettlementEpoch::to_raw);
    let Some(record) = record else {
        return Ok(ReleaseFacts {
            record: None,
            last_settled_slash_epoch,
        });
    };
    let total = record.bonded_total.to_raw();
    let kind = record.holdings.kind();
    let skip_scan = identity_known
        || cold_authority_pin(
            RetentionBondPostKind::Release,
            bond_debit,
            &record.bond_spend_pk,
            auth_pubkey,
        )
        .is_err()
        || total == 0
        || total != bond_debit
        || record.bad_intervals.len() >= MAX_BOND_BAD_INTERVALS;
    let per_shard_last_served = if skip_scan {
        Vec::new()
    } else {
        release_last_served(view, persona, &record).map_err(fault)?
    };
    let record = ReleaseRecordFacts::new(
        total,
        record.bad_intervals.len(),
        record.bond_spend_pk.clone(),
        kind,
        kind.last_served_scan(),
        per_shard_last_served,
        skip_scan,
    )
    .map_err(|_| ShimFault)?;
    Ok(ReleaseFacts {
        record: Some(record),
        last_settled_slash_epoch,
    })
}

/// The claimant's record as the emission bundle carries it.
fn emission_bond(record: &BondRecord) -> Result<EmissionBondFacts, ShimFault> {
    let shard_ids = match &record.holdings {
        Holdings::ShardSet(held) => held.iter().map(|h| h.shard.to_raw()).collect(),
        Holdings::CompleteTree => Vec::new(),
    };
    Ok(EmissionBondFacts {
        join_settlement_epoch: record.join_settlement_epoch.to_raw(),
        holdings: HoldingsDescriptor {
            kind: record.holdings.kind(),
            shard_ids: ShardSet::new(shard_ids).map_err(|_| ShimFault)?,
        },
        claimed_settlement_epochs: record
            .claimed_settlement_epochs
            .iter()
            .copied()
            .map(SettlementEpoch::to_raw)
            .collect(),
    })
}

/// The §8.7.2 E6/E7 bundle: the claim-slot bit (the record gone, or a
/// claimed epoch already consumed) and the facts, each claimed epoch's
/// gathered by the validator ([`emission_epoch_facts`]).
fn emission_facts(
    view: &SnapshotView<'_>,
    rule_set: &RuleSet,
    persona: &PCanonicalId,
    epochs: &[u64],
) -> Result<(bool, EmissionFacts), ShimFault> {
    let record = view.bond_record(persona).map_err(|_| ShimFault)?;
    let conflict = record.as_ref().is_none_or(|record| {
        epochs.iter().any(|epoch| {
            record
                .claimed_settlement_epochs
                .iter()
                .any(|claimed| claimed.to_raw() == *epoch)
        })
    });
    let bond = record.as_ref().map(emission_bond).transpose()?;
    let snapshots = emission_epoch_facts(view, rule_set, persona, epochs)
        .map_err(|_| ShimFault)?
        .into_iter()
        .map(|facts| {
            // An epoch that has not settled has no snapshot: the engine reads
            // the absent budget row and refuses the claim (§8.7.2 E7).
            let snapshot = facts.snapshot.unwrap_or(EmissionEpochSnapshot {
                bonds: Vec::new(),
                shards: Vec::new(),
                pairs: Vec::new(),
                claimant_bond_idx: None,
            });
            EmissionEpochSnapshotFacts {
                has_budget_row: facts.budget.is_some(),
                settlement_epoch: facts.settlement_epoch,
                close_block_height: facts.close_height.map_or(0, BlockHeight::to_raw),
                sigma_work_milli: facts.sigma_work_milli.unwrap_or(0),
                budget_atomic: facts.budget.unwrap_or(0),
                claimant_bond_idx: snapshot.claimant_bond_idx,
                bonds: snapshot
                    .bonds
                    .into_iter()
                    .map(|bond| EmissionCloseBondFacts {
                        join_settlement_epoch: bond.join_settlement_epoch,
                        is_foundation_complete_tree: bond.is_foundation_complete_tree,
                        bad_intervals: bond.bad_intervals,
                    })
                    .collect(),
                shards: snapshot
                    .shards
                    .into_iter()
                    .map(|shard| EmissionShardFacts {
                        shard_id: shard.shard_id,
                        close: shard.close,
                    })
                    .collect(),
                credit_pairs: snapshot
                    .pairs
                    .into_iter()
                    .map(|pair| EmissionCreditPairFacts {
                        bond_idx: pair.bond_idx,
                        shard_idx: pair.shard_idx,
                    })
                    .collect(),
            }
        })
        .collect();
    Ok((conflict, EmissionFacts { bond, snapshots }))
}

/// Every fact the contract names, off one snapshot and the pool.
#[allow(
    clippy::too_many_arguments,
    reason = "the contract's five probes, the snapshot and the pool"
)]
fn gather(
    snapshot: &ReadSnapshot<'_>,
    rule_set: &RuleSet,
    pool: &Pool,
    txid: &TxHash,
    key_images: &[[u8; 32]],
    reference_block: &BlockHash,
    bond_probe: Option<BondProbe<'_>>,
    emission_probe: Option<(&[u8; 32], &[u64])>,
) -> Result<SubmitFacts, ShimFault> {
    let fault = |_| ShimFault;
    let view = SnapshotView::new(snapshot);
    let held = pool.record(txid);
    let in_pool = held.is_some();
    let in_pool_broadcast = held.is_some_and(|r| r.public);
    let in_chain = snapshot
        .tx_location(txid)
        .map_err(fault)?
        .map(|location| location.height);
    let key_image_conflicts = key_images
        .iter()
        .map(|key_image| classify(&view, pool, txid, in_pool, key_image))
        .collect::<Result<Vec<_>, _>>()?;
    let connecting = Tip::connecting_height(view.tip().map_err(fault)?.as_ref());
    let reference = match view.height_of(reference_block).map_err(fault)? {
        None => None,
        Some(height) => match (
            view.root_at(height).map_err(fault)?,
            view.depth_at(connecting).map_err(fault)?,
        ) {
            (AtHeight::Recorded(root), AtHeight::Recorded(tree_depth)) => Some(ReferenceFacts {
                height,
                root: *root.as_bytes(),
                tree_depth,
            }),
            _ => return Err(ShimFault),
        },
    };
    let AtHeight::Recorded(fee_per_byte) =
        relay_floor_at(&view, connecting).map_err(|_| ShimFault)?
    else {
        return Err(ShimFault);
    };
    // The door's fee predicate's operand: the engine judges the fee by
    // CEN-M3's own rule over the window (the review of #1102, S5).
    let AtHeight::Recorded(fee_floor_window) =
        relay_floor_window(&view, connecting).map_err(|_| ShimFault)?
    else {
        return Err(ShimFault);
    };
    let identity_known = in_chain.is_some() || in_pool_broadcast;

    let mut facts = SubmitFacts {
        in_pool,
        in_pool_broadcast,
        in_chain,
        key_image_conflicts,
        reference,
        fee_per_byte,
        fee_floor_window: Some(fee_floor_window),
        weight_limit: u64::try_from(shekyl_wire::transaction::TX_WEIGHT_LIMIT)
            .map_err(|_| ShimFault)?,
        chain_height: ChainCount::from_raw(connecting.to_raw()),
        bond_record_exists: None,
        bond_record_bonded_total: None,
        release: None,
        emission: None,
        emission_claim_conflict: None,
    };
    if let Some(probe) = bond_probe {
        let record = view.bond_record(probe.p_canonical_id()).map_err(fault)?;
        facts.bond_record_exists = Some(record.is_some());
        if let BondProbe::Release {
            p_canonical_id,
            auth_pubkey,
            bond_debit,
        } = probe
        {
            facts.bond_record_bonded_total = record.as_ref().map(|r| r.bonded_total.to_raw());
            facts.release = Some(release_facts(
                &view,
                p_canonical_id,
                auth_pubkey,
                bond_debit,
                identity_known,
            )?);
        }
    }
    if let Some((id, epochs)) = emission_probe {
        let persona = PCanonicalId::from_bytes(*id);
        let (conflict, emission) = emission_facts(&view, rule_set, &persona, epochs)?;
        facts.emission_claim_conflict = Some(conflict);
        facts.emission = Some(emission);
    }
    Ok(facts)
}

impl<C: ChainSource> SubmitStateShim for RustPoolShim<C> {
    fn snapshot_facts(
        &self,
        txid: &TxHash,
        key_images: &[[u8; 32]],
        reference_block: &BlockHash,
        bond_probe: Option<BondProbe<'_>>,
        emission_probe: Option<(&[u8; 32], &[u64])>,
    ) -> Result<SubmitFacts, ShimFault> {
        let pool = self.pool.lock().map_err(|_| ShimFault)?;
        self.chain.read(|snapshot, rule_set| {
            gather(
                snapshot,
                rule_set,
                &pool,
                txid,
                key_images,
                reference_block,
                bond_probe,
                emission_probe,
            )
        })?
    }

    fn commit(
        &self,
        blob: &[u8],
        txid: &TxHash,
        _meta: &TxMeta,
        _cert: &VerificationCertificate,
        _expected: &SubmitFacts,
    ) -> CommitOutcome {
        let Ok(parsed) = parse_submission(&hex::encode(blob)) else {
            return CommitOutcome::InternalFault;
        };
        if parsed.txid != *txid {
            return CommitOutcome::InternalFault;
        }
        // The door's step 1 — the signatures, the range proof, the FCMP++
        // proof — on a snapshot of its own, before the pool's lock: the lock
        // guards the view-bound half alone (the review of #1102, S1). Every
        // submit pays it, a duplicate the pool holds unpublished included,
        // so a concealed answer costs what a fresh accept does (B2).
        let prior = self
            .chain
            .read(|snapshot, rule_set| {
                stateless(&parsed.tx, &SnapshotView::new(snapshot), rule_set, None)
            })
            .ok()
            .and_then(Result::ok)
            .and_then(Result::ok);
        let Ok(mut pool) = self.pool.lock() else {
            return CommitOutcome::InternalFault;
        };
        let now = (self.clock)();
        let outcome = self.chain.read(|snapshot, rule_set| {
            let view = SnapshotView::new(snapshot);
            let admitted = pool.admit_judged(
                parsed.tx.clone(),
                prior,
                Arrival::Relayed,
                now,
                &view,
                rule_set,
                &self.policy,
            );
            match admitted {
                Ok(Admission::Admitted { .. }) => CommitOutcome::Committed,
                Ok(Admission::Duplicate(_) | Admission::Refused(Judged::Chain { .. })) => {
                    let emission_probe = parsed.emission_probe();
                    match gather(
                        snapshot,
                        rule_set,
                        &pool,
                        txid,
                        &parsed.key_images,
                        &parsed.reference_block,
                        parsed.bond_probe(),
                        emission_probe.as_ref().map(|(id, epochs)| (id, *epochs)),
                    ) {
                        Ok(fresh) => CommitOutcome::Raced(Box::new(fresh)),
                        Err(ShimFault) => CommitOutcome::InternalFault,
                    }
                }
                Ok(Admission::Refused(Judged::Policy(refused)))
                    if refused.rule == PolicyRow::M3 =>
                {
                    CommitOutcome::PrunedOnInsert
                }
                // CEN-M10's rising minimum: the pool is full of entries
                // paying at least as much — the C++ insert-tail prune's
                // answer.
                Ok(Admission::PoolFull) => CommitOutcome::PrunedOnInsert,
                Ok(Admission::Refused(_) | Admission::Kept) | Err(_) => {
                    CommitOutcome::InternalFault
                }
            }
        });
        outcome.unwrap_or(CommitOutcome::InternalFault)
    }

    fn relay(&self, _txid: &TxHash) {}
}
