// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J, the emission's **view-bound** rows (`CHAIN_RULES_SLICE_8.md`
//! §5 row 9): every claimed epoch has a frozen close and its as-of-`E`
//! snapshot is gathered (CEN-J23), and the retention crate's verify
//! decides the claim over those snapshots, the claimant's record, the
//! reference's root and the statics' operands (CEN-J25) —
//! [`judge_emission_claim`] below, run in `tx_against` after the bond-post
//! arms and before the signatures, where the C++ emission arm sits in
//! `check_tx_inputs` (`blockchain.cpp`, the `is_archival_emission_tx`
//! branch; the verify at `:4015`, the budget check at `:3935`).
//!
//! **One gather for two readers.** The snapshot a claim is verified over is
//! assembled by [`gather_epoch_snapshot`] — the same function the epoch
//! close folded `Σwork(E)` from (`archival/close.rs`, `Transition::close`)
//! — over the same universe: the closed shards *before* the close height,
//! and every record with a recorded credit at `E`. The verify's recompute
//! of `Σwork(E)` is then over the rows the close saw, and the compare with
//! the frozen row (`EmissionVerifyError::SigmaWorkMismatch`) can fail only
//! on a claim that lies, never on a snapshot that drifted. The C++ reaches
//! the frozen operands through one LMDB gather too (`db_lmdb.cpp:7708`,
//! `gather_archival_emission_epoch_snapshot`), **but reads the shard
//! segments and bond values as they are now** rather than as of `E`'s
//! close; the Rust reads them through [`ClosedUniverse::before`] and
//! [`shard_close`](crate::archival::shard_close) at the close height, the
//! same correction row 8's J15 made for the join's gather (slice 8 §5 row
//! 9, "corpus parity — the same correction as row 8's").
//!
//! **What the verify consumes and what it yields.** The crossing's inputs
//! are the vin ([`J19::parse`]), the connecting height, the claimant's
//! record as the view holds it before the block
//! ([`ChainView::bond_record`]), the per-epoch sources (J23's gathers with
//! the frozen `Σwork(E)` and `budget(E)`), the reference's anchor and
//! layers ([`ReferenceContext`], J21's), the signable hash
//! ([`J22::signable_hash`]) and the reward commit set with its sum
//! ([`J24::reward_commits`]). Its outcome is the verdict. The
//! `EmissionVerified` it also yields — `epochs_to_commit`, `total_reward` —
//! is **not consumed here**: the fold's L7 claim arm re-reads the claimed
//! epochs from the vin, and the C++'s `total_reward` reaches no accumulator
//! (`already_generated_coins` advances by `base_reward` alone,
//! `blockchain.cpp:5936`; the value is only logged, `:4043`). The
//! inflation-audit operand the census names is the sum J24 defines, bound
//! here by the verify's equality with the claimed rewards
//! (`VoutSumMismatch`).
//!
//! **Loci.** Both rows refuse at the transaction ([`TxContext::locus`]), as
//! the statics do (J19–J24) and as J21 does: the emission is one per body
//! (H6), and the C++ rejects the transaction. The fold's L7 claim arm,
//! which sees only what these rows admitted, keeps its input locus and
//! stays as the backstop beneath them — the J4-over-L7 arrangement
//! (`rules/tx_bond.rs`).
//!
//! The positive witness is the driver's claim
//! (`shekyl-chain-ingest`, `scenario_emission_tests`), whose `judged_by`
//! names both rows; the harness's `fixture::emission_vin` is a parseable
//! vin with filler backing and auths that J23 refuses on the mock's
//! closeless chain and J25 would refuse on any chain.

use shekyl_archival_retention::{
    emission_vin_verify, emission_vin_verify_auth, emission_vin_verify_backing,
    emission_vin_verify_claims_under, p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin,
    ClaimantBondRecord, EmissionEpochSource, EmissionVerifyContext, EpochCloseInputs,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch};

use crate::archival::{gather_epoch_snapshot, recorded_credits, ClosedUniverse, EpochSnapshot};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::ViewRead;
use crate::rule_set::RuleSet;
use crate::rules::tx_against::ReferenceContext;
use crate::rules::tx_emission::{the_emission, J19, J22, J24};
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Verdict};
use crate::view::{ChainView, Tip};

/// CEN-J23: every claimed epoch has a **frozen budget row** — it closed
/// and was not pruned (`has_budget_row`, `blockchain.cpp:3935`) — and its
/// as-of-`E` snapshot is gathered for the verify. The row reads `budget(E)`
/// (A8) and `Σwork(E)` (A7): the close writes both in one event
/// (`EpochClose`), so a budget without a denominator is not a state the
/// fold produces, and this row refuses it as it refuses the absent budget
/// rather than naming a `Corrupt` for a shape nothing writes. A claimed
/// epoch so far ahead that its close height does not fit a `u64` has no
/// close and is refused the same way.
///
/// The gather is [`gather_epoch_snapshot`] over the universe the close
/// read ([`ClosedUniverse::before`] the close height) and A11's records,
/// with the claimant named so its index among the bonds is the source's
/// `claimant_bond_idx`; the credits are the recorded ones
/// ([`recorded_credits`]) — a closed epoch's credits are all recorded.
pub(crate) struct J23;

impl Rule for J23 {
    const ROW: CenRow = CenRow::J23;
}

/// One claimed epoch's gathered source: the snapshot the close read and
/// the two values it froze. Kept whole because `EmissionEpochSource`
/// borrows the snapshot's rows.
struct GatheredEpoch<'r> {
    epoch: u64,
    close_height: u64,
    snapshot: EpochSnapshot<'r>,
    sigma_work_milli: u64,
    budget: u64,
}

impl J23 {
    /// Gather every claimed epoch, in claim order. `Ok(Err)` is this row's
    /// refusal; `Err` is the view's fault.
    fn gather<'id, 'r, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        rule_set: &RuleSet,
        vin: &ArchivalRewardEmissionVin,
        persona: &PCanonicalId,
        records: &'r [(PCanonicalId, shekyl_types::archival::BondRecord)],
    ) -> Result<Verdict<Vec<GatheredEpoch<'r>>>, ViewRead<V::Fault>> {
        let schedule = rule_set.settlement_schedule();
        let mut gathered = Vec::with_capacity(vin.settlement_epochs.len());
        for &epoch in &vin.settlement_epochs {
            let e = SettlementEpoch::from_raw(epoch);
            let (Some(budget), Some(sigma_work), Some(close_height)) = (
                view.budget(e).map_err(ViewRead::View)?,
                view.sigma_work(e).map_err(ViewRead::View)?,
                schedule.close_height(epoch),
            ) else {
                return Ok(Err(InvalidBlock::new(Self::ROW, cx.locus())));
            };
            // The close ran at the block whose connecting height is one
            // below the close height (`Transition::close`: `count =
            // connecting + 1 = (E + 1) · SEB`), and read the universe
            // before that connecting height.
            let Some(closing_connected) = close_height.checked_sub(1) else {
                return Ok(Err(InvalidBlock::new(Self::ROW, cx.locus())));
            };
            let universe = ClosedUniverse::before(view, BlockHeight::from_raw(closing_connected))?;
            let snapshot = gather_epoch_snapshot(view, &universe, records, Some(persona), |p| {
                recorded_credits(view, *p, e)
            })?;
            gathered.push(GatheredEpoch {
                epoch,
                close_height,
                snapshot,
                sigma_work_milli: sigma_work.to_raw(),
                budget: budget.to_raw(),
            });
        }
        Ok(Ok(gathered))
    }
}

/// CEN-J25: the coarse verify — `shekyl_emission_vin_verify`
/// (`blockchain.cpp:4015`), here the retention crate's three legs and
/// their join: [`emission_vin_verify_claims_under`] (`REWARD_EMISSION_LEG.md`
/// §7.1 claims 1–5: alignment, the claim window against the connecting
/// height, the claimant's bond posture and holdings, dedup against the
/// record's claimed epochs, the per-epoch work arithmetic against the
/// frozen `Σwork(E)` and `budget(E)`, and the reward total's equality with
/// J24's sum), [`emission_vin_verify_backing`] (claim 6, the membership-only
/// proof against J21's anchor at `tree_depth + 1` layers over J22's
/// signable hash) and [`emission_vin_verify_auth`] (claim 8, both hybrid
/// auths over the Q1 messages). Any non-OK refuses here; the crate's
/// error names which claim, the verdict does not (`InvalidBlock` carries
/// the row). This row mints coins — the census flags the site
/// load-bearing — and it is the only place the mint's amount is bound to
/// the chain's state.
///
/// The claimant's record is read **before the block** (A1), as the C++
/// reads `get_archival_bond_value` off the DB before `add_block`; a
/// persona with no record verifies as `bond: None`, which the posture
/// step refuses.
pub(crate) struct J25;

impl Rule for J25 {
    const ROW: CenRow = CenRow::J25;
}

impl J25 {
    /// The verify over the gathered epochs. `Ok(Err)` is this row's
    /// refusal, or J24's where the commit set is not well-defined; `Err`
    /// is the view's fault from the record read.
    fn verify<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        rule_set: &RuleSet,
        vin: &ArchivalRewardEmissionVin,
        persona: &PCanonicalId,
        reference: &ReferenceContext,
        gathered: &[GatheredEpoch<'_>],
    ) -> Result<Verdict<()>, ViewRead<V::Fault>> {
        let refuse = || Err(InvalidBlock::new(Self::ROW, cx.locus()));
        let schedule = rule_set.settlement_schedule();
        let sources: Vec<EmissionEpochSource<'_>> = gathered
            .iter()
            .map(|g| EmissionEpochSource {
                inputs: EpochCloseInputs::under_schedule(
                    schedule,
                    g.epoch,
                    g.close_height,
                    &g.snapshot.bonds,
                    &g.snapshot.shards,
                    &g.snapshot.pairs,
                ),
                persisted_sigma_work_milli: g.sigma_work_milli,
                claimant_bond_idx: g.snapshot.claimant_bond_idx,
                budget: g.budget,
            })
            .collect();

        let record = view.bond_record(persona).map_err(ViewRead::View)?;
        let holdings = record.as_ref().map(|r| r.holdings.descriptor());
        let claimed: Vec<u64> = record
            .as_ref()
            .map(|r| {
                r.claimed_settlement_epochs
                    .iter()
                    .map(|e| e.to_raw())
                    .collect()
            })
            .unwrap_or_default();
        let bond = record
            .as_ref()
            .zip(holdings.as_ref())
            .map(|(r, holdings)| ClaimantBondRecord {
                join_settlement_epoch: r.join_settlement_epoch.to_raw(),
                holdings,
                claimed_settlement_epochs: &claimed,
            });

        let (commits, vout_reward_sum) = match J24::reward_commits(cx) {
            Ok(Some(set)) => set,
            Ok(None) => return Ok(refuse()),
            Err(refused) => return Ok(Err(refused)),
        };
        let Some(signable) = J22::signable_hash(cx) else {
            return Ok(refuse());
        };
        let signable = signable.to_bytes();
        let Some(layers) = reference.tree_depth.checked_add(1) else {
            return Ok(refuse());
        };

        // The connecting height, as the C++ passes `chain_height`: one
        // above the tip the block is judged against.
        let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
        let ctx = EmissionVerifyContext {
            current_block_height: connecting.to_raw(),
            bond,
            vout_reward_sum,
        };
        let Ok(claims) = emission_vin_verify_claims_under(schedule, vin, &ctx, &sources) else {
            return Ok(refuse());
        };
        let Ok(backing) =
            emission_vin_verify_backing(vin, reference.anchor.as_bytes(), layers, signable)
        else {
            return Ok(refuse());
        };
        let Ok(auth) = emission_vin_verify_auth(vin, &commits, &signable) else {
            return Ok(refuse());
        };
        // The join is the verdict. Its yield (`epochs_to_commit`,
        // `total_reward`) has no consumer on this path — see the module
        // doc.
        let _verified = emission_vin_verify(claims, backing, auth);
        Ok(Ok(()))
    }
}

/// The rows this sequence records, in order.
const CLAIM_ROWS: [CenRow; 2] = [CenRow::J23, CenRow::J25];

/// The emission's view-bound sequence: J23's gathers, then J25's verify.
/// Off the `Emission` class both rows are recorded **vacuous**. On it,
/// `reference` is J21's context from `judge_reference`; an emission the
/// caller reached here without one is a sequence wired wrong, and the
/// claim is refused under J25 rather than verified against nothing.
///
/// A vin this sequence cannot read — J19 has refused it in `tx_form`;
/// asked alone, the parse fails here — is refused under J23, the first row
/// that would have read it (the I5/H10 arrangement).
///
/// # Errors
///
/// The view's fault, from the budget, denominator, record and gather
/// reads; [`ViewRead::Corrupt`] from the gather's shard-close placement
/// ([`crate::Corrupt::ShardCloseUnplaced`]).
pub(crate) fn judge_emission_claim<'id, V: ChainView<'id>>(
    cx: &TxContext<'_>,
    view: &V,
    rule_set: &RuleSet,
    reference: Option<&ReferenceContext>,
    coverage: &mut RuleCoverage,
) -> Result<Verdict<()>, ViewRead<V::Fault>> {
    if let Some((_, bytes)) = the_emission(cx) {
        let Some(vin) = J19::parse(bytes) else {
            return Ok(Err(InvalidBlock::new(J23::ROW, cx.locus())));
        };
        let persona = p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey);
        let records = view.bond_records().map_err(ViewRead::View)?;
        let gathered = match J23::gather(cx, view, rule_set, &vin, &persona, &records)? {
            Ok(gathered) => gathered,
            Err(refused) => return Ok(Err(refused)),
        };
        coverage.insert(J23::ROW);
        let Some(reference) = reference else {
            return Ok(Err(InvalidBlock::new(J25::ROW, cx.locus())));
        };
        match J25::verify(cx, view, rule_set, &vin, &persona, reference, &gathered)? {
            Ok(()) => {}
            Err(refused) => return Ok(Err(refused)),
        }
        coverage.insert(J25::ROW);
        return Ok(Ok(()));
    }
    for row in CLAIM_ROWS {
        coverage.insert(row);
    }
    Ok(Ok(()))
}

#[cfg(test)]
#[path = "tx_emission_against_tests.rs"]
mod tests;
