// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.J, the emission's **view-bound** rows (`CHAIN_RULES_SLICE_8.md`
//! §5 row 9): every claimed epoch has a frozen close and its as-of-`E`
//! snapshot is gathered (CEN-J23), the retention crate's verify decides
//! the claim over those snapshots, the claimant's record, the reference's
//! root and the statics' operands (CEN-J25), and the fee inputs' FCMP++
//! proof verifies as CEN-I15's over the `ToKey` subset (CEN-J26) —
//! [`judge_emission_claim`] below, run in `tx_against` after the bond-post
//! arms and before the signatures, where the C++ emission arm sits in
//! `check_tx_inputs` (`blockchain.cpp`, the `is_archival_emission_tx`
//! branch; the verify at `:4015`, the budget check at `:3935`, the
//! fee-input proof at `:4046–4105`).
//!
//! **One gather for two readers.** The snapshot a claim is verified over is
//! assembled by [`gather_epoch_snapshot`] — the same function the slash
//! pass folded `Σwork(E)` from (`archival/close.rs`, `Transition::gather`;
//! `ARCHIVAL_SETTLEMENT_WRITER.md` §15, `SO-D11`) — over the same
//! universe ([`gather_universe`]: the shards closed and final as of the
//! block that settled `E`) and the same credits: every pair whose
//! settlement row for `E` is Served ([`ServedAt`], one read per persona
//! for the epochs the claim cites). The verify's
//! recompute of `Σwork(E)` is then over the rows the pass saw, and the
//! compare with the frozen row (`EmissionVerifyError::SigmaWorkMismatch`)
//! can fail only on a claim that lies, never on a snapshot that drifted.
//! The bond records are read as they are now. The pass gathered after
//! `E`'s own slashes, so a record slashed for `E` is out of `E`'s market
//! in both readings, and a later interval opens at a later epoch. One
//! field of a record can still move under a settled epoch: a complete
//! tree that is slashed or released becomes a compact record, and
//! `market_member_at_epoch` reads that flag. The epoch close had the same
//! exposure and it is not closed here. The C++, consensus until `DEL-008`, gathers at the
//! epoch close on any pass and reads the shard segments and bond values
//! as they are now.
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
//! **Loci.** All three rows refuse at the transaction
//! ([`TxContext::locus`]), as the statics do (J19–J24) and as J21 does:
//! the emission is one per body (H6), and the C++ rejects the
//! transaction. The fold's L7 claim arm, which sees only what these rows
//! admitted, keeps its input locus and stays as the backstop beneath them
//! — the J4-over-L7 arrangement (`rules/tx_bond.rs`).
//!
//! The positive witness is the driver's claim
//! (`shekyl-chain-ingest`, `scenario_emission_tests`), whose `judged_by`
//! names all three rows; the harness's `fixture::emission_vin` is a
//! parseable vin with filler backing and auths that J23 refuses on the
//! mock's closeless chain and J25 would refuse on any chain, so J26's
//! refusals are fixtured on [`I15::verify`] directly and driven on the
//! claim with its fee proof corrupted.

use std::collections::BTreeSet;

use shekyl_archival_retention::{
    emission_vin_verify, emission_vin_verify_auth, emission_vin_verify_backing,
    emission_vin_verify_claims_under, p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin,
    ClaimantBondRecord, EmissionEpochSource, EmissionVerifyContext, EpochCloseInputs,
};
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use crate::archival::{gather_epoch_snapshot, gather_universe, EpochSnapshot, ServedAt};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::ViewRead;
use crate::rule_set::RuleSet;
use crate::rules::tx_against::{to_key_slots, ReferenceContext, I15};
use crate::rules::tx_emission::{the_emission, J19, J22, J24};
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Verdict};
use crate::view::{ChainView, Tip};

/// CEN-J23: every claimed epoch is **closed and settled** — it has its
/// frozen budget row (A8) and its `Σwork` row (A7) — and its snapshot is
/// gathered for the verify. The two rows are written an epoch apart: the
/// close freezes the budget at `(E+1)·SEB − 1`, and the slash pass writes
/// `Σwork(E)` at `(E+2)·SEB − 1` (`SO-D11`). Between them the epoch has a
/// budget and no denominator, which is an ordinary state and this row's
/// refusal: **`Σwork`'s existence is the citing gate**, so an epoch is
/// claimable from the block after its slash pass (`SO-D11d`). A claimed
/// epoch so far ahead that its close height does not fit a `u64` has no
/// close and is refused the same way.
///
/// The gather is [`gather_epoch_snapshot`] over the universe the pass
/// read ([`gather_universe`]) and A11's records, with the claimant named
/// so its index among the bonds is the source's `claimant_bond_idx`; the
/// credits are the Served rows ([`ServedAt`]) — a settled epoch's rows are
/// all recorded, and one read per persona covers every epoch the claim cites.
pub(crate) struct J23;

impl Rule for J23 {
    const ROW: CenRow = CenRow::J23;
}

/// One claimed epoch the citing gate admitted: a frozen budget, a frozen
/// `Σwork`, and a close height. The snapshot is gathered after every cited
/// epoch has passed the gate, so a missing row refuses before any
/// settlement hop.
struct CitedEpoch {
    /// The epoch as the vin spells it.
    raw: u64,
    epoch: SettlementEpoch,
    close_height: BlockHeight,
    sigma_work_milli: u64,
    budget: u64,
}

/// One claimed epoch's gathered source: the snapshot the slash pass read
/// and the two values it froze. Kept whole because `EmissionEpochSource`
/// borrows the snapshot's rows.
struct GatheredEpoch<'r> {
    epoch: u64,
    close_height: BlockHeight,
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
        // The citing gate first. A missing budget or Σwork refuses the
        // claim before any persona's settlement rows are read.
        let mut cited = Vec::with_capacity(vin.settlement_epochs.len());
        for &epoch in &vin.settlement_epochs {
            let settled = SettlementEpoch::from_raw(epoch);
            let (Some(budget), Some(sigma_work), Some(close_height)) = (
                view.budget(settled).map_err(ViewRead::View)?,
                view.sigma_work(settled).map_err(ViewRead::View)?,
                schedule.close_height(epoch).map(BlockHeight::from_raw),
            ) else {
                return Ok(Err(InvalidBlock::new(Self::ROW, cx.locus())));
            };
            cited.push(CitedEpoch {
                raw: epoch,
                epoch: settled,
                close_height,
                sigma_work_milli: sigma_work.to_raw(),
                budget: budget.to_raw(),
            });
        }
        // A set: a claim that cites an epoch twice reads it once.
        let epochs: BTreeSet<SettlementEpoch> = cited.iter().map(|cited| cited.epoch).collect();
        let credits = ServedAt::read(view, records.iter().map(|(persona, _)| *persona), &epochs)?;
        let mut gathered = Vec::with_capacity(cited.len());
        for cited in cited {
            let universe = gather_universe(view, schedule, rule_set.reorg_cap(), cited.epoch)?;
            let rows = records.iter().map(|(persona, record)| (persona, record));
            let snapshot = gather_epoch_snapshot(view, &universe, rows, Some(persona), |holder| {
                Ok(credits
                    .shards(holder, cited.epoch)
                    .iter()
                    .copied()
                    .map(ShardId::to_raw)
                    .collect())
            })?;
            gathered.push(GatheredEpoch {
                epoch: cited.raw,
                close_height: cited.close_height,
                snapshot,
                sigma_work_milli: cited.sigma_work_milli,
                budget: cited.budget,
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
                    g.close_height.to_raw(),
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

/// CEN-J26: the fee-input FCMP++ proof — absent iff the emission has no
/// fee inputs; present, it verifies over the `txin_to_key` subset
/// **exactly as CEN-I15** (`blockchain.cpp:4046–4105`, "§7.1 step 7 …
/// identical to bond-post funding inputs"). The body is [`I15::verify`]
/// over [`to_key_slots`] — the one derivation of which inputs are `ToKey`,
/// shared with the spend's and the bond post's attributions — against
/// J21's context; the absent⇔ clause is
/// H22's shape, required in `tx_form` and refused again by I15's body
/// rather than assumed. Refuses at the transaction, as the C++ does
/// (`reject_form`).
///
/// The one row of the emission's sequence the backing proof does not
/// cover: J25's membership-only proof is over the vin's backing output
/// and J22's signable hash, this one over the fee spends and the full
/// prefix hash. A claim whose fee proof is corrupt passes J21, J23 and
/// J25 and is refused here — the driver's second refusal for the row.
pub(crate) struct J26;

impl Rule for J26 {
    const ROW: CenRow = CenRow::J26;
}

impl J26 {
    /// The fee-input proof against `reference`.
    fn check(cx: &TxContext<'_>, reference: &ReferenceContext) -> Verdict<()> {
        I15::verify(cx.tx, &to_key_slots(cx.tx), reference)
            .map_err(|()| InvalidBlock::new(Self::ROW, cx.locus()))
    }
}

/// The rows this sequence records, in order.
const CLAIM_ROWS: [CenRow; 3] = [CenRow::J23, CenRow::J25, CenRow::J26];

/// The emission's view-bound sequence: J23's gathers, J25's verify, then
/// J26's fee-input proof. Off the `Emission` class all three rows are
/// recorded **vacuous**. On it, `reference` is J21's context from
/// `judge_reference`; an emission the caller reached here without one is
/// a sequence wired wrong, and the claim is refused under J25 rather than
/// verified against nothing.
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
        if let Err(refused) = J26::check(cx, reference) {
            return Ok(Err(refused));
        }
        coverage.insert(J26::ROW);
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
