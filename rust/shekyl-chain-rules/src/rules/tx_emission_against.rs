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
//! The bond records are read as they are now, except for one field. The
//! pass gathered after `E`'s own slashes, so a record slashed for `E` is
//! out of `E`'s market in both readings, a later interval opens at a later
//! epoch, and the join epoch never moves. The complete-tree flag can: a
//! complete tree that is slashed or released afterwards holds a compact
//! set, and `market_member_at_epoch` reads that flag. So the pass froze
//! the flag beside `Σwork(E)` — the complete trees it excluded from `E`'s
//! market (A22, SI-31; `SO-D12h`) — and the re-gather takes every bond's
//! flag from that set and never from the record. The C++, consensus until
//! `DEL-008`, gathers at the epoch close on any pass and reads the shard
//! segments and bond values as they are now.
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

use std::collections::{BTreeMap, BTreeSet};

use shekyl_archival_retention::{
    emission_vin_verify, emission_vin_verify_auth, emission_vin_verify_backing,
    emission_vin_verify_claims_under, p_canonical_id_from_hybrid_pubkey, ArchivalRewardEmissionVin,
    ClaimantBondRecord, EmissionEpochSource, EmissionVerifyContext, EpochCloseInputs,
};
use shekyl_types::archival::CompleteTreeSet;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

use crate::archival::{gather_epoch_snapshot, gather_universe, EpochSnapshot, ServedAt};
use crate::census::CenRow;
use crate::coverage::RuleCoverage;
use crate::fault::{Corrupt, ViewRead};
use crate::rule_set::RuleSet;
use crate::rules::tx_against::ReferenceContext;
use crate::rules::tx_emission::{the_emission, J19, J22, J24};
use crate::rules::{Rule, TxContext};
use crate::verdict::{InvalidBlock, Verdict};
use crate::view::{ChainView, Tip};
use crate::{Claimable, EpochFloor};

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
/// all recorded, and one read per persona covers every epoch the claim cites;
/// the complete-tree flags are the set the pass froze (A22). A settled
/// epoch without that set is a lost row, [`Corrupt::CompleteTreesAbsent`],
/// never a refusal of the claim.
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
    /// The complete trees the epoch's pass froze (A22): every bond's
    /// complete-tree flag in the re-gather.
    complete_trees: CompleteTreeSet,
}

impl CitedEpoch {
    /// CEN-J23's citing gate for one claimed epoch: its frozen budget, its
    /// `Σwork` and its close height, or `None` when any is missing — an
    /// epoch that has not settled, for which nothing may be gathered (its
    /// slash pass has not run, and its universe may lie above the tip).
    fn cite<'id, V: ChainView<'id>>(
        view: &V,
        rule_set: &RuleSet,
        floor: EpochFloor<Claimable>,
        raw: u64,
    ) -> Result<Option<Self>, ViewRead<V::Fault>> {
        let epoch = SettlementEpoch::from_raw(raw);
        let budget = view.budget(epoch, floor).map_err(ViewRead::View)?;
        let sigma_work = view.sigma_work(epoch, floor).map_err(ViewRead::View)?;
        let close_height = rule_set
            .settlement_schedule()
            .close_height(raw)
            .map(BlockHeight::from_raw);
        // Written in the pass's write set with `Σwork(E)` (SI-31). A settled
        // epoch without the set is a lost row, whether or not the budget or
        // the close height is present yet.
        let complete_trees = match sigma_work {
            Some(_) => Some(
                view.complete_trees(epoch, floor)
                    .map_err(ViewRead::View)?
                    .ok_or(ViewRead::Corrupt(Corrupt::CompleteTreesAbsent { epoch }))?,
            ),
            None => None,
        };
        let (Some(budget), Some(sigma_work), Some(close_height), Some(complete_trees)) =
            (budget, sigma_work, close_height, complete_trees)
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            raw,
            epoch,
            close_height,
            sigma_work_milli: sigma_work.to_raw(),
            budget: budget.to_raw(),
            complete_trees,
        }))
    }
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
        connecting: BlockHeight,
    ) -> Result<Verdict<Vec<GatheredEpoch<'r>>>, ViewRead<V::Fault>> {
        let schedule = rule_set.settlement_schedule();
        // Every cited epoch passed [`J25::window`], so none is below the
        // claimable floor and no read here can reach a retired row.
        let floor = EpochFloor::<Claimable>::under(connecting, schedule);
        // The citing gate first. A missing budget or Σwork refuses the
        // claim before any persona's settlement rows are read.
        let mut cited = Vec::with_capacity(vin.settlement_epochs.len());
        for &epoch in &vin.settlement_epochs {
            let Some(epoch) = CitedEpoch::cite(view, rule_set, floor, epoch)? else {
                return Ok(Err(InvalidBlock::new(Self::ROW, cx.locus())));
            };
            cited.push(epoch);
        }
        // The read's keys. The vin's epochs are already strictly increasing
        // (`EpochsNotStrictlyIncreasing`), so the set is that list.
        let epochs: BTreeSet<SettlementEpoch> = cited.iter().map(|cited| cited.epoch).collect();
        let credits = ServedAt::read(
            view,
            records.iter().map(|(persona, _)| *persona),
            &epochs,
            floor,
        )?;
        let mut gathered = Vec::with_capacity(cited.len());
        for cited in cited {
            let snapshot = gather_claimed_epoch(
                view,
                rule_set,
                records,
                persona,
                &credits,
                cited.epoch,
                &cited.complete_trees,
            )?;
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

/// One claimed epoch's snapshot: the universe the epoch's slash pass read
/// and A11's records, the claimant named, the Served rows as credits — the
/// one gather [`J23`] and [`emission_epoch_facts`] share.
fn gather_claimed_epoch<'id, 'r, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    records: &'r [(PCanonicalId, shekyl_types::archival::BondRecord)],
    persona: &PCanonicalId,
    credits: &ServedAt,
    epoch: SettlementEpoch,
    complete_trees: &CompleteTreeSet,
) -> Result<EpochSnapshot<'r>, ViewRead<V::Fault>> {
    let universe = gather_universe(
        view,
        rule_set.settlement_schedule(),
        rule_set.reorg_cap(),
        epoch,
    )?;
    let rows = records.iter().map(|(persona, record)| (persona, record));
    gather_epoch_snapshot(
        view,
        &universe,
        rows,
        Some(persona),
        complete_trees,
        |holder| {
            Ok(credits
                .shards(holder, epoch)
                .iter()
                .copied()
                .map(ShardId::to_raw)
                .collect())
        },
    )
}

/// One settlement epoch's close facts as CEN-J23 reads them for an
/// emission claim — what [`emission_epoch_facts`] hands a reader outside
/// the validator that must present the same facts (the submit engine over
/// the Rust pool, DRS-E5 PR-b M9), so the gather has one implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionEpochFacts {
    /// The epoch.
    pub settlement_epoch: u64,
    /// Its close height under the rule set, `None` past a `u64`.
    pub close_height: Option<BlockHeight>,
    /// Where the epoch stands for a claim at the connecting height.
    pub standing: EmissionEpochStanding,
}

/// Where one claimed epoch stands for a claim connecting at the view's
/// next height: three states, so "expired" and "not settled" are never
/// told apart by which fields happen to be absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmissionEpochStanding {
    /// Below the claim window at the connecting height: under the
    /// claimable [`EpochFloor`], which is the window's own floor
    /// (`claim_window_floor`, the one CEN-J25's window and the verify's
    /// `EpochClaimExpired` use). **Nothing was read for it**: its rows may
    /// be retired, and a read below the floor is SI-32. A claim on it is
    /// refused as expired.
    Expired {
        /// The oldest claimable epoch at the connecting height.
        window_floor: SettlementEpoch,
    },
    /// Inside the window and not settled: CEN-J23's citing gate refuses
    /// it. Each frozen row it already has — the budget once the close
    /// froze it, `Σwork` once the slash pass wrote it — and no gather: its
    /// slash pass may not have run, and its universe may lie above the tip.
    Unsettled {
        /// The frozen `Σwork(E)` (A7), if the slash pass wrote it.
        sigma_work_milli: Option<u64>,
        /// The frozen budget (A8), if the close froze it.
        budget: Option<u64>,
    },
    /// Settled: CEN-J23's citing gate admits it, with the rows it read and
    /// the snapshot its gather builds.
    Settled {
        /// The frozen `Σwork(E)` (A7).
        sigma_work_milli: u64,
        /// The frozen budget (A8).
        budget: u64,
        /// What the epoch's slash pass read, with the claimant named.
        snapshot: EmissionEpochSnapshot,
    },
}

/// The snapshot of a settled epoch in an [`EmissionEpochFacts`]: what its
/// slash pass read, with the claimant named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionEpochSnapshot {
    /// Every bond with a credit at the epoch: join epoch, whether it is the
    /// foundation's complete-tree bond, and its bad intervals.
    pub bonds: Vec<EpochCloseBondFacts>,
    /// Every closed shard, then each open shard a bond holds a credit on.
    pub shards: Vec<shekyl_archival_retention::EpochCloseShard>,
    /// One pair per `(bond, credited shard)`.
    pub pairs: Vec<shekyl_archival_retention::CreditPair>,
    /// The claimant's index into `bonds`, when it has a credit.
    pub claimant_bond_idx: Option<usize>,
}

/// One bond in an [`EmissionEpochFacts`], owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochCloseBondFacts {
    /// The bond's join epoch.
    pub join_settlement_epoch: u64,
    /// The foundation's complete-tree bond.
    pub is_support_complete_tree: bool,
    /// Its bad intervals.
    pub bad_intervals: Vec<shekyl_types::archival::BadInterval>,
}

/// The close facts of every epoch in `epochs` for `persona`'s emission
/// claim, read off `view` under `rule_set` — CEN-J23's citing gate and
/// gather ([`CitedEpoch::cite`], [`gather_claimed_epoch`]) for every epoch
/// the claim window still holds, without J23's refusal: each epoch
/// answers with its [`EmissionEpochStanding`], because the caller presents
/// facts and the validator judges.
///
/// The claim window is checked first, against the claimable [`EpochFloor`]
/// of the height the view's next block connects at (the window's own
/// floor, as [`J25`]'s window check). An epoch below it is
/// [`EmissionEpochStanding::Expired`] and is not read: its rows may already
/// be retired, and a read below the floor is SI-32.
///
/// # Errors
///
/// The view's fault, or a shard close the gather cannot place
/// ([`crate::Corrupt::ShardCloseUnplaced`]), or
/// [`crate::Corrupt::CompleteTreesAbsent`] when a frozen `Σwork` has no set.
pub fn emission_epoch_facts<'id, V: ChainView<'id>>(
    view: &V,
    rule_set: &RuleSet,
    persona: &PCanonicalId,
    epochs: &[u64],
) -> Result<Vec<EmissionEpochFacts>, ViewRead<V::Fault>> {
    let records = view.bond_records().map_err(ViewRead::View)?;
    let schedule = rule_set.settlement_schedule();
    let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
    let floor = EpochFloor::<Claimable>::under(connecting, schedule);
    let mut cited = BTreeMap::new();
    for &raw in epochs {
        if floor.below(SettlementEpoch::from_raw(raw)).is_some() {
            continue;
        }
        if let Some(epoch) = CitedEpoch::cite(view, rule_set, floor, raw)? {
            cited.insert(raw, epoch);
        }
    }
    let settled: BTreeSet<SettlementEpoch> = cited.values().map(|cited| cited.epoch).collect();
    let credits = ServedAt::read(
        view,
        records.iter().map(|(persona, _)| *persona),
        &settled,
        floor,
    )?;
    let mut out = Vec::with_capacity(epochs.len());
    for &raw in epochs {
        let standing = if let Some(window_floor) = floor.below(SettlementEpoch::from_raw(raw)) {
            EmissionEpochStanding::Expired { window_floor }
        } else if let Some(cited) = cited.get(&raw) {
            let snapshot = gather_claimed_epoch(
                view,
                rule_set,
                &records,
                persona,
                &credits,
                cited.epoch,
                &cited.complete_trees,
            )?;
            EmissionEpochStanding::Settled {
                sigma_work_milli: cited.sigma_work_milli,
                budget: cited.budget,
                snapshot: EmissionEpochSnapshot {
                    bonds: snapshot
                        .bonds
                        .iter()
                        .map(|bond| EpochCloseBondFacts {
                            join_settlement_epoch: bond.join_settlement_epoch,
                            is_support_complete_tree: bond.is_support_complete_tree,
                            bad_intervals: bond.bad_intervals.to_vec(),
                        })
                        .collect(),
                    shards: snapshot.shards,
                    pairs: snapshot.pairs,
                    claimant_bond_idx: snapshot.claimant_bond_idx,
                },
            }
        } else {
            let epoch = SettlementEpoch::from_raw(raw);
            EmissionEpochStanding::Unsettled {
                sigma_work_milli: view
                    .sigma_work(epoch, floor)
                    .map_err(ViewRead::View)?
                    .map(shekyl_types::archival::SigmaWorkMilli::to_raw),
                budget: view
                    .budget(epoch, floor)
                    .map_err(ViewRead::View)?
                    .map(shekyl_units::AtomicUnits::to_raw),
            }
        };
        out.push(EmissionEpochFacts {
            settlement_epoch: raw,
            close_height: schedule.close_height(raw).map(BlockHeight::from_raw),
            standing,
        });
    }
    Ok(out)
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
    /// The claim window, before anything is read: every cited epoch is at
    /// or above the claimable [`EpochFloor`] of the connecting height,
    /// which is `claim_window_floor` of its epoch — the floor the verify's
    /// step 1 refuses `EpochClaimExpired` below, and the floor J23's reads
    /// then carry, one value for both. Run ahead
    /// of CEN-J23 because J23 reads the cited epochs' rows, and the rows of
    /// an expired epoch may be retired (`ARCHIVAL_SETTLEMENT_WRITER.md`
    /// §17): the store refuses a read below the claimable floor as a fault
    /// (SI-32), and a claim's epochs are the sender's to choose. An expired
    /// claim is this row's refusal, as it was when the verify reached it
    /// first; the verify still checks the window itself.
    fn window(
        cx: &TxContext<'_>,
        rule_set: &RuleSet,
        vin: &ArchivalRewardEmissionVin,
        connecting: BlockHeight,
    ) -> Verdict<()> {
        let floor = EpochFloor::<Claimable>::under(connecting, rule_set.settlement_schedule());
        if vin
            .settlement_epochs
            .iter()
            .any(|&epoch| floor.below(SettlementEpoch::from_raw(epoch)).is_some())
        {
            return Err(InvalidBlock::new(Self::ROW, cx.locus()));
        }
        Ok(())
    }

    /// The verify over the gathered epochs. `Ok(Err)` is this row's
    /// refusal, or J24's where the commit set is not well-defined; `Err`
    /// is the view's fault from the record read.
    #[allow(
        clippy::too_many_arguments,
        reason = "the claim, its context, and the connecting height the window was checked at"
    )]
    fn verify<'id, V: ChainView<'id>>(
        cx: &TxContext<'_>,
        view: &V,
        rule_set: &RuleSet,
        vin: &ArchivalRewardEmissionVin,
        persona: &PCanonicalId,
        reference: &ReferenceContext,
        gathered: &[GatheredEpoch<'_>],
        connecting: BlockHeight,
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

        // `connecting` is the height the C++ passes as `chain_height`: one
        // above the tip the block is judged against, the same height the
        // window was checked at.
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

/// The rows this sequence records, in order. J26 left it on 2026-10-16:
/// the fee-input proof reads no chain and runs in `form`
/// ([`crate::rules::proofs::judge_proofs`]), which records it, vacuous or judged.
const CLAIM_ROWS: [CenRow; 2] = [CenRow::J23, CenRow::J25];

/// The emission's view-bound sequence: J25's claim window (before any
/// read), J23's gathers, J25's verify, then J26's fee-input proof. Off the
/// `Emission` class all three rows are recorded **vacuous**. On it,
/// `reference` is J21's context from `judge_reference`; an emission the
/// caller reached here without one is a sequence wired wrong, and the claim
/// is refused under J25 rather than verified against nothing.
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
        let connecting = Tip::connecting_height(view.tip().map_err(ViewRead::View)?.as_ref());
        if let Err(expired) = J25::window(cx, rule_set, &vin, connecting) {
            return Ok(Err(expired));
        }
        let records = view.bond_records().map_err(ViewRead::View)?;
        let gathered = match J23::gather(cx, view, rule_set, &vin, &persona, &records, connecting)?
        {
            Ok(gathered) => gathered,
            Err(refused) => return Ok(Err(refused)),
        };
        coverage.insert(J23::ROW);
        let Some(reference) = reference else {
            return Ok(Err(InvalidBlock::new(J25::ROW, cx.locus())));
        };
        match J25::verify(
            cx, view, rule_set, &vin, &persona, reference, &gathered, connecting,
        )? {
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
