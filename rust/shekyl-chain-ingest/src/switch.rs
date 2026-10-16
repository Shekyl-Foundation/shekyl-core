// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The switch — an alternative block's arrival, the fork choice, and the
//! reorganization as one write closure (DRS-E5 a5,
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.3; CEN-K5, K5b, K6, K7).
//!
//! Two messages on the single writer, with the RandomX between them:
//!
//! 1. [`OfferAlt`] — a formed block whose parent is not the tip. The cheap
//!    tier judges it over the stitched [`AltView`] (`alt_against`), AL1
//!    stores the verdict, and the fork choice reads the two cumulative
//!    difficulties and the checkpoint table (K6). A winning verdict comes
//!    back as a [`SwitchPlan`]: the blocks the switch will judge, each with
//!    its seed claim, for the caller to `form` off the actor (step 1 of
//!    §2.3 — the M alt entries and, unless the verdict is the checkpoint's,
//!    the N demoted blocks).
//! 2. [`Reorganize`] — the formed blocks, with the tip the plan was made
//!    against. On the actor, before any write: the plan is held to the
//!    store (a tip that moved is a driver defect, never a switch); the cap
//!    is checked (`E5-Q6`); each demoted block the plan formed — the
//!    `Switch` arm, which re-admits them — is judged by the cheap tier
//!    over a snapshot taken here, where its history is exactly the chain
//!    below it (SAL-13; a refusal is SI-27). `ForcedSwitch` forms none of
//!    them and discards them (K7), so the tier does not run and SI-27 does
//!    not arm. Then one `store.write`: the
//!    pops and SI-5 (`pop_many`), the demoted rows from their verdicts
//!    (K7; the checkpoint arm discards them), every alt entry through the
//!    full `validate` and `connect` (K5; K5b's witness travels in the alt
//!    row), and the alt rows removed. A promotion verdict aborts the
//!    transaction — the store is the pre-switch chain — and the failing alt
//!    suffix is removed in a write of its own.
//!
//!    Proofs run in `form`, off the actor, under the plan's claims. A
//!    promoted block that fails there never becomes a [`Reorganize`]:
//!    [`RefusePromotion`] carries the verdict back, the plan is held to
//!    the store, and the failing suffix is removed with no pop. A refusal
//!    under claims the plan did not derive is the driver's, observed
//!    before this message, and the alt stays — the same class as a stale
//!    reference.
//!
//! The listed bodies of an alt block are not the alt row's (`AltValid`'s
//! `into_candidate`: the bodies are the pool's to hold until promotion), so
//! the caller supplies them with the formed blocks; the pool is that caller
//! from PR-b on. The demoted blocks' bodies come back as
//! [`SwitchDone::returned`], which the caller drops until PR-b (`E5-Q10`).
//!
//! Not here: the arrival router's other arms beyond answering an orphan or
//! a held hash, the orphan policy, and A1/A4's Rust holder — the DRS-X
//! Round 0 designs them with the live sources.

use std::collections::{BTreeMap, BTreeSet};

use kameo::message::{Context, Message};
use shekyl_chain_rules::{
    alt_against, seed_height, target_claim, validate, Candidate, CenRow, Fault, InvalidBlock,
    ReferenceClaim, ReferenceClaims, StructurallyValid, Target, Tip, Trust,
    REFERENCE_BLOCK_MAX_AGE,
};
use shekyl_chain_store::store::{
    AltCannot, AltChain, AltView, ChainStore, RawRows, ReadSnapshot, StoreCannot, StoreError,
    WriteBatch,
};
use shekyl_difficulty::{fork_choice, ForkChoiceVerdict};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, CurveTreeRoot};
use shekyl_wire::{Block, Transaction};

use super::{fault_reply, Connector, PlanMismatchReason, RunFault};
use crate::schedule::ChainRules;
use shekyl_chain_rules::{AtHeight, HeaderView};

/// A switch deeper than the cap in force: refused **locally**, before any
/// pop and before any RandomX (`E5-Q6`). Never a verdict against the alt
/// block, never peer-punishable (C2-R1 Q1c F-1(a)): the block stays stored.
///
/// The cap is a **policy** limit and `PopBelowFloor` is a **capability**
/// limit; two independent operands earn two refusals (`E5-Q6`'s ruling,
/// the discriminator SLK-2 applied a third time).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PopBeyondReorgCap {
    /// Blocks the switch would pop: the recorded tip's height less the
    /// fork point's.
    pub depth: BlockCount,
    /// `RuleSet::reorg_cap` in force at the alternative tip's height.
    pub cap: BlockCount,
}

/// A formed block whose parent is not the recorded tip — an alternative
/// arrival (module docs, message 1).
#[derive(Debug)]
pub struct OfferAlt(pub StructurallyValid);

/// What an [`OfferAlt`] did.
#[derive(Debug)]
pub enum Offered {
    /// The cheap tier refused the block — a verdict; nothing was stored.
    Refused(InvalidBlock),
    /// The block's parent chain reaches no recorded block (CEN-K2's
    /// orphan, `AltCannot::Unlinked`); nothing was stored. `at` is the
    /// first hash neither table holds.
    Unlinked {
        /// The first unheld hash on the walk.
        at: BlockHash,
    },
    /// The store already holds the block — as an alternative (CEN-K3) or
    /// on the recorded chain.
    AlreadyHeld,
    /// Stored; the incumbent stays (K6: not strictly heavier, no
    /// checkpoint names it).
    Held {
        /// The block's height on its chain.
        height: BlockHeight,
    },
    /// Stored, and the fork choice switches — but the fork is deeper than
    /// the cap (`E5-Q6`): a local outcome, the block stays stored.
    BeyondCap(PopBeyondReorgCap),
    /// Stored, and the fork choice switches: form what the plan names and
    /// send [`Reorganize`].
    SwitchDue(SwitchPlan),
}

/// One block a switch will judge, with what `form` needs beside the
/// substrate: the height (which rule set), the seed claim (CEN-D3) and the
/// target claim (CEN-D4) on the chain the block is on. The third claim —
/// the references — needs the listed bodies, which the plan does not
/// carry; the caller makes it from the plan's header chain
/// ([`SwitchPlan::references_for`]).
#[derive(Clone, Debug)]
pub struct PlannedBlock {
    /// The height the block sits at on its chain.
    pub height: BlockHeight,
    /// The block's identity.
    pub hash: BlockHash,
    /// The seed the honest producer claimed: the identity at
    /// `seed_height(height)` on the block's own chain, or the null hash
    /// below the first epoch.
    pub seed: BlockHash,
    /// The target the honest producer claimed: CEN-D4 over the headers
    /// below `height` on the block's own chain — the stitched view for an
    /// alt entry, the recorded chain for a demoted block (#1081's
    /// contract; `validate` and `alt_against` each derive it again and
    /// fault `Stale::Target` on a disagreement, which during a switch is a
    /// driver defect).
    pub target: Target,
    /// The proof-of-work hash this node recorded for the block when it
    /// first judged it, under the seed it was recorded under — `block_pow`
    /// for a demoted block, the alt row's for a promoted one. The caller
    /// forms through it (`substrate::Recalled`) instead of hashing again.
    pub recorded: shekyl_chain_rules::ProvenPow,
}

/// A recorded block the switch will demote.
#[derive(Clone, Debug)]
pub struct PlannedDemotion {
    /// Height, identity, seed claim.
    pub at: PlannedBlock,
    /// The block as recorded, with its listed bodies and witness
    /// (`ReadSnapshot::candidate_at`, SAL-13).
    pub candidate: shekyl_chain_rules::Candidate,
}

/// An alt entry the switch will promote. The block and witness are the
/// alt row's; the listed bodies are the caller's (module docs).
#[derive(Clone, Debug)]
pub struct PlannedPromotion {
    /// Height, identity, seed claim.
    pub at: PlannedBlock,
    /// The block as the alt row holds it.
    pub block: Block,
    /// The witness the alt row carries (CEN-K5b).
    pub witness: Option<AttestationWitness>,
}

/// One header of the chain a switch promotes onto, as a reference claim
/// reads it: its identity and the curve-tree root at its height — the
/// header's `curve_tree_root`, which CEN-B5 holds to `root_at(height)` for
/// every block that connected, and which promotion holds for every alt
/// entry before any successor's claim over it is compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedHeader {
    /// The header's height on the post-switch chain.
    pub height: BlockHeight,
    /// The block's identity — what a listed body's `reference_block` names.
    pub hash: BlockHash,
    /// The tree root at `height` (CEN-I12's anchor).
    pub root: CurveTreeRoot,
}

/// What [`Offered::SwitchDue`] asks the caller to form.
#[derive(Clone, Debug)]
pub struct SwitchPlan {
    /// The recorded tip the plan was made against.
    pub tip: Tip,
    /// The fork point: the recorded block the alternative chain leaves from.
    pub root: Tip,
    /// The alternative chain's tip — the offered block.
    pub alt_tip: BlockHash,
    /// The fork choice's arm: `ForcedSwitch` discards the demoted chain
    /// (K7), so its blocks are not formed.
    pub verdict: ForkChoiceVerdict,
    /// The recorded blocks above the fork point, ascending.
    pub demoted: Vec<PlannedDemotion>,
    /// The alt entries, ascending, ending at the offered block.
    pub promoted: Vec<PlannedPromotion>,
    /// The post-switch header chain a promoted block may reference,
    /// ascending: CEN-I11's window below the first promoted height, read
    /// off the recorded chain, then the alt entries themselves — the
    /// stitched view, as the plan read it (`AltView::header_at`). The
    /// caller claims each promoted block's references off it
    /// ([`Self::references_for`]); a reference outside it is not claimed,
    /// and `validate` refuses it on CEN-I10/I11.
    pub headers: Vec<PlannedHeader>,
}

impl SwitchPlan {
    /// The reference claims for `candidate`, the bodies of the promoted
    /// block `at`: every reference it names that [`Self::headers`] holds
    /// **below** `at.height`, at that header's height and root. The third
    /// claim to `form` (`CHAIN_RULES_CRATE.md` §4.6); `validate` compares
    /// it with the chain inside the switch's closure and faults
    /// `Stale::Reference` on a disagreement — a driver defect, as a stale
    /// target is.
    #[must_use]
    pub fn references_for(&self, at: &PlannedBlock, candidate: &Candidate) -> ReferenceClaims {
        ReferenceClaims::gather(candidate, |reference| {
            self.headers
                .iter()
                .find(|header| header.hash == *reference && header.height < at.height)
                .map(|header| ReferenceClaim {
                    height: header.height,
                    root: header.root,
                })
        })
    }
}

/// What [`plan`] made of a winning verdict.
enum Planned {
    /// The switch to carry out.
    Due(SwitchPlan),
    /// Deeper than the cap (`E5-Q6`): local, the block stays stored.
    BeyondCap(PopBeyondReorgCap),
    /// CEN-D6 refused an alt entry's target on its own headers: that
    /// block's verdict (`target` module docs), so there is no claim to
    /// make and nothing is formed. As a promotion verdict does (K5), the
    /// refused entry and every entry above it leave the alt table —
    /// `remove`, ascending — in a write of their own.
    Refused {
        /// The verdict.
        refused: InvalidBlock,
        /// The refused entry and its successors, ascending.
        remove: Vec<BlockHash>,
    },
}

/// The formed blocks a [`SwitchPlan`] named, back to the actor (module
/// docs, message 2). A promoted block `form` refused is
/// [`RefusePromotion`], not a reorganization.
#[derive(Debug)]
pub struct Reorganize {
    /// The plan's tip; the switch refuses if the store's tip moved.
    pub tip: Tip,
    /// The plan's alternative tip.
    pub alt_tip: BlockHash,
    /// The demoted blocks, formed, ascending; empty when the plan's verdict
    /// is `ForcedSwitch`.
    pub demoted: Vec<StructurallyValid>,
    /// The alt entries, formed, ascending.
    pub promoted: Vec<StructurallyValid>,
}

/// A promoted block's `form` refused under the plan's own claims (module
/// docs). The proofs ran off the actor; the closure does not open, so the
/// main chain is not popped. The failing alt suffix is removed, as a
/// promotion verdict's is (K5).
#[derive(Debug)]
pub struct RefusePromotion {
    /// The plan's tip; nothing is removed if the store's tip moved.
    pub tip: Tip,
    /// The plan's alternative tip.
    pub alt_tip: BlockHash,
    /// The promoted block `form` refused.
    pub hash: BlockHash,
    /// The verdict.
    pub refused: InvalidBlock,
}

/// A switch that landed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwitchDone {
    /// The blocks popped, ascending by height.
    pub demoted: Vec<(BlockHeight, BlockHash)>,
    /// Whether the demoted blocks were kept as alt rows (`Switch`) or
    /// discarded (`ForcedSwitch`, K7).
    pub demoted_kept: bool,
    /// The blocks connected, ascending.
    pub promoted: Vec<(BlockHeight, BlockHash)>,
    /// The demoted blocks' listed transactions, in chain order — the
    /// pool's from PR-b; dropped by the one caller until then (`E5-Q10`).
    pub returned: Vec<Transaction>,
    /// The census rows the promoted blocks' verdicts exercised.
    pub exercised: BTreeSet<&'static str>,
}

/// What a [`Reorganize`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Switched {
    /// The switch landed.
    Done(SwitchDone),
    /// A promoted block failed `validate` (K5): the transaction rolled
    /// back, the main chain is the pre-switch chain, and the failing alt
    /// suffix — the refused block and every alt entry above it — was
    /// removed.
    Refused {
        /// Where the refused block sits on the alternative chain.
        at: BlockHeight,
        /// The refused block.
        hash: BlockHash,
        /// The verdict.
        refused: InvalidBlock,
        /// The alt rows removed with it, ascending.
        removed: Vec<BlockHash>,
    },
    /// The fork is deeper than the cap (`E5-Q6`): local, nothing popped.
    BeyondCap(PopBeyondReorgCap),
    /// A pop met the undo floor (`StoreCannot::PopBelowFloor`): this node
    /// cannot follow the heavier chain. F-1 fail-stop, local — never a
    /// verdict, never peer-punishable; nothing moved.
    BelowFloor {
        /// The tip the pop met.
        tip: u64,
        /// The persisted undo floor.
        floor: u64,
    },
}

/// **AL6.** How many alternative blocks the store holds — the alt table's
/// one metric (`E5-Q7`: PoW bounds the table, this measures it) and how a
/// caller sees K7's arm: a difficulty switch leaves the demoted blocks
/// held, a checkpoint-forced one does not.
#[derive(Clone, Copy, Debug)]
pub struct AltBlocksHeld;

impl Message<AltBlocksHeld> for Connector {
    type Reply = Result<u64, RunFault>;

    async fn handle(
        &mut self,
        _: AltBlocksHeld,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.writer.read()?.alt_block_count()?)
    }
}

/// Why a switch's write closure stopped, carried out of `store.write` so a
/// verdict and a local limit roll back without becoming faults.
enum Stop {
    Fault(RunFault),
    Refused {
        index: usize,
        at: BlockHeight,
        hash: BlockHash,
        refused: InvalidBlock,
    },
    BelowFloor {
        tip: u64,
        floor: u64,
    },
}

impl From<StoreError> for Stop {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::Cannot(StoreCannot::PopBelowFloor { tip, floor }) => {
                Self::BelowFloor { tip, floor }
            }
            other => Self::Fault(RunFault::Store(other)),
        }
    }
}

impl From<RunFault> for Stop {
    fn from(f: RunFault) -> Self {
        Self::Fault(f)
    }
}

impl Message<OfferAlt> for Connector {
    type Reply = Result<Offered, RunFault>;

    async fn handle(
        &mut self,
        msg: OfferAlt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (rules, trust) = (self.rules, self.trust);
        self.writer
            .with_store(|store| offer(store, rules, trust, msg.0))
    }
}

impl Message<Reorganize> for Connector {
    type Reply = Result<Switched, RunFault>;

    async fn handle(
        &mut self,
        msg: Reorganize,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let (rules, trust) = (self.rules, self.trust);
        self.writer
            .with_store(|store| switch(store, rules, trust, msg))
    }
}

impl Message<RefusePromotion> for Connector {
    type Reply = Result<Switched, RunFault>;

    async fn handle(
        &mut self,
        msg: RefusePromotion,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.writer.with_store(|store| refuse_promotion(store, msg))
    }
}

/// The offer's body, under the run's `trust`.
fn offer(
    store: &ChainStore,
    rules: ChainRules,
    trust: Trust,
    formed: StructurallyValid,
) -> Result<Offered, RunFault> {
    let hash = formed.hash();
    let parent = formed.candidate().block.header.previous;
    let snap = store.begin_read()?;
    let tip = snap.tip()?.recorded;
    if tip.is_some_and(|t| t.hash == parent) {
        return Err(RunFault::NotAlternative { parent });
    }
    // A block the recorded chain already holds is held: as an alt row too
    // it would sit in both tables, and the next switch that demoted it
    // would meet its own row.
    if snap.height_of(&hash)?.is_some() {
        return Ok(Offered::AlreadyHeld);
    }
    let chain = match AltChain::build(&snap, &parent) {
        Ok(chain) => chain,
        Err(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked { at }))) => {
            return Ok(Offered::Unlinked { at })
        }
        Err(e) => return Err(e.into()),
    };
    let height = chain.candidate_height();
    let in_force = rules.in_force(height);
    let view = AltView::new(&snap, chain);
    let admitted = match alt_against(formed, &view, &in_force, &trust) {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(refused)) => return Ok(Offered::Refused(refused)),
        Err(fault) => return Err(snapshot_fault(store, height, fault)),
    };
    drop(view);
    let alternative = admitted.cumulative_difficulty();
    let inserted: Result<(), StoreError> = store.write(|batch| batch.insert_alt_block(admitted));
    match inserted {
        Ok(()) => {}
        Err(StoreError::Cannot(StoreCannot::Alt(AltCannot::AlreadyHeld))) => {
            return Ok(Offered::AlreadyHeld)
        }
        Err(e) => return Err(e.into()),
    }
    let tip = tip.expect("an alternative chain links to a recorded block");
    let current = recorded_work(&snap, tip.height)?;
    // K6: the comparison's one implementation; the checkpoint arm is the
    // release's pin at the block's height naming this block.
    let checkpoint = trust.anchors().expected_at(height) == Some(hash);
    let verdict = fork_choice(current, alternative, checkpoint);
    if verdict == ForkChoiceVerdict::KeepCurrent {
        return Ok(Offered::Held { height });
    }
    drop(snap);
    // A fresh snapshot: the plan's alternative chain includes the row just
    // written.
    let snap = store.begin_read()?;
    match plan(store, &snap, rules, tip, hash, verdict)? {
        Planned::Due(plan) => Ok(Offered::SwitchDue(plan)),
        Planned::BeyondCap(beyond) => Ok(Offered::BeyondCap(beyond)),
        Planned::Refused { refused, remove } => {
            remove_alt_suffix(store, &remove)?;
            Ok(Offered::Refused(refused))
        }
    }
}

/// The plan for switching from `tip` onto the alternative chain ending at
/// `alt_tip`, or the cap's refusal (`E5-Q6`), read on `snap`. Each
/// block's target is claimed here, through the one derivation
/// (`target_claim`) over the chain the block is on: the stitched view for
/// an alt entry, the recorded chain below it for a demoted block. A D6
/// refusal on an alt entry is that block's verdict ([`Planned::Refused`]);
/// on a demoted block the `Switch` arm forms, it is a recorded block
/// failing its own rules — SI-27, the writer halts, as the cheap tier's
/// refusal does in [`switch`]. `ForcedSwitch` forms none of them (K7).
fn plan(
    store: &ChainStore,
    snap: &ReadSnapshot<'_>,
    rules: ChainRules,
    tip: Tip,
    alt_tip: BlockHash,
    verdict: ForkChoiceVerdict,
) -> Result<Planned, RunFault> {
    let chain = AltChain::build(snap, &alt_tip)?;
    let root = chain.root();
    if let Err(beyond) = within_cap(rules, &chain, tip) {
        return Ok(Planned::BeyondCap(beyond));
    }
    let stitched = AltView::new(snap, chain.clone());
    let entries = chain.entries();
    // K7: ForcedSwitch discards the demoted chain, so the plan does not
    // read the blocks it will not form. The Switch arm re-admits them and
    // claims their seed and target over the chain below each one.
    let mut demoted = Vec::new();
    if verdict == ForkChoiceVerdict::Switch {
        let mut height = root.height;
        while height < tip.height {
            height = height.checked_add(BlockCount::ONE).expect("below the tip");
            let candidate = match snap.candidate_at(height)? {
                AtHeight::Recorded(candidate) => candidate,
                AtHeight::AboveTip => unreachable!("heights up to the tip are recorded"),
            };
            let recorded = match snap.recorded_pow(height)? {
                AtHeight::Recorded(pow) => pow.proven(),
                AtHeight::AboveTip => unreachable!("heights up to the tip are recorded"),
            };
            // The recorded chain below this block, as the cheap tier will see
            // it in `switch` (SAL-13): the seed and the target over the same view.
            let parent = recorded_hash(snap, BlockHeight::from_raw(height.to_raw() - 1))?;
            let below = AltView::new(snap, AltChain::build(snap, &parent)?);
            let target = match target_claim(&below, height, &rules.in_force(height)) {
                Ok(Ok(target)) => target,
                Ok(Err(_refused)) => {
                    return Err(halt_writer(store, |batch| batch.refuse_demotion(height)))
                }
                Err(fault) => return Err(snapshot_fault(store, height, fault)),
            };
            demoted.push(PlannedDemotion {
                at: PlannedBlock {
                    height,
                    hash: recorded_hash(snap, height)?,
                    seed: claimed_seed(&below, height)?,
                    target,
                    recorded,
                },
                candidate,
            });
        }
    }
    let mut promoted = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let height = entry.block.height();
        let witness = entry
            .block
            .attestation_witness()
            .map(|bytes| AttestationWitness::new(bytes.to_vec()))
            .transpose()
            .expect("an alt row's witness was held well-formed when it was read (AL4)");
        let target = match target_claim(&stitched, height, &rules.in_force(height)) {
            Ok(Ok(target)) => target,
            Ok(Err(refused)) => {
                return Ok(Planned::Refused {
                    refused,
                    remove: entries[index..].iter().map(|e| e.id).collect(),
                })
            }
            Err(fault) => return Err(snapshot_fault(store, height, fault)),
        };
        promoted.push(PlannedPromotion {
            at: PlannedBlock {
                height,
                hash: entry.id,
                seed: claimed_seed(&stitched, height)?,
                target,
                recorded: entry.block.pow().proven(),
            },
            block: entry.block.block().clone(),
            witness,
        });
    }
    // The header chain the promoted blocks may reference: CEN-I11's window
    // below the first promoted height, then the entries — every height
    // through the stitched view, so one reader answers both halves.
    let first_promoted = root.height.to_raw() + 1;
    let floor = first_promoted.saturating_sub(REFERENCE_BLOCK_MAX_AGE.to_raw());
    let alt_tip_height = chain.parent().height.to_raw();
    let mut headers =
        Vec::with_capacity(usize::try_from(alt_tip_height - floor + 1).expect("fits"));
    for raw in floor..=alt_tip_height {
        let height = BlockHeight::from_raw(raw);
        let AtHeight::Recorded(record) = stitched.header_at(height)? else {
            unreachable!("the stitched view answers every height through its tip")
        };
        headers.push(PlannedHeader {
            height,
            hash: record.hash,
            root: record.header.curve_tree_root,
        });
    }
    Ok(Planned::Due(SwitchPlan {
        tip,
        root,
        alt_tip,
        verdict,
        demoted,
        promoted,
        headers,
    }))
}

/// `E5-Q6`: the depth `chain` would pop from `tip`, against the cap in
/// force at the alternative tip's height.
fn within_cap(rules: ChainRules, chain: &AltChain, tip: Tip) -> Result<(), PopBeyondReorgCap> {
    let depth = BlockCount::from_raw(tip.height.to_raw() - chain.root().height.to_raw());
    let cap = rules.in_force(chain.parent().height).reorg_cap();
    if depth > cap {
        return Err(PopBeyondReorgCap { depth, cap });
    }
    Ok(())
}

/// The switch's body, under the run's `trust`.
/// The plan's tip is still the store's, and `alt_tip` still builds an
/// alternative chain. A moved tip is stale; an unlinked tip is a plan
/// mismatch. Nothing is written.
fn alternative_chain(
    snap: &ReadSnapshot<'_>,
    planned: Tip,
    alt_tip: &BlockHash,
) -> Result<AltChain, RunFault> {
    let tip = snap.tip()?.recorded;
    if tip != Some(planned) {
        return Err(RunFault::StalePlan { planned, tip });
    }
    match AltChain::build(snap, alt_tip) {
        Ok(chain) => Ok(chain),
        Err(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked { .. }))) => {
            Err(RunFault::PlanMismatch {
                reason: PlanMismatchReason::AlternativeTipUnheld,
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// [`RefusePromotion`]'s body. The closure does not open: a proof that
/// failed under the plan's claims is the block's verdict, and the main
/// chain stays where it is.
fn refuse_promotion(store: &ChainStore, msg: RefusePromotion) -> Result<Switched, RunFault> {
    let snap = store.begin_read()?;
    let chain = alternative_chain(&snap, msg.tip, &msg.alt_tip)?;
    let entries = chain.entries();
    if entries.is_empty() {
        return Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::AlternativeTipRecorded,
        });
    }
    let Some(index) = entries.iter().position(|entry| entry.id == msg.hash) else {
        return Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::RefusedBlockUnheld,
        });
    };
    let at = entries[index].block.height();
    let removed: Vec<BlockHash> = entries[index..].iter().map(|entry| entry.id).collect();
    drop(snap);
    remove_alt_suffix(store, &removed)?;
    Ok(Switched::Refused {
        at,
        hash: msg.hash,
        refused: msg.refused,
        removed,
    })
}

/// The switch's body, under the run's `trust`.
fn switch(
    store: &ChainStore,
    rules: ChainRules,
    trust: Trust,
    msg: Reorganize,
) -> Result<Switched, RunFault> {
    let snap = store.begin_read()?;
    // The plan is held to the store before anything is judged.
    let chain = alternative_chain(&snap, msg.tip, &msg.alt_tip)?;
    let tip = msg.tip;
    if let Err(beyond) = within_cap(rules, &chain, tip) {
        return Ok(Switched::BeyondCap(beyond));
    }
    let root = chain.root();
    let entries = chain.entries().to_vec();
    let alt_tip_height = chain.parent().height;
    // K6, re-derived on the actor: the caller carries formed blocks, not
    // the verdict. An alternative tip the recorded chain holds is no
    // alternative chain at all.
    let Some(last) = entries.last() else {
        return Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::AlternativeTipRecorded,
        });
    };
    let alternative = last.block.cumulative_difficulty();
    let checkpoint = trust.anchors().expected_at(alt_tip_height) == Some(msg.alt_tip);
    let verdict = fork_choice(recorded_work(&snap, tip.height)?, alternative, checkpoint);
    let keep_demoted = match verdict {
        ForkChoiceVerdict::KeepCurrent => {
            return Err(RunFault::PlanMismatch {
                reason: PlanMismatchReason::IncumbentKept,
            })
        }
        ForkChoiceVerdict::Switch => true,
        ForkChoiceVerdict::ForcedSwitch => false,
    };

    // The promoted blocks are the alt entries, in order, each with the
    // witness its row carries (K5b).
    if msg.promoted.len() != entries.len() {
        return Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::PromotedLength,
        });
    }
    for (formed, entry) in msg.promoted.iter().zip(&entries) {
        let witness = formed
            .candidate()
            .attestation_witness
            .as_ref()
            .map(AttestationWitness::as_bytes);
        if formed.hash() != entry.id || witness != entry.block.attestation_witness() {
            return Err(RunFault::PlanMismatch {
                reason: PlanMismatchReason::PromotedRow,
            });
        }
    }

    // The demoted blocks: the recorded chain above the fork point, read
    // before the closure (SAL-13). Their bodies return to the pool either
    // way; their rows are written only on the difficulty arm (K7).
    let depth = tip.height.to_raw() - root.height.to_raw();
    let mut demoted = Vec::new();
    let mut witnesses = Vec::new();
    let mut returned = Vec::new();
    for offset in 1..=depth {
        let height = BlockHeight::from_raw(root.height.to_raw() + offset);
        let candidate = match snap.candidate_at(height)? {
            AtHeight::Recorded(candidate) => candidate,
            AtHeight::AboveTip => unreachable!("heights up to the tip are recorded"),
        };
        demoted.push((height, recorded_hash(&snap, height)?));
        witnesses.push(candidate.attestation_witness.clone());
        returned.extend(candidate.transactions);
    }
    let expected_demoted = if keep_demoted { demoted.len() } else { 0 };
    // CEN-K5b's other direction: a demoted row carries the witness its
    // height row held, so the formed block must carry that one.
    if msg.demoted.len() != expected_demoted
        || msg.demoted.iter().zip(demoted.iter().zip(&witnesses)).any(
            |(formed, ((_, hash), witness))| {
                formed.hash() != *hash || formed.candidate().attestation_witness != *witness
            },
        )
    {
        return Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::DemotedChain,
        });
    }

    // SAL-13 / CEN-K7: each demoted block through the cheap tier, over the
    // chain below it on this snapshot. A refusal is a recorded block that
    // fails its own rules — SI-27, the writer halts.
    let mut demoted_rows = Vec::with_capacity(msg.demoted.len());
    for (formed, (height, _)) in msg.demoted.into_iter().zip(&demoted) {
        let parent = recorded_hash(&snap, BlockHeight::from_raw(height.to_raw() - 1))?;
        let below = AltChain::build(&snap, &parent)?;
        let view = AltView::new(&snap, below);
        match alt_against(formed, &view, &rules.in_force(*height), &trust) {
            Ok(Ok(admitted)) => demoted_rows.push(admitted),
            Ok(Err(_refused)) => {
                let height = *height;
                return Err(halt_writer(store, |batch| batch.refuse_demotion(height)));
            }
            Err(fault) => return Err(snapshot_fault(store, *height, fault)),
        }
    }

    // The closure: pops and SI-5, the demoted rows, promotion, removes.
    let outcome: Result<SwitchDone, Stop> = store.write(|batch| {
        batch.pop_many(depth)?;
        for admitted in demoted_rows {
            // A recorded block can already sit in the alt table (a replay
            // `Apply` connects without consulting it); the row written now
            // is the tier's verdict over the recorded block, so it replaces
            // the older one.
            if batch.has_alt_block(&admitted.hash())? {
                batch.remove_alt_block(&admitted.hash())?;
            }
            batch.insert_alt_block(admitted)?;
        }
        let view = batch.chain_view();
        let mut done = SwitchDone {
            demoted: demoted.clone(),
            demoted_kept: keep_demoted,
            ..SwitchDone::default()
        };
        for (index, (formed, entry)) in msg.promoted.into_iter().zip(&entries).enumerate() {
            let height = entry.block.height();
            let in_force = rules.in_force(height);
            match validate(formed, &view, &in_force, &trust) {
                Ok(Ok(valid)) => {
                    let hash = valid.block().hash();
                    done.exercised
                        .extend(valid.coverage().iter().map(CenRow::as_str));
                    batch.connect(valid, in_force)?;
                    done.promoted.push((height, hash));
                }
                Ok(Err(refused)) => {
                    return Err(Stop::Refused {
                        index,
                        at: height,
                        hash: entry.id,
                        refused,
                    })
                }
                Err(fault) => return Err(Stop::Fault(super::validate_fault(batch, height, fault))),
            }
        }
        for entry in &entries {
            batch.remove_alt_block(&entry.id)?;
        }
        done.returned = returned;
        Ok(done)
    });
    match outcome {
        Ok(done) => Ok(Switched::Done(done)),
        Err(Stop::Fault(fault)) => Err(fault),
        Err(Stop::BelowFloor { tip, floor }) => Ok(Switched::BelowFloor { tip, floor }),
        Err(Stop::Refused {
            index,
            at,
            hash,
            refused,
        }) => {
            // K5: the failing alt suffix leaves the store, in its own write
            // — the switch's transaction rolled back with everything in it.
            let removed: Vec<BlockHash> = entries[index..].iter().map(|e| e.id).collect();
            remove_alt_suffix(store, &removed)?;
            Ok(Switched::Refused {
                at,
                hash,
                refused,
                removed,
            })
        }
    }
}

/// The identity recorded at `height`, which the caller has bounded by the
/// tip; above it is a store that lost a row it just named.
fn recorded_hash(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<BlockHash, RunFault> {
    match snap.block_info(height)? {
        AtHeight::Recorded(info) => Ok(info.hash),
        AtHeight::AboveTip => unreachable!("the caller bounded the height by the tip"),
    }
}

/// The recorded cumulative difficulty at `height` (the incumbent's work).
fn recorded_work(
    snap: &ReadSnapshot<'_>,
    height: BlockHeight,
) -> Result<shekyl_difficulty::CumulativeDifficulty, RunFault> {
    match snap.block_info(height)? {
        AtHeight::Recorded(info) => Ok(info.cumulative_difficulty),
        AtHeight::AboveTip => unreachable!("the tip is recorded"),
    }
}

/// A fault the cheap tier raised over a snapshot view. A corrupt read halts
/// the writer through a batch that arms it, as `validate`'s does through
/// the connect batch; [`fault_reply`] maps the rest.
fn snapshot_fault(store: &ChainStore, height: BlockHeight, fault: Fault<StoreError>) -> RunFault {
    fault_reply(height, fault, |observed| {
        halt_writer(store, |batch| batch.refuse_corrupt(observed))
    })
}

/// Arm a halt and return it. `arm` notes the invariant on a batch whose
/// closure then fails, so `ChainStore::write` prefers that
/// `InvariantViolated` over the error the closure returned.
fn halt_writer(
    store: &ChainStore,
    arm: impl for<'id> FnOnce(&mut WriteBatch<'_, 'id>) -> StoreError,
) -> RunFault {
    let halted: Result<(), RunFault> = store.write(|batch| Err(RunFault::Store(arm(batch))));
    halted.expect_err("an armed invariant halts the writer")
}

/// The alt suffix a refusal names, removed in its own write after the
/// judging write aborted.
fn remove_alt_suffix(store: &ChainStore, ids: &[BlockHash]) -> Result<(), RunFault> {
    let cleared: Result<(), StoreError> = store.write(|batch| {
        for id in ids {
            batch.remove_alt_block(id)?;
        }
        Ok(())
    });
    cleared?;
    Ok(())
}

/// The seed claim for the block at `height` on `view`. The seed height is
/// at or below the block's parent, and this view reaches at least that
/// parent — an alt entry's stitched chain, or the recorded chain below a
/// demoted block.
fn claimed_seed(view: &AltView<'_>, height: BlockHeight) -> Result<BlockHash, RunFault> {
    let Some(at) = seed_height(height) else {
        return Ok(BlockHash::NULL);
    };
    match view.header_at(at)? {
        AtHeight::Recorded(record) => Ok(record.hash),
        AtHeight::AboveTip => unreachable!(
            "the seed height sits below the block, and this view reaches at least the block's parent"
        ),
    }
}

/// Replace the run's trust with a fixture table — test-only, so the fork
/// choice's checkpoint arm (CEN-K6/K7) can be reached on a regtest chain,
/// which no release anchors.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct AnchorForTests(pub Trust);

#[cfg(test)]
impl Message<AnchorForTests> for Connector {
    type Reply = ();

    async fn handle(&mut self, msg: AnchorForTests, _ctx: &mut Context<Self, Self::Reply>) {
        self.trust = msg.0;
    }
}

/// Every table of the store as stored bytes (`ReadSnapshot::table_rows`) —
/// a differential's read, not a consensus one.
#[derive(Clone, Copy, Debug)]
pub struct TableRows;

impl Message<TableRows> for Connector {
    type Reply = Result<BTreeMap<&'static str, RawRows>, RunFault>;

    async fn handle(&mut self, _: TableRows, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        Ok(self.writer.read()?.table_rows()?)
    }
}
