// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The scenario driver — a scripted chain over the production stack
//! (`CHAIN_RULES_SLICE_6.md` §5.3, RULED 2026-09-24).
//!
//! `mine(n)` builds each block the way a miner does: ask the connector
//! what the chain is ([`TemplateFacts`] — the tip, the root at the
//! connecting height, the parent's emission, the F20 window and the C2
//! median, all read on the view the validator will judge against and
//! through the validator's own definitions), price a coinbase with
//! `shekyl-block-template`, `form` it under a substrate, and `Apply` it.
//! The block that lands is one the validator admitted; everything the store
//! recorded is the verdict's; nothing here writes state a rule reads back.
//! That is what makes a chain built
//! here a **witness** rather than a fixture (`50-testing.mdc`): every rule
//! that has landed judged every block, and a rule that lands later judges
//! the same blocks again.
//!
//! # One event at a time — and what that does not cover
//!
//! Template generation is serial: a miner cannot build `h + 1` until `h`
//! is connected, because `h + 1`'s header carries the root *after* `h`
//! and its coinbase is priced at `h`'s record. The driver models that path
//! faithfully — template, form, connect, repeat — and so exercises
//! `form → validate → connect` and **deliberately not the sequencer's
//! lookahead**. Replay-with-a-trace (`pipeline::run` over a corpus) covers
//! that. Two instruments, two subjects: scenario coverage is not ingest
//! end-to-end coverage, and a test that wants the pipeline's concurrency
//! judged uses the replay.
//!
//! # What is real and what is placeholder
//!
//! Real: the template, the coinbase and its hybrid-KEM output, the
//! validator, the store, the burn fold. Under a [`ProductionSubstrate`]
//! the PoW is real RandomX at the fixed regtest difficulty; the default
//! [`Clocked`] over the harness longhash keeps the clock deterministic and
//! the hash free. Nothing is a placeholder any more: the curve-tree root
//! stopped being one with DRS-E3, the two medians with slice 7 commit 4,
//! and the frozen-segment count and the burn with slice 7 wave B — each
//! read through the validator's own definition on the view it judges
//! against, and the producer's ledger of what it priced (`Priced`, handed
//! to `connect` through `Composed`) went with the last of them.

use std::path::PathBuf;

use kameo::actor::ActorRef;
use shekyl_block_template::{
    build, EmissionOperands, MinerKeys, Template, TemplateContext, TemplateError,
};
use shekyl_chain_rules::{
    form, seed_height, Candidate, CenRow, FormAttempt, InvalidBlock, ReferenceClaims, RuleSet,
    StructurallyValid, Substrate, Target,
};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::ChainStore;
use shekyl_economics::EconomicParams;
use shekyl_harness_wallet::MinerWallet;
use shekyl_types::archival::BondRecord;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, PCanonicalId, SettlementEpoch,
    Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::Transaction;
use zeroize::Zeroizing;

use crate::connector::{
    AltBlocksHeld, Apply, BondRecordOf, BudgetAccruingOf, ChainFacts, Connector, ConnectorArgs,
    Digest, HashAt, HeaderAt, OfferAlt, Offered, PlannedBlock, RefusePromotion, Reorganize, Rewind,
    Rewound, RootAt, RunFault, SwitchPlan, Switched, TableRows, TemplateFacts,
};
use crate::schedule::ChainRules;
use crate::target::TargetLedger;
use crate::test_support::{cleanup, open_store, open_store_under, tmp};

#[path = "scenario_types.rs"]
mod types;

pub use types::{
    Clocked, FreeHash, Mined, NextBlock, ReorgTiming, StepOutcome, Unconnected, CLOCK_START,
};

/// One block `form` refused while a switch was forming, in the
/// demoted-then-promoted order the plan named.
struct FormRefusal {
    /// Its place in that order. Below the demoted length, the block is one
    /// this node connected; at or above it, the block is a promotion.
    index: usize,
    /// The block's identity.
    hash: BlockHash,
    /// The verdict.
    refused: InvalidBlock,
}

/// The connector actor's task handle.
type ConnectorTask = tokio::task::JoinHandle<
    Result<(Connector, kameo::error::ActorStopReason), kameo::error::PanicError>,
>;

/// Spawn a connector whose task the caller keeps.
fn spawn_connector(args: ConnectorArgs) -> (ActorRef<Connector>, ConnectorTask) {
    let prepared = kameo::actor::PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
    let actor = prepared.actor_ref().clone();
    let task = prepared.spawn(args);
    (actor, task)
}

/// The driver. Owns the connector (and through it the store) and the
/// clock; every block it mines pays the harness miner.
pub struct Scenario<P> {
    path: PathBuf,
    connector: ActorRef<Connector>,
    /// The connector's task, joined on [`close`](Self::close) and
    /// [`reopen`](Self::reopen) so the store it owns is dropped before the
    /// file is touched (`test_support::JoinedConnector`'s reason).
    task: Option<ConnectorTask>,
    /// How this driver's store is opened, again on [`reopen`](Self::reopen).
    opener: Box<dyn Fn(&std::path::Path) -> ChainStore + Send + Sync>,
    substrate: Clocked<P>,
    /// The harness miner (`shekyl-harness-wallet`): the one wallet the
    /// rules fixture, the store's tests and this driver all pay, so a
    /// spend the spender builds over any of their chains is of an output
    /// the same secrets recover.
    wallet: &'static MinerWallet,
    /// The template's view of the miner, built once from the wallet's
    /// public half.
    miner: MinerKeys,
    params: EconomicParams,
    rules: ChainRules,
    next_tx_secret: u64,
    /// The headers the next target claim reads, extended as each block
    /// connects — the pipeline's ledger, filled the same way (`target`).
    targets: TargetLedger,
}

/// The rules every scenario runs under: regtest at fixed difficulty one,
/// so a nonce of zero satisfies any longhash — real or free — and the
/// subject stays the chain, not the search.
pub const RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: Some(std::num::NonZeroU128::MIN),
    schedule: shekyl_chain_rules::FakechainSchedule::PRODUCTION,
};

impl Scenario<FreeHash> {
    /// A scenario over the free longhash, at a fresh store named `name`.
    pub fn open(name: &str) -> Self {
        Self::open_with(name, FreeHash)
    }
}

impl<P: Substrate + Send + Sync + 'static> Scenario<P>
where
    P::Fault: std::fmt::Debug,
{
    /// A scenario over `pow`'s longhash, at a fresh store named `name`.
    pub fn open_with(name: &str, pow: P) -> Self {
        Self::open_under_with(name, pow, RULES, open_store)
    }

    /// A scenario under `rules` rather than [`RULES`] — a levered regtest
    /// schedule, with the store opened under that schedule's pair the way
    /// the daemon opens it (`test_support::open_store_under`, `ARW-15`).
    /// The callers are the chains that need a slash deadline inside what a
    /// test can mine: slice 8's reinstate measurement
    /// (`archival_slash_tests`, the open interval only a slash writes).
    pub fn open_under(name: &str, pow: P, rules: ChainRules) -> Self {
        Self::open_under_with(name, pow, rules, move |path| {
            open_store_under(
                path,
                &rules.in_force(BlockHeight::from_raw(0)),
                ApplyPolicy::Full,
            )
        })
    }

    fn open_under_with(
        name: &str,
        pow: P,
        rules: ChainRules,
        store: impl Fn(&std::path::Path) -> ChainStore + Send + Sync + 'static,
    ) -> Self {
        let path = tmp(name);
        let (connector, task) = spawn_connector(ConnectorArgs {
            store: store(&path),
            rules,
        });
        Self {
            path,
            connector,
            task: Some(task),
            opener: Box::new(store),
            substrate: Clocked::new(pow),
            wallet: MinerWallet::harness(),
            miner: {
                let recipient = MinerWallet::harness().recipient();
                MinerKeys {
                    spend_public: recipient.spend_public,
                    x25519_pk: recipient.x25519_pk,
                    ml_kem_ek: recipient.ml_kem_ek.clone(),
                }
            },
            params: EconomicParams::default(),
            rules,
            next_tx_secret: 1,
            targets: TargetLedger::new(),
        }
    }

    /// The connector, for a test that wants to ask it something directly.
    pub const fn connector(&self) -> &ActorRef<Connector> {
        &self.connector
    }

    /// The miner every block of this scenario pays, secrets included.
    pub const fn wallet(&self) -> &'static MinerWallet {
        self.wallet
    }

    /// What the chain is now, as the producer reads it.
    pub async fn facts(&self) -> Result<ChainFacts, RunFault> {
        self.connector
            .ask(TemplateFacts)
            .await
            .map_err(handler_error)
    }

    /// Mine `n` empty blocks; every one must land.
    pub async fn mine(&mut self, n: u64) -> Vec<Mined> {
        let mut mined = Vec::with_capacity(usize::try_from(n).expect("fits"));
        for _ in 0..n {
            mined.push(
                self.mine_listing(Vec::new())
                    .await
                    .unwrap_or_else(|outcome| panic!("an empty block always lands: {outcome}")),
            );
        }
        mined
    }

    /// Build the next block listing `listed`, form it, and apply it.
    /// A refusal is returned, not panicked: some scenarios ask for one.
    pub async fn mine_listing(&mut self, listed: Vec<Transaction>) -> Result<Mined, StepOutcome> {
        let next = self.next_template(listed).await?;
        self.connect_template(next).await
    }

    /// The next block's template listing `listed`, with the seed and the
    /// target the producer claims for it — what a miner is handed. Its
    /// nonce is the template's; [`connect_template`](Self::connect_template)
    /// connects whatever block the caller puts back in it.
    pub async fn next_template(
        &mut self,
        listed: Vec<Transaction>,
    ) -> Result<NextBlock, StepOutcome> {
        let facts = self.facts().await.map_err(StepOutcome::Connector)?;
        let now = self.substrate.tick();
        let template = self
            .template(&facts, now, &listed)
            .map_err(StepOutcome::Template)?;
        let height = facts.connecting;
        let (seed, target) = self.claimed_seed_and_target(height).await?;
        Ok(NextBlock {
            height,
            template,
            seed,
            target,
        })
    }

    /// Form `next`'s block and apply it: the connector's own door, the way
    /// [`mine_listing`](Self::mine_listing) applies what it built.
    pub async fn connect_template(&mut self, next: NextBlock) -> Result<Mined, StepOutcome> {
        let NextBlock {
            height,
            template,
            seed,
            target,
        } = next;
        // Nothing the producer priced is handed to `connect`: the reward it
        // priced is judged by F14b/F18, the burn by F17, and both are
        // recorded from the verdict (the ledger that carried the burn left
        // with wave B).
        let rule_set = self.rules.in_force(height);
        let candidate = Candidate::new(template.block.clone(), template.transactions.clone());
        // The third claim, off the same ledger (its window covers CEN-I11's).
        let references = match ReferenceClaims::from_headers(&self.targets, height, &candidate) {
            Ok(references) => references,
            Err(never) => match never {},
        };
        let formed = form(
            candidate,
            &rule_set,
            &self.substrate,
            seed,
            target,
            &references,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault");
        let formed = formed.map_err(StepOutcome::Refused)?;

        let applied = self
            .connector
            .ask(Apply(vec![(height, Ok(formed))]))
            .await
            .map_err(handler_error)
            .map_err(StepOutcome::Connector)?;
        if let Some((_, refused)) = applied.refused {
            return Err(StepOutcome::Refused(refused));
        }
        // Connected: its header joins the window the next claim reads. A
        // refused block never does, so a test that mines again after a
        // refusal claims against the chain, not the refused block.
        self.targets
            .extend(height, &template.block, target)
            .unwrap_or_else(|corrupt| panic!("the scenario's chain is consistent: {corrupt}"));
        self.targets.forget_below_window_of(height);
        let (_, hash) = applied.connected[0];
        let judged_by = CenRow::ALL
            .iter()
            .copied()
            .filter(|row| applied.exercised.contains(row.as_str()))
            .collect();
        let (_, emission) = applied.emission[0];
        let (_, weights) = applied.weights[0];
        let (_, archival) = applied
            .archival
            .into_iter()
            .next()
            .expect("one connected block carries one archival delta");
        Ok(Mined {
            height,
            hash,
            template,
            judged_by,
            emission,
            weights,
            archival,
            seed,
            target,
        })
    }

    /// Advance the driver's clock by one block interval without mining, so
    /// two drivers that mined the same prefix build different blocks from
    /// here on — how a test makes a second branch.
    pub fn idle(&self) {
        self.substrate.tick();
    }

    /// How many alternative blocks the store holds (`AltBlocksHeld`, AL6).
    pub async fn alt_blocks_held(&self) -> Result<u64, RunFault> {
        self.connector
            .ask(AltBlocksHeld)
            .await
            .map_err(handler_error)
    }

    /// The logical-state digest of the store (`Digest`).
    pub async fn digest(&self) -> Result<crate::trace::Digest, RunFault> {
        self.connector.ask(Digest).await.map_err(handler_error)
    }

    /// Offer `mined` — a block another driver mined on another branch — as
    /// an alternative arrival: formed here under this driver's substrate
    /// with the seed and target its producer claimed, then [`OfferAlt`].
    /// No reference claims: the cheap tier judges headers (CEN-K4), and
    /// the proofs are verified at promotion, where the plan carries the
    /// claims ([`SwitchPlan::references_for`]).
    pub async fn offer(&self, mined: &Mined) -> Result<Offered, RunFault> {
        let formed = form(
            mined.candidate(),
            &self.rules.in_force(mined.height),
            &self.substrate,
            mined.seed,
            mined.target,
            &ReferenceClaims::EMPTY,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault")
        .expect("a block another driver connected forms");
        self.connector
            .ask(OfferAlt(formed))
            .await
            .map_err(handler_error)
    }

    /// Build the next block on `facts` without connecting it.
    ///
    /// Formed under [`ReferenceClaims::EMPTY`]: signatures and the
    /// range-proof batch run, the membership proofs do not. The header
    /// joins this driver's target ledger, so the next claim reads a block
    /// the store has never held. Nothing is applied, and the ledger is not
    /// trimmed — the header is not in the store, and a later connected
    /// claim is what bounds the window.
    #[cfg(test)]
    pub async fn assemble_unconnected(
        &mut self,
        facts: &ChainFacts,
        listed: &[Transaction],
    ) -> Result<Unconnected, StepOutcome> {
        let now = self.substrate.tick();
        let height = facts.connecting;
        let (seed, target) = self.claimed_seed_and_target(height).await?;
        let template = self
            .template(facts, now, listed)
            .map_err(StepOutcome::Template)?;
        let candidate = Candidate::new(template.block.clone(), template.transactions.clone());
        let formed = form(
            candidate.clone(),
            &self.rules.in_force(height),
            &self.substrate,
            seed,
            target,
            &ReferenceClaims::EMPTY,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault")
        .map_err(StepOutcome::Refused)?;
        self.targets
            .extend(height, &template.block, target)
            .unwrap_or_else(|corrupt| panic!("the scenario's chain is consistent: {corrupt}"));
        Ok(Unconnected {
            height,
            hash: formed.hash(),
            candidate,
            seed,
            target,
        })
    }

    /// Offer `block` the way [`Self::offer`] offers a connected one: formed
    /// again here under empty reference claims, then [`OfferAlt`].
    #[cfg(test)]
    pub async fn offer_unconnected(&self, block: &Unconnected) -> Result<Offered, RunFault> {
        let formed = form(
            block.candidate.clone(),
            &self.rules.in_force(block.height),
            &self.substrate,
            block.seed,
            block.target,
            &ReferenceClaims::EMPTY,
            FormAttempt::FIRST,
        )
        .expect("the driver's substrate does not fault")
        .expect("a block assembled under empty claims forms");
        self.connector
            .ask(OfferAlt(formed))
            .await
            .map_err(handler_error)
    }

    /// Carry out `plan` (DRS-E5 §2.3 step 1, then [`Reorganize`]): form the
    /// demoted blocks unless the verdict is the checkpoint's, and the alt
    /// entries from their rows' blocks, witnesses and listed bodies (the
    /// store's, AL8). A promoted block `form` refuses under the plan's claims is
    /// [`RefusePromotion`]: the failing suffix is removed and nothing is
    /// popped. A demoted block this node connected forms without claims; a
    /// refusal there is an invariant, not a verdict. After
    /// [`Switched::Done`], the header ledger drops every height above the
    /// fork, so the next claim reloads the chain this switch connected.
    pub async fn reorganize(&mut self, plan: &SwitchPlan) -> Result<Switched, RunFault> {
        self.reorganize_timed(plan)
            .await
            .map(|(switched, _)| switched)
    }

    /// [`Self::reorganize`], reporting how long the forming (step 1, the
    /// RandomX) and the [`Reorganize`] message (the judging, the closure)
    /// each took — the switch PR's cap-depth measurement. A switch that
    /// lands drops the losing branch from the header ledger
    /// ([`Self::reorganize`]).
    pub async fn reorganize_timed(
        &mut self,
        plan: &SwitchPlan,
    ) -> Result<(Switched, ReorgTiming), RunFault> {
        let started = std::time::Instant::now();
        // Demoted blocks carry no reference claims: the cheap tier never
        // compares one (it judges headers), so a claim would buy no
        // verdict and cost N blocks' proofs verified again — proofs the
        // chain verified when it connected them. Promoted blocks claim off
        // the plan's header chain (`SwitchPlan::references_for`).
        let mut work: Vec<(Candidate, PlannedBlock, ReferenceClaims)> = Vec::new();
        if plan.verdict != shekyl_difficulty::ForkChoiceVerdict::ForcedSwitch {
            work.extend(
                plan.demoted
                    .iter()
                    .map(|d| (d.candidate.clone(), d.at.clone(), ReferenceClaims::EMPTY)),
            );
        }
        let demoted_len = work.len();
        work.extend(plan.promoted.iter().map(|p| {
            let candidate = Candidate::new(p.block.clone(), p.transactions.clone())
                .with_attestation_witness(p.witness.clone());
            let references = plan.references_for(&p.at, &candidate);
            (candidate, p.at.clone(), references)
        }));
        let mut formed_all = match self.form_parallel(work) {
            Ok(formed) => formed,
            Err(refusal) => {
                let formed = started.elapsed();
                if refusal.index < demoted_len {
                    let (hash, refused) = (refusal.hash, refusal.refused);
                    panic!(
                        "a demoted block this node connected forms without reference claims: {refused} ({hash:?})"
                    );
                }
                let started = std::time::Instant::now();
                let switched = self
                    .connector
                    .ask(RefusePromotion {
                        tip: plan.tip,
                        alt_tip: plan.alt_tip,
                        hash: refusal.hash,
                        refused: refusal.refused,
                    })
                    .await
                    .map_err(handler_error)?;
                return Ok((
                    switched,
                    ReorgTiming {
                        form: formed,
                        switch: started.elapsed(),
                    },
                ));
            }
        };
        let promoted = formed_all.split_off(demoted_len);
        let demoted = formed_all;
        let formed = started.elapsed();
        let started = std::time::Instant::now();
        let switched = self
            .connector
            .ask(Reorganize {
                tip: plan.tip,
                alt_tip: plan.alt_tip,
                demoted,
                promoted,
            })
            .await
            .map_err(handler_error)?;
        if let Switched::Done(_) = &switched {
            // The ledger still holds the losing branch above the fork. A
            // later claim reloads only the heights it lacks, so those
            // headers have to leave before the next block is priced against
            // this chain. The seed is read from the store at each mine;
            // there is no seed ledger to drop. A refusal, the cap, or the
            // floor leaves the chain where it was, and the ledger with it.
            self.targets.rewind_to(plan.root.height);
        }
        Ok((
            switched,
            ReorgTiming {
                form: formed,
                switch: started.elapsed(),
            },
        ))
    }

    /// `form` every `(candidate, plan)` pair, in order, across the cores
    /// this host offers — step 1 of the switch, which production runs on
    /// its RandomX workers off the actor (`DRS_E5_POOL_ALT_PRUNE.md` §2.3).
    ///
    /// Through [`Recalled`](crate::substrate::Recalled): every block a plan
    /// names was hashed when this node first judged it, and the plan
    /// carries that record, so a switch calls RandomX only where a seed
    /// claim differs from the recorded one (ruling 3, 2026-10-15). The
    /// first refusal, in plan order, is the result; every thread is joined.
    fn form_parallel(
        &self,
        work: Vec<(Candidate, PlannedBlock, ReferenceClaims)>,
    ) -> Result<Vec<StructurallyValid>, FormRefusal> {
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let chunk = work.len().div_ceil(threads).max(1);
        let recalled = crate::substrate::Recalled::new(
            &self.substrate,
            work.iter()
                .map(|(_, at, _)| (at.hash, at.recorded.seed(), at.recorded.pow())),
        );
        let substrate = &recalled;
        let rules = self.rules;
        let mut chunks = Vec::new();
        let mut rest = work;
        let mut start = 0;
        while !rest.is_empty() {
            let n = chunk.min(rest.len());
            let tail = rest.split_off(n);
            chunks.push((start, rest));
            start += n;
            rest = tail;
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunks
                .into_iter()
                .map(|(start, chunk)| {
                    scope.spawn(move || {
                        let mut formed = Vec::with_capacity(chunk.len());
                        for (local, (candidate, at, references)) in chunk.into_iter().enumerate() {
                            let hash = at.hash;
                            match form(
                                candidate,
                                &rules.in_force(at.height),
                                substrate,
                                at.seed,
                                at.target,
                                &references,
                                FormAttempt::FIRST,
                            ) {
                                Ok(Ok(valid)) => formed.push(valid),
                                Ok(Err(refused)) => {
                                    return Err(FormRefusal {
                                        index: start + local,
                                        hash,
                                        refused,
                                    });
                                }
                                Err(fault) => {
                                    panic!("the driver's substrate does not fault: {fault:?}")
                                }
                            }
                        }
                        Ok(formed)
                    })
                })
                .collect();
            let mut formed = Vec::new();
            let mut refusal: Option<FormRefusal> = None;
            for handle in handles {
                match handle.join().expect("a forming thread") {
                    Ok(blocks) => {
                        if refusal.is_none() {
                            formed.extend(blocks);
                        }
                    }
                    Err(found) => {
                        refusal = Some(match refusal {
                            Some(kept) if kept.index <= found.index => kept,
                            _ => found,
                        });
                    }
                }
            }
            match refusal {
                Some(refusal) => Err(refusal),
                None => Ok(formed),
            }
        })
    }

    /// Pop the chain back to `to`.
    pub async fn rewind_to(&mut self, to: BlockHeight) -> Result<Rewound, RunFault> {
        self.targets.rewind_to(to);
        self.connector
            .ask(Rewind { to })
            .await
            .map_err(handler_error)
    }

    /// The block's identity at `height`, if recorded.
    pub async fn hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, RunFault> {
        self.connector
            .ask(HashAt { height })
            .await
            .map_err(handler_error)
    }

    /// The store's curve-tree root going into `height` (`RootAt`).
    pub async fn root_at(&self, height: BlockHeight) -> Result<Option<CurveTreeRoot>, RunFault> {
        self.connector
            .ask(RootAt { height })
            .await
            .map_err(handler_error)
    }

    /// `persona`'s bond record as the store holds it (`BondRecordOf`).
    pub async fn bond_record(&self, persona: PCanonicalId) -> Result<Option<BondRecord>, RunFault> {
        self.connector
            .ask(BondRecordOf { persona })
            .await
            .map_err(handler_error)
    }

    /// `epoch`'s accruing budget as the store holds it (`BudgetAccruingOf`).
    pub async fn budget_accruing(
        &self,
        epoch: SettlementEpoch,
    ) -> Result<Option<AtomicUnits>, RunFault> {
        self.connector
            .ask(BudgetAccruingOf { epoch })
            .await
            .map_err(handler_error)
    }

    /// Stop the connector and join its task, so the store it owns is dropped
    /// before the file is opened again ([`Self::reopen`], [`Self::with_store`]).
    async fn stop_connector(&mut self) {
        let _already_stopped = self.connector.stop_gracefully().await.is_err();
        if let Some(task) = self.task.take() {
            drop(task.await.expect("the connector task joins"));
        }
    }

    /// A fresh connector over the store at [`Self`]'s path, under the same rules.
    fn start_connector(&mut self) {
        let (connector, task) = spawn_connector(ConnectorArgs {
            store: (self.opener)(&self.path),
            rules: self.rules,
        });
        self.task = Some(task);
        self.connector = connector;
    }

    /// Stop the connector, release the store, remove the file.
    pub async fn close(mut self) {
        self.stop_connector().await;
        cleanup(&self.path);
    }

    /// Stop the connector and release the store, run `edit` on the file —
    /// a test's out-of-band change, made where no writer is live — and
    /// start a fresh connector over the reopened store. The clock, the
    /// wallet and the template counter carry over.
    pub async fn reopen(&mut self, edit: impl FnOnce(&std::path::Path)) {
        self.stop_connector().await;
        edit(&self.path);
        self.start_connector();
    }

    /// Every table of the store as stored bytes (`TableRows`), for a
    /// differential against another driver's store.
    pub async fn table_rows(
        &self,
    ) -> Result<
        std::collections::BTreeMap<&'static str, shekyl_chain_store::store::RawRows>,
        RunFault,
    > {
        self.connector.ask(TableRows).await.map_err(handler_error)
    }

    /// The seed and target an honest producer claims for `height`.
    ///
    /// The seed is the identity at the seed height, or the null hash below
    /// the first epoch (CEN-D3). The target is the validator's derivation
    /// over the headers below `height`, the store answering what the ledger
    /// lacks (`target` module docs).
    async fn claimed_seed_and_target(
        &mut self,
        height: BlockHeight,
    ) -> Result<(BlockHash, Target), StepOutcome> {
        let seed = match seed_height(height) {
            None => BlockHash::NULL,
            Some(at) => self
                .connector
                .ask(HashAt { height: at })
                .await
                .map_err(handler_error)
                .map_err(StepOutcome::Connector)?
                .expect("the seed height is below the tip"),
        };
        let rule_set = self.rules.in_force(height);
        for at in self.targets.missing_for(height) {
            let record = self
                .connector
                .ask(HeaderAt { height: at })
                .await
                .map_err(handler_error)
                .map_err(StepOutcome::Connector)?
                .expect("the window is below the tip");
            self.targets.record(at, record);
        }
        let target = self
            .targets
            .claim(height, &rule_set)
            .unwrap_or_else(|corrupt| panic!("the scenario's chain is consistent: {corrupt}"))
            .map_err(StepOutcome::Refused)?;
        Ok((seed, target))
    }

    /// The template for `facts`, listing `listed`, at clock `now`.
    fn template(
        &mut self,
        facts: &ChainFacts,
        now: Timestamp,
        listed: &[Transaction],
    ) -> Result<Template, TemplateError> {
        // Written straight into the zeroizing cell: no bare copy of the
        // scalar's bytes exists on this stack after the context drops.
        let mut tx_key_secret = Zeroizing::new([0u8; 32]);
        tx_key_secret[..8].copy_from_slice(&self.next_tx_secret.to_le_bytes());
        // A commitment per template, from the same counter, so two
        // templates never share one. Nothing opens it: the driver holds no
        // witness key or seed yet, so its blocks issue no draw. The driver
        // that reveals a seed commits to one it can open (`SO-D12`
        // increment 3).
        let mut commitment = *shekyl_wire::tx_extra::CONFORMING_DRAW_COMMITMENT.as_bytes();
        commitment[..8].copy_from_slice(&self.next_tx_secret.to_le_bytes());
        self.next_tx_secret += 1;
        let rule_set: RuleSet = self.rules.in_force(facts.connecting);
        build(&TemplateContext {
            height: facts.connecting,
            previous: facts.previous,
            curve_tree_root: facts.curve_tree_root,
            // The driver mints no attestation records (CEN-I20 admits no
            // 0x0B field on the coinbase), so every template commits the
            // empty set's root — the arm CEN-B4 judges a witness-less block
            // against (slice 8 row 10).
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
            major_version: rule_set.header_major_version(),
            now,
            median_timestamp: facts.median_timestamp,
            unlock_window: rule_set.mined_money_unlock_window(),
            emission: EmissionOperands {
                already_generated_coins: facts.parent_coins_generated,
                total_burned: facts.total_burned,
                // CEN-G6b: the effective median the validator will judge
                // this block's weight against, read on the same view.
                median_weight: facts.medians.effective_median.to_raw(),
                tx_volume: facts.tx_volume,
                // CEN-F17's `n`, as the validator reads it: the shards the
                // parent chain has closed, read on the same view by the
                // validator's own definition. (Zero until a scenario chain
                // issues `T` ids; it was a literal zero until wave B.)
                closed_shards: facts.closed_shards,
            },
            params: &self.params,
            miner: &self.miner,
            tx_key_secret,
            extra_nonce: [0; shekyl_wire::tx_extra::COINBASE_NONCE_BYTES],
            draw_commitment: shekyl_wire::tx_extra::DrawCommitment::from_bytes(commitment),
            listed,
        })
    }
}

/// The reply error's handler arm, or a panic on a transport failure — the
/// actor is in-process and a dead mailbox is a test-harness defect.
fn handler_error<M>(e: kameo::error::SendError<M, RunFault>) -> RunFault {
    match e {
        kameo::error::SendError::HandlerError(fault) => fault,
        other => panic!("connector mailbox: {other}"),
    }
}

#[path = "scenario_pool.rs"]
mod pool;

#[cfg(test)]
#[path = "scenario_tests.rs"]
mod scenario_tests;
