// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue's admission, and the draws a mined block reads, on the
//! single writer (`SO-D12` increment 4c; `ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.5, §9.1).
//!
//! Both run here because both read `D`, and the drawable memo is this
//! actor's.
//!
//! - [`OfferBundle`] — the producer files a bundle. The queue's admission
//!   is the bundle rule run against the tip: `judge_bundles` over the
//!   store's bundle view at `h_incl = tip + 1`, in the same write that
//!   queues it. It is shaped like offering an alternative block: the
//!   offer is judged, and the verdict is the reply.
//! - [`LearnDraws`] — the producer mined `h` and asks for its draws, which
//!   the verifier's own selection derives (`draw_targets`) on this
//!   writer's view, with the endpoint each persona's bond record carries.
//! - **Upkeep**, after every write that moves the tip: an entry whose
//!   window closed leaves; an entry whose admitting tip is no longer on
//!   the chain is judged again by the same rule, and leaves if refused.
//!   An entry above the tip waits for its block to reconnect.
//! - **Reconcile**, at start: the store drops a body no entry names and an
//!   entry whose body is gone (SI-41), and this actor logs what went.
//!
//! The queue is not the connect path. No block carries a reference until
//! 4b, so nothing the queue admits is ever connected from it here.

use kameo::message::{Context, Message};
use shekyl_archival_retention::{bundle_root, BundleBody, BundleRef};
use shekyl_bundle_producer::{DrawTarget, Targets};
use shekyl_chain_rules::{
    draw_targets, judge_bundles, remember_window_epochs, AdmissionFault, BundleInvalid,
    BundleRefused, CenRow, ChainView, DrawableMemo, HeaderView, ViewRead,
};
use shekyl_chain_store::store::{
    QueueCannot, StoreBundleView, StoreCannot, StoreError, WriteBatch,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use zeroize::Zeroizing;

use super::{Connector, RunFault};
use crate::schedule::ChainRules;

/// File a bundle with the queue.
pub struct OfferBundle {
    /// The reference: what a block will carry when references travel.
    pub reference: BundleRef,
    /// The body it names.
    pub body: BundleBody,
}

/// What the queue did with an offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleOffered {
    /// Admitted against the tip at `tip_height`, and queued.
    Queued {
        /// The bundle's block.
        h: BlockHeight,
        /// The tip it was judged against.
        tip_height: BlockHeight,
    },
    /// A bundle for `h` is already admitted on this chain. Another bundle
    /// for `h` won; nothing is wrong with this one.
    AlreadyRevealed {
        /// The bundle's block.
        h: BlockHeight,
    },
    /// The queue already holds a bundle for `h`.
    AlreadyQueued {
        /// The bundle's block.
        h: BlockHeight,
    },
    /// The rule refused it. For this daemon's own bundle that is a
    /// producer defect: the producer logs it with the row and reports it.
    Refused {
        /// The bundle's block.
        h: BlockHeight,
        /// The census row the refusal is a verdict under, when it is one.
        row: Option<CenRow>,
        /// What refused it, for the log.
        why: String,
    },
}

/// Derive the draws of a block this daemon mined.
pub struct LearnDraws {
    /// The block.
    pub h: BlockHeight,
    /// Its hash when the producer claimed it.
    pub hash: BlockHash,
    /// The seed it drew. Wiped when this message drops.
    pub seed: Zeroizing<[u8; 32]>,
}

/// What [`LearnDraws`] found.
#[derive(Debug)]
pub enum Learned {
    /// The draws, with each persona's endpoint.
    Targets(Targets),
    /// The block at `h` is not the one claimed: it was popped, or replaced.
    NotOnChain,
    /// The view could not answer for a block it holds; the producer asks
    /// again on the next tip.
    Unanswered(String),
}

/// What the start's reconcile dropped (SI-41), for the log.
pub(crate) fn log_reconciled(report: &shekyl_chain_store::store::QueueReconciled) {
    if report.is_clean() {
        return;
    }
    for h in &report.entries_without_body {
        tracing::warn!(
            h = h.to_raw(),
            "bundle queue: dropped the entry for height {} at open; its body was not stored",
            h.to_raw()
        );
    }
    if !report.bodies_without_holder.is_empty() {
        tracing::warn!(
            count = report.bodies_without_holder.len(),
            "bundle queue: dropped {} stored bodies at open that no entry held",
            report.bodies_without_holder.len()
        );
    }
}

impl Message<OfferBundle> for Connector {
    type Reply = Result<BundleOffered, RunFault>;

    async fn handle(
        &mut self,
        msg: OfferBundle,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rules = self.rules;
        let memo = &mut self.memo;
        self.writer
            .write(|batch| offer(batch, rules, memo, &msg.reference, &msg.body))
    }
}

impl Message<LearnDraws> for Connector {
    type Reply = Result<Learned, RunFault>;

    async fn handle(
        &mut self,
        msg: LearnDraws,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let rules = self.rules;
        let memo = &mut self.memo;
        // A write that writes nothing: the store's bundle view is the
        // batch's, so the derivation reads through one. It commits empty.
        self.writer
            .write(|batch| learn(batch, rules, memo, msg.h, msg.hash, &msg.seed))
    }
}

impl Connector {
    /// The queue's upkeep after a write that moved the tip (module docs).
    /// An empty queue reads one snapshot and writes nothing.
    pub(crate) fn upkeep_queue(&mut self) -> Result<(), RunFault> {
        if self.writer.read()?.queued_bundles()?.is_empty() {
            return Ok(());
        }
        let rules = self.rules;
        let memo = &mut self.memo;
        self.writer.write(|batch| upkeep(batch, rules, memo))
    }

    /// The open's reconcile of the queue and the body store (SI-41).
    pub(crate) fn reconcile_queue(&mut self) -> Result<(), RunFault> {
        let report = self
            .writer
            .write(|batch| batch.reconcile_bundle_queue().map_err(RunFault::Store))?;
        log_reconciled(&report);
        Ok(())
    }
}

/// `h_incl`, the rule set in force there, and the tip it sits on.
fn including(
    batch: &WriteBatch<'_, '_>,
    rules: ChainRules,
) -> Result<
    Option<(
        BlockHeight,
        BlockHash,
        BlockHeight,
        shekyl_chain_rules::RuleSet,
    )>,
    RunFault,
> {
    let Some(tip) = batch.chain_view().tip()? else {
        return Ok(None);
    };
    let h_incl = tip
        .height
        .checked_add(BlockCount::ONE)
        .ok_or(RunFault::NoNextHeight { tip: tip.height })?;
    Ok(Some((tip.height, tip.hash, h_incl, rules.in_force(h_incl))))
}

/// A view read's fault, as the count raises it: a `Corrupt` halts the
/// writer, a store fault is the store's.
fn view_fault(batch: &WriteBatch<'_, '_>, fault: ViewRead<StoreError>) -> RunFault {
    match fault {
        ViewRead::View(error) => RunFault::Store(error),
        ViewRead::Corrupt(corrupt) => RunFault::Store(batch.refuse_corrupt(corrupt)),
    }
}

/// Why the rule refused a bundle, as the queue reports it.
enum Refusal {
    /// A bundle for `h` is already admitted on this chain.
    AlreadyRevealed,
    /// Any other refusal: its census row when it is a verdict, and what it
    /// says.
    Rule { row: Option<CenRow>, why: String },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyRevealed => f.write_str("a bundle for this block is already admitted"),
            Self::Rule { why, .. } => f.write_str(why),
        }
    }
}

/// Judge one bundle against the tip, on this batch: `None` admitted, or
/// the refusal. A view fault is the writer's.
fn judge(
    batch: &WriteBatch<'_, '_>,
    memo: &mut DrawableMemo,
    h_incl: BlockHeight,
    rule_set: &shekyl_chain_rules::RuleSet,
    reference: &BundleRef,
    body: &BundleBody,
) -> Result<Option<Refusal>, RunFault> {
    let view = batch.chain_view();
    remember_window_epochs(&view, h_incl, rule_set, memo).map_err(|f| view_fault(batch, f))?;
    let bundle_view = StoreBundleView::new(&view, memo, h_incl, rule_set.settlement_schedule());
    let refs = std::slice::from_ref(reference);
    let Ok(root) = bundle_root(refs) else {
        unreachable!("one reference is a section count that fits");
    };
    let Err(fault) = judge_bundles(
        refs,
        std::slice::from_ref(body),
        &root,
        h_incl,
        &bundle_view,
        rule_set,
    ) else {
        return Ok(None);
    };
    let row = fault.row();
    Ok(Some(match fault {
        AdmissionFault::View(error)
        | AdmissionFault::Bundle {
            refused: BundleRefused::View(error),
            ..
        } => return Err(RunFault::Store(error)),
        AdmissionFault::Bundle {
            refused: BundleRefused::Invalid(BundleInvalid::AlreadyRevealed),
            ..
        } => Refusal::AlreadyRevealed,
        AdmissionFault::Bundle { refused, .. } => Refusal::Rule {
            row,
            why: refused.to_string(),
        },
        AdmissionFault::Section(refused) => Refusal::Rule {
            row,
            why: refused.to_string(),
        },
        AdmissionFault::Awaiting => Refusal::Rule {
            row,
            why: "a drawable epoch the section names is not on this chain".into(),
        },
    }))
}

fn offer(
    batch: &WriteBatch<'_, '_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
    reference: &BundleRef,
    body: &BundleBody,
) -> Result<BundleOffered, RunFault> {
    let h = reference.h();
    let Some((tip_height, tip_hash, h_incl, rule_set)) = including(batch, rules)? else {
        return Ok(BundleOffered::Refused {
            h,
            row: None,
            why: "the chain is empty".into(),
        });
    };
    match judge(batch, memo, h_incl, &rule_set, reference, body)? {
        None => {}
        Some(Refusal::AlreadyRevealed) => return Ok(BundleOffered::AlreadyRevealed { h }),
        Some(Refusal::Rule { row, why }) => return Ok(BundleOffered::Refused { h, row, why }),
    }
    let capacity = rule_set
        .settlement_schedule()
        .challenge_response_blocks()
        .map_or(0, core::num::NonZeroU64::get);
    match batch.queue_bundle(reference, body, tip_height, tip_hash, capacity) {
        Ok(()) => Ok(BundleOffered::Queued { h, tip_height }),
        Err(StoreError::Cannot(StoreCannot::Queue(QueueCannot::Held { h }))) => {
            Ok(BundleOffered::AlreadyQueued { h })
        }
        Err(StoreError::Cannot(StoreCannot::Queue(cannot))) => Ok(BundleOffered::Refused {
            h,
            row: None,
            why: cannot.to_string(),
        }),
        Err(error) => Err(RunFault::Store(error)),
    }
}

fn learn(
    batch: &WriteBatch<'_, '_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
    h: BlockHeight,
    hash: BlockHash,
    seed: &[u8; 32],
) -> Result<Learned, RunFault> {
    let Some((_, _, h_incl, rule_set)) = including(batch, rules)? else {
        return Ok(Learned::NotOnChain);
    };
    let view = batch.chain_view();
    match view.header_at(h)? {
        shekyl_chain_rules::AtHeight::Recorded(header) if header.hash == hash => {}
        _ => return Ok(Learned::NotOnChain),
    }
    remember_window_epochs(&view, h_incl, &rule_set, memo).map_err(|f| view_fault(batch, f))?;
    let bundle_view = StoreBundleView::new(&view, memo, h_incl, rule_set.settlement_schedule());
    let derived = match draw_targets(&bundle_view, h, seed, &rule_set) {
        Ok(derived) => derived,
        Err(BundleRefused::View(error)) => return Err(RunFault::Store(error)),
        Err(other) => return Ok(Learned::Unanswered(other.to_string())),
    };
    let mut targets = Targets::default();
    for target in derived.economy {
        let Some(record) = view.bond_record(&target.pair.persona)? else {
            return Ok(Learned::Unanswered(format!(
                "economy draw {} names a persona with no bond record",
                target.draw
            )));
        };
        targets.economy.push(DrawTarget {
            draw: target.draw,
            persona: target.pair.persona,
            shard: target.pair.shard,
            receipt_key: target.receipt_key,
            endpoint: record.endpoint,
        });
    }
    for target in derived.support {
        let Some(record) = view.bond_record(&target.persona)? else {
            return Ok(Learned::Unanswered(format!(
                "support draw {} names a persona with no bond record",
                target.draw
            )));
        };
        targets.support.push(DrawTarget {
            draw: target.draw,
            persona: target.persona,
            shard: target.shard,
            receipt_key: target.receipt_key,
            endpoint: record.endpoint,
        });
    }
    Ok(Learned::Targets(targets))
}

fn upkeep(
    batch: &WriteBatch<'_, '_>,
    rules: ChainRules,
    memo: &mut DrawableMemo,
) -> Result<(), RunFault> {
    let Some((tip_height, tip_hash, h_incl, rule_set)) = including(batch, rules)? else {
        return Ok(());
    };
    let window = rule_set
        .settlement_schedule()
        .challenge_response_blocks()
        .map_or(BlockCount::ZERO, |w| BlockCount::from_raw(w.get()));
    let capacity = window.to_raw();
    for entry in batch.queued_bundles()? {
        let h = entry.h;
        if h >= h_incl {
            // Popped and not reconnected: the window cannot have closed,
            // and there is nothing to judge until the block is back.
            continue;
        }
        if h_incl > h.saturating_add(window) {
            batch.unqueue_bundle(h)?;
            tracing::info!(
                h = h.to_raw(),
                "bundle queue: the window for height {} closed",
                h.to_raw()
            );
            continue;
        }
        let admitted_on_chain = match batch.chain_view().header_at(entry.queued.tip_height)? {
            shekyl_chain_rules::AtHeight::Recorded(header) => header.hash == entry.queued.tip_hash,
            shekyl_chain_rules::AtHeight::AboveTip => false,
        };
        if admitted_on_chain {
            continue;
        }
        let refused = judge(
            batch,
            memo,
            h_incl,
            &rule_set,
            &entry.queued.reference,
            &entry.body,
        )?;
        batch.unqueue_bundle(h)?;
        match refused {
            None => {
                batch
                    .queue_bundle(
                        &entry.queued.reference,
                        &entry.body,
                        tip_height,
                        tip_hash,
                        capacity,
                    )
                    .map_err(RunFault::Store)?;
            }
            Some(refused) => {
                tracing::info!(
                    h = h.to_raw(),
                    "bundle queue: the entry for height {} left after a reorg: {refused}",
                    h.to_raw()
                );
            }
        }
    }
    Ok(())
}

/// Test only: apply one block, admitting every queued bundle inside its
/// window through the store's staged door (increment 4a's
/// `connect_admitting`), and take those entries out of the queue. This is
/// what 4b's connect does with the references a block carries, played by
/// the queue's own entries so the gate test can show a produced bundle
/// connect before references travel.
#[cfg(test)]
pub(crate) struct ApplyAdmitting {
    /// The height the source claims for the block.
    pub(crate) height: BlockHeight,
    /// The formed block.
    pub(crate) formed: shekyl_chain_rules::Verdict<shekyl_chain_rules::StructurallyValid>,
}

/// What [`ApplyAdmitting`] did: the block, and the verifier's verdicts on
/// the bundles it admitted, or why the section was refused.
#[cfg(test)]
pub(crate) struct AppliedAdmitting {
    pub(crate) applied: super::Applied,
    pub(crate) admitted: Result<Vec<shekyl_chain_rules::Admitted>, String>,
}

#[cfg(test)]
impl Message<ApplyAdmitting> for Connector {
    type Reply = Result<AppliedAdmitting, RunFault>;

    async fn handle(
        &mut self,
        msg: ApplyAdmitting,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        use shekyl_chain_rules::validate_with_memo;
        let rules = self.rules;
        let trust = self.trust;
        let memo = &mut self.memo;
        let out = self.writer.write(|batch| {
            let view = batch.chain_view();
            let (height, _) = super::connecting(view.tip()?)?;
            if height != msg.height {
                return Err(RunFault::HeightClaim {
                    claimed: msg.height,
                    connecting: height,
                });
            }
            let mut applied = super::Applied::default();
            let formed = match msg.formed {
                Ok(formed) => formed,
                Err(refused) => {
                    applied.refused = Some((height, refused));
                    return Ok(AppliedAdmitting {
                        applied,
                        admitted: Ok(Vec::new()),
                    });
                }
            };
            let in_force = rules.in_force(height);
            let valid = match validate_with_memo(formed, &view, &in_force, &trust, Some(&mut *memo))
            {
                Ok(Ok(valid)) => valid,
                Ok(Err(refused)) => {
                    applied.refused = Some((height, refused));
                    return Ok(AppliedAdmitting {
                        applied,
                        admitted: Ok(Vec::new()),
                    });
                }
                Err(fault) => return Err(super::validate_fault(batch, height, fault)),
            };
            let window = in_force
                .settlement_schedule()
                .challenge_response_blocks()
                .map_or(BlockCount::ZERO, |w| BlockCount::from_raw(w.get()));
            let entries: Vec<_> = batch
                .queued_bundles()?
                .into_iter()
                .filter(|entry| entry.h < height && height <= entry.h.saturating_add(window))
                .collect();
            remember_window_epochs(&view, height, &in_force, &mut *memo)
                .map_err(|f| view_fault(batch, f))?;
            let refs: Vec<BundleRef> = entries.iter().map(|e| e.queued.reference.clone()).collect();
            let bodies: Vec<BundleBody> = entries.iter().map(|e| e.body.clone()).collect();
            let Ok(root) = bundle_root(&refs) else {
                unreachable!("a test section's count fits");
            };
            let judged = {
                let bundle_view =
                    StoreBundleView::new(&view, &*memo, height, in_force.settlement_schedule());
                judge_bundles(&refs, &bodies, &root, height, &bundle_view, &in_force)
            };
            let admitted = match judged {
                Ok(admitted) => admitted,
                Err(fault) => {
                    return Ok(AppliedAdmitting {
                        applied,
                        admitted: Err(format!("{fault:?}")),
                    })
                }
            };
            let hash = valid.block().hash();
            applied.roots.push((height, valid.block().root_after()));
            applied.weights.push((height, *valid.block().weights()));
            applied.emission.push((height, *valid.block().emission()));
            applied
                .archival
                .push((height, valid.block().archival().clone()));
            applied
                .exercised
                .extend(valid.coverage().iter().map(CenRow::as_str));
            batch.connect_admitting(valid, in_force, Some((&*memo, &admitted)))?;
            super::retire_below_the_anchor(batch, &trust, height)?;
            for entry in &entries {
                batch.unqueue_bundle(entry.h)?;
            }
            applied.connected.push((height, hash));
            Ok(AppliedAdmitting {
                applied,
                admitted: Ok(admitted),
            })
        })?;
        if !out.applied.connected.is_empty() {
            self.tip_moved();
        }
        Ok(out)
    }
}
