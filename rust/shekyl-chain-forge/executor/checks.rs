// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What a named event holds the chain to (`CHAIN_FORGE.md` §3).
//!
//! A consumer asks for the chain up to an event's name, so the name is a
//! promise about the state there. Each check reads that state from the
//! store or the block the validator judged, and a chain that does not
//! keep the promise fails the forge rather than publishing the name.

use shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC;
use shekyl_chain_forge::Check;
use shekyl_chain_ingest::chain_drive::{is_pruning_boundary, spender_owning_before};
use shekyl_chain_ingest::scenario_shard::{closed_shards, ClosedShard};
use shekyl_chain_rules::{AtHeight, CenRow, ChainView, EpochFloor};
use shekyl_chain_store::store::{ArchivalGood, AtIndex};
use shekyl_crypto_pq::account::normalize_seed;
use shekyl_fcmp::tree::SELENE_CHUNK_WIDTH;
use shekyl_harness_spender::{Owner, Persona};
use shekyl_harness_wallet::HARNESS_SEED;
use shekyl_network::Network;
use shekyl_types::archival::SettlementOutcome;
use shekyl_types::{BlockCount, BlockHeight, SettlementEpoch, ShardId};

use super::{Forge, ForgeFault};

/// Blocks a body-fill walk needs its funding output aged by at the cut: the
/// spendable age and the reference anchor's, with a not-ready retry's room.
const BODY_FILL_FUNDING_AGE: u64 = 20;
/// Blocks a body-fill walk's live steps need after its cut, before the
/// boundary that ends them: the fill, the post and its confirmation.
const BODY_FILL_ROOM: u64 = 20;
/// The latest a CompleteTree walk may start after shard B's close: its fill
/// runs while B is not yet final, with margin under the reorg cap.
const BODY_FILL_AFTER_CLOSE: u64 = 6;
/// What the walk's confirm step needs above the floor and the fee, so the
/// bond post leaves a change output (the walk's `FUNDING_CUSHION`).
const BODY_FILL_CUSHION: u64 = 12_000_000_000;
/// A weight no bond post reaches: the bound the funding's fee is priced at.
const BODY_FILL_POST_WEIGHT: u64 = 1 << 20;

/// The last reorg the plan made.
#[derive(Clone, Copy, Debug)]
pub(super) struct LastReorg {
    /// The height it forked at.
    pub fork: BlockHeight,
    /// The tip it popped from.
    pub popped_tip: BlockHeight,
    /// The leaf count at the first block above the fork, before the pop.
    pub leaves_above_fork: u64,
    /// The leaf count above the popped tip, before the pop.
    pub leaves_above_tip: u64,
    /// The rewind left the fork's leaf count, depth and root as they were.
    pub restored: bool,
}

/// The harness persona's funding output.
#[derive(Clone, Copy, Debug)]
pub(super) struct HarnessFunding {
    /// Its one-time key.
    pub output_key: [u8; 32],
    /// The block that listed it.
    pub paid_at: BlockHeight,
}

/// The persona a wallet restored from the harness seed derives at slot 0.
pub(super) fn harness_persona() -> Persona {
    Persona::from_master(&normalize_seed(&HARNESS_SEED), Network::Regtest, 0)
}

fn index(height: BlockHeight) -> usize {
    usize::try_from(height.to_raw()).expect("a forged chain's height fits")
}

fn failed(what: Check, why: impl std::fmt::Display) -> ForgeFault {
    ForgeFault::Plan(format!("check {what:?}: {why}"))
}

impl Forge {
    /// [`Check`]: `Ok(Some(height))` names the earlier block the event
    /// belongs to, `Ok(None)` the tip.
    pub(super) async fn check(
        &mut self,
        what: Check,
        persona: Option<u32>,
        shard: Option<u64>,
    ) -> Result<Option<BlockHeight>, ForgeFault> {
        let tip = self.chain.last().expect("genesis at least").height;
        match what {
            Check::TreeDepthThree => self.check_tree_depth(tip).await.map(|()| None),
            Check::SeedBoundary => self.check_seed_boundary(tip).map(|()| None),
            Check::BurnPositive => self
                .chain
                .iter()
                .find(|block| {
                    block.emission.fee_burn.actually_destroyed > 0
                        && block.emission.fee_burn.staker_pool_amount > 0
                })
                .map(|block| Some(block.height))
                .ok_or_else(|| failed(what, "no block burned and fed the pool")),
            Check::ServeCredit => self
                .chain
                .iter()
                .find(|block| {
                    !block.bundle_bodies.is_empty() && block.judged_by.contains(&CenRow::J37)
                })
                .map(|block| Some(block.height))
                .ok_or_else(|| failed(what, "no block admitted a bundle")),
            Check::SettledEpoch => {
                let slot = persona.ok_or_else(|| failed(what, "names a persona"))?;
                self.check_settled(slot, tip).await.map(|()| None)
            }
            Check::Discarded => {
                let id = shard.ok_or_else(|| failed(what, "names a shard"))?;
                self.check_discarded(id, tip).await.map(Some)
            }
            Check::SettledOnDiscarded => {
                let slot = persona.ok_or_else(|| failed(what, "names a persona"))?;
                let id = shard.ok_or_else(|| failed(what, "names a shard"))?;
                self.check_discarded(id, tip).await?;
                let joined = self
                    .personas
                    .get(&slot)
                    .ok_or_else(|| failed(what, "the persona has not joined"))?;
                let id_of = joined.persona.id();
                let held = ShardId::from_raw(id);
                let served = self.chain[index(tip)]
                    .archival
                    .settlements()
                    .iter()
                    .any(|row| {
                        row.persona == id_of
                            && row.shard == held
                            && row.row.outcome() == SettlementOutcome::Served
                    });
                if served {
                    Ok(None)
                } else {
                    Err(failed(
                        what,
                        format!("{tip} settled no Served pair on shard {id}"),
                    ))
                }
            }
            Check::PruneBoundary => {
                if !is_pruning_boundary(tip, self.schedule) {
                    return Err(failed(what, format!("{tip} is not a pruning boundary")));
                }
                let cap = self.reorg_cap;
                let floor = self
                    .scenario()
                    .with_store(|store, _| {
                        store
                            .begin_read()
                            .expect("a snapshot")
                            .undo_floor()
                            .expect("the floor reads")
                    })
                    .await;
                let expected = tip
                    .checked_sub_count(BlockCount::from_raw(cap))
                    .ok_or_else(|| failed(what, "a boundary below the cap"))?;
                if floor == expected {
                    Ok(None)
                } else {
                    Err(failed(
                        what,
                        format!("the undo floor is {floor}, not {expected}"),
                    ))
                }
            }
            Check::Unstake => {
                let released = self
                    .personas
                    .values()
                    .any(|joined| joined.released.is_some_and(|(_, listed)| listed == tip));
                if released {
                    Ok(None)
                } else {
                    Err(failed(what, format!("{tip} lists no Release")))
                }
            }
            Check::ReorgCrossesEpoch | Check::ReorgCrossesPrune | Check::ReorgCrossesChunk => {
                self.check_reorg(what).map(|()| None)
            }
            Check::BodyFillCompleteTree => self.check_complete_tree_cut(tip).await.map(|()| None),
            Check::BodyFillMarket => self.check_market_cut(tip).await.map(|()| None),
        }
    }

    /// The tip lists a spend whose proof is over three layers, at the
    /// reference the depth is judged at (CEN-I13).
    async fn check_tree_depth(&mut self, tip: BlockHeight) -> Result<(), ForgeFault> {
        const DEPTH_OF_THREE_LAYERS: u8 = 2;
        let what = Check::TreeDepthThree;
        let listed = self.chain[index(tip)]
            .template
            .transactions
            .last()
            .ok_or_else(|| failed(what, format!("{tip} lists nothing")))?;
        let shekyl_wire::Ct::Fcmp {
            prunable: Some(prunable),
            ..
        } = &listed.ct
        else {
            return Err(failed(
                what,
                "the listed body is not a spend with its proof",
            ));
        };
        if prunable.tree_depth != u64::from(DEPTH_OF_THREE_LAYERS) {
            return Err(failed(
                what,
                format!("the proof's depth is {}", prunable.tree_depth),
            ));
        }
        let reference = shekyl_chain_rules::newest_admissible_reference(tip)
            .ok_or_else(|| failed(what, "no reference below the tip"))?;
        let depth = self
            .scenario()
            .read_chain(move |view, _| view.depth_at(reference).expect("the depth reads"))
            .await;
        if depth == AtHeight::Recorded(DEPTH_OF_THREE_LAYERS) {
            Ok(())
        } else {
            Err(failed(
                what,
                format!("the tree at {reference} is {depth:?}"),
            ))
        }
    }

    /// The tip is the first block on a seed other than genesis's, and lists
    /// a spend.
    fn check_seed_boundary(&self, tip: BlockHeight) -> Result<(), ForgeFault> {
        let what = Check::SeedBoundary;
        let genesis = self.chain[0].hash;
        let first = self
            .chain
            .iter()
            .skip(1)
            .find(|block| block.seed != genesis)
            .ok_or_else(|| failed(what, "the seed never moved"))?;
        if first.height != tip {
            return Err(failed(
                what,
                format!("the seed moved at {}, the tip is {tip}", first.height),
            ));
        }
        if first.template.transactions.is_empty() {
            return Err(failed(
                what,
                "the first block on the new seed lists no spend",
            ));
        }
        Ok(())
    }

    /// CF-E13 at the slash pass of the persona's first drawn epoch.
    async fn check_settled(&mut self, slot: u32, tip: BlockHeight) -> Result<(), ForgeFault> {
        let what = Check::SettledEpoch;
        let joined = self
            .personas
            .get(&slot)
            .ok_or_else(|| failed(what, "the persona has not joined"))?;
        let persona = joined.persona.id();
        let epoch = SettlementEpoch::from_raw(joined.join_epoch.to_raw() + 1);
        let pass = self.schedule.slash_deadline_height(epoch.to_raw());
        if tip.to_raw() != pass {
            return Err(failed(
                what,
                format!("the tip {tip} is not epoch {epoch}'s pass {pass}"),
            ));
        }
        let served: Vec<ShardId> = self.chain[index(tip)]
            .archival
            .settlements()
            .iter()
            .filter(|row| {
                row.epoch == epoch
                    && row.persona == persona
                    && row.row.outcome() == SettlementOutcome::Served
            })
            .map(|row| row.shard)
            .collect();
        let Some(&shard) = served.first() else {
            return Err(failed(
                what,
                format!("epoch {epoch} settled no Served pair"),
            ));
        };
        if self
            .chain
            .iter()
            .any(|block| !block.archival.slashes().is_empty())
        {
            return Err(failed(what, "a slash row precedes the settled epoch"));
        }
        let (sigma, budget, market, watermark) = self
            .scenario()
            .with_store(move |store, _| {
                let read = store.begin_read().expect("a snapshot");
                (
                    read.sigma_work(epoch, EpochFloor::NONE)
                        .expect("Σwork reads"),
                    read.budget(epoch, EpochFloor::NONE)
                        .expect("the budget reads"),
                    read.r_market(shard, epoch, EpochFloor::NONE)
                        .expect("r_market reads"),
                    read.last_settled_slash_epoch()
                        .expect("the watermark reads"),
                )
            })
            .await;
        if !sigma.is_some_and(|work| work.to_raw() > 0) {
            return Err(failed(what, format!("Σwork({epoch}) is {sigma:?}")));
        }
        if !budget.is_some_and(|units| units.to_raw() > 0) {
            return Err(failed(what, format!("the budget of {epoch} is {budget:?}")));
        }
        if !market.is_some_and(|holders| holders.to_raw() > 0) {
            return Err(failed(
                what,
                format!("r_market({shard:?}, {epoch}) is {market:?}"),
            ));
        }
        if watermark != Some(epoch) {
            return Err(failed(
                what,
                format!("the watermark is {watermark:?}, not {epoch}"),
            ));
        }
        Ok(())
    }

    /// Shard `id`'s close, and a spend its body holds.
    pub(super) fn close_of(&self, id: u64) -> Result<ClosedShard, ForgeFault> {
        self.closed
            .iter()
            .find(|closed| closed.shard == ShardId::from_raw(id))
            .copied()
            .ok_or_else(|| ForgeFault::Plan(format!("shard {id} is not closed")))
    }

    /// The boundary that discards `closed`'s bodies.
    pub(super) fn discard_boundary(&self, closed: ClosedShard) -> BlockHeight {
        let close_epoch = self.schedule.epoch_at(closed.close_height).to_raw();
        BlockHeight::from_raw((close_epoch + 2) * self.schedule.blocks().get())
    }

    /// Shard `id`'s bodies are discarded at the tip, read off one of its
    /// spends. The boundary that discarded them.
    async fn check_discarded(
        &mut self,
        id: u64,
        tip: BlockHeight,
    ) -> Result<BlockHeight, ForgeFault> {
        let what = Check::Discarded;
        let closed = self.close_of(id)?;
        let boundary = self.discard_boundary(closed);
        if tip < boundary {
            return Err(failed(
                what,
                format!("the tip {tip} is below the boundary {boundary}"),
            ));
        }
        let before_close = closed
            .close_height
            .checked_sub_count(BlockCount::ONE)
            .expect("a shard closes above genesis");
        let hash = self.chain[index(before_close)]
            .template
            .transactions
            .first()
            .ok_or_else(|| failed(what, format!("{before_close} lists no spend")))?
            .txid_parts()
            .hash;
        let held = ShardId::from_raw(id);
        let (good, in_shard) = self
            .scenario()
            .with_store(move |store, _| {
                let read = store.begin_read().expect("a snapshot");
                let record = read
                    .tx_record(&hash)
                    .expect("the record reads")
                    .expect("the spend is recorded");
                (
                    read.tx_archival_good(record.location.id)
                        .expect("the good reads"),
                    read.tx_shard(record.location).expect("the shard reads"),
                )
            })
            .await;
        if in_shard != held {
            return Err(failed(
                what,
                format!("the spend is in {in_shard:?}, not {held:?}"),
            ));
        }
        if !matches!(good, AtIndex::Recorded(ArchivalGood::Discarded)) {
            return Err(failed(what, format!("shard {id}'s spend reads {good:?}")));
        }
        Ok(boundary)
    }

    /// The last reorg straddled what `what` names.
    fn check_reorg(&self, what: Check) -> Result<(), ForgeFault> {
        let reorg = self
            .last_reorg
            .ok_or_else(|| failed(what, "the plan has not reorged"))?;
        let (fork, popped) = (reorg.fork.to_raw(), reorg.popped_tip.to_raw());
        let blocks = self.schedule.blocks().get();
        let crosses = match what {
            Check::ReorgCrossesEpoch => (fork + 1..=popped).any(|h| h.is_multiple_of(blocks)),
            Check::ReorgCrossesPrune => (fork + 1..=popped)
                .any(|h| is_pruning_boundary(BlockHeight::from_raw(h), self.schedule)),
            _ => {
                let width = u64::try_from(SELENE_CHUNK_WIDTH).expect("a width fits");
                reorg.restored
                    && reorg.leaves_above_fork.div_ceil(width)
                        < reorg.leaves_above_tip.div_ceil(width)
            }
        };
        if crosses {
            Ok(())
        } else {
            Err(failed(what, format!("the reorg was {reorg:?}")))
        }
    }

    /// What both body-fill cuts hold: the harness wallet has a matured,
    /// unspent coinbase, and its persona one funding output, aged and large
    /// enough for a bond post with change.
    async fn check_body_fill_funding(
        &mut self,
        what: Check,
        cut: BlockHeight,
    ) -> Result<(), ForgeFault> {
        let funding = self
            .harness_funding
            .ok_or_else(|| failed(what, "the plan has not funded the harness persona"))?;
        if funding.paid_at.to_raw() + BODY_FILL_FUNDING_AGE > cut.to_raw() {
            return Err(failed(
                what,
                format!("funded at {}, too near {cut}", funding.paid_at),
            ));
        }
        if self.first_kept <= 1 {
            return Err(failed(what, "the plan spends the wallet's first coinbase"));
        }
        let connecting = cut + BlockCount::ONE;
        let network = self.scenario().network_id();
        let spender =
            spender_owning_before(network, &self.chain, funding.paid_at, &[funding.output_key]);
        let persona = harness_persona();
        let amount = spender
            .owned_input(
                &Owner::persona(persona.keys()),
                funding.output_key,
                connecting,
            )
            .input
            .amount
            .to_raw();
        let rate = self.scenario().connecting_default_rate().await;
        let fee = shekyl_economics::quantized_fee(BODY_FILL_POST_WEIGHT, rate)
            .ok_or_else(|| failed(what, "the post's fee does not price"))?;
        let needed = ARCHIVAL_BOND_FLOOR_ATOMIC + BODY_FILL_CUSHION + fee;
        if amount <= needed {
            return Err(failed(
                what,
                format!("the funding pays {amount}, needs over {needed}"),
            ));
        }
        Ok(())
    }

    /// The CompleteTree walk's cut: shard A final, shard B just closed and
    /// not final, with room before B's freeze epoch.
    async fn check_complete_tree_cut(&mut self, cut: BlockHeight) -> Result<(), ForgeFault> {
        let what = Check::BodyFillCompleteTree;
        let [a, b, ..] = self.closed.as_slice() else {
            return Err(failed(what, "two shards closed"));
        };
        let (a, b) = (*a, *b);
        let c = cut.to_raw();
        if a.close_height.to_raw() + self.reorg_cap > c {
            return Err(failed(what, format!("shard A is not final at {cut}")));
        }
        let b_close = b.close_height.to_raw();
        if !(b_close..=b_close + BODY_FILL_AFTER_CLOSE).contains(&c) {
            return Err(failed(
                what,
                format!("{cut} is outside shard B's window from {b_close}"),
            ));
        }
        let epoch_end =
            (self.schedule.epoch_at(b.close_height).to_raw() + 1) * self.schedule.blocks().get();
        if c + BODY_FILL_ROOM > epoch_end {
            return Err(failed(
                what,
                format!("{cut} leaves no room before {epoch_end}"),
            ));
        }
        self.check_body_fill_funding(what, cut).await
    }

    /// The Market walk's cut: the block before the first admissible join,
    /// shard A final, the next shard open, with room before A's discard.
    async fn check_market_cut(&mut self, cut: BlockHeight) -> Result<(), ForgeFault> {
        let what = Check::BodyFillMarket;
        if self.join_eve != Some(cut) {
            return Err(failed(
                what,
                format!("{cut} is not the block before the join"),
            ));
        }
        let a = *self
            .closed
            .first()
            .ok_or_else(|| failed(what, "a shard closed"))?;
        if a.close_height.to_raw() + self.reorg_cap > cut.to_raw() {
            return Err(failed(what, format!("shard A is not final at {cut}")));
        }
        if cut.to_raw() + BODY_FILL_ROOM > self.discard_boundary(a).to_raw() {
            return Err(failed(
                what,
                format!("{cut} leaves no room before A's discard"),
            ));
        }
        let closed_now = closed_shards(self.scenario()).await;
        let known = u64::try_from(self.closed.len()).expect("a count fits");
        if closed_now != known {
            return Err(failed(
                what,
                format!("{closed_now} shards closed, the plan knows {known}"),
            ));
        }
        self.check_body_fill_funding(what, cut).await
    }
}
