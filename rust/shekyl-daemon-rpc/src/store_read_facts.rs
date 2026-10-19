// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`ChainReadFacts`] over the chain store: a child of
//! [`store_facts`](super), so it shares the fault mapping and the tip read,
//! and holds to the same two rules — one snapshot per call, one source per
//! value.
//!
//! - The alt reads are the store's. Hashes come off the table in its key
//!   order. Chains are [`ReadSnapshot::alternate_chains`]: the same walk
//!   admission uses, so a stored chain that does not reach the main chain,
//!   or that links to itself, is this node's inconsistency.
//! - The tree after block `h` is the tree a block at `h + 1` is checked
//!   against: the store's `root_at(h + 1)` and `leaf_count_at(h + 1)`, the
//!   depth derived from the count (`ChainView::depth_at`, `CTW-Q4`). The
//!   tree after the tip and the tree after a named height are the same
//!   read, so `get_curve_tree_info` is `get_curve_tree_checkpoint` at the
//!   tip by construction.
//! - The emission of a range is the supply accumulator's growth across it
//!   (`coins_generated`, CEN-G12's paid reward); its fees are each listed
//!   body's `ct.fee`, read off the recorded transaction.
//! - The claim source is the claim verify's own citing gate and gather
//!   (`emission_epoch_facts`, CEN-J23) over every window epoch, and the
//!   record read the release verify reads (`release_last_served`, folded
//!   by `whole_record_last_served`). An epoch the gate does not admit is
//!   listed without a snapshot (`SO-D11g`).
//! - The coverage list is the shards a join can hold — closed and final,
//!   the byte-cut universe CEN-J15 judges (`ClosedUniverse::final_before`)
//!   — with the market's counts at the slash pass's watermark.
//! - The longhash is RandomX under the seed CEN-D3 names, over a cache
//!   the daemon's cache store already holds. `calc_pow` never derives one.

use shekyl_archival_retention::{
    claim_window_floor, whole_record_last_served, ShardClose, ShardCoverageIn,
};
use shekyl_chain_rules::{
    emission_epoch_facts, release_last_served, seed_height, shard_close, AtHeight, ChainView,
    Claimable, ClosedUniverse, EpochFloor, Pricing, SettlementSchedule,
};
use shekyl_chain_store::store::{
    AltCannot, AltChain, ReadSnapshot, SnapshotView, StoreCannot, StoreError,
};
use shekyl_pow_randomx::{compute_hash, Seedhash};
use shekyl_types::archival::Holdings;
use shekyl_types::{BlockHash, BlockHeight, PCanonicalId, PowHash, SettlementEpoch, ShardId};
use shekyl_wire::{Ct, Transaction};

use super::{connecting, count_at, derivation_fault, store_fault, tip_of, StoreFacts};
use crate::chain_facts::FactsFault;
use crate::read_facts::{
    AltChainFacts, ChainReadFacts, ClaimSource, ClaimantBond, CoinbaseRange, CoinbaseSum,
    CurveTreeFacts, PowAt, PowSeed, ShardCoverage,
};

/// The tree after the block at `after`: the store's state at `after + 1`.
/// `None` when `after` is above the tip.
fn tree_after(
    snap: &ReadSnapshot<'_>,
    after: BlockHeight,
) -> Result<Option<CurveTreeFacts>, FactsFault> {
    let view = SnapshotView::new(snap);
    let Some(next) = after.to_raw().checked_add(1).map(BlockHeight::from_raw) else {
        return Ok(None);
    };
    let root = match view.root_at(next).map_err(store_fault)? {
        AtHeight::Recorded(root) => root,
        AtHeight::AboveTip => return Ok(None),
    };
    // The root, the count and the depth answer from one snapshot: a root
    // recorded at `next` with no count beside it is the store disagreeing
    // with itself.
    let leaf_count = match view.leaf_count_at(next).map_err(store_fault)? {
        AtHeight::Recorded(count) => count,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    let depth = match view.depth_at(next).map_err(store_fault)? {
        AtHeight::Recorded(depth) => depth,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    Ok(Some(CurveTreeFacts {
        after,
        root,
        depth,
        leaf_count,
    }))
}

/// The supply accumulator at `height`, a recorded block's.
fn coins_through(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<u128, FactsFault> {
    match snap.block_info(height).map_err(store_fault)? {
        AtHeight::Recorded(info) => Ok(u128::from(info.coins_generated.to_raw())),
        AtHeight::AboveTip => Err(FactsFault::Inconsistent),
    }
}

/// The fees the block at `height` lists: each listed body's `ct.fee`, read
/// off the recorded pruned segment (the base carries the fee, so a pruned
/// transaction still has one). A listed hash the store cannot find is the
/// store disagreeing with itself.
fn fees_at(snap: &ReadSnapshot<'_>, height: BlockHeight) -> Result<u128, FactsFault> {
    let block = match snap.block(height).map_err(store_fault)? {
        AtHeight::Recorded(body) => body.block,
        AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
    };
    let mut fees = 0u128;
    for hash in &block.transaction_hashes {
        let Some(record) = snap.tx_record(hash).map_err(store_fault)? else {
            tracing::error!(?hash, %height, "a listed transaction is not in the store");
            return Err(FactsFault::Inconsistent);
        };
        let tx = Transaction::read(&mut record.pruned.as_bytes()).map_err(|error| {
            tracing::error!(%error, ?hash, "a recorded transaction's base does not parse");
            FactsFault::Inconsistent
        })?;
        // A listed body is an FCMP++ spend. The coinbase is the miner
        // transaction, not a hash in `transaction_hashes`, so a `Null`
        // base here is the block disagreeing with its own list.
        let fee = match tx.ct {
            Ct::Fcmp { fee, .. } => fee,
            Ct::Null(_) => {
                tracing::error!(?hash, "a listed transaction is not an FCMP++ spend");
                return Err(FactsFault::Inconsistent);
            }
        };
        fees += u128::from(fee);
    }
    Ok(fees)
}

/// One stored chain as the facts layer reports it. Entries come back
/// ascending, just above the recorded root; the reply is tip-first, and
/// the parent is that root. A chain built from an alt tip with no entries
/// named a recorded block as the tip, which a listing of alt tips does
/// not.
fn alt_chain_facts(chain: &AltChain) -> Result<AltChainFacts, FactsFault> {
    let entries = chain.entries();
    let Some(tip) = entries.last() else {
        tracing::error!("an alternative chain built from a stored tip has no alt block");
        return Err(FactsFault::Inconsistent);
    };
    Ok(AltChainFacts {
        blocks: entries.iter().rev().map(|entry| entry.id).collect(),
        tip_height: tip.block.height(),
        cumulative_difficulty: tip.block.cumulative_difficulty().to_raw(),
        parent: chain.root().hash,
    })
}

/// The slash pass's gather at the watermark.
///
/// The pass writes `r_market`, `Σwork` and the watermark one grace epoch
/// after the epoch closes (`scan_slashes`, `SO-D11`). The coverage list's
/// profit hint is that gather. Before any pass the watermark cell is
/// absent: the wire epoch is [`SettlementEpoch::ZERO`] and no row is read.
///
/// `Σwork` and `budget` are read through the claimable floor at the
/// caller's connecting height, and `r_market` through the pricing floor
/// at the same height ([`EpochFloor`]). The watermark is the latest
/// settled epoch, inside both windows on a coherent chain. A row the
/// boundary has retired is a store fault (SI-32), not an absent gather.
#[derive(Clone, Copy)]
struct SlashGather {
    /// The epoch the pass wrote. `None` before any pass.
    written: Option<SettlementEpoch>,
    budget: Option<u64>,
    sigma_work_milli: Option<u64>,
    /// Pricing floor at the connecting height this gather was read for.
    /// [`Self::served`] reads `r_market` through it.
    pricing: EpochFloor<Pricing>,
}

impl SlashGather {
    fn read(
        view: &SnapshotView<'_>,
        connecting: BlockHeight,
        schedule: SettlementSchedule,
    ) -> Result<Self, FactsFault> {
        let claimable = EpochFloor::<Claimable>::under(connecting, schedule);
        let pricing = EpochFloor::<Pricing>::under(connecting, schedule);
        let Some(epoch) = view.last_settled_slash_epoch().map_err(store_fault)? else {
            return Ok(Self {
                written: None,
                budget: None,
                sigma_work_milli: None,
                pricing,
            });
        };
        Ok(Self {
            written: Some(epoch),
            budget: view
                .budget(epoch, claimable)
                .map_err(store_fault)?
                .map(shekyl_units::AtomicUnits::to_raw),
            sigma_work_milli: view
                .sigma_work(epoch, claimable)
                .map_err(store_fault)?
                .map(shekyl_types::archival::SigmaWorkMilli::to_raw),
            pricing,
        })
    }

    /// `r_market` for `shard` at the written epoch, through the pricing
    /// floor captured at [`Self::read`]. Before any pass there is no epoch
    /// to read, and the served count is zero.
    fn served(&self, view: &SnapshotView<'_>, shard: ShardId) -> Result<u64, FactsFault> {
        let Some(epoch) = self.written else {
            return Ok(0);
        };
        Ok(view
            .r_market(shard, epoch, self.pricing)
            .map_err(store_fault)?
            .map_or(0, shekyl_types::archival::RMarket::to_raw))
    }

    fn epoch(&self) -> SettlementEpoch {
        self.written.unwrap_or(SettlementEpoch::ZERO)
    }
}

impl ChainReadFacts for StoreFacts {
    fn alt_block_hashes(&self) -> Result<Vec<BlockHash>, FactsFault> {
        let snap = self.snapshot()?;
        tip_of(&snap)?;
        Ok(snap
            .alt_blocks()
            .map_err(store_fault)?
            .into_iter()
            .map(|entry| entry.id)
            .collect())
    }

    fn alternate_chains(&self) -> Result<Vec<AltChainFacts>, FactsFault> {
        let snap = self.snapshot()?;
        tip_of(&snap)?;
        // The store walks. `Unlinked` on a chain the table already holds is
        // the invariant breaking: admission refuses that orphan, so a stored
        // one was written around it. It stays a cannot for an offer. Here,
        // where the rows are the store's own, it is this node's inconsistency.
        let chains = match snap.alternate_chains() {
            Ok(chains) => chains,
            Err(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked { at }))) => {
                tracing::error!(
                    hash = %at,
                    "a stored alternative chain does not reach the main chain"
                );
                return Err(FactsFault::Inconsistent);
            }
            Err(other) => return Err(store_fault(other)),
        };
        chains.iter().map(alt_chain_facts).collect()
    }

    fn curve_tree(&self) -> Result<CurveTreeFacts, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        // The tip's own successor state is the last row connect wrote.
        tree_after(&snap, tip)?.ok_or(FactsFault::Inconsistent)
    }

    fn curve_tree_after(&self, height: BlockHeight) -> Result<Option<CurveTreeFacts>, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        if height > tip {
            return Ok(None);
        }
        tree_after(&snap, height)?
            .map(Some)
            .ok_or(FactsFault::Inconsistent)
    }

    fn coinbase_sum(&self, start: BlockHeight, count: u64) -> Result<CoinbaseRange, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let chain = count_at(tip).to_raw();
        // The C++ handler's bound, as it wrote it: a start at or past the
        // count, or a count larger than the chain. A range that starts
        // inside and runs past the tip is summed through the tip, as its
        // `for_blocks_range` stopped at the table's end.
        if start.to_raw() >= chain || count > chain {
            return Ok(CoinbaseRange::TooLarge);
        }
        let Some(last) = count.checked_sub(1) else {
            return Ok(CoinbaseRange::Summed(CoinbaseSum::default()));
        };
        let end = BlockHeight::from_raw(start.to_raw().saturating_add(last).min(tip.to_raw()));
        let before = match start.to_raw().checked_sub(1) {
            Some(parent) => coins_through(&snap, BlockHeight::from_raw(parent))?,
            None => 0,
        };
        let emission = coins_through(&snap, end)?
            .checked_sub(before)
            .ok_or(FactsFault::Inconsistent)?;
        let mut fees = 0u128;
        for height in start.to_raw()..=end.to_raw() {
            fees += fees_at(&snap, BlockHeight::from_raw(height))?;
        }
        Ok(CoinbaseRange::Summed(CoinbaseSum { emission, fees }))
    }

    fn pow_hash(&self, pow_blob: &[u8], seed: PowSeed) -> Result<PowAt, FactsFault> {
        let seed = match seed {
            PowSeed::Given(seed) => seed,
            PowSeed::AtHeight(height) => match seed_height(height) {
                // Genesis admission: no block 0 yet, the null seed (CEN-D3).
                None => BlockHash::NULL,
                Some(seed_height) => {
                    let snap = self.snapshot()?;
                    let (tip, _) = tip_of(&snap)?;
                    match snap.block_info(seed_height).map_err(store_fault)? {
                        AtHeight::Recorded(info) => info.hash,
                        AtHeight::AboveTip => return Ok(PowAt::SeedAboveTip { seed_height, tip }),
                    }
                }
            },
        };
        // A held cache or nothing: `lookup`, never `lookup_or_derive`. The
        // seed may be the chain's own and still not held (the store keeps
        // two, the validator's current and spare).
        let Some(cache) = self.caches.lookup(&Seedhash::from_bytes(*seed.as_bytes())) else {
            return Ok(PowAt::SeedNotHeld { seed });
        };
        // Under a permit in calc_pow's class: below the chain's forms and
        // chain sync's, above the miner's. The facts run on a blocking
        // thread, so the wait is one.
        let _permit = self.budget.acquire(shekyl_hash_budget::Class::CalcPow);
        Ok(PowAt::Hashed(PowHash::from_bytes(compute_hash(
            &cache, pow_blob,
        ))))
    }

    fn emission_claim_source(&self, persona: &PCanonicalId) -> Result<ClaimSource, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let view = SnapshotView::new(&snap);
        let at = connecting(tip);
        let rule_set = self.rules.in_force(at);
        let schedule = rule_set.settlement_schedule();
        let settled = schedule.epoch_at(at);
        let bond = match view.bond_record(persona).map_err(store_fault)? {
            None => None,
            Some(record) => {
                let maxima = release_last_served(&view, persona, &record).map_err(store_fault)?;
                Some(ClaimantBond {
                    join_settlement_epoch: record.join_settlement_epoch,
                    holdings_kind: record.holdings.kind(),
                    held_shards: match &record.holdings {
                        Holdings::ShardSet(held) => {
                            held.as_slice().iter().map(|h| h.shard).collect()
                        }
                        Holdings::CompleteTree => Vec::new(),
                    },
                    claimed_settlement_epochs: record.claimed_settlement_epochs.clone(),
                    bonded_total: record.bonded_total,
                    bad_interval_count: record.bad_intervals.len(),
                    last_served: whole_record_last_served(&maxima),
                    last_settled_slash: view.last_settled_slash_epoch().map_err(store_fault)?,
                })
            }
        };
        let window: Vec<u64> = (claim_window_floor(settled.to_raw())..settled.to_raw()).collect();
        let epochs =
            emission_epoch_facts(&view, &rule_set, persona, &window).map_err(derivation_fault)?;
        Ok(ClaimSource {
            chain_height: count_at(tip),
            current_settled_epoch: settled,
            bond,
            epochs,
        })
    }

    fn shard_coverage(&self) -> Result<ShardCoverage, FactsFault> {
        let snap = self.snapshot()?;
        let (tip, _) = tip_of(&snap)?;
        let view = SnapshotView::new(&snap);
        let at = connecting(tip);
        let rule_set = self.rules.in_force(at);
        let universe = ClosedUniverse::final_before(&view, at, rule_set.reorg_cap())
            .map_err(derivation_fault)?;
        let count = universe.count().get();
        let gather = SlashGather::read(&view, at, rule_set.settlement_schedule())?;
        let mut bonded = vec![0u64; usize::try_from(count).map_err(|_| FactsFault::Internal)?];
        for (_, record) in view.bond_records().map_err(store_fault)? {
            if let Holdings::ShardSet(held) = &record.holdings {
                for h in held.as_slice() {
                    if let Some(slot) = usize::try_from(h.shard.to_raw())
                        .ok()
                        .and_then(|i| bonded.get_mut(i))
                    {
                        *slot += 1;
                    }
                }
            }
        }
        let mut shards = Vec::with_capacity(bonded.len());
        for (k, bonded_count) in (0..count).zip(bonded) {
            let shard = ShardId::from_raw(k);
            let ShardClose::ClosedAt(closed) =
                shard_close(&view, shard, &universe).map_err(derivation_fault)?
            else {
                tracing::error!(shard = k, "a shard below the closed count reads open");
                return Err(FactsFault::Inconsistent);
            };
            let served = gather.served(&view, shard)?;
            shards.push(ShardCoverageIn {
                shard_id: k,
                bonded_count,
                served_count: served,
                freeze_height: closed.to_raw(),
            });
        }
        let leaf_count = match view.leaf_count_at(at).map_err(store_fault)? {
            AtHeight::Recorded(n) => n,
            AtHeight::AboveTip => return Err(FactsFault::Inconsistent),
        };
        Ok(ShardCoverage {
            as_of: tip,
            leaf_count,
            settled_epoch: gather.epoch(),
            budget: gather.budget,
            sigma_work_milli: gather.sigma_work_milli,
            shards,
        })
    }
}
