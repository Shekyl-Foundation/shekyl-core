// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Closing archival shards on a driven chain — the `close_shard()` step
//! (`CHAIN_RULES_SLICE_8.md` §5 row 6).
//!
//! A shard is `W` bytes of archival good — the prunable regions and
//! `pqc_auths` of a chain's listed transactions
//! ([`Transaction::archival_len`]; a coinbase adds nothing) — and shard
//! `k` closes in the block whose cumulative length reaches `(k + 1) · W`
//! ([`shekyl_types::shard_of`]). CEN-J15 admits a compact JoinMarket only
//! onto shards that are **closed, final and priced** at the parent, so a
//! scenario about a compact holding fills its shards first: the driver's
//! real coinbase spends, as many per block as the full-reward zone takes,
//! until the producer's `closed_shards` moves. Then it waits for the two
//! operands the rule reads after the close — `reorg_cap` blocks for
//! finality and an epoch close for the price — and joins.
//!
//! Nothing here is a lever. `W` is the production constant
//! ([`SHARD_LENGTH`]), every byte is a proof the validator verifies, and
//! the price is the epoch close's own `r_market` row for the shard
//! (`archival/close.rs`: every closed shard in the universe is priced at
//! every close, bonds or none). That is a few hundred real spends per
//! shard, built in parallel and listed [`SPENDS_PER_BLOCK`] at a time —
//! minutes, not seconds — so the scenarios that call this run in the live
//! lane (`cargo test -p shekyl-chain-ingest --features pipeline -- --ignored`).
//!
//! The supply is coinbases: one per block, each spendable [`maturity`]
//! blocks after its height ([`first_spending_height`] is coinbase 0's).
//! Filling at [`SPENDS_PER_BLOCK`] a block therefore mines the supply
//! ahead first — empty blocks are cheap, proofs are not — sized from the
//! first spend's own archival length rather than a number written down.

use shekyl_archival_retention::{draw_count, draw_horizon};
use shekyl_chain_rules::{FakechainSchedule, SettlementEpochBlocks, SettlementSchedule};
use shekyl_types::archival::COUNTED_DRAWS;
use shekyl_types::archival::SHARD_LENGTH;
use shekyl_types::{BlockCount, BlockHeight, ChainCount, ShardId};
use shekyl_wire::Transaction;

use crate::archival_driver::{first_spending_height, FEE};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::schedule::ChainRules;
use shekyl_harness_spender::Spender;

/// The levered settlement epoch, in blocks. The production epoch (10,000
/// blocks) never prices a shard inside what a test mines; under this one
/// a shard closed at `h` is priced by the close at the end of the epoch
/// after `h`'s, and eleven epochs of misses and the grace epoch — a slash
/// — are a few hundred blocks.
pub const EPOCH_BLOCKS: u64 = 20;

/// The levered reorg cap, in blocks. It sits inside [`EPOCH_BLOCKS`].
pub const REORG_CAP_BLOCKS: u64 = 10;

/// Regtest rules under the levered schedule: the pair every scenario that
/// closes a shard mines under.
pub fn levered_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(EPOCH_BLOCKS).expect("non-zero"),
            BlockCount::from_raw(REORG_CAP_BLOCKS),
        )
        .expect("the cap sits inside the epoch"),
    }
}

/// The settlement schedule [`levered_rules`] runs.
pub fn levered_schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(EPOCH_BLOCKS).expect("non-zero"))
}

/// The most drawable pairs a chain on the settled schedule draws in one
/// epoch: the levered slash chain's two shards.
pub const SETTLED_PAIRS: u64 = 2;

/// The settled epoch, in blocks: the shortest levered epoch in which the
/// count rule issues every pair of a set of up to [`SETTLED_PAIRS`] its
/// [`COUNTED_DRAWS`] when every drawing block's bundle is admitted by the
/// next block.
///
/// [`EPOCH_BLOCKS`] is too short for that. The count rule's horizon has a
/// floor (`draw_horizon_floor_blocks`, 200 blocks) far above a 20-block
/// epoch, so one pair is drawn about once an epoch there and never settles
/// Served or Missed. A chain whose settlement is fed by admitted draws runs
/// under this schedule instead. The rule itself is not touched: the epoch
/// is found by running it.
///
/// Derived, not written down: the epoch is searched from the shortest one
/// with a response window, one window step at a time, running the count
/// phase's own arithmetic ([`draw_horizon`], [`draw_count`]) block by block
/// as the transition does. The shortfall opens at `COUNTED_DRAWS · D`; a
/// block's visible shortfall is its predecessor's less the draws its
/// predecessor admitted; the block before is still in flight when a block
/// counts; and the last block's draws are admitted by the first block of
/// the next epoch. The first epoch that leaves no shortfall for every set
/// size from one to [`SETTLED_PAIRS`] is the answer. A chain that moves
/// onto it still asserts that its pairs reached [`COUNTED_DRAWS`] before
/// it reads a settlement (rule 47): the derivation is the reason to expect
/// it, the chain's own index is the evidence.
pub fn settled_epoch_blocks() -> u64 {
    static SETTLED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SETTLED.get_or_init(|| {
        (1u64..)
            .map(|step| step * shekyl_archival_retention::constants::W2_EPOCH_DIVISOR)
            .find(|&blocks| (1..=SETTLED_PAIRS).all(|pairs| issues_every_pair(blocks, pairs)))
            .expect("some epoch issues every pair its counted draws")
    })
}

/// Whether an epoch of `blocks` leaves no shortfall for a set of `pairs`
/// (see [`settled_epoch_blocks`]).
fn issues_every_pair(blocks: u64, pairs: u64) -> bool {
    let schedule = SettlementSchedule::new(SettlementEpochBlocks::new(blocks).expect("non-zero"));
    let Some(window) = schedule.challenge_response_blocks() else {
        return false;
    };
    let params = shekyl_archival_retention::archival_params();
    let counted = u64::try_from(COUNTED_DRAWS).expect("a small constant");
    let mut visible = counted * pairs;
    let mut carry = 0u32;
    let mut previous = 0u64;
    for relative in 0..blocks {
        // The predecessor admitted the draws of the block before it.
        let admitted = previous.min(visible);
        let unsettled = visible.saturating_sub(previous);
        let horizon = draw_horizon(relative, blocks, window.get(), params);
        let (count, next_carry) = draw_count(pairs, unsettled, horizon, blocks, carry, params)
            .expect("the levered schedule has a target");
        carry = next_carry;
        if relative > 0 {
            visible -= admitted;
        }
        previous = count;
    }
    // The epoch's last block is admitted by the next epoch's first.
    visible.saturating_sub(previous) == 0
}

/// Regtest rules under the settled schedule ([`settled_epoch_blocks`]),
/// with the levered reorg cap.
pub fn settled_rules() -> ChainRules {
    ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: FakechainSchedule::new(
            SettlementEpochBlocks::new(settled_epoch_blocks()).expect("non-zero"),
            BlockCount::from_raw(REORG_CAP_BLOCKS),
        )
        .expect("the cap sits inside the settled epoch"),
    }
}

/// The settlement schedule [`settled_rules`] runs.
pub fn settled_schedule() -> SettlementSchedule {
    SettlementSchedule::new(SettlementEpochBlocks::new(settled_epoch_blocks()).expect("non-zero"))
}

/// Coinbases a shard fill spends from. Those below it stay for the posts
/// that ride the chain: a join spends coinbase 0.
pub const FILL_FROM_COINBASE: u64 = 10;

/// Spends listed per fill block. One driven coinbase spend measures about
/// 13.2 KB of archival good and a little more on the wire; sixteen sit
/// near 230 KB, under the 300,000-byte full-reward zone with room for the
/// coinbase, so a fill block is never penalised and never near the
/// `2 × median` weight limit.
pub const SPENDS_PER_BLOCK: usize = 16;

/// Blocks after a coinbase's height before it may be spent: the unlock
/// window, one, and the reference age — [`first_spending_height`]
/// measured from coinbase 0.
pub fn maturity() -> u64 {
    first_spending_height().to_raw()
}

/// A shard the fill closed, and the block that closed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedShard {
    pub shard: ShardId,
    /// The height whose fold first counted the shard closed: the block
    /// `closed_and_final` measures finality from.
    pub close_height: BlockHeight,
}

/// What a fill left behind.
#[derive(Debug)]
pub struct Filled {
    /// Every shard the fill closed, ascending.
    pub closed: Vec<ClosedShard>,
}

/// The shards the producer counts closed at the next connecting height.
pub async fn closed_shards(scenario: &Scenario<FreeHash>) -> u64 {
    scenario
        .facts()
        .await
        .expect("the connector answers")
        .closed_shards
        .get()
}

/// Mine empty blocks until the chain's next block connects at `height`.
pub async fn mine_to(
    scenario: &mut Scenario<FreeHash>,
    chain: &mut Vec<Mined>,
    height: BlockHeight,
) {
    while next_height(chain) < height {
        let block = scenario
            .mine_listing(Vec::new())
            .await
            .expect("empty blocks land");
        chain.push(block);
    }
}

/// The height the chain's next block connects at: its length, as a count.
fn next_height(chain: &[Mined]) -> BlockHeight {
    ChainCount::from_raw(u64::try_from(chain.len()).expect("a test chain's length is a count"))
        .next_height()
}

/// Fill the chain with real spends until `want` shards are closed. Spends
/// coinbases from `first_coinbase` upward — the ones below it are never
/// touched, and the caller's posts ride those — and extends `chain` in
/// place with every block mined.
///
/// Panics if the chain already has `want` shards closed: the caller asked
/// for a fill it did not need.
pub async fn close_shards(
    scenario: &mut Scenario<FreeHash>,
    chain: &mut Vec<Mined>,
    first_coinbase: u64,
    want: u64,
) -> Filled {
    let have = closed_shards(scenario).await;
    assert!(
        have < want,
        "{have} shard(s) already closed; nothing to fill toward {want}"
    );
    let maturity = maturity();
    let w = SHARD_LENGTH.to_raw();

    // A sample spend of coinbase `first_coinbase`, matured, sizes the fill.
    // It is measured and dropped, not listed: the supply mined next ages
    // its reference past CEN-I11's window, and the first batch rebuilds it.
    mine_to(
        scenario,
        chain,
        BlockHeight::from_raw(first_coinbase + maturity),
    )
    .await;
    let mut spender = Spender::over(chain);
    let per_spend = spender
        .spend_coinbase(
            scenario.wallet(),
            BlockHeight::from_raw(first_coinbase),
            next_height(chain),
            FEE,
        )
        .archival_len()
        .to_raw();
    assert!(per_spend > 0, "a driven spend carries archival good");

    // The supply, mined ahead: enough coinbases that every fill block lists
    // a full batch. An upper bound — the bytes already folded are not
    // subtracted — so the fill never waits a block per spend; a surplus is
    // empty blocks, which cost a tenth of a second each.
    let spends_needed = ((want - have) * w).div_ceil(per_spend) + 1;
    let supply_through = first_coinbase + spends_needed + maturity;
    let before = chain.len();
    mine_to(scenario, chain, BlockHeight::from_raw(supply_through)).await;
    for block in &chain[before..] {
        spender.push(block);
    }

    let mut closed = Vec::new();
    let mut next_coinbase = first_coinbase;
    let mut pending: Vec<Transaction> = Vec::new();
    loop {
        let have_now = closed_shards(scenario).await;
        while closed.len() < usize::try_from(have_now - have).expect("small") {
            // The block just connected moved the count: the last block in
            // the chain closed shard `have + closed.len()`.
            closed.push(ClosedShard {
                shard: ShardId::from_raw(have + closed.len() as u64),
                close_height: chain.last().expect("a block connected").height,
            });
        }
        if have_now >= want {
            break;
        }
        let connecting = next_height(chain);
        // Coinbase `c` is spendable at `c + maturity`; the matured supply not
        // yet spent, bounded by the batch.
        let matured_through = connecting.to_raw().saturating_sub(maturity);
        let available = (matured_through + 1).saturating_sub(next_coinbase);
        let batch = usize::try_from(available)
            .expect("small")
            .min(SPENDS_PER_BLOCK - pending.len());
        if pending.is_empty() && batch == 0 {
            // The supply ran short of the bound: one empty block matures
            // one more coinbase.
            mine_to(scenario, chain, connecting + BlockCount::ONE).await;
            spender.push(chain.last().expect("mined"));
            continue;
        }
        let coinbases: Vec<u64> = (next_coinbase..next_coinbase + batch as u64).collect();
        next_coinbase += batch as u64;
        // The proofs are the cost; build the batch across the cores.
        let built: Vec<Transaction> = std::thread::scope(|s| {
            let handles: Vec<_> = coinbases
                .iter()
                .map(|&c| {
                    let spender = &spender;
                    let wallet = scenario.wallet();
                    s.spawn(move || {
                        spender.spend_coinbase(wallet, BlockHeight::from_raw(c), connecting, FEE)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("a spend builds"))
                .collect()
        });
        pending.extend(built);
        let listed = std::mem::take(&mut pending);
        let block = scenario
            .mine_listing(listed)
            .await
            .unwrap_or_else(|outcome| panic!("a fill block of real spends connects: {outcome}"));
        spender.push(&block);
        chain.push(block);
    }
    Filled { closed }
}

/// The first height at or after `from` such that it and the `following`
/// heights after it sit in one levered epoch and none of them is an epoch
/// close (the block at `last_block(E)`). A scenario whose join block and
/// the blocks after it must read posts, not a close, starts there.
pub fn inside_one_epoch(from: BlockHeight, following: u64) -> BlockHeight {
    inside_one_epoch_of(levered_schedule(), from, following)
}

/// [`inside_one_epoch`] under `schedule`.
pub fn inside_one_epoch_of(
    schedule: SettlementSchedule,
    from: BlockHeight,
    following: u64,
) -> BlockHeight {
    let blocks = schedule.blocks().get();
    let mut height = from.to_raw();
    while (0..=following).any(|k| (height + k + 1).is_multiple_of(blocks)) {
        height += 1;
    }
    BlockHeight::from_raw(height)
}

/// The first settlement epoch whose emission gather prices `close`'s
/// shard under `rules`: the first `w` whose slash pass — the block at
/// `slash_deadline_height(w)` — finds the shard closed **and final**
/// (`ARCHIVAL_SETTLEMENT_WRITER.md` `SO-D11f`). The pass's universe is the
/// shards final as of its parent, so it needs
/// `close_height + reorg_cap + 1 ≤ slash_deadline_height(w)`.
pub fn first_pricing_epoch(rules: &ChainRules, close: ClosedShard) -> u64 {
    let in_force = rules.in_force(close.close_height);
    let schedule = in_force.settlement_schedule();
    let final_for_a_pass_at = close.close_height.to_raw() + in_force.reorg_cap().to_raw() + 1;
    (0u64..)
        .find(|&w| schedule.slash_deadline_height(w) >= final_for_a_pass_at)
        .expect("a test chain's epochs are small")
}

/// The first height a compact JoinMarket onto `shard` connects at under
/// `rules` — CEN-J15's two post-close operands, read at the parent `P`:
///
/// - **final:** `close_height + reorg_cap ≤ P`;
/// - **priced:** `r_market(shard, w)` exists for `w`, the slash watermark
///   as of `P` (`SO-D11c`). The rows of epoch `w` are written by its slash
///   pass, over the shards final at that pass, so the first watermark that
///   prices the shard is [`first_pricing_epoch`] and `P` is at least that
///   pass's block. Every later pass prices it too.
///
/// The priced operand lifts last — a pass that sees the shard final is a
/// parent at which it is final — so the join lands on the block after
/// that pass. One block earlier the post is refused on J15.
pub fn first_admissible_compact_join(rules: &ChainRules, close: ClosedShard) -> BlockHeight {
    let schedule = rules.in_force(close.close_height).settlement_schedule();
    let pass = schedule.slash_deadline_height(first_pricing_epoch(rules, close));
    BlockHeight::from_raw(pass + 1)
}

#[cfg(test)]
mod settled_tests {
    use super::*;

    /// The settled epoch is the shortest that issues every pair its counted
    /// draws, and the levered one does not. The derivation and this check
    /// share the arithmetic, so the moved chains' own index assertions
    /// (rule 47) are the evidence the arithmetic is right. Red edits: search
    /// past the first epoch that works (a longer epoch is returned); accept
    /// an epoch that leaves shortfall (the levered epoch then passes).
    #[test]
    fn the_settled_epoch_is_the_shortest_that_issues_every_pair() {
        let blocks = settled_epoch_blocks();
        let step = shekyl_archival_retention::constants::W2_EPOCH_DIVISOR;
        assert!(
            (1..=SETTLED_PAIRS).all(|pairs| issues_every_pair(blocks, pairs)),
            "{blocks} blocks issue every pair"
        );
        assert!(
            !(1..=SETTLED_PAIRS).all(|pairs| issues_every_pair(blocks - step, pairs)),
            "{} blocks do not",
            blocks - step
        );
        assert!(
            !issues_every_pair(EPOCH_BLOCKS, 1),
            "the levered epoch is too short"
        );
        let _ = settled_rules();
    }
}
