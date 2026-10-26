// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Pop round trips over archival state (DRS-X PR 3e, e2; CEN-L7 and the
//! archival substrate cases the C++ pinned in `archival_substrate_lmdb`).
//!
//! One family: every block from the first join on is connected, popped and
//! connected again, and the store is read at each step. Popping a block puts
//! the store back to the state its parent left; connecting the same block
//! again derives the state the first connect wrote. "The store" is three
//! reads, each through the connector over the store itself, never a fold:
//!
//! - the archival snapshot, every family (`ArchivalState`): bonds with their
//!   claimed epochs and first paying height, serve credits, `R_market`,
//!   `Σwork`, budgets, slash log and applied slashes, the accruing budget and
//!   the slash watermark;
//! - the logical-state digest (`Digest`);
//! - every table as stored bytes (`TableRows`): settlements, the archival
//!   journals, the curve tree the drain grows (CEN-L11), the coins generated.
//!
//! The pop is compared exactly at every block but a pruning boundary. The
//! boundary batch (`prune_at_boundary`, at `E·SEB` for `E ≥ 2`: every
//! twentieth block on the levered schedule from block 40) deletes rows
//! below its floors and journals none of it, by design: the prunable halves
//! of old bodies (`txs_prunable`, `txs_pqc_auths`), the undo journal below
//! its floor and the floor itself (`properties`), the slash log and the
//! Release journal below theirs, the per-block draw and support rows, and
//! each per-epoch family below its epoch floor (`epoch_retire.rs`). Every
//! block that can connect after the boundary reads at or above those floors
//! (SI-32 refuses one that does not), so no pop needs the rows back. At a
//! boundary block, and in those tables and archival families only, a row the
//! pop left unlike its parent's must be what the connect left; a row the
//! popped block added must be gone, as everywhere. The reconnect retires the
//! same rows again and is compared whole.
//!
//! Two chains, because the archival events need two shapes of persona:
//!
//! - [`a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on`]
//!   is `scenario_emission_tests`'s frozen-membership chain: a compact
//!   persona and two complete trees join in one block, all three are Served
//!   for one epoch, one tree releases, the other is slashed, and the compact
//!   persona's claim connects at the first block of `served + W`, the
//!   boundary where the claimable rows below `served − 1` retire.
//! - [`a_slash_and_reinstate_chain_pops_and_reconnects_at_every_block_from_the_join_on`]
//!   is `archival_slash_tests`'s levered chain: a compact persona on two
//!   shards is slashed on the one it never served, reinstates, and releases
//!   at the cooldown's boundary. (A complete tree's slash is final, so the
//!   Reinstate needs a compact record.)
//!
//! Both fill shards with real proofs first (CEN-J15 admits a compact join
//! only onto closed shards), so both are minutes and run in nightly.yml's
//! chain-ingest-ignored job.

use shekyl_archival_retention::settlement_select::issued_draw_term;
use shekyl_archival_retention::{
    claim_window_floor, claimant_reward_share, epoch_close_compute, shard_contribution_micro,
    CreditPair, EmissionEpochSource, EpochCloseBond, EpochCloseInputs, EpochCloseShard, ShardClose,
    ShardWorkEntry, WorkEpochClaim, MAX_CLAIM_AGE_W, RELEASE_COOLDOWN_EPOCHS,
};
use shekyl_chain_rules::EpochFloor;
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFamily};
use shekyl_chain_store::store::RawRows;
use shekyl_types::archival::{
    FirstPayingHeight, IndexedDraw, IssuedDigest, IssuedDraw, SettlementOutcome,
};
use shekyl_types::{BlockCount, BlockHeight, ChainCount, SettlementEpoch, ShardId};
use shekyl_wire::Transaction;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::archival_driver::{first_spending_height, record_of, ENDPOINT, FEE};
use crate::connector::{ArchivalState, Inject, Injected, IssueDraws, Rewound};
use crate::emission_assembly::{assemble_emission_claim, ClaimTerms};
use crate::scenario::{FreeHash, Mined, NextBlock, Scenario};
use crate::scenario_archival::{complete_tree, shard_set, Persona};
use crate::scenario_shard::{
    close_shards, first_admissible_compact_join, inside_one_epoch, levered_rules, levered_schedule,
    EPOCH_BLOCKS,
};
use crate::source::ServeCredit;
use shekyl_harness_spender::{Owner, Recipient, Spender};

/// The fill spends coinbases from here up; the posts ride the ones below.
const FILL_FROM_COINBASE: u64 = 10;

/// `FAILURE_WINDOW_M`: the misses after which the pass slashes a pair.
const FAILURE_WINDOW: u64 = 11;

/// The claim's transaction key; the driver takes it as an argument.
const CLAIM_TX_KEY: [u8; 32] = [0x6c; 32];

/// The tables a pruning boundary's batch retires rows from (module docs).
const RETIRED_AT_A_BOUNDARY: &[&str] = &[
    "txs_prunable",
    "txs_pqc_auths",
    "undo_log",
    "properties",
    "archival_slash_log",
    "archival_release_journal",
    "archival_block_draws",
    "archival_support_block",
    "archival_sigma_work",
    "archival_complete_trees",
    "archival_budget",
    "archival_settlement",
    "archival_support_settlement",
    "archival_issued_draw",
    "archival_support_issued",
    "archival_issued_digest",
    "archival_drawable_digest",
    "archival_slash_applied",
    "archival_r_market",
];

/// The archival families those tables carry.
const FAMILIES_RETIRED_AT_A_BOUNDARY: &[SnapshotFamily] = &[
    SnapshotFamily::SigmaWork,
    SnapshotFamily::Budget,
    SnapshotFamily::RMarket,
    SnapshotFamily::SlashLog,
    SnapshotFamily::SlashApplied,
];

/// Whether the block at `height` runs the boundary batch on the levered
/// schedule: `E·SEB` with `E ≥ 2`.
fn is_pruning_boundary(height: BlockHeight) -> bool {
    let h = height.to_raw();
    h.is_multiple_of(EPOCH_BLOCKS) && h >= 2 * EPOCH_BLOCKS
}

/// The store at one tip, as the three reads give it.
struct Tip {
    height: BlockHeight,
    archival: ArchivalSnapshot,
    digest: crate::trace::Digest,
    rows: BTreeMap<&'static str, RawRows>,
}

/// Read the store at its tip.
async fn tip_of(scenario: &Scenario<FreeHash>) -> Tip {
    let facts = scenario.facts().await.expect("facts");
    Tip {
        height: BlockHeight::from_raw(facts.connecting.to_raw() - 1),
        archival: scenario
            .connector()
            .ask(ArchivalState)
            .await
            .expect("the archival snapshot"),
        digest: scenario.digest().await.expect("the digest"),
        rows: scenario.table_rows().await.expect("the rows"),
    }
}

/// `got` is the store `want` describes. A table one side never created and
/// the other emptied hold the same rows. With `retired`, `got` is the store
/// after a pop and `retired.0` the store the popped block's connect wrote:
/// in the tables `retired.1` names, a row of `want` that `got` lacks or holds
/// otherwise is accepted when `got` holds what the connect left there.
fn assert_same(step: &str, want: &Tip, got: &Tip, retired: Option<(&Tip, &[&str])>) {
    assert_eq!(got.height, want.height, "{step}: the tip");
    let diff = want.archival.diff(&got.archival);
    let diverged: Vec<_> = diff
        .diverged()
        .filter(|d| match retired {
            Some((connected, _)) if FAMILIES_RETIRED_AT_A_BOUNDARY.contains(&d.family) => {
                !left_as_retired(
                    want.archival.rows(d.family),
                    got.archival.rows(d.family),
                    connected.archival.rows(d.family),
                )
            }
            _ => true,
        })
        .collect();
    assert!(
        diverged.is_empty(),
        "{step}: archival families differ: {diverged:?}"
    );
    let index = |rows: &RawRows| -> BTreeMap<Vec<u8>, Vec<u8>> { rows.iter().cloned().collect() };
    let none = RawRows::new();
    let tables: std::collections::BTreeSet<&str> =
        want.rows.keys().chain(got.rows.keys()).copied().collect();
    let differ: Vec<&str> = tables
        .into_iter()
        .filter(|t| {
            let (w, g) = (
                want.rows.get(t).unwrap_or(&none),
                got.rows.get(t).unwrap_or(&none),
            );
            match retired {
                Some((connected, names)) if names.contains(t) => !left_as_retired(
                    &index(w),
                    &index(g),
                    &index(connected.rows.get(t).unwrap_or(&none)),
                ),
                _ => w != g,
            }
        })
        .collect();
    let detail: Vec<String> = differ
        .iter()
        .map(|t| {
            table_diff(
                t,
                want.rows.get(t).unwrap_or(&none),
                got.rows.get(t).unwrap_or(&none),
            )
        })
        .collect();
    assert!(
        differ.is_empty(),
        "{step}: tables differ: {differ:?}\n{}",
        detail.join("\n")
    );
    assert_eq!(got.digest, want.digest, "{step}: the digest");
}

/// A retiring table or family after a pop: every row `got` holds is
/// `want`'s, or is what `connected` holds for that key; every row of `want`
/// that `got` lacks, `connected` lacks too. A row only `got` and `connected`
/// hold — one the popped block added — fails.
fn left_as_retired(
    want: &BTreeMap<Vec<u8>, Vec<u8>>,
    got: &BTreeMap<Vec<u8>, Vec<u8>>,
    connected: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> bool {
    let held_rows_ok = got.iter().all(|(k, v)| match want.get(k) {
        Some(w) if w == v => true,
        Some(_) => connected.get(k) == Some(v),
        None => false,
    });
    let lacked_rows_ok = want
        .keys()
        .filter(|k| !got.contains_key(*k))
        .all(|k| !connected.contains_key(k));
    held_rows_ok && lacked_rows_ok
}

/// One table's difference, for the failure message: the row counts, then
/// up to four keys present on one side only or with unequal values.
fn table_diff(table: &str, want: &RawRows, got: &RawRows) -> String {
    let want: BTreeMap<&[u8], &[u8]> = want
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let got: BTreeMap<&[u8], &[u8]> = got
        .iter()
        .map(|(k, v)| (k.as_slice(), v.as_slice()))
        .collect();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let only_want: Vec<String> = want
        .keys()
        .filter(|k| !got.contains_key(*k))
        .take(4)
        .map(|k| hex(k))
        .collect();
    let only_got: Vec<String> = got
        .keys()
        .filter(|k| !want.contains_key(*k))
        .take(4)
        .map(|k| hex(k))
        .collect();
    let unequal: Vec<String> = want
        .iter()
        .filter_map(|(k, v)| {
            got.get(k)
                .filter(|g| *g != v)
                .map(|g| format!("{}: {} -> {}", hex(k), hex(v), hex(g)))
        })
        .take(4)
        .collect();
    format!(
        "  {table}: {} rows wanted, {} held; only wanted {only_want:?}; only held {only_got:?}; unequal {unequal:?}",
        want.len(),
        got.len()
    )
}

/// A scenario whose every block, once connected, is popped and connected
/// again before the next is built.
struct RoundTrips {
    scenario: Scenario<FreeHash>,
    chain: Vec<Mined>,
    tip: Tip,
    /// Blocks round-tripped.
    trips: u64,
    /// Of them, pruning boundaries.
    boundaries: u64,
    /// Round-tripped blocks that closed an epoch: at a zero budget, and
    /// with one.
    closes: [u64; 2],
}

impl RoundTrips {
    async fn start(scenario: Scenario<FreeHash>, chain: Vec<Mined>) -> Self {
        let tip = tip_of(&scenario).await;
        Self {
            scenario,
            chain,
            tip,
            trips: 0,
            boundaries: 0,
            closes: [0, 0],
        }
    }

    /// The height of the next block.
    fn height(&self) -> BlockHeight {
        BlockHeight::from_raw(u64::try_from(self.chain.len()).expect("a height"))
    }

    /// A spender over the chain as it stands.
    fn spender(&self) -> Spender {
        Spender::over(&self.chain)
    }

    /// Connect the next block listing `listed`; pop it and assert the store
    /// is its parent's; connect it again and assert the store is what the
    /// first connect wrote.
    async fn mine(&mut self, listed: Vec<Transaction>) -> Mined {
        let block = self
            .scenario
            .mine_listing(listed)
            .await
            .unwrap_or_else(|outcome| panic!("block {} connects: {outcome}", self.height()));
        let connected = tip_of(&self.scenario).await;
        let parent = self.tip.height;
        assert_eq!(block.height, parent + BlockCount::ONE);
        let rewound = self
            .scenario
            .rewind_to(parent)
            .await
            .expect("the rewind answers");
        assert!(
            matches!(rewound, Rewound::Popped { popped: 1, .. }),
            "block {} pops: {rewound:?}",
            block.height
        );
        let popped = tip_of(&self.scenario).await;
        assert_same(
            &format!("popping block {}", block.height),
            &self.tip,
            &popped,
            is_pruning_boundary(block.height).then_some((&connected, RETIRED_AT_A_BOUNDARY)),
        );
        let again = self
            .scenario
            .connect_template(NextBlock {
                height: block.height,
                template: block.template.clone(),
                seed: block.seed,
                target: block.target,
            })
            .await
            .unwrap_or_else(|outcome| panic!("block {} reconnects: {outcome}", block.height));
        assert_eq!(again.hash, block.hash, "the same block");
        assert_eq!(again.archival, block.archival, "the same delta");
        let reconnected = tip_of(&self.scenario).await;
        assert_same(
            &format!("reconnecting block {}", block.height),
            &connected,
            &reconnected,
            None,
        );
        if let Some(close) = again.archival.close() {
            self.closes[usize::from(close.budget().to_raw() != 0)] += 1;
        }
        self.trips += 1;
        self.boundaries += u64::from(is_pruning_boundary(block.height));
        self.tip = connected;
        self.chain.push(again.clone());
        again
    }

    /// Empty blocks until `to` is the next height.
    async fn mine_to(&mut self, to: BlockHeight) {
        while self.height() < to {
            self.mine(Vec::new()).await;
        }
    }

    /// Issue `epoch`'s draws on `shard`: three per persona at the epoch's
    /// first heights, passed or not. One call per epoch: the door writes
    /// the epoch's digest whole.
    async fn issue(&mut self, epoch: SettlementEpoch, draws_of: &[(PersonaId, ShardId, bool)]) {
        let open = levered_schedule().open_height(epoch.to_raw());
        let mut digest = IssuedDigest::ZERO;
        let mut draws = Vec::new();
        for &(persona, shard, passed) in draws_of {
            for k in 0..3u64 {
                let issuing_height = BlockHeight::from_raw(open + k);
                digest.fold(&issued_draw_term(&persona, shard, epoch, issuing_height, 0));
                draws.push(IndexedDraw {
                    persona,
                    shard,
                    issuing_height,
                    draw: 0,
                    state: IssuedDraw {
                        revealed_at: BlockHeight::from_raw(open + k + 1),
                        passed,
                    },
                });
            }
        }
        self.scenario
            .connector()
            .ask(IssueDraws {
                epoch,
                draws,
                digest,
            })
            .await
            .expect("the door issues the draws");
        self.reread().await;
    }

    /// Read the tip again after a write outside a block (the draw door, the
    /// credit injector), so the next pop is compared against it.
    async fn reread(&mut self) {
        self.tip = tip_of(&self.scenario).await;
    }
}

type PersonaId = shekyl_types::PCanonicalId;

/// Feed `spender` every block of `chain` it has not seen.
fn catch_up(spender: &mut Spender, chain: &[Mined], seen: &mut usize) {
    for block in &chain[*seen..] {
        spender.push(block);
    }
    *seen = chain.len();
}

/// The claim chain (module docs), every block from the joins on popped and
/// reconnected.
///
/// Events round-tripped, in chain order: three joins in one block at a
/// non-zero epoch; the drain of their funding outputs into the tree ten
/// blocks later (CEN-L11); each epoch's close; `served`'s pass (settlements, `R_market`, `Σwork`, the frozen
/// complete-tree set); a Release; a slash, whose pop is its revert; the
/// claim at the first block of `served + W`, which sets the first paying
/// height once and is the block whose batch retires the claimable rows
/// below `served − 1`. Popping the claim and connecting it again mints once:
/// the record names the epoch once and the coins generated at the tip are
/// the first connect's.
///
/// Supersedes, from `archival_substrate_lmdb` at `eb5be7767`:
/// `bond_post_connect_pop_roundtrip_through_real_block_path` (a join at a
/// non-zero epoch), `release_connect_pop_roundtrip_through_real_block_path`,
/// `budget_close_row_revert_and_reclose_symmetry` (close rows; its
/// zero-budget row has no driven witness, since every close here carries the
/// staker emission), `emission_snapshot_identity_and_descriptor_immunity`
/// (`Σwork` read from the store at each tip),
/// `emission_claim_first_paying_set_once_and_pop_symmetric`,
/// `emission_claim_apply_journal_and_revert_roundtrip`,
/// `emission_connect_pop_roundtrip_through_real_block_path` and
/// `emission_claim_prune_straddle_no_double_mint`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills a shard with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn a_claim_chain_pops_and_reconnects_at_every_block_from_the_joins_on() {
    let rules = levered_rules();
    let schedule = levered_schedule();
    let mut scenario = Scenario::open_under("archival-pop-claim", FreeHash, rules);
    let mut mined = scenario.mine(first_spending_height().to_raw()).await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 1).await;
    let [closed] = filled.closed.as_slice() else {
        panic!("one shard closed");
    };
    let join_height = inside_one_epoch(first_admissible_compact_join(&rules, *closed), 1);
    crate::scenario_shard::mine_to(&mut scenario, &mut mined, join_height).await;
    let mut chain = RoundTrips::start(scenario, mined).await;

    let persona = Persona::at(1);
    let released = Persona::at(2);
    let slashed = Persona::at(3);
    let recipient = Recipient::persona(persona.keys());
    // One spender for the persona's own outputs, fed every block from here
    // on: it watches the keys it is told to own from the block that pays
    // them.
    let mut spender = chain.spender();
    let mut seen = chain.chain.len();
    let (joins, backing_key, fee_key) = {
        let funding = spender.spend_coinbase_to(
            chain.scenario.wallet(),
            BlockHeight::ZERO,
            join_height,
            FEE,
            Some(&persona.join(shard_set(vec![0]), ENDPOINT)),
            &recipient,
        );
        let backing_key = funding.prefix.outputs[0].key;
        let fee_key = funding.prefix.outputs[1].key;
        spender.own(backing_key);
        spender.own(fee_key);
        let trees: Vec<Transaction> = [&released, &slashed]
            .into_iter()
            .zip(1u64..)
            .map(|(tree, coinbase)| {
                spender.spend_coinbase_posting(
                    chain.scenario.wallet(),
                    BlockHeight::from_raw(coinbase),
                    join_height,
                    FEE,
                    Some(&tree.join(complete_tree(), ENDPOINT)),
                )
            })
            .collect();
        ([vec![funding], trees].concat(), backing_key, fee_key)
    };
    let joined = chain.mine(joins).await;
    assert_eq!(joined.height, join_height);
    assert_eq!(joined.archival.records().len(), 3, "three joins");
    let join_epoch = schedule.epoch_at(join_height);
    assert!(join_epoch.to_raw() > 0, "the joins are at a non-zero epoch");
    let served = SettlementEpoch::from_raw(join_epoch.to_raw() + 1);
    let shard = ShardId::from_raw(0);

    // `served`: every pair passes. Then eleven epochs in which the second
    // tree alone is drawn and fails, so the pass of the eleventh slashes it.
    let all = [persona.id(), released.id(), slashed.id()];
    let passing: Vec<_> = all.iter().map(|p| (*p, shard, true)).collect();
    chain.issue(served, &passing).await;
    let slash_epoch = SettlementEpoch::from_raw(served.to_raw() + FAILURE_WINDOW);
    for raw in (served.to_raw() + 1)..=slash_epoch.to_raw() {
        chain
            .issue(
                SettlementEpoch::from_raw(raw),
                &[(slashed.id(), shard, false)],
            )
            .await;
    }

    // Through `served`'s pass.
    let at_pass = BlockHeight::from_raw(schedule.slash_deadline_height(served.to_raw()));
    chain.mine_to(at_pass + BlockCount::ONE).await;
    let count_at_close = (served.to_raw() + 1) * EPOCH_BLOCKS;
    let close = *chain.chain[usize::try_from(count_at_close - 1).expect("small")]
        .archival
        .close()
        .expect("the block that completes the epoch carries its close");
    let pass = chain.chain[usize::try_from(at_pass.to_raw()).expect("small")]
        .archival
        .clone();
    let mut settled: Vec<_> = pass
        .settlements()
        .iter()
        .map(|s| (s.persona, s.row.outcome()))
        .collect();
    settled.sort_unstable_by_key(|(persona, _)| *persona);
    let mut expected: Vec<_> = all
        .iter()
        .map(|p| (*p, SettlementOutcome::Served))
        .collect();
    expected.sort_unstable_by_key(|(persona, _)| *persona);
    assert_eq!(settled, expected, "all three pairs settled Served");
    let gather = pass
        .gathers()
        .iter()
        .find(|g| g.epoch() == served)
        .expect("the pass gathers the epoch it settles");

    // `Σwork(served)` read from the store, not the fold: the snapshot every
    // round trip compared carries it, and the store answers it by key.
    let stored_sigma = chain
        .scenario
        .with_store(|store, _| {
            store
                .begin_read()
                .expect("a snapshot")
                .sigma_work(served, EpochFloor::NONE)
                .expect("the read")
        })
        .await
        .expect("Σwork(served) is a row after the pass");
    assert_eq!(stored_sigma, gather.sigma_work());

    // The arithmetic the pass did: three credited bonds, the two trees out
    // of the market.
    let bond = |complete| EpochCloseBond {
        join_settlement_epoch: join_epoch.to_raw(),
        is_support_complete_tree: complete,
        bad_intervals: &[],
    };
    let bonds = [bond(false), bond(true), bond(true)];
    let shards = [EpochCloseShard {
        shard_id: 0,
        close: ShardClose::ClosedAt(closed.close_height),
    }];
    let pairs: Vec<CreditPair> = (0..bonds.len())
        .map(|bond_idx| CreditPair {
            bond_idx,
            shard_idx: 0,
        })
        .collect();
    let inputs = EpochCloseInputs::under_schedule(
        schedule,
        served.to_raw(),
        count_at_close,
        &bonds,
        &shards,
        &pairs,
    );
    let result = epoch_close_compute(&inputs).expect("the pairs index their bonds and shard");
    assert_eq!(gather.sigma_work().to_raw(), result.sigma_work_milli);
    let share = claimant_reward_share(&EmissionEpochSource {
        inputs: inputs.clone(),
        persisted_sigma_work_milli: result.sigma_work_milli,
        claimant_bond_idx: Some(0),
        budget: close.budget().to_raw(),
    })
    .expect("the claimant indexes its bond");
    assert!(
        share.is_member && share.reward > 0,
        "the server is owed a share"
    );
    let scarcity = shard_contribution_micro(&inputs, &result.r_market_by_shard, 0);

    // The Release, in the block after the pass.
    let release = released.release(
        record_of(&chain.scenario, &released)
            .await
            .bonded_total
            .to_raw(),
    );
    catch_up(&mut spender, &chain.chain, &mut seen);
    let releasing = spender.spend_coinbase_posting(
        chain.scenario.wallet(),
        BlockHeight::from_raw(3),
        chain.height(),
        FEE,
        Some(&release),
    );
    let block = chain.mine(vec![releasing]).await;
    assert_eq!(block.archival.records().len(), 1, "the release's write");

    // Through the eleventh miss's pass: the slash.
    let slash_height = BlockHeight::from_raw(schedule.slash_deadline_height(slash_epoch.to_raw()));
    chain.mine_to(slash_height + BlockCount::ONE).await;
    let slashes = chain.chain[usize::try_from(slash_height.to_raw()).expect("small")]
        .archival
        .slashes();
    assert_eq!(slashes.len(), 1, "one slash, at the eleventh miss's pass");
    assert_eq!(slashes[0].entry.persona, slashed.id());

    // The claim, at the first block of `served + W`: `served` is the oldest
    // claimable epoch there, and that block's batch retires below it.
    let connecting = BlockHeight::from_raw(schedule.open_height(served.to_raw() + MAX_CLAIM_AGE_W));
    assert_eq!(
        claim_window_floor(schedule.epoch_at(connecting).to_raw()),
        served.to_raw(),
        "`served` is the oldest claimable epoch at the claim"
    );
    chain.mine_to(connecting).await;
    let relay_floor = chain
        .scenario
        .read_chain(|view, _| {
            let next = shekyl_chain_rules::Tip::connecting_height(
                shekyl_chain_rules::HeaderView::tip(view)
                    .expect("tip")
                    .as_ref(),
            );
            match shekyl_chain_rules::relay_floor_window(view, next).expect("floors") {
                shekyl_chain_rules::AtHeight::Recorded(floors) => {
                    floors.into_iter().min().expect("a window")
                }
                shekyl_chain_rules::AtHeight::AboveTip => unreachable!("the connecting height"),
            }
        })
        .await;
    catch_up(&mut spender, &chain.chain, &mut seen);
    let claim_tx = {
        let owner = Owner::persona(persona.keys());
        let terms = ClaimTerms {
            holdings: shard_set(vec![0]),
            settlement_epochs: vec![served.to_raw()],
            work_claim: vec![WorkEpochClaim {
                epoch: served.to_raw(),
                shard_entries: vec![ShardWorkEntry {
                    shard_id: 0,
                    serve_credit_bit: true,
                    scarcity_micro: u32::try_from(scarcity).expect("a per-entry term fits"),
                }],
            }],
            reward_amount_plain: vec![share.reward],
        };
        let mut fee = FEE;
        let mut priced = None;
        for _ in 0..8 {
            let backing = spender.owned_input(&owner, backing_key, connecting);
            let fee_input = spender.owned_input(&owner, fee_key, connecting);
            let claim = assemble_emission_claim(
                persona.keys(),
                &Zeroizing::new(CLAIM_TX_KEY),
                vec![fee_input.input],
                backing.input,
                terms.clone(),
                fee,
                &backing.tree,
            );
            let tx = Transaction::from_bytes(&claim.bytes).expect("the claim parses");
            let weight = u64::try_from(tx.weight()).expect("a weight fits");
            let needed = shekyl_economics::quantized_fee(weight, relay_floor).expect("priceable");
            if needed <= fee {
                priced = Some(tx);
                break;
            }
            fee = needed;
        }
        priced.expect("the claim's floor price settles")
    };
    let generated_before = chain
        .scenario
        .facts()
        .await
        .expect("facts")
        .parent_coins_generated;
    let claimed = chain.mine(vec![claim_tx]).await;
    assert_eq!(claimed.height, connecting);
    let record = record_of(&chain.scenario, &persona).await;
    assert_eq!(
        record.claimed_settlement_epochs,
        vec![served],
        "after the pop and the reconnect the record names the epoch once"
    );
    assert_eq!(
        record.first_paying_emission_height,
        FirstPayingHeight::new(connecting),
        "the first paying height is the claim's, set once"
    );
    let generated_after = chain
        .scenario
        .facts()
        .await
        .expect("facts")
        .parent_coins_generated;
    assert_eq!(
        generated_after, claimed.emission.coins_generated,
        "the coins generated at the tip are the claim block's, across its pop and reconnect"
    );
    assert_eq!(
        generated_after.to_raw() - generated_before.to_raw(),
        claimed.emission.paid.to_raw(),
        "the claim block minted once"
    );

    // Every close here has a budget: the staker emission accrues on every
    // block, so a driven chain closes no epoch at zero.
    assert_eq!(chain.closes[0], 0, "no close at a zero budget");
    assert!(chain.closes[1] > 0, "closes were round-tripped");
    eprintln!(
        "claim chain: {} blocks round-tripped ({} pruning boundaries), {} closes with a zero budget, {} with one",
        chain.trips, chain.boundaries, chain.closes[0], chain.closes[1]
    );
    chain.scenario.close().await;
}

/// The slash-and-reinstate chain (module docs), every block from the join
/// on popped and reconnected: a compact join on two shards at a non-zero
/// epoch; its first serve credit; eleven epochs of settlements, passed on one
/// shard and missed on the other, with injected credits; the slash, whose
/// pop is its revert; the Reinstate that closes the interval; the release
/// at the cooldown's boundary.
///
/// Supersedes, from `archival_substrate_lmdb` at `eb5be7767`:
/// `bond_post_connect_pop_roundtrip_through_real_block_path` (the compact
/// join), `same_epoch_slashes_coalesce_one_open_interval` (the slash and its
/// revert), `reinstate_standing_only_zero_credit_roundtrip` and
/// `release_connect_pop_roundtrip_through_real_block_path`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fills two shards with real proofs; minutes; run by nightly.yml's chain-ingest-ignored job"]
async fn a_slash_and_reinstate_chain_pops_and_reconnects_at_every_block_from_the_join_on() {
    let rules = levered_rules();
    let schedule = levered_schedule();
    let mut scenario = Scenario::open_under("archival-pop-reinstate", FreeHash, rules);
    let mut mined = scenario
        .mine(ChainCount::from_next_height(first_spending_height()).to_raw())
        .await;
    let filled = close_shards(&mut scenario, &mut mined, FILL_FROM_COINBASE, 2).await;
    let admissible = filled
        .closed
        .iter()
        .map(|&close| first_admissible_compact_join(&rules, close))
        .max()
        .expect("two shards closed");
    crate::scenario_shard::mine_to(&mut scenario, &mut mined, admissible).await;
    let mut chain = RoundTrips::start(scenario, mined).await;

    let persona = Persona::at(11);
    let (served, unserved) = (ShardId::from_raw(1), ShardId::from_raw(0));
    let join_height = chain.height();
    let join_epoch = schedule.epoch_at_height(join_height.to_raw());
    assert!(join_epoch > 0, "the join is at a non-zero epoch");
    let joining = chain.spender().spend_coinbase_posting(
        chain.scenario.wallet(),
        BlockHeight::ZERO,
        join_height,
        FEE,
        Some(&persona.join(
            shard_set(vec![unserved.to_raw(), served.to_raw()]),
            ENDPOINT,
        )),
    );
    let joined = chain.mine(vec![joining]).await;
    assert_eq!(joined.archival.records().len(), 1, "the join");

    let credited = chain
        .mine(vec![persona.serve_credit(served.to_raw(), join_epoch + 1)])
        .await;
    assert_eq!(credited.archival.serve_credits().len(), 1);

    for epoch in (join_epoch + 1)..=(join_epoch + FAILURE_WINDOW) {
        chain
            .issue(
                SettlementEpoch::from_raw(epoch),
                &[
                    (persona.id(), served, true),
                    (persona.id(), unserved, false),
                ],
            )
            .await;
    }
    for epoch in (join_epoch + 2)..=(join_epoch + FAILURE_WINDOW) {
        let Injected { .. } = chain
            .scenario
            .connector()
            .ask(Inject(ServeCredit {
                persona: persona.id(),
                shard: served,
                epoch: SettlementEpoch::from_raw(epoch),
            }))
            .await
            .expect("the injector writes");
    }
    chain.reread().await;
    let slash_epoch = join_epoch + FAILURE_WINDOW;
    let deadline = schedule.slash_deadline_height(slash_epoch);
    chain.mine_to(BlockHeight::from_raw(deadline + 1)).await;
    let slashing = &chain.chain[usize::try_from(deadline).expect("small")].archival;
    assert_eq!(
        slashing.slashes().len(),
        1,
        "one slash, in the deadline block"
    );
    assert_eq!(slashing.slashes()[0].entry.shard, unserved);
    let slashed = record_of(&chain.scenario, &persona).await;

    let reinstating = chain.spender().spend_coinbase_posting(
        chain.scenario.wallet(),
        BlockHeight::from_raw(1),
        chain.height(),
        FEE,
        Some(&persona.reinstate(&slashed)),
    );
    let reinstate_epoch = schedule.epoch_at_height(chain.height().to_raw());
    let reinstated = chain.mine(vec![reinstating]).await;
    assert_eq!(reinstated.archival.records().len(), 1, "the reinstate");
    assert_eq!(
        reinstated.archival.records()[0].record().bonded_total,
        slashed.bonded_total,
        "zero money"
    );

    // The release at the cooldown's boundary over the served anchor, as
    // `archival_slash_tests` places it.
    let anchor = reinstate_epoch + 1;
    let boundary = schedule.slash_deadline_height(anchor);
    assert_eq!(
        schedule.epoch_at_height(boundary + 1),
        anchor + RELEASE_COOLDOWN_EPOCHS,
        "the block after the anchor's deadline opens the cooldown's boundary epoch"
    );
    chain
        .mine(vec![
            persona.serve_credit(served.to_raw(), anchor),
            persona.serve_credit(unserved.to_raw(), anchor),
        ])
        .await;
    chain.mine_to(BlockHeight::from_raw(boundary + 1)).await;
    let stored = record_of(&chain.scenario, &persona).await;
    let releasing = chain.spender().spend_coinbase_posting(
        chain.scenario.wallet(),
        BlockHeight::from_raw(2),
        chain.height(),
        FEE,
        Some(&persona.release(stored.bonded_total.to_raw())),
    );
    let released = chain.mine(vec![releasing]).await;
    assert_eq!(released.archival.records().len(), 1, "the release");
    assert_eq!(
        released.archival.records()[0]
            .record()
            .bonded_total
            .to_raw(),
        0
    );

    eprintln!(
        "slash-and-reinstate chain: {} blocks round-tripped ({} pruning boundaries)",
        chain.trips, chain.boundaries
    );
    chain.scenario.close().await;
}
