// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The switch through the production stack (DRS-E5 a5;
//! `DRS_E5_POOL_ALT_PRUNE.md` §2.3): two drivers mine the same prefix and
//! then different branches; one driver's blocks arrive at the other as
//! alternatives. A switch is correct when nothing is left over — the store
//! that switched equals the store that connected the winning branch
//! directly, digest for digest.

use shekyl_types::{BlockHash, BlockHeight};

use crate::connector::{Offered, PlanMismatchReason, RunFault, Switched};
use crate::scenario::{FreeHash, Mined, Scenario};

/// A driver over a fresh store with `prefix` empty blocks.
async fn with_prefix(name: &str, prefix: u64) -> Scenario<FreeHash> {
    let mut s = Scenario::open(name);
    s.mine(prefix).await;
    s
}

/// Offer every block of `branch`; every offer but the last must be held,
/// and the last must name a switch. Returns that plan.
async fn offer_branch(x: &Scenario<FreeHash>, branch: &[Mined]) -> crate::SwitchPlan {
    let (last, held) = branch.split_last().expect("a branch");
    for mined in held {
        match x.offer(mined).await.expect("offer") {
            Offered::Held { height } => assert_eq!(height, mined.height),
            other => panic!("block {:?} not held: {other:?}", mined.height),
        }
    }
    match x.offer(last).await.expect("offer") {
        Offered::SwitchDue(plan) => plan,
        other => panic!("the heavier tip did not name a switch: {other:?}"),
    }
}

const PREFIX: u64 = 5;

#[tokio::test]
async fn a_heavier_branch_switches_and_equals_the_branch_connected_directly() {
    let mut x = with_prefix("switch-direct-x", PREFIX).await;
    let mut y = with_prefix("switch-direct-y", PREFIX).await;
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    assert_ne!(
        a[0].hash, b[0].hash,
        "the branches differ from the first block"
    );

    // Equal work keeps the incumbent (K6): B's third block ties A's tip.
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.root.height, BlockHeight::from_raw(PREFIX - 1));
    assert_eq!(plan.demoted.len(), 3);
    assert_eq!(plan.promoted.len(), 4);

    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert_eq!(
        done.demoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        a.iter().map(|m| m.hash).collect::<Vec<_>>()
    );
    assert_eq!(
        done.promoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        b.iter().map(|m| m.hash).collect::<Vec<_>>()
    );

    // Nothing left over: the store that switched is the store that
    // connected B directly, and its alt table is exactly A.
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    assert_same_chain(&x, &y, &a.iter().collect::<Vec<_>>(), "A → B equals B").await;

    // The demoted blocks are alt rows now (K7), and the promoted rows are
    // gone: three held, B's four removed.
    assert_eq!(x.alt_blocks_held().await.expect("al6"), 3);
    // Offering one again finds it held.
    assert!(matches!(
        x.offer(&a[0]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn switching_back_restores_the_chain_that_never_switched() {
    let mut x = with_prefix("switch-back-x", PREFIX).await;
    let mut y = with_prefix("switch-back-y", PREFIX).await;
    let mut z = with_prefix("switch-back-z", PREFIX).await;
    let a = x.mine(3).await;
    let a_again = z.mine(3).await;
    assert_eq!(
        a.iter().map(|m| m.hash).collect::<Vec<_>>(),
        a_again.iter().map(|m| m.hash).collect::<Vec<_>>(),
        "the driver is deterministic: z re-mines x's branch"
    );
    let a_ext = z.mine(2).await;
    y.idle();
    let b = y.mine(4).await;

    let plan = offer_branch(&x, &b).await;
    assert!(matches!(
        x.reorganize(&plan).await.expect("switch"),
        Switched::Done(_)
    ));
    // A, extended past B, arrives: its first three blocks are held from the
    // demotion, the extension ties then wins.
    let plan = offer_branch(&x, &a_ext).await;
    assert_eq!(
        plan.promoted.len(),
        5,
        "A's three demoted rows and its two new blocks"
    );
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch back") else {
        panic!("the switch back did not land");
    };
    assert_eq!(done.demoted.len(), 4, "B's four blocks");
    assert_eq!(x.digest().await.expect("d"), z.digest().await.expect("d"));
    x.close().await;
    y.close().await;
    z.close().await;
}

#[tokio::test]
async fn an_orphan_is_unlinked_and_an_extension_is_not_an_alternative() {
    let mut x = with_prefix("switch-arms-x", PREFIX).await;
    let mut y = with_prefix("switch-arms-y", PREFIX).await;
    y.idle();
    let b = y.mine(2).await;
    // b[1]'s parent is b[0], which x has never seen.
    match x.offer(&b[1]).await.expect("offer") {
        Offered::Unlinked { at } => assert_eq!(at, b[0].hash),
        other => panic!("an orphan was not unlinked: {other:?}"),
    }
    // A block on x's own tip is an extension: a driver defect, the writer
    // stays up.
    let mut w = with_prefix("switch-arms-w", PREFIX).await;
    let ext = w.mine(1).await;
    assert!(matches!(
        x.offer(&ext[0]).await,
        Err(RunFault::NotAlternative { .. })
    ));
    assert!(x.mine(1).await.len() == 1, "the writer is up");
    x.close().await;
    y.close().await;
    w.close().await;
}

#[tokio::test]
async fn a_promoted_block_that_fails_validate_rolls_back_and_removes_its_suffix() {
    let mut x = with_prefix("switch-refused-x", PREFIX).await;
    let mut y = with_prefix("switch-refused-y", PREFIX).await;
    x.mine(2).await;
    y.idle();
    let mut b = y.mine(3).await;
    // B's tip commits to a tree root its chain does not hold: the cheap
    // tier reads no chain state and admits it; promotion's `validate`
    // (CEN-B5) refuses it.
    let tip = b.last_mut().expect("tip");
    tip.template.block.header.curve_tree_root = shekyl_types::CurveTreeRoot::from_bytes([0x42; 32]);
    tip.hash = tip.template.block.hash();
    let before = x.digest().await.expect("d");

    let plan = offer_branch(&x, &b).await;
    match x.reorganize(&plan).await.expect("switch") {
        Switched::Refused {
            hash,
            refused,
            removed,
            ..
        } => {
            assert_eq!(hash, b[2].hash);
            assert_eq!(
                refused.rule,
                shekyl_chain_rules::CenRow::B5,
                "promotion's root check refused it"
            );
            assert_eq!(
                removed,
                vec![b[2].hash],
                "the refused block and nothing below it"
            );
        }
        other => panic!("the refusal did not roll back: {other:?}"),
    }
    assert_eq!(
        x.digest().await.expect("d"),
        before,
        "the main chain is the pre-switch chain"
    );
    // The suffix below the refused block is still held.
    assert!(matches!(
        x.offer(&b[0]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    x.close().await;
    y.close().await;
}

/// Switch `x` (which mines `depth` blocks above the prefix) onto `y`'s
/// heavier branch of `depth + 1`. Returns both branches, the deep-reorg
/// record and the following-degraded latch after the switch.
async fn switch_of_depth(
    name: &str,
    depth: usize,
) -> (
    Vec<Mined>,
    Vec<Mined>,
    Option<crate::connector::DeepReorg>,
    Option<shekyl_chain_store::codec::FollowingDegraded>,
) {
    let mut x = with_prefix(&format!("{name}-x"), PREFIX).await;
    let mut y = with_prefix(&format!("{name}-y"), PREFIX).await;
    let count = u64::try_from(depth).expect("fits");
    let a = x.mine(count).await;
    y.idle();
    let b = y.mine(count + 1).await;
    let plan = offer_branch(&x, &b).await;
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert_eq!(done.demoted.len(), depth, "the switch popped {depth}");
    let record = x.last_deep_reorg().await;
    let latch = x.following_degraded().await;
    x.close().await;
    y.close().await;
    (a, b, record, latch)
}

/// S1's deep-reorg event: a switch that pops exactly the lock window leaves
/// no record; one block deeper writes the record (depth, fork height, the
/// tips it left and connected) and leaves `following_degraded` clear, so a
/// persona still reads the daemon as following. The window is
/// `shekyl_consensus::DEFAULT_LOCK_WINDOW`, never restated.
#[tokio::test]
async fn a_switch_deeper_than_the_lock_window_is_recorded_and_the_node_still_follows() {
    let window = shekyl_consensus::DEFAULT_LOCK_WINDOW;
    let (_, _, record, latch) = switch_of_depth("switch-deep-at", window).await;
    assert_eq!(
        record, None,
        "a switch of exactly the window leaves no record"
    );
    assert_eq!(latch, None);

    let (a, b, record, latch) = switch_of_depth("switch-deep-past", window + 1).await;
    assert_eq!(
        record,
        Some(crate::connector::DeepReorg {
            depth: shekyl_types::BlockCount::from_raw(u64::try_from(window + 1).expect("fits")),
            fork_at: BlockHeight::from_raw(PREFIX - 1),
            old_tip: a.last().expect("A").hash,
            new_tip: b.last().expect("B").hash,
        }),
        "one block deeper records the switch it made"
    );
    assert_eq!(
        latch, None,
        "a deep reorganization the node followed does not mark it degraded"
    );
}

/// Rewrite the recorded blocks at `heights` (all below a fork point) with
/// timestamp `at`, keeping each row's identity coherent: the blob,
/// `block_info`'s hash and timestamp, and the hash index all name the
/// rewritten block, so the reads that check a blob against its recorded
/// identity (CEN-B6) pass. The links into those heights from above still
/// name the old blocks, which nothing on the switch path re-reads: the
/// alternative chain links to the root, and the demoted blocks' history is
/// read by height. The links cannot all be made coherent: cascading
/// `prev_id` upward reaches the root, and a root with a new identity is no
/// longer the block the alternative chain links to. The tier reads
/// timestamps from the header in the blob, not from `block_info`, so the
/// blob has to change. What is left is a recorded chain whose next block
/// fails its own timestamp rule: the store SI-27 is for. The test asserts
/// that exact row at that height, so a fault from anything else fails it.
fn rewrite_timestamps(path: &std::path::Path, heights: &[BlockHeight], at: u64) {
    use redb::ReadableTable;
    use shekyl_chain_store::codec::{BlockBody, BlockInfo};
    use shekyl_chain_store::codec::{Canonical, Raw};
    use shekyl_chain_store::lmdb_order::LmdbHashKey;
    use shekyl_chain_store::schema::{BLOCKS, BLOCK_HEIGHTS, BLOCK_INFO};
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut blocks = txn.open_table(BLOCKS).expect("blocks");
        let mut infos = txn.open_table(BLOCK_INFO).expect("block_info");
        let mut index = txn.open_table(BLOCK_HEIGHTS).expect("block_heights");
        for &height in heights {
            let raw = height.to_raw();
            let bytes = blocks
                .get(raw)
                .expect("g")
                .expect("a recorded block")
                .value()
                .bytes()
                .to_vec();
            let mut block = shekyl_wire::Block::from_bytes(&bytes).expect("parses");
            let old = block.hash();
            block.header.timestamp = at;
            let new = block.hash();
            blocks
                .insert(raw, Raw::<BlockBody>::new(&block.serialize()))
                .expect("blob");
            let mut info: BlockInfo = infos
                .get(raw)
                .expect("g")
                .expect("row")
                .value()
                .decode()
                .expect("decodes");
            assert_eq!(info.hash, old, "the row named the block");
            info.hash = new;
            info.timestamp = shekyl_types::Timestamp::from_raw(at);
            infos
                .insert(raw, info.encoded().as_encoded())
                .expect("info");
            index
                .remove(LmdbHashKey::from_bytes(old.to_bytes()))
                .expect("old key");
            index
                .insert(
                    LmdbHashKey::from_bytes(new.to_bytes()),
                    height.encoded().as_encoded(),
                )
                .expect("new key");
        }
    }
    txn.commit().expect("commit");
}

#[tokio::test]
async fn a_demoted_block_the_tier_refuses_halts_the_writer_si27() {
    // SI-27: a recorded block passes its own cheap tier. Between the plan
    // and the switch, the recorded blocks below the fork point are given
    // timestamps above A's first block (`rewrite_timestamps`), so the
    // window's median that block's timestamp rule (CEN-C2) reads is above
    // it: the store holds a chain that fails its own rules. The scenario's
    // difficulty is fixed, so the target the tier derives does not read
    // those timestamps and the claim still matches; the refusal is C2's.
    // Eleven blocks below the root, so the window is unpadded (CEN-C3):
    // padding repeats block 0, whose identity is also the seed below the
    // first epoch and cannot move.
    const LONG_PREFIX: u64 = 12;
    let mut x = with_prefix("switch-si27-x", LONG_PREFIX).await;
    let mut y = with_prefix("switch-si27-y", LONG_PREFIX).await;
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let plan = offer_branch(&x, &b).await;
    // Every block below the root but genesis. The root keeps its identity,
    // so the alternative chain still links to it.
    let below_root: Vec<BlockHeight> = (1..LONG_PREFIX - 1).map(BlockHeight::from_raw).collect();
    let late = plan
        .demoted
        .first()
        .expect("A's first block is demoted")
        .candidate
        .block
        .header
        .timestamp
        + 10_000;
    x.reopen(|path| rewrite_timestamps(path, &below_root, late))
        .await;
    let err = x.reorganize(&plan).await.expect_err("SI-27 halts");
    let want = shekyl_chain_store::store::StoreInvariant::DemotedBlockRefused {
        height: a[0].height,
    };
    assert!(
        matches!(&err, RunFault::Store(shekyl_chain_store::store::StoreError::InvariantViolated(row)) if *row == want),
        "{err:?}"
    );
    // The writer is over.
    assert!(matches!(x.facts().await, Err(RunFault::Over(_))));
    x.close().await;
    y.close().await;
}

// ---------------------------------------------------------------------------
// a6 — the three refusals distinguished, §4's boundary and floor fixtures,
// and the self-differential (`E5-Q9` re-ruled 2026-10-15).
// ---------------------------------------------------------------------------

/// The one table two stores holding the same chain legitimately differ
/// on: each holds the alternative blocks it switched away from. Never
/// excluded — [`assert_same_chain`] asserts it exactly.
const ALT_TABLE: &str = "alt_blocks";

/// The alt blocks' listed bodies, keyed as [`ALT_TABLE`] is: excluded from
/// the byte comparison with it, and asserted to hold exactly its keys.
const ALT_BODIES_TABLE: &str = "alt_block_bodies";

/// The tables other than the alt table whose rows differ between `x` and
/// `y`, every one compared at the byte level (`TableRows`).
async fn differing_tables(x: &Scenario<FreeHash>, y: &Scenario<FreeHash>) -> Vec<&'static str> {
    let a = x.table_rows().await.expect("rows");
    let b = y.table_rows().await.expect("rows");
    let names: std::collections::BTreeSet<&'static str> =
        a.keys().chain(b.keys()).copied().collect();
    names
        .into_iter()
        .filter(|name| *name != ALT_TABLE && *name != ALT_BODIES_TABLE)
        .filter(|name| a.get(name) != b.get(name))
        .collect()
}

/// The blocks a store's alt table holds, by hash, decoded from its rows.
async fn alt_hashes(s: &Scenario<FreeHash>) -> std::collections::BTreeSet<BlockHash> {
    use shekyl_chain_store::codec::{AltBlock, Canonical};
    s.table_rows()
        .await
        .expect("rows")
        .get(ALT_TABLE)
        .map(|rows| {
            rows.iter()
                .map(|(_, value)| AltBlock::decode(value).expect("decodes").block().hash())
                .collect()
        })
        .unwrap_or_default()
}

/// `switched` holds the chain `direct` connected directly: every table but
/// the alt table byte-equal, and the alt table exactly — `switched` holds
/// `kept` (the blocks it demoted and kept), `direct` holds nothing.
async fn assert_same_chain(
    switched: &Scenario<FreeHash>,
    direct: &Scenario<FreeHash>,
    kept: &[&Mined],
    why: &str,
) {
    assert_eq!(
        differing_tables(switched, direct).await,
        Vec::<&str>::new(),
        "{why}"
    );
    assert_eq!(
        alt_hashes(switched).await,
        kept.iter().map(|m| m.hash).collect(),
        "{why}: the switched store's alt table is exactly the demoted blocks it kept"
    );
    assert!(
        alt_hashes(direct).await.is_empty(),
        "{why}: the directly connected store holds no alternative block"
    );
    for store in [switched, direct] {
        let rows = store.table_rows().await.expect("rows");
        let keys = |name| {
            rows.get(name)
                .map(|rows| rows.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>())
                .unwrap_or_default()
        };
        assert_eq!(
            keys(ALT_BODIES_TABLE),
            keys(ALT_TABLE),
            "{why}: every alt row has its bodies, and no bodies outlive a row"
        );
    }
}

/// The levered schedule `scenario_shard` runs: a 20-block epoch and a reorg
/// cap of 10, so the cap and the undo floor are reachable in a test.
fn levered() -> crate::schedule::ChainRules {
    crate::scenario_shard::levered_rules()
}

const LEVERED_CAP: u64 = crate::scenario_shard::REORG_CAP_BLOCKS;

#[tokio::test]
async fn a_switch_popping_exactly_the_cap_lands_and_one_more_is_refused_locally() {
    // Tip 29; a fork rooted at 19 pops ten (the cap), one rooted at 18
    // pops eleven. The refusal is the cap's, before any pop and before any
    // RandomX, never a verdict: the block stays stored, the chain is
    // untouched.
    let mut x = Scenario::open_under("switch-cap-x", FreeHash, levered());
    x.mine(30).await;
    let mut at_cap = Scenario::open_under("switch-cap-y", FreeHash, levered());
    at_cap.mine(20).await;
    at_cap.idle();
    let b = at_cap.mine(LEVERED_CAP + 1).await;
    let plan = offer_branch(&x, &b).await;
    assert_eq!(
        plan.demoted.len(),
        usize::try_from(LEVERED_CAP).expect("small")
    );
    assert!(matches!(
        x.reorganize(&plan).await.expect("switch"),
        Switched::Done(_)
    ));

    let mut over = Scenario::open_under("switch-cap-z", FreeHash, levered());
    let mut x2 = Scenario::open_under("switch-cap-x2", FreeHash, levered());
    x2.mine(30).await;
    over.mine(19).await;
    over.idle();
    let b = over.mine(LEVERED_CAP + 2).await;
    let before = x2.digest().await.expect("d");
    let (last, held) = b.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x2.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    match x2.offer(last).await.expect("offer") {
        Offered::BeyondCap { beyond, evidence } => {
            assert_eq!(beyond.depth.to_raw(), LEVERED_CAP + 1);
            assert_eq!(beyond.cap.to_raw(), LEVERED_CAP);
            let latch = x2.following_degraded().await;
            assert_eq!(
                latch.map(|held| held.tip),
                Some(evidence.tip),
                "a stored fork past the cap sets following_degraded; \
                 skipping note_degraded on BeyondCap leaves it clear"
            );
        }
        other => panic!("one past the cap was not refused locally: {other:?}"),
    }
    assert_eq!(x2.digest().await.expect("d"), before, "nothing popped");
    assert_eq!(
        x2.alt_blocks_held().await.expect("al6"),
        LEVERED_CAP + 2,
        "the refused-for-depth block stays stored"
    );
    for s in [x, at_cap, over, x2] {
        s.close().await;
    }
}

#[tokio::test]
async fn a_pop_below_the_undo_floor_is_a_local_fail_stop_not_a_verdict() {
    // §4's floor fixture. The retention prune at the epoch-2 boundary
    // keeps the journal from `40 − 10`; a rewind lowers the tip to 35
    // without moving the floor, so a fork inside the cap (rooted at 28,
    // seven pops) reaches below the journal at height 29. The cap check
    // passes; the floor refuses — two operands, two refusals (`E5-Q6`).
    let mut x = Scenario::open_under("switch-floor-x", FreeHash, levered());
    x.mine(50).await;
    x.rewind_to(BlockHeight::from_raw(35))
        .await
        .expect("rewind");
    let mut y = Scenario::open_under("switch-floor-y", FreeHash, levered());
    y.mine(29).await;
    y.idle();
    let b = y.mine(8).await;
    let before = x.digest().await.expect("d");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.demoted.len(), 7, "inside the cap");
    let held_before = x.alt_blocks_held().await.expect("alt held before");
    match x.reorganize(&plan).await.expect("switch") {
        Switched::BelowFloor {
            tip,
            floor,
            evidence,
        } => {
            assert!(tip < floor, "the pop that met the floor");
            assert!(
                floor > plan.root.height.to_raw(),
                "the floor is above the fork point"
            );
            let latch = x.following_degraded().await;
            assert_eq!(
                latch.map(|held| (held.fork_at, held.tip)),
                Some((evidence.fork_at, evidence.tip)),
                "a BelowFloor switch sets following_degraded; \
                 skipping note_degraded on BelowFloor leaves the cell clear"
            );
        }
        other => panic!("the floor did not refuse locally: {other:?}"),
    }
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");
    // The heavier chain this node could not follow stays stored: the
    // refusal is local and moves nothing, the alt table included.
    // Supersedes the alt-store half of the C++ core test
    // `gen_reorg_watermark_refused_switch` (`expected_alt_count`).
    assert_eq!(
        x.alt_blocks_held().await.expect("alt held after"),
        held_before,
        "the refused branch's blocks stay in the alt store"
    );
    assert!(
        held_before >= u64::try_from(b.len()).expect("fits"),
        "the offered branch is held as alternatives: {held_before} < {}",
        b.len()
    );
    assert_eq!(x.mine(1).await.len(), 1, "a local refusal is not a halt");
    x.close().await;
    y.close().await;
}

/// `pop_blocks`' bound (DX-Q3, Q7; the landed defect was a store fault
/// that stopped ingest): a count whose lowest block is below the undo
/// floor is refused before any pop, as a reply; one whose lowest block is
/// the floor pops; and the writer stays up either way.
#[tokio::test]
async fn pop_blocks_below_the_undo_floor_is_refused_before_any_pop() {
    use crate::connector::{PopBlocks, Rewound};
    let mut x = Scenario::open_under("pop-floor-x", FreeHash, levered());
    x.mine(50).await;
    let pop = |count| x.connector().ask(PopBlocks { count });
    let Rewound::Refused { tip, floor } = pop(50).await.expect("a reply") else {
        panic!("popping genesis is refused");
    };
    assert_eq!(tip.to_raw(), 49);
    assert!(floor.to_raw() > 1, "the prune moved the floor: {floor:?}");
    let before = x.digest().await.expect("d");
    let below = tip.to_raw() - (floor.to_raw() - 2);
    assert_eq!(
        pop(below).await.expect("a reply, not a fault"),
        Rewound::Refused { tip, floor },
        "the lowest block popped would be {}",
        floor.to_raw() - 1
    );
    assert_eq!(x.digest().await.expect("d"), before, "nothing popped");
    let at = tip.to_raw() - (floor.to_raw() - 1);
    let popped = pop(at).await.expect("it pops");
    assert_eq!(popped.popped(), at, "down to the floor's parent");
    x.idle();
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
}

/// The spending height: block 0's coinbase has matured for it.
const AT: u64 = crate::test_support::FIRST_SPEND_HEIGHT + 1;

/// The spend self-differential, and the planted rows that witness it.
#[path = "switch_differential_tests.rs"]
mod switch_differential_tests;

/// A promotion `form` refuses, and the header ledger after a switch.
#[path = "switch_promotion_tests.rs"]
mod switch_promotion_tests;

#[tokio::test]
async fn a_recorded_block_offered_as_an_alternative_is_already_held() {
    // Relayed twice: a block on x's own chain below the tip arrives as if
    // it were an alternative. It is held already — never stored as an alt
    // row as well, where a later switch demoting it would meet its own row.
    let mut x = with_prefix("switch-recorded-x", PREFIX).await;
    let own = x.mine(3).await;
    assert!(matches!(
        x.offer(&own[1]).await.expect("offer"),
        Offered::AlreadyHeld
    ));
    assert_eq!(x.alt_blocks_held().await.expect("al6"), 0);
    x.close().await;
}

#[tokio::test]
async fn a_stale_or_mismatched_plan_is_a_driver_defect_and_the_writer_stays_up() {
    let mut x = with_prefix("switch-plan-x", PREFIX).await;
    let mut y = with_prefix("switch-plan-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let plan = offer_branch(&x, &b).await;
    let before = x.digest().await.expect("d");

    // The promoted blocks are not the alternative chain's entries.
    let mut short = plan.clone();
    short.promoted.pop();
    assert!(matches!(
        x.reorganize(&short).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::PromotedLength,
        })
    ));
    // A demoted block formed with a witness its height row does not hold
    // (CEN-K5b's demoted direction).
    let mut witnessed = plan.clone();
    witnessed.demoted[0].candidate.attestation_witness =
        Some(shekyl_types::archival::AttestationWitness::new(vec![0x5E; 8]).expect("non-empty"));
    assert!(matches!(
        x.reorganize(&witnessed).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::DemotedChain,
        })
    ));
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");

    // The tip moves between the plan and the switch: the plan is stale.
    x.mine(1).await;
    assert!(matches!(
        x.reorganize(&plan).await,
        Err(RunFault::StalePlan { .. })
    ));
    assert_eq!(x.mine(1).await.len(), 1, "a driver defect is not a halt");
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_plan_naming_a_recorded_block_as_its_alternative_tip_is_a_mismatch_not_a_crash() {
    // A driver defect a malformed plan carries: its alternative tip is a
    // block the recorded chain holds, so the alternative chain has no
    // entries. The actor replies; it does not panic, and stays up.
    let mut x = with_prefix("switch-empty-plan-x", PREFIX).await;
    let mut y = with_prefix("switch-empty-plan-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let mut plan = offer_branch(&x, &b).await;
    plan.alt_tip = x
        .hash_at(BlockHeight::from_raw(PREFIX))
        .await
        .expect("read")
        .expect("recorded");
    plan.promoted.clear();
    assert!(matches!(
        x.reorganize(&plan).await,
        Err(RunFault::PlanMismatch {
            reason: PlanMismatchReason::AlternativeTipRecorded,
        })
    ));
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
    y.close().await;
}

/// A longhash probe: every call is counted, and every target is satisfied
/// (the free hash), so a test can see how many times a step asked RandomX.
#[derive(Clone)]
struct CountingPow(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl CountingPow {
    fn new() -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    fn calls(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl shekyl_chain_rules::Substrate for CountingPow {
    type Fault = std::convert::Infallible;
    type Held = ();

    fn local_clock(&self) -> Result<shekyl_types::Timestamp, Self::Fault> {
        Ok(crate::scenario::CLOCK_START)
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<shekyl_types::PowHash, Self::Fault> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(shekyl_types::PowHash::from_bytes([0; 32]))
    }
}

/// Two drivers under the levered set (cap 10): `x` holds 30 blocks and the
/// probe, `y` mines the 11-block branch rooted at 19 that pops exactly the
/// cap. Returns `x`, its probe, `y` and the branch, offered up to the plan.
async fn at_the_cap_with_a_probe(
    name: &str,
) -> (
    Scenario<CountingPow>,
    CountingPow,
    Scenario<CountingPow>,
    crate::SwitchPlan,
) {
    let probe = CountingPow::new();
    let mut x = Scenario::open_under(&format!("{name}-x"), probe.clone(), levered());
    let mut y = Scenario::open_under(&format!("{name}-y"), CountingPow::new(), levered());
    x.mine(30).await;
    y.mine(20).await;
    y.idle();
    let b = y.mine(LEVERED_CAP + 1).await;
    let (last, held) = b.split_last().expect("a branch");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    let Offered::SwitchDue(plan) = x.offer(last).await.expect("offer") else {
        panic!("the heavier tip did not name a switch");
    };
    (x, probe, y, plan)
}

#[tokio::test]
async fn a_switch_at_the_cap_calls_randomx_zero_times() {
    // Ruling 3 (2026-10-15): every block the switch re-judges was hashed
    // when this node first judged it — the demoted ones at connect, the
    // promoted ones at arrival — and the plan carries those records. The
    // switch's forming asks RandomX nothing.
    let (mut x, probe, y, plan) = at_the_cap_with_a_probe("switch-recall").await;
    assert_eq!(
        plan.demoted.len(),
        usize::try_from(LEVERED_CAP).expect("small")
    );
    let before = probe.calls();
    let switched = x.reorganize(&plan).await.expect("switch");
    assert!(matches!(switched, Switched::Done(_)), "{switched:?}");
    assert_eq!(
        probe.calls() - before,
        0,
        "N + M = {} blocks re-formed through their recorded PoW",
        plan.demoted.len() + plan.promoted.len()
    );
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_seed_claim_that_differs_from_the_recorded_one_recomputes() {
    // The record is keyed by (identity, seed): a claim under another seed
    // is not the recorded computation, so it goes to RandomX — once — and
    // then to CEN-D3, which refuses the claim as it would without a record.
    let (mut x, probe, y, mut plan) = at_the_cap_with_a_probe("switch-recall-seed").await;
    plan.promoted[0].at.seed = BlockHash::from_bytes([0x5D; 32]);
    let before = probe.calls();
    let out = x.reorganize(&plan).await;
    assert_eq!(
        probe.calls() - before,
        1,
        "only the mismatched claim recomputes"
    );
    assert!(matches!(out, Err(RunFault::StaleSeed { .. })), "{out:?}");
    x.close().await;
    y.close().await;
}

/// The third claim during a switch (2026-10-16, `CHAIN_RULES_CRATE.md`
/// §4.6): a promoted block's spend is verified in `form` against the
/// plan's header chain, and `validate` compares the claim with the chain
/// inside the closure. A claim the chain refutes — the reference at
/// another height, or no claim where the chain holds the reference in
/// the window — is `RunFault::StaleReference`, a driver defect: never a
/// verdict, never a second verify, the transaction rolled back and the
/// writer up. A stale target claim is the same class. A claim with the
/// wrong **root** never reaches the comparison: the root is the
/// verifier's input, so the proof fails against it and `form` refuses the
/// spend on CEN-I15 — the claim cannot widen what the chain accepts. The
/// honest plan then lands. That refusal is observed through `form`
/// directly. It is not [`crate::RefusePromotion`]: a false claim must not
/// delete a chain the honest claim accepts.
#[tokio::test]
async fn a_reference_or_target_claim_the_switch_cannot_make_is_a_driver_defect() {
    let mut x = Scenario::open("switch-stale-claim-x");
    let mut y = Scenario::open("switch-stale-claim-y");
    x.mine(AT).await;
    let prefix = y.mine(AT).await;
    let a = x.mine(1).await;
    y.idle();
    // B's first block lists a spend referencing a block below the fork
    // point — inside the plan's header window.
    let spend = shekyl_harness_spender::Spender::over(&prefix).spend_coinbase(
        y.wallet(),
        BlockHeight::from_raw(0),
        BlockHeight::from_raw(AT),
        crate::test_support::Family::Main.fee(),
    );
    let mut b = vec![y
        .mine_listing(vec![spend])
        .await
        .unwrap_or_else(|o| panic!("the spend connects: {o}"))];
    b.extend(y.mine(1).await);
    let reference = *b[0]
        .candidate()
        .proof_references()
        .iter()
        .next()
        .expect("the spend names a reference");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.demoted.len(), 1);
    let position = plan
        .headers
        .iter()
        .position(|h| h.hash == reference)
        .expect("the plan's header chain holds the reference");
    assert!(
        plan.headers[position].height < plan.promoted[0].at.height,
        "the reference is below the block that spends it"
    );
    let before = x.digest().await.expect("digest");

    // Another root for the reference: the proof fails against it in
    // `form` — CEN-I15 at the spend, the claim's own refusal, before any
    // closure. Through `form` directly, as the driver would see it.
    let mut wrong_root = plan.clone();
    let wrong = shekyl_types::CurveTreeRoot::from_bytes([0xd1; 32]);
    assert_ne!(wrong_root.headers[position].root, wrong);
    wrong_root.headers[position].root = wrong;
    {
        let at = &plan.promoted[0].at;
        let candidate = b[0].candidate();
        let claims = wrong_root.references_for(at, &candidate);
        assert_eq!(claims.get(&reference).map(|c| c.root), Some(wrong));
        let verdict = shekyl_chain_rules::form(
            candidate,
            &crate::scenario::RULES.in_force(at.height),
            &FreeHash,
            at.seed,
            at.target,
            &claims,
            shekyl_chain_rules::FormAttempt::FIRST,
        )
        .expect("the free substrate does not fault");
        match verdict {
            Err(refused) => {
                assert_eq!(refused.rule, shekyl_chain_rules::CenRow::I15);
                assert_eq!(
                    refused.locus,
                    shekyl_chain_rules::Locus::Tx {
                        slot: shekyl_chain_rules::TxSlot::Listed(0)
                    }
                );
            }
            Ok(_) => panic!("a proof verified against a root it was not built over"),
        }
    }

    // The reference at another height, its root right: the proof verifies
    // in `form` and the comparison inside the closure refutes the height,
    // with both claims named.
    let mut wrong_height = plan.clone();
    let shifted = BlockHeight::from_raw(plan.headers[position].height.to_raw() + 1);
    assert!(shifted < plan.promoted[0].at.height);
    wrong_height.headers[position].height = shifted;
    match x.reorganize(&wrong_height).await {
        Err(RunFault::StaleReference {
            height,
            slot,
            reference: named,
            claims,
            ..
        }) => {
            assert_eq!(height, b[0].height);
            assert_eq!(slot, shekyl_chain_rules::TxSlot::Listed(0));
            assert_eq!(named, reference);
            assert_eq!(claims.claimed.map(|c| c.height), Some(shifted));
            assert_eq!(claims.expected.root, plan.headers[position].root);
            assert_eq!(claims.expected.height, plan.headers[position].height);
        }
        other => panic!("expected StaleReference, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // No claim at all for a reference the chain holds in the window.
    let mut unclaimed = plan.clone();
    unclaimed.headers.remove(position);
    match x.reorganize(&unclaimed).await {
        Err(RunFault::StaleReference { claims, .. }) => {
            assert_eq!(claims.claimed, None);
            assert_eq!(claims.expected.root, plan.headers[position].root);
        }
        other => panic!("expected StaleReference, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // A target claim the stitched headers do not derive.
    let mut wrong_target = plan.clone();
    let claimed = plan.promoted[0].at.target;
    let other = shekyl_chain_rules::Target::for_tests(
        core::num::NonZeroU128::new(claimed.difficulty().to_raw().saturating_mul(2).max(2))
            .expect("non-zero"),
    );
    assert_ne!(other, claimed);
    wrong_target.promoted[0].at.target = other;
    match x.reorganize(&wrong_target).await {
        Err(RunFault::StaleTarget {
            height,
            claimed: was,
            expected,
            ..
        }) => {
            assert_eq!(height, b[0].height);
            assert_eq!(was, other);
            assert_eq!(expected, claimed);
        }
        other => panic!("expected StaleTarget, got {other:?}"),
    }
    assert_eq!(x.digest().await.expect("digest"), before, "rolled back");

    // The writer is up and the honest plan lands.
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the honest switch did not land");
    };
    assert_eq!(done.promoted.len(), 2);
    assert_same_chain(&x, &y, &a.iter().collect::<Vec<_>>(), "A → B equals B").await;
    x.close().await;
    y.close().await;
}
