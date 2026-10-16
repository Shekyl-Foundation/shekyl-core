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

use std::collections::HashMap;

use shekyl_difficulty::ForkChoiceVerdict;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::Transaction;

use crate::connector::{Offered, RunFault, Switched};
use crate::scenario::{FreeHash, Mined, Scenario};

/// The listed bodies of `branches`' blocks, by hash — what the pool will
/// hold for the switch from PR-b on.
fn bodies<'a>(
    branches: impl IntoIterator<Item = &'a Mined>,
) -> HashMap<BlockHash, Vec<Transaction>> {
    branches
        .into_iter()
        .map(|m| (m.hash, m.template.transactions.clone()))
        .collect()
}

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
    assert_eq!(plan.verdict, ForkChoiceVerdict::Switch);
    assert_eq!(plan.root.height, BlockHeight::from_raw(PREFIX - 1));
    assert_eq!(plan.demoted.len(), 3);
    assert_eq!(plan.promoted.len(), 4);

    let Switched::Done(done) = x.reorganize(&plan, &bodies(&b)).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert!(
        done.demoted_kept,
        "a difficulty switch keeps the demoted chain (K7)"
    );
    assert_eq!(
        done.demoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        a.iter().map(|m| m.hash).collect::<Vec<_>>()
    );
    assert_eq!(
        done.promoted.iter().map(|(_, h)| *h).collect::<Vec<_>>(),
        b.iter().map(|m| m.hash).collect::<Vec<_>>()
    );

    // Nothing left over: the store that switched is the store that
    // connected B directly.
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));

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
        x.reorganize(&plan, &bodies(&b)).await.expect("switch"),
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
    let Switched::Done(done) = x
        .reorganize(&plan, &bodies(a.iter().chain(&a_ext)))
        .await
        .expect("switch back")
    else {
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
    match x.reorganize(&plan, &bodies(&b)).await.expect("switch") {
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

/// A trust whose one anchor pins `mined` at its height — a fixture table
/// (no regtest run is anchored), leaked for the `'static` the release
/// tables have.
fn anchoring(mined: &Mined) -> shekyl_chain_rules::Trust {
    let pins: &'static [shekyl_chain_rules::Anchor] =
        Box::leak(Box::new([shekyl_chain_rules::Anchor {
            height: mined.height,
            hash: mined.hash,
        }]));
    shekyl_chain_rules::Trust::full(shekyl_chain_rules::ReleaseAnchors::for_tests(None, pins))
}

#[tokio::test]
async fn a_checkpoint_forced_switch_discards_the_demoted_chain() {
    let mut x = with_prefix("switch-forced-x", PREFIX).await;
    let mut y = with_prefix("switch-forced-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    // A release pins B's first block above x's tip (K6's checkpoint arm).
    // Above the tip it is no floor yet (CEN-E2), so the branch is offered.
    x.connector()
        .ask(crate::connector::AnchorForTests(anchoring(&b[3])))
        .await
        .expect("anchor");
    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.verdict, ForkChoiceVerdict::ForcedSwitch);
    let Switched::Done(done) = x.reorganize(&plan, &bodies(&b)).await.expect("switch") else {
        panic!("the forced switch did not land");
    };
    assert!(!done.demoted_kept, "the checkpoint arm discards (K7)");
    assert_eq!(done.demoted.len(), 3);
    assert_eq!(
        x.alt_blocks_held().await.expect("al6"),
        0,
        "nothing re-entered"
    );
    assert_eq!(x.digest().await.expect("d"), y.digest().await.expect("d"));
    x.close().await;
    y.close().await;
}

#[tokio::test]
async fn a_demoted_block_the_tier_refuses_halts_the_writer_si27() {
    let mut x = with_prefix("switch-si27-x", PREFIX).await;
    let mut y = with_prefix("switch-si27-y", PREFIX).await;
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let plan = offer_branch(&x, &b).await;
    // Between the plan and the switch, a release anchors A's second block
    // under another hash: the recorded chain now fails its own tier (the
    // anchor floors every fork rooted below it), and the switch's demotion
    // judges A's first block against it.
    let mut wrong = a[1].clone();
    wrong.hash = BlockHash::from_bytes([0xEE; 32]);
    x.connector()
        .ask(crate::connector::AnchorForTests(anchoring(&wrong)))
        .await
        .expect("anchor");
    let err = x
        .reorganize(&plan, &bodies(&b))
        .await
        .expect_err("SI-27 halts");
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

/// The tables two stores that hold the same chain may still disagree on:
/// each holds the alternative blocks it switched away from.
const EXPECTED_TO_DIFFER: &[&str] = &["alt_blocks"];

/// The tables whose rows differ between `x` and `y`, every table compared
/// at the byte level (`TableRows`) except [`EXPECTED_TO_DIFFER`].
async fn differing_tables(x: &Scenario<FreeHash>, y: &Scenario<FreeHash>) -> Vec<&'static str> {
    let a = x.table_rows().await.expect("rows");
    let b = y.table_rows().await.expect("rows");
    let names: std::collections::BTreeSet<&'static str> =
        a.keys().chain(b.keys()).copied().collect();
    names
        .into_iter()
        .filter(|name| !EXPECTED_TO_DIFFER.contains(name))
        .filter(|name| a.get(name) != b.get(name))
        .collect()
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
        x.reorganize(&plan, &bodies(&b)).await.expect("switch"),
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
        Offered::BeyondCap(beyond) => {
            assert_eq!(beyond.depth.to_raw(), LEVERED_CAP + 1);
            assert_eq!(beyond.cap.to_raw(), LEVERED_CAP);
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
    match x.reorganize(&plan, &bodies(&b)).await.expect("switch") {
        Switched::BelowFloor { tip, floor } => {
            assert!(tip < floor, "the pop that met the floor");
            assert!(
                floor > plan.root.height.to_raw(),
                "the floor is above the fork point"
            );
        }
        other => panic!("the floor did not refuse locally: {other:?}"),
    }
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");
    assert_eq!(x.mine(1).await.len(), 1, "a local refusal is not a halt");
    x.close().await;
    y.close().await;
}

/// The spending height: block 0's coinbase has matured for it.
const AT: u64 = crate::test_support::FIRST_SPEND_HEIGHT + 1;

/// The self-differential: `x` connects a prefix and branch A (`depth`
/// blocks, the first listing a validating user spend), `y` the same prefix
/// and branch B (`depth + 1` blocks), `z` the prefix, A, and two blocks
/// more. B arrives at `x`: after the switch every table but the alt table
/// is byte-equal to `y`'s, and the spend is in the returned bodies. A's
/// extension arrives: after the switch back `x` equals `z`.
async fn spend_differential(name: &str, rules: crate::schedule::ChainRules, depth: u64) {
    let open = |side: &str| Scenario::open_under(&format!("{name}-{side}"), FreeHash, rules);
    let (mut x, mut y, mut z) = (open("x"), open("y"), open("z"));
    let prefix = x.mine(AT).await;
    y.mine(AT).await;
    z.mine(AT).await;
    let spend = shekyl_harness_spender::Spender::over(&prefix).spend_coinbase(
        x.wallet(),
        BlockHeight::from_raw(0),
        BlockHeight::from_raw(AT),
        crate::test_support::Family::Main.fee(),
    );
    let mut a = vec![x
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend connects: {o}"))];
    a.extend(x.mine(depth - 1).await);
    z.mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend connects: {o}"));
    z.mine(depth - 1).await;
    let a_ext = z.mine(2).await;
    y.idle();
    let b = y.mine(depth + 1).await;

    let plan = offer_branch(&x, &b).await;
    assert_eq!(plan.demoted.len(), usize::try_from(depth).expect("small"));
    let Switched::Done(done) = x.reorganize(&plan, &bodies(&b)).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert!(
        done.returned.iter().any(|tx| tx.hash() == spend.hash()),
        "the demoted spend comes back for the pool"
    );
    assert_eq!(
        differing_tables(&x, &y).await,
        Vec::<&str>::new(),
        "A → B equals B"
    );

    // Back to A: B is one block longer than A was, so the way back pops
    // `depth + 1`. Inside the cap it lands and equals the chain that never
    // switched; at the cap it is one past it and refused locally.
    let (last, held) = a_ext.split_last().expect("two blocks");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    match x.offer(last).await.expect("offer") {
        Offered::SwitchDue(plan) => {
            assert!(
                depth < x_cap(rules),
                "a switch back past the cap was planned"
            );
            assert!(matches!(
                x.reorganize(&plan, &bodies(a.iter().chain(&a_ext)))
                    .await
                    .expect("switch back"),
                Switched::Done(_)
            ));
            assert_eq!(
                differing_tables(&x, &z).await,
                Vec::<&str>::new(),
                "A → B → A equals the chain that never switched"
            );
        }
        Offered::BeyondCap(beyond) => {
            assert_eq!(depth, x_cap(rules), "only the cap-depth run is refused");
            assert_eq!(beyond.depth.to_raw(), depth + 1);
        }
        other => panic!("A's heavier extension: {other:?}"),
    }
    for s in [x, y, z] {
        s.close().await;
    }
}

/// The reorg cap `rules` puts in force at genesis.
fn x_cap(rules: crate::schedule::ChainRules) -> u64 {
    rules
        .in_force(BlockHeight::from_raw(0))
        .reorg_cap()
        .to_raw()
}

#[tokio::test]
async fn the_self_differential_holds_at_a_shallow_depth_with_a_spend() {
    spend_differential("switch-diff-shallow", crate::scenario::RULES, 3).await;
}

#[tokio::test]
async fn the_self_differential_holds_at_the_cap_depth_with_a_spend() {
    // The levered set's cap; `production_cap_switch_timing` runs the
    // genesis cap of 720 in the ignored lane.
    spend_differential("switch-diff-cap", levered(), LEVERED_CAP).await;
}

/// Rewrite the undo row at `height` so the `archival_budget_accruing`
/// pre-image it would restore is one atomic unit off.
fn corrupt_accrual_preimage(path: &std::path::Path, height: BlockHeight) {
    use redb::ReadableTable;
    use shekyl_chain_store::codec::Canonical;
    use shekyl_chain_store::codec::{UndoEntry, UndoLog};
    let ordinal = shekyl_chain_store::schema::ordinal_of("archival_budget_accruing")
        .expect("the accrual table is catalogued");
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut undo = txn
            .open_table(shekyl_chain_store::schema::UNDO_LOG)
            .expect("t");
        let mut log: UndoLog = undo
            .get(height.to_raw())
            .expect("get")
            .expect("the height has a journal row")
            .value()
            .decode()
            .expect("decodes");
        let entry = log
            .0
            .iter_mut()
            .find_map(|entry| match entry {
                UndoEntry::Replaced {
                    table,
                    prior: Some(prior),
                    ..
                } if *table == ordinal => Some(prior),
                _ => None,
            })
            .expect("the connect replaced an accruing row");
        let value = u64::from_le_bytes((**entry).try_into().expect("eight bytes")) + 1;
        *entry = value.to_le_bytes().to_vec().into_boxed_slice();
        undo.insert(height.to_raw(), log.encoded().as_encoded())
            .expect("plant");
    }
    txn.commit().expect("commit");
}

#[tokio::test]
async fn a_corrupted_undo_row_makes_the_differential_fail() {
    // The mutation control: the same switch as the shallow differential,
    // with one pre-image off by one unit in the journal row of A's FIRST
    // block — the last row the switch pops. A corrupted row above it is
    // caught by the journal itself: the next pop finds the restored value
    // is not the post-image it recorded (SI-6, `PostImageMismatch`, seen
    // on the tip's row). The lowest popped row has no pop after it, so its
    // pre-image becomes the fork point's state unread; B folds onto it,
    // and only the differential can see it — which is what makes the
    // differential's equality not vacuous.
    let mut x = with_prefix("switch-diff-mut-x", PREFIX).await;
    let mut y = with_prefix("switch-diff-mut-y", PREFIX).await;
    let a = x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    let lowest = a[0].height;
    x.reopen(|path| corrupt_accrual_preimage(path, lowest))
        .await;
    let plan = offer_branch(&x, &b).await;
    assert!(matches!(
        x.reorganize(&plan, &bodies(&b)).await.expect("switch"),
        Switched::Done(_)
    ));
    let differ = differing_tables(&x, &y).await;
    assert!(
        differ.contains(&"archival_budget_accruing"),
        "the corrupted pre-image shows: {differ:?}"
    );
    x.close().await;
    y.close().await;
}

/// Rewrite the alt row of `hash` to carry `witness` — a row AL1 never
/// writes (the tier stores the witness the block arrived with), planted
/// under the store's back.
fn plant_alt_witness(path: &std::path::Path, hash: BlockHash, witness: Vec<u8>) {
    use redb::ReadableTable;
    use shekyl_chain_store::codec::{AltBlock, Canonical};
    let db = redb::Database::open(path).expect("open raw");
    let txn = db.begin_write().expect("write");
    {
        let mut table = txn
            .open_table(shekyl_chain_store::schema::ALT_BLOCKS)
            .expect("t");
        let (key, row) = table
            .iter()
            .expect("iter")
            .map(|row| {
                let (k, v) = row.expect("row");
                (k.value(), v.value().decode().expect("decodes"))
            })
            .find(|(_, row): &(_, AltBlock)| row.block().hash() == hash)
            .expect("the alt row is held");
        let tampered = AltBlock::checked(row.facts(), &row.block().serialize(), Some(witness))
            .expect("well formed");
        table
            .insert(key, tampered.encoded().as_encoded())
            .expect("plant");
    }
    txn.commit().expect("commit");
}

#[tokio::test]
async fn a_tampered_witness_on_an_alt_row_fails_promotion_k5b() {
    // CEN-K5b: the witness a promoted block is judged with is the one its
    // alt row carries. The scenario mints no attestation records, so every
    // honest row's witness is `None`; plant a witness on B's second row and
    // CEN-B4, run by promotion's `validate`, refuses it against the
    // header's empty attestation root. The switch rolls back and the
    // suffix from that block leaves.
    let mut x = with_prefix("switch-k5b-x", PREFIX).await;
    let mut y = with_prefix("switch-k5b-y", PREFIX).await;
    x.mine(3).await;
    y.idle();
    let b = y.mine(4).await;
    for mined in &b[..3] {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    let target = b[1].hash;
    x.reopen(|path| plant_alt_witness(path, target, vec![0xA7; 16]))
        .await;
    let before = x.digest().await.expect("d");
    let Offered::SwitchDue(plan) = x.offer(&b[3]).await.expect("offer") else {
        panic!("the heavier tip did not name a switch");
    };
    assert!(
        plan.promoted[1].witness.is_some(),
        "the plan carries the row's witness"
    );
    match x.reorganize(&plan, &bodies(&b)).await.expect("switch") {
        Switched::Refused {
            hash,
            refused,
            removed,
            ..
        } => {
            assert_eq!(hash, target);
            assert_eq!(refused.rule, shekyl_chain_rules::CenRow::B4);
            assert_eq!(removed, vec![b[1].hash, b[2].hash, b[3].hash]);
        }
        other => panic!("a tampered witness was promoted: {other:?}"),
    }
    assert_eq!(x.digest().await.expect("d"), before);
    x.close().await;
    y.close().await;
}

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
        x.reorganize(&short, &bodies(&b)).await,
        Err(RunFault::PlanMismatch { .. })
    ));
    // A demoted block formed with a witness its height row does not hold
    // (CEN-K5b's demoted direction).
    let mut witnessed = plan.clone();
    witnessed.demoted[0].candidate.attestation_witness =
        Some(shekyl_types::archival::AttestationWitness::new(vec![0x5E; 8]).expect("non-empty"));
    assert!(matches!(
        x.reorganize(&witnessed, &bodies(&b)).await,
        Err(RunFault::PlanMismatch { .. })
    ));
    assert_eq!(x.digest().await.expect("d"), before, "nothing moved");

    // The tip moves between the plan and the switch: the plan is stale.
    x.mine(1).await;
    assert!(matches!(
        x.reorganize(&plan, &bodies(&b)).await,
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
        x.reorganize(&plan, &bodies(&b)).await,
        Err(RunFault::PlanMismatch { .. })
    ));
    assert_eq!(x.mine(1).await.len(), 1, "the writer is up");
    x.close().await;
    y.close().await;
}
