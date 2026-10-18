// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The spend self-differential (`DRS_E5_POOL_ALT_PRUNE.md` §2.3, `E5-Q9`):
//! a chain that switches onto a heavier branch, and back, equals the chain
//! that connected the winner directly. A corrupted undo pre-image and a
//! tampered alt witness show that equality is not vacuous.

use shekyl_types::{BlockHash, BlockHeight};

use crate::connector::{Offered, Switched};
use crate::scenario::{FreeHash, Mined, Scenario};

use super::{
    assert_same_chain, differing_tables, levered, offer_branch, with_prefix, AT, LEVERED_CAP,
    PREFIX,
};

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
    let Switched::Done(done) = x.reorganize(&plan).await.expect("switch") else {
        panic!("the switch did not land");
    };
    assert!(
        done.returned.iter().any(|tx| tx.hash() == spend.hash()),
        "the demoted spend comes back for the pool"
    );
    // The death rule: the switch's last connect takes the tip to
    // `AT + depth`, so a demoted row at or below `AT + depth − cap` left
    // with its bodies — at the cap, A's first block, which no switch back
    // could reach (it would pop `depth + 1`).
    let cap = x_cap(rules);
    let kept: Vec<&Mined> = a
        .iter()
        .filter(|m| m.height.to_raw() + cap > AT + depth)
        .collect();
    assert_eq!(kept.len(), a.len() - usize::from(depth == cap));
    assert_same_chain(&x, &y, &kept, "A → B equals B").await;

    // Back to A: B is one block longer than A was, so the way back pops
    // `depth + 1`. Inside the cap it lands and equals the chain that never
    // switched. At the cap it is one past it: A's first block is gone, so
    // A's extension does not link (it would have been refused on the cap).
    if depth == cap {
        match x.offer(&a_ext[0]).await.expect("offer") {
            Offered::Unlinked { at } => assert_eq!(at, a[0].hash),
            other => panic!("A's first block was retired: {other:?}"),
        }
        for s in [x, y, z] {
            s.close().await;
        }
        return;
    }
    let (last, held) = a_ext.split_last().expect("two blocks");
    for mined in held {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    match x.offer(last).await.expect("offer") {
        Offered::SwitchDue(plan) => {
            assert!(matches!(
                x.reorganize(&plan).await.expect("switch back"),
                Switched::Done(_)
            ));
            assert_same_chain(
                &x,
                &z,
                &b.iter().collect::<Vec<_>>(),
                "A → B → A equals the chain that never switched",
            )
            .await;
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
        x.reorganize(&plan).await.expect("switch"),
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
    match x.reorganize(&plan).await.expect("switch") {
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
