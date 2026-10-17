// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool and blocks, over the production stack (DRS-E5 PR-b b4): a
//! switch's returns run the door (CEN-K10); an alternative's bodies are
//! the store's, promoted from it whatever the pool decided, and offered to
//! the pool for relay (CEN-K9); a connect past the cap retires an alt row
//! and its bodies; CEN-M8's anchor spares a re-admission the proof; and the
//! door verifies nothing the shared function does not.
//!
//! Two drivers mine one prefix and then different branches; one's blocks
//! arrive at the other as alternatives (the switch tests' shape).

use shekyl_chain_rules::{
    judge_slot_stateless, probes, AdmissionPolicy, CenRow, HeaderView, PolicyRow, ReferenceClaims,
    RuleCoverage, Tip, TxSlot,
};
use shekyl_chain_store::pool::{PoolStore, Standing};
use shekyl_harness_spender::Spender;
use shekyl_mempool::{
    judge, shown, Admission, Arrival, Duplicate, Evicted, Judged, KeyImages, Limits, Pool,
};
use shekyl_types::UnixSeconds;

use crate::connector::{Offered, Switched};
use crate::pool_door_tests::{matured, paying_the_floor, AT};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::test_support::{h, tmp};

/// Offer every block of `branch`; the last must name a switch.
async fn offer_branch(x: &Scenario<FreeHash>, branch: &[Mined]) -> crate::SwitchPlan {
    let (last, held) = branch.split_last().expect("a branch");
    for mined in held {
        assert!(
            matches!(x.offer(mined).await.expect("offer"), Offered::Held { .. }),
            "block {:?} not held",
            mined.height
        );
    }
    match x.offer(last).await.expect("offer") {
        Offered::SwitchDue(plan) => plan,
        other => panic!("the heavier tip did not name a switch: {other:?}"),
    }
}

/// An empty pool at `path`, over `x`'s chain.
async fn open_pool(x: &mut Scenario<FreeHash>, path: &std::path::Path) -> Pool {
    x.read_chain(|view, rule_set| {
        Pool::open(
            path,
            shekyl_types::UnixSeconds::from_raw(1),
            view,
            rule_set,
            &AdmissionPolicy::GENESIS,
        )
        .expect("open")
        .0
    })
    .await
}

/// CEN-K10 and CEN-M3 together: two transactions a popped block listed come
/// back through the door — the one paying the floor is admitted, public
/// (a block carried it); the one paying one atomic unit is refused on the
/// floor exactly as a relayed one is (no `kept_by_block` exemption).
#[tokio::test]
async fn a_switchs_returns_run_the_door_and_the_floor_refuses_one_below_it() {
    let (mut x, prefix) = matured("pool-returns-x").await;
    let mut y = Scenario::open("pool-returns-y");
    y.mine(AT).await;
    let paid = paying_the_floor(&mut x, &prefix, 0).await;
    let cheap = Spender::over(&prefix).spend_coinbase(x.wallet(), h(1), h(AT), 1);
    let _a = x
        .mine_listing(vec![paid.clone(), cheap.clone()])
        .await
        .unwrap_or_else(|o| panic!("a block may carry a transaction below the floor: {o}"));
    y.idle();
    let b = y.mine(2).await;
    let plan = offer_branch(&x, &b).await;

    let path = tmp("pool-returns-pool");
    let mut pool = open_pool(&mut x, &path).await;
    let (switched, admissions) = x
        .reorganize_with_pool(&plan, &mut pool, UnixSeconds::from_raw(10))
        .await
        .expect("switch");
    assert!(matches!(switched, Switched::Done(_)), "the switch landed");
    assert_eq!(admissions.len(), 2, "both listed transactions came back");
    assert_eq!(
        admissions[0],
        (
            paid.txid_parts().hash,
            Admission::Admitted {
                evicted: Vec::new()
            }
        )
    );
    match &admissions[1] {
        (txid, Admission::Refused(Judged::Policy(r))) => {
            assert_eq!(*txid, cheap.txid_parts().hash);
            assert_eq!(r.rule, PolicyRow::M3, "below the floor, returned or not");
        }
        other => panic!("the cheap return is refused on M3: {other:?}"),
    }
    let record = pool.record(&paid.txid_parts().hash).expect("held");
    assert!(record.public, "a block carried it");
    assert!(shown(&record), "and the node shows it");
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
}

/// CEN-K10's retention: a returned spend whose reference has aged out of
/// CEN-I11's window on the chain the switch left is kept — refused by the
/// chain-bound half, held, shown nowhere — and CEN-M10 evicts it after the
/// kept lifetime, not the admitted one.
#[tokio::test]
async fn a_returned_spend_whose_reference_aged_out_is_kept_and_evicted_after_the_cap() {
    let (mut x, prefix) = matured("pool-aged-x").await;
    let mut y = Scenario::open("pool-aged-y");
    y.mine(AT).await;
    let spend = paying_the_floor(&mut x, &prefix, 0).await;
    let _a = x
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend connects: {o}"));
    // A is 109 blocks, the spend in its first; B, one heavier, takes the
    // chain past CEN-I11's hundred-block window from the spend's
    // reference, so the switch returns it aged out.
    x.mine(108).await;
    y.idle();
    let b = y.mine(110).await;
    let plan = offer_branch(&x, &b).await;

    let path = tmp("pool-aged-pool");
    let mut pool = open_pool(&mut x, &path).await;
    let now = UnixSeconds::from_raw(1_000);
    let (_, admissions) = x
        .reorganize_with_pool(&plan, &mut pool, now)
        .await
        .expect("switch");
    let txid = spend.txid_parts().hash;
    assert_eq!(admissions, vec![(txid, Admission::Kept)]);
    let record = pool.record(&txid).expect("kept");
    let Standing::Kept { returned_at } = record.standing else {
        panic!("kept: {record:?}");
    };
    assert!(!shown(&record));
    assert_eq!(pool.listing().count(), 0, "kept is shown nowhere");
    assert_eq!(pool.peer_sync().count(), 0);
    let template = x
        .read_chain(|view, rule_set| {
            shekyl_mempool::select(&pool, view, rule_set, u64::MAX).expect("template")
        })
        .await;
    assert!(
        template.transactions.is_empty() && template.refused.is_empty(),
        "a kept entry is never a candidate: {template:?}"
    );
    assert!(
        !pool
            .key_images()
            .contains(&shekyl_types::KeyImage::from_bytes(
                match &spend.prefix.inputs[0] {
                    shekyl_wire::transaction::Input::ToKey { key_image, .. } => *key_image,
                    _ => unreachable!("a spend"),
                }
            )),
        "a kept entry blocks no other spend"
    );
    // A reconcile leaves a kept entry kept: the door still refuses it on
    // the chain-bound half, and only its age or its bytes remove it.
    let reconciled = x
        .read_chain(|view, rule_set| {
            pool.reconcile(view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("reconcile")
        })
        .await;
    assert_eq!(reconciled.kept, vec![txid]);
    assert!(reconciled.removed.is_empty());
    // Aged in blocks from its return: a block short of the cap it stays;
    // at the cap — no switch back reaches further — it goes.
    let kept_for = pool.limits().kept_for.to_raw();
    let at = |blocks: u64| shekyl_types::BlockHeight::from_raw(returned_at.to_raw() + blocks);
    assert!(pool.evict(at(kept_for - 1), &[]).expect("evict").is_empty());
    assert_eq!(
        pool.evict(at(kept_for), &[]).expect("evict"),
        vec![(txid, Evicted::KeptAged)]
    );
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
}

/// The bodies the store holds for the alt block `hash` (AL8).
async fn stored_bodies(
    x: &mut Scenario<FreeHash>,
    hash: shekyl_types::BlockHash,
) -> Option<shekyl_chain_store::codec::AltBodies> {
    x.with_store(|store, _| {
        store
            .begin_read()
            .expect("a snapshot")
            .alt_block_bodies(&hash)
            .expect("the alt rows agree")
    })
    .await
}

/// CEN-K9 (the review of #1102, B1): an alternative's listed bodies are the
/// store's, so no pool decision can stop its promotion. The alternative
/// lists three bodies: one this node's branch also mined, one paying one
/// atomic unit (below this node's floor, which no consensus rule sets), and
/// one this node holds unpublished. The store holds all three under the
/// block's hash. Offered to the pool for relay, the first is on the chain,
/// the second is refused on the floor, and the third is made public — a
/// block published it, and a pool that kept it hidden would tell an
/// alternative's sender which stem transactions it held. Then the pool file
/// is discarded, and the switch still lands.
#[tokio::test]
async fn an_alternatives_bodies_are_the_stores_and_its_promotion_needs_no_pool() {
    let (mut x, prefix) = matured("pool-alt-bodies-x").await;
    let mut y = Scenario::open("pool-alt-bodies-y");
    y.mine(AT).await;
    let shared = paying_the_floor(&mut x, &prefix, 0).await;
    let stem = paying_the_floor(&mut x, &prefix, 2).await;
    let cheap = Spender::over(&prefix).spend_coinbase(x.wallet(), h(1), h(AT), 1);
    let _a = x
        .mine_listing(vec![shared.clone()])
        .await
        .unwrap_or_else(|o| panic!("the shared spend connects here: {o}"));
    y.idle();
    let mut b = vec![y
        .mine_listing(vec![shared.clone(), cheap.clone(), stem.clone()])
        .await
        .unwrap_or_else(|o| panic!("the alternative connects all three: {o}"))];
    b.extend(y.mine(1).await);

    let path = tmp("pool-alt-bodies-pool");
    let mut pool = open_pool(&mut x, &path).await;
    let now = UnixSeconds::from_raw(10);
    let policy = AdmissionPolicy::GENESIS;
    let (sid, cid, tid) = (
        shared.txid_parts().hash,
        cheap.txid_parts().hash,
        stem.txid_parts().hash,
    );
    let held = x
        .read_chain(|view, rule_set| {
            pool.admit(stem.clone(), Arrival::Relayed, now, view, rule_set, &policy)
                .expect("no fault")
        })
        .await;
    assert_eq!(
        held,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    assert!(
        !shown(&pool.record(&tid).expect("held")),
        "in its stem phase"
    );

    assert!(
        matches!(x.offer(&b[0]).await.expect("offer"), Offered::Held { .. }),
        "equal work: held"
    );
    let bodies = stored_bodies(&mut x, b[0].hash)
        .await
        .expect("AL1 wrote the bodies");
    assert_eq!(bodies.transactions(), b[0].template.transactions.as_slice());
    let offers = x
        .read_chain(|view, rule_set| pool.supplement(&bodies, now, view, rule_set, &policy))
        .await;
    assert!(offers.faults.is_empty(), "{:?}", offers.faults);
    assert_eq!(offers.admissions.len(), 3);
    assert_eq!(
        offers.admissions[0],
        (sid, Admission::Duplicate(Duplicate::OnChain))
    );
    match &offers.admissions[1] {
        (txid, Admission::Refused(Judged::Policy(r))) => {
            assert_eq!(*txid, cid);
            assert_eq!(r.rule, PolicyRow::M3);
        }
        other => panic!("the cheap body is refused on the floor: {other:?}"),
    }
    assert_eq!(
        offers.admissions[2],
        (tid, Admission::Duplicate(Duplicate::InPool))
    );
    assert!(pool.record(&cid).is_none(), "the pool does not hold it");
    let carried = pool.record(&tid).expect("held");
    assert!(carried.public, "a block published it");
    assert!(shown(&carried));

    // The pool file is discardable (SPL-Q8): discard it.
    drop(pool);
    drop(std::fs::remove_file(&path));
    let plan = offer_branch(&x, &b[1..]).await;
    let switched = x.reorganize(&plan).await.expect("switch");
    assert!(
        matches!(switched, Switched::Done(_)),
        "promoted from the store's bodies: {switched:?}"
    );
    assert_eq!(x.hash_at(b[0].height).await.expect("read"), Some(b[0].hash));
    x.close().await;
    y.close().await;
}

/// The other direction (B1): a switch returns a demoted block's bodies to
/// the pool's door, which refuses one below the floor — and the store keeps
/// the demoted block's bodies with its row, so a switch back to that branch
/// lands. A third driver re-mines the first branch and extends it.
#[tokio::test]
async fn a_switch_back_promotes_a_demoted_body_the_door_refused() {
    let (mut x, prefix) = matured("pool-switch-back-x").await;
    let mut y = Scenario::open("pool-switch-back-y");
    y.mine(AT).await;
    let mut z = Scenario::open("pool-switch-back-z");
    z.mine(AT).await;
    let cheap = Spender::over(&prefix).spend_coinbase(x.wallet(), h(1), h(AT), 1);
    let a = x
        .mine_listing(vec![cheap.clone()])
        .await
        .unwrap_or_else(|o| panic!("a block may carry a transaction below the floor: {o}"));
    let a_again = z
        .mine_listing(vec![cheap.clone()])
        .await
        .unwrap_or_else(|o| panic!("z re-mines it: {o}"));
    assert_eq!(a_again.hash, a.hash, "the driver is deterministic");
    let a_ext = z.mine(2).await;
    y.idle();
    let b = y.mine(2).await;

    let path = tmp("pool-switch-back-pool");
    let mut pool = open_pool(&mut x, &path).await;
    let plan = offer_branch(&x, &b).await;
    let (switched, admissions) = x
        .reorganize_with_pool(&plan, &mut pool, UnixSeconds::from_raw(10))
        .await
        .expect("switch");
    assert!(matches!(switched, Switched::Done(_)));
    match admissions.as_slice() {
        [(txid, Admission::Refused(Judged::Policy(r)))] => {
            assert_eq!(*txid, cheap.txid_parts().hash);
            assert_eq!(r.rule, PolicyRow::M3);
        }
        other => panic!("the door refuses the cheap return: {other:?}"),
    }
    assert!(pool.is_empty());
    assert!(
        stored_bodies(&mut x, a.hash).await.is_some(),
        "the demoted block's bodies went back with its row"
    );

    let plan = offer_branch(&x, &a_ext).await;
    let switched = x.reorganize(&plan).await.expect("switch back");
    assert!(
        matches!(switched, Switched::Done(_)),
        "the switch back lands on the store's bodies: {switched:?}"
    );
    assert_eq!(x.digest().await.expect("d"), z.digest().await.expect("d"));
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
    z.close().await;
}

/// The death rule (B1): the connect that advances the tip to `t` removes
/// every alt row at or below `t − cap`, with its bodies — no switch reaches
/// it — and keeps the one at `t − cap + 1`. Under the genesis cap of 720 a
/// test would mine hundreds of blocks; the levered rules' cap is the same
/// rule at a small number.
#[tokio::test]
async fn the_connect_past_the_cap_retires_an_alt_row_and_its_bodies() {
    use crate::scenario_shard::{levered_rules, REORG_CAP_BLOCKS};
    let mut x = Scenario::open_under("pool-death-x", FreeHash, levered_rules());
    let mut y = Scenario::open_under("pool-death-y", FreeHash, levered_rules());
    x.mine(30).await;
    y.mine(30).await;
    // x's two new blocks and the alternative's two sit at the same heights,
    // so the alternative is no heavier: both are held and nothing switches.
    x.mine(2).await;
    y.idle();
    let b = y.mine(2).await;
    for mined in &b {
        assert!(matches!(
            x.offer(mined).await.expect("offer"),
            Offered::Held { .. }
        ));
    }
    // One block at a time, so each connect's sweep is the one under test:
    // until the tip reaches `b[0] + cap` both rows are reachable. x's tip is
    // the alternative's second height.
    let mut tip = b[1].height.to_raw();
    while tip + 1 < b[0].height.to_raw() + REORG_CAP_BLOCKS {
        x.mine(1).await;
        tip += 1;
        let first = stored_bodies(&mut x, b[0].hash).await;
        let second = stored_bodies(&mut x, b[1].hash).await;
        assert!(
            first.is_some() && second.is_some(),
            "both reachable at tip {tip}"
        );
    }
    x.mine(1).await;
    // The tip is `b[0] + cap`: that row is at `tip − cap` and leaves with
    // its bodies; `b[1]`'s, at `tip − cap + 1`, stays.
    let first = stored_bodies(&mut x, b[0].hash).await;
    let second = stored_bodies(&mut x, b[1].hash).await;
    assert!(
        first.is_none(),
        "the row at tip − cap and its bodies are gone"
    );
    assert!(second.is_some(), "the row at tip − cap + 1 stays");
    assert_eq!(x.alt_blocks_held().await.expect("count"), 1);
    x.mine(1).await;
    assert!(stored_bodies(&mut x, b[1].hash).await.is_none());
    assert_eq!(x.alt_blocks_held().await.expect("count"), 0);
    x.close().await;
    y.close().await;
}

/// CEN-M8: a reconcile on the anchor the door last verified the proof
/// against does not verify it again; the anchor is held in memory only, so
/// an open — the file is not trusted (the review of #1102, S2) — verifies
/// it once. Counted by the validator's own verify probe.
#[tokio::test]
async fn a_reconcile_on_the_same_anchor_skips_the_proof_and_an_open_verifies_it() {
    let (mut scenario, mined) = matured("pool-m8").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-m8-pool");
    let (same, reopened) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let now = UnixSeconds::from_raw(1);
            let (mut pool, _, _) = Pool::open(&path, now, view, rule_set, &policy).expect("open");
            let admitted = pool
                .admit(
                    spend,
                    shekyl_mempool::Arrival::Relayed,
                    now,
                    view,
                    rule_set,
                    &policy,
                )
                .expect("no fault");
            assert_eq!(
                admitted,
                Admission::Admitted {
                    evicted: Vec::new()
                },
                "fixture"
            );

            // The same anchor: the reconcile verifies no proof.
            let before = probes::fcmp_verifies();
            let reconciled = pool.reconcile(view, rule_set, &policy).expect("reconcile");
            let same = (probes::fcmp_verifies() - before, reconciled.admitted);
            drop(pool);

            // Reopened: no anchor in the file, so the proof is verified.
            let before = probes::fcmp_verifies();
            let (_, _, reconciled) =
                Pool::open(&path, now, view, rule_set, &policy).expect("reopen");
            (
                same,
                (probes::fcmp_verifies() - before, reconciled.admitted),
            )
        })
        .await;
    assert_eq!(same, (0, vec![txid]), "the cache spares the proof");
    assert_eq!(reopened, (1, vec![txid]), "an open trusts no anchor");
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The probe at run time: the door verifies exactly what the shared
/// function verifies — the same FCMP++ proofs and the same signatures —
/// and so nothing outside it.
#[tokio::test]
async fn the_door_verifies_exactly_what_the_shared_function_verifies() {
    let (mut scenario, mined) = matured("pool-probe").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let (door, shared) = scenario
        .read_chain(|view, rule_set| {
            let count = || (probes::fcmp_verifies(), probes::signature_verifies());
            let before = count();
            let judged = judge(
                &spend,
                view,
                &KeyImages::default(),
                rule_set,
                &AdmissionPolicy::GENESIS,
                None,
            )
            .expect("no fault");
            assert!(
                matches!(judged, Judged::Admitted { .. }),
                "fixture: {judged:?}"
            );
            let after_door = count();
            let connecting = Tip::connecting_height(view.tip().expect("tip").as_ref());
            let claims =
                ReferenceClaims::for_transaction(view, connecting, &spend).expect("claims");
            let mut coverage = RuleCoverage::EMPTY;
            judge_slot_stateless(&spend, TxSlot::Lone, rule_set, &claims, None, &mut coverage)
                .expect("the shared function admits it");
            let after_shared = count();
            (
                (after_door.0 - before.0, after_door.1 - before.1),
                (after_shared.0 - after_door.0, after_shared.1 - after_door.1),
            )
        })
        .await;
    assert_eq!(
        door, shared,
        "the door's verifies are the shared function's"
    );
    assert!(door.0 >= 1 && door.1 >= 1, "the subject exists: {door:?}");
    scenario.close().await;
}

fn fee_of(tx: &shekyl_wire::Transaction) -> u64 {
    match &tx.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => 0,
    }
}

/// Template selection (b6) as a pure function of the pool and the parent:
/// most fee per weight first, a candidate too heavy for what is left
/// skipped; each candidate judged again by `tx_against` against the
/// parent, so an admitted entry whose image the chain spent since it was
/// admitted is not selected, and CEN-M10 evicts it from the template's
/// refusals.
#[tokio::test]
async fn the_template_rejudges_against_its_parent_and_m10_evicts_what_it_refuses() {
    let (mut scenario, mined) = matured("pool-template").await;
    let first = paying_the_floor(&mut scenario, &mined, 0).await;
    let second = paying_the_floor(&mut scenario, &mined, 1).await;
    let dear = {
        let floor = fee_of(&second);
        Spender::over(&mined).spend_coinbase(scenario.wallet(), h(2), h(AT), floor * 10)
    };
    let (id1, id2, id3) = (
        first.txid_parts().hash,
        second.txid_parts().hash,
        dear.txid_parts().hash,
    );
    let path = tmp("pool-template-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let (ordered, budgeted) = scenario
        .read_chain(|view, rule_set| {
            for tx in [first.clone(), second.clone(), dear.clone()] {
                let txid = tx.txid_parts().hash;
                assert_eq!(
                    pool.admit(
                        tx,
                        shekyl_mempool::Arrival::Relayed,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &AdmissionPolicy::GENESIS,
                    )
                    .expect("no fault"),
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
                assert!(pool.fluffed(&txid).expect("publish"));
            }
            let all = shekyl_mempool::select(&pool, view, rule_set, u64::MAX).expect("template");
            let weight = pool
                .listing()
                .find(|(txid, _)| *txid == id3)
                .expect("shown")
                .1
                .weight;
            let one = shekyl_mempool::select(&pool, view, rule_set, weight).expect("template");
            (all, one)
        })
        .await;
    assert_eq!(
        ordered.transactions[0].0, id3,
        "the dearest per weight first"
    );
    assert_eq!(ordered.transactions.len(), 3);
    assert_eq!(
        budgeted
            .transactions
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![id3],
        "the budget holds only the first"
    );

    // Another body over `first`'s image connects; the pool is not told.
    let twin = Spender::over(&mined).spend_coinbase(
        scenario.wallet(),
        h(0),
        h(AT),
        fee_of(&first) + 1_000,
    );
    let _connected = scenario
        .mine_listing(vec![twin])
        .await
        .unwrap_or_else(|o| panic!("the twin connects: {o}"));
    let template = scenario
        .read_chain(|view, rule_set| {
            shekyl_mempool::select(&pool, view, rule_set, u64::MAX).expect("template")
        })
        .await;
    assert_eq!(
        template
            .transactions
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![id3, id2],
        "the spent one is not selected"
    );
    assert_eq!(template.refused.len(), 1);
    assert_eq!(template.refused[0].0, id1);
    assert_eq!(
        template.refused[0].1.rule,
        CenRow::I7,
        "judged against the parent"
    );
    let refused: Vec<_> = template.refused.iter().map(|(id, _)| *id).collect();
    assert_eq!(
        pool.evict(shekyl_types::BlockHeight::ZERO, &refused)
            .expect("evict"),
        vec![(id1, Evicted::Refused)]
    );
    assert!(pool.record(&id2).is_some() && pool.record(&id3).is_some());
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// CEN-M10 at admission (the review of #1102, B3), over real spends: with
/// room for one, a spend paying more per weight than the held one evicts it
/// in the same write as its own insert, and a spend paying less is refused
/// as `PoolFull` before the door runs. The pool file agrees.
#[tokio::test]
async fn a_full_pool_admits_a_better_payer_by_evicting_the_cheapest() {
    let (mut scenario, mined) = matured("pool-full").await;
    let low = paying_the_floor(&mut scenario, &mined, 0).await;
    let fee = fee_of(&low);
    let (high, lower) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(1), h(AT), fee * 4),
            spender.spend_coinbase(wallet, h(2), h(AT), fee * 2),
        )
    };
    let (low_id, high_id) = (low.txid_parts().hash, high.txid_parts().hash);
    let room = [&low, &high, &lower]
        .iter()
        .map(|tx| u64::try_from(tx.weight()).expect("fits"))
        .max()
        .expect("three");
    let path = tmp("pool-full-pool");
    let (first, second, third, held) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let now = UnixSeconds::from_raw(1);
            let (mut pool, _, _) = Pool::open(&path, now, view, rule_set, &policy).expect("open");
            pool.set_limits(Limits {
                max_weight: room,
                ..pool.limits()
            });
            let mut admit = |tx: &shekyl_wire::Transaction| {
                pool.admit(tx.clone(), Arrival::Relayed, now, view, rule_set, &policy)
                    .expect("no fault")
            };
            let first = admit(&low);
            let second = admit(&high);
            let third = admit(&lower);
            let held: Vec<_> = pool.listing().map(|(txid, _)| txid).collect();
            (first, second, third, held)
        })
        .await;
    assert_eq!(
        first,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    assert_eq!(
        second,
        Admission::Admitted {
            evicted: vec![low_id]
        },
        "the cheaper entry left to make room"
    );
    assert_eq!(third, Admission::PoolFull, "the rising minimum");
    assert_eq!(
        held,
        Vec::<shekyl_types::TxHash>::new(),
        "nothing is fluffed"
    );
    let (store, _) = PoolStore::create(&path).expect("the file");
    let filed: Vec<_> = store
        .begin_read()
        .expect("read")
        .txids()
        .expect("txids")
        .collect::<Result<_, _>>()
        .expect("rows");
    assert_eq!(
        filed,
        vec![high_id],
        "the eviction and the insert were one write"
    );
    drop(store);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// An admitted entry has no timer (B3): once the chain has moved past
/// CEN-I11's window from its reference, the reconcile removes it on that
/// refusal.
#[tokio::test]
async fn an_admitted_entry_leaves_when_its_reference_leaves_the_window() {
    let (mut scenario, mined) = matured("pool-window").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-window-pool");
    let mut pool = open_pool(&mut scenario, &path).await;
    let admitted = scenario
        .read_chain(|view, rule_set| {
            pool.admit(
                spend,
                Arrival::Relayed,
                UnixSeconds::from_raw(1),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("no fault")
        })
        .await;
    assert_eq!(
        admitted,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    scenario
        .mine(shekyl_chain_rules::REFERENCE_BLOCK_MAX_AGE.to_raw())
        .await;
    let reconciled = scenario
        .read_chain(|view, rule_set| {
            pool.reconcile(view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("reconcile")
        })
        .await;
    match reconciled.removed.as_slice() {
        [(id, shekyl_mempool::Removed::Refused(Judged::Chain { refused, .. }))] => {
            assert_eq!(*id, txid);
            assert_eq!(refused.rule, CenRow::I11, "the reference aged out");
        }
        other => panic!("removed on CEN-I11: {other:?}"),
    }
    assert!(pool.is_empty());
    drop(pool);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}
