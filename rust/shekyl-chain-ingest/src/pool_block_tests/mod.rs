// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool and blocks, over the production stack (DRS-E5 PR-b b4): a
//! switch's returns run the door and are dropped if refused (no reorg
//! retention: CEN-K10 is deleted); an alternative's bodies are
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
use shekyl_chain_store::pool::PoolStore;
use shekyl_harness_spender::Spender;
use shekyl_mempool::{
    judge, shown, Admission, Duplicate, Evicted, Judged, KeyImages, Limits, Pool,
};
use shekyl_types::UnixSeconds;

use crate::connector::{Offered, Switched};
use crate::pool_door_tests::{matured, paying_the_floor, AT};
use crate::scenario::{FreeHash, Mined, Scenario};
use crate::test_support::{h, tmp};

mod producer;

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

/// A switch's returns and CEN-M3 together: two transactions a popped block listed come
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
    let record = pool
        .relay_view()
        .record(&paid.txid_parts().hash)
        .expect("held");
    assert!(record.public, "a block carried it");
    assert!(shown(&record), "and the node shows it");
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
}

/// CEN-K10 has no retention (ruled 2026-10-17): a returned spend whose
/// reference has aged out of CEN-I11's window on the chain the switch left
/// is refused by the door like any arrival and not held — not kept, not
/// shown, not filed, and its key image free. Its body is not lost: the
/// demoted block's bodies are the chain store's (AL8), which is what a
/// switch back connects. A relayed resubmit is judged again and refused.
#[tokio::test]
async fn a_returned_spend_the_chain_refuses_is_dropped_and_the_store_keeps_its_body() {
    let (mut x, prefix) = matured("pool-aged-x").await;
    let mut y = Scenario::open("pool-aged-y");
    y.mine(AT).await;
    let spend = paying_the_floor(&mut x, &prefix, 0).await;
    let a = x
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
    match admissions.as_slice() {
        [(id, Admission::Refused(Judged::Chain(refused)))] => {
            assert_eq!(*id, txid);
            assert_eq!(refused.rule, CenRow::I11, "its reference aged out");
        }
        other => panic!("the aged-out return is refused: {other:?}"),
    }
    assert!(pool.relay_view().record(&txid).is_none(), "not held");
    assert_eq!(pool.relay_view().len(), 0);
    assert!(
        !pool
            .relay_view()
            .key_images()
            .contains(&shekyl_types::KeyImage::from_bytes(
                match &spend.prefix.inputs[0] {
                    shekyl_wire::transaction::Input::ToKey { key_image, .. } => *key_image,
                    _ => unreachable!("a spend"),
                }
            )),
        "its key image blocks no other spend"
    );
    // The body is the store's: the demoted block's row carries it.
    let demoted = stored_bodies(&mut x, a.hash)
        .await
        .expect("the demoted block's bodies are the store's");
    assert!(demoted.transactions().contains(&spend));
    // Submitted again by relay, it is judged like any arrival.
    let again = x
        .read_chain(|view, rule_set| {
            pool.admit(
                spend.clone(),
                UnixSeconds::from_raw(2),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("no fault")
        })
        .await;
    match again {
        Admission::Refused(Judged::Chain(refused)) => {
            assert_eq!(refused.rule, CenRow::I11, "its reference aged out");
        }
        other => panic!("a resubmit is judged again: {other:?}"),
    }
    assert!(pool.relay_view().record(&txid).is_none());
    drop(pool);
    let filed = PoolStore::create(&path)
        .expect("the pool file")
        .0
        .begin_read()
        .expect("a snapshot")
        .len()
        .expect("len");
    assert_eq!(filed, 0, "nothing was filed");
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
            pool.admit(stem.clone(), now, view, rule_set, &policy)
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
        !shown(&pool.relay_view().record(&tid).expect("held")),
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
    assert!(
        pool.relay_view().record(&cid).is_none(),
        "the pool does not hold it"
    );
    let carried = pool.relay_view().record(&tid).expect("held");
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
    assert!(pool.relay_view().is_empty());
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

/// Regtest at fixed difficulty one under a reorg cap of `cap` blocks: a
/// cap wide enough for a long branch to sit inside it, and small enough to
/// cross in a test.
fn rules_with_cap(cap: u64) -> crate::schedule::ChainRules {
    crate::schedule::ChainRules::Regtest {
        fixed_difficulty: Some(std::num::NonZeroU128::MIN),
        schedule: shekyl_chain_rules::FakechainSchedule::new(
            shekyl_chain_rules::SettlementEpochBlocks::new(100).expect("non-zero"),
            shekyl_types::BlockCount::from_raw(cap),
        )
        .expect("the cap sits inside the epoch"),
    }
}

/// Offer every block of `branch` to `x` and require each to be held.
async fn hold_all(x: &Scenario<FreeHash>, branch: &[Mined]) {
    for mined in branch {
        assert!(
            matches!(x.offer(mined).await.expect("offer"), Offered::Held { .. }),
            "block {:?} not held",
            mined.height
        );
    }
}

/// The death rule (B1) takes a branch whole: the connect that advances the
/// tip to `t` removes every alt row at or below `t − cap` and every row
/// built on one of them (`store/alt.rs`). Under a cap of 40 a 30-block
/// branch, mined beside the main chain from its block 1, is all reachable
/// until the tip is its lowest row (2) plus the cap. The connect that
/// crosses that row leaves the other 29 above the line, every one built on
/// it, and takes them too. A one-row branch at 3 hanging from main block 2
/// stays until its own row is crossed.
#[tokio::test]
async fn the_connect_that_crosses_a_branch_retires_it_whole() {
    const CAP: u64 = 40;
    const LENGTH: u64 = 30;
    let rules = rules_with_cap(CAP);
    let mut x = Scenario::open_under("pool-death-x", FreeHash, rules);
    let mut y = Scenario::open_under("pool-death-y", FreeHash, rules);
    let mut z = Scenario::open_under("pool-death-z", FreeHash, rules);
    x.mine(2).await;
    y.mine(2).await;
    z.mine(3).await;
    y.idle();
    let mut branch = Vec::new();
    for _ in 0..LENGTH {
        x.mine(1).await;
        // The same height as x's new tip, so no heavier: held, not switched.
        let mined = y.mine(1).await;
        hold_all(&x, &mined).await;
        branch.extend(mined);
    }
    let lowest = branch[0].height.to_raw();
    assert_eq!(lowest, 2);
    z.idle();
    let beside = z.mine(1).await;
    hold_all(&x, &beside).await;
    assert_eq!(beside[0].height, h(3));
    let held = LENGTH + 1;
    // One block at a time, so each connect's sweep is the one under test.
    let mut tip = branch.last().expect("branch").height.to_raw();
    while tip + 1 < lowest + CAP {
        x.mine(1).await;
        tip += 1;
        assert_eq!(
            x.alt_blocks_held().await.expect("count"),
            held,
            "every row reachable at tip {tip}"
        );
    }
    x.mine(1).await;
    // The tip is `lowest + cap`: the branch's lowest row is at `tip − cap`,
    // the other 29 above it and every one built on it.
    for mined in &branch {
        assert!(
            stored_bodies(&mut x, mined.hash).await.is_none(),
            "the branch's row at {} left with its lowest",
            mined.height.to_raw()
        );
    }
    assert!(stored_bodies(&mut x, beside[0].hash).await.is_some());
    assert_eq!(x.alt_blocks_held().await.expect("count"), 1);
    x.mine(1).await;
    assert_eq!(x.alt_blocks_held().await.expect("count"), 0);
    x.close().await;
    y.close().await;
    z.close().await;
}

/// A rewind takes the branches built on the blocks it pops: they no longer
/// reach the main chain (`store/alt.rs`). Main blocks 0..=6; `y`'s two rows
/// at 5 and 6 hang from main block 4, `z`'s row at 3 from main block 2.
/// Rewinding to 3 pops 4, 5 and 6: `y`'s branch leaves, `z`'s stays.
#[tokio::test]
async fn a_rewind_takes_the_branches_on_what_it_pops() {
    let mut x = Scenario::open("pool-rewind-x");
    let mut y = Scenario::open("pool-rewind-y");
    let mut z = Scenario::open("pool-rewind-z");
    x.mine(7).await;
    y.mine(5).await;
    y.idle();
    let on_popped = y.mine(2).await;
    z.mine(3).await;
    z.idle();
    let on_kept = z.mine(1).await;
    hold_all(&x, &on_popped).await;
    hold_all(&x, &on_kept).await;
    assert_eq!(x.alt_blocks_held().await.expect("count"), 3);
    x.rewind_to(h(3)).await.expect("rewind");
    assert_eq!(x.alt_blocks_held().await.expect("count"), 1);
    assert!(stored_bodies(&mut x, on_kept[0].hash).await.is_some());
    for mined in &on_popped {
        assert!(stored_bodies(&mut x, mined.hash).await.is_none());
    }
    x.close().await;
    y.close().await;
    z.close().await;
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
                .admit(spend, now, view, rule_set, &policy)
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
            judge_slot_stateless(&spend, TxSlot::Lone, rule_set, &claims, &mut coverage)
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
