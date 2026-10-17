// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool and blocks, over the production stack (DRS-E5 PR-b b4): a
//! switch's returns run the door (CEN-K10), an alternative's bodies are
//! supplemented through it and promoted from the pool (CEN-K9), CEN-M8's
//! anchor spares a re-admission the proof, and the door verifies nothing
//! the shared function does not.
//!
//! Two drivers mine one prefix and then different branches; one's blocks
//! arrive at the other as alternatives (the switch tests' shape).

use shekyl_chain_rules::{
    judge_slot_stateless, probes, AdmissionPolicy, CenRow, HeaderView, PolicyRow, ReferenceClaims,
    RuleCoverage, Tip, TxSlot,
};
use shekyl_chain_store::pool::{PoolStore, ProvenReference, Standing};
use shekyl_harness_spender::Spender;
use shekyl_mempool::{judge, shown, Admission, Evicted, Judged, KeyImages, Limits, Pool};
use shekyl_types::{CurveTreeRoot, UnixSeconds};

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
        Pool::open(path, view, rule_set, &AdmissionPolicy::GENESIS)
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
    assert_eq!(admissions[0], (paid.txid_parts().hash, Admission::Admitted));
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
async fn a_returned_spend_whose_reference_aged_out_is_kept_and_evicted_after_the_week() {
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
    assert_eq!(record.standing, Standing::Kept);
    assert!(!shown(&record));
    assert_eq!(pool.listing().count(), 0, "kept is shown nowhere");
    assert_eq!(pool.peer_sync().count(), 0);
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
    // Past the admitted lifetime it stays; past the kept one it goes.
    let limits = Limits::GENESIS;
    let later = UnixSeconds::from_raw(now.to_raw() + limits.admitted_lifetime + 1);
    assert!(pool.evict(later, &limits, &[]).expect("evict").is_empty());
    let week = UnixSeconds::from_raw(now.to_raw() + limits.kept_lifetime + 1);
    assert_eq!(
        pool.evict(week, &limits, &[]).expect("evict"),
        vec![(txid, Evicted::KeptAged)]
    );
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
}

/// CEN-K9: an alternative's listed bodies are offered to the door before
/// the block is held. A body refused on its bytes refuses the alternative
/// (the answer is the door's, at `Lone`); one the door admits is held, and
/// the switch that promotes the block reads it from the pool.
#[tokio::test]
async fn an_alternatives_bodies_are_supplemented_through_the_door_and_promoted_from_the_pool() {
    let (mut x, prefix) = matured("pool-supplement-x").await;
    let mut y = Scenario::open("pool-supplement-y");
    y.mine(AT).await;
    let _a = x.mine(1).await;
    let spend = paying_the_floor(&mut y, &prefix, 0).await;
    y.idle();
    let mut b = vec![y
        .mine_listing(vec![spend.clone()])
        .await
        .unwrap_or_else(|o| panic!("the spend connects on the alternative: {o}"))];
    b.extend(y.mine(1).await);

    let path = tmp("pool-supplement-pool");
    let mut pool = open_pool(&mut x, &path).await;
    let now = UnixSeconds::from_raw(10);
    // A moved body in the alternative's listing refuses it.
    let mut moved = spend.clone();
    moved.prefix.unlock_time += 1;
    let refused = x
        .read_chain(|view, rule_set| {
            pool.supplement(vec![moved], now, view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("no fault")
        })
        .await;
    match refused {
        Err(r) => {
            assert_eq!(r.rule, CenRow::I18);
            assert_eq!(
                r.locus,
                shekyl_chain_rules::Locus::Input {
                    slot: TxSlot::Lone,
                    input: 0
                }
            );
        }
        Ok(()) => panic!("a moved body refuses the alternative"),
    }
    assert!(pool.is_empty(), "a refused body is not held");
    // The real bodies are supplemented and held, public.
    for mined in &b {
        let listed = mined.template.transactions.clone();
        let supplemented = x
            .read_chain(|view, rule_set| {
                pool.supplement(listed, now, view, rule_set, &AdmissionPolicy::GENESIS)
                    .expect("no fault")
            })
            .await;
        assert_eq!(supplemented, Ok(()));
    }
    let txid = spend.txid_parts().hash;
    assert!(pool.record(&txid).expect("held").public);
    // The switch reads the promoted bodies from the pool.
    let plan = offer_branch(&x, &b).await;
    let (switched, _) = x
        .reorganize_with_pool(&plan, &mut pool, now)
        .await
        .expect("switch");
    assert!(
        matches!(switched, Switched::Done(_)),
        "promoted from the pool's bodies"
    );
    // Mined now: the reconcile removes it.
    let reconciled = x
        .read_chain(|view, rule_set| {
            pool.reconcile(view, rule_set, &AdmissionPolicy::GENESIS)
                .expect("reconcile")
        })
        .await;
    assert!(reconciled
        .removed
        .iter()
        .any(|(id, why)| *id == txid && *why == shekyl_mempool::Removed::Mined));
    drop(pool);
    drop(std::fs::remove_file(&path));
    x.close().await;
    y.close().await;
}

/// CEN-M8: a re-admission whose anchor is the chain's claim does not verify
/// the FCMP++ proof again; one whose stored anchor moved does, and stores
/// the chain's. Counted by the validator's own verify probe.
#[tokio::test]
async fn a_readmission_on_the_same_anchor_skips_the_proof_and_a_moved_anchor_verifies_it() {
    let (mut scenario, mined) = matured("pool-m8").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-m8-pool");
    let (admitted_anchor, same, moved) = scenario
        .read_chain(|view, rule_set| {
            let policy = AdmissionPolicy::GENESIS;
            let (mut pool, _, _) = Pool::open(&path, view, rule_set, &policy).expect("open");
            let admitted = pool
                .admit(
                    spend,
                    shekyl_mempool::Arrival::Relayed,
                    UnixSeconds::from_raw(1),
                    view,
                    rule_set,
                    &policy,
                )
                .expect("no fault");
            assert_eq!(admitted, Admission::Admitted, "fixture");
            let Standing::Admitted { proven } = pool.record(&txid).expect("held").standing else {
                unreachable!("admitted");
            };
            let anchor = proven.expect("a spend's anchor");
            drop(pool);

            // The same anchor: the reconcile at open verifies no proof.
            let before = probes::fcmp_verifies();
            let (pool, _, reconciled) = Pool::open(&path, view, rule_set, &policy).expect("reopen");
            let same = (
                probes::fcmp_verifies() - before,
                reconciled.admitted.clone(),
            );
            drop(pool);

            // A moved anchor: the proof is verified again, and the chain's
            // anchor replaces the stored one.
            {
                let (store, _) = PoolStore::create(&path).expect("the file");
                let off = ProvenReference {
                    root: CurveTreeRoot::from_bytes([0x77; 32]),
                    ..anchor
                };
                store
                    .write(|batch| batch.stand(&txid, Standing::Admitted { proven: Some(off) }))
                    .expect("plant");
            }
            let before = probes::fcmp_verifies();
            let (pool, _, _) = Pool::open(&path, view, rule_set, &policy).expect("reopen");
            let moved = (
                probes::fcmp_verifies() - before,
                pool.record(&txid).expect("held").standing,
            );
            (anchor, same, moved)
        })
        .await;
    assert_eq!(same, (0, vec![txid]), "the cache spares the proof");
    assert_eq!(
        moved,
        (
            1,
            Standing::Admitted {
                proven: Some(admitted_anchor)
            }
        ),
        "a moved anchor is verified again and replaced"
    );
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
