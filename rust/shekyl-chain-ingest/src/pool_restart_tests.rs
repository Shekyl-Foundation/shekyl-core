// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file across a restart (DRS-E5 PR-b b5; `DRS_E1_SPOOL.md` SPL-7,
//! `SPL-Q5`, `SPL-Q8`): the reconcile at open brings what the file held up
//! to the chain as it stands, and the file is discardable — a node that
//! loses it loses only the transactions it held.

use shekyl_chain_rules::AdmissionPolicy;
use shekyl_chain_store::pool::PoolOpen;
use shekyl_mempool::{Admission, Arrival, Pool, Removed};
use shekyl_types::UnixSeconds;

use crate::pool_door_tests::{matured, paying_the_floor};
use crate::test_support::tmp;

/// Two spends held; the node stops; a block mines one while the pool file
/// is closed (the chain committed, the pool did not — SPL-7's crash
/// between the two commits); at open the reconcile removes the mined one
/// from memory and from the file, keeps the other admitted with its
/// public bit, and a second open finds the file already reconciled.
#[tokio::test]
async fn a_restart_reconciles_the_pool_file_against_the_chain() {
    let (mut scenario, mined) = matured("pool-restart").await;
    let a = paying_the_floor(&mut scenario, &mined, 0).await;
    let b = paying_the_floor(&mut scenario, &mined, 1).await;
    let (ida, idb) = (a.txid_parts().hash, b.txid_parts().hash);
    let path = tmp("pool-restart-pool");
    let policy = AdmissionPolicy::GENESIS;
    scenario
        .read_chain(|view, rule_set| {
            let (mut pool, how, _) = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("open");
            assert_eq!(how, PoolOpen::Created);
            for tx in [a.clone(), b] {
                assert_eq!(
                    pool.admit(
                        tx,
                        Arrival::Relayed,
                        UnixSeconds::from_raw(1),
                        view,
                        rule_set,
                        &policy
                    )
                    .expect("no fault"),
                    Admission::Admitted {
                        evicted: Vec::new()
                    }
                );
            }
            assert!(pool.fluffed(&idb).expect("publish"));
        })
        .await;
    // The chain moves while the pool is closed.
    let _mined = scenario
        .mine_listing(vec![a])
        .await
        .unwrap_or_else(|o| panic!("a connects: {o}"));
    let (first, second) = scenario
        .read_chain(|view, rule_set| {
            let (pool, how, reconciled) = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("open");
            assert_eq!(how, PoolOpen::Opened);
            let held = (
                pool.record(&ida).is_some(),
                pool.record(&idb).map(|r| r.public),
            );
            drop(pool);
            let first = (reconciled, held);
            let (_, _, again) = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("reopen");
            (first, again)
        })
        .await;
    let (reconciled, held) = first;
    assert_eq!(reconciled.removed, vec![(ida, Removed::Mined)]);
    assert_eq!(reconciled.admitted, vec![idb]);
    assert_eq!(held, (false, Some(true)), "a gone, b held and still public");
    assert!(
        second.removed.is_empty(),
        "the file was reconciled the first time"
    );
    assert_eq!(second.admitted, vec![idb]);
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The file is discardable (`SPL-Q8`): removed between runs, the pool opens
/// empty on a fresh file, the chain is untouched, and the transaction the
/// lost file held is admitted again when it arrives again.
#[tokio::test]
async fn the_pool_file_can_be_discarded() {
    let (mut scenario, mined) = matured("pool-discard").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let path = tmp("pool-discard-pool");
    let policy = AdmissionPolicy::GENESIS;
    let digest_before = scenario.digest().await.expect("digest");
    scenario
        .read_chain(|view, rule_set| {
            let (mut pool, _, _) = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("open");
            pool.admit(
                spend.clone(),
                Arrival::Relayed,
                UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("no fault");
        })
        .await;
    std::fs::remove_file(&path).expect("the operator discards the pool file");
    let readmitted = scenario
        .read_chain(|view, rule_set| {
            let (mut pool, how, reconciled) = Pool::open(
                &path,
                shekyl_types::UnixSeconds::from_raw(1),
                view,
                rule_set,
                &policy,
            )
            .expect("open");
            assert_eq!(how, PoolOpen::Created, "a fresh file");
            assert!(pool.is_empty() && reconciled.removed.is_empty());
            pool.admit(
                spend,
                Arrival::Relayed,
                UnixSeconds::from_raw(2),
                view,
                rule_set,
                &policy,
            )
            .expect("no fault")
        })
        .await;
    assert_eq!(
        readmitted,
        Admission::Admitted {
            evicted: Vec::new()
        }
    );
    assert_eq!(
        scenario.digest().await.expect("digest"),
        digest_before,
        "the chain never read the pool file"
    );
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// Kept has one entry point (the review of #1102, S4): the reconcile never
/// makes an admitted entry kept. Two bodies over one coinbase's image are
/// in the file as admitted (held before the chain moved), one paying above
/// the floor and one paying one atomic unit; a third body over the same
/// image is mined. At open both are refused by CEN-I7 — the cheap one with
/// CEN-M3 beside it, in the door's one answer — and both leave.
#[tokio::test]
async fn a_reconcile_removes_an_admitted_entry_the_chain_now_refuses() {
    use shekyl_chain_rules::{CenRow, PolicyRow};
    use shekyl_chain_store::pool::{PoolRecord, PoolStore, Standing};
    use shekyl_harness_spender::Spender;
    use shekyl_mempool::Judged;

    use crate::pool_door_tests::AT;
    use crate::test_support::h;

    let (mut scenario, mined) = matured("pool-keep-policy").await;
    let good = paying_the_floor(&mut scenario, &mined, 0).await;
    let fee = match &good.ct {
        shekyl_wire::transaction::Ct::Fcmp { fee, .. } => *fee,
        shekyl_wire::transaction::Ct::Null(_) => unreachable!("a spend"),
    };
    let (paid, cheap) = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (
            spender.spend_coinbase(wallet, h(0), h(AT), fee + 1_000),
            spender.spend_coinbase(wallet, h(0), h(AT), 1),
        )
    };
    let (idp, idc) = (paid.txid_parts().hash, cheap.txid_parts().hash);
    let path = tmp("pool-keep-policy-pool");
    {
        let (store, _) = PoolStore::create(&path).expect("create");
        for (at, tx) in [(1, &paid), (2, &cheap)] {
            let record = PoolRecord {
                received: shekyl_chain_store::pool::ReceivedHour::from_raw(at),
                public: true,
                standing: Standing::Admitted,
            };
            store
                .write(|batch| batch.insert(tx.txid_parts().hash, &record, &tx.serialize()))
                .expect("planted");
        }
    }
    let _mined = scenario
        .mine_listing(vec![good])
        .await
        .unwrap_or_else(|o| panic!("the third body connects: {o}"));
    let reconciled = scenario
        .read_chain(|view, rule_set| {
            Pool::open(
                &path,
                // Past both filed hours, so neither is clamped and the order held
                // stands.
                shekyl_types::UnixSeconds::from_raw(1_700_000_000),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("open")
            .2
        })
        .await;
    assert!(reconciled.kept.is_empty(), "the reconcile keeps nothing");
    assert!(reconciled.admitted.is_empty());
    match reconciled.removed.as_slice() {
        [(
            first,
            Removed::Refused(Judged::Chain {
                refused: a,
                policy: None,
            }),
        ), (
            second,
            Removed::Refused(Judged::Chain {
                refused: b,
                policy: Some(m3),
            }),
        )] => {
            assert_eq!((*first, *second), (idp, idc), "in the order held");
            assert_eq!((a.rule, b.rule), (CenRow::I7, CenRow::I7));
            assert_eq!(m3.rule, PolicyRow::M3);
        }
        other => panic!("both leave, each on the door's answer: {other:?}"),
    }
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}

/// The file's receive time is not trusted (the review of #1102, S2): a
/// filed spend claiming to have arrived years from now opens at the hour of
/// `now`, and its weight and fee are read off its bytes.
#[tokio::test]
async fn an_open_clamps_a_receive_time_from_the_future() {
    use shekyl_chain_store::pool::{PoolRecord, PoolStore, ReceivedHour, Standing};

    let (mut scenario, mined) = matured("pool-clamp").await;
    let spend = paying_the_floor(&mut scenario, &mined, 0).await;
    let txid = spend.txid_parts().hash;
    let path = tmp("pool-clamp-pool");
    {
        let (store, _) = PoolStore::create(&path).expect("create");
        let record = PoolRecord {
            received: ReceivedHour::from_raw(u64::MAX / 2),
            public: true,
            standing: Standing::Admitted,
        };
        store
            .write(|batch| batch.insert(txid, &record, &spend.serialize()))
            .expect("planted");
    }
    let now = UnixSeconds::from_raw(1_700_000_000);
    let (received, listed) = scenario
        .read_chain(|view, rule_set| {
            let (pool, _, reconciled) =
                Pool::open(&path, now, view, rule_set, &AdmissionPolicy::GENESIS).expect("open");
            assert_eq!(reconciled.admitted, vec![txid]);
            let listed = pool.listing().find(|(id, _)| *id == txid).expect("shown").1;
            (pool.record(&txid).expect("held").received, listed)
        })
        .await;
    assert_eq!(received, ReceivedHour::of(now));
    assert_eq!(listed.weight, u64::try_from(spend.weight()).expect("fits"));
    drop(std::fs::remove_file(&path));
    scenario.close().await;
}
