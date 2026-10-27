// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool's own bookkeeping over the harness chain: CEN-M1 before the
//! door, and a refusal that leaves no trace in memory or in the file.

use shekyl_chain_rules::harness::fixture::{listed_on, spendable_chain};
use shekyl_chain_rules::{AdmissionPolicy, RuleSet, Tip};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, UnixSeconds};

use super::{Admission, Arrival, Duplicate, Pool, Step1};
use crate::door::Judged;

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "shekyl-mempool-{name}-{}-{:?}.redb",
        std::process::id(),
        std::thread::current().id()
    ));
    drop(std::fs::remove_file(&p));
    p
}

/// CEN-M1 answers before the door: a transaction the chain holds is a
/// duplicate even when its bytes would be refused — nothing is judged.
#[test]
fn a_transaction_the_chain_holds_is_a_duplicate_and_is_not_judged() {
    let path = tmp("m1-chain");
    let base = spendable_chain();
    let tx = listed_on(&base, [0x41; 32]);
    let chain = base.with_transaction(tx.txid_parts().hash);
    let admission = chain.with_view(|view| {
        let (mut pool, _, _) = Pool::open(
            &path,
            UnixSeconds::from_raw(1),
            &view,
            &RuleSet::GENESIS,
            &AdmissionPolicy::GENESIS,
        )
        .unwrap();
        pool.admit(
            tx,
            UnixSeconds::from_raw(1),
            &view,
            &RuleSet::GENESIS,
            &AdmissionPolicy::GENESIS,
        )
        .unwrap()
    });
    assert_eq!(admission, Admission::Duplicate(Duplicate::OnChain));
    drop(std::fs::remove_file(&path));
}

/// A refusal is the door's answer and leaves nothing: not in memory, not
/// in the file — a reopen finds an empty pool.
#[test]
fn a_refused_transaction_leaves_no_trace() {
    let path = tmp("refused");
    let chain = spendable_chain();
    let tx = listed_on(&chain, [0x42; 32]);
    chain.with_view(|view| {
        let (mut pool, _, _) = Pool::open(
            &path,
            UnixSeconds::from_raw(1),
            &view,
            &RuleSet::GENESIS,
            &AdmissionPolicy::GENESIS,
        )
        .unwrap();
        let admission = pool
            .admit_from(
                tx,
                Step1::Judge(None),
                Arrival::Carried,
                UnixSeconds::from_raw(1),
                &view,
                &RuleSet::GENESIS,
                &AdmissionPolicy::GENESIS,
            )
            .unwrap();
        // A block-carried body the door refuses is not held, whatever
        // refused it (CEN-K10: no reorg retention).
        assert!(
            matches!(admission, Admission::Refused(Judged::Stateless(_))),
            "a fixture body is refused on its bytes: {admission:?}"
        );
        assert!(pool.is_empty());
        drop(pool);
        let (pool, _, reconciled) = Pool::open(
            &path,
            UnixSeconds::from_raw(1),
            &view,
            &RuleSet::GENESIS,
            &AdmissionPolicy::GENESIS,
        )
        .unwrap();
        assert!(pool.is_empty());
        assert_eq!(reconciled, crate::reconcile::Reconciled::default());
    });
    drop(std::fs::remove_file(&path));
}

fn marker(height: u64, byte: u8, work: u128) -> super::JudgedTip {
    super::JudgedTip {
        tip: Tip {
            height: BlockHeight::from_raw(height),
            hash: BlockHash::from_bytes([byte; 32]),
        },
        work: CumulativeDifficulty::from_raw(work),
    }
}

/// Fork-choice work orders the judged tip. A same-height reorg is heavier,
/// so it replaces the marker and a template on the old tip no longer
/// matches it. A lighter snapshot does not put the old tip back, and equal
/// work under two hashes clears the marker.
#[test]
fn work_orders_the_judged_tip_across_a_reorg() {
    let old = marker(4, 0xA1, 100);
    let same_height = marker(4, 0xB2, 140);
    let shorter = marker(3, 0xC3, 180);
    let tie = marker(4, 0xD4, 140);
    assert_eq!(super::judged_tip_after(None, old), Some(old));
    assert_eq!(super::judged_tip_after(Some(old), old), Some(old));
    assert_eq!(
        super::judged_tip_after(Some(old), same_height),
        Some(same_height)
    );
    assert_eq!(super::judged_tip_after(Some(old), shorter), Some(shorter));
    assert_eq!(
        super::judged_tip_after(Some(same_height), old),
        Some(same_height)
    );
    assert_eq!(super::judged_tip_after(Some(same_height), tie), None);
}
