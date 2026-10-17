// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool door over the captured chains (DRS-E5 PR-b b2): every listed
//! transaction a captured chain connected passes the door's consensus
//! halves against that block's parent.
//!
//! The replay connects each captured chain into a real store; this test
//! then walks it back from the tip — read the tip block's bodies, pop it,
//! and offer each body to the door against the parent the pop left, under
//! the rule set in force at that height. The validator admitted every one
//! of those bodies at that slot, so the door (the validator's own
//! judgement at `TxSlot::Lone`) must not refuse one on a consensus row. A
//! policy refusal is allowed and counted: the captured wallets priced
//! their fees for the chain that mined them, not for this relay floor.
//!
//! The scenario half of door == validator — the refusals, each on the same
//! row both ways — is `pool_door_tests.rs`.

#![cfg(test)]

use std::sync::Arc;

use shekyl_chain_rules::{AdmissionPolicy, AtHeight};
use shekyl_chain_store::apply_policy::ApplyPolicy;
use shekyl_chain_store::store::{SnapshotView, StoreError};
use shekyl_mempool::{judge, Judged, KeyImages};

use super::{captured_chains, mock_with_the_real_clock, replay_keeping_store};
use crate::test_support::{cleanup, h, open_store_under};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_captured_body_passes_the_doors_consensus_halves_against_its_parent() {
    let substrate = mock_with_the_real_clock();
    let (mut admitted, mut priced_out) = (0usize, 0usize);
    for (dir, manifest) in captured_chains() {
        let (report, path, rules) = replay_keeping_store(
            &dir,
            &manifest,
            Arc::clone(&substrate),
            ApplyPolicy::Full,
            "pool-door",
        )
        .await;
        report
            .unwrap_or_else(|e| panic!("{}: the captured chain must replay: {e}", manifest.shape));
        let store = open_store_under(&path, &rules.in_force(h(0)), ApplyPolicy::Full);
        loop {
            let snap = store.begin_read().expect("read");
            let Some(tip) = snap.tip().expect("tip").recorded.map(|t| t.height) else {
                break;
            };
            if tip.to_raw() == 0 {
                break;
            }
            let AtHeight::Recorded(candidate) = snap.candidate_at(tip).expect("the tip's bodies")
            else {
                panic!("{}: the tip has no candidate", manifest.shape);
            };
            drop(snap);
            let popped: Result<_, StoreError> = store.write(|batch| batch.pop());
            popped.expect("the tip pops");
            let snap = store.begin_read().expect("read");
            let view = SnapshotView::new(&snap);
            let rule_set = rules.in_force(tip);
            for tx in &candidate.transactions {
                match judge(
                    tx,
                    &view,
                    &KeyImages::default(),
                    &rule_set,
                    &AdmissionPolicy::GENESIS,
                )
                .unwrap_or_else(|fault| panic!("{}: the door faulted: {fault:?}", manifest.shape))
                {
                    Judged::Admitted { .. } => admitted += 1,
                    Judged::Policy(_) => priced_out += 1,
                    refused @ (Judged::Stateless(_) | Judged::Chain(_)) => panic!(
                        "{}: a body block {tip:?} connected is refused by the door: {refused:?}",
                        manifest.shape
                    ),
                }
            }
        }
        drop(store);
        cleanup(&path);
    }
    // The subject exists: the captured chains list bodies, and the door
    // judged every one of them.
    assert!(
        admitted + priced_out > 0,
        "no captured body reached the door"
    );
    eprintln!(
        "pool door over the captured chains: {admitted} admitted, {priced_out} below the floor"
    );
}
