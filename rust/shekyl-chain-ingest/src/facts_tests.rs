// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The facts seam, exercised through the connector it feeds: `Composed`
//! folds the producer's priced figures onto the parent's record and hands
//! `connect` what the store persists; a height nobody priced is
//! `NoFacts`, not a default.

use std::collections::BTreeMap;
use std::sync::Arc;

use kameo::actor::Spawn;
use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{
    form, AtHeight, Candidate, FormAttempt, RuleSet, StructurallyValid, Verdict,
};
use shekyl_chain_store::store::Origin;
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, Transaction};

use crate::connector::{Apply, Connector, ConnectorArgs, RunFault};
use crate::facts::{block_weight, Composed, Priced, PricedAt};
use crate::schedule::ChainRules;
use crate::test_support::{chain, cleanup, h, open_store, root_after, tmp};

const GENESIS_RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: None,
};

/// A producer's ledger: what it priced each height at.
#[derive(Default)]
struct Table(BTreeMap<u64, Priced>);

impl PricedAt for Table {
    fn priced_at(&self, height: BlockHeight) -> Option<Priced> {
        self.0.get(&height.to_raw()).copied()
    }
}

/// `height` priced at `reward`, burning `burned`, the fixture root after.
fn priced(height: u64, reward: u64, burned: u64) -> (u64, Priced) {
    (
        height,
        Priced {
            block_reward: AtomicUnits::from_raw(reward),
            burned: AtomicUnits::from_raw(burned),
            root_after: root_after(height),
            long_term_effective_median: LongTermWeight::from_raw(300_000),
        },
    )
}

fn formed(
    height: u64,
    block: &Block,
    txs: &[Transaction],
    seed: BlockHash,
) -> (BlockHeight, Verdict<StructurallyValid>) {
    let verdict = form(
        Candidate::new(block.clone(), txs.to_vec()),
        &RuleSet::GENESIS,
        &MockSubstrate::default(),
        seed,
        FormAttempt::FIRST,
    )
    .expect("mock substrate forms");
    (h(height), verdict)
}

#[tokio::test]
async fn composed_folds_the_priced_reward_onto_the_parents_record() {
    let path = tmp("facts-composed-fold");
    let chain = chain(3);
    let table = Table(
        [priced(0, 10, 0), priced(1, 20, 3), priced(2, 30, 4)]
            .into_iter()
            .collect(),
    );
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        facts: Arc::new(Composed::new(table)),
    });

    let (h0, f0) = formed(0, &chain[0].0, &chain[0].1, BlockHash::NULL);
    let (h1, f1) = formed(1, &chain[1].0, &chain[1].1, chain[0].0.hash());
    let (h2, f2) = formed(2, &chain[2].0, &chain[2].1, chain[0].0.hash());
    let applied = connector
        .ask(Apply(vec![(h0, f0), (h1, f1), (h2, f2)]))
        .await
        .expect("connects");
    assert_eq!(applied.connected.len(), 3);
    assert!(applied.refused.is_none());
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;

    let store = open_store(&path);
    let read = store.begin_read().expect("read");
    // CEN-F13's accumulator: each record is its parent's plus its reward.
    let coins: Vec<u64> = (0..3)
        .map(|hh| match read.block_info(h(hh)).expect("read") {
            AtHeight::Recorded(info) => info.coins_generated.to_raw(),
            AtHeight::AboveTip => panic!("recorded"),
        })
        .collect();
    assert_eq!(coins, vec![10, 30, 60]);
    // The burn is recorded per block and folded.
    assert_eq!(read.total_burned().expect("read").to_raw(), 7);
    // The root after `h` is the state at `h + 1` (SCW-19).
    for hh in 0..3u64 {
        assert_eq!(
            read.root_at(h(hh + 1)).expect("read"),
            AtHeight::Recorded(root_after(hh)),
            "root_after({hh}) at {}",
            hh + 1
        );
    }
    // The weight is the wire's: coinbase plus bodies.
    for (hh, (block, txs)) in chain.iter().enumerate() {
        let expected = u64::try_from(
            block.miner_transaction.weight() + txs.iter().map(Transaction::weight).sum::<usize>(),
        )
        .expect("fits");
        match read.block_info(h(hh as u64)).expect("read") {
            AtHeight::Recorded(info) => {
                assert_eq!(info.weight.to_raw(), expected, "weight at {hh}")
            }
            AtHeight::AboveTip => panic!("recorded"),
        }
    }
    drop(read);
    drop(store);
    cleanup(&path);
}

#[tokio::test]
async fn a_height_nobody_priced_is_no_facts_and_the_writer_stays_up() {
    let path = tmp("facts-composed-unpriced");
    let chain = chain(2);
    // Height 1 is missing from the ledger.
    let table = Table([priced(0, 10, 0)].into_iter().collect());
    let connector = Connector::spawn(ConnectorArgs {
        store: open_store(&path),
        rules: GENESIS_RULES,
        facts: Arc::new(Composed::new(table)),
    });

    let (h0, f0) = formed(0, &chain[0].0, &chain[0].1, BlockHash::NULL);
    let (h1, f1) = formed(1, &chain[1].0, &chain[1].1, chain[0].0.hash());
    let err = connector
        .ask(Apply(vec![(h0, f0), (h1, f1)]))
        .await
        .expect_err("height 1 has no price");
    assert!(
        matches!(
            err,
            kameo::error::SendError::HandlerError(RunFault::NoFacts { height }) if height == h(1)
        ),
        "{err}"
    );

    // The closure aborted as a unit: genesis did not land either (one
    // write transaction per Apply), and the writer is not over.
    let (h0, f0) = formed(0, &chain[0].0, &chain[0].1, BlockHash::NULL);
    let applied = connector
        .ask(Apply(vec![(h0, f0)]))
        .await
        .expect("the writer stays up; genesis alone is priced");
    assert_eq!(applied.connected.len(), 1);
    connector.stop_gracefully().await.expect("stop");
    connector.wait_for_shutdown().await;
    cleanup(&path);
}

/// Why a `Composed` field is `PassedThrough` — the two distances from done
/// that `Provenance::passed_through` folds into one count (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    /// A provisional source of our own; a deletion when the row lands.
    Composed,
    /// Nothing of ours produces it; the caller supplies it as the trace did.
    NoSourceYet,
}

#[test]
fn every_composed_origin_is_passed_through_until_its_row_lands() {
    // The honesty pin: `Composed` marks nothing `Derived` today — `Derived`
    // is what `Provenance::is_parity_evidence` trusts, and a self-computed
    // field marked so would let a driver-built store claim parity evidence
    // for a field no rule judged. The `DeletedBy` rows that make each
    // field the validator's have not landed on the verdict. When one does,
    // this test names the field whose origin flips — and the `Why` column
    // says how far each field is from that: four have a provisional source
    // here, two have none.
    let chain = chain(1);
    let table = Table([priced(0, 10, 0)].into_iter().collect());
    let composed = Composed::new(table);
    let mock = shekyl_chain_rules::harness::MockChain::default();
    let (h0, f0) = formed(0, &chain[0].0, &chain[0].1, BlockHash::NULL);
    let formed = f0.expect("forms");
    mock.with_view(|view| {
        let valid = shekyl_chain_rules::harness::judged(shekyl_chain_rules::validate(
            formed,
            &view,
            &RuleSet::GENESIS,
            &shekyl_chain_rules::Trust::UNANCHORED,
        ))
        .expect("genesis validates on an empty chain");
        let facts =
            crate::facts::FactsFor::facts_for(&composed, h0, &valid, &view).expect("priced");
        assert_eq!(facts.weight.value, block_weight(&valid));
        assert_eq!(
            facts.coins_generated.value.to_raw(),
            10,
            "genesis folds from zero"
        );
        assert_eq!(facts.root_after.value, root_after(0));
        let table = [
            ("weight", facts.weight.origin, Why::Composed),
            (
                "long_term_weight",
                facts.long_term_weight.origin,
                Why::Composed,
            ),
            (
                "coins_generated",
                facts.coins_generated.origin,
                Why::Composed,
            ),
            ("burned", facts.burned.origin, Why::Composed),
            ("root_after", facts.root_after.origin, Why::NoSourceYet),
            (
                "long_term_effective_median",
                facts.long_term_effective_median.origin,
                Why::NoSourceYet,
            ),
        ];
        for (field, origin, _) in table {
            assert_eq!(origin, Origin::PassedThrough, "{field}");
        }
        // The decomposition of the E6 counter: how many passed-through
        // fields are one deletion from `Derived`, and how many wait on a
        // source that does not exist here yet.
        let composed = table
            .iter()
            .filter(|(_, _, why)| *why == Why::Composed)
            .count();
        let unsourced = table
            .iter()
            .filter(|(_, _, why)| *why == Why::NoSourceYet)
            .count();
        assert_eq!(
            (composed, unsourced),
            (4, 2),
            "passed-through = 4 composed + 2 unsourced"
        );
    });
    let _ = CurveTreeRoot::EMPTY;
}
