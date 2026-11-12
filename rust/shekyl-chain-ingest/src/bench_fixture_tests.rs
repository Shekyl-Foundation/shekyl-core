// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block-path bench fixtures (`benches/fixtures/block_path_*.corpus`):
//! the generator that writes them and the test that holds them to the tree.
//!
//! A fixture is a chain the scenario driver mined: coinbase-only blocks up
//! to the first height at which enough coinbases have matured, then one
//! block listing real spends of one shape, filled to the block weight
//! limit in force on that chain. Every block in it was admitted by the
//! validator when it was written, and the proofs in it were made once. A
//! bench that proved on every run would be timing the prover
//! (`bench_support.rs` says what the bench does measure).
//!
//! # The limit a fixture fills
//!
//! The limit is twice the effective median (CEN-G6b). On a chain whose
//! history is coinbase-only both medians sit at the full-reward zone, so
//! the limit is twice the zone. The surge ceiling (`S` times the long-term
//! median, then twice that) is reachable only after about a hundred blocks
//! of growing history, which a fixture does not carry.
//!
//! # Keeping them current
//!
//! [`every_block_path_fixture_replays`] runs in the default lane: each
//! committed corpus replays into a fresh store and its subject block passes
//! `form`, connects and pops. A consensus change that refuses a fixture
//! fails there, by fixture name, and the fix is
//! [`regenerate_block_path_fixtures`]: an `#[ignore]`d writer, never run by
//! a lane, because a lane that rewrote a fixture and then replayed it would
//! pass every night.

#![cfg(test)]

use std::io::Cursor;
use std::path::PathBuf;

use shekyl_harness_spender::Spender;
use shekyl_harness_wallet::MinerWallet;
use shekyl_network::Network;
use shekyl_types::BlockHeight;
use shekyl_wire::transaction::{COINBASE_RESERVE, MAX_FCMP_INPUTS, MAX_OUTPUTS};
use shekyl_wire::Transaction;

use crate::bench_support::BlockPath;
use crate::corpus::CorpusWriter;
use crate::scenario::{Mined, Scenario};
use crate::test_support::{h, Family, FIRST_SPEND_HEIGHT};

/// One fixture: its file stem and the spends its subject block lists.
struct Shape {
    /// `benches/fixtures/block_path_<name>.corpus`.
    name: &'static str,
    /// Coinbases each transaction spends.
    inputs_per_tx: u64,
    /// The spend of `coinbases` (their heights) connecting at `at`.
    build: fn(&Spender, &MinerWallet, &[BlockHeight], BlockHeight) -> Transaction,
}

/// The shapes, in `DAEMON_REDB_STORE.md` §1.3a.7's order where they are
/// that set's.
const SHAPES: &[Shape] = &[
    // Shape 1: the smallest spend. The per-transaction fixed costs (one
    // membership proof, one signature set) are highest per byte here, so
    // this block holds the most transactions and costs the most to verify
    // (`block_connect_verify`'s argmax).
    Shape {
        name: "spend_1in_2out",
        inputs_per_tx: 1,
        build: |spender, wallet, coinbases, at| {
            spender.spend_coinbase(wallet, coinbases[0], at, Family::Main.fee())
        },
    },
    // Shape 2: spends at the input cap. The most membership proof, key
    // images and signatures a transaction carries.
    Shape {
        name: "spend_8in_2out",
        inputs_per_tx: MAX_FCMP_INPUTS as u64,
        build: |spender, wallet, coinbases, at| {
            spender
                .spend_coinbases(wallet, coinbases, at, Family::Main.fee())
                .0
        },
    },
    // Shape 4: spends at the output cap. The most range proof, outputs and
    // tree leaves a transaction carries.
    Shape {
        name: "spend_1in_16out",
        inputs_per_tx: 1,
        build: |spender, wallet, coinbases, at| {
            spender.spend_coinbase_paying(
                wallet,
                coinbases[0],
                at,
                Family::Main.fee(),
                MAX_OUTPUTS,
            )
        },
    },
];

/// The weight a block's listed transactions may sum to on a fixture chain:
/// the limit at the zone, less the coinbase's reserve.
fn listed_budget() -> usize {
    let params = shekyl_economics::economic_params();
    let limit = shekyl_economics::block_weight_limit(params.full_reward_zone, params);
    usize::try_from(limit).expect("the limit fits") - COINBASE_RESERVE
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benches/fixtures")
        .join(format!("block_path_{name}.corpus"))
}

/// Mine `shape`'s chain: the history, then the subject block.
async fn mine(shape: &Shape) -> Vec<Mined> {
    // One probe transaction says what the shape weighs, so the count that
    // fills the budget is known before the history's length is.
    let probe_at = FIRST_SPEND_HEIGHT + shape.inputs_per_tx - 1;
    let weight = {
        let mut probe = Scenario::open(&format!("bench-probe-{}", shape.name));
        let mined = probe.mine(probe_at).await;
        let spender = Spender::over(&mined);
        let coinbases: Vec<BlockHeight> = (0..shape.inputs_per_tx).map(h).collect();
        (shape.build)(&spender, probe.wallet(), &coinbases, h(probe_at)).weight()
    };
    let count = u64::try_from(listed_budget() / weight).expect("fits");
    assert!(count > 0, "{}: one transaction fits a block", shape.name);

    // The last coinbase spent is block `count * inputs - 1`'s; the subject
    // block connects at the first height it has matured for.
    let spent = count * shape.inputs_per_tx;
    let at = FIRST_SPEND_HEIGHT + spent - 1;
    let mut scenario = Scenario::open(&format!("bench-fixture-{}", shape.name));
    let mut mined = scenario.mine(at).await;
    let listed: Vec<Transaction> = {
        let spender = Spender::over(&mined);
        let wallet = scenario.wallet();
        (0..count)
            .map(|tx| {
                let first = tx * shape.inputs_per_tx;
                let coinbases: Vec<BlockHeight> =
                    (first..first + shape.inputs_per_tx).map(h).collect();
                (shape.build)(&spender, wallet, &coinbases, h(at))
            })
            .collect()
    };
    let subject = scenario
        .mine_listing(listed)
        .await
        .unwrap_or_else(|outcome| panic!("{}: the subject block lands: {outcome}", shape.name));
    eprintln!(
        "{}: {count} transactions of weight {weight}, block weight {} at height {at}",
        shape.name,
        subject.weights.weight.to_raw()
    );
    mined.push(subject);
    mined
}

fn corpus_of(mined: &[Mined]) -> Vec<u8> {
    let mut writer =
        CorpusWriter::create(Cursor::new(Vec::new()), Network::Regtest, BlockHeight::ZERO)
            .expect("a corpus header");
    for block in mined {
        let txs: Vec<Vec<u8>> = block
            .template
            .transactions
            .iter()
            .map(Transaction::serialize)
            .collect();
        writer
            .append(&block.template.block.serialize(), &txs)
            .expect("a mined block is a corpus record");
    }
    writer.finish().expect("a finished corpus").into_inner()
}

/// Rewrite every fixture. Run by hand after a consensus change refuses one:
///
/// ```text
/// cargo test -p shekyl-chain-ingest --release regenerate_block_path_fixtures -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "fixture regenerator: rewrites benches/fixtures/block_path_*.corpus; run by hand, never by a lane"]
async fn regenerate_block_path_fixtures() {
    // `BLOCK_PATH_SHAPE=<name>` rewrites that one fixture; unset, all.
    let only = std::env::var("BLOCK_PATH_SHAPE").ok();
    if let Some(name) = &only {
        assert!(
            SHAPES.iter().any(|shape| shape.name == name),
            "BLOCK_PATH_SHAPE names no shape: {name}"
        );
    }
    for shape in SHAPES {
        if only.as_deref().is_some_and(|name| name != shape.name) {
            continue;
        }
        let corpus = corpus_of(&mine(shape).await);
        let path = fixture_path(shape.name);
        std::fs::create_dir_all(path.parent().expect("a fixtures directory"))
            .expect("the fixtures directory");
        std::fs::write(&path, &corpus).expect("write the fixture");
        eprintln!("{}: {} bytes", path.display(), corpus.len());
    }
}

/// Each committed fixture replays, and its subject block passes the three
/// calls the benches measure.
#[test]
fn every_block_path_fixture_replays() {
    for shape in SHAPES {
        let path = fixture_path(shape.name);
        let corpus = std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}; write it with regenerate_block_path_fixtures",
                path.display()
            )
        });
        let (mut chain, subject) = BlockPath::replayed(&corpus);
        assert!(
            !subject.transactions.is_empty(),
            "{}: the subject block lists the shape's spends",
            shape.name
        );
        let claimed = chain.claims(&subject);
        let formed = chain.form(subject, &claimed);
        chain.connect(formed, &claimed);
        chain.pop();
    }
}
