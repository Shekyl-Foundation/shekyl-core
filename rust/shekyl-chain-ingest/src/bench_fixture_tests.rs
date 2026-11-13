// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The block-path bench fixtures (`benches/fixtures/block_path_*.corpus`):
//! the generator that writes them and the test that holds them to the tree.
//!
//! A fixture is a chain the scenario driver mined: coinbase-only blocks up
//! to the first height at which enough coinbases have matured, then one
//! block listing real spends of one shape. Each shape has two: a **full**
//! block, filled to the block weight limit in force on that chain, and a
//! **unit** block of four transactions. Every block in it was admitted by the
//! validator when it was written, and the proofs in it were made once. A
//! bench that proved on every run would be timing the prover
//! (`bench_support.rs` says what the bench does measure).
//!
//! # Why two sizes
//!
//! The shape set is defined at the weight limit (`DAEMON_REDB_STORE.md`
//! §1.3a.7), and a full block is what `PB-D1` times. An instruction count
//! of one is too slow for every pull request: forming the 45 spends of the
//! smallest shape is 17.1 billion instructions, about twenty minutes of
//! callgrind on a loaded workstation, and the connect and pop rows pay it
//! again in setup because only `form` mints what `connect` takes (first
//! capture, 2026-11-12). `form` judges each listed transaction on its own
//! and then folds the range proofs, so a block of four carries every term
//! a block of forty-five does: the per-PR rows count the unit block, and
//! the full block's rows are the nightly capture's (`nightly.yml`,
//! `bench-full`), which compares them with the night before.
//!
//! # The limit a full fixture fills
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
//! `form`, connects and pops. It also holds each fixture to its name: every
//! listed transaction has the shape's inputs, outputs and bond post, and a
//! full block has no room for one more, so a cap that moved, or a corpus
//! under the wrong name, fails here and does not go on being counted as
//! the boundary it no longer is. A consensus change that refuses a fixture
//! fails there too, by fixture name.
//!
//! The fix is [`regenerate_block_path_fixtures`]: an `#[ignore]`d writer,
//! never run by a lane, because a lane that rewrote a fixture and then
//! replayed it would pass every night. It is armed (rule 50): it refuses
//! unless `SHEKYL_PINNED_REGEN_DECISION` cites the dated entry of the bench
//! manifest's change log ([`DECISION_LOG`]) that records why the fixtures
//! moved. A rewritten fixture moves every count taken over it, so the
//! entry is also where the new counts go.

#![cfg(test)]

use std::io::Cursor;
use std::path::PathBuf;

use shekyl_harness_spender::{complete_tree, Persona, Spender};
use shekyl_harness_wallet::MinerWallet;
use shekyl_network::Network;
use shekyl_types::BlockHeight;
use shekyl_wire::transaction::{Input, COINBASE_RESERVE, MAX_FCMP_INPUTS, MAX_OUTPUTS};
use shekyl_wire::Transaction;

use crate::archival_driver::{ENDPOINT, FEE};
use crate::bench_support::BlockPath;
use crate::corpus::CorpusWriter;
use crate::scenario::{Mined, Scenario};
use crate::test_support::{h, Family, FIRST_SPEND_HEIGHT};

/// How many transactions a fixture's subject block lists.
#[derive(Clone, Copy)]
enum Size {
    /// [`UNIT_TRANSACTIONS`]: the block the per-PR rows count.
    Unit,
    /// As many as the weight limit admits: the block the nightly capture
    /// counts, and the shape set's own definition (§1.3a.7).
    Full,
}

impl Size {
    const ALL: [Self; 2] = [Self::Unit, Self::Full];

    const fn suffix(self) -> &'static str {
        match self {
            Self::Unit => "unit",
            Self::Full => "full",
        }
    }
}

/// The transactions a [`Size::Unit`] block lists. More than one, so the
/// block's range-proof batch folds several proofs as a full block's does;
/// few, so a row is about a minute of callgrind and not twenty.
const UNIT_TRANSACTIONS: u64 = 4;

/// One shape: its name and the spends a subject block of it lists.
struct Shape {
    /// `benches/fixtures/block_path_<name>_<size>.corpus`.
    name: &'static str,
    /// Coinbases each transaction spends.
    inputs_per_tx: u64,
    /// Outputs each transaction pays.
    outputs_per_tx: usize,
    /// Whether each transaction carries a bond post.
    posts_a_bond: bool,
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
        outputs_per_tx: 2,
        posts_a_bond: false,
        build: |spender, wallet, coinbases, at| {
            spender.spend_coinbase(wallet, coinbases[0], at, Family::Main.fee())
        },
    },
    // Shape 2: spends at the input cap. The most membership proof, key
    // images and signatures a transaction carries.
    Shape {
        name: "spend_8in_2out",
        inputs_per_tx: MAX_FCMP_INPUTS as u64,
        outputs_per_tx: 2,
        posts_a_bond: false,
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
        outputs_per_tx: MAX_OUTPUTS,
        posts_a_bond: false,
        build: |spender, wallet, coinbases, at| {
            spender.spend_coinbase_paying(wallet, coinbases[0], at, Family::Main.fee(), MAX_OUTPUTS)
        },
    },
    // Shape 6: bond posts. Each transaction is a coinbase spend with a
    // complete-tree join riding it, by its own persona: the post's input,
    // its cleartext term and the bond slot's signature, which CEN-J27,
    // CEN-H21 and CEN-L7 judge beside the spend's rows. A complete-tree
    // join needs no closed shard, so the chain is the other shapes'.
    Shape {
        name: "bond_post",
        inputs_per_tx: 1,
        outputs_per_tx: 2,
        posts_a_bond: true,
        build: |spender, wallet, coinbases, at| {
            // One persona a transaction: the slot is the coinbase's height.
            let slot = u32::try_from(coinbases[0].to_raw()).expect("a short chain");
            let persona = Persona::at(slot);
            let join = persona.join(complete_tree(), ENDPOINT);
            spender.spend_coinbase_posting(wallet, coinbases[0], at, FEE, Some(&join))
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

fn fixture_name(shape: &Shape, size: Size) -> String {
    format!("{}_{}", shape.name, size.suffix())
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benches/fixtures")
        .join(format!("block_path_{name}.corpus"))
}

/// Mine `shape`'s chain at `size`: the history, then the subject block.
async fn mine(shape: &Shape, size: Size) -> Vec<Mined> {
    let name = fixture_name(shape, size);
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
    let fills = u64::try_from(listed_budget() / weight).expect("fits");
    assert!(
        fills >= UNIT_TRANSACTIONS,
        "{name}: a full block holds at least the unit block's transactions"
    );
    let count = match size {
        Size::Unit => UNIT_TRANSACTIONS,
        Size::Full => fills,
    };

    // The last coinbase spent is block `count * inputs - 1`'s; the subject
    // block connects at the first height it has matured for.
    let spent = count * shape.inputs_per_tx;
    let at = FIRST_SPEND_HEIGHT + spent - 1;
    let mut scenario = Scenario::open(&format!("bench-fixture-{name}"));
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
        .unwrap_or_else(|outcome| panic!("{name}: the subject block lands: {outcome}"));
    eprintln!(
        "{name}: {count} transactions of weight {weight}, block weight {} at height {at}",
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

/// Where a regeneration is recorded: the bench manifest's change log.
const DECISION_LOG: &str = "docs/benchmarks/shekyl_rust_v0.manifest.md";

/// Rewrite the fixtures. Run by hand after a consensus change refuses one,
/// citing the manifest change-log entry that records the move:
///
/// ```text
/// SHEKYL_PINNED_REGEN_DECISION="YYYY-MM-DD <rationale>" \
///   cargo test -p shekyl-chain-ingest regenerate_block_path_fixtures -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "fixture regenerator: rewrites benches/fixtures/block_path_*.corpus; run by hand, never by a lane"]
async fn regenerate_block_path_fixtures() {
    // `BLOCK_PATH_FIXTURE=<shape>_<size>` rewrites that one fixture;
    // unset, all.
    let only = std::env::var("BLOCK_PATH_FIXTURE").ok();
    // Before anything is mined or written.
    shekyl_crypto_pq::test_support::regen_decision_in_log_or_refuse(
        only.as_deref().unwrap_or("every block-path fixture"),
        DECISION_LOG,
    );
    let mut written = 0;
    for shape in SHAPES {
        for size in Size::ALL {
            let name = fixture_name(shape, size);
            if only.as_deref().is_some_and(|only| only != name) {
                continue;
            }
            let corpus = corpus_of(&mine(shape, size).await);
            let path = fixture_path(&name);
            std::fs::create_dir_all(path.parent().expect("a fixtures directory"))
                .expect("the fixtures directory");
            std::fs::write(&path, &corpus).expect("write the fixture");
            eprintln!("{}: {} bytes", path.display(), corpus.len());
            written += 1;
        }
    }
    assert!(written > 0, "BLOCK_PATH_FIXTURE names no fixture: {only:?}");
}

/// Each committed fixture replays, and its subject block passes the three
/// calls the benches measure.
#[test]
fn every_block_path_fixture_replays() {
    for shape in SHAPES {
        for size in Size::ALL {
            let name = fixture_name(shape, size);
            let path = fixture_path(&name);
            let corpus = std::fs::read(&path).unwrap_or_else(|e| {
                panic!(
                    "{}: {e}; write it with regenerate_block_path_fixtures",
                    path.display()
                )
            });
            let (mut chain, subject) = BlockPath::replayed(&corpus);
            let listed = u64::try_from(subject.transactions.len()).expect("fits");
            let mut weight = 0;
            for tx in &subject.transactions {
                let spends = tx
                    .prefix
                    .inputs
                    .iter()
                    .filter(|input| matches!(input, Input::ToKey { .. }))
                    .count();
                let posts = tx
                    .prefix
                    .inputs
                    .iter()
                    .filter(|input| matches!(input, Input::BondPost(_)))
                    .count();
                assert_eq!(
                    u64::try_from(spends).expect("fits"),
                    shape.inputs_per_tx,
                    "{name}: inputs"
                );
                assert_eq!(
                    tx.prefix.outputs.len(),
                    shape.outputs_per_tx,
                    "{name}: outputs"
                );
                assert_eq!(posts, usize::from(shape.posts_a_bond), "{name}: bond posts");
                assert_eq!(
                    spends + posts,
                    tx.prefix.inputs.len(),
                    "{name}: no other input kind"
                );
                weight += tx.weight();
            }
            match size {
                Size::Unit => assert_eq!(listed, UNIT_TRANSACTIONS, "{name}"),
                // Full means full: one more transaction of the shape would
                // pass the budget. A raised limit or a lighter transaction
                // leaves the block short of the boundary it is named for.
                Size::Full => {
                    let one = subject.transactions[0].weight();
                    assert!(weight <= listed_budget(), "{name}: within the budget");
                    assert!(
                        weight + one > listed_budget(),
                        "{name}: {listed} transactions of {one} leave room in {}; regenerate",
                        listed_budget()
                    );
                }
            }
            let claimed = chain.claims(&subject);
            let formed = chain.form(subject, &claimed);
            chain.connect(formed, &claimed);
            chain.pop();
        }
    }
}
