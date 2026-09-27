// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! E6 slice 7 commit 2 (a): **the G2 measurement**, taken through the
//! driver before any 4.G rule exists (`CHAIN_RULES_SLICE_7.md` §3.1, §5 row
//! 2). CEN-G2 is the pairing of a block's listed bodies to the hashes its
//! header declares. Nothing in the validator holds it today: the merkle
//! over the declared list is an input to the identity (B6), the bodies
//! arrive positionally, and `ValidatedBlock::derive` recomputes each
//! identity from the body. These tests build the first two-body block the
//! driver has ever listed, replay it three ways through the production
//! pipeline against three fresh stores, and record what each does.
//!
//! **They pin today's gap.** When commit 6 lands G2 as a `FormRule`, the
//! reorder and the substitution refuse at their loci and these assertions
//! flip — the same shape as the E2 family's `assert_pinned_gap`: a refusal
//! here before then means the row landed early, and the census flips, not
//! this file.
//!
//! What is measured, not asserted from the plan:
//!
//! 1. Two bodies through `mine_listing` connect (the driver's first).
//! 2. The same block with its bodies **swapped** connects, and the store
//!    assigns the two transactions' outputs **in body order** — so two
//!    honest nodes handed the same block with bodies in different orders
//!    disagree on every global output index in it. That order is the curve
//!    tree's drain order (`GlobalOutputIndex`'s doc; E3 §3.3), which is why
//!    G2 is a precondition for E3's correctness.
//! 3. The same block with one body **substituted** by a transaction the
//!    header never listed connects, and the unlisted body's outputs are
//!    recorded under a block whose identity does not cover them.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::Candidate;
use shekyl_chain_store::store::{AtIndex, ChainStore, Horizons};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_economics::FULL_REWARD_ZONE;
use shekyl_types::{
    BlockHash, BlockHeight, BlockWeight, GlobalOutputIndex, LongTermWeight, Timestamp, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, Transaction};

use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::scenario::{Mined, Scenario, RULES};
use crate::source::IngestEvent;
use crate::test_support::{
    anchor, cleanup, key_image, open_store, spend, tmp, Family, GrownTree, Scripted, EPOCH,
    FIRST_SPEND_HEIGHT,
};
use crate::trace::{Facts, Trace, TraceWriter};

/// A chain the driver built: every block's template, as `(block, bodies)`.
type Chain = Vec<(Block, Vec<Transaction>)>;

/// What the driver built: every mined block, and the two bodies of the last
/// one in the header's order.
struct Driven {
    mined: Vec<Mined>,
    a: Transaction,
    b: Transaction,
}

impl Driven {
    fn chain(&self) -> Chain {
        self.mined
            .iter()
            .map(|m| (m.template.block.clone(), m.template.transactions.clone()))
            .collect()
    }

    /// The facts the driver's producer recorded per block — the trace the
    /// replay passes through, so the replay's `connect` sees the rewards the
    /// driver priced. The root after each block is the validator's
    /// derivation (DRS-E3): the replay derives it again and holds it to this
    /// row (CTW-5), so the row carries what the same blocks grow
    /// (`GrownTree`, the production `tree_after` over the driver's chain) —
    /// a root the driver's headers carry (B5) and the replay must reproduce.
    fn trace(&self) -> Trace {
        let mut w = TraceWriter::new(Vec::new()).expect("header");
        let tree = GrownTree::over(&self.chain());
        let mut coins = AtomicUnits::ZERO;
        for m in &self.mined {
            coins = AtomicUnits::from_raw(shekyl_economics::advance_already_generated(
                coins.to_raw(),
                m.template.block_reward.to_raw(),
            ));
            let facts = Facts {
                weight: BlockWeight::from_raw(m.template.block_weight),
                long_term_weight: LongTermWeight::from_raw(FULL_REWARD_ZONE),
                coins_generated: coins,
                burned: m.template.fees_burned,
                root_after: tree.root_after(m.height.to_raw()),
                long_term_effective_median: LongTermWeight::from_raw(FULL_REWARD_ZONE),
                cumulative_difficulty: CumulativeDifficulty::from_raw(
                    u128::from(m.height.to_raw()) + 1,
                ),
            };
            w.push_facts(m.height, &facts).expect("facts");
        }
        Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
    }
}

/// Mine `FIRST_SPEND_HEIGHT` empty blocks, then one block listing two
/// anchored spends — the first two-body block through the driver.
async fn two_body_chain(name: &str) -> Driven {
    let mut scenario = Scenario::open(name);
    let mut mined = scenario.mine(FIRST_SPEND_HEIGHT).await;
    let hashes: Vec<BlockHash> = mined.iter().map(|m| m.hash).collect();
    let at = FIRST_SPEND_HEIGHT;
    let a = anchor(&hashes, at, spend(key_image(Family::Main, at)));
    let b = anchor(&hashes, at, spend(key_image(Family::Fork, at)));
    let two = scenario
        .mine_listing(vec![a.clone(), b.clone()])
        .await
        .unwrap_or_else(|outcome| panic!("the driver lists two bodies: {outcome}"));
    assert_eq!(
        two.template.block.transaction_hashes,
        vec![a.hash(), b.hash()],
        "the template declares the bodies it was handed, in order"
    );
    assert_eq!(two.height, BlockHeight::from_raw(at));
    mined.push(two);
    Driven { mined, a, b }
}

/// Replay `chain` through the production pipeline into a fresh store at
/// `name`, with the driver's facts, returning the report and the store's
/// path (the caller cleans up after reading it).
async fn replay(name: &str, chain: &Chain, trace: Trace) -> (RunReport, std::path::PathBuf) {
    let path = tmp(&format!("g2-{name}"));
    let mut source = Scripted::new(
        chain
            .iter()
            .map(|(b, txs)| IngestEvent::Extend(Box::new(Candidate::new(b.clone(), txs.clone()))))
            .collect(),
    );
    // C1 judges the header against the substrate's clock; the driver's
    // blocks carry the driver's timestamps, so the replay clock is the last
    // of them (a header may not lead the clock by more than FTL; it may
    // trail it freely).
    let clock = Timestamp::from_raw(chain.last().expect("non-empty").0.header.timestamp);
    let substrate = MockSubstrate {
        clock,
        longhash: MockSubstrate::always_satisfies,
    };
    let report = run(
        &mut source,
        Arc::new(substrate),
        Arc::new(Metrics::new()),
        RULES,
        open_store(&path),
        Arc::new(trace),
        PipelineConfig {
            window: NonZeroUsize::new(4).expect("non-zero"),
            hashers: NonZeroUsize::new(2).expect("non-zero"),
        },
    )
    .await
    .unwrap_or_else(|fault| panic!("{name}: the run faulted: {fault}"));
    (report, path)
}

/// Every recorded output's originating transaction, in global-index order —
/// the order the curve tree will drain them in.
fn output_origins(path: &std::path::Path) -> Vec<TxHash> {
    let store = ChainStore::open_read_only(path, Horizons::production(EPOCH).expect("SEB > D_MAX"))
        .expect("reopen read-only");
    let snapshot = store.begin_read().expect("read");
    let mut origins = Vec::new();
    for index in 0u64.. {
        match snapshot
            .output_origin(GlobalOutputIndex::from_raw(index))
            .expect("output_origin reads")
        {
            AtIndex::Recorded(out) => origins.push(out.tx_hash),
            AtIndex::BeyondCount => break,
        }
    }
    origins
}

fn connected_through(report: &RunReport, chain: &Chain, name: &str) {
    assert!(
        report.refused.is_none(),
        "{name}: G2 is Pending, so the block connects today; a refusal here means the row \
         landed — flip the census and this file, in that order: {:?}",
        report.refused
    );
    assert_eq!(
        report.connected.len(),
        chain.len(),
        "{name}: every block connected"
    );
}

/// (1) and (2): the driver's two-body block connects; the same block with
/// its bodies swapped connects too, and the two stores assign the two
/// transactions' outputs in opposite orders.
#[tokio::test]
async fn a_reordered_two_body_block_connects_and_two_stores_disagree_on_output_order() {
    let driven = two_body_chain("g2-reorder-driver").await;
    let (chain, a, b) = (driven.chain(), &driven.a, &driven.b);
    let at = usize::try_from(FIRST_SPEND_HEIGHT).expect("small");

    let (as_listed, listed_path) = replay("as-listed", &chain, driven.trace()).await;
    connected_through(&as_listed, &chain, "as listed");

    let mut swapped = chain.clone();
    swapped[at].1.swap(0, 1);
    assert_eq!(
        swapped[at].0.transaction_hashes,
        vec![a.hash(), b.hash()],
        "the header still declares [a, b]; only the bodies moved"
    );
    let (reordered, swapped_path) = replay("swapped", &swapped, driven.trace()).await;
    connected_through(&reordered, &swapped, "swapped");
    assert_eq!(
        as_listed.connected, reordered.connected,
        "both runs connect the same block identities — the identity is over the declared list"
    );

    // The measurement: the store's output order follows the bodies, not the
    // header. Under [a, b] a's outputs precede b's; under [b, a] they follow.
    let listed_order = output_origins(&listed_path);
    let swapped_order = output_origins(&swapped_path);
    cleanup(&listed_path);
    cleanup(&swapped_path);
    let position = |order: &[TxHash], tx: &Transaction| {
        order
            .iter()
            .position(|h| *h == tx.hash())
            .unwrap_or_else(|| panic!("{} has recorded outputs", tx.hash()))
    };
    assert!(
        position(&listed_order, a) < position(&listed_order, b),
        "as listed: a's outputs take the lower global indices"
    );
    assert!(
        position(&swapped_order, b) < position(&swapped_order, a),
        "swapped: b's outputs take the lower global indices — the same block, a different \
         output order, and (E3 §3.3) a different leaf order"
    );
    assert_ne!(
        listed_order, swapped_order,
        "two honest nodes handed the same block in different body orders now hold different \
         output tables"
    );
}

/// (3): a body the header never listed connects in place of one it did,
/// and its outputs are recorded under a block whose identity does not
/// cover it.
#[tokio::test]
async fn a_substituted_body_the_header_never_listed_connects() {
    let driven = two_body_chain("g2-substitute-driver").await;
    let (chain, a, b) = (driven.chain(), &driven.a, &driven.b);
    let at = usize::try_from(FIRST_SPEND_HEIGHT).expect("small");
    let hashes: Vec<BlockHash> = chain[..at].iter().map(|(blk, _)| blk.hash()).collect();
    // A third spend, admissible on its own: anchored like the others, a key
    // image neither family used at this height.
    let c = anchor(
        &hashes,
        FIRST_SPEND_HEIGHT,
        spend(key_image(Family::Fork, FIRST_SPEND_HEIGHT + 1_000)),
    );
    assert_ne!(c.hash(), b.hash());

    let mut substituted = chain.clone();
    substituted[at].1[1] = c.clone();
    assert_eq!(
        substituted[at].0.transaction_hashes,
        vec![a.hash(), b.hash()],
        "the header still declares b"
    );
    let (report, path) = replay("substituted", &substituted, driven.trace()).await;
    connected_through(&report, &substituted, "substituted");

    let order = output_origins(&path);
    cleanup(&path);
    assert!(
        order.contains(&c.hash()),
        "the unlisted body's outputs are recorded — under a block whose identity never named it"
    );
    assert!(
        !order.contains(&b.hash()),
        "the declared body was never recorded; the header lists a hash with no body behind it"
    );
}
