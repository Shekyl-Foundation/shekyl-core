// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CEN-G2 through the production pipeline (`CHAIN_RULES_SLICE_7.md` §3.1,
//! §5 rows 2 and 6). CEN-G2 is the pairing of a block's listed bodies to
//! the hashes its header declares. These tests build the first two-body
//! block the driver ever listed, replay it three ways through the pipeline
//! against three fresh stores, and hold what each does.
//!
//! **What commit 2 measured, before the rule existed (2026-09-26,
//! records-was):** the merkle over the declared list is an input to the
//! identity (B6), the bodies arrive positionally, and nothing compared a
//! body to the hash it came in under — so (2) the same block with its
//! bodies **swapped** connected, and the store assigned the two
//! transactions' outputs **in body order**: two honest nodes handed the same
//! block with bodies in different orders disagreed on every global output
//! index in it, which is the curve tree's drain order (`GlobalOutputIndex`'s
//! doc; E3 §3.3) — why G2 is a precondition for E3's correctness rather
//! than a tidiness rule; and (3) the same block with one body
//! **substituted** by a transaction the header never listed connected, and
//! the unlisted body's outputs were recorded under a block whose identity
//! did not cover them.
//!
//! **What commit 6 holds, with G2 a `FormRule` (slice 7 Q7):**
//!
//! 1. Two bodies through `mine_listing` connect, as before.
//! 2. The swap is refused at `Locus::Tx { slot: Listed(0) }` — the first
//!    index whose body is not the declared hash — before any body reaches
//!    the store: the output table holds neither transaction.
//! 3. The substitution is refused at `Listed(1)`: index 0 still agrees, so
//!    the locus is the rule's evidence, not "a mismatch somewhere". Nothing
//!    of the block is recorded.
//!
//! The refusal is `form`'s, so the pipeline never opened a write for the
//! block; the empty output table is what makes the drain-order hazard
//! closed rather than narrowed.

use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_chain_rules::harness::MockSubstrate;
use shekyl_chain_rules::{Candidate, CenRow, Locus, TxSlot};
use shekyl_chain_store::store::{AtIndex, ChainStore, Horizons};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHash, BlockHeight, GlobalOutputIndex, Timestamp, TxHash};
use shekyl_wire::{Block, Transaction};

use crate::metrics::Metrics;
use crate::pipeline::{run, PipelineConfig, RunReport};
use crate::scenario::{Mined, Scenario, RULES};
use crate::source::IngestEvent;
use crate::test_support::{
    anchor, cleanup, key_image, open_store, spend, tmp, trace_with, Family, Scripted,
    TraceEconomics, EPOCH, FIRST_SPEND_HEIGHT,
};
use crate::trace::Trace;

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

    /// The trace for replaying `chain`. Economics are what the driver priced
    /// for the block at that height. The root after each block is what
    /// `chain` grows: [`trace_with`](crate::test_support::trace_with) writes
    /// it from that chain's tree, so the row describes these bodies.
    ///
    /// `chain` is the driver's blocks in order. Body order is not part of
    /// the block hash, so a mutation of the listed bodies still names the
    /// block the driver mined.
    fn trace(&self, chain: &Chain) -> Trace {
        assert_eq!(
            chain.len(),
            self.mined.len(),
            "a replay trace covers every block the driver mined"
        );
        for (index, (mined, (block, _))) in self.mined.iter().zip(chain).enumerate() {
            let height = u64::try_from(index).expect("a fixture height fits");
            assert_eq!(
                mined.height.to_raw(),
                height,
                "the driver mined densely from genesis"
            );
            assert_eq!(
                mined.hash,
                block.hash(),
                "height {height}: the replayed header is the block the driver mined"
            );
        }
        // The trace's accumulator is the tree's derivation (slice 7 commit
        // 5), not a fold over the driver's priced rewards: the replay then
        // holds the validator's paid reward to the ratified composition,
        // and `Priced` no longer carries a reward to fold.
        trace_with(
            chain,
            |height| {
                let mined = &self.mined[usize::try_from(height).expect("a fixture height fits")];
                // Regtest difficulty is 1, so the accumulator after this
                // block is `height + 1`.
                TraceEconomics {
                    burned: mined.template.fees_burned,
                    cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
                }
            },
            false,
        )
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
/// `name` under `trace`. Returns the report and the store's path; the
/// caller cleans up after reading it.
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

/// The refusal is G2's, at `locus`, on the two-body block — and the run
/// connected exactly the blocks before it.
fn refused_on_g2(report: &RunReport, name: &str, locus: Locus) {
    let (at, refused) = report
        .refused
        .as_ref()
        .unwrap_or_else(|| panic!("{name}: G2 refuses this shape; the run connected it"));
    assert_eq!(
        *at,
        BlockHeight::from_raw(FIRST_SPEND_HEIGHT),
        "{name}: refused at the two-body block"
    );
    assert_eq!(
        refused.rule,
        CenRow::G2,
        "{name}: the row is G2, not a neighbour"
    );
    assert_eq!(
        refused.locus, locus,
        "{name}: the locus is the rule's evidence"
    );
    assert_eq!(
        report.connected.len(),
        usize::try_from(FIRST_SPEND_HEIGHT).expect("small"),
        "{name}: every block before the refusal connected, and nothing after"
    );
}

fn connected_through(report: &RunReport, chain: &Chain, name: &str) {
    assert!(
        report.refused.is_none(),
        "{name}: a well-paired block connects: {:?}",
        report.refused
    );
    assert_eq!(
        report.connected.len(),
        chain.len(),
        "{name}: every block connected"
    );
    // CTW-5. The count is first (rule 47): a comparison that ran over
    // nothing is not a comparison. The trace was built for this chain, so
    // a divergence here is the oracle disagreeing with the store.
    let heights = u64::try_from(chain.len()).expect("a fixture chain fits");
    assert_eq!(
        report.roots.compared(),
        heights,
        "{name}: {heights} blocks connected and {} had a recorded root",
        report.roots.compared()
    );
    assert!(
        !report.roots.any_diverged(),
        "{name}: the derived root differs from the trace at {:?}",
        report.roots.diverged().map(|d| d.at).collect::<Vec<_>>()
    );
}

/// (1) and (2): the driver's two-body block connects and records a's
/// outputs before b's; the same block with its bodies swapped is refused on
/// G2 at `Listed(0)`, and the second store records neither.
#[tokio::test]
async fn a_reordered_two_body_block_is_refused_on_g2_and_records_no_output() {
    let driven = two_body_chain("g2-reorder-driver").await;
    let (chain, a, b) = (driven.chain(), &driven.a, &driven.b);
    let at = usize::try_from(FIRST_SPEND_HEIGHT).expect("small");

    let (as_listed, listed_path) = replay("as-listed", &chain, driven.trace(&chain)).await;
    connected_through(&as_listed, &chain, "as listed");

    let mut swapped = chain.clone();
    swapped[at].1.swap(0, 1);
    assert_eq!(
        swapped[at].0.transaction_hashes,
        vec![a.hash(), b.hash()],
        "the header still declares [a, b]; only the bodies moved"
    );
    let (reordered, swapped_path) = replay("swapped", &swapped, driven.trace(&swapped)).await;
    refused_on_g2(
        &reordered,
        "swapped",
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );

    // As listed, the store's output order is the declared order: a's
    // outputs take the lower global indices. Swapped, the block never
    // reached the store — the hazard commit 2 measured (two honest nodes
    // holding different output tables for one block) is closed at `form`.
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
        !swapped_order.contains(&a.hash()) && !swapped_order.contains(&b.hash()),
        "swapped: neither body's outputs are recorded — the refusal is form's, before a write"
    );
}

/// (3): a body the header never listed, in place of one it did, is refused
/// on G2 at `Listed(1)` — index 0 agrees — and nothing of the block is
/// recorded.
#[tokio::test]
async fn a_substituted_body_the_header_never_listed_is_refused_on_g2() {
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
    let (report, path) = replay("substituted", &substituted, driven.trace(&substituted)).await;
    refused_on_g2(
        &report,
        "substituted",
        Locus::Tx {
            slot: TxSlot::Listed(1),
        },
    );

    let order = output_origins(&path);
    cleanup(&path);
    assert!(
        !order.contains(&c.hash()) && !order.contains(&a.hash()) && !order.contains(&b.hash()),
        "no body of the refused block is recorded — not the unlisted one, not the listed ones"
    );
}
