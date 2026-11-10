// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The corpus's archival inputs, enumerated both ways
//! (`CHAIN_RULES_SLICE_8.md` §5 row 2 (a)).
//!
//! [`the_corpus_carries_exactly_these_archival_inputs`] reads every archival
//! input off the captured chains and holds them to a table written from the
//! first run: height, slot, kind, and the facts the 4.J rows judge (the hint
//! recomputes; the post's money terms; a credit's shard and epoch; a claim's
//! epochs).
//! The positive witnesses are a list: a rule that refuses one of these blocks
//! has refused a named input. The four chains with no archival input are the
//! empty list, so a capture that grows one fails the table.

use std::path::Path;

use shekyl_archival_retention::{p_canonical_id_from_hybrid_pubkey, BondPostKind as RetentionKind};
use shekyl_chain_rules::ArchivalKey;
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId};
use shekyl_wire::transaction::{BondPostKind, Holdings as WireHoldings};
use shekyl_wire::Input;

use crate::corpus::CorpusReader;
use crate::source::{IngestEvent, Source};
use crate::vectors_tests::captured_chains;

// ---------------------------------------------------------------------
// (a) The corpus, enumerated
// ---------------------------------------------------------------------

/// One archival input as the corpus carries it, reduced to the facts the
/// 4.J rows read. Heights are the block's; `slot` is the listed index.
#[derive(Debug, PartialEq, Eq)]
enum Archival {
    /// A bond post vin: its kind, whether the vin's `p_canonical_id` hint
    /// is the recompute over its `hybrid_public_key` (J11's clause), and
    /// the money terms J14 reads.
    Post {
        height: BlockHeight,
        slot: usize,
        kind: &'static str,
        hint_recomputes: bool,
        holdings: WireHoldings,
        bonded_total: u64,
        credit: u64,
        debit: u64,
    },
    /// A serve-credit **vin** (none in the corpus today).
    CreditVin {
        height: BlockHeight,
        slot: usize,
        shard: u64,
        epoch: u64,
    },
    /// An emission vin: the claimant and the epochs claimed (J19's parse).
    Claim {
        height: BlockHeight,
        slot: usize,
        epochs: Vec<u64>,
    },
}

/// Every archival input of the chain at `dir`, in corpus order, with the
/// persona each names — so the table can say *the claim is the join's
/// persona* rather than carry two hashes.
fn enumerate(dir: &Path) -> Vec<(PCanonicalId, Archival)> {
    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height();
    let mut found = Vec::new();
    while let Some(event) = reader.next().expect("corpus reads") {
        match event.event {
            IngestEvent::Extend(candidate) => {
                for (slot, tx) in candidate.transactions.iter().enumerate() {
                    for input in &tx.prefix.inputs {
                        match input {
                            Input::BondPost(post) => {
                                let recomputed =
                                    p_canonical_id_from_hybrid_pubkey(&post.hybrid_public_key);
                                let kind = match &post.kind {
                                    BondPostKind::JoinMarket { .. } => "JoinMarket",
                                    BondPostKind::Other(k) => match RetentionKind::from_u8(*k) {
                                        Ok(RetentionKind::Release) => "Release",
                                        Ok(RetentionKind::Reinstate) => "Reinstate",
                                        _ => "unknown",
                                    },
                                };
                                found.push((
                                    post.p_canonical_id,
                                    Archival::Post {
                                        height,
                                        slot,
                                        kind,
                                        hint_recomputes: recomputed == post.p_canonical_id,
                                        holdings: post.holdings.clone(),
                                        bonded_total: post.bonded_total_atomic,
                                        credit: post.bond_credit,
                                        debit: post.bond_debit,
                                    },
                                ));
                            }
                            Input::ServeCredit { .. } => {
                                let Some(ArchivalKey::ServeCredit { p, shard, epoch }) =
                                    ArchivalKey::of(input)
                                else {
                                    panic!(
                                        "{}: an unparseable serve credit at {height}",
                                        dir.display()
                                    );
                                };
                                found.push((
                                    PCanonicalId::from_bytes(p),
                                    Archival::CreditVin {
                                        height,
                                        slot,
                                        shard,
                                        epoch,
                                    },
                                ));
                            }
                            Input::ArchivalRewardEmission { .. } => {
                                let Some(ArchivalKey::Claims { p, epochs }) =
                                    ArchivalKey::of(input)
                                else {
                                    panic!(
                                        "{}: an unparseable emission vin at {height}",
                                        dir.display()
                                    );
                                };
                                found.push((
                                    PCanonicalId::from_bytes(p),
                                    Archival::Claim {
                                        height,
                                        slot,
                                        epochs,
                                    },
                                ));
                            }
                            Input::Gen(_) | Input::ToKey { .. } => {}
                        }
                    }
                }
                height = height.saturating_add(BlockCount::ONE);
            }
            IngestEvent::Rewind { to } => {
                height = to.saturating_add(BlockCount::ONE);
            }
        }
    }
    found
}

/// What the corpus carries, read off the Rust daemon's `bond-post`
/// capture at the E2 re-baseline (2026-11-01) and held. **Both
/// directions:** every chain in the corpus is here, the four with no
/// archival input as the empty list, so a capture that grows one fails
/// this table rather than slipping past it.
///
/// The facts the 4.J rows judge, as the corpus has them:
///
/// - **J11** — the post's hint recomputes from its `hybrid_public_key`.
/// - **J14** — the join carries `credit == bonded_total == one floor` on
///   the complete tree. The corpus has no compact join, so it does **not**
///   distinguish a per-shard floor from a flat one; the driver's two-shard
///   join and its one-floor negative (`scenario_archival_tests`) are the
///   witnesses that do.
/// - **No serve-credit vin, no credit, no claim, and no Release or
///   Reinstate** anywhere in the corpus: J4–J6, J13, J18–J20 have no
///   corpus-positive witness, which is why (b)–(d) build theirs on the
///   driver. No captured chain crosses a settlement epoch; `emission-claim`
///   returns with SO-D12 4b's evidence run (`docs/FOLLOWUPS.md`).
fn expected(shape: &str) -> Vec<Archival> {
    match shape {
        "bond-post" => vec![Archival::Post {
            height: BlockHeight::from_raw(98),
            slot: 0,
            kind: "JoinMarket",
            hint_recomputes: true,
            holdings: WireHoldings::CompleteTree,
            bonded_total: 750_000_000,
            credit: 750_000_000,
            debit: 0,
        }],
        "limit-full" | "median-full" | "spend-1in-2out" | "spend-depth3" => Vec::new(),
        other => panic!("a chain this table does not know: {other}"),
    }
}

#[test]
fn the_corpus_carries_exactly_these_archival_inputs() {
    let chains = captured_chains();
    assert_eq!(chains.len(), 5, "the corpus has five chains");
    for (dir, manifest) in chains {
        let found = enumerate(&dir);
        let inputs: Vec<&Archival> = found.iter().map(|(_, input)| input).collect();
        let expected = expected(&manifest.shape);
        assert_eq!(
            inputs,
            expected.iter().collect::<Vec<_>>(),
            "{}: the archival inputs the corpus carries",
            manifest.shape
        );
        // Every archival input of a chain names one persona — the join's.
        let personas: std::collections::BTreeSet<&PCanonicalId> =
            found.iter().map(|(p, _)| p).collect();
        assert!(
            personas.len() <= 1,
            "{}: one persona per chain, found {}",
            manifest.shape,
            personas.len()
        );
    }
}
