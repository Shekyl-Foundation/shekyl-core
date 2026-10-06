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
//! recomputes; the credit's epoch against the join's; the claim's epochs).
//! The positive witnesses are a list: a rule that refuses one of these blocks
//! has refused a named input. The four chains with no archival input are the
//! empty list, so a capture that grows one fails the table.

use std::path::Path;

use shekyl_archival_retention::{
    p_canonical_id_from_hybrid_pubkey, serve_credit_epoch_ok, BondPostKind as RetentionKind,
    ARCHIVAL_BOND_FLOOR_ATOMIC,
};
use shekyl_chain_rules::{ArchivalKey, SettlementEpochBlocks, SettlementSchedule};
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
    /// A serve-credit **vin** (none in the corpus today — the injected
    /// credit is a record, below).
    CreditVin {
        height: BlockHeight,
        slot: usize,
        shard: u64,
        epoch: u64,
    },
    /// An `Inject` record: a credit no block produced, attributed to the
    /// tip it was written at. Not a vin: J4–J6 never see it.
    Injected {
        at_tip: BlockHeight,
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
fn enumerate(dir: &Path) -> (Vec<(PCanonicalId, Archival)>, SettlementSchedule) {
    let manifest_text = std::fs::read_to_string(dir.join("manifest.json")).expect("manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).expect("json");
    let seb = manifest["settlement_epoch_blocks"]
        .as_u64()
        .expect("the manifest names its schedule");
    let schedule = SettlementSchedule::new(SettlementEpochBlocks::new(seb).expect("non-zero"));

    let corpus = std::fs::read(dir.join("corpus.e2")).expect("read corpus.e2");
    let mut reader =
        CorpusReader::open(std::io::Cursor::new(corpus.as_slice())).expect("open corpus");
    let mut height = reader.first_height();
    let mut tip: Option<BlockHeight> = None;
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
                tip = Some(height);
                height = height.saturating_add(BlockCount::ONE);
            }
            IngestEvent::Rewind { to } => {
                tip = Some(to);
                height = to.saturating_add(BlockCount::ONE);
            }
            IngestEvent::Inject(credit) => found.push((
                credit.persona,
                Archival::Injected {
                    at_tip: tip.expect("the corpus law refuses an inject before any block"),
                    shard: credit.shard.to_raw(),
                    epoch: credit.epoch.to_raw(),
                },
            )),
        }
    }
    (found, schedule)
}

/// What the corpus carries, read off the two chains on 2026-10-04 and
/// held. **Both directions:** every chain in the corpus is here, the four
/// with no archival input as the empty list, so a capture that grows one
/// fails this table rather than slipping past it.
///
/// The facts the 4.J rows will judge, as the corpus has them today:
///
/// - **J11** — both posts' hints recompute from their `hybrid_public_key`.
/// - **J14** — both joins carry `credit == bonded_total == one floor`:
///   the complete tree's floor and a one-shard compact set's are the same
///   number (`bond_floor_of`), so the corpus does **not** distinguish a
///   per-shard floor from a flat one; a rule that gets the multiplier
///   wrong passes the corpus. The driver's two-shard join and its
///   one-floor negative (`scenario_archival_tests`) are the witnesses
///   that do.
/// - **J5** — the one credit is the injector's, at epoch `E_join + 1`,
///   written while epoch 0 was still open (tip 115 of a 512-block epoch):
///   a credit *for* an epoch that has not begun. It is a record, not a
///   vin, so J4–J6 never read it; its epoch arithmetic is the injector's
///   contract (`Inject`'s law), not 4.J's.
/// - **J19/J20** — the one claim names the credited epoch and no other,
///   two epochs after the join, by the join's persona.
/// - **No serve-credit vin and no Release or Reinstate** anywhere in the
///   corpus: J4–J6, J13, J18 have no corpus-positive witness, which is why
///   (b)–(d) build theirs on the driver.
fn expected(shape: &str) -> Vec<Archival> {
    match shape {
        "bond-post" => vec![Archival::Post {
            height: BlockHeight::from_raw(98),
            slot: 0,
            kind: "JoinMarket",
            hint_recomputes: true,
            holdings: WireHoldings::CompleteTree,
            bonded_total: ARCHIVAL_BOND_FLOOR_ATOMIC,
            credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
            debit: 0,
        }],
        "emission-claim" => vec![
            Archival::Post {
                height: BlockHeight::from_raw(98),
                slot: 0,
                kind: "JoinMarket",
                hint_recomputes: true,
                holdings: WireHoldings::ShardSetCompact(vec![0]),
                bonded_total: ARCHIVAL_BOND_FLOOR_ATOMIC,
                credit: ARCHIVAL_BOND_FLOOR_ATOMIC,
                debit: 0,
            },
            Archival::Injected {
                at_tip: BlockHeight::from_raw(115),
                shard: 0,
                epoch: 1,
            },
            Archival::Claim {
                height: BlockHeight::from_raw(1025),
                slot: 0,
                epochs: vec![1],
            },
        ],
        "limit-full" | "median-full" | "spend-1in-2out" | "spend-depth3" => Vec::new(),
        other => panic!("a chain this table does not know: {other}"),
    }
}

#[test]
fn the_corpus_carries_exactly_these_archival_inputs() {
    let chains = captured_chains();
    assert_eq!(chains.len(), 6, "the corpus has six chains");
    for (dir, manifest) in chains {
        let (found, schedule) = enumerate(&dir);
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
        if manifest.shape == "emission-claim" {
            // The injected credit sits at `E_join + 1` — the epoch J5 will
            // accept — and the claim lands after that epoch settled.
            let join_epoch = schedule.epoch_at_height(98);
            assert_eq!(join_epoch, 0);
            assert!(serve_credit_epoch_ok(1, join_epoch));
            assert_eq!(
                schedule.epoch_at_height(115),
                0,
                "injected before its epoch opened"
            );
            assert_eq!(schedule.epoch_at_height(1025), 2);
        }
    }
}
