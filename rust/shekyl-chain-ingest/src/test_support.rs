// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures shared by the artifact and pipeline tests: a chain the landed
//! rules accept under the mock substrate, its corpus bytes, and a trace
//! whose facts the chain's headers agree with (CEN-B5: the header root at
//! `h` is `root_after(h − 1)`).

use std::collections::VecDeque;

use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::digest_v0::LogicalStateDigestV0;
use shekyl_chain_store::store::ChainStore;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, KeyImage, LongTermWeight,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use crate::corpus::CorpusWriter;
use crate::source::{IngestEvent, Seq, Sequenced, Source};
use crate::trace::{Facts, Trace, TraceWriter};

/// A settlement epoch for test stores.
pub const EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(10_000) {
    Some(e) => e,
    None => unreachable!(),
};

/// A fresh temp path for a store.
pub fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("shekyl-ingest-{}-{name}", std::process::id()));
    // A stale directory from an earlier run is not an error worth stopping for.
    let _stale = std::fs::remove_dir_all(&p);
    p
}

pub fn cleanup(p: &std::path::Path) {
    let _gone = std::fs::remove_dir_all(p);
}

pub fn h(n: u64) -> BlockHeight {
    BlockHeight::from_raw(n)
}

/// The curve-tree root the chain records **at** `height`: the empty tree
/// at genesis, else a function of the height so chains are not capped by a
/// byte (the store fixtures' `0xc0 + h` caps at 63).
pub fn root_at(height: u64) -> CurveTreeRoot {
    match height.checked_sub(1) {
        None => CurveTreeRoot::EMPTY,
        Some(parent) => root_after(parent),
    }
}

/// `root_after(h)` — what block `h`'s connect writes at `h + 1`.
pub fn root_after(height: u64) -> CurveTreeRoot {
    let mut bytes = [0x5cu8; 32];
    bytes[..8].copy_from_slice(&(height + 1).to_le_bytes());
    CurveTreeRoot::from_bytes(bytes)
}

pub fn coinbase(height: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height + 60,
            inputs: vec![Input::Gen(height)],
            outputs: vec![Output {
                amount: 0,
                key: [0x40; 32],
                view_tag: 1,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Null(CtBase {
            enc_amounts: vec![[0x55; 9]],
            enc_labels: vec![[0x66; 9]],
            commitments: vec![[0x70; 32]],
        }),
    }
}

/// A spend of key image `[key_image; 32]`.
pub fn spend(key_image: u8) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image: [key_image; 32],
            }],
            outputs: vec![Output {
                amount: 0,
                key: [0x80; 32],
                view_tag: 2,
            }],
            extra: Vec::new(),
        },
        ct: Ct::Fcmp {
            fee: 7,
            reference_block: BlockHash::from_bytes([0x99; 32]),
            base: CtBase {
                enc_amounts: vec![[0x11; 9]],
                enc_labels: vec![[0x22; 9]],
                commitments: vec![[0xa0; 32]],
            },
            pqc_auths: Vec::new(),
            prunable: None,
        },
    }
}

/// A block at `height` on `previous`, listing `listed`, with `nonce`.
pub fn block_with_nonce(
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
    nonce: u32,
) -> Block {
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce,
            curve_tree_root: root_at(height),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    }
}

pub fn block(height: u64, previous: BlockHash, listed: &[Transaction]) -> Block {
    block_with_nonce(height, previous, listed, 7)
}

/// A chain listing `listed[h]` at height `h`, each block on the last.
pub fn chain_listing(listed: Vec<Vec<Transaction>>) -> Vec<(Block, Vec<Transaction>)> {
    let mut previous = BlockHash::NULL;
    listed
        .into_iter()
        .enumerate()
        .map(|(hh, txs)| {
            let b = block(hh as u64, previous, &txs);
            previous = b.hash();
            (b, txs)
        })
        .collect()
}

/// A chain of `n` blocks: genesis lists nothing; block `h > 0` lists one
/// spend of key image `h`.
pub fn chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    chain_listing(
        (0..n)
            .map(|hh| {
                if hh == 0 {
                    Vec::new()
                } else {
                    vec![spend(u8::try_from(hh % 250 + 1).expect("small"))]
                }
            })
            .collect(),
    )
}

pub fn wire(b: &Block, txs: &[Transaction]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let bodies = txs
        .iter()
        .map(|t| {
            let mut body = Vec::new();
            t.write(&mut body).expect("write");
            body
        })
        .collect();
    (b.serialize(), bodies)
}

/// The corpus of `chain`.
pub fn corpus_of(chain: &[(Block, Vec<Transaction>)]) -> Vec<u8> {
    let mut w = CorpusWriter::new(Vec::new(), h(0)).expect("header");
    for (b, txs) in chain {
        let (bb, bodies) = wire(b, txs);
        w.push(&bb, &bodies).expect("verified");
    }
    w.finish().expect("trailer")
}

/// Facts for `height`, agreeing with [`root_after`].
pub fn facts_at(height: u64) -> Facts {
    Facts {
        weight: BlockWeight::from_raw(1_000 + height),
        long_term_weight: LongTermWeight::from_raw(900 + height),
        coins_generated: AtomicUnits::from_raw((height + 1) * 1_000_000),
        burned: AtomicUnits::from_raw(0),
        root_after: root_after(height),
        long_term_effective_median: LongTermWeight::from_raw(300_000 + 7 * height),
        cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
    }
}

/// The spent-key set of `chain` after its last block: one key image per
/// listed spend.
pub fn spent_keys_of(chain: &[(Block, Vec<Transaction>)]) -> Vec<[u8; 32]> {
    chain
        .iter()
        .flat_map(|(_, txs)| txs.iter())
        .flat_map(|t| t.prefix.inputs.iter())
        .filter_map(|i| match i {
            Input::ToKey { key_image, .. } => Some(KeyImage::from_bytes(*key_image).to_bytes()),
            _ => None,
        })
        .collect()
}

/// A trace with facts for every height of `chain` and, when `checkpoint`
/// is set, the LMDB-shaped checkpoint after the last block — computed
/// from the chain itself, the way the exporter would from LMDB.
pub fn trace_of(chain: &[(Block, Vec<Transaction>)], checkpoint: bool) -> Trace {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    for (hh, _) in chain.iter().enumerate() {
        w.push_facts(h(hh as u64), &facts_at(hh as u64))
            .expect("facts");
    }
    if checkpoint && !chain.is_empty() {
        let last = chain.len() as u64 - 1;
        let hashes: Vec<[u8; 32]> = chain.iter().map(|(b, _)| b.hash().to_bytes()).collect();
        w.push_checkpoint_families(h(last), &hashes, &spent_keys_of(chain), root_after(last))
            .expect("checkpoint");
    }
    Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
}

/// The redb-shaped digest one would expect after `chain`.
pub fn expected_state(chain: &[(Block, Vec<Transaction>)]) -> LogicalStateDigestV0 {
    let hashes: Vec<[u8; 32]> = chain.iter().map(|(b, _)| b.hash().to_bytes()).collect();
    let last = chain.len() as u64 - 1;
    LogicalStateDigestV0::from_families(&hashes, &spent_keys_of(chain), root_after(last))
}

pub fn open_store(path: &std::path::Path) -> ChainStore {
    ChainStore::create(path, EPOCH).expect("create")
}

/// A source that plays a script of events, sequenced from `FIRST`.
pub struct Scripted {
    events: VecDeque<IngestEvent>,
    seq: Seq,
}

impl Scripted {
    pub fn new(events: Vec<IngestEvent>) -> Self {
        Self {
            events: events.into(),
            seq: Seq::FIRST,
        }
    }
}

impl Source for Scripted {
    type Fault = std::convert::Infallible;

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        let Some(ev) = self.events.pop_front() else {
            return Ok(None);
        };
        let seq = self.seq;
        self.seq = seq.next();
        Ok(Some(Sequenced::new(seq, ev)))
    }
}
