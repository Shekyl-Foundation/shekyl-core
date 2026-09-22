// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures shared by the artifact, corpus and pipeline tests: a chain the
//! landed rules accept under the mock substrate, its corpus bytes, and a
//! trace whose facts the chain's headers agree with (CEN-B5: the header
//! root at `h` is `root_after(h − 1)`).
//!
//! Every key image a fixture spends encodes the **whole height** and a
//! family tag ([`key_image`]), so no chain or fork length collides on
//! SI-1 (a `u8` per height would have made height 251 respend height 1's
//! image, and a fork past 96 blocks overflow the byte — caps a test would
//! meet as a store halt, misattributed to the pipeline).

use std::collections::VecDeque;

use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_chain_store::store::ChainStore;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, KeyImage, LongTermWeight,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Ct, CtBase, Input, Output, Transaction, TxPrefix};

use crate::corpus::{CorpusNet, CorpusWriter};
use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};
use crate::trace::{Digest, Facts, Trace, TraceWriter};

/// A settlement epoch for test stores.
pub const EPOCH: SettlementEpochBlocks = match SettlementEpochBlocks::new(10_000) {
    Some(e) => e,
    None => unreachable!(),
};

/// A fresh temp path for a store.
///
/// A redb store is **one file**, so a stale one is removed with
/// `remove_file`; `remove_dir_all` on a file fails with `NotADirectory`,
/// which is how an earlier version of this helper left every store behind
/// and would have handed a same-named test a *reopened* stale store rather
/// than a fresh one (`ChainStore::create` reopens an existing path).
pub fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("shekyl-ingest-{}-{name}", std::process::id()));
    cleanup(&p);
    assert!(
        !p.exists(),
        "stale store at {} could not be removed",
        p.display()
    );
    p
}

/// Remove the store at `p` (a file — or a directory, should a helper ever
/// make one). Absence is not an error.
pub fn cleanup(p: &std::path::Path) {
    let _gone = std::fs::remove_file(p).or_else(|_| std::fs::remove_dir_all(p));
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

/// A wire-valid miner transaction for `height`: the sole `Input::Gen` the
/// wire demands (the rules harness's `fixture::coinbase` has no inputs and
/// does not survive `Block::read`; RD-F16). Saturating, so a fixture at
/// `u64::MAX` still serializes.
pub fn coinbase(height: u64) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: height.saturating_add(60),
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

/// Which chain a key image belongs to, so a fork's spends never collide
/// with the main chain's at any height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    /// The chain [`chain`] builds.
    Main = 0xA0,
    /// The fork [`reorg`] builds onto it.
    Fork = 0xB0,
}

/// The key image block `height` of `family` spends: the family tag, then
/// the height's eight little-endian bytes, then a fill byte.
pub fn key_image(family: Family, height: u64) -> [u8; 32] {
    let mut bytes = [0x11u8; 32];
    bytes[0] = family as u8;
    bytes[1..9].copy_from_slice(&height.to_le_bytes());
    bytes
}

/// A spend of `key_image`.
pub fn spend(key_image: [u8; 32]) -> Transaction {
    Transaction {
        prefix: TxPrefix {
            unlock_time: 0,
            inputs: vec![Input::ToKey {
                amount: 0,
                key_offsets: Vec::new(),
                key_image,
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
    chain_listing_with(listed, block)
}

/// [`chain_listing`] with the block builder supplied — a mined chain hands
/// one that searches nonces (the mutation family's D1 case).
pub fn chain_listing_with(
    listed: Vec<Vec<Transaction>>,
    mut make: impl FnMut(u64, BlockHash, &[Transaction]) -> Block,
) -> Vec<(Block, Vec<Transaction>)> {
    let mut previous = BlockHash::NULL;
    listed
        .into_iter()
        .enumerate()
        .map(|(hh, txs)| {
            let b = make(hh as u64, previous, &txs);
            previous = b.hash();
            (b, txs)
        })
        .collect()
}

/// A chain of `n` blocks: genesis lists nothing; block `h > 0` lists one
/// spend of the main family's key image for `h`.
pub fn chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    chain_listing(
        (0..n)
            .map(|hh| {
                if hh == 0 {
                    Vec::new()
                } else {
                    vec![spend(key_image(Family::Main, hh))]
                }
            })
            .collect(),
    )
}

/// The reorg family (§3.8, RD-Q13): a main chain of `main_len` blocks, a
/// `Rewind { to }`, then `fork_len` fork blocks chained onto `main[to]`
/// with nonces and key images the main chain never used. `fork_len` must
/// exceed `main_len - 1 - to` so the fork's tip is beyond every pre-switch
/// tip (corpus module docs: a checkpoint height is compared the first time
/// it is the tip).
pub struct Reorg {
    /// The chain before the switch.
    pub main: Vec<(Block, Vec<Transaction>)>,
    /// Where the switch rewinds to.
    pub to: u64,
    /// The chain after the switch: `main[..=to]` then the fork blocks.
    pub after: Vec<(Block, Vec<Transaction>)>,
}

pub fn reorg(main_len: u64, to: u64, fork_len: u64) -> Reorg {
    assert!(to + 1 < main_len, "the rewind must pop at least one block");
    assert!(
        to + fork_len >= main_len,
        "the fork's tip must reach beyond every pre-switch tip"
    );
    let main = chain(main_len);
    let mut after: Vec<(Block, Vec<Transaction>)> =
        main[..=usize::try_from(to).expect("small")].to_vec();
    let mut previous = after.last().expect("non-empty").0.hash();
    for i in 0..fork_len {
        let height = to + 1 + i;
        let txs = vec![spend(key_image(Family::Fork, height))];
        let b = block_with_nonce(
            height,
            previous,
            &txs,
            99 + u32::try_from(i).expect("small"),
        );
        previous = b.hash();
        after.push((b, txs));
    }
    Reorg { main, to, after }
}

/// The reorg as a corpus: main's blocks, a rewind record, the fork's.
pub fn corpus_of_reorg(r: &Reorg) -> Vec<u8> {
    let mut w = CorpusWriter::create(std::io::Cursor::new(Vec::new()), CorpusNet::Fakechain, h(0))
        .expect("header");
    for (b, txs) in &r.main {
        let (bytes, bodies) = wire(b, txs);
        w.append(&bytes, &bodies).expect("append");
    }
    w.rewind(h(r.to)).expect("rewind");
    for (b, txs) in &r.after[usize::try_from(r.to).expect("small") + 1..] {
        let (bytes, bodies) = wire(b, txs);
        w.append(&bytes, &bodies).expect("append fork");
    }
    w.finish().expect("count").into_inner()
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
    corpus_from(h(0), chain)
}

/// The corpus of `chain`, whose first block is at `first`.
pub fn corpus_from(first: BlockHeight, chain: &[(Block, Vec<Transaction>)]) -> Vec<u8> {
    let mut w = CorpusWriter::create(
        std::io::Cursor::new(Vec::new()),
        CorpusNet::Fakechain,
        first,
    )
    .expect("header");
    for (b, txs) in chain {
        let (bb, bodies) = wire(b, txs);
        w.append(&bb, &bodies).expect("verified");
    }
    w.finish().expect("count").into_inner()
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
/// from the chain itself, the way the daemon's walker would from LMDB.
pub fn trace_of(chain: &[(Block, Vec<Transaction>)], checkpoint: bool) -> Trace {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    for (hh, _) in chain.iter().enumerate() {
        w.push_facts(h(hh as u64), &facts_at(hh as u64))
            .expect("facts");
    }
    if checkpoint && !chain.is_empty() {
        w.push_checkpoint(&expected_state(chain))
            .expect("checkpoint");
    }
    Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
}

/// The redb-shaped digest one would expect after `chain`.
pub fn expected_state(chain: &[(Block, Vec<Transaction>)]) -> Digest {
    let hashes: Vec<[u8; 32]> = chain.iter().map(|(b, _)| b.hash().to_bytes()).collect();
    let last = chain.len() as u64 - 1;
    digest_v0(&hashes, &spent_keys_of(chain), root_after(last).as_bytes())
}

pub fn open_store(path: &std::path::Path) -> ChainStore {
    ChainStore::create(path, EPOCH).expect("create")
}

/// A source that plays a script of events, sequenced from `FIRST`, whose
/// first `Extend` is at `first`.
pub struct Scripted {
    first: BlockHeight,
    events: VecDeque<Sequenced<IngestEvent>>,
}

impl Scripted {
    /// Events numbered consecutively from `FIRST`, starting at height 0.
    pub fn new(events: Vec<IngestEvent>) -> Self {
        Self::from(h(0), events)
    }

    /// Events numbered consecutively from `FIRST`, starting at `first`.
    pub fn from(first: BlockHeight, events: Vec<IngestEvent>) -> Self {
        let mut seq = SequenceNo::FIRST;
        let events = events
            .into_iter()
            .map(|event| {
                let at = seq;
                seq = seq.next();
                Sequenced { seq: at, event }
            })
            .collect();
        Self { first, events }
    }

    /// Events with the numbers given — for a source that breaks the
    /// numbering contract on purpose.
    pub fn numbered(first: BlockHeight, events: Vec<Sequenced<IngestEvent>>) -> Self {
        Self {
            first,
            events: events.into(),
        }
    }
}

impl Source for Scripted {
    type Fault = std::convert::Infallible;

    fn first_height(&self) -> BlockHeight {
        self.first
    }

    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault> {
        Ok(self.events.pop_front())
    }
}
