// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fixtures shared by the artifact, corpus and pipeline tests: a chain the
//! landed rules accept under the mock substrate, its corpus bytes, and a
//! trace whose facts the chain's headers agree with (CEN-B5: the header
//! root at `h` is the root after `h − 1`'s drain).
//!
//! Since DRS-E3 the root is the validator's derivation — the curve tree
//! grown over the outputs that matured — and no function of the height can
//! supply it. [`GrownTree`] is the fixture's tree: a `ChainView` over the
//! blocks built so far, advanced by the production `tree_after` as each
//! block is added, so a chain's headers and its trace carry the roots the
//! store will derive when it connects them. One derivation (the rules
//! crate's), driven over a fixture view; not a second definition of the
//! drain.
//!
//! [`trace_with`] is how a fixture trace is built. It grows that tree over
//! the chain it is given and writes each row's `root_after` from it; the
//! caller supplies the economics and cannot name a root. [`trace_of`] is
//! [`trace_with`] with the synthetic economics. [`facts_at`] is the other
//! door, for a caller that must name the root.
//!
//! Every key image a fixture spends encodes the **whole height** and a
//! family tag ([`key_image`]), so no chain or fork length collides on
//! SI-1 (a `u8` per height would have made height 251 respend height 1's
//! image, and a fork past 96 blocks overflow the byte — caps a test would
//! meet as a store halt, misattributed to the pipeline).

use core::convert::Infallible;
use std::collections::{BTreeMap, VecDeque};

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{
    tree_after, AtHeight, BlockOutputs, ChainView, LeafSource, RecordedBlock, RecordedWeights,
    RuleSet, Tip, TreeFrontier,
};
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_chain_store::store::ChainStore;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{
    AttestationRoot, BlockCount, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot,
    GlobalOutputIndex, KeyImage, LongTermWeight, TxHash,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::tx_extra::{admitted_leaf_blob, parse, pqc_leaf_entries_per_output};
use shekyl_wire::{Block, BlockHeader, Ct, Input, Transaction};

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

/// The curve tree a synthetic chain grows (module docs): the outputs of
/// every block built so far, the root and leaf count going into each
/// height, and the layer chunks — advanced by the production derivation
/// (`shekyl_chain_rules::tree_after`) as blocks are pushed, exactly as
/// `connect` will advance the store's when it connects them.
#[derive(Default)]
pub struct GrownTree {
    /// `outputs[h]` — block `h`'s outputs as leaf sources, global indices
    /// assigned dense in connect order (miner first, then listed).
    outputs: Vec<BlockOutputs>,
    /// `roots[h]` — the root going into `h`; `roots[0]` is the empty tree.
    roots: Vec<CurveTreeRoot>,
    /// `leaf_counts[h]` — the leaf count going into `h`.
    leaf_counts: Vec<u64>,
    /// `(layer, chunk)` → hash, every chunk any grow wrote.
    layers: BTreeMap<(u8, u64), [u8; 32]>,
    next_output: u64,
}

impl GrownTree {
    /// An empty tree with no blocks.
    #[must_use]
    pub fn new() -> Self {
        Self {
            roots: vec![CurveTreeRoot::EMPTY],
            leaf_counts: vec![0],
            ..Self::default()
        }
    }

    /// The tree after every block of `chain`, in order.
    #[must_use]
    pub fn over(chain: &[(Block, Vec<Transaction>)]) -> Self {
        let mut tree = Self::new();
        for (block, txs) in chain {
            tree.push(block, txs);
        }
        tree
    }

    /// How many blocks have been pushed — the next connecting height.
    #[must_use]
    pub fn built(&self) -> u64 {
        self.outputs.len() as u64
    }

    /// The root the header connecting at `height` must carry (CEN-B5):
    /// the root going into `height`.
    #[must_use]
    pub fn root_going_into(&self, height: u64) -> CurveTreeRoot {
        self.roots[at(height)]
    }

    /// The root after block `height`'s drain — what its connect writes at
    /// `height + 1`.
    #[must_use]
    pub fn root_after(&self, height: u64) -> CurveTreeRoot {
        self.roots[at(height + 1)]
    }

    /// Connect `block` at the next height: derive its drain over the tree
    /// as it stands, apply the growth, then register its outputs.
    pub fn push(&mut self, block: &Block, txs: &[Transaction]) {
        let height = h(self.built());
        let (root, drain) = tree_after(self, height, &RuleSet::GENESIS)
            .expect("a fixture chain's view is complete and its points decompress");
        let mut leaf_count = self.leaf_counts[at(height.to_raw())];
        if let Some(drain) = drain {
            for write in &drain.growth().layer_writes {
                self.layers.insert((write.layer, write.chunk), write.hash);
            }
            leaf_count = drain.growth().leaf_count_after();
        }
        self.roots.push(root);
        self.leaf_counts.push(leaf_count);
        let coinbase = self.register(&block.miner_transaction);
        let listed = txs.iter().flat_map(|tx| self.register(tx)).collect();
        self.outputs.push(BlockOutputs { coinbase, listed });
    }

    /// One transaction's outputs as leaf sources, assigned the next global
    /// indices — the store's own keying (SOK-2, dense in connect order).
    fn register(&mut self, tx: &Transaction) -> Vec<LeafSource> {
        let commitments = match &tx.ct {
            Ct::Null(base) | Ct::Fcmp { base, .. } => &base.commitments,
        };
        let fields = parse(&tx.prefix.extra).expect("fixture extra parses");
        let blob =
            admitted_leaf_blob(&fields, tx.prefix.outputs.len()).expect("fixture leaf field");
        let entries = pqc_leaf_entries_per_output(&blob).expect("whole entries");
        tx.prefix
            .outputs
            .iter()
            .zip(commitments)
            .zip(entries)
            .map(|((output, commitment), entry)| {
                let index = GlobalOutputIndex::from_raw(self.next_output);
                self.next_output += 1;
                let mut pqc_leaf_commitment = [0u8; 32];
                pqc_leaf_commitment.copy_from_slice(&entry[..32]);
                LeafSource {
                    output: index,
                    key: output.key,
                    commitment: *commitment,
                    pqc_leaf_commitment,
                }
            })
            .collect()
    }

    fn recorded<T: Clone>(rows: &[T], height: BlockHeight) -> AtHeight<T> {
        usize::try_from(height.to_raw())
            .ok()
            .and_then(|i| rows.get(i))
            .map_or(AtHeight::AboveTip, |row| AtHeight::Recorded(row.clone()))
    }
}

/// Only what `tree_after` reads is answered from the tree; the block-side
/// reads are not this view's job (the pipeline's store answers those).
impl<'id> ChainView<'id> for GrownTree {
    type Fault = Infallible;

    fn has_key_image(&self, _: &KeyImage) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn block_at(&self, _: BlockHeight) -> Result<AtHeight<RecordedBlock>, Infallible> {
        Ok(AtHeight::AboveTip)
    }

    fn height_of(&self, _: &BlockHash) -> Result<Option<BlockHeight>, Infallible> {
        Ok(None)
    }

    fn weights_window(
        &self,
        _: BlockHeight,
        _: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, Infallible> {
        Ok(AtHeight::AboveTip)
    }

    fn has_transaction(&self, _: &TxHash) -> Result<bool, Infallible> {
        Ok(false)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, Infallible> {
        Ok(Self::recorded(&self.roots, height))
    }

    fn tip(&self) -> Result<Option<Tip>, Infallible> {
        Ok(None)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, Infallible> {
        let leaf_count = *self.leaf_counts.last().expect("never empty");
        let last_chunks = TreeFrontier::last_chunk_indices(leaf_count)
            .into_iter()
            .map(|key| self.layers[&key])
            .collect();
        Ok(TreeFrontier {
            leaf_count,
            last_chunks,
        })
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, Infallible> {
        Ok(Self::recorded(&self.leaf_counts, height))
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, Infallible> {
        Ok(Self::recorded(&self.outputs, height))
    }
}

/// The miner transaction for `height`: the rules harness's, which since
/// slice 4 is the one definition of a coinbase every landed 4.F row
/// accepts (sole `Input::Gen(height)`, `Null` ct, one output with a
/// canonical key and a non-trivial mask, `unlock_time = height + 60`) and
/// which round-trips through `Block::read`. This crate's private copy
/// (RD-F16, minted when the harness fixture had no inputs) carried a key
/// that was not a point and stopped connecting the day F9 landed — the
/// coupling Q7 of that slice named: a test's fixture is cross-lane through
/// the rules it must satisfy. Saturating at `u64::MAX` as before.
pub fn coinbase(height: u64) -> Transaction {
    fixture::coinbase(height)
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

/// The key image block `height` of `family` spends: `k·G` for a `k` that
/// is distinct per `(family, height)` — a canonical prime-order point
/// (CEN-H11), which a family tag over height bytes was not. Computed, not
/// pinned (`fixture::point_at`): the seed-epoch tests spend a fresh image
/// per block for two thousand blocks, past any table. The family offsets
/// (`1_000` main, `2_000_000` fork) keep the two chains' images apart and
/// clear of the pinned table's range, which the same fixtures use for keys
/// and masks. At 4.H an image is held to pointness only; when CEN-I15 binds
/// it to the spent output (slice 6) these become captured spends' own
/// images.
pub fn key_image(family: Family, height: u64) -> [u8; 32] {
    let offset = match family {
        Family::Main => 1_000,
        Family::Fork => 2_000_000,
    };
    fixture::point_at(offset + height)
}

/// A spend of `key_image`: the rules harness's two-output [`fixture::listed`].
/// The same body the store connects, so a point rule cannot refuse this
/// crate's chains alone. Bare — its reference is written when it is placed
/// on a chain ([`chain_listing_with`] anchors every listed body at its
/// height), so a spend is chain-relative here as it is in production.
pub fn spend(key_image: [u8; 32]) -> Transaction {
    fixture::listed(key_image)
}

/// The first height at which a block may list a spend (CEN-I11: the
/// reference is at least `REFERENCE_BLOCK_MIN_AGE` below the connecting
/// height, and the youngest reference any chain has is genesis). [`chain`]
/// lists nothing below it; a listing that puts a spend lower asks for a
/// shape consensus refuses, and the builder says so.
pub const FIRST_SPEND_HEIGHT: u64 = shekyl_chain_rules::REFERENCE_BLOCK_MIN_AGE.to_raw();

/// A fixture height as an index into a hash or block list.
pub fn at(height: u64) -> usize {
    usize::try_from(height).expect("a fixture height fits usize")
}

/// `tx` anchored for a block at `height` on the chain whose block hashes so
/// far are `hashes`: the harness's [`fixture::anchored_at`] — the newest
/// reference CEN-I11 admits. A serve credit is left as it is. A spend or
/// an emission below `FIRST_SPEND_HEIGHT` is refused by the builder.
pub fn anchor(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    fixture::anchored_at(hashes, height, tx)
}

/// A block at `height` on `previous`, listing `listed`, with `nonce`, whose
/// header carries `root` — the tree state going into `height`
/// ([`GrownTree::root_going_into`]; CEN-B5).
pub fn block_with_nonce(
    root: CurveTreeRoot,
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
            curve_tree_root: root,
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    }
}

pub fn block(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
) -> Block {
    block_with_nonce(root, height, previous, listed, 7)
}

/// A chain listing `listed[h]` at height `h`, each block on the last.
pub fn chain_listing(listed: Vec<Vec<Transaction>>) -> Vec<(Block, Vec<Transaction>)> {
    chain_listing_with(listed, block)
}

/// [`chain_listing`] with the block builder supplied — a mined chain hands
/// one that searches nonces (the mutation family's D1 case). Each block is
/// anchored on the chain so far and `make` receives the root the tree has
/// going into its height ([`GrownTree`], advanced per block).
pub fn chain_listing_with(
    listed: Vec<Vec<Transaction>>,
    mut make: impl FnMut(CurveTreeRoot, u64, BlockHash, &[Transaction]) -> Block,
) -> Vec<(Block, Vec<Transaction>)> {
    let mut hashes: Vec<BlockHash> = Vec::new();
    let mut tree = GrownTree::new();
    listed
        .into_iter()
        .enumerate()
        .map(|(hh, txs)| {
            let hh = hh as u64;
            let txs: Vec<Transaction> = txs.into_iter().map(|tx| anchor(&hashes, hh, tx)).collect();
            let previous = hashes.last().copied().unwrap_or(BlockHash::NULL);
            let b = make(tree.root_going_into(hh), hh, previous, &txs);
            tree.push(&b, &txs);
            hashes.push(b.hash());
            (b, txs)
        })
        .collect()
}

/// A chain of `n` blocks: block `h ≥ FIRST_SPEND_HEIGHT` lists one spend of
/// the main family's key image for `h`; the blocks below list nothing —
/// nothing they could list would be admissible (CEN-I11). A chain shorter
/// than `FIRST_SPEND_HEIGHT + 1` blocks carries no spend at all.
pub fn chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    chain_listing(
        (0..n)
            .map(|hh| {
                if hh < FIRST_SPEND_HEIGHT {
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
/// with nonces and key images the main chain never used, and **three-output
/// spends where the main chain's have two** — so the fork's tree differs
/// from the main chain's once its own outputs mature, as a real fork's
/// would, and a root comparison that failed to retract the abandoned
/// branch would show it (`pipeline_tests`). `fork_len` must exceed
/// `main_len - 1 - to` so the fork's tip is beyond every pre-switch tip
/// (corpus module docs: a checkpoint height is compared the first time it
/// is the tip).
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
    let mut hashes: Vec<BlockHash> = after.iter().map(|(b, _)| b.hash()).collect();
    // The fork's tree is the main chain's through `to`, then its own.
    let mut tree = GrownTree::over(&after);
    for i in 0..fork_len {
        let height = to + 1 + i;
        // A fork block lists a spend where a main block would (CEN-I11's
        // floor), anchored on the fork's own chain.
        let txs: Vec<Transaction> = if height < FIRST_SPEND_HEIGHT {
            Vec::new()
        } else {
            vec![anchor(
                &hashes,
                height,
                fixture::spend(key_image(Family::Fork, height), 3),
            )]
        };
        let b = block_with_nonce(
            tree.root_going_into(height),
            height,
            *hashes.last().expect("non-empty"),
            &txs,
            99 + u32::try_from(i).expect("small"),
        );
        tree.push(&b, &txs);
        hashes.push(b.hash());
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

/// The trace row's economics. `root_after` is not a field: [`trace_with`]
/// writes it from the chain's [`GrownTree`], so a trace built this way
/// cannot record a root the chain it names did not grow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEconomics {
    /// `block_info.bi_weight`.
    pub weight: BlockWeight,
    /// `block_info.bi_long_term_block_weight`.
    pub long_term_weight: LongTermWeight,
    /// `block_info.bi_coins`.
    pub coins_generated: AtomicUnits,
    /// `block_burn[h]`, zero when the row is absent.
    pub burned: AtomicUnits,
    /// The long-term effective median in force for the block.
    pub long_term_effective_median: LongTermWeight,
    /// `block_info.bi_diff` — the accumulator the trace holds the
    /// validator's derivation to.
    pub cumulative_difficulty: CumulativeDifficulty,
}

impl TraceEconomics {
    fn with_root(self, root_after: CurveTreeRoot) -> Facts {
        Facts {
            weight: self.weight,
            long_term_weight: self.long_term_weight,
            coins_generated: self.coins_generated,
            burned: self.burned,
            root_after,
            long_term_effective_median: self.long_term_effective_median,
            cumulative_difficulty: self.cumulative_difficulty,
        }
    }
}

/// Synthetic economics for `height`: distinct per height, zero burn, the
/// accumulator `height + 1`.
fn synthetic_economics(height: u64) -> TraceEconomics {
    TraceEconomics {
        weight: BlockWeight::from_raw(1_000 + height),
        long_term_weight: LongTermWeight::from_raw(900 + height),
        coins_generated: AtomicUnits::from_raw((height + 1) * 1_000_000),
        burned: AtomicUnits::from_raw(0),
        long_term_effective_median: LongTermWeight::from_raw(300_000 + 7 * height),
        cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
    }
}

/// Facts for `height` whose recorded root after the drain is `root_after`.
///
/// The door for a caller that must name the root. The CTW-5 negative
/// control plants a wrong one here; a trace for a chain uses [`trace_with`],
/// which fills the root from that chain and does not take one.
pub fn facts_at(height: u64, root_after: CurveTreeRoot) -> Facts {
    synthetic_economics(height).with_root(root_after)
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

/// A trace for `chain`. Each row's `root_after` is [`GrownTree::root_after`]
/// of this chain; `economics` supplies everything else and is called once
/// per height, from genesis, in order. `checkpoint` appends the digest of
/// that same tree after the tip.
///
/// Heights are the chain's indices. A chain whose first block is not
/// genesis is not this constructor's input.
pub fn trace_with(
    chain: &[(Block, Vec<Transaction>)],
    mut economics: impl FnMut(u64) -> TraceEconomics,
    checkpoint: bool,
) -> Trace {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    let tree = GrownTree::over(chain);
    for index in 0..chain.len() {
        let height = u64::try_from(index).expect("a fixture height fits");
        let facts = economics(height).with_root(tree.root_after(height));
        w.push_facts(h(height), &facts).expect("facts");
    }
    if checkpoint && !chain.is_empty() {
        let tip = u64::try_from(chain.len() - 1).expect("a non-empty chain has a tip");
        w.push_checkpoint(&digest_of(chain, tree.root_after(tip).as_bytes()))
            .expect("checkpoint");
    }
    Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
}

/// [`trace_with`] with the synthetic economics: distinct per height, zero burn.
pub fn trace_of(chain: &[(Block, Vec<Transaction>)], checkpoint: bool) -> Trace {
    trace_with(chain, synthetic_economics, checkpoint)
}

/// The redb-shaped digest of `chain` given the root after its tip.
fn digest_of(chain: &[(Block, Vec<Transaction>)], root_after_tip: &[u8; 32]) -> Digest {
    let hashes: Vec<[u8; 32]> = chain
        .iter()
        .map(|(block, _)| block.hash().to_bytes())
        .collect();
    digest_v0(&hashes, &spent_keys_of(chain), root_after_tip)
}

/// The redb-shaped digest one would expect after `chain`.
pub fn expected_state(chain: &[(Block, Vec<Transaction>)]) -> Digest {
    let last = u64::try_from(chain.len() - 1).expect("a chain has a tip");
    digest_of(chain, GrownTree::over(chain).root_after(last).as_bytes())
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
