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
//! Every spend a chain lists is a **real** one since slice 6 row 6: the
//! harness miner's coinbase, matured, sourced and proven by
//! [`shekyl_harness_spender::Spender`] over the wallet-side tree fed the
//! same blocks ([`Growing`]), so CEN-I13/I15 judge it rather than skip a
//! filler. Block `c` spends the coinbase that matured for it — block
//! `c − FIRST_SPEND_HEIGHT`'s — and a fork's block at `c` spends the same
//! coinbase at another fee ([`Family::fee`]), so the two chains' trees
//! differ once those outputs mature, as a real fork's do. The one fixture
//! key image left ([`key_image`]) names bodies no spend rule judges: the
//! archival join a mutation duplicates, the unjudged artifact filler.
//!
//! Most of these fixtures serve the pipeline tests, which exist only with the
//! `pipeline` feature. The artifact and corpus tests use a small core. So a
//! build without the feature leaves the rest unused by design; that build
//! expects the dead code rather than scattering a feature gate over each
//! pipeline-only helper, and the expectation fails the moment it no longer
//! holds.
#![cfg_attr(
    not(feature = "pipeline"),
    expect(
        dead_code,
        reason = "pipeline-only fixtures are unused when the pipeline tests are not built"
    )
)]

use std::collections::VecDeque;
use std::sync::Mutex;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{Candidate, RecordedWeights, RuleSet, ViewRead};
use shekyl_chain_store::archival_snapshot::ArchivalSnapshot;
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::digest_v0::digest_v0;
use shekyl_chain_store::store::ChainStore;
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_economics::{base_block_reward, EconomicParams};
use shekyl_harness_spender::{first_spending_height, MinerWallet};
use shekyl_harness_wallet::coinbase::repay;
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, LongTermWeight,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Input, Transaction};

#[cfg(feature = "pipeline")]
use crate::connector::{Connector, ConnectorArgs};
use crate::corpus::{CorpusNet, CorpusWriter};
use crate::source::{IngestEvent, SequenceNo, Sequenced, Source};
use crate::trace::{Digest, Facts, Trace, TraceWriter};

mod growing;
mod tree;

pub use growing::Growing;
pub use tree::GrownTree;

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

/// Which chain a spend belongs to. A fork block at `c` spends the coinbase
/// the main block at `c` spent — the store un-spent it when the main
/// block popped — at this family's fee, so the fork's body is a different
/// transaction with different outputs, and the two trees differ once
/// those outputs mature (the reorg family's premise, [`reorg_of`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Family {
    /// The chain [`chain`] builds.
    Main = 0xA0,
    /// The fork [`reorg`] builds onto it.
    Fork = 0xB0,
}

impl Family {
    /// The fee a spend of this family pays. Any figure the coinbase funds
    /// serves; the two differ so that a fork's spend of a coinbase is not
    /// the main chain's body.
    #[must_use]
    pub const fn fee(self) -> u64 {
        match self {
            Family::Main => 1_000_000,
            Family::Fork => 2_000_000,
        }
    }
}

/// A fixture key image for a body **no spend rule judges**: `k·G` for a
/// `k` distinct per `(family, height)` — a canonical prime-order point
/// (CEN-H11). Since slice 6 row 6 every spend a chain lists is a real
/// one, with its own image ([`Growing::spend_matured`]); this names the
/// archival join the mutation family duplicates (a bond post, judged by
/// 4.J, not I13/I15), the artifact tests' unjudged filler, and the foreign
/// member a digest control plants. A spend of a fixture image is not a
/// shape a connected chain carries any more.
pub fn key_image(family: Family, height: u64) -> [u8; 32] {
    let offset = match family {
        Family::Main => 1_000,
        Family::Fork => 2_000_000,
    };
    fixture::point_at(offset + height)
}

/// The rules harness's two-output filler spend of `key_image`
/// ([`fixture::listed`]) — a conforming body, not a proven one. For the
/// artifact tests, which judge nothing: a connected chain lists real
/// spends ([`Growing::spend_matured`]), and a filler that reached
/// `connect` would be CEN-I13's refusal.
pub fn filler_spend(key_image: [u8; 32]) -> Transaction {
    fixture::listed(key_image)
}

/// The first height at which a block may list a spend: the height at which
/// block 0's coinbase can be spent against a root that holds it —
/// [`first_spending_height`] under the genesis rule set (the unlock
/// window, one, and the reference age; the derivation is that function's
/// doc). Derived, not pinned: a reader who wants the figure evaluates it.
/// Block `c ≥ FIRST_SPEND_HEIGHT` spends the coinbase of block
/// `c − FIRST_SPEND_HEIGHT`, the one that matured for it; [`chain`] lists
/// nothing below.
pub const FIRST_SPEND_HEIGHT: u64 = first_spending_height(&RuleSet::GENESIS).to_raw();

/// A fixture height as an index into a hash or block list.
pub fn at(height: u64) -> usize {
    usize::try_from(height).expect("a fixture height fits usize")
}

/// A **fixture** body `tx` anchored for a block at `height` on the chain
/// whose block hashes so far are `hashes`: the harness's
/// [`fixture::anchored_at`] — the newest reference CEN-I11 admits. For the
/// archival bodies (a join, a serve credit, which is left as it is); a
/// real spend carries its reference inside its proof and is never passed
/// here — rewriting it would be the forged-reference shape, not an anchor.
pub fn anchor(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    fixture::anchored_at(hashes, height, tx)
}

/// A block at `height` on `previous`, listing `listed`, with `nonce`, whose
/// header carries `root` — the tree state going into `height`
/// ([`GrownTree::root_going_into`]; CEN-B5) — and whose coinbase pays
/// `reward`: what CEN-F18 owes it, priced by [`reward_for`] over the tree
/// the block extends (a block nothing will judge may pass `0`). The
/// coinbase is re-paid through the harness wallet ([`repay`]), so its
/// commitment and encrypted amount are the amount's: a bare amount write
/// over the fixture's commitment would be an output no scanner recovers
/// and no spend can prove.
pub fn block_with_nonce(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
    reward: u64,
    nonce: u32,
) -> Block {
    let mut miner_transaction = coinbase(height);
    assert!(
        repay(
            &mut miner_transaction,
            MinerWallet::harness().recipient(),
            reward
        ),
        "the harness coinbase is the shape `repay` prices"
    );
    Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce,
            curve_tree_root: root,
            // The empty set's root: a block carrying no witness is judged
            // against it (CEN-B4, slice 8 row 10).
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
        },
        miner_transaction,
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    }
}

pub fn block(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
    reward: u64,
) -> Block {
    block_with_nonce(root, height, previous, listed, reward, 7)
}

/// What a fixture chain's genesis coinbase pays. At genesis the validator
/// derives no reward — the configured emission stands whole, whatever it
/// is (CEN-F11) — so the figure is the fixture's to choose, and it
/// chooses the emission curve's own first figure, the base reward over
/// nothing yet generated. The bare harness coinbase pays zero, which no
/// spend can fund a fee from; endowed, block 0's coinbase is the first a
/// chain spends, at [`FIRST_SPEND_HEIGHT`] exactly as the maturity law
/// states it — not block 1's a height later, which would have put a `+ 1`
/// with no law behind it into every count built on the first spend.
pub fn genesis_endowment() -> u64 {
    base_block_reward(0, &EconomicParams::default())
        .expect("the curve's first figure is priced at every parameter set")
}

/// What CEN-F18 owes the coinbase of the next block on `tree`, listing
/// `listed` — [`fixture::priced`], which settles through the validator's
/// reward chain. `height` is that next height: a caller that prices a
/// different one is naming a block this tree is not building.
///
/// [`genesis_endowment`] at genesis, where nothing is derived and the
/// configured figure stands; `0` for a block the chain refuses before F18.
pub fn reward_for(
    tree: &GrownTree,
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: &[Transaction],
) -> u64 {
    assert_eq!(
        height,
        tree.built(),
        "reward_for prices the block this tree connects next"
    );
    if height == 0 {
        return genesis_endowment();
    }
    let provisional = block(root, height, previous, listed, 0);
    let priced = match fixture::priced(tree, Candidate::new(provisional, listed.to_vec())) {
        Ok(candidate) => candidate,
        Err(ViewRead::View(never)) => match never {},
        Err(ViewRead::Corrupt(corrupt)) => {
            panic!("the fixture chain's parent reads are corrupt: {corrupt:?}")
        }
    };
    priced.block.miner_transaction.prefix.outputs[0].amount
}

/// The main chain the tests share, grown once per process and extended
/// on demand: `chain(n)` is a prefix of `chain(m)` for `n ≤ m`, so every
/// test reads one chain and no spend is proven twice. A real spend costs
/// about two seconds to prove; the family alone asks for twenty chains of
/// the same shape.
static MAIN: Mutex<Vec<(Block, Vec<Transaction>)>> = Mutex::new(Vec::new());

/// A chain of `n` blocks: block `c ≥ FIRST_SPEND_HEIGHT` lists one real
/// spend of the coinbase that matured for it (block
/// `c − FIRST_SPEND_HEIGHT`'s, [`Growing::spend_matured`]); the blocks
/// below list nothing — no coinbase has matured for them. A chain shorter
/// than `FIRST_SPEND_HEIGHT + 1` blocks carries no spend at all.
pub fn chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    let mut main = MAIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let have = u64::try_from(main.len()).expect("a fixture chain fits");
    if have < n {
        let mut growing = Growing::over(&main);
        for _ in have..n {
            let listed = growing.spend_matured(Family::Main).into_iter().collect();
            growing.extend(listed, 7);
        }
        *main = growing.finish();
    }
    main[..at(n)].to_vec()
}

/// A chain of `n` blocks listing nothing. For a test whose subject is
/// not the bodies — a planted work decrease, an epoch step — and for a
/// block that must find many coinbases unspent ([`Growing::spend_of`]).
pub fn bare_chain(n: u64) -> Vec<(Block, Vec<Transaction>)> {
    let mut growing = Growing::new();
    for _ in 0..n {
        growing.extend(Vec::new(), 7);
    }
    growing.finish()
}

/// The reorg family (§3.8, RD-Q13): a main chain, a `Rewind { to }`, then
/// `fork_len` fork blocks chained onto `main[to]` with nonces the main
/// chain never used. A fork block at `c ≥ FIRST_SPEND_HEIGHT` spends the
/// coinbase that matured for it — the one the main block at `c` spent,
/// which the rewind un-spent — **at the fork family's fee**, so the body
/// is another transaction with other outputs, and the fork's tree differs
/// from the main chain's once those outputs mature (`tx_spendable_age`
/// blocks on), as a real fork's would; a root comparison that failed to
/// retract the abandoned branch would show it (`pipeline_tests`).
/// `fork_len` must exceed `main_len - 1 - to` so the fork's tip is beyond
/// every pre-switch tip (corpus module docs: a checkpoint height is
/// compared the first time it is the tip).
pub struct Reorg {
    /// The chain before the switch.
    pub main: Vec<(Block, Vec<Transaction>)>,
    /// Where the switch rewinds to.
    pub to: u64,
    /// The chain after the switch: `main[..=to]` then the fork blocks.
    pub after: Vec<(Block, Vec<Transaction>)>,
}

/// [`reorg_of`] over the shared [`chain`] of `main_len` blocks.
pub fn reorg(main_len: u64, to: u64, fork_len: u64) -> Reorg {
    reorg_of(chain(main_len), to, fork_len)
}

/// A [`Reorg`] from `main` to `to` with a fork of `fork_len` blocks.
pub fn reorg_of(main: Vec<(Block, Vec<Transaction>)>, to: u64, fork_len: u64) -> Reorg {
    let main_len = u64::try_from(main.len()).expect("a fixture chain fits");
    assert!(to + 1 < main_len, "the rewind must pop at least one block");
    assert!(
        to + fork_len >= main_len,
        "the fork's tip must reach beyond every pre-switch tip"
    );
    // The fork's trees are the main chain's through `to`, then their own.
    let mut growing = Growing::over(&main[..=at(to)]);
    for i in 0..fork_len {
        let listed = growing.spend_matured(Family::Fork).into_iter().collect();
        growing.extend(listed, 99 + u32::try_from(i).expect("small"));
    }
    Reorg {
        main,
        to,
        after: growing.finish(),
    }
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

/// The trace row's economics — the values a chain does **not** determine.
///
/// `root_after` is not a field: [`trace_with`] writes it from the chain's
/// [`GrownTree`], so a trace built this way cannot record a root the chain
/// it names did not grow. Since slice 7 commit 4 the same holds for the
/// three weight values (`weight`, `long_term_weight`,
/// `long_term_effective_median`), since commit 5 for `coins_generated`,
/// and since slice 6 row 6 for `burned`: the tree derives them by the
/// validator's own definitions as it grows — a real spend's fee burns a
/// share, so the burn is the bodies' to determine — and a caller cannot
/// name them. A trace whose medians, burn or accumulator disagreed with
/// its chain would be the fixture problem the oracles exist to rule out,
/// and the type makes it unrepresentable rather than the test-writer's to
/// avoid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceEconomics {
    /// `block_info.bi_diff` — the accumulator the trace holds the
    /// validator's derivation to.
    pub cumulative_difficulty: CumulativeDifficulty,
}

impl TraceEconomics {
    /// The row: what the chain determined (`tree`, at `height`) beside
    /// what it did not (`self`).
    fn over(self, tree: &GrownTree, height: u64) -> Facts {
        let weights = tree.weights_of(height);
        Facts {
            weight: weights.weight,
            long_term_weight: weights.long_term_weight,
            coins_generated: tree.coins_generated_at(height),
            burned: tree.burned_at(h(height)),
            root_after: tree.root_after(height),
            long_term_effective_median: tree.median_for(height),
            cumulative_difficulty: self.cumulative_difficulty,
        }
    }
}

/// Synthetic economics for `height`: the accumulator `height + 1`.
fn synthetic_economics(height: u64) -> TraceEconomics {
    TraceEconomics {
        cumulative_difficulty: CumulativeDifficulty::from_raw(u128::from(height) + 1),
    }
}

/// Facts for `height` naming every value a chain determines: the root
/// after the drain, the weights under the median, the accumulator.
///
/// The door for a caller that must name them. The CTW-5 negative control
/// plants a wrong root here, the G6 control a wrong median, the F14b/G12
/// control a wrong accumulator; a trace for a chain uses [`trace_with`],
/// which fills every derived value from that chain and takes none. The
/// burn is zero: every caller's chain lists nothing (three blocks, below
/// the first spend), and a block listing nothing burns nothing.
pub fn facts_at(
    height: u64,
    root_after: CurveTreeRoot,
    weights: RecordedWeights,
    long_term_effective_median: LongTermWeight,
    coins_generated: AtomicUnits,
) -> Facts {
    let economics = synthetic_economics(height);
    Facts {
        weight: weights.weight,
        long_term_weight: weights.long_term_weight,
        coins_generated,
        burned: AtomicUnits::from_raw(0),
        root_after,
        long_term_effective_median,
        cumulative_difficulty: economics.cumulative_difficulty,
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

/// What a test trace's covered-tip checkpoint records. The checkpoint's two
/// encodings travel together (`trace.rs`), so this names both at once.
#[derive(Clone, Copy, Debug)]
pub enum Pinned<'a> {
    /// The grown tree's own state after the tip: its digest, and the
    /// archival rows the store writes for a chain that posts no bonds
    /// ([`GrownTree::archival_snapshot_after`]).
    OfTree,
    /// A state read from a reference store — the pair as the LMDB walker
    /// would have taken it, for chains the tree cannot derive (bond posts,
    /// an injected credit).
    Read {
        /// The reference digest.
        digest: Digest,
        /// The reference rows.
        archival: &'a ArchivalSnapshot,
    },
}

/// A trace for `chain`. Each row's `root_after` is [`GrownTree::root_after`]
/// of this chain and its three weight values are the tree's derivation at
/// that height ([`GrownTree::weights_of`], [`GrownTree::median_for`]);
/// `economics` supplies the rest and is called once per height, from
/// genesis, in order. `pinned` appends the checkpoint — both encodings —
/// after the tip, when given.
///
/// Heights are the chain's indices. A chain whose first block is not
/// genesis is not this constructor's input.
pub fn trace_pinned(
    chain: &[(Block, Vec<Transaction>)],
    mut economics: impl FnMut(u64) -> TraceEconomics,
    pinned: Option<Pinned<'_>>,
) -> Trace {
    let mut w = TraceWriter::new(Vec::new()).expect("header");
    let tree = GrownTree::over(chain);
    for index in 0..chain.len() {
        let height = u64::try_from(index).expect("a fixture height fits");
        let facts = economics(height).over(&tree, height);
        w.push_facts(h(height), &facts).expect("facts");
    }
    if let Some(pinned) = pinned {
        let (digest, archival) = match pinned {
            Pinned::OfTree => {
                let tip = chain
                    .len()
                    .checked_sub(1)
                    .and_then(|t| u64::try_from(t).ok())
                    .expect("a checkpoint of the tree needs a tip: the chain is empty");
                (
                    digest_of(chain, tree.root_after(tip).as_bytes()),
                    tree.archival_snapshot_after(tip),
                )
            }
            Pinned::Read { digest, archival } => (digest, archival.clone()),
        };
        w.push_checkpoint(&digest).expect("checkpoint");
        w.push_archival_snapshot(&archival)
            .expect("archival snapshot");
    }
    Trace::read(std::io::Cursor::new(w.finish().expect("trailer"))).expect("read")
}

/// [`trace_pinned`] with the tree's own checkpoint, or none.
pub fn trace_with(
    chain: &[(Block, Vec<Transaction>)],
    economics: impl FnMut(u64) -> TraceEconomics,
    checkpoint: bool,
) -> Trace {
    trace_pinned(chain, economics, checkpoint.then_some(Pinned::OfTree))
}

/// [`trace_with`] with the synthetic economics: distinct per height, zero burn.
pub fn trace_of(chain: &[(Block, Vec<Transaction>)], checkpoint: bool) -> Trace {
    trace_with(chain, synthetic_economics, checkpoint)
}

/// [`trace_pinned`] with the synthetic economics and a checkpoint read
/// from a reference store ([`Pinned::Read`]).
pub fn trace_read(
    chain: &[(Block, Vec<Transaction>)],
    digest: Digest,
    archival: &ArchivalSnapshot,
) -> Trace {
    trace_pinned(
        chain,
        synthetic_economics,
        Some(Pinned::Read { digest, archival }),
    )
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

/// A store under the `(SEB, cap)` pair of the rule set that will judge its
/// blocks — a chain mined on a levered regtest schedule opens its store
/// the way the daemon did (`Horizons::under`), or `connect` refuses the
/// first block for naming another epoch (`ARW-15`).
///
/// The archival [`ApplyPolicy`] is the caller's: the replays pass
/// [`ApplyPolicy::Full`]; the sufficiency stamp (DRS-E4 §3.8 item 2) opens
/// a store with one family's writer stubbed and asks whether the comparator
/// notices.
///
/// [`ApplyPolicy`]: shekyl_chain_store::apply_policy::ApplyPolicy
/// [`ApplyPolicy::Full`]: shekyl_chain_store::apply_policy::ApplyPolicy::Full
pub fn open_store_under(
    path: &std::path::Path,
    in_force: &RuleSet,
    policy: shekyl_chain_store::apply_policy::ApplyPolicy,
) -> ChainStore {
    let horizons = shekyl_chain_store::store::Horizons::under(in_force)
        .expect("a well-formed rule set's pair is a store schedule");
    ChainStore::with_horizons(path, policy, horizons).expect("create")
}

/// A connector whose task the test holds, so that stopping it can wait until
/// the actor — and the [`ChainStore`] it owns — has been dropped.
///
/// [`kameo::actor::ActorRef::wait_for_shutdown`] is not that wait. kameo 0.20
/// resolves it when the mailbox closes, which is before `on_stop` runs and
/// before the task drops the actor value; a store reopened after it races
/// that drop and meets redb's single-writer lock as `DatabaseAlreadyOpen`.
/// The drop flushes the file, so the window is widest on a disk-backed temp
/// directory under load. Joining the task closes it — the same join the
/// production run does after stopping its connector (`pipeline.rs`).
#[cfg(feature = "pipeline")]
pub struct JoinedConnector {
    pub actor: kameo::actor::ActorRef<Connector>,
    task: tokio::task::JoinHandle<
        Result<(Connector, kameo::error::ActorStopReason), kameo::error::PanicError>,
    >,
}

#[cfg(feature = "pipeline")]
impl JoinedConnector {
    pub fn spawn(args: ConnectorArgs) -> Self {
        let prepared = kameo::actor::PreparedActor::<Connector>::new(kameo::mailbox::unbounded());
        let actor = prepared.actor_ref().clone();
        let task = prepared.spawn(args);
        Self { actor, task }
    }

    /// Wait for the actor's task to end, dropping the actor and releasing its
    /// store. The caller has already stopped it.
    pub async fn join(self) {
        drop(self.task.await.expect("the connector task joins"));
    }

    /// Stop the actor, then [`Self::join`].
    pub async fn stop_and_join(self) {
        let _already_stopped = self.actor.stop_gracefully().await.is_err();
        self.join().await;
    }
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
