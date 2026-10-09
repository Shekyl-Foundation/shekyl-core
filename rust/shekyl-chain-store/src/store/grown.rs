// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A fixture chain that lists real spends.
//!
//! [`Listed`] is the vocabulary a test writes. [`Grown`] realises it over
//! the wallet-side tree and judges the block through [`Grown::judge_listing`],
//! the one root-endow-judge-record step the connect loops share. The
//! candidate builder, the pricer and the two-stage judge stay in the parent:
//! this module calls them, and a refusal path that must not record calls
//! them directly.
//!
//! Items are `pub(in super::super)` — visible to the store module, which is
//! what `pub(super)` meant when this code lived in `connect_fixtures`. A
//! `pub(super)` item here would be visible only to that parent, and a parent
//! cannot re-export an item further than the item itself is visible.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{Candidate, ChainValid, RuleSet};
use shekyl_harness_spender::{
    complete_tree, first_spending_height, Linked, MinerWallet, Persona, PostedBond, Spender,
};
use shekyl_harness_wallet::coinbase::repay;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, Ct, Input, Transaction};

use super::super::store_tests::TestErr;
use super::super::*;
use super::{batch_root_going_into, candidate_over, judge_under, root_going_into};

/// What a fixture block lists. A chain is a `&[Vec<Listed>]`, one entry
/// per height from genesis; `connect_chain*` realises each block's entries
/// when that block is built, so a spend is made over the chain as it
/// stands at its height. The body variant is as large as a transaction
/// and the spend one eight bytes; a listing is a few entries a test wrote
/// out, never a collection the difference would cost anything in.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(in super::super) enum Listed {
    /// A **real spend**, paying `fee`: of the lowest coinbase that has
    /// matured for the connecting height ([`FIRST_SPEND_HEIGHT`] blocks
    /// below it or more) and that no block on the chain spent, two outputs
    /// back to the miner — the spender's shape ([`Grown::spend_of`]). Its
    /// one input carries a PQC auth, so the txid is 4-part
    /// (`pqc_auth_hash: Some(_)`), the shape that writes a
    /// `txs_pqc_auth_hash` row (amendment A3, `PDM-Q-F26` leg 1). A block
    /// listing `n` spends needs `n` matured coinbases unspent; at
    /// `FIRST_SPEND_HEIGHT` there is one, and each block above it matures
    /// one more ([`prefix_maturing`]).
    Spend { fee: u64 },
    /// `n` matured coinbases in **one** transaction, paying `fee`
    /// ([`Grown::spend_many`]). A block that keeps adding spends until a
    /// measured length is crossed realises one of these at a time
    /// ([`Grown::stage`]).
    Spends { n: usize, fee: u64 },
    /// A **real join**: the zero-fee spend [`Listed::Spend`] makes, with
    /// the `JoinMarket` post of the persona at `slot` ([`Persona::at`])
    /// riding it ([`Grown::join`]) — a complete-tree bond at
    /// [`JOIN_ENDPOINT`], the one post the production constructors build
    /// over no closed shard. A join funds its bond from a spend, and
    /// CEN-J27 judges that spend as CEN-I13/I15 judge any other, so a
    /// join's reference and proof are the chain's to make as a spend's are
    /// — it is listed, never held. It opens the persona's `archival_bond`
    /// row; the credit for it is [`serve_credit`]'s ([`credited`] pairs
    /// them).
    Join { slot: u32 },
    /// A body listed as given, anchored for its height ([`anchor`]): a
    /// serve credit, an emission. Never a spend or a join — their
    /// reference and proof are the chain's to make, not a value a test
    /// holds before the chain exists.
    Body(Transaction),
}

/// The endpoint every fixture join names. No landed rule reads a record's
/// endpoint (the challenger side, CEN-J1/J10, is pending), so one value
/// serves every persona.
const JOIN_ENDPOINT: [u8; 32] = [0xEE; 32];

/// A zero-fee [`Listed::Spend`].
pub(in super::super) const fn spend() -> Listed {
    Listed::Spend { fee: 0 }
}

/// A [`Listed::Spend`] paying `fee` — what a test needs when the block
/// must **burn**: CEN-F17 splits the listed fees, and a chain of zero-fee
/// bodies destroys nothing whatever else it does. The fee comes out of the
/// spent coinbase's reward, so it is bounded by what the chain paid that
/// coinbase.
pub(in super::super) const fn spend_paying(fee: u64) -> Listed {
    Listed::Spend { fee }
}

/// [`Listed::Spends`]: `n` coinbases in one transaction, paying `fee`.
pub(in super::super) const fn spends(n: usize, fee: u64) -> Listed {
    Listed::Spends { n, fee }
}

/// A [`Listed::Body`].
pub(in super::super) fn body(tx: Transaction) -> Listed {
    Listed::Body(tx)
}

/// The serve credit for the persona at `slot`, for shard 0 in
/// `settlement_epoch`: the spender persona's vin
/// ([`Persona::serve_credit_vin`]) in the rules harness's CEN-H20 body
/// (`fixture::serve_credit_only_with`) — the one legal listed shape with
/// no key image and no `pqc_auths`, 3-part. The epoch is the caller's
/// derivation: CEN-J5 admits a credit for epoch `E` only when `E ≥` the
/// epoch the persona's join settled in `+ 1`.
pub(in super::super) fn serve_credit(slot: u32, settlement_epoch: u64) -> Transaction {
    fixture::serve_credit_only_with(Persona::at(slot).serve_credit_vin(0, settlement_epoch))
}

/// A serve credit **with the record it credits**: the [`Listed::Join`]
/// that opens the `archival_bond` row of the persona at `slot` (a real
/// spend funding the bond — 4-part, like every spend), and the credit for
/// that persona ([`serve_credit`]). A credit for a persona with no record
/// is refused (CEN-L7 since DRS-E4 commit 4; CEN-J4 is the row), so a
/// credit connects only behind its join. The join spends, so it sits no
/// lower than [`FIRST_SPEND_HEIGHT`], and the credit lists in the block
/// **after** it:
/// CEN-J4 reads the record off the view the block is judged against, which
/// a join in the same block has not yet written — the C++ reads it so
/// (`check_tx_inputs` runs before `add_block`), and a same-block pair is
/// refused there. *Records-was:* until E6 slice 8 row 3 the pair was
/// listed in one block, which the fold's in-block sequencing admitted
/// (`archival/inputs.rs`, `apply_input`) and the C++ never did.
///
/// The credit is for settlement epoch 1, the first a persona joining in
/// epoch 0 may serve (CEN-J5, `E ≥ join + 1`): under the genesis schedule
/// (`GENESIS` rules) epoch 0 runs past every height a fixture chain here
/// reaches, so a join at or above [`FIRST_SPEND_HEIGHT`] settles in epoch
/// 0. A chain under a shorter schedule derives its own epoch and pairs
/// [`Listed::Join`] with [`serve_credit`] itself (`prune_tests`). Which
/// epoch a fixture chain is *in* when it lists the credit is CEN-J7's (E6
/// slice C), not yet a Rust rule.
///
/// The credit is the harness's, in the **`RF-D1`** shape CEN-H20 requires:
/// a prunable region holding one pruned pass record per serve-credit vin.
/// Before that shape was required (`SHT-9`), a credit with no region
/// connected and then halted the store ten heights later, on SI-7:
/// its txid mixes the null hash where its `txs_prunable_hash` row is
/// `keccak256("")`, so the drain's reconstruction named another
/// transaction. `prune_tests` connects one past that age (its own
/// `sized_credit`, the same shape with the record's length chosen).
pub(in super::super) fn credited(slot: u32) -> (Listed, Transaction) {
    (Listed::Join { slot }, serve_credit(slot, 1))
}

/// The first height at which a block may list a spend: the spender crate's
/// [`first_spending_height`] under the genesis rule set. A spend needs a
/// coinbase that has **matured** — unlocked (`mined_money_unlock_window`
/// blocks after its height, CEN-I9), in the tree (it enters with the drain
/// of the block that unlocked it), and referenced from a header at least
/// `REFERENCE_BLOCK_MIN_AGE` blocks old (CEN-I11) — and the oldest coinbase
/// any chain has is genesis's, so the first spend sits `window + 1 +
/// MIN_AGE` blocks up, spending block 0's. Every chain here that lists a
/// spend starts with this many coinbase-only blocks ([`spendable_prefix`]);
/// a fixture chain listing a spend lower is asking the store to record
/// what consensus refuses. Along a chain, the coinbase that matures for
/// height `h` is block `h − FIRST_SPEND_HEIGHT`'s.
pub(in super::super) const FIRST_SPEND_HEIGHT: u64 =
    first_spending_height(&RuleSet::GENESIS).to_raw();

/// A fixture height as an index into a hash list.
pub(in super::super) fn at(height: u64) -> usize {
    usize::try_from(height).expect("a fixture height fits usize")
}

/// Coinbase-only blocks through the height below `height`, then `listed`
/// from `height` up — so a listing in a test reads as offsets from the
/// height its first block connects at.
pub(in super::super) fn prefix_to(
    height: BlockHeight,
    listed: Vec<Vec<Listed>>,
) -> Vec<Vec<Listed>> {
    let mut all: Vec<Vec<Listed>> = (0..height.to_raw()).map(|_| Vec::new()).collect();
    all.extend(listed);
    all
}

/// [`prefix_to`] `FIRST_SPEND_HEIGHT` — the first block of `listed` is the
/// first that may spend, and it finds exactly one coinbase (genesis's)
/// matured.
pub(in super::super) fn spendable_prefix(listed: Vec<Vec<Listed>>) -> Vec<Vec<Listed>> {
    prefix_to(BlockHeight::from_raw(FIRST_SPEND_HEIGHT), listed)
}

/// The lowest height whose block finds `n` coinbases matured and
/// unspent on a chain that has spent nothing: the coinbases that have
/// matured for height `h` are blocks `0 ..= h − FIRST_SPEND_HEIGHT`'s —
/// one at `FIRST_SPEND_HEIGHT`, one more per block above — so `n` of them
/// at `FIRST_SPEND_HEIGHT + n − 1`. A test listing `n` spends in one block
/// puts the block here or higher ([`prefix_to`]).
pub(in super::super) const fn height_maturing(n: u64) -> BlockHeight {
    BlockHeight::from_raw(FIRST_SPEND_HEIGHT + n - 1)
}

/// `tx` anchored for a block connecting at `height` on the chain whose
/// block hashes are `hashes`: the harness's [`fixture::anchored_at`]. A
/// serve credit stays as it is at any height. An emission — including one
/// with no fee input, CEN-J21 — is anchored to the block
/// `REFERENCE_BLOCK_MIN_AGE` below, the newest CEN-I11 admits
/// ([`fixture::newest_admissible_reference`]), one anchoring body with
/// the rules harness's so the store cannot anchor a body differently from
/// the crate that judges it; it panics below `REFERENCE_BLOCK_MIN_AGE`.
/// Spends are not anchored here: a spend is **built** at its height, by
/// [`Grown::spend_of`], reference and proof together.
pub(in super::super) fn anchor(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    fixture::anchored_at(hashes, height, tx)
}

/// A chain as the store connected it, with the wallet-side tree a real
/// spend is made in ([`Spender`]) kept in step with the store's: every
/// block recorded asserts the two agree on the root going into it — the
/// second-oracle property the spender crate states (its docs) — so a spend
/// built here is valid against the root the header it references carries,
/// and a disagreement is found at the block that opened it, not at CEN-I15
/// some heights later.
///
/// The chain also keeps **which coinbases its blocks spent** (by the key
/// images its listed inputs carry), so [`Self::spend`] names a coinbase
/// CEN-I7 has not seen spent and two spends built for one block name two.
pub(in super::super) struct Grown {
    /// Each connected block's hash — the priced block's identity
    /// (`judge_under` docs), what a body anchors on.
    pub(in super::super) hashes: Vec<BlockHash>,
    spender: Spender,
    /// Each connected block as judged, with the bodies it listed: what
    /// the wallet-side tree is rebuilt from when a block is popped
    /// ([`Self::pop`]; the client only grows).
    blocks: Vec<(Block, Vec<Transaction>)>,
    /// Coinbase heights a connected block's listed input spent.
    spent: BTreeSet<u64>,
    /// Per connected height, the coinbases its spends took — undone by
    /// [`Self::pop`].
    spent_at: Vec<Vec<u64>>,
    /// Per connected height, the key images its listed inputs carried —
    /// what the spent-image rows and the block digest record — so a test
    /// reads the image a block spent off the chain ([`Self::images_at`])
    /// rather than naming it.
    images: Vec<Vec<[u8; 32]>>,
    /// Spends built by [`Self::spend_posting`] and not yet recorded: the key
    /// image each carries, to the coinbase height it spends. [`Self::spend`]
    /// skips these coinbases too, so two spends for one block differ;
    /// [`Self::record`] moves the ones the block listed to `spent` and
    /// forgets the rest (built and dropped — not spent).
    building: BTreeMap<[u8; 32], u64>,
}

impl Grown {
    /// An empty chain — for a test that connects its blocks by hand
    /// ([`Self::realise`], [`Self::record`]).
    pub(in super::super) fn new() -> Self {
        Self {
            hashes: Vec::new(),
            spender: Spender::over::<Linked<'_>>(&[]),
            blocks: Vec::new(),
            spent: BTreeSet::new(),
            spent_at: Vec::new(),
            images: Vec::new(),
            building: BTreeMap::new(),
        }
    }

    /// The next connecting height.
    pub(in super::super) fn height(&self) -> BlockHeight {
        BlockHeight::from_raw(self.hashes.len() as u64)
    }

    /// The tip's hash; `BlockHash::NULL` for an empty chain.
    pub(in super::super) fn tip(&self) -> BlockHash {
        self.hashes.last().copied().unwrap_or(BlockHash::NULL)
    }

    /// The key images the block connected at `height` spent, in listing
    /// order ([`key_images`] over its listed bodies).
    pub(in super::super) fn images_at(&self, height: BlockHeight) -> &[[u8; 32]] {
        &self.images[at(height.to_raw())]
    }

    /// The coinbases matured for the block connecting next and spent by no
    /// block on this chain, lowest first — `0 ..= height −
    /// FIRST_SPEND_HEIGHT` less [`Self::spent`] ([`height_maturing`]).
    pub(in super::super) fn matured(&self) -> Vec<u64> {
        let Some(newest) = self.height().to_raw().checked_sub(FIRST_SPEND_HEIGHT) else {
            return Vec::new();
        };
        (0..=newest).filter(|h| !self.spent.contains(h)).collect()
    }

    /// A real spend for the block connecting next, paying `fee`, of the
    /// lowest matured coinbase no block spent and no earlier
    /// [`Self::spend`] for this block took — [`Listed::Spend`] realised.
    /// Panics when none has matured: the chain is below
    /// `FIRST_SPEND_HEIGHT`, or the block lists more spends than
    /// [`height_maturing`] allows at its height.
    pub(in super::super) fn spend(&mut self, fee: u64) -> Transaction {
        let coinbase = self.next_coinbase();
        self.spend_of(coinbase, fee)
    }

    /// A real join for the block connecting next — [`Listed::Join`]
    /// realised: [`Self::spend`]'s zero-fee spend of the next matured
    /// coinbase, carrying the complete-tree `JoinMarket` post of the
    /// persona at `slot` at [`JOIN_ENDPOINT`]
    /// ([`Spender::spend_coinbase_posting`]). The bond is a sink the
    /// spend's outputs shrink by, so the coinbase must pay at least the
    /// bond floor over the fee — every fixture coinbase does.
    pub(in super::super) fn join(&mut self, slot: u32) -> Transaction {
        let coinbase = self.next_coinbase();
        let persona = Persona::at(slot);
        let bond = persona.join(complete_tree(), JOIN_ENDPOINT);
        self.spend_posting(coinbase, 0, Some(&bond))
    }

    /// The lowest matured coinbase no block spent and no spend built for
    /// this block took. Panics when none has matured: the chain is below
    /// `FIRST_SPEND_HEIGHT`, or the block lists more spends than
    /// [`height_maturing`] allows at its height.
    fn next_coinbase(&self) -> u64 {
        self.matured()
            .into_iter()
            .find(|h| !self.building.values().any(|b| b == h))
            .unwrap_or_else(|| {
                panic!(
                    "no coinbase has matured unspent for height {}: the first spend sits at \
                     {FIRST_SPEND_HEIGHT}, and a block at height h finds at most \
                     h − {FIRST_SPEND_HEIGHT} + 1 matured",
                    self.height()
                )
            })
    }

    /// A real spend for the block connecting next of block `coinbase`'s
    /// coinbase, paying `fee` and the rest back to the miner in two
    /// outputs, anchored at the newest reference CEN-I11 admits
    /// ([`Spender::spend_coinbase`]). The caller names a coinbase in
    /// [`Self::matured`]; the spender's path assembly asserts it is in the
    /// tree, and CEN-I7 refuses the block if the chain already spent it.
    /// The spending wallet is the miner's — the one every fixture coinbase
    /// pays.
    ///
    /// Proving costs about two seconds, so the spend is memoised across
    /// the process by what determines it ([`Self::spend_posting`]).
    pub(in super::super) fn spend_of(&mut self, coinbase: u64, fee: u64) -> Transaction {
        self.spend_posting(coinbase, fee, None)
    }

    /// One real spend of the `n` lowest matured coinbases no block spent
    /// and no spend built for this block took — the multi-input shape
    /// ([`Spender::spend_coinbases`]), each input its own `pqc_auths`
    /// slot, so a body's archival length grows by a hybrid key and
    /// signature per input. This is how a chain reaches a shard boundary
    /// with bytes every landed rule verifies; the prune tests' padded
    /// serve-credit records are the cheap stand-in, and the `#[ignore]`d
    /// nightly twin in `prune_tests` is this method's caller. Not
    /// memoised: its chains are not shared across tests. Panics when fewer
    /// than `n` have matured.
    pub(in super::super) fn spend_many(&mut self, n: usize, fee: u64) -> Transaction {
        let coinbases: Vec<u64> = self
            .matured()
            .into_iter()
            .filter(|h| !self.building.values().any(|b| b == h))
            .take(n)
            .collect();
        assert_eq!(
            coinbases.len(),
            n,
            "{n} coinbases have matured unspent for height {}",
            self.height()
        );
        let heights: Vec<BlockHeight> = coinbases
            .iter()
            .map(|&c| BlockHeight::from_raw(c))
            .collect();
        // The spender yields the coinbases in the body's input order
        // (sorted by key image, CEN-I5), the order `key_images` reads.
        let (tx, in_input_order) =
            self.spender
                .spend_coinbases(MinerWallet::harness(), &heights, self.height(), fee);
        for (image, coinbase) in key_images(&tx).into_iter().zip(in_input_order) {
            self.building.insert(image, coinbase.to_raw());
        }
        tx
    }

    /// [`Self::spend_of`] with a bond post riding the spend
    /// ([`Spender::spend_coinbase_posting`]): the post is the prefix's one
    /// extra input and its term moves the outputs — a join's bond is a
    /// sink they shrink by.
    ///
    /// Proving costs about two seconds, so the spend is memoised across
    /// the process by what determines it: the reference block's hash
    /// (which commits to every block through the reference — the spent
    /// coinbase, its amount and the tree the path is read from), the
    /// coinbase, the connecting height, the fee, and the post's wire bytes
    /// (a persona's post names its keys, holdings and endpoint; two
    /// personas' joins over one coinbase differ). A stale hit cannot pass
    /// silently: a proof over another chain fails CEN-I15 at judge.
    pub(in super::super) fn spend_posting(
        &mut self,
        coinbase: u64,
        fee: u64,
        bond: Option<&PostedBond<'_>>,
    ) -> Transaction {
        let connecting = self.height().to_raw();
        let reference = shekyl_chain_rules::newest_admissible_reference(self.height())
            .expect("a spending height has a reference");
        let posted = bond.map(|bond| {
            let mut bytes = Vec::new();
            bond.input
                .write(&mut bytes)
                .expect("a bond post input writes");
            bytes
        });
        let key = ProvedKey {
            reference: self.hashes[at(reference.to_raw())],
            coinbase,
            connecting,
            fee,
            bond_wire: posted,
        };
        let mut proved = PROVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = proved
            .entry(key)
            .or_insert_with(|| {
                self.spender.spend_coinbase_posting(
                    MinerWallet::harness(),
                    BlockHeight::from_raw(coinbase),
                    BlockHeight::from_raw(connecting),
                    fee,
                    bond,
                )
            })
            .clone();
        self.building.insert(spent_image(&tx), coinbase);
        tx
    }

    /// `listed` realised for the block connecting next: each
    /// [`Listed::Spend`] built ([`Self::spend`]), each [`Listed::Join`]
    /// built ([`Self::join`]), each [`Listed::Body`] anchored
    /// ([`anchor`]).
    pub(in super::super) fn realise(&mut self, listed: &[Listed]) -> Vec<Transaction> {
        let height = self.height().to_raw();
        listed
            .iter()
            .map(|entry| match entry {
                Listed::Spend { fee } => self.spend(*fee),
                Listed::Spends { n, fee } => self.spend_many(*n, *fee),
                Listed::Join { slot } => self.join(*slot),
                Listed::Body(tx) => anchor(&self.hashes, height, tx.clone()),
            })
            .collect()
    }

    /// Realise one listing entry. A block that decides whether to add
    /// another spend after measuring the one it just built uses this,
    /// then [`Self::judge_listing`] once for the block.
    pub(in super::super) fn stage(&mut self, entry: &Listed) -> Transaction {
        let mut txs = self.realise(std::slice::from_ref(entry));
        txs.pop().expect("one listing realises one body")
    }

    /// The candidate for the block connecting next on the committed
    /// `store`, listing `listed` realised ([`Self::realise`]) and carrying
    /// the root the store recorded going into its height
    /// ([`root_going_into`]) — for a test that connects a block by hand
    /// after [`connect_chain`] committed the chain.
    pub(in super::super) fn next(&mut self, store: &ChainStore, listed: &[Listed]) -> Candidate {
        let height = self.height().to_raw();
        let txs = self.realise(listed);
        candidate_over(root_going_into(store, height), height, self.tip(), txs)
    }

    /// Judge the block connecting next under `rules`, listing `txs`
    /// (already realised). Endows genesis. Records the block on both trees.
    /// The caller connects the returned verdict (`batch.connect`).
    pub(in super::super) fn judge_listing<'b, 'id>(
        &mut self,
        view: &BatchView<'b, 'id>,
        rules: &RuleSet,
        txs: &[Transaction],
    ) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
        let height = self.height().to_raw();
        let cand = candidate_at(view, height, self.tip(), txs.to_vec())?;
        let judged = judge_under(view, cand, rules)?;
        self.record(judged.block().block(), txs);
        Ok(judged)
    }

    /// Record `block`, connected listing `listed`, on both trees — holding
    /// them to one root — and mark the coinbases its inputs spent.
    pub(in super::super) fn record(&mut self, block: &Block, listed: &[Transaction]) {
        self.spender
            .push_agreeing(&Linked::new(block, listed), block.header.curve_tree_root);
        self.hashes.push(block.hash());
        let images: Vec<[u8; 32]> = listed.iter().flat_map(key_images).collect();
        let mut took = Vec::new();
        for key_image in &images {
            if let Some(coinbase) = self.building.remove(key_image) {
                self.spent.insert(coinbase);
                took.push(coinbase);
            }
        }
        self.spent_at.push(took);
        self.images.push(images);
        self.blocks.push((block.clone(), listed.to_vec()));
        // A spend built for this block and not listed was not spent.
        self.building.clear();
    }
}

impl Grown {
    /// The block connected at `height`, as judged.
    pub(in super::super) fn block(&self, height: BlockHeight) -> &Block {
        &self.blocks[at(height.to_raw())].0
    }

    /// The tip popped, as the store's `pop` leaves the chain: its hash,
    /// its images and the coinbases it spent are forgotten, and the
    /// wallet-side tree is rebuilt over the blocks that remain (the
    /// client only grows). A spend built after this is for the popped
    /// height again, of a coinbase the remaining chain has not spent.
    pub(in super::super) fn pop(&mut self) {
        self.blocks.pop().expect("a block to pop");
        self.hashes.pop();
        self.images.pop();
        for coinbase in self.spent_at.pop().expect("a block to pop") {
            self.spent.remove(&coinbase);
        }
        self.building.clear();
        let linked: Vec<Linked<'_>> = self
            .blocks
            .iter()
            .map(|(block, listed)| Linked::new(block, listed))
            .collect();
        self.spender = Spender::over(&linked);
    }
}

/// Price a genesis candidate's coinbase at [`GENESIS_ENDOWMENT`] with the
/// wallet's [`repay`] — amount, commitment and ciphertext together — so it
/// is a coinbase the miner's scan recovers and a spend can be built over.
pub(in super::super) fn endow_genesis(genesis: &mut Candidate) {
    assert_eq!(genesis.block.number(), Some(0), "only genesis is endowed");
    assert!(
        repay(
            &mut genesis.block.miner_transaction,
            MinerWallet::harness().recipient(),
            GENESIS_ENDOWMENT,
        ),
        "the fixture's genesis coinbase is one `repay` prices"
    );
}

/// The candidate connecting at `height` over `previous`, listing `txs`,
/// carrying the batch's root going into that height. Genesis is endowed.
fn candidate_at<'b, 'id>(
    view: &BatchView<'b, 'id>,
    height: u64,
    previous: BlockHash,
    txs: Vec<Transaction>,
) -> Result<Candidate, StoreError> {
    let root = batch_root_going_into(view, height)?;
    let mut cand = candidate_over(root, height, previous, txs);
    if height == 0 {
        endow_genesis(&mut cand);
    }
    Ok(cand)
}

/// The chain record over blocks a test connected by hand — each **as
/// judged**, with the bodies it listed — for a test that drives `connect`
/// itself and then needs a spend built over the chain it connected
/// ([`Grown::spend`]). Every block is held to the root check
/// [`Grown::record`] makes.
pub(in super::super) fn grown_over<'a>(
    blocks: impl IntoIterator<Item = (&'a Block, &'a [Transaction])>,
) -> Grown {
    let mut grown = Grown::new();
    for (block, listed) in blocks {
        grown.record(block, listed);
    }
    grown
}

/// The spent key image of a built spend ([`Grown::spend_posting`]'s
/// shape): one `ToKey` input, with a bond post beside it or not.
fn spent_image(tx: &Transaction) -> [u8; 32] {
    match key_images(tx).as_slice() {
        [key_image] => *key_image,
        _ => panic!("a built spend has one ToKey input"),
    }
}

/// The key images a transaction's inputs carry — what a block's digest and
/// the spent-image rows record ([`Grown`] builds the spends, so a test
/// reads the images off the connected bodies rather than naming them).
pub(in super::super) fn key_images(tx: &Transaction) -> Vec<[u8; 32]> {
    tx.prefix
        .inputs
        .iter()
        .filter_map(|input| match input {
            Input::ToKey { key_image, .. } => Some(*key_image),
            _ => None,
        })
        .collect()
}

/// Output `vout` of `tx` as the store records it — its one-time key and
/// its commitment (from the ct base, `Null` or `Fcmp`) — for a test that
/// reads an output back by global index and must know what the connected
/// transaction, not a named point, put there.
pub(in super::super) fn output_of(tx: &Transaction, vout: usize) -> ([u8; 32], [u8; 32]) {
    let key = tx.prefix.outputs[vout].key;
    let commitment = match &tx.ct {
        Ct::Null(base) | Ct::Fcmp { base, .. } => base.commitments[vout],
    };
    (key, commitment)
}

/// What determines a memoised spend ([`Grown::spend_posting`]).
///
/// The reference block's hash commits to every block through the reference
/// — the spent coinbase, its amount and the tree the path is read from.
/// The bond wire bytes name the post's keys, holdings and endpoint, so two
/// personas' joins over one coinbase differ. A stale hit cannot pass
/// silently: a proof over another chain fails CEN-I15 at judge.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProvedKey {
    reference: BlockHash,
    coinbase: u64,
    connecting: u64,
    fee: u64,
    bond_wire: Option<Vec<u8>>,
}

/// Spends proved in this process, keyed by [`ProvedKey`].
static PROVED: Mutex<BTreeMap<ProvedKey, Transaction>> = Mutex::new(BTreeMap::new());

/// Connect `listed` as consecutive blocks from genesis in one batch —
/// `connect` is handed nothing but the verdict since E6 slice 7 wave B;
/// everything `block_info` and the burn fold record is the validator's over
/// the chain the fixture built. Each block's listing is realised as the
/// chain stands at its height ([`Grown::realise`]: spends built, bodies
/// anchored), and every header carries the root the store recorded going
/// into its height ([`batch_root_going_into`], the derived root of the
/// previous connect — CEN-B5), so a caller lists [`spend`]s and the
/// reference, the proof and the root are written where they are known.
/// Genesis is **endowed** ([`GENESIS_ENDOWMENT`]): a coinbase built by
/// `candidate_over` pays zero, genesis's stands as built (CEN-F11), and a
/// zero-amount coinbase is not an input a spend can be signed over — so
/// without the endowment the chain's first matured coinbase, the one
/// [`FIRST_SPEND_HEIGHT`] is derived from, could never be spent.
/// Returns the chain, with each block's hash in `hashes`.
pub(in super::super) fn connect_chain(store: &ChainStore, listed: &[Vec<Listed>]) -> Grown {
    connect_chain_anchored(store, listed).0
}

/// A genesis coinbase amount large enough for CEN-F17's burn to register.
/// The burn is `fees × base_rate × √(volume / baseline) × (supply /
/// asymptote)`, and on a fixture chain the supply is a few blocks'
/// rewards against an asymptote of `2³²` coins — a ratio that rounds to
/// zero in the fixed point, so a fee-bearing body on such a chain destroys
/// nothing. Genesis pays what it is configured to (CEN-F11), so the
/// fixture endows it: a quarter of the asymptote, well under it (F13's
/// curve still prices every later height) and enough for a one-coin fee to
/// destroy a visible amount. The same endowment is what makes genesis's
/// coinbase spendable at all ([`connect_chain`]).
const GENESIS_ENDOWMENT: u64 = shekyl_economics::EMISSION_CURVE_ASYMPTOTE / 4;

/// [`connect_chain`], also returning the burn the verdict derived for each
/// block (CEN-F17 / G11's `actually_destroyed` — what `connect` wrote as
/// `block_burn[h]` and folded into `total_burned`). A test of the burn
/// rows lists [`spend_paying`] spends here and reads the expected fold off
/// the verdicts, never off a planted figure.
pub(in super::super) fn connect_chain_burning(
    store: &ChainStore,
    listed: &[Vec<Listed>],
) -> (Grown, Vec<AtomicUnits>) {
    let (grown, _, burns) = connect_listing(store, listed);
    (grown, burns)
}

/// [`connect_chain`], also returning the listed transactions **as
/// connected** — the spends built, the bodies anchored — for a test that
/// then reads them back by hash.
pub(in super::super) fn connect_chain_anchored(
    store: &ChainStore,
    listed: &[Vec<Listed>],
) -> (Grown, Vec<Vec<Transaction>>) {
    let (grown, connected, _) = connect_listing(store, listed);
    (grown, connected)
}

/// The one connect loop behind the `connect_chain*` fixtures: the chain,
/// each block's bodies as connected, and each block's derived burn.
fn connect_listing(
    store: &ChainStore,
    listed: &[Vec<Listed>],
) -> (Grown, Vec<Vec<Transaction>>, Vec<AtomicUnits>) {
    let mut grown = Grown::new();
    let mut connected: Vec<Vec<Transaction>> = Vec::new();
    let mut burns: Vec<AtomicUnits> = Vec::new();
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for entries in listed {
            let txs = grown.realise(entries);
            // The identity is the priced block's (`judge_under` docs), so
            // `judge_listing` records the block as judged, not as built.
            let judged = grown.judge_listing(&view, &RuleSet::GENESIS, &txs)?;
            connected.push(txs);
            burns.push(judged.block().emission().burned());
            batch.connect(judged, RuleSet::GENESIS)?;
        }
        Ok(())
    });
    out.expect("chain connects");
    (grown, connected, burns)
}
