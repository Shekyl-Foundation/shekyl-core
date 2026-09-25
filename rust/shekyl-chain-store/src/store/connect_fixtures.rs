// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared `connect` / `pop` test fixtures. One place with `facts` so the
//! header root a candidate carries (`root_at_height`) cannot drift from the
//! root the connect of the parent wrote.

use core::convert::Infallible;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{
    form, validate, AtHeight, Candidate, ChainValid, ChainView, Fault, FormAttempt, RuleSet,
    StructurallyValid, Substrate, Trust,
};
use shekyl_types::{
    AttestationRoot, BlockHash, BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight, PowHash,
    Timestamp,
};
use shekyl_units::AtomicUnits;
use shekyl_wire::{Block, BlockHeader, Input, Transaction};

use super::store_tests::TestErr;
use super::view::BatchView;
use super::*;
use crate::codec::Present;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::SPENT_KEYS;

/// The coinbase for `height`: the rules harness's, which satisfies every
/// landed 4.F row (a sole `Input::Gen(height)`, `Null` ct, one output with
/// a canonical key and a non-trivial mask, `unlock_time = height + 60`).
/// One definition of "a valid coinbase" for every crate that judges one —
/// a private copy here drifted from the rules the moment slice 4 landed
/// F9/F10 (its keys were not points).
pub(super) fn coinbase(height: u64) -> Transaction {
    fixture::coinbase(height)
}

/// A spend-shaped listed transaction: the `key_image`-th table point in,
/// `outputs` outputs out. The body is [`fixture::spend`] — one definition,
/// shared with the rules harness and the ingest, so a point rule cannot
/// refuse this crate's fixtures alone. Indices `9..=16` stay clear of the
/// keys (`1..`) and masks (`2..`) that body draws. One per-input PQC auth
/// makes the txid 4-part (`pqc_auth_hash: Some(_)`), the shape that writes
/// a `txs_pqc_auth_hash` row (amendment A3, `PDM-Q-F26` leg 1). The auth
/// and the proof are the harness's filler: no landed rule verifies either,
/// and what the store records is the auth's count-prefixed digest.
pub(super) fn spend(key_image: usize, outputs: usize) -> Transaction {
    fixture::spend(fixture::point(key_image), outputs)
}

/// The root the header at `height` must carry under CEN-B5: the tree state
/// *at* `height` — the `root_after` the connect of `height − 1` wrote
/// (`facts(height − 1)`), or the empty tree at genesis. Kept in one place
/// with `facts` so the two cannot drift.
pub(super) fn root_at_height(height: u64) -> CurveTreeRoot {
    match height.checked_sub(1) {
        None => CurveTreeRoot::EMPTY,
        Some(parent) => facts(parent, 0).root_after.value,
    }
}

pub(super) fn candidate(height: u64, previous: BlockHash, listed: Vec<Transaction>) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            curve_tree_root: root_at_height(height),
            attestation_root: AttestationRoot::from_bytes([0x33; 32]),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

pub(super) fn facts(height: u64, burned: u64) -> ConnectFacts {
    ConnectFacts {
        weight: Fact::passed_through(BlockWeight::from_raw(1_000 + height)),
        long_term_weight: Fact::passed_through(LongTermWeight::from_raw(900 + height)),
        coins_generated: Fact::passed_through(AtomicUnits::from_raw((height + 1) * 1_000_000)),
        burned: Fact::passed_through(AtomicUnits::from_raw(burned)),
        root_after: Fact::passed_through(CurveTreeRoot::from_bytes(
            [0xc0 + u8::try_from(height).expect("small"); 32],
        )),
        // Distinct per height, so a test that reads it back can tell `h`
        // from `h ± 1` (the SCR-19 indexing rule as a test, §3.6).
        long_term_effective_median: Fact::passed_through(LongTermWeight::from_raw(
            300_000 + 7 * height,
        )),
    }
}

/// The world the fixtures are judged in: a clock after every fixture
/// timestamp (`candidate` stamps `1_000 + 60·h`), and a longhash of zeros,
/// which satisfies every target. The store's tests are about the store;
/// the substrate is the validation crate's subject and is mocked here as
/// plainly as possible.
pub(super) struct FixtureSubstrate;

impl FixtureSubstrate {
    pub(super) const CLOCK: Timestamp = Timestamp::from_raw(1_000_000);
}

impl Substrate for FixtureSubstrate {
    type Fault = Infallible;

    fn local_clock(&self) -> Result<Timestamp, Infallible> {
        Ok(Self::CLOCK)
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Infallible> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

/// The seed CEN-D3 expects for a candidate on `view`'s tip — what an honest
/// driver claims to `form`: the null hash at genesis admission, else the
/// identity of the block at `shekyl_chain_rules::seed_height(connecting)`.
/// Read from the same view the verdict will be minted against, as E2's
/// replay driver will.
fn expected_seed<'id, V: ChainView<'id>>(view: &V) -> Result<BlockHash, V::Fault> {
    let connecting = BlockHeight::from_raw(view.tip()?.map_or(0, |tip| tip.height.to_raw() + 1));
    let Some(seed_height) = shekyl_chain_rules::seed_height(connecting) else {
        return Ok(BlockHash::NULL);
    };
    Ok(match view.block_at(seed_height)? {
        AtHeight::Recorded(block) => block.hash,
        AtHeight::AboveTip => panic!("the seed height is below the tip"),
    })
}

/// The stateless stage over the fixture substrate, under `GENESIS`,
/// claiming the seed `view` expects.
pub(super) fn formed<'id, V: ChainView<'id>>(
    view: &V,
    candidate: Candidate,
) -> Result<StructurallyValid, V::Fault> {
    let seed = expected_seed(view)?;
    Ok(
        match form(
            candidate,
            &RuleSet::GENESIS,
            &FixtureSubstrate,
            seed,
            FormAttempt::FIRST,
        ) {
            Ok(Ok(formed)) => formed,
            Ok(Err(refused)) => panic!("the fixtures satisfy every stateless rule: {refused}"),
            Err(never) => match never {},
        },
    )
}

/// Both stages; the store's own fault is the only one the fixtures expect
/// to see in the outer position (a stale claim or a corrupt view would be
/// a fixture bug, named as such).
pub(super) fn judge<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    match validate(
        formed(view, candidate)?,
        view,
        &RuleSet::GENESIS,
        &Trust::UNANCHORED,
    ) {
        Ok(verdict) => Ok(verdict.expect("the fixtures satisfy every landed rule")),
        Err(Fault::View(fault)) => Err(fault),
        Err(Fault::Stale(stale)) => panic!("fixture claim went stale: {stale}"),
        Err(Fault::Corrupt(corrupt)) => panic!("fixture view is corrupt: {corrupt}"),
    }
}

/// Reach the SI-1 belt. CEN-I7 refuses a recorded key image at `validate`
/// (slice 6 commit 4), so a double spend no longer walks through
/// [`judge`] to the store; what the belt beneath the rule still guards is
/// the table **moving under a judged token**. This judges `candidate`
/// against the batch's view, then records its first listed input's key
/// image as spent — the same `Present` row `connect` would write — and
/// only then connects. Returns `connect`'s outcome: SI-1, poisoning the
/// batch.
pub(super) fn connect_with_image_planted_under_the_token(
    store: &ChainStore,
    candidate: Candidate,
    height: u64,
) -> Result<Connected, TestErr> {
    let Some(Input::ToKey { key_image, .. }) = candidate
        .transactions
        .first()
        .and_then(|tx| tx.prefix.inputs.first())
    else {
        panic!("the candidate's first listed transaction spends");
    };
    let planted = LmdbHashKey::from_bytes(*key_image);
    store.write(|batch| {
        let view = batch.chain_view();
        let judged = judge(&view, candidate)?;
        batch
            .open_insert_table(SPENT_KEYS, StoreInvariant::KeyImageNotFresh)?
            .insert(planted, Present)?;
        Ok(batch.connect(judged, facts(height, 0), RuleSet::GENESIS)?)
    })
}

/// The first height at which a block may list a spend. CEN-I11 wants a
/// spend's reference at least `REFERENCE_BLOCK_MIN_AGE` below the
/// connecting height, and the youngest reference any chain has is genesis
/// — so the first spend sits at height `MIN_AGE`, referencing block 0.
/// Every chain here that lists a spend starts with this many coinbase-only
/// blocks ([`spendable_prefix`]); a fixture chain listing a spend lower is
/// asking the store to record what consensus refuses.
pub(super) const FIRST_SPEND_HEIGHT: u64 = shekyl_chain_rules::REFERENCE_BLOCK_MIN_AGE.to_raw();

/// A fixture height as an index into a hash list.
pub(super) fn at(height: u64) -> usize {
    usize::try_from(height).expect("a fixture height fits usize")
}

/// `FIRST_SPEND_HEIGHT` coinbase-only blocks, then `listed` — the listing a
/// chain that carries spends is built from, so the spend heights in a test
/// read as offsets from the first admissible one.
pub(super) fn spendable_prefix(listed: &[Vec<Transaction>]) -> Vec<Vec<Transaction>> {
    let mut all = vec![Vec::new(); usize::try_from(FIRST_SPEND_HEIGHT).expect("small")];
    all.extend_from_slice(listed);
    all
}

/// [`spend`], anchored for a block connecting at `height` on the chain
/// whose block hashes are `hashes`: its reference is the block
/// `REFERENCE_BLOCK_MIN_AGE` below — the newest CEN-I11 admits
/// ([`fixture::newest_admissible_reference`]). One anchoring body with the
/// rules harness's ([`fixture::referencing`]), so the store cannot anchor
/// a spend differently from the crate that judges it.
pub(super) fn spend_at(
    hashes: &[BlockHash],
    height: u64,
    key_image: usize,
    outputs: usize,
) -> Transaction {
    anchor(hashes, height, spend(key_image, outputs))
}

/// `tx` anchored for a block connecting at `height` (see [`spend_at`]):
/// the harness's [`fixture::anchored_at`]. A serve credit stays as it is
/// at any height. A spend or an emission — including an emission with no
/// fee input, CEN-J21 — is anchored, and panics below
/// `FIRST_SPEND_HEIGHT`.
pub(super) fn anchor(hashes: &[BlockHash], height: u64, tx: Transaction) -> Transaction {
    fixture::anchored_at(hashes, height, tx)
}

/// Connect `listed` as consecutive blocks from genesis in one batch,
/// handing each `facts(h, 0)`. Every listed transaction is anchored on the
/// chain as it is built ([`anchor`]), so a caller lists bare [`spend`]s
/// and the reference is written where the hashes are known. Returns each
/// block's hash.
pub(super) fn connect_chain(store: &ChainStore, listed: &[Vec<Transaction>]) -> Vec<BlockHash> {
    connect_chain_with_burn(store, listed, 0)
}

/// [`connect_chain`] with a uniform per-block `burned` fact (pop tests
/// fold a non-zero burn so they can assert the pre-image on pop).
pub(super) fn connect_chain_with_burn(
    store: &ChainStore,
    listed: &[Vec<Transaction>],
    burned: u64,
) -> Vec<BlockHash> {
    connect_chain_anchored(store, listed, burned).0
}

/// [`connect_chain_with_burn`], also returning the listed transactions
/// **as connected** — anchored — for a test that then reads them back by
/// hash.
pub(super) fn connect_chain_anchored(
    store: &ChainStore,
    listed: &[Vec<Transaction>],
    burned: u64,
) -> (Vec<BlockHash>, Vec<Vec<Transaction>>) {
    let mut hashes: Vec<BlockHash> = Vec::new();
    let mut anchored = Vec::new();
    let mut previous = BlockHash::NULL;
    let mut cands = Vec::new();
    for (h, txs) in listed.iter().enumerate() {
        let h = h as u64;
        let txs: Vec<Transaction> = txs
            .iter()
            .map(|tx| anchor(&hashes, h, tx.clone()))
            .collect();
        anchored.push(txs.clone());
        let cand = candidate(h, previous, txs);
        previous = cand.block.hash();
        hashes.push(previous);
        cands.push(cand);
    }
    let out: Result<(), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        for (h, cand) in cands.into_iter().enumerate() {
            batch.connect(
                judge(&view, cand)?,
                facts(h as u64, burned),
                RuleSet::GENESIS,
            )?;
        }
        Ok(())
    });
    out.expect("chain connects");
    (hashes, anchored)
}

pub(super) fn connect_genesis(store: &ChainStore, burned: u64) -> (Connected, Block) {
    let cand = candidate(0, BlockHash::NULL, Vec::new());
    let block = cand.block.clone();
    let out: Result<Connected, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, cand)?;
        Ok(batch.connect(valid, facts(0, burned), RuleSet::GENESIS)?)
    });
    (out.expect("genesis connects"), block)
}
