// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shared `connect` / `pop` test fixtures. One place with `facts` so the
//! header root a candidate carries — [`root_going_into`] on a committed
//! snapshot, [`batch_root_going_into`] inside a batch — cannot drift from
//! the root the connect of the parent wrote.
//!
//! A chain that lists a spend lists a **real** one (slice 6 row 6): a
//! proof over a coinbase the chain mined, built by the harness spender
//! against the wallet-side tree [`Grown`] keeps in step with the store's.
//! Every `connect_chain*` takes a listing of [`Listed`] — a spend named by
//! its fee, built when its block is, or a body given whole — and returns
//! the [`Grown`] chain, which builds the next block's spend for a test
//! that connects one by hand.

use core::convert::Infallible;

use shekyl_chain_rules::harness::fixture;
use shekyl_chain_rules::{
    form, validate, AtHeight, Candidate, ChainValid, ChainView, Corrupt, Fault, FormAttempt,
    PaidEmission, RuleSet, StructurallyValid, Substrate, Trust, ViewRead, Weights,
};
use shekyl_types::{AttestationRoot, BlockHash, BlockHeight, CurveTreeRoot, PowHash, Timestamp};
use shekyl_wire::{Block, BlockHeader, Input, Transaction};

use super::store_tests::TestErr;
use super::view::BatchView;
use super::*;
use crate::codec::Present;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::SPENT_KEYS;

mod grown;

pub(super) use grown::{
    anchor, at, body, connect_chain, connect_chain_anchored, connect_chain_burning, credited,
    endow_genesis, grown_over, height_maturing, key_images, output_of, prefix_to, serve_credit,
    spend, spend_paying, spendable_prefix, spends, Grown, Listed, FIRST_SPEND_HEIGHT,
};

/// The coinbase for `height`: the rules harness's, which satisfies every
/// landed 4.F row (a sole `Input::Gen(height)`, `Null` ct, one output with
/// a canonical key and a non-trivial mask, `unlock_time = height + 60`).
/// One definition of "a valid coinbase" for every crate that judges one —
/// a private copy here drifted from the rules the moment slice 4 landed
/// F9/F10 (its keys were not points).
pub(super) fn coinbase(height: u64) -> Transaction {
    fixture::coinbase(height)
}

/// A candidate for a height **nothing has drained into**: its header carries
/// the empty tree, which is what CEN-B5 requires while `root_at(height)` is
/// `EMPTY` — every height below `mined_money_unlock_window` on a chain whose
/// listed outputs (if any) are younger than `tx_spendable_age`. Since
/// DRS-E3 the root is the validator's derivation, recorded by `connect`,
/// so a fixture cannot compute it from the height alone: a candidate for a
/// grown height reads the root off the store ([`root_going_into`] on a
/// snapshot, [`batch_root_going_into`] inside a batch) and builds with
/// [`candidate_over`]. [`connect_chain`] does exactly that per block.
pub(super) fn candidate(height: u64, previous: BlockHash, listed: Vec<Transaction>) -> Candidate {
    candidate_over(CurveTreeRoot::EMPTY, height, previous, listed)
}

/// [`candidate`] whose header carries `root` — the tree state going into
/// `height` as the store recorded it.
pub(super) fn candidate_over(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: Vec<Transaction>,
) -> Candidate {
    let block = Block {
        header: BlockHeader {
            major_version: 1,
            minor_version: 0,
            timestamp: 1_000 + height * 60,
            previous,
            nonce: 7,
            curve_tree_root: root,
            // The empty set's root: a candidate carrying no witness is judged
            // against it (CEN-B4, slice 8 row 10).
            attestation_root: AttestationRoot::from_bytes(
                shekyl_archival_retention::empty_attestation_root(),
            ),
        },
        miner_transaction: coinbase(height),
        transaction_hashes: listed.iter().map(Transaction::hash).collect(),
    };
    Candidate::new(block, listed)
}

/// `root_at(height)` as the root a header connecting there must carry
/// (CEN-B5). `AboveTip` is a fixture bug: height 0 is the seal's empty
/// tree, and every later height is the row the previous connect wrote.
fn recorded_root(
    at: Result<AtHeight<CurveTreeRoot>, StoreError>,
    height: u64,
) -> Result<CurveTreeRoot, StoreError> {
    let AtHeight::Recorded(root) = at? else {
        panic!("no root recorded going into height {height}");
    };
    Ok(root)
}

/// The root a header connecting at `height` must carry, as the committed
/// store holds it. A read fault is a fixture bug.
pub(super) fn root_going_into(store: &ChainStore, height: u64) -> CurveTreeRoot {
    let snap = store.begin_read().expect("read");
    recorded_root(snap.root_at(BlockHeight::from_raw(height)), height).expect("root read")
}

/// [`root_going_into`] read from the batch's view, which sees this batch's
/// own connects. A store fault propagates; `AboveTip` is still a fixture bug.
pub(super) fn batch_root_going_into(
    view: &BatchView<'_, '_>,
    height: u64,
) -> Result<CurveTreeRoot, StoreError> {
    recorded_root(view.root_at(BlockHeight::from_raw(height)), height)
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

/// `candidate` with its coinbase paying what CEN-F18 owes it on `view` —
/// the harness's one pricer, at the height the view says the candidate
/// connects at. The view's own fault is the only error: a corrupt parent
/// read is a fixture bug, not a block the test is asking to refuse.
pub(super) fn priced<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<Candidate, StoreError> {
    match fixture::priced(view, candidate) {
        Ok(candidate) => Ok(candidate),
        Err(ViewRead::View(fault)) => Err(fault),
        Err(ViewRead::Corrupt(corrupt)) => panic!("fixture view is corrupt: {corrupt:?}"),
    }
}

/// [`priced`] against the **committed** store — for a test that needs a
/// block's identity (to build its child, to read it back) before the batch
/// that connects it. Opens a batch that only reads.
pub(super) fn priced_on(store: &ChainStore, candidate: Candidate) -> Candidate {
    let out: Result<Candidate, TestErr> =
        store.write(|batch| Ok(priced(&batch.chain_view(), candidate)?));
    out.expect("pricing only reads")
}

/// The stateless stage over the fixture substrate, under `GENESIS`,
/// claiming the seed `view` expects.
pub(super) fn formed<'id, V: ChainView<'id>>(
    view: &V,
    candidate: Candidate,
) -> Result<StructurallyValid, V::Fault> {
    formed_under(view, candidate, &RuleSet::GENESIS)
}

/// [`formed`] under an explicit rule set (a Fakechain set for tests that
/// run a shortened schedule).
pub(super) fn formed_under<'id, V: ChainView<'id>>(
    view: &V,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<StructurallyValid, V::Fault> {
    let seed = expected_seed(view)?;
    Ok(
        match form(
            candidate,
            rules,
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
    judge_under(view, candidate, &RuleSet::GENESIS)
}

/// [`judge`] under an explicit rule set.
///
/// The candidate's coinbase is **priced here**, against the view it is
/// judged on, before the stateless stage: `candidate_over` builds a
/// coinbase paying zero (no fixture can price without the chain), and
/// CEN-F18 (E6 slice 7 wave B) refuses any block above genesis whose
/// coinbase does not pay exactly what the block owes it. The harness's
/// `priced_at` is the one pricer every crate's fixtures share. A
/// consequence for the caller: a block's identity is known **after** it is
/// judged, so a chain of fixtures takes each `previous` from the verdict
/// ([`ChainValid::block`]), not from the unpriced candidate — except at
/// genesis, whose configured coinbase stands as built.
pub(super) fn judge_under<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    match judge_or_corrupt(view, candidate, rules)? {
        Ok(valid) => Ok(valid),
        Err(corrupt) => panic!("fixture view is corrupt: {corrupt}"),
    }
}

/// [`judge_under`] for a fixture that built the corrupt state on purpose:
/// the validator's [`Corrupt`] comes back as a value, for the test to hand
/// to `refuse_corrupt` as the ingest would.
pub(super) fn judge_or_corrupt<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<Result<ChainValid<'id, BatchView<'b, 'id>>, Corrupt>, StoreError> {
    let candidate = priced(view, candidate)?;
    match validate(
        formed_under(view, candidate, rules)?,
        view,
        rules,
        &Trust::UNANCHORED,
    ) {
        Ok(verdict) => Ok(Ok(verdict.expect("the fixtures satisfy every landed rule"))),
        Err(Fault::View(fault)) => Err(fault),
        Err(Fault::Stale(stale)) => panic!("fixture claim went stale: {stale}"),
        Err(Fault::Corrupt(corrupt)) => Ok(Err(corrupt)),
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
        Ok(batch.connect(judged, RuleSet::GENESIS)?)
    })
}

pub(super) fn connect_genesis(store: &ChainStore) -> (Connected, Block) {
    let (connected, block, _) = connect_genesis_judged(store);
    (connected, block)
}

/// [`connect_genesis`], also returning what the verdict derived and
/// `connect` recorded from it — the weights (CEN-G6/G6b) and the paid
/// emission (CEN-F14b, G12) — for a test that reads `block_info` back and
/// must know what the validator, not a fixture, said.
pub(super) fn connect_genesis_judged(
    store: &ChainStore,
) -> (Connected, Block, (Weights, PaidEmission)) {
    let cand = candidate(0, BlockHash::NULL, Vec::new());
    let block = cand.block.clone();
    let out: Result<(Connected, (Weights, PaidEmission)), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let valid = judge(&view, cand)?;
        let derived = (*valid.block().weights(), *valid.block().emission());
        Ok((batch.connect(valid, RuleSet::GENESIS)?, derived))
    });
    let (connected, derived) = out.expect("genesis connects");
    (connected, block, derived)
}
