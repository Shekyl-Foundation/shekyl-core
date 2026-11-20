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
use shekyl_chain_rules::target_claim;
use shekyl_chain_rules::{
    form, validate, validate_with_memo, AtHeight, Candidate, ChainValid, ChainView, Corrupt,
    DrawableMemo, Fault, FormAttempt, FormClaims, GenesisPin, HeaderView, PaidEmission,
    ReferenceClaims, RuleSet, StructurallyValid, Substrate, Target, Trust, Verdict, ViewRead,
    Weights,
};
use shekyl_harness_spender::{MinerWallet, Persona};
use shekyl_network::{Network, NetworkId};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, PowHash, SectionRoot, Timestamp};
use shekyl_wire::block::HEADER_MINOR_VERSION;
use shekyl_wire::{Block, BlockHeader, Input, Transaction};

use super::store_tests::TestErr;
use super::view::BatchView;
use super::*;
use crate::codec::Present;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::SPENT_KEYS;

mod grown;

pub(super) use grown::{
    anchor, at, connect_chain, connect_chain_anchored, connect_chain_burning, endow_genesis,
    grown_over, height_maturing, key_images, output_of, prefix_to, spend, spend_paying,
    spendable_prefix, Grown, Listed, FIRST_SPEND_HEIGHT,
};

/// The identity a fixture chain carries (`CHAIN_FORGE.md` §6, `CF-R15`):
/// what its spends and posts sign under, which miner its coinbases pay,
/// and the genesis `validate` holds height 0 to. One chain carries one;
/// [`Grown`] holds it and every block it builds or judges uses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Identity {
    /// A chain that mines its own genesis, under the harness id
    /// (`Trust::UNPINNED`): every chain a test builds from nothing. The
    /// harness id ends in `CF-5` (`CF-R15`).
    Harness,
    /// A chain over regtest's table genesis, under regtest's id: a forged
    /// chain a test starts from ([`super::forged_fill`]), and the blocks the
    /// test connects on top of it.
    Regtest,
}

impl Identity {
    /// What `validate` takes on the release's word: no pin for a chain
    /// that mines its own genesis, regtest's table genesis otherwise.
    pub(super) const fn trust(self) -> Trust {
        match self {
            Self::Harness => Trust::UNPINNED,
            Self::Regtest => Trust::full(GenesisPin::for_network(Network::Regtest)),
        }
    }

    /// The id every spend and post on the chain signs under: the one its
    /// [`trust`](Self::trust) derives (`NI-R10`).
    pub(super) fn network_id(self) -> NetworkId {
        self.trust().network_id()
    }

    /// The miner every coinbase the fixtures build pays, and the wallet a
    /// spend of one is made from.
    pub(super) fn miner(self) -> &'static MinerWallet {
        match self {
            Self::Harness => MinerWallet::harness(),
            Self::Regtest => MinerWallet::harness_regtest(),
        }
    }

    /// The persona at `slot`, derived under the chain's network name.
    pub(super) fn persona(self, slot: u32) -> Persona {
        match self {
            Self::Harness => Persona::at(slot),
            Self::Regtest => Persona::on(Network::Regtest, slot),
        }
    }

    /// The lowest height whose coinbase the miner holds: genesis's on a
    /// harness chain ([`endow_genesis`] pays it), block 1's on regtest's,
    /// whose genesis is the table's.
    pub(super) const fn first_held_coinbase(self) -> u64 {
        match self {
            Self::Harness => 0,
            Self::Regtest => 1,
        }
    }

    /// The timestamp a block at `height` carries.
    ///
    /// A harness chain stamps from [`HARNESS_GENESIS_STAMP`] and does not
    /// read `parent_timestamp`. A regtest chain is [`FIXTURE_SPACING`] past
    /// its parent, which is how a block built on the forged chain stays on
    /// the forged chain's clock.
    ///
    /// # Panics
    ///
    /// When `self` is [`Self::Regtest`] and `parent_timestamp` is [`None`]:
    /// a regtest chain starts from its replayed genesis, so the parent is
    /// known.
    pub(super) fn timestamp(self, height: BlockHeight, parent_timestamp: Option<u64>) -> u64 {
        match self {
            Self::Harness => HARNESS_GENESIS_STAMP + height.to_raw() * FIXTURE_SPACING,
            Self::Regtest => {
                parent_timestamp.expect("a regtest block stamps its time after its parent")
                    + FIXTURE_SPACING
            }
        }
    }

    /// The substrate clock blocks on this chain are judged against: past
    /// every stamp the chain and the blocks a test adds on top of it carry.
    pub(super) const fn clock(self) -> Timestamp {
        match self {
            Self::Harness => FixtureSubstrate::CLOCK,
            Self::Regtest => Timestamp::from_raw(
                Network::Regtest.genesis().timestamp().get() + REGTEST_CLOCK_PAST_MINT,
            ),
        }
    }

    /// The world `form` judges a block on this chain in: [`Self::clock`] and
    /// a longhash of zeros.
    pub(super) const fn substrate(self) -> FixtureSubstrate {
        FixtureSubstrate::at(self.clock())
    }
}

/// Seconds between the blocks a fixture chain builds. A harness block at
/// height `h` is stamped [`HARNESS_GENESIS_STAMP`] plus this many times `h`.
/// A block built on a regtest chain is this many past its parent.
const FIXTURE_SPACING: u64 = 60;

/// The timestamp of height 0 on a harness chain.
const HARNESS_GENESIS_STAMP: u64 = 1_000;

/// How far past regtest's mint [`Identity::Regtest`]'s clock sits: a forged
/// chain stamped one second apart, then a hundred thousand blocks at
/// [`FIXTURE_SPACING`] on top of it.
const REGTEST_CLOCK_PAST_MINT: u64 = 10_000_000;

/// The nonce every fixture header carries. No rule reads it; the longhash
/// is the substrate's.
const FIXTURE_NONCE: u32 = 7;

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
/// `height` as the store recorded it. A harness chain under the genesis
/// rules ([`candidate_carrying`]).
pub(super) fn candidate_over(
    root: CurveTreeRoot,
    height: u64,
    previous: BlockHash,
    listed: Vec<Transaction>,
) -> Candidate {
    candidate_carrying(
        Identity::Harness,
        &RuleSet::GENESIS,
        root,
        BlockHeight::from_raw(height),
        previous,
        None,
        listed,
    )
}

/// The block connecting at `height` on a chain carrying `identity`, judged
/// under `rules`.
///
/// One constructor. `rules` names the header version and the coinbase's
/// unlock window. `identity` names the miner the coinbase pays and the
/// timestamp ([`Identity::timestamp`]). The coinbase amount is zero:
/// [`priced_as`] writes what CEN-F18 owes, and a harness genesis is endowed
/// afterwards ([`endow_genesis`]). The unlock saturates, as the harness
/// coinbase does, so a record built at `u64::MAX` is bytes rather than a
/// panic — the rules refuse it, and the store tests that exercise the
/// height want the bytes.
///
/// `parent_timestamp` is the parent block's stamp. A harness chain does
/// not read it. A regtest chain requires it.
pub(super) fn candidate_carrying(
    identity: Identity,
    rules: &RuleSet,
    root: CurveTreeRoot,
    height: BlockHeight,
    previous: BlockHash,
    parent_timestamp: Option<u64>,
    listed: Vec<Transaction>,
) -> Candidate {
    let timestamp = identity.timestamp(height, parent_timestamp);
    let height = height.to_raw();
    let unlock_time = height.saturating_add(rules.mined_money_unlock_window().to_raw());
    let block = Block {
        header: BlockHeader {
            major_version: rules.header_major_version(),
            minor_version: HEADER_MINOR_VERSION,
            timestamp,
            previous,
            nonce: FIXTURE_NONCE,
            curve_tree_root: root,
            // The empty section's root: a candidate carrying no references is
            // judged against it (CEN-J29).
            section_root: SectionRoot::from_bytes(shekyl_archival_retention::empty_section_root()),
        },
        miner_transaction: shekyl_harness_wallet::coinbase::paying(
            identity.miner().recipient(),
            height,
            unlock_time,
            0,
        ),
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

/// The world a fixture block is judged in: a clock, and a longhash of
/// zeros, which satisfies every target. The store's tests are about the
/// store; the substrate is the validation crate's subject and is mocked
/// here as plainly as possible.
///
/// The clock is the chain's ([`Identity::clock`]). [`Self::CLOCK`] is the
/// harness chain's, past every stamp [`HARNESS_GENESIS_STAMP`] +
/// [`FIXTURE_SPACING`] · h that a unit test builds. [`Self::HARNESS`] is
/// that clock for a caller that judges a harness candidate without a
/// [`Grown`] chain.
#[derive(Clone, Copy)]
pub(super) struct FixtureSubstrate {
    clock: Timestamp,
}

impl FixtureSubstrate {
    /// The harness chain's clock.
    pub(super) const CLOCK: Timestamp = Timestamp::from_raw(1_000_000);

    /// [`Self::CLOCK`] as a substrate.
    pub(super) const HARNESS: Self = Self { clock: Self::CLOCK };

    /// A substrate whose clock is `clock`.
    pub(super) const fn at(clock: Timestamp) -> Self {
        Self { clock }
    }
}

impl Substrate for FixtureSubstrate {
    type Fault = Infallible;

    fn local_clock(&self) -> Result<Timestamp, Infallible> {
        Ok(self.clock)
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
pub(super) fn expected_seed<'id, V: HeaderView<'id>>(view: &V) -> Result<BlockHash, V::Fault> {
    let connecting = BlockHeight::from_raw(view.tip()?.map_or(0, |tip| tip.height.to_raw() + 1));
    let Some(seed_height) = shekyl_chain_rules::seed_height(connecting) else {
        return Ok(BlockHash::NULL);
    };
    Ok(match view.header_at(seed_height)? {
        AtHeight::Recorded(record) => record.hash,
        AtHeight::AboveTip => panic!("the seed height is below the tip"),
    })
}

/// The target CEN-D4 derives on `view` for the next block under `rules`:
/// what an honest driver claims to `form`, through the validator's one
/// derivation (`target_claim`). The view's own fault is the only error; a
/// corrupt header chain or a zero difficulty is a fixture bug.
pub(super) fn expected_target<'id, V: HeaderView<'id>>(
    view: &V,
    rules: &RuleSet,
) -> Result<Target, V::Fault> {
    let connecting = BlockHeight::from_raw(view.tip()?.map_or(0, |tip| tip.height.to_raw() + 1));
    match target_claim(view, connecting, rules) {
        Ok(target) => Ok(target),
        Err(Fault::View(fault)) => Err(fault),
        Err(_) => panic!("the fixture chain's headers are not a chain"),
    }
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

/// [`priced`] paying `identity`'s miner.
pub(super) fn priced_as<'b, 'id>(
    identity: Identity,
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
) -> Result<Candidate, StoreError> {
    match fixture::priced_paying(view, candidate, identity.miner()) {
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
/// claiming the seed, target and reference roots `view` expects. `view`
/// is any [`HeaderView`]: the batch's chain view for a connect, the
/// stitched `AltView` for the alt tier (`alt_tests::admitted`) — the
/// seed, the target window and the reference window are header reads
/// either way (`ReferenceClaims::from_headers`).
pub(super) fn formed<'id, V: HeaderView<'id>>(
    view: &V,
    candidate: Candidate,
) -> Result<StructurallyValid, V::Fault> {
    formed_under(view, candidate, &RuleSet::GENESIS)
}

/// [`formed`] under an explicit rule set (a levered set for tests that
/// run a shortened schedule).
pub(super) fn formed_under<'id, V: HeaderView<'id>>(
    view: &V,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<StructurallyValid, V::Fault> {
    match formed_as(Identity::Harness, view, candidate, rules)? {
        Ok(formed) => Ok(formed),
        Err(refused) => panic!("the fixtures satisfy every stateless rule: {refused}"),
    }
}

/// [`formed_under`] claiming `identity`'s network, judged on its clock
/// ([`Identity::substrate`]). A stateless refusal is the [`Err`] of the
/// verdict: a fixture door panics on it, and a forged block's door names
/// the block.
pub(super) fn formed_as<'id, V: HeaderView<'id>>(
    identity: Identity,
    view: &V,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<Verdict<StructurallyValid>, V::Fault> {
    let seed = expected_seed(view)?;
    let connecting = BlockHeight::from_raw(view.tip()?.map_or(0, |tip| tip.height.to_raw() + 1));
    let references = ReferenceClaims::from_headers(view, connecting, &candidate)?;
    let claims = FormClaims {
        rule_set: rules,
        seed,
        target: expected_target(view, rules)?,
        references: &references,
        network: identity.network_id(),
    };
    let substrate = identity.substrate();
    match form(candidate, &claims, &substrate, FormAttempt::FIRST) {
        Ok(verdict) => Ok(verdict),
        Err(never) => match never {},
    }
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
    judge_or_corrupt_as(Identity::Harness, view, candidate, rules)
}

/// [`judge_or_corrupt`] on a chain carrying `identity`.
pub(super) fn judge_or_corrupt_as<'b, 'id>(
    identity: Identity,
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<Result<ChainValid<'id, BatchView<'b, 'id>>, Corrupt>, StoreError> {
    let candidate = priced_as(identity, view, candidate)?;
    let formed = match formed_as(identity, view, candidate, rules)? {
        Ok(formed) => formed,
        Err(refused) => panic!("the fixtures satisfy every stateless rule: {refused}"),
    };
    match validate(formed, view, rules, &identity.trust()) {
        Ok(verdict) => Ok(Ok(verdict.expect("the fixtures satisfy every landed rule"))),
        Err(Fault::View(fault)) => Err(fault),
        Err(Fault::Stale(stale)) => panic!("fixture claim went stale: {stale}"),
        Err(Fault::Corrupt(corrupt)) => Ok(Err(corrupt)),
    }
}

/// [`judge_under`] with the connect loop's drawable memo, on a chain
/// carrying `identity`: the coinbase priced to its miner, the network
/// claimed and the genesis pinned as it says. A [`Corrupt`] still panics:
/// this door is for a block the rules accept.
pub(super) fn judge_with_memo_as<'b, 'id>(
    identity: Identity,
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
    memo: Option<&mut DrawableMemo>,
) -> Result<ChainValid<'id, BatchView<'b, 'id>>, StoreError> {
    let candidate = priced_as(identity, view, candidate)?;
    match judge_as_built(identity, view, candidate, rules, memo)? {
        Ok(valid) => Ok(valid),
        Err(refused) => panic!("the fixtures satisfy every landed rule: {refused}"),
    }
}

/// Both stages over `candidate` exactly as it came: nothing priced, nothing
/// rebuilt. A forged block is judged this way, so the block connected is
/// the one the forge wrote, or the verdict is the row that refused it.
///
/// A refusal is returned, not panicked: the fixture door
/// ([`judge_with_memo_as`]) treats one as a fixture bug, and the forged
/// door names the block and the commit it was forged at.
pub(super) fn judge_as_built<'b, 'id>(
    identity: Identity,
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
    memo: Option<&mut DrawableMemo>,
) -> Result<Verdict<ChainValid<'id, BatchView<'b, 'id>>>, StoreError> {
    let formed = match formed_as(identity, view, candidate, rules)? {
        Ok(formed) => formed,
        Err(refused) => return Ok(Err(refused)),
    };
    match validate_with_memo(formed, view, rules, &identity.trust(), memo) {
        Ok(verdict) => Ok(verdict),
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
