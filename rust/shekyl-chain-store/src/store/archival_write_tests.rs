// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival writer (`archival_write.rs`, DRS-E4 commit 5): what one
//! block's [`ArchivalDelta`] leaves in the store, read back through the
//! production snapshot API and compared with the **verdict** that produced
//! it — never with a figure the test planted. The join and its credit
//! (phase 2), the accrual (9a), the epoch close (9c) on a short Fakechain
//! schedule, the attestation witness (5), the regtest injector door
//! (`ChainStore::regtest_inject_serve_credit`), ARW-9's skip-and-widen
//! under a stubbed family, and CEN-L7's `NotSettled` arm over a
//! **persisted** record — the arm the rules crate cannot reach on its own,
//! because its driver has no record that outlives a block.
//!
//! Every write is `pop`ped back and checked gone, and every close is
//! re-connected after its pop: the journal (SI-19/SI-23) is exercised by
//! round trip, not by reading the undo rows.
//!
//! The slash writes (9b) have no fixture here: the slash deadline is
//! `last_block(E) + CHALLENGE_RESOLUTION_BLOCKS`, not levered by the
//! schedule, so no chain shorter than ten thousand blocks reaches them.
//! `slash_scan_bench_tests.rs` (the B9 measurement, `#[ignore]`d) is that
//! path's one witness.

use shekyl_chain_rules::harness::{assert_refused, fixture};
use shekyl_chain_rules::{
    validate, ArchivalDelta, AtHeight, Candidate, CenRow, FakechainSchedule, Fault, Locus,
    RecordWriteKind, ReleaseAnchors, RuleSet, Trust, TxSlot, Verdict,
};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockCount, BlockHash, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_wire::{Input, Transaction};

use super::connect_fixtures::{
    anchor, batch_root_going_into, candidate_over, connect_chain, credited, formed_under,
    judge_under, priced, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::view::BatchView;
use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::SettlementEpochBlocks;
use crate::ids::ServeCreditKey;
use crate::schema::ARCHIVAL_SERVE_CREDIT;

/// The persona every join here opens a record for.
const P: [u8; 32] = [0x5a; 32];

fn persona(p: [u8; 32]) -> PCanonicalId {
    PCanonicalId::from_bytes(p)
}

fn epoch(n: u64) -> SettlementEpoch {
    SettlementEpoch::from_raw(n)
}

fn shard(n: u64) -> ShardId {
    ShardId::from_raw(n)
}

/// A `(SEB, cap)` pair at compile time; a bad one is a compile error
/// (`prune_tests.rs`'s shape).
const fn pair(seb: u64, cap: u64) -> FakechainSchedule {
    let Some(epoch) = SettlementEpochBlocks::new(seb) else {
        panic!("a zero epoch");
    };
    match FakechainSchedule::new(epoch, BlockCount::from_raw(cap)) {
        Ok(pair) => pair,
        Err(_) => panic!("the cap is not inside the epoch"),
    }
}

/// A sixteen-block settlement epoch, so a chain a few blocks past the first
/// admissible spend height closes an epoch with a record and a credit in
/// it: the join at height 10 is in epoch 0, and block 15 closes it.
const SHORT_SEB: u64 = 16;
const SHORT_RETENTION: u64 = 8;
const SHORT: RuleSet = RuleSet::fakechain(None, pair(SHORT_SEB, 4));

fn short_store(path: &std::path::Path) -> ChainStore {
    let horizons = Horizons::new(
        SHORT.settlement_schedule().blocks(),
        BlockCount::from_raw(SHORT_RETENTION),
        SHORT.reorg_cap(),
    )
    .expect("cap ≤ retention < epoch");
    ChainStore::with_horizons(path, ApplyPolicy::Full, horizons).expect("create")
}

/// Judge and connect one block at `height = hashes.len()` on the chain
/// `hashes`, listing `listed` (anchored on it), under `rules`; the hash
/// goes onto `hashes`, and the verdict's archival delta — what the writer
/// was handed — comes back for the assertions to read against.
fn connect_one(
    store: &ChainStore,
    hashes: &mut Vec<BlockHash>,
    listed: Vec<Transaction>,
    rules: RuleSet,
    witness: Option<AttestationWitness>,
) -> ArchivalDelta {
    let height = u64::try_from(hashes.len()).expect("fits");
    let previous = hashes.last().copied().unwrap_or(BlockHash::NULL);
    let listed: Vec<Transaction> = listed
        .into_iter()
        .map(|tx| anchor(hashes, height, tx))
        .collect();
    let out: Result<(BlockHash, ArchivalDelta), TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height)?;
        let cand = candidate_over(root, height, previous, listed).with_attestation_witness(witness);
        let judged = judge_under(&view, cand, &rules)?;
        let hash = judged.block().hash();
        let delta = judged.block().archival().clone();
        batch.connect(judged, rules)?;
        Ok((hash, delta))
    });
    let (hash, delta) = out.expect("the block connects");
    hashes.push(hash);
    delta
}

/// `connect_one` for a coinbase-only block.
fn connect_empty(store: &ChainStore, hashes: &mut Vec<BlockHash>, rules: RuleSet) -> ArchivalDelta {
    connect_one(store, hashes, Vec::new(), rules, None)
}

/// [`judge_under`] that hands the **verdict** back instead of panicking on
/// a refusal — for the one test here whose block is meant not to connect.
/// The verdict is read through the rules crate's own `assert_refused`, the
/// idiom every rule test uses; the store names no verdict type
/// (`check_store_error_conversion_ban.py` clause 2).
fn verdict_under<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<Verdict<()>, StoreError> {
    let candidate = priced(view, candidate)?;
    match validate(
        formed_under(view, candidate, rules)?,
        view,
        rules,
        &Trust::UNANCHORED,
    ) {
        Ok(Ok(_)) => Ok(Ok(())),
        Ok(Err(refused)) => Ok(Err(refused)),
        Err(Fault::View(fault)) => Err(fault),
        Err(Fault::Stale(stale)) => panic!("fixture claim went stale: {stale}"),
        Err(Fault::Corrupt(corrupt)) => panic!("fixture view is corrupt: {corrupt}"),
    }
}

fn pop(store: &ChainStore) {
    let out: Result<Popped, TestErr> = store.write(|batch| Ok(batch.pop()?));
    out.expect("pop");
}

// ------------------------------------------------------- phase 2 and 9a

/// A JoinMarket and the credit behind it land as the rows the delta names
/// — the record the delta inserted, the credit's pass bit, the open
/// epoch's accrual post-image — and the pop lifts all three, the accrual
/// back to the pre-image the blocks before had written.
#[test]
fn a_join_and_its_credit_land_as_the_deltas_rows_and_a_pop_lifts_them() {
    let path = tmp("aw-join-credit");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut hashes = Vec::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    }
    let p = persona(P);
    let before = store
        .begin_read()
        .expect("read")
        .budget_accruing(epoch(0))
        .expect("read");
    assert!(before.is_some(), "the coinbase-only blocks accrued");

    let [join, credit] = credited(11, P);
    let delta = connect_one(
        &store,
        &mut hashes,
        vec![join, credit],
        RuleSet::GENESIS,
        None,
    );
    let [write] = delta.records() else {
        panic!("one record write: {:?}", delta.records());
    };
    assert_eq!(write.kind(), RecordWriteKind::Insert);
    assert_eq!(*write.persona(), p);
    assert_eq!(delta.serve_credits().len(), 1);
    assert!(
        delta.close().is_none(),
        "epoch 0 is open under the production SEB"
    );
    assert_ne!(
        Some(delta.accrual().total),
        before,
        "this block's inflow moved the accrual"
    );

    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.bond_record(&p).expect("read"),
        Some(write.record().clone())
    );
    assert_eq!(
        snap.bond_records().expect("read"),
        vec![(p, write.record().clone())]
    );
    assert!(snap.pass_count(&p, shard(0), epoch(0)).expect("read").any());
    assert_eq!(
        snap.budget_accruing(epoch(0)).expect("read"),
        Some(delta.accrual().total)
    );
    drop(snap);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.bond_record(&p).expect("read"), None);
    assert!(snap.bond_records().expect("read").is_empty());
    assert!(!snap.pass_count(&p, shard(0), epoch(0)).expect("read").any());
    assert_eq!(snap.budget_accruing(epoch(0)).expect("read"), before);
    drop(snap);
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------------------- phase 9c

/// On a sixteen-block schedule block 15 closes epoch 0: the close's
/// `r_market` (the credited shard), `Σwork` and `budget` land as the
/// verdict computed them, and the accruing row is **removed** rather than
/// left as a second copy of the budget. The pop restores the accruing row
/// to the block-14 post-image and clears the three close rows; the
/// re-connect closes again, identically.
#[test]
fn a_close_freezes_the_verdicts_figures_removes_the_accruing_row_and_pops_back() {
    let path = tmp("aw-close");
    let store = short_store(&path);
    let mut hashes = Vec::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut hashes, SHORT);
    }
    let p = persona(P);
    let [join, credit] = credited(12, P);
    connect_one(&store, &mut hashes, vec![join, credit], SHORT, None);
    let mut accrued_through_14 = None;
    for _ in (FIRST_SPEND_HEIGHT + 1)..(SHORT_SEB - 1) {
        accrued_through_14 = Some(connect_empty(&store, &mut hashes, SHORT).accrual().total);
    }
    let accrued_through_14 = accrued_through_14.expect("blocks 11..=14 connected");
    assert_eq!(hashes.len(), 15, "the next block is 15, the closing one");

    let closing = connect_one(&store, &mut hashes, Vec::new(), SHORT, None);
    let close = closing.close().expect("block 15 closes epoch 0");
    assert_eq!(close.epoch(), epoch(0));
    assert_eq!(
        closing.accrual().total,
        close.budget(),
        "the close's budget is the open epoch's accrual through this block"
    );
    let r_market = close.r_market().to_vec();
    assert!(
        r_market.iter().any(|(s, _)| *s == shard(0)),
        "the credited shard is in the close: {r_market:?}"
    );

    let snap = store.begin_read().expect("read");
    assert_eq!(snap.budget(epoch(0)).expect("read"), Some(close.budget()));
    assert_eq!(
        snap.sigma_work(epoch(0)).expect("read"),
        Some(close.sigma_work())
    );
    for (s, r) in &r_market {
        assert_eq!(snap.r_market(*s, epoch(0)).expect("read"), Some(*r));
    }
    assert_eq!(
        snap.budget_accruing(epoch(0)).expect("read"),
        None,
        "ARW-Q3: the accruing row is removed at the close"
    );
    assert!(
        snap.bond_record(&p).expect("read").is_some(),
        "the record outlives the close"
    );
    drop(snap);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.budget(epoch(0)).expect("read"), None);
    assert_eq!(snap.sigma_work(epoch(0)).expect("read"), None);
    for (s, _) in &r_market {
        assert_eq!(snap.r_market(*s, epoch(0)).expect("read"), None);
    }
    assert_eq!(
        snap.budget_accruing(epoch(0)).expect("read"),
        Some(accrued_through_14),
        "the pop puts the block-14 accrual back"
    );
    drop(snap);

    hashes.pop();
    let again = connect_one(&store, &mut hashes, Vec::new(), SHORT, None);
    assert_eq!(again, closing, "the same block, the same verdict");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.budget(epoch(0)).expect("read"), Some(close.budget()));
    assert_eq!(
        snap.sigma_work(epoch(0)).expect("read"),
        Some(close.sigma_work())
    );
    assert_eq!(snap.budget_accruing(epoch(0)).expect("read"), None);
    drop(snap);
    drop(store);
    cleanup(&path);
}

// -------------------------------------------------------------- phase 5

/// The candidate's attestation witness is written **unjudged** at the
/// block's height (CEN-B4's gap, DRS-E4 §3.2 phase 5): a block carrying
/// one reads back its bytes, a block without reads back `None`, and the
/// pop lifts the row with the block.
#[test]
fn the_attestation_witness_is_written_at_the_blocks_height_and_popped_with_it() {
    let path = tmp("aw-witness");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut hashes = Vec::new();
    connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    let bytes = vec![0xab; 40];
    let witness = AttestationWitness::new(bytes.clone()).expect("non-empty, under the cap");
    connect_one(
        &store,
        &mut hashes,
        Vec::new(),
        RuleSet::GENESIS,
        Some(witness),
    );

    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(0))
            .expect("read"),
        AtHeight::Recorded(None)
    );
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(1))
            .expect("read"),
        AtHeight::Recorded(Some(bytes))
    );
    drop(snap);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.attestation_witness_at(BlockHeight::from_raw(1))
            .expect("read"),
        AtHeight::AboveTip
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------------- the injector

/// The regtest door: refused under any trust that carries an anchor
/// (Fakechain is the one posture no release vouches for), refused on an
/// empty chain, refused for a persona with no record (a bit for a
/// stranger would be SI-15 at the next read), and otherwise a pass bit at
/// the tip's height that the journal never saw — a pop below it leaves the
/// bit, as the C++'s does.
#[test]
fn the_injector_opens_only_unanchored_and_writes_an_unjournaled_bit_at_the_tip() {
    let path = tmp("aw-inject");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(P);

    let empty = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, p, shard(3), epoch(0))
        .unwrap_err();
    assert!(
        matches!(empty, StoreError::Cannot(StoreCannot::ChainEmpty)),
        "{empty:?}"
    );

    let mut hashes = Vec::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    }
    let stranger = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, p, shard(3), epoch(0))
        .unwrap_err();
    assert!(
        matches!(
            stranger,
            StoreError::Cannot(StoreCannot::InjectionForUnbondedPersona { persona }) if persona == p
        ),
        "{stranger:?}"
    );
    connect_one(
        &store,
        &mut hashes,
        vec![fixture::join_market(fixture::point(11), P)],
        RuleSet::GENESIS,
        None,
    );
    let tip = BlockHeight::from_raw(FIRST_SPEND_HEIGHT);

    let anchored = Trust::full(ReleaseAnchors::for_tests(Some(hashes[0]), &[]));
    let off = store
        .regtest_inject_serve_credit(anchored, p, shard(3), epoch(0))
        .unwrap_err();
    assert!(
        matches!(off, StoreError::Cannot(StoreCannot::InjectionOffFakechain)),
        "{off:?}"
    );
    assert!(
        !store
            .begin_read()
            .expect("read")
            .pass_count(&p, shard(3), epoch(0))
            .expect("read")
            .any(),
        "a refused injection writes nothing"
    );

    let at = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, p, shard(3), epoch(0))
        .expect("Fakechain, a tip recorded, a record held");
    assert_eq!(at, tip, "attributed to the tip");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.pass_count(&p, shard(3), epoch(0))
            .expect("read")
            .to_raw(),
        1
    );
    assert!(!snap.pass_count(&p, shard(3), epoch(1)).expect("read").any());
    drop(snap);

    // Not journaled: a block above the bit, popped, leaves it.
    connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.tip().expect("read").recorded.map(|t| t.height),
        Some(tip)
    );
    assert_eq!(
        snap.pass_count(&p, shard(3), epoch(0))
            .expect("read")
            .to_raw(),
        1,
        "the injected bit survives the pop below it"
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}

/// The door writes one family and does not skip: a session stubbing
/// `ServeCredit` is refused at the table, not silently widened.
#[test]
fn the_injector_is_refused_when_serve_credits_are_stubbed() {
    let path = tmp("aw-inject-stubbed");
    let policy = ApplyPolicy::stubbed(&[ArchivalFamily::ServeCredit]).expect("non-empty");
    let store = ChainStore::with_apply_policy(&path, policy, EPOCH).expect("create");
    let mut hashes = Vec::new();
    connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    let err = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, persona([0x1f; 32]), shard(0), epoch(0))
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Cannot(StoreCannot::FamilyStubbed(ArchivalFamily::ServeCredit))
        ),
        "{err:?}"
    );
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------------------- ARW-9

/// Skip-and-widen: a session stubbing `Bond` connects the join without
/// writing its record, writes the credit behind it without the
/// record-exists belt (the belt reads a table this session does not
/// write), and the file's provenance names the family — the block is
/// accepted, and the file is no longer parity evidence. The reads say so
/// too, in their own voice: the production `pass_count` over that credit
/// is SI-15 (`ServeCreditWithoutBond`), because the read belt knows the
/// tables and not the session's policy. The credit's row is witnessed at
/// the table, beneath the belt.
#[test]
fn a_stubbed_family_is_skipped_and_widens_the_files_provenance() {
    let path = tmp("aw-arw9");
    let policy = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
    let store = ChainStore::with_apply_policy(&path, policy, EPOCH).expect("create");
    let p = persona(P);
    let [join, credit] = credited(13, P);
    let listing: Vec<Vec<Transaction>> = (0..FIRST_SPEND_HEIGHT)
        .map(|_| Vec::new())
        .chain(core::iter::once(vec![join, credit]))
        .collect();
    let hashes = connect_chain(&store, &listing);
    assert_eq!(
        hashes.len(),
        usize::try_from(FIRST_SPEND_HEIGHT + 1).expect("fits")
    );

    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.bond_record(&p).expect("read"),
        None,
        "the record was skipped, not written"
    );
    let row = snap
        .open_table(ARCHIVAL_SERVE_CREDIT)
        .expect("table")
        .get(
            ServeCreditKey::new(
                p,
                shard(0),
                epoch(0),
                BlockHeight::from_raw(FIRST_SPEND_HEIGHT),
            )
            .key(),
        )
        .expect("get")
        .is_some();
    assert!(
        row,
        "the credit was written behind a record this session does not hold"
    );
    let read = snap.pass_count(&p, shard(0), epoch(0)).unwrap_err();
    assert!(
        matches!(
            read,
            StoreError::InvariantViolated(StoreInvariant::ServeCreditWithoutBond { persona }) if persona == p
        ),
        "the read belt does not know the policy: {read:?}"
    );
    drop(snap);
    let provenance = store.provenance();
    assert!(provenance.stubbed().contains(ArchivalFamily::Bond));
    assert!(!provenance.is_parity_evidence());
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------- CEN-L7 over a record

/// A claim for the open epoch by a persona whose record the store
/// **holds** — inserted by an earlier block, read back through the batch
/// view — is `NotSettled`, refused at CEN-L7 on the emission's vin. The
/// rules crate's driver can reach this arm only over a record the same
/// block inserted; over a persisted one it is the store's to witness.
#[test]
fn a_claim_on_the_open_epoch_over_a_persisted_record_is_refused_at_l7() {
    let path = tmp("aw-claim-open");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut hashes = Vec::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    }
    let claimant = fixture::claimant(0xc1);
    connect_one(
        &store,
        &mut hashes,
        vec![fixture::join_market(fixture::point(14), claimant)],
        RuleSet::GENESIS,
        None,
    );
    assert!(
        store
            .begin_read()
            .expect("read")
            .bond_record(&persona(claimant))
            .expect("read")
            .is_some(),
        "the record is persisted before the claim is judged"
    );

    let height = u64::try_from(hashes.len()).expect("fits");
    let open = RuleSet::GENESIS
        .settlement_schedule()
        .epoch_at(BlockHeight::from_raw(height))
        .to_raw();
    let Input::ArchivalRewardEmission { canonical_bytes } = fixture::emission_vin(0xc1, &[open])
    else {
        unreachable!("emission_vin builds an emission input");
    };
    let claim = fixture::balanced_emission(fixture::point(15), canonical_bytes, 1_000_000);
    let claim = anchor(&hashes, height, claim);
    let previous = *hashes.last().expect("a chain");
    let out: Result<Verdict<()>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height)?;
        let cand = candidate_over(root, height, previous, vec![claim]);
        Ok(verdict_under(&view, cand, &RuleSet::GENESIS)?)
    });
    assert_refused(
        out.expect("judging only reads"),
        CenRow::L7,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 1,
        },
    );
    drop(store);
    cleanup(&path);
}
