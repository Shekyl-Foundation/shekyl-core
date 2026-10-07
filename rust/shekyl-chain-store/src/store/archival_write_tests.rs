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
//! The slash writes (9b) have no single-block fixture: a slash needs `M`
//! epochs of misses settled 2-of-3 and then one epoch of grace
//! (`SLASH_GRACE_EPOCHS · SEB`), so its witness is a chain, not a block.
//! `slash_scan_bench_tests.rs` builds it — 1 300 connects at `SEB = 100` —
//! and `slash_writes_land_at_the_m_epoch_deadline` there is the 9b witness
//! in the unit lane; the `#[ignore]`d B9 bench shares the chain.

use shekyl_archival_retention::BlockAttestationWitness;
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

/// The fixture-persona tag every join here opens a record for.
const P: [u8; 32] = [0x5a; 32];

/// The id the persona tagged `p` is recorded under — the recompute over
/// its derived identity key (CEN-J11), not the tag.
fn persona(p: [u8; 32]) -> PCanonicalId {
    fixture::persona(p).id
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
/// it: the join at height 5 is in epoch 0, block 15 closes that, and
/// block 31 closes epoch 1 — the first the persona may be credited for.
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

/// A JoinMarket and, one block above it, the credit on its record land as
/// the rows the two deltas name — the record the join's delta inserted,
/// the credit's pass bit, each block's open-epoch accrual post-image — and
/// the pops lift them in order: the credit's pop the pass bit and the
/// accrual back to the join block's, the join's pop the record and the
/// accrual back to the pre-image the blocks before had written. The credit
/// is for epoch 1 (CEN-J5: the join's epoch plus one); the pass bit is
/// read under that key.
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
    let joined = connect_one(&store, &mut hashes, vec![join], RuleSet::GENESIS, None);
    let [write] = joined.records() else {
        panic!("one record write: {:?}", joined.records());
    };
    assert_eq!(write.kind(), RecordWriteKind::Insert);
    assert_eq!(*write.persona(), p);
    assert!(joined.serve_credits().is_empty());
    assert!(
        joined.close().is_none(),
        "epoch 0 is open under the production SEB"
    );
    assert_ne!(
        Some(joined.accrual().total),
        before,
        "this block's inflow moved the accrual"
    );

    let credited_delta = connect_one(&store, &mut hashes, vec![credit], RuleSet::GENESIS, None);
    assert!(
        credited_delta.records().is_empty(),
        "a credit writes no record"
    );
    assert_eq!(credited_delta.serve_credits().len(), 1);
    assert_ne!(
        credited_delta.accrual().total,
        joined.accrual().total,
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
    assert!(snap.pass_count(&p, shard(0), epoch(1)).expect("read").any());
    assert_eq!(
        snap.budget_accruing(epoch(0)).expect("read"),
        Some(credited_delta.accrual().total)
    );
    drop(snap);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.bond_record(&p).expect("read"),
        Some(write.record().clone()),
        "the credit's pop leaves the join's record"
    );
    assert!(!snap.pass_count(&p, shard(0), epoch(1)).expect("read").any());
    assert_eq!(
        snap.budget_accruing(epoch(0)).expect("read"),
        Some(joined.accrual().total)
    );
    drop(snap);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.bond_record(&p).expect("read"), None);
    assert!(snap.bond_records().expect("read").is_empty());
    assert_eq!(snap.budget_accruing(epoch(0)).expect("read"), before);
    drop(snap);
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------------------- phase 9c

/// On a sixteen-block schedule block 31 closes epoch 1 — the first epoch
/// the persona who joined at height 5, in epoch 0, may serve (CEN-J5), and
/// so the first close with a credit in it: the credit for epoch 1 is
/// listed at height 18, inside the epoch and past its seal block (what
/// CEN-J7 will require; E6 slice C). The close's `r_market` (the credited
/// shard), `Σwork` and `budget` land as the verdict computed them, and the
/// accruing row is **removed** rather than left as a second copy of the
/// budget. The pop restores the accruing row to the block-30 post-image
/// and clears the three close rows; the re-connect closes again,
/// identically. *Records-was:* until E6 slice 8 row 3 this closed epoch 0
/// at block 15 over a credit for epoch 0 listed beside its join — a credit
/// the C++ refuses twice over (no record before the block, CEN-J4; the
/// join's own epoch, CEN-J5).
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
    connect_one(&store, &mut hashes, vec![join], SHORT, None);
    const CREDIT_HEIGHT: u64 = SHORT_SEB + 2;
    const CLOSING_HEIGHT: u64 = 2 * SHORT_SEB - 1;
    for _ in (FIRST_SPEND_HEIGHT + 1)..CREDIT_HEIGHT {
        connect_empty(&store, &mut hashes, SHORT);
    }
    assert_eq!(hashes.len(), 18, "the next block is 18, the credit's");
    connect_one(&store, &mut hashes, vec![credit], SHORT, None);
    let mut accrued_through_30 = None;
    for _ in (CREDIT_HEIGHT + 1)..CLOSING_HEIGHT {
        accrued_through_30 = Some(connect_empty(&store, &mut hashes, SHORT).accrual().total);
    }
    let accrued_through_30 = accrued_through_30.expect("blocks 19..=30 connected");
    assert_eq!(hashes.len(), 31, "the next block is 31, the closing one");

    let closing = connect_one(&store, &mut hashes, Vec::new(), SHORT, None);
    let close = closing.close().expect("block 31 closes epoch 1");
    assert_eq!(close.epoch(), epoch(1));
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
    assert_eq!(snap.budget(epoch(1)).expect("read"), Some(close.budget()));
    assert_eq!(
        snap.sigma_work(epoch(1)).expect("read"),
        Some(close.sigma_work())
    );
    for (s, r) in &r_market {
        assert_eq!(snap.r_market(*s, epoch(1)).expect("read"), Some(*r));
    }
    assert_eq!(
        snap.budget_accruing(epoch(1)).expect("read"),
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
    assert_eq!(snap.budget(epoch(1)).expect("read"), None);
    assert_eq!(snap.sigma_work(epoch(1)).expect("read"), None);
    for (s, _) in &r_market {
        assert_eq!(snap.r_market(*s, epoch(1)).expect("read"), None);
    }
    assert_eq!(
        snap.budget_accruing(epoch(1)).expect("read"),
        Some(accrued_through_30),
        "the pop puts the block-30 accrual back"
    );
    drop(snap);

    hashes.pop();
    let again = connect_one(&store, &mut hashes, Vec::new(), SHORT, None);
    assert_eq!(again, closing, "the same block, the same verdict");
    let snap = store.begin_read().expect("read");
    assert_eq!(snap.budget(epoch(1)).expect("read"), Some(close.budget()));
    assert_eq!(
        snap.sigma_work(epoch(1)).expect("read"),
        Some(close.sigma_work())
    );
    assert_eq!(snap.budget_accruing(epoch(1)).expect("read"), None);
    drop(snap);
    drop(store);
    cleanup(&path);
}

// -------------------------------------------------------------- phase 5

/// The candidate's attestation witness is written at the block's height
/// (DRS-E4 §3.2 phase 5), once CEN-B4 has judged it: a block carrying one
/// reads back its bytes, a block without reads back `None`, and the pop
/// lifts the row with the block. The witness here is the canonical
/// zero-pass witness — the only one B4 admits against the fixtures' empty
/// root — so what is pinned is the write and the pop, not the judgement.
#[test]
fn the_attestation_witness_is_written_at_the_blocks_height_and_popped_with_it() {
    let path = tmp("aw-witness");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut hashes = Vec::new();
    connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    let bytes = BlockAttestationWitness { passes: Vec::new() }
        .to_canonical_bytes()
        .expect("zero passes is under the cap");
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
/// writing its record, and the file's provenance names the family — the
/// block is accepted, and the file is no longer parity evidence. The
/// credit behind that join, in the next block, is **refused at CEN-J4**
/// (E6 slice 8 row 3): the validator reads the record off the tables, not
/// the session's policy, and this session wrote none. So a `Bond`-stubbed
/// session cannot connect a serve credit at all, which is the honest
/// consequence — the stub is a measurement lever, and a credit it let
/// through would be SI-15 (`ServeCreditWithoutBond`) at the next read.
///
/// *Records-was:* until row 3 this test listed the credit in the **same
/// block** as the join and witnessed its row written behind a record the
/// session did not hold, with SI-15 at the read; the fold's in-block
/// sequencing admitted the pair. The rule refuted that arrangement
/// (`connect_fixtures::credited`); SI-15's read witness is
/// `archival_read_tests`' own.
#[test]
fn a_stubbed_family_is_skipped_and_widens_the_files_provenance() {
    let path = tmp("aw-arw9");
    let policy = ApplyPolicy::stubbed(&[ArchivalFamily::Bond]).expect("non-empty");
    let store = ChainStore::with_apply_policy(&path, policy, EPOCH).expect("create");
    let p = persona(P);
    let [join, credit] = credited(13, P);
    let listing: Vec<Vec<Transaction>> = (0..FIRST_SPEND_HEIGHT)
        .map(|_| Vec::new())
        .chain(core::iter::once(vec![join]))
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
    drop(snap);
    let provenance = store.provenance();
    assert!(provenance.stubbed().contains(ArchivalFamily::Bond));
    assert!(!provenance.is_parity_evidence());

    // The credit, one block above the join it names: J4 reads the table
    // the policy skipped.
    let height = FIRST_SPEND_HEIGHT + 1;
    let credit = anchor(&hashes, height, credit);
    let previous = *hashes.last().expect("a chain");
    let out: Result<Verdict<()>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height)?;
        let cand = candidate_over(root, height, previous, vec![credit]);
        Ok(verdict_under(&view, cand, &RuleSet::GENESIS)?)
    });
    assert_refused(
        out.expect("judging only reads"),
        CenRow::J4,
        Locus::Input {
            slot: TxSlot::Listed(0),
            input: 0,
        },
    );
    let snap = store.begin_read().expect("read");
    assert!(
        snap.open_table(ARCHIVAL_SERVE_CREDIT)
            .expect("table")
            .get(ServeCreditKey::new(p, shard(0), epoch(1), BlockHeight::from_raw(height)).key())
            .expect("get")
            .is_none(),
        "nothing reached the writer"
    );
    drop(snap);
    drop(store);
    cleanup(&path);
}

// ------------------------------------------------ CEN-J23 over a record

/// A claim for the open epoch by a persona whose record the store
/// **holds** — inserted by an earlier block, read back through the batch
/// view — is refused at CEN-J23 on the transaction: the open epoch has no
/// frozen close to gather, whatever the record says. Until E6 slice 8
/// row 9 this claim passed every rule and met the fold's `NotSettled` arm
/// at CEN-L7 on the emission's vin; that arm is now the backstop beneath
/// J23's read, reached only if the two disagreed. The rules crate's driver
/// reaches a persisted record only through a block the same run
/// connected; over one read back from the store it is the store's to
/// witness, through the batch view.
#[test]
fn a_claim_on_the_open_epoch_over_a_persisted_record_is_refused_at_j23() {
    let path = tmp("aw-claim-open");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut hashes = Vec::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    }
    // The join is built from the tag `[0xc1; 32]`; `emission_vin(0xc1, …)`
    // claims as the same persona, whose id is `fixture::claimant(0xc1)`.
    connect_one(
        &store,
        &mut hashes,
        vec![fixture::join_market(fixture::point(14), [0xc1; 32])],
        RuleSet::GENESIS,
        None,
    );
    assert!(
        store
            .begin_read()
            .expect("read")
            .bond_record(&PCanonicalId::from_bytes(fixture::claimant(0xc1)))
            .expect("read")
            .is_some(),
        "the record is persisted before the claim is judged"
    );
    // Through the genesis coinbase's maturity, so the tree the claim
    // references has a leaf and a depth (CEN-J21 below): a coinbase's
    // outputs enter the tree at `height + mined_money_unlock_window`, and
    // the reference sits `REFERENCE_BLOCK_MIN_AGE` below the claim's block.
    for _ in 0..=RuleSet::GENESIS.mined_money_unlock_window().to_raw() {
        connect_empty(&store, &mut hashes, RuleSet::GENESIS);
    }

    let height = u64::try_from(hashes.len()).expect("fits");
    let open = RuleSet::GENESIS
        .settlement_schedule()
        .epoch_at(BlockHeight::from_raw(height))
        .to_raw();
    let Input::ArchivalRewardEmission { canonical_bytes } = fixture::emission_vin(0xc1, &[open])
    else {
        unreachable!("emission_vin builds an emission input");
    };
    let mut claim = fixture::balanced_emission(fixture::point(15), canonical_bytes, 1_000_000);
    // CEN-J21 (E6 slice 8 row 9) judges the declared depth against the
    // tree's at the reference before J23 reads the claim. The harness's
    // shape declares `0`, the mock's empty tree; here the tree holds the
    // genesis coinbase's leaf at the reference, so its depth there is at
    // least `1` — the smallest depth J21 admits.
    if let shekyl_wire::Ct::Fcmp {
        prunable: Some(p), ..
    } = &mut claim.ct
    {
        p.tree_depth = 1;
    }
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
        CenRow::J23,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    drop(store);
    cleanup(&path);
}
