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

use std::collections::BTreeSet;

use shekyl_chain_rules::harness::{assert_refused, fixture};
use shekyl_chain_rules::{
    form, validate, ArchivalDelta, AtHeight, BlockDrawsFloor, Candidate, CenRow, Corrupt,
    DrawCountFault, FakechainSchedule, Fault, FormAttempt, HeaderView, Locus, RecordWriteKind,
    ReferenceClaims, ReleaseAnchors, RuleSet, Trust, TxSlot, Verdict,
};
use shekyl_types::archival::{
    AttestationWitness, BlockDraws, IndexedDraw, IssuedDigest, IssuedDraw,
};
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_wire::Input;

use shekyl_archival_retention::{draw_count, draw_horizon};
use shekyl_harness_spender::Persona;
use shekyl_store_codec::Canonical;

use super::connect_fixtures::{
    anchor, batch_root_going_into, body, candidate_over, connect_chain, credited, expected_seed,
    expected_target, priced, spendable_prefix, FixtureSubstrate, Grown, Listed, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::view::BatchView;
use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{SettlementEpochBlocks, SigmaWorkMilli};
use crate::ids::ServeCreditKey;
use crate::schema::ARCHIVAL_SERVE_CREDIT;
use shekyl_chain_rules::EpochFloor;

/// The slot of the persona every join here opens a record for
/// ([`Persona::at`]; each test has its own store).
const P_SLOT: u32 = 11;

/// The id the persona at `slot` is recorded under — the recompute over
/// its derived identity key (CEN-J11).
fn persona(slot: u32) -> PCanonicalId {
    Persona::at(slot).id()
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

/// A settlement epoch just long enough to hold the first admissible spend
/// height, so a chain a few blocks past it closes an epoch with a record
/// and a credit in it: the join sits at [`FIRST_SPEND_HEIGHT`], in epoch
/// 0 — the premise the harness credit is built on ([`credited`] credits
/// epoch 1, "a fixture join is in epoch 0") — and
/// [`CLOSING_HEIGHT`] closes epoch 1, the first the persona may be
/// credited for (CEN-J5). Before the spend height was derived from
/// coinbase maturity it sat at 5 and this epoch was sixteen blocks.
const SHORT_SEB: u64 = FIRST_SPEND_HEIGHT + 14;
/// The epoch the join is listed in: epoch 0, by the epoch's length.
const JOIN_EPOCH: u64 = FIRST_SPEND_HEIGHT / SHORT_SEB;
const _: () = assert!(
    JOIN_EPOCH == 0,
    "the harness credit is for a join in epoch 0"
);
/// The first epoch the persona may serve: not the join's own (CEN-J5).
const CREDIT_EPOCH: u64 = JOIN_EPOCH + 1;
/// The credit is listed in its epoch's third block — inside the epoch and
/// past its seal block (what CEN-J7 will require; E6 slice C).
const CREDIT_HEIGHT: u64 = CREDIT_EPOCH * SHORT_SEB + 2;
/// The credited epoch's last block, the one that closes it.
const CLOSING_HEIGHT: u64 = (CREDIT_EPOCH + 1) * SHORT_SEB - 1;
const _: () = assert!(FIRST_SPEND_HEIGHT < CREDIT_HEIGHT && CREDIT_HEIGHT < CLOSING_HEIGHT);
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

/// Judge and connect one block at the chain's next height, listing
/// `listed` realised on it ([`Grown::realise`]: joins built, bodies
/// anchored), under `rules`; the block goes onto `grown` as judged, and
/// the verdict's archival delta — what the writer was handed — comes back
/// for the assertions to read against. Genesis is endowed, as
/// [`connect_chain`] endows it, so the coinbase a join funds its bond from
/// pays.
fn connect_one(
    store: &ChainStore,
    grown: &mut Grown,
    listed: &[Listed],
    rules: RuleSet,
) -> ArchivalDelta {
    let out: Result<ArchivalDelta, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let txs = grown.realise(listed);
        let judged = grown.judge_listing(&view, &rules, &txs)?;
        let delta = judged.block().archival().clone();
        batch.connect(judged, rules)?;
        Ok(delta)
    });
    out.expect("the block connects")
}

/// `connect_one` for a coinbase-only block.
fn connect_empty(store: &ChainStore, grown: &mut Grown, rules: RuleSet) -> ArchivalDelta {
    connect_one(store, grown, &[], rules)
}

/// [`super::connect_fixtures::judge_under`] that hands the **verdict** back instead of panicking on
/// a refusal — either stage's, since `form` verifies the proofs and
/// signatures (2026-10-16) — for the one test here whose block is meant
/// not to connect. The verdict is read through the rules crate's own
/// `assert_refused`, the idiom every rule test uses; the store names no
/// verdict type (`check_store_error_conversion_ban.py` clause 2).
fn verdict_under<'b, 'id>(
    view: &BatchView<'b, 'id>,
    candidate: Candidate,
    rules: &RuleSet,
) -> Result<Verdict<()>, StoreError> {
    let candidate = priced(view, candidate)?;
    let connecting = BlockHeight::from_raw(view.tip()?.map_or(0, |tip| tip.height.to_raw() + 1));
    let references = ReferenceClaims::from_headers(view, connecting, &candidate)?;
    let formed = match form(
        candidate,
        rules,
        &FixtureSubstrate,
        expected_seed(view)?,
        expected_target(view, rules)?,
        &references,
        FormAttempt::FIRST,
    ) {
        Ok(Ok(formed)) => formed,
        Ok(Err(refused)) => return Ok(Err(refused)),
        Err(never) => match never {},
    };
    match validate(formed, view, rules, &Trust::UNANCHORED) {
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
    let mut grown = Grown::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut grown, RuleSet::GENESIS);
    }
    let p = persona(P_SLOT);
    let before = store
        .begin_read()
        .expect("read")
        .budget_accruing(epoch(0))
        .expect("read");
    assert!(before.is_some(), "the coinbase-only blocks accrued");

    let (join, credit) = credited(P_SLOT);
    let joined = connect_one(&store, &mut grown, &[join], RuleSet::GENESIS);
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

    let credited_delta = connect_one(&store, &mut grown, &[body(credit)], RuleSet::GENESIS);
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

/// On the `SHORT` schedule `CLOSING_HEIGHT` closes `CREDIT_EPOCH` — the
/// first epoch the persona who joined at `FIRST_SPEND_HEIGHT`, in
/// `JOIN_EPOCH`, may serve (CEN-J5). SI-21's two write sets, a block
/// apart in kind and an epoch apart in time: the close freezes `budget`
/// and **removes** the accruing row; the epoch's `r_market` and `Σwork`
/// are the slash pass's, written an epoch later with the settlement rows
/// they are folded over (`SO-D11`). Between the two the epoch has a
/// budget and no `Σwork`. The pop restores the accruing row to the
/// post-image of the block below the close, takes the budget back and
/// takes the earlier epoch's gather the same block wrote; the re-connect
/// writes them again, identically.
#[test]
fn a_close_freezes_the_budget_and_the_slash_pass_an_epoch_later_gathers() {
    let path = tmp("aw-close");
    let store = short_store(&path);
    let mut grown = Grown::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut grown, SHORT);
    }
    let p = persona(P_SLOT);
    let (join, credit) = credited(P_SLOT);
    connect_one(&store, &mut grown, &[join], SHORT);
    for _ in (FIRST_SPEND_HEIGHT + 1)..CREDIT_HEIGHT {
        connect_empty(&store, &mut grown, SHORT);
    }
    assert_eq!(
        grown.height().to_raw(),
        CREDIT_HEIGHT,
        "the next block is {CREDIT_HEIGHT}, the credit's"
    );
    connect_one(&store, &mut grown, &[body(credit)], SHORT);
    let mut accrued_before_close = None;
    for _ in (CREDIT_HEIGHT + 1)..CLOSING_HEIGHT {
        accrued_before_close = Some(connect_empty(&store, &mut grown, SHORT).accrual().total);
    }
    let accrued_before_close =
        accrued_before_close.expect("the blocks between the credit and the close connected");
    assert_eq!(
        grown.height().to_raw(),
        CLOSING_HEIGHT,
        "the next block is {CLOSING_HEIGHT}, the closing one"
    );

    let closing = connect_one(&store, &mut grown, &[], SHORT);
    let close = *closing
        .close()
        .unwrap_or_else(|| panic!("block {CLOSING_HEIGHT} closes epoch {CREDIT_EPOCH}"));
    assert_eq!(close.epoch(), epoch(CREDIT_EPOCH));
    assert_eq!(
        closing.accrual().total,
        close.budget(),
        "the close's budget is the open epoch's accrual through this block"
    );
    // The same block runs the slash pass of the epoch before, and that
    // pass is what gathers (`SO-D11`): one gather, for `CREDIT_EPOCH − 1`.
    let earlier = epoch(CREDIT_EPOCH - 1);
    assert_eq!(
        closing
            .gathers()
            .iter()
            .map(shekyl_chain_rules::EpochGather::epoch)
            .collect::<Vec<_>>(),
        [earlier]
    );
    let zero = SigmaWorkMilli::from_raw(0);
    assert_eq!(closing.gathers()[0].sigma_work(), zero);

    // The state between an epoch's close and its slash pass: a budget and
    // no denominator.
    let between = |store: &ChainStore| {
        let snap = store.begin_read().expect("read");
        assert_eq!(
            snap.budget(epoch(CREDIT_EPOCH), EpochFloor::NONE)
                .expect("read"),
            Some(close.budget())
        );
        assert_eq!(
            snap.sigma_work(epoch(CREDIT_EPOCH), EpochFloor::NONE)
                .expect("read"),
            None,
            "the closed epoch has no Σwork until its slash pass"
        );
        assert_eq!(
            snap.sigma_work(earlier, EpochFloor::NONE).expect("read"),
            Some(zero)
        );
        assert_eq!(
            snap.budget_accruing(epoch(CREDIT_EPOCH)).expect("read"),
            None,
            "ARW-Q3: the accruing row is removed at the close"
        );
        assert!(
            snap.bond_record(&p).expect("read").is_some(),
            "the record outlives the close"
        );
    };
    between(&store);

    pop(&store);
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.budget(epoch(CREDIT_EPOCH), EpochFloor::NONE)
            .expect("read"),
        None
    );
    assert_eq!(
        snap.sigma_work(earlier, EpochFloor::NONE).expect("read"),
        None,
        "the pop takes the gather the block wrote with it"
    );
    assert_eq!(
        snap.budget_accruing(epoch(CREDIT_EPOCH)).expect("read"),
        Some(accrued_before_close),
        "the pop puts the accrual of the block below the close back"
    );
    drop(snap);

    grown.pop();
    let again = connect_one(&store, &mut grown, &[], SHORT);
    assert_eq!(again, closing, "the same block, the same verdict");
    between(&store);

    // One epoch on, the pass of `CREDIT_EPOCH` gathers it. The persona's
    // serve credit is a pass row, not a Served settlement row — no draw
    // was issued — so it is credited nothing (`SO-D11a`), and the epoch's
    // Σwork is a written zero a claim can cite.
    let mut last = None;
    for _ in 0..SHORT_SEB {
        last = Some(connect_empty(&store, &mut grown, SHORT));
    }
    let settling = last.expect("an epoch of blocks");
    assert_eq!(
        settling
            .gathers()
            .iter()
            .map(|g| (g.epoch(), g.sigma_work()))
            .collect::<Vec<_>>(),
        [(epoch(CREDIT_EPOCH), zero)]
    );
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.sigma_work(epoch(CREDIT_EPOCH), EpochFloor::NONE)
            .expect("read"),
        Some(zero)
    );
    assert!(
        snap.served_at(&p, &BTreeSet::from([epoch(CREDIT_EPOCH)]), EpochFloor::NONE)
            .expect("read")
            .is_empty(),
        "no draw was issued, so no shard is Served"
    );
    for (s, r) in settling.gathers()[0].r_market() {
        assert_eq!(
            snap.r_market(*s, epoch(CREDIT_EPOCH), EpochFloor::NONE)
                .expect("read"),
            Some(*r)
        );
    }
    drop(snap);
    drop(store);
    cleanup(&path);
}

// -------------------------------------------------------------- phase 5

/// The attestation witness row has one persisted form per block (DRS-E4
/// §3.2 phase 5): the empty set is `None` on the candidate and **no row**
/// — `Recorded(None)` at the height, `AboveTip` once the block is popped
/// — and the only other spelling of the empty set, an eight-byte zero
/// count on the sidecar, is refused at CEN-B4 (`Locus::Block`) before the
/// writer is handed anything, so no node records a present-but-empty row
/// for a block its peers record none for. A present row needs a genuine
/// non-empty witness, which no block can carry until CEN-I20's coinbase
/// grammar admits the `0x0B` field (`CHAIN_RULES_SLICE_8.md` §5.1, row 10
/// finding); the write itself is the FFI's and the rules crate's to
/// witness until then.
#[test]
fn the_empty_attestation_set_is_no_row_and_a_zero_count_sidecar_is_refused() {
    let path = tmp("aw-witness");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut grown = Grown::new();
    connect_empty(&store, &mut grown, RuleSet::GENESIS);
    connect_empty(&store, &mut grown, RuleSet::GENESIS);

    let snap = store.begin_read().expect("read");
    for h in 0..2 {
        assert_eq!(
            snap.attestation_witness_at(BlockHeight::from_raw(h))
                .expect("read"),
            AtHeight::Recorded(None)
        );
    }
    drop(snap);

    // The zero-count sidecar on the block that would connect at height 2.
    let zero_count = AttestationWitness::new(0u64.to_le_bytes().to_vec())
        .expect("eight bytes: non-empty, under the cap");
    let height = grown.height().to_raw();
    let previous = grown.tip();
    let out: Result<Verdict<()>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height)?;
        let cand = candidate_over(root, height, previous, Vec::new())
            .with_attestation_witness(Some(zero_count));
        Ok(verdict_under(&view, cand, &RuleSet::GENESIS)?)
    });
    assert_refused(out.expect("judging only reads"), CenRow::B4, Locus::Block);

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
    let p = persona(P_SLOT);

    let empty = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, p, shard(3), epoch(0))
        .unwrap_err();
    assert!(
        matches!(empty, StoreError::Cannot(StoreCannot::ChainEmpty)),
        "{empty:?}"
    );

    let mut grown = Grown::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut grown, RuleSet::GENESIS);
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
        &mut grown,
        &[Listed::Join { slot: P_SLOT }],
        RuleSet::GENESIS,
    );
    let tip = BlockHeight::from_raw(FIRST_SPEND_HEIGHT);

    let anchored = Trust::full(ReleaseAnchors::for_tests(Some(grown.hashes[0]), &[]));
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
    connect_empty(&store, &mut grown, RuleSet::GENESIS);
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
    let mut grown = Grown::new();
    connect_empty(&store, &mut grown, RuleSet::GENESIS);
    let err = store
        .regtest_inject_serve_credit(Trust::UNANCHORED, persona(0x1f), shard(0), epoch(0))
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
    let p = persona(P_SLOT);
    let (join, credit) = credited(P_SLOT);
    let listing = spendable_prefix(vec![vec![join]]);
    let grown = connect_chain(&store, &listing);
    assert_eq!(grown.height().to_raw(), FIRST_SPEND_HEIGHT + 1);

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
    let credit = anchor(&grown.hashes, BlockHeight::from_raw(height), credit);
    let previous = grown.tip();
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

// ------------------------------------------------ CEN-J26 before a record

/// A claim for the open epoch by a persona whose record the store
/// **holds** — inserted by an earlier block, read back through the batch
/// view — carrying the fixture's filler fee proof. *Was* CEN-J23's refusal
/// on the transaction (the open epoch has no frozen close to gather,
/// whatever the record says; until E6 slice 8 row 9 it met the fold's
/// `NotSettled` arm at CEN-L7 instead). Since 2026-10-16 the fee proof is
/// verified in `form` against the claimed reference root
/// (`CHAIN_RULES_CRATE.md` §4.6), ahead of every view-bound row, so a
/// claim wrong in its proof and in its epoch is **CEN-J26's**, and the
/// persisted record is never read. J23's refusal over a persisted record
/// with a proof that verifies is the ingest driver's, whose claims are
/// real (`scenario_emission_tests`, the pass-block claim).
#[test]
fn a_claim_with_a_filler_fee_proof_is_refused_at_j26_before_the_persisted_record_is_read() {
    let path = tmp("aw-claim-open");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let mut grown = Grown::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut grown, RuleSet::GENESIS);
    }
    // The join is the persona at `P_SLOT`'s; the claim below names its
    // identity key (`emission_vin_for`), so it claims as the same persona,
    // whose id the record is under.
    let claimant = Persona::at(P_SLOT);
    connect_one(
        &store,
        &mut grown,
        &[Listed::Join { slot: P_SLOT }],
        RuleSet::GENESIS,
    );
    assert!(
        store
            .begin_read()
            .expect("read")
            .bond_record(&claimant.id())
            .expect("read")
            .is_some(),
        "the record is persisted before the claim is judged"
    );
    // Through the genesis coinbase's maturity, so the tree the claim
    // references has a leaf and a depth (CEN-J21 below): a coinbase's
    // outputs enter the tree at `height + mined_money_unlock_window`, and
    // the reference sits `REFERENCE_BLOCK_MIN_AGE` below the claim's block.
    for _ in 0..=RuleSet::GENESIS.mined_money_unlock_window().to_raw() {
        connect_empty(&store, &mut grown, RuleSet::GENESIS);
    }

    let height = grown.height().to_raw();
    let open = RuleSet::GENESIS
        .settlement_schedule()
        .epoch_at(BlockHeight::from_raw(height))
        .to_raw();
    let Input::ArchivalRewardEmission { canonical_bytes } =
        fixture::emission_vin_for(claimant.identity(), &[open])
    else {
        unreachable!("emission_vin_for builds an emission input");
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
    // Anchored as every listed body is, then keyed and signed as the
    // claimant's own: the fixture signer keys an emission slot from the
    // identity seed of the fixture persona the vin names, and this
    // claimant is the spender's, so its slot is the persona's identity
    // (CEN-J20) under its own signature.
    let claim = fixture::signed_claiming(
        anchor(&grown.hashes, BlockHeight::from_raw(height), claim),
        &fixture::Claimant {
            identity: claimant.identity(),
            sign: &|hash| claimant.identity_signature(hash),
        },
    );
    let previous = grown.tip();
    let out: Result<Verdict<()>, TestErr> = store.write(|batch| {
        let view = batch.chain_view();
        let root = batch_root_going_into(&view, height)?;
        let cand = candidate_over(root, height, previous, vec![claim]);
        Ok(verdict_under(&view, cand, &RuleSet::GENESIS)?)
    });
    assert_refused(
        out.expect("judging only reads"),
        CenRow::J26,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    drop(store);
    cleanup(&path);
}

/// The draw-issue door (`SO-D10f`) beside the credit injector: Fakechain
/// only, bonded personas only, a draw issued once, and the digest the
/// caller folded stored as given. Not journaled, like the credit.
#[test]
fn the_draw_issue_opens_only_unanchored_for_a_bonded_persona_and_adds_each_draw_once() {
    let path = tmp("aw-issue-draws");
    let store = ChainStore::create(&path, EPOCH).expect("create");
    let p = persona(P_SLOT);
    let draw = |j: u32, passed: bool| IndexedDraw {
        persona: p,
        shard: shard(3),
        issuing_height: BlockHeight::from_raw(FIRST_SPEND_HEIGHT),
        draw: j,
        state: IssuedDraw {
            revealed_at: BlockHeight::from_raw(FIRST_SPEND_HEIGHT + 1),
            passed,
        },
    };
    let digest = IssuedDigest::from_bytes([0x5a; 32]);

    let mut grown = Grown::new();
    for _ in 0..FIRST_SPEND_HEIGHT {
        connect_empty(&store, &mut grown, RuleSet::GENESIS);
    }
    let stranger = store
        .regtest_issue_draws(Trust::UNANCHORED, epoch(0), &[draw(0, false)], digest)
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
        &mut grown,
        &[Listed::Join { slot: P_SLOT }],
        RuleSet::GENESIS,
    );
    let anchored = Trust::full(ReleaseAnchors::for_tests(Some(grown.hashes[0]), &[]));
    let off = store
        .regtest_issue_draws(anchored, epoch(0), &[draw(0, false)], digest)
        .unwrap_err();
    assert!(
        matches!(off, StoreError::Cannot(StoreCannot::InjectionOffFakechain)),
        "{off:?}"
    );
    let read = |e: u64| {
        let snap = store.begin_read().expect("read");
        (
            snap.issued_draws(epoch(e), EpochFloor::NONE).expect("read"),
            snap.issued_digest(epoch(e), EpochFloor::NONE)
                .expect("read"),
        )
    };
    assert_eq!(
        read(0),
        (vec![], IssuedDigest::ZERO),
        "a refused issue writes nothing"
    );

    store
        .regtest_issue_draws(
            Trust::UNANCHORED,
            epoch(0),
            &[draw(1, true), draw(0, false)],
            digest,
        )
        .expect("Fakechain, a record held, draws not yet issued");
    assert_eq!(
        read(0),
        (vec![draw(0, false), draw(1, true)], digest),
        "both draws in index order, the digest as given"
    );
    assert_eq!(
        read(1),
        (vec![], IssuedDigest::ZERO),
        "another epoch is untouched"
    );

    // A draw the index holds is not issued again, and the refused batch
    // writes nothing: not the fresh draw listed before it, not the digest.
    let again = store
        .regtest_issue_draws(
            Trust::UNANCHORED,
            epoch(0),
            &[draw(2, false), draw(1, false)],
            IssuedDigest::ZERO,
        )
        .unwrap_err();
    assert!(
        matches!(
            again,
            StoreError::Cannot(StoreCannot::DrawAlreadyIssued { persona }) if persona == p
        ),
        "{again:?}"
    );
    assert_eq!(read(0), (vec![draw(0, false), draw(1, true)], digest));

    // Not journaled: a block above the draws, popped, leaves them.
    connect_empty(&store, &mut grown, RuleSet::GENESIS);
    pop(&store);
    assert_eq!(read(0), (vec![draw(0, false), draw(1, true)], digest));
    cleanup(&path);
}

fn draws_of(store: &ChainStore, height: u64, floor: BlockDrawsFloor) -> Option<BlockDraws> {
    store
        .begin_read()
        .expect("read")
        .block_draws(BlockHeight::from_raw(height), floor)
        .expect("the floor admits the read")
}

/// A windowless schedule writes a zero row at every height, including the
/// opening block. The boundary of `B` retires below `(B − 1)·SEB`, and a
/// pop does not put a retired row back. Red edit: skip the row, or retire
/// it through the undo log.
#[test]
fn a_windowless_schedule_writes_a_zero_row_that_the_boundary_retires() {
    let path = tmp("windowless_draws");
    let rules = RuleSet::fakechain(None, pair(2, 1));
    let store = ChainStore::with_horizons(
        &path,
        ApplyPolicy::Full,
        Horizons::new(
            rules.settlement_schedule().blocks(),
            BlockCount::from_raw(1),
            BlockCount::from_raw(1),
        )
        .expect("the cap is inside the epoch"),
    )
    .expect("create");
    let mut grown = Grown::new();
    let zero = BlockDraws {
        count: 0,
        carry: 0,
        shortfall: 0,
        issued_short: 0,
        revealed: false,
    };
    for height in 0u64..=3 {
        let delta = connect_empty(&store, &mut grown, rules);
        assert_eq!(delta.draws(), zero);
        assert_eq!(draws_of(&store, height, BlockDrawsFloor::NONE), Some(zero));
    }
    pop(&store);
    grown.pop();
    assert_eq!(draws_of(&store, 3, BlockDrawsFloor::NONE), None);
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);

    // Height 4 is the boundary of B = 2. Rows strictly below `(2 − 1)·2` go.
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);
    assert_eq!(draws_of(&store, 0, BlockDrawsFloor::NONE), None);
    assert_eq!(draws_of(&store, 1, BlockDrawsFloor::NONE), None);
    assert_eq!(draws_of(&store, 2, BlockDrawsFloor::NONE), Some(zero));
    assert_eq!(draws_of(&store, 4, BlockDrawsFloor::NONE), Some(zero));

    let floor = BlockDrawsFloor::retired_by(2, rules.settlement_schedule());
    let refused = store
        .begin_read()
        .expect("read")
        .block_draws(BlockHeight::ZERO, floor)
        .unwrap_err();
    assert!(
        matches!(
            refused,
            StoreError::InvariantViolated(StoreInvariant::BlockDrawsReadBelowFloor {
                asked,
                floor: kept
            }) if asked == BlockHeight::ZERO && kept == floor.height().expect("a floor")
        ),
        "{refused:?}"
    );

    pop(&store);
    grown.pop();
    assert_eq!(draws_of(&store, 0, BlockDrawsFloor::NONE), None);
    assert_eq!(draws_of(&store, 4, BlockDrawsFloor::NONE), None);
    let delta = connect_empty(&store, &mut grown, rules);
    assert_eq!(delta.draws(), zero);
    assert_eq!(draws_of(&store, 0, BlockDrawsFloor::NONE), None);
    cleanup(&path);
}

fn plant_draws(path: &std::path::Path, height: u64, row: BlockDraws) {
    super::archival_read_tests::plant(path, |txn| {
        let mut table = txn
            .open_table(crate::schema::ARCHIVAL_BLOCK_DRAWS)
            .expect("the draw table");
        table
            .insert(height, row.encoded().as_encoded())
            .expect("overwrite");
    });
}

/// The count of `h + 1` reads the row at `h`, and an opening block starts
/// from zero even when the row before it carries a shortfall. `|D|` is
/// empty on this chain, so the count is zero and the carry is the prior's.
/// Red edit: recompute from the row the writer just stored, or carry the
/// shortfall across `h_open`.
#[test]
fn the_count_reads_the_prior_row_and_resets_at_the_opening_block() {
    let path = tmp("draw_count_order");
    let rules = RuleSet::fakechain(None, pair(20, 1));
    let horizons = Horizons::new(
        rules.settlement_schedule().blocks(),
        BlockCount::from_raw(4),
        BlockCount::from_raw(1),
    )
    .expect("the cap is inside the epoch");
    let mut grown = Grown::new();
    {
        let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("create");
        connect_empty(&store, &mut grown, rules);
    }
    let planted = BlockDraws {
        count: 4,
        carry: 0x11,
        shortfall: 1000,
        issued_short: 250,
        revealed: false,
    };
    plant_draws(&path, 0, planted);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("reopen");
    let delta = connect_empty(&store, &mut grown, rules);
    let window = rules
        .settlement_schedule()
        .challenge_response_blocks()
        .expect("20 blocks has a window of 1")
        .get();
    let (count, carry) = draw_count(0, 750, draw_horizon(1, 20, window), 20, planted.carry)
        .expect("the horizon fits");
    assert_eq!(delta.draws().shortfall, 750);
    assert_eq!(delta.draws().carry, carry);
    assert_eq!(u64::from(delta.draws().count), count);
    assert_eq!(delta.draws().issued_short, 0);
    assert!(!delta.draws().revealed);
    assert_eq!(draws_of(&store, 0, BlockDrawsFloor::NONE), Some(planted));

    for _ in 2..=19 {
        connect_empty(&store, &mut grown, rules);
    }
    drop(store);
    let across = BlockDraws {
        count: 9,
        carry: 5,
        shortfall: 999,
        issued_short: 0,
        revealed: false,
    };
    plant_draws(&path, 19, across);
    let store = ChainStore::with_horizons(&path, ApplyPolicy::Full, horizons).expect("reopen");
    let open = connect_empty(&store, &mut grown, rules);
    assert_eq!(
        open.draws(),
        BlockDraws {
            count: 0,
            carry: 0,
            shortfall: 0,
            issued_short: 0,
            revealed: false,
        },
        "an opening block does not inherit the shortfall"
    );
    assert_eq!(draws_of(&store, 19, BlockDrawsFloor::NONE), Some(across));
    cleanup(&path);
}

/// SI-33's two count arms, through `refuse_corrupt` as the ingest would
/// hand them on. A missing prior row, and a reduction larger than the
/// stored shortfall. Red edit: clamp the reduction, or treat a missing
/// row as a zero.
#[test]
fn a_count_fault_halts_the_writer_through_refuse_corrupt() {
    let rules = RuleSet::fakechain(None, pair(20, 1));
    let horizons = Horizons::new(
        rules.settlement_schedule().blocks(),
        BlockCount::from_raw(4),
        BlockCount::from_raw(1),
    )
    .expect("the cap is inside the epoch");

    let excess = tmp("draw_count_excess");
    {
        let store =
            ChainStore::with_horizons(&excess, ApplyPolicy::Full, horizons).expect("create");
        let mut grown = Grown::new();
        connect_empty(&store, &mut grown, rules);
        drop(store);
        plant_draws(
            &excess,
            0,
            BlockDraws {
                count: 0,
                carry: 0,
                shortfall: 0,
                issued_short: 1,
                revealed: false,
            },
        );
        let store =
            ChainStore::with_horizons(&excess, ApplyPolicy::Full, horizons).expect("reopen");
        let out: Result<(), TestErr> = store.write(|batch| {
            let view = batch.chain_view();
            let Err(corrupt) = grown.judge_empty_or_corrupt(&view, &rules)? else {
                panic!("the count accepted a reduction past the shortfall");
            };
            assert_eq!(
                corrupt,
                Corrupt::DrawCount {
                    height: BlockHeight::from_raw(1),
                    why: DrawCountFault::IssuedExceedsShortfall {
                        issued: 1,
                        shortfall: 0,
                    },
                }
            );
            Err(batch.refuse_corrupt(corrupt).into())
        });
        let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
            panic!("aborted, not refused");
        };
        assert!(
            refused.contains("issued 1 against a shortfall of 0"),
            "{refused}"
        );
    }
    cleanup(&excess);

    let missing = tmp("draw_count_missing");
    let store = ChainStore::with_horizons(&missing, ApplyPolicy::Full, horizons).expect("create");
    let mut grown = Grown::new();
    connect_empty(&store, &mut grown, rules);
    let out: Result<(), TestErr> = store.write(|batch| {
        batch
            .open_remove_table(
                crate::schema::ARCHIVAL_BLOCK_DRAWS,
                StoreInvariant::TipMismatch,
            )?
            .remove(0)?;
        let view = batch.chain_view();
        let Err(corrupt) = grown.judge_empty_or_corrupt(&view, &rules)? else {
            panic!("the count accepted a height whose prior row is gone");
        };
        assert_eq!(
            corrupt,
            Corrupt::DrawCount {
                height: BlockHeight::from_raw(1),
                why: DrawCountFault::MissingPrior {
                    prior: BlockHeight::ZERO,
                },
            }
        );
        Err(batch.refuse_corrupt(corrupt).into())
    });
    let TestErr::Store(refused) = out.expect_err("the batch is refused") else {
        panic!("aborted, not refused");
    };
    assert!(
        refused.contains("no draw row is recorded at height 0"),
        "{refused}"
    );
    cleanup(&missing);
}
