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

use shekyl_chain_rules::harness::{assert_refused, fixture};
use shekyl_chain_rules::{
    validate, ArchivalDelta, AtHeight, Candidate, CenRow, FakechainSchedule, Fault, Locus,
    RecordWriteKind, ReleaseAnchors, RuleSet, Trust, TxSlot, Verdict,
};
use shekyl_types::archival::AttestationWitness;
use shekyl_types::{BlockCount, BlockHeight, PCanonicalId, SettlementEpoch, ShardId};
use shekyl_wire::Input;

use shekyl_harness_spender::Persona;

use super::connect_fixtures::{
    anchor, batch_root_going_into, body, candidate_over, connect_chain, credited, formed_under,
    priced, spendable_prefix, Grown, Listed, FIRST_SPEND_HEIGHT,
};
use super::store_tests::{cleanup, tmp, TestErr, EPOCH};
use super::view::BatchView;
use super::*;
use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::SettlementEpochBlocks;
use crate::ids::ServeCreditKey;
use crate::schema::ARCHIVAL_SERVE_CREDIT;

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

/// On the `SHORT` schedule `CLOSING_HEIGHT` closes `CREDIT_EPOCH` —
/// the first epoch the persona who joined at `FIRST_SPEND_HEIGHT`, in
/// `JOIN_EPOCH`, may serve (CEN-J5), and so the first close with a credit
/// in it: the credit for that epoch is listed at `CREDIT_HEIGHT`, inside
/// the epoch and past its seal block. The close's `r_market` (the credited
/// shard), `Σwork` and `budget` land as the verdict computed them, and the
/// accruing row is **removed** rather than left as a second copy of the
/// budget. The pop restores the accruing row to the post-image of the
/// block below the close and clears the three close rows; the re-connect closes again,
/// identically. *Records-was:* until E6 slice 8 row 3 this closed epoch 0
/// at block 15 over a credit for epoch 0 listed beside its join — a credit
/// the C++ refuses twice over (no record before the block, CEN-J4; the
/// join's own epoch, CEN-J5).
#[test]
fn a_close_freezes_the_verdicts_figures_removes_the_accruing_row_and_pops_back() {
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
    let close = closing
        .close()
        .unwrap_or_else(|| panic!("block {CLOSING_HEIGHT} closes epoch {CREDIT_EPOCH}"));
    assert_eq!(close.epoch(), epoch(CREDIT_EPOCH));
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
    assert_eq!(
        snap.budget(epoch(CREDIT_EPOCH)).expect("read"),
        Some(close.budget())
    );
    assert_eq!(
        snap.sigma_work(epoch(CREDIT_EPOCH)).expect("read"),
        Some(close.sigma_work())
    );
    for (s, r) in &r_market {
        assert_eq!(
            snap.r_market(*s, epoch(CREDIT_EPOCH)).expect("read"),
            Some(*r)
        );
    }
    assert_eq!(
        snap.budget_accruing(epoch(CREDIT_EPOCH)).expect("read"),
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
    assert_eq!(snap.budget(epoch(CREDIT_EPOCH)).expect("read"), None);
    assert_eq!(snap.sigma_work(epoch(CREDIT_EPOCH)).expect("read"), None);
    for (s, _) in &r_market {
        assert_eq!(snap.r_market(*s, epoch(CREDIT_EPOCH)).expect("read"), None);
    }
    assert_eq!(
        snap.budget_accruing(epoch(CREDIT_EPOCH)).expect("read"),
        Some(accrued_before_close),
        "the pop puts the accrual of the block below the close back"
    );
    drop(snap);

    grown.pop();
    let again = connect_one(&store, &mut grown, &[], SHORT);
    assert_eq!(again, closing, "the same block, the same verdict");
    let snap = store.begin_read().expect("read");
    assert_eq!(
        snap.budget(epoch(CREDIT_EPOCH)).expect("read"),
        Some(close.budget())
    );
    assert_eq!(
        snap.sigma_work(epoch(CREDIT_EPOCH)).expect("read"),
        Some(close.sigma_work())
    );
    assert_eq!(
        snap.budget_accruing(epoch(CREDIT_EPOCH)).expect("read"),
        None
    );
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
    let credit = anchor(&grown.hashes, height, credit);
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
        anchor(&grown.hashes, height, claim),
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
        CenRow::J23,
        Locus::Tx {
            slot: TxSlot::Listed(0),
        },
    );
    drop(store);
    cleanup(&path);
}
