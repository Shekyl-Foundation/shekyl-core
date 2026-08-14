// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the P-scan accrual (`engine/pscan/accrual.rs`).
//!
//! Wired as a `#[path]` child of `accrual::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;
use shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS;
use shekyl_engine_state::pscan_state::MintLineageOutput;

use crate::engine::pscan::reconcile::ReconcileVerdict;
use crate::engine::pscan::scan_step::{BlockRange, EpochInflowDelta, ScanStepResult};

/// A funding-only scan-step result over `[start, end)` carrying `deltas`.
fn step(start: u64, end: u64, deltas: &[(u64, u64)]) -> ScanStepResult {
    ScanStepResult {
        watched_personas: Vec::new(),
        spent_funding: Vec::new(),
        range: BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
            .expect("range"),
        funding: deltas
            .iter()
            .map(|&(e, a)| EpochInflowDelta {
                epoch: SettlementEpoch::from_raw(e),
                amount: AtomicUnits::from_raw(a),
            })
            .collect(),
        bond_post_matches: Vec::new(),
        funding_outputs: Vec::new(),
    }
}

/// A minimal held-funding record for the arm-#1 prune tests (identity
/// fields only; the prune keys on `gindex`).
fn funding_match(gindex: u64, height: u64) -> FundingOutputMatch {
    FundingOutputMatch {
        p_slot: shekyl_types::PSlot::from_raw(0),
        index_in_transaction: 0,
        gindex: shekyl_types::GlobalOutputIndex::from_raw(gindex),
        output_key: [0u8; 32],
        commitment: [0u8; 32],
        ciphertext_x25519: [0u8; 32],
        ciphertext_ml_kem: Vec::new(),
        amount: AtomicUnits::from_raw(1),
        height: BlockHeight::from_raw(height),
        epoch: SettlementEpoch::from_raw(settlement_epoch_at_height(height)),
        lineage: shekyl_engine_state::pscan_state::MintLineageOutput::ExternalTransfer,
        spendable_height: BlockHeight::from_raw(height),
    }
}

/// SP-R0 arm #1: prune-at-ingest removes spent records after the extend —
/// a discover-then-spend within one step nets to no record — and the
/// DQ-F fire counter advances by exactly the number of removed records.
#[test]
fn ingest_prunes_spent_funding_and_counts_the_fire() {
    use crate::engine::pscan::scan_step::SpentFundingMatch;
    let mut acc = PScanAccrual::genesis();

    // Step 1: discover gindex 7.
    let mut r1 = step(0, 10, &[]);
    r1.funding_outputs.push(funding_match(7, 5));
    acc.ingest(&r1, &VerifiedBatch::for_test(0, 10, [0x01; 32]))
        .expect("ingest 1");
    assert_eq!(acc.funding_outputs().len(), 1);
    assert_eq!(acc.spent_pruned_total(), 0, "nothing spent yet");

    // Step 2: its spend is observed — record pruned, counter fires.
    let mut r2 = step(10, 20, &[]);
    r2.spent_funding.push(SpentFundingMatch {
        gindex: shekyl_types::GlobalOutputIndex::from_raw(7),
    });
    acc.ingest(&r2, &VerifiedBatch::for_test(10, 20, [0x02; 32]))
        .expect("ingest 2");
    assert!(acc.funding_outputs().is_empty(), "spent record pruned");
    assert_eq!(acc.spent_pruned_total(), 1, "the fire counter advanced");

    // Step 3: discover-then-spend within one step — extend-then-retain
    // nets to no record; the counter still counts the real prune.
    let mut r3 = step(20, 30, &[]);
    r3.funding_outputs.push(funding_match(9, 22));
    r3.spent_funding.push(SpentFundingMatch {
        gindex: shekyl_types::GlobalOutputIndex::from_raw(9),
    });
    acc.ingest(&r3, &VerifiedBatch::for_test(20, 30, [0x03; 32]))
        .expect("ingest 3");
    assert!(
        acc.funding_outputs().is_empty(),
        "in-step spend nets to nothing"
    );
    assert_eq!(acc.spent_pruned_total(), 2);
}

/// SP-R0 arm #2: `retire_persona` is one atomic in-memory mutation —
/// the persona's matches + pending entry leave together with the
/// retired-record append — idempotent on re-fire, and round-trips the seal.
/// Per the funded-gate invariant the retiring slot is already drained (the
/// actor returns `SkippedFunded` for a funded slot), so a *different*,
/// still-live slot's funding is untouched by the retire.
#[test]
fn retire_persona_prunes_atomically_and_round_trips() {
    use shekyl_types::{PCanonicalId, PSlot};
    let id = PCanonicalId::from_bytes([7; 32]);
    let other = PCanonicalId::from_bytes([8; 32]);
    let mut acc = PScanAccrual::genesis();
    let mut r1 = step(0, 10, &[]);
    // A live slot-0 funding output belonging to a persona that is NOT
    // retiring here — it must survive the retire of the drained slot below.
    r1.funding_outputs.push(funding_match(3, 5)); // slot 0 (funding_match pins p_slot 0)
    r1.bond_post_matches.push(BondPostMatch {
        height: BlockHeight::from_raw(4),
        p_canonical_id: id,
        post_kind: 0,
    });
    r1.bond_post_matches.push(BondPostMatch {
        height: BlockHeight::from_raw(6),
        p_canonical_id: other,
        post_kind: 0,
    });
    acc.ingest(&r1, &VerifiedBatch::for_test(0, 10, [0x01; 32]))
        .expect("ingest");
    // seed the pending trigger the retire consumes
    acc.record_pending_unbond_for_test(id, SettlementEpoch::from_raw(0));

    // Retire `id` at a DRAINED slot (slot 5 holds no funding) — the
    // funded-gate invariant the caller upholds.
    assert!(acc.retire_persona(
        id,
        PSlot::from_raw(5),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(30),
    ));
    assert!(acc
        .bond_post_matches()
        .iter()
        .all(|m| m.p_canonical_id != id));
    assert!(
        acc.bond_post_matches()
            .iter()
            .any(|m| m.p_canonical_id == other),
        "other personas' history untouched"
    );
    assert_eq!(
        acc.funding_outputs().len(),
        1,
        "a live slot's funding is untouched by another slot's retire"
    );
    assert!(!acc.pending_unbonds().contains_key(&id));
    assert_eq!(acc.retired_records().len(), 1);
    assert_eq!(acc.retired_pruned_total(), 1);

    // Idempotent on re-fire (the O(log n) index short-circuits before any
    // mutation or the funded-gate assert).
    assert!(!acc.retire_persona(
        id,
        PSlot::from_raw(5),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(31),
    ));
    assert_eq!(acc.retired_records().len(), 1);
    assert_eq!(acc.retired_pruned_total(), 1);

    // Round-trips the seal.
    let back = PScanAccrual::from_state(&acc.to_state());
    assert_eq!(back.retired_records(), acc.retired_records());
    assert!(!back.pending_unbonds().contains_key(&id));
}

fn epoch(e: u64) -> SettlementEpoch {
    SettlementEpoch::from_raw(e)
}

const SEB: u64 = SETTLEMENT_EPOCH_BLOCKS;

fn match_post(height: u64, id: u8, kind: u8) -> BondPostMatch {
    BondPostMatch {
        height: BlockHeight::from_raw(height),
        p_canonical_id: PCanonicalId::from_bytes([id; 32]),
        post_kind: kind,
    }
}

/// A scan step over `[start, end)` carrying `matches` (no funding). The
/// step's watch union is the matched personas — a real sweep can only
/// match a persona it watches.
fn match_step(start: u64, end: u64, matches: Vec<BondPostMatch>) -> ScanStepResult {
    let watched_personas = matches.iter().map(|m| m.p_canonical_id).collect();
    ScanStepResult {
        watched_personas,
        spent_funding: Vec::new(),
        range: BlockRange::new(BlockHeight::from_raw(start), BlockHeight::from_raw(end))
            .expect("range"),
        funding: Vec::new(),
        bond_post_matches: matches,
        funding_outputs: Vec::new(),
    }
}

#[test]
fn accumulates_matches_and_builds_a_reconcile_set_over_the_verified_covered() {
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &match_step(0, 5, vec![match_post(2, 0xAA, 0)]),
        &VerifiedBatch::for_test(0, 5, [0x01; 32]),
    )
    .expect("batch 1");
    acc.ingest(
        &match_step(5, 9, vec![match_post(6, 0xBB, 2)]),
        &VerifiedBatch::for_test(5, 9, [0x02; 32]),
    )
    .expect("batch 2");

    let set = acc.reconcile_set();
    // `covered` is the cumulative [0, 9) the verified batches advanced it to.
    assert_eq!(set.covered().low(), BlockHeight::from_raw(0));
    assert_eq!(set.covered().high(), BlockHeight::from_raw(9));
    assert_eq!(set.matches().len(), 2);
    assert_eq!(
        set.reconcile(
            PCanonicalId::from_bytes([0xAA; 32]),
            BlockHeight::from_raw(2)
        ),
        ReconcileVerdict::Present {
            height: BlockHeight::from_raw(2),
            post_kind: 0,
        }
    );
    // A persona this scan never WATCHED cannot be read as absent — the
    // provenance gate returns unknown (its match rows could not exist).
    // The watched-but-unmatched → absent case is pinned in the
    // reconcile-type tests.
    assert_eq!(
        set.reconcile(
            PCanonicalId::from_bytes([0xEE; 32]),
            BlockHeight::from_raw(3)
        ),
        ReconcileVerdict::OutsideCovered
    );
}

#[test]
fn ingest_refuses_a_verified_batch_that_does_not_meet_the_frontier() {
    // The structural guard: `covered` only grows behind a `VerifiedBatch` that
    // *contiguously meets* the frontier. A verified range that skips it is refused
    // (FrontierGap) rather than recording a `covered` with an unverified hole — so a
    // future fast-forward can't widen the verified frontier without verification.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(&step(0, 5, &[]), &VerifiedBatch::for_test(0, 5, [0u8; 32]))
        .expect("batch 1");
    let err = acc
        .ingest(&step(5, 9, &[]), &VerifiedBatch::for_test(6, 9, [0u8; 32]))
        .expect_err("a verified range that skips the frontier must be refused");
    assert!(
        matches!(err, AccrualError::FrontierGap { .. }),
        "got {err:?}"
    );
    assert_eq!(
        acc.next_height(),
        BlockHeight::from_raw(5),
        "the frontier did not advance over the refused batch"
    );
    assert_eq!(
        acc.reconcile_set().covered().high(),
        BlockHeight::from_raw(5),
        "covered did not widen over the refused batch"
    );
}

#[test]
fn matches_and_covered_round_trip_through_to_state_from_state() {
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &match_step(0, 7, vec![match_post(3, 0xAA, 0), match_post(5, 0xBB, 2)]),
        &VerifiedBatch::for_test(0, 7, [0x42; 32]),
    )
    .expect("ingest");
    let back = PScanAccrual::from_state(&acc.to_state());
    assert_eq!(
            back, acc,
            "matches + covered survive the seal round-trip (covered reconstructed from the sealed frontier)"
        );
    assert_eq!(
        back.reconcile_set().covered().high(),
        BlockHeight::from_raw(7)
    );
    assert_eq!(back.reconcile_set().matches().len(), 2);
}

#[test]
fn bond_post_match_debug_is_redacted() {
    let rendered = format!("{:?}", match_post(123_456, 0xAB, 2));
    assert!(
        rendered.contains("redacted"),
        "Debug must redact persona history: {rendered}"
    );
    assert!(
        !rendered.contains("123456") && !rendered.contains("171"),
        "neither the height nor the id byte may appear: {rendered}"
    );
}

#[test]
fn ingest_accumulates_across_steps_and_advances_the_frontier() {
    // Two steps within epoch 0, then a step finishing it.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, 4_000, &[(0, 100)]),
        &VerifiedBatch::for_test(0, 4_000, [0u8; 32]),
    )
    .expect("step1");
    acc.ingest(
        &step(4_000, SEB, &[(0, 50)]),
        &VerifiedBatch::for_test(4_000, SEB, [0u8; 32]),
    )
    .expect("step2");
    assert_eq!(acc.next_height(), BlockHeight::from_raw(SEB));
    // Epoch 0 is now finalized (close == SEB <= frontier) → 100 + 50.
    let inflow = acc.finalized_inflow(epoch(0)).expect("epoch 0 finalized");
    assert_eq!(inflow.epoch(), epoch(0));
    assert_eq!(inflow.atomic(), AtomicUnits::from_raw(150));
}

#[test]
fn finalized_inflow_refuses_an_in_progress_epoch() {
    // Frontier mid epoch 0 ⇒ epoch 0's accrual is partial ⇒ no PFundingInflow.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, 4_000, &[(0, 100)]),
        &VerifiedBatch::for_test(0, 4_000, [0u8; 32]),
    )
    .expect("partial");
    assert!(
        acc.finalized_inflow(epoch(0)).is_none(),
        "an in-progress epoch must not yield a (partial) PFundingInflow"
    );
}

#[test]
fn finalized_empty_epoch_is_a_real_zero_distinct_from_unfinalized() {
    // Scan past epoch 0 with nothing of ours in it.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, SEB, &[(1, 5)]),
        &VerifiedBatch::for_test(0, SEB, [0u8; 32]),
    )
    .expect("ingest");
    // Epoch 0 finalized with no funding → Some(ZERO); epoch 1 in progress → None.
    assert_eq!(
        acc.finalized_inflow(epoch(0))
            .expect("epoch 0 finalized")
            .atomic(),
        AtomicUnits::ZERO
    );
    assert!(
        acc.finalized_inflow(epoch(1)).is_none(),
        "epoch 1 in progress"
    );
}

#[test]
fn resume_from_a_sealed_state_continues_without_double_count() {
    // Scan a partial epoch 0, seal, "crash" (snapshot → reload), then finish it.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, 6_000, &[(0, 50)]),
        &VerifiedBatch::for_test(0, 6_000, [0u8; 32]),
    )
    .expect("step1");
    let sealed = acc.to_state();

    let mut resumed = PScanAccrual::from_state(&sealed);
    assert_eq!(resumed.next_height(), BlockHeight::from_raw(6_000));
    // Still partial after reload — the guard holds across a crash.
    assert!(resumed.finalized_inflow(epoch(0)).is_none());

    // Continue from the frontier to the epoch boundary — same epoch accrues.
    resumed
        .ingest(
            &step(6_000, SEB, &[(0, 25)]),
            &VerifiedBatch::for_test(6_000, SEB, [0u8; 32]),
        )
        .expect("step2");
    assert_eq!(
        resumed
            .finalized_inflow(epoch(0))
            .expect("finalized")
            .atomic(),
        AtomicUnits::from_raw(75),
        "resume must continue the accrual, not double-count or drop it"
    );
}

#[test]
fn rejects_a_non_contiguous_step() {
    let mut acc = PScanAccrual::genesis(); // frontier = 0
    let err = acc
        .ingest(
            &step(5, 6, &[(0, 1)]),
            &VerifiedBatch::for_test(5, 6, [0u8; 32]),
        )
        .expect_err("a gap must fail closed");
    assert_eq!(
        err,
        AccrualError::NonContiguous {
            frontier: BlockHeight::from_raw(0),
            step_start: BlockHeight::from_raw(5),
        }
    );
}

#[test]
fn accrual_overflow_fails_closed() {
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, 1, &[(0, u64::MAX)]),
        &VerifiedBatch::for_test(0, 1, [0u8; 32]),
    )
    .expect("near-max");
    let err = acc
        .ingest(
            &step(1, 2, &[(0, 1)]),
            &VerifiedBatch::for_test(1, 2, [0u8; 32]),
        )
        .expect_err("overflow must fail closed");
    assert_eq!(err, AccrualError::InflowOverflow { epoch: epoch(0) });
}

#[test]
fn ingest_overflow_is_a_no_op_so_a_retry_cannot_double_count() {
    // Epoch 0 seeded near the ceiling; the frontier sits at height 1.
    let mut acc = PScanAccrual::genesis();
    acc.ingest(
        &step(0, 1, &[(0, u64::MAX)]),
        &VerifiedBatch::for_test(0, 1, [0x11; 32]),
    )
    .expect("seed epoch 0 near max");

    // A batch whose deltas would partially apply under a naive loop: a benign
    // epoch-1 delta lands first, then an epoch-0 delta overflows. With atomic
    // ingest the whole batch is rejected and `self` is untouched.
    let err = acc
        .ingest(
            &step(1, 2, &[(1, 5), (0, 1)]),
            &VerifiedBatch::for_test(1, 2, [0x22; 32]),
        )
        .expect_err("the overflowing delta must reject the batch");
    assert_eq!(err, AccrualError::InflowOverflow { epoch: epoch(0) });

    // No partial mutation: the benign epoch-1 delta did NOT survive, the frontier
    // did not advance, and the anchor was not changed — so the sweep's retry of
    // [1, 2) re-ingests from a clean state instead of double-counting.
    let sealed = acc.to_state();
    assert_eq!(
        sealed.accrual_for(epoch(1)),
        AtomicUnits::ZERO,
        "the benign delta from the failed batch must not have been applied"
    );
    assert_eq!(
        sealed.accrual_for(epoch(0)),
        AtomicUnits::from_raw(u64::MAX),
        "epoch 0 is unchanged by the rejected batch"
    );
    assert_eq!(
        acc.next_height(),
        BlockHeight::from_raw(1),
        "the frontier did not advance over the rejected batch"
    );
    assert_eq!(
        acc.frontier_hash(),
        [0x11; 32],
        "the verified-frontier anchor was not changed by the rejected batch"
    );
}

#[test]
fn to_state_then_from_state_round_trips() {
    let mut acc = PScanAccrual::genesis();
    // A non-zero frontier hash so the round-trip exercises the verified-frontier
    // anchor, not just the height.
    acc.ingest(
        &step(0, 10, &[(0, 7), (2, 9)]),
        &VerifiedBatch::for_test(0, 10, [0x42; 32]),
    )
    .expect("ingest");
    acc.record_unbond(PCanonicalId::from_bytes([0x11; 32]), epoch(0));
    assert_eq!(acc.frontier_hash(), [0x42; 32]);
    let back = PScanAccrual::from_state(&acc.to_state());
    assert_eq!(
        back, acc,
        "the in-memory accrual (incl. frontier hash + pending unbonds) mirrors the persisted state"
    );
    assert_eq!(
        back.frontier_hash(),
        [0x42; 32],
        "the verified-frontier anchor round-trips through the seal"
    );
}

/// WI-2 D-A1: per-output funding records accumulate through `ingest` and
/// survive the `to_state` → `from_state` seal round-trip unchanged (the
/// funding-selection substrate is durable).
#[test]
fn funding_outputs_accumulate_and_round_trip_through_the_seal() {
    let record = FundingOutputMatch {
        p_slot: shekyl_types::PSlot::from_raw(3),
        index_in_transaction: 1,
        gindex: shekyl_types::GlobalOutputIndex::from_raw(42),
        output_key: [0xBB; 32],
        commitment: [0xCC; 32],
        ciphertext_x25519: [0xDD; 32],
        ciphertext_ml_kem: vec![0xEE; 4],
        amount: AtomicUnits::from_raw(500),
        height: BlockHeight::from_raw(5),
        epoch: epoch(0),
        lineage: MintLineageOutput::ExternalTransfer,
        spendable_height: shekyl_engine_state::transfer::eligible_height(
            BlockHeight::from_raw(5),
            shekyl_types::Timelock::None,
        ),
    };
    let mut acc = PScanAccrual::genesis();
    let mut step = step(0, 10, &[(0, 500)]);
    step.funding_outputs = vec![record.clone()];
    acc.ingest(&step, &VerifiedBatch::for_test(0, 10, [0x42; 32]))
        .expect("ingest");
    assert_eq!(acc.funding_outputs(), std::slice::from_ref(&record));

    let back = PScanAccrual::from_state(&acc.to_state());
    assert_eq!(
        back.funding_outputs(),
        &[record],
        "the funding-selection substrate survives the seal round-trip"
    );
    assert_eq!(back, acc);
}

#[test]
fn settled_epoch_excludes_the_in_progress_frontier_epoch() {
    let mut acc = PScanAccrual::genesis();
    assert_eq!(acc.settled_epoch(), None, "no epoch closed yet");
    // Edge case (the retire-boundary off-by-one): frontier EXACTLY on the epoch-2
    // boundary (`2·SEB`) — epoch 1 fully scanned, epoch 2 not yet started. The
    // just-completed epoch is settled; the empty in-progress epoch is not. Guards
    // against a cursor-shape change silently shifting the boundary by one.
    acc.ingest(
        &step(0, 2 * SEB, &[]),
        &VerifiedBatch::for_test(0, 2 * SEB, [0u8; 32]),
    )
    .expect("to edge");
    assert_eq!(
        acc.settled_epoch(),
        Some(epoch(1)),
        "on the epoch boundary, the just-completed epoch settles, not the in-progress one"
    );
    // Frontier mid epoch 2 (2·SEB + 1): still epochs 0,1 settled; epoch 2 in progress.
    acc.ingest(
        &step(2 * SEB, 2 * SEB + 1, &[]),
        &VerifiedBatch::for_test(2 * SEB, 2 * SEB + 1, [0u8; 32]),
    )
    .expect("past edge");
    assert_eq!(
        acc.settled_epoch(),
        Some(epoch(1)),
        "the latest settled epoch is the one before the in-progress frontier epoch"
    );
}

#[test]
fn record_unbond_is_idempotent_and_durable() {
    let id = PCanonicalId::from_bytes([0xAB; 32]);
    let mut acc = PScanAccrual::genesis();
    acc.record_unbond(id, epoch(5));
    // Re-seeing the same persona keeps the first recorded epoch.
    acc.record_unbond(id, epoch(9));
    assert_eq!(acc.pending_unbonds().get(&id), Some(&epoch(5)));

    // It survives a seal + reload (the durable retire-trigger).
    let back = PScanAccrual::from_state(&acc.to_state());
    assert_eq!(back.pending_unbonds().get(&id), Some(&epoch(5)));
}
