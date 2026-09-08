// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the emission-claim assembly workflow
//! (`engine/emission_claim.rs`).
//!
//! Wired as a `#[path]` child of `emission_claim::tests`, so
//! `use super::*` and `super::test_fixtures` resolve into the workflow
//! module and private items stay testable; the sibling file exists so
//! the decomposition ratchet counts the workflow file, not its test
//! suite (the `proofs_tests.rs` pattern).

use super::test_fixtures::{
    resigma, snapshot, source_at_count, source_with, zero_share_snapshot, BUDGET, SHARD_A, SHARD_B,
};
use super::*;
use crate::engine::emission_source::EpochSnapshot;
use shekyl_archival_retention::ShardSet;
use shekyl_types::ChainCount;

use shekyl_archival_retention::{
    as_of_e_served_work, bond_wire::MAX_HOLDINGS_SHARDS, claimed_epochs_check_and_set,
    credited_work_milli, reward_share_floor, settlement_epoch_at_height, ClaimedEpochsError,
    CreditPair, EpochCloseInputs, EpochCloseShard, EMISSION_KAT_SHAPE, MAX_CLAIM_AGE_W,
    SETTLEMENT_EPOCH_BLOCKS,
};

/// Disable the §4 value gate for tests whose subject is elsewhere
/// (sizing, ordering, self-check): no candidate Σ is below zero.
const NO_FLOOR: u64 = 0;

/// The derivation's structural checks in one grid: boundary verdicts
/// come from the read-only predicates (each skip reason at its exact
/// boundary), share positivity is the claimability predicate, and the
/// selected epochs are the survivors in window order.
///
/// Coverage boundary (50-testing.mdc): the share equalities below
/// bite against **recompute-chain determinism and
/// builder-consumes-verify-functions** — builder and test call the
/// same chain, so they do NOT cover that the assembled claim
/// verifies. That is the step-7 differential's job
/// ([`self_check_accepts_assembled_and_refuses_every_mutation`]),
/// which drives the landed verifier over the assembled vin.
#[test]
fn boundary_verdicts_and_share_positivity_select_the_batch() {
    // settled = W + 10 puts the expiry floor at 10 (a real bottom
    // boundary, not saturated-to-zero).
    let settled = MAX_CLAIM_AGE_W + 10;
    let floor = settled - MAX_CLAIM_AGE_W;
    let source = source_with(
        settled,
        vec![20],
        vec![
            snapshot(floor - 1),            // expired (one below the floor)
            snapshot(floor),                // claimable (the floor itself)
            snapshot(20),                   // already claimed
            zero_share_snapshot(25, true),  // zero share (gated cause)
            zero_share_snapshot(26, false), // zero share (no-credit cause)
            snapshot(settled - 1),          // claimable (youngest settled)
            snapshot(settled),              // not settled (== settled)
        ],
    );
    let derived = derive_claimable_epochs(&source).expect("two epochs claimable");

    let selected: Vec<u64> = derived
        .claimable
        .iter()
        .map(|c| c.settlement_epoch)
        .collect();
    assert_eq!(selected, vec![floor, settled - 1]);
    assert_eq!(
        derived.skipped,
        vec![
            (floor - 1, EpochSkip::WindowExpired),
            (20, EpochSkip::AlreadyClaimed),
            (25, EpochSkip::ZeroShare),
            (26, EpochSkip::ZeroShare),
            (settled, EpochSkip::NotSettled),
        ],
        "each boundary must map to its read-only-predicate verdict; the \
         two zero causes must be indistinguishable (cause-blind)"
    );

    // Share positivity is the wire-positivity predicate: every
    // selected reward is strictly positive (encodable) and byte-exact
    // against verify's step-4/5 recompute — composed here from the
    // literal chain (`as_of_e_served_work` → `credited_work_milli` →
    // `reward_share_floor`) so the shared evaluation head the
    // derivation consumes is pinned against the chain, not against
    // itself. The carried row is the admitting evaluation's.
    for c in &derived.claimable {
        assert!(c.reward > 0, "claimable ⇒ wire-encodable (> 0)");
        let snap = source
            .epochs
            .iter()
            .find(|s| s.settlement_epoch == c.settlement_epoch)
            .unwrap();
        let bonds = snap.bonds_view();
        let view = snap.source(&bonds);
        let served = as_of_e_served_work(&view.inputs).unwrap();
        let idx = view.claimant_bond_idx.unwrap();
        let credited = credited_work_milli(served.work_by_bond[idx], served.member[idx]);
        assert_eq!(
            c.reward,
            reward_share_floor(view.budget, credited, view.persisted_sigma_work_milli),
            "derivation reward must equal verify's recompute"
        );
        let entry_sum: u64 = c
            .claim
            .shard_entries
            .iter()
            .map(|e| u64::from(e.scarcity_micro))
            .sum();
        assert_eq!(
            entry_sum, served.work_micro_by_bond[idx],
            "the carried row must be the admitting evaluation's (micro-space)"
        );
    }
}

/// Drift tripwire for the read-only boundary predicates: the connect
/// mutator's classification must agree with the predicates the
/// derivation consumes ([`epoch_is_not_settled`] /
/// [`epoch_is_claim_expired`] / [`claimed_epochs_contains`]) at every
/// epoch across the window. If the connect predicate's boundaries
/// ever move, this differential fails before any consensus KAT does.
#[test]
fn read_only_predicates_agree_with_connect_mutator() {
    let settled = MAX_CLAIM_AGE_W + 10;
    let claimed = vec![15, 20, 30];
    for epoch in 0..=settled + 2 {
        let mut scratch = claimed.clone();
        let verdict = claimed_epochs_check_and_set(&mut scratch, epoch, settled);
        let expected = if epoch_is_not_settled(epoch, settled) {
            Err(ClaimedEpochsError::NotSettled)
        } else if epoch_is_claim_expired(epoch, settled) {
            Err(ClaimedEpochsError::Expired)
        } else if claimed_epochs_contains(&claimed, epoch) {
            Ok(false)
        } else {
            Ok(true)
        };
        assert_eq!(verdict, expected, "predicates diverged at epoch {epoch}");
    }
}

/// Verify step 2's join bound, applied at derivation: a record whose
/// join epoch is newer than the frozen rows' (retire-then-rejoin)
/// defers pre-join epochs ([`EpochSkip::BeforeJoin`]) instead of
/// assembling a batch the self-check — and the chain — would refuse
/// whole (`EpochBeforeJoin` ⇒ cause-blind `SelfCheckFailed`), blocking
/// the valid epochs behind it until the offender aged out.
#[test]
fn join_bound_defers_pre_join_epochs() {
    let epochs = || vec![snapshot(4), snapshot(5), snapshot(6)];

    // Rejoined at epoch 5: E ∈ {4, 5} predate/equal the record's join
    // (the frozen rows still carry the shape's original join).
    let mut rejoined = source_with(10, vec![], epochs());
    rejoined.bond.as_mut().unwrap().join_settlement_epoch = 5;
    let derived = derive_claimable_epochs(&rejoined).expect("epoch 6 claimable");
    let selected: Vec<u64> = derived
        .claimable
        .iter()
        .map(|c| c.settlement_epoch)
        .collect();
    assert_eq!(selected, vec![6]);
    assert_eq!(
        derived.skipped,
        vec![(4, EpochSkip::BeforeJoin), (5, EpochSkip::BeforeJoin)]
    );

    // Premise arm (the skip is load-bearing): the vin the builder
    // would have assembled without the join bound — built against the
    // pre-rejoin record, where all three epochs clear it — drives the
    // landed verifier to `EpochBeforeJoin` when self-checked against
    // the rejoined record, surfaced as the blind `SelfCheckFailed`.
    let pre_rejoin = source_with(10, vec![], epochs());
    let derived_pre = derive_claimable_epochs(&pre_rejoin).expect("all claimable");
    let assembled =
        assemble_claims(&derived_pre, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits");
    let vin = dummy_leg_vin(&assembled);
    self_check_claims(&pre_rejoin, &vin, assembled.total_reward)
        .expect("sanity: verifies against the pre-rejoin record");
    assert!(matches!(
        self_check_claims(&rejoined, &vin, assembled.total_reward),
        Err(EmissionClaimError::SelfCheckFailed)
    ));
}

/// Oldest-first 15-cap: with more claimable epochs than the batch
/// bound, exactly the oldest 15 are selected (nearest expiry — the
/// order that never strands a savable epoch) and the rest defer.
/// Epochs start at the shape's first post-join epoch (`E_join + 1`,
/// verify step 2's bound — the dedicated join KAT covers the skip).
#[test]
fn batch_caps_at_fifteen_oldest_first() {
    let settled = 20;
    let first = EMISSION_KAT_SHAPE.join_settlement_epoch + 1;
    let epochs: Vec<EpochSnapshot> = (first..=18).map(snapshot).collect();
    let source = source_with(settled, vec![], epochs);
    let derived = derive_claimable_epochs(&source).expect("claimable");

    let selected: Vec<u64> = derived
        .claimable
        .iter()
        .map(|c| c.settlement_epoch)
        .collect();
    let expected: Vec<u64> = (first..first + MAX_SETTLEMENT_EPOCHS_PER_EMISSION as u64).collect();
    assert_eq!(selected, expected, "oldest 15, window order");
    assert!(
        selected.windows(2).all(|w| w[0] < w[1]),
        "wire invariant: strictly increasing"
    );
    assert_eq!(
        derived.skipped,
        vec![
            (17, EpochSkip::BatchDeferred),
            (18, EpochSkip::BatchDeferred),
        ]
    );
}

/// Idle refusals: no bond record, an empty window, and an
/// all-skipped window each refuse `NoClaimableEpochs` — an idle
/// state, not an error, and cause-blind (no per-epoch payload).
#[test]
fn refuses_idle_when_nothing_claimable() {
    // No bond record.
    let mut source = source_with(10, vec![], vec![snapshot(5)]);
    source.bond = None;
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::NoClaimableEpochs)
    ));

    // Empty window.
    let source = source_with(10, vec![], vec![]);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::NoClaimableEpochs)
    ));

    // Every epoch skipped (zero share both causes + already claimed).
    let source = source_with(
        10,
        vec![5],
        vec![
            zero_share_snapshot(4, true),
            snapshot(5),
            zero_share_snapshot(6, false),
        ],
    );
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::NoClaimableEpochs)
    ));
}

/// The close-boundary count (module doc "Step 7"): at the one count
/// `chain_height == h_close(E)` the connect window admits `E` and
/// the budget row exists (the close ran while connecting `E`'s last
/// block — `blockchain_db.cpp` `add_block`), but verify's strict
/// step-1 predicate rejects a claim of `E` in the very next block.
/// The derivation defers `E` ([`EpochSkip::NotFinalized`]) so the
/// assembled batch verifies at the gather tip; one count later `E`
/// is claimable.
#[test]
fn close_boundary_count_defers_the_youngest_epoch_one_block() {
    let epoch = 5;
    let h_close = epoch_close_height(epoch).expect("fixture epoch closes");
    // Fixture-coherence premise: at the boundary count the connect
    // window already admits the epoch — the deferral below is doing
    // real work, not restating the top boundary's `NotSettled`.
    assert_eq!(settlement_epoch_at_height(h_close), epoch + 1);

    // At the boundary count: epoch 4 selected, epoch 5 defers.
    let at_boundary = source_at_count(h_close, vec![], vec![snapshot(4), snapshot(5)]);
    let derived = derive_claimable_epochs(&at_boundary).expect("epoch 4 claimable");
    let selected: Vec<u64> = derived
        .claimable
        .iter()
        .map(|c| c.settlement_epoch)
        .collect();
    assert_eq!(selected, vec![4]);
    assert_eq!(derived.skipped, vec![(5, EpochSkip::NotFinalized)]);

    // The deferred batch passes the self-check at the boundary count.
    let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits");
    self_check_claims(
        &at_boundary,
        &dummy_leg_vin(&assembled),
        assembled.total_reward,
    )
    .expect("the deferred batch must verify at the gather tip");

    // Premise arm (the deferral is load-bearing): an `E`-bearing vin
    // — assembled one count past the boundary, where `E` is
    // claimable — is exactly the vin the builder would have built at
    // the boundary count without the strict-finalization skip. The
    // real verifier refuses it there (`EpochNotFinalized`, surfaced
    // blind), so the skip is what stands between the builder and a
    // spurious whole-batch `SelfCheckFailed`.
    let past_boundary = source_at_count(h_close + 1, vec![], vec![snapshot(4), snapshot(5)]);
    let derived_past = derive_claimable_epochs(&past_boundary).expect("both claimable");
    let selected_past: Vec<u64> = derived_past
        .claimable
        .iter()
        .map(|c| c.settlement_epoch)
        .collect();
    assert_eq!(
        selected_past,
        vec![4, 5],
        "one count past the boundary the epoch is claimable"
    );
    let assembled_past =
        assemble_claims(&derived_past, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits");
    let e_bearing = dummy_leg_vin(&assembled_past);
    self_check_claims(&past_boundary, &e_bearing, assembled_past.total_reward)
        .expect("sanity: the E-bearing vin verifies one count past the boundary");
    assert!(
        matches!(
            self_check_claims(&at_boundary, &e_bearing, assembled_past.total_reward),
            Err(EmissionClaimError::SelfCheckFailed)
        ),
        "at the boundary count the same vin must refuse (verify: EpochNotFinalized)"
    );
}

/// A window epoch without a frozen close row skips (`NoCloseRow`,
/// mirroring the verify shim's reject) without poisoning the batch.
#[test]
fn missing_close_row_skips_the_epoch_only() {
    let mut no_row = snapshot(5);
    no_row.has_budget_row = false;
    let source = source_with(10, vec![], vec![no_row, snapshot(6)]);
    let derived = derive_claimable_epochs(&source).expect("epoch 6 claimable");
    assert_eq!(derived.claimable.len(), 1);
    assert_eq!(derived.claimable[0].settlement_epoch, 6);
    assert_eq!(derived.skipped, vec![(5, EpochSkip::NoCloseRow)]);
}

/// A window epoch with no close height at all (`(E+1)·SEB` overflows
/// u64) cannot come from an honest daemon — PR 1's decode invariant
/// pins `E < settlement_epoch_at_height(chain_height)` — so the
/// derivation refuses it loudly (`SourceInvalid`) instead of deferring
/// it as transiently `NotFinalized` (it can never finalize). Built
/// directly: a hostile source, unreachable through the decode path
/// (the module-doc conversion-guard idiom).
#[test]
fn overflowing_close_height_is_source_invalid() {
    let epoch = u64::MAX - 1;
    assert!(
        epoch_close_height(epoch).is_none(),
        "premise: the close height must not exist"
    );
    let snap = EpochSnapshot {
        settlement_epoch: epoch,
        close_block_height: 0,
        sigma_work_milli: 0,
        budget_atomic: BUDGET,
        has_budget_row: true,
        bonds: vec![],
        shards: vec![],
        credit_pairs: vec![],
        claimant_bond_idx: None,
    };
    let mut source = source_with(10, vec![], vec![snap]);
    // Hostile boundary operands that admit the epoch through the
    // window predicates (decode refuses this pair; the derivation
    // must still fail closed on it).
    source.current_settled_epoch = u64::MAX;
    source.chain_height = ChainCount::from_raw(u64::MAX);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::SourceInvalid { epoch: e }) if e == epoch
    ));
}

/// Internally inconsistent gather rows refuse loudly (untrusted
/// daemon), never skip-and-continue: a credit pair indexing outside
/// the arrays, and a claimant index outside the bond rows.
#[test]
fn malformed_gather_is_loud() {
    let mut bad_pair = snapshot(5);
    bad_pair.credit_pairs.push(CreditPair {
        bond_idx: 9,
        shard_idx: 0,
    });
    let source = source_with(10, vec![], vec![bad_pair]);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::SourceInvalid { epoch: 5 })
    ));

    let mut bad_claimant = snapshot(5);
    bad_claimant.claimant_bond_idx = Some(9);
    let source = source_with(10, vec![], vec![bad_claimant]);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::SourceInvalid { epoch: 5 })
    ));
}

// ── Steps 2 + 5: assembly ───────────────────────────────────────────

/// Canonical row form, integer-exact against verify's compares:
/// credited shards only (ascending `shard_id`, bit set), per-entry
/// scarcity equal to verify's `ScarcityMismatch` recompute (first-
/// position id resolution), entry sum equal to verify's
/// `WorkTotalMismatch` operand, rewards verbatim from the derivation,
/// and the holdings copied by value from the record.
#[test]
fn assembles_canonical_rows_rewards_and_holdings() {
    let mut snap = snapshot(5);
    let close = epoch_close_height(5).expect("fixture epoch closes");
    // Shard rows deliberately in descending id order (canonicality is
    // the builder's, not the daemon's); the claimant is credited on A
    // and B, the other bond alone on shard 11 (must not appear).
    snap.shards = vec![
        EpochCloseShard {
            shard_id: SHARD_B,
            has_segment: true,
            freeze_height: close - 8_000,
        },
        EpochCloseShard {
            shard_id: SHARD_A,
            has_segment: true,
            freeze_height: close - 5_000,
        },
        EpochCloseShard {
            shard_id: 11,
            has_segment: true,
            freeze_height: close - 2_000,
        },
    ];
    snap.credit_pairs = vec![
        CreditPair {
            bond_idx: 0,
            shard_idx: 1,
        },
        CreditPair {
            bond_idx: 0,
            shard_idx: 0,
        },
        CreditPair {
            bond_idx: 1,
            shard_idx: 2,
        },
    ];
    resigma(&mut snap);
    let source = source_with(10, vec![], vec![snap]);
    let derived = derive_claimable_epochs(&source).expect("claimable");
    let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits");

    assert_eq!(assembled.settlement_epochs, vec![5]);
    assert_eq!(
        assembled.reward_amount_plain,
        vec![derived.claimable[0].reward],
        "the builder never invents an amount — verbatim the derivation share"
    );
    assert_eq!(assembled.total_reward, derived.claimable[0].reward);
    assert!(assembled.size_deferred.is_empty());
    assert_eq!(
        assembled.holdings,
        source.bond.as_ref().unwrap().holdings,
        "by-value record copy (§5.3/§6.4.1), never recomputed"
    );

    let claim = &assembled.work_claim[0];
    assert_eq!(claim.epoch, 5);
    let ids: Vec<u64> = claim.shard_entries.iter().map(|e| e.shard_id).collect();
    assert_eq!(
        ids,
        vec![SHARD_A, SHARD_B],
        "credited shards only, ascending shard_id"
    );
    assert!(claim.shard_entries.iter().all(|e| e.serve_credit_bit));

    // Verify's step-4 compares, run over the same view.
    let snap = &source.epochs[0];
    let bonds = snap.bonds_view();
    let view = snap.source(&bonds);
    let served = as_of_e_served_work(&view.inputs).unwrap();
    let mut entry_sum = 0u64;
    for entry in &claim.shard_entries {
        let idx = view
            .inputs
            .shards
            .iter()
            .position(|s| s.shard_id == entry.shard_id)
            .unwrap();
        let expected = shard_contribution_micro(&view.inputs, &served.r_market_by_shard, idx);
        assert_eq!(
            u64::from(entry.scarcity_micro),
            expected,
            "verify's ScarcityMismatch compare (tolerance zero, micro)"
        );
        entry_sum += expected;
    }
    assert_eq!(
        entry_sum, served.work_micro_by_bond[0],
        "verify's WorkTotalMismatch compare (tolerance zero, micro-space)"
    );
}

/// The u64→u32 conversion guard bites **at the builder's conversion
/// site**, not the encoder's `ScarcityOverflow`. The production
/// decode path cannot reach it — `verify_view` pins
/// `age_weight_milli` to the compiled constant, bounding an honest
/// recompute to `WORK_MICRO_PER_MILLI · (WORK_MILLI_SCALE + weight)`
/// (const-asserted at module scope) — so the KAT builds the hostile view
/// directly and drives the same per-epoch row builder the derivation runs.
#[test]
fn scarcity_conversion_refuses_at_the_builder() {
    let bonds = [EpochCloseBond {
        join_settlement_epoch: 0,
        is_foundation_complete_tree: false,
        bad_intervals: &[],
    }];
    let shards = [EpochCloseShard {
        shard_id: SHARD_A,
        has_segment: true,
        freeze_height: 0,
    }];
    let pairs = [CreditPair {
        bond_idx: 0,
        shard_idx: 0,
    }];
    let view = EmissionEpochSource {
        inputs: EpochCloseInputs {
            settlement_epoch: 4,
            close_block_height: epoch_close_height(4).unwrap(),
            settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
            // Hostile: unreachable through `verify_view` (which pins the
            // weight to the compiled ~2000). Drives the micro recompute over
            // u32::MAX without overflowing the u128 quotient into
            // `mul_div_floor`'s 0-fallback: `g = 1000 + weight`, `r = 1`, so
            // `scarcity_micro = 1000·g ≈ 1.0×10¹⁰ ∈ (u32::MAX, u64::MAX]`.
            // (`u64::MAX` would overflow to 0 — no longer a hostile value.)
            age_weight_milli: 10_000_000,
            bonds: &bonds,
            shards: &shards,
            credit_pairs: &pairs,
        },
        persisted_sigma_work_milli: 1,
        claimant_bond_idx: Some(0),
        budget: BUDGET,
    };
    let served = as_of_e_served_work(&view.inputs).unwrap();
    // Premise armed: the recompute really exceeds the wire field.
    assert!(
        shard_contribution_micro(&view.inputs, &served.r_market_by_shard, 0) > u64::from(u32::MAX),
        "fixture must drive the recompute over u32::MAX"
    );
    assert!(matches!(
        work_epoch_claim(&view, &served, 0),
        Err(EmissionClaimError::ScarcityConversion {
            epoch: 4,
            shard_id: SHARD_A
        })
    ));
}

/// Bound-or-split at exact byte boundaries: at the projection the
/// batch fits; one byte under, the youngest epoch defers
/// (`size_deferred`) and the older two keep their claim; one byte
/// under a single epoch's floor, the terminal refusal fires with the
/// measured projection. The boundary lengths are measured through the
/// same construction site the assembly uses ([`claims_vin`] at the
/// structural maxima).
#[test]
fn size_bound_defers_youngest_then_refuses() {
    let source = source_with(10, vec![], vec![snapshot(3), snapshot(4), snapshot(5)]);
    let derived = derive_claimable_epochs(&source).expect("three claimable");

    let full =
        assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits default");
    assert_eq!(full.settlement_epochs, vec![3, 4, 5]);
    let max_len = |n: usize| {
        claims_vin(
            full.holdings.clone(),
            full.settlement_epochs[..n].to_vec(),
            full.work_claim[..n].to_vec(),
            full.reward_amount_plain[..n].to_vec(),
            MAX_BACKING_PROOF_BYTES,
            u8::MAX,
        )
        .serialize()
        .unwrap()
        .len()
    };
    let len3 = max_len(3);
    let len1 = max_len(1);

    let at = assemble_claims(&derived, len3, NO_FLOOR).expect("exactly at the bound");
    assert_eq!(at.settlement_epochs, vec![3, 4, 5]);
    assert!(at.size_deferred.is_empty());

    let under = assemble_claims(&derived, len3 - 1, NO_FLOOR).expect("splits");
    assert_eq!(under.settlement_epochs, vec![3, 4], "oldest retained");
    assert_eq!(under.size_deferred, vec![5]);
    assert_eq!(
        under.total_reward,
        under.reward_amount_plain.iter().sum::<u64>()
    );

    assert!(matches!(
        assemble_claims(&derived, len1 - 1, NO_FLOOR),
        Err(EmissionClaimError::SizeBoundExceeded {
            epoch: 3,
            projected,
            budget,
        }) if projected == len1 && budget == len1 - 1
    ));
}

/// The §4 value gate at its exact boundary (`ENGINE_CADENCE_DRIVER.md`
/// §4): Σreward at the floor assembles; one atomic unit under, the
/// whole set is held (`ValueDeferred` carries every `(epoch, reward)`
/// pair and the Σ), and the refusal fires **before** the size loop —
/// with an impossible byte budget alongside the failing floor, the
/// verdict is still `ValueDeferred`, pinning the gate order the
/// assembly doc claims. Same derived set + same floor ⇒ same verdict
/// both calls — the inclusion decision is policy-deterministic
/// (uniform across wallets), which is the §4 uniformity property as
/// distinct from submission *timing*.
#[test]
fn value_gate_holds_whole_set_below_floor_and_precedes_sizing() {
    let source = source_with(10, vec![], vec![snapshot(3), snapshot(4), snapshot(5)]);
    let derived = derive_claimable_epochs(&source).expect("three claimable");
    let total: u64 = derived.claimable.iter().map(|c| c.reward).sum();
    assert!(total > 0, "fixture must carry non-zero rewards");

    // At the floor: assembles (the floor is a minimum, not exceeded-by).
    let at = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, total).expect("at floor");
    assert_eq!(at.total_reward, total);

    // One under: the whole set is held, pairs and Σ carried.
    let expected_pairs: Vec<(u64, u64)> = derived
        .claimable
        .iter()
        .map(|c| (c.settlement_epoch, c.reward))
        .collect();
    let verdict = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, total + 1);
    match verdict {
        Err(EmissionClaimError::ValueDeferred {
            value_deferred,
            total_reward,
            fee_floor,
        }) => {
            assert_eq!(value_deferred, expected_pairs);
            assert_eq!(total_reward, total);
            assert_eq!(fee_floor, total + 1);
        }
        other => panic!("expected ValueDeferred, got {other:?}"),
    }

    // Gate order: a budget that would refuse every epoch on size never
    // gets consulted when the value gate holds the set.
    assert!(matches!(
        assemble_claims(&derived, 1, total + 1),
        Err(EmissionClaimError::ValueDeferred { .. })
    ));
}

/// A gather carrying two credits for one (claimant, shard) is
/// malformed (the ledger key `P‖shard‖E` is unique) — refused at
/// derivation (where the row is now built), before the double-counted
/// claim can enter a batch.
#[test]
fn duplicate_credited_shard_is_source_invalid() {
    let mut snap = snapshot(5);
    snap.credit_pairs.push(CreditPair {
        bond_idx: 0,
        shard_idx: 0,
    });
    resigma(&mut snap);
    let source = source_with(10, vec![], vec![snap]);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::SourceInvalid { epoch: 5 })
    ));
}

/// Duplicate `shard_id` rows where the credited row is shadowed by an
/// earlier one: the id-resolved recompute (verify's lookup) diverges
/// from the pair-indexed accumulation, so the entry-sum compare
/// refuses at derivation — the vin would be doomed to
/// `WorkTotalMismatch` on-chain.
#[test]
fn shadowed_shard_row_is_source_invalid() {
    let mut snap = snapshot(5);
    let close = epoch_close_height(5).expect("fixture epoch closes");
    snap.shards = vec![
        EpochCloseShard {
            shard_id: SHARD_A,
            has_segment: true,
            freeze_height: close - 1_000,
        },
        EpochCloseShard {
            shard_id: SHARD_A,
            has_segment: true,
            freeze_height: close - 9_000,
        },
    ];
    snap.credit_pairs = vec![CreditPair {
        bond_idx: 0,
        shard_idx: 1,
    }];
    resigma(&mut snap);
    let source = source_with(10, vec![], vec![snap]);
    assert!(matches!(
        derive_claimable_epochs(&source),
        Err(EmissionClaimError::SourceInvalid { epoch: 5 })
    ));
}

// ── Step 7: the build-time self-check ───────────────────────────────

/// The assembled claims inside a vin whose cryptographic legs are
/// canonical-length dummies — sufficient for the claims leg, whose
/// verifier never reads their content (module doc coverage boundary;
/// the backing/auth legs' self-check composition is PR 3's, with real
/// legs). Built through the production construction site
/// ([`claims_vin`]) with minimal proof/depth.
fn dummy_leg_vin(assembled: &AssembledClaims) -> ArchivalRewardEmissionVin {
    claims_vin(
        assembled.holdings.clone(),
        assembled.settlement_epochs.clone(),
        assembled.work_claim.clone(),
        assembled.reward_amount_plain.clone(),
        1,
        0,
    )
}

/// The step-7 differential: the assembled vin passes the **landed**
/// `emission_vin_verify_claims` (the premise — assembly is
/// verifier-accepted, which is what makes the derivation and assembly
/// KATs' determinism halves sufficient in aggregate), and every
/// mutation flips accept → refuse through the same verifier. Each arm
/// names the verify compare it arms; a mutation that did not move the
/// verdict would fail its assert (no dead differential arms).
///
/// The surfaced refusal is `SelfCheckFailed` in every arm — a unit
/// variant, so cause-blindness is structural (CB-5: the operand the
/// verifier rejected on is unrepresentable in the surfaced error).
#[test]
fn self_check_accepts_assembled_and_refuses_every_mutation() {
    // Epoch 6 is present in the source but gated (persisted Σwork = 0)
    // — skipped by the derivation, available to the swap arm below.
    let source = source_with(
        10,
        vec![],
        vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
    );
    let derived = derive_claimable_epochs(&source).expect("epochs 4, 5 claimable");
    let assembled = assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR).expect("fits");
    let base = dummy_leg_vin(&assembled);

    // Premise: the unmutated assembly is verifier-accepted.
    self_check_claims(&source, &base, assembled.total_reward)
        .expect("assembled vin must pass the landed verifier");

    type Mutation = fn(&mut ArchivalRewardEmissionVin);
    let mutations: [(&str, Mutation); 6] = [
        ("scarcity +1 (verify: ScarcityMismatch)", |vin| {
            vin.work_claim[0].shard_entries[0].scarcity_micro += 1;
        }),
        (
            "credit bit cleared (verify: ServeCreditBitMismatch)",
            |vin| {
                vin.work_claim[0].shard_entries[0].serve_credit_bit = false;
            },
        ),
        ("reward +1 (verify: RewardMismatch)", |vin| {
            vin.reward_amount_plain[0] += 1;
        }),
        (
            "credited entries dropped (verify: WorkTotalMismatch)",
            |vin| {
                vin.work_claim[0].shard_entries.clear();
            },
        ),
        (
            "epoch swapped to the gated epoch (verify: RewardMismatch \
             — its recomputed share is zero)",
            |vin| {
                vin.settlement_epochs[1] = 6;
                vin.work_claim[1].epoch = 6;
            },
        ),
        ("holdings swapped (verify: HoldingsMismatch)", |vin| {
            vin.holdings.shard_ids = ShardSet::new(vec![SHARD_B]).unwrap();
        }),
    ];
    for (name, mutate) in mutations {
        let mut vin = base.clone();
        mutate(&mut vin);
        assert!(
            matches!(
                self_check_claims(&source, &vin, assembled.total_reward),
                Err(EmissionClaimError::SelfCheckFailed)
            ),
            "mutation must flip accept → refuse: {name}"
        );
    }

    // Context arms: the vout sum the caller constructed (verify:
    // VoutSumMismatch — the loud inflation check bites on the real
    // vouts, not the vin's own amounts echoed back) …
    assert!(matches!(
        self_check_claims(&source, &base, assembled.total_reward + 1),
        Err(EmissionClaimError::SelfCheckFailed)
    ));
    // … and the bond record's claimed set (verify: EpochAlreadyClaimed
    // — proves the `record()` marshaling reaches the dedup compare).
    let claimed_source = source_with(
        10,
        vec![4],
        vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
    );
    assert!(matches!(
        self_check_claims(&claimed_source, &base, assembled.total_reward),
        Err(EmissionClaimError::SelfCheckFailed)
    ));

    // A claimed epoch missing from the source forecloses marshaling
    // the verify call at all — same blind refusal, logged locally.
    let mut vin = base.clone();
    vin.settlement_epochs[1] = 99;
    vin.work_claim[1].epoch = 99;
    assert!(matches!(
        self_check_claims(&source, &vin, assembled.total_reward),
        Err(EmissionClaimError::SelfCheckFailed)
    ));

    // A source whose bond record vanished (a caller pairing bug — the
    // refetch path) is the same blind refusal, never a panic.
    let mut bondless = source_with(
        10,
        vec![],
        vec![snapshot(4), snapshot(5), zero_share_snapshot(6, true)],
    );
    bondless.bond = None;
    assert!(matches!(
        self_check_claims(&bondless, &base, assembled.total_reward),
        Err(EmissionClaimError::SelfCheckFailed)
    ));
}

/// More credited shards than the wire admits: the production encoder
/// refuses during the sizing measurement (`ShardEntriesExceeded` →
/// `RowsUnencodable`) — the structural bound is armed, not assumed
/// from the daemon's cardinality.
#[test]
fn oversized_shard_entries_refuse_rows_unencodable() {
    let mut snap = snapshot(5);
    snap.shards = (0..=MAX_HOLDINGS_SHARDS as u64)
        .map(|shard_id| EpochCloseShard {
            shard_id,
            has_segment: false,
            freeze_height: 0,
        })
        .collect();
    snap.credit_pairs = (0..=MAX_HOLDINGS_SHARDS)
        .map(|shard_idx| CreditPair {
            bond_idx: 0,
            shard_idx,
        })
        .collect();
    resigma(&mut snap);
    let source = source_with(10, vec![], vec![snap]);
    let derived = derive_claimable_epochs(&source).expect("admitted");
    assert!(matches!(
        assemble_claims(&derived, EMISSION_CLAIMS_SIZE_BUDGET, NO_FLOOR),
        Err(EmissionClaimError::RowsUnencodable(
            EmissionWireError::ShardEntriesExceeded { got }
        )) if got == MAX_HOLDINGS_SHARDS + 1
    ));
}
