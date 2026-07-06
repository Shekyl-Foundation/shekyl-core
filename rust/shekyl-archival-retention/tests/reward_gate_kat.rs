// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! M1 reward-gate activation-boundary KAT (ARCHIVAL_REWARD_GATE_M1.md §5,
//! cases G-1..G-10).
//!
//! The §7 dead-rule acceptance relocates the armed-gate-with-no-trigger risk
//! to time: the gate fires once, at the activation boundary, and is never
//! exercised again — no steady-state test and no runtime signal covers the
//! boundary after launch. These cases have exactly one chance to be right:
//! the comparison direction and off-by-one at `frozen_shard_count < K_COVER`,
//! the `chain_epochs == 0` genesis composition, and the exact epoch of first
//! non-zero accrual.
//!
//! The fixture injects `frozen_shard_count` and `k_cover` per case —
//! parameterized, never baked from the provisional constant — so the corpus
//! survives the §4 constant finalization without rewrite. The C++ count-pass
//! boundary (the `freeze_height ≤ H_close` filter this KAT structurally
//! cannot reach — G-10 injects the count) is pinned separately in
//! `tests/unit_tests/archival_substrate_lmdb.cpp` per §11.8 M3-1/M3-2.
//!
//! Wire-level companions (G-5/G-7/G-8): the §2.3 positivity rule and the
//! arithmetic core of the §2.2 zero-tolerance compare. The full vin-verifier
//! composition is PR-E3's surface (forward obligation, §6 wallet-builder
//! row); what is pinned here is everything the compare will consume.

use shekyl_archival_retention::{
    curve_milli, epoch_close_compute, reward_share_floor, ArchivalRewardEmissionVin, BadInterval,
    BandedCurveParams, CreditPair, EmissionWireError, EpochCloseBond, EpochCloseInputs,
    EpochCloseResult, EpochCloseShard, HoldingsDescriptor, HoldingsKind, KCover,
    MembershipOnlyBacking, ShardWorkEntry, WorkEpochClaim,
};
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

const KAT: &str = include_str!("fixtures/reward_gate_kat_v1.json");

/// Owned mirror of the fixture's epoch-close scenario, so per-case variants
/// (genesis edge, single-shard credits, per-epoch frozen counts) can be built
/// by overriding one field at a time.
struct Scenario {
    settlement_epoch: u64,
    close_block_height: u64,
    settlement_epoch_blocks: u64,
    age_weight_milli: u64,
    curve: BandedCurveParams,
    bonds: Vec<(u64, bool, Vec<BadInterval>, Vec<u64>)>,
    shards: Vec<EpochCloseShard>,
    credit_pairs: Vec<CreditPair>,
}

impl Scenario {
    fn from_fixture(doc: &serde_json::Value) -> Self {
        let base = &doc["base"];
        Scenario {
            settlement_epoch: base["settlement_epoch"].as_u64().expect("epoch"),
            close_block_height: base["close_block_height"].as_u64().expect("close height"),
            settlement_epoch_blocks: base["settlement_epoch_blocks"].as_u64().expect("seb"),
            age_weight_milli: base["age_weight_milli"].as_u64().expect("age weight"),
            curve: BandedCurveParams {
                plateau_work_milli: base["curve"]["plateau_work_milli"]
                    .as_u64()
                    .expect("plateau_work"),
                plateau_value_milli: base["curve"]["plateau_value_milli"]
                    .as_u64()
                    .expect("plateau_value"),
            },
            bonds: base["bonds"]
                .as_array()
                .expect("bonds")
                .iter()
                .map(|b| {
                    (
                        b["join_epoch"].as_u64().expect("join_epoch"),
                        b["complete_tree"].as_bool().expect("complete_tree"),
                        b["bad_intervals"]
                            .as_array()
                            .expect("bad_intervals")
                            .iter()
                            .map(|iv| BadInterval {
                                start_epoch: iv["start"].as_u64().expect("start"),
                                end_exclusive: iv["end_exclusive"].as_u64().expect("end_exclusive"),
                            })
                            .collect(),
                        b["held_shard_ids"]
                            .as_array()
                            .expect("held_shard_ids")
                            .iter()
                            .map(|v| v.as_u64().expect("shard id"))
                            .collect(),
                    )
                })
                .collect(),
            shards: parse_shards(&base["shards"]),
            credit_pairs: parse_pairs(&base["credit_pairs"]),
        }
    }

    fn compute(&self, frozen_shard_count: u64, k_cover: u64) -> EpochCloseResult {
        let bonds: Vec<EpochCloseBond<'_>> = self
            .bonds
            .iter()
            .map(|(join, complete, bad, held)| EpochCloseBond {
                join_settlement_epoch: *join,
                is_foundation_complete_tree: *complete,
                bad_intervals: bad,
                held_shard_ids: held,
            })
            .collect();
        epoch_close_compute(&EpochCloseInputs {
            settlement_epoch: self.settlement_epoch,
            close_block_height: self.close_block_height,
            settlement_epoch_blocks: self.settlement_epoch_blocks,
            age_weight_milli: self.age_weight_milli,
            curve: self.curve,
            bonds: &bonds,
            shards: &self.shards,
            credit_pairs: &self.credit_pairs,
            frozen_shard_count,
            // PF-6a: per-case injection is the KAT's contract (the fixture
            // survives the §4 seal); `for_kat` rides the dev-only
            // consensus-kat feature.
            k_cover: KCover::for_kat(k_cover),
        })
        .expect("well-formed fixture indices")
    }
}

fn parse_shards(v: &serde_json::Value) -> Vec<EpochCloseShard> {
    v.as_array()
        .expect("shards")
        .iter()
        .map(|s| EpochCloseShard {
            shard_id: s["shard_id"].as_u64().expect("shard_id"),
            has_segment: s["has_segment"].as_bool().expect("has_segment"),
            freeze_height: s["freeze_height"].as_u64().expect("freeze_height"),
        })
        .collect()
}

fn parse_pairs(v: &serde_json::Value) -> Vec<CreditPair> {
    v.as_array()
        .expect("credit_pairs")
        .iter()
        .map(|p| CreditPair {
            bond_idx: usize::try_from(p["bond"].as_u64().expect("bond idx")).unwrap(),
            shard_idx: usize::try_from(p["shard"].as_u64().expect("shard idx")).unwrap(),
        })
        .collect()
}

fn expected_result(v: &serde_json::Value) -> EpochCloseResult {
    EpochCloseResult {
        r_market_by_shard: v["r_market_by_shard"]
            .as_array()
            .expect("r_market_by_shard")
            .iter()
            .map(|x| x.as_u64().expect("count"))
            .collect(),
        sigma_work_milli: v["sigma_work_milli"].as_u64().expect("sigma_work_milli"),
    }
}

fn zero_shape(n: usize) -> EpochCloseResult {
    EpochCloseResult {
        r_market_by_shard: vec![0u64; n],
        sigma_work_milli: 0,
    }
}

fn fixture() -> (serde_json::Value, Scenario, u64) {
    let doc: serde_json::Value = serde_json::from_str(KAT).expect("kat json");
    let k_cover = doc["k_cover"].as_u64().expect("k_cover");
    let scenario = Scenario::from_fixture(&doc);
    (doc, scenario, k_cover)
}

/// G-1: `frozen_shard_count = K_COVER − 1` — provably zero, and G-6: the
/// zeroing is the exact result shape, no field escapes.
#[test]
fn g1_g6_below_threshold_is_exact_zero_shape() {
    let (_, scenario, k_cover) = fixture();
    let out = scenario.compute(k_cover - 1, k_cover);
    assert_eq!(out, zero_shape(scenario.shards.len()));
}

/// G-2: `frozen_shard_count = K_COVER` — non-zero, and equal to the ungated
/// computation's output (the gate at/above threshold is the identity).
#[test]
fn g2_at_threshold_is_ungated_identity() {
    let (doc, scenario, k_cover) = fixture();
    let want = expected_result(&doc["ungated_expected"]);
    let at_threshold = scenario.compute(k_cover, k_cover);
    assert_eq!(at_threshold, want);
    assert!(at_threshold.sigma_work_milli > 0, "provably non-zero");
    // Identity against the gate-disabled computation, not just the pin.
    assert_eq!(at_threshold, scenario.compute(k_cover, 0));
}

/// G-3: first non-zero accrual lands at exactly the first epoch whose
/// `frozen_shard_count` reaches `K_COVER`; the prior epoch's is zero.
#[test]
fn g3_first_nonzero_accrual_at_exact_boundary_epoch() {
    let (doc, scenario, k_cover) = fixture();
    let counts: Vec<u64> = doc["g3_frozen_counts_by_epoch"]
        .as_array()
        .expect("g3 counts")
        .iter()
        .map(|v| v.as_u64().expect("count"))
        .collect();
    let first_nonzero =
        usize::try_from(doc["g3_first_nonzero_index"].as_u64().expect("index")).unwrap();
    let want_boundary = expected_result(&doc["ungated_expected"]);

    for (i, &frozen) in counts.iter().enumerate() {
        let out = scenario.compute(frozen, k_cover);
        if i < first_nonzero {
            assert_eq!(out, zero_shape(scenario.shards.len()), "epoch index {i}");
        } else {
            assert_eq!(out, want_boundary, "epoch index {i}");
        }
    }
    // The fixture's boundary is the fixture's claim; re-derive it so a
    // drifted fixture cannot silently pass.
    assert_eq!(
        counts.iter().position(|&c| c >= k_cover),
        Some(first_nonzero)
    );
}

/// G-4: `chain_epochs == 0` genesis edge — the gate composes with the
/// `shard_age_milli` genesis zero without masking or double-zeroing.
#[test]
fn g4_genesis_edge_composes_with_gate() {
    let (doc, mut scenario, k_cover) = fixture();
    let edge = &doc["genesis_edge"];
    scenario.close_block_height = edge["close_block_height"].as_u64().expect("close height");
    scenario.shards = parse_shards(&edge["shards"]);
    assert!(
        scenario.close_block_height < scenario.settlement_epoch_blocks,
        "fixture must exercise chain_epochs == 0"
    );

    // Gated at the genesis edge: well-defined zero shape (the table's pin).
    assert_eq!(
        scenario.compute(k_cover - 1, k_cover),
        zero_shape(scenario.shards.len())
    );
    // Ungated at the genesis edge: the age term is zero but the computation
    // is live — pinned non-zero values prove the gate zero and the genesis
    // age zero are distinct effects, not a masked double-zero.
    let want = expected_result(&edge["ungated_expected"]);
    assert_eq!(scenario.compute(k_cover, k_cover), want);
    assert!(want.sigma_work_milli > 0);
}

/// G-9: `K_COVER = 0` degenerate — the gate is the identity everywhere
/// (`frozen_shard_count < 0` is never true), including composed with the
/// G-4 genesis edge. This is the §4 provisional-sentinel semantics.
#[test]
fn g9_k_cover_zero_is_identity_everywhere() {
    let (doc, mut scenario, k_cover) = fixture();
    let want = expected_result(&doc["ungated_expected"]);
    assert_eq!(scenario.compute(0, 0), want);
    assert_eq!(scenario.compute(u64::MAX, 0), want);

    // Composed with the genesis edge: identity there too.
    let edge = &doc["genesis_edge"];
    scenario.close_block_height = edge["close_block_height"].as_u64().expect("close height");
    scenario.shards = parse_shards(&edge["shards"]);
    let edge_want = expected_result(&edge["ungated_expected"]);
    assert_eq!(scenario.compute(0, 0), edge_want);
    // And the two zeros compose: gating (k_cover back above the count)
    // still zeroes at the edge — k_cover = 0 was the identity, not a mask.
    assert_eq!(
        scenario.compute(0, k_cover),
        zero_shape(scenario.shards.len())
    );
}

/// G-10: participation-independence (§11 M2-1, executable). The segment
/// count is at/above threshold while credits touch fewer than `K_COVER`
/// distinct shards: not gated, accrual non-zero. The gate reads the
/// injected segment-table count, never the served set.
#[test]
fn g10_gate_is_participation_independent() {
    let (doc, mut scenario, k_cover) = fixture();
    let variant = &doc["single_shard_variant"];
    scenario.credit_pairs = parse_pairs(&variant["credit_pairs"]);
    let distinct_credited: std::collections::BTreeSet<usize> =
        scenario.credit_pairs.iter().map(|p| p.shard_idx).collect();
    assert!(
        (distinct_credited.len() as u64) < k_cover,
        "fixture must credit fewer distinct shards than k_cover"
    );

    let frozen = variant["frozen_shard_count"].as_u64().expect("frozen");
    assert!(frozen >= k_cover);
    let out = scenario.compute(frozen, k_cover);
    assert_eq!(out, expected_result(&variant["expected"]));
    assert!(out.sigma_work_milli > 0, "not gated: accrual is non-zero");
}

// ── Wire-level companions ───────────────────────────────────────────────────

/// Deterministic minimal vin for the wire cases (same construction discipline
/// as `kat_emission_auth_msg.rs`: every byte fixed, no RNG).
fn wire_vin(
    settlement_epochs: Vec<u64>,
    reward_amount_plain: Vec<u64>,
) -> ArchivalRewardEmissionVin {
    let work_claim = settlement_epochs
        .iter()
        .map(|&epoch| WorkEpochClaim {
            epoch,
            shard_entries: vec![ShardWorkEntry {
                shard_id: 7,
                serve_credit_bit: true,
                scarcity_milli: 500,
            }],
        })
        .collect();
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0x5A; SINGLE_KEY_CANONICAL_LEN],
        holdings: HoldingsDescriptor {
            kind: HoldingsKind::ShardSetCompact,
            shard_ids: vec![7],
        },
        settlement_epochs,
        work_claim,
        backing: MembershipOnlyBacking {
            proof: vec![0xEE; 64],
            pseudo_out: [0x22; 32],
            pqc_pk_hash: [0x33; 32],
            backing_pubkey: vec![0xB2; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain,
        auth_backing: vec![0xC3; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0xD4; SINGLE_SIG_CANONICAL_LEN],
    }
}

/// G-7: §2.3 wire positivity — any `reward_amount_plain[i] == 0` rejected at
/// `validate()`, stateless; a fully positive vin serializes.
#[test]
fn g7_wire_positivity_rejects_zero_amounts_statelessly() {
    assert!(wire_vin(vec![11, 12], vec![1_000, 2_000])
        .serialize()
        .is_ok());
    assert!(matches!(
        wire_vin(vec![11, 12], vec![1_000, 0]).validate(),
        Err(EmissionWireError::RewardAmountZero { index: 1 })
    ));
    assert!(matches!(
        wire_vin(vec![11, 12], vec![0, 2_000]).serialize(),
        Err(EmissionWireError::RewardAmountZero { index: 0 })
    ));
}

/// G-5 + G-8 (arithmetic core): claims against a gated epoch are rejected
/// structurally, and a batch spanning the boundary rejects whole.
///
/// The gate zeroes the stored `Σwork(E)`; §2.2's zero-tolerance compare
/// recomputes each claimed epoch's share from the stored row. What is pinned
/// here is the composition the future PR-E3 verifier consumes:
///
/// - `reward_share_floor(·, ·, 0) == 0` for every operand the wire can carry,
///   while §2.3 makes zero amounts unencodable — so **no encodable claim row
///   for a gated epoch can ever equal its recomputed share**. The rejection
///   is structural, not a zero-amount pass (G-5), and one gated epoch in a
///   batch fails the whole vin's compare (G-8 reject-whole).
/// - The boundary epoch alone recomputes a positive, encodable share from
///   the ungated `Σwork` (G-8 accept side).
#[test]
fn g5_g8_gated_epoch_share_is_structurally_unclaimable() {
    let (doc, scenario, k_cover) = fixture();

    // Gated epoch: stored sigma is zero. Every possible share is zero…
    let gated = scenario.compute(k_cover - 1, k_cover);
    assert_eq!(gated.sigma_work_milli, 0);
    for budget in [1u64, 1_000_000, u64::MAX] {
        for capped in [0u64, 1, 8_000, u64::MAX] {
            assert_eq!(
                reward_share_floor(budget, capped, gated.sigma_work_milli),
                0
            );
        }
    }
    // …and zero is unencodable (G-7), so no claim row can match: any vin
    // whose settlement_epochs include the gated epoch rejects whole.

    // Boundary epoch: the recomputed share is positive and encodable.
    let boundary = scenario.compute(k_cover, k_cover);
    let want = expected_result(&doc["ungated_expected"]);
    assert_eq!(boundary, want);
    let capped = curve_milli(1_090, &scenario.curve); // b0's work at the boundary
    let share = reward_share_floor(1_000_000, capped, boundary.sigma_work_milli);
    assert!(share > 0, "boundary share must be positive");
    assert!(
        wire_vin(vec![10], vec![share]).serialize().is_ok(),
        "boundary share must be encodable"
    );
}
