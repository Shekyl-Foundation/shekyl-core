// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! PR-E3 emission verify-body KATs (`REWARD_EMISSION_VIN_PLAN.md` §7.1;
//! `REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 3).
//!
//! Every rejection KAT is an armed trigger against a §7.1 step over a
//! production-shaped fixture: the honest claim is **built from the same
//! sourcing functions the verify recomputes with** (`as_of_e_served_work`,
//! `sigma_work_milli`, `reward_share_floor`), so an accept asserts the
//! numerator-is-a-denominator-term identity, and each single-field mutation
//! must flip the verdict to its specific error. The positive membership-only
//! proof path is pinned in `shekyl-fcmp`'s KATs and the FFI roundtrip — not
//! re-fixtured here (step 6's negative paths are).

use shekyl_archival_retention::emission_verify::{
    emission_vin_verify, emission_vin_verify_backing, emission_vin_verify_claims, AuthVerified,
    BackingVerified, ClaimantBondRecord, EmissionEpochSource, EmissionVerifyContext,
    EmissionVerifyError,
};
use shekyl_archival_retention::CreditPair as Pair;
use shekyl_archival_retention::{
    as_of_e_served_work, curve_milli, epoch_close_height, reward_share_floor, sigma_work_milli,
    ArchivalRewardEmissionVin, BandedCurveParams, EpochCloseBond, EpochCloseInputs,
    EpochCloseShard, HoldingsDescriptor, HoldingsKind, KCover, MembershipOnlyBacking,
    ShardWorkEntry, WorkEpochClaim, ARCHIVAL_REWARD_AGE_WEIGHT_MILLI, MAX_CLAIM_AGE_W,
    SETTLEMENT_EPOCH_BLOCKS,
};
use shekyl_crypto_pq::derivation::hash_pqc_public_key;
use shekyl_crypto_pq::multisig::{SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN};

/// Claimed settlement epoch for the base fixture.
const E: u64 = 5;
/// Gate-1 per-epoch budget operand.
const BUDGET: u64 = 1_000_000;
/// Claimed shard (claimant-credited) and the second, other-P-only shard.
const SHARD_A: u64 = 7;
const SHARD_B: u64 = 9;

/// Owned as-of-`E` fixture rows: two bonds (idx 0 = claimant, idx 1 = other),
/// two shards, credits {claimant→A, other→A, other→B} — `R_market(A) = 2`,
/// `R_market(B) = 1`, claimant work = its shard-A term only.
struct Fixture {
    epoch: u64,
    bonds: Vec<EpochCloseBond<'static>>,
    shards: Vec<EpochCloseShard>,
    pairs: Vec<Pair>,
    curve: BandedCurveParams,
}

impl Fixture {
    fn new(epoch: u64) -> Self {
        let close = epoch_close_height(epoch).expect("fixture epoch closes");
        Self {
            epoch,
            bonds: vec![
                EpochCloseBond {
                    join_settlement_epoch: 1,
                    is_foundation_complete_tree: false,
                    bad_intervals: &[],
                },
                EpochCloseBond {
                    join_settlement_epoch: 1,
                    is_foundation_complete_tree: false,
                    bad_intervals: &[],
                },
            ],
            shards: vec![
                EpochCloseShard {
                    shard_id: SHARD_A,
                    has_segment: true,
                    freeze_height: close - 5_000,
                },
                EpochCloseShard {
                    shard_id: SHARD_B,
                    has_segment: true,
                    freeze_height: close - 8_000,
                },
            ],
            pairs: vec![
                Pair {
                    bond_idx: 0,
                    shard_idx: 0,
                },
                Pair {
                    bond_idx: 1,
                    shard_idx: 0,
                },
                Pair {
                    bond_idx: 1,
                    shard_idx: 1,
                },
            ],
            curve: BandedCurveParams::default_provisional(),
        }
    }

    fn inputs(&self) -> EpochCloseInputs<'_> {
        EpochCloseInputs {
            settlement_epoch: self.epoch,
            close_block_height: epoch_close_height(self.epoch).expect("close height"),
            settlement_epoch_blocks: SETTLEMENT_EPOCH_BLOCKS,
            age_weight_milli: ARCHIVAL_REWARD_AGE_WEIGHT_MILLI,
            curve: self.curve,
            bonds: &self.bonds,
            shards: &self.shards,
            credit_pairs: &self.pairs,
            frozen_shard_count: self.shards.len() as u64,
            k_cover: KCover::for_kat(0),
        }
    }

    /// The persisted `Σwork(E)` this fixture's close would have stored —
    /// derived through the same sourcing function the verify recomputes with.
    fn persisted_sigma(&self) -> u64 {
        let served = as_of_e_served_work(&self.inputs()).expect("well-formed fixture");
        sigma_work_milli(&served.work_by_bond, &self.curve, &served.member)
    }

    /// Claimant's honest `(work_P, expected reward)` under [`Self::persisted_sigma`].
    fn honest_claim(&self) -> (u64, u64) {
        let served = as_of_e_served_work(&self.inputs()).expect("well-formed fixture");
        let work = served.work_by_bond[0];
        assert!(served.member[0] && work > 0, "fixture claimant must earn");
        let capped = curve_milli(work, &self.curve);
        let reward = reward_share_floor(BUDGET, capped, self.persisted_sigma());
        assert!(reward > 0, "fixture reward must be wire-encodable (>0)");
        (work, reward)
    }
}

fn holdings() -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: vec![SHARD_A],
    }
}

fn honest_vin(fx: &Fixture) -> ArchivalRewardEmissionVin {
    let (work, reward) = fx.honest_claim();
    ArchivalRewardEmissionVin {
        p_pubkey: vec![0x11; SINGLE_KEY_CANONICAL_LEN],
        holdings: holdings(),
        settlement_epochs: vec![fx.epoch],
        work_claim: vec![WorkEpochClaim {
            epoch: fx.epoch,
            shard_entries: vec![ShardWorkEntry {
                shard_id: SHARD_A,
                serve_credit_bit: true,
                scarcity_milli: u32::try_from(work).expect("fixture scarcity fits u32"),
            }],
        }],
        backing: MembershipOnlyBacking {
            proof: vec![0xAB; 64],
            pseudo_out: [0x22; 32],
            pqc_pk_hash: [0x33; 32],
            backing_pubkey: vec![0x44; SINGLE_KEY_CANONICAL_LEN],
            tree_depth: 3,
        },
        reward_amount_plain: vec![reward],
        auth_backing: vec![0x55; SINGLE_SIG_CANONICAL_LEN],
        auth_claim: vec![0x66; SINGLE_SIG_CANONICAL_LEN],
    }
}

/// Base accepting context: one block past `h_close(E)`, matching bond record
/// with an empty claimed set, vout sum equal to the honest reward.
struct Ctx {
    height: u64,
    bond_holdings: HoldingsDescriptor,
    claimed: Vec<u64>,
    join: u64,
    vout_sum: u64,
}

impl Ctx {
    fn accepting(fx: &Fixture) -> Self {
        let (_, reward) = fx.honest_claim();
        Self {
            height: epoch_close_height(fx.epoch).expect("close") + 1,
            bond_holdings: holdings(),
            claimed: vec![],
            join: 1,
            vout_sum: reward,
        }
    }

    fn as_context(&self) -> EmissionVerifyContext<'_> {
        EmissionVerifyContext {
            current_block_height: self.height,
            bond: Some(ClaimantBondRecord {
                join_settlement_epoch: self.join,
                holdings: &self.bond_holdings,
                claimed_settlement_epochs: &self.claimed,
            }),
            vout_reward_sum: self.vout_sum,
        }
    }
}

fn source(fx: &Fixture) -> EmissionEpochSource<'_> {
    EmissionEpochSource {
        inputs: fx.inputs(),
        persisted_sigma_work_milli: fx.persisted_sigma(),
        claimant_bond_idx: Some(0),
        budget: BUDGET,
    }
}

// ---------------------------------------------------------------------------
// Accept + assembly
// ---------------------------------------------------------------------------

/// Steps 1–5 accept the honest claim built from the same sourcing functions —
/// the work-claim identity (numerator == P's term in the persisted
/// denominator) plus the R1.B zero-tolerance economics compare, end to end.
#[test]
fn claims_accept_minimal_valid_emission() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let ctx = Ctx::accepting(&fx);
    let claims = emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)])
        .expect("honest claim accepts");
    assert_eq!(claims.epochs_to_commit(), &[E]);
    assert_eq!(claims.total_reward(), fx.honest_claim().1);

    // Assembly: the final verdict requires all three witnesses. The auth and
    // backing forges are `consensus-kat`-only — in production the auth minter
    // does not exist until C-1 (fail-closed by type, §3.0).
    let verdict = emission_vin_verify(
        claims,
        BackingVerified::kat_forge(),
        AuthVerified::kat_forge(),
    );
    assert_eq!(verdict.epochs_to_commit, vec![E]);
    assert_eq!(verdict.total_reward, fx.honest_claim().1);
}

// ---------------------------------------------------------------------------
// Step 1 — finalization + claim-age boundaries (F-E1)
// ---------------------------------------------------------------------------

/// F-E1 boundary: cite `E` at `h_close(E)` → reject, at `h_close(E)+1` →
/// accept. The strict `>` forecloses the same-block close/claim race
/// independently of connect-hook ordering.
#[test]
fn finalization_boundary() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let mut ctx = Ctx::accepting(&fx);

    ctx.height = epoch_close_height(E).unwrap(); // == h_close(E)
    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err();
    assert!(
        matches!(err, EmissionVerifyError::EpochNotFinalized { epoch, .. } if epoch == E),
        "at h_close: {err}"
    );

    ctx.height = epoch_close_height(E).unwrap() + 1;
    emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)])
        .expect("accepts at h_close + 1");
}

/// §6.6 claim-age boundary: `E` at `C − W` accepts; one epoch older rejects.
/// `C` is the tip epoch index — the same operand the connect-time
/// `claimed_epochs_check_and_set` windows against, so verify and connect
/// cannot disagree about expiry.
#[test]
fn claim_age_boundary() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let mut ctx = Ctx::accepting(&fx);

    // Tip epoch C = E + W → floor = E: still claimable.
    ctx.height = (E + MAX_CLAIM_AGE_W) * SETTLEMENT_EPOCH_BLOCKS + 1;
    emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)])
        .expect("accepts at the window floor");

    // Tip epoch C = E + W + 1 → floor = E + 1: expired.
    ctx.height = (E + MAX_CLAIM_AGE_W + 1) * SETTLEMENT_EPOCH_BLOCKS + 1;
    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err();
    assert!(
        matches!(err, EmissionVerifyError::EpochClaimExpired { epoch, floor }
            if epoch == E && floor == E + 1),
        "past the window: {err}"
    );
}

// ---------------------------------------------------------------------------
// Step 2 — bond posture
// ---------------------------------------------------------------------------

#[test]
fn bond_posture_rejections() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let ctx = Ctx::accepting(&fx);

    // No bond record.
    let mut no_bond = ctx.as_context();
    no_bond.bond = None;
    assert!(matches!(
        emission_vin_verify_claims(&vin, &no_bond, &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::BondMissing
    ));

    // Holdings descriptor drift between vin and record.
    let mut drifted = Ctx::accepting(&fx);
    drifted.bond_holdings.shard_ids = vec![SHARD_A, SHARD_B];
    assert!(matches!(
        emission_vin_verify_claims(&vin, &drifted.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::HoldingsMismatch
    ));

    // Join epoch too late: E < E_join + 1.
    let mut late_join = Ctx::accepting(&fx);
    late_join.join = E;
    let err =
        emission_vin_verify_claims(&vin, &late_join.as_context(), &[source(&fx)]).unwrap_err();
    assert!(
        matches!(err, EmissionVerifyError::EpochBeforeJoin { epoch, join_settlement_epoch }
            if epoch == E && join_settlement_epoch == E),
        "late join: {err}"
    );
}

// ---------------------------------------------------------------------------
// Step 3 — read-only dedup (WS-2 §6.2)
// ---------------------------------------------------------------------------

/// Cross-block double-claim: `E` already in the pre-block claimed set →
/// reject. The check is read-only — the set is untouched (the write side is
/// the connect path's `claimed_epochs_check_and_set`, item 3a).
#[test]
fn dedup_read_only_rejects_claimed_epoch() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let mut ctx = Ctx::accepting(&fx);
    ctx.claimed = vec![E - 2, E];

    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err();
    assert!(matches!(
        err,
        EmissionVerifyError::EpochAlreadyClaimed { epoch } if epoch == E
    ));
    assert_eq!(ctx.claimed, vec![E - 2, E], "read-only: set unchanged");
}

// ---------------------------------------------------------------------------
// Step 4 — work recompute polarity
// ---------------------------------------------------------------------------

/// Wrong-epoch polarity: the marshaled snapshot must be for the claimed `E`;
/// a mismatch is a loud marshaling error, never a silent mis-verification.
#[test]
fn wrong_epoch_source_rejects() {
    let fx = Fixture::new(E);
    let wrong = Fixture::new(E + 1);
    let vin = honest_vin(&fx);
    let ctx = Ctx::accepting(&fx);

    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&wrong)]).unwrap_err();
    assert!(
        matches!(err, EmissionVerifyError::EpochSourceMisaligned { claimed, marshaled, .. }
            if claimed == E && marshaled == E + 1),
        "wrong epoch: {err}"
    );
}

/// Wrong-P polarity: the claimant index resolving to a different bond makes
/// the recomputed `work_P` diverge from the claim (the other bond also
/// served shard B) — the omitted-term completeness check fires.
#[test]
fn wrong_claimant_rejects() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let ctx = Ctx::accepting(&fx);

    let mut src = source(&fx);
    src.claimant_bond_idx = Some(1);
    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[src]).unwrap_err();
    assert!(
        matches!(err, EmissionVerifyError::WorkTotalMismatch { epoch, .. } if epoch == E),
        "wrong claimant: {err}"
    );
}

#[test]
fn work_claim_entry_polarity() {
    let fx = Fixture::new(E);
    let ctx = Ctx::accepting(&fx);

    // Scarcity off by one → per-entry exactness fires.
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries[0].scarcity_milli += 1;
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::ScarcityMismatch {
            shard_id: SHARD_A,
            ..
        }
    ));

    // Credit bit asserted on a shard the claimant never served.
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries.push(ShardWorkEntry {
        shard_id: SHARD_B,
        serve_credit_bit: true,
        scarcity_milli: 1,
    });
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::ServeCreditBitMismatch {
            shard_id: SHARD_B,
            claimed: true,
            ..
        }
    ));

    // Credit bit denied on the shard the ledger says was served.
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries[0].serve_credit_bit = false;
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::ServeCreditBitMismatch {
            shard_id: SHARD_A,
            claimed: false,
            ..
        }
    ));

    // A truthful bit=false entry must carry zero scarcity — nonzero is
    // unvalidated misinformation even though it adds no work.
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries.push(ShardWorkEntry {
        shard_id: SHARD_B,
        serve_credit_bit: false,
        scarcity_milli: 250,
    });
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::ScarcityMismatch {
            shard_id: SHARD_B,
            claimed: 250,
            recomputed: 0,
            ..
        }
    ));

    // Omitting the credited shard leaves the entry sum short of the
    // recompute.
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries.clear();
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::WorkTotalMismatch { claimed: 0, .. }
    ));

    // Duplicate shard entries reject outright.
    let mut vin = honest_vin(&fx);
    let dup = vin.work_claim[0].shard_entries[0].clone();
    vin.work_claim[0].shard_entries.push(dup);
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::WorkClaimDuplicateShard {
            shard_id: SHARD_A,
            ..
        }
    ));
}

/// No-credit sentinel: a bonded-but-never-credited claimant recomputes zero
/// work, so any positive (wire-encodable) reward claim rejects — the Q12
/// economic leg, without an accept-with-zero branch.
#[test]
fn no_credit_claimant_rejects() {
    let fx = Fixture::new(E);
    let ctx = Ctx::accepting(&fx);

    let mut src = source(&fx);
    src.claimant_bond_idx = None;

    // Asserting a credit bit with no credit row → step 4.
    let vin = honest_vin(&fx);
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[src.clone()]).unwrap_err(),
        EmissionVerifyError::ServeCreditBitMismatch {
            shard_id: SHARD_A,
            claimed: true,
            ..
        }
    ));

    // Truthful zero-work claim, positive reward → step 5 (recompute is 0).
    let mut vin = honest_vin(&fx);
    vin.work_claim[0].shard_entries[0] = ShardWorkEntry {
        shard_id: SHARD_A,
        serve_credit_bit: false,
        scarcity_milli: 0,
    };
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[src]).unwrap_err(),
        EmissionVerifyError::RewardMismatch { recomputed: 0, .. }
    ));
}

// ---------------------------------------------------------------------------
// Step 5 — economics polarity
// ---------------------------------------------------------------------------

#[test]
fn economics_polarity() {
    let fx = Fixture::new(E);
    let ctx = Ctx::accepting(&fx);

    // Claimed amount one atomic unit high → zero-tolerance reject.
    let mut vin = honest_vin(&fx);
    vin.reward_amount_plain[0] += 1;
    assert!(matches!(
        emission_vin_verify_claims(&vin, &ctx.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::RewardMismatch { epoch: E, .. }
    ));

    // Per-epoch amounts verified but vout sum drifts → loud inflation check.
    let vin = honest_vin(&fx);
    let mut drifted = Ctx::accepting(&fx);
    drifted.vout_sum += 1;
    assert!(matches!(
        emission_vin_verify_claims(&vin, &drifted.as_context(), &[source(&fx)]).unwrap_err(),
        EmissionVerifyError::VoutSumMismatch { .. }
    ));
}

// ---------------------------------------------------------------------------
// Step 6 — backing negative paths
// ---------------------------------------------------------------------------

#[test]
fn backing_rejects_leaf_mismatch_then_bad_proof() {
    let fx = Fixture::new(E);

    // The revealed pubkey does not hash to the committed leaf scalar.
    let vin = honest_vin(&fx);
    assert!(matches!(
        emission_vin_verify_backing(&vin, &[0u8; 32], 3, [0u8; 32]).unwrap_err(),
        EmissionVerifyError::BackingLeafMismatch
    ));

    // Leaf equality holds but the proof bytes are garbage → fcmp rejects.
    let mut vin = honest_vin(&fx);
    vin.backing.pqc_pk_hash = hash_pqc_public_key(&vin.backing.backing_pubkey);
    assert!(matches!(
        emission_vin_verify_backing(&vin, &[0u8; 32], 3, [0u8; 32]).unwrap_err(),
        EmissionVerifyError::BackingRejected(_)
    ));
}

// ---------------------------------------------------------------------------
// Marshaling guards
// ---------------------------------------------------------------------------

#[test]
fn source_count_mismatch_rejects() {
    let fx = Fixture::new(E);
    let vin = honest_vin(&fx);
    let ctx = Ctx::accepting(&fx);

    let err = emission_vin_verify_claims(&vin, &ctx.as_context(), &[]).unwrap_err();
    assert!(matches!(
        err,
        EmissionVerifyError::EpochSourceMisaligned {
            claimed: 1,
            marshaled: 0,
            ..
        }
    ));
}
