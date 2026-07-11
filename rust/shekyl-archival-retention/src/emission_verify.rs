// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `shekyl_emission_vin_verify` — the PR-E3 fail-fast verify body
//! (`REWARD_EMISSION_VIN_PLAN.md` §7.1 / PR-E3;
//! `REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 3).
//!
//! The §7.1 step map and where each step lives:
//!
//! | §7.1 step | Where |
//! |---|---|
//! | 1. finalization & claim-age bounds (F-E1) | [`emission_vin_verify_claims`] |
//! | 2. bond posture | [`emission_vin_verify_claims`] |
//! | 3. dedup (**read-only** layer, WS-2 §6.2) | [`emission_vin_verify_claims`] |
//! | 4. work recompute (M-2 as-of-E sourcing) | [`emission_vin_verify_claims`] |
//! | 5. economics (three-channel, R1.B) | [`emission_vin_verify_claims`] |
//! | 6. membership-only backing | [`emission_vin_verify_backing`] |
//! | 7. FCMP balance for fee inputs | C++ tx layer (existing `shekyl_fcmp_verify` over the fee `txin_to_key`s; not this module) |
//! | 8. hybrid auth gate (§2, R1.A) | [`emission_vin_verify_auth`] (landed with C-1 block 3) |
//!
//! ## Fail-closed by type (§3.0 gate-last)
//!
//! The final verdict [`EmissionVerified`] is only constructible through
//! [`emission_vin_verify`], which consumes three **sealed witnesses**:
//! [`ClaimsVerified`] (steps 1–5), [`BackingVerified`] (step 6), and
//! [`AuthVerified`] (step 8) — each mintable only by its verify function in
//! this module. The dispatch cannot skip a step: an acceptance without all
//! three witnesses is unrepresentable, not merely rejected.
//!
//! ## Dedup layering (WS-2 §6.2)
//!
//! Step 3 here is the **read-only** `claimed_epochs_contains` check against
//! the *pre-block* bond record. The write side
//! ([`claimed_epochs_check_and_set`](crate::claimed_epochs_check_and_set))
//! runs at connect only, and the intra-block same-`(P,E)` collision is caught
//! by the block-level uniqueness pass (item 3a) — neither is this module's
//! concern, by design.

use crate::claimed_epochs::{claim_window_floor, claimed_epochs_contains};
use crate::consensus_state::{
    as_of_e_served_work, capped_work_milli, epoch_close_height, settlement_epoch_at_height,
    shard_contribution_milli, CreditIndexOutOfRange, EpochCloseInputs, ServedWork,
};
use crate::emission_wire::{ArchivalRewardEmissionVin, EmissionAuthRole, RewardCommit, WireError};
use crate::reward_arithmetic::reward_share_floor;
use shekyl_crypto_pq::derivation::hash_pqc_public_key;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_fcmp::proof::{verify_membership_only, ShekylFcmpProof};
use shekyl_fcmp::PqcLeafScalar;
use thiserror::Error;

/// Rejection reasons for the §7.1 verify body. Every variant is a consensus
/// rejection — there is no "warning" tier; the vin is invalid.
#[derive(Debug, Error)]
pub enum EmissionVerifyError {
    /// Structural wire invariant failed ([`ArchivalRewardEmissionVin::validate`]).
    #[error("structural: {0}")]
    Structural(#[from] WireError),

    /// The caller-marshaled epoch sources are not aligned 1:1 with the vin's
    /// claimed `settlement_epochs` (count or epoch value). A marshaling bug,
    /// surfaced loudly rather than mis-verified.
    #[error("epoch sources misaligned with claim: index {index}, claimed {claimed}, marshaled {marshaled}")]
    EpochSourceMisaligned {
        index: usize,
        claimed: u64,
        marshaled: u64,
    },

    /// Step 1 (F-E1): claimed `E` is not finalized —
    /// `current_block_height <= h_close(E) = (E+1)·SETTLEMENT_EPOCH_BLOCKS`
    /// (or `h_close(E)` overflows: an impossible epoch).
    #[error("epoch {epoch} not finalized at height {current_block_height}")]
    EpochNotFinalized {
        epoch: u64,
        current_block_height: u64,
    },

    /// Step 1 (§6.6): claimed `E` has fallen below the claim window
    /// (`E < current_settled_epoch − MAX_CLAIM_AGE_W`).
    #[error("epoch {epoch} below claim window floor {floor}")]
    EpochClaimExpired { epoch: u64, floor: u64 },

    /// Step 2: no bond record exists for `P`.
    #[error("no bond record for claimant")]
    BondMissing,

    /// Step 2: the vin's holdings descriptor does not match the bond record.
    #[error("vin holdings descriptor does not match bond record")]
    HoldingsMismatch,

    /// Step 2: claimed `E < E_join + 1` — the join epoch itself accrues no
    /// claimable work (mirrors `good_through`'s join clause).
    #[error("epoch {epoch} precedes claimable range for join epoch {join_settlement_epoch}")]
    EpochBeforeJoin {
        epoch: u64,
        join_settlement_epoch: u64,
    },

    /// Step 3 (WS-2 read-only layer): `E` is already in the pre-block
    /// claimed set — a cross-block double-claim.
    #[error("epoch {epoch} already claimed")]
    EpochAlreadyClaimed { epoch: u64 },

    /// Step 4: the frozen gather rows are internally malformed
    /// (a credit pair indexes outside the bond/shard arrays).
    #[error("epoch {epoch}: malformed gather ({0})", .source_err)]
    GatherMalformed {
        epoch: u64,
        source_err: crate::consensus_state::CreditIndexOutOfRange,
    },

    /// Step 4: the source's `claimant_bond_idx` indexes outside the gathered
    /// bond rows — a marshaling bug or malformed gather. A structured
    /// fail-closed rejection, mirroring the FFI numerator's `ERR_INDEX_RANGE`
    /// guard, rather than an indexing panic on the consensus verify path.
    #[error(
        "epoch {epoch}: claimant bond index {claimant_bond_idx} out of range ({bonds_len} bonds)"
    )]
    ClaimantIndexOutOfRange {
        epoch: u64,
        claimant_bond_idx: usize,
        bonds_len: usize,
    },

    /// Step 4: a work-claim entry repeats a `shard_id` within one epoch.
    #[error("epoch {epoch}: duplicate shard {shard_id} in work claim")]
    WorkClaimDuplicateShard { epoch: u64, shard_id: u64 },

    /// Step 4: an entry's `serve_credit_bit` contradicts the frozen
    /// serve-credit ledger (claims a credit that does not exist, or denies
    /// one that does — §5.4 "must match the challenge state at `E`").
    #[error("epoch {epoch}, shard {shard_id}: serve_credit_bit {claimed} contradicts ledger")]
    ServeCreditBitMismatch {
        epoch: u64,
        shard_id: u64,
        claimed: bool,
    },

    /// Step 4: an entry's `scarcity_milli` differs from the recompute over
    /// the frozen as-of-`E` rows (integer-exact, tolerance zero).
    #[error("epoch {epoch}, shard {shard_id}: scarcity {claimed} != recomputed {recomputed}")]
    ScarcityMismatch {
        epoch: u64,
        shard_id: u64,
        claimed: u64,
        recomputed: u64,
    },

    /// Step 4: the per-shard entries do not sum to the recomputed
    /// `work_P(E)` — an omitted (or padded) credited shard.
    #[error("epoch {epoch}: work claim total {claimed} != recomputed {recomputed}")]
    WorkTotalMismatch {
        epoch: u64,
        claimed: u64,
        recomputed: u64,
    },

    /// Step 5 (R1.B zero-tolerance): claimed `reward_amount_plain` differs
    /// from the three-channel recompute
    /// `floor(budget·capped_P / Σwork)` over the **persisted** denominator.
    #[error("epoch {epoch}: reward {claimed} != recomputed {recomputed}")]
    RewardMismatch {
        epoch: u64,
        claimed: u64,
        recomputed: u64,
    },

    /// Step 5: Σ per-epoch rewards overflows u64 (unreachable for honest
    /// budgets; untrusted input is rejected, not saturated).
    #[error("reward total overflows u64")]
    RewardTotalOverflow,

    /// Step 5 (loud inflation check): Σ `reward_amount_plain` differs from
    /// the emission tx's reward vout sum.
    #[error("reward total {reward_total} != vout sum {vout_sum}")]
    VoutSumMismatch { reward_total: u64, vout_sum: u64 },

    /// Step 6: `hash_pqc_public_key(backing_pubkey) != pqc_pk_hash` — the
    /// revealed backing pubkey is not the in-circuit committed leaf.
    #[error("backing pubkey does not hash to the committed leaf scalar")]
    BackingLeafMismatch,

    /// Step 6: membership-only proof rejected.
    #[error("membership-only backing rejected: {0}")]
    BackingRejected(#[from] shekyl_fcmp::proof::VerifyError),

    /// Step 8: a hybrid pubkey or signature field failed canonical
    /// deserialization for the named auth role (wire lengths were canonical —
    /// [`ArchivalRewardEmissionVin::validate`] pinned those — but the bytes
    /// are not a well-formed hybrid encoding).
    #[error("{role:?} auth pubkey/signature failed canonical deserialization")]
    AuthMalformed { role: EmissionAuthRole },

    /// Step 8: the hybrid (Ed25519 **and** ML-DSA-65) signature did not
    /// verify over the role's Q1 domain-separated binding message.
    #[error("{role:?} hybrid auth signature rejected")]
    AuthRejected { role: EmissionAuthRole },
}

/// The claimant's **pre-block** bond record — step 2/3 operands, marshaled
/// by value from the LMDB record as it stood before this block's
/// transactions (Q7: no callbacks across the FFI).
#[derive(Debug, Clone)]
pub struct ClaimantBondRecord<'a> {
    /// `E_join` — step 2's `E ≥ E_join + 1` operand.
    pub join_settlement_epoch: u64,
    /// The record's holdings descriptor; step 2 demands equality with the
    /// vin's (§5.3 / §6.4.1).
    pub holdings: &'a crate::bond_wire::HoldingsDescriptor,
    /// The record's `claimed_settlement_epochs` set (strictly increasing) —
    /// step 3's read-only dedup operand.
    pub claimed_settlement_epochs: &'a [u64],
}

/// One claimed epoch's frozen as-of-`E` source rows — the item-2 snapshot,
/// decoded (`REWARD_EMISSION_E3_GATING_ROUND.md` §3 item 2).
#[derive(Debug, Clone)]
pub struct EmissionEpochSource<'a> {
    /// The frozen gather rows for `E` — the same rows the epoch close
    /// computed from (`inputs.settlement_epoch` must equal the claimed `E`).
    pub inputs: EpochCloseInputs<'a>,
    /// The **persisted** `Σwork(E)` — never a recompute (the M1 `K_COVER`
    /// gate's outcome reaches verify only through the stored value, and
    /// `bad_intervals` may have grown since the close).
    pub persisted_sigma_work_milli: u64,
    /// Claimant `P`'s index into `inputs.bonds`, or `None` when `P` has no
    /// serve-credit row in `E` (its work is then zero by construction).
    pub claimant_bond_idx: Option<usize>,
    /// `budget(E)` — the gate-1 per-epoch reward budget (economics layer
    /// operand; an input to this body, not a recompute).
    pub budget: u64,
}

/// Chain-tip context for the verify body.
#[derive(Debug, Clone)]
pub struct EmissionVerifyContext<'a> {
    /// Height of the block carrying the emission tx.
    pub current_block_height: u64,
    /// The claimant's pre-block bond record; `None` = no record (reject).
    pub bond: Option<ClaimantBondRecord<'a>>,
    /// Σ of the emission tx's reward vout `amount_plain`s — step 5's loud
    /// zero-tolerance compare operand.
    pub vout_reward_sum: u64,
}

/// Sealed witness: §7.1 steps 1–5 passed. Minted only by
/// [`emission_vin_verify_claims`].
#[derive(Debug)]
pub struct ClaimsVerified {
    epochs_to_commit: Vec<u64>,
    total_reward: u64,
}

impl ClaimsVerified {
    /// The claimed epochs, in wire order — the connect path's
    /// `claimed_epochs_check_and_set` inputs.
    #[must_use]
    pub fn epochs_to_commit(&self) -> &[u64] {
        &self.epochs_to_commit
    }

    /// Σ per-epoch rewards (== the reward vout sum, verified).
    #[must_use]
    pub fn total_reward(&self) -> u64 {
        self.total_reward
    }
}

/// Sealed witness: §7.1 step 6 passed (leaf-hash equality +
/// membership-only proof). Minted only by [`emission_vin_verify_backing`].
#[derive(Debug)]
pub struct BackingVerified {
    _sealed: (),
}

impl BackingVerified {
    /// KAT-only forge (see [`AuthVerified::kat_forge`]): the assembly KAT
    /// exercises [`emission_vin_verify`] without constructing a real
    /// membership-only proof — the positive proof path is pinned in
    /// `shekyl-fcmp`'s own KATs and the FFI roundtrip, not re-fixtured here.
    #[cfg(feature = "consensus-kat")]
    #[must_use]
    pub const fn kat_forge() -> Self {
        Self { _sealed: () }
    }
}

/// Sealed witness: the §2/R1.A hybrid auth gate passed (§7.1 step 8).
///
/// The only production minter is [`emission_vin_verify_auth`] — both hybrid
/// auths (Auth-B stake-side, Auth-P claim-side) verified over the Q1
/// domain-separated binding messages, with the Auth-B leaf gate checked
/// first. Fail-closed by type (§3.0): dispatch cannot assemble a verdict
/// without this witness, so an unauthenticated acceptance is
/// unrepresentable.
#[derive(Debug)]
pub struct AuthVerified {
    _sealed: (),
}

impl AuthVerified {
    /// KAT-only forge, gated like `KCover::for_kat` (PF-6a): enabled only
    /// through dev-dependencies; never on a production dependency edge.
    /// (Named `kat_forge`, not `for_kat`, so the PF-6a CI tripwire's
    /// call-site grep stays scoped to `KCover` alone.)
    #[cfg(feature = "consensus-kat")]
    #[must_use]
    pub const fn kat_forge() -> Self {
        Self { _sealed: () }
    }
}

/// The final accept verdict — constructible only through
/// [`emission_vin_verify`], i.e. only with all three witnesses in hand.
#[derive(Debug)]
pub struct EmissionVerified {
    /// The claimed epochs the connect path commits via
    /// `claimed_epochs_check_and_set`.
    pub epochs_to_commit: Vec<u64>,
    /// Σ per-epoch rewards (== the reward vout sum, verified).
    pub total_reward: u64,
}

/// True when `epoch` predates the bond record's market entry —
/// step 2's `E ≥ E_join + 1` bound ([`EmissionVerifyError::EpochBeforeJoin`]),
/// read against the **current record's** join epoch (a retire-then-rejoin
/// lifecycle re-derives `E_join` from the rejoin height, so frozen per-epoch
/// rows may carry an older join than the record that must sign the claim).
///
/// Single source of the join boundary: the verify body and the wallet claim
/// builder's step-1 derivation both resolve through this one predicate, so a
/// builder that admits an epoch verify rejects here is unrepresentable.
#[must_use]
pub fn epoch_is_before_join(epoch: u64, join_settlement_epoch: u64) -> bool {
    epoch < join_settlement_epoch.saturating_add(1)
}

/// The claimant's steps-4/5 evaluation over one epoch's frozen rows — the
/// shared head of the verify body's per-epoch recompute and the wallet claim
/// builder's step-1 derivation (`EMISSION_CLAIM_BUILDER.md` §2: claimable ⇔
/// the recomputed share is strictly positive, **the same recompute verify
/// runs** — one function, not a mirrored copy that can drift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimantShare {
    /// The full [`as_of_e_served_work`] recompute (the per-entry compares
    /// and the builder's row assembly consume its per-shard terms).
    pub served: ServedWork,
    /// `work_P(E)` — zero when the claimant has no serve-credit row.
    pub work_p: u64,
    /// Market membership at `E` (the claimant's mask term).
    pub is_member: bool,
    /// `reward_share_floor(budget, capped_work_milli(work_P, member, curve),
    /// persisted Σwork)` — verify's step-5 `RewardMismatch` operand and the
    /// builder's claimability/wire-positivity predicate.
    pub reward: u64,
}

/// Rejection reasons for [`claimant_reward_share`] — internally inconsistent
/// gather rows; each maps to its verify rejection (or the builder's
/// `SourceInvalid` refusal) at the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimantShareError {
    /// Malformed gather indices (verify: [`EmissionVerifyError::GatherMalformed`]).
    Gather(CreditIndexOutOfRange),
    /// `claimant_bond_idx` outside the bond rows (verify:
    /// [`EmissionVerifyError::ClaimantIndexOutOfRange`]).
    ClaimantIndexOutOfRange {
        claimant_bond_idx: usize,
        bonds_len: usize,
    },
}

/// Steps 4 + 5 evaluation head: the served-work recompute over the frozen
/// rows, the bounds-checked claimant extraction (absent serve-credit row ⇒
/// zero work, exactly as the close treated it), and the three-channel
/// economics over the **persisted** denominator (R1.B: canonical
/// `reward_arithmetic`, floor + burn-the-dust).
pub fn claimant_reward_share(
    source: &EmissionEpochSource<'_>,
) -> Result<ClaimantShare, ClaimantShareError> {
    let served = as_of_e_served_work(&source.inputs).map_err(ClaimantShareError::Gather)?;
    // Bounds-check the caller-supplied index before indexing so a malformed
    // gather is a clean rejection, not a daemon-aborting panic (fail-closed,
    // as the FFI numerator's ERR_INDEX_RANGE guard does).
    let (work_p, is_member) = match source.claimant_bond_idx {
        Some(idx) if idx >= served.work_by_bond.len() => {
            return Err(ClaimantShareError::ClaimantIndexOutOfRange {
                claimant_bond_idx: idx,
                bonds_len: served.work_by_bond.len(),
            });
        }
        Some(idx) => (served.work_by_bond[idx], served.member[idx]),
        None => (0, false),
    };
    // The capped term is the same single-sourced per-P definition that built
    // the persisted `Σwork(E)` denominator.
    let capped = capped_work_milli(work_p, is_member, &source.inputs.curve);
    let reward = reward_share_floor(source.budget, capped, source.persisted_sigma_work_milli);
    Ok(ClaimantShare {
        served,
        work_p,
        is_member,
        reward,
    })
}

/// §7.1 steps 1–5 over the frozen as-of-`E` sources.
///
/// `epoch_sources` must be aligned 1:1 with `vin.settlement_epochs` (the C++
/// shim marshals one item-2 snapshot per claimed epoch; a missing finalized
/// `Σwork(E)` row means the shim never reaches this call). Fail-fast in step
/// order; the set is never mutated (step 3 is the WS-2 read-only layer).
pub fn emission_vin_verify_claims(
    vin: &ArchivalRewardEmissionVin,
    ctx: &EmissionVerifyContext<'_>,
    epoch_sources: &[EmissionEpochSource<'_>],
) -> Result<ClaimsVerified, EmissionVerifyError> {
    // Step 0 — structural (re-run defensively; `read_payload` enforced it on
    // parse, but the in-memory struct may not have come from the wire).
    vin.validate()?;

    // Source alignment: a marshaling bug is a loud error, never a
    // mis-verification against the wrong epoch's rows.
    if epoch_sources.len() != vin.settlement_epochs.len() {
        return Err(EmissionVerifyError::EpochSourceMisaligned {
            index: epoch_sources.len().min(vin.settlement_epochs.len()),
            claimed: vin.settlement_epochs.len() as u64,
            marshaled: epoch_sources.len() as u64,
        });
    }
    for (i, (&epoch, source)) in vin
        .settlement_epochs
        .iter()
        .zip(epoch_sources.iter())
        .enumerate()
    {
        if source.inputs.settlement_epoch != epoch {
            return Err(EmissionVerifyError::EpochSourceMisaligned {
                index: i,
                claimed: epoch,
                marshaled: source.inputs.settlement_epoch,
            });
        }
    }

    // Step 1 — finalization & claim-age bounds (F-E1), explicit structural
    // checks per epoch (deterministic and order-independent under reorg).
    //
    // The window operand is the tip epoch index: `claimed_epochs_check_and_set`
    // (the connect-time writer) treats `E` as settled iff `E < C`, and
    // `E < settlement_epoch_at_height(H)` ⟺ `h_close(E) ≤ H` — the close has
    // been processed. Verify and connect must derive the same `C` or a vin
    // accepted here could fail (or worse, pass) the write-side window check.
    // At `H == h_close(E)` exactly, the strict `>` finalization check below is
    // the tighter boundary (the F-E1 KAT pins reject-at-`h_close`,
    // accept-at-`h_close + 1`), so the same-block close/claim race is
    // foreclosed structurally.
    let current_settled = settlement_epoch_at_height(ctx.current_block_height);
    let window_floor = claim_window_floor(current_settled);
    for &epoch in &vin.settlement_epochs {
        let finalized =
            epoch_close_height(epoch).is_some_and(|h_close| ctx.current_block_height > h_close);
        if !finalized {
            return Err(EmissionVerifyError::EpochNotFinalized {
                epoch,
                current_block_height: ctx.current_block_height,
            });
        }
        if epoch < window_floor {
            return Err(EmissionVerifyError::EpochClaimExpired {
                epoch,
                floor: window_floor,
            });
        }
    }

    // Step 2 — bond posture.
    let bond = ctx.bond.as_ref().ok_or(EmissionVerifyError::BondMissing)?;
    if vin.holdings != *bond.holdings {
        return Err(EmissionVerifyError::HoldingsMismatch);
    }
    for &epoch in &vin.settlement_epochs {
        // The join boundary is [`epoch_is_before_join`] — the same predicate
        // the wallet claim builder's derivation calls, so the two cannot
        // drift (one definition, not parallel inline copies).
        if epoch_is_before_join(epoch, bond.join_settlement_epoch) {
            return Err(EmissionVerifyError::EpochBeforeJoin {
                epoch,
                join_settlement_epoch: bond.join_settlement_epoch,
            });
        }
    }

    // Step 3 — dedup, read-only layer (WS-2 §6.2): the pre-block set only.
    for &epoch in &vin.settlement_epochs {
        if claimed_epochs_contains(bond.claimed_settlement_epochs, epoch) {
            return Err(EmissionVerifyError::EpochAlreadyClaimed { epoch });
        }
    }

    // Steps 4 + 5 — per-epoch work recompute and economics.
    let mut total_reward: u64 = 0;
    for (i, source) in epoch_sources.iter().enumerate() {
        let epoch = vin.settlement_epochs[i];
        let claim = &vin.work_claim[i];

        // Steps 4 + 5 head — recompute `work_P(E)` and the reward share
        // through the shared evaluation ([`claimant_reward_share`]: the
        // single sourcing function per WS-1 §5.5 — the numerator is P's
        // exact term in the persisted denominator by construction — plus
        // the R1.B economics). The wallet claim builder derives claimability
        // from the same function, so builder and verify cannot drift.
        let share = claimant_reward_share(source).map_err(|share_err| match share_err {
            ClaimantShareError::Gather(source_err) => {
                EmissionVerifyError::GatherMalformed { epoch, source_err }
            }
            ClaimantShareError::ClaimantIndexOutOfRange {
                claimant_bond_idx,
                bonds_len,
            } => EmissionVerifyError::ClaimantIndexOutOfRange {
                epoch,
                claimant_bond_idx,
                bonds_len,
            },
        })?;
        let (served, work_p, is_member) = (&share.served, share.work_p, share.is_member);

        // Per-entry exactness (§5.4): the bit must equal the ledger fact,
        // the scarcity must equal the member-masked recompute — a claim
        // carrying unvalidated misinformation is rejected even when the
        // totals happen to agree.
        let mut entry_sum: u64 = 0;
        let mut seen_shards: Vec<u64> = Vec::with_capacity(claim.shard_entries.len());
        for entry in &claim.shard_entries {
            if seen_shards.contains(&entry.shard_id) {
                return Err(EmissionVerifyError::WorkClaimDuplicateShard {
                    epoch,
                    shard_id: entry.shard_id,
                });
            }
            seen_shards.push(entry.shard_id);

            let credited = source.claimant_bond_idx.is_some_and(|claimant| {
                source.inputs.credit_pairs.iter().any(|pair| {
                    pair.bond_idx == claimant
                        && source.inputs.shards[pair.shard_idx].shard_id == entry.shard_id
                })
            });
            if entry.serve_credit_bit != credited {
                return Err(EmissionVerifyError::ServeCreditBitMismatch {
                    epoch,
                    shard_id: entry.shard_id,
                    claimed: entry.serve_credit_bit,
                });
            }

            // Expected contribution: exactly the term `as_of_e_served_work`
            // added for this pair (zero for non-members and uncredited
            // shards) — recomputed per shard so a wrong per-shard split
            // cannot hide behind a correct total.
            let expected = if credited && is_member {
                let shard_idx = source
                    .inputs
                    .shards
                    .iter()
                    .position(|s| s.shard_id == entry.shard_id)
                    .expect("credited pair implies the shard row exists");
                shard_contribution_milli(&source.inputs, &served.r_market_by_shard, shard_idx)
            } else {
                0
            };
            if u64::from(entry.scarcity_milli) != expected {
                return Err(EmissionVerifyError::ScarcityMismatch {
                    epoch,
                    shard_id: entry.shard_id,
                    claimed: u64::from(entry.scarcity_milli),
                    recomputed: expected,
                });
            }
            entry_sum = entry_sum.saturating_add(u64::from(entry.scarcity_milli));
        }

        // Completeness: an omitted credited shard leaves `entry_sum` short
        // of the recompute; a padded one was already rejected per entry.
        // Soundness of the per-shard (`entry_sum`, deduped by `shard_id`) vs
        // per-pair (`work_p`, one term per credit pair) comparison rests on the
        // serve-credit key `P‖shard‖E` being unique: the gather yields at most
        // one credit pair per (claimant, shard) in an epoch, so `work_p` counts
        // each shard once — the same multiplicity `entry_sum` uses. Relaxing
        // that key's uniqueness would double-count `work_p` and must revisit
        // this check (dedup `work_p` by shard).
        if entry_sum != work_p {
            return Err(EmissionVerifyError::WorkTotalMismatch {
                epoch,
                claimed: entry_sum,
                recomputed: work_p,
            });
        }

        // Step 5 — the shared evaluation's reward term (three-channel
        // economics over the persisted denominator; R1.B: canonical
        // `reward_arithmetic`, u128 numerator-before-divide, floor +
        // burn-the-dust), computed above by [`claimant_reward_share`].
        let expected_reward = share.reward;
        let claimed_reward = vin.reward_amount_plain[i];
        if claimed_reward != expected_reward {
            return Err(EmissionVerifyError::RewardMismatch {
                epoch,
                claimed: claimed_reward,
                recomputed: expected_reward,
            });
        }
        total_reward = total_reward
            .checked_add(claimed_reward)
            .ok_or(EmissionVerifyError::RewardTotalOverflow)?;
    }

    // Step 5 (loud inflation check) — Σ rewards == reward vout sum,
    // zero tolerance.
    if total_reward != ctx.vout_reward_sum {
        return Err(EmissionVerifyError::VoutSumMismatch {
            reward_total: total_reward,
            vout_sum: ctx.vout_reward_sum,
        });
    }

    Ok(ClaimsVerified {
        epochs_to_commit: vin.settlement_epochs.clone(),
        total_reward,
    })
}

/// §7.1 step 6 — membership-only backing (PR-E1 seam; **not**
/// `shekyl_fcmp_verify`: no key image — anti-replay is the per-epoch dedup).
///
/// Two checks, in order: the revealed `backing_pubkey` must hash to the
/// in-circuit committed leaf scalar (`hash_pqc_public_key`, the Auth-B leaf
/// gate's structural half), then the proof must verify against the reference
/// block's tree root at its depth.
pub fn emission_vin_verify_backing(
    vin: &ArchivalRewardEmissionVin,
    tree_root: &[u8; 32],
    tree_depth: u8,
    signable_tx_hash: [u8; 32],
) -> Result<BackingVerified, EmissionVerifyError> {
    let backing = &vin.backing;

    if hash_pqc_public_key(&backing.backing_pubkey) != backing.pqc_pk_hash {
        return Err(EmissionVerifyError::BackingLeafMismatch);
    }

    let proof = ShekylFcmpProof {
        data: backing.proof.clone(),
        num_inputs: 1, // single-input pin (§8.0.1 auth arity)
        tree_depth: backing.tree_depth,
    };
    let ok = verify_membership_only(
        &proof,
        &[backing.pseudo_out],
        &[PqcLeafScalar(backing.pqc_pk_hash)],
        tree_root,
        tree_depth,
        signable_tx_hash,
    )?;
    if !ok {
        return Err(EmissionVerifyError::BackingRejected(
            shekyl_fcmp::proof::VerifyError::BatchVerificationFailed,
        ));
    }
    Ok(BackingVerified { _sealed: () })
}

/// §7.1 step 8 — the §2/R1.A hybrid auth gate (the C-1 `AuthVerified`
/// production minter).
///
/// Recomputes both Q1 binding messages through the vin's own
/// [`ArchivalRewardEmissionVin::auth_msgs`] (the single builder signer and
/// verifier share, so they cannot drift), then verifies:
///
/// 1. **Auth-B (stake-side)** — the leaf gate first
///    (`hash_pqc_public_key(backing_pubkey) == pqc_pk_hash`, the same
///    order the PR-E1 `shekyl_emission_hybrid_auth_verify` primitive pins:
///    a signature over an unrelated-but-valid key must not pass), then the
///    hybrid signature `auth_backing` under `backing_pubkey` over the
///    backing-role message. This binds the auth to the **proven leaf**, not
///    merely *a* leaf (gate-6 §9.6).
/// 2. **Auth-P (claim-side)** — the hybrid signature `auth_claim` under
///    `p_pubkey` over the claim-role message. No leaf gate: `P`'s binding is
///    `P_canonical_id`, field 1 of the message inventory (§6.1).
///
/// Both signatures are hybrid (Ed25519 **and** ML-DSA-65) per the ratified
/// R1.A posture — Auth-P has no membership-proof classical fallback, so an
/// ML-DSA-only auth would be a single point of cryptographic failure.
///
/// `reward_commits` and `signable_tx_hash` are the same tx-level context the
/// wallet builder signed over; a destination swap or cross-tx replay changes
/// the recomputed message and both signatures reject.
pub fn emission_vin_verify_auth(
    vin: &ArchivalRewardEmissionVin,
    reward_commits: &[RewardCommit],
    signable_tx_hash: &[u8; 32],
) -> Result<AuthVerified, EmissionVerifyError> {
    let msgs = vin.auth_msgs(reward_commits, signable_tx_hash)?;

    // Auth-B: leaf-binding first (order pinned by the PR-E1 primitive).
    if hash_pqc_public_key(&vin.backing.backing_pubkey) != vin.backing.pqc_pk_hash {
        return Err(EmissionVerifyError::BackingLeafMismatch);
    }
    verify_hybrid_auth(
        &vin.backing.backing_pubkey,
        &msgs.backing,
        &vin.auth_backing,
        EmissionAuthRole::Backing,
    )?;

    // Auth-P: pseudonym key, message-bound via P_canonical_id.
    verify_hybrid_auth(
        &vin.p_pubkey,
        &msgs.claim,
        &vin.auth_claim,
        EmissionAuthRole::Claim,
    )?;

    Ok(AuthVerified { _sealed: () })
}

/// One hybrid (Ed25519 + ML-DSA-65) auth verification with role-tagged
/// rejections. Lengths are already canonical (`validate` pinned them);
/// deserialization can still fail on malformed component encodings.
fn verify_hybrid_auth(
    pubkey_bytes: &[u8],
    msg: &[u8; 64],
    sig_bytes: &[u8],
    role: EmissionAuthRole,
) -> Result<(), EmissionVerifyError> {
    let Ok(pubkey) = HybridPublicKey::from_canonical_bytes(pubkey_bytes) else {
        return Err(EmissionVerifyError::AuthMalformed { role });
    };
    let Ok(sig) = HybridSignature::from_canonical_bytes(sig_bytes) else {
        return Err(EmissionVerifyError::AuthMalformed { role });
    };
    match HybridEd25519MlDsa.verify(&pubkey, msg, &sig) {
        Ok(true) => Ok(()),
        // Ok(false) and Err collapse to one rejection: the split is a
        // library-reporting detail, not a consensus distinction.
        _ => Err(EmissionVerifyError::AuthRejected { role }),
    }
}

/// The fail-closed assembly: all three witnesses, or no verdict.
///
/// Infallible by design — every fallible check already ran inside the
/// witness minters, and the types guarantee they did. C-1's dispatch calls
/// the three minters in the §7.1 fail-fast order and assembles here.
#[must_use]
pub fn emission_vin_verify(
    claims: ClaimsVerified,
    _backing: BackingVerified,
    _auth: AuthVerified,
) -> EmissionVerified {
    EmissionVerified {
        epochs_to_commit: claims.epochs_to_commit,
        total_reward: claims.total_reward,
    }
}
