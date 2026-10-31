// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Reward-emission vin verify / extract / uniqueness FFI.

use shekyl_archival_retention::{
    emission_block_claims_unique, emission_vin_verify, emission_vin_verify_auth,
    emission_vin_verify_backing, emission_vin_verify_claims, ArchivalRewardEmissionVin,
    ClaimantBondRecord, EmissionEpochSource, EmissionVerifyContext, EmissionVerifyError,
    EpochCloseBond, EpochCloseInputs, HoldingsDescriptor, HoldingsKind, RewardCommit, ShardSet,
};
use shekyl_peer_policy::DropVerdict;

use super::epoch_close::{
    decode_epoch_rows, DecodedEpochRows, ShekylArchivalEmissionEpochSnapshot,
};

// ---------------------------------------------------------------------------
// C-1 emission-vin verify FFI (`REWARD_EMISSION_E3_GATING_ROUND.md` §9.5
// items 3–5; `REWARD_EMISSION_VIN_PLAN.md` §7.1). Two entries: a pre-parse
// extractor the C++ dispatch uses for operand gathering (bond record + epoch
// snapshots are keyed by fields inside the opaque blob), and the coarse
// verify call that runs the full §7.1 body — claims (1–5), backing (6), and
// the hybrid auth gate (8) — in one FFI crossing (`40-ffi-discipline.mdc`).
// ---------------------------------------------------------------------------

/// Verdict: the emission vin verified end-to-end.
pub const SHEKYL_EMISSION_VIN_OK: u8 = 0;
/// Required pointer was null (or an output buffer was too small).
pub const SHEKYL_EMISSION_VIN_ERR_NULL_PTR: u8 = 1;
/// The canonical bytes failed the wire parse (tag, bounds, ordering,
/// positivity, trailing bytes) or the in-memory structural re-validate.
pub const SHEKYL_EMISSION_VIN_ERR_WIRE: u8 = 2;
/// Caller marshaling is inconsistent — epoch snapshots misaligned with the
/// claimed set, malformed gather rows, or a claimant index out of range.
/// Never a claimant-attributable rejection: this is a daemon bug surfaced
/// loudly (`EmissionVerifyError::EpochSourceMisaligned` and kin).
pub const SHEKYL_EMISSION_VIN_ERR_MARSHAL: u8 = 3;
/// Step 1: a claimed epoch is not finalized at the carrying height.
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED: u8 = 4;
/// Step 1: a claimed epoch fell below the claim window (`MAX_CLAIM_AGE_W`).
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED: u8 = 5;
/// Step 2: no bond record for the claimant.
pub const SHEKYL_EMISSION_VIN_ERR_BOND_MISSING: u8 = 6;
/// Step 2: vin holdings descriptor does not match the bond record.
pub const SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH: u8 = 7;
/// Step 2: a claimed epoch precedes the claimable range for the join epoch.
pub const SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN: u8 = 8;
/// Step 3 (WS-2 read-only layer): a claimed epoch is already in the
/// pre-block claimed set.
pub const SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED: u8 = 9;
/// Step 4: the work claim contradicts the frozen as-of-`E` recompute
/// (duplicate shard, credit-bit mismatch, scarcity mismatch, or total).
pub const SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH: u8 = 10;
/// Step 5 (R1.B zero-tolerance): a per-epoch reward amount differs from the
/// three-channel recompute, or the total overflows.
pub const SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH: u8 = 11;
/// Step 5 (loud inflation check): Σ rewards != reward vout sum.
pub const SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH: u8 = 12;
/// **Retired (`PL-D3`, 2026-09-14): never emitted.** Was "revealed backing
/// pubkey does not hash to the committed leaf"; the leaf hash left the wire
/// and the binding moved into the membership-only proof (a wrong key now
/// rejects as `SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED`). The number stays
/// reserved so no later code is misread by a caller built against this table.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF: u8 = 13;
/// Step 6: membership-only proof rejected.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED: u8 = 14;
/// Step 8: an auth pubkey/signature failed hybrid deserialization.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED: u8 = 15;
/// Step 8: a hybrid auth signature rejected over its Q1 binding message.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED: u8 = 16;

/// PWD-B7: map an emission-vin FFI code onto a drop verdict.
///
/// Wire, vout-sum, backing, and auth failures describe the input. Null and
/// marshal failures are ours. Epoch/bond/work/reward codes describe our
/// chain. Unrecognised codes stay unclassified (do not sever).
#[no_mangle]
pub extern "C" fn shekyl_emission_vin_drop_verdict(code: u8) -> u8 {
    emission_vin_drop_verdict(code).to_byte()
}

fn emission_vin_drop_verdict(code: u8) -> DropVerdict {
    match code {
        SHEKYL_EMISSION_VIN_ERR_NULL_PTR | SHEKYL_EMISSION_VIN_ERR_MARSHAL => {
            DropVerdict::InternalFailure
        }
        SHEKYL_EMISSION_VIN_ERR_WIRE
        | SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH
        | SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF
        | SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED
        | SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED
        | SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED => DropVerdict::AttributableForm,
        SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED
        | SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED
        | SHEKYL_EMISSION_VIN_ERR_BOND_MISSING
        | SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH
        | SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN
        | SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED
        | SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH
        | SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH => DropVerdict::PolicyOrState,
        _ => DropVerdict::Unclassified,
    }
}

/// Pure code mapping — no re-decision (the decision-placement pin: every
/// consensus decision lives in `shekyl-archival-retention`; this collapses
/// diagnostic detail the C ABI cannot carry).
pub(crate) fn map_emission_vin_error(err: &EmissionVerifyError) -> u8 {
    use EmissionVerifyError as E;
    match err {
        E::Structural(_) => SHEKYL_EMISSION_VIN_ERR_WIRE,
        E::EpochSourceMisaligned { .. }
        | E::GatherMalformed { .. }
        | E::ClaimantIndexOutOfRange { .. } => SHEKYL_EMISSION_VIN_ERR_MARSHAL,
        E::EpochNotFinalized { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_NOT_FINALIZED,
        E::EpochClaimExpired { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_EXPIRED,
        E::BondMissing => SHEKYL_EMISSION_VIN_ERR_BOND_MISSING,
        E::HoldingsMismatch => SHEKYL_EMISSION_VIN_ERR_HOLDINGS_MISMATCH,
        E::EpochBeforeJoin { .. } => SHEKYL_EMISSION_VIN_ERR_EPOCH_BEFORE_JOIN,
        E::EpochAlreadyClaimed { .. } => SHEKYL_EMISSION_VIN_ERR_ALREADY_CLAIMED,
        E::WorkClaimDuplicateShard { .. }
        | E::ServeCreditBitMismatch { .. }
        | E::ScarcityMismatch { .. }
        | E::WorkTotalMismatch { .. } => SHEKYL_EMISSION_VIN_ERR_WORK_MISMATCH,
        E::RewardMismatch { .. } | E::RewardTotalOverflow => {
            SHEKYL_EMISSION_VIN_ERR_REWARD_MISMATCH
        }
        E::VoutSumMismatch { .. } => SHEKYL_EMISSION_VIN_ERR_VOUT_SUM_MISMATCH,
        E::BackingRejected(_) => SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED,
        E::AuthMalformed { .. } => SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED,
        E::AuthRejected { .. } => SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED,
    }
}

/// Length-exact parse of the canonical vin bytes (tag included): the wire
/// codec's own tag/bounds/ordering checks plus a trailing-bytes rejection.
fn parse_emission_vin(bytes: &[u8]) -> Result<ArchivalRewardEmissionVin, u8> {
    let mut cursor = bytes;
    let vin =
        ArchivalRewardEmissionVin::read(&mut cursor).map_err(|_| SHEKYL_EMISSION_VIN_ERR_WIRE)?;
    if !cursor.is_empty() {
        return Err(SHEKYL_EMISSION_VIN_ERR_WIRE);
    }
    Ok(vin)
}

/// Block-level intra-block cross-tx `(P, E)` uniqueness verdict
/// (`REWARD_EMISSION_E3_GATING_ROUND.md` §6.2 layer 2; decision-placement
/// pin §9.5 item 6 — C++ marshals the block's claim pairs, Rust decides).
///
/// `pairs_ptr` is a flattened array of `num_pairs` 40-byte entries:
/// `p_canonical_id[32] ‖ epoch_le[8]`, one entry per `(P, E_i)` of every
/// emission vin in the block, in block order.
///
/// Returns 1 when every pair is distinct (block passes this layer), 0 on any
/// duplicate — or on a null pointer with `num_pairs > 0` (fail closed).
///
/// # Safety
///
/// When `num_pairs > 0`, `pairs_ptr` must address `num_pairs * 40` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_emission_block_claims_unique(
    pairs_ptr: *const u8,
    num_pairs: usize,
) -> u8 {
    if num_pairs == 0 {
        return 1;
    }
    if pairs_ptr.is_null() {
        return 0;
    }
    let Some(byte_len) = num_pairs.checked_mul(40) else {
        return 0;
    };
    if byte_len > isize::MAX as usize {
        return 0;
    }
    let flat = unsafe { std::slice::from_raw_parts(pairs_ptr, byte_len) };
    let mut pairs = Vec::with_capacity(num_pairs);
    for entry in flat.chunks_exact(40) {
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&entry[..32]);
        let epoch = u64::from_le_bytes(entry[32..40].try_into().expect("8-byte chunk"));
        pairs.push((pid, epoch));
    }
    u8::from(emission_block_claims_unique(&pairs))
}

/// The full §7.1 emission verify body in one coarse FFI crossing: wire parse,
/// claims steps 1–5 over the marshaled as-of-`E` snapshots, membership-only
/// backing (step 6), and the hybrid auth gate (step 8) — assembling the three
/// sealed witnesses into the verdict. Step 7 (FCMP balance over the fee
/// `txin_to_key`s) stays with the existing C++ tx layer.
///
/// Inputs mirror the operands' production sites:
/// - `vin_ptr[0..vin_len]`: the `txin_archival_reward_emission` canonical
///   bytes, tag included (the C++ shim's opaque blob, unparsed by C++).
/// - Bond record (`bond_present`, `bond_join_settlement_epoch`,
///   `bond_holdings_*`, `claimed_epochs_*`): the claimant's **pre-block**
///   `ArchivalBondValue` fields, keyed by the extract call's
///   `P_canonical_id`. `bond_present == 0` marshals "no record" (reject) —
///   the remaining bond arguments are then ignored.
/// - `snapshots_ptr[0..snapshots_len]`: one frozen as-of-`E` snapshot per
///   claimed epoch, in claim order
///   (`BlockchainLMDB::gather_archival_emission_epoch_snapshot`), each
///   carrying the **persisted** `Σwork(E)` and `budget(E)` close rows.
/// - `tree_root`/`tree_depth`: the reference block's curve-tree root context.
/// - `signable_tx_hash`: the emission tx's signable hash (32 bytes).
/// - `reward_commits_ptr[0..reward_commits_len]`: the ordered reward vout
///   commit set as flattened 72-byte entries
///   (`commitment[32] ‖ amount_plain LE u64[8] ‖ one_time_key[32]`) — the
///   R1.A destination binding the auths signed over.
/// - `vout_reward_sum`: Σ reward vout `amount_plain` (step 5's loud compare).
///
/// On `SHEKYL_EMISSION_VIN_OK`: `*out_total_reward` is the verified Σ reward
/// (the connect arm's mint amount) and `out_epochs_ptr[0..*out_epochs_len]`
/// holds the epochs to commit via
/// `shekyl_archival_claimed_epochs_check_and_set`, in wire order. Outputs are
/// zeroed on entry; a non-zero return never leaves stale values.
///
/// # Safety
///
/// All pointers must satisfy their stated lengths for the duration of the
/// call, including each snapshot's embedded row arrays and each bond row's
/// interval buffer per its embedded lengths. `tree_root` and
/// `signable_tx_hash` must address 32 readable bytes each;
/// `out_epochs_ptr[0..epochs_cap]`, `out_epochs_len`, and `out_total_reward`
/// must be writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)] // coarse-call FFI: one crossing carries every §7.1 operand
pub unsafe extern "C" fn shekyl_emission_vin_verify(
    vin_ptr: *const u8,
    vin_len: usize,
    current_block_height: u64,
    vout_reward_sum: u64,
    bond_present: u8,
    bond_join_settlement_epoch: u64,
    bond_holdings_kind: u8,
    bond_shard_ids_ptr: *const u64,
    bond_shard_ids_len: usize,
    claimed_epochs_ptr: *const u64,
    claimed_epochs_len: usize,
    snapshots_ptr: *const ShekylArchivalEmissionEpochSnapshot,
    snapshots_len: usize,
    tree_root: *const u8,
    tree_depth: u8,
    signable_tx_hash: *const u8,
    reward_commits_ptr: *const u8,
    reward_commits_len: usize,
    out_total_reward: *mut u64,
    out_epochs_ptr: *mut u64,
    epochs_cap: usize,
    out_epochs_len: *mut usize,
) -> u8 {
    if vin_ptr.is_null()
        || vin_len == 0
        || tree_root.is_null()
        || signable_tx_hash.is_null()
        || (snapshots_ptr.is_null() && snapshots_len > 0)
        || (reward_commits_ptr.is_null() && reward_commits_len > 0)
        || out_total_reward.is_null()
        || out_epochs_ptr.is_null()
        || out_epochs_len.is_null()
    {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe {
        *out_total_reward = 0;
        *out_epochs_len = 0;
    }

    let bytes = unsafe { std::slice::from_raw_parts(vin_ptr, vin_len) };
    let vin = match parse_emission_vin(bytes) {
        Ok(vin) => vin,
        Err(code) => return code,
    };

    // Bond record marshaling (step 2/3 operands, pre-block state).
    let bond_holdings;
    let claimed_epochs: &[u64];
    let bond = if bond_present == 0 {
        None
    } else {
        if (bond_shard_ids_ptr.is_null() && bond_shard_ids_len > 0)
            || (claimed_epochs_ptr.is_null() && claimed_epochs_len > 0)
        {
            return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
        }
        let Ok(kind) = HoldingsKind::from_u8(bond_holdings_kind) else {
            return SHEKYL_EMISSION_VIN_ERR_MARSHAL;
        };
        let shard_ids_raw: Vec<u64> = if bond_shard_ids_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(bond_shard_ids_ptr, bond_shard_ids_len) }.to_vec()
        };
        // The record is trusted substrate (its holdings were built from a
        // validated vin's `ShardSet`), so re-validating here is a corruption
        // guard: an oversize/duplicate record-holdings is a marshal error.
        let Ok(shard_ids) = ShardSet::new(shard_ids_raw) else {
            return SHEKYL_EMISSION_VIN_ERR_MARSHAL;
        };
        bond_holdings = HoldingsDescriptor { kind, shard_ids };
        claimed_epochs = if claimed_epochs_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(claimed_epochs_ptr, claimed_epochs_len) }
        };
        Some(ClaimantBondRecord {
            join_settlement_epoch: bond_join_settlement_epoch,
            holdings: &bond_holdings,
            claimed_settlement_epochs: claimed_epochs,
        })
    };

    // Snapshot decode: owned rows first, then the borrowing source structs
    // (EpochCloseInputs borrows the bond/shard/pair rows; the two-pass shape
    // keeps every borrow anchored to this frame).
    let raw_snaps: &[ShekylArchivalEmissionEpochSnapshot] = if snapshots_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(snapshots_ptr, snapshots_len) }
    };
    let mut decoded = Vec::with_capacity(raw_snaps.len());
    for snap in raw_snaps {
        let rows = match unsafe {
            decode_epoch_rows(
                snap.bonds_ptr,
                snap.bonds_len,
                snap.shards_ptr,
                snap.shards_len,
                snap.credit_pairs_ptr,
                snap.credit_pairs_len,
            )
        } {
            Ok(rows) => rows,
            Err(_) => return SHEKYL_EMISSION_VIN_ERR_MARSHAL,
        };
        decoded.push(rows);
    }
    let bonds_per: Vec<Vec<EpochCloseBond<'_>>> =
        decoded.iter().map(DecodedEpochRows::bonds).collect();
    let sources: Vec<EmissionEpochSource<'_>> = raw_snaps
        .iter()
        .zip(&decoded)
        .zip(&bonds_per)
        .map(|((snap, rows), bonds)| EmissionEpochSource {
            // Single-sourced verify-view construction (constants + stubbed
            // close-only M1 operands) — see `EpochCloseInputs::verify_view`.
            inputs: EpochCloseInputs::verify_view(
                snap.settlement_epoch,
                snap.close_block_height,
                bonds,
                &rows.shards,
                &rows.pairs,
            ),
            persisted_sigma_work_milli: snap.sigma_work_milli,
            claimant_bond_idx: (snap.claimant_bond_idx != usize::MAX)
                .then_some(snap.claimant_bond_idx),
            budget: snap.budget_atomic,
        })
        .collect();

    let ctx = EmissionVerifyContext {
        current_block_height,
        bond,
        vout_reward_sum,
    };

    // Auth context: the ordered reward vout commit set, flattened 72-byte
    // entries (commitment ‖ amount LE ‖ one-time key).
    let commits_bytes: &[u8] = if reward_commits_len == 0 {
        &[]
    } else {
        let Some(flat_len) = reward_commits_len.checked_mul(72) else {
            return SHEKYL_EMISSION_VIN_ERR_MARSHAL;
        };
        unsafe { std::slice::from_raw_parts(reward_commits_ptr, flat_len) }
    };
    let reward_commits: Vec<RewardCommit> = commits_bytes
        .chunks_exact(72)
        .map(|chunk| RewardCommit {
            commitment: chunk[0..32].try_into().expect("32-byte slice"),
            amount_plain: u64::from_le_bytes(chunk[32..40].try_into().expect("8-byte slice")),
            one_time_key: chunk[40..72].try_into().expect("32-byte slice"),
        })
        .collect();

    let tree_root_arr: [u8; 32] = unsafe { *tree_root.cast::<[u8; 32]>() };
    let tx_hash_arr: [u8; 32] = unsafe { *signable_tx_hash.cast::<[u8; 32]>() };

    // Fail-fast minting of the three sealed witnesses. Claims (steps 1–5)
    // first, then the hybrid auth gate (step 8) *before* the membership-only
    // backing (step 6): the auths are orders of magnitude cheaper than the
    // FCMP proof, so a forged vin is rejected before the expensive
    // verification (DoS ordering — not consensus-visible, since every
    // ordering rejects the same vins, and the verdict still requires all
    // three witnesses).
    let claims = match emission_vin_verify_claims(&vin, &ctx, &sources) {
        Ok(claims) => claims,
        Err(e) => return map_emission_vin_error(&e),
    };
    let auth = match emission_vin_verify_auth(&vin, &reward_commits, &tx_hash_arr) {
        Ok(auth) => auth,
        Err(e) => return map_emission_vin_error(&e),
    };
    let backing = match emission_vin_verify_backing(&vin, &tree_root_arr, tree_depth, tx_hash_arr) {
        Ok(backing) => backing,
        Err(e) => return map_emission_vin_error(&e),
    };
    let verdict = emission_vin_verify(claims, backing, auth);

    if verdict.epochs_to_commit.len() > epochs_cap {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            verdict.epochs_to_commit.as_ptr(),
            out_epochs_ptr,
            verdict.epochs_to_commit.len(),
        );
        *out_epochs_len = verdict.epochs_to_commit.len();
        *out_total_reward = verdict.total_reward;
    }
    SHEKYL_EMISSION_VIN_OK
}

/// `epoch` was inserted into the claimed set (and stale entries pruned).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED: u8 = 0;
/// `epoch` was already claimed — the connect path treats this as a hard
/// error, never a soft skip (WS-2 §6.2: verify's contains-check plus the
/// block-level `(P,E)` pass foreclose it; reaching it means a dedup layer
/// was bypassed).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED: u8 = 1;
/// `epoch >= current_settled_epoch`: not yet settled, unclaimable.
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED: u8 = 2;
/// `epoch` has fallen below the claim window (`MAX_CLAIM_AGE_W`).
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED: u8 = 3;
/// Null pointer, capacity overflow, or a set that is not strictly increasing.
pub const SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID: u8 = 4;

#[cfg(test)]
mod tests {
    /// The C++ header's `SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS` sizes the
    /// epoch buffers its callers hand [`super::shekyl_archival_emission_vin_extract`];
    /// it is a hand-written mirror of the generated
    /// [`shekyl_archival_retention::MAX_SETTLEMENT_EPOCHS_PER_EMISSION`]. A key
    /// raised without the header would make every C++ caller's buffer too short
    /// for a vin the parse accepts, so the extract would refuse it on capacity.
    #[test]
    fn the_headers_epoch_buffer_is_the_wire_cap() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/shekyl/shekyl_ffi.h");
        let header = std::fs::read_to_string(&path).expect("the emission entry's header");
        let mut defined = None;
        for line in header.lines() {
            let mut words = line.split_whitespace();
            if words.next() == Some("#define")
                && words.next() == Some("SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS")
            {
                let value = words.next().expect("the define carries a value");
                defined = Some(value.parse::<usize>().expect("a decimal cap"));
            }
        }
        assert_eq!(
            defined,
            Some(shekyl_archival_retention::MAX_SETTLEMENT_EPOCHS_PER_EMISSION),
            "SHEKYL_EMISSION_MAX_SETTLEMENT_EPOCHS in shekyl_ffi.h"
        );
    }
}
