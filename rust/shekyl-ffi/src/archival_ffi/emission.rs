// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Reward-emission vin verify / extract / uniqueness FFI.

use shekyl_archival_retention::{
    as_of_e_served_work, bond_post_block_unique, claimed_epochs_check_and_set, credited_work_milli,
    emission_block_claims_unique, emission_vin_verify, emission_vin_verify_auth,
    emission_vin_verify_backing, emission_vin_verify_claims, p_canonical_id_from_hybrid_pubkey,
    ArchivalRewardEmissionVin, ClaimantBondRecord, ClaimedEpochsError, EmissionEpochSource,
    EmissionVerifyContext, EmissionVerifyError, EpochCloseBond, EpochCloseInputs,
    HoldingsDescriptor, HoldingsKind, RewardCommit, ShardSet, MAX_CLAIMED_EPOCH_ENTRIES,
};

use super::epoch_close::{
    decode_epoch_rows, DecodedEpochRows, ShekylArchivalEmissionEpochSnapshot,
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE, SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR,
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK,
};

/// Claimant work over the as-of-`E` snapshot: `work_P(E)` milli and its
/// membership-gated credited term — the emission verify numerator
/// (`REWARD_EMISSION_VIN_PLAN.md` §8.0.2 step 4).
///
/// Sources via [`as_of_e_served_work`], the same single sourcing function
/// whose output built the persisted `Σwork(E)` denominator at close, over the
/// same frozen gather — so `out_credited_work_milli` is `P`'s exact per-P term
/// of that denominator by construction (WS-1 §5.5: sourcing divergence, the
/// M-2 silent over/under-mint, is unrepresentable rather than tested-against).
/// This is the numerator only — it does not read `snapshot.sigma_work_milli`,
/// so an empty epoch persists
/// `Σwork(E) == 0` while this may return a positive credited term; the consumer
/// divides through the persisted denominator (reward is 0 at `Σwork(E) == 0`,
/// enforced by `reward_share_floor`).
///
/// Both outputs are zero when `claimant_bond_idx == SIZE_MAX` (no credit row
/// for `P` in `E`) or when `P` is not a market member at `E` (foundation
/// complete-tree, joined too late, or a bad interval covering `E`). Errors
/// reuse the `SHEKYL_ARCHIVAL_EPOCH_CLOSE_*` codes; outputs are zeroed before
/// computation so a failure never leaves stale values.
///
/// # Safety
///
/// `snapshot` must point to a valid struct whose array pointers satisfy their
/// stated lengths for the duration of the call, including each bond's
/// interval buffer per its embedded lengths. `out_work_milli` and
/// `out_credited_work_milli` must be writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_emission_epoch_work(
    snapshot: *const ShekylArchivalEmissionEpochSnapshot,
    out_work_milli: *mut u64,
    out_credited_work_milli: *mut u64,
) -> u8 {
    if snapshot.is_null() || out_work_milli.is_null() || out_credited_work_milli.is_null() {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_NULL_PTR;
    }
    unsafe {
        *out_work_milli = 0;
        *out_credited_work_milli = 0;
    }
    let snap = unsafe { &*snapshot };

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
        Err(code) => return code,
    };

    if snap.claimant_bond_idx == usize::MAX {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK;
    }
    if snap.claimant_bond_idx >= rows.joins.len() {
        return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE;
    }

    let bonds = rows.bonds();
    // Single-sourced verify-view construction (constants + stubbed close-only
    // M1 operands) — see `EpochCloseInputs::verify_view`.
    let inputs = EpochCloseInputs::verify_view(
        snap.settlement_epoch,
        snap.close_block_height,
        &bonds,
        &rows.shards,
        &rows.pairs,
    );
    let served = match as_of_e_served_work(&inputs) {
        Ok(served) => served,
        Err(_) => return SHEKYL_ARCHIVAL_EPOCH_CLOSE_ERR_INDEX_RANGE,
    };

    let work = served.work_by_bond[snap.claimant_bond_idx];
    // Single-sourced per-P credited term: non-members contribute nothing to
    // the stored denominator, so their credited term is zero here too.
    let credited = credited_work_milli(work, served.member[snap.claimant_bond_idx]);
    unsafe {
        *out_work_milli = work;
        *out_credited_work_milli = credited;
    }
    SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK
}

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
/// Step 6: revealed backing pubkey does not hash to the committed leaf.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF: u8 = 13;
/// Step 6: membership-only proof rejected.
pub const SHEKYL_EMISSION_VIN_ERR_BACKING_REJECTED: u8 = 14;
/// Step 8: an auth pubkey/signature failed hybrid deserialization.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_MALFORMED: u8 = 15;
/// Step 8: a hybrid auth signature rejected over its Q1 binding message.
pub const SHEKYL_EMISSION_VIN_ERR_AUTH_REJECTED: u8 = 16;

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
        E::BackingLeafMismatch => SHEKYL_EMISSION_VIN_ERR_BACKING_LEAF,
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

/// Pre-parse extractor for the C++ dispatch's operand gathering: parses the
/// opaque `txin_archival_reward_emission` bytes and surfaces the two fields
/// the daemon needs **before** it can marshal the verify call — the
/// claimant's `P_canonical_id` (bond-record key, recomputed from `P_pubkey`
/// per emission §6.1) and the claimed `settlement_epochs` (one as-of-`E`
/// snapshot gather per entry).
///
/// Extraction implies nothing about validity beyond the wire parse; the
/// verify call re-parses and re-validates the same bytes (the blob, not this
/// call's outputs, is the consensus input).
///
/// `out_epochs_ptr` must address `epochs_cap ≥ MAX_SETTLEMENT_EPOCHS_PER_EMISSION`
/// writable `u64`s (the parse rejects longer sets, so that capacity is always
/// sufficient).
///
/// # Safety
///
/// `vin_ptr[0..vin_len]` must be readable; `out_p_canonical_id` must address
/// 32 writable bytes; `out_epochs_ptr[0..epochs_cap]` and `out_epochs_len`
/// must be writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_emission_vin_extract(
    vin_ptr: *const u8,
    vin_len: usize,
    out_p_canonical_id: *mut u8,
    out_epochs_ptr: *mut u64,
    epochs_cap: usize,
    out_epochs_len: *mut usize,
) -> u8 {
    if vin_ptr.is_null()
        || vin_len == 0
        || out_p_canonical_id.is_null()
        || out_epochs_ptr.is_null()
        || out_epochs_len.is_null()
    {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }
    unsafe { *out_epochs_len = 0 };

    let bytes = unsafe { std::slice::from_raw_parts(vin_ptr, vin_len) };
    let vin = match parse_emission_vin(bytes) {
        Ok(vin) => vin,
        Err(code) => return code,
    };
    if vin.settlement_epochs.len() > epochs_cap {
        return SHEKYL_EMISSION_VIN_ERR_NULL_PTR;
    }

    let pid = p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey);
    unsafe {
        std::ptr::copy_nonoverlapping(pid.as_bytes().as_ptr(), out_p_canonical_id, 32);
        std::ptr::copy_nonoverlapping(
            vin.settlement_epochs.as_ptr(),
            out_epochs_ptr,
            vin.settlement_epochs.len(),
        );
        *out_epochs_len = vin.settlement_epochs.len();
    }
    SHEKYL_EMISSION_VIN_OK
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

/// Block-level intra-block cross-tx bond-post uniqueness verdict — at most
/// one bond-post vin per `P_canonical_id` per block (gate-4 §3.5; the
/// emission `(P, E)` pass's sibling above, keyed on `P` alone). Per-tx verify
/// runs against pre-block DB state, so every same-`P` same-block pair passes
/// it independently; this pass is the layer that rejects the block. C++ only
/// marshals the ids; the verdict is decided in
/// `shekyl-archival-retention::bond_post::bond_post_block_unique`.
///
/// `ids_ptr` is a flattened array of `num_ids` 32-byte `P_canonical_id`
/// entries, one per bond-post vin in the block, in block order.
///
/// Returns 1 when every id is distinct (block passes this layer), 0 on any
/// duplicate — or on a null pointer with `num_ids > 0` (fail closed).
///
/// # Safety
///
/// When `num_ids > 0`, `ids_ptr` must address `num_ids * 32` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_bond_post_block_unique(
    ids_ptr: *const u8,
    num_ids: usize,
) -> u8 {
    if num_ids == 0 {
        return 1;
    }
    if ids_ptr.is_null() {
        return 0;
    }
    let Some(byte_len) = num_ids.checked_mul(32) else {
        return 0;
    };
    if byte_len > isize::MAX as usize {
        return 0;
    }
    let flat = unsafe { std::slice::from_raw_parts(ids_ptr, byte_len) };
    let mut ids = Vec::with_capacity(num_ids);
    for entry in flat.chunks_exact(32) {
        let mut pid = [0u8; 32];
        pid.copy_from_slice(entry);
        ids.push(pid);
    }
    u8::from(bond_post_block_unique(&ids))
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

/// Record `epoch` as claimed in the caller-owned claimed-epoch buffer — the
/// **single writer** for `ArchivalBondValue::claimed_settlement_epochs`
/// (WS-2 §6.2; the read side is `claimed_epochs_contains` on the verify
/// path). Wraps [`claimed_epochs_check_and_set`]: window maintenance
/// (prune below `current_settled_epoch − W`) happens on insert, so the
/// buffer contents *and* length change on success.
///
/// `set_ptr[0..*set_len_ptr]` is the strictly increasing claimed set on
/// entry; on `INSERTED` the updated set is written back in place and
/// `*set_len_ptr` holds the new length (never exceeding the entry cap, so
/// a `MAX_CLAIMED_EPOCH_ENTRIES`-sized buffer is always sufficient). On any
/// other return the buffer and length are unchanged.
///
/// # Safety
///
/// `set_ptr` must address `set_cap` valid, writable `u64`s; `set_len_ptr`
/// must be a valid writable `usize` pointer with `*set_len_ptr <= set_cap`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_archival_claimed_epochs_check_and_set(
    set_ptr: *mut u64,
    set_len_ptr: *mut usize,
    set_cap: usize,
    epoch: u64,
    current_settled_epoch: u64,
) -> u8 {
    if set_ptr.is_null() || set_len_ptr.is_null() {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    let len = unsafe { *set_len_ptr };
    // Value-preserving: MAX_CLAIMED_EPOCH_ENTRIES is const-asserted == 32,
    // which fits in usize on every supported target.
    #[allow(clippy::cast_possible_truncation)]
    if len > set_cap || set_cap > MAX_CLAIMED_EPOCH_ENTRIES as usize {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    let mut set: Vec<u64> = unsafe { std::slice::from_raw_parts(set_ptr, len) }.to_vec();
    // The at-rest codec enforces strict ordering; re-check here so a
    // corrupted buffer cannot silently satisfy the binary-search contract.
    if !set.windows(2).all(|w| w[0] < w[1]) {
        return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
    }
    match claimed_epochs_check_and_set(&mut set, epoch, current_settled_epoch) {
        Ok(true) => {
            // Fail closed rather than overrun: the window prune bounds the set
            // below `set_cap` in practice, but a debug_assert vanishes in
            // release, so guard the write at runtime — an insert that grew the
            // set past the caller's buffer is a structured error, never a
            // copy_nonoverlapping past the end.
            if set.len() > set_cap {
                return SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_INVALID;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(set.as_ptr(), set_ptr, set.len());
                *set_len_ptr = set.len();
            }
            SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED
        }
        Ok(false) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED,
        Err(ClaimedEpochsError::NotSettled) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_NOT_SETTLED,
        Err(ClaimedEpochsError::Expired) => SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ERR_EXPIRED,
    }
}
