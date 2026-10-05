// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI for the DRS-E2 trace writer — the one door the C++ LMDB exporter
//! hands bytes through (`DRS_E2_REPLAY_DRIVER.md` §3.9, RD-Q2).
//!
//! **Harvest shim, dies at cutover** (§1.3). The exporter is C++ because
//! LMDB is; everything it produces is written by Rust
//! (`shekyl_chain_ingest::trace::TraceWriter`), so the artifact's format is
//! Rust-minted (RD-F9). The checkpoint the exporter pushes is the daemon's
//! own `BlockchainLMDB::logical_state_digest_v0` — one read snapshot over
//! the three families, hashed through `shekyl_logical_state_digest_v0` by
//! the same `digest_v0` the redb side uses (RD-Q9) — so the C++ never
//! hashes and never walks a family this crate would have to walk again.
//!
//! Byte transport is what D12 allows across this boundary; verdicts are what
//! it rejected. Nothing here carries a secret; every input is a recorded
//! public fact.
//!
//! # Lifecycle
//!
//! `open` → `push_facts`* (consecutive heights) → `push_checkpoint`?
//! (at most one, at the last facts row) →
//! `finish` (writes the trailer, frees) or `abort` (frees without a
//! trailer; the file is then a truncated trace and a reader refuses it).
//! A `finish` or `abort` consumes the handle; using it afterwards is
//! undefined behaviour, as for every opaque handle in this crate.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use shekyl_chain_ingest::snapshot_json;
use shekyl_chain_ingest::trace::{Facts, TraceFault, TraceWriter};
use shekyl_chain_store::archival_snapshot::{ArchivalSnapshot, SnapshotFault};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::archival::{
    BadInterval, BondRecord, FirstPayingHeight, HeldShard, Holdings, RMarket, SigmaWorkMilli,
    SlashLogEntry, SlashedHolding,
};
use shekyl_types::{
    BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight, PCanonicalId, SettlementEpoch, ShardId,
};
use shekyl_units::AtomicUnits;

use crate::legacy_util::{array_from_ptr, slice_from_ptr, slice_from_typed_ptr};

/// Success.
pub const SHEKYL_E2_TRACE_OK: i32 = 0;
/// A required pointer was null.
pub const SHEKYL_E2_TRACE_ERR_NULL_PTR: i32 = -1;
/// Reserved: no count crosses this boundary any more (the checkpoint is a
/// finished digest). Kept so the codes the header declares stay stable.
pub const SHEKYL_E2_TRACE_ERR_OVERFLOW: i32 = -2;
/// The writer refused the record: a facts height gap, a height past
/// `u64::MAX`, a checkpoint with no facts record to anchor to, a second
/// checkpoint, facts after the checkpoint, an archival snapshot with no
/// checkpoint to pair with, a second snapshot, or a `finish` with the
/// checkpoint and not its snapshot.
pub const SHEKYL_E2_TRACE_ERR_SEQUENCE: i32 = -3;
/// The underlying file write failed.
pub const SHEKYL_E2_TRACE_ERR_IO: i32 = -4;
/// The path bytes are not UTF-8.
pub const SHEKYL_E2_TRACE_ERR_BAD_PATH: i32 = -5;
/// An archival row was refused by the snapshot's shape checks
/// (`DRS_E4_ARCHIVAL_WRITER.md` §3.8.1): a duplicate key, a second row of a
/// singleton family, an over-cap holdings list, an epoch-marker slash-log
/// sequence, an empty or over-cap witness. The C++ marshalled something the
/// Rust writer could not have stored; the builder stays usable.
pub const SHEKYL_E2_TRACE_ERR_ROW: i32 = -6;

/// Opaque trace-writer handle.
pub struct ShekylE2TraceWriter {
    inner: TraceWriter<BufWriter<File>>,
}

/// Opaque archival-snapshot builder (§3.8.1): the C++ walker marshals one
/// decoded row per call and the Rust side encodes it. Consumed by
/// [`shekyl_e2_trace_push_archival_snapshot`] or freed by
/// [`shekyl_e2_archival_snapshot_free`].
pub struct ShekylE2ArchivalSnapshot {
    inner: ArchivalSnapshot,
}

fn code(fault: &TraceFault) -> i32 {
    match fault {
        TraceFault::HeightGap { .. }
        | TraceFault::HeightExhausted { .. }
        | TraceFault::UnanchoredCheckpoint
        | TraceFault::CheckpointNotTip { .. }
        | TraceFault::DuplicateCheckpoint { .. }
        | TraceFault::FactsAfterCheckpoint { .. }
        | TraceFault::UnanchoredSnapshot
        | TraceFault::SnapshotNotTip { .. }
        | TraceFault::DuplicateSnapshot { .. }
        | TraceFault::MissingSnapshot { .. } => SHEKYL_E2_TRACE_ERR_SEQUENCE,
        TraceFault::Snapshot(_) => SHEKYL_E2_TRACE_ERR_ROW,
        // `Io` is the writer's only other fault; the reader-side arms cannot
        // come out of a writer and are reported as I/O if they ever do.
        TraceFault::Io(_)
        | TraceFault::BadMagic
        | TraceFault::UnsupportedVersion { .. }
        | TraceFault::ReservedNonZero
        | TraceFault::UnknownTag(_)
        | TraceFault::ReservedTag(_)
        | TraceFault::TrailerMismatch { .. }
        | TraceFault::Truncated
        | TraceFault::TrailingBytes => SHEKYL_E2_TRACE_ERR_IO,
    }
}

fn row_code(fault: &SnapshotFault) -> i32 {
    tracing::error!("e2 trace: archival row: {fault}");
    SHEKYL_E2_TRACE_ERR_ROW
}

/// Create the trace file at `path` (`path_len` UTF-8 bytes, not
/// NUL-terminated) and write its header. Returns null on failure, with the
/// reason logged.
///
/// # Safety
///
/// `path` must be valid for `path_len` bytes of reads for the duration of
/// the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_open(
    path: *const u8,
    path_len: usize,
) -> *mut ShekylE2TraceWriter {
    let Some(bytes) = (unsafe { slice_from_ptr(path, path_len) }) else {
        tracing::error!("e2 trace: null or oversized path");
        return std::ptr::null_mut();
    };
    let Ok(path) = std::str::from_utf8(bytes) else {
        tracing::error!("e2 trace: path is not UTF-8");
        return std::ptr::null_mut();
    };
    let file = match File::create(Path::new(path)) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("e2 trace: cannot create {path}: {e}");
            return std::ptr::null_mut();
        }
    };
    match TraceWriter::new(BufWriter::new(file)) {
        Ok(inner) => Box::into_raw(Box::new(ShekylE2TraceWriter { inner })),
        Err(e) => {
            tracing::error!("e2 trace: cannot write header to {path}: {e}");
            std::ptr::null_mut()
        }
    }
}

/// The facts for `height` (must be the next consecutive height): the six
/// recorded facts in the trace's `Facts` order (comparison inputs for the
/// replay's oracles, never handed to `connect`) and the cumulative
/// difficulty as two `u64` halves (`lo`, `hi`). `root_after` is 32 bytes.
///
/// # Safety
///
/// `writer` must be a live handle from [`shekyl_e2_trace_open`];
/// `root_after` must be valid for 32 bytes of reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_push_facts(
    writer: *mut ShekylE2TraceWriter,
    height: u64,
    weight: u64,
    long_term_weight: u64,
    coins_generated: u64,
    burned: u64,
    root_after: *const u8,
    long_term_effective_median: u64,
    cumulative_difficulty_lo: u64,
    cumulative_difficulty_hi: u64,
) -> i32 {
    if writer.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(root) = (unsafe { array_from_ptr::<32>(root_after) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `open`.
    let w = unsafe { &mut *writer };
    let facts = Facts {
        weight: BlockWeight::from_raw(weight),
        long_term_weight: LongTermWeight::from_raw(long_term_weight),
        coins_generated: AtomicUnits::from_raw(coins_generated),
        burned: AtomicUnits::from_raw(burned),
        root_after: CurveTreeRoot::from_bytes(root),
        long_term_effective_median: LongTermWeight::from_raw(long_term_effective_median),
        cumulative_difficulty: CumulativeDifficulty::from_raw(
            (u128::from(cumulative_difficulty_hi) << 64) | u128::from(cumulative_difficulty_lo),
        ),
    };
    match w.inner.push_facts(BlockHeight::from_raw(height), &facts) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: facts at {height}: {e}");
            code(&e)
        }
    }
}

/// The LMDB logical state after the last facts row (the covered tip): the
/// 32-byte `digest_v0` the daemon's own walker computed under one read
/// snapshot (`BlockchainLMDB::logical_state_digest_v0`, itself through
/// `shekyl_logical_state_digest_v0`). Height is the writer's last facts
/// row — the C++ does not name it.
///
/// # Safety
///
/// `writer` must be a live handle from [`shekyl_e2_trace_open`]; `digest`
/// must be valid for 32 bytes of reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_push_checkpoint(
    writer: *mut ShekylE2TraceWriter,
    digest: *const u8,
) -> i32 {
    if writer.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(state) = (unsafe { array_from_ptr::<32>(digest) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `open`.
    let w = unsafe { &mut *writer };
    match w.inner.push_checkpoint(&state) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: checkpoint: {e}");
            code(&e)
        }
    }
}

// ---- the archival snapshot (DRS-E4 §3.8.1) -----------------------------
//
// The C++ walker (`BlockchainLMDB::archival_snapshot_rows`) opens one read
// snapshot, cursors each archival table, decodes each row with the codec
// it already has, and calls one pusher per row with the decoded fields.
// Every encoding — the row key's little-endian integers, the `Canonical`
// value — is this side's, so the trace's bytes and redb's are one function
// (`ArchivalSnapshot`'s typed constructors). The two §3.8.1 projections the
// C++ must not forget (`r = 0` is no row; an epoch-marker slash-log
// sequence is no row) are applied here, not in C++: `push_r_market` drops
// a zero, and `push_slash_log` refuses `u32::MAX`.

/// A new, empty snapshot builder. Never null.
#[no_mangle]
pub extern "C" fn shekyl_e2_archival_snapshot_new() -> *mut ShekylE2ArchivalSnapshot {
    Box::into_raw(Box::new(ShekylE2ArchivalSnapshot {
        inner: ArchivalSnapshot::empty(),
    }))
}

/// Free a builder that was not pushed into a trace.
///
/// # Safety
///
/// `snapshot` must be a live handle from [`shekyl_e2_archival_snapshot_new`]
/// that has not been consumed by [`shekyl_e2_trace_push_archival_snapshot`],
/// not used again after this call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_free(snapshot: *mut ShekylE2ArchivalSnapshot) {
    if !snapshot.is_null() {
        // SAFETY: the caller's contract — a live, unconsumed handle.
        drop(unsafe { Box::from_raw(snapshot) });
    }
}

/// One `archival_bond` row, from the C++ `ArchivalBondValue`'s decoded
/// fields. `holdings_kind` is the record's kind byte (`0` compact, `1`
/// complete tree); `held_shards` and `add_epochs` are the compact set's two
/// index-parallel arrays of `holdings_count` each (ignored for a complete
/// tree, which holds nothing per shard); `bad_intervals` is
/// `bad_interval_count` pairs `(start_epoch, end_exclusive)` as
/// `2 × count` `u64`s; `first_paying_emission_height` is the C++ sentinel
/// form, `0` for none.
///
/// # Safety
///
/// `snapshot` must be a live handle; `persona` and `endpoint` valid for 32
/// bytes of reads; each array pointer valid for its stated count of
/// elements (a null pointer is permitted only with a zero count).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_bond(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    persona: *const u8,
    hybrid_pubkey: *const u8,
    hybrid_pubkey_len: usize,
    bond_spend_pk: *const u8,
    bond_spend_pk_len: usize,
    endpoint: *const u8,
    join_settlement_epoch: u64,
    bonded_total: u64,
    holdings_kind: u8,
    held_shards: *const u64,
    add_epochs: *const u64,
    holdings_count: usize,
    bad_intervals: *const u64,
    bad_interval_count: usize,
    claimed_epochs: *const u64,
    claimed_count: usize,
    first_paying_emission_height: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let (Some(persona), Some(endpoint)) = (unsafe { array_from_ptr::<32>(persona) }, unsafe {
        array_from_ptr::<32>(endpoint)
    }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let (Some(hybrid_pubkey), Some(bond_spend_pk)) = (
        unsafe { slice_from_ptr(hybrid_pubkey, hybrid_pubkey_len) },
        unsafe { slice_from_ptr(bond_spend_pk, bond_spend_pk_len) },
    ) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let Some(pairs) = bad_interval_count.checked_mul(2) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let (Some(held), Some(adds), Some(intervals), Some(claimed)) = (
        unsafe { slice_from_typed_ptr(held_shards, holdings_count) },
        unsafe { slice_from_typed_ptr(add_epochs, holdings_count) },
        unsafe { slice_from_typed_ptr(bad_intervals, pairs) },
        unsafe { slice_from_typed_ptr(claimed_epochs, claimed_count) },
    ) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let holdings = match holdings_kind {
        0 => {
            let held = held
                .iter()
                .zip(adds)
                .map(|(shard, add_epoch)| HeldShard {
                    shard: ShardId::from_raw(*shard),
                    add_epoch: SettlementEpoch::from_raw(*add_epoch),
                })
                .collect();
            match Holdings::shard_set(held) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("e2 trace: archival bond holdings: {e}");
                    return SHEKYL_E2_TRACE_ERR_ROW;
                }
            }
        }
        1 => Holdings::CompleteTree,
        other => {
            tracing::error!("e2 trace: archival bond holdings kind {other} names neither shape");
            return SHEKYL_E2_TRACE_ERR_ROW;
        }
    };
    let record = BondRecord {
        hybrid_pubkey: hybrid_pubkey.to_vec(),
        bond_spend_pk: bond_spend_pk.to_vec(),
        endpoint,
        join_settlement_epoch: SettlementEpoch::from_raw(join_settlement_epoch),
        bonded_total: AtomicUnits::from_raw(bonded_total),
        holdings,
        bad_intervals: intervals
            .chunks_exact(2)
            .map(|iv| BadInterval {
                start_epoch: iv[0],
                end_exclusive: iv[1],
            })
            .collect(),
        claimed_settlement_epochs: claimed
            .iter()
            .map(|e| SettlementEpoch::from_raw(*e))
            .collect(),
        first_paying_emission_height: FirstPayingHeight::new(BlockHeight::from_raw(
            first_paying_emission_height,
        )),
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s
        .inner
        .push_bond(&PCanonicalId::from_bytes(persona), &record)
    {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_serve_credit` pass bit.
///
/// # Safety
///
/// `snapshot` must be a live handle; `persona` valid for 32 bytes of reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_serve_credit(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    persona: *const u8,
    shard: u64,
    epoch: u64,
    height: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(persona) = (unsafe { array_from_ptr::<32>(persona) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.push_serve_credit(
        &PCanonicalId::from_bytes(persona),
        ShardId::from_raw(shard),
        SettlementEpoch::from_raw(epoch),
        BlockHeight::from_raw(height),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_r_market` row. A zero `r` is accepted and **not stored**
/// (§3.6's projection, applied here so the walker cannot forget it).
///
/// # Safety
///
/// `snapshot` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_r_market(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    shard: u64,
    epoch: u64,
    r: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.push_r_market(
        ShardId::from_raw(shard),
        SettlementEpoch::from_raw(epoch),
        RMarket::from_raw(r),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_sigma_work` row.
///
/// # Safety
///
/// `snapshot` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_sigma_work(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    epoch: u64,
    sigma_work_milli: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.push_sigma_work(
        SettlementEpoch::from_raw(epoch),
        SigmaWorkMilli::from_raw(sigma_work_milli),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_budget` row.
///
/// # Safety
///
/// `snapshot` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_budget(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    epoch: u64,
    budget: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.push_budget(
        SettlementEpoch::from_raw(epoch),
        AtomicUnits::from_raw(budget),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_attestation_witness` row: the stored bytes. The C++
/// stores no row for an empty attestation set, so an empty `bytes` here is
/// a walker defect and is refused as a row.
///
/// # Safety
///
/// `snapshot` must be a live handle; `bytes` valid for `len` bytes of
/// reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_attestation_witness(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    height: u64,
    bytes: *const u8,
    len: usize,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(bytes) = (unsafe { slice_from_ptr(bytes, len) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s
        .inner
        .push_attestation_witness(BlockHeight::from_raw(height), bytes)
    {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_slash_log` row, from the C++ `ArchivalSlashRevertValue`'s
/// decoded fields with the slashed amount projected out (`ARW-Q2`).
/// `holding_pre_kind` is the row's kind byte (`0` a compact set that held
/// the shard since `slashed_shard_add_epoch`, `1` a complete tree). The C++
/// epoch-marker rows (`seq = u32::MAX`) are refused as rows: the walker
/// skips them, and one that did not is caught here.
///
/// # Safety
///
/// `snapshot` must be a live handle; `persona` valid for 32 bytes of reads.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_slash_log(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    height: u64,
    seq: u32,
    persona: *const u8,
    shard: u64,
    epoch: u64,
    holding_pre_kind: u8,
    slashed_shard_add_epoch: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(persona) = (unsafe { array_from_ptr::<32>(persona) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let holding = match holding_pre_kind {
        0 => SlashedHolding::Shard {
            add_epoch: SettlementEpoch::from_raw(slashed_shard_add_epoch),
        },
        1 => SlashedHolding::CompleteTree,
        other => {
            tracing::error!("e2 trace: archival slash-log kind {other} names neither shape");
            return SHEKYL_E2_TRACE_ERR_ROW;
        }
    };
    let entry = SlashLogEntry {
        persona: PCanonicalId::from_bytes(persona),
        shard: ShardId::from_raw(shard),
        epoch: SettlementEpoch::from_raw(epoch),
        holding,
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s
        .inner
        .push_slash_log(BlockHeight::from_raw(height), seq, &entry)
    {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// One `archival_slash_applied` member.
///
/// # Safety
///
/// `snapshot` must be a live handle; `persona` valid for 32 bytes of reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_push_slash_applied(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    persona: *const u8,
    shard: u64,
    epoch: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(persona) = (unsafe { array_from_ptr::<32>(persona) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.push_slash_applied(
        &PCanonicalId::from_bytes(persona),
        ShardId::from_raw(shard),
        SettlementEpoch::from_raw(epoch),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// The open epoch's accrued total — at most once. The C++ side is the
/// checked sum of `archival_budget_accrual[h]` over the open epoch's
/// heights; a range holding none calls nothing.
///
/// # Safety
///
/// `snapshot` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_set_budget_accruing(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    epoch: u64,
    total: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s.inner.set_budget_accruing(
        SettlementEpoch::from_raw(epoch),
        AtomicUnits::from_raw(total),
    ) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// The slash watermark — at most once. The C++ `UINT64_MAX` sentinel is
/// no row (`ARW-Q11`): the walker calls nothing for it.
///
/// # Safety
///
/// `snapshot` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_set_last_slash_epoch(
    snapshot: *mut ShekylE2ArchivalSnapshot,
    epoch: u64,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &mut *snapshot };
    match s
        .inner
        .set_last_slash_epoch(SettlementEpoch::from_raw(epoch))
    {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => row_code(&e),
    }
}

/// Write the snapshot as the trace's `0x04` record, at the checkpoint's
/// height (the writer's; the C++ does not name it), and free the builder.
/// The builder is consumed whether or not this succeeds; the writer stays
/// usable.
///
/// # Safety
///
/// `writer` must be a live handle from [`shekyl_e2_trace_open`]; `snapshot`
/// a live handle from [`shekyl_e2_archival_snapshot_new`], not used again
/// after this call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_push_archival_snapshot(
    writer: *mut ShekylE2TraceWriter,
    snapshot: *mut ShekylE2ArchivalSnapshot,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live builder, consumed here.
    let snapshot = unsafe { Box::from_raw(snapshot) };
    if writer.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live handle from `open`.
    let w = unsafe { &mut *writer };
    match w.inner.push_archival_snapshot(&snapshot.inner) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: archival snapshot: {e}");
            code(&e)
        }
    }
}

/// Write the snapshot's rows as JSON at `path` (`path_len` UTF-8 bytes, not
/// NUL-terminated) — the `ARW-Q15` capture: the LMDB unit fixture's
/// archival state as committed data the Rust replayer is held to
/// (`shekyl_chain_ingest::snapshot_json`). The builder is **not** consumed.
///
/// # Safety
///
/// `snapshot` must be a live handle; `path` valid for `path_len` bytes of
/// reads.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_archival_snapshot_write_json(
    snapshot: *const ShekylE2ArchivalSnapshot,
    path: *const u8,
    path_len: usize,
) -> i32 {
    if snapshot.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let Some(bytes) = (unsafe { slice_from_ptr(path, path_len) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    let Ok(path) = std::str::from_utf8(bytes) else {
        return SHEKYL_E2_TRACE_ERR_BAD_PATH;
    };
    // SAFETY: the caller's contract — a live handle from `new`.
    let s = unsafe { &*snapshot };
    match std::fs::write(Path::new(path), snapshot_json::to_json(&s.inner)) {
        Ok(()) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: archival snapshot json to {path}: {e}");
            SHEKYL_E2_TRACE_ERR_IO
        }
    }
}

/// Write the trailer, flush, and free the handle. The handle is consumed
/// whether or not this succeeds.
///
/// # Safety
///
/// `writer` must be a live handle from [`shekyl_e2_trace_open`], not used
/// again after this call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_finish(writer: *mut ShekylE2TraceWriter) -> i32 {
    if writer.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    // SAFETY: the caller's contract — a live pointer from `open`, consumed here.
    let boxed = unsafe { Box::from_raw(writer) };
    match boxed.inner.finish() {
        Ok(_) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: finish: {e}");
            code(&e)
        }
    }
}

/// Free the handle without a trailer; the file is left truncated and a
/// reader refuses it.
///
/// # Safety
///
/// As [`shekyl_e2_trace_finish`].
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_abort(writer: *mut ShekylE2TraceWriter) {
    if !writer.is_null() {
        // SAFETY: the caller's contract — a live pointer from `open`.
        drop(unsafe { Box::from_raw(writer) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_chain_ingest::trace::Trace;
    use shekyl_chain_store::digest_v0::digest_v0;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "shekyl-e2-trace-{}-{name}.trace",
            std::process::id()
        ));
        p
    }

    #[test]
    fn a_trace_written_through_the_ffi_reads_back_through_the_two_doors() {
        let path = tmp("roundtrip");
        let s = path.to_str().expect("utf-8");
        let w = unsafe { shekyl_e2_trace_open(s.as_ptr(), s.len()) };
        assert!(!w.is_null());
        let root = [0xc1u8; 32];
        for h in 0..2u64 {
            let rc = unsafe {
                shekyl_e2_trace_push_facts(
                    w,
                    h,
                    1_000 + h,
                    900 + h,
                    50,
                    h,
                    root.as_ptr(),
                    800,
                    7,
                    1,
                )
            };
            assert_eq!(rc, SHEKYL_E2_TRACE_OK);
        }
        let state = digest_v0(&[[0x11; 32], [0x12; 32]], &[[0x21; 32]], &root);
        let rc = unsafe { shekyl_e2_trace_push_checkpoint(w, state.as_ptr()) };
        assert_eq!(rc, SHEKYL_E2_TRACE_OK);
        // A second checkpoint is refused (one, at the covered tip); the handle stays usable.
        let rc = unsafe { shekyl_e2_trace_push_checkpoint(w, state.as_ptr()) };
        assert_eq!(rc, SHEKYL_E2_TRACE_ERR_SEQUENCE);
        assert_eq!(
            unsafe { shekyl_e2_trace_push_checkpoint(w, std::ptr::null()) },
            SHEKYL_E2_TRACE_ERR_NULL_PTR
        );
        // The checkpoint's pair (§3.8.1): an empty archival snapshot — ten
        // zero counts — is emitted, never omitted.
        let snap = shekyl_e2_archival_snapshot_new();
        assert_eq!(
            unsafe { shekyl_e2_trace_push_archival_snapshot(w, snap) },
            SHEKYL_E2_TRACE_OK
        );
        assert_eq!(unsafe { shekyl_e2_trace_finish(w) }, SHEKYL_E2_TRACE_OK);

        let trace = Trace::read(File::open(&path).expect("open")).expect("read");
        let borrowed = trace.borrow(BlockHeight::from_raw(1)).expect("covered");
        assert_eq!(borrowed.value().weight, BlockWeight::from_raw(1_001));
        assert_eq!(
            borrowed.value().cumulative_difficulty,
            CumulativeDifficulty::from_raw((1u128 << 64) | 7)
        );
        let expected = trace
            .expect(BlockHeight::from_raw(1))
            .expect("checkpointed");
        assert_eq!(*expected.value(), state);
        let (at, snapshot) = trace.archival_snapshot().expect("paired snapshot");
        assert_eq!(at, BlockHeight::from_raw(1));
        assert_eq!(snapshot.value().row_count(), 0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_checkpoint_without_its_snapshot_is_refused_at_finish() {
        let path = tmp("unpaired");
        let s = path.to_str().expect("utf-8");
        let w = unsafe { shekyl_e2_trace_open(s.as_ptr(), s.len()) };
        assert!(!w.is_null());
        let root = [0xc1u8; 32];
        let rc = unsafe {
            shekyl_e2_trace_push_facts(w, 0, 1_000, 900, 50, 0, root.as_ptr(), 800, 7, 1)
        };
        assert_eq!(rc, SHEKYL_E2_TRACE_OK);
        let state = digest_v0(&[[0x11; 32]], &[], &root);
        assert_eq!(
            unsafe { shekyl_e2_trace_push_checkpoint(w, state.as_ptr()) },
            SHEKYL_E2_TRACE_OK
        );
        // `0x02` without `0x04` is one encoding of a checkpoint without the
        // other (§3.8.1's pairing); the writer refuses to seal it.
        assert_eq!(
            unsafe { shekyl_e2_trace_finish(w) },
            SHEKYL_E2_TRACE_ERR_SEQUENCE
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn nulls_bad_paths_and_aborts() {
        assert!(unsafe { shekyl_e2_trace_open(std::ptr::null(), 4) }.is_null());
        let bad = [0xffu8, 0xfe];
        assert!(unsafe { shekyl_e2_trace_open(bad.as_ptr(), 2) }.is_null());
        assert_eq!(
            unsafe {
                shekyl_e2_trace_push_facts(
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                    0,
                    0,
                    0,
                )
            },
            SHEKYL_E2_TRACE_ERR_NULL_PTR
        );
        assert_eq!(
            unsafe { shekyl_e2_trace_finish(std::ptr::null_mut()) },
            SHEKYL_E2_TRACE_ERR_NULL_PTR
        );
        let path = tmp("abort");
        let s = path.to_str().expect("utf-8");
        let w = unsafe { shekyl_e2_trace_open(s.as_ptr(), s.len()) };
        assert!(!w.is_null());
        assert_eq!(
            unsafe { shekyl_e2_trace_push_facts(w, 0, 1, 1, 1, 0, std::ptr::null(), 1, 0, 0) },
            SHEKYL_E2_TRACE_ERR_NULL_PTR
        );
        unsafe { shekyl_e2_trace_abort(w) };
        // Aborted: header only, no trailer — a reader refuses it.
        assert!(matches!(
            Trace::read(File::open(&path).expect("open")).expect_err("truncated"),
            TraceFault::Truncated
        ));
        std::fs::remove_file(&path).ok();
    }
}
