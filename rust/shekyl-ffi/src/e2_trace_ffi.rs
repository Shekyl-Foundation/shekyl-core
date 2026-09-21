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
//! Rust-minted (RD-F9) and its checkpoints are hashed by the same function
//! the redb side uses (RD-Q9) — the C++ never hashes.
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

use shekyl_chain_ingest::trace::{Facts, TraceFault, TraceWriter};
use shekyl_difficulty::CumulativeDifficulty;
use shekyl_types::{BlockHeight, BlockWeight, CurveTreeRoot, LongTermWeight};
use shekyl_units::AtomicUnits;

use crate::legacy_util::{array_from_ptr, slice_from_ptr};

/// Success.
pub const SHEKYL_E2_TRACE_OK: i32 = 0;
/// A required pointer was null.
pub const SHEKYL_E2_TRACE_ERR_NULL_PTR: i32 = -1;
/// A count overflowed `usize` when widened to bytes.
pub const SHEKYL_E2_TRACE_ERR_OVERFLOW: i32 = -2;
/// The writer refused the record: a facts height gap, a checkpoint with no
/// facts record to anchor to, or a second checkpoint at one height.
pub const SHEKYL_E2_TRACE_ERR_SEQUENCE: i32 = -3;
/// The underlying file write failed.
pub const SHEKYL_E2_TRACE_ERR_IO: i32 = -4;
/// The path bytes are not UTF-8.
pub const SHEKYL_E2_TRACE_ERR_BAD_PATH: i32 = -5;

/// Opaque trace-writer handle.
pub struct ShekylE2TraceWriter {
    inner: TraceWriter<BufWriter<File>>,
}

fn code(fault: &TraceFault) -> i32 {
    match fault {
        TraceFault::HeightGap { .. }
        | TraceFault::UnanchoredCheckpoint
        | TraceFault::CheckpointNotTip { .. }
        | TraceFault::DuplicateCheckpoint { .. }
        | TraceFault::FactsAfterCheckpoint { .. } => SHEKYL_E2_TRACE_ERR_SEQUENCE,
        // `Io` is the writer's only other fault; the reader-side arms cannot
        // come out of a writer and are reported as I/O if they ever do.
        TraceFault::Io(_)
        | TraceFault::BadMagic
        | TraceFault::UnsupportedVersion { .. }
        | TraceFault::ReservedNonZero
        | TraceFault::UnknownTag(_)
        | TraceFault::ReservedTag(_)
        | TraceFault::TrailerMismatch { .. }
        | TraceFault::Truncated => SHEKYL_E2_TRACE_ERR_IO,
    }
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
/// passed-through facts in `ConnectFacts` order and the cumulative
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

/// The LMDB logical state after the last facts row (the covered tip), from
/// the three families the exporter walked: `n_blocks` concatenated 32-byte
/// block hashes in height order, `n_spent` concatenated 32-byte key images
/// in any order, the 32-byte live root. Hashed here, never by the caller.
/// Height is the writer's last facts row — the C++ does not name it.
///
/// # Safety
///
/// `writer` must be a live handle; `block_hashes` / `spent_keys` may be null
/// only when the corresponding count is 0 and must otherwise be valid for
/// `count * 32` bytes of reads; `curve_root` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_e2_trace_push_checkpoint(
    writer: *mut ShekylE2TraceWriter,
    block_hashes: *const u8,
    n_blocks: u64,
    spent_keys: *const u8,
    n_spent: u64,
    curve_root: *const u8,
) -> i32 {
    if writer.is_null() {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    }
    let blocks = match unsafe { hashes_from_raw(block_hashes, n_blocks) } {
        Ok(s) => s,
        Err(c) => return c,
    };
    let spent = match unsafe { hashes_from_raw(spent_keys, n_spent) } {
        Ok(s) => s,
        Err(c) => return c,
    };
    let Some(root) = (unsafe { array_from_ptr::<32>(curve_root) }) else {
        return SHEKYL_E2_TRACE_ERR_NULL_PTR;
    };
    // SAFETY: the caller's contract — a live handle from `open`.
    let w = unsafe { &mut *writer };
    match w
        .inner
        .push_checkpoint_families(blocks, spent, CurveTreeRoot::from_bytes(root))
    {
        Ok(_) => SHEKYL_E2_TRACE_OK,
        Err(e) => {
            tracing::error!("e2 trace: checkpoint: {e}");
            code(&e)
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

/// Borrow `n` concatenated 32-byte hashes (the digest FFI's seam, SA-R-7).
///
/// # Safety
///
/// `ptr` valid for `n * 32` bytes when `n > 0`.
unsafe fn hashes_from_raw<'a>(ptr: *const u8, n: u64) -> Result<&'a [[u8; 32]], i32> {
    if n == 0 {
        return Ok(&[]);
    }
    let count = usize::try_from(n).map_err(|_| SHEKYL_E2_TRACE_ERR_OVERFLOW)?;
    let byte_len = count.checked_mul(32).ok_or(SHEKYL_E2_TRACE_ERR_OVERFLOW)?;
    let Some(bytes) = (unsafe { slice_from_ptr(ptr, byte_len) }) else {
        return Err(if ptr.is_null() {
            SHEKYL_E2_TRACE_ERR_NULL_PTR
        } else {
            SHEKYL_E2_TRACE_ERR_OVERFLOW
        });
    };
    let (chunks, rem) = bytes.as_chunks::<32>();
    debug_assert!(rem.is_empty(), "byte_len is a multiple of 32");
    Ok(chunks)
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
        let hashes = [[0x11u8; 32], [0x12u8; 32]].concat();
        let spent = [0x21u8; 32];
        let rc = unsafe {
            shekyl_e2_trace_push_checkpoint(w, hashes.as_ptr(), 2, spent.as_ptr(), 1, root.as_ptr())
        };
        assert_eq!(rc, SHEKYL_E2_TRACE_OK);
        // A second checkpoint is refused (one, at the covered tip); the handle stays usable.
        let rc = unsafe {
            shekyl_e2_trace_push_checkpoint(w, hashes.as_ptr(), 2, spent.as_ptr(), 1, root.as_ptr())
        };
        assert_eq!(rc, SHEKYL_E2_TRACE_ERR_SEQUENCE);
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
        assert_eq!(
            *expected.value(),
            digest_v0(&[[0x11; 32], [0x12; 32]], &[[0x21; 32]], &root)
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
