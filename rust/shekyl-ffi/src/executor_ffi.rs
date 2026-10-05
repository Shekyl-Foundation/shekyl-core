// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The thread ledger's C surface.
//!
//! The socketless asio executor is one row.
//! [`ExecutorBudget::above_floor`] is its floor. This module records that
//! row and does not spawn or join. The threads are the caller's.
//! [`shekyl_thread_ledger_report`] copies every row: dedicated threads,
//! executor rows, and Tokio runtimes.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use shekyl_thread_ledger::{
    record_executor, BlockingLanes, ExecutorBudget, ExecutorRow, ThreadName,
};

static EXECUTORS: LazyLock<Mutex<HashMap<u64, ExecutorRow>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_EXECUTOR: AtomicU64 = AtomicU64::new(1);

/// Record the executor when `workers` is at least one more than `lanes`.
/// Returns 1 and writes `*out_handle` on success. Below the floor returns
/// 0 and records nothing.
///
/// # Safety
/// `name` is a non-null NUL-terminated string. `out_handle` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_executor_record(
    name: *const c_char,
    lanes: usize,
    workers: usize,
    out_handle: *mut u64,
) -> i32 {
    if name.is_null() || out_handle.is_null() {
        return 0;
    }
    let Ok(text) = unsafe { CStr::from_ptr(name) }.to_str() else {
        return 0;
    };
    let Ok(name) = ThreadName::new(text) else {
        return 0;
    };
    let Ok(budget) = ExecutorBudget::above_floor(BlockingLanes::new(lanes), workers) else {
        return 0;
    };
    let row = record_executor(&name, budget);
    let handle = NEXT_EXECUTOR.fetch_add(1, Ordering::Relaxed);
    EXECUTORS
        .lock()
        .expect("executor table")
        .insert(handle, row);
    unsafe {
        *out_handle = handle;
    }
    1
}

/// Drop the executor row. The threads are the caller's.
#[no_mangle]
pub extern "C" fn shekyl_executor_release(handle: u64) {
    EXECUTORS.lock().expect("executor table").remove(&handle);
}

/// Copy the thread-ledger report into `buf`, NUL-terminated.
///
/// Always returns the report's full byte length, excluding the NUL. A
/// null `buf` or a `len` of 0 writes nothing. A short buffer is truncated
/// and still NUL-terminated. A return greater than or equal to `len`
/// means the caller retries with a larger buffer: the return is the full
/// length, so a truncated fill is distinguishable from an exact fit.
///
/// # Safety
///
/// `buf`, when non-null and `len` is non-zero, points at `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_thread_ledger_report(buf: *mut c_char, len: usize) -> usize {
    let report = shekyl_thread_ledger::report();
    let bytes = report.as_bytes();
    if !buf.is_null() && len > 0 {
        let n = bytes.len().min(len - 1);
        // The report is not a secret. A short copy is the caller's signal
        // to retry, and the NUL keeps a C string well-formed either way.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast(), n);
            *buf.add(n) = 0;
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::shekyl_thread_ledger_report;

    /// A one-byte buffer writes only the NUL. Returning that written count
    /// (zero) is the contract this replaced. The edit that makes this red
    /// is returning the truncated count instead of the full length.
    #[test]
    fn a_short_buffer_returns_the_full_length() {
        for _ in 0..8 {
            let report = shekyl_thread_ledger::report();
            let full = report.len();
            let probed = unsafe { shekyl_thread_ledger_report(std::ptr::null_mut(), 0) };
            let mut one = [0xFFu8; 1];
            let short = unsafe { shekyl_thread_ledger_report(one.as_mut_ptr().cast(), one.len()) };
            let mut prefix = [0xFFu8; 4];
            let truncated =
                unsafe { shekyl_thread_ledger_report(prefix.as_mut_ptr().cast(), prefix.len()) };
            let mut fitted = vec![0xFFu8; full + 1];
            let written =
                unsafe { shekyl_thread_ledger_report(fitted.as_mut_ptr().cast(), fitted.len()) };
            if shekyl_thread_ledger::report() != report {
                continue;
            }
            assert!(
                full > prefix.len(),
                "the fixture report is longer than the short buffer"
            );
            assert_eq!(probed, full);
            assert_eq!(short, full);
            assert_eq!(truncated, full);
            assert_eq!(written, full);
            assert_eq!(one[0], 0, "a one-byte buffer still ends in NUL");
            assert_eq!(&prefix[..3], &report.as_bytes()[..3]);
            assert_eq!(prefix[3], 0);
            assert_eq!(&fitted[..full], report.as_bytes());
            assert_eq!(fitted[full], 0);
            return;
        }
        panic!("the ledger changed on every attempt");
    }
}
