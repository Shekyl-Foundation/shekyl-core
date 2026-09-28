// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The socketless asio executor, as one ledger row.
//!
//! [`ExecutorBudget::above_floor`] is the floor. This module records the
//! row and does not spawn or join. The threads are the caller's.

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
