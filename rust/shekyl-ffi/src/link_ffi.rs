// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The operator's link budget at the C boundary.
//!
//! Rates are KiB/s. The budget stores bytes per second. Activity is the
//! monotonic instant of the last byte, not a grant. The stall check reads
//! [`shekyl_monotonic_ms`] and [`shekyl_recv_mark_ms`] beside
//! [`shekyl_link_activity`].

use shekyl_capped_stream::{monotonic_ms, node_gate, recv_mark_ms};

/// The operator rate is KiB/s. The budget stores bytes per second.
const BYTES_PER_KIB: u64 = 1024;

fn store_rate(kbps: i64, set: impl Fn(Option<u64>)) {
    if kbps < 0 {
        set(None);
    } else {
        let kbps = u64::try_from(kbps).unwrap_or(0);
        set(Some(kbps.saturating_mul(BYTES_PER_KIB)));
    }
}

fn load_rate(rate: Option<u64>) -> i64 {
    match rate {
        None => -1,
        Some(bytes) => i64::try_from(bytes / BYTES_PER_KIB).unwrap_or(i64::MAX),
    }
}

/// `kbps` negative removes the up bucket. Zero or positive is KiB/s.
#[no_mangle]
pub extern "C" fn shekyl_link_set_up(kbps: i64) {
    store_rate(kbps, |rate| node_gate().set_up(rate));
}

/// `kbps` negative removes the down bucket. Zero or positive is KiB/s.
#[no_mangle]
pub extern "C" fn shekyl_link_set_down(kbps: i64) {
    store_rate(kbps, |rate| node_gate().set_down(rate));
}

/// The up rate in KiB/s, or -1 when that direction is unlimited.
#[no_mangle]
pub extern "C" fn shekyl_link_get_up() -> i64 {
    load_rate(node_gate().rate_up())
}

/// The down rate in KiB/s, or -1 when that direction is unlimited.
#[no_mangle]
pub extern "C" fn shekyl_link_get_down() -> i64 {
    load_rate(node_gate().rate_down())
}

/// Bytes and packets the budget has moved. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_totals(
    bytes_down: *mut u64,
    packets_down: *mut u64,
    bytes_up: *mut u64,
    packets_up: *mut u64,
) {
    let observed = node_gate().totals();
    unsafe {
        if !bytes_down.is_null() {
            *bytes_down = observed.bytes_down;
        }
        if !packets_down.is_null() {
            *packets_down = observed.packets_down;
        }
        if !bytes_up.is_null() {
            *bytes_up = observed.bytes_up;
        }
        if !packets_up.is_null() {
            *packets_up = observed.packets_up;
        }
    }
}

/// Bytes per second on this connection, from the engine's clock, over
/// the link budget's recent-speed window. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_speed(
    id: u64,
    bytes_per_sec_up: *mut u64,
    bytes_per_sec_down: *mut u64,
) {
    let (up, down) = node_gate().speed(id);
    unsafe {
        if !bytes_per_sec_up.is_null() {
            *bytes_per_sec_up = up;
        }
        if !bytes_per_sec_down.is_null() {
            *bytes_per_sec_down = down;
        }
    }
}

/// Bytes this connection has moved. Null pointers are skipped.
#[no_mangle]
pub extern "C" fn shekyl_link_connection(id: u64, bytes_up: *mut u64, bytes_down: *mut u64) {
    let observed = node_gate().connection(id);
    unsafe {
        if !bytes_up.is_null() {
            *bytes_up = observed.bytes_up;
        }
        if !bytes_down.is_null() {
            *bytes_down = observed.bytes_down;
        }
    }
}

/// Monotonic milliseconds of the last byte read or written. A grant is
/// not a byte. Zero until that direction has moved one. Null pointers
/// are skipped. The stall check uses this with [`shekyl_monotonic_ms`].
#[no_mangle]
pub extern "C" fn shekyl_link_activity(id: u64, last_send_ms: *mut u64, last_recv_ms: *mut u64) {
    let (send, recv) = node_gate().activity(id);
    unsafe {
        if !last_send_ms.is_null() {
            *last_send_ms = send;
        }
        if !last_recv_ms.is_null() {
            *last_recv_ms = recv;
        }
    }
}

/// The same instants as unix milliseconds, for the operator view.
/// Zero stays zero. The stall check does not call this.
#[no_mangle]
pub extern "C" fn shekyl_link_unix_ms(id: u64, last_send_ms: *mut u64, last_recv_ms: *mut u64) {
    let (send, recv) = node_gate().activity_unix(id);
    unsafe {
        if !last_send_ms.is_null() {
            *last_send_ms = send;
        }
        if !last_recv_ms.is_null() {
            *last_recv_ms = recv;
        }
    }
}

/// Milliseconds on the monotonic clock the byte stamps use.
#[no_mangle]
pub extern "C" fn shekyl_monotonic_ms() -> u64 {
    monotonic_ms()
}

/// The stall mark. A receive instant of zero uses admission.
#[no_mangle]
pub extern "C" fn shekyl_recv_mark_ms(recv_ms: u64, started_ms: u64) -> u64 {
    recv_mark_ms(recv_ms, started_ms)
}
