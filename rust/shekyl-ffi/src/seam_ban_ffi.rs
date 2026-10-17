// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Ban list FFI. The C names and the 96-byte view stay what the header
//! publishes. The list itself is the transport layer's, read through the
//! seam's process sockets and, when a hub is bound, through that hub.

use std::ffi::{c_char, CStr};
use std::net::{IpAddr, Ipv4Addr};

use shekyl_seam::{deadline_after, BanLeft, Ipv4Subnet, ListedBan};

use super::{ban_now, hub, process_sockets};

/// One ban, as `getbans` reads it. `text` is a host or `address/prefix`.
/// `permanent` is 1 when the ban has no deadline. `remaining_ns` is
/// time left on a deadline, and 0 when the ban is permanent.
#[repr(C)]
pub struct ShekylBanView {
    /// 1 is a host, 2 is an IPv4 subnet.
    pub kind: u8,
    /// 1 when the ban has no deadline.
    pub permanent: u8,
    pub _pad: [u8; 6],
    /// NUL-terminated. Unused bytes are zero.
    pub text: [c_char; 80],
    /// Nanoseconds until the deadline. Zero when `permanent` is 1.
    pub remaining_ns: u64,
}

const _: () = assert!(std::mem::size_of::<ShekylBanView>() == 96);

const BAN_KIND_HOST: u8 = 1;
const BAN_KIND_SUBNET: u8 = 2;

fn c_text(text: *const c_char) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let raw = unsafe { CStr::from_ptr(text) };
    raw.to_str().ok().map(str::to_owned)
}

fn parse_subnet(text: &str) -> Option<Ipv4Subnet> {
    let (addr, prefix) = text.split_once('/')?;
    let addr: Ipv4Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    Ipv4Subnet::new(addr, prefix)
}

fn fill_text(text: &str) -> Option<[c_char; 80]> {
    let bytes = text.as_bytes();
    if bytes.len() >= 80 {
        return None;
    }
    let mut out: [c_char; 80] = [0; 80];
    for (slot, &byte) in out.iter_mut().zip(bytes) {
        *slot = c_char::from_ne_bytes([byte]);
    }
    Some(out)
}

/// Ban `text` for `duration_ns` from the process clock.
///
/// `subnet` nonzero reads `text` as `address/prefix`. Returns 0 when the
/// duration fits, -1 when it does not, and -2 when `text` is not that
/// address. A duration that is already covered by a later deadline is
/// still 0: the list does not shorten.
///
/// When a hub is bound, the ban closes the sockets the list drops.
///
/// # Safety
/// `text` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ban_for(text: *const c_char, subnet: i32, duration_ns: u64) -> i32 {
    let Some(text) = c_text(text) else {
        return -2;
    };
    let now = ban_now();
    let Some(until) = deadline_after(now, duration_ns) else {
        return -1;
    };
    if subnet != 0 {
        let Some(prefix) = parse_subnet(&text) else {
            return -2;
        };
        if let Some(hub) = hub() {
            let _closed = hub.ban_subnet(prefix, until);
        } else {
            let _closed = process_sockets().ban_subnet(prefix, until, now);
        }
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        if let Some(hub) = hub() {
            let _closed = hub.ban_host(host, until);
        } else {
            let _closed = process_sockets().ban_host(host, until, now);
        }
    }
    0
}

/// Ban `text` until it is lifted. No deadline is stored.
///
/// `subnet` nonzero reads `text` as `address/prefix`. Returns 0 when the
/// ban is stored or was already permanent, and -2 when `text` is not that
/// address. A bound hub closes the sockets the new ban drops.
///
/// # Safety
/// `text` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ban_permanent(text: *const c_char, subnet: i32) -> i32 {
    let Some(text) = c_text(text) else {
        return -2;
    };
    if subnet != 0 {
        let Some(prefix) = parse_subnet(&text) else {
            return -2;
        };
        if let Some(hub) = hub() {
            let _closed = hub.ban_subnet_permanent(prefix);
        } else {
            let _closed = process_sockets().ban_subnet_permanent(prefix);
        }
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        if let Some(hub) = hub() {
            let _closed = hub.ban_host_permanent(host);
        } else {
            let _closed = process_sockets().ban_host_permanent(host);
        }
    }
    0
}

/// Lift a host or subnet ban. Returns 0 when an entry was removed, -1
/// when there was none, and -2 when `text` is not that address.
/// Open sockets stay open.
///
/// # Safety
/// `text` is a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ban_lift(text: *const c_char, subnet: i32) -> i32 {
    let Some(text) = c_text(text) else {
        return -2;
    };
    let removed = if subnet != 0 {
        let Some(prefix) = parse_subnet(&text) else {
            return -2;
        };
        process_sockets().lift_subnet(prefix)
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        process_sockets().lift_host(host)
    };
    if removed {
        0
    } else {
        -1
    }
}

/// Time left on the longest ban that covers `host`. Returns 1 and writes
/// `out` for a deadline, 2 for a permanent ban (`out` is left unchanged),
/// 0 when the host is not banned, and -2 when `host` is not an address.
///
/// # Safety
/// `host` is a NUL-terminated string. `out` is writable when non-null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ban_remaining_ns(host: *const c_char, out: *mut u64) -> i32 {
    let Some(host) = c_text(host) else {
        return -2;
    };
    let Some(host) = host.parse::<IpAddr>().ok() else {
        return -2;
    };
    match process_sockets().remaining(host, ban_now()) {
        Some(BanLeft::Remaining { nanos }) => {
            if !out.is_null() {
                unsafe { *out = nanos };
            }
            1
        }
        Some(BanLeft::Permanent) => 2,
        None => 0,
    }
}

/// Copy bans still in force. `*count` is how many there are. When `cap`
/// is smaller, the buffer receives the first `cap` and the return is -1.
/// A null `out` with `cap` 0 only writes the count.
///
/// # Safety
/// `out` is writable for `cap` entries when non-null. `count` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_bans_copy(
    out: *mut ShekylBanView,
    cap: usize,
    count: *mut usize,
) -> i32 {
    if count.is_null() {
        return -1;
    }
    let rows = process_sockets().listed(ban_now());
    let views: Vec<ShekylBanView> = rows.iter().filter_map(ban_view).collect();
    unsafe { *count = views.len() };
    if out.is_null() {
        return if cap == 0 { 0 } else { -1 };
    }
    let n = cap.min(views.len());
    unsafe {
        std::ptr::copy_nonoverlapping(views.as_ptr(), out, n);
    }
    if n == views.len() {
        0
    } else {
        -1
    }
}

/// Drop every ban. Open sockets stay open.
///
/// The list is process-global and outlives one `node_server`. The daemon
/// lifts entries one at a time. A test process calls this so a fresh
/// server is not born inside the previous server's bans.
#[no_mangle]
pub extern "C" fn shekyl_bans_clear() {
    process_sockets().clear_bans();
}

fn ban_view(row: &ListedBan) -> Option<ShekylBanView> {
    let (kind, text, left) = match row {
        ListedBan::Host { host, left } => (BAN_KIND_HOST, host.to_string(), *left),
        ListedBan::Subnet { subnet, left } => (
            BAN_KIND_SUBNET,
            format!("{}/{}", subnet.network(), subnet.prefix_len()),
            *left,
        ),
    };
    let (permanent, remaining_ns) = match left {
        BanLeft::Permanent => (1, 0),
        BanLeft::Remaining { nanos } => (0, nanos),
    };
    Some(ShekylBanView {
        kind,
        permanent,
        _pad: [0; 6],
        text: fill_text(&text)?,
        remaining_ns,
    })
}
