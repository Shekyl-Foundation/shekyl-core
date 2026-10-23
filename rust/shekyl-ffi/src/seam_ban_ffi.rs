// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Ban list FFI. The C names and the 96-byte view stay what the header
//! publishes. The list itself is the transport layer's, read through the
//! seam's process sockets and, when a hub is bound, through that hub.

use std::ffi::{c_char, CStr};
use std::net::{IpAddr, Ipv4Addr};

use std::time::Duration;

use shekyl_seam::{deadline_after, BanLeft, Ipv4Subnet, ListedBan, Sockets};

/// The subnet a ban names, for the daemon's owners.
pub use shekyl_seam::Ipv4Subnet as Subnet;

use super::{ban_now, hub, process_sockets};

/// What a ban names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanTarget {
    /// One host.
    Host(IpAddr),
    /// An IPv4 subnet.
    Subnet(Ipv4Subnet),
}

/// How long a ban lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanSpan {
    /// Until it is lifted.
    Permanent,
    /// For this long from the process clock.
    For(Duration),
}

/// The ban verbs over one socket table, through the bound hub while there
/// is one (`DRS_X_STORE_FLIP.md` DX-Q3, Q11). The daemon installs its
/// node's table as the process table before the hub binds, so the hub's
/// table is that one; going through the hub also closes the sockets a new
/// ban drops. The RPC's ban handle and this module's C entry points both
/// ban through here, so a ban has one path.
#[derive(Clone)]
pub struct BanPath {
    sockets: Sockets,
}

impl BanPath {
    /// The verbs over `sockets`, or the bound hub's table while a hub is
    /// bound.
    #[must_use]
    pub const fn over(sockets: Sockets) -> Self {
        Self { sockets }
    }

    /// The verbs over the process table.
    #[must_use]
    pub fn process() -> Self {
        Self::over(process_sockets())
    }

    /// Ban `target` for `span`. `false` when the span's deadline does not
    /// fit the clock; nothing is banned then. A deadline already covered
    /// by a later one does not shorten it.
    pub fn ban(&self, target: BanTarget, span: BanSpan) -> bool {
        let now = ban_now();
        let until = match span {
            BanSpan::Permanent => None,
            BanSpan::For(left) => {
                let nanos = u64::try_from(left.as_nanos()).unwrap_or(u64::MAX);
                let Some(until) = deadline_after(now, nanos) else {
                    return false;
                };
                Some(until)
            }
        };
        let bound = hub();
        let _closed = match (target, until, bound) {
            (BanTarget::Host(host), Some(until), Some(hub)) => hub.ban_host(host, until),
            (BanTarget::Host(host), None, Some(hub)) => hub.ban_host_permanent(host),
            (BanTarget::Subnet(subnet), Some(until), Some(hub)) => hub.ban_subnet(subnet, until),
            (BanTarget::Subnet(subnet), None, Some(hub)) => hub.ban_subnet_permanent(subnet),
            (BanTarget::Host(host), Some(until), None) => self.sockets.ban_host(host, until, now),
            (BanTarget::Host(host), None, None) => self.sockets.ban_host_permanent(host),
            (BanTarget::Subnet(subnet), Some(until), None) => {
                self.sockets.ban_subnet(subnet, until, now)
            }
            (BanTarget::Subnet(subnet), None, None) => self.sockets.ban_subnet_permanent(subnet),
        };
        true
    }

    /// Lift `target`'s ban. `false` when there was none. Open sockets stay
    /// open.
    pub fn lift(&self, target: BanTarget) -> bool {
        match (target, hub()) {
            (BanTarget::Host(host), Some(hub)) => hub.lift_host(host),
            (BanTarget::Subnet(subnet), Some(hub)) => hub.lift_subnet(subnet),
            (BanTarget::Host(host), None) => self.sockets.lift_host(host),
            (BanTarget::Subnet(subnet), None) => self.sockets.lift_subnet(subnet),
        }
    }

    /// Time left on the longest ban that covers `host`; `None` when it is
    /// not banned.
    #[must_use]
    pub fn remaining(&self, host: IpAddr) -> Option<BanLeft> {
        match hub() {
            Some(hub) => hub.remaining(host),
            None => self.sockets.remaining(host, ban_now()),
        }
    }

    /// Whether `host` is banned now.
    #[must_use]
    pub fn is_banned(&self, host: IpAddr) -> bool {
        self.remaining(host).is_some()
    }

    /// The bans in force, with their time left.
    #[must_use]
    pub fn listed(&self) -> Vec<ListedBan> {
        match hub() {
            Some(hub) => hub.listed_bans(),
            None => self.sockets.listed(ban_now()),
        }
    }
}

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
    let target = if subnet != 0 {
        let Some(prefix) = parse_subnet(&text) else {
            return -2;
        };
        BanTarget::Subnet(prefix)
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        BanTarget::Host(host)
    };
    if !BanPath::process().ban(target, BanSpan::For(Duration::from_nanos(duration_ns))) {
        return -1;
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
/// Bans `subnet` for the life of the process: the ban file's subnet
/// entries, applied by the daemon's Rust `main()`. Before the seam binds,
/// the process table carries it into the hub.
pub fn ban_subnet_permanent(subnet: Ipv4Subnet) {
    let _banned = BanPath::process().ban(BanTarget::Subnet(subnet), BanSpan::Permanent);
}

/// Whether `host` is banned with no deadline (a ban file entry, by host
/// or by subnet), read off the process table.
#[must_use]
pub fn is_banned_permanently(host: IpAddr) -> bool {
    matches!(BanPath::process().remaining(host), Some(BanLeft::Permanent))
}

/// Whether `host` is banned at the process clock.
///
/// A bound hub answers from the table it was built with. With no hub, the
/// process table answers, and a deadline that has passed is not a ban: the
/// lookup drops it. A permanent ban is in force at every tick. This is a
/// read; it closes nothing.
#[must_use]
pub fn host_is_banned(host: IpAddr) -> bool {
    BanPath::process().is_banned(host)
}

/// Bans `host` for the life of the process: the ban file's host entries.
pub fn ban_host_permanent(host: IpAddr) {
    let _banned = BanPath::process().ban(BanTarget::Host(host), BanSpan::Permanent);
}

#[no_mangle]
pub unsafe extern "C" fn shekyl_ban_permanent(text: *const c_char, subnet: i32) -> i32 {
    let Some(text) = c_text(text) else {
        return -2;
    };
    if subnet != 0 {
        let Some(prefix) = parse_subnet(&text) else {
            return -2;
        };
        ban_subnet_permanent(prefix);
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        ban_host_permanent(host);
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
        BanPath::process().lift(BanTarget::Subnet(prefix))
    } else {
        let Some(host) = text.parse::<IpAddr>().ok() else {
            return -2;
        };
        BanPath::process().lift(BanTarget::Host(host))
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
    match BanPath::process().remaining(host) {
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
    let rows = BanPath::process().listed();
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
