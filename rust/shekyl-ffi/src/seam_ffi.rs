// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI for the p2p seam.
//!
//! C++ calls `open`, `send`, and `close`. Rust calls the bound post, which
//! only enqueues onto the connection's strand. The strand calls back when
//! the handler is armed, when a delivery returns, when `closed` starts,
//! and when the executor drops the link.
//!
//! `open` drives inbound on a joined thread so the synchronous call has a
//! reader. Zone bind moves that drive onto the transport runtime; the
//! thread is the harness shape until then. The ceiling is the one the
//! caller already resolved. This module does not resolve another.

use std::ffi::{c_char, c_void, CStr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
use shekyl_seam::{
    connector_from_index, deadline_after, direction_from_index, drive_inbound, BanLeft, CloseCause,
    CloseKind, ConnectorId, Direction, Endpoint, Hub, Ipv4Subnet, ListedBan, Post, SocketId,
    TOR_HOST_MAX,
};
use shekyl_timing_engine::{Clock, MonotonicClock, Tick};

use crate::inbound_ceiling_ffi::{
    ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_BOUNDED, SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER, SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT, SHEKYL_INBOUND_CEILING_UNLIMITED,
};
use crate::legacy_util::slice_from_ptr;

/// Outbound cap for the loopback harness. Not the measured session limit.
const HARNESS_SEND_CAP: usize = 64 * 1024;

/// `established`. Matches the C header.
pub(crate) const POST_ESTABLISHED: u32 = 1;
/// `deliver`.
const POST_DELIVER: u32 = 2;
/// `closed`.
const POST_CLOSED: u32 = 3;

/// Clearnet. Matches [`ConnectorId::Clearnet`].
pub const SHEKYL_CONNECTOR_CLEARNET: u32 = 0;
/// Tor. Matches [`ConnectorId::Tor`].
pub const SHEKYL_CONNECTOR_TOR: u32 = 1;
/// Accepted sockets.
pub const SHEKYL_DIRECTION_INBOUND: u32 = 0;
/// Dialed sockets.
pub const SHEKYL_DIRECTION_OUTBOUND: u32 = 1;

/// `epee::net_utils::address_type`. The encoding uses these tags.
pub(crate) const ADDR_IPV4: u8 = 1;
pub(crate) const ADDR_IPV6: u8 = 2;
pub(crate) const ADDR_TOR: u8 = 4;

const _: () = {
    assert!(ConnectorId::Clearnet as u8 as u32 == SHEKYL_CONNECTOR_CLEARNET);
    assert!(ConnectorId::Tor as u8 as u32 == SHEKYL_CONNECTOR_TOR);
    assert!(Direction::Inbound.index() == SHEKYL_DIRECTION_INBOUND as usize);
    assert!(Direction::Outbound.index() == SHEKYL_DIRECTION_OUTBOUND as usize);
    assert!(ADDR_IPV4 == 1 && ADDR_IPV6 == 2 && ADDR_TOR == 4);
    assert!(TOR_HOST_MAX == 62);
    assert!(POST_ESTABLISHED == 1 && POST_DELIVER == 2 && POST_CLOSED == 3);
};

/// One peer address, encoded for the adapter.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylSeamAddress {
    pub connector: u8,
    pub address_type: u8,
    pub zone_only: u8,
    pub _pad: u8,
    pub port: u16,
    pub len: u16,
    pub bytes: [u8; TOR_HOST_MAX],
}

/// What `established` carries upward.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylSeamObserved {
    pub connector: u8,
    pub direction: u8,
    pub address_type: u8,
    pub zone_only: u8,
    pub port: u16,
    pub len: u16,
    pub bytes: [u8; TOR_HOST_MAX],
}

/// `id` is zero when the open was refused. `cause_kind` is then the D12
/// discriminant, and zero when `id` is a socket.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylSeamOpenResult {
    pub id: u64,
    pub cause_kind: u8,
    pub _pad: u8,
    pub reply_code: u16,
}

type PostFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    id: u64,
    kind: u32,
    observed: *const ShekylSeamObserved,
    bytes: *const u8,
    len: usize,
    cause: *const CloseCause,
);

/// The executor pointer. C++ keeps it alive for as long as the bind stands.
struct Ctx(*mut c_void);

// The pointer is the executor, not a handler. Every thread which posts may
// share it, and the post only enqueues.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    fn get(&self) -> *mut c_void {
        self.0
    }
}

struct Bound {
    ctx: Ctx,
    post: PostFn,
}

static STATE: Mutex<Option<Hub>> = Mutex::new(None);

pub(crate) fn hub() -> Option<Hub> {
    STATE.lock().expect("seam state").clone()
}

/// Tests that bind the process hub take this for the whole test.
///
/// The hub is one static. Two tests binding it at once would publish over
/// each other. A poisoned lock is the previous test's panic; the next test
/// still needs the gate.
#[cfg(test)]
pub(crate) fn seam_bind_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

/// One admission table for the process. A new binding does not mint ids
/// again: a `reap` that arrives after the swap names an id the new hub
/// does not hold.
pub(crate) fn process_sockets() -> shekyl_seam::Sockets {
    static TABLE: OnceLock<shekyl_seam::Sockets> = OnceLock::new();
    TABLE.get_or_init(shekyl_seam::Sockets::new).clone()
}

/// The clock ban deadlines and the bound hub share. A ban written before
/// the seam is bound is still read against this origin after bind.
fn process_clock() -> Arc<MonotonicClock> {
    static CLOCK: OnceLock<Arc<MonotonicClock>> = OnceLock::new();
    Arc::clone(CLOCK.get_or_init(|| Arc::new(MonotonicClock::new())))
}

fn ban_now() -> Tick {
    process_clock().now()
}

/// Close the published hub, join its harness threads, then publish `next`.
///
/// The previous hub stays published through [`Hub::shutdown`], so a strand
/// callback during the close still reaches it. The next hub is published
/// only after that returns.
fn store(next: Option<Hub>) {
    if let Some(current) = hub() {
        current.shutdown();
    }
    *STATE.lock().expect("seam state") = next;
}

pub(crate) fn ceiling_from_abi(ceiling: ShekylInboundCeiling) -> Option<InboundCeiling> {
    match ceiling.kind {
        SHEKYL_INBOUND_CEILING_BOUNDED => Some(InboundCeiling::Bounded(ceiling.ceiling)),
        SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT => Some(InboundCeiling::Unbounded(
            UnboundedReason::NoPerProcessLimit,
        )),
        SHEKYL_INBOUND_CEILING_UNLIMITED => {
            Some(InboundCeiling::Unbounded(UnboundedReason::Unlimited))
        }
        SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE => {
            Some(InboundCeiling::Unbounded(UnboundedReason::LimitUnreadable))
        }
        SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE => {
            Some(InboundCeiling::Unbounded(UnboundedReason::CountUnreadable))
        }
        SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER => {
            Some(InboundCeiling::Unbounded(UnboundedReason::ExceedsCounter))
        }
        _ => None,
    }
}

/// Install the post callback and the caller's ceiling.
///
/// A null `post`, a null `ctx`, or a null `ceiling` clears the seam.
/// Returns 0 when the seam is installed or cleared, and -1 when `ceiling`
/// is not a known decision.
///
/// A previous binding is closed and its harness threads are joined before
/// this call publishes the next one. `ctx` from that binding stays valid
/// until this call returns.
///
/// # Safety
/// `post` does not call back into the seam before it returns.
/// `ctx` stays valid until the next bind returns, because shutdown still
/// posts to the previous callback. `ceiling` is readable when non-null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_bind(
    ctx: *mut c_void,
    post: Option<PostFn>,
    ceiling: *const ShekylInboundCeiling,
) -> i32 {
    let Some(post) = post else {
        store(None);
        return 0;
    };
    if ctx.is_null() || ceiling.is_null() {
        store(None);
        return if ceiling.is_null() && !ctx.is_null() {
            -1
        } else {
            0
        };
    }
    let ceiling = unsafe { *ceiling };
    let Some(ceiling) = ceiling_from_abi(ceiling) else {
        store(None);
        return -1;
    };
    let bound = Bound {
        ctx: Ctx(ctx),
        post,
    };
    let clock: Arc<dyn Clock + Send + Sync> = process_clock();
    store(Some(Hub::new(
        process_sockets(),
        ceiling,
        Arc::new(move |item: Post| post_one(&bound, item)),
        clock,
    )));
    0
}

/// Replace the inbound bound. Returns 0 on success. -1 when the seam is
/// unbound or `ceiling` is not a known decision.
///
/// # Safety
/// `ceiling` is readable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_set_ceiling(ceiling: *const ShekylInboundCeiling) -> i32 {
    if ceiling.is_null() {
        return -1;
    }
    let Some(ceiling) = ceiling_from_abi(unsafe { *ceiling }) else {
        return -1;
    };
    let Some(hub) = hub() else {
        return -1;
    };
    hub.set_ceiling(ceiling);
    0
}

/// Install the in-memory harness dialer. Returns 0, or -1 when unbound.
///
/// The harness admits on the hub's table and discards outbound bytes.
/// Zone bind does not call this.
#[no_mangle]
pub extern "C" fn shekyl_seam_install_loopback() -> i32 {
    let Some(hub) = hub() else {
        return -1;
    };
    hub.install_loopback(HARNESS_SEND_CAP);
    0
}

/// Dial through the installed dialer and wait until the handler is armed.
///
/// `id` is zero and `cause_kind` is the D12 cause when the dial or the arm
/// fails. The inbound pump runs on a thread this call starts; [`shekyl_seam_reap`]
/// joins it.
///
/// # Safety
/// `addr` is readable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_open(
    addr: *const ShekylSeamAddress,
    inbound: u8,
) -> ShekylSeamOpenResult {
    let refused = |cause: CloseCause| ShekylSeamOpenResult {
        id: 0,
        cause_kind: cause.kind() as u8,
        _pad: 0,
        reply_code: cause.reply_code(),
    };
    if addr.is_null() {
        return refused(CloseCause::new(CloseKind::LocalClose));
    }
    let Some(hub) = hub() else {
        return refused(CloseCause::new(CloseKind::LocalClose));
    };
    let addr = unsafe { &*addr };
    let Some(endpoint) = endpoint_from_c(addr, inbound != 0) else {
        return refused(CloseCause::new(CloseKind::LocalClose));
    };
    let attached = match hub.connect(&endpoint) {
        Ok(attached) => attached,
        Err(cause) => return refused(cause),
    };
    let id = attached.id;
    let session = attached.session;
    let hub_pump = hub.clone();
    let pump = thread::spawn(move || drive_inbound(&hub_pump, id, session));
    hub.track_pump(id, pump);
    if hub.await_armed(id) {
        ShekylSeamOpenResult {
            id: id.get(),
            cause_kind: 0,
            _pad: 0,
            reply_code: 0,
        }
    } else {
        refused(
            hub.cause(id)
                .unwrap_or_else(|| CloseCause::new(CloseKind::LocalClose)),
        )
    }
}

/// The strand finished `established`. `armed` is nonzero when the handler
/// was created. Zero records [`CloseKind::LocalClose`] and wakes the opener.
#[no_mangle]
pub extern "C" fn shekyl_seam_handler_armed(id: u64, armed: i32) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    hub.handler_armed(id, armed != 0);
}

/// 1 when a hub is bound. The Levin puppet has none; production does.
#[no_mangle]
pub extern "C" fn shekyl_seam_is_bound() -> i32 {
    i32::from(hub().is_some())
}

/// 1 when remembering `(kind, reply)` on `connector` should stop dials to
/// that address. An unknown kind is 0. An unknown connector does not
/// count a proxy reply: an unclear cause stays dialable.
#[no_mangle]
pub extern "C" fn shekyl_close_implicates_address(kind: u8, reply: u16, connector: u8) -> i32 {
    let Some(kind) = CloseKind::ALL
        .iter()
        .copied()
        .find(|item| item.code() == kind)
    else {
        return 0;
    };
    let Some(connector) = ConnectorId::ALL
        .iter()
        .copied()
        .find(|item| *item as u8 == connector)
    else {
        return i32::from(matches!(
            kind,
            CloseKind::DialFailed | CloseKind::LevinHandshakeRejected
        ));
    };
    let cause = if matches!(kind, CloseKind::ProxyRefused) {
        CloseCause::proxy_refused(reply)
    } else {
        CloseCause::new(kind)
    };
    i32::from(cause.implicates_address(connector))
}

/// The cause recorded on `id`, if the row still holds one.
///
/// Returns 1 and writes `kind_out` and `reply_out`. Returns 0 when there
/// is no hub, no row, or no cause yet.
///
/// # Safety
/// `kind_out` and `reply_out` are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_session_cause(
    id: u64,
    kind_out: *mut u8,
    reply_out: *mut u16,
) -> i32 {
    if id == 0 || kind_out.is_null() || reply_out.is_null() {
        return 0;
    }
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return 0;
    };
    let Some(cause) = hub.cause(id) else {
        return 0;
    };
    unsafe {
        *kind_out = cause.kind().code();
        *reply_out = cause.reply_code();
    }
    1
}

/// Inject one frame into the harness channel and return when `deliver`
/// has been posted. `0` means it was posted.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_deliver(id: u64, bytes: *const u8, len: usize) -> i32 {
    let Some(frame) = (unsafe { slice_from_ptr(bytes, len) }) else {
        return -1;
    };
    let Some(hub) = hub() else {
        return -1;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return -1;
    };
    let before = hub.posted_deliveries(id).unwrap_or(0);
    if !hub.inject(id, frame.to_vec()) {
        return -1;
    }
    if hub.wait_delivery_posted(id, before) {
        0
    } else {
        -1
    }
}

/// The strand finished `handle_recv`. `accepted` is nonzero when the
/// handler took the bytes.
#[no_mangle]
pub extern "C" fn shekyl_seam_delivery_finished(id: u64, accepted: i32) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    hub.delivery_finished(id, accepted != 0);
}

/// The strand has started `closed`.
#[no_mangle]
pub extern "C" fn shekyl_seam_handler_gone(id: u64) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    hub.handler_gone(id);
}

/// The executor dropped the link. The row is removed and the harness
/// threads are joined.
#[no_mangle]
pub extern "C" fn shekyl_seam_reap(id: u64) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    hub.reap(id);
}

/// Copy one whole message into the byte cap. `1` is accepted. `0` is not.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_send(id: u64, bytes: *const u8, len: usize) -> i32 {
    let Some(frame) = (unsafe { slice_from_ptr(bytes, len) }) else {
        return 0;
    };
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return 0;
    };
    if hub.send(id, frame.to_vec()) {
        1
    } else {
        0
    }
}

/// The same send, with the registry and the cause.
///
/// `found` is 1 when the registry held `id`. `cause_kind` is the close
/// code when one was recorded, and 0 when there is none.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero. `found` and
/// `cause_kind` are writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_send_report(
    id: u64,
    bytes: *const u8,
    len: usize,
    found: *mut i32,
    cause_kind: *mut u8,
) -> i32 {
    if found.is_null() || cause_kind.is_null() {
        return 0;
    }
    unsafe {
        *found = 0;
        *cause_kind = 0;
    }
    let Some(frame) = (unsafe { slice_from_ptr(bytes, len) }) else {
        return 0;
    };
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return 0;
    };
    let report = hub.send_report(id, frame.to_vec());
    unsafe {
        *found = i32::from(report.found);
        *cause_kind = report.cause.map(CloseKind::code).unwrap_or(0);
    }
    i32::from(report.accepted)
}

/// Record local close when no cause is recorded yet, and post `closed`.
#[no_mangle]
pub extern "C" fn shekyl_seam_close(id: u64) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    hub.close(id);
}

/// Live sockets for one connector and direction.
#[no_mangle]
pub extern "C" fn shekyl_seam_socket_count(connector: u32, direction: u32) -> u64 {
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(connector) = connector_from_index(connector) else {
        return 0;
    };
    let Some(direction) = direction_from_index(direction) else {
        return 0;
    };
    hub.socket_count(connector, direction)
}

/// Inbound sockets on every connector.
#[no_mangle]
pub extern "C" fn shekyl_seam_inbound_held() -> u64 {
    hub().map(|hub| hub.inbound_held()).unwrap_or(0)
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
    pub text: [u8; 80],
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

fn fill_text(text: &str) -> Option<[u8; 80]> {
    let bytes = text.as_bytes();
    if bytes.len() >= 80 {
        return None;
    }
    let mut out = [0u8; 80];
    out[..bytes.len()].copy_from_slice(bytes);
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

fn endpoint_from_c(addr: &ShekylSeamAddress, inbound: bool) -> Option<Endpoint> {
    let _ = connector_from_index(u32::from(addr.connector))?;
    let len = usize::from(addr.len);
    if len > TOR_HOST_MAX {
        return None;
    }
    let direction = if inbound {
        Direction::Inbound
    } else {
        Direction::Outbound
    };
    match (addr.connector, addr.address_type, addr.zone_only, direction) {
        (connector, ADDR_IPV4, 0, direction)
            if u32::from(connector) == SHEKYL_CONNECTOR_CLEARNET && len == 4 =>
        {
            let ip = Ipv4Addr::new(addr.bytes[0], addr.bytes[1], addr.bytes[2], addr.bytes[3]);
            Some(Endpoint::Clearnet {
                ip: IpAddr::V4(ip),
                port: addr.port,
                direction,
            })
        }
        (connector, ADDR_IPV6, 0, direction)
            if u32::from(connector) == SHEKYL_CONNECTOR_CLEARNET && len == 16 =>
        {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&addr.bytes[..16]);
            Some(Endpoint::Clearnet {
                ip: IpAddr::V6(Ipv6Addr::from(octets)),
                port: addr.port,
                direction,
            })
        }
        (connector, ADDR_TOR, 1, Direction::Inbound)
            if u32::from(connector) == SHEKYL_CONNECTOR_TOR && len == 0 =>
        {
            Some(Endpoint::TorInbound)
        }
        (connector, ADDR_TOR, 0, Direction::Outbound)
            if u32::from(connector) == SHEKYL_CONNECTOR_TOR && len > 0 =>
        {
            let Ok(host) = std::str::from_utf8(&addr.bytes[..len]) else {
                tracing::error!("tor dial refused: host is not a v3 onion");
                return None;
            };
            let Some(key) = shekyl_onion_v3::v3_pubkey(host) else {
                tracing::error!("tor dial refused: host is not a v3 onion");
                return None;
            };
            Some(Endpoint::Tor {
                key,
                port: addr.port,
            })
        }
        _ => None,
    }
}

pub(crate) fn observed_c(endpoint: &Endpoint) -> ShekylSeamObserved {
    let mut out = ShekylSeamObserved {
        connector: endpoint.connector() as u8,
        direction: direction_byte(endpoint.direction()),
        address_type: 0,
        zone_only: 0,
        port: 0,
        len: 0,
        bytes: [0; TOR_HOST_MAX],
    };
    match endpoint {
        Endpoint::Clearnet { ip, port, .. } => {
            out.port = *port;
            match ip {
                IpAddr::V4(ip) => {
                    out.address_type = ADDR_IPV4;
                    out.len = 4;
                    out.bytes[..4].copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    out.address_type = ADDR_IPV6;
                    out.len = 16;
                    out.bytes[..16].copy_from_slice(&ip.octets());
                }
            }
        }
        Endpoint::TorInbound => {
            out.address_type = ADDR_TOR;
            out.zone_only = 1;
        }
        Endpoint::Tor { key, port } => {
            let raw = shekyl_onion_v3::v3_onion_hostname(key);
            let bytes = raw.as_bytes();
            debug_assert_eq!(bytes.len(), TOR_HOST_MAX);
            out.address_type = ADDR_TOR;
            out.port = *port;
            out.len = u16::try_from(bytes.len()).expect("tor host fits");
            out.bytes[..bytes.len()].copy_from_slice(bytes);
        }
    }
    out
}

fn direction_byte(direction: Direction) -> u8 {
    match direction {
        Direction::Inbound => u8::try_from(SHEKYL_DIRECTION_INBOUND).expect("direction fits"),
        Direction::Outbound => u8::try_from(SHEKYL_DIRECTION_OUTBOUND).expect("direction fits"),
    }
}

/// Post one item. Split out so each arm can borrow its payload for the call.
fn post_one(bound: &Bound, item: Post) {
    match item {
        Post::Established { id, endpoint } => {
            let observed = observed_c(&endpoint);
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    id.get(),
                    POST_ESTABLISHED,
                    &raw const observed,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                );
            }
        }
        // The adapter keeps one binding per connector and routes every post
        // by `observed->connector`. Deliver and Closed once posted a null
        // `observed`, so both landed on the clearnet binding and every Tor
        // delivery was dropped after its `Established`.
        Post::Deliver {
            id,
            connector,
            bytes,
        } => {
            let observed = routing_c(connector);
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    id.get(),
                    POST_DELIVER,
                    &raw const observed,
                    bytes.as_ptr(),
                    bytes.len(),
                    std::ptr::null(),
                );
            }
        }
        Post::Closed {
            id,
            connector,
            cause,
        } => {
            let observed = routing_c(connector);
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    id.get(),
                    POST_CLOSED,
                    &raw const observed,
                    std::ptr::null(),
                    0,
                    &raw const cause,
                );
            }
        }
    }
}

/// The connector alone, for posts the adapter only routes. The endpoint
/// itself travelled on `Established`.
fn routing_c(connector: ConnectorId) -> ShekylSeamObserved {
    ShekylSeamObserved {
        connector: connector as u8,
        direction: 0,
        address_type: 0,
        zone_only: 0,
        port: 0,
        len: 0,
        bytes: [0; TOR_HOST_MAX],
    }
}
