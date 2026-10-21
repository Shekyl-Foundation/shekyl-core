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

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::ThreadId;

use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
use shekyl_seam::{
    connector_from_index, direction_from_index, CloseCause, CloseKind, ConnectorId, Direction,
    Endpoint, Hub, Post, SocketId, TOR_HOST_MAX,
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
/// The outbound handshake's result: `bytes` is one [`ShekylSeamHandshakeResult`].
pub(crate) const POST_HANDSHAKE: u32 = 4;

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
    assert!(ConnectorId::Clearnet.index() == 0);
    assert!(ConnectorId::Tor.index() == 1);
    assert!(ConnectorId::Clearnet as u8 as u32 == SHEKYL_CONNECTOR_CLEARNET);
    assert!(ConnectorId::Tor as u8 as u32 == SHEKYL_CONNECTOR_TOR);
    assert!(Direction::Inbound.index() == SHEKYL_DIRECTION_INBOUND as usize);
    assert!(Direction::Outbound.index() == SHEKYL_DIRECTION_OUTBOUND as usize);
    assert!(ADDR_IPV4 == 1 && ADDR_IPV6 == 2 && ADDR_TOR == 4);
    assert!(TOR_HOST_MAX == 62);
    assert!(POST_ESTABLISHED == 1 && POST_DELIVER == 2 && POST_CLOSED == 3 && POST_HANDSHAKE == 4);
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

/// What a kept dial's handshake notification carries. The strand reads
/// these fields and does not answer. Only a kept dial is posted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylSeamHandshakeResult {
    /// The peer's `CORE_SYNC_DATA`.
    pub current_height: u64,
    pub cumulative_difficulty: u64,
    pub cumulative_difficulty_top64: u64,
    pub top_id: [u8; 32],
}

impl ShekylSeamHandshakeResult {
    /// The struct's bytes in its C layout, written field by field so the
    /// post carries no padding read from the stack.
    fn to_bytes(self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[0..8].copy_from_slice(&self.current_height.to_ne_bytes());
        out[8..16].copy_from_slice(&self.cumulative_difficulty.to_ne_bytes());
        out[16..24].copy_from_slice(&self.cumulative_difficulty_top64.to_ne_bytes());
        out[24..56].copy_from_slice(&self.top_id);
        out
    }
}

const _: () = {
    assert!(std::mem::size_of::<ShekylSeamHandshakeResult>() == 56);
    assert!(std::mem::offset_of!(ShekylSeamHandshakeResult, current_height) == 0);
    assert!(std::mem::offset_of!(ShekylSeamHandshakeResult, top_id) == 24);
};

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

/// The lock around installing the socket table and binding a hub on it.
///
/// [`install_process_sockets`] and [`shekyl_seam_bind`] both take it, from
/// the table read through the hub store, so a bind cannot publish a hub
/// over a table install is replacing. It is re-entrant on the calling
/// thread: a test that already holds it may bind. A poisoned lock is the
/// previous holder's panic; the next caller still needs the gate.
pub(crate) fn seam_bind_lock() -> &'static BindGate {
    static GATE: BindGate = BindGate::new();
    &GATE
}

struct BindState {
    owner: Option<ThreadId>,
    depth: u32,
}

pub(crate) struct BindGate {
    state: Mutex<BindState>,
    changed: Condvar,
}

pub(crate) struct BindGuard {
    gate: &'static BindGate,
}

impl BindGate {
    const fn new() -> Self {
        Self {
            state: Mutex::new(BindState {
                owner: None,
                depth: 0,
            }),
            changed: Condvar::new(),
        }
    }

    pub(crate) fn lock(&'static self) -> BindGuard {
        let me = std::thread::current().id();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.owner == Some(me) {
                state.depth += 1;
                return BindGuard { gate: self };
            }
            if state.owner.is_none() {
                state.owner = Some(me);
                state.depth = 1;
                return BindGuard { gate: self };
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn unlock(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.depth -= 1;
        if state.depth == 0 {
            state.owner = None;
            self.changed.notify_one();
        }
    }
}

impl Drop for BindGuard {
    fn drop(&mut self) {
        self.gate.unlock();
    }
}

/// The node's socket table, or the table a reader created before `main`
/// installed one. A bound hub keeps the table it was built with, so
/// [`install_process_sockets`] refuses once a hub exists.
static PROCESS_SOCKETS: Mutex<Option<shekyl_seam::Sockets>> = Mutex::new(None);

/// Install the node's socket table as the process table.
///
/// Returns `false` when a hub is already bound: that hub holds the previous
/// table, and replacing it would split bans from the zone. An unbound table
/// a reader created first is replaced, so a later reader sees the node's.
/// Production `main` installs before any reader, and this replacement is
/// what a shared test process needs after another test has read the table.
#[must_use]
pub fn install_process_sockets(sockets: shekyl_seam::Sockets) -> bool {
    // The same lock [`shekyl_seam_bind`] holds from its table read through
    // the hub store. A bind in that window makes this install wait, then
    // see the hub and refuse: the hub keeps the table it was built with.
    #[cfg(test)]
    INSTALL_AT_LOCK.store(1, std::sync::atomic::Ordering::SeqCst);
    let _bind = seam_bind_lock().lock();
    #[cfg(test)]
    INSTALL_AT_LOCK.store(2, std::sync::atomic::Ordering::SeqCst);
    if hub().is_some() {
        return false;
    }
    let mut slot = PROCESS_SOCKETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(sockets);
    true
}

/// Set by [`install_process_sockets`] to 1 just before it takes
/// [`seam_bind_lock`], and to 2 once it holds the lock. The race test
/// reads it.
#[cfg(test)]
static INSTALL_AT_LOCK: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// The process's one admission table. A new binding does not mint ids
/// again: a `reap` that arrives after the swap names an id the new hub
/// does not hold.
///
/// Before [`install_process_sockets`], the first call creates the table.
/// After it, every call is the node's table.
#[must_use]
pub fn process_sockets() -> shekyl_seam::Sockets {
    let mut slot = PROCESS_SOCKETS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if slot.is_none() {
        *slot = Some(shekyl_seam::Sockets::new());
    }
    slot.clone().expect("the table was just set")
}

/// The process's one clock (Rick, 2026-10-14): ban deadlines, the bound
/// hub, the zone host's engine and the link gate all read this origin. A
/// ban written before the seam is bound is still read against it after
/// bind, and an engine `now` compares with a ban without an offset.
pub(crate) fn process_clock() -> Arc<MonotonicClock> {
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
        crate::dialer_ffi::stop();
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
/// A null `post` or a null `ctx` clears the seam. Returns 0.
///
/// The hub's inbound ceiling is this process's, resolved here from its
/// descriptor limit and the reservation in the remnant's preparation;
/// nothing about it crosses from C++. A harness that wants another bound
/// sets it after the bind with [`shekyl_seam_set_ceiling`].
///
/// A previous binding is closed and its harness threads are joined before
/// this call publishes the next one. `ctx` from that binding stays valid
/// until this call returns.
///
/// # Safety
/// `post` does not call back into the seam before it returns.
/// `ctx` stays valid until the next bind returns, because shutdown still
/// posts to the previous callback.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_bind(ctx: *mut c_void, post: Option<PostFn>) -> i32 {
    let Some(post) = post else {
        let _bind = seam_bind_lock().lock();
        store(None);
        return 0;
    };
    if ctx.is_null() {
        let _bind = seam_bind_lock().lock();
        store(None);
        return 0;
    }
    let ceiling = crate::inbound_ceiling_ffi::configured();
    tracing::info!(target: "p2p", ceiling = ?ceiling, "the inbound ceiling the seam binds with");
    let bound = Bound {
        ctx: Ctx(ctx),
        post,
    };
    let clock: Arc<dyn Clock + Send + Sync> = process_clock();
    // The table this hub is built on and the store of the hub are one
    // critical section with [`install_process_sockets`].
    let hub = {
        let _bind = seam_bind_lock().lock();
        let hub = Hub::new(
            process_sockets(),
            ceiling,
            Arc::new(move |item: Post| post_one(&bound, item)),
            clock,
        );
        // `store` stops the previous hub's dialer; this hub's is built after.
        store(Some(hub.clone()));
        hub
    };
    crate::dialer_ffi::ensure_dialer(&hub);
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

/// Dial through the installed dialer and adopt the channel. The harness
/// and the unit tests open sessions here; the daemon's dialer is
/// `shekyl-dialer`, which runs the handshake between the two steps.
///
/// Returns as soon as the row exists, without waiting for the strand to
/// arm its handler (the C++ dial path that needed the wait is deleted,
/// 2026-10-13). `id` is zero and `cause_kind` is the D12 cause when the
/// dial fails. The inbound pump runs where the installed dialer runs
/// pumps; the harness's thread is joined by [`shekyl_seam_reap`].
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
    hub.drive(id, attached.session);
    ShekylSeamOpenResult {
        id: id.get(),
        cause_kind: 0,
        _pad: 0,
        reply_code: 0,
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

/// Record `kind` when the row has no cause yet. An unknown kind records
/// nothing. The row stays until [`shekyl_seam_reap`].
#[no_mangle]
pub extern "C" fn shekyl_seam_record_cause(id: u64, kind: u8, reply: u16) {
    let Some(hub) = hub() else {
        return;
    };
    let Some(id) = SocketId::from_ffi(id) else {
        return;
    };
    let Some(kind) = CloseKind::from_code(kind) else {
        return;
    };
    let cause = if kind == CloseKind::ProxyRefused {
        CloseCause::proxy_refused(reply)
    } else {
        CloseCause::new(kind)
    };
    hub.finish(id, cause);
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

/// The ban table's entries, as the C++ and the daemon's owners reach them.
#[path = "seam_ban_ffi.rs"]
pub mod bans;

pub use bans::ShekylBanView;

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
        Post::HandshakeResult {
            id,
            connector,
            sync,
        } => {
            let observed = routing_c(connector);
            let result = ShekylSeamHandshakeResult {
                current_height: sync.current_height,
                cumulative_difficulty: sync.cumulative_difficulty,
                cumulative_difficulty_top64: sync.cumulative_difficulty_top64,
                top_id: sync.top_id,
            };
            let bytes = result.to_bytes();
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    id.get(),
                    POST_HANDSHAKE,
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
            // The dialer hears every close, with the cause. A kept session
            // leaves its count; SessionRefused is the lists' PayloadRefused.
            crate::dialer_ffi::on_closed(id, cause);
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
    use shekyl_seam::{Hub, Post};
    use shekyl_timing_engine::Clock;

    use super::{install_process_sockets, process_sockets, seam_bind_lock, store, INSTALL_AT_LOCK};

    /// A bind that has read the table and not yet stored the hub holds
    /// [`seam_bind_lock`]. An install that arrives in that window waits,
    /// then sees the hub and refuses. Red edit: drop the lock from
    /// `install_process_sockets`. The install returns before the hub is
    /// stored, and the hub is left on the table it did not install.
    #[test]
    fn a_bind_holding_the_lock_refuses_the_install() {
        let gate = seam_bind_lock().lock();
        store(None);
        INSTALL_AT_LOCK.store(0, Ordering::SeqCst);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let admitted = install_process_sockets(shekyl_seam::Sockets::new());
            done_tx.send(admitted).expect("the test is listening");
        });
        let started = Instant::now();
        while INSTALL_AT_LOCK.load(Ordering::SeqCst) != 1 {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "install never reached the lock"
            );
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            INSTALL_AT_LOCK.load(Ordering::SeqCst),
            1,
            "install took the lock before the bind stored the hub"
        );
        assert!(
            done_rx.try_recv().is_err(),
            "install returned while the bind still held the lock"
        );
        let clock: Arc<dyn Clock + Send + Sync> = super::process_clock();
        let hub = Hub::new(
            process_sockets(),
            InboundCeiling::Unbounded(UnboundedReason::Unlimited),
            Arc::new(|_: Post| {}),
            clock,
        );
        store(Some(hub));
        drop(gate);
        let admitted = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("install finished after the bind released the lock");
        assert!(
            !admitted,
            "a bind that stored its hub before releasing the lock refuses the install"
        );
        let _gate = seam_bind_lock().lock();
        store(None);
    }
}
