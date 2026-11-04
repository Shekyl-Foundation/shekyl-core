// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI for the p2p seam.
//!
//! C++ calls `open`, `send`, and `close`. Rust calls the bound post, which
//! only enqueues onto the connection's strand. The hub's post sink is the
//! chain-sync router (`shekyl_chain_sync_runtime::router`), attached to the
//! node's sync owner; a bind with no owner is refused. The strand calls back when
//! the handler is armed, when a delivery returns, when `closed` starts,
//! and when the executor drops the link.
//!
//! `open` drives inbound on a joined thread so the synchronous call has a
//! reader. Zone bind moves that drive onto the transport runtime; the
//! thread is the harness shape until then. The ceiling is the one the
//! caller already resolved. This module does not resolve another.

use std::ffi::c_void;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use shekyl_chain_sync_runtime::router::Router;
use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
use shekyl_seam::{
    CloseCause, CloseKind, ConnectorId, Direction, Endpoint, Hub, Post, SocketId, TOR_HOST_MAX,
};
use shekyl_timing_engine::{Clock, EngineService, Handle, MonotonicClock, Tick};

use crate::inbound_ceiling_ffi::{
    ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_BOUNDED, SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER, SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT, SHEKYL_INBOUND_CEILING_UNLIMITED,
};
use crate::legacy_util::slice_from_ptr;

/// `established`. Matches the C header.
pub(crate) const POST_ESTABLISHED: u32 = 1;
/// `deliver`.
const POST_DELIVER: u32 = 2;
/// `closed`.
const POST_CLOSED: u32 = 3;
/// A kept dial's handshake completed. No bytes: the C++ relay reads only
/// that the session is established; the peer's claim is chain sync's.
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

/// Serializes tests that bind a hub or read the process socket table.
///
/// Production [`install_process_sockets`] and [`shekyl_seam_bind`] do not
/// take it. They take [`hold_table`], from the table read through the hub
/// store. A test holds this lock and then binds; bind does not take it
/// again. The guard is a [`MutexGuard`], so it is `!Send`. A poisoned lock
/// is the previous holder's panic; the next test still needs the gate.
#[cfg(test)]
pub(crate) fn seam_bind_lock() -> &'static TestSeam {
    static GATE: TestSeam = TestSeam(Mutex::new(()));
    &GATE
}

/// Bind the seam as the daemon does, for a test: a stand-in owner is
/// installed first ([`crate::chain_sync_ffi::install_test_owner`]) and its
/// ends kept until the next such bind, so the router is the production
/// one, attached. A test that reads the owner's side installs its own
/// owner and calls [`shekyl_seam_bind`] directly.
///
/// # Safety
/// As [`shekyl_seam_bind`].
#[cfg(test)]
pub(crate) unsafe fn bind_attached(ctx: *mut c_void, post: Option<PostFn>) -> i32 {
    static KEPT: Mutex<Option<crate::chain_sync_ffi::TestOwner>> = Mutex::new(None);
    let owner = crate::chain_sync_ffi::install_test_owner();
    *KEPT.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner);
    // SAFETY: the caller's contract is shekyl_seam_bind's.
    unsafe { shekyl_seam_bind(ctx, post) }
}

/// The test serializer. [`TestSeam::lock`] is the only way in, so every
/// caller holds a real [`MutexGuard`].
#[cfg(test)]
pub(crate) struct TestSeam(Mutex<()>);

#[cfg(test)]
impl TestSeam {
    pub(crate) fn lock(&'static self) -> MutexGuard<'static, ()> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The table read, the table replace, and the hub store are one section.
///
/// Distinct from [`PROCESS_SOCKETS`]: bind calls [`process_sockets`], which
/// takes that mutex itself, so this one cannot be it. Install and bind both
/// take this one first, so the two orders cannot deadlock on each other.
fn hold_table() -> MutexGuard<'static, ()> {
    static TABLE: Mutex<()> = Mutex::new(());
    TABLE.lock().unwrap_or_else(PoisonError::into_inner)
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
    // The same section [`shekyl_seam_bind`] holds from its table read
    // through the hub store. A bind in that window makes this install
    // wait, then see the hub and refuse: the hub keeps the table it was
    // built with.
    let _table = hold_table();
    if hub().is_some() {
        return false;
    }
    let mut slot = PROCESS_SOCKETS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    *slot = Some(sockets);
    true
}

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

/// The process timing engine and how many times one has been started.
///
/// The service lives here so a handle alone cannot close it. `started`
/// advances only when a new engine is created, and a ban timer reads it
/// under this same lock, so the claim names the engine the task registers
/// on. Closing the engine does not reuse the number: the next start is the
/// next generation.
struct ProcessTiming {
    service: Option<EngineService<MonotonicClock>>,
    started: u64,
}

fn process_engine_slot() -> &'static Mutex<ProcessTiming> {
    static ENGINE: Mutex<ProcessTiming> = Mutex::new(ProcessTiming {
        service: None,
        started: 0,
    });
    &ENGINE
}

/// The process's one timing engine. The zone host and the Tor supervisor
/// arm deadlines on it.
pub(crate) fn process_engine() -> Handle<MonotonicClock> {
    process_engine_generation().0
}

/// The running process engine and the generation a ban timer claims.
///
/// Both come from one hold of the engine lock. A timer started from this
/// pair registers on the engine the generation names, including when a
/// close and a new engine overlap the start.
pub(crate) fn process_engine_generation() -> (Handle<MonotonicClock>, u64) {
    let mut slot = process_engine_slot().lock().expect("process engine");
    if slot.service.is_none() {
        let clock = MonotonicClock::clone(&process_clock());
        slot.service = Some(EngineService::start(clock));
        slot.started = slot.started.checked_add(1).expect("ban timer generations");
    }
    let generation = slot.started;
    let handle = slot
        .service
        .as_ref()
        .expect("the engine was just started")
        .handle();
    (handle, generation)
}

/// Stop the process engine. The next [`process_engine`] starts another,
/// and that start is the next ban-timer generation.
pub(crate) fn close_process_engine() {
    let mut slot = process_engine_slot().lock().expect("process engine");
    if let Some(engine) = slot.service.take() {
        engine.close();
    }
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
/// A null `post` or a null `ctx` clears the seam. Returns 0, or -1 when no
/// chain-sync owner is there to attach the router to: none was installed,
/// or the daemon's bind already took it. The seam would run without chain
/// sync, so the bind is refused, the binding in place is kept, and the
/// zone's start fails (CS-5).
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
        let _table = hold_table();
        store(None);
        return 0;
    };
    if ctx.is_null() {
        let _table = hold_table();
        store(None);
        return 0;
    }
    // The node's chain-sync owner, which it left for this bind. Without it
    // the seam would run without chain sync: refused, and the zone's
    // start fails with the cause.
    let (router_tx, hub_tx) = match crate::chain_sync_ffi::take() {
        Ok(attach) => attach,
        Err(refused) => {
            tracing::error!(target: "p2p", "the seam bind was refused: {}", refused.cause());
            return -1;
        }
    };
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
        let _table = hold_table();
        // The Rust Levin router is the post sink, attached to the node's
        // owner: chain sync's messages go to the owner and the rest reach
        // the C++ handler.
        let forward: shekyl_chain_sync_runtime::router::Forward =
            Arc::new(move |item: Post| post_one(&bound, item));
        let sink = Router::attached(forward, router_tx);
        let hub = Hub::new(process_sockets(), ceiling, sink.into_sink(), clock);
        // `store` stops the previous hub's dialer; this hub's is built after.
        store(Some(hub.clone()));
        hub
    };
    // The owner gone already is a node whose owner ended before its seam
    // bound. The node reports that end to the stop owner; here it is only
    // logged.
    if hub_tx.send(Arc::new(hub.clone())).is_err() {
        tracing::info!(target: "p2p", "the chain-sync owner stopped before the seam bound");
    }
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

/// Copy one whole message into the byte cap. `1` is accepted, `0` is not.
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

/// The ban table's entries, as the C++ and the daemon's owners reach them.
#[path = "seam_ban_ffi.rs"]
pub mod bans;

pub use bans::ShekylBanView;

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
        // Chain sync's owner's: the router keeps it, and the strand does
        // not read it.
        Post::Opened { .. } => {}
        // The C++ relay hears that the kept dial's session is established.
        // The peer's claim is the router's, for chain sync's owner.
        Post::HandshakeResult { id, connector, .. } => {
            let observed = routing_c(connector);
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    id.get(),
                    POST_HANDSHAKE,
                    &raw const observed,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                );
            }
        }
        Post::Closed { id, connector, end } => {
            // The dialer hears every close, with the row's end. A kept
            // session leaves its count; SessionRefused is the lists'
            // PayloadRefused. The C side reads the end's D12 cause.
            crate::dialer_ffi::on_closed(id, end);
            let cause = end.cause();
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
#[path = "seam_ffi_tests.rs"]
mod tests;
