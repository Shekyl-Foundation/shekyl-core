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
use std::sync::{Arc, Mutex};
use std::thread;

use shekyl_peer_policy::{InboundCeiling, UnboundedReason};
use shekyl_seam::{
    connector_from_index, direction_from_index, drive_inbound, CloseCause, CloseKind, ConnectorId,
    Direction, Endpoint, Hub, Post, SocketId, TOR_HOST_MAX,
};

use crate::inbound_ceiling_ffi::{
    ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_BOUNDED, SHEKYL_INBOUND_CEILING_COUNT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_EXCEEDS_COUNTER, SHEKYL_INBOUND_CEILING_LIMIT_UNREADABLE,
    SHEKYL_INBOUND_CEILING_NO_PER_PROCESS_LIMIT, SHEKYL_INBOUND_CEILING_UNLIMITED,
};
use crate::legacy_util::slice_from_ptr;

/// Outbound cap for the loopback harness. Not the measured session limit.
const HARNESS_SEND_CAP: usize = 64 * 1024;

/// `established`. Matches the C header.
const POST_ESTABLISHED: u32 = 1;
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
const ADDR_IPV4: u8 = 1;
const ADDR_IPV6: u8 = 2;
const ADDR_I2P: u8 = 3;
const ADDR_TOR: u8 = 4;

const _: () = {
    assert!(ConnectorId::Clearnet as u8 as u32 == SHEKYL_CONNECTOR_CLEARNET);
    assert!(ConnectorId::Tor as u8 as u32 == SHEKYL_CONNECTOR_TOR);
    assert!(Direction::Inbound.index() == SHEKYL_DIRECTION_INBOUND as usize);
    assert!(Direction::Outbound.index() == SHEKYL_DIRECTION_OUTBOUND as usize);
    assert!(ADDR_IPV4 == 1 && ADDR_IPV6 == 2 && ADDR_I2P == 3 && ADDR_TOR == 4);
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

fn hub() -> Option<Hub> {
    STATE.lock().expect("seam state").clone()
}

/// One admission table for the process. A new binding does not mint ids
/// again: a `reap` that arrives after the swap names an id the new hub
/// does not hold.
fn process_sockets() -> shekyl_seam::Sockets {
    static TABLE: std::sync::OnceLock<shekyl_seam::Sockets> = std::sync::OnceLock::new();
    TABLE.get_or_init(shekyl_seam::Sockets::new).clone()
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

fn ceiling_from_abi(ceiling: ShekylInboundCeiling) -> Option<InboundCeiling> {
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
    store(Some(Hub::with_clock(
        process_sockets(),
        ceiling,
        Arc::new(move |item: Post| post_one(&bound, item)),
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
        return refused(CloseCause::new(CloseKind::DialFailed));
    }
    let Some(hub) = hub() else {
        return refused(CloseCause::new(CloseKind::DialFailed));
    };
    let addr = unsafe { &*addr };
    let Some(endpoint) = endpoint_from_c(addr, inbound != 0) else {
        return refused(CloseCause::new(CloseKind::DialFailed));
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
            let host = std::str::from_utf8(&addr.bytes[..len]).ok()?;
            Some(Endpoint::Tor {
                host: host.to_owned(),
                port: addr.port,
            })
        }
        _ => None,
    }
}

fn observed_c(endpoint: &Endpoint) -> ShekylSeamObserved {
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
        Endpoint::Tor { host, port } => {
            let raw = host.as_bytes();
            let len = raw.len().min(TOR_HOST_MAX);
            out.address_type = ADDR_TOR;
            out.port = *port;
            out.len = u16::try_from(len).expect("tor host fits");
            out.bytes[..len].copy_from_slice(&raw[..len]);
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
        Post::Deliver { id, bytes } => unsafe {
            (bound.post)(
                bound.ctx.get(),
                id.get(),
                POST_DELIVER,
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len(),
                std::ptr::null(),
            );
        },
        Post::Closed { id, cause } => unsafe {
            (bound.post)(
                bound.ctx.get(),
                id.get(),
                POST_CLOSED,
                std::ptr::null(),
                std::ptr::null(),
                0,
                &raw const cause,
            );
        },
    }
}
