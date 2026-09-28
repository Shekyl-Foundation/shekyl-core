// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! FFI for the p2p seam.
//!
//! C++ calls `send`, `close`, and `await_handler`. Rust calls the bound
//! post function, which only enqueues onto the connection's strand.
//! The strand calls back when the handler exists, when a delivery
//! returns, and when `closed` starts.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use shekyl_seam::{Hub, Post};
use shekyl_thread_ledger::{record_executor, BlockingLanes, ExecutorRow, ThreadName};
use shekyl_transport_layer::{CloseCause, ConnectorId, Direction, SocketId};

const SEND_CAP: usize = 64 * 1024;

/// Clearnet. Matches [`ConnectorId::Clearnet`].
pub const SHEKYL_CONNECTOR_CLEARNET: u32 = 0;
/// Tor. Matches [`ConnectorId::Tor`].
pub const SHEKYL_CONNECTOR_TOR: u32 = 1;
/// Accepted sockets.
pub const SHEKYL_DIRECTION_INBOUND: u32 = 0;
/// Dialed sockets.
pub const SHEKYL_DIRECTION_OUTBOUND: u32 = 1;

const _: () = {
    assert!(ConnectorId::Clearnet as u8 as u32 == SHEKYL_CONNECTOR_CLEARNET);
    assert!(ConnectorId::Tor as u8 as u32 == SHEKYL_CONNECTOR_TOR);
    assert!(Direction::Inbound.index() == SHEKYL_DIRECTION_INBOUND as usize);
    assert!(Direction::Outbound.index() == SHEKYL_DIRECTION_OUTBOUND as usize);
};

type PostFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    id: u64,
    kind: u32,
    bytes: *const u8,
    len: usize,
    cause: *const CloseCause,
);

/// The executor pointer. C++ keeps it alive for as long as the bind stands.
struct Ctx(*mut c_void);

// The pointer is the executor, not a handler. The bind contract is that
// every thread which posts may share it, and the post only enqueues.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    fn get(&self) -> *mut c_void {
        self.0
    }
}

/// The executor pointer and the enqueue function. Not a handler.
struct Bound {
    ctx: Ctx,
    post: PostFn,
}

static STATE: Mutex<Option<Hub>> = Mutex::new(None);
static EXECUTORS: LazyLock<Mutex<HashMap<u64, ExecutorRow>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_EXECUTOR: AtomicU64 = AtomicU64::new(1);

fn hub() -> Option<Hub> {
    STATE.lock().expect("seam state poisoned").clone()
}

fn id_of(hub: &Hub, raw: u64) -> Option<SocketId> {
    hub.id_of(raw)
}

fn bytes_of(bytes: *const u8, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if bytes.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(bytes, len) }.to_vec())
}

/// Install the post callback. A null `post` or a null `ctx` clears the seam.
///
/// # Safety
/// `post` stays callable, and `ctx` stays valid, until the next bind.
/// `post` does not call back into the seam before it returns.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_bind(ctx: *mut c_void, post: Option<PostFn>) {
    let mut state = STATE.lock().expect("seam state poisoned");
    let Some(post) = post else {
        *state = None;
        return;
    };
    if ctx.is_null() {
        *state = None;
        return;
    }
    let bound = Bound {
        ctx: Ctx(ctx),
        post,
    };
    *state = Some(Hub::new(
        SEND_CAP,
        Arc::new(move |item: Post| {
            let cause = item.cause;
            let bytes = item.bytes;
            let kind = match item.kind {
                shekyl_seam::PostKind::Established => 1,
                shekyl_seam::PostKind::Deliver => 2,
                shekyl_seam::PostKind::Closed => 3,
            };
            unsafe {
                (bound.post)(
                    bound.ctx.get(),
                    item.id.get(),
                    kind,
                    bytes.as_ptr(),
                    bytes.len(),
                    cause
                        .as_ref()
                        .map(std::ptr::from_ref)
                        .unwrap_or(std::ptr::null()),
                );
            }
        }),
    ));
}

/// Reserve an outbound clearnet socket. `0` is refusal.
#[no_mangle]
pub extern "C" fn shekyl_seam_open_outbound(ipv4: u32) -> u64 {
    let Some(hub) = hub() else {
        return 0;
    };
    hub.open_outbound(Ipv4Addr::from(ipv4))
        .map(SocketId::get)
        .unwrap_or(0)
}

/// Post `established` and wait until the strand has built the handler.
///
/// The state lock is not held across the wait.
#[no_mangle]
pub extern "C" fn shekyl_seam_await_handler(id: u64) -> i32 {
    let Some(hub) = hub() else {
        return -1;
    };
    let Some(id) = id_of(&hub, id) else {
        return -1;
    };
    if hub.await_handler(id) {
        0
    } else {
        -1
    }
}

/// The strand finished `established`.
#[no_mangle]
pub extern "C" fn shekyl_seam_handler_ready(id: u64) {
    let Some(hub) = hub() else {
        return;
    };
    if let Some(id) = id_of(&hub, id) {
        hub.handler_ready(id);
    }
}

/// Post one delivery. `0` means it was posted.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_deliver(id: u64, bytes: *const u8, len: usize) -> i32 {
    let Some(owned) = bytes_of(bytes, len) else {
        return -1;
    };
    let Some(hub) = hub() else {
        return -1;
    };
    let Some(id) = id_of(&hub, id) else {
        return -1;
    };
    if hub.deliver(id, &owned) {
        0
    } else {
        -1
    }
}

/// The strand finished `handle_recv`.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero and `bytes` is
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_deliver_result(
    id: u64,
    bytes: *const u8,
    len: usize,
    accepted: i32,
) -> i32 {
    let Some(owned) = bytes_of(bytes, len) else {
        return -1;
    };
    let Some(hub) = hub() else {
        return -1;
    };
    let Some(id) = id_of(&hub, id) else {
        return -1;
    };
    if hub.deliver_result(id, &owned, accepted != 0) {
        0
    } else {
        -1
    }
}

/// The strand has started `closed`.
#[no_mangle]
pub extern "C" fn shekyl_seam_handler_gone(id: u64) {
    let Some(hub) = hub() else {
        return;
    };
    if let Some(id) = id_of(&hub, id) {
        hub.handler_gone(id);
    }
}

/// Copy one whole message into the byte cap. `1` is accepted. `0` is not.
///
/// # Safety
/// `bytes` is readable for `len` when `len` is nonzero.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_send(id: u64, bytes: *const u8, len: usize) -> i32 {
    let Some(owned) = bytes_of(bytes, len) else {
        return 0;
    };
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(id) = id_of(&hub, id) else {
        return 0;
    };
    if hub.send(id, owned) {
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
    if let Some(id) = id_of(&hub, id) {
        hub.close(id);
    }
}

/// Write the recorded cause. Returns 1 when one is recorded.
///
/// # Safety
/// `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_cause(id: u64, out: *mut CloseCause) -> i32 {
    if out.is_null() {
        return 0;
    }
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(id) = id_of(&hub, id) else {
        return 0;
    };
    let Some(cause) = hub.cause(id) else {
        return 0;
    };
    unsafe {
        *out = cause;
    }
    1
}

/// Live sockets for one connector and direction.
#[no_mangle]
pub extern "C" fn shekyl_seam_socket_count(connector: u32, direction: u32) -> u64 {
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(connector) = connector_of(connector) else {
        return 0;
    };
    let Some(direction) = direction_of(direction) else {
        return 0;
    };
    hub.socket_count(connector, direction)
}

/// Inbound sockets on every connector.
#[no_mangle]
pub extern "C" fn shekyl_seam_inbound_held() -> u64 {
    hub().map(|hub| hub.inbound_held()).unwrap_or(0)
}

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
    let Ok(budget) = shekyl_seam::executor_floor(BlockingLanes::new(lanes), workers) else {
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

fn connector_of(id: u32) -> Option<ConnectorId> {
    match id {
        SHEKYL_CONNECTOR_CLEARNET => Some(ConnectorId::Clearnet),
        SHEKYL_CONNECTOR_TOR => Some(ConnectorId::Tor),
        _ => None,
    }
}

fn direction_of(id: u32) -> Option<Direction> {
    match id {
        SHEKYL_DIRECTION_INBOUND => Some(Direction::Inbound),
        SHEKYL_DIRECTION_OUTBOUND => Some(Direction::Outbound),
        _ => None,
    }
}
