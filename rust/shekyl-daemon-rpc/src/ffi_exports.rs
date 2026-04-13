//! C FFI entry points for starting/stopping the Axum daemon RPC server.
//!
//! These are `#[no_mangle] extern "C"` functions called from `daemon.cpp`
//! via the declarations in `shekyl_ffi.h`. They live in this crate (not
//! `shekyl-ffi`) so that `libshekyl_ffi.a` does not pull in daemon-specific
//! symbols that reference `core_rpc_ffi_*`.

use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

static DAEMON_RPC_RUNNING: AtomicBool = AtomicBool::new(false);

/// Opaque handle returned to C++ for a running daemon RPC server.
#[repr(C)]
pub struct ShekylDaemonRpcHandle {
    shutdown: *const tokio::sync::Notify,
    rt: *const tokio::runtime::Runtime,
}

/// Start the Axum daemon RPC server on a dedicated Tokio runtime.
///
/// Returns an opaque handle, or null on failure. Caller must eventually call
/// `shekyl_daemon_rpc_stop` to shut down.
///
/// # Safety
///
/// - `rpc_server_ptr` must be a valid pointer to an initialized `core_rpc_server`,
///   or null (returns null immediately).
/// - `bind_addr` must be a valid null-terminated C string, or null (returns null).
/// - The pointed-to `core_rpc_server` must remain alive for the lifetime of the
///   returned handle.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_start(
    rpc_server_ptr: *mut std::ffi::c_void,
    bind_addr: *const c_char,
    restricted: bool,
) -> *mut ShekylDaemonRpcHandle {
    if rpc_server_ptr.is_null() || bind_addr.is_null() {
        return std::ptr::null_mut();
    }
    if DAEMON_RPC_RUNNING.swap(true, Ordering::SeqCst) {
        return std::ptr::null_mut();
    }

    let bind = match std::ffi::CStr::from_ptr(bind_addr).to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => {
            DAEMON_RPC_RUNNING.store(false, Ordering::SeqCst);
            return std::ptr::null_mut();
        }
    };

    let core = match crate::core::CoreRpc::from_raw(rpc_server_ptr) {
        Some(c) => std::sync::Arc::new(c),
        None => {
            DAEMON_RPC_RUNNING.store(false, Ordering::SeqCst);
            return std::ptr::null_mut();
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("daemon-rpc")
        .build()
    {
        Ok(r) => r,
        Err(_) => {
            DAEMON_RPC_RUNNING.store(false, Ordering::SeqCst);
            return std::ptr::null_mut();
        }
    };

    let config = crate::server::ServerConfig {
        bind_address: bind,
        restricted,
        ..Default::default()
    };

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_for_server = shutdown.clone();

    rt.spawn(async move {
        if let Err(e) = crate::server::run_server(core, config, shutdown_for_server).await {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });

    let handle = Box::new(ShekylDaemonRpcHandle {
        shutdown: std::sync::Arc::into_raw(shutdown),
        rt: Box::into_raw(Box::new(rt)) as *const _,
    });

    Box::into_raw(handle)
}

/// Stop the Axum daemon RPC server and release all resources.
///
/// # Safety
///
/// - `handle` must be a pointer returned by `shekyl_daemon_rpc_start`, or null
///   (no-op). Each handle must be stopped exactly once.
#[no_mangle]
pub unsafe extern "C" fn shekyl_daemon_rpc_stop(handle: *mut ShekylDaemonRpcHandle) {
    if handle.is_null() {
        return;
    }
    let handle = Box::from_raw(handle);

    if !handle.shutdown.is_null() {
        let notify = std::sync::Arc::from_raw(handle.shutdown);
        notify.notify_one();
    }

    if !handle.rt.is_null() {
        let rt = Box::from_raw(handle.rt as *mut tokio::runtime::Runtime);
        rt.shutdown_background();
    }

    DAEMON_RPC_RUNNING.store(false, Ordering::SeqCst);
}
