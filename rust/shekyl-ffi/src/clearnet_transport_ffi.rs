// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fd handoff for the clearnet network pipe. C++ releases the asio socket.
//! This pipe owns that descriptor. The session above it sees plaintext.

use std::ffi::c_void;
use std::net::TcpStream;
use std::sync::Arc;

use shekyl_p2p_transport::{ClosedCallback, Pipe, PlainCallback};

use crate::legacy_util::{array_from_ptr, slice_from_ptr};

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};

fn stream_from_native(native: isize) -> Option<TcpStream> {
    if native < 0 {
        return None;
    }
    #[cfg(unix)]
    {
        let Ok(fd) = i32::try_from(native) else {
            return None;
        };
        Some(unsafe { TcpStream::from_raw_fd(fd) })
    }
    #[cfg(windows)]
    {
        let Ok(socket) = usize::try_from(native) else {
            return None;
        };
        Some(unsafe { TcpStream::from_raw_socket(socket as RawSocket) })
    }
}

/// `initiator` is nonzero when this node dialed.
///
/// # Safety
/// A non-negative `native` is an owned connected TCP socket and is closed
/// on every return. `network_id` is 16 readable bytes when non-null. `on_plain`
/// and `on_closed` are callable until [`shekyl_clearnet_detach`] joins the
/// pipe threads. `ctx` stays valid for that same interval.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_attach(
    native: isize,
    network_id: *const u8,
    initiator: i32,
    on_plain: PlainCallback,
    on_closed: ClosedCallback,
    ctx: *mut c_void,
) -> *mut Pipe {
    let Some(stream) = stream_from_native(native) else {
        return std::ptr::null_mut();
    };
    if network_id.is_null() {
        drop(stream);
        return std::ptr::null_mut();
    }
    let Some(id) = (unsafe { array_from_ptr::<16>(network_id) }) else {
        drop(stream);
        return std::ptr::null_mut();
    };
    match Pipe::attach(stream, &id, initiator != 0, on_plain, on_closed, ctx) {
        Ok(pipe) => Arc::into_raw(pipe).cast_mut(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`] and has not been detached.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_start(link: *const Pipe) {
    if !link.is_null() {
        unsafe { &*link }.start();
    }
}

/// # Safety
/// `link` is a live pipe pointer published under the caller's mutex, which
/// `detach` also takes before freeing it.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_pin(link: *const Pipe) {
    if !link.is_null() {
        unsafe { Arc::increment_strong_count(link) };
    }
}

/// # Safety
/// Pairs with one [`shekyl_clearnet_pin`] on the same pointer.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_unpin(link: *const Pipe) {
    if !link.is_null() {
        unsafe { Arc::decrement_strong_count(link) };
    }
}

/// # Safety
/// `link` is pinned, or the caller holds the publication mutex for the call.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_write(
    link: *const Pipe,
    data: *const u8,
    len: usize,
) -> i32 {
    if link.is_null() {
        return -1;
    }
    let bytes = if data.is_null() {
        if len != 0 {
            return -1;
        }
        &[][..]
    } else {
        match unsafe { slice_from_ptr(data, len) } {
            Some(bytes) => bytes,
            None => return -1,
        }
    };
    if unsafe { &*link }.write(bytes).is_ok() {
        0
    } else {
        -1
    }
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`]. Called once.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_detach(link: *mut Pipe) {
    if link.is_null() {
        return;
    }
    let pipe = unsafe { Arc::from_raw(link) };
    pipe.shutdown();
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`] and has not been detached.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_read_done(link: *const Pipe) {
    if !link.is_null() {
        unsafe { &*link }.read_done();
    }
}
