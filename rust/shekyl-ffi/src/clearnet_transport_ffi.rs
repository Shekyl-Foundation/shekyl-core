// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Fd handoff for the clearnet Noise channel. C++ dups the socket and stops
//! reading it. This thread owns the duplicate.

use std::ffi::c_void;
use std::net::TcpStream;

use shekyl_p2p_transport::Link;

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::{FromRawSocket, RawSocket};

fn stream_from_native(native: isize) -> Option<TcpStream> {
    #[cfg(unix)]
    {
        let fd = i32::try_from(native).ok()?;
        Some(unsafe { TcpStream::from_raw_fd(fd) })
    }
    #[cfg(windows)]
    {
        let socket = u64::try_from(native).ok()?;
        Some(unsafe { TcpStream::from_raw_socket(socket as RawSocket) })
    }
}

/// `initiator` is nonzero when this node dialed.
///
/// # Safety
/// `native` is an owned duplicate of a connected TCP socket. `network_id` is
/// 16 readable bytes. `on_plain` may be called from a Rust thread until
/// [`shekyl_clearnet_detach`]. `ctx` stays valid for that same interval.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_attach(
    native: isize,
    network_id: *const u8,
    initiator: i32,
    on_plain: extern "C" fn(*mut c_void, *const u8, usize),
    ctx: *mut c_void,
) -> *mut Link {
    if network_id.is_null() {
        return std::ptr::null_mut();
    }
    let mut id = [0u8; 16];
    std::ptr::copy_nonoverlapping(network_id, id.as_mut_ptr(), 16);
    let Some(stream) = stream_from_native(native) else {
        return std::ptr::null_mut();
    };
    match Link::attach(stream, &id, initiator != 0, on_plain, ctx) {
        Ok(link) => Box::into_raw(link),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`] and has not been detached.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_write(
    link: *mut Link,
    data: *const u8,
    len: usize,
) -> i32 {
    if link.is_null() || (data.is_null() && len != 0) {
        return -1;
    }
    let bytes = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    };
    if (*link).write(bytes).is_ok() {
        0
    } else {
        -1
    }
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`]. Called once.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_detach(link: *mut Link) {
    if !link.is_null() {
        drop(Box::from_raw(link));
    }
}

/// # Safety
/// `link` came from [`shekyl_clearnet_attach`] and has not been detached.
#[no_mangle]
pub unsafe extern "C" fn shekyl_clearnet_read_done(link: *mut Link) {
    if !link.is_null() {
        shekyl_p2p_transport::release_read_budget(&*link);
    }
}
