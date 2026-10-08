// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Close-cause questions the C++ handshake still asks.
//!
//! [`shekyl_close_implicates_address`] is whether a cause should stop
//! dials to that address. The C++ handshake classifies, then asks.
//! The outbound handshake owner, once it lives in Rust, holds the cause
//! and does not read it back through [`shekyl_seam_session_cause`].

use shekyl_seam::{CloseCause, CloseKind, ConnectorId, SocketId};

use crate::seam_ffi::hub;

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
