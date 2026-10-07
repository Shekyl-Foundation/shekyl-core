// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The published seam board, as C reads it.
//!
//! A count is an integer: [`shekyl_seam_board_count`] for one connector
//! and direction, [`shekyl_seam_board_direction_count`] for that direction
//! on every connector. Both count a row whether or not the handshake has
//! finished. Address walks use [`shekyl_seam_board`]: one snapshot, and
//! each visit is one fixed-size row. The row is the admission id, the
//! handshake flag, and the endpoint. Connector and direction are fields
//! of that endpoint.

use std::ffi::c_void;

use shekyl_seam::{connector_from_index, direction_from_index, Row};

use crate::seam_ffi::{
    hub, observed_c, ShekylSeamObserved, SHEKYL_DIRECTION_INBOUND, SHEKYL_DIRECTION_OUTBOUND,
};

/// One published row.
///
/// `endpoint` is the address, the connector, and the direction observed
/// at admission. `established` is 1 after the Levin handshake. It is not
/// an input to [`shekyl_seam_board_count`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShekylSeamBoardRow {
    pub id: u64,
    pub established: u8,
    /// Aligns `endpoint` to 8. Not a field.
    pub _pad: [u8; 7],
    pub endpoint: ShekylSeamObserved,
    /// Aligns the unix-second fields. Not a field.
    pub _pad_tail: [u8; 2],
    /// Unix seconds at admission.
    pub started: u64,
    /// Unix seconds of the last delivered frame. Zero until one arrives.
    pub last_recv: u64,
    /// Unix seconds of the last accepted send. Zero until one leaves.
    pub last_send: u64,
}

const _: () = {
    assert!(std::mem::size_of::<ShekylSeamObserved>() == 70);
    assert!(std::mem::offset_of!(ShekylSeamBoardRow, established) == 8);
    assert!(std::mem::offset_of!(ShekylSeamBoardRow, endpoint) == 16);
    assert!(std::mem::offset_of!(ShekylSeamBoardRow, started) == 88);
    assert!(std::mem::size_of::<ShekylSeamBoardRow>() == 112);
    assert!(SHEKYL_DIRECTION_INBOUND == 0 && SHEKYL_DIRECTION_OUTBOUND == 1);
};

fn board_row(row: &Row) -> ShekylSeamBoardRow {
    ShekylSeamBoardRow {
        id: row.id().get(),
        established: u8::from(row.established()),
        _pad: [0; 7],
        endpoint: observed_c(&row.endpoint()),
        _pad_tail: [0; 2],
        started: row.started_unix(),
        last_recv: row.last_recv_unix(),
        last_send: row.last_send_unix(),
    }
}

/// Rows of `connector` and `direction` on the process hub.
///
/// The handshake flag is not read. A missing hub is zero. An index that
/// is not a connector or a direction is zero: this process holds no such rows.
#[no_mangle]
pub extern "C" fn shekyl_seam_board_count(connector: u32, direction: u32) -> u64 {
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(connector) = connector_from_index(connector) else {
        return 0;
    };
    let Some(direction) = direction_from_index(direction) else {
        return 0;
    };
    u64::try_from(hub.board().count(connector, direction)).unwrap_or(u64::MAX)
}

/// 1 when `id`'s row has finished the Levin handshake, 0 when the row is
/// present and the handshake has not, -1 when the hub has no such row.
#[no_mangle]
pub extern "C" fn shekyl_seam_session_established(id: u64) -> i32 {
    if id == 0 {
        return -1;
    }
    let Some(hub) = hub() else {
        return -1;
    };
    match hub.board().rows().iter().find(|row| row.id().get() == id) {
        Some(row) => i32::from(row.established()),
        None => -1,
    }
}

/// Rows in `direction` on every connector.
///
/// The sum of [`shekyl_seam_board_count`] across the connectors this
/// process names. A missing hub, or a direction index that is not one, is zero.
#[no_mangle]
pub extern "C" fn shekyl_seam_board_direction_count(direction: u32) -> u64 {
    let Some(hub) = hub() else {
        return 0;
    };
    let Some(direction) = direction_from_index(direction) else {
        return 0;
    };
    u64::try_from(hub.board().direction_count(direction)).unwrap_or(u64::MAX)
}

/// Visit the process hub's board, one fixed-size row per call.
///
/// There is one hub and one snapshot. Each call of `visit` receives one
/// row, and the pointer is valid only for that call. A missing hub, or a
/// board with no rows, visits once with a null row.
///
/// # Safety
/// `visit` receives `ctx` and a pointer to one row of this call's buffer,
/// or null when the board is empty. `visit` does not call back into the seam.
#[no_mangle]
pub unsafe extern "C" fn shekyl_seam_board(
    ctx: *mut c_void,
    visit: Option<unsafe extern "C" fn(*mut c_void, *const ShekylSeamBoardRow)>,
) -> i32 {
    let Some(visit) = visit else {
        return -1;
    };
    let Some(hub) = hub() else {
        unsafe { visit(ctx, std::ptr::null()) };
        return 0;
    };
    let rows: Vec<ShekylSeamBoardRow> = hub.board().rows().iter().map(board_row).collect();
    if rows.is_empty() {
        unsafe { visit(ctx, std::ptr::null()) };
        return 0;
    }
    for row in &rows {
        unsafe { visit(ctx, row) };
    }
    0
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use shekyl_seam::CloseCause;

    use super::*;
    use crate::inbound_ceiling_ffi::{ShekylInboundCeiling, SHEKYL_INBOUND_CEILING_UNLIMITED};
    use crate::seam_ffi::{
        seam_bind_lock, shekyl_seam_bind, shekyl_seam_close, shekyl_seam_handler_armed,
        shekyl_seam_handler_gone, shekyl_seam_install_loopback, shekyl_seam_open, shekyl_seam_reap,
        ShekylSeamAddress, ShekylSeamObserved, ADDR_IPV4, POST_ESTABLISHED,
        SHEKYL_CONNECTOR_CLEARNET, SHEKYL_CONNECTOR_TOR,
    };
    use crate::zone_ffi::shekyl_zone_session_established;

    const DOC_OCTETS: [u8; 4] = [203, 0, 113, 10];
    const DOC_PORT: u16 = 18_080;
    /// An index that is not a connector and not a direction.
    const UNNAMED_INDEX: u32 = u32::MAX;

    struct Seen {
        rows: Vec<ShekylSeamBoardRow>,
        pointer_was_null: bool,
    }

    unsafe extern "C" fn collect(ctx: *mut c_void, row: *const ShekylSeamBoardRow) {
        let seen = unsafe { &mut *ctx.cast::<Seen>() };
        if row.is_null() {
            seen.pointer_was_null = true;
            return;
        }
        // One fixed-size row. The pointer is valid only for this call.
        seen.pointer_was_null = false;
        seen.rows.push(unsafe { row.read() });
    }

    /// Stores the admission id. The post runs under the hub lock, so this
    /// does not call back into the seam.
    unsafe extern "C" fn note_established(
        ctx: *mut c_void,
        id: u64,
        kind: u32,
        _observed: *const ShekylSeamObserved,
        _bytes: *const u8,
        _len: usize,
        _cause: *const CloseCause,
    ) {
        if kind != POST_ESTABLISHED {
            return;
        }
        let slot = unsafe { &*ctx.cast::<Mutex<Option<u64>>>() };
        *slot.lock().expect("arm slot") = Some(id);
    }

    fn unlimited() -> ShekylInboundCeiling {
        ShekylInboundCeiling {
            kind: SHEKYL_INBOUND_CEILING_UNLIMITED,
            ceiling: 0,
            soft_limit: 0,
            held: 0,
        }
    }

    fn doc_address() -> ShekylSeamAddress {
        let mut addr = ShekylSeamAddress {
            connector: u8::try_from(SHEKYL_CONNECTOR_CLEARNET).expect("connector fits"),
            address_type: ADDR_IPV4,
            zone_only: 0,
            _pad: 0,
            port: DOC_PORT,
            len: u16::try_from(DOC_OCTETS.len()).expect("ipv4 len"),
            bytes: [0; shekyl_seam::TOR_HOST_MAX],
        };
        addr.bytes[..DOC_OCTETS.len()].copy_from_slice(&DOC_OCTETS);
        addr
    }

    fn visit(seen: &mut Seen) -> i32 {
        seen.rows.clear();
        seen.pointer_was_null = false;
        unsafe { shekyl_seam_board((seen as *mut Seen).cast::<c_void>(), Some(collect)) }
    }

    fn assert_doc_endpoint(row: &ShekylSeamBoardRow) {
        assert_eq!(
            row.endpoint.connector,
            u8::try_from(SHEKYL_CONNECTOR_CLEARNET).expect("connector fits")
        );
        assert_eq!(u32::from(row.endpoint.direction), SHEKYL_DIRECTION_OUTBOUND);
        assert_eq!(row.endpoint.address_type, ADDR_IPV4);
        assert_eq!(row.endpoint.zone_only, 0);
        assert_eq!(row.endpoint.port, DOC_PORT);
        assert_eq!(
            row.endpoint.len,
            u16::try_from(DOC_OCTETS.len()).expect("ipv4 len")
        );
        assert_eq!(&row.endpoint.bytes[..DOC_OCTETS.len()], &DOC_OCTETS);
    }

    #[test]
    fn the_board_call_refuses_a_null_visit() {
        assert_eq!(unsafe { shekyl_seam_board(std::ptr::null_mut(), None) }, -1);
    }

    #[test]
    fn an_unestablished_outbound_row_survives_the_copy() {
        let _bind = seam_bind_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = Arc::new(Mutex::new(None::<u64>));
        let stop = Arc::new(AtomicBool::new(false));
        let slot_for_armer = Arc::clone(&slot);
        let stop_for_armer = Arc::clone(&stop);
        let armer = thread::spawn(move || {
            while !stop_for_armer.load(Ordering::Relaxed) {
                let id = slot_for_armer.lock().expect("arm slot").take();
                if let Some(id) = id {
                    shekyl_seam_handler_armed(id, 1);
                    return;
                }
                thread::sleep(Duration::from_millis(1));
            }
        });

        let ceiling = unlimited();
        let bound = unsafe {
            shekyl_seam_bind(
                Arc::as_ptr(&slot).cast_mut().cast::<c_void>(),
                Some(note_established),
                &raw const ceiling,
            )
        };
        assert_eq!(bound, 0);
        assert_eq!(shekyl_seam_install_loopback(), 0);

        let mut seen = Seen {
            rows: Vec::new(),
            pointer_was_null: false,
        };
        assert_eq!(visit(&mut seen), 0);
        assert!(seen.pointer_was_null);
        assert!(seen.rows.is_empty());
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_OUTBOUND),
            0
        );

        let addr = doc_address();
        let opened = unsafe { shekyl_seam_open(&raw const addr, 0) };
        assert_ne!(opened.id, 0, "cause {}", opened.cause_kind);

        assert_eq!(visit(&mut seen), 0);
        assert!(!seen.pointer_was_null);
        assert_eq!(seen.rows.len(), 1);
        let row = seen.rows[0];
        assert_eq!(row.id, opened.id);
        assert_eq!(row.established, 0);
        assert_doc_endpoint(&row);
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_OUTBOUND),
            1
        );
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_INBOUND),
            0
        );
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_TOR, SHEKYL_DIRECTION_OUTBOUND),
            0
        );
        assert_eq!(
            shekyl_seam_board_direction_count(SHEKYL_DIRECTION_OUTBOUND),
            1
        );
        assert_eq!(
            shekyl_seam_board_count(UNNAMED_INDEX, SHEKYL_DIRECTION_OUTBOUND),
            0
        );
        assert_eq!(shekyl_seam_board_direction_count(UNNAMED_INDEX), 0);

        shekyl_zone_session_established(opened.id);
        assert_eq!(visit(&mut seen), 0);
        assert_eq!(seen.rows.len(), 1);
        assert_eq!(seen.rows[0].id, opened.id);
        assert_eq!(seen.rows[0].established, 1);
        assert_doc_endpoint(&seen.rows[0]);
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_OUTBOUND),
            1
        );

        shekyl_seam_close(opened.id);
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_OUTBOUND),
            0
        );
        assert_eq!(visit(&mut seen), 0);
        assert!(seen.pointer_was_null);
        assert!(seen.rows.is_empty());

        shekyl_seam_handler_gone(opened.id);
        shekyl_seam_reap(opened.id);
        unsafe {
            shekyl_seam_bind(std::ptr::null_mut(), None, std::ptr::null());
        }
        assert_eq!(
            shekyl_seam_board_count(SHEKYL_CONNECTOR_CLEARNET, SHEKYL_DIRECTION_OUTBOUND),
            0
        );
        assert_eq!(visit(&mut seen), 0);
        assert!(seen.pointer_was_null);

        stop.store(true, Ordering::Relaxed);
        armer.join().expect("armer");
    }
}
