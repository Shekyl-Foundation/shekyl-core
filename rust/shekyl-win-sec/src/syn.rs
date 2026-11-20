// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A dial socket's SYN retransmissions, for the clearnet connector.
//!
//! By default Windows retries a connect the far end refused: it resends the
//! SYN after each reset, 0.5 s apart, and reports the refusal after about
//! 2.0 s. Clearnet's dial deadline is 1.415 s, so on Windows a refusing peer
//! ended as the deadline's timeout instead of its refusal (shekyl-dev,
//! `data/windows-refused-connect/`, 2026-11-03: loopback and a remote host's
//! reset alike). `SIO_TCP_INITIAL_RTO` caps the retransmissions, and one cap
//! governs both: a cap of `n` gives `n` resends of a lost SYN and `n` retries
//! after a reset. Measured at a cap of 1: a refusal in about 0.5 s, and a lost
//! SYN still resent once at +1.0 s, as Linux does inside the same deadline.
//!
//! It lives here rather than beside its caller for the reason
//! [`crate::free_bytes_available`] does: `shekyl-clearnet` denies `unsafe`,
//! and this is one Win32 call.

use std::os::windows::io::AsRawSocket;

use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAIoctl, SIO_TCP_INITIAL_RTO, SOCKET, SOCKET_ERROR,
    TCP_INITIAL_RTO_DEFAULT_RTT, TCP_INITIAL_RTO_PARAMETERS,
};

/// The two `MaxSynRetransmissions` values the field reserves: "no
/// retransmissions" and "unspecified" (`mstcpip.h`'s `(UCHAR)-2` and
/// `(UCHAR)-1`). windows-sys declares them as `u16`, 65534 and 65535, though
/// the field is a `u8`, so they are written here as the byte the field holds.
const RESERVED: [u8; 2] = [0xFE, 0xFF];

/// The system's default initial retransmission timeout: only the SYN count
/// changes. 0 and "unspecified" behaved the same in every measured case.
#[allow(clippy::cast_possible_truncation)] // the constant is 0
const DEFAULT_RTT: u16 = TCP_INITIAL_RTO_DEFAULT_RTT as u16;

/// Cap `socket`'s SYN retransmissions at `retries`, before it connects.
///
/// # Errors
///
/// `InvalidInput` for a `retries` the field reserves (`0xFE`, `0xFF`), and the
/// WinSock error when the system refuses the option. The socket is unchanged
/// then, and still dials with the system's default retries.
pub fn cap_syn_retransmissions(socket: &impl AsRawSocket, retries: u8) -> std::io::Result<()> {
    if RESERVED.contains(&retries) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "0xFE and 0xFF are reserved SYN retransmission values",
        ));
    }
    let params = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: DEFAULT_RTT,
        MaxSynRetransmissions: retries,
    };
    // A socket handle is pointer-sized; `RawSocket` carries it as `u64`.
    let handle = SOCKET::try_from(socket.as_raw_socket()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a socket handle wider than a pointer",
        )
    })?;
    let size = u32::try_from(std::mem::size_of::<TCP_INITIAL_RTO_PARAMETERS>())
        .expect("a four-byte struct (u16, u8, padding) fits in u32");
    let mut returned = 0u32;
    // SAFETY: the handle is a live socket borrowed for the call. `params` is
    // a local the call only reads, `size` is its size, there is no output
    // buffer (null, length 0), `returned` is a local, and the call is
    // synchronous: no overlapped structure and no completion routine.
    let rc = unsafe {
        WSAIoctl(
            handle,
            SIO_TCP_INITIAL_RTO,
            (&raw const params).cast(),
            size,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        // SAFETY: reads this thread's last WinSock error, set by the call
        // above; it takes nothing.
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    Ok(())
}
