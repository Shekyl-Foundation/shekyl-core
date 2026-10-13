// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The transport deadlines (D9), the send-queue cap, the shutdown wait and
//! the runtime budget, as numbers this crate owns.
//!
//! Moved from the C++ `node_server::transport_spans` with the P2P-3
//! cutover (2026-10-13), so retuning a span no longer means editing C++.
//! The provenance below is that function's, kept with the numbers.
//!
//! Clearnet dial, handshake and gap: twice the sum of the 700 ms
//! GEO-satellite RTT ceiling and the node-local residual, rounded up to
//! 1 ms. Residuals are the larger of the LAN, South America (~170 ms) and
//! New York (~24 ms) legs in
//! `docs/benchmarks/p2p_cutover_crossbuild_20260929.md`: dial 1.415 s
//! (residual 7.2 ms), handshake 1.426 s (12.6 ms, the measured median of
//! the body), gap 1.430 s (residual 14.7 ms). The ~700 ms handshake tail
//! is not a term in any of these.
//!
//! Tor dial 9.1 s: 2 × p99 (4.54 s) of the floor dial distribution, South
//! America circuit, proof-of-work on. A clearnet dial through a SOCKS
//! proxy uses this clock: the worst measured SOCKS path, pending its own
//! distribution. The three clearnet legs had no proxy. Tor gap 2.6 s: the
//! outbound direction, the larger of the two distant-circuit gaps.
//!
//! Shutdown waits out the longest armed deadline, the Tor dial. The send
//! queue holds one admitted packet, room for the largest legitimate
//! message (Levin's default packet bound). Workers and blocking are the
//! structural floor; the thread-budget leg replaces them after the ledger
//! row.

/// Clearnet connect, from the dial to the socket.
pub const CLEARNET_DIAL_WITHIN_NANOS: u64 = 1_415_000_000;
/// Clearnet handshake, from the socket to the session.
pub const CLEARNET_HANDSHAKE_WITHIN_NANOS: u64 = 1_426_000_000;
/// Clearnet gap: the longest silence a session keeps.
pub const CLEARNET_GAP_WITHIN_NANOS: u64 = 1_430_000_000;
/// Tor connect through the SOCKS proxy; also the proxied clearnet dial.
pub const TOR_DIAL_WITHIN_NANOS: u64 = 9_100_000_000;
/// Tor gap: the longest silence a session keeps.
pub const TOR_GAP_WITHIN_NANOS: u64 = 2_600_000_000;
/// Bytes of session plaintext the writer holds: `LEVIN_DEFAULT_MAX_PACKET_SIZE`.
pub const SEND_QUEUE_BYTES: u64 = 100_000_000;
/// The pool's shutdown wait: the longest armed deadline, the Tor dial.
pub const SHUTDOWN_TIMEOUT_NANOS: u64 = TOR_DIAL_WITHIN_NANOS;
/// The runtime's worker threads: the structural floor.
pub const WORKERS: usize = 2;
/// The runtime's blocking threads: the structural floor.
pub const BLOCKING: usize = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// The shutdown wait covers every armed deadline, as the provenance
    /// says; a retune that raised a deadline past it would leave a pool
    /// shut down under a live timer.
    #[test]
    fn the_shutdown_wait_covers_every_deadline() {
        for within in [
            CLEARNET_DIAL_WITHIN_NANOS,
            CLEARNET_HANDSHAKE_WITHIN_NANOS,
            CLEARNET_GAP_WITHIN_NANOS,
            TOR_DIAL_WITHIN_NANOS,
            TOR_GAP_WITHIN_NANOS,
        ] {
            assert!(SHUTDOWN_TIMEOUT_NANOS >= within);
        }
    }

    /// Each clearnet span is 2 × (700 ms + its residual), rounded up to
    /// 1 ms: the derivation, not the literal, is what the numbers mean.
    #[test]
    fn each_clearnet_span_is_twice_the_ceiling_plus_its_residual() {
        const GEO_RTT_CEILING_NANOS: u64 = 700_000_000;
        for (span, residual_micros) in [
            (CLEARNET_DIAL_WITHIN_NANOS, 7_200),
            (CLEARNET_HANDSHAKE_WITHIN_NANOS, 12_600),
            (CLEARNET_GAP_WITHIN_NANOS, 14_700),
        ] {
            let exact = 2 * (GEO_RTT_CEILING_NANOS + residual_micros * 1_000);
            let rounded_up = exact.div_ceil(1_000_000) * 1_000_000;
            assert_eq!(span, rounded_up);
        }
    }
}
