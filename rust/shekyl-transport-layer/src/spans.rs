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
//! The Tor spans are RustPath (Rick, 2026-10-14), measured on the Rust
//! dialer from cold first contact: two runs of 100 fresh client starts,
//! each with a fresh managed Tor, against a responder on the measurement
//! host and on the floor device, with both spans lifted to 120 s so
//! neither distribution was cut where it is derived
//! (`docs/benchmarks/p2p_tor_gap_cold_20261014.md`, from its
//! `_rerunA.tsv` and `_rerunB.tsv`; 189 sessions).
//!
//! Tor dial 120 s: bounded by Tor's own SOCKS timeout (`SocksTimeout`,
//! 2 minutes by default; the managed Tor does not set it), past which
//! Tor fails the request itself. The distribution is censored there: 4 of
//! the 200 dials ran past 120 s, and the pooled p99 of the sessions was
//! 112.7 s (p50 6.4 s, p90 65.3 s). A clearnet dial through a SOCKS
//! proxy uses this clock.
//!
//! Tor gap 31 s: 2 × 15.50 s of the pooled outbound gap, the dialer's
//! SOCKS success to the peer's first complete Levin frame (n = 189).
//! 15.50 s is rank 187 of 189, about p98.9; the nearest-rank p99 is
//! 18.69 s and the maximum 46.91 s, a single circuit. The inbound gap's
//! pooled p99 was 27.69 s.
//!
//! Reopen both at 500 pooled Rust-path samples.
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
pub const TOR_DIAL_WITHIN_NANOS: u64 = 120_000_000_000;
/// Tor gap: the longest silence a session keeps.
#[cfg(not(feature = "measurement-spans"))]
pub const TOR_GAP_WITHIN_NANOS: u64 = 31_000_000_000;
/// What the Tor spans were measured on: the Rust path.
pub const TOR_SPANS_BASIS: shekyl_relay_privacy::AdmissibleBasis =
    shekyl_relay_privacy::AdmissibleBasis::RustPath;

/// Whether this build lifts the Tor spans for the cold-first-contact
/// measurement (Rick, 2026-10-14). The zone host logs a warning at start
/// when it does.
pub const MEASUREMENT_SPANS: bool = cfg!(feature = "measurement-spans");
/// The measurement build's Tor gap: 120 s, the dial's bound, so the gap's
/// distribution is read rather than cut at the span it derives. A harness
/// input, not a derived span. The dial is 120 s in every build.
#[cfg(feature = "measurement-spans")]
pub const MEASUREMENT_SPAN_NANOS: u64 = 120_000_000_000;
/// Tor gap, measurement build.
#[cfg(feature = "measurement-spans")]
pub const TOR_GAP_WITHIN_NANOS: u64 = MEASUREMENT_SPAN_NANOS;
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
