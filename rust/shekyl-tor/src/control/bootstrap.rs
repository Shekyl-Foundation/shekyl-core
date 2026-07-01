// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bootstrap readiness — the `BootstrapState` a consumer waits on, and the sans-IO
//! parser that extracts Tor's bootstrap progress from a `GETINFO
//! status/bootstrap-phase` reply (SP-T0b, design §3b).
//!
//! Readiness is driven by a **poll** (a `GETINFO` command), never a `STATUS_CLIENT`
//! subscription — so it never touches `SETEVENTS` and cannot entangle a consumer's
//! event set (that was the retracted "tap"; see §3b). This module is the pure half:
//! the state type and the field extractor, pinned by KATs. The poll task that drives
//! the state lives in [`super::actor`].
//!
//! **`progress` is telemetry; `Ready` is the gate.** The `progress` byte exists for
//! the UX phase ("Connecting to the network… 45%", DQ-T0.3 / rule 82). Gate logic
//! keys on the [`BootstrapState::Ready`] transition **only** — never on
//! `progress >= 100`, which would be a second, divergent gate.

use super::framing::ControlReply;

/// The readiness state a consumer observes over the `watch` channel (design §3b).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapState {
    /// Tor is still bootstrapping. `progress` (0–99) is **telemetry** for the
    /// "Connecting…" UX only — never gate on it; the gate is [`Self::Ready`].
    Connecting {
        /// Tor's reported `PROGRESS=` percent, clamped by the poll task so it never
        /// renders backward (monotonicity is a cosmetic property, not enforced).
        progress: u8,
    },
    /// Tor reached 100% — the transport is usable. **The one transition the gate keys
    /// on.**
    Ready,
    /// The control connection died mid-bootstrap (the poll task's `ask` failed). A
    /// terminal state, so a consumer awaiting readiness gets a prompt answer instead
    /// of hanging until the lifecycle deadline (T0b-2 policy).
    Failed,
}

/// Extract Tor's bootstrap `PROGRESS=` percent from a `GETINFO status/bootstrap-phase`
/// reply. Returns `Some(percent)` (a valid `0..=100`) when the real field is present, or
/// `None` when the reply is not a bootstrap-phase reply, carries no parseable
/// `PROGRESS=`, or reports a value outside `0..=100`.
///
/// `None` means **unknown, skip** — *not* "0% bootstrapped": a malformed or missing
/// field must not publish `Connecting { progress: 0 }` (which would look like a fresh
/// start), so the poll task holds the last state and keeps polling. An **out-of-range**
/// value (a Tor bug / format change reporting e.g. `PROGRESS=150`) is malformed for the
/// same reason — and rejecting it here is what stops it being read as `>= 100` and
/// **falsely gating `Ready`**.
///
/// **Decoy-resistant.** The bootstrap-phase line is `<severity> BOOTSTRAP
/// PROGRESS=<n> TAG=<t> SUMMARY="<free text>"`; the quoted `SUMMARY` can contain a
/// planted `PROGRESS=` (`SUMMARY="… PROGRESS=99 …"`). Only the key/value fields
/// **before** the quoted summary are scanned, so the real field is parsed and the
/// decoy inside the string is ignored — the same refuse-planted-tokens discipline as
/// the `AUTHCHALLENGE` parser.
#[must_use]
pub fn parse_bootstrap_progress(reply: &ControlReply) -> Option<u8> {
    let line = reply
        .lines()
        .iter()
        .find_map(|l| l.strip_prefix("status/bootstrap-phase="))?;
    // Everything before the first quote is the unquoted key=value region; `SUMMARY`
    // (the only quoted field) and any decoy inside it sit after it.
    let fields = line.split('"').next().unwrap_or(line);
    let value = fields
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix("PROGRESS="))?;
    // A percent is 0..=100; anything outside is malformed (not a reading), so it can
    // never be seen as `>= 100` and falsely gate `Ready`.
    value.parse::<u8>().ok().filter(|&percent| percent <= 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::framing::ReplyFramer;

    /// Frame exactly one reply from a wire fragment (the path the actor uses).
    fn frame_one(bytes: &[u8]) -> ControlReply {
        let mut framer = ReplyFramer::default();
        framer.push_bytes(bytes);
        framer
            .next_reply()
            .expect("frames cleanly")
            .expect("one complete reply")
    }

    #[test]
    fn parses_progress_100_the_ready_gate() {
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n\
              250 OK\r\n",
        );
        // The poll task maps 100 → BootstrapState::Ready (the gate).
        assert_eq!(parse_bootstrap_progress(&reply), Some(100));
    }

    #[test]
    fn parses_a_mid_progress_value() {
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn SUMMARY=\"Connecting\"\r\n\
              250 OK\r\n",
        );
        // The poll task maps this → BootstrapState::Connecting { progress: 45 }.
        assert_eq!(parse_bootstrap_progress(&reply), Some(45));
    }

    #[test]
    fn absent_progress_is_none_not_zero() {
        // A bootstrap-phase line with no PROGRESS= field: unknown, skip — NOT 0%.
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP TAG=starting SUMMARY=\"Starting\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), None);
    }

    #[test]
    fn ignores_a_progress_decoy_inside_the_quoted_summary() {
        // The real field is 30; the SUMMARY string plants PROGRESS=99. A naive
        // `contains("PROGRESS=")` scan would read 99 (or, for the 100 decoy below,
        // falsely gate Ready). The real field wins.
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=30 TAG=conn SUMMARY=\"handshake PROGRESS=99 done\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), Some(30));
    }

    #[test]
    fn a_ready_decoy_in_the_summary_does_not_falsely_gate() {
        // The dangerous case: real progress 10, but SUMMARY plants PROGRESS=100. A
        // `contains("PROGRESS=100")` gate (what the measurement uses today) would fire
        // Ready far too early. The real field (10) is what we read.
        let reply = frame_one(
            b"250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=10 TAG=conn SUMMARY=\"stuck at PROGRESS=100 earlier\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), Some(10));
    }

    #[test]
    fn handles_a_bootstrap_line_with_no_summary() {
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=75 TAG=circuit_create\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), Some(75));
    }

    #[test]
    fn non_bootstrap_reply_is_none() {
        // A GETINFO version reply, say — no bootstrap-phase line.
        assert_eq!(
            parse_bootstrap_progress(&frame_one(b"250-version=0.4.9.9\r\n250 OK\r\n")),
            None
        );
    }

    #[test]
    fn non_numeric_progress_is_none() {
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=xx TAG=conn SUMMARY=\"x\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), None);
    }

    #[test]
    fn out_of_range_progress_is_none_not_ready() {
        // A percent is 0..=100; a bogus 150 (Tor bug / format change) parses as a `u8`
        // but is NOT a valid reading. It must be None — never seen as `>= 100`, which
        // would falsely gate Ready.
        let reply = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=150 TAG=x SUMMARY=\"x\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&reply), None);
        // The boundary holds: exactly 100 is still the valid Ready gate.
        let ready = frame_one(
            b"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n\
              250 OK\r\n",
        );
        assert_eq!(parse_bootstrap_progress(&ready), Some(100));
    }
}
