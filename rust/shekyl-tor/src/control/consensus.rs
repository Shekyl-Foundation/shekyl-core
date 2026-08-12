// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parsing the `GETINFO ns/all` consensus reply into the relay candidates
//! vanguard selection draws from (PR-C2).
//!
//! `ns/all` returns one network-status router entry per relay, each a small
//! block of lines (dir-spec §3.4.1):
//!
//! ```text
//! r <nickname> <identity-b64> <digest-b64> <date> <time> <ip> <or> <dir>
//! s <flag> <flag> …
//! w Bandwidth=<n> [Measured=<n>] [Unmeasured=1]
//! ```
//!
//! The framer folds the whole `250+ns/all=…` data block into a single
//! [`ControlReply`] line (`"ns/all=\n<entry>\n<entry>…"`), so this module
//! splits that one line on `\n` and walks the `r`/`s`/`w` entries. Only the
//! three fields selection needs are kept: the identity (→
//! [`RelayFingerprint`]), the consensus bandwidth weight, and whether the
//! relay carries the flags that make it an eligible vanguard.

use super::framing::ControlReply;
use super::vanguards::RelayFingerprint;

/// A relay from the consensus, reduced to what vanguard selection weighs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusRelay {
    /// Identity fingerprint — the token `HSLayer2Nodes`/`HSLayer3Nodes` name
    /// it by.
    pub fingerprint: RelayFingerprint,
    /// The consensus `w Bandwidth=` weight — the value Tor's own path
    /// selection weights by; vanguard selection weights by it too (the
    /// mechanism ruling's "bandwidth-weighted"). `0` when the `w` line was
    /// absent, which makes the relay unselectable (weight 0).
    pub bandwidth: u64,
    /// Whether the relay's `s` flags satisfy the vanguard requirement,
    /// evaluated at parse time so selection filters without re-parsing (see
    /// `REQUIRED_FLAGS`).
    pub eligible: bool,
}

/// The flags a relay must carry to be an eligible vanguard.
///
/// **Provisional (PR-C2), rig/spec-confirmable.** Vanguards are middle
/// positions, so the `Guard` flag is deliberately **not** required (that is
/// the entry-guard flag); what matters is that the relay is real bandwidth
/// (`Fast`), long-lived (`Stable`), and in the consensus as usable
/// (`Valid`, `Running`). A stricter or looser set is a selection-policy
/// re-pin the W₂ rig can inform.
const REQUIRED_FLAGS: [&str; 4] = ["Fast", "Stable", "Valid", "Running"];

/// Do these flags (the `s` line with its `s ` prefix already stripped)
/// satisfy [`REQUIRED_FLAGS`]?
fn is_eligible(flags: &str) -> bool {
    let present: Vec<&str> = flags.split_ascii_whitespace().collect();
    REQUIRED_FLAGS
        .iter()
        .all(|req| present.iter().any(|f| f == req))
}

/// Parse the candidate relay set from a `GETINFO ns/all` reply.
///
/// Malformed or incomplete entries (no parseable identity) are skipped
/// rather than failing the whole parse — a single bad router line must not
/// deny a persona its vanguards. Returns an empty vec if the `ns/all=`
/// payload is absent.
#[must_use]
pub fn parse_ns_all(reply: &ControlReply) -> Vec<ConsensusRelay> {
    let Some(payload) = reply.lines().iter().find_map(|l| l.strip_prefix("ns/all=")) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    // The r/s/w lines of the entry currently being assembled.
    let mut fp: Option<RelayFingerprint> = None;
    let mut eligible = false;
    let mut bandwidth = 0u64;

    // Emit the in-progress entry (if it has an identity) and reset.
    let mut flush =
        |fp: &mut Option<RelayFingerprint>, eligible: &mut bool, bandwidth: &mut u64| {
            if let Some(fingerprint) = fp.take() {
                out.push(ConsensusRelay {
                    fingerprint,
                    bandwidth: *bandwidth,
                    eligible: *eligible,
                });
            }
            *eligible = false;
            *bandwidth = 0;
        };

    for line in payload.split('\n') {
        if let Some(rest) = line.strip_prefix("r ") {
            // A new router entry starts — emit the previous one first.
            flush(&mut fp, &mut eligible, &mut bandwidth);
            // `r <nick> <identity-b64> …` — field index 1 is the identity.
            fp = rest
                .split_ascii_whitespace()
                .nth(1)
                .and_then(decode_identity_b64)
                .map(RelayFingerprint::from_bytes);
        } else if let Some(rest) = line.strip_prefix("s ") {
            eligible = is_eligible(rest);
        } else if let Some(rest) = line.strip_prefix("w ") {
            bandwidth = parse_bandwidth(rest);
        }
    }
    flush(&mut fp, &mut eligible, &mut bandwidth);
    out
}

/// `Bandwidth=<n>` from a `w` line's arguments (`0` if absent/unparseable).
fn parse_bandwidth(w_args: &str) -> u64 {
    w_args
        .split_ascii_whitespace()
        .find_map(|tok| tok.strip_prefix("Bandwidth="))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Decode a consensus `r`-line identity: standard-alphabet base64 of the
/// 20-byte identity digest, **unpadded** (27 chars). `None` on any
/// non-alphabet byte or a length that does not yield 20 bytes.
fn decode_identity_b64(field: &str) -> Option<[u8; 20]> {
    let bytes = base64_decode_unpadded(field)?;
    (bytes.len() == 20).then(|| {
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes);
        out
    })
}

/// RFC 4648 standard-alphabet base64 decode, no padding. Fixed-purpose (the
/// consensus identity field), the decode counterpart to `onion`'s hand-rolled
/// `base64_encode`; pinned by test.
fn base64_decode_unpadded(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(b - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        acc = (acc << 6) | val(b)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // The masked value is 0..=255 by construction, so this is the
            // intended byte extraction, not a lossy cast.
            out.push(u8::try_from((acc >> bits) & 0xFF).expect("masked to a byte"));
        }
    }
    // Any leftover bits must be zero padding, never dropped data.
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply_ns_all(payload: &str) -> ControlReply {
        // Build the folded reply the framer produces for `250+ns/all=…`.
        let mut framer = super::super::framing::ReplyFramer::new();
        let mut wire = String::from("250+ns/all=\r\n");
        for line in payload.lines() {
            wire.push_str(line);
            wire.push_str("\r\n");
        }
        wire.push_str(".\r\n250 OK\r\n");
        framer.push_bytes(wire.as_bytes());
        framer.next_reply().expect("framed").expect("one reply")
    }

    /// Identity base64 for an all-`0x11` 20-byte fingerprint, standard
    /// alphabet unpadded — computed once and pinned.
    const FP11_B64: &str = "ERERERERERERERERERERERERERE";

    #[test]
    fn base64_decode_round_trips_a_known_identity() {
        let decoded = base64_decode_unpadded(FP11_B64).expect("valid b64");
        assert_eq!(decoded, vec![0x11u8; 20]);
    }

    #[test]
    fn base64_decode_rejects_non_alphabet_and_nonzero_padding() {
        assert!(base64_decode_unpadded("====").is_none(), "padding byte");
        assert!(base64_decode_unpadded("ERER RER").is_none(), "space");
        // Trailing bits carrying data (not zero) must not be silently dropped.
        assert!(base64_decode_unpadded("EE").is_none());
    }

    #[test]
    fn parses_an_eligible_relay_with_its_bandwidth() {
        let relays = parse_ns_all(&reply_ns_all(&format!(
            "r Alice {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Guard Running Stable Valid V2Dir\n\
             w Bandwidth=4200 Measured=4000\n\
             p reject 1-65535"
        )));
        assert_eq!(relays.len(), 1);
        assert_eq!(
            relays[0].fingerprint,
            RelayFingerprint::from_bytes([0x11; 20])
        );
        assert_eq!(relays[0].bandwidth, 4200);
        assert!(relays[0].eligible);
    }

    #[test]
    fn a_relay_missing_a_required_flag_is_ineligible_but_still_listed() {
        // No `Stable` -> ineligible; still parsed (selection filters, not
        // the parser, so the candidate set stays inspectable).
        let relays = parse_ns_all(&reply_ns_all(&format!(
            "r Bob {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Running Valid\n\
             w Bandwidth=10"
        )));
        assert_eq!(relays.len(), 1);
        assert!(!relays[0].eligible);
    }

    #[test]
    fn multiple_entries_split_on_r_lines_and_missing_w_is_zero() {
        // Standard-alphabet unpadded base64 of 20 × 0x22.
        let fp22 = "IiIiIiIiIiIiIiIiIiIiIiIiIiI";
        let relays = parse_ns_all(&reply_ns_all(&format!(
            "r Alice {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Stable Valid Running\n\
             w Bandwidth=100\n\
             r Carol {fp22} def 2026-08-11 00:00:00 5.6.7.8 9001 0\n\
             s Fast Stable Valid Running"
        )));
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].bandwidth, 100);
        // Carol has no `w` line: bandwidth 0 (unselectable), not inherited
        // from Alice.
        assert_eq!(relays[1].bandwidth, 0);
        assert_eq!(
            relays[1].fingerprint,
            RelayFingerprint::from_bytes([0x22; 20])
        );
    }

    #[test]
    fn absent_payload_is_empty_not_a_panic() {
        let reply = {
            let mut f = super::super::framing::ReplyFramer::new();
            f.push_bytes(b"250 OK\r\n");
            f.next_reply().expect("framed").expect("reply")
        };
        assert!(parse_ns_all(&reply).is_empty());
    }
}
