// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parsing the `GETINFO ns/all` consensus reply into the relay candidates
//! vanguard selection draws from (VG-2).
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

use super::encoding::base64_decode_unpadded;
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
/// **Provisional (VG-2), rig/spec-confirmable.** Vanguards are middle
/// positions, so the `Guard` flag is deliberately **not** required (that is
/// the entry-guard flag); what matters is that the relay is real bandwidth
/// (`Fast`), long-lived (`Stable`), and in the consensus as usable
/// (`Valid`, `Running`). A stricter or looser set is a selection-policy re-pin
/// the W₂ rig can inform — recorded with its blocker and reopening criterion
/// under "Vanguard eligibility flag set" in `docs/FOLLOWUPS.md` (V3.x), because
/// a comment pointing at a future consumer is not a deferral record.
///
/// Not to be confused with [`NUM_LAYER2_GUARDS`](super::vanguards::NUM_LAYER2_GUARDS)
/// / [`NUM_LAYER3_GUARDS`](super::vanguards::NUM_LAYER3_GUARDS), which are
/// spec-pinned from the Sybil rotation table and are **not** provisional.
const REQUIRED_FLAGS: [&str; 4] = ["Fast", "Stable", "Valid", "Running"];

/// Do these flags (the `s` line with its `s ` prefix already stripped)
/// satisfy [`REQUIRED_FLAGS`]?
fn is_eligible(flags: &str) -> bool {
    let present: Vec<&str> = flags.split_ascii_whitespace().collect();
    REQUIRED_FLAGS
        .iter()
        .all(|req| present.iter().any(|f| f == req))
}

/// A parsed `ns/all` reply: the relays we could read, and how many router
/// entries the reply announced.
///
/// The two counts are separate because **downstream cannot tell a relay that
/// left the network from a relay we failed to decode**, and it acts very
/// differently on the two: `restore` treats "absent from the consensus" as
/// "this vanguard is dead, replace it". A line-shape change in a future tor
/// (a moved identity field, padded base64, a renamed flag) would silently look
/// like the whole network churning at once and re-draw the persona's entire
/// guard topology — the exact failure full vanguards exists to prevent. Keeping
/// `announced` lets [`Self::is_trustworthy`] refuse instead.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConsensusView {
    /// Every router entry whose identity decoded.
    pub relays: Vec<ConsensusRelay>,
    /// Router entries the reply announced (`r ` lines), decoded or not.
    pub announced: usize,
}

/// One announced entry in this many must decode before the view is treated as a
/// picture of the network rather than of our parser.
///
/// Deliberately loose: skipping the occasional odd entry is the documented,
/// wanted behaviour (one bad router line must not deny a persona its
/// vanguards). What it catches is the *wholesale* shortfall — a format change,
/// a truncated reply, a wrong key — where the honest answer is "we do not know
/// what the consensus contains", not "everything the operator pinned is gone".
const MIN_DECODED_IN: usize = 2;

impl ConsensusView {
    /// Did enough of the announced entries decode for absence to mean the relay
    /// left the network, rather than that we could not read it?
    ///
    /// An empty reply announces nothing and so proves nothing — never
    /// trustworthy, however it came to be empty.
    #[must_use]
    pub fn is_trustworthy(&self) -> bool {
        self.announced > 0 && self.relays.len() >= self.announced.div_ceil(MIN_DECODED_IN)
    }
}

/// Parse the candidate relay set from a `GETINFO ns/all` reply.
///
/// Malformed or incomplete entries (no parseable identity) are skipped rather
/// than failing the whole parse — a single bad router line must not deny a
/// persona its vanguards — but every skip is **counted**, so a caller can tell
/// a lenient skip from a wholesale parse failure ([`ConsensusView`]). An absent
/// `ns/all=` payload yields the empty view, which is never trustworthy.
#[must_use]
pub fn parse_ns_all(reply: &ControlReply) -> ConsensusView {
    let Some(payload) = reply.lines().iter().find_map(|l| l.strip_prefix("ns/all=")) else {
        return ConsensusView::default();
    };

    let mut relays = Vec::new();
    let mut announced = 0usize;
    // The r/s/w lines of the entry currently being assembled.
    let mut fp: Option<RelayFingerprint> = None;
    let mut eligible = false;
    let mut bandwidth = 0u64;

    // Emit the in-progress entry (if it has an identity) and reset.
    let mut flush =
        |fp: &mut Option<RelayFingerprint>, eligible: &mut bool, bandwidth: &mut u64| {
            if let Some(fingerprint) = fp.take() {
                relays.push(ConsensusRelay {
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
            announced += 1;
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
    ConsensusView { relays, announced }
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
    fn a_consensus_identity_field_decodes_to_its_20_bytes() {
        // The codec itself is pinned against RFC 4648 in `control::encoding`;
        // what this pins is the *field* contract — 27 unpadded chars in, exactly
        // 20 bytes out, anything else rejected rather than truncated.
        assert_eq!(decode_identity_b64(FP11_B64), Some([0x11u8; 20]));
        assert_eq!(
            decode_identity_b64("Zm9v"),
            None,
            "3 bytes is not an identity"
        );
        assert_eq!(decode_identity_b64("ERER RER"), None, "space");
    }

    #[test]
    fn parses_an_eligible_relay_with_its_bandwidth() {
        let view = parse_ns_all(&reply_ns_all(&format!(
            "r Alice {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Guard Running Stable Valid V2Dir\n\
             w Bandwidth=4200 Measured=4000\n\
             p reject 1-65535"
        )));
        assert_eq!(view.relays.len(), 1);
        assert_eq!(
            view.relays[0].fingerprint,
            RelayFingerprint::from_bytes([0x11; 20])
        );
        assert_eq!(view.relays[0].bandwidth, 4200);
        assert!(view.relays[0].eligible);
    }

    #[test]
    fn a_relay_missing_a_required_flag_is_ineligible_but_still_listed() {
        // No `Stable` -> ineligible; still parsed (selection filters, not
        // the parser, so the candidate set stays inspectable).
        let view = parse_ns_all(&reply_ns_all(&format!(
            "r Bob {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Running Valid\n\
             w Bandwidth=10"
        )));
        assert_eq!(view.relays.len(), 1);
        assert!(!view.relays[0].eligible);
    }

    #[test]
    fn multiple_entries_split_on_r_lines_and_missing_w_is_zero() {
        // Standard-alphabet unpadded base64 of 20 × 0x22.
        let fp22 = "IiIiIiIiIiIiIiIiIiIiIiIiIiI";
        let view = parse_ns_all(&reply_ns_all(&format!(
            "r Alice {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Stable Valid Running\n\
             w Bandwidth=100\n\
             r Carol {fp22} def 2026-08-11 00:00:00 5.6.7.8 9001 0\n\
             s Fast Stable Valid Running"
        )));
        assert_eq!(view.relays.len(), 2);
        assert_eq!(view.relays[0].bandwidth, 100);
        // Carol has no `w` line: bandwidth 0 (unselectable), not inherited
        // from Alice.
        assert_eq!(view.relays[1].bandwidth, 0);
        assert_eq!(
            view.relays[1].fingerprint,
            RelayFingerprint::from_bytes([0x22; 20])
        );
    }

    #[test]
    fn absent_payload_is_empty_and_never_trustworthy() {
        let reply = {
            let mut f = super::super::framing::ReplyFramer::new();
            f.push_bytes(b"250 OK\r\n");
            f.next_reply().expect("framed").expect("reply")
        };
        let view = parse_ns_all(&reply);
        assert!(view.relays.is_empty());
        assert_eq!(view.announced, 0);
        // The load-bearing half: an empty view must never read as "the network
        // is empty", because the caller would take that as every pinned vanguard
        // having left and re-draw the persona's whole topology.
        assert!(!view.is_trustworthy());
    }

    #[test]
    fn a_wholesale_decode_failure_is_distinguishable_from_relay_churn() {
        // The realistic break: a future tor moves the identity field, so every
        // `r` line is announced but none decodes. Skipping them is still correct
        // per-entry — what must NOT happen is the caller reading the shortfall as
        // the whole network having churned.
        let broken: String = (0..10)
            .map(|i| {
                format!(
                    "r Relay{i} not-base64-here abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
                     s Fast Stable Valid Running\n\
                     w Bandwidth=10\n"
                )
            })
            .collect();
        let view = parse_ns_all(&reply_ns_all(&broken));
        assert_eq!(view.announced, 10);
        assert!(view.relays.is_empty());
        assert!(!view.is_trustworthy());
    }

    #[test]
    fn the_documented_occasional_skip_stays_trustworthy() {
        // One bad router line among many must not deny a persona its vanguards —
        // the leniency this parser is specified to have. The floor only catches
        // the wholesale case.
        let fp22 = "IiIiIiIiIiIiIiIiIiIiIiIiIiI";
        let view = parse_ns_all(&reply_ns_all(&format!(
            "r Alice {FP11_B64} abc 2026-08-11 00:00:00 1.2.3.4 9001 0\n\
             s Fast Stable Valid Running\n\
             w Bandwidth=100\n\
             r Mangled !!!! def 2026-08-11 00:00:00 5.6.7.8 9001 0\n\
             s Fast Stable Valid Running\n\
             w Bandwidth=100\n\
             r Carol {fp22} def 2026-08-11 00:00:00 5.6.7.8 9001 0\n\
             s Fast Stable Valid Running\n\
             w Bandwidth=100"
        )));
        assert_eq!(view.announced, 3);
        assert_eq!(view.relays.len(), 2);
        assert!(view.is_trustworthy());
    }
}
