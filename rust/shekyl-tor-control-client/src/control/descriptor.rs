// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What the clock ruling reads from Tor's own descriptors and consensus
//! (`TOR_SUPERVISOR.md` §4.2, §4.5; Rick, 2026-11-01).
//!
//! - A descriptor's `revision-counter`: a directory refuses an upload whose
//!   counter is not above the copy it holds (tor 0.4.9.14 `hs_cache.c:185`),
//!   so a copy whose counter is not this service's is stale. Ours is `GETINFO
//!   hs/service/desc/id/<onion>` (`control_getinfo.c:569`), which is the
//!   service's `desc_current` only (`hs_service.c:4222-4242`); a directory's
//!   is the `HS_DESC_CONTENT` event Tor sends after each fetch it stored
//!   (`hs_client.c:1688`, `control_events.c:2225`). Not `GETINFO
//!   hs/client/desc/id`: the client cache keeps one copy and discards a
//!   fetched one with a lower counter (`hs_cache.c:837-842`), so it cannot
//!   show which directory held what.
//! - Which descriptor ours is: its blinded key, from the signing-key
//!   certificate, which the blinded key signs and names in its
//!   signed-with-key extension (`hs_service.c:1794-1796`,
//!   `CERT_FLAG_INCLUDE_SIGNING_KEY`). A client asks for the current time
//!   period's descriptor (`hs_client.c:232`). From the time period's start
//!   to the next shared-random run (12:00 to 00:00 UTC on the public
//!   network) the service's `desc_current` is the previous period's and the
//!   one clients ask for is `desc_next` (`hs_service.c:2127-2139`), whose
//!   counter no control command gives. The blinded key says which case
//!   holds.
//! - The consensus's `valid-after` (`GETINFO consensus/valid-after`,
//!   `networkstatus.c:2700`, ISO 8601 UTC): nothing legitimate produces a
//!   consensus from the future, so a local clock behind it is this
//!   machine's.

use super::encoding::{base64_decode_unpadded, base64_encode_padded};
use super::framing::ControlReply;
use super::onion::ServiceId;
use super::vanguards::RelayFingerprint;

/// The `revision-counter` of a descriptor's outer layer, the one line of it
/// that is plaintext.
#[must_use]
pub fn revision_counter(descriptor: &str) -> Option<u64> {
    descriptor
        .lines()
        .find_map(|line| line.strip_prefix("revision-counter "))
        .and_then(|value| value.trim().parse().ok())
}

/// This service's `desc_current`, as the directory check compares copies
/// with it: the descriptor id a fetch names (the blinded key, unpadded
/// base64, as `HS_DESC` writes it) and its counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDescriptor {
    /// The blinded key, as `HS_DESC` and `HS_DESC_CONTENT` name it.
    pub descriptor_id: String,
    /// Its `revision-counter`.
    pub revision_counter: u64,
}

/// This service's `desc_current`, from the reply to `GETINFO
/// hs/service/desc/id/<onion>` (a `250+` data block). `None` when the reply
/// carries no descriptor, or one whose counter or blinded key cannot be read.
#[must_use]
pub fn parse_service_descriptor(reply: &ControlReply) -> Option<ServiceDescriptor> {
    reply.lines().iter().find_map(|line| {
        let (key, descriptor) = line.split_once('\n')?;
        if !key.starts_with("hs/service/desc/id/") {
            return None;
        }
        Some(ServiceDescriptor {
            descriptor_id: blinded_key(descriptor)?,
            revision_counter: revision_counter(descriptor)?,
        })
    })
}

/// The `descriptor-signing-key-cert`'s signed-with-key extension: the
/// blinded key, rendered as `HS_DESC` renders a descriptor id (base64, no
/// padding). The certificate is Tor's (`cert-spec.txt` §2.1): version 1,
/// type, expiry, key type, the certified key, then the extensions, each a
/// length, a type and flags; type 4 carries the 32-byte signing key.
fn blinded_key(descriptor: &str) -> Option<String> {
    const SIGNED_WITH_KEY: u8 = 4;
    let mut lines = descriptor
        .lines()
        .skip_while(|line| line.trim() != "descriptor-signing-key-cert");
    lines.next()?;
    if lines.next()?.trim() != "-----BEGIN ED25519 CERT-----" {
        return None;
    }
    let body: String = lines
        .take_while(|line| line.trim() != "-----END ED25519 CERT-----")
        .map(str::trim)
        .collect();
    let cert = base64_decode_unpadded(body.trim_end_matches('='))?;
    if cert.first() != Some(&1) {
        return None;
    }
    let mut at = 40; // version, type, expiry (4), key type, certified key (32)
    let extensions = *cert.get(39)?;
    for _ in 0..extensions {
        let length = usize::from(u16::from_be_bytes([*cert.get(at)?, *cert.get(at + 1)?]));
        let kind = *cert.get(at + 2)?;
        let data = cert.get(at + 4..at + 4 + length)?;
        if kind == SIGNED_WITH_KEY && length == 32 {
            return Some(base64_encode_padded(data).trim_end_matches('=').to_owned());
        }
        at += 4 + length;
    }
    None
}

/// The consensus's `valid-after`, in Unix seconds, from the reply to
/// `GETINFO consensus/valid-after`.
#[must_use]
pub fn parse_consensus_valid_after(reply: &ControlReply) -> Option<u64> {
    reply
        .lines()
        .iter()
        .find_map(|line| line.strip_prefix("consensus/valid-after="))
        .and_then(|value| iso_utc_seconds(value.trim()))
}

/// `YYYY-MM-DD HH:MM:SS`, UTC, as Tor's `format_iso_time` writes it, in
/// Unix seconds. Anything else is `None`.
fn iso_utc_seconds(text: &str) -> Option<u64> {
    let (date, time) = text.split_once(' ')?;
    let mut date = date.splitn(3, '-').map(str::parse::<i64>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.splitn(3, ':').map(str::parse::<i64>);
    let (hour, minute, second) = (time.next()?.ok()?, time.next()?.ok()?, time.next()?.ok()?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// An `HS_DESC_CONTENT` event: the descriptor one directory returned for a
/// fetch Tor stored. Only the counter is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsDescContent {
    /// The onion address, without `.onion`.
    pub address: Option<ServiceId>,
    /// The descriptor id: the blinded key.
    pub descriptor_id: Option<String>,
    /// The directory that returned it.
    pub hsdir: Option<RelayFingerprint>,
    /// The copy's `revision-counter`.
    pub revision_counter: Option<u64>,
}

/// `HS_DESC_CONTENT <address> <descriptor id> <hsdir>`, then the descriptor
/// as the data block (`control_events.c:2251`).
pub(super) fn hs_desc_content(rest: &str) -> HsDescContent {
    let (header, descriptor) = rest.split_once('\n').unwrap_or((rest, ""));
    let mut fields = header.split_whitespace();
    let address = fields.next().and_then(ServiceId::parse);
    let descriptor_id = fields.next().map(str::to_owned);
    let hsdir = fields.next().and_then(|longname| {
        let fingerprint = longname.split(['~', '=']).next().unwrap_or(longname);
        RelayFingerprint::parse(fingerprint)
    });
    HsDescContent {
        address,
        descriptor_id,
        hsdir,
        revision_counter: revision_counter(descriptor),
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::{parse_event, TorEvent};
    use super::super::framing::ReplyFramer;
    use super::*;

    fn frame(bytes: &str) -> ControlReply {
        let mut framer = ReplyFramer::default();
        framer.push_bytes(bytes.as_bytes());
        framer
            .next_reply()
            .expect("well-formed")
            .expect("one reply")
    }

    /// The outer layer as tor 0.4.9.14 writes it (`hs_descriptor.c`): the
    /// counter is the one plaintext line a reader needs.
    const OUTER: &str = "hs-descriptor 3\r\ndescriptor-lifetime 180\r\ndescriptor-signing-key-cert\r\n-----BEGIN ED25519 CERT-----\r\nAQgABvnN\r\n-----END ED25519 CERT-----\r\nrevision-counter 3929208370\r\nsuperencrypted\r\n-----BEGIN MESSAGE-----\r\n..dot-stuffed\r\n-----END MESSAGE-----\r\nsignature abc\r\n";

    #[test]
    fn the_counter_is_read_from_a_descriptor() {
        assert_eq!(revision_counter("revision-counter 42\nother"), Some(42));
        assert_eq!(revision_counter("no counter here"), None);
    }

    /// A signing-key certificate as Tor writes one (`cert-spec.txt` §2.1):
    /// type 8, an ed25519 certified key, one extension of type 4 carrying
    /// `signer`, the blinded key, then a 64-byte signature.
    fn signing_cert(signer: [u8; 32]) -> String {
        let mut cert = vec![1, 8, 0, 0, 0x1d, 0x4c, 1];
        cert.extend([0xAB; 32]);
        cert.push(1);
        cert.extend([0, 32, 4, 0]);
        cert.extend(signer);
        cert.extend([0xCD; 64]);
        let encoded = base64_encode_padded(&cert);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).expect("ascii"))
            .collect();
        format!(
            "-----BEGIN ED25519 CERT-----\r\n{}\r\n-----END ED25519 CERT-----",
            lines.join("\r\n")
        )
    }

    /// **Ours names its descriptor** (Rick, 2026-11-01, as found live the
    /// same day): the reply's counter, and the blinded key from the signing
    /// certificate rendered as `HS_DESC` renders a descriptor id. The
    /// directory check compares only a copy of that descriptor. Fails if
    /// `blinded_key` reads the certified key instead of the extension, or
    /// pads the id (no fetch's id would ever match).
    #[test]
    fn our_descriptor_comes_from_the_service_descriptor_reply() {
        let onion = "dslbwwu6sfukamiltaij744ly3aqhtl3lbi7e6mdzv6m6hha425mmhqd";
        let mut signer = [0_u8; 32];
        for (i, byte) in signer.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("small") * 7;
        }
        let descriptor = format!(
            "hs-descriptor 3\r\ndescriptor-lifetime 180\r\ndescriptor-signing-key-cert\r\n{}\r\nrevision-counter 3929208370\r\nsuperencrypted\r\n",
            signing_cert(signer)
        );
        let reply = frame(&format!(
            "250+hs/service/desc/id/{onion}=\r\n{descriptor}.\r\n250 OK\r\n"
        ));
        let ours = parse_service_descriptor(&reply).expect("a descriptor");
        assert_eq!(ours.revision_counter, 3_929_208_370);
        assert_eq!(
            ours.descriptor_id.len(),
            43,
            "unpadded, as HS_DESC writes it"
        );
        assert_eq!(
            base64_decode_unpadded(&ours.descriptor_id).as_deref(),
            Some(&signer[..])
        );
        // No certificate: nothing to say which descriptor the counter is.
        let bare = frame(&format!(
            "250+hs/service/desc/id/{onion}=\r\n{OUTER}.\r\n250 OK\r\n"
        ));
        assert_eq!(parse_service_descriptor(&bare), None);
    }

    /// The format `format_iso_time` writes, and the instant it names.
    #[test]
    fn valid_after_is_read_as_unix_seconds() {
        let reply = frame("250-consensus/valid-after=2026-11-01 00:00:00\r\n250 OK\r\n");
        assert_eq!(parse_consensus_valid_after(&reply), Some(1_793_491_200));
        let epoch = frame("250-consensus/valid-after=1970-01-01 00:00:00\r\n250 OK\r\n");
        assert_eq!(parse_consensus_valid_after(&epoch), Some(0));
        let leap = frame("250-consensus/valid-after=2024-02-29 12:34:56\r\n250 OK\r\n");
        assert_eq!(parse_consensus_valid_after(&leap), Some(1_709_210_096));
        let junk = frame("250-consensus/valid-after=yesterday\r\n250 OK\r\n");
        assert_eq!(parse_consensus_valid_after(&junk), None);
    }

    /// The event Tor sends after a fetch it stored, framed as a `650+` data
    /// reply: the header names the directory, the block is the descriptor.
    #[test]
    fn a_directorys_copy_is_read_from_hs_desc_content() {
        let onion = "dslbwwu6sfukamiltaij744ly3aqhtl3lbi7e6mdzv6m6hha425mmhqd";
        let reply = frame(&format!(
            "650+HS_DESC_CONTENT {onion} nFQ9sNMB8qvVnYKG0QxhL4hxuVM0a4gzzBIB+Eb04/E $95B556218614D4F2A3B0F24329AD31103D31FFF6~relay\r\n{OUTER}.\r\n650 OK\r\n"
        ));
        let Some(TorEvent::HsDescContent(content)) = parse_event(&reply) else {
            panic!("not HS_DESC_CONTENT");
        };
        assert_eq!(content.address, ServiceId::parse(onion));
        assert_eq!(
            content.descriptor_id.as_deref(),
            Some("nFQ9sNMB8qvVnYKG0QxhL4hxuVM0a4gzzBIB+Eb04/E")
        );
        assert_eq!(
            content.hsdir,
            RelayFingerprint::parse("95B556218614D4F2A3B0F24329AD31103D31FFF6")
        );
        assert_eq!(content.revision_counter, Some(3_929_208_370));
    }
}
