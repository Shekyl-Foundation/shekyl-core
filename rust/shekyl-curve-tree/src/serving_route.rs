// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The archival serving route's shared constants — the half of `RF-R1`
//! that **both** ends read.
//!
//! `shekyl-p-serve` answers `GET /shard/{id}` on a persona's onion and
//! `shekyl-p-fetch` dials it. Neither may depend on the other (`SF-D4`:
//! the two ends of `PWD-E9` do not share a dependency graph), so the
//! route grammar they must agree on lives here, in the codec crate both
//! already depend on for the `RF-D4` frame. Two constants that happen to
//! agree are not the ratification; one constant read twice is
//! ([`ARCHIVAL_SHARD_FETCH.md`](../../../docs/design/ARCHIVAL_SHARD_FETCH.md)
//! `SF-D4`, `SF-D5`). The living contract is
//! [`ARCHIVAL_SERVING_ROUTE.md`](../../../docs/design/ARCHIVAL_SERVING_ROUTE.md).
//!
//! This module owns **grammar**, not behaviour: it does no I/O, holds no
//! key, and does not decide what a decoded header *means* — `P`'s
//! pre-sign gate and the client's transcript are the two crates' own
//! (`SF-D5`, `SF-D8`). What is here is exactly what would otherwise be
//! written twice: the virtual port, the route prefix, the response header
//! set, the one request header's name and textual encoding, and the
//! serving endpoint's onion-address derivation.

use sha3::{Digest, Sha3_256};

/// Virtual port the persona's onion publishes — the port the fetch client
/// dials. **RULED 80** (`SF-D5`).
///
/// 80 because it is the onion-service convention and carries no
/// information: a non-default port is a per-operator distinguisher on an
/// address whose whole purpose is to be indistinguishable. Not a setting,
/// for that reason. Home is this crate (`SF-D4`); the wallet's serving
/// task and the daemon's fetch client both read this declaration.
pub const SERVING_VIRTUAL_PORT: u16 = 80;

/// The one route the endpoint answers. Ruled `RF-R1`: `GET /shard/{id}`,
/// `{id}` an exact decimal `u64`, no suffix, no query string.
///
/// Not a format-round candidate — §9.5's exclusion stands — and not
/// consensus. **Do not rename this to restore `provisional` or mint a
/// version token.** A later request contract is an additional path that
/// suffixes `/shard/`, with a named reopening, and `SF-D1` requires any
/// such path to be usable by both callers; until then this is the only
/// route.
pub const ROUTE_PREFIX: &str = "/shard/";

/// Response content type for shard bytes.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Every header name the endpoint ever emits, in emission order — the
/// **complete** set. `shekyl-p-serve` asserts it emits exactly these
/// (`two_personas_are_header_identical`); `shekyl-p-fetch` refuses a head
/// carrying anything else as malformed (`SF-D6`). Adding a header without
/// updating this constant fails both, rather than silently widening the
/// fingerprint on one side.
pub const RESPONSE_HEADER_NAMES: &[&str] = &["content-type", "content-length"];

/// The one required request header (`SF-D5`, second amendment): its value
/// is [`REQUEST_HEADER_HEX_LEN`] lowercase hex characters decoding to
/// [`REQUEST_HEADER_BYTES`] bytes, `nonce[32] ‖ anchor_height_le[8] ‖
/// anchor_hash[32]`.
///
/// Spelling is the lowercase form the client emits. HTTP header names are
/// case-insensitive on the wire; the *value* is not — one canonical
/// textual encoding, and [`decode_request_header`] is that encoding's only
/// decoder. `P` signs the **decoded** bytes, never this text, so a lenient
/// server and a strict client could never sign different transcripts for
/// one request. Missing, duplicate, malformed, or wrong-length values are
/// the identical complete-head 404 (`RF-R1`); all other request headers
/// remain ignored. Not `x-`-prefixed for the reason `RF-R1` gave the path.
pub const REQUEST_HEADER_NAME: &str = "shekyl-pass-request";

/// Decoded length of the request header value. The layout and the
/// transcript `P` signs over it are `shekyl-archival-retention`'s
/// (`pass_anchor::PASS_REQUEST_HEADER_LEN`); the fetch crate const-asserts
/// the two equal. This crate owns only the textual carrier.
pub const REQUEST_HEADER_BYTES: usize = 72;

/// Textual length of the request header value: two hex digits per byte.
pub const REQUEST_HEADER_HEX_LEN: usize = REQUEST_HEADER_BYTES * 2;

/// Encode a decoded request header for the wire: lowercase hex, exactly
/// [`REQUEST_HEADER_HEX_LEN`] characters.
#[must_use]
pub fn encode_request_header(bytes: &[u8; REQUEST_HEADER_BYTES]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(REQUEST_HEADER_HEX_LEN);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decode a request header value. `None` unless it is exactly
/// [`REQUEST_HEADER_HEX_LEN`] lowercase hex characters — uppercase,
/// whitespace, a `0x` prefix, or any other length is not a second spelling
/// of the same bytes, it is not the header.
#[must_use]
pub fn decode_request_header(text: &str) -> Option<[u8; REQUEST_HEADER_BYTES]> {
    let text = text.as_bytes();
    if text.len() != REQUEST_HEADER_HEX_LEN {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; REQUEST_HEADER_BYTES];
    for (i, pair) in text.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// The raw 32-byte Ed25519 public key of a persona's v3 onion service, as
/// the bond record carries it (`EU-D3`: the `.onion` is display form; the
/// wire never carries it).
///
/// Minted here per the `SF-D7` amendment so the fetch target is a type
/// with a provenance obligation rather than a bare array the client trusts
/// because the caller handed it over. The obligation: build this from the
/// **record** read (the `ArchivalBondValue` endpoint column at the
/// drawable snapshot, `EU-D4`), never from a vin and never from a
/// response. The crate cannot check where the bytes came from; the type
/// is what the review checks. The bond wire itself stays a bare array
/// (rule 42 — the genesis-frozen wire is not touched for type hygiene).
///
/// Its one method derives the address to dial. The endpoint is immutable
/// for the record's life (`EU` kind-4 rejection, 2026-09-13), so a value
/// built once at draw time is good for the whole fetch.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ServingEndpoint([u8; 32]);

impl ServingEndpoint {
    /// Wrap the endpoint column of an authorized bond record. Consensus has
    /// already refused the all-zero endpoint on both sides of the record,
    /// so there is nothing left for this constructor to validate — the
    /// name is the provenance statement.
    #[must_use]
    pub const fn from_record_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw key, as the record holds it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The v3 `.onion` hostname this endpoint is dialled at, per
    /// rend-spec-v3 §6:
    /// `base32(pubkey ‖ SHA3-256(".onion checksum" ‖ pubkey ‖ 0x03)[..2] ‖ 0x03) ‖ ".onion"`,
    /// 56 lowercase base32 characters plus the suffix.
    ///
    /// The same construction `shekyl-tor-control-client` uses to fail-stop
    /// when tor reports a different `ServiceID` than the persona advertises
    /// (`onion_identity::service_id_from_pubkey`); the two are pinned to
    /// the same vector in this module's tests, so the address a persona
    /// publishes and the address a daemon derives from its record cannot
    /// drift apart.
    #[must_use]
    pub fn onion_address(&self) -> String {
        const VERSION: u8 = 0x03;
        const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

        let mut hasher = Sha3_256::new();
        hasher.update(CHECKSUM_PREFIX);
        hasher.update(self.0);
        hasher.update([VERSION]);
        let checksum = hasher.finalize();

        let mut raw = [0u8; 35];
        raw[..32].copy_from_slice(&self.0);
        raw[32..34].copy_from_slice(&checksum[..2]);
        raw[34] = VERSION;

        let mut address = base32_lower(&raw);
        address.push_str(".onion");
        address
    }
}

/// RFC 4648 base32, lowercase, unpadded. 35 bytes is a whole number of
/// 5-byte groups (7 × 5), so no padding case arises for the one real
/// input; the general path is written and tested rather than assumed.
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((acc >> bits) & 0x1f).expect("5-bit index");
            out.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = usize::try_from((acc << (5 - bits)) & 0x1f).expect("5-bit index");
        out.push(char::from(ALPHABET[index]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_header_round_trips_and_is_lowercase_hex() {
        let mut bytes = [0u8; REQUEST_HEADER_BYTES];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i * 3 % 256).unwrap();
        }
        let text = encode_request_header(&bytes);
        assert_eq!(text.len(), REQUEST_HEADER_HEX_LEN);
        assert!(text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
        assert_eq!(decode_request_header(&text), Some(bytes));
    }

    #[test]
    fn request_header_has_one_spelling() {
        let bytes = [0xabu8; REQUEST_HEADER_BYTES];
        let text = encode_request_header(&bytes);
        assert_eq!(decode_request_header(&text), Some(bytes));
        // Uppercase is the same bytes in a second spelling — refused.
        assert_eq!(decode_request_header(&text.to_ascii_uppercase()), None);
        // Wrong length, either way.
        assert_eq!(
            decode_request_header(&text[..REQUEST_HEADER_HEX_LEN - 2]),
            None
        );
        assert_eq!(decode_request_header(&format!("{text}00")), None);
        // Prefix, whitespace, non-hex.
        assert_eq!(decode_request_header(&format!("0x{}", &text[2..])), None);
        assert_eq!(decode_request_header(&format!(" {}", &text[1..])), None);
        assert_eq!(decode_request_header(&format!("g{}", &text[1..])), None);
        assert_eq!(decode_request_header(""), None);
    }

    /// RFC 4648 §10 vectors, lowercased and unpadded.
    #[test]
    fn base32_matches_rfc_4648_vectors() {
        assert_eq!(base32_lower(b""), "");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    /// Golden KAT, shared with `shekyl-tor-control-client`: this is the
    /// public key its `service_id_golden_kat` derives from the hs-id seed
    /// `[0x42; 32]`, and the address below is the literal that test pins.
    /// The persona publishes at the address tor confirms for this key; the
    /// daemon dials the address this method derives from the record. Both
    /// pinned to one string, so a drift on either side is a red test, not
    /// a live persona nobody can reach.
    #[test]
    fn onion_address_matches_the_publish_side_golden_kat() {
        let pubkey: [u8; 32] = [
            0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e,
            0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06,
            0x98, 0x81, 0xdb, 0x12,
        ];
        let endpoint = ServingEndpoint::from_record_bytes(pubkey);
        assert_eq!(
            endpoint.onion_address(),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.onion"
        );
        assert_eq!(endpoint.as_bytes(), &pubkey);
    }

    #[test]
    fn onion_address_is_well_formed_for_any_key() {
        let endpoint = ServingEndpoint::from_record_bytes([0x77u8; 32]);
        let address = endpoint.onion_address();
        let (host, suffix) = address.split_at(56);
        assert_eq!(suffix, ".onion");
        assert!(host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        // The version byte lands in the final base32 group: v3 ends in 'd'.
        assert!(host.ends_with('d'), "v3 addresses end in 'd': {host}");
    }

    #[test]
    fn route_constants_are_the_ruled_values() {
        assert_eq!(SERVING_VIRTUAL_PORT, 80);
        assert_eq!(ROUTE_PREFIX, "/shard/");
        assert!(!ROUTE_PREFIX.contains("provisional"));
        assert!(!ROUTE_PREFIX.contains("v0"));
        assert_eq!(RESPONSE_HEADER_NAMES, &["content-type", "content-length"]);
        assert_eq!(
            REQUEST_HEADER_NAME,
            REQUEST_HEADER_NAME.to_ascii_lowercase()
        );
        assert!(!REQUEST_HEADER_NAME.starts_with("x-"));
        assert_eq!(REQUEST_HEADER_BYTES, 32 + 8 + 32);
    }
}
