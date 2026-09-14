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
//! set, and the one request header's name and textual encoding.
//!
//! The onion hostname a daemon dials is not grammar. It is a function of
//! the bond-record endpoint column, owned by `shekyl-onion-v3` (the one
//! rend-spec transform) and typed as `shekyl-p-fetch::ServingEndpoint`
//! (the daemon's dial target). Wallet serving publishes through
//! `OnionIdentity`. Those stay different types (`PWD-E9`).

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
