// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The byte↔text encodings the control port speaks, in one place.
//!
//! Three call sites need them — the SAFECOOKIE handshake (uppercase hex), the
//! `ADD_ONION` key blob (padded base64), and the consensus `r`-line identity
//! (unpadded base64) — and each one previously carried its own table. That is
//! the shape this module exists to remove: **one alphabet constant, one bit
//! packing, one set of RFC 4648 §10 vectors**, so a correction cannot land on
//! one half of a codec and miss the other.
//!
//! Hand-rolled rather than a dependency, for the reason rule 17 weighs: these
//! are fixed-width, fixed-purpose conversions where the alphabet *is* the
//! load-bearing property (it is what makes a control token structurally
//! injection-free), and a few dozen lines of table lookup pinned by the RFC's
//! own vectors adds no supply-chain edge.

/// Uppercase hex — Tor's control-port convention for byte strings
/// (`AUTHCHALLENGE`/`AUTHENTICATE` nonces and hashes, and the `$`-prefixed relay
/// identity specifier).
pub(super) fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// The RFC 4648 §4 standard alphabet — the single source of truth both
/// directions read.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet, **padded** base64 (RFC 4648 §4) — the `ADD_ONION` key
/// blob's encoding.
pub(super) fn base64_encode_padded(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Standard-alphabet base64 decode with **no padding** — the shape the consensus
/// `r`-line identity field uses (27 chars for a 20-byte digest).
///
/// `None` on any non-alphabet byte (`=` included: this input is never padded) or
/// on trailing bits that carry data rather than zero padding, so a truncated or
/// re-encoded identity cannot decode to a *different* relay.
pub(super) fn base64_decode_unpadded(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        acc = (acc << 6) | sextet(b)?;
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

/// The 6-bit value of one alphabet character. A direct match rather than a scan
/// of [`ALPHABET`], because the decoder runs over every relay identity in the
/// consensus; `the_decoder_inverts_the_shared_alphabet` is what keeps the two
/// from drifting apart.
fn sextet(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some(u32::from(b - b'A')),
        b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_upper_is_fixed_width_uppercase() {
        assert_eq!(hex_upper(&[0x00, 0x0a, 0xff, 0xab]), "000AFFAB");
        // Two chars per byte, always — a 32-byte hash renders 64.
        assert_eq!(hex_upper(&[0u8; 32]).len(), 64);
    }

    #[test]
    fn base64_encode_matches_rfc4648_vectors() {
        // RFC 4648 §10 — pins the alphabet, the padding, and the bit packing.
        // A drift in any of the three would produce a blob tor rejects (or, worse,
        // a blob tor accepts as a *different* key).
        assert_eq!(base64_encode_padded(b""), "");
        assert_eq!(base64_encode_padded(b"f"), "Zg==");
        assert_eq!(base64_encode_padded(b"fo"), "Zm8=");
        assert_eq!(base64_encode_padded(b"foo"), "Zm9v");
        assert_eq!(base64_encode_padded(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode_padded(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode_padded(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_decode_matches_rfc4648_vectors_unpadded() {
        // The same §10 corpus read back, padding stripped — the coverage the
        // decoder lacked while it lived in another file with one pinned identity.
        for (plain, encoded) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy"),
        ] {
            assert_eq!(
                base64_decode_unpadded(encoded).as_deref(),
                Some(plain),
                "decode({encoded})",
            );
            // And the two halves agree: encode-then-strip-padding round trips.
            assert_eq!(
                base64_encode_padded(plain).trim_end_matches('='),
                encoded,
                "encode({plain:?})",
            );
        }
    }

    #[test]
    fn the_decoder_inverts_the_shared_alphabet() {
        // `sextet` is a fast match, not a scan of `ALPHABET`; this is the pin that
        // makes it a genuine inverse of the constant both halves are defined by, so
        // a correction to the alphabet cannot land on the encoder alone.
        for (i, &b) in ALPHABET.iter().enumerate() {
            assert_eq!(
                sextet(b),
                Some(u32::try_from(i).expect("64 alphabet slots")),
                "alphabet[{i}] = {}",
                b as char,
            );
        }
    }

    #[test]
    fn base64_decode_rejects_non_alphabet_and_nonzero_padding() {
        assert!(base64_decode_unpadded("====").is_none(), "padding byte");
        assert!(base64_decode_unpadded("ERER RER").is_none(), "space");
        // Trailing bits carrying data (not zero) must not be silently dropped.
        assert!(base64_decode_unpadded("EE").is_none());
    }
}
