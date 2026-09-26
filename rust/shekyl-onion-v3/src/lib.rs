// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! rend-spec-v3 §6 onion hostname from an Ed25519 public key.
//!
//! This crate is **encoding only**. It holds no secret, opens no socket,
//! and does not name a Tor instance. Two owners read it so they cannot
//! drift:
//!
//! - the wallet serving path (`shekyl-tor-control-client::OnionIdentity`)
//!   publishes at the address this function derives from the persona's
//!   expanded key;
//! - the daemon fetch path (`shekyl-p-fetch::ServingEndpoint`) dials the
//!   address this function derives from the bond-record endpoint column.
//!
//! Those are different types on purpose (`PWD-E9`: the serving P's Tor
//! instance is wallet-owned; every other Tor process is daemon-owned).
//! The transform they share is this one function of 32 public bytes.
//! [`is_v3_onion_hostname`] is that encoding run backwards: decode, then
//! compare to [`v3_service_id`]. It still holds no secret and names no
//! Tor instance.

#![deny(unsafe_code)]

use sha3::{Digest, Sha3_256};

/// Version byte of a v3 onion address (rend-spec-v3 §6).
const ONION_ADDRESS_VERSION: u8 = 0x03;

/// Domain-separation prefix for the v3 address checksum (rend-spec-v3 §6).
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// 56-character lowercase base32 v3 service id (no `.onion` suffix).
#[must_use]
pub fn v3_service_id(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(ONION_CHECKSUM_PREFIX);
    hasher.update(pubkey);
    hasher.update([ONION_ADDRESS_VERSION]);
    let checksum = hasher.finalize();

    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum[..2]);
    raw[34] = ONION_ADDRESS_VERSION;
    base32_lower(&raw)
}

/// `{service_id}.onion` — the hostname a SOCKS5h CONNECT names.
#[must_use]
pub fn v3_onion_hostname(pubkey: &[u8; 32]) -> String {
    let mut address = v3_service_id(pubkey);
    address.push_str(".onion");
    address
}

/// Whether `host` is a v3 onion hostname: 56 lowercase base32 characters,
/// the `.onion` suffix, version byte 3, and the rend-spec checksum.
///
/// The checksum is [`v3_service_id`] of the decoded key. A hostname this
/// function accepts re-encodes to itself.
#[must_use]
pub fn is_v3_onion_hostname(host: &str) -> bool {
    let Some(id) = host.strip_suffix(".onion") else {
        return false;
    };
    if id.len() != 56 {
        return false;
    }
    let Some(raw) = base32_decode_35(id) else {
        return false;
    };
    if raw[34] != ONION_ADDRESS_VERSION {
        return false;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[..32]);
    v3_service_id(&pubkey) == id
}

/// Inverse of [`base32_lower`] for the 35-byte v3 address body.
///
/// 56 characters are exactly 35 bytes, so a leftover bit is a rejection.
fn base32_decode_35(id: &str) -> Option<[u8; 35]> {
    let mut out = [0u8; 35];
    let mut filled = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in id.bytes() {
        let value = match byte {
            b'a'..=b'z' => u32::from(byte) - u32::from(b'a'),
            b'2'..=b'7' => u32::from(byte) - u32::from(b'2') + 26,
            _ => return None,
        };
        acc = (acc << 5) | value;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if filled == out.len() {
                return None;
            }
            out[filled] = u8::try_from((acc >> bits) & 0xff).ok()?;
            filled += 1;
        }
    }
    if bits != 0 || filled != out.len() {
        None
    } else {
        Some(out)
    }
}

/// RFC 4648 base32, lowercase, unpadded.
///
/// 35 bytes is a whole number of 5-byte groups (7 × 5), so no padding
/// case arises for the one real input; the general path is written and
/// tested rather than assumed.
///
/// `acc` holds only the `bits` not yet emitted (fewer than 5 after each
/// byte), so it never carries more than 12 live bits and the shift cannot
/// lose anything. Rust's `<<` would discard high bits silently rather than
/// trip `overflow-checks`, so the mask is legibility, not correctness —
/// but a reader should not have to know that to trust the loop.
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
        acc &= (1 << bits) - 1;
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

    /// Golden KAT shared with `shekyl-tor-control-client`: this is the
    /// public key its `service_id_golden_kat` derives from the hs-id seed
    /// `[0x42; 32]`, and the address below is the literal that test pins.
    /// The persona publishes at the address tor confirms for this key; the
    /// daemon dials the address `v3_onion_hostname` derives from the
    /// record. Both pinned to one string, so a drift on either side is a
    /// red test, not a live persona nobody can reach.
    #[test]
    fn hostname_matches_the_publish_side_golden_kat() {
        let pubkey: [u8; 32] = [
            0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e,
            0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06,
            0x98, 0x81, 0xdb, 0x12,
        ];
        assert_eq!(
            v3_service_id(&pubkey),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad"
        );
        assert_eq!(
            v3_onion_hostname(&pubkey),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.onion"
        );
    }

    #[test]
    fn hostname_is_well_formed_for_any_key() {
        let address = v3_onion_hostname(&[0x77u8; 32]);
        let (host, suffix) = address.split_at(56);
        assert_eq!(suffix, ".onion");
        assert!(host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        // The version byte lands in the final base32 group: v3 ends in 'd'.
        assert!(host.ends_with('d'), "v3 addresses end in 'd': {host}");
    }

    #[test]
    fn a_v3_hostname_verifies_and_a_changed_character_does_not() {
        let host = v3_onion_hostname(&[0x11; 32]);
        assert!(is_v3_onion_hostname(&host));
        assert!(is_v3_onion_hostname(
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad.onion"
        ));
        let mut chars: Vec<char> = host.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let flipped: String = chars.into_iter().collect();
        assert!(!is_v3_onion_hostname(&flipped));
        assert!(!is_v3_onion_hostname("not-an-onion"));
        assert!(!is_v3_onion_hostname(&host.to_ascii_uppercase()));
    }
}
