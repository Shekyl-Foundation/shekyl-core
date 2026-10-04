// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! rend-spec-v3 §6 onion hostname from an Ed25519 public key.
//!
//! It holds no secret, opens no socket, and does not name a Tor instance.
//! Two owners read it so they cannot drift:
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
//! [`v3_pubkey`] runs it backwards: the hostname must be the canonical
//! encoding of its key, and that key must decompress to an Edwards point
//! that is not small-order. It still holds no secret and names no Tor
//! instance.

#![deny(unsafe_code)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha3::{Digest, Sha3_256};

/// Version byte of a v3 onion address (rend-spec-v3 §6).
const ONION_ADDRESS_VERSION: u8 = 0x03;

/// Domain-separation prefix for the v3 address checksum (rend-spec-v3 §6).
const ONION_CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// 56-character lowercase base32 v3 service id (no `.onion` suffix).
///
/// Encodes the bytes it is given. Whether they are a curve point is
/// [`v3_pubkey`]'s question.
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

/// Whether `host` is a v3 onion hostname.
///
/// This is [`v3_pubkey`]`(host).is_some()`.
#[must_use]
pub fn is_v3_onion_hostname(host: &str) -> bool {
    v3_pubkey(host).is_some()
}

/// The 32-byte service key of a v3 onion hostname, when `host` is one.
///
/// The hostname is not returned. A caller that needs the address again
/// re-encodes the key with [`v3_onion_hostname`].
///
/// `host` must be the canonical lowercase encoding of its key. Tor's
/// parser tolerates either case; this one does not, so one service has
/// one spelling. The key must decompress to an Edwards point that is not
/// small-order. A torsion component past that subgroup is accepted.
#[must_use]
pub fn v3_pubkey(host: &str) -> Option<[u8; 32]> {
    let id = host.strip_suffix(".onion")?;
    if id.len() != 56 {
        return None;
    }
    let raw = base32_decode_35(id)?;
    if raw[34] != ONION_ADDRESS_VERSION {
        return None;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[..32]);
    if v3_service_id(&pubkey) != id {
        return None;
    }
    let point = CompressedEdwardsY(pubkey).decompress()?;
    if point.is_small_order() {
        return None;
    }
    Some(pubkey)
}

/// Inverse of [`base32_lower`] for the 35-byte v3 address body.
///
/// The alphabet is lowercase `a-z` and `2-7`. Tor's parser accepts
/// uppercase as well; this one rejects it, so one service has one spelling.
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
        assert_eq!(v3_pubkey(&host), Some([0x11; 32]));
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

    /// Tor's `test_build_address` (`src/test/test_hs_common.c`). The script
    /// `hs_build_address.py` builds this hostname from the first public key
    /// of RFC 8032 §7.1. Both literals are from that test.
    #[test]
    fn pubkey_matches_tors_address_vector() {
        let pubkey: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let host = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        assert_eq!(v3_pubkey(host), Some(pubkey));
        assert_eq!(v3_onion_hostname(&pubkey), host);
        assert!(is_v3_onion_hostname(host));
    }

    /// A correct checksum over a key that is not a curve point, and one
    /// over the identity. The hostnames were built with SHA3-256 and
    /// base32 outside this crate. The encoder still spells them; the
    /// parser refuses them.
    #[test]
    fn a_checksum_over_a_non_point_is_not_a_key() {
        let mut not_a_point = [0u8; 32];
        not_a_point[0] = 2;
        let host = "aiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab3did.onion";
        assert_eq!(v3_onion_hostname(&not_a_point), host);
        assert_eq!(v3_pubkey(host), None);

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let host = "aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaahmjqd.onion";
        assert_eq!(v3_onion_hostname(&identity), host);
        assert_eq!(v3_pubkey(host), None);
    }
}
