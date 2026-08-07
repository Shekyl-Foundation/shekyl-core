//! Shekyl's hash primitives, both backed by the audited RustCrypto `sha3` crate.
//!
//! Two primitives, two jobs, and the split is the point:
//!
//! - [`cn_fast_hash`] / [`tree_hash`] — **Keccak-256, for consensus parity only.**
//!   Use these *iff* the output must be byte-identical to the Monero-descended C++
//!   daemon: `prefix_hash`, `tree_hash`, block IDs, `pqc_signing_payload_hashes`,
//!   `multisig_pqc_leaf_hash`. They are un-domained because the thing they must
//!   match is un-domained.
//! - [`cshake256_32`] — **cSHAKE256 (SP 800-185), for everything new.** A new
//!   artifact on no consensus path takes this, with a customization string, so
//!   domain separation is structural rather than definitional.
//!
//! # Why Keccak-256 is not the default
//!
//! "Keccak-256" does not identify a function. Original Keccak (0x01 padding, what
//! this crate computes, and what Ethereum's `keccak256` is) and NIST FIPS 202
//! SHA3-256 (0x06) share a permutation and a rate and differ in one byte — so an
//! independent implementer reading "Keccak-256" has a coin-flip, and the failure is
//! silent: a different digest, no diagnostic. That ambiguity is tolerable exactly
//! where a KAT and a C++ twin pin it, and nowhere else. `cSHAKE256` has one meaning.
//!
//! # Keccak-256 (consensus)
//!
//! Original Keccak padding (0x01), NOT NIST SHA3 padding (0x06). Consensus-critical:
//! the output must be byte-identical to the C `src/crypto/keccak.c` (the empty-input
//! KAT in `tests` pins exactly that). The byte-identity, not the implementation
//! crate, is what is genesis-locked — `sha3` and the prior `tiny-keccak` both compute
//! the same original-Keccak-256, and standardizing on the RustCrypto crate collapses
//! the codebase onto one audited keccak (shekyl-oxide already uses `sha3`).
//!
//! The `cn_fast_hash` *name* is the inherited CryptoNote consensus-primitive name
//! ("cn" = CryptoNote; the *fast* hash vs. the slow PoW hash), kept for 1:1 source
//! mapping to the C++ daemon; a rule-93 rename to `keccak256` is a tracked follow-up
//! (see `60-no-monero-legacy.mdc`).

#![deny(unsafe_code)]

use sha3::digest::core_api::CoreWrapper;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core, Digest, Keccak256};

pub const HASH_SIZE: usize = 32;

pub type Hash = [u8; HASH_SIZE];

/// Compute `cn_fast_hash` — Keccak-256 with original padding, via RustCrypto `sha3`.
///
/// Matches `cn_fast_hash` in `src/crypto/hash.c` (keccak1600 absorb, first 32 bytes;
/// rate 136 bytes for 256-bit output). `sha3::Keccak256` is the original Keccak
/// variant (0x01 padding), so this is byte-identical to the prior tiny-keccak impl and
/// to the C++ daemon — verified by the empty-input KAT below and the live coinbase/
/// spend hash KATs in shekyl-wire.
pub fn cn_fast_hash(data: &[u8]) -> Hash {
    Keccak256::digest(data).into()
}

/// cSHAKE256 (SP 800-185) with a customization string, 32-byte output.
///
/// **The default for any new hashed artifact.** The customization string makes
/// domain separation structural: two contexts cannot collide even over identical
/// input bytes, without anyone having to remember a convention. Use
/// [`cn_fast_hash`] only where byte-identity with the C++ daemon is required.
///
/// `customization` follows the house convention `b"shekyl/<domain>-v1"` (see
/// `shekyl/archival-bond-post-v1`, `shekyl/receive-label-hash-v1`); version it, so
/// a preimage change is a new domain rather than a silent reinterpretation.
///
/// # Panics
///
/// Panics if `customization` is empty: cSHAKE with an empty function-name and
/// empty customization is defined to be plain SHAKE256, which would silently drop
/// the domain separation this primitive exists to provide.
///
/// This is the canonical home for the primitive. Two open-coded copies predate it
/// — `shekyl-archival-retention::hash` and `shekyl-crypto-pq::label` — and are
/// tracked for collapse onto this one (FOLLOWUPS), mirroring the one-audited-keccak
/// consolidation described above.
#[must_use]
pub fn cshake256_32(customization: &[u8], input: &[u8]) -> Hash {
    // cSHAKE with an empty function-name AND empty customization is defined to be
    // plain SHAKE256 (SP 800-185 §3.3; RustCrypto special-cases it back to SHAKE
    // padding). That would silently strip the domain separation this primitive
    // exists to provide, so an empty customization is a caller bug, not a valid
    // "no domain" request — reject it loudly rather than degrade in release.
    assert!(
        !customization.is_empty(),
        "cshake256_32 requires a non-empty customization string \
         (empty customization degrades to plain SHAKE256, defeating domain separation)"
    );
    let core = CShake256Core::new(customization);
    let mut hasher: CShake256 = CoreWrapper::from_core(core);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; HASH_SIZE];
    reader.read(&mut out);
    out
}

/// Compute `tree_hash_cnt`: largest power of 2 strictly less than count.
/// Equivalent to `tree_hash_cnt` in `src/crypto/tree-hash.c`.
fn tree_hash_cnt(count: usize) -> usize {
    debug_assert!(count >= 3);
    let mut pow = 2usize;
    while pow < count {
        pow <<= 1;
    }
    pow >> 1
}

/// Compute Merkle tree hash from a list of 32-byte hashes.
///
/// Matches `tree_hash` in `src/crypto/tree-hash.c` exactly.
pub fn tree_hash(hashes: &[Hash]) -> Hash {
    let count = hashes.len();
    match count {
        0 => [0u8; HASH_SIZE],
        1 => hashes[0],
        2 => {
            let mut buf = [0u8; 2 * HASH_SIZE];
            buf[..HASH_SIZE].copy_from_slice(&hashes[0]);
            buf[HASH_SIZE..].copy_from_slice(&hashes[1]);
            cn_fast_hash(&buf)
        }
        _ => {
            let mut cnt = tree_hash_cnt(count);
            let mut ints = vec![[0u8; HASH_SIZE]; cnt];

            let skip = 2 * cnt - count;
            ints[..skip].copy_from_slice(&hashes[..skip]);

            let mut i = skip;
            let mut j = skip;
            while j < cnt {
                let mut buf = [0u8; 2 * HASH_SIZE];
                buf[..HASH_SIZE].copy_from_slice(&hashes[i]);
                buf[HASH_SIZE..].copy_from_slice(&hashes[i + 1]);
                ints[j] = cn_fast_hash(&buf);
                i += 2;
                j += 1;
            }
            debug_assert_eq!(i, count);

            while cnt > 2 {
                cnt >>= 1;
                for k in 0..cnt {
                    let mut buf = [0u8; 2 * HASH_SIZE];
                    buf[..HASH_SIZE].copy_from_slice(&ints[2 * k]);
                    buf[HASH_SIZE..].copy_from_slice(&ints[2 * k + 1]);
                    ints[k] = cn_fast_hash(&buf);
                }
            }

            let mut buf = [0u8; 2 * HASH_SIZE];
            buf[..HASH_SIZE].copy_from_slice(&ints[0]);
            buf[HASH_SIZE..].copy_from_slice(&ints[1]);
            cn_fast_hash(&buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash() {
        let h = cn_fast_hash(&[]);
        // Known Keccak-256 of empty input (original padding, NOT SHA3)
        let expected = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(
            h, expected,
            "cn_fast_hash of empty input must match Keccak-256"
        );
    }

    #[test]
    fn known_hash() {
        let h = cn_fast_hash(b"Shekyl");
        assert_eq!(h.len(), HASH_SIZE);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn cshake256_nist_sp800_185_kat() {
        // Known-answer test pinned to an *external* authority — NIST SP 800-185
        // cSHAKE256 Sample #3 (not a value regenerated from our own output). This
        // is what fixes customization handling, cSHAKE padding, and XOF extraction
        // to the standard so any independent implementer computes the same bytes.
        //
        //   function name N = "" (empty), customization S = "Email Signature",
        //   input X = 00 01 02 03, requested output = 512 bits.
        //
        // `cshake256_32` takes the first 32 bytes of that XOF stream (our N is
        // always empty — CShake256Core::new maps its arg to S), so we pin the
        // leading 32 bytes of the published 64-byte sample output.
        let digest = cshake256_32(b"Email Signature", &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(
            digest,
            [
                0xd0, 0x08, 0x82, 0x8e, 0x2b, 0x80, 0xac, 0x9d, 0x22, 0x18, 0xff, 0xee, 0x1d, 0x07,
                0x0c, 0x48, 0xb8, 0xe4, 0xc8, 0x7b, 0xff, 0x32, 0xc9, 0x69, 0x9d, 0x5b, 0x68, 0x96,
                0xee, 0xe0, 0xed, 0xd1,
            ],
        );
    }

    #[test]
    fn cshake256_domain_separation() {
        // The whole point of the customization string: identical input under two
        // different domains must not collide.
        let input = b"same bytes, different domain";
        let a = cshake256_32(b"shekyl/domain-a-v1", input);
        let b = cshake256_32(b"shekyl/domain-b-v1", input);
        assert_ne!(
            a, b,
            "distinct customizations must not collide on same input"
        );
        assert_eq!(a.len(), HASH_SIZE);
    }

    #[test]
    #[should_panic(expected = "non-empty customization")]
    fn cshake256_rejects_empty_customization() {
        // An empty customization silently degrades to plain SHAKE256 (no domain
        // separation); the guard must reject it rather than return a SHAKE digest.
        let _hash = cshake256_32(b"", b"anything");
    }

    #[test]
    fn tree_hash_single() {
        let h = [0xABu8; HASH_SIZE];
        assert_eq!(tree_hash(&[h]), h);
    }

    #[test]
    fn tree_hash_two() {
        let a = cn_fast_hash(b"a");
        let b = cn_fast_hash(b"b");
        let root = tree_hash(&[a, b]);
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&a);
        combined[32..].copy_from_slice(&b);
        assert_eq!(root, cn_fast_hash(&combined));
    }
}
