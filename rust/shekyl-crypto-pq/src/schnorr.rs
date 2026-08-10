// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Domain-separated Schnorr over the Ed25519 group — the single owner of
//! the house signing pattern for **raw-scalar** keys.
//!
//! # Why this exists rather than `ed25519_dalek`
//!
//! The wallet's spend secret is a raw Ed25519 *scalar* (`spend_pk = b·G`,
//! `account::rederive_account`). RFC 8032 is structurally impossible for
//! such a key: it derives both the scalar and the nonce prefix by hashing
//! a 32-byte seed we do not have. Every in-tree surface that signs with
//! `b` (or with another raw scalar such as the view secret) therefore
//! uses this construction:
//!
//! ```text
//! c = H(domain ‖ P ‖ R ‖ msg)      (SHA-512, wide-reduced)
//! s = k - c·sk
//! sig = R ‖ s                       (64 bytes)
//! verify:  s·G + c·P == R
//! ```
//!
//! # One owner, not three
//!
//! This construction previously existed as three byte-identical copies
//! (`shekyl-proofs` tx-proof, `shekyl-proofs` reserve-proof, and wallet
//! message signing). Copies of a signing routine do not drift
//! *harmlessly*: the hedged nonce below was added to one copy and the
//! other two kept a bare-RNG nonce, so the same spend scalar was
//! protected on one surface and not on the others. `domain` is the only
//! thing that legitimately varies, so it is the only parameter.
//!
//! # The nonce is hedged, and RNG failure is fail-safe
//!
//! `k = H(domain ‖ "nonce" ‖ sk ‖ msg ‖ 32 fresh random bytes)`. The
//! `"nonce"` sub-label separates nonce derivation from the challenge
//! hash under the same domain string, so the two uses cannot collide.
//!
//! Schnorr nonce *reuse across distinct messages* leaks the secret
//! scalar outright, which makes the RNG the sharpest edge in the
//! construction. Two properties follow deliberately:
//!
//! * A **failing** OS RNG degrades to a deterministic, RFC-6979-style
//!   nonce — never to a repeated one, and never to a panic. The
//!   fresh-entropy draw and its failure policy are owned by
//!   [`crate::rng::hedged_fresh32`], the single home of that decision;
//!   see `rng`'s module docs for the fail-safe/fail-loud split.
//! * A **predictable** RNG is likewise harmless: the secret scalar and
//!   the message are already in the hash, so `k` stays unpredictable to
//!   anyone who does not hold `sk`.

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest as _, Sha512};
use zeroize::Zeroize as _;

/// Wire length of a house Schnorr signature: `R ‖ s`.
pub const SIG_LEN: usize = 64;

/// Sub-label that separates nonce derivation from the challenge hash
/// under the same `domain` string.
const NONCE_LABEL: &[u8] = b"nonce";

/// Challenge scalar `c = H(domain ‖ P ‖ R ‖ msg)`.
#[must_use]
pub fn challenge(
    domain: &[u8],
    public_key: &EdwardsPoint,
    r_point: &EdwardsPoint,
    msg: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(public_key.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());
    hasher.update(msg);
    Scalar::from_hash(hasher)
}

/// Hedged nonce — see the module docs for why this is neither a bare RNG
/// draw nor a purely deterministic one.
fn hedged_nonce(domain: &[u8], secret_key: &Scalar, msg: &[u8]) -> Scalar {
    // Fail-safe, not fail-stop: on RNG failure the block is all-zeros and
    // `k` is the deterministic H(domain ‖ "nonce" ‖ sk ‖ msg).
    let mut fresh = crate::rng::hedged_fresh32();
    let mut hasher = Sha512::new();
    hasher.update(domain);
    hasher.update(NONCE_LABEL);
    hasher.update(secret_key.as_bytes());
    hasher.update(msg);
    hasher.update(fresh);
    fresh.zeroize();
    Scalar::from_hash(hasher)
}

/// Sign `msg` under `domain` with a raw scalar key.
///
/// `public_key` must be `secret_key·G`; it is a parameter rather than a
/// recomputation because every caller already holds it, and it enters
/// the challenge hash (key-prefixing).
#[must_use]
pub fn sign(
    domain: &[u8],
    secret_key: &Scalar,
    public_key: &EdwardsPoint,
    msg: &[u8],
) -> [u8; SIG_LEN] {
    let mut k = hedged_nonce(domain, secret_key, msg);
    let r_point = ED25519_BASEPOINT_TABLE * &k;
    let c = challenge(domain, public_key, &r_point, msg);
    let s = k - c * secret_key;
    k.zeroize();

    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(r_point.compress().as_bytes());
    sig[32..].copy_from_slice(&s.to_bytes());
    sig
}

/// Verify a signature produced by [`sign`] under the same `domain`.
///
/// Non-canonical `s`, and `R` or `P` that do not decompress, are
/// refusals rather than errors: every input is attacker-supplied public
/// data and the answer is "no".
#[must_use]
pub fn verify(domain: &[u8], public_key: &EdwardsPoint, msg: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    let Some(r_point) = CompressedEdwardsY(r_bytes).decompress() else {
        return false;
    };
    let mut s_arr = [0u8; 32];
    s_arr.copy_from_slice(&sig[32..]);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_arr)) else {
        return false;
    };
    let c = challenge(domain, public_key, &r_point, msg);
    ED25519_BASEPOINT_TABLE * &s + c * public_key == r_point
}

/// Verify against a **compressed** public key, refusing keys that do not
/// decompress. Convenience for callers whose public key arrives as
/// address bytes rather than as a point.
#[must_use]
pub fn verify_compressed(
    domain: &[u8],
    public_key: &[u8; 32],
    msg: &[u8],
    sig: &[u8; SIG_LEN],
) -> bool {
    let Some(point) = CompressedEdwardsY(*public_key).decompress() else {
        return false;
    };
    verify(domain, &point, msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"shekyl/schnorr-test-v1";

    fn keypair(seed: u8) -> (Scalar, EdwardsPoint) {
        let sk = Scalar::from_bytes_mod_order([seed; 32]);
        let pk = ED25519_BASEPOINT_TABLE * &sk;
        (sk, pk)
    }

    #[test]
    fn sign_verify_round_trips() {
        let (sk, pk) = keypair(0x24);
        let sig = sign(DOMAIN, &sk, &pk, b"hello");
        assert!(verify(DOMAIN, &pk, b"hello", &sig));
        assert!(verify_compressed(
            DOMAIN,
            &pk.compress().to_bytes(),
            b"hello",
            &sig
        ));
    }

    /// Every binding input flips the verdict — including `domain`, which
    /// is the whole reason this is parameterized rather than copied.
    #[test]
    fn domain_message_and_key_all_bind() {
        let (sk, pk) = keypair(0x24);
        let sig = sign(DOMAIN, &sk, &pk, b"hello");
        assert!(!verify(b"shekyl/schnorr-other-v1", &pk, b"hello", &sig));
        assert!(!verify(DOMAIN, &pk, b"hellp", &sig));
        let (_sk2, pk2) = keypair(0x25);
        assert!(!verify(DOMAIN, &pk2, b"hello", &sig));
    }

    /// The nonce is hedged, not deterministic: two signatures over the
    /// same message under a working RNG differ. (A deterministic
    /// fallback is only reached when the OS RNG fails, which no test can
    /// induce here — the property that matters, and that this asserts,
    /// is that the healthy path does not collapse to one nonce.)
    #[test]
    fn healthy_rng_produces_distinct_nonces() {
        let (sk, pk) = keypair(0x31);
        let a = sign(DOMAIN, &sk, &pk, b"same message");
        let b = sign(DOMAIN, &sk, &pk, b"same message");
        assert_ne!(a[..32], b[..32], "R must differ — nonce is hedged");
        assert!(verify(DOMAIN, &pk, b"same message", &a));
        assert!(verify(DOMAIN, &pk, b"same message", &b));
    }

    /// A non-canonical `s` is refused rather than wide-reduced — the
    /// malleability edge that `from_canonical_bytes` exists to close.
    #[test]
    fn non_canonical_scalar_is_refused() {
        let (sk, pk) = keypair(0x24);
        let mut sig = sign(DOMAIN, &sk, &pk, b"hello");
        sig[63] = 0xFF;
        assert!(!verify(DOMAIN, &pk, b"hello", &sig));
    }

    /// A public key that does not decompress is a refusal, not a panic.
    #[test]
    fn undecompressable_public_key_is_refused() {
        let (sk, pk) = keypair(0x24);
        let sig = sign(DOMAIN, &sk, &pk, b"hello");
        assert!(!verify_compressed(DOMAIN, &[0xFF; 32], b"hello", &sig));
    }
}
