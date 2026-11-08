// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A v3 onion service's Ed25519 keypair: the RFC 8032 expanded secret Tor
//! takes in an `ED25519-V3` key blob, and the public key the `.onion`
//! address encodes.
//!
//! The expansion (`SHA-512` of a 32-byte seed, the low half clamped) and the
//! public key (a base-point multiplication by that clamped secret) are
//! secret-byte operations, so they live here (rule 36). Every other crate
//! takes an [`OnionKeypair`]: the Tor control client builds its
//! `OnionIdentity` from one, the address from [`OnionKeypair::public_key`]
//! and the key blob from [`OnionKeypair::expanded_secret`], and computes
//! nothing secret itself.
//!
//! Two constructors, one per owner of an onion:
//!
//! - a persona's durable onion, [`crate::archival_p::derive_p_onion_keypair`]
//!   (the GF-9 serving label, network-scoped and `p_slot`-bound, frozen
//!   under `ARCHIVAL_P_DERIVE_V2`), which keeps the derived seed inside this
//!   crate;
//! - the daemon's onion for one boot, [`OnionKeypair::ephemeral`], which
//!   draws its seed from the operating system's CSPRNG.
//!
//! # The `Scalar` trap (verified against a real tor)
//!
//! `curve25519_dalek::Scalar::from_bytes_mod_order(clamp_integer(b))`
//! **reduces mod ℓ**, and a clamped integer is ≥ 2²⁵⁴ > ℓ, so writing a
//! `Scalar` back as the key blob yields a *different* (still valid) key and
//! an unreachable address. The clamp here is applied to raw bytes and never
//! round-tripped through a `Scalar`; the public key is the base point times
//! the clamped integer itself ([`EdwardsPoint::mul_base_clamped`]). The SP-T3
//! spike's live apparatus asserts a real tor reports a byte-identical
//! `ServiceID` for this expansion (the `published != service_id` fail-stop
//! in its `bring_up_with_pow`, on the `SHEKYL_TEST_TOR_BINARY` lane).

use curve25519_dalek::EdwardsPoint;
use rand::RngCore as _;
use sha2::{Digest as _, Sha512};

use crate::error::CryptoError;
use crate::heap_secret::HeapSecret;

/// Length of the RFC 8032 expanded secret: the clamped scalar, then the
/// signing prefix. Tor's `ED25519-V3` key blob is these bytes.
pub const ONION_EXPANDED_SECRET_BYTES: usize = 64;

/// A v3 onion service's keypair.
///
/// The expanded secret sits at one heap address and is wiped there on drop.
/// No `Clone`, so each copy of a serving secret is visible where it is made
/// ([`Self::duplicate`]); no `Debug`, so the type cannot reach a log through
/// a derive.
pub struct OnionKeypair {
    expanded: HeapSecret<ONION_EXPANDED_SECRET_BYTES>,
    public_key: [u8; 32],
}

impl OnionKeypair {
    /// A fresh keypair for an onion that lives for one process. The 32-byte
    /// seed is drawn from the operating system's CSPRNG into a buffer this
    /// call wipes, expanded, and never returned.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGenerationFailed`] when the operating system's
    /// CSPRNG refuses. There is no fallback: an onion key from anything else
    /// would be guessable.
    pub fn ephemeral() -> Result<Self, CryptoError> {
        let mut seed = HeapSecret::<32>::zeroed();
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_array_mut())
            .map_err(|e| CryptoError::KeyGenerationFailed(format!("onion seed: {e}")))?;
        Ok(Self::from_seed(seed.as_array()))
    }

    /// The keypair for a 32-byte seed: RFC 8032 §5.1.5 expansion, and the
    /// public key from the expanded secret. Crate-private: a seed is created
    /// and consumed inside this crate.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let mut expanded = HeapSecret::<ONION_EXPANDED_SECRET_BYTES>::zeroed();
        // Straight out of the digest into the wiped buffer. The digest's
        // `GenericArray` is not `Zeroize`, so it is consumed in the
        // expression rather than bound to a local that outlives the copy
        // (rule 35's hand-off discipline).
        expanded
            .as_array_mut()
            .copy_from_slice(&Sha512::digest(seed));
        let secret = expanded.as_array_mut();
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        let public_key = public_key_of(expanded.as_array());
        Self {
            expanded,
            public_key,
        }
    }

    /// The Ed25519 public key, which the v3 `.onion` address encodes.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// The expanded secret, borrowed: the bytes Tor's `ED25519-V3` key blob
    /// carries. A copy is `*keypair.expanded_secret()`, visible at the call.
    #[must_use]
    pub fn expanded_secret(&self) -> &[u8; ONION_EXPANDED_SECRET_BYTES] {
        self.expanded.as_array()
    }

    /// A second keypair holding the same key, at its own heap address. The
    /// one way to copy a serving secret, so every copy is named where it is
    /// made.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            expanded: HeapSecret::copied_from(self.expanded.as_array()),
            public_key: self.public_key,
        }
    }
}

/// The public key for an expanded secret: the base point times the clamped
/// low half, taken as the integer it is (no reduction; the module doc's
/// trap). `mul_base_clamped` takes its 32 bytes by value; `low` is wiped
/// here, and the callee's own copy is a stack argument this crate cannot
/// reach, the same as every by-value secret argument to `curve25519-dalek`.
fn public_key_of(expanded: &[u8; ONION_EXPANDED_SECRET_BYTES]) -> [u8; 32] {
    let mut low = [0u8; 32];
    low.copy_from_slice(&expanded[..32]);
    let point = EdwardsPoint::mul_base_clamped(low);
    zeroize::Zeroize::zeroize(&mut low);
    point.compress().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion_clamps_and_is_not_a_reduced_scalar() {
        // The module doc's trap, as an assertion: the clamped low half
        // carries the ed25519 clamp bits unreduced (bit 254 set, bits 0-2
        // and 255 clear). A `Scalar::to_bytes()` round-trip would reduce
        // mod ℓ and clear bit 254.
        let seed = [0x11u8; 32];
        let keypair = OnionKeypair::from_seed(&seed);
        let expanded = keypair.expanded_secret();
        assert_eq!(expanded[0] & 0b0000_0111, 0, "low three bits cleared");
        assert_eq!(expanded[31] & 0b1000_0000, 0, "bit 255 cleared");
        assert_eq!(expanded[31] & 0b0100_0000, 0x40, "bit 254 set");
        // The high half is the untouched PRF secret (SHA-512's tail).
        let raw = Sha512::digest(seed);
        assert_eq!(&expanded[32..], &raw[32..]);
    }

    /// The public key computed from the expanded secret is the key
    /// `ed25519-dalek` derives from the seed by its own RFC 8032 expansion,
    /// so the key Tor receives and the address the persona advertises are
    /// two views of one key.
    #[test]
    fn the_public_key_from_the_expanded_secret_is_the_seeds_verifying_key() {
        for seed in [[0u8; 32], [0x11; 32], [0x42; 32], [0x5c; 32], [0xff; 32]] {
            let keypair = OnionKeypair::from_seed(&seed);
            let dalek = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            assert_eq!(keypair.public_key(), dalek, "seed {:02x}", seed[0]);
        }
    }

    /// The address for a fixed seed, byte-exact. This string was pinned on
    /// the expansion's previous home (`shekyl-tor-control-client`'s
    /// `service_id_golden_kat`), so the move changes no address.
    #[test]
    fn the_address_for_a_fixed_seed_is_unchanged() {
        let keypair = OnionKeypair::from_seed(&[0x42u8; 32]);
        assert_eq!(
            shekyl_onion_v3::v3_service_id(&keypair.public_key()),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad",
        );
    }

    #[test]
    fn the_keypair_is_deterministic_and_seed_bound() {
        let a = OnionKeypair::from_seed(&[0x5au8; 32]);
        let a2 = OnionKeypair::from_seed(&[0x5au8; 32]);
        let b = OnionKeypair::from_seed(&[0x5bu8; 32]);
        assert_eq!(a.public_key(), a2.public_key());
        assert_eq!(a.expanded_secret(), a2.expanded_secret());
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn a_duplicate_is_the_same_key_at_another_address() {
        let a = OnionKeypair::from_seed(&[0x77u8; 32]);
        let d = a.duplicate();
        assert_eq!(a.public_key(), d.public_key());
        assert_eq!(a.expanded_secret(), d.expanded_secret());
        assert!(!std::ptr::eq(a.expanded_secret(), d.expanded_secret()));
    }

    #[test]
    fn two_ephemeral_keypairs_differ() {
        let a = OnionKeypair::ephemeral().expect("OS CSPRNG");
        let b = OnionKeypair::ephemeral().expect("OS CSPRNG");
        assert_ne!(a.public_key(), b.public_key());
    }
}
