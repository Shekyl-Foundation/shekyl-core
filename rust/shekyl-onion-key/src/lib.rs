// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A v3 onion service's Ed25519 keypair: the RFC 8032 expanded secret Tor
//! takes in an `ED25519-V3` key blob, and the public key the `.onion`
//! address encodes.
//!
//! The expansion (SHA-512 of a [`ONION_SEED_BYTES`]-byte seed, the low half
//! clamped) and the public key (a base-point multiplication by that clamped
//! secret) are secret-byte operations, so they live here (rule 36). A
//! persona seed is still derived in `shekyl-crypto-pq`
//! (`derive_p_onion_keypair`). That function calls [`OnionKeypair::from_seed`]
//! and the seed never leaves the derivation. The daemon's onion for one
//! boot is [`OnionKeypair::ephemeral`], which draws its seed from the
//! operating system's CSPRNG and does not return it.
//!
//! Every other crate takes an [`OnionKeypair`]. The Tor control client
//! builds an `OnionIdentity` from one, the address from
//! [`OnionKeypair::public_key`] and the key blob from
//! [`OnionKeypair::expanded_secret`], and hashes, clamps and multiplies
//! nothing itself.
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

#![deny(unsafe_code)]

use curve25519_dalek::EdwardsPoint;
use rand::RngCore as _;
use sha2::{Digest as _, Sha512};
use shekyl_heap_secret::HeapSecret;

/// RFC 8032 seed length. Expansion hashes these bytes. Tor does not store them.
pub const ONION_SEED_BYTES: usize = 32;

/// The clamped scalar occupies the low half of the expanded secret.
const ONION_SCALAR_BYTES: usize = 32;

/// The signing prefix occupies the high half. It is not clamped.
const ONION_PREFIX_BYTES: usize = 32;

/// Ed25519 public key length. The `.onion` address encodes these bytes.
pub const ONION_PUBLIC_KEY_BYTES: usize = 32;

/// Length of the RFC 8032 expanded secret: the clamped scalar, then the
/// signing prefix. Tor's `ED25519-V3` key blob is these bytes.
pub const ONION_EXPANDED_SECRET_BYTES: usize = ONION_SCALAR_BYTES + ONION_PREFIX_BYTES;

const _: () = assert!(ONION_SEED_BYTES == ONION_SCALAR_BYTES);
const _: () = assert!(ONION_PUBLIC_KEY_BYTES == ONION_SCALAR_BYTES);
const _: () = assert!(ONION_EXPANDED_SECRET_BYTES == ONION_SCALAR_BYTES + ONION_PREFIX_BYTES);

/// First byte of the scalar. Its low three bits are cleared.
const CLAMP_FIRST_BYTE: usize = 0;
/// Last byte of the scalar. Its high bit is cleared and the next bit is set.
const CLAMP_LAST_SCALAR_BYTE: usize = ONION_SCALAR_BYTES - 1;

/// Clears the low three bits of [`CLAMP_FIRST_BYTE`] (RFC 8032 §5.1.5).
const CLAMP_CLEAR_LOW_THREE_BITS: u8 = 0xf8;
/// Clears bit 255, the high bit of [`CLAMP_LAST_SCALAR_BYTE`].
const CLAMP_CLEAR_HIGH_BIT: u8 = 0x7f;
/// Sets bit 254, the second-highest bit of [`CLAMP_LAST_SCALAR_BYTE`].
const CLAMP_SET_SECOND_HIGH_BIT: u8 = 0x40;

/// The operating system's CSPRNG refused to fill an onion seed.
///
/// There is no fallback. An onion key from any other source would be
/// guessable, so the caller fails the boot rather than substituting.
#[derive(Debug)]
pub struct OnionSeedRngError {
    source: rand::Error,
}

impl std::fmt::Display for OnionSeedRngError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "onion seed: {}", self.source)
    }
}

impl std::error::Error for OnionSeedRngError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// A v3 onion service's keypair.
///
/// The expanded secret sits at one heap address and is wiped there on drop.
/// No `Clone`: a second owner calls [`Self::duplicate`], and the bytes Tor
/// receives are the separate copy [`Self::expanded_secret`] lends into the
/// `ED25519-V3` blob. No `Debug`, so the type cannot reach a log through a
/// derive.
pub struct OnionKeypair {
    expanded: HeapSecret<ONION_EXPANDED_SECRET_BYTES>,
    public_key: [u8; ONION_PUBLIC_KEY_BYTES],
}

impl OnionKeypair {
    /// A fresh keypair for an onion that lives for one process. The seed is
    /// drawn from the operating system's CSPRNG into a buffer this call
    /// wipes, expanded, and never returned.
    ///
    /// # Errors
    ///
    /// [`OnionSeedRngError`] when the operating system's CSPRNG refuses.
    pub fn ephemeral() -> Result<Self, OnionSeedRngError> {
        let mut seed = HeapSecret::<ONION_SEED_BYTES>::zeroed();
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_array_mut())
            .map_err(|source| OnionSeedRngError { source })?;
        Ok(Self::from_seed(seed.as_array()))
    }

    /// The keypair for a seed: RFC 8032 §5.1.5 expansion, and the public key
    /// from the expanded secret.
    ///
    /// This is the expansion primitive. A caller that already holds a seed
    /// expands it here rather than hashing and clamping the bytes itself.
    /// [`Self::ephemeral`] draws a boot seed in this crate and does not
    /// return it. The production caller that creates a persona seed is
    /// `shekyl-crypto-pq`'s `derive_p_onion_keypair`, and that seed does not
    /// leave the derivation.
    #[must_use]
    pub fn from_seed(seed: &[u8; ONION_SEED_BYTES]) -> Self {
        let mut expanded = HeapSecret::<ONION_EXPANDED_SECRET_BYTES>::zeroed();
        // The digest is written only into the heap buffer. `Sha512::digest`
        // would also return an unwiped `GenericArray`. sha2 0.10 has no
        // `zeroize` feature, so this hasher drops with its state still
        // resident; what the call removes is that second copy, the returned
        // digest. (sha3's hasher wipes itself. sha2's does not.)
        let mut hasher = Sha512::new();
        hasher.update(seed);
        hasher.finalize_into(expanded.as_array_mut().into());
        let secret = expanded.as_array_mut();
        secret[CLAMP_FIRST_BYTE] &= CLAMP_CLEAR_LOW_THREE_BITS;
        secret[CLAMP_LAST_SCALAR_BYTE] &= CLAMP_CLEAR_HIGH_BIT;
        secret[CLAMP_LAST_SCALAR_BYTE] |= CLAMP_SET_SECOND_HIGH_BIT;
        let public_key = public_key_of(expanded.as_array());
        Self {
            expanded,
            public_key,
        }
    }

    /// The Ed25519 public key, which the v3 `.onion` address encodes.
    #[must_use]
    pub fn public_key(&self) -> [u8; ONION_PUBLIC_KEY_BYTES] {
        self.public_key
    }

    /// The expanded secret, borrowed: the bytes Tor's `ED25519-V3` key blob
    /// carries. A copy of those bytes is `*keypair.expanded_secret()`.
    /// `[u8; N]` is `Copy`, and `OnionKey::from_expanded_bytes` takes the
    /// array by value, so that expression is the protocol-boundary copy.
    /// [`Self::duplicate`] is a different one: a second keypair, for a
    /// second owner of the same key.
    #[must_use]
    pub fn expanded_secret(&self) -> &[u8; ONION_EXPANDED_SECRET_BYTES] {
        self.expanded.as_array()
    }

    /// A second keypair holding the same key, at its own heap address.
    ///
    /// This is the copy a serving handoff makes. It is not the only copy of
    /// the bytes: [`Self::expanded_secret`] is what the Tor control client
    /// reads when it builds one `ED25519-V3` blob.
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
/// trap). `mul_base_clamped` takes its scalar bytes by value; `scalar` is
/// wiped here, and the callee's own copy is a stack argument this crate
/// cannot reach, the same as every by-value secret argument to
/// `curve25519-dalek`.
fn public_key_of(expanded: &[u8; ONION_EXPANDED_SECRET_BYTES]) -> [u8; ONION_PUBLIC_KEY_BYTES] {
    let mut scalar = [0u8; ONION_SCALAR_BYTES];
    scalar.copy_from_slice(&expanded[..ONION_SCALAR_BYTES]);
    let point = EdwardsPoint::mul_base_clamped(scalar);
    zeroize::Zeroize::zeroize(&mut scalar);
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
        let seed = [0x11u8; ONION_SEED_BYTES];
        let keypair = OnionKeypair::from_seed(&seed);
        let expanded = keypair.expanded_secret();
        assert_eq!(
            expanded[CLAMP_FIRST_BYTE] & !CLAMP_CLEAR_LOW_THREE_BITS,
            0,
            "low three bits cleared"
        );
        assert_eq!(
            expanded[CLAMP_LAST_SCALAR_BYTE] & !CLAMP_CLEAR_HIGH_BIT,
            0,
            "bit 255 cleared"
        );
        assert_eq!(
            expanded[CLAMP_LAST_SCALAR_BYTE] & CLAMP_SET_SECOND_HIGH_BIT,
            CLAMP_SET_SECOND_HIGH_BIT,
            "bit 254 set"
        );
        // The high half is the untouched prefix (SHA-512's tail). The
        // oracle's returned digest is test-only; production writes the
        // digest straight into the heap buffer.
        let raw = Sha512::digest(seed);
        assert_eq!(&expanded[ONION_SCALAR_BYTES..], &raw[ONION_SCALAR_BYTES..]);
    }

    /// The public key computed from the expanded secret is the key
    /// `ed25519-dalek` derives from the seed by its own RFC 8032 expansion,
    /// so the key Tor receives and the address the persona advertises are
    /// two views of one key.
    #[test]
    fn the_public_key_from_the_expanded_secret_is_the_seeds_verifying_key() {
        for seed in [
            [0u8; ONION_SEED_BYTES],
            [0x11; ONION_SEED_BYTES],
            [0x42; ONION_SEED_BYTES],
            [0x5c; ONION_SEED_BYTES],
            [0xff; ONION_SEED_BYTES],
        ] {
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
        let keypair = OnionKeypair::from_seed(&[0x42u8; ONION_SEED_BYTES]);
        assert_eq!(
            shekyl_onion_v3::v3_service_id(&keypair.public_key()),
            "efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad",
        );
    }

    #[test]
    fn the_keypair_is_deterministic_and_seed_bound() {
        let a = OnionKeypair::from_seed(&[0x5au8; ONION_SEED_BYTES]);
        let a2 = OnionKeypair::from_seed(&[0x5au8; ONION_SEED_BYTES]);
        let b = OnionKeypair::from_seed(&[0x5bu8; ONION_SEED_BYTES]);
        assert_eq!(a.public_key(), a2.public_key());
        assert_eq!(a.expanded_secret(), a2.expanded_secret());
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn a_duplicate_is_the_same_key_at_another_address() {
        let a = OnionKeypair::from_seed(&[0x77u8; ONION_SEED_BYTES]);
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
