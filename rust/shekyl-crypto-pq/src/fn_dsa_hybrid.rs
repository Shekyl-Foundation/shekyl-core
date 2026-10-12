// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Hybrid Ed25519 + FN-DSA-1024 signatures — scheme byte 3.
//!
//! The same nested combiner as [`crate::signature`] (SA-R-1, the private
//! `hybrid_combiner` module) with FN-DSA-1024 as the post-quantum half:
//!
//! ```text
//! preimage  = cSHAKE256-64(customization = domain, input = 0x03 ‖ message)
//! σ_pq      = FN-DSA-1024.Sign(preimage, ctx = "", raw message)   // PQ-inner
//! σ_ed      = Ed25519.Sign(preimage ‖ σ_pq)                       // classical-outer
//! ```
//!
//! # What it is for, and what it is not for
//!
//! The serve receipt and the witness's carrier signature
//! (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §6, §7.3). Both are signatures whose
//! value expires within an epoch. Persona identity, transaction
//! authorization and everything else long-lived stay on Ed25519 + ML-DSA-65
//! and FIPS 204. That isolation is the reason this is a second scheme
//! rather than a replacement.
//!
//! # Pre-standard
//!
//! FN-DSA (Falcon) has no final standard: FIPS 206 is not published. The
//! `fn-dsa` crate says of itself that keys and signatures it produces may
//! stop verifying under later versions and that only 1.0 will be stable.
//! Every byte this module emits is therefore a property of the pinned crate
//! version. The vectors in `docs/test_vectors/FN_DSA_HYBRID_V1_KAT.json`
//! pin that; `docs/design/FN_DSA_HYBRID.md` is the dependency record; a
//! genesis build on a pre-1.0 lock is refused in CI.
//!
//! # Distinct types
//!
//! [`FnDsaHybridPublicKey`], [`FnDsaHybridSecretKey`] and
//! [`FnDsaHybridSignature`] share no type with the ML-DSA scheme's
//! `Hybrid*`. An API that takes a receipt key cannot be handed an identity
//! key; a receipt signature cannot be offered where a transaction
//! authorization is expected. The parsers enforce the same thing on bytes:
//! each accepts its own scheme byte and no other.
//!
//! Sizes are fixed and derived from the crate's own constants
//! ([`FN_DSA_1024_PUBLIC_KEY_LENGTH`] and its siblings); none is written
//! here as a number.
//!
//! # Randomness
//!
//! - **Key generation** is deterministic from two 32-byte seeds
//!   ([`HybridEd25519FnDsa::keypair_from_seeds`]): the Ed25519 half is the
//!   RFC 8032 seed, the FN-DSA half seeds a ChaCha20 stream the generator
//!   draws from — the pattern [`crate::derivation::keygen_from_seed`] uses
//!   for ML-DSA. The generator draws 32 bytes once and is deterministic
//!   after that. [`HybridEd25519FnDsa::generate_keypair`] draws both seeds
//!   from the OS and **fails** if it cannot (key material is fail-loud,
//!   [`crate::rng`]).
//! - **Signing** takes OS randomness through the crate-private `rng::HedgedOsRng`.
//!   FN-DSA's signer hedges internally — the drawn seed is replaced by
//!   `SHAKE256(H(signing key) ‖ μ ‖ seed)` before use — so the adapter's
//!   zero-on-failure fallback yields a deterministic signature, never a
//!   panic and never a reused nonce across messages.
//!
//! # Floating point
//!
//! Key generation and verification are integer-only in the crate. Signing
//! uses hardware `f64` on x86_64 and aarch64, which both mandate strict
//! IEEE-754. The vectors pin all three operations on both architectures: if
//! a signing vector ever differs between them, that is a determinism defect
//! to report, not a test to loosen (a deterministic signer that is not
//! bit-reproducible can emit two signatures over one hashed point).
//!
//! # Memory
//!
//! A decoded FN-DSA-1024 signing key is a ~114 kB context (the secret
//! basis in FFT form plus working buffers) and the key generator carries
//! ~48 kB of scratch. Both are locals of the private `fn_dsa_sign` and
//! `fn_dsa_keygen`, wiped by the crate when they drop. The crate's
//! `small_context` feature would shrink the first to ~82 kB for ~25% more
//! signing time; it is not enabled and has not been measured here.
//!
//! These are **stack** objects, and the crate hands the signing key back by
//! value, so a caller's stack depth matters: signing needs up to 256 KiB in
//! an optimized build and up to 640 KiB in an unoptimized one (verification
//! needs 64 KiB and 128 KiB). `the_scheme_runs_on_a_small_stack` holds
//! those, with its measurements. A caller that signs from deep inside a
//! task should sign from a shallower frame, or hold a decoded key across
//! signatures rather than decoding per signature — the choice belongs to
//! the first consumer, the serve path's signing capability.
//!
//! [`FnDsaHybridSigner`] is that held key. It decodes once, into a heap
//! slot, and signs from there: the context and its working buffers are
//! never on the signing caller's stack again, and the decode is paid once
//! per key instead of once per signature. Its stack needs, with their
//! measurements, are on `a_held_key_signs_on_a_small_stack`.

use crate::heap_secret::HeapSecret;
use crate::hybrid_combiner::{self, decode_canonical, encode_canonical, CANONICAL_OVERHEAD};
use crate::rng::{key_material32, HedgedOsRng};
use crate::seeded_rng::SeededRng;
use crate::signature::{
    SignatureScheme, HYBRID_KEY_VERSION, HYBRID_SCHEME_ID_ED25519_FN_DSA_1024, HYBRID_SIG_VERSION,
};
use crate::CryptoError;
use ed25519_dalek::{
    SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey,
    PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH,
};
use fn_dsa::{
    sign_key_size, signature_size, vrfy_key_size, KeyPairGenerator as _, KeyPairGenerator1024,
    SigningKey as _, SigningKey1024, VerifyingKey as _, VerifyingKey1024, DOMAIN_NONE,
    FN_DSA_LOGN_1024, HASH_ID_RAW,
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// FN-DSA-1024 verifying-key length, from the crate.
pub const FN_DSA_1024_PUBLIC_KEY_LENGTH: usize = vrfy_key_size(FN_DSA_LOGN_1024);
/// FN-DSA-1024 signing-key length, from the crate.
pub const FN_DSA_1024_SECRET_KEY_LENGTH: usize = sign_key_size(FN_DSA_LOGN_1024);
/// FN-DSA-1024 signature length, from the crate. Fixed: the compressed
/// signature is padded to it.
pub const FN_DSA_1024_SIGNATURE_LENGTH: usize = signature_size(FN_DSA_LOGN_1024);

/// A canonical Ed25519 + FN-DSA-1024 public key.
///
/// Constructed only by [`Self::from_canonical_bytes`] and by key
/// generation, both of which establish that the two halves decode: a value
/// of this type is a key both verifiers will accept as a key.
#[derive(Clone, PartialEq, Eq)]
pub struct FnDsaHybridPublicKey {
    ed25519: [u8; ED25519_PUBLIC_KEY_LENGTH],
    fn_dsa: [u8; FN_DSA_1024_PUBLIC_KEY_LENGTH],
}

impl std::fmt::Debug for FnDsaHybridPublicKey {
    /// No key bytes: a receipt key is public, and it is still not something
    /// a log line should carry in full.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnDsaHybridPublicKey(..)")
    }
}

impl FnDsaHybridPublicKey {
    /// Canonical wire length: the four-byte header and two length-prefixed
    /// halves.
    pub const CANONICAL_LEN: usize =
        CANONICAL_OVERHEAD + ED25519_PUBLIC_KEY_LENGTH + FN_DSA_1024_PUBLIC_KEY_LENGTH;

    /// The canonical encoding: version 1, scheme byte 3.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_canonical(
            HYBRID_KEY_VERSION,
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            &self.ed25519,
            &self.fn_dsa,
        )
    }

    /// Parse the canonical encoding.
    ///
    /// # Errors
    ///
    /// Any version but 1, any scheme byte but 3, a non-zero reserved field,
    /// either length off, a trailing byte, an Ed25519 half that is not a
    /// curve point, or an FN-DSA half the crate does not decode — which
    /// includes every non-canonical encoding of a valid key, since the
    /// crate accepts exactly one encoding per key.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let (ed25519, fn_dsa) = decode_canonical(
            bytes,
            HYBRID_KEY_VERSION,
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            ED25519_PUBLIC_KEY_LENGTH,
            FN_DSA_1024_PUBLIC_KEY_LENGTH,
            "invalid canonical FN-DSA hybrid public key",
        )?;
        let ed25519: [u8; ED25519_PUBLIC_KEY_LENGTH] = ed25519
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        let fn_dsa: [u8; FN_DSA_1024_PUBLIC_KEY_LENGTH] = fn_dsa
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ed25519VerifyingKey::from_bytes(&ed25519).map_err(|_| CryptoError::InvalidKeyMaterial)?;
        VerifyingKey1024::decode(&fn_dsa).ok_or(CryptoError::InvalidKeyMaterial)?;
        Ok(Self { ed25519, fn_dsa })
    }
}

/// An Ed25519 + FN-DSA-1024 secret key. Wiped on drop; never serialized.
///
/// There is no canonical encoding for it and no `Clone`: the receipt key is
/// re-derived from the wallet seed, and the witness key lives for one block
/// in memory. Neither is written anywhere.
///
/// Both halves live on the heap, each at the one address it was written
/// to, and are wiped there on drop. The bytes are borrowed, not
/// dereferenced: the array is `Copy`, and a deref would let a caller
/// rebuild the stack copy a move used to leave behind. Moving this type
/// moves two pointers.
pub struct FnDsaHybridSecretKey {
    ed25519: HeapSecret<ED25519_SECRET_KEY_LENGTH>,
    fn_dsa: HeapSecret<FN_DSA_1024_SECRET_KEY_LENGTH>,
}

impl std::fmt::Debug for FnDsaHybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnDsaHybridSecretKey([REDACTED])")
    }
}

/// A canonical Ed25519 + FN-DSA-1024 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct FnDsaHybridSignature {
    ed25519: [u8; ED25519_SIGNATURE_LENGTH],
    fn_dsa: [u8; FN_DSA_1024_SIGNATURE_LENGTH],
}

impl std::fmt::Debug for FnDsaHybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnDsaHybridSignature(..)")
    }
}

impl FnDsaHybridSignature {
    /// Canonical wire length: the four-byte header and two length-prefixed
    /// halves.
    pub const CANONICAL_LEN: usize =
        CANONICAL_OVERHEAD + ED25519_SIGNATURE_LENGTH + FN_DSA_1024_SIGNATURE_LENGTH;

    /// The canonical encoding: version 2 (the nested combiner), scheme
    /// byte 3.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_canonical(
            HYBRID_SIG_VERSION,
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            &self.ed25519,
            &self.fn_dsa,
        )
    }

    /// Parse the canonical encoding.
    ///
    /// This establishes the frame: version 2, scheme byte 3, both lengths,
    /// nothing trailing. Whether the FN-DSA half is the one canonical
    /// encoding of a signature is settled by the crate when the signature
    /// is verified, where a non-canonical encoding fails like a wrong one.
    ///
    /// # Errors
    ///
    /// Any version but 2 (a version-1 parallel signature included), any
    /// scheme byte but 3, a non-zero reserved field, either length off, or
    /// a trailing byte.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let (ed25519, fn_dsa) = decode_canonical(
            bytes,
            HYBRID_SIG_VERSION,
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            ED25519_SIGNATURE_LENGTH,
            FN_DSA_1024_SIGNATURE_LENGTH,
            "invalid canonical FN-DSA hybrid signature",
        )?;
        let malformed =
            || CryptoError::SerializationError("invalid canonical FN-DSA hybrid signature".into());
        Ok(Self {
            ed25519: ed25519.try_into().map_err(|_| malformed())?,
            fn_dsa: fn_dsa.try_into().map_err(|_| malformed())?,
        })
    }
}

/// The Ed25519 + FN-DSA-1024 scheme.
pub struct HybridEd25519FnDsa;

impl HybridEd25519FnDsa {
    /// The key pair two seeds determine.
    ///
    /// `ed25519_seed` is the RFC 8032 seed. `fn_dsa_seed` seeds a ChaCha20
    /// stream from which FN-DSA key generation draws; the same seeds give
    /// the same key pair on every supported architecture (pinned by
    /// vector). The caller owns both seeds and their wiping.
    ///
    /// # Errors
    ///
    /// Only if the generated FN-DSA key does not decode, which would be a
    /// defect in the pinned crate rather than a property of any seed.
    pub fn keypair_from_seeds(
        ed25519_seed: &[u8; 32],
        fn_dsa_seed: &[u8; 32],
    ) -> Result<(FnDsaHybridPublicKey, FnDsaHybridSecretKey), CryptoError> {
        let ed25519_signing = Ed25519SigningKey::from_bytes(ed25519_seed);
        let (fn_dsa_public, fn_dsa_secret) = fn_dsa_keygen(fn_dsa_seed);
        VerifyingKey1024::decode(&fn_dsa_public).ok_or_else(|| {
            CryptoError::KeyGenerationFailed(
                "FN-DSA-1024 keygen produced an undecodable key".into(),
            )
        })?;
        Ok((
            FnDsaHybridPublicKey {
                ed25519: ed25519_signing.verifying_key().to_bytes(),
                fn_dsa: fn_dsa_public,
            },
            FnDsaHybridSecretKey {
                // The RFC 8032 secret key is the seed. Copied from the
                // caller's borrow straight to the heap, so it is never a
                // by-value array on this stack.
                ed25519: HeapSecret::copied_from(ed25519_seed),
                fn_dsa: fn_dsa_secret,
            },
        ))
    }

    /// A fresh key pair from OS randomness — for a key that is never
    /// re-derived, such as the witness's per-block key.
    ///
    /// # Errors
    ///
    /// If the OS RNG fails. Key material has no safe fallback.
    pub fn generate_keypair() -> Result<(FnDsaHybridPublicKey, FnDsaHybridSecretKey), CryptoError> {
        let entropy = |e: rand::Error| CryptoError::KeyGenerationFailed(format!("OS RNG: {e}"));
        let ed25519_seed = key_material32().map_err(entropy)?;
        let fn_dsa_seed = key_material32().map_err(entropy)?;
        Self::keypair_from_seeds(&ed25519_seed, &fn_dsa_seed)
    }

    /// The nested sign with this scheme's post-quantum half
    /// ([`hybrid_combiner::sign_nested`]); the free parameter is where
    /// FN-DSA's signer draws its seed.
    fn sign_with_rng(
        secret_key: &FnDsaHybridSecretKey,
        domain: &[u8],
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        let (ed25519, fn_dsa) = hybrid_combiner::sign_nested(
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            secret_key.ed25519.as_array(),
            domain,
            message,
            |inner| fn_dsa_sign(secret_key.fn_dsa.as_array(), rng, inner),
        )?;
        Ok(FnDsaHybridSignature { ed25519, fn_dsa })
    }
}

// Test-support surface, behind `test-utils` like its ML-DSA counterpart.
#[cfg(any(test, feature = "test-utils"))]
impl HybridEd25519FnDsa {
    /// Deterministic nested sign for vectors and benches: FN-DSA's signer
    /// draws from a ChaCha20 stream over `rng_seed` instead of the OS.
    pub fn sign_with_rng_seed(
        &self,
        secret_key: &FnDsaHybridSecretKey,
        domain: &[u8],
        message: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        let mut rng = SeededRng::from_seed(rng_seed);
        Self::sign_with_rng(secret_key, domain, message, &mut rng)
    }
}

impl SignatureScheme for HybridEd25519FnDsa {
    type PublicKey = FnDsaHybridPublicKey;
    type SecretKey = FnDsaHybridSecretKey;
    type Signature = FnDsaHybridSignature;

    fn sign(
        &self,
        secret_key: &FnDsaHybridSecretKey,
        domain: &[u8],
        message: &[u8],
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        Self::sign_with_rng(secret_key, domain, message, &mut HedgedOsRng)
    }

    fn verify(
        &self,
        public_key: &FnDsaHybridPublicKey,
        domain: &[u8],
        message: &[u8],
        signature: &FnDsaHybridSignature,
    ) -> Result<(), CryptoError> {
        hybrid_combiner::verify_nested(
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            &hybrid_combiner::NestedSignature {
                ed25519_public: &public_key.ed25519,
                ed25519_signature: &signature.ed25519,
                sigma_pq: &signature.fn_dsa,
            },
            domain,
            message,
            || VerifyingKey1024::decode(&public_key.fn_dsa).ok_or(CryptoError::InvalidKeyMaterial),
            // Empty FN-DSA context, raw message: the 64-byte preimage is
            // already domain-separated and scheme-bound, as the ML-DSA half
            // signs it with an empty ML-DSA context (SA-R-3). `sigma_pq` is
            // the half the classical signature wraps. Pinned by vector.
            |fn_dsa_public, inner, sigma_pq| {
                fn_dsa_public.verify(sigma_pq, &DOMAIN_NONE, &HASH_ID_RAW, inner)
            },
        )
    }
}

/// The pinned crate's decoded signing key wipes itself when it drops. The
/// held signer below rests on that for the 118,640 bytes it keeps resident,
/// so it is asserted where a crate bump that dropped the derive would fail
/// to compile, instead of being read once and trusted afterwards.
const _: fn() = || {
    fn wipes_itself_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
    wipes_itself_on_drop::<SigningKey1024>();
};

/// An Ed25519 + FN-DSA-1024 secret key **decoded once and held**, for a
/// caller that signs many messages under one key — the serve path's receipt
/// capability (`docs/design/FN_DSA_HYBRID.md`, `FND-4`).
///
/// [`SignatureScheme::sign`] decodes the FN-DSA half on every call: a
/// 118,640-byte context (the secret basis in FFT form and the signer's
/// working buffers) built on the caller's stack, used once and wiped. This type
/// decodes it once into a heap slot and signs from there. What that removes
/// from each signature is the decode and every byte of that context on the
/// signing stack.
///
/// # What it produces
///
/// The signature [`HybridEd25519FnDsa`] produces for the same key, domain
/// and message: the same nested body (the private
/// `hybrid_combiner::sign_nested`), the same scheme byte, the same
/// randomness policy. A decoded key is a function of the key bytes alone
/// and the working buffers carry nothing from one signature to the next,
/// so given the same draw the two paths emit the same bytes
/// (`a_held_key_signs_the_bytes_the_scheme_signs`).
///
/// # Secrets
///
/// Both halves are on the heap, each at one address for the signer's life,
/// and both are wiped there on drop: the Ed25519 seed by its buffer, the
/// decoded FN-DSA key by the crate's `Zeroize` run on it in place, under
/// which the crate's own `ZeroizeOnDrop` also runs. Moving the signer moves
/// two pointers. There is no `Clone`, no encoding, no accessor for either
/// half, and `Debug` prints nothing of them.
///
/// **One residue, paid once per signer.** The crate hands a decoded key
/// back by value, so [`Self::new`] cannot decode into the heap slot
/// directly. It decodes into a local, exchanges that local with the heap
/// slot, and wipes the local. What it cannot reach is the crate's own
/// frame: in a build that does not construct the return value in place,
/// `SigningKey1024::decode` leaves the copy it built on its dead stack
/// frame. [`SignatureScheme::sign`] has the same residue on every
/// signature; here it is once, at construction, on the constructing thread.
pub struct FnDsaHybridSigner {
    ed25519: HeapSecret<ED25519_SECRET_KEY_LENGTH>,
    /// `Some` for the signer's whole life. It is an `Option` because that
    /// is what the crate's `decode` returns: holding the `Option` is what
    /// lets the key reach the heap without being moved out of it through
    /// one more stack copy.
    fn_dsa: Box<Option<SigningKey1024>>,
}

impl FnDsaHybridSigner {
    /// Decode `secret_key` once and hold it.
    ///
    /// The key is borrowed: the caller keeps its own copy and its wiping.
    /// Construction is the expensive step — it needs the stack one
    /// [`SignatureScheme::sign`] needs (`a_held_key_signs_on_a_small_stack`)
    /// — so it belongs where the key is installed, not on a signing path.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyMaterial`] if the FN-DSA half does not
    /// decode. A malformed key is refused here, before any signature is
    /// asked for.
    pub fn new(secret_key: &FnDsaHybridSecretKey) -> Result<Self, CryptoError> {
        Ok(Self {
            fn_dsa: fn_dsa_decode_held(secret_key.fn_dsa.as_array())?,
            ed25519: HeapSecret::copied_from(secret_key.ed25519.as_array()),
        })
    }

    /// Sign `message` under `domain` with the held key, drawing FN-DSA's
    /// seed from the OS through the hedged adapter, as
    /// [`SignatureScheme::sign`] does.
    ///
    /// `&mut self`: the crate's signer writes its working buffers, which
    /// live inside the held key. One signer signs one message at a time.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidInput`] for an empty domain;
    /// [`CryptoError::InvalidKeyMaterial`] if the crate's signer gives up,
    /// which it does only after treating a long run of rejected samples as
    /// a bad key.
    pub fn sign(
        &mut self,
        domain: &[u8],
        message: &[u8],
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        self.sign_with_rng(domain, message, &mut HedgedOsRng)
    }

    /// The nested sign over the held key; the free parameter is where
    /// FN-DSA's signer draws its seed. The body is
    /// [`hybrid_combiner::sign_nested`], the one
    /// [`HybridEd25519FnDsa`] signs through.
    fn sign_with_rng(
        &mut self,
        domain: &[u8],
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        // Borrowed in its heap slot, never moved out of it.
        let held = (*self.fn_dsa)
            .as_mut()
            .ok_or(CryptoError::InvalidKeyMaterial)?;
        let (ed25519, fn_dsa) = hybrid_combiner::sign_nested(
            HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
            self.ed25519.as_array(),
            domain,
            message,
            |inner| {
                let mut signature = [0u8; FN_DSA_1024_SIGNATURE_LENGTH];
                // Empty FN-DSA context, raw message, as `fn_dsa_sign` has
                // it. `None` means the key is invalid; the buffer has the
                // exact length.
                held.sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, inner, &mut signature)
                    .ok_or(CryptoError::InvalidKeyMaterial)?;
                Ok(signature)
            },
        )?;
        Ok(FnDsaHybridSignature { ed25519, fn_dsa })
    }

    /// Wipe the decoded key where it lies, in its heap slot. Drop calls
    /// this; it is a method so the wipe can be observed without reading
    /// freed memory.
    ///
    /// The crate's `Zeroize` is run on the key in place. `zeroize`'s wipe
    /// of the enclosing `Option` is not used here: it takes the value out
    /// to drop it, which is two copies of the context on the stack of
    /// whatever frame the signer happens to be dropped in.
    fn wipe(&mut self) {
        if let Some(held) = (*self.fn_dsa).as_mut() {
            held.zeroize();
        }
    }
}

// Test-support surface, behind `test-utils` like the scheme's own.
#[cfg(any(test, feature = "test-utils"))]
impl FnDsaHybridSigner {
    /// Deterministic nested sign for vectors and benches: FN-DSA's signer
    /// draws from a ChaCha20 stream over `rng_seed` instead of the OS. For
    /// one key, domain, message and seed this is byte for byte
    /// [`HybridEd25519FnDsa::sign_with_rng_seed`].
    pub fn sign_with_rng_seed(
        &mut self,
        domain: &[u8],
        message: &[u8],
        rng_seed: &[u8; 32],
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        let mut rng = SeededRng::from_seed(rng_seed);
        self.sign_with_rng(domain, message, &mut rng)
    }
}

impl Drop for FnDsaHybridSigner {
    fn drop(&mut self) {
        self.wipe();
        // `ed25519` wipes itself when its own drop runs, after this.
    }
}

impl ZeroizeOnDrop for FnDsaHybridSigner {}

impl std::fmt::Debug for FnDsaHybridSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnDsaHybridSigner([REDACTED])")
    }
}

/// Decode an FN-DSA-1024 signing key and leave it in a heap slot.
///
/// The crate returns the decoded key by value, inside an `Option`. It is
/// decoded into a local of this frame, exchanged with the heap slot — a
/// byte exchange between the two places, with no third copy — and the local
/// is then wiped over its whole length, which `zeroize` does for an
/// `Option` whether or not it still holds a value.
///
/// `#[inline(never)]` keeps that local in this frame, as it does for
/// `fn_dsa_sign`: inlined, it would sit on the caller's stack for as long
/// as the caller ran.
#[inline(never)]
fn fn_dsa_decode_held(
    secret: &[u8; FN_DSA_1024_SECRET_KEY_LENGTH],
) -> Result<Box<Option<SigningKey1024>>, CryptoError> {
    let mut held = empty_key_slot();
    let mut decoded = SigningKey1024::decode(secret);
    std::mem::swap(&mut *held, &mut decoded);
    // `decoded` now holds what the heap slot held, which was `None`; its
    // bytes are still this frame's, and they are wiped here.
    decoded.zeroize();
    if held.is_none() {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    Ok(held)
}

/// An empty heap slot for a decoded key.
///
/// Its own frame, so that whatever stack the empty value takes on its way
/// to the heap is given back before the decode runs.
#[inline(never)]
fn empty_key_slot() -> Box<Option<SigningKey1024>> {
    Box::new(None)
}

/// FN-DSA-1024 key generation from `seed`.
///
/// Returns the encoded public key and the encoded secret. The secret is
/// wrapped so it wipes on drop. The generator's scratch is a local of this
/// function and is wiped by the crate when it drops.
///
/// `#[inline(never)]` keeps that scratch in this frame. Inlining it stacks
/// the scratch on the caller, and `the_scheme_runs_on_a_small_stack` fails
/// when that happens.
#[inline(never)]
fn fn_dsa_keygen(
    seed: &[u8; 32],
) -> (
    [u8; FN_DSA_1024_PUBLIC_KEY_LENGTH],
    HeapSecret<FN_DSA_1024_SECRET_KEY_LENGTH>,
) {
    // The stream every seeded key in this crate is generated from. The
    // cipher is on the heap and is wiped there when this function returns.
    let mut rng = SeededRng::from_seed(seed);
    let mut generator = KeyPairGenerator1024::default();
    // Allocated at its final address and written there: the secret key is
    // never an array on this stack.
    let mut secret = HeapSecret::<FN_DSA_1024_SECRET_KEY_LENGTH>::zeroed();
    let mut public = [0u8; FN_DSA_1024_PUBLIC_KEY_LENGTH];
    generator.keygen(
        FN_DSA_LOGN_1024,
        &mut rng,
        secret.as_array_mut(),
        &mut public,
    );
    (public, secret)
}

/// One FN-DSA-1024 signature over `inner`, drawn from `rng`.
///
/// Returns the fixed-length signature. `InvalidKeyMaterial` means `secret`
/// did not decode: the crate reports a failed sign the same way, after it
/// has treated a long run of rejected samples as a bad key. The decoded
/// signing key is a local of this function and is wiped by the crate when
/// it drops.
///
/// `#[inline(never)]` keeps that key in this frame. Inlining it stacks the
/// key on the caller, and `the_scheme_runs_on_a_small_stack` fails when
/// that happens.
#[inline(never)]
fn fn_dsa_sign(
    secret: &[u8; FN_DSA_1024_SECRET_KEY_LENGTH],
    rng: &mut (impl RngCore + CryptoRng),
    inner: &[u8; 64],
) -> Result<[u8; FN_DSA_1024_SIGNATURE_LENGTH], CryptoError> {
    // Borrowed out of the `Option` it was decoded into, not moved: a move
    // is another ~114 kB of stack in an unoptimized build, and a second
    // copy of the key for the crate's wipe-on-drop to miss.
    let mut decoded = SigningKey1024::decode(secret);
    let signing_key = decoded.as_mut().ok_or(CryptoError::InvalidKeyMaterial)?;
    let mut signature = [0u8; FN_DSA_1024_SIGNATURE_LENGTH];
    // `None` means the key is invalid; the buffer has the exact length.
    signing_key
        .sign(rng, &DOMAIN_NONE, &HASH_ID_RAW, inner, &mut signature)
        .ok_or(CryptoError::InvalidKeyMaterial)?;
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Moving a secret key moves two pointers and no key byte: an inline
    /// array would leave an unwiped copy behind at every move.
    #[test]
    fn a_secret_key_holds_neither_half_inline() {
        assert_eq!(
            std::mem::size_of::<FnDsaHybridSecretKey>(),
            2 * std::mem::size_of::<usize>(),
            "both halves of the secret key must stay on the heap"
        );
    }

    /// The Ed25519 half is the seed the caller passed, as RFC 8032 has it:
    /// copying it from the borrow must give the key `SigningKey` would.
    #[test]
    fn the_ed25519_half_is_the_seed() {
        let seed = [0x1d; 32];
        let (public, secret) = HybridEd25519FnDsa::keypair_from_seeds(&seed, &[2; 32]).unwrap();
        assert_eq!(secret.ed25519.as_array(), &seed);
        assert_eq!(
            public.ed25519,
            Ed25519SigningKey::from_bytes(secret.ed25519.as_array())
                .verifying_key()
                .to_bytes()
        );
    }
    use crate::error::PqcVerifyError;
    use crate::signature::{verify_pqc_auth, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_CARRIER};

    const D: &[u8] = SCHEME_DOMAIN_RECEIPT;

    fn keypair() -> (FnDsaHybridPublicKey, FnDsaHybridSecretKey) {
        HybridEd25519FnDsa::keypair_from_seeds(&[7u8; 32], &[8u8; 32]).expect("keygen")
    }

    #[test]
    fn sign_with_os_randomness_verifies_and_is_randomized() {
        let (pk, sk) = keypair();
        let scheme = HybridEd25519FnDsa;
        let a = scheme.sign(&sk, D, b"message").expect("sign");
        let b = scheme.sign(&sk, D, b"message").expect("sign");
        scheme.verify(&pk, D, b"message", &a).expect("verifies");
        scheme.verify(&pk, D, b"message", &b).expect("verifies");
        assert_ne!(a, b, "two production signatures draw different seeds");
    }

    #[test]
    fn keygen_is_a_function_of_both_seeds() {
        let (pk, _) = keypair();
        let (same, _) = keypair();
        assert_eq!(pk, same);
        let (other_ed, _) =
            HybridEd25519FnDsa::keypair_from_seeds(&[9u8; 32], &[8u8; 32]).expect("keygen");
        let (other_fn, _) =
            HybridEd25519FnDsa::keypair_from_seeds(&[7u8; 32], &[9u8; 32]).expect("keygen");
        assert_ne!(pk, other_ed);
        assert_ne!(pk, other_fn);
        assert_ne!(other_ed, other_fn);
    }

    /// The witness's key: fresh from the OS, never re-derived.
    #[test]
    fn generated_keypairs_are_fresh_and_usable() {
        let (pk_a, sk_a) = HybridEd25519FnDsa::generate_keypair().expect("OS RNG");
        let (pk_b, _) = HybridEd25519FnDsa::generate_keypair().expect("OS RNG");
        assert_ne!(pk_a, pk_b);
        let scheme = HybridEd25519FnDsa;
        let sig = scheme
            .sign(&sk_a, SCHEME_DOMAIN_WITNESS_CARRIER, b"set commitment")
            .expect("sign");
        scheme
            .verify(
                &pk_a,
                SCHEME_DOMAIN_WITNESS_CARRIER,
                b"set commitment",
                &sig,
            )
            .expect("verifies under its own key");
        assert!(scheme
            .verify(
                &pk_b,
                SCHEME_DOMAIN_WITNESS_CARRIER,
                b"set commitment",
                &sig
            )
            .is_err());
    }

    #[test]
    fn domain_and_message_bind() {
        let (pk, sk) = keypair();
        let scheme = HybridEd25519FnDsa;
        let sig = scheme.sign(&sk, D, b"message").expect("sign");
        assert!(scheme
            .verify(&pk, SCHEME_DOMAIN_WITNESS_CARRIER, b"message", &sig)
            .is_err());
        assert!(scheme.verify(&pk, D, b"massage", &sig).is_err());
    }

    /// SA-R-2 holds for this scheme as for the other: no bare-message path,
    /// refused with an error rather than the hash helper's assertion.
    #[test]
    fn empty_domain_is_refused() {
        let (pk, sk) = keypair();
        let scheme = HybridEd25519FnDsa;
        assert!(matches!(
            scheme.sign(&sk, b"", b"message"),
            Err(CryptoError::InvalidInput(_))
        ));
        let sig = scheme.sign(&sk, D, b"message").expect("sign");
        assert!(matches!(
            scheme.verify(&pk, b"", b"message", &sig),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    #[test]
    fn canonical_round_trips() {
        let (pk, sk) = keypair();
        let key_bytes = pk.to_canonical_bytes();
        assert_eq!(key_bytes.len(), FnDsaHybridPublicKey::CANONICAL_LEN);
        assert_eq!(
            FnDsaHybridPublicKey::from_canonical_bytes(&key_bytes).expect("parses"),
            pk
        );
        let sig = HybridEd25519FnDsa.sign(&sk, D, b"message").expect("sign");
        let sig_bytes = sig.to_canonical_bytes();
        assert_eq!(sig_bytes.len(), FnDsaHybridSignature::CANONICAL_LEN);
        assert_eq!(
            FnDsaHybridSignature::from_canonical_bytes(&sig_bytes).expect("parses"),
            sig
        );
    }

    /// The header is the gate. Each byte of it, and each length, refuses on
    /// its own; a signature that would verify is the control.
    #[test]
    fn the_signature_parser_holds_its_header() {
        let (pk, sk) = keypair();
        let scheme = HybridEd25519FnDsa;
        let good = scheme
            .sign(&sk, D, b"message")
            .expect("sign")
            .to_canonical_bytes();
        let parsed = FnDsaHybridSignature::from_canonical_bytes(&good).expect("control parses");
        scheme
            .verify(&pk, D, b"message", &parsed)
            .expect("control verifies");

        let mutated = |at: usize, value: u8| {
            let mut bytes = good.clone();
            bytes[at] = value;
            FnDsaHybridSignature::from_canonical_bytes(&bytes)
        };
        assert!(mutated(0, 1).is_err(), "a version-1 signature is refused");
        assert!(mutated(0, 3).is_err(), "an unknown version is refused");
        assert!(mutated(1, 1).is_err(), "the ML-DSA scheme byte is refused");
        assert!(
            mutated(1, 2).is_err(),
            "the multisig scheme byte is refused"
        );
        assert!(mutated(1, 4).is_err(), "an unknown scheme byte is refused");
        assert!(mutated(2, 1).is_err(), "a reserved byte is refused");
        assert!(mutated(3, 1).is_err(), "a reserved byte is refused");
        assert!(mutated(4, 63).is_err(), "a wrong Ed25519 length is refused");

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(FnDsaHybridSignature::from_canonical_bytes(&trailing).is_err());
        assert!(FnDsaHybridSignature::from_canonical_bytes(&good[..good.len() - 1]).is_err());
        assert!(FnDsaHybridSignature::from_canonical_bytes(&[]).is_err());
    }

    #[test]
    fn the_key_parser_holds_its_header() {
        let (pk, _) = keypair();
        let good = pk.to_canonical_bytes();
        let mutated = |at: usize, value: u8| {
            let mut bytes = good.clone();
            bytes[at] = value;
            FnDsaHybridPublicKey::from_canonical_bytes(&bytes)
        };
        assert!(
            mutated(0, 2).is_err(),
            "the signature version is not a key version"
        );
        assert!(mutated(1, 1).is_err(), "the ML-DSA scheme byte is refused");
        assert!(mutated(2, 1).is_err(), "a reserved byte is refused");
        // The FN-DSA key opens with a byte naming its degree; another degree
        // is another scheme's key.
        let fn_dsa_at = CANONICAL_OVERHEAD + ED25519_PUBLIC_KEY_LENGTH;
        assert!(mutated(fn_dsa_at, good[fn_dsa_at] - 1).is_err());

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(FnDsaHybridPublicKey::from_canonical_bytes(&trailing).is_err());
    }

    /// The serve path's refusal trailer is a signature-length run of `0xFF`
    /// in the place a receipt would be. It must never parse as one: the
    /// first byte is the version, and `0xFF` is not 2.
    #[test]
    fn an_all_ones_fill_is_not_a_signature() {
        let fill = vec![0xFFu8; FnDsaHybridSignature::CANONICAL_LEN];
        assert!(FnDsaHybridSignature::from_canonical_bytes(&fill).is_err());
        let fill = vec![0xFFu8; FnDsaHybridPublicKey::CANONICAL_LEN];
        assert!(FnDsaHybridPublicKey::from_canonical_bytes(&fill).is_err());
    }

    /// Scheme 3 signs receipts and carriers. It does not authorize a
    /// transaction: the `pqc_auths` verifier knows schemes 1 and 2 and
    /// refuses this one by its discriminant, whatever the bytes are.
    #[test]
    fn a_receipt_key_cannot_authorize_a_transaction() {
        let (pk, sk) = keypair();
        let sig = HybridEd25519FnDsa.sign(&sk, D, b"tx hash").expect("sign");
        assert_eq!(
            verify_pqc_auth(
                HYBRID_SCHEME_ID_ED25519_FN_DSA_1024,
                &pk.to_canonical_bytes(),
                &sig.to_canonical_bytes(),
                b"tx hash",
            ),
            Err(PqcVerifyError::SchemeMismatch)
        );
        // And offered under scheme 1's discriminant, the bytes do not parse.
        assert_eq!(
            verify_pqc_auth(
                crate::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
                &pk.to_canonical_bytes(),
                &sig.to_canonical_bytes(),
                b"tx hash",
            ),
            Err(PqcVerifyError::DeserializationFailed)
        );
    }

    /// The scheme byte is inside the signed preimage, not only in the
    /// header: the two schemes' preimages over one domain and message
    /// differ, so no signature half made under one is a half under the
    /// other.
    #[test]
    fn the_scheme_byte_is_bound_in_the_preimage() {
        let fn_dsa = hybrid_combiner::preimage(HYBRID_SCHEME_ID_ED25519_FN_DSA_1024, D, b"message")
            .expect("preimage");
        let ml_dsa = hybrid_combiner::preimage(
            crate::signature::HYBRID_SCHEME_ID_ED25519_ML_DSA_65,
            D,
            b"message",
        )
        .expect("preimage");
        assert_ne!(fn_dsa, ml_dsa);
    }

    /// Key generation and signing each hold a large local — ~48 kB of
    /// generator scratch, a ~114 kB decoded signing key — and an
    /// unoptimized build copies such locals on every move. Measured on
    /// x86_64 at this commit, the smallest stack each ran on was:
    ///
    /// | | unoptimized | optimized |
    /// | --- | --- | --- |
    /// | key generation | 512 KiB | 128 KiB |
    /// | signing | 640 KiB | 256 KiB |
    /// | verification | 128 KiB | 64 KiB |
    ///
    /// (ladder steps, so each figure is an upper bound on the need). This
    /// test holds the whole scheme to half of the 2 MiB a spawned thread
    /// gets by default in an unoptimized build, and a quarter of it in an
    /// optimized one. A regression that moves the signing key again (the
    /// first draft did, and needed 1.25 MiB), or a crate bump that grows
    /// the context, fails here rather than as an overflow in a serving
    /// task.
    #[test]
    fn the_scheme_runs_on_a_small_stack() {
        const STACK_BYTES: usize = if cfg!(debug_assertions) {
            1024 * 1024
        } else {
            512 * 1024
        };
        std::thread::Builder::new()
            .stack_size(STACK_BYTES)
            .spawn(|| {
                let (pk, sk) = keypair();
                let scheme = HybridEd25519FnDsa;
                let sig = scheme.sign(&sk, D, b"message").expect("sign");
                scheme.verify(&pk, D, b"message", &sig).expect("verifies");
            })
            .expect("spawn")
            .join()
            .expect("the scheme ran within the stack");
    }

    // ---- The held key (`FnDsaHybridSigner`) ---------------------------

    /// The held key is the scheme's signer with the decode taken out, and
    /// nothing else: for one key, domain, message and draw the two paths
    /// emit the same bytes. Held against the scheme's own seeded entry —
    /// the one the pinned vectors go through — over both surfaces, several
    /// draws, and one signer reused throughout, so a working buffer that
    /// carried anything from one signature into the next would show.
    #[test]
    fn a_held_key_signs_the_bytes_the_scheme_signs() {
        let (pk, sk) = keypair();
        let scheme = HybridEd25519FnDsa;
        let mut signer = FnDsaHybridSigner::new(&sk).expect("a generated key decodes");
        let messages: [&[u8]; 3] = [b"", b"message", &[0xA5; 112]];
        for domain in [SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_CARRIER] {
            for message in messages {
                for seed_byte in [0u8, 0x33, 0xFF] {
                    let seed = [seed_byte; 32];
                    let expected = scheme
                        .sign_with_rng_seed(&sk, domain, message, &seed)
                        .expect("the scheme signs");
                    let held = signer
                        .sign_with_rng_seed(domain, message, &seed)
                        .expect("the held key signs");
                    assert_eq!(
                        held.to_canonical_bytes(),
                        expected.to_canonical_bytes(),
                        "the held key must emit the scheme's bytes"
                    );
                    scheme
                        .verify(&pk, domain, message, &held)
                        .expect("and they verify");
                }
            }
        }
    }

    /// The production entry: OS randomness through the hedged adapter. Many
    /// signatures from one held key, each verifying under the public key
    /// with the scheme's verifier, no two alike.
    #[test]
    fn a_held_key_signs_many_and_each_verifies() {
        let (pk, sk) = keypair();
        let mut signer = FnDsaHybridSigner::new(&sk).expect("decodes");
        // The signer borrowed the key; it does not need it afterwards.
        drop(sk);
        let scheme = HybridEd25519FnDsa;
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for round in 0u8..16 {
            // The same message every other round: a repeat must still draw
            // a fresh seed.
            let message = [round / 2; 112];
            let signature = signer.sign(D, &message).expect("sign");
            scheme
                .verify(&pk, D, &message, &signature)
                .expect("verifies under the public key");
            let bytes = signature.to_canonical_bytes();
            assert_eq!(bytes.len(), FnDsaHybridSignature::CANONICAL_LEN);
            assert!(
                !seen.contains(&bytes),
                "two production signatures draw different seeds"
            );
            seen.push(bytes);
        }
    }

    /// Domain and message bind through the held key as through the scheme,
    /// and the empty domain is refused with the same error (SA-R-2).
    #[test]
    fn a_held_key_binds_domain_and_message() {
        let (pk, sk) = keypair();
        let mut signer = FnDsaHybridSigner::new(&sk).expect("decodes");
        let scheme = HybridEd25519FnDsa;
        let signature = signer.sign(D, b"message").expect("sign");
        scheme
            .verify(&pk, D, b"message", &signature)
            .expect("control verifies");
        assert!(scheme
            .verify(&pk, SCHEME_DOMAIN_WITNESS_CARRIER, b"message", &signature)
            .is_err());
        assert!(scheme.verify(&pk, D, b"massage", &signature).is_err());
        let (other_pk, _) =
            HybridEd25519FnDsa::keypair_from_seeds(&[9u8; 32], &[8u8; 32]).expect("keygen");
        assert!(scheme.verify(&other_pk, D, b"message", &signature).is_err());
        assert!(matches!(
            signer.sign(b"", b"message"),
            Err(CryptoError::InvalidInput(_))
        ));
        // A refused call leaves the signer usable.
        let again = signer.sign(D, b"message").expect("sign");
        scheme
            .verify(&pk, D, b"message", &again)
            .expect("verifies after a refusal");
    }

    /// A malformed key is refused when the signer is built, not at the
    /// first signature. Three ways the FN-DSA half can be wrong: another
    /// degree in its header byte, an all-ones fill, an all-zero fill. The
    /// scheme's per-call signer is the control: it refuses the same keys,
    /// but only once asked to sign.
    #[test]
    fn a_malformed_key_is_refused_at_construction() {
        let corruptions: [fn(&mut [u8; FN_DSA_1024_SECRET_KEY_LENGTH]); 3] = [
            |bytes| bytes[0] -= 1,
            |bytes| bytes.fill(0xFF),
            |bytes| bytes.fill(0),
        ];
        for corrupt in corruptions {
            let (_, mut sk) = keypair();
            FnDsaHybridSigner::new(&sk).expect("control: the intact key decodes");
            corrupt(sk.fn_dsa.as_array_mut());
            assert!(matches!(
                FnDsaHybridSigner::new(&sk),
                Err(CryptoError::InvalidKeyMaterial)
            ));
            assert!(matches!(
                HybridEd25519FnDsa.sign(&sk, D, b"message"),
                Err(CryptoError::InvalidKeyMaterial)
            ));
        }
    }

    /// Moving the signer moves two pointers: neither half is inline, and
    /// the decoded key is the size the module's stack figures rest on.
    /// Measured on x86_64 at this commit: 118,640 bytes for the `Option`
    /// the heap slot holds.
    #[test]
    fn a_held_signer_holds_neither_half_inline() {
        assert_eq!(
            std::mem::size_of::<FnDsaHybridSigner>(),
            2 * std::mem::size_of::<usize>(),
            "both halves of the held key must stay on the heap"
        );
        let slot = std::mem::size_of::<Option<SigningKey1024>>();
        assert!(
            (100 * 1024..=128 * 1024).contains(&slot),
            "the decoded key is {slot} bytes; the stack bounds below and \
             the resident cost per held persona were sized for 118,640"
        );
    }

    /// A move leaves the decoded key at the address it was decoded to.
    #[test]
    fn a_move_does_not_move_the_held_key() {
        let (_, sk) = keypair();
        let signer = FnDsaHybridSigner::new(&sk).expect("decodes");
        let before = std::ptr::from_ref::<Option<SigningKey1024>>(&signer.fn_dsa);
        let moved = Box::new(std::convert::identity(signer));
        let after = std::ptr::from_ref::<Option<SigningKey1024>>(&moved.fn_dsa);
        assert_eq!(before, after);
    }

    /// The wipe drop performs reaches the decoded key. Observed through the
    /// one field of it the crate lets a caller read: the degree, 1024
    /// (`logn` = 10) in a decoded key and zero once the crate's `Zeroize`
    /// has run over the structure. That derive covers every field, the
    /// secret basis and the working buffers among them.
    #[test]
    fn drop_wipes_the_held_key_in_place() {
        let (_, sk) = keypair();
        let mut signer = FnDsaHybridSigner::new(&sk).expect("decodes");
        let address = std::ptr::from_ref::<Option<SigningKey1024>>(&signer.fn_dsa);
        let degree =
            |signer: &FnDsaHybridSigner| (*signer.fn_dsa).as_ref().map(SigningKey1024::get_logn);
        assert_eq!(degree(&signer), Some(FN_DSA_LOGN_1024));
        signer.wipe();
        assert_eq!(degree(&signer), Some(0), "the crate's wipe ran on the key");
        assert_eq!(
            address,
            std::ptr::from_ref::<Option<SigningKey1024>>(&signer.fn_dsa),
            "and it ran where the key lies"
        );
        // Idempotent: drop wipes again, and the crate's own drop after it.
        signer.wipe();
    }

    #[test]
    fn a_held_signer_prints_no_key() {
        let (_, sk) = keypair();
        let signer = FnDsaHybridSigner::new(&sk).expect("decodes");
        assert_eq!(format!("{signer:?}"), "FnDsaHybridSigner([REDACTED])");
    }

    /// What holding the key buys on the stack (`FND-4`). The smallest stack
    /// each step ran on, x86_64 at this commit, by a ladder of 8 KiB steps
    /// (so each figure is an upper bound on the need):
    ///
    /// | | unoptimized | optimized |
    /// | --- | --- | --- |
    /// | `HybridEd25519FnDsa::sign` (decodes per call) | 568 KiB | 248 KiB |
    /// | `FnDsaHybridSigner::sign` (held key) | 112 KiB | 16 KiB |
    /// | `FnDsaHybridSigner::new` (the one decode) | 544 KiB | 360 KiB |
    /// | dropping a `FnDsaHybridSigner` | 16 KiB | 16 KiB |
    ///
    /// 16 KiB is the ladder's first step, not a measured floor.
    ///
    /// Construction costs more than a per-call sign in an optimized build
    /// because it wipes the local the key was decoded into, and `zeroize`
    /// wipes an `Option` by taking its value out: two more copies of the
    /// context's size on the stack, both of them zeros. That is paid once,
    /// where the key is installed.
    ///
    /// This test holds a held-key signature, with the signer's drop, to an
    /// eighth of a default thread stack unoptimized and a thirty-second of
    /// it optimized, and construction to the bound the whole scheme is held
    /// to in `the_scheme_runs_on_a_small_stack`. A change that puts the
    /// context back on the signing stack, or a wipe on drop that takes the
    /// key out of its slot (the first draft's did, and a drop then needed
    /// more stack than a signature), fails here.
    #[test]
    fn a_held_key_signs_on_a_small_stack() {
        const SIGN_STACK_BYTES: usize = if cfg!(debug_assertions) {
            256 * 1024
        } else {
            64 * 1024
        };
        const BUILD_STACK_BYTES: usize = if cfg!(debug_assertions) {
            1024 * 1024
        } else {
            512 * 1024
        };
        let (pk, sk) = keypair();
        let mut signer = std::thread::Builder::new()
            .stack_size(BUILD_STACK_BYTES)
            .spawn(move || FnDsaHybridSigner::new(&sk).expect("decodes"))
            .expect("spawn")
            .join()
            .expect("the key was decoded within the stack");
        let signatures = std::thread::Builder::new()
            .stack_size(SIGN_STACK_BYTES)
            .spawn(move || {
                let first = signer.sign(D, b"message").expect("sign");
                let second = signer.sign(D, b"message").expect("sign");
                // The signer drops here, on this stack.
                [first, second]
            })
            .expect("spawn")
            .join()
            .expect("the held key signed, and dropped, within the stack");
        for signature in &signatures {
            HybridEd25519FnDsa
                .verify(&pk, D, b"message", signature)
                .expect("verifies");
        }
    }
}
