// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A decoded Ed25519 + FN-DSA-1024 key held across signatures.
//!
//! [`super::HybridEd25519FnDsa`] decodes the FN-DSA half on every sign.
//! [`FnDsaHybridSigner`] decodes it once into a heap slot and signs from
//! there, through the same decoded-key call the per-call path uses after
//! its own decode. The serve path's receipt capability is the caller
//! (`docs/design/FN_DSA_HYBRID.md`, `FND-4`).

use ed25519_dalek::SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH;
use fn_dsa::{SigningKey as _, SigningKey1024};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::heap_secret::HeapSecret;
use crate::rng::HedgedOsRng;
#[cfg(any(test, feature = "test-utils"))]
use crate::seeded_rng::SeededRng;
use crate::CryptoError;

use super::{
    nest_fn_dsa_signature, sign_decoded_key, FnDsaHybridSecretKey, FnDsaHybridSignature,
    FN_DSA_1024_SECRET_KEY_LENGTH,
};

/// The pinned crate's decoded signing key wipes itself when it drops. The
/// held signer rests on that for the context it keeps resident, so a crate
/// bump that dropped the derive fails here instead of being trusted.
const _: fn() = || {
    fn wipes_itself_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
    wipes_itself_on_drop::<SigningKey1024>();
};

/// An Ed25519 + FN-DSA-1024 secret key decoded once and held.
///
/// [`crate::signature::SignatureScheme::sign`] builds a 118,640-byte context
/// on the caller's stack, uses it once and wipes it. This type decodes that
/// context once into a heap slot. A signature then costs neither the decode
/// nor those bytes on the signing stack.
///
/// # What it produces
///
/// The signature [`super::HybridEd25519FnDsa`] produces for the same key,
/// domain and message. A decoded key is a function of the key bytes alone,
/// and the working buffers carry nothing from one signature to the next, so
/// the same draw emits the same bytes
/// (`a_held_key_signs_the_bytes_the_scheme_signs`).
///
/// # Secrets
///
/// Both halves are on the heap, each at one address for the signer's life,
/// and both are wiped there on drop: the Ed25519 seed by its buffer, the
/// decoded FN-DSA key by the crate's `Zeroize` run on it in place, after
/// which the crate's own `ZeroizeOnDrop` runs too. Moving the signer moves
/// two pointers. There is no `Clone`, no encoding, no accessor for either
/// half, and `Debug` prints nothing of them.
///
/// **One residue, paid once per signer.** The crate returns a decoded key
/// by value, so [`Self::new`] cannot decode straight into the heap slot.
/// It decodes into a local, exchanges that local with the slot, and wipes
/// the local. The crate's own frame is out of reach: where the return value
/// is not constructed in place, `SigningKey1024::decode` leaves the copy it
/// built on its dead stack frame. The per-call signer leaves that residue
/// on every signature; here it is once, at construction.
pub struct FnDsaHybridSigner {
    ed25519: HeapSecret<ED25519_SECRET_KEY_LENGTH>,
    fn_dsa: DecodedFnDsaKey,
}

/// The decoded FN-DSA key, in the heap slot it occupies for the signer's life.
///
/// `Option` is only how the crate's `decode` returns the key, which is what
/// lets the bytes reach the heap without one more stack move
/// ([`fn_dsa_decode_held`]). After [`FnDsaHybridSigner::new`] the slot is
/// occupied. [`Self::key_mut`] is that fact; a missing key is a broken
/// signer, not bad key material.
struct DecodedFnDsaKey(Box<Option<SigningKey1024>>);

impl DecodedFnDsaKey {
    fn key_mut(&mut self) -> &mut SigningKey1024 {
        self.0
            .as_mut()
            .as_mut()
            .expect("a built signer holds its decoded key")
    }

    /// The heap slot, for tests that watch the key stay at one address and
    /// that watch the crate's wipe reach it. Not a production accessor.
    #[cfg(test)]
    fn slot(&self) -> &Option<SigningKey1024> {
        &self.0
    }

    /// The crate's `Zeroize`, in place. `Option::zeroize` takes the value
    /// out, which is two copies of the context on the dropping frame
    /// (`FN_DSA_HYBRID.md` `FND-20`).
    fn wipe(&mut self) {
        if let Some(key) = self.0.as_mut().as_mut() {
            key.zeroize();
        }
    }
}

impl FnDsaHybridSigner {
    /// Decode `secret_key` once and hold it.
    ///
    /// The key is borrowed: the caller keeps its own copy and its wiping.
    /// Construction is the expensive step — it needs the stack one
    /// [`crate::signature::SignatureScheme::sign`] needs
    /// (`a_held_key_signs_on_a_small_stack`) — so it belongs where the key
    /// is installed, not on a signing path.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKeyMaterial`] if the FN-DSA half does not
    /// decode. A malformed key is refused here, before any signature is
    /// asked for.
    pub fn new(secret_key: &FnDsaHybridSecretKey) -> Result<Self, CryptoError> {
        Ok(Self {
            fn_dsa: DecodedFnDsaKey(fn_dsa_decode_held(secret_key.fn_dsa.as_array())?),
            ed25519: HeapSecret::copied_from(secret_key.ed25519.as_array()),
        })
    }

    /// Sign `message` under `domain` with the held key, drawing FN-DSA's
    /// seed from the OS through the hedged adapter, as
    /// [`crate::signature::SignatureScheme::sign`] does.
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

    /// The nested sign over the held key. `rng` is where FN-DSA draws its
    /// seed. The body is [`super::nest_fn_dsa_signature`], the one
    /// [`super::HybridEd25519FnDsa`] signs through.
    fn sign_with_rng(
        &mut self,
        domain: &[u8],
        message: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<FnDsaHybridSignature, CryptoError> {
        let ed25519 = self.ed25519.as_array();
        let key = self.fn_dsa.key_mut();
        nest_fn_dsa_signature(ed25519, domain, message, |inner| {
            sign_decoded_key(key, rng, inner)
        })
    }

    /// Wipe the decoded key where it lies. Drop calls this; it is a method
    /// so the wipe can be observed without reading freed memory.
    fn wipe(&mut self) {
        self.fn_dsa.wipe();
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl FnDsaHybridSigner {
    /// Deterministic nested sign for vectors and benches. FN-DSA draws from a
    /// ChaCha20 stream over `rng_seed` instead of the OS. For one key, domain,
    /// message and seed this is byte for byte
    /// [`super::HybridEd25519FnDsa::sign_with_rng_seed`].
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

// A marker, and it wipes nothing: `ZeroizeOnDrop` has no methods. The wipe
// is the `Drop` impl above, which runs the crate's `Zeroize` on the decoded
// key in place; the Ed25519 seed is wiped by its own buffer's drop. This
// impl asserts that promise to the type system, so the signer meets a
// `ZeroizeOnDrop` bound and reads as what it is, a type that wipes itself.
//
// Written by hand and not derived because the derive would call `zeroize` on
// each field, and for the key's slot that is `Option::zeroize`, which takes
// the value out: two copies of a 118,640-byte context on the stack of
// whatever frame the signer is dropped in (`FN_DSA_HYBRID.md` `FND-20`).
//
// Held by `the_signer_is_wiped_on_drop` (the bound) and
// `drop_wipes_the_held_key_in_place` (what the `Drop` impl's wipe does).
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
/// [`super::fn_dsa_sign`]: inlined, it would sit on the caller's stack for
/// as long as the caller ran.
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

#[cfg(test)]
mod tests {
    use super::*;

    use fn_dsa::{SigningKey1024, FN_DSA_LOGN_1024};

    use crate::signature::{SignatureScheme, SCHEME_DOMAIN_RECEIPT, SCHEME_DOMAIN_WITNESS_CARRIER};

    use super::super::HybridEd25519FnDsa;

    const D: &[u8] = SCHEME_DOMAIN_RECEIPT;

    fn keypair() -> (super::super::FnDsaHybridPublicKey, FnDsaHybridSecretKey) {
        HybridEd25519FnDsa::keypair_from_seeds(&[7u8; 32], &[8u8; 32]).expect("keygen")
    }

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

    /// The test seam other crates corrupt a key through makes a key the
    /// held signer refuses to build from, and leaves the Ed25519 half alone.
    #[test]
    fn the_test_corruption_makes_the_key_undecodable() {
        let (_, mut sk) = keypair();
        let ed25519_before = *sk.ed25519.as_array();
        FnDsaHybridSigner::new(&sk).expect("control: the intact key decodes");
        sk.corrupt_fn_dsa_half_for_tests();
        assert!(matches!(
            FnDsaHybridSigner::new(&sk),
            Err(CryptoError::InvalidKeyMaterial)
        ));
        assert_eq!(sk.ed25519.as_array(), &ed25519_before);
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
        let before = std::ptr::from_ref(signer.fn_dsa.slot());
        let moved = Box::new(std::convert::identity(signer));
        let after = std::ptr::from_ref(moved.fn_dsa.slot());
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
        let address = std::ptr::from_ref(signer.fn_dsa.slot());
        let degree = |signer: &FnDsaHybridSigner| {
            signer.fn_dsa.slot().as_ref().map(SigningKey1024::get_logn)
        };
        assert_eq!(degree(&signer), Some(FN_DSA_LOGN_1024));
        signer.wipe();
        assert_eq!(degree(&signer), Some(0), "the crate's wipe ran on the key");
        assert_eq!(
            address,
            std::ptr::from_ref(signer.fn_dsa.slot()),
            "and it ran where the key lies"
        );
        // Idempotent: drop wipes again, and the crate's own drop after it.
        signer.wipe();
    }

    /// The promise the `ZeroizeOnDrop` marker makes, as a bound: the signer,
    /// and both things it holds, are wiped on drop. `drop_wipes_the_held_key_in_place`
    /// shows the wipe itself.
    #[test]
    fn the_signer_is_wiped_on_drop() {
        fn wiped_on_drop<T: ZeroizeOnDrop>() {}
        wiped_on_drop::<FnDsaHybridSigner>();
        wiped_on_drop::<SigningKey1024>();
        wiped_on_drop::<HeapSecret<ED25519_SECRET_KEY_LENGTH>>();
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
    /// key out of its slot, fails here.
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
