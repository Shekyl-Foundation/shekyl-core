// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve side of the SF-D8 pass countersignature.
//!
//! A `P` answering a shard request binds the daemon's 72-byte request
//! header, the shard id and a nonce-salted digest of the response it
//! delivers under `SCHEME_DOMAIN_ATTESTATION`; the daemon verifies that
//! binding against the `P` public key it already holds from the bond
//! record. The transcript both ends agree on —
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8] ‖ delivery_digest[32]` —
//! the digest construction and the anchor-gate constants are consensus
//! values owned by `shekyl_archival_retention::pass_anchor`; this module
//! only pairs them with a signer.
//!
//! ## The envelope has a width, and the width is the scheme
//!
//! The countersignature closes the response as a fixed-width envelope, and
//! that width is the canonical length of one hybrid scheme's signature.
//! [`PassKey`] and [`PassSigner`] are generic over it: `PassKey<W>` signs
//! with the scheme whose signature is `W` bytes, and the serve loop it is
//! handed to writes a `W`-byte envelope, declares it in the content length
//! and fills `W` bytes of refusal trailer. Nothing in the loop names a
//! width of its own.
//!
//! Two widths exist, and [`EnvelopeWidth`] is sealed over them:
//!
//! | Width | Scheme | Key | Status |
//! | --- | --- | --- | --- |
//! | [`IDENTITY_ENVELOPE_LEN`] (3,385) | 1, Ed25519 + ML-DSA-65 | the bond identity key | **live**: every production signer |
//! | [`RECEIPT_ENVELOPE_LEN`] (1,356) | 3, Ed25519 + FN-DSA-1024 | the persona's receipt key | **STAGED**: no production endpoint is bound at it (`FN_DSA_HYBRID.md` §9) |
//!
//! The width decides the signature type, so the two cannot disagree: a key
//! declared at one width cannot return the other scheme's signature, and a
//! width that is neither can have no key and no endpoint.
//!
//! ```compile_fail
//! // A width that is no scheme's signature length has no envelope: no
//! // endpoint can be bound at it.
//! use std::sync::Arc;
//! use shekyl_p_serve::{PServeEndpoint, PassSigner, ShardProvider};
//! async fn bind(provider: Arc<dyn ShardProvider>, signer: Arc<dyn PassSigner<64>>) {
//!     let _ = PServeEndpoint::bind(provider, signer).await;
//! }
//! ```
//!
//! ```compile_fail
//! // …and nothing can implement a key at it.
//! use shekyl_p_serve::{PassKey, SignRefused};
//! use shekyl_types::BlockHeight;
//! struct Odd;
//! impl PassKey<64> for Odd {
//!     fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> { Ok(()) }
//!     fn sign_pass(&self, _: &[u8; 112]) -> Result<[u8; 64], SignRefused> {
//!         Err(SignRefused::new("never"))
//!     }
//! }
//! ```
//!
//! ```compile_fail
//! // A key at the receipt width cannot return an identity signature.
//! use shekyl_crypto_pq::signature::HybridSignature;
//! use shekyl_p_serve::{PassKey, SignRefused, RECEIPT_ENVELOPE_LEN};
//! use shekyl_types::BlockHeight;
//! struct Mixed;
//! impl PassKey<RECEIPT_ENVELOPE_LEN> for Mixed {
//!     fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> { Ok(()) }
//!     fn sign_pass(&self, _: &[u8; 112]) -> Result<HybridSignature, SignRefused> {
//!         Err(SignRefused::new("never"))
//!     }
//! }
//! ```
//!
//! The control for the three refusals above: the same shapes at a real
//! width, with its own signature type, compile. A refusal that came from a
//! misspelt import and not from the width would fail this too.
//!
//! ```
//! use std::sync::Arc;
//! use shekyl_crypto_pq::signature::HybridSignature;
//! use shekyl_p_serve::{
//!     PServeEndpoint, PassKey, PassSigner, ShardProvider, SignRefused, IDENTITY_ENVELOPE_LEN,
//! };
//! use shekyl_types::BlockHeight;
//! struct Plain;
//! impl PassKey<IDENTITY_ENVELOPE_LEN> for Plain {
//!     fn ready(&self, _: u64, _: BlockHeight) -> Result<(), SignRefused> { Ok(()) }
//!     fn sign_pass(&self, _: &[u8; 112]) -> Result<HybridSignature, SignRefused> {
//!         Err(SignRefused::new("never"))
//!     }
//! }
//! async fn bind(
//!     provider: Arc<dyn ShardProvider>,
//!     signer: Arc<dyn PassSigner<IDENTITY_ENVELOPE_LEN>>,
//! ) {
//!     let _ = PServeEndpoint::bind(provider, signer).await;
//! }
//! ```
//!
//! An endpoint is bound with one signer and so at one width. There is no
//! endpoint that answers at either.
//!
//! ## Who holds the key
//!
//! This crate holds none. [`PassSigner`] is the seam: the host supplies an
//! object that knows the persona's current height (for the anchor gate)
//! and can produce its scheme's signature over the transcript. Where that
//! object's secret lives is the host's design — SH-2 for the bonded
//! persona, an ephemeral keypair for tests via `TestKeySigner` (armed by
//! the `test-signer` feature) — and the serve loop never sees more than
//! the returned signature.
//!
//! [`sign_pass_transcript`] is the one place the domain and the transcript
//! are paired for *signing*. Implementors call it rather than reaching for
//! `HybridEd25519MlDsa::sign` directly, so a host cannot bind the
//! transcript under a neighbouring domain and produce a signature the
//! daemon's `verify_pass_transcript` rejects.
//!
//! Inland clocks are ordinal [`shekyl_types::BlockHeight`]; depths are
//! [`shekyl_types::BlockCount`].
//!
//! ```compile_fail
//! // HEIGHT_SEMANTICS.md C9: own_height is ordinal, not a chain count.
//! use shekyl_p_serve::anchor_within_gate;
//! use shekyl_types::{BlockHeight, ChainCount};
//! let _ = anchor_within_gate(ChainCount::from_raw(10_000), BlockHeight::from_raw(9_280));
//! ```

use shekyl_archival_retention::pass_anchor::{
    PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_LAG_BLOCKS, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
};
use shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_crypto_pq::CryptoError;
use shekyl_types::BlockHeight;

/// Width of the envelope the **bond identity key** closes a response with:
/// the canonical encoding of a hybrid scheme-1 signature (Ed25519 +
/// ML-DSA-65), and nothing else. 3,385 bytes. The live width.
///
/// The envelope is last so that holding it means the whole body was
/// delivered.
pub const IDENTITY_ENVELOPE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// Width of the envelope a persona's **receipt key** closes a response
/// with: the canonical encoding of a hybrid scheme-3 signature (Ed25519 +
/// FN-DSA-1024). 1,356 bytes. STAGED: no production endpoint is bound at
/// this width (`FN_DSA_HYBRID.md` §9).
pub const RECEIPT_ENVELOPE_LEN: usize = FnDsaHybridSignature::CANONICAL_LEN;

mod sealed {
    pub trait Sealed<const W: usize> {}
}

/// The countersignature envelope, as a type to hang its widths on. Never
/// constructed.
pub enum PassEnvelope {}

/// "The pass envelope can be `W` bytes wide": `W` is the canonical length
/// of one hybrid scheme's signature, and [`Self::Signature`] is that
/// scheme's signature type.
///
/// Sealed, with one implementation per scheme, each written with the
/// signature type's own `CANONICAL_LEN` as `W`. So a width is a scheme and
/// a scheme is a width: there is no way to state a `W` with another
/// scheme's signature type, and no `W` but these two. Were the two schemes'
/// signatures ever the same length, the two implementations would overlap
/// and this crate would not compile, which is the right outcome: the width
/// alone could then no longer tell a reader which scheme it holds.
pub trait EnvelopeWidth<const W: usize>: sealed::Sealed<W> {
    /// The signature that fills a `W`-byte envelope.
    type Signature: Send + 'static;

    /// `signature`'s canonical encoding, as the envelope. `None` if the
    /// encoding fails or is not exactly `W` bytes, so that a short or long
    /// envelope cannot reach the wire.
    fn envelope(signature: &Self::Signature) -> Option<[u8; W]>;
}

impl sealed::Sealed<IDENTITY_ENVELOPE_LEN> for PassEnvelope {}
impl EnvelopeWidth<IDENTITY_ENVELOPE_LEN> for PassEnvelope {
    type Signature = HybridSignature;

    fn envelope(signature: &HybridSignature) -> Option<[u8; IDENTITY_ENVELOPE_LEN]> {
        signature.to_canonical_bytes().ok()?.try_into().ok()
    }
}

impl sealed::Sealed<RECEIPT_ENVELOPE_LEN> for PassEnvelope {}
impl EnvelopeWidth<RECEIPT_ENVELOPE_LEN> for PassEnvelope {
    type Signature = FnDsaHybridSignature;

    fn envelope(signature: &FnDsaHybridSignature) -> Option<[u8; RECEIPT_ENVELOPE_LEN]> {
        signature.to_canonical_bytes().try_into().ok()
    }
}

/// The signature a `W`-byte envelope carries.
pub type EnvelopeSignature<const W: usize> = <PassEnvelope as EnvelopeWidth<W>>::Signature;

/// A [`PassKey`] of the live scheme: the bond identity key's.
pub type IdentityPassKey = dyn PassKey<IDENTITY_ENVELOPE_LEN>;

/// A [`PassSigner`] of the live scheme: the bond identity key's.
pub type IdentityPassSigner = dyn PassSigner<IDENTITY_ENVELOPE_LEN>;

/// Where the persona's attestation signing key lives.
///
/// One method, synchronous, called from the serve loop's blocking pool
/// once per shard the persona is about to serve. Implementors sign with
/// [`sign_pass_transcript`] so the domain cannot drift from what the
/// daemon's `verify_pass_transcript` checks.
///
/// The host supplies this; the serve loop never sees the secret. Height
/// for the pre-sign gate is [`PassSigner::own_height`] — a signer is a
/// key plus a height source, not a second `sign_pass`.
///
/// `W` is the width of the envelope this key's signature fills, and so the
/// scheme it signs with ([`EnvelopeWidth`]).
pub trait PassKey<const W: usize>: Send + Sync
where
    PassEnvelope: EnvelopeWidth<W>,
{
    /// Whether this key will sign a pass for `shard_id` at `anchor_height`.
    ///
    /// Asked once per request, after the shard is opened and before the
    /// first response byte, so it must be cheap and must not sign. An
    /// `Err` means the answer is already known — no key is resident, or
    /// the host will not sign for this shard — and the serve loop answers
    /// the bare 503 without sending a shard it could not countersign.
    /// `Ok` is not a promise: a signer can still fail at
    /// [`Self::sign_pass`], after the body, and that is the refusal
    /// trailer. The two arguments are what the key may decide on; the
    /// request's nonce and anchor hash are not offered, because nothing a
    /// key refuses by policy depends on them.
    ///
    /// **No default, on purpose.** A default of "yes" would let a new
    /// implementor that forgets this method stream whole shards it cannot
    /// sign — honest bandwidth spent on responses that all end in the
    /// refusal trailer — with nothing in the type system to say so. Every
    /// key states its answer.
    ///
    /// # Errors
    ///
    /// Returns [`SignRefused`] when the key will not sign. Counted in
    /// `sign_failure_count`.
    fn ready(&self, shard_id: u64, anchor_height: BlockHeight) -> Result<(), SignRefused>;

    /// Sign the 112-byte SF-D8 transcript with this key's scheme, under
    /// that scheme's domain for it (the attestation domain for the identity
    /// key, the receipt domain for the receipt key).
    ///
    /// # Errors
    ///
    /// Returns [`SignRefused`] when the signer fails after [`Self::ready`]
    /// said yes — it went offline, or the signature could not be made. The
    /// serve loop asks only after the body is out, so it closes the
    /// response with the refusal trailer in place of the signature and
    /// counts it in `late_sign_failure_count`. That is apart from
    /// `sign_failure_count` (a pre-flight refusal: the 503, no shard sent)
    /// and from `lookup_failure_count` (store-read faults), so an operator
    /// can tell "signer failed with the shard already sent" from "key not
    /// available" and from "store not readable". An ordinary miss — a
    /// shard the persona does not hold — is counted by none of them.
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<EnvelopeSignature<W>, SignRefused>;
}

/// The persona's signing seam, supplied by the host at [`bind`]: a
/// [`PassKey`] plus the height the pre-sign gate runs against.
///
/// Both methods are synchronous and are called from the serve loop's
/// blocking pool, never on an executor thread: `own_height` may be a
/// bounded store read (a host that stamps an atomic is also fine), and
/// `sign_pass` is one hybrid sign.
///
/// [`bind`]: crate::PServeEndpoint::bind
pub trait PassSigner<const W: usize>: PassKey<W>
where
    PassEnvelope: EnvelopeWidth<W>,
{
    /// The persona's current chain height, for the SF-D5 anchor gate. A
    /// value within `L` of true is sufficient.
    ///
    /// `None` means the height could not be read — the serving store is
    /// unreadable, or whatever the host reads it from is gone. The serve
    /// loop renders the 503 and counts a **lookup failure**
    /// (the same bucket as a store read that fails on the shard itself),
    /// so a host that has lost its store is visible in the aggregate
    /// rather than refusing every anchor silently. A fresh store at
    /// height `0` is `Some(0)`, not `None`: readable, and below the gate.
    fn own_height(&self) -> Option<BlockHeight>;
}

/// A host's refusal to sign. The detail is operator-facing, never sent on
/// the wire (the client sees a bare 404).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRefused {
    pub detail: String,
}

impl SignRefused {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for SignRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "pass countersignature refused: {}", self.detail)
    }
}

impl std::error::Error for SignRefused {}

/// Sign an SF-D8 transcript under `SCHEME_DOMAIN_ATTESTATION`.
///
/// This is the only signing call in the serving stack; keeping the domain
/// here means a `PassSigner` implementation cannot drift from what
/// `verify_pass_transcript` checks.
///
/// # Errors
///
/// Propagates the underlying scheme's failure (malformed key material).
pub fn sign_pass_transcript(
    secret: &HybridSecretKey,
    message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
) -> Result<HybridSignature, CryptoError> {
    HybridEd25519MlDsa.sign(secret, SCHEME_DOMAIN_ATTESTATION, message)
}

/// The SF-D5 pre-sign gate: `anchor_height ∈ [p − 720 − L, p − 720 + L]`
/// for the persona's own height `p`.
///
/// Two-sided with the same `L` as admission so a `P` one block behind does
/// not refuse the network and no `P` gates distinctively. A persona whose
/// own height is below the anchor depth has no admissible anchor at all
/// and refuses everything — nobody can have anchored at `tip − 720` yet.
#[must_use]
pub fn anchor_within_gate(own_height: BlockHeight, anchor_height: BlockHeight) -> bool {
    let Some(centre) = own_height.checked_sub_count(PASS_ANCHOR_DEPTH_BLOCKS) else {
        return false;
    };
    let lo = centre.saturating_sub_count(PASS_ANCHOR_LAG_BLOCKS);
    let hi = centre.saturating_add(PASS_ANCHOR_LAG_BLOCKS);
    (lo..=hi).contains(&anchor_height)
}

/// A `PassSigner` over an ephemeral, non-derived keypair, for tests.
///
/// Armed explicitly by the test that needs it: construct with
/// [`TestKeySigner::ephemeral`], read the public key with
/// [`TestKeySigner::public_key`] to hand to the client under test, move the
/// height with [`TestKeySigner::set_height`]. Nothing here is derived from
/// a wallet seed and nothing here may reach a bonded persona — the cfg
/// gate is the only reason the type compiles, and
/// `scripts/ci/check_p_fetch_dep_cut.py` asserts the `test-signer` feature
/// is unreachable from every production graph.
#[cfg(any(test, feature = "test-signer"))]
pub struct TestKeySigner {
    secret: HybridSecretKey,
    public: shekyl_crypto_pq::signature::HybridPublicKey,
    height: std::sync::atomic::AtomicU64,
}

#[cfg(any(test, feature = "test-signer"))]
impl TestKeySigner {
    /// A fresh random keypair at `height`.
    ///
    /// # Panics
    ///
    /// Only if the underlying keygen fails, which is a broken crypto
    /// backend, not a test condition.
    #[must_use]
    pub fn ephemeral(height: BlockHeight) -> Self {
        let (public, secret) = HybridEd25519MlDsa
            .generate_ephemeral_keypair_for_tests()
            .expect("ephemeral hybrid keygen");
        Self {
            secret,
            public,
            height: std::sync::atomic::AtomicU64::new(height.to_raw()),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> &shekyl_crypto_pq::signature::HybridPublicKey {
        &self.public
    }

    pub fn set_height(&self, height: BlockHeight) {
        self.height
            .store(height.to_raw(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassKey<IDENTITY_ENVELOPE_LEN> for TestKeySigner {
    /// The ephemeral key is always resident and signs for any shard.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        sign_pass_transcript(&self.secret, message).map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassSigner<IDENTITY_ENVELOPE_LEN> for TestKeySigner {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(
            self.height.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }
}

/// A `PassSigner` at the **receipt** width over an ephemeral scheme-3
/// keypair, for tests: the staged scheme's counterpart of
/// [`TestKeySigner`], under the same `test-signer` gate and the same rule —
/// nothing here is derived from a wallet seed and nothing here may reach a
/// bonded persona.
///
/// It exists so that the serve loop and the fetch client can be exercised
/// at the second width, each against the other and against the first:
/// that is how "a target is one scheme" is tested from both ends.
#[cfg(any(test, feature = "test-signer"))]
pub struct TestReceiptKeySigner {
    secret: shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSecretKey,
    public: shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey,
    height: std::sync::atomic::AtomicU64,
}

#[cfg(any(test, feature = "test-signer"))]
impl TestReceiptKeySigner {
    /// A fresh random scheme-3 keypair at `height`.
    ///
    /// # Panics
    ///
    /// Only if the OS RNG fails, which is a broken host, not a test
    /// condition.
    #[must_use]
    pub fn ephemeral(height: BlockHeight) -> Self {
        let (public, secret) =
            shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa::generate_keypair()
                .expect("ephemeral scheme-3 keygen");
        Self {
            secret,
            public,
            height: std::sync::atomic::AtomicU64::new(height.to_raw()),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> &shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey {
        &self.public
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassKey<RECEIPT_ENVELOPE_LEN> for TestReceiptKeySigner {
    /// The ephemeral key is always resident and signs for any shard.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        shekyl_crypto_pq::fn_dsa_hybrid::HybridEd25519FnDsa
            .sign(
                &self.secret,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_RECEIPT,
                message,
            )
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassSigner<RECEIPT_ENVELOPE_LEN> for TestReceiptKeySigner {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(
            self.height.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::{verify_pass_transcript, PassRequestHeader};

    const DEPTH: u64 = PASS_ANCHOR_DEPTH_BLOCKS.to_raw();
    const L: u64 = PASS_ANCHOR_LAG_BLOCKS.to_raw();

    const fn bh(n: u64) -> BlockHeight {
        BlockHeight::from_raw(n)
    }

    #[test]
    fn gate_is_two_sided_and_inclusive_around_p_minus_depth() {
        let p = 10_000;
        let c = p - DEPTH;
        assert!(anchor_within_gate(bh(p), bh(c)));
        assert!(anchor_within_gate(bh(p), bh(c - L)));
        assert!(anchor_within_gate(bh(p), bh(c + L)));
        assert!(!anchor_within_gate(bh(p), bh(c - L - 1)));
        assert!(!anchor_within_gate(bh(p), bh(c + L + 1)));
    }

    #[test]
    fn gate_refuses_everything_below_the_anchor_depth() {
        assert!(!anchor_within_gate(bh(DEPTH - 1), bh(0)));
        assert!(!anchor_within_gate(bh(0), bh(0)));
        // Exactly at depth: centre is 0, lower bound saturates.
        assert!(anchor_within_gate(bh(DEPTH), bh(0)));
        assert!(anchor_within_gate(bh(DEPTH), bh(L)));
        assert!(!anchor_within_gate(bh(DEPTH), bh(L + 1)));
        // No wrap at the top.
        assert!(anchor_within_gate(bh(u64::MAX), bh(u64::MAX - DEPTH)));
    }

    #[test]
    fn test_key_signer_round_trips_through_the_consensus_verifier() {
        let signer = TestKeySigner::ephemeral(bh(DEPTH + 50));
        let f = PassRequestHeader::from_parts([7; 32], bh(49), [8; 32]);
        let digest = [9u8; 32];
        let sig = signer.sign_pass(&f.transcript(7, &digest)).expect("sign");
        assert_eq!(
            sig.to_canonical_bytes().unwrap().len(),
            IDENTITY_ENVELOPE_LEN
        );
        let ok = verify_pass_transcript(
            signer.public_key(),
            f.nonce(),
            f.anchor_height(),
            f.anchor_hash(),
            7,
            &digest,
            &sig,
        );
        assert!(ok.is_ok());
        // The delivery digest is bound: another digest does not verify.
        assert!(verify_pass_transcript(
            signer.public_key(),
            f.nonce(),
            f.anchor_height(),
            f.anchor_hash(),
            7,
            &[10u8; 32],
            &sig,
        )
        .is_err());
        // Shard id is bound: a neighbouring id does not verify.
        let bad = verify_pass_transcript(
            signer.public_key(),
            f.nonce(),
            f.anchor_height(),
            f.anchor_hash(),
            8,
            &digest,
            &sig,
        );
        assert!(bad.is_err());
    }
}
