// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve side of the SF-D8 pass countersignature.
//!
//! A `P` answering a shard request binds the daemon's 72-byte request
//! header and the shard id under `SCHEME_DOMAIN_ATTESTATION`; the daemon
//! verifies that binding against the `P` public key it already holds from
//! the bond record. The transcript both ends agree on —
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8]` —
//! and the anchor-gate constants are consensus values owned by
//! `shekyl_archival_retention::pass_anchor`; this module only pairs them
//! with a signer.
//!
//! ## Who holds the key
//!
//! This crate holds none. [`PassSigner`] is the seam: the host supplies an
//! object that knows the persona's current height (for the anchor gate)
//! and can produce a `HybridSignature` over the transcript. Where that
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

use shekyl_archival_retention::pass_anchor::{
    pass_countersignature_message, PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_HASH_LEN,
    PASS_ANCHOR_HEIGHT_LEN, PASS_ANCHOR_LAG_BLOCKS, PASS_COUNTERSIGNATURE_MESSAGE_LEN,
    PASS_NONCE_LEN, PASS_REQUEST_HEADER_LEN,
};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_crypto_pq::CryptoError;

/// Length of the countersignature envelope that precedes the frame on the
/// wire: the canonical `HybridSignature` encoding, and nothing else.
pub const SIGNATURE_ENVELOPE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// The persona's signing seam, supplied by the host at [`bind`].
///
/// Both methods are synchronous and are called from the serve loop's
/// blocking pool, never on an executor thread: `own_height` may be a
/// bounded store read (a host that stamps an atomic is also fine), and
/// `sign_pass` is one hybrid sign.
///
/// [`bind`]: crate::PServeEndpoint::bind
pub trait PassSigner: Send + Sync {
    /// The persona's current chain height, for the SF-D5 anchor gate. A
    /// value within `L` of true is sufficient. A host that cannot read
    /// its height returns `0`, which refuses every anchor — fail closed.
    fn own_height(&self) -> u64;

    /// Sign the 80-byte SF-D8 transcript under the attestation domain.
    /// Implementors build the signature via [`sign_pass_transcript`].
    ///
    /// # Errors
    ///
    /// Returns [`SignRefused`] when the host cannot sign — key not
    /// resident, signer offline, or a host-side policy refusal. The serve
    /// loop turns this into the identical 404 and counts it separately
    /// from lookup failures so an operator can tell "shard not held" from
    /// "key not available".
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused>;
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

/// The decoded 72-byte request header, split into its three fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHeaderFields {
    pub nonce: [u8; PASS_NONCE_LEN],
    pub anchor_height: u64,
    pub anchor_hash: [u8; PASS_ANCHOR_HASH_LEN],
}

impl RequestHeaderFields {
    /// Split the decoded header. Infallible: the length is in the type.
    #[must_use]
    pub fn from_header(header: &[u8; PASS_REQUEST_HEADER_LEN]) -> Self {
        const HEIGHT_END: usize = PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN;
        let mut nonce = [0u8; PASS_NONCE_LEN];
        nonce.copy_from_slice(&header[..PASS_NONCE_LEN]);
        let mut height_le = [0u8; PASS_ANCHOR_HEIGHT_LEN];
        height_le.copy_from_slice(&header[PASS_NONCE_LEN..HEIGHT_END]);
        let mut anchor_hash = [0u8; PASS_ANCHOR_HASH_LEN];
        anchor_hash.copy_from_slice(&header[HEIGHT_END..]);
        Self {
            nonce,
            anchor_height: u64::from_le_bytes(height_le),
            anchor_hash,
        }
    }

    /// The SF-D8 transcript for this header and `shard_id`.
    #[must_use]
    pub fn transcript(&self, shard_id: u64) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&self.nonce, self.anchor_height, &self.anchor_hash, shard_id)
    }
}

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
pub fn anchor_within_gate(own_height: u64, anchor_height: u64) -> bool {
    let Some(centre) = own_height.checked_sub(PASS_ANCHOR_DEPTH_BLOCKS) else {
        return false;
    };
    let lo = centre.saturating_sub(PASS_ANCHOR_LAG_BLOCKS);
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
    pub fn ephemeral(height: u64) -> Self {
        let (public, secret) = HybridEd25519MlDsa
            .generate_ephemeral_keypair_for_tests()
            .expect("ephemeral hybrid keygen");
        Self {
            secret,
            public,
            height: std::sync::atomic::AtomicU64::new(height),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> &shekyl_crypto_pq::signature::HybridPublicKey {
        &self.public
    }

    pub fn set_height(&self, height: u64) {
        self.height
            .store(height, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassSigner for TestKeySigner {
    fn own_height(&self) -> u64 {
        self.height.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        sign_pass_transcript(&self.secret, message).map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::pass_anchor::pass_request_header_bytes;
    use shekyl_archival_retention::verify_pass_transcript;

    const DEPTH: u64 = PASS_ANCHOR_DEPTH_BLOCKS;
    const L: u64 = PASS_ANCHOR_LAG_BLOCKS;

    #[test]
    fn gate_is_two_sided_and_inclusive_around_p_minus_depth() {
        let p = 10_000;
        let c = p - DEPTH;
        assert!(anchor_within_gate(p, c));
        assert!(anchor_within_gate(p, c - L));
        assert!(anchor_within_gate(p, c + L));
        assert!(!anchor_within_gate(p, c - L - 1));
        assert!(!anchor_within_gate(p, c + L + 1));
    }

    #[test]
    fn gate_refuses_everything_below_the_anchor_depth() {
        assert!(!anchor_within_gate(DEPTH - 1, 0));
        assert!(!anchor_within_gate(0, 0));
        // Exactly at depth: centre is 0, lower bound saturates.
        assert!(anchor_within_gate(DEPTH, 0));
        assert!(anchor_within_gate(DEPTH, L));
        assert!(!anchor_within_gate(DEPTH, L + 1));
        // No wrap at the top.
        assert!(anchor_within_gate(u64::MAX, u64::MAX - DEPTH));
    }

    #[test]
    fn header_fields_split_and_rejoin() {
        let h = pass_request_header_bytes(&[0x11; 32], 0x0102_0304_0506_0708, &[0x22; 32]);
        let f = RequestHeaderFields::from_header(&h);
        assert_eq!(f.nonce, [0x11; 32]);
        assert_eq!(f.anchor_height, 0x0102_0304_0506_0708);
        assert_eq!(f.anchor_hash, [0x22; 32]);
        assert_eq!(
            f.transcript(9),
            pass_countersignature_message(&[0x11; 32], 0x0102_0304_0506_0708, &[0x22; 32], 9)
        );
    }

    #[test]
    fn test_key_signer_round_trips_through_the_consensus_verifier() {
        let signer = TestKeySigner::ephemeral(DEPTH + 50);
        let f = RequestHeaderFields {
            nonce: [7; 32],
            anchor_height: 49,
            anchor_hash: [8; 32],
        };
        let sig = signer.sign_pass(&f.transcript(7)).expect("sign");
        assert_eq!(
            sig.to_canonical_bytes().unwrap().len(),
            SIGNATURE_ENVELOPE_LEN
        );
        let ok = verify_pass_transcript(
            signer.public_key(),
            &f.nonce,
            f.anchor_height,
            &f.anchor_hash,
            7,
            &sig,
        );
        assert!(ok.is_ok());
        // Shard id is bound: a neighbouring id does not verify.
        let bad = verify_pass_transcript(
            signer.public_key(),
            &f.nonce,
            f.anchor_height,
            &f.anchor_hash,
            8,
            &sig,
        );
        assert!(bad.is_err());
    }
}
