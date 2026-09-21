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
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, HybridSignature, SignatureScheme,
    SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_crypto_pq::CryptoError;
use shekyl_types::BlockHeight;

/// Length of the countersignature envelope that precedes the frame on the
/// wire: the canonical `HybridSignature` encoding, and nothing else.
pub const SIGNATURE_ENVELOPE_LEN: usize = HybridSignature::CANONICAL_LEN;

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
pub trait PassKey: Send + Sync {
    /// Sign the 80-byte SF-D8 transcript under the attestation domain.
    ///
    /// # Errors
    ///
    /// Returns [`SignRefused`] when the host cannot sign — key not
    /// resident, signer offline, or a host-side policy refusal. The serve
    /// loop turns this into the identical 404 and counts it in
    /// `sign_failure_count`, separately from `lookup_failure_count`
    /// (store-read faults), so an operator can tell "key not available"
    /// from "store not readable". An ordinary miss — a shard the persona
    /// does not hold — is counted by neither.
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused>;
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
pub trait PassSigner: PassKey {
    /// The persona's current chain height, for the SF-D5 anchor gate. A
    /// value within `L` of true is sufficient.
    ///
    /// `None` means the height could not be read — the serving store is
    /// unreadable, or whatever the host reads it from is gone. The serve
    /// loop renders the identical 404 and counts a **lookup failure**
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
impl PassKey for TestKeySigner {
    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        sign_pass_transcript(&self.secret, message).map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassSigner for TestKeySigner {
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
        let sig = signer.sign_pass(&f.transcript(7)).expect("sign");
        assert_eq!(
            sig.to_canonical_bytes().unwrap().len(),
            SIGNATURE_ENVELOPE_LEN
        );
        let ok = verify_pass_transcript(
            signer.public_key(),
            f.nonce(),
            f.anchor_height(),
            f.anchor_hash(),
            7,
            &sig,
        );
        assert!(ok.is_ok());
        // Shard id is bound: a neighbouring id does not verify.
        let bad = verify_pass_transcript(
            signer.public_key(),
            f.nonce(),
            f.anchor_height(),
            f.anchor_hash(),
            8,
            &sig,
        );
        assert!(bad.is_err());
    }
}
