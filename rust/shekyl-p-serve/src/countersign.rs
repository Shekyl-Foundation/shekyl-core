// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The serve side of the SF-D8 pass receipt.
//!
//! A `P` answering a shard request binds the daemon's 73-byte request
//! header, the shard id and a nonce-salted digest of the response it
//! delivers with its **receipt key** (Ed25519 + FN-DSA-1024, hybrid scheme
//! 3) under `SCHEME_DOMAIN_RECEIPT`; the requester verifies that binding
//! against the `receipt_sign_pk` it holds from the bond record. The
//! transcript both ends agree on —
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8] ‖ delivery_digest[32]` —
//! the digest construction and the anchor-gate constants are consensus
//! values owned by `shekyl_archival_retention::pass_anchor`; this module
//! only pairs them with a signer.
//!
//! The receipt closes the response as a fixed-width envelope of
//! [`RECEIPT_ENVELOPE_LEN`] bytes, the canonical length of a scheme-3
//! signature. The envelope is last so that holding it means the whole body
//! was delivered.
//!
//! ## Who holds the key
//!
//! This crate holds none. [`PassSigner`] is the seam: the host supplies an
//! object that knows the persona's current height (for the anchor gate)
//! and can produce a receipt over the transcript. Where that object's
//! secret lives is the host's design — the stake actor's held receipt key
//! for the bonded persona, an ephemeral keypair for tests via
//! `TestReceiptKeySigner` (armed by the `test-signer` feature) — and the
//! serve loop never sees more than the returned signature.
//!
//! [`sign_receipt_transcript`] pairs a transcript with the receipt domain,
//! and is the only signing call for it. Implementors call it rather than
//! the scheme's `sign`, so a host cannot bind the transcript under a
//! neighbouring domain.
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
    PassTranscript, PASS_ANCHOR_DEPTH_BLOCKS, PASS_ANCHOR_LAG_BLOCKS,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{FnDsaHybridSignature, FnDsaHybridSigner};
use shekyl_crypto_pq::signature::SCHEME_DOMAIN_RECEIPT;
use shekyl_crypto_pq::CryptoError;
use shekyl_types::BlockHeight;

/// Width of the envelope a persona's **receipt key** closes a response
/// with: the canonical encoding of a hybrid scheme-3 signature (Ed25519 +
/// FN-DSA-1024). 1,356 bytes.
pub const RECEIPT_ENVELOPE_LEN: usize = FnDsaHybridSignature::CANONICAL_LEN;

/// `signature`'s canonical encoding, as the envelope. `None` if it is not
/// exactly [`RECEIPT_ENVELOPE_LEN`] bytes, so that a short or long envelope
/// cannot reach the wire.
#[must_use]
pub(crate) fn envelope(signature: &FnDsaHybridSignature) -> Option<[u8; RECEIPT_ENVELOPE_LEN]> {
    signature.to_canonical_bytes().try_into().ok()
}

/// Where the persona's receipt key lives.
///
/// Called from the serve loop's blocking pool once per shard the persona
/// is about to serve. Implementors sign through
/// [`sign_receipt_transcript`], so the domain cannot drift from the
/// verifier that checks it.
///
/// The host supplies this; the serve loop never sees the secret. Height
/// for the pre-sign gate is [`PassSigner::own_height`] — a signer is a
/// key plus a height source, not a second `sign_pass`.
pub trait PassKey: Send + Sync {
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

    /// Sign the SF-D8 transcript with the receipt key, under the receipt
    /// domain. The signature covers [`PassTranscript::message`].
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
    fn sign_pass(&self, transcript: &PassTranscript) -> Result<FnDsaHybridSignature, SignRefused>;
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

/// Sign an SF-D8 transcript under `SCHEME_DOMAIN_RECEIPT`.
///
/// The only place a pass transcript is paired with that domain
/// (`FN_DSA_HYBRID.md` §9). Its non-test caller is the stake actor's held
/// receipt key (`shekyl-engine-core`, `HeldPersona::sign_receipt_transcript`),
/// which the serving task's receipt capability asks to sign.
/// `TestReceiptKeySigner` is the other caller, behind `test-signer`.
///
/// # Errors
///
/// Propagates the held signer's failure: the scheme's signer gave up, or
/// the domain was refused. A key that does not decode never reaches here;
/// the signer is built from a decoded key.
pub fn sign_receipt_transcript(
    signer: &mut FnDsaHybridSigner,
    transcript: &PassTranscript,
) -> Result<FnDsaHybridSignature, CryptoError> {
    signer.sign(SCHEME_DOMAIN_RECEIPT, &transcript.message())
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

/// A `PassSigner` over an ephemeral scheme-3 keypair, for tests.
///
/// Armed explicitly by the test that needs it: construct with
/// [`TestReceiptKeySigner::ephemeral`], read the public key with
/// [`TestReceiptKeySigner::public_key`] to hand to the client under test,
/// move the height with [`TestReceiptKeySigner::set_height`]. Nothing here
/// is derived from a wallet seed and nothing here may reach a bonded
/// persona — the cfg gate is the only reason the type compiles, and
/// `scripts/ci/check_p_fetch_dep_cut.py` asserts the `test-signer` feature
/// is unreachable from every production graph.
#[cfg(any(test, feature = "test-signer"))]
pub struct TestReceiptKeySigner {
    /// Interior mutability: [`PassKey::sign_pass`] takes `&self`, and the
    /// held signer signs through `&mut self` because its working buffers
    /// live in the decoded key. A poisoned lock is recovered: the signer
    /// holds no invariant a panic could have broken mid-update.
    signer: std::sync::Mutex<FnDsaHybridSigner>,
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
        let signer = FnDsaHybridSigner::new(&secret).expect("a generated scheme-3 key decodes");
        // The encoded secret's only job was the decode. The signer holds
        // the key; dropping the encoding wipes it.
        drop(secret);
        Self {
            signer: std::sync::Mutex::new(signer),
            public,
            height: std::sync::atomic::AtomicU64::new(height.to_raw()),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> &shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey {
        &self.public
    }

    pub fn set_height(&self, height: BlockHeight) {
        self.height
            .store(height.to_raw(), std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassKey for TestReceiptKeySigner {
    /// The ephemeral key is always resident and signs for any shard.
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(
        &self,
        message: &crate::PassTranscript,
    ) -> Result<FnDsaHybridSignature, SignRefused> {
        let mut signer = self
            .signer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sign_receipt_transcript(&mut signer, message).map_err(|e| SignRefused::new(e.to_string()))
    }
}

#[cfg(any(test, feature = "test-signer"))]
impl PassSigner for TestReceiptKeySigner {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(
            self.height.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_archival_retention::{verify_receipt_transcript, PassRequestHeader};

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
        let signer = TestReceiptKeySigner::ephemeral(bh(DEPTH + 50));
        let f = PassRequestHeader::from_parts(
            shekyl_archival_retention::PassStream::Economy,
            [7; 32],
            bh(49),
            shekyl_types::BlockHash::from_bytes([8; 32]),
        );
        let digest = [9u8; 32];
        let sig = signer.sign_pass(&f.transcript(7, digest)).expect("sign");
        assert_eq!(sig.to_canonical_bytes().len(), RECEIPT_ENVELOPE_LEN);
        let ok = verify_receipt_transcript(signer.public_key(), &f.transcript(7, digest), &sig);
        assert!(ok.is_ok());
        // The delivery digest is bound: another digest does not verify.
        assert!(
            verify_receipt_transcript(signer.public_key(), &f.transcript(7, [10u8; 32]), &sig)
                .is_err()
        );
        // Shard id is bound: a neighbouring id does not verify.
        let bad = verify_receipt_transcript(signer.public_key(), &f.transcript(8, digest), &sig);
        assert!(bad.is_err());
    }
}
