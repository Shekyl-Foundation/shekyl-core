// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The derived-weight batch verify: the one Bulletproof+ verify a Shekyl
//! validator calls (CEN-H19's verification half; ruling R3, 2026-10-15).
//!
//! # What is derived, and from what
//!
//! A batch verify folds every proof's verification equation into one
//! multiscalar multiplication, each scaled by a per-proof weight, and checks
//! the sum is the identity. The weights must be unpredictable to whoever
//! chose the proofs, or a forger could pick two invalid proofs whose errors
//! cancel under them. Upstream draws them from the caller's RNG (`OsRng`),
//! which makes the verdict a property of one node's entropy, not of the
//! bytes.
//!
//! Here the weights are a pure function of the batch. The seed is
//! `cSHAKE256(`[`BATCH_WEIGHTS_CUSTOMIZATION`]`, preimage)[..32]` over the
//! canonical encoding of every `(proof, commitments)` pair in batch order
//! ([`batch_weights_seed`] states the encoding), and the weights are the
//! draws of a [`ChaCha20Rng`] seeded with it. The vendored verifier consumes
//! the RNG exactly once per proof, for that proof's weight
//! (`plus/weighted_inner_product.rs`, `verifier_weight`, drawn before the
//! proof's sanity checks so draw `k` is always proof `k`'s); nothing else in
//! the verify path reads it. That is the premise R3 rests on, and the test
//! `the_rng_feeds_one_weight_per_proof_and_nothing_else` holds it.
//!
//! # Why a producer who knows the weights cannot use them
//!
//! The block's producer knows every weight before anyone verifies, because
//! the producer built the batch. Knowing them does not help: the seed commits to every
//! value the batch equation reads — each proof's bytes and each commitment
//! as carried — so changing any proof or commitment re-derives every weight.
//! For an invalid batch to pass, the derived weights must cancel the invalid
//! proofs' error terms; for fixed bytes that happens with probability about
//! `1/ℓ`, and each new attempt is a fresh cSHAKE output. Grinding is
//! therefore an `ℓ ≈ 2^252` search. This is the same Fiat–Shamir argument
//! each proof's own challenges rest on (the transcript in `plus/transcript.rs`
//! is a hash of the statement for the same reason).
//!
//! # The batch is whatever the caller passes, and nothing smaller
//!
//! [`verify_batch`] derives its seed from the slice it is given and from
//! nothing else. A validator passes the whole block (`shekyl-chain-rules`'
//! H19 fold); the submit engine passes one transaction. A subset is never
//! verified under a larger batch's seed: the only way to verify part of a
//! batch is to call [`verify_batch`] on that part, which derives that part's
//! own seed. The locus search after a failed block batch does exactly that,
//! one proof at a time.

use std_shims::vec::Vec;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use shekyl_curve_io::CompressedPoint;

use crate::{batch_verifier::BatchVerifier, Bulletproof};

/// The cSHAKE256 customization for the batch weights' seed (ruling R3).
///
/// Registered in `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv` (mechanism 1). A
/// change to [`batch_weights_seed`]'s preimage is a new domain (`-v2`), not a
/// reinterpretation of this one.
pub const BATCH_WEIGHTS_CUSTOMIZATION: &[u8] = b"shekyl/bp-plus-batch-weights-v1";

/// One proof and the commitments it proves in range, as the verifier reads
/// them: the commitments are the transaction's output commitments as carried
/// (`outPk` masks), from which the statement reconstructs `V = C·8⁻¹`.
#[derive(Clone, Copy, Debug)]
pub struct BatchEntry<'a> {
    /// The aggregate range proof.
    pub proof: &'a Bulletproof,
    /// The commitments it covers, in output order.
    pub commitments: &'a [CompressedPoint],
}

/// The seed the batch's weights are drawn from.
///
/// `cSHAKE256(BATCH_WEIGHTS_CUSTOMIZATION, preimage)[..32]`, where
///
/// ```text
/// preimage = n_le4 ‖ entry_1 ‖ … ‖ entry_n
/// entry    = len_le4(proof) ‖ proof ‖ m_le4 ‖ C_1 ‖ … ‖ C_m
/// ```
///
/// `proof` is [`Bulletproof::serialize`] — the wire `BpPlus` bytes,
/// `A ‖ A1 ‖ B ‖ r1 ‖ s1 ‖ d1 ‖ vec(L) ‖ vec(R)` — and `C_i` are the 32-byte
/// commitments in order. Every count and length is framed, so the encoding
/// is injective over batches, and it covers every value the batch equation
/// reads: the generators are fixed, and the transcript is a function of the
/// proof and the commitments.
///
/// # Panics
///
/// If a count or length exceeds `u32::MAX`. A proof is under a kilobyte and
/// a batch is bounded by a block, so neither is reachable.
#[must_use]
pub fn batch_weights_seed(batch: &[BatchEntry<'_>]) -> [u8; 32] {
    let le4 = |n: usize| {
        u32::try_from(n)
            .expect("a batch count fits in u32")
            .to_le_bytes()
    };
    let mut preimage = Vec::with_capacity(4 + batch.len() * 1024);
    preimage.extend_from_slice(&le4(batch.len()));
    for entry in batch {
        let proof = entry.proof.serialize();
        preimage.extend_from_slice(&le4(proof.len()));
        preimage.extend_from_slice(&proof);
        preimage.extend_from_slice(&le4(entry.commitments.len()));
        for commitment in entry.commitments {
            preimage.extend_from_slice(&commitment.to_bytes());
        }
    }
    shekyl_crypto_hash::cshake256_32(BATCH_WEIGHTS_CUSTOMIZATION, &preimage)
}

/// Verify every proof in `batch` with one multiscalar multiplication, under
/// weights derived from the batch itself ([`batch_weights_seed`]).
///
/// `true` iff every proof is well-formed and verifies, except with
/// probability about `1/ℓ` per batch (the module docs). The seed is computed
/// over the whole batch before the first proof is accumulated. An empty batch
/// is `true`.
#[must_use]
pub fn verify_batch(batch: &[BatchEntry<'_>]) -> bool {
    let mut rng = ChaCha20Rng::from_seed(batch_weights_seed(batch));
    let mut verifier = BatchVerifier::new();
    for entry in batch {
        // `false` is a proof that is not sane (a point that does not
        // decompress, a commitment count the statement refuses, an L/R
        // length the generators do not fit); the verifier is then in an
        // undefined state and must not be run.
        if !entry
            .proof
            .batch_verify(&mut rng, &mut verifier, entry.commitments)
        {
            return false;
        }
    }
    verifier.verify()
}
