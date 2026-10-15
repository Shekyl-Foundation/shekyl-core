// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The batch weights of an FCMP++ verify, derived from the statement
//! (ruling R3, 2026-10-15).
//!
//! [`crate::proof::verify`] and [`crate::proof::verify_membership_only`] are
//! the two callers. Each builds one [`BatchWeights`] and draws every batch
//! verifier's weights from its [`BatchWeights::rng`], before any statement
//! is queued.
//!
//! The vendored verifiers read their RNG only for batch weights — one per
//! statement queued on the Ed25519 verifier (`multiexp::BatchVerifier::queue`:
//! four per input in the SAL, one in the membership-only spend auth), one for
//! the root-blind proof of knowledge, and one in each circuit statement's
//! verify (`generalized-bulletproofs`' arithmetic-circuit proof); the
//! inner-product verify reads none. So, as for the BP+ batch
//! (`shekyl-bulletproofs`' `derived.rs`), the weights are a pure function of
//! the statement: a prover who knows them in advance cannot use them,
//! because changing any value the equations read re-derives every weight,
//! and cancelling an invalid statement's error under fixed weights is a
//! `1/ℓ` event per attempt.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::proof::{KeyImage, ShekylFcmpProof};
use crate::MAX_INPUTS;

/// The cSHAKE256 customization for a full FCMP++ verify's batch-weight seed
/// (CEN-I15's body; ruling R3, 2026-10-15). Registered in
/// `docs/design/CRYPTO_DOMAIN_REGISTRY.tsv`, mechanism 1; a change to
/// [`BatchWeights`]'s layout is a new domain (`-v2`).
pub const FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION: &[u8] = b"shekyl/fcmp-pp-batch-weights-v1";

/// The cSHAKE256 customization for a membership-only verify's batch-weight
/// seed (the emission backing path). A separate domain from
/// [`FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION`]: the two verifies read different
/// statements (no key images here), so their seeds are separate messages.
pub const FCMP_MEMBERSHIP_ONLY_BATCH_WEIGHTS_CUSTOMIZATION: &[u8] =
    b"shekyl/fcmp-membership-only-batch-weights-v1";

/// Which verify this statement is.
///
/// The two are separate messages. The full verify commits to its key
/// images; the membership-only verify omits that list, rather than framing
/// an empty one.
pub(crate) enum BatchKind<'a> {
    /// CEN-I15's body. Domain [`FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION`].
    Full { key_images: &'a [KeyImage] },
    /// The emission backing path. Domain
    /// [`FCMP_MEMBERSHIP_ONLY_BATCH_WEIGHTS_CUSTOMIZATION`].
    MembershipOnly,
}

/// Every value a verify reads, in the order the seed commits to them.
///
/// ```text
/// len_le4(proof) ‖ proof ‖ num_inputs_le4 ‖ layers_u8 ‖ tree_root ‖ signable_tx_hash
///   ‖ n_le4 ‖ KI_1 … KI_n          ([`BatchKind::Full`] only)
///   ‖ n_le4 ‖ K_1 … K_n            (each PQC key point K = k·G_k, compressed)
///   ‖ n_le4 ‖ C'_1 … C'_n          (pseudo-outputs)
/// ```
pub(crate) struct BatchWeights<'a> {
    pub(crate) proof: &'a ShekylFcmpProof,
    /// The tree depth the verify was given. The caller has already required
    /// it equal the proof's own depth.
    pub(crate) layers: u8,
    pub(crate) tree_root: &'a [u8; 32],
    pub(crate) signable_tx_hash: &'a [u8; 32],
    pub(crate) kind: BatchKind<'a>,
    /// Each PQC key point, compressed.
    pub(crate) pqc_key_points: &'a [[u8; 32]],
    pub(crate) pseudo_outs: &'a [[u8; 32]],
}

impl BatchWeights<'_> {
    /// The generator the three batch verifiers draw their weights from: a
    /// [`ChaCha20Rng`] seeded with `cSHAKE256(domain, preimage)[..32]`.
    pub(crate) fn rng(&self) -> ChaCha20Rng {
        ChaCha20Rng::from_seed(self.seed())
    }

    fn domain(&self) -> &'static [u8] {
        match self.kind {
            BatchKind::Full { .. } => FCMP_PP_BATCH_WEIGHTS_CUSTOMIZATION,
            BatchKind::MembershipOnly => FCMP_MEMBERSHIP_ONLY_BATCH_WEIGHTS_CUSTOMIZATION,
        }
    }

    fn seed(&self) -> [u8; 32] {
        shekyl_crypto_hash::cshake256_32(self.domain(), &self.preimage())
    }

    /// The length-framed preimage. Counts are `u32` little-endian; a count
    /// past `u32::MAX` cannot occur under [`MAX_INPUTS`].
    fn preimage(&self) -> Vec<u8> {
        let le4 = |n: usize| {
            u32::try_from(n)
                .expect("a proof and its input lists are bounded far below u32::MAX")
                .to_le_bytes()
        };
        // A framed 32-byte element. The three lists are key images, PQC
        // points and pseudo-outputs; membership-only omits the first.
        const FRAMED_POINT: usize = 32;
        const LIST_HEADER: usize = 4;
        const POINT_LISTS: usize = 3;
        let mut preimage = Vec::with_capacity(
            self.proof.data.len()
                + LIST_HEADER
                + LIST_HEADER
                + 1
                + FRAMED_POINT
                + FRAMED_POINT
                + LIST_HEADER * POINT_LISTS
                + FRAMED_POINT * POINT_LISTS * MAX_INPUTS,
        );
        preimage.extend_from_slice(&le4(self.proof.data.len()));
        preimage.extend_from_slice(&self.proof.data);
        preimage.extend_from_slice(&self.proof.num_inputs.to_le_bytes());
        preimage.push(self.layers);
        preimage.extend_from_slice(self.tree_root);
        preimage.extend_from_slice(self.signable_tx_hash);
        if let BatchKind::Full { key_images } = self.kind {
            preimage.extend_from_slice(&le4(key_images.len()));
            for key_image in key_images {
                preimage.extend_from_slice(key_image.as_bytes());
            }
        }
        for list in [self.pqc_key_points, self.pseudo_outs] {
            preimage.extend_from_slice(&le4(list.len()));
            for item in list {
                preimage.extend_from_slice(item);
            }
        }
        preimage
    }
}

#[cfg(test)]
#[path = "batch_weights_tests.rs"]
mod batch_weights_tests;
