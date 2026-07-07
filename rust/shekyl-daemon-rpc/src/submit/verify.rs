// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Phase-C cryptographic-verification seam
//! (`docs/design/DAEMON_SUBMIT_VERDICT.md` §3.1 Phase C).
//!
//! The engine owns the *deterministic policy arithmetic* of Phase C
//! (ref-age window, fee floor, weight rule) directly; the **expensive
//! cryptography** — FCMP++ membership, BP+ range proofs, CT balance, PQC
//! hybrid auth with scheme-id consistency, and the archival-arm battery
//! (§8.7.1) — sits behind this trait. Production implements it over the
//! native Rust crates (`shekyl-fcmp`, `shekyl-bulletproofs`,
//! `shekyl-ct-balance`, `shekyl-crypto-pq`, `shekyl-archival-retention`);
//! the race suite implements it as a deterministic mock.
//!
//! Phase C holds no locks **by construction** (round-2 F18): this trait is
//! called with plain facts, never with a handle into pool or blockchain
//! state, so an implementation *cannot* reach `check_tx_inputs` or any
//! lock-taking C++ path.

use crate::submit::facts::SubmitFacts;
use crate::submit::phase_a::ParsedSubmission;
use shekyl_rpc_types::RejectCause;

/// Why Phase-C verification refused the transaction.
///
/// The closed set of causes a verifier may emit — constraining the seam so
/// an implementation cannot smuggle identity or transport dispositions
/// into a verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailure {
    /// Proof/balance/auth/shape failure that is deterministic for these
    /// bytes against the canonical root: invalid FCMP++ membership proof,
    /// BP+ failure, CT imbalance, PQC auth failure or scheme-id
    /// inconsistency, output-key/commitment-mask violations (§8 rows O6,
    /// N6–N8), archival window/deadline/shape failures (§8.7.1).
    Malformed,
    /// The proof is inconsistent with the snapshot's tree state in a way a
    /// rebuild against a fresh root fixes: tree depth out of range
    /// (`TreeDepthTooLarge`) or a root-table inconsistency.
    StaleRoot,
    /// An archival claim slot is already consumed (§8.7.1 rows BP3 / SC2:
    /// a bond record already posted for this `P`; a serve-credit already
    /// claimed for this `(P, shard, epoch)`) — the claim-slot leg of
    /// `DoubleSpendConflict`.
    DoubleSpendConflict,
}

impl From<VerifyFailure> for RejectCause {
    fn from(failure: VerifyFailure) -> Self {
        match failure {
            VerifyFailure::Malformed => RejectCause::Malformed,
            VerifyFailure::StaleRoot => RejectCause::StaleRoot,
            VerifyFailure::DoubleSpendConflict => RejectCause::DoubleSpendConflict,
        }
    }
}

/// The Phase-C cryptographic battery.
pub trait TxVerifier {
    /// Verify `parsed` against the snapshot facts (root, tree depth,
    /// archival facts). Success is the engine's license to mint the
    /// [`crate::submit::VerificationCertificate`]; failure maps to a
    /// [`RejectCause`] via [`VerifyFailure`].
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure>;
}

// Forwarding impl, mirroring the `SubmitStateShim` one: shared-verifier
// ownership (engine + assertion handle) without orphan-rule friction.
impl<T: TxVerifier + ?Sized> TxVerifier for std::sync::Arc<T> {
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyFailure> {
        (**self).verify(parsed, facts)
    }
}
