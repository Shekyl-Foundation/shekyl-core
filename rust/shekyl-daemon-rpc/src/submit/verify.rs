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

use std::fmt;

use crate::submit::facts::SubmitFacts;
use crate::submit::phase_a::ParsedSubmission;
use shekyl_rpc_types::RejectCause;

/// Why Phase-C verification refused the transaction.
///
/// The closed set of causes a verifier may emit — constraining the seam so
/// an implementation cannot smuggle identity or transport dispositions
/// into a verification failure. This is the wire-cause: [`From`] maps it
/// onto [`RejectCause`] with no remainder (CB-5). The operator-facing
/// leg name lives on [`VerifyReject`]; a cause without a reason is not a
/// [`TxVerifier`] error.
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

/// A Phase-C refusal: the wire-cause plus the daemon-side diagnostic.
///
/// Mirrors [`crate::submit::PhaseAReject`]: the reason never crosses the
/// RPC boundary (§2.2 / CB-5 — a submitter learns only [`RejectCause`]);
/// operators read the engine's one `info` line. Constructors are the only
/// construction sites, and they refuse an empty reason, so a silent
/// `Malformed` is unrepresentable at this seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReject {
    cause: VerifyFailure,
    reason: String,
}

impl VerifyReject {
    /// Shape / proof / auth failure, named.
    pub fn malformed(reason: impl fmt::Display) -> Self {
        Self::new(VerifyFailure::Malformed, reason)
    }

    /// Snapshot-tree inconsistency a rebuild against a fresh root fixes.
    pub fn stale_root(reason: impl fmt::Display) -> Self {
        Self::new(VerifyFailure::StaleRoot, reason)
    }

    /// Consumed archival claim slot.
    pub fn double_spend(reason: impl fmt::Display) -> Self {
        Self::new(VerifyFailure::DoubleSpendConflict, reason)
    }

    /// Wrap a scripted cause (mocks). Still requires a reason.
    pub fn from_cause(cause: VerifyFailure, reason: impl fmt::Display) -> Self {
        Self::new(cause, reason)
    }

    fn new(cause: VerifyFailure, reason: impl fmt::Display) -> Self {
        let reason = reason.to_string();
        assert!(
            !reason.is_empty(),
            "VerifyReject reason must name the failing leg (programmer invariant)"
        );
        Self { cause, reason }
    }

    /// The wire-cause this refusal maps to.
    pub fn cause(&self) -> VerifyFailure {
        self.cause
    }

    /// Operator-facing diagnostic, logged daemon-side only.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for VerifyReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.cause, self.reason)
    }
}

impl std::error::Error for VerifyReject {}

impl From<VerifyReject> for VerifyFailure {
    fn from(reject: VerifyReject) -> Self {
        reject.cause
    }
}

impl From<VerifyReject> for RejectCause {
    fn from(reject: VerifyReject) -> Self {
        reject.cause.into()
    }
}

/// The Phase-C cryptographic battery.
pub trait TxVerifier {
    /// Verify `parsed` against the snapshot facts (root, tree depth,
    /// archival facts). Success is the engine's license to mint the
    /// [`crate::submit::VerificationCertificate`]; failure maps to a
    /// [`RejectCause`] via [`VerifyReject::cause`]. The reason is for
    /// the operator log, never the wire.
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyReject>;
}

// Forwarding impl, mirroring the `SubmitStateShim` one: shared-verifier
// ownership (engine + assertion handle) without orphan-rule friction.
impl<T: TxVerifier + ?Sized> TxVerifier for std::sync::Arc<T> {
    fn verify(&self, parsed: &ParsedSubmission, facts: &SubmitFacts) -> Result<(), VerifyReject> {
        (**self).verify(parsed, facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "must name the failing leg")]
    fn a_reject_without_a_reason_is_unrepresentable() {
        let _ = VerifyReject::malformed("");
    }

    #[test]
    fn from_strips_the_reason_at_the_wire() {
        let reject = VerifyReject::malformed("O6: degenerate output commitment");
        assert_eq!(reject.cause(), VerifyFailure::Malformed);
        assert_eq!(RejectCause::from(reject), RejectCause::Malformed);
    }
}
