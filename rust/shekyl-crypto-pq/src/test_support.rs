// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Cross-suite test helpers.
//!
//! `#[doc(hidden)] pub` so both the in-crate `#[cfg(test)]` modules and the
//! `tests/` integration suites reach one copy. This grants no capability the
//! `encrypted_output_field` lesson warns about: the only export is an
//! assertion guard — it constructs nothing and unlocks nothing.

/// Environment variable arming a pinned-fixture regenerator:
/// `YYYY-MM-DD <rationale>`, the date naming the
/// `docs/V3_WALLET_DECISION_LOG.md` entry that authorizes moving a pinned
/// vector.
pub const PINNED_REGEN_DECISION_ENV: &str = "SHEKYL_PINNED_REGEN_DECISION";

/// Refuse to regenerate `fixture` unless [`PINNED_REGEN_DECISION_ENV`] cites
/// the decision-log entry that authorizes the move (rule 50: a regenerator
/// that rewrites fixtures on request is a one-command silencer for a failing
/// tripwire). Returns the citation for embedding in the regenerated file.
///
/// The one validation body for every armed regenerator in this crate —
/// `leaf_commitment.rs`, `wallet_envelope.rs`, `tests/scan_output_kat.rs`,
/// `tests/kat_hybrid_v2.rs` all call here.
pub fn regen_decision_or_refuse(fixture: &str) -> String {
    let decision = std::env::var(PINNED_REGEN_DECISION_ENV).unwrap_or_default();
    let cited = decision.len() > 11
        && decision.as_bytes()[..10]
            .iter()
            .enumerate()
            .all(|(i, b)| match i {
                4 | 7 => *b == b'-',
                _ => b.is_ascii_digit(),
            })
        && decision.as_bytes()[10] == b' ';
    assert!(
        cited,
        "refusing to regenerate {fixture}: set \
         {PINNED_REGEN_DECISION_ENV}=\"YYYY-MM-DD <rationale>\" citing the \
         docs/V3_WALLET_DECISION_LOG.md entry that authorizes the move (got: \
         {decision:?}). Moving a pinned vector is a format decision, not a test \
         fix — see 50-testing.mdc."
    );
    decision
}
