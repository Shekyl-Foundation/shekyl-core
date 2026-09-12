// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **Cold authority** for a bond-post — the single check standing between a
//! compromised serving host and a collateral-draining exit, and the one
//! place that says *which* posts need it.
//!
//! Two functions, one predicate:
//!
//! - [`requires_cold_authority`] answers **whether** a post must authorize
//!   against the record's cold key. It is the selector, stated once, as an
//!   exhaustive truth table over `(post_kind, bond_debit)`.
//! - [`cold_authority_pin`] is the composed gate consensus calls: it consults
//!   the predicate and, when it holds, runs [`debit_auth_pin`] — the
//!   comparison of the presented authorizer against the **record's committed
//!   `bond_spend_pk`**, never a key the transaction brings along and never the
//!   persona's identity key.
//!
//! # The selector, and why it has two arms
//!
//! Until 2026-09-11 this module said *"the selector is `bond_debit > 0`, not
//! the post kind."* That sentence did not describe the code. The C++ Release
//! arm has always pinned **on kind, unconditionally** — a zero-debit Release
//! with the wrong key is refused here (UB3) before the debit-term guards
//! (UB9) ever see it, and `DAEMON_SUBMIT_VERDICT.md` §8.7.1.1 pins that
//! order. Only the `HoldingsUpdate` arm actually selects on the debit term,
//! because that is how it tells its add (credit, identity-key) from its drop
//! (debit, cold-key). So the truth table the code implements is:
//!
//! | `post_kind`      | requires cold authority |
//! |------------------|-------------------------|
//! | `Release`        | **always**              |
//! | `HoldingsUpdate` | iff `bond_debit > 0`    |
//! | `JoinMarket`     | never (the credit that *commits* the cold key) |
//! | `Rebond`         | never (credit path; verify requires `bond_debit == 0`) |
//!
//! Encoding the Release arm as `bond_debit > 0` would have been a behavior
//! change on a pinned ordering, not a restatement. The old sentence is kept
//! here as history because its shape — a selector described in prose that the
//! arms did not actually share — is the defect this module now closes.
//!
//! Keying on kind *alone* is also wrong, in the other direction: a
//! `HoldingsUpdate`-add is a credit the identity key authorizes, and applying
//! the pin to it rejects every valid add. (An earlier revision listed
//! `Rebond` as a consumer for the same reason — it read "record-mutating
//! arms" as if it meant "value-out arms". Every debit mutates the record; not
//! every record mutation is a debit.)
//!
//! # Why "cold authority" and not "debit authorization"
//!
//! The thing being protected is not value. It is **the persona's ability to
//! act against a compromised host**. A serving host holds the identity hybrid
//! key and can produce a valid Auth-P, so anything the identity key could
//! authorize, a host attacker can authorize. `bond_spend_pk` is cold
//! (`ARCHIVAL_CHALLENGE_MECHANISM.md` §hot-key), and this module is what
//! makes that coldness load-bearing rather than aspirational. Today every
//! post that needs cold authority happens to move value out; the ruled
//! `EndpointUpdate` (challenge mechanism §9.5, carrier ruled 2026-08-10)
//! moves none and needs it anyway. That post is **not** in the table yet —
//! it lands with its wire — but the predicate is named for the property, so
//! adding it is one arm rather than a re-derivation.
//!
//! # The cross-check
//!
//! [`cold_authority_pin`] **refuses** when called for a post the predicate
//! excludes ([`ColdAuthorityError::NotAColdAuthorityPost`]). That arm is
//! unreachable today and exists for the maintainer who adds a kind: an arm
//! that calls the gate without adding the predicate row fails loudly; an arm
//! that adds the row without calling the gate is caught by
//! `scripts/ci/check_debit_auth_single_source.sh`, which asserts every
//! consensus call site by name. Neither instrument sees the other's blind
//! spot, which is the point of having two.
//!
//! `SA-2b` moved *where the authorizer travels* — `bond_wire` forbids
//! `bond_spend_pk` on the vin for non-JoinMarket kinds, because a
//! vin-carried key would be a forgeable self-assertion — but it did not
//! remove the requirement. The authorizer now rides the surface-A
//! `pqc_auths` slot, and the pin is what ties that slot to the record.
//!
//! **One implementation.** C++ reaches the composed gate over FFI as
//! `shekyl_archival_cold_authority_pin`; Rust calls it natively
//! (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1 row UB3). A second implementation is
//! precisely the edit that must never land: two copies would drift on the
//! one predicate that has no recovery. The authoritative list of call sites
//! is the gate script above, which asserts each by name — named here rather
//! than restated because a count in prose is a defect generator.

use thiserror::Error;

use crate::bond_wire::{BondPostKind, HYBRID_PUBKEY_CANONICAL_BYTES};

/// Why a debit was refused authorization. Two arms rather than one so the
/// operator log distinguishes *a record that authorizes nothing* from *a
/// wrong key presented against a record that does* — different causes with
/// different remedies (rule 82).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DebitAuthError {
    /// The record commits no usable `bond_spend_pk`. **Fail closed**: this
    /// is not "fall back to the identity key", it is "this record
    /// authorizes no debit at all". Any length other than the canonical
    /// one counts — an absent key and a truncated key are the same
    /// refusal, because neither is a key the cold signer can hold.
    #[error(
        "bond record commits no bond_spend_pk (not {HYBRID_PUBKEY_CANONICAL_BYTES} bytes); \
         a debit cannot be authorized, and the identity key never authorizes a value-out"
    )]
    RecordCommitsNoKey,
    /// The presented authorizer is not the record's committed key —
    /// identity-key or foreign-key debit authorization.
    #[error(
        "pqc auth key does not match the record's committed bond_spend_pk \
         (identity-key or foreign-key debit authorization is forbidden)"
    )]
    AuthKeyMismatch,
}

/// Pin a debit's presented authorizer against the record's committed
/// `bond_spend_pk`.
///
/// `record_bond_spend_pk` is the record's committed copy as stored
/// (possibly empty — a record may commit no key); `auth_pubkey` is the
/// bond slot's `pqc_auths[i].hybrid_public_key`.
///
/// The presented key's length is not checked separately: equality with a
/// value already pinned to the canonical length implies it. That is the
/// oracle's exact shape, kept deliberately so the two paths cannot
/// disagree about a length edge.
pub fn debit_auth_pin(
    record_bond_spend_pk: &[u8],
    auth_pubkey: &[u8],
) -> Result<(), DebitAuthError> {
    if record_bond_spend_pk.len() != HYBRID_PUBKEY_CANONICAL_BYTES {
        return Err(DebitAuthError::RecordCommitsNoKey);
    }
    // Public keys on both sides — a plain comparison, matching the oracle.
    // There is no secret here whose timing could leak.
    if auth_pubkey != record_bond_spend_pk {
        return Err(DebitAuthError::AuthKeyMismatch);
    }
    Ok(())
}

/// Whether a bond-post of this kind, carrying this debit term, must authorize
/// against the record's **cold** `bond_spend_pk` (via [`cold_authority_pin`])
/// rather than the persona's identity key.
///
/// This is the selector, stated once. The match is exhaustive on purpose: a
/// new [`BondPostKind`] does not compile until someone decides its row, and
/// the decision is recorded here rather than implied by which arms happen to
/// call the pin. See the module doc for why `Release` is unconditional and
/// `HoldingsUpdate` is not.
#[must_use]
pub fn requires_cold_authority(post_kind: BondPostKind, bond_debit: u64) -> bool {
    match post_kind {
        // Unconditional on kind: the C++ arm has always pinned before the
        // debit-term guards, and §8.7.1.1 orders UB3 ahead of UB9.
        BondPostKind::Release => true,
        // The debit term is how this kind tells its drop (cold) from its add
        // (identity). It is the ONLY kind where the term selects.
        BondPostKind::HoldingsUpdate => bond_debit > 0,
        // Credit paths. JoinMarket is the post that *commits* the cold key;
        // Rebond's verify requires `bond_debit == 0`.
        BondPostKind::JoinMarket | BondPostKind::Rebond => false,
    }
}

/// Why the composed cold-authority gate refused. The two pin arms are
/// forwarded from [`DebitAuthError`] unchanged so the operator log keeps its
/// distinction; the third is the cross-check arm and names an implementation
/// error, never the sender's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ColdAuthorityError {
    /// The gate was invoked for a post that [`requires_cold_authority`] says
    /// needs none. Unreachable through a correct caller: it means a consensus
    /// arm and the predicate disagree about this kind, and the arm — not the
    /// transaction — is what is wrong. Refused rather than passed so the
    /// disagreement cannot silently authorize hot.
    #[error(
        "cold_authority_pin invoked for post_kind {post_kind:?} with bond_debit {bond_debit}, \
         which requires no cold authority; the calling arm and requires_cold_authority disagree"
    )]
    NotAColdAuthorityPost {
        post_kind: BondPostKind,
        bond_debit: u64,
    },
    /// See [`DebitAuthError::RecordCommitsNoKey`].
    #[error(transparent)]
    RecordCommitsNoKey(DebitAuthError),
    /// See [`DebitAuthError::AuthKeyMismatch`].
    #[error(transparent)]
    AuthKeyMismatch(DebitAuthError),
}

impl From<DebitAuthError> for ColdAuthorityError {
    fn from(e: DebitAuthError) -> Self {
        match e {
            DebitAuthError::RecordCommitsNoKey => Self::RecordCommitsNoKey(e),
            DebitAuthError::AuthKeyMismatch => Self::AuthKeyMismatch(e),
        }
    }
}

/// The composed gate consensus calls for a bond-post that may need cold
/// authority: consult [`requires_cold_authority`], then run
/// [`debit_auth_pin`] against the record's committed key.
///
/// Byte-identical to calling [`debit_auth_pin`] directly on every input the
/// consensus arms pass today (all of which satisfy the predicate). The only
/// new behavior is the refusal for a predicate-false post, which no correct
/// caller reaches.
pub fn cold_authority_pin(
    post_kind: BondPostKind,
    bond_debit: u64,
    record_bond_spend_pk: &[u8],
    auth_pubkey: &[u8],
) -> Result<(), ColdAuthorityError> {
    if !requires_cold_authority(post_kind, bond_debit) {
        return Err(ColdAuthorityError::NotAColdAuthorityPost {
            post_kind,
            bond_debit,
        });
    }
    debit_auth_pin(record_bond_spend_pk, auth_pubkey).map_err(ColdAuthorityError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(fill: u8) -> Vec<u8> {
        vec![fill; HYBRID_PUBKEY_CANONICAL_BYTES]
    }

    #[test]
    fn the_committed_key_authorizes_itself() {
        assert_eq!(debit_auth_pin(&canonical(7), &canonical(7)), Ok(()));
    }

    #[test]
    fn a_record_committing_no_key_authorizes_nothing() {
        // The dangerous alternative is an identity-key fallback: a record
        // with no committed authorizer must refuse every debit, including
        // one presenting a perfectly well-formed key.
        assert_eq!(
            debit_auth_pin(&[], &canonical(7)),
            Err(DebitAuthError::RecordCommitsNoKey)
        );
    }

    #[test]
    fn a_truncated_committed_key_is_no_key_not_a_short_key() {
        // Truncation must not become "compare the bytes that are there":
        // an attacker-influenced short commitment would otherwise be
        // easier to match than a full one.
        let short = vec![7u8; HYBRID_PUBKEY_CANONICAL_BYTES - 1];
        assert_eq!(
            debit_auth_pin(&short, &short),
            Err(DebitAuthError::RecordCommitsNoKey)
        );
    }

    #[test]
    fn a_foreign_key_does_not_authorize_a_debit() {
        assert_eq!(
            debit_auth_pin(&canonical(7), &canonical(8)),
            Err(DebitAuthError::AuthKeyMismatch)
        );
    }

    #[test]
    fn a_one_byte_difference_at_the_tail_is_refused() {
        // Guards against a prefix-only comparison.
        let mut presented = canonical(7);
        *presented.last_mut().expect("canonical key is non-empty") = 8;
        assert_eq!(
            debit_auth_pin(&canonical(7), &presented),
            Err(DebitAuthError::AuthKeyMismatch)
        );
    }
}

#[cfg(test)]
mod cold_authority_tests {
    use super::*;

    fn canonical(fill: u8) -> Vec<u8> {
        vec![fill; HYBRID_PUBKEY_CANONICAL_BYTES]
    }

    /// The selector as a truth table, one row per `(kind, debit)` cell that
    /// matters. Exhaustive over `BondPostKind` by construction of the match;
    /// this pins the VALUE of each arm, which the compiler does not.
    #[test]
    fn requires_cold_authority_truth_table() {
        use BondPostKind::*;
        // Release: unconditional on kind — a zero-debit Release is still
        // pinned (UB3 before UB9, §8.7.1.1).
        assert!(requires_cold_authority(Release, 0));
        assert!(requires_cold_authority(Release, 1));
        assert!(requires_cold_authority(Release, u64::MAX));
        // HoldingsUpdate: the debit term selects drop (cold) vs add (identity).
        assert!(!requires_cold_authority(HoldingsUpdate, 0));
        assert!(requires_cold_authority(HoldingsUpdate, 1));
        assert!(requires_cold_authority(HoldingsUpdate, u64::MAX));
        // Credit paths: never, regardless of what the term says.
        assert!(!requires_cold_authority(JoinMarket, 0));
        assert!(!requires_cold_authority(JoinMarket, 1));
        assert!(!requires_cold_authority(Rebond, 0));
        assert!(!requires_cold_authority(Rebond, 1));
    }

    /// The composed gate is byte-identical to the bare pin wherever the
    /// predicate holds: same Ok, same two refusals, forwarded unchanged.
    #[test]
    fn composed_gate_forwards_the_pin_unchanged_where_the_predicate_holds() {
        for (kind, debit) in [
            (BondPostKind::Release, 0u64),
            (BondPostKind::Release, 7),
            (BondPostKind::HoldingsUpdate, 7),
        ] {
            assert_eq!(
                cold_authority_pin(kind, debit, &canonical(7), &canonical(7)),
                Ok(()),
                "{kind:?}/{debit}"
            );
            assert_eq!(
                cold_authority_pin(kind, debit, &[], &canonical(7)),
                Err(ColdAuthorityError::RecordCommitsNoKey(
                    DebitAuthError::RecordCommitsNoKey
                )),
                "{kind:?}/{debit}"
            );
            assert_eq!(
                cold_authority_pin(kind, debit, &canonical(7), &canonical(8)),
                Err(ColdAuthorityError::AuthKeyMismatch(
                    DebitAuthError::AuthKeyMismatch
                )),
                "{kind:?}/{debit}"
            );
        }
    }

    /// The cross-check arm: invoking the gate on a predicate-false post is a
    /// refusal, never a silent pass — and it is refused BEFORE the keys are
    /// looked at, so a perfectly matching key pair does not rescue it.
    #[test]
    fn composed_gate_refuses_a_post_that_needs_no_cold_authority() {
        for (kind, debit) in [
            (BondPostKind::JoinMarket, 0u64),
            (BondPostKind::Rebond, 0),
            (BondPostKind::HoldingsUpdate, 0),
        ] {
            assert_eq!(
                cold_authority_pin(kind, debit, &canonical(7), &canonical(7)),
                Err(ColdAuthorityError::NotAColdAuthorityPost {
                    post_kind: kind,
                    bond_debit: debit
                }),
                "{kind:?}/{debit}"
            );
        }
    }
}
