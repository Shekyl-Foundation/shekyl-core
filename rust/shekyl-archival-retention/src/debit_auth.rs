// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! **Cold authority** for a bond-post: whether a post must authorize against
//! the record's committed `bond_spend_pk`, and the pin that makes that
//! comparison. A serving host holds the identity key, so an identity-authorized
//! debit is a collateral drain; this module is what makes the cold key
//! load-bearing.
//!
//! - [`requires_cold_authority`] is the selector — exhaustive over
//!   `(post_kind, bond_debit)`.
//! - [`cold_authority_pin`] consults the selector and, when it holds, runs
//!   [`debit_auth_pin`] against the **record's committed** key. Never a key
//!   the transaction brings along, never the persona's identity key.
//!
//! | `post_kind`      | requires cold authority |
//! |------------------|-------------------------|
//! | `Release`        | always                  |
//! | `HoldingsUpdate` | iff `bond_debit > 0`    |
//! | `JoinMarket`     | never                   |
//! | `Rebond`         | never                   |
//!
//! `Release` is unconditional because UB3 runs before the debit-term guards
//! (UB9); a zero-debit Release with the wrong key is refused here, not later.
//! `HoldingsUpdate` keys on the term because that is how the kind tells drop
//! (cold) from add (identity). Credit paths never pin: JoinMarket is the post
//! that *commits* the cold key; Rebond's verify requires `bond_debit == 0`.
//!
//! [`cold_authority_pin`] refuses a predicate-false call
//! ([`ColdAuthorityError::NotAColdAuthorityPost`]) before the keys are
//! compared, so a matching pair does not rescue an arm/predicate disagreement.
//! `scripts/ci/check_debit_auth_single_source.sh` catches an arm that forgets
//! the call. C++ reaches the composed gate as
//! `shekyl_archival_cold_authority_pin`; the Rust submit battery calls it
//! natively (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1 row UB3).

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

/// Whether this `(post_kind, bond_debit)` must authorize against the record's
/// cold `bond_spend_pk`. Exhaustive: a new [`BondPostKind`] does not compile
/// until its row is decided here.
#[must_use]
pub fn requires_cold_authority(post_kind: BondPostKind, bond_debit: u64) -> bool {
    match post_kind {
        // Release: always (UB3 before UB9, §8.7.1.1). EndpointUpdate — C1
        // (`EU-D2`): zero debit, cold anyway. The endpoint is spoiled precisely
        // when the hot key is the attacker's (host compromise, deanonymization
        // — §9.5), so hot authorization would be a flapping contest decided by
        // whoever posts last. Cold authority is what the attacker does not have.
        BondPostKind::Release | BondPostKind::EndpointUpdate => true,
        BondPostKind::HoldingsUpdate => bond_debit > 0,
        BondPostKind::JoinMarket | BondPostKind::Rebond => false,
    }
}

/// Why [`cold_authority_pin`] refused. `Pin` forwards [`DebitAuthError`] so
/// the operator log keeps the no-key / wrong-key distinction; the other arm
/// is an implementation error, never the sender's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ColdAuthorityError {
    /// The gate was invoked for a post that [`requires_cold_authority`]
    /// excludes. Refused rather than passed so an arm/predicate disagreement
    /// cannot silently authorize hot.
    #[error(
        "cold_authority_pin invoked for post_kind {post_kind:?} with bond_debit {bond_debit}, \
         which requires no cold authority; the calling arm and requires_cold_authority disagree"
    )]
    NotAColdAuthorityPost {
        post_kind: BondPostKind,
        bond_debit: u64,
    },
    #[error(transparent)]
    Pin(#[from] DebitAuthError),
}

/// Consult [`requires_cold_authority`], then [`debit_auth_pin`].
///
/// Predicate-false is a refusal, before the keys are compared. Byte-identical
/// to [`debit_auth_pin`] on every input the consensus arms pass today.
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
    Ok(debit_auth_pin(record_bond_spend_pk, auth_pubkey)?)
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

    /// Exhaustive over `BondPostKind` by construction of the match; this pins
    /// the VALUE of each arm, which the compiler does not.
    #[test]
    fn requires_cold_authority_truth_table() {
        use BondPostKind::*;
        assert!(requires_cold_authority(Release, 0));
        assert!(requires_cold_authority(Release, 1));
        assert!(requires_cold_authority(Release, u64::MAX));
        assert!(!requires_cold_authority(HoldingsUpdate, 0));
        assert!(requires_cold_authority(HoldingsUpdate, 1));
        assert!(requires_cold_authority(HoldingsUpdate, u64::MAX));
        assert!(!requires_cold_authority(JoinMarket, 0));
        assert!(!requires_cold_authority(JoinMarket, 1));
        assert!(!requires_cold_authority(Rebond, 0));
        assert!(!requires_cold_authority(Rebond, 1));
        assert!(requires_cold_authority(EndpointUpdate, 0));
        assert!(requires_cold_authority(EndpointUpdate, 1));
    }

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
                Err(ColdAuthorityError::Pin(DebitAuthError::RecordCommitsNoKey)),
                "{kind:?}/{debit}"
            );
            assert_eq!(
                cold_authority_pin(kind, debit, &canonical(7), &canonical(8)),
                Err(ColdAuthorityError::Pin(DebitAuthError::AuthKeyMismatch)),
                "{kind:?}/{debit}"
            );
        }
    }

    /// Predicate-false is a refusal BEFORE the keys are looked at, so a
    /// matching pair does not rescue it.
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
