// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **debit authorization pin** — the single check standing between a
//! compromised serving host and a collateral-draining exit.
//!
//! Every value-out bond-post arm (`Unbond`, `HoldingsUpdate`, `Rebond`)
//! authorizes against the **record's committed `bond_spend_pk`**, never
//! against a key the transaction brings along and never against the
//! persona's identity key. That distinction is the whole point: a
//! serving host holds the identity hybrid key and can therefore produce a
//! valid Auth-P, so an identity-authorized debit would let a host
//! compromise become a collateral drain. `bond_spend_pk` is cold
//! (`ARCHIVAL_CHALLENGE_MECHANISM.md` §hot-key), and this function is what
//! makes that coldness load-bearing rather than aspirational.
//!
//! `SA-2b` moved *where the authorizer travels* — `bond_wire` forbids
//! `bond_spend_pk` on the vin for non-JoinMarket kinds, because a
//! vin-carried key would be a forgeable self-assertion — but it did not
//! remove the requirement. The authorizer now rides the surface-A
//! `pqc_auths` slot, and this pin is what ties that slot to the record.
//!
//! **One copy, two callers.** The C++ block path calls this over FFI
//! (`shekyl_archival_debit_auth_pin`, replacing the former
//! `archival_debit_auth_pin` helper in `blockchain.cpp`) and the Rust
//! submit battery calls it natively
//! (`DAEMON_SUBMIT_VERDICT.md` §8.7.1.1 row UB3). A second implementation
//! of this check is precisely the edit that must never land: the two
//! copies would drift on the one predicate that has no recovery.

use thiserror::Error;

use crate::bond_wire::HYBRID_PUBKEY_CANONICAL_BYTES;

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
