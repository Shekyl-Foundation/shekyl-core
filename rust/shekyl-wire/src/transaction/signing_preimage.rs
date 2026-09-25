// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **PQC signing preimage** — what every hybrid (Ed25519 + ML-DSA)
//! signature on a transaction is over (`FCMP_SPEND_SIGNING_PREIMAGE.md`
//! §1.1). The derivation of record: the wallet signs over it
//! (`shekyl-tx-builder`), the daemon verifies against it through
//! `shekyl_tx_pqc_signing_payload_hashes`, and the validator records it as
//! CEN-I17. One body; the KAT in `tests/pqc_signing_preimage_kat.rs` holds
//! it to the specification's output over eight daemon-accepted shapes.
//!
//! A signature must bind everything about the transaction that is not
//! discardable, the discardable regions by digest, the signer's own public
//! key, and every other input's key — so that no proof, output, reference
//! or key can be substituted under a standing signature. The preimage is
//! that set of bindings, composed from the transaction's own typed parts:
//!
//! ```text
//! payload(i)     = pruned ‖ prunable_hash ‖ header(i) ‖ key_hashes
//! signed_hash(i) = keccak256(payload(i))
//! ```
//!
//! Three of the four components are the transaction's, shared by every
//! input; only `header(i)` is the signing input's. [`PqcSigningPreimage`]
//! is therefore a value derived once per transaction, from which each
//! input's payload is composed.

use shekyl_crypto_hash::keccak256;
use shekyl_types::PrunableHash;

use super::{Ct, PqcAuth, Transaction};

/// A transaction's PQC signing preimage — the components shared by every
/// input's payload, derived once. `payload(i)` and `signed_hash(i)` are
/// composed from it per input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqcSigningPreimage {
    /// The pruned segment ([`super::TxSegments::pruned`]): version, prefix,
    /// CT type, fee, reference block and the committed base — everything a
    /// node retains after pruning, bound in full.
    pruned: Vec<u8>,
    /// The prunable region, bound by its digest — the txid's
    /// [`PrunableHash`] component: the proof and the pseudo-outs cannot be
    /// swapped without changing every signature's preimage.
    prunable_hash: PrunableHash,
    /// `keccak256` of every input's hybrid public key, in input order: each
    /// input's signature binds every input's key, so no one key can be
    /// substituted without invalidating the others.
    key_hashes: Vec<[u8; 32]>,
}

impl PqcSigningPreimage {
    /// The preimage of `tx`, or `None` for a body that carries no per-input
    /// PQC authentication and so has none: a coinbase (`Null` CT), the
    /// serve-credit form (its countersignature rides the vin; `pqc_auths` is
    /// empty), and the storage-pruned spend form (no prunable region to
    /// bind).
    #[must_use]
    pub fn of(tx: &Transaction) -> Option<Self> {
        let Ct::Fcmp {
            pqc_auths,
            prunable: Some(_),
            ..
        } = &tx.ct
        else {
            return None;
        };
        if pqc_auths.is_empty() {
            return None;
        }
        let mut pruned = Vec::new();
        tx.write_pruned(&mut pruned)
            .expect("writing to a Vec is infallible");
        Some(Self {
            pruned,
            prunable_hash: tx.prunable_hash(),
            key_hashes: pqc_auths
                .iter()
                .map(|auth| keccak256(&auth.hybrid_public_key))
                .collect(),
        })
    }

    /// `payload(i)`: the preimage for the input whose authentication is
    /// `auth` — the shared bindings with that input's own header (its
    /// scheme and public key, never its signature: a signature is not over
    /// itself) between the region digest and the key hashes.
    #[must_use]
    pub fn payload(&self, auth: &PqcAuth) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            self.pruned.len() + 32 + auth.hybrid_public_key.len() + 32 * self.key_hashes.len(),
        );
        payload.extend_from_slice(&self.pruned);
        payload.extend_from_slice(self.prunable_hash.as_bytes());
        auth.write_header(&mut payload)
            .expect("writing to a Vec is infallible");
        for key_hash in &self.key_hashes {
            payload.extend_from_slice(key_hash);
        }
        payload
    }

    /// `signed_hash(i) = keccak256(payload(i))` — the 32 bytes the input's
    /// hybrid signature is made over and verified against.
    #[must_use]
    pub fn signed_hash(&self, auth: &PqcAuth) -> [u8; 32] {
        keccak256(&self.payload(auth))
    }
}

impl Transaction {
    /// Every input's `signed_hash(i)`, in input order — one per `pqc_auths`
    /// entry (`== nvin` for a body [`Transaction::validate`] admits; a
    /// hand-built body with mismatched arity yields one per auth, and the
    /// arity is the validator's to refuse). Empty for a body with no
    /// preimage ([`PqcSigningPreimage::of`]).
    #[must_use]
    pub fn pqc_signing_payload_hashes(&self) -> Vec<[u8; 32]> {
        let Some(preimage) = PqcSigningPreimage::of(self) else {
            return Vec::new();
        };
        let Ct::Fcmp { pqc_auths, .. } = &self.ct else {
            return Vec::new();
        };
        pqc_auths
            .iter()
            .map(|auth| preimage.signed_hash(auth))
            .collect()
    }
}
