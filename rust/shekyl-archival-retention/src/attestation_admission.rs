// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Block-level attestation admission (`ARCHIVAL_CREDIT_WIRE.md` §3–§4): the
//! body both verifiers run over a block's kept headers and its sidecar
//! witness — the daemon's FFI (`shekyl_archival_verify_attestation`, which
//! marshals raw pointers into these calls and maps the refusals onto its
//! verdict codes) and the Rust validator (CEN-B4 in `shekyl-chain-rules`,
//! which reads the operands off its view). One body, two callers: a second
//! orchestration of these steps would be the drift the FFI's verdict codes
//! were written to diagnose (`05-system-thinking`, a derivation two lanes
//! need is a function).
//!
//! The admission is three staged calls, in the order the C++ runs them:
//!
//! 1. [`AttestationSet::parse`] — the header blob split and parsed (cap
//!    first, before per-record work), the witness decoded (an empty blob
//!    is the zero-record set), the pass headers paired with the witness
//!    entries in `tx_extra` order.
//! 2. [`AttestationSet::verify_root`] — the recompute against the mined
//!    `attestation_root`. Signatures are **not** evaluated here, so a
//!    marshaling drift reads as a root mismatch and not as a forgery.
//! 3. [`AttestationSet::verify_countersignatures`] — every record's
//!    `P`-countersignature under the connecting chain's anchor window
//!    (`SF-D8`), with the bond's committed hybrid pubkey supplied by the
//!    caller per `p_id`: the FFI from the `(p_id, pubkey)` pairs C++ read,
//!    the validator from its `bond_record` read.
//!
//! What stays with each caller is what differs between them: the FFI's
//! raw-pointer marshaling, its anchor-table shape check and its
//! pair-set-equality check (a C++/Rust step-1/step-2 parse agreement, not
//! a property of the block); the validator's `tx_extra` parse, its window
//! fill from the view, and its locus.

use shekyl_crypto_pq::signature::HybridPublicKey;

use crate::attestation_wire::{
    attestation_root, pass_records_from_headers_and_witness, verify_pass_countersignature,
    AttestationHeader, BlockAttestationWitness, PassCountersignatureError, PassRecord,
    ATTESTATION_HEADER_LEN, MAX_ATTESTATION_RECORDS,
};
use crate::pass_anchor::PassAnchorWindow;

/// Why a block's attestation set did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationSetError {
    /// The kept-header blob was not a whole number of
    /// [`ATTESTATION_HEADER_LEN`]-byte records, or a record's kind byte was
    /// neither miss nor pass.
    #[error("attestation header blob is malformed")]
    MalformedHeaders,
    /// More than [`MAX_ATTESTATION_RECORDS`] header records — refused before
    /// any per-record parse work proportional to the count.
    #[error("attestation header count exceeds {MAX_ATTESTATION_RECORDS}")]
    CapExceeded,
    /// The witness did not decode, or its entry count did not match the
    /// block's pass headers.
    #[error("attestation witness is malformed or does not pair with the pass headers")]
    MalformedWitness,
}

/// Why the recomputed root was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationRootError {
    /// A record's signature could not be serialized into the root's
    /// preimage — a witness that decoded and still cannot be committed.
    #[error("attestation witness is malformed")]
    MalformedWitness,
    /// The recompute does not equal the mined header field.
    #[error("recomputed attestation_root does not equal the mined root")]
    Mismatch,
}

/// Why one pass record's countersignature was refused at admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CountersignatureRefusal {
    /// The block carries a pass record but its predecessor is below the
    /// anchor threshold: no window exists that early (the genesis
    /// boundary).
    #[error("pass record below the anchor threshold: no admission window exists")]
    BelowAnchorThreshold,
    /// The record names a `p_id` with no bond record.
    #[error("pass record names a persona with no bond record")]
    BondAbsent,
    /// The record's carried anchor height lies outside the admission
    /// window — a stale or pre-fetched read. No hash exists to check
    /// against, so no signature was evaluated.
    #[error("pass anchor height outside the admission window")]
    AnchorOutOfWindow,
    /// The signature failed, or the record's `p_id` is not the supplied
    /// pubkey's canonical id — a forgery signal.
    #[error("pass countersignature does not verify")]
    CountersigInvalid,
}

/// A block's attestation set, parsed and paired: the pass records the
/// kept headers and the witness describe together.
#[derive(Debug, Clone)]
pub struct AttestationSet {
    records: Vec<PassRecord>,
}

impl AttestationSet {
    /// Parse the coinbase's kept-header blob and the sidecar witness.
    ///
    /// `headers` is the raw `tx_extra` blob of [`ATTESTATION_HEADER_LEN`]-byte
    /// records — empty is the committed empty set; whether the extra was
    /// *readable* at all is the caller's to decide first. `witness` is the
    /// opaque sidecar in [`BlockAttestationWitness`]'s canonical form: no
    /// bytes is the zero-record set — its only encoding — and any
    /// non-empty blob must decode exactly (an eight-byte zero count is
    /// malformed). The cap is checked before any per-record parse.
    ///
    /// # Errors
    ///
    /// [`AttestationSetError`], in the order the checks run: cap, header
    /// shape, witness decode, pairing.
    pub fn parse(headers: &[u8], witness: &[u8]) -> Result<Self, AttestationSetError> {
        if !headers.len().is_multiple_of(ATTESTATION_HEADER_LEN) {
            return Err(AttestationSetError::MalformedHeaders);
        }
        if headers.len() / ATTESTATION_HEADER_LEN > MAX_ATTESTATION_RECORDS {
            return Err(AttestationSetError::CapExceeded);
        }
        let mut parsed_headers = Vec::with_capacity(headers.len() / ATTESTATION_HEADER_LEN);
        for chunk in headers.chunks_exact(ATTESTATION_HEADER_LEN) {
            let header = AttestationHeader::from_canonical_bytes(chunk)
                .map_err(|_| AttestationSetError::MalformedHeaders)?;
            parsed_headers.push(header);
        }

        let witness = BlockAttestationWitness::from_canonical_bytes(witness)
            .map_err(|_| AttestationSetError::MalformedWitness)?;

        let records = pass_records_from_headers_and_witness(&parsed_headers, &witness)
            .map_err(|_| AttestationSetError::MalformedWitness)?;
        Ok(Self { records })
    }

    /// The pass records, in `tx_extra` pass order.
    #[must_use]
    pub fn records(&self) -> &[PassRecord] {
        &self.records
    }

    /// Recompute the root over the records and compare it with the mined
    /// header field. Signatures are not evaluated.
    ///
    /// # Errors
    ///
    /// [`AttestationRootError::Mismatch`] when the recompute differs;
    /// [`AttestationRootError::MalformedWitness`] when a record cannot be
    /// committed.
    pub fn verify_root(&self, mined: &[u8; 32]) -> Result<(), AttestationRootError> {
        let recomputed =
            attestation_root(&self.records).map_err(|_| AttestationRootError::MalformedWitness)?;
        if recomputed == *mined {
            Ok(())
        } else {
            Err(AttestationRootError::Mismatch)
        }
    }

    /// Verify every record's `P`-countersignature.
    ///
    /// `window` is the connecting chain's anchor window for the block's
    /// predecessor, or `None` below the threshold where no window exists;
    /// `pubkey_of(p_id)` is the bond's committed hybrid pubkey, or `None`
    /// when the persona has no bond record. A block with no pass record
    /// passes without consulting either.
    ///
    /// # Errors
    ///
    /// The first record's [`CountersignatureRefusal`], in record order:
    /// the threshold before any record, then per record the bond, the
    /// window, the signature.
    pub fn verify_countersignatures<'k>(
        &self,
        window: Option<&PassAnchorWindow>,
        pubkey_of: impl Fn(&[u8; 32]) -> Option<&'k HybridPublicKey>,
    ) -> Result<(), CountersignatureRefusal> {
        if self.records.is_empty() {
            return Ok(());
        }
        let window = window.ok_or(CountersignatureRefusal::BelowAnchorThreshold)?;
        for record in &self.records {
            let pubkey = pubkey_of(&record.p_id).ok_or(CountersignatureRefusal::BondAbsent)?;
            verify_pass_countersignature(window, pubkey, record).map_err(|e| match e {
                PassCountersignatureError::AnchorOutOfWindow { .. } => {
                    CountersignatureRefusal::AnchorOutOfWindow
                }
                PassCountersignatureError::PIdMismatch
                | PassCountersignatureError::InvalidSignature => {
                    CountersignatureRefusal::CountersigInvalid
                }
            })?;
        }
        Ok(())
    }
}
