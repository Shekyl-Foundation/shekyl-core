// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation wire codec and pass-countersignature verify.
//!
//! Record format: [`ARCHIVAL_CREDIT_WIRE.md`](../../../docs/design/ARCHIVAL_CREDIT_WIRE.md)
//! §3, amended by [`ARCHIVAL_SHARD_FETCH.md`](../../../docs/design/ARCHIVAL_SHARD_FETCH.md)
//! `SF-D8`. Window arithmetic and the signed transcript live in [`crate::pass_anchor`].

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_crypto_pq::CryptoError;
use shekyl_types::BlockHeight;

use crate::attestation::AttestationKind;
use crate::hash::cshake256_32;
use crate::id::p_canonical_id_from_hybrid_pubkey;
use crate::pass_anchor::{
    pass_countersignature_message, PassAnchorWindow, PASS_ANCHOR_HASH_LEN, PASS_ANCHOR_HEIGHT_LEN,
    PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_NONCE_LEN,
};

/// cSHAKE customization for `attestation_root` over the ordered pass-record set.
pub const ATTESTATION_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-root-v1";

/// Canonical kept-header length: `p_id(32) + shard_id(8) + settlement_epoch(8) + kind(1)`.
pub const ATTESTATION_HEADER_LEN: usize = 32 + 8 + 8 + 1;

/// Genesis-frozen consensus cap on attestation records per block. Equals C++
/// `config::ARCHIVAL_MAX_ATTESTATION_RECORDS`.
pub const MAX_ATTESTATION_RECORDS: usize = 256;

/// Fixed framing prefix of a canonical witness: `count_le(8)`.
pub const WITNESS_PREFIX_LEN: usize = 8;

/// One witness entry: `nonce(32) ‖ anchor_height_le(8) ‖ signature_canonical`.
pub const WITNESS_ENTRY_LEN: usize =
    PASS_NONCE_LEN + PASS_ANCHOR_HEIGHT_LEN + HybridSignature::CANONICAL_LEN;

/// Exact maximum canonical byte length of a [`BlockAttestationWitness`].
/// C++ `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` must equal this.
pub const MAX_ATTESTATION_WITNESS_BYTES: usize =
    WITNESS_PREFIX_LEN + MAX_ATTESTATION_RECORDS * WITNESS_ENTRY_LEN;

const KIND_MISS: u8 = 0;
const KIND_PASS: u8 = 1;

/// Kept per-record header (§3.1): `p_id, shard_id, E, kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationHeader {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub kind: AttestationKind,
}

/// A header failed to decode from its canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationHeaderError {
    #[error("attestation header wrong length: expected {ATTESTATION_HEADER_LEN}, got {0}")]
    WrongLength(usize),
    #[error("attestation header kind byte {0} is neither miss (0) nor pass (1)")]
    BadKind(u8),
}

impl AttestationHeader {
    /// Canonical bytes: `p_id ‖ shard_id_le ‖ settlement_epoch_le ‖ kind`.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> [u8; ATTESTATION_HEADER_LEN] {
        let mut out = [0u8; ATTESTATION_HEADER_LEN];
        out[0..32].copy_from_slice(&self.p_id);
        out[32..40].copy_from_slice(&self.shard_id.to_le_bytes());
        out[40..48].copy_from_slice(&self.settlement_epoch.to_le_bytes());
        out[48] = match self.kind {
            AttestationKind::Miss => KIND_MISS,
            AttestationKind::Pass => KIND_PASS,
        };
        out
    }

    /// Decode; rejects a wrong length or an out-of-range `kind` byte.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, AttestationHeaderError> {
        if bytes.len() != ATTESTATION_HEADER_LEN {
            return Err(AttestationHeaderError::WrongLength(bytes.len()));
        }
        let mut p_id = [0u8; 32];
        p_id.copy_from_slice(&bytes[0..32]);
        let shard_id = u64::from_le_bytes(bytes[32..40].try_into().expect("8 bytes"));
        let settlement_epoch = u64::from_le_bytes(bytes[40..48].try_into().expect("8 bytes"));
        let kind = match bytes[48] {
            KIND_MISS => AttestationKind::Miss,
            KIND_PASS => AttestationKind::Pass,
            other => return Err(AttestationHeaderError::BadKind(other)),
        };
        Ok(Self {
            p_id,
            shard_id,
            settlement_epoch,
            kind,
        })
    }
}

/// One pass attestation: identity + terms + carried nonce/anchor height + signature.
///
/// No `kind` field — Pass is the type. Miss records never appear here.
#[derive(Debug, Clone)]
pub struct PassRecord {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub nonce: [u8; PASS_NONCE_LEN],
    pub anchor_height: BlockHeight,
    pub signature: HybridSignature,
}

impl PassRecord {
    #[must_use]
    pub fn to_header(&self) -> AttestationHeader {
        AttestationHeader {
            p_id: self.p_id,
            shard_id: self.shard_id,
            settlement_epoch: self.settlement_epoch,
            kind: AttestationKind::Pass,
        }
    }

    /// Transcript `P` signed for this record given the connecting chain's hash
    /// at `anchor_height`.
    #[must_use]
    pub fn countersignature_message(
        &self,
        anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    ) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
        pass_countersignature_message(&self.nonce, self.anchor_height, anchor_hash, self.shard_id)
    }
}

/// `attestation_root` over the block's pass-records (§3.2).
///
/// Each record contributes `header ‖ nonce ‖ anchor_height_le ‖ signature`.
/// Records are sorted by those canonical bytes before hashing. Empty set is
/// the customization over the bare count prefix.
pub fn attestation_root(records: &[PassRecord]) -> Result<[u8; 32], CryptoError> {
    const NONCE_END: usize = ATTESTATION_HEADER_LEN + PASS_NONCE_LEN;
    const ANCHOR_END: usize = NONCE_END + PASS_ANCHOR_HEIGHT_LEN;
    const RECORD_LEN: usize = ANCHOR_END + HybridSignature::CANONICAL_LEN;
    let mut record_bytes: Vec<[u8; RECORD_LEN]> = Vec::with_capacity(records.len());
    for record in records {
        let mut rec = [0u8; RECORD_LEN];
        rec[..ATTESTATION_HEADER_LEN].copy_from_slice(&record.to_header().to_canonical_bytes());
        rec[ATTESTATION_HEADER_LEN..NONCE_END].copy_from_slice(&record.nonce);
        rec[NONCE_END..ANCHOR_END].copy_from_slice(&record.anchor_height.to_raw().to_le_bytes());
        rec[ANCHOR_END..].copy_from_slice(&record.signature.to_canonical_bytes()?);
        record_bytes.push(rec);
    }
    record_bytes.sort_unstable();

    let mut input = Vec::with_capacity(8 + records.len() * RECORD_LEN);
    input.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for rec in &record_bytes {
        input.extend_from_slice(rec);
    }
    Ok(cshake256_32(ATTESTATION_ROOT_CUSTOMIZATION, &input))
}

/// Empty-set root: `attestation_root(&[])`.
#[inline]
pub fn empty_attestation_root() -> [u8; 32] {
    attestation_root(&[]).expect("empty attestation_root is infallible")
}

/// One witness entry: carried nonce, anchor height, and signature.
#[derive(Debug, Clone)]
pub struct PassWitness {
    pub nonce: [u8; PASS_NONCE_LEN],
    pub anchor_height: BlockHeight,
    pub signature: HybridSignature,
}

impl PassWitness {
    fn canonical_bytes_eq(&self, other: &Self) -> bool {
        self.nonce == other.nonce
            && self.anchor_height == other.anchor_height
            && self.signature.ed25519 == other.signature.ed25519
            && self.signature.ml_dsa == other.signature.ml_dsa
    }
}

/// Prunable attestation witness for one block: one entry per pass header, in
/// `tx_extra` pass order. Miss headers consume no entry.
#[derive(Debug, Clone)]
pub struct BlockAttestationWitness {
    pub passes: Vec<PassWitness>,
}

impl PartialEq for BlockAttestationWitness {
    fn eq(&self, other: &Self) -> bool {
        self.passes.len() == other.passes.len()
            && self
                .passes
                .iter()
                .zip(&other.passes)
                .all(|(a, b)| a.canonical_bytes_eq(b))
    }
}
impl Eq for BlockAttestationWitness {}

/// A witness blob failed to decode/encode, or declared a record count out of range.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error(
        "attestation witness shorter than the {WITNESS_PREFIX_LEN}-byte count prefix: got {0}"
    )]
    TooShort(usize),
    #[error("attestation witness count {0} exceeds cap {MAX_ATTESTATION_RECORDS}")]
    CountExceedsCap(u64),
    #[error("attestation witness length {got}, expected {expected} for {count} entry(ies)")]
    LengthMismatch {
        count: usize,
        expected: usize,
        got: usize,
    },
    #[error("attestation witness signature {index} invalid: {source}")]
    Signature {
        index: usize,
        #[source]
        source: CryptoError,
    },
}

impl BlockAttestationWitness {
    /// Canonical bytes: `count_le(8) ‖ (nonce ‖ anchor_height_le ‖ signature)[0..count]`.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        let count = self.passes.len();
        if count > MAX_ATTESTATION_RECORDS {
            return Err(WitnessError::CountExceedsCap(count as u64));
        }
        let mut out = Vec::with_capacity(WITNESS_PREFIX_LEN + count * WITNESS_ENTRY_LEN);
        out.extend_from_slice(&(count as u64).to_le_bytes());
        for (index, entry) in self.passes.iter().enumerate() {
            let sig = entry
                .signature
                .to_canonical_bytes()
                .map_err(|source| WitnessError::Signature { index, source })?;
            debug_assert_eq!(sig.len(), HybridSignature::CANONICAL_LEN);
            out.extend_from_slice(&entry.nonce);
            out.extend_from_slice(&entry.anchor_height.to_raw().to_le_bytes());
            out.extend_from_slice(&sig);
        }
        Ok(out)
    }

    /// Decode a witness blob. Cap is checked before allocating.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() < WITNESS_PREFIX_LEN {
            return Err(WitnessError::TooShort(bytes.len()));
        }
        let count_u64 =
            u64::from_le_bytes(bytes[0..WITNESS_PREFIX_LEN].try_into().expect("8 bytes"));
        if count_u64 > MAX_ATTESTATION_RECORDS as u64 {
            return Err(WitnessError::CountExceedsCap(count_u64));
        }
        let count = usize::try_from(count_u64).expect("count ≤ cap fits usize");
        let expected = WITNESS_PREFIX_LEN + count * WITNESS_ENTRY_LEN;
        if bytes.len() != expected {
            return Err(WitnessError::LengthMismatch {
                count,
                expected,
                got: bytes.len(),
            });
        }
        let mut passes = Vec::with_capacity(count);
        for index in 0..count {
            let start = WITNESS_PREFIX_LEN + index * WITNESS_ENTRY_LEN;
            let nonce_end = start + PASS_NONCE_LEN;
            let anchor_end = nonce_end + PASS_ANCHOR_HEIGHT_LEN;
            let end = start + WITNESS_ENTRY_LEN;
            let mut nonce = [0u8; PASS_NONCE_LEN];
            nonce.copy_from_slice(&bytes[start..nonce_end]);
            let anchor_height = BlockHeight::from_raw(u64::from_le_bytes(
                bytes[nonce_end..anchor_end].try_into().expect("8 bytes"),
            ));
            let signature = HybridSignature::from_canonical_bytes(&bytes[anchor_end..end])
                .map_err(|source| WitnessError::Signature { index, source })?;
            passes.push(PassWitness {
                nonce,
                anchor_height,
                signature,
            });
        }
        Ok(Self { passes })
    }
}

/// Kept pass headers and witness entries disagreed on count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("attestation pairing count mismatch: {pass_headers} pass header(s) vs {signatures} witness entry(ies)")]
pub struct WitnessPairingError {
    pub pass_headers: usize,
    pub signatures: usize,
}

/// Zip kept pass headers with witness entries in `tx_extra` pass order.
pub fn pass_records_from_headers_and_witness(
    headers: &[AttestationHeader],
    witness: &BlockAttestationWitness,
) -> Result<Vec<PassRecord>, WitnessPairingError> {
    let pass: Vec<&AttestationHeader> = headers
        .iter()
        .filter(|h| h.kind == AttestationKind::Pass)
        .collect();
    if pass.len() != witness.passes.len() {
        return Err(WitnessPairingError {
            pass_headers: pass.len(),
            signatures: witness.passes.len(),
        });
    }
    Ok(pass
        .into_iter()
        .zip(&witness.passes)
        .map(|(h, entry)| PassRecord {
            p_id: h.p_id,
            shard_id: h.shard_id,
            settlement_epoch: h.settlement_epoch,
            nonce: entry.nonce,
            anchor_height: entry.anchor_height,
            signature: entry.signature.clone(),
        })
        .collect())
}

/// Why one pass record's countersignature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassCountersignatureError {
    #[error("pass record p_id is not the supplied pubkey's canonical id")]
    PIdMismatch,
    #[error("pass anchor height {anchor_height} outside admission window [{first}, {last}]")]
    AnchorOutOfWindow {
        anchor_height: BlockHeight,
        first: BlockHeight,
        last: BlockHeight,
    },
    #[error("pass countersignature does not verify")]
    InvalidSignature,
}

/// Verify one pass record at admission.
///
/// 1. `record.p_id` is this pubkey's canonical id.
/// 2. `record.anchor_height` is inside `window`.
/// 3. The hybrid signature covers the transcript built from the carried nonce
///    and height, the connecting chain's hash at that height, and `shard_id`.
pub fn verify_pass_countersignature(
    window: &PassAnchorWindow,
    p_pubkey: &HybridPublicKey,
    record: &PassRecord,
) -> Result<(), PassCountersignatureError> {
    let pubkey_bytes = p_pubkey
        .to_canonical_bytes()
        .map_err(|_| PassCountersignatureError::PIdMismatch)?;
    if p_canonical_id_from_hybrid_pubkey(&pubkey_bytes).as_bytes() != &record.p_id {
        return Err(PassCountersignatureError::PIdMismatch);
    }
    let anchor_hash = window.hash_at(record.anchor_height).ok_or(
        PassCountersignatureError::AnchorOutOfWindow {
            anchor_height: record.anchor_height,
            first: window.first(),
            last: window.last(),
        },
    )?;
    verify_pass_transcript(
        p_pubkey,
        &record.nonce,
        record.anchor_height,
        anchor_hash,
        record.shard_id,
        &record.signature,
    )
}

/// Verify a pass countersignature over its transcript, with the anchor hash
/// supplied by the caller.
///
/// This is the signature check alone — steps 1 and 2 of
/// [`verify_pass_countersignature`] (id binding, admission window) are the
/// admission path's. The fetch client calls this directly at response time
/// (`SF-D8`): it holds the requester-side nonce, anchor, and the `P`
/// pubkey from the bond record, and has no admission window to consult.
/// Keeping the domain pairing here means admission and fetch cannot drift.
pub fn verify_pass_transcript(
    p_pubkey: &HybridPublicKey,
    nonce: &[u8; PASS_NONCE_LEN],
    anchor_height: BlockHeight,
    anchor_hash: &[u8; PASS_ANCHOR_HASH_LEN],
    shard_id: u64,
    signature: &HybridSignature,
) -> Result<(), PassCountersignatureError> {
    let message = pass_countersignature_message(nonce, anchor_height, anchor_hash, shard_id);
    HybridEd25519MlDsa
        .verify(
            p_pubkey,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            &message,
            signature,
        )
        .map_err(|_| PassCountersignatureError::InvalidSignature)
}

#[cfg(test)]
#[path = "attestation_wire_tests.rs"]
mod tests;
