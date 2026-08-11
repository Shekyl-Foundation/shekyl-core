// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Attestation wire + admission verify — the §3 record format and the §4
//! *admission* half of the seam (block-validation time, pre-prune).
//!
//! Design of record: [`ARCHIVAL_CREDIT_WIRE.md`](../../../docs/design/ARCHIVAL_CREDIT_WIRE.md)
//! (TJ-B step 3, shape 4). This module owns the parts admission touches — the
//! kept **header** bytes (`p_id, shard_id, E, kind`), the block-bound **nonce**,
//! the **`attestation_root`** over the **pass-record** set (header‖signature
//! pairs), and the **countersignature verify**. Its sibling [`crate::attestation`]
//! owns the settlement fold; the two never share a signature, which is the §4
//! seam.
//!
//! # What `P` countersigns — the nonce alone
//!
//! The countersignature covers **the nonce alone**
//! (`H(r ‖ cb_out_key ‖ P ‖ s ‖ E)`). Every term is on-chain or derivable, so
//! admission can recompute and verify it. An earlier draft considered
//! `H(nonce ‖ transfer_digest)`, but `transfer_digest` digests off-chain shard
//! bytes that consensus cannot reconstruct — that reading is not
//! consensus-verifiable. Nonce-only is also *complete*: `shard_id` is already a
//! nonce term, so a content digest adds no binding `s` does not carry. §9.4's
//! topology binding carries the read-happened property.
//!
//! # Pass is a type, not a kind check
//!
//! Root and verify take [`PassRecord`] — identity + terms + signature, with
//! **no `kind` field**. Wire encode materializes `kind = Pass`. A miss is a
//! kept header alone and cannot enter these APIs. That is the admission half of
//! the same make-bad-states-unrepresentable seam settlement already uses
//! (`settle_epoch(passes, issued)` — absolute-2, §7.1 ratification).

use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme,
};
use shekyl_crypto_pq::CryptoError;

use crate::attestation::AttestationKind;
use crate::hash::cshake256_32;
use crate::id::p_canonical_id_from_hybrid_pubkey;

/// cSHAKE customization for the block-bound challenge nonce (§3, copy-freeride
/// repair: the `cb_out_key` term binds the attestation to *this* block's
/// coinbase output).
pub const ATTESTATION_NONCE_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-nonce-v1";

/// cSHAKE customization for `attestation_root` over the ordered pass-record set.
pub const ATTESTATION_ROOT_CUSTOMIZATION: &[u8] = b"shekyl/archival-attestation-root-v1";

/// Canonical kept-header length: `p_id(32) + shard_id(8) + settlement_epoch(8) +
/// kind(1)` (§3.1). The `kind` byte is the sole prune-surviving *discriminant*
/// on the full kept header (`p_id ‖ s ‖ E ‖ kind` all ride `prefix_hash`).
pub const ATTESTATION_HEADER_LEN: usize = 32 + 8 + 8 + 1;

/// Genesis-frozen consensus cap on attestation records per block. It must equal
/// C++ `config::ARCHIVAL_MAX_ATTESTATION_RECORDS` (the cross-language witness KAT
/// pins the equality). It bounds both the admission record count and the witness
/// decode's up-front allocation, so a hostile `count` field cannot force an
/// unbounded reservation before the length is validated.
pub const MAX_ATTESTATION_RECORDS: usize = 256;

/// Fixed framing prefix of a canonical witness: `r(32) ‖ count_le(8)`.
pub const WITNESS_PREFIX_LEN: usize = 32 + 8;

/// The EXACT maximum canonical byte length of a [`BlockAttestationWitness`]:
/// `r(32) ‖ count(8) ‖ MAX_ATTESTATION_RECORDS × HybridSignature`. This is the
/// authority the C++ transport cap must respect: the coarse
/// `config::ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES` must **over-bound** this value
/// (`cpp_cap ≥ this`), never under-bound it — a C++ cap below this maximum would
/// reject on the wire a witness that Rust admits, i.e. a consensus split. The
/// direction is gated cross-language by the FFI bound test; this const is the
/// single Rust-side authority for that check.
pub const MAX_ATTESTATION_WITNESS_BYTES: usize =
    WITNESS_PREFIX_LEN + MAX_ATTESTATION_RECORDS * HybridSignature::CANONICAL_LEN;

/// Fixed nonce preimage length: `r(32) ‖ cb_out_key(32) ‖ p_id(32) ‖ s(8) ‖ E(8)`.
const NONCE_INPUT_LEN: usize = 32 + 32 + 32 + 8 + 8;

/// `kind` byte encodings — fixed, not a bit in a status field, so a decoder
/// rejects anything that is neither (no silent third state).
const KIND_MISS: u8 = 0;
const KIND_PASS: u8 = 1;

/// The kept per-record header (§3.1), permanent in the coinbase `tx_extra` and
/// committed via `prefix_hash`. The full header (`p_id, shard_id, E, kind`)
/// survives the signature prune; settlement folds the gathered `kind` values
/// after the scan has already keyed by `(P, s, E)`.
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
    /// Byte length is not [`ATTESTATION_HEADER_LEN`].
    #[error("attestation header wrong length: expected {ATTESTATION_HEADER_LEN}, got {0}")]
    WrongLength(usize),
    /// The `kind` byte is neither [`KIND_MISS`] nor [`KIND_PASS`].
    #[error("attestation header kind byte {0} is neither miss (0) nor pass (1)")]
    BadKind(u8),
}

impl AttestationHeader {
    /// Canonical bytes: `p_id ‖ shard_id_le ‖ settlement_epoch_le ‖ kind`.
    /// Little-endian for the counters, matching the archival lineage
    /// (`challenge.rs` uses `to_le_bytes`); fixed-width so the layout is
    /// position-addressable and never ambiguous.
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

    /// Decode; rejects a wrong length or an out-of-range `kind` byte (loud, not
    /// a silent default — a malformed header is a block-validity failure).
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

/// One **pass** attestation: identity + terms + countersignature.
///
/// There is no `kind` field — Pass is the type. [`Self::to_header`] materializes
/// the kept wire header with `kind = Pass`. Miss records never carry a
/// signature and never appear here, so root/verify cannot represent
/// miss-with-signature.
#[derive(Debug, Clone)]
pub struct PassRecord {
    pub p_id: [u8; 32],
    pub shard_id: u64,
    pub settlement_epoch: u64,
    pub signature: HybridSignature,
}

impl PassRecord {
    /// Kept header for this pass (`kind = Pass`).
    #[must_use]
    pub fn to_header(&self) -> AttestationHeader {
        AttestationHeader {
            p_id: self.p_id,
            shard_id: self.shard_id,
            settlement_epoch: self.settlement_epoch,
            kind: AttestationKind::Pass,
        }
    }

    /// Block-bound nonce for this record's identity and terms.
    #[must_use]
    pub fn nonce(&self, r: &[u8; 32], cb_out_key: &[u8; 32]) -> [u8; 32] {
        attestation_nonce(
            r,
            cb_out_key,
            &self.p_id,
            self.shard_id,
            self.settlement_epoch,
        )
    }
}

/// The block-bound challenge nonce `H(r ‖ cb_out_key ‖ p_id ‖ shard_id ‖ E)`
/// (§3). `r` is the producer's revealed randomness (prunable side table with
/// the signatures — admission/pre-prune only), `cb_out_key` the coinbase output
/// key (the copy-freeride bind; kept). Every term is on-chain or derivable at
/// admission, so verify recomputes it identically.
///
/// Prefer [`PassRecord::nonce`] at call sites that already hold a pass record
/// so the terms cannot drift from the record.
#[must_use]
pub fn attestation_nonce(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_id: &[u8; 32],
    shard_id: u64,
    settlement_epoch: u64,
) -> [u8; 32] {
    // Fixed-size stack preimage — consensus-adjacent, called per pass at
    // admission; no heap alloc on the hot path.
    let mut input = [0u8; NONCE_INPUT_LEN];
    input[0..32].copy_from_slice(r);
    input[32..64].copy_from_slice(cb_out_key);
    input[64..96].copy_from_slice(p_id);
    input[96..104].copy_from_slice(&shard_id.to_le_bytes());
    input[104..112].copy_from_slice(&settlement_epoch.to_le_bytes());
    cshake256_32(ATTESTATION_NONCE_CUSTOMIZATION, &input)
}

/// `attestation_root` over the block's **pass-records** (§3.2) — the value
/// stored in the block field and mined over as a merkle leaf.
///
/// Each record contributes `header_canonical ‖ signature_canonical`, so the root
/// commits the header↔signature **pairing** — not signatures alone, and not in
/// an unstated positional order. Records are **sorted by these canonical
/// bytes** before hashing, giving one defined order every producer and every
/// re-validating node (reading signatures from the **prunable** side table at
/// admission / pre-prune) reproduces identically. Post-prune the **stored**
/// root is trusted (mined into the block hash); settlement never recomputes it.
///
/// The input type is [`PassRecord`]: miss-with-signature is unrepresentable.
/// Each signature is in its authoritative fixed-length canonical encoding
/// ([`HybridSignature::to_canonical_bytes`]), so a malformed (wrong-length)
/// signature is a loud [`CryptoError`], not a silent truncation.
///
/// **Defined-empty** (§3.2 invariant): an empty set hashes to the customization
/// over the bare count prefix, a fixed constant, so the leaf is never omitted
/// and the count never desyncs.
pub fn attestation_root(records: &[PassRecord]) -> Result<[u8; 32], CryptoError> {
    const RECORD_LEN: usize = ATTESTATION_HEADER_LEN + HybridSignature::CANONICAL_LEN;
    let mut record_bytes: Vec<[u8; RECORD_LEN]> = Vec::with_capacity(records.len());
    for record in records {
        let mut rec = [0u8; RECORD_LEN];
        rec[..ATTESTATION_HEADER_LEN].copy_from_slice(&record.to_header().to_canonical_bytes());
        rec[ATTESTATION_HEADER_LEN..].copy_from_slice(&record.signature.to_canonical_bytes()?);
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

/// Empty-set root: `attestation_root(&[])`. Infallibly the defined-empty
/// commitment a block header carries with no pass records (not the all-zero
/// hash). Prefer this over re-hexing the KAT pin at call sites.
#[inline]
pub fn empty_attestation_root() -> [u8; 32] {
    // No signatures to canonicalize; the empty path cannot fail.
    attestation_root(&[]).expect("empty attestation_root is infallible")
}

/// The prunable, admission-only **attestation witness** for one block
/// (§3.2/§4, transport shape B2). It carries exactly the data the block *hash*
/// does not commit directly — the producer's revealed randomness `r` and the
/// per-pass [`HybridSignature`]s — transported **alongside** the block, stored
/// only in the height-keyed side table, and dropped after the retention horizon.
/// It is never in the block blob (which rides the never-pruned `blocks` store,
/// so blob-resident bytes cannot prune — the reason shape 1 was rejected). Its
/// integrity does not need the blob: [`attestation_root`] (the mined header
/// field) commits the header↔signature set, and admission recomputes it over
/// these signatures paired with the kept `tx_extra` headers.
///
/// # The pairing rule (consensus — pinned here because the block-hash
/// differential is structurally blind to it)
///
/// The block-hash / C++↔Rust differential cannot see this witness (it is not in
/// the hash), so the sig↔header pairing must be stated, not inferred:
/// `pass_signatures[i]` is the countersignature for the **i-th pass header** —
/// the kept `tx_extra` headers filtered to `kind = Pass`, in `tx_extra` order.
/// Miss headers consume no signature. [`pass_records_from_headers_and_witness`]
/// is the single executable statement of this zip; both producer and validator
/// go through it so the rule cannot drift between call sites. A pass-header /
/// signature **count** mismatch is a loud error (a block-validity failure at
/// admission); any *content* pairing disagreement instead surfaces as an
/// `attestation_root` mismatch (self-enforcing).
#[derive(Debug, Clone)]
pub struct BlockAttestationWitness {
    /// The producer's revealed randomness — one per **block**, not per record
    /// (a nonce term every record shares). Lives here (prunable), never in the
    /// coinbase `tx_extra`, because its only consumer is admission (§4).
    pub r: [u8; 32],
    /// One signature per pass header, in `tx_extra` pass order.
    pub pass_signatures: Vec<HybridSignature>,
}

// HybridSignature is not `PartialEq`; compare its canonical field bytes. Two
// witnesses are equal iff `r` and every paired signature's `(ed25519, ml_dsa)`
// bytes match — enough for round-trip assertions without widening the crypto
// type's derives.
impl PartialEq for BlockAttestationWitness {
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r
            && self.pass_signatures.len() == other.pass_signatures.len()
            && self
                .pass_signatures
                .iter()
                .zip(&other.pass_signatures)
                .all(|(a, b)| a.ed25519 == b.ed25519 && a.ml_dsa == b.ml_dsa)
    }
}
impl Eq for BlockAttestationWitness {}

/// A witness blob failed to decode/encode, or declared a record count out of range.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// Shorter than the fixed `r(32) ‖ count(8)` prefix ([`WITNESS_PREFIX_LEN`]).
    #[error(
        "attestation witness shorter than the {WITNESS_PREFIX_LEN}-byte r‖count prefix: got {0}"
    )]
    TooShort(usize),
    /// The declared (or encode-side) count exceeds [`MAX_ATTESTATION_RECORDS`].
    /// Checked **before** any length arithmetic on decode, so it also caps the
    /// allocation and rules out a `count · CANONICAL_LEN` overflow. Held as the
    /// raw wire `u64` — the value may not fit `usize` on a 32-bit target, which
    /// is itself a reason to reject.
    #[error("attestation witness count {0} exceeds cap {MAX_ATTESTATION_RECORDS}")]
    CountExceedsCap(u64),
    /// Total length is not exactly
    /// `WITNESS_PREFIX_LEN + count · HybridSignature::CANONICAL_LEN`.
    #[error("attestation witness length {got}, expected {expected} for {count} signature(s)")]
    LengthMismatch {
        count: usize,
        expected: usize,
        got: usize,
    },
    /// The `index`-th signature failed canonical encode/decode.
    #[error("attestation witness signature {index} invalid: {source}")]
    Signature {
        index: usize,
        #[source]
        source: CryptoError,
    },
}

impl BlockAttestationWitness {
    /// Canonical bytes: `r(32) ‖ count_le(8) ‖ signature[0..count]`, each in
    /// [`HybridSignature::to_canonical_bytes`] (fixed
    /// [`HybridSignature::CANONICAL_LEN`]). This is the exact byte stream carried
    /// alongside the block and pinned by the cross-language witness KAT — the
    /// `count` prefix mirrors [`attestation_root`]'s `u64`-LE length prefix so
    /// the two encodings share one integer convention.
    ///
    /// Rejects a signature count above [`MAX_ATTESTATION_RECORDS`] (same cap as
    /// decode) so an over-cap producer cannot emit a blob the decoder would
    /// refuse — encode and decode share one validity surface.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, WitnessError> {
        let count = self.pass_signatures.len();
        if count > MAX_ATTESTATION_RECORDS {
            return Err(WitnessError::CountExceedsCap(count as u64));
        }
        let mut out =
            Vec::with_capacity(WITNESS_PREFIX_LEN + count * HybridSignature::CANONICAL_LEN);
        out.extend_from_slice(&self.r);
        out.extend_from_slice(&(count as u64).to_le_bytes());
        for (index, sig) in self.pass_signatures.iter().enumerate() {
            let bytes = sig
                .to_canonical_bytes()
                .map_err(|source| WitnessError::Signature { index, source })?;
            debug_assert_eq!(bytes.len(), HybridSignature::CANONICAL_LEN);
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }

    /// Decode a witness blob. Rejects a short prefix, an over-cap count (before
    /// allocating), a total length that is not an exact `count`-many signatures,
    /// and any malformed signature — all loud, because a malformed witness is a
    /// block-validity failure at admission, never a silent default.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, WitnessError> {
        if bytes.len() < WITNESS_PREFIX_LEN {
            return Err(WitnessError::TooShort(bytes.len()));
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        let count_u64 =
            u64::from_le_bytes(bytes[32..WITNESS_PREFIX_LEN].try_into().expect("8 bytes"));
        // Cap BEFORE the length multiply: bounds the allocation and forecloses a
        // `count · CANONICAL_LEN` overflow on a hostile count. Compared in u64 so
        // the check itself never truncates on a 32-bit target.
        if count_u64 > MAX_ATTESTATION_RECORDS as u64 {
            return Err(WitnessError::CountExceedsCap(count_u64));
        }
        // ≤ MAX_ATTESTATION_RECORDS now, so this narrowing is infallible on every
        // target width (the cap fits every usize).
        let count = usize::try_from(count_u64).expect("count ≤ cap fits usize");
        let expected = WITNESS_PREFIX_LEN + count * HybridSignature::CANONICAL_LEN;
        if bytes.len() != expected {
            return Err(WitnessError::LengthMismatch {
                count,
                expected,
                got: bytes.len(),
            });
        }
        let mut pass_signatures = Vec::with_capacity(count);
        for index in 0..count {
            let start = WITNESS_PREFIX_LEN + index * HybridSignature::CANONICAL_LEN;
            let end = start + HybridSignature::CANONICAL_LEN;
            let sig = HybridSignature::from_canonical_bytes(&bytes[start..end])
                .map_err(|source| WitnessError::Signature { index, source })?;
            pass_signatures.push(sig);
        }
        Ok(Self { r, pass_signatures })
    }
}

/// The kept pass headers and the witness signatures disagreed on count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("attestation pairing count mismatch: {pass_headers} pass header(s) vs {signatures} witness signature(s)")]
pub struct WitnessPairingError {
    pub pass_headers: usize,
    pub signatures: usize,
}

/// Reconstruct the block's [`PassRecord`] set by zipping the kept **pass**
/// headers with the witness signatures — the single executable statement of the
/// §3.2 pairing rule. `headers` is the full kept set (pass **and** miss, in
/// `tx_extra` order); it is filtered to `kind = Pass` and zipped positionally
/// with `witness.pass_signatures`. Both admission's `attestation_root` recompute
/// and any later re-check call this, so the pairing cannot drift between sites.
/// A pass-header / signature count mismatch is a [`WitnessPairingError`] (a
/// block-validity failure).
pub fn pass_records_from_headers_and_witness(
    headers: &[AttestationHeader],
    witness: &BlockAttestationWitness,
) -> Result<Vec<PassRecord>, WitnessPairingError> {
    let pass: Vec<&AttestationHeader> = headers
        .iter()
        .filter(|h| h.kind == AttestationKind::Pass)
        .collect();
    if pass.len() != witness.pass_signatures.len() {
        return Err(WitnessPairingError {
            pass_headers: pass.len(),
            signatures: witness.pass_signatures.len(),
        });
    }
    Ok(pass
        .into_iter()
        .zip(&witness.pass_signatures)
        .map(|(h, sig)| PassRecord {
            p_id: h.p_id,
            shard_id: h.shard_id,
            settlement_epoch: h.settlement_epoch,
            signature: sig.clone(),
        })
        .collect())
}

/// Verify one **pass** record's countersignature at admission (§3.3 step b).
///
/// Two bindings, both self-contained so no correctness rides on the caller:
///
/// 1. **`p_id` binds the key.** The record's `p_id` must be *this pubkey's*
///    canonical id ([`p_canonical_id_from_hybrid_pubkey`]).
/// 2. **The signature covers the nonce.** Recompute
///    `H(r ‖ cb_out_key ‖ P ‖ s ‖ E)` from the record's terms and check `P`'s
///    hybrid countersignature over it.
///
/// Kind is not checked: a miss cannot be a [`PassRecord`].
#[must_use]
pub fn verify_pass_countersignature(
    r: &[u8; 32],
    cb_out_key: &[u8; 32],
    p_pubkey: &HybridPublicKey,
    record: &PassRecord,
) -> bool {
    // Binding 1: the record's p_id must be this pubkey's canonical id.
    let Ok(pubkey_bytes) = p_pubkey.to_canonical_bytes() else {
        return false;
    };
    if p_canonical_id_from_hybrid_pubkey(&pubkey_bytes).as_bytes() != &record.p_id {
        return false;
    }
    // Binding 2: P's countersignature over the block-bound nonce.
    let nonce = record.nonce(r, cb_out_key);
    HybridEd25519MlDsa
        .verify(
            p_pubkey,
            shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
            &nonce,
            &record.signature,
        )
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_crypto_pq::signature::HybridSecretKey;

    fn keypair() -> (HybridPublicKey, HybridSecretKey) {
        HybridEd25519MlDsa
            .generate_ephemeral_keypair_for_tests()
            .expect("keypair generates")
    }

    /// Sign under the attestation surface domain (SA-R-2) — one place so
    /// the domain cannot drift across the many structural tests below.
    fn att_sign(sk: &HybridSecretKey, msg: &[u8]) -> HybridSignature {
        HybridEd25519MlDsa
            .sign(
                sk,
                shekyl_crypto_pq::signature::SCHEME_DOMAIN_ATTESTATION,
                msg,
            )
            .expect("attestation sign")
    }

    /// This pubkey's canonical id — the value the record's `p_id` must equal.
    fn p_id_of(pubkey: &HybridPublicKey) -> [u8; 32] {
        let bytes = pubkey.to_canonical_bytes().expect("canonical pubkey");
        *p_canonical_id_from_hybrid_pubkey(&bytes).as_bytes()
    }

    fn pass_record(
        p_id: [u8; 32],
        shard_id: u64,
        settlement_epoch: u64,
        signature: HybridSignature,
    ) -> PassRecord {
        PassRecord {
            p_id,
            shard_id,
            settlement_epoch,
            signature,
        }
    }

    #[test]
    fn header_bytes_roundtrip_and_reject_malformed() {
        for kind in [AttestationKind::Pass, AttestationKind::Miss] {
            let h = AttestationHeader {
                p_id: [7u8; 32],
                shard_id: 42,
                settlement_epoch: 1000,
                kind,
            };
            let bytes = h.to_canonical_bytes();
            assert_eq!(bytes.len(), ATTESTATION_HEADER_LEN);
            assert_eq!(AttestationHeader::from_canonical_bytes(&bytes), Ok(h));
        }
        // Wrong length and a bad kind byte are loud errors, not silent defaults.
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&[0u8; 10]),
            Err(AttestationHeaderError::WrongLength(10))
        );
        let mut bad = AttestationHeader {
            p_id: [7u8; 32],
            shard_id: 42,
            settlement_epoch: 1000,
            kind: AttestationKind::Pass,
        }
        .to_canonical_bytes();
        bad[48] = 2;
        assert_eq!(
            AttestationHeader::from_canonical_bytes(&bad),
            Err(AttestationHeaderError::BadKind(2))
        );
    }

    #[test]
    fn pass_record_to_header_is_always_pass() {
        // Structural seam: PassRecord cannot carry Miss; wire kind is Pass.
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"x");
        let rec = pass_record([1u8; 32], 2, 3, sig);
        assert_eq!(rec.to_header().kind, AttestationKind::Pass);
    }

    #[test]
    fn nonce_binds_every_term() {
        let base = attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 5);
        // Changing any input changes the nonce (no term is dead).
        assert_ne!(base, attestation_nonce(&[9; 32], &[2; 32], &[3; 32], 4, 5)); // r
        assert_ne!(base, attestation_nonce(&[1; 32], &[9; 32], &[3; 32], 4, 5)); // cb_out_key
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[9; 32], 4, 5)); // p_id
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 9, 5)); // shard
        assert_ne!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 9)); // epoch
        assert_eq!(base, attestation_nonce(&[1; 32], &[2; 32], &[3; 32], 4, 5));
    }

    #[test]
    fn pass_record_nonce_matches_free_function() {
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"n");
        let rec = pass_record([3u8; 32], 4, 5, sig);
        let (r, cb) = ([1u8; 32], [2u8; 32]);
        assert_eq!(
            rec.nonce(&r, &cb),
            attestation_nonce(&r, &cb, &rec.p_id, rec.shard_id, rec.settlement_epoch)
        );
    }

    #[test]
    fn a_valid_countersignature_verifies_and_a_wrong_key_or_term_fails() {
        let (pubkey, secret) = keypair();
        let (r, cb) = ([11u8; 32], [22u8; 32]);
        let p_id = p_id_of(&pubkey);
        let nonce = attestation_nonce(&r, &cb, &p_id, 42, 1000);
        let sig = att_sign(&secret, &nonce);
        let rec = pass_record(p_id, 42, 1000, sig);

        assert!(verify_pass_countersignature(&r, &cb, &pubkey, &rec));

        // A signature over a DIFFERENT block's r must not verify — this is the
        // copy-freeride / cross-block replay defence at the crypto layer.
        assert!(!verify_pass_countersignature(&[99; 32], &cb, &pubkey, &rec));
        // Nor a different coinbase output key (the copy bind).
        assert!(!verify_pass_countersignature(&r, &[99; 32], &pubkey, &rec));
        // Nor a different (shard, epoch) term.
        let mut other = rec.clone();
        other.shard_id = 43;
        assert!(!verify_pass_countersignature(&r, &cb, &pubkey, &other));

        // Binding 1 in isolation: a record whose p_id is NOT this key's id fails
        // even when the signature covers that record's own nonce.
        let foreign_id = [0xABu8; 32];
        let foreign_nonce = attestation_nonce(&r, &cb, &foreign_id, 42, 1000);
        let sig_over_foreign = att_sign(&secret, &foreign_nonce);
        let foreign = pass_record(foreign_id, 42, 1000, sig_over_foreign);
        assert!(!verify_pass_countersignature(&r, &cb, &pubkey, &foreign));
    }

    #[test]
    fn attestation_root_is_defined_empty_order_independent_and_pairing_committed() {
        // Defined-empty (§3.2 invariant): the empty set has a fixed root, never
        // omitted, so the merkle leaf and count never desync.
        let empty = attestation_root(&[]).unwrap();
        assert_eq!(empty, attestation_root(&[]).unwrap());

        let (_pk, sk) = keypair();
        let s1 = att_sign(&sk, b"a");
        let s2 = att_sign(&sk, b"b");
        let r1 = pass_record([7u8; 32], 42, 1000, s1.clone());
        let r2 = pass_record([7u8; 32], 43, 1000, s2.clone());

        // A non-empty set differs from empty.
        assert_ne!(attestation_root(std::slice::from_ref(&r1)).unwrap(), empty);

        // ORDER-INDEPENDENT: the internal sort yields one canonical order.
        let ab = attestation_root(&[r1.clone(), r2.clone()]).unwrap();
        let ba = attestation_root(&[r2.clone(), r1.clone()]).unwrap();
        assert_eq!(ab, ba);

        // PAIRING IS COMMITTED: swapping which signature rides which terms
        // changes the root.
        let swapped = attestation_root(&[
            pass_record(r1.p_id, r1.shard_id, r1.settlement_epoch, s2),
            pass_record(r2.p_id, r2.shard_id, r2.settlement_epoch, s1),
        ])
        .unwrap();
        assert_ne!(ab, swapped);
    }

    #[test]
    fn witness_roundtrips_including_empty() {
        let (_pk, sk) = keypair();
        let s0 = att_sign(&sk, b"w0");
        let s1 = att_sign(&sk, b"w1");
        let w = BlockAttestationWitness {
            r: [0x5A; 32],
            pass_signatures: vec![s0, s1],
        };
        let bytes = w.to_canonical_bytes().unwrap();
        // Layout: r(32) ‖ count_le(8) ‖ 2 × CANONICAL_LEN.
        assert_eq!(
            bytes.len(),
            WITNESS_PREFIX_LEN + 2 * HybridSignature::CANONICAL_LEN
        );
        assert_eq!(&bytes[0..32], &[0x5A; 32]);
        assert_eq!(&bytes[32..WITNESS_PREFIX_LEN], &2u64.to_le_bytes());
        assert_eq!(
            BlockAttestationWitness::from_canonical_bytes(&bytes).unwrap(),
            w
        );

        // Codec-defined-empty: a zero-signature witness is still a valid
        // `r ‖ count=0` encoding. That is distinct from the C++ side-table
        // convention, which skips writing a row for empty/absent witnesses
        // (interim / all-miss blocks store nothing; absent key ≡ no witness).
        let empty = BlockAttestationWitness {
            r: [1; 32],
            pass_signatures: vec![],
        };
        let eb = empty.to_canonical_bytes().unwrap();
        assert_eq!(eb.len(), WITNESS_PREFIX_LEN);
        assert_eq!(
            BlockAttestationWitness::from_canonical_bytes(&eb).unwrap(),
            empty
        );
    }

    #[test]
    fn witness_decode_rejects_malformed() {
        let (_pk, sk) = keypair();
        let s0 = att_sign(&sk, b"w");
        let good = BlockAttestationWitness {
            r: [7; 32],
            pass_signatures: vec![s0],
        }
        .to_canonical_bytes()
        .unwrap();

        // Short prefix.
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&[0u8; WITNESS_PREFIX_LEN - 1]),
            Err(WitnessError::TooShort(n)) if n == WITNESS_PREFIX_LEN - 1
        ));

        // Declares one signature, carries none.
        let mut short_body = Vec::new();
        short_body.extend_from_slice(&[0u8; 32]);
        short_body.extend_from_slice(&1u64.to_le_bytes());
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&short_body),
            Err(WitnessError::LengthMismatch {
                count: 1,
                got: WITNESS_PREFIX_LEN,
                ..
            })
        ));

        // Over-cap count is rejected before allocating — a hostile u64 cannot
        // trigger a `count · CANONICAL_LEN` reservation.
        let mut over = Vec::new();
        over.extend_from_slice(&[0u8; 32]);
        over.extend_from_slice(&((MAX_ATTESTATION_RECORDS as u64) + 1).to_le_bytes());
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&over),
            Err(WitnessError::CountExceedsCap(n)) if n == MAX_ATTESTATION_RECORDS as u64 + 1
        ));

        // Corrupt the first signature's leading version byte.
        let mut corrupt = good.clone();
        corrupt[WITNESS_PREFIX_LEN] ^= 0xFF;
        assert!(matches!(
            BlockAttestationWitness::from_canonical_bytes(&corrupt),
            Err(WitnessError::Signature { index: 0, .. })
        ));
    }

    #[test]
    fn witness_encode_rejects_over_cap() {
        let (_pk, sk) = keypair();
        let sig = att_sign(&sk, b"x");
        let over = BlockAttestationWitness {
            r: [0; 32],
            pass_signatures: vec![sig; MAX_ATTESTATION_RECORDS + 1],
        };
        assert!(matches!(
            over.to_canonical_bytes(),
            Err(WitnessError::CountExceedsCap(n)) if n == (MAX_ATTESTATION_RECORDS as u64) + 1
        ));
    }

    #[test]
    fn pairing_zips_pass_headers_and_reproduces_the_root() {
        // Two pass records with a MISS interleaved: the witness holds only the
        // two pass signatures, and the zip must skip the miss.
        let (pk, sk) = keypair();
        let p_id = p_id_of(&pk);
        let (r, cb) = ([3u8; 32], [4u8; 32]);
        let sig_for = |shard: u64, epoch: u64| {
            let nonce = attestation_nonce(&r, &cb, &p_id, shard, epoch);
            att_sign(&sk, &nonce)
        };
        let s_a = sig_for(10, 1000);
        let s_b = sig_for(20, 1000);

        let headers = vec![
            AttestationHeader {
                p_id,
                shard_id: 10,
                settlement_epoch: 1000,
                kind: AttestationKind::Pass,
            },
            AttestationHeader {
                p_id,
                shard_id: 99,
                settlement_epoch: 1000,
                kind: AttestationKind::Miss,
            },
            AttestationHeader {
                p_id,
                shard_id: 20,
                settlement_epoch: 1000,
                kind: AttestationKind::Pass,
            },
        ];
        let witness = BlockAttestationWitness {
            r,
            pass_signatures: vec![s_a.clone(), s_b.clone()],
        };

        let records = pass_records_from_headers_and_witness(&headers, &witness).unwrap();
        assert_eq!(records.len(), 2);
        // The reconstructed records verify against P (pairing landed correctly).
        for rec in &records {
            assert!(verify_pass_countersignature(&r, &cb, &pk, rec));
        }
        // And their root matches the direct construction from the same pairs.
        let direct = attestation_root(&[
            pass_record(p_id, 10, 1000, s_a.clone()),
            pass_record(p_id, 20, 1000, s_b.clone()),
        ])
        .unwrap();
        assert_eq!(attestation_root(&records).unwrap(), direct);

        // A count mismatch (one pass header dropped from the witness) is loud.
        let short_witness = BlockAttestationWitness {
            r,
            pass_signatures: vec![s_a.clone()],
        };
        assert_eq!(
            pass_records_from_headers_and_witness(&headers, &short_witness).unwrap_err(),
            WitnessPairingError {
                pass_headers: 2,
                signatures: 1
            }
        );

        // PAIRING-SWAP NEGATIVE CONTROL: feeding the two pass signatures in the
        // wrong order mis-binds each sig to the other's terms, so the recomputed
        // root differs — the property the cross-language KAT extends over the FFI.
        let swapped_witness = BlockAttestationWitness {
            r,
            pass_signatures: vec![s_b, s_a],
        };
        let swapped = pass_records_from_headers_and_witness(&headers, &swapped_witness).unwrap();
        assert_ne!(attestation_root(&swapped).unwrap(), direct);
    }
}
