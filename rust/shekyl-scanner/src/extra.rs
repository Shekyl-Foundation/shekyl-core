// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Scan-side view of transaction `extra`.
//!
//! The genesis tag set and its codec live in [`shekyl_wire::tx_extra`]
//! (`GENESIS_TX_WIRE_FORMAT.md` §9.6a). This module does not re-implement
//! that grammar: [`Extra::read`] parses through `shekyl-wire` and keeps the
//! fields the scanner needs (tx pubkeys, nonce, `0x06`/`0x07`). Genesis tags
//! the scan path does not consume — including `0x0B` archival attestation —
//! are skipped rather than treated as unknown. Retired inherited tags
//! (`0x03`, `0xDE`) fail closed with the wire parser.

use std::io::{self, BufRead, Write};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use shekyl_curve_io::CompressedPoint;
use shekyl_wire::tx_extra::{self, TxExtraField};

// PaymentId moved to `shekyl-engine-state`; re-exported here so `crate::extra::PaymentId`
// and `use crate::extra::PaymentId` continue to resolve while the migration is in flight.
pub use shekyl_engine_state::PaymentId;

const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

pub(crate) const ARBITRARY_DATA_MARKER: u8 = 127;

/// The maximum length for data within an arbitrary-data nonce.
pub const MAX_ARBITRARY_DATA_SIZE: usize = MAX_TX_EXTRA_NONCE_SIZE - 1;

/// The maximum length for a transaction's extra under current relay rules.
pub const MAX_EXTRA_SIZE_BY_RELAY_RULE: usize = 1060;

/// Shekyl tx_extra tag for hybrid KEM ciphertext (X25519 + ML-KEM-768).
pub const TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT: u8 = tx_extra::TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT;

/// Shekyl tx_extra tag for PQC leaf hash commitments.
pub const TX_EXTRA_TAG_PQC_LEAF_HASHES: u8 = tx_extra::TX_EXTRA_TAG_PQC_LEAF_HASHES;

/// A field within the TX extra.
///
/// This is the scanner's typed view, not a second codec. Parse and serialize
/// go through [`shekyl_wire::tx_extra`]. Variants that existed only to admit
/// inherited merge-mining (`0x03`) and minergate (`0xDE`) are gone: those
/// tags are not in the genesis grammar, and a wallet extra that could emit
/// them would be refused at admission.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum ExtraField {
    /// Padding (block of zeroes).
    Padding(usize),
    /// The transaction key (commitment to randomness for output derivation).
    PublicKey(EdwardsPoint),
    /// Nonce field (used for payment IDs and arbitrary data).
    Nonce(Vec<u8>),
    /// Additional per-output transaction keys.
    PublicKeys(Vec<EdwardsPoint>),
    /// PQC KEM ciphertext blob (Shekyl tag 0x06).
    PqcKemCiphertext(Vec<u8>),
    /// PQC leaf hash commitments (Shekyl tag 0x07).
    PqcLeafHashes(Vec<u8>),
}

fn decompress_key(bytes: [u8; 32]) -> Option<EdwardsPoint> {
    CompressedPoint(bytes).decompress()
}

impl ExtraField {
    fn to_wire(&self) -> TxExtraField {
        match self {
            ExtraField::Padding(n) => TxExtraField::Padding(*n),
            ExtraField::PublicKey(key) => TxExtraField::PubKey(key.compress().to_bytes()),
            ExtraField::Nonce(data) => TxExtraField::Nonce(data.clone()),
            ExtraField::PublicKeys(keys) => TxExtraField::AdditionalPubKeys(
                keys.iter().map(|key| key.compress().to_bytes()).collect(),
            ),
            ExtraField::PqcKemCiphertext(data) => TxExtraField::PqcKemCiphertext(data.clone()),
            ExtraField::PqcLeafHashes(data) => TxExtraField::PqcLeafHashes(data.clone()),
        }
    }

    /// Map a genesis wire field into the scan view. Returns `None` for
    /// genesis tags the scanner does not consume, and for `0x01`/`0x04`
    /// fields whose bytes are not a canonical Edwards point.
    ///
    /// Admission treats those 32-byte keys as opaque (`shekyl-wire`
    /// `PubKey([u8; 32])`), so a consensus-valid extra can carry a
    /// non-point. Failing the whole extra would drop a present `0x06`/`0x07`
    /// and make curve-tree decode fall back to zero `h_pqc`. A bad `0x04`
    /// is skipped as a field — dropping individual keys would shift later
    /// per-output additional keys.
    fn try_from_wire(field: TxExtraField) -> Option<Self> {
        match field {
            TxExtraField::Padding(n) => Some(ExtraField::Padding(n)),
            TxExtraField::PubKey(bytes) => decompress_key(bytes).map(ExtraField::PublicKey),
            TxExtraField::Nonce(data) => Some(ExtraField::Nonce(data)),
            TxExtraField::AdditionalPubKeys(keys) => {
                let mut pts = Vec::with_capacity(keys.len());
                for key in keys {
                    pts.push(decompress_key(key)?);
                }
                Some(ExtraField::PublicKeys(pts))
            }
            TxExtraField::PqcKemCiphertext(data) => Some(ExtraField::PqcKemCiphertext(data)),
            TxExtraField::PqcLeafHashes(data) => Some(ExtraField::PqcLeafHashes(data)),
            TxExtraField::PqcOwnership(_)
            | TxExtraField::MultisigMigration(_)
            | TxExtraField::PqcViewTagHints(_)
            | TxExtraField::PqcSpendAuthPubkeys(_)
            | TxExtraField::ArchivalAttestation(_) => None,
        }
    }

    /// Write the ExtraField through the `shekyl-wire` codec.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.serialize())
    }

    /// Serialize the ExtraField to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        tx_extra::serialize(&[self.to_wire()])
            .expect("scan ExtraField values are within shekyl-wire serialize caps")
    }
}

/// The result of decoding a transaction's extra field.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Extra(pub(crate) Vec<ExtraField>);

impl Extra {
    /// The keys within this extra.
    ///
    /// Returns all `PublicKey` fields and the first set of `PublicKeys`.
    pub fn keys(&self) -> Option<(Vec<EdwardsPoint>, Option<Vec<EdwardsPoint>>)> {
        let mut keys = vec![];
        let mut additional = None;
        for field in &self.0 {
            match field.clone() {
                ExtraField::PublicKey(this_key) => keys.push(this_key),
                ExtraField::PublicKeys(these_additional) => {
                    additional = additional.or(Some(these_additional))
                }
                _ => (),
            }
        }
        if keys.is_empty() {
            None
        } else {
            Some((keys, additional))
        }
    }

    /// The payment ID embedded within this extra.
    pub fn payment_id(&self) -> Option<PaymentId> {
        for field in &self.0 {
            if let ExtraField::Nonce(data) = field {
                let mut reader = data.as_slice();
                let res = PaymentId::read(&mut reader).ok();
                if !reader.is_empty() {
                    None?;
                }
                return res;
            }
        }
        None
    }

    /// The arbitrary data within this extra.
    ///
    /// Walks the already-parsed nonce fields. Re-serializing and re-parsing a
    /// truncated blob was inherited "parse what you can" behaviour; with
    /// `shekyl-wire` as the codec a mid-field truncate is an error, not a
    /// partial extra, and PQC extras routinely exceed the old 1060-byte
    /// relay cap.
    pub fn arbitrary_data(&self) -> Vec<Vec<u8>> {
        let mut res = vec![];
        for field in &self.0 {
            if let ExtraField::Nonce(data) = field {
                if data.first() == Some(&ARBITRARY_DATA_MARKER) {
                    res.push(data[1..].to_vec());
                }
            }
        }
        res
    }

    /// Extract PQC KEM ciphertext blob from the extra fields.
    pub fn pqc_kem_ciphertext(&self) -> Option<&[u8]> {
        for field in &self.0 {
            if let ExtraField::PqcKemCiphertext(data) = field {
                return Some(data);
            }
        }
        None
    }

    /// Extract PQC leaf hash commitments from the extra fields.
    pub fn pqc_leaf_hashes(&self) -> Option<&[u8]> {
        for field in &self.0 {
            if let ExtraField::PqcLeafHashes(data) = field {
                return Some(data);
            }
        }
        None
    }

    /// Transaction extra for a hybrid-PQC transfer: tx pubkey plus ONE
    /// `0x06` field carrying every output's KEM ciphertext concatenated
    /// in output order (`n_out × HYBRID_KEM_CT_LEN` bytes).
    ///
    /// The single-field packing is the read-side contract everywhere:
    /// [`Extra::pqc_kem_ciphertext`] is first-match and every consumer
    /// slices output `o`'s ciphertext at `o * HYBRID_KEM_CT_LEN` within
    /// that one blob (`shekyl-scanner`'s scan path, the engine
    /// proof-check path, and `shekyl-wire::tx_extra::pqc_kem_per_output`)
    /// — and the writers (`cryptonote_tx_utils.cpp` coinbase/genesis/transfer,
    /// until those move) emit the same single concatenated field. This
    /// writer's pre-fix one-field-per-output packing was the sole deviant
    /// and made every output at vout ≥ 1 — including all change — silently
    /// unscannable (`FOLLOWUPS.md` "KEM-ciphertext extra packing
    /// mismatch", 2026-07-24).
    ///
    /// # Panics
    ///
    /// Panics if any ciphertext is not exactly
    /// [`shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN`] bytes. Because
    /// readers slice the blob at fixed offsets, a single wrong-length
    /// entry would shift every later output's slice and silently make
    /// those vouts unscannable — the same failure class the
    /// single-field packing fix closed. The lengths are fixed by the
    /// KEM algorithms, so a violation is a caller bug, not an input
    /// this function can validate away: the panic aborts transaction
    /// assembly while the transaction is still local — before signing
    /// and broadcast — rather than publishing outputs the recipient
    /// can never see.
    pub fn for_hybrid_transfer(
        tx_pubkey: EdwardsPoint,
        kem_ciphertexts: impl IntoIterator<Item = Vec<u8>>,
    ) -> Extra {
        use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;

        let kem_ciphertexts = kem_ciphertexts.into_iter();
        let mut blob = Vec::with_capacity(kem_ciphertexts.size_hint().0 * HYBRID_KEM_CT_LEN);
        for (vout, kem) in kem_ciphertexts.enumerate() {
            assert_eq!(
                kem.len(),
                HYBRID_KEM_CT_LEN,
                "output {vout}: hybrid KEM ciphertext must be exactly \
                 HYBRID_KEM_CT_LEN ({HYBRID_KEM_CT_LEN}) bytes — a wrong-length \
                 entry shifts every later output's slice offset",
            );
            blob.extend_from_slice(&kem);
        }
        let mut fields = vec![ExtraField::PublicKey(tx_pubkey)];
        if !blob.is_empty() {
            fields.push(ExtraField::PqcKemCiphertext(blob));
        }
        Extra(fields)
    }

    /// Append a PQC leaf-hash commitment field (Shekyl tag `0x07`,
    /// `N × 32` bytes — `H(pqc_pk)` per output, in output order).
    ///
    /// The daemon's curve-tree ingestion reads this field to set each new
    /// output's `h_pqc` leaf component; an output ingested **without** it
    /// carries a zero leaf hash and can never satisfy the spend-side
    /// `pqc_auths`-derived hash check — i.e. it is unspendable. Every
    /// transaction whose outputs must be spendable appends this field:
    /// bond-post/emission change (stake_engine.rs) and the ordinary
    /// transfer path (sign_bridge.rs; its omission there made every
    /// transfer output unspendable — surfaced live by the PR-4b bond e2e).
    pub fn push_pqc_leaf_hashes(&mut self, blob: Vec<u8>) {
        self.0.push(ExtraField::PqcLeafHashes(blob));
    }

    #[allow(dead_code)]
    pub(crate) fn new(key: EdwardsPoint, additional: Vec<EdwardsPoint>) -> Extra {
        let mut res = Extra(Vec::with_capacity(3));
        res.0.push(ExtraField::PublicKey(key));
        if !additional.is_empty() {
            res.0.push(ExtraField::PublicKeys(additional));
        }
        res
    }

    #[allow(dead_code)]
    pub(crate) fn push_nonce(&mut self, nonce: Vec<u8>) {
        self.0.push(ExtraField::Nonce(nonce));
    }

    /// Write the Extra.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.serialize())
    }

    /// Serialize the Extra to a `Vec<u8>` through the `shekyl-wire` codec.
    pub fn serialize(&self) -> Vec<u8> {
        let fields: Vec<TxExtraField> = self.0.iter().map(ExtraField::to_wire).collect();
        tx_extra::serialize(&fields)
            .expect("scan ExtraField values are within shekyl-wire serialize caps")
    }

    /// Read an `Extra` through [`shekyl_wire::tx_extra::parse`]. An unknown
    /// or retired tag is an error — extras that cannot exist at admission
    /// are not scanned as a partial field list. A well-formed extra whose
    /// `0x01`/`0x04` bytes are not Edwards points still yields its other
    /// fields; those keys are simply absent from the scan view.
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<Extra> {
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        let parsed = tx_extra::parse(&buf)?;
        let mut fields = Vec::with_capacity(parsed.len());
        for field in parsed {
            if let Some(mapped) = ExtraField::try_from_wire(field) {
                fields.push(mapped);
            }
        }
        Ok(Extra(fields))
    }
}

#[cfg(test)]
mod pqc_leaf_hashes_tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    fn leaf_blob(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from(i).expect("test fixture n <= 256"))
            .collect()
    }

    /// Scanner first-match behavior. Daemon parity on duplicate/malformed `0x07`
    /// is unverified — owned by the Tier-B seam test (`recon_tier_b.rs`).
    #[test]
    fn pqc_leaf_hashes_round_trip() {
        let payload = leaf_blob(64);
        let field = ExtraField::PqcLeafHashes(payload.clone());
        let mut wire = Vec::new();
        field.write(&mut wire).unwrap();
        let extra = Extra::read(&mut wire.as_slice()).unwrap();
        assert_eq!(extra.pqc_leaf_hashes(), Some(payload.as_slice()));
    }

    #[test]
    fn pqc_leaf_hashes_after_pubkey_field() {
        let payload = leaf_blob(32);
        let extra = Extra(vec![
            ExtraField::PublicKey(ED25519_BASEPOINT_POINT),
            ExtraField::PqcLeafHashes(payload.clone()),
        ]);
        let wire = extra.serialize();
        let parsed = Extra::read(&mut wire.as_slice()).unwrap();
        assert_eq!(parsed.pqc_leaf_hashes(), Some(payload.as_slice()));
    }

    #[test]
    fn pqc_leaf_hashes_duplicate_tag_returns_first_match() {
        let first = leaf_blob(32);
        let second = leaf_blob(64);
        let extra = Extra(vec![
            ExtraField::PqcLeafHashes(first.clone()),
            ExtraField::PqcLeafHashes(second),
        ]);
        let wire = extra.serialize();
        let parsed = Extra::read(&mut wire.as_slice()).unwrap();
        assert_eq!(parsed.pqc_leaf_hashes(), Some(first.as_slice()));
    }

    /// Retired inherited tags must fail closed. The previous ExtraField
    /// grammar admitted `0x03`/`0xDE` and Extra::read stopped on unknown
    /// rather than erroring, so a wallet extra could still carry tags
    /// admission now rejects.
    #[test]
    fn retired_inherited_tags_fail_closed() {
        let err = Extra::read(&mut [0x03, 0x21, 0x00].as_slice()).unwrap_err();
        assert!(
            err.to_string().contains("unknown tag"),
            "0x03 must fail as unknown, got {err}"
        );
        let err = Extra::read(&mut [0xDE, 0x00].as_slice()).unwrap_err();
        assert!(
            err.to_string().contains("unknown tag"),
            "0xDE must fail as unknown, got {err}"
        );
    }

    /// Admission treats `0x01` as opaque 32 bytes. A non-point must not fail
    /// the extra: scan simply has no tx pubkey, and `0x06`/`0x07` still land.
    #[test]
    fn invalid_tx_pubkey_does_not_drop_pqc_fields() {
        use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
        let kem = vec![0xAA; HYBRID_KEM_CT_LEN];
        let leaf = leaf_blob(32);
        let wire = tx_extra::serialize(&[
            TxExtraField::PubKey([0xFF; 32]),
            TxExtraField::PqcKemCiphertext(kem.clone()),
            TxExtraField::PqcLeafHashes(leaf.clone()),
        ])
        .expect("opaque-key extra serializes");
        let parsed = Extra::read(&mut wire.as_slice()).expect("well-formed extra parses");
        assert!(
            parsed.keys().is_none(),
            "a non-point 0x01 is absent from the scan view"
        );
        assert_eq!(parsed.pqc_kem_ciphertext(), Some(kem.as_slice()));
        assert_eq!(parsed.pqc_leaf_hashes(), Some(leaf.as_slice()));
    }

    /// A mixed `0x04` list must not shift: one non-point drops the whole
    /// additional-keys field, not later keys, and does not hide `0x07`.
    #[test]
    fn invalid_additional_pubkey_skips_the_field_not_the_extra() {
        let leaf = leaf_blob(32);
        let good = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let wire = tx_extra::serialize(&[
            TxExtraField::AdditionalPubKeys(vec![good, [0xFF; 32]]),
            TxExtraField::PqcLeafHashes(leaf.clone()),
        ])
        .expect("mixed additional-keys extra serializes");
        let parsed = Extra::read(&mut wire.as_slice()).expect("well-formed extra parses");
        assert!(
            parsed.keys().is_none(),
            "a 0x04 field with any non-point is skipped whole"
        );
        assert_eq!(parsed.pqc_leaf_hashes(), Some(leaf.as_slice()));
    }

    /// A genesis tag the scanner does not consume must not hide `0x06`/`0x07`.
    /// The inherited Extra::read stopped at the first unknown tag; `0x0B` is
    /// in the grammar, so stopping would drop the PQC scan fields whenever
    /// an attestation appears before them.
    #[test]
    fn attestation_does_not_hide_pqc_scan_fields() {
        use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;
        let pk = ED25519_BASEPOINT_POINT.compress().to_bytes();
        let kem = vec![0xAA; HYBRID_KEM_CT_LEN];
        let leaf = leaf_blob(32);
        let wire = tx_extra::serialize(&[
            TxExtraField::ArchivalAttestation(vec![0xA7; 16]),
            TxExtraField::PubKey(pk),
            TxExtraField::PqcKemCiphertext(kem.clone()),
            TxExtraField::PqcLeafHashes(leaf.clone()),
        ])
        .expect("genesis extra serializes");
        let parsed = Extra::read(&mut wire.as_slice()).expect("attestation-bearing extra parses");
        assert_eq!(parsed.pqc_kem_ciphertext(), Some(kem.as_slice()));
        assert_eq!(parsed.pqc_leaf_hashes(), Some(leaf.as_slice()));
        assert!(
            parsed.keys().is_some(),
            "tx pubkey after an attestation field must still be visible"
        );
    }
}

#[cfg(test)]
mod hybrid_transfer_packing_tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN;

    fn ct(fill: u8) -> Vec<u8> {
        vec![fill; HYBRID_KEM_CT_LEN]
    }

    /// The write-side half of the single-field packing contract: one
    /// `0x06` field, ciphertexts concatenated in output order, so the
    /// readers' `o * HYBRID_KEM_CT_LEN` slicing recovers each entry.
    #[test]
    fn for_hybrid_transfer_packs_one_field_in_output_order() {
        let extra = Extra::for_hybrid_transfer(ED25519_BASEPOINT_POINT, [ct(0xAA), ct(0xBB)]);
        let blob = extra.pqc_kem_ciphertext().expect("one 0x06 field present");
        assert_eq!(blob.len(), 2 * HYBRID_KEM_CT_LEN);
        assert_eq!(&blob[..HYBRID_KEM_CT_LEN], ct(0xAA).as_slice());
        assert_eq!(&blob[HYBRID_KEM_CT_LEN..], ct(0xBB).as_slice());
        let n_kem_fields = extra
            .0
            .iter()
            .filter(|f| matches!(f, ExtraField::PqcKemCiphertext(_)))
            .count();
        assert_eq!(n_kem_fields, 1, "exactly one concatenated 0x06 field");
    }

    /// A wrong-length ciphertext must refuse loudly at construction —
    /// packed as-is it would shift every later output's slice offset
    /// and silently make those vouts unscannable.
    #[test]
    #[should_panic(expected = "hybrid KEM ciphertext must be exactly")]
    fn for_hybrid_transfer_rejects_wrong_length_ciphertext() {
        let short = vec![0xCC; HYBRID_KEM_CT_LEN - 1];
        let _ = Extra::for_hybrid_transfer(ED25519_BASEPOINT_POINT, [ct(0xAA), short]);
    }
}
