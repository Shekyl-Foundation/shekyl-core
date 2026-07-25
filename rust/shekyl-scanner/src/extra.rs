// Copyright (c) 2025-2026, The Shekyl Foundation
//
// Adapted from monero-oxide (shekyl-wallet), MIT license.
// All rights reserved.
// BSD-3-Clause

//! Transaction extra field parsing with Shekyl extensions.
//!
//! Extends the standard extra field with tags for:
//! - 0x06: PQC KEM ciphertext (hybrid X25519 + ML-KEM-768)
//! - 0x07: PQC leaf hash commitments (for FCMP++ binding)

use std::io::{self, BufRead, Write};

use zeroize::Zeroize;

use curve25519_dalek::edwards::EdwardsPoint;

use shekyl_curve_io::*;

// PaymentId moved to `shekyl-engine-state`; re-exported here so `crate::extra::PaymentId`
// and `use crate::extra::PaymentId` continue to resolve while the migration is in flight.
pub use shekyl_engine_state::PaymentId;

pub(crate) const MAX_TX_EXTRA_PADDING_COUNT: usize = 255;
const MAX_TX_EXTRA_NONCE_SIZE: usize = 255;

pub(crate) const ARBITRARY_DATA_MARKER: u8 = 127;

/// The maximum length for data within an arbitrary-data nonce.
pub const MAX_ARBITRARY_DATA_SIZE: usize = MAX_TX_EXTRA_NONCE_SIZE - 1;

/// The maximum length for a transaction's extra under current relay rules.
pub const MAX_EXTRA_SIZE_BY_RELAY_RULE: usize = 1060;

/// Shekyl tx_extra tag for hybrid KEM ciphertext (X25519 + ML-KEM-768).
pub const TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT: u8 = 0x06;

/// Shekyl tx_extra tag for PQC leaf hash commitments.
pub const TX_EXTRA_TAG_PQC_LEAF_HASHES: u8 = 0x07;

/// A field within the TX extra.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum ExtraField {
    /// Padding (block of zeroes).
    Padding(usize),
    /// The transaction key (commitment to randomness for output derivation).
    PublicKey(EdwardsPoint),
    /// Nonce field (used for payment IDs and arbitrary data).
    Nonce(Vec<u8>),
    /// Merge-mining field.
    MergeMining(u64, [u8; 32]),
    /// Additional per-output transaction keys.
    PublicKeys(Vec<EdwardsPoint>),
    /// Minergate tag (closed-source, parsed for completeness).
    MysteriousMinergate(Vec<u8>),
    /// PQC KEM ciphertext blob (Shekyl tag 0x06).
    PqcKemCiphertext(Vec<u8>),
    /// PQC leaf hash commitments (Shekyl tag 0x07).
    PqcLeafHashes(Vec<u8>),
}

impl ExtraField {
    /// Write the ExtraField.
    pub fn write<W: Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            ExtraField::Padding(size) => {
                w.write_all(&[0])?;
                for _ in 1..*size {
                    write_byte(&0u8, w)?;
                }
            }
            ExtraField::PublicKey(key) => {
                w.write_all(&[1])?;
                w.write_all(&key.compress().to_bytes())?;
            }
            ExtraField::Nonce(data) => {
                w.write_all(&[2])?;
                write_vec(write_byte, data, w)?;
            }
            ExtraField::MergeMining(height, merkle) => {
                w.write_all(&[3])?;
                write_varint(height, w)?;
                w.write_all(merkle)?;
            }
            ExtraField::PublicKeys(keys) => {
                w.write_all(&[4])?;
                write_vec(write_point, keys, w)?;
            }
            ExtraField::MysteriousMinergate(data) => {
                w.write_all(&[0xDE])?;
                write_vec(write_byte, data, w)?;
            }
            ExtraField::PqcKemCiphertext(data) => {
                w.write_all(&[TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT])?;
                write_vec(write_byte, data, w)?;
            }
            ExtraField::PqcLeafHashes(data) => {
                w.write_all(&[TX_EXTRA_TAG_PQC_LEAF_HASHES])?;
                write_vec(write_byte, data, w)?;
            }
        }
        Ok(())
    }

    /// Serialize the ExtraField to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut res = Vec::with_capacity(1 + 8);
        self.write(&mut res)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        res
    }

    /// Read an ExtraField.
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<ExtraField> {
        Ok(match read_byte(r)? {
            0 => ExtraField::Padding({
                let mut size: usize = 1;
                loop {
                    let buf = r.fill_buf()?;
                    let mut n_consume = 0;
                    for v in buf {
                        if *v != 0u8 {
                            Err(io::Error::other("non-zero value after padding"))?
                        }
                        n_consume += 1;
                        size += 1;
                        if size > MAX_TX_EXTRA_PADDING_COUNT {
                            Err(io::Error::other("padding exceeded max count"))?
                        }
                    }
                    if n_consume == 0 {
                        break;
                    }
                    r.consume(n_consume);
                }
                size
            }),
            1 => ExtraField::PublicKey(read_point(r)?),
            2 => ExtraField::Nonce(read_vec(read_byte, Some(MAX_TX_EXTRA_NONCE_SIZE), r)?),
            3 => ExtraField::MergeMining(read_varint(r)?, read_bytes(r)?),
            4 => ExtraField::PublicKeys(read_vec(read_point, None, r)?),
            TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT => {
                ExtraField::PqcKemCiphertext(read_vec(read_byte, None, r)?)
            }
            TX_EXTRA_TAG_PQC_LEAF_HASHES => {
                ExtraField::PqcLeafHashes(read_vec(read_byte, None, r)?)
            }
            0xDE => ExtraField::MysteriousMinergate(read_vec(read_byte, None, r)?),
            _ => Err(io::Error::other("unknown extra field"))?,
        })
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
    pub fn arbitrary_data(&self) -> Vec<Vec<u8>> {
        let serialized = self.serialize();
        let bounded_extra =
            Self::read(&mut &serialized[..serialized.len().min(MAX_EXTRA_SIZE_BY_RELAY_RULE)])
                .expect("`Extra::read` only fails if the IO fails and `&[u8]` won't");

        let mut res = vec![];
        for field in &bounded_extra.0 {
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
    /// proof-check path, `shekyl-wire::tx_extra::pqc_kem_per_output`,
    /// and the C++ `wallet2` reader) — and the C++ writers
    /// (`cryptonote_tx_utils.cpp` coinbase/genesis/transfer) emit the
    /// same single concatenated field. This writer's pre-fix
    /// one-field-per-output packing was the sole deviant and made
    /// every output at vout ≥ 1 — including all change — silently
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
        for field in &self.0 {
            field.write(w)?;
        }
        Ok(())
    }

    /// Serialize the Extra to a `Vec<u8>`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        self.write(&mut buf)
            .expect("write failed but <Vec as io::Write> doesn't fail");
        buf
    }

    /// Read an `Extra`.
    #[allow(clippy::unnecessary_wraps)]
    pub fn read<R: BufRead>(r: &mut R) -> io::Result<Extra> {
        let mut res = Extra(vec![]);
        while !r.fill_buf()?.is_empty() {
            let Ok(field) = ExtraField::read(r) else {
                break;
            };
            res.0.push(field);
        }
        Ok(res)
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
