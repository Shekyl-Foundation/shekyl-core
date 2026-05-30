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

use shekyl_oxide::io::*;

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
