// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `tx_extra` TLV parsing (GENESIS_TX_WIRE_FORMAT.md §9.6a).
//!
//! The transaction `extra` blob is kept **opaque** (`Vec<u8>`) on
//! [`crate::TxPrefix`] so block/tx round-trip is byte-trivial; this module is the
//! additive, structured view over it. It parses the tag-prefixed field sequence
//! and re-serializes it byte-identically, and gives **per-output** access to the
//! PQC scan fields — `0x06` hybrid KEM ciphertexts (`x25519 ‖ ML-KEM-768` per
//! output) and `0x07` leaf hashes (`h_pqc` per output).
//!
//! Tag grammars are transcribed from `src/cryptonote_basic/tx_extra.h`. Most tags
//! are `tag · V(len) · blob` (`FIELD(std::string)`); `0x01` is a bare 32-byte key;
//! `0x04` is `V(count) · count×32`; `0x05` is `V(count) · count×{u8,u8,[32]}`;
//! `0x00` padding is a run of zero bytes to the end of `extra`.

use std::io::{self, Read, Write};

use crate::bytes::{read_array, read_byte};
use crate::varint::{read_varint, write_varint};

/// `0x00` — padding (a run of zero bytes to the end of `extra`).
pub const TX_EXTRA_TAG_PADDING: u8 = 0x00;
/// `0x01` — transaction public key.
pub const TX_EXTRA_TAG_PUBKEY: u8 = 0x01;
/// `0x02` — extra nonce.
pub const TX_EXTRA_TAG_NONCE: u8 = 0x02;
/// `0x04` — additional per-output tx public keys.
pub const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;
/// `0x05` — PQC ownership entries.
pub const TX_EXTRA_TAG_PQC_OWNERSHIP: u8 = 0x05;
/// `0x06` — per-output hybrid KEM ciphertexts.
pub const TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT: u8 = 0x06;
/// `0x07` — per-output PQC leaf hashes.
pub const TX_EXTRA_TAG_PQC_LEAF_HASHES: u8 = 0x07;
/// `0x08` — multisig migration blob.
pub const TX_EXTRA_TAG_MULTISIG_MIGRATION: u8 = 0x08;
/// `0x09` — PQC view-tag hints blob.
pub const TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS: u8 = 0x09;
/// `0x0A` — PQC spend-auth pubkeys blob.
pub const TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS: u8 = 0x0A;

/// X25519 ciphertext bytes per output (`tx_extra.h`).
pub const X25519_CT_BYTES: usize = 32;
/// ML-KEM-768 ciphertext bytes per output (`tx_extra.h`).
pub const ML_KEM_768_CT_BYTES: usize = 1088;
/// Hybrid KEM ciphertext bytes per output (`32 + 1088`).
pub const HYBRID_KEM_CT_BYTES: usize = X25519_CT_BYTES + ML_KEM_768_CT_BYTES;
/// PQC leaf-hash bytes per output.
pub const PQC_LEAF_HASH_BYTES: usize = 32;

/// Parse-safety cap on declared lengths/counts.
const READ_LEN_CAP: usize = 1_000_000;

/// A single `0x05` PQC ownership entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PqcOwnershipEntry {
    /// Output index this entry covers.
    pub output_index: u8,
    /// Scheme id (`1` single-signer, `2` multisig).
    pub scheme_id: u8,
    /// Group id (zero-hash for single-signer).
    pub group_id: [u8; 32],
}

/// A parsed `tx_extra` field. The `0x06`/`0x07` payloads are kept as concatenated
/// blobs (their on-wire form); use [`pqc_kem_per_output`] / [`pqc_leaf_hashes_per_output`]
/// to split them by output count.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TxExtraField {
    /// `0x00` — `n` zero bytes (the run, including the tag byte).
    Padding(usize),
    /// `0x01` — transaction public key.
    PubKey([u8; 32]),
    /// `0x02` — extra nonce.
    Nonce(Vec<u8>),
    /// `0x04` — additional per-output tx public keys.
    AdditionalPubKeys(Vec<[u8; 32]>),
    /// `0x05` — PQC ownership entries.
    PqcOwnership(Vec<PqcOwnershipEntry>),
    /// `0x06` — per-output hybrid KEM ciphertexts, concatenated.
    PqcKemCiphertext(Vec<u8>),
    /// `0x07` — per-output PQC leaf hashes, concatenated.
    PqcLeafHashes(Vec<u8>),
    /// `0x08` — multisig migration blob.
    MultisigMigration(Vec<u8>),
    /// `0x09` — PQC view-tag hints blob.
    PqcViewTagHints(Vec<u8>),
    /// `0x0A` — PQC spend-auth pubkeys blob.
    PqcSpendAuthPubkeys(Vec<u8>),
}

/// A per-output hybrid KEM ciphertext from a `0x06` field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext {
    /// Ephemeral X25519 ciphertext.
    pub x25519: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub ml_kem: Vec<u8>,
}

fn read_blob<R: Read>(r: &mut R, what: &str) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len > READ_LEN_CAP {
        return Err(io::Error::other(format!(
            "tx_extra: {what} length {len} exceeds cap {READ_LEN_CAP}"
        )));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_blob<W: Write>(w: &mut W, tag: u8, blob: &[u8]) -> io::Result<()> {
    w.write_all(&[tag])?;
    write_varint(blob.len(), w)?;
    w.write_all(blob)
}

/// Parse the `extra` blob into its tag-prefixed fields. Errors on an unknown tag
/// (tx_extra has no generic skip — an unknown tag means an unparseable blob) or a
/// non-zero byte inside padding.
pub fn parse(extra: &[u8]) -> io::Result<Vec<TxExtraField>> {
    let mut cur = extra;
    let mut fields = Vec::new();
    while !cur.is_empty() {
        let tag = read_byte(&mut cur)?;
        let field = match tag {
            TX_EXTRA_TAG_PADDING => {
                // Padding runs to the end of `extra` and must be all-zero. Scan
                // the remaining slice in place (no allocation/copy), then drain.
                if cur.iter().any(|&b| b != 0) {
                    return Err(io::Error::other("tx_extra: non-zero byte in padding"));
                }
                let field = TxExtraField::Padding(1 + cur.len());
                cur = &[];
                field
            }
            TX_EXTRA_TAG_PUBKEY => TxExtraField::PubKey(read_array(&mut cur)?),
            TX_EXTRA_TAG_NONCE => TxExtraField::Nonce(read_blob(&mut cur, "nonce")?),
            TX_EXTRA_TAG_ADDITIONAL_PUBKEYS => {
                let count: usize = read_varint(&mut cur)?;
                if count > READ_LEN_CAP {
                    return Err(io::Error::other(format!(
                        "tx_extra: additional_pubkeys count {count} exceeds cap"
                    )));
                }
                let mut keys = Vec::new();
                for _ in 0..count {
                    keys.push(read_array(&mut cur)?);
                }
                TxExtraField::AdditionalPubKeys(keys)
            }
            TX_EXTRA_TAG_PQC_OWNERSHIP => {
                let count: usize = read_varint(&mut cur)?;
                if count > READ_LEN_CAP {
                    return Err(io::Error::other(format!(
                        "tx_extra: pqc_ownership count {count} exceeds cap"
                    )));
                }
                let mut entries = Vec::new();
                for _ in 0..count {
                    entries.push(PqcOwnershipEntry {
                        output_index: read_byte(&mut cur)?,
                        scheme_id: read_byte(&mut cur)?,
                        group_id: read_array(&mut cur)?,
                    });
                }
                TxExtraField::PqcOwnership(entries)
            }
            TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT => {
                TxExtraField::PqcKemCiphertext(read_blob(&mut cur, "pqc_kem")?)
            }
            TX_EXTRA_TAG_PQC_LEAF_HASHES => {
                TxExtraField::PqcLeafHashes(read_blob(&mut cur, "pqc_leaf_hashes")?)
            }
            TX_EXTRA_TAG_MULTISIG_MIGRATION => {
                TxExtraField::MultisigMigration(read_blob(&mut cur, "multisig_migration")?)
            }
            TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS => {
                TxExtraField::PqcViewTagHints(read_blob(&mut cur, "pqc_view_tag_hints")?)
            }
            TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS => {
                TxExtraField::PqcSpendAuthPubkeys(read_blob(&mut cur, "pqc_spend_auth_pubkeys")?)
            }
            other => {
                return Err(io::Error::other(format!(
                    "tx_extra: unknown tag {other:#04x}"
                )))
            }
        };
        fields.push(field);
    }
    Ok(fields)
}

/// Re-serialize parsed fields back to the `extra` blob (byte-identical to the
/// input for a faithfully-parsed blob).
pub fn serialize(fields: &[TxExtraField]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        write_field(&mut out, field).expect("Vec write is infallible");
    }
    out
}

fn write_field<W: Write>(w: &mut W, field: &TxExtraField) -> io::Result<()> {
    match field {
        TxExtraField::Padding(n) => {
            // `n` zero bytes total (the tag is the first padding byte). Stream
            // from a fixed buffer rather than allocating an `n`-byte scratch Vec.
            let zeros = [0u8; 256];
            let mut remaining = *n;
            while remaining > 0 {
                let take = remaining.min(zeros.len());
                w.write_all(&zeros[..take])?;
                remaining -= take;
            }
            Ok(())
        }
        TxExtraField::PubKey(key) => {
            w.write_all(&[TX_EXTRA_TAG_PUBKEY])?;
            w.write_all(key)
        }
        TxExtraField::Nonce(blob) => write_blob(w, TX_EXTRA_TAG_NONCE, blob),
        TxExtraField::AdditionalPubKeys(keys) => {
            w.write_all(&[TX_EXTRA_TAG_ADDITIONAL_PUBKEYS])?;
            write_varint(keys.len(), w)?;
            for key in keys {
                w.write_all(key)?;
            }
            Ok(())
        }
        TxExtraField::PqcOwnership(entries) => {
            w.write_all(&[TX_EXTRA_TAG_PQC_OWNERSHIP])?;
            write_varint(entries.len(), w)?;
            for entry in entries {
                w.write_all(&[entry.output_index, entry.scheme_id])?;
                w.write_all(&entry.group_id)?;
            }
            Ok(())
        }
        TxExtraField::PqcKemCiphertext(blob) => {
            write_blob(w, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, blob)
        }
        TxExtraField::PqcLeafHashes(blob) => write_blob(w, TX_EXTRA_TAG_PQC_LEAF_HASHES, blob),
        TxExtraField::MultisigMigration(blob) => {
            write_blob(w, TX_EXTRA_TAG_MULTISIG_MIGRATION, blob)
        }
        TxExtraField::PqcViewTagHints(blob) => write_blob(w, TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS, blob),
        TxExtraField::PqcSpendAuthPubkeys(blob) => {
            write_blob(w, TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS, blob)
        }
    }
}

/// Split a `0x06` blob into per-output hybrid KEM ciphertexts (§9.6a). Errors if
/// the blob is not a whole number of `HYBRID_KEM_CT_BYTES`-sized entries.
pub fn pqc_kem_per_output(blob: &[u8]) -> io::Result<Vec<KemCiphertext>> {
    if !blob.len().is_multiple_of(HYBRID_KEM_CT_BYTES) {
        return Err(io::Error::other(format!(
            "tx_extra: 0x06 blob len {} not a multiple of {HYBRID_KEM_CT_BYTES}",
            blob.len()
        )));
    }
    Ok(blob
        .chunks_exact(HYBRID_KEM_CT_BYTES)
        .map(|chunk| {
            let mut x25519 = [0u8; 32];
            x25519.copy_from_slice(&chunk[..X25519_CT_BYTES]);
            KemCiphertext {
                x25519,
                ml_kem: chunk[X25519_CT_BYTES..].to_vec(),
            }
        })
        .collect())
}

/// Split a `0x07` blob into per-output leaf hashes (§9.6a). Errors if the blob is
/// not a whole number of `PQC_LEAF_HASH_BYTES`-sized entries.
pub fn pqc_leaf_hashes_per_output(blob: &[u8]) -> io::Result<Vec<[u8; 32]>> {
    if !blob.len().is_multiple_of(PQC_LEAF_HASH_BYTES) {
        return Err(io::Error::other(format!(
            "tx_extra: 0x07 blob len {} not a multiple of {PQC_LEAF_HASH_BYTES}",
            blob.len()
        )));
    }
    Ok(blob
        .chunks_exact(PQC_LEAF_HASH_BYTES)
        .map(|chunk| {
            let mut h = [0u8; 32];
            h.copy_from_slice(chunk);
            h
        })
        .collect())
}
