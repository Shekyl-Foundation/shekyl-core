// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `0x0D` multisig-entry codec (`docs/PQC_MULTISIG.md` §7.4).
//!
//! One [`MultisigEntry`] per output paid to a multisig group. The tag and
//! the [`super::TxExtraField::PqcMultisig`] arm stay in the parent parser;
//! this module owns the entry, its length law, and the shape rule that
//! admission runs after a successful parse.

use std::io;

use crate::bytes::{read_array, read_byte};

use super::{KemCiphertext, PqcFieldShapeError, TxExtraField, HYBRID_KEM_CT_BYTES};

/// The most members a multisig group has. Pinned equal to
/// `shekyl_crypto_pq::multisig::MAX_MULTISIG_PARTICIPANTS` in the test build
/// (`kem_layout_pins`), for the same reason as the KEM sizes.
pub const MULTISIG_MAX_MEMBERS: u8 = 5;
/// Bytes of one member's per-output key hash in a [`MultisigEntry`].
pub const MULTISIG_KEY_HASH_BYTES: usize = 32;
/// Bytes of the AEAD tag that closes a [`MultisigEntry`]'s encrypted hashes.
pub const MULTISIG_HASHES_TAG_BYTES: usize = 16;
/// Bytes one member adds to an entry, apart from the two header bytes and
/// the one AEAD tag: the hybrid ciphertext plus that member's key hash.
pub const MULTISIG_MEMBER_WIRE_STRIDE: usize = HYBRID_KEM_CT_BYTES + MULTISIG_KEY_HASH_BYTES;

/// One output's entry in the `0x0D` field:
/// `out_idx ‖ n ‖ ct_1 … ct_n ‖ enc(h_1 … h_n)`.
///
/// - `out_idx` — the output this entry belongs to.
/// - `n` — the group's member count, `1..=`[`MULTISIG_MAX_MEMBERS`]. It is on
///   the wire so the field parses without the address; the entry's length is
///   then exactly [`MultisigEntry::wire_len`]`(n)`.
/// - `ct_i` — a hybrid KEM ciphertext to member `i`'s own KEM key. Member `i`
///   alone recovers the per-output secret its signing key derives from.
/// - `enc(h_1 … h_n)` — the members' per-output key hashes, encrypted under
///   the output's group secret, then its [`MULTISIG_HASHES_TAG_BYTES`]-byte
///   AEAD tag. Opaque here: the codec checks its length, the wallet opens it.
///
/// The fields are private and [`MultisigEntry::new`] checks both lengths, so
/// an entry whose ciphertext count and hash blob disagree with `n` does not
/// exist.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MultisigEntry {
    out_idx: u8,
    member_cts: Vec<KemCiphertext>,
    enc_key_hashes: Vec<u8>,
}

/// Why a [`MultisigEntry`] cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultisigEntryError {
    /// The member count is 0 or above [`MULTISIG_MAX_MEMBERS`].
    MemberCount {
        /// The count given.
        n: usize,
    },
    /// The encrypted hash blob is not [`MultisigEntry::enc_key_hashes_len`]`(n)` bytes.
    EncryptedHashesLength {
        /// The length given.
        got: usize,
        /// `n · MULTISIG_KEY_HASH_BYTES + MULTISIG_HASHES_TAG_BYTES`.
        expected: usize,
    },
}

impl std::fmt::Display for MultisigEntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemberCount { n } => write!(
                f,
                "multisig entry: {n} members; 1..={MULTISIG_MAX_MEMBERS} required"
            ),
            Self::EncryptedHashesLength { got, expected } => write!(
                f,
                "multisig entry: encrypted key hashes are {got} bytes; {expected} required"
            ),
        }
    }
}

impl std::error::Error for MultisigEntryError {}

impl MultisigEntry {
    /// The encrypted hash blob's length for `n` members.
    #[must_use]
    pub const fn enc_key_hashes_len(n: u8) -> usize {
        (n as usize) * MULTISIG_KEY_HASH_BYTES + MULTISIG_HASHES_TAG_BYTES
    }

    /// The entry's wire length for `n` members: two header bytes, `n` times
    /// [`MULTISIG_MEMBER_WIRE_STRIDE`], and the AEAD tag.
    #[must_use]
    pub const fn wire_len(n: u8) -> usize {
        2 + (n as usize) * MULTISIG_MEMBER_WIRE_STRIDE + MULTISIG_HASHES_TAG_BYTES
    }

    /// Build an entry, checking the member count and the hash blob's length.
    ///
    /// # Errors
    ///
    /// [`MultisigEntryError`] when either length is wrong.
    pub fn new(
        out_idx: u8,
        member_cts: Vec<KemCiphertext>,
        enc_key_hashes: Vec<u8>,
    ) -> Result<Self, MultisigEntryError> {
        let n = member_cts.len();
        let n_u8 = u8::try_from(n)
            .ok()
            .filter(|n| (1..=MULTISIG_MAX_MEMBERS).contains(n))
            .ok_or(MultisigEntryError::MemberCount { n })?;
        let expected = Self::enc_key_hashes_len(n_u8);
        if enc_key_hashes.len() != expected {
            return Err(MultisigEntryError::EncryptedHashesLength {
                got: enc_key_hashes.len(),
                expected,
            });
        }
        Ok(Self {
            out_idx,
            member_cts,
            enc_key_hashes,
        })
    }

    /// The output this entry belongs to.
    #[must_use]
    pub const fn out_idx(&self) -> u8 {
        self.out_idx
    }

    /// The member count `n`.
    #[must_use]
    pub fn n(&self) -> u8 {
        u8::try_from(self.member_cts.len()).expect("checked at construction")
    }

    /// The members' KEM ciphertexts, member order.
    #[must_use]
    pub fn member_cts(&self) -> &[KemCiphertext] {
        &self.member_cts
    }

    /// The encrypted key hashes followed by their AEAD tag.
    #[must_use]
    pub fn enc_key_hashes(&self) -> &[u8] {
        &self.enc_key_hashes
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.push(self.out_idx);
        out.push(self.n());
        for ct in &self.member_cts {
            out.extend_from_slice(&ct.to_bytes());
        }
        out.extend_from_slice(&self.enc_key_hashes);
    }
}

pub(super) fn multisig_entries_bytes(entries: &[MultisigEntry]) -> Vec<u8> {
    let len = entries.iter().map(|e| MultisigEntry::wire_len(e.n())).sum();
    let mut out = Vec::with_capacity(len);
    for entry in entries {
        entry.write_to(&mut out);
    }
    out
}

/// Split a `0x0D` payload into its entries. Every entry must be whole: a
/// member count outside `1..=`[`MULTISIG_MAX_MEMBERS`] or a short tail is a
/// parse error. Order and output indices are the shape rule's
/// ([`check_pqc_multisig_shape`]), not the parser's.
pub(super) fn parse_multisig_entries(mut blob: &[u8]) -> io::Result<Vec<MultisigEntry>> {
    let mut entries = Vec::new();
    while !blob.is_empty() {
        let out_idx = read_byte(&mut blob)?;
        let n = read_byte(&mut blob)?;
        if n == 0 || n > MULTISIG_MAX_MEMBERS {
            return Err(io::Error::other(format!(
                "tx_extra: 0x0d entry member count {n} not in 1..={MULTISIG_MAX_MEMBERS}"
            )));
        }
        let mut member_cts = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let ct: [u8; HYBRID_KEM_CT_BYTES] = read_array(&mut blob)?;
            member_cts.push(KemCiphertext::from_bytes(&ct));
        }
        let hashes_len = MultisigEntry::enc_key_hashes_len(n);
        if blob.len() < hashes_len {
            return Err(io::Error::other("tx_extra: 0x0d entry truncated"));
        }
        let (hashes, rest) = blob.split_at(hashes_len);
        blob = rest;
        entries.push(
            MultisigEntry::new(out_idx, member_cts, hashes.to_vec())
                .expect("both lengths were read to n"),
        );
    }
    Ok(entries)
}

/// The `0x0D` shape rule (CEN-I19's multisig clause): the field is optional;
/// when present it is the only one, holds at least one entry, its entries
/// are strictly ascending by output index, and each names an output the
/// transaction has. Each entry's own length is exact by the parse.
///
/// A transaction carries `0x0D` only when it pays a multisig group, so the
/// field's presence says so. That is inherent to Option E′ and was equally
/// true of the retired `0x09` / `0x0A` (`docs/PQC_MULTISIG.md` §7.4).
pub fn check_pqc_multisig_shape(
    fields: &[TxExtraField],
    n_outputs: usize,
) -> Result<(), PqcFieldShapeError> {
    let found: Vec<&[MultisigEntry]> = fields
        .iter()
        .filter_map(|f| match f {
            TxExtraField::PqcMultisig(entries) => Some(entries.as_slice()),
            _ => None,
        })
        .collect();
    let entries = match found.as_slice() {
        [] => return Ok(()),
        [entries] => *entries,
        many => {
            return Err(PqcFieldShapeError::MultisigDuplicate { count: many.len() });
        }
    };
    if entries.is_empty() {
        return Err(PqcFieldShapeError::MultisigEmpty);
    }
    let mut previous: Option<u8> = None;
    for (position, entry) in entries.iter().enumerate() {
        let out_idx = entry.out_idx();
        if previous.is_some_and(|p| out_idx <= p) {
            return Err(PqcFieldShapeError::MultisigOrder { position });
        }
        if usize::from(out_idx) >= n_outputs {
            return Err(PqcFieldShapeError::MultisigOutputIndex { out_idx, n_outputs });
        }
        previous = Some(out_idx);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{KemCiphertext, PqcFieldShapeError, TxExtraField, HYBRID_KEM_CT_BYTES};
    use super::*;

    fn ms(out_idx: u8) -> MultisigEntry {
        MultisigEntry::new(
            out_idx,
            vec![KemCiphertext::from_bytes(&[0x11; HYBRID_KEM_CT_BYTES])],
            vec![0x22; MultisigEntry::enc_key_hashes_len(1)],
        )
        .expect("one member, right lengths")
    }

    #[test]
    fn multisig_shape_admits_absent_and_ascending_entries() {
        assert_eq!(check_pqc_multisig_shape(&[], 2), Ok(()));
        let one = [TxExtraField::PqcMultisig(vec![ms(1)])];
        assert_eq!(check_pqc_multisig_shape(&one, 2), Ok(()));
        let two = [TxExtraField::PqcMultisig(vec![ms(0), ms(3)])];
        assert_eq!(check_pqc_multisig_shape(&two, 4), Ok(()));
    }

    #[test]
    fn multisig_shape_refusals_name_their_defect() {
        let dup = [
            TxExtraField::PqcMultisig(vec![ms(0)]),
            TxExtraField::PqcMultisig(vec![ms(1)]),
        ];
        assert_eq!(
            check_pqc_multisig_shape(&dup, 2),
            Err(PqcFieldShapeError::MultisigDuplicate { count: 2 })
        );
        assert_eq!(
            check_pqc_multisig_shape(&[TxExtraField::PqcMultisig(Vec::new())], 2),
            Err(PqcFieldShapeError::MultisigEmpty)
        );
        for order in [vec![ms(1), ms(0)], vec![ms(1), ms(1)]] {
            assert_eq!(
                check_pqc_multisig_shape(&[TxExtraField::PqcMultisig(order)], 2),
                Err(PqcFieldShapeError::MultisigOrder { position: 1 })
            );
        }
        assert_eq!(
            check_pqc_multisig_shape(&[TxExtraField::PqcMultisig(vec![ms(2)])], 2),
            Err(PqcFieldShapeError::MultisigOutputIndex {
                out_idx: 2,
                n_outputs: 2
            })
        );
        // No outputs: any entry names an output that does not exist.
        assert_eq!(
            check_pqc_multisig_shape(&[TxExtraField::PqcMultisig(vec![ms(0)])], 0),
            Err(PqcFieldShapeError::MultisigOutputIndex {
                out_idx: 0,
                n_outputs: 0
            })
        );
    }
}
