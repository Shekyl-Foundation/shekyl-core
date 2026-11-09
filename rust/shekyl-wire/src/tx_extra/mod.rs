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
//! output) and `0x07` leaf entries (`CM ‖ record`, 64 bytes per output).
//!
//! This crate owns the **Shekyl genesis `tx_extra` tag set**
//! (`GENESIS_TX_WIRE_FORMAT.md` §9.6a). Tag grammars: most tags are
//! `tag · V(len) · blob`; `0x01` is a bare [`TX_EXTRA_PUBKEY_LEN`]-byte key;
//! `0x04` is `V(count) · count×32`; `0x00` padding is a run of zero bytes
//! (≤ [`TX_EXTRA_PADDING_MAX_COUNT`]). Inherited Monero tags that are **not**
//! part of the genesis grammar — merge-mining (`0x03`) and the "mysterious
//! minergate" (`0xDE`) — are **rejected** (rule 60). The byte values stay
//! retired. The coinbase admission grammar (CEN-I20) is [`coinbase`]: one
//! constructor and one slice match. This file is the codec those call.

use std::borrow::Cow;
use std::io::{self, Read, Write};

pub use shekyl_types::archival::{DrawCommitment, DRAW_COMMITMENT_LEN};

use crate::bytes::{read_array, read_byte};
use crate::varint::{read_varint, write_varint};
use crate::READ_LEN_CAP;

mod coinbase;

pub use coinbase::{
    build_coinbase_extra, check_coinbase_extra_shape, check_tx_extra_shape, coinbase_extra_len,
    CoinbaseBuildError, CoinbaseGrammarError, ExtraSubject, COINBASE_NONCE_BYTES,
    COINBASE_NONCE_OFFSET_FROM_PUBKEY, COINBASE_NONCE_OFFSET_IN_EXTRA,
};

/// `0x00` — padding (a run of zero bytes to the end of `extra`).
pub const TX_EXTRA_TAG_PADDING: u8 = 0x00;
/// `0x01` — transaction public key.
pub const TX_EXTRA_TAG_PUBKEY: u8 = 0x01;
/// Byte length of a [`TxExtraField::PubKey`].
pub const TX_EXTRA_PUBKEY_LEN: usize = 32;
/// `0x02` — extra nonce.
pub const TX_EXTRA_TAG_NONCE: u8 = 0x02;
/// `0x04` — additional per-output tx public keys.
pub const TX_EXTRA_TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;
// `0x05` was PQC_OWNERSHIP — a per-output `(scheme_id, group_id)` ownership
// entry with no producer and no reader, superseded by the in-circuit
// leaf-commitment binding (`PL-D3`, `docs/FCMP_PLUS_PLUS.md` "PQC ownership
// binding") and by the address fingerprint as group identity
// (`docs/PQC_MULTISIG.md` §5.3). REJECTED 2026-09-22; the byte stays retired
// like `0x03` / `0xDE`, so a later tag cannot reuse a meaning
// old software parsed differently.
/// `0x06` — per-output hybrid KEM ciphertexts.
pub const TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT: u8 = 0x06;
/// `0x07` — per-output PQC leaf entries (`CM ‖ record`, `PL-D3`; the
/// constant keeps the tag's historical name).
pub const TX_EXTRA_TAG_PQC_LEAF_ENTRIES: u8 = 0x07;
// `0x08` is RESERVED for the multisig group-rotation / migration transaction
// (`docs/PQC_MULTISIG.md` §7.4, "Reserved tags"): a reserved slot lives in
// the spec's table with no code symbol until its producer is designed
// (rule 23).
// `0x09` was the Option D multisig view-tag hints and `0x0A` its per-member
// spend-auth pubkeys. Option E′ replaced both with `0x0D` (one entry per
// multisig output; `docs/PQC_MULTISIG.md` §7.4). Neither ever had a
// producer. Both bytes stay retired like `0x03` / `0x05` / `0xDE` — never
// reused — and parse as unknown tags.

/// `0x0B` — archival attestation blob. A present tag with an empty payload
/// encodes as two bytes (`0x0B 0x00`), not as an absent extra. The consensus
/// reader's committed empty set is a successful parse with the tag **absent**;
/// present-empty and absent both yield an empty blob at that API.
pub const TX_EXTRA_TAG_ARCHIVAL_ATTESTATION: u8 = 0x0B;

/// `0x0C` — the secret draw's commitment: 32 bytes, no length prefix, as
/// the pubkey is encoded (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §4.2; `SO-D12i`).
/// Required in every coinbase and refused everywhere else.
pub const TX_EXTRA_TAG_DRAW_COMMITMENT: u8 = 0x0C;

/// `0x0D` — the multisig entries: one [`MultisigEntry`] per output paid to
/// a multisig group, sorted by output index (`docs/PQC_MULTISIG.md` §7.4).
/// Each entry carries the group members' own KEM ciphertexts and the
/// encrypted hashes of their per-output signing keys.
pub const TX_EXTRA_TAG_PQC_MULTISIG: u8 = 0x0D;

/// The most members a multisig group has. Pinned equal to
/// `shekyl_crypto_pq::multisig::MAX_MULTISIG_PARTICIPANTS` in the test build
/// (`kem_layout_pins`), for the same reason as the KEM sizes.
pub const MULTISIG_MAX_MEMBERS: u8 = 5;
/// Bytes of one member's per-output key hash in a [`MultisigEntry`].
pub const MULTISIG_KEY_HASH_BYTES: usize = 32;
/// Bytes of the AEAD tag that closes a [`MultisigEntry`]'s encrypted hashes.
pub const MULTISIG_HASHES_TAG_BYTES: usize = 16;

/// X25519 ciphertext bytes per output.
pub const X25519_CT_BYTES: usize = 32;
/// ML-KEM-768 ciphertext bytes per output.
pub const ML_KEM_768_CT_BYTES: usize = 1088;
/// Hybrid KEM ciphertext bytes per output (`32 + 1088`).
pub const HYBRID_KEM_CT_BYTES: usize = X25519_CT_BYTES + ML_KEM_768_CT_BYTES;
/// PQC leaf entry bytes per output: the leaf commitment point `CM` (32,
/// compressed Ed25519) followed by the post-quantum record (32) — `PL-D3` /
/// `PL-D3a` (`docs/design/FCMP_SPEND_LINKABILITY.md` §6.2). The leaf's 4th
/// scalar is `CM.x`; the record is checked by nothing live.
pub const PQC_LEAF_ENTRY_LEN: usize = 64;
/// Byte length of the commitment point at the front of each `0x07` entry.
pub const PQC_LEAF_POINT_BYTES: usize = 32;

// The three KEM sizes above are WIRE-FREEZE pins: they must never
// silently track a crypto-library change (that would be an unversioned
// format change, rule 42) — but they must also never silently diverge
// from what the KEM actually emits (`shekyl-crypto-pq`, the
// cryptographic source of truth). `shekyl-crypto-pq` is deliberately a
// dev-only dependency (the serializer's runtime dep surface stays
// minimal), so the pins are asserted in the test build: divergence
// fails `cargo test -p shekyl-wire` at compile time, forcing an
// explicit wire-version decision instead of a corrupt parse.
#[cfg(test)]
mod kem_layout_pins {
    const _: () = assert!(super::X25519_CT_BYTES == shekyl_crypto_pq::kem::X25519_KEM_CT_LEN);
    const _: () = assert!(super::ML_KEM_768_CT_BYTES == shekyl_crypto_pq::kem::ML_KEM_768_CT_LEN);
    const _: () = assert!(super::HYBRID_KEM_CT_BYTES == shekyl_crypto_pq::kem::HYBRID_KEM_CT_LEN);
    const _: () =
        assert!(super::PQC_LEAF_ENTRY_LEN == shekyl_crypto_pq::leaf_commitment::PQC_LEAF_ENTRY_LEN);
    const _: () = assert!(
        super::PQC_LEAF_POINT_BYTES == shekyl_crypto_pq::leaf_commitment::PQC_LEAF_POINT_LEN
    );
    const _: () = assert!(
        super::MULTISIG_MAX_MEMBERS == shekyl_crypto_pq::multisig::MAX_MULTISIG_PARTICIPANTS
    );
}

/// Max padding run in bytes, **including** the tag byte. Longer padding does
/// not parse.
pub const TX_EXTRA_PADDING_MAX_COUNT: usize = 255;
/// Max extra-nonce payload in bytes. The coinbase nonce is not this cap; it
/// is [`COINBASE_NONCE_BYTES`], fixed.
pub const TX_EXTRA_NONCE_MAX_COUNT: usize = 255;

/// A parsed `tx_extra` field. The `0x06`/`0x07` payloads are kept as concatenated
/// blobs (their on-wire form); use [`pqc_kem_per_output`] / [`pqc_leaf_entries_per_output`]
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
    /// `0x06` — per-output hybrid KEM ciphertexts, concatenated.
    PqcKemCiphertext(Vec<u8>),
    /// `0x07` — per-output PQC leaf entries (`CM ‖ record`), concatenated.
    PqcLeafEntries(Vec<u8>),
    /// `0x0B` — archival attestation blob.
    ArchivalAttestation(Vec<u8>),
    /// `0x0C` — the secret draw's commitment.
    DrawCommitment(DrawCommitment),
    /// `0x0D` — the multisig entries, in wire order.
    PqcMultisig(Vec<MultisigEntry>),
}

impl TxExtraField {
    /// The tag byte this field serializes as.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Padding(_) => TX_EXTRA_TAG_PADDING,
            Self::PubKey(_) => TX_EXTRA_TAG_PUBKEY,
            Self::Nonce(_) => TX_EXTRA_TAG_NONCE,
            Self::AdditionalPubKeys(_) => TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
            Self::PqcKemCiphertext(_) => TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT,
            Self::PqcLeafEntries(_) => TX_EXTRA_TAG_PQC_LEAF_ENTRIES,
            Self::ArchivalAttestation(_) => TX_EXTRA_TAG_ARCHIVAL_ATTESTATION,
            Self::DrawCommitment(_) => TX_EXTRA_TAG_DRAW_COMMITMENT,
            Self::PqcMultisig(_) => TX_EXTRA_TAG_PQC_MULTISIG,
        }
    }

    /// The payload a reader of this field is handed.
    ///
    /// Padding is a length, not a payload, and returns `None`. Additional
    /// pubkeys and multisig entries are owned because the enum stores them
    /// parsed; every other payload is borrowed from the field.
    #[must_use]
    pub fn payload(&self) -> Option<Cow<'_, [u8]>> {
        match self {
            Self::Padding(_) => None,
            Self::PubKey(key) => Some(Cow::Borrowed(key)),
            Self::DrawCommitment(commitment) => Some(Cow::Borrowed(commitment.as_bytes())),
            Self::AdditionalPubKeys(keys) => {
                let mut bytes = Vec::with_capacity(keys.len() * TX_EXTRA_PUBKEY_LEN);
                for key in keys {
                    bytes.extend_from_slice(key);
                }
                Some(Cow::Owned(bytes))
            }
            Self::PqcMultisig(entries) => Some(Cow::Owned(multisig_entries_bytes(entries))),
            Self::Nonce(bytes)
            | Self::PqcKemCiphertext(bytes)
            | Self::PqcLeafEntries(bytes)
            | Self::ArchivalAttestation(bytes) => Some(Cow::Borrowed(bytes)),
        }
    }
}

/// A per-output hybrid KEM ciphertext from a `0x06` field.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KemCiphertext {
    /// Ephemeral X25519 ciphertext.
    pub x25519: [u8; 32],
    /// ML-KEM-768 ciphertext — fixed size by spec, so a wrong length is
    /// unrepresentable (and the split avoids a per-output heap allocation).
    pub ml_kem: [u8; ML_KEM_768_CT_BYTES],
}

impl KemCiphertext {
    /// The `x25519 ‖ ml_kem` wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HYBRID_KEM_CT_BYTES] {
        let mut out = [0u8; HYBRID_KEM_CT_BYTES];
        out[..X25519_CT_BYTES].copy_from_slice(&self.x25519);
        out[X25519_CT_BYTES..].copy_from_slice(&self.ml_kem);
        out
    }

    /// Split `HYBRID_KEM_CT_BYTES` wire bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; HYBRID_KEM_CT_BYTES]) -> Self {
        let mut x25519 = [0u8; X25519_CT_BYTES];
        x25519.copy_from_slice(&bytes[..X25519_CT_BYTES]);
        let mut ml_kem = [0u8; ML_KEM_768_CT_BYTES];
        ml_kem.copy_from_slice(&bytes[X25519_CT_BYTES..]);
        Self { x25519, ml_kem }
    }
}

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
    /// The encrypted hash blob is not `n · 32 + 16` bytes.
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

    /// The entry's wire length for `n` members: `2 + n·1152 + 16`.
    #[must_use]
    pub const fn wire_len(n: u8) -> usize {
        2 + (n as usize) * HYBRID_KEM_CT_BYTES + Self::enc_key_hashes_len(n)
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

fn multisig_entries_bytes(entries: &[MultisigEntry]) -> Vec<u8> {
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
/// ([`check_pqc_field_shape_of`]), not the parser's.
fn parse_multisig_entries(mut blob: &[u8]) -> io::Result<Vec<MultisigEntry>> {
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

fn read_blob<R: Read>(r: &mut R, what: &str) -> io::Result<Vec<u8>> {
    read_blob_bounded(r, what, READ_LEN_CAP)
}

/// Read a `V(len)·blob`, rejecting (before allocating) any declared length above
/// `max`. Use a tag-specific `max` (e.g. the nonce's 255) so a hostile length can't
/// drive a large allocation that the tag's own cap would reject anyway.
fn read_blob_bounded<R: Read>(r: &mut R, what: &str, max: usize) -> io::Result<Vec<u8>> {
    let len: usize = read_varint(r)?;
    if len > max {
        return Err(io::Error::other(format!(
            "tx_extra: {what} length {len} exceeds cap {max}"
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
                // Padding is the rest of `extra` — all-zero, capped at 255 incl. the
                // tag. Validate the remaining slice **in place** (no copy of
                // attacker-controlled bytes): check the cap first (O(1)), then scan
                // for non-zero (bounded to <=254), then consume the remainder.
                let run = 1 + cur.len();
                if run > TX_EXTRA_PADDING_MAX_COUNT {
                    return Err(io::Error::other(format!(
                        "tx_extra: padding run {run} exceeds {TX_EXTRA_PADDING_MAX_COUNT}"
                    )));
                }
                if cur.iter().any(|&b| b != 0) {
                    return Err(io::Error::other("tx_extra: non-zero byte in padding"));
                }
                cur = &[];
                TxExtraField::Padding(run)
            }
            TX_EXTRA_TAG_PUBKEY => TxExtraField::PubKey(read_array(&mut cur)?),
            TX_EXTRA_TAG_NONCE => {
                // Reject `> TX_EXTRA_NONCE_MAX_COUNT` before allocating the payload.
                TxExtraField::Nonce(read_blob_bounded(
                    &mut cur,
                    "nonce",
                    TX_EXTRA_NONCE_MAX_COUNT,
                )?)
            }
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
            TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT => {
                TxExtraField::PqcKemCiphertext(read_blob(&mut cur, "pqc_kem")?)
            }
            TX_EXTRA_TAG_PQC_LEAF_ENTRIES => {
                TxExtraField::PqcLeafEntries(read_blob(&mut cur, "pqc_leaf_hashes")?)
            }
            TX_EXTRA_TAG_ARCHIVAL_ATTESTATION => {
                TxExtraField::ArchivalAttestation(read_blob(&mut cur, "archival_attestation")?)
            }
            TX_EXTRA_TAG_DRAW_COMMITMENT => {
                TxExtraField::DrawCommitment(DrawCommitment::from_bytes(read_array(&mut cur)?))
            }
            TX_EXTRA_TAG_PQC_MULTISIG => TxExtraField::PqcMultisig(parse_multisig_entries(
                &read_blob(&mut cur, "pqc_multisig")?,
            )?),
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
///
/// **Symmetric with [`parse`]** — it never emits bytes `parse` would reject. Each
/// field's parse-cap is checked **up front, O(n)** — padding (`1..=255` + last), the
/// nonce cap, the `AdditionalPubKeys` count, and the length-prefixed
/// blobs (`0x06`/`0x07`/…) against `READ_LEN_CAP`. A `debug_assert!` round-trip backs
/// this up in debug/test builds (free in release), so a future field kind that forgets
/// its cap check is caught in CI rather than silently emitting a self-invalid blob.
pub fn serialize(fields: &[TxExtraField]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let last = fields.len().saturating_sub(1);
    for (i, field) in fields.iter().enumerate() {
        // Reject any field that would emit bytes `parse` rejects (keep serialize/parse
        // inverses — the public `TxExtraField` admits out-of-range values).
        match field {
            TxExtraField::Padding(n) => {
                if *n == 0 || *n > TX_EXTRA_PADDING_MAX_COUNT {
                    return Err(io::Error::other(format!(
                        "tx_extra: padding run {n} not in 1..={TX_EXTRA_PADDING_MAX_COUNT}"
                    )));
                }
                if i != last {
                    return Err(io::Error::other(
                        "tx_extra: padding must be the last field (it consumes to end)",
                    ));
                }
            }
            TxExtraField::Nonce(blob) if blob.len() > TX_EXTRA_NONCE_MAX_COUNT => {
                return Err(io::Error::other(format!(
                    "tx_extra: nonce {} exceeds {TX_EXTRA_NONCE_MAX_COUNT}",
                    blob.len()
                )));
            }
            TxExtraField::AdditionalPubKeys(keys) if keys.len() > READ_LEN_CAP => {
                return Err(io::Error::other(format!(
                    "tx_extra: additional_pubkeys count {} exceeds cap {READ_LEN_CAP}",
                    keys.len()
                )));
            }
            TxExtraField::PqcMultisig(entries)
                if entries
                    .iter()
                    .map(|e| MultisigEntry::wire_len(e.n()))
                    .sum::<usize>()
                    > READ_LEN_CAP =>
            {
                return Err(io::Error::other(format!(
                    "tx_extra: 0x0d multisig entries exceed cap {READ_LEN_CAP}"
                )));
            }
            TxExtraField::PqcKemCiphertext(b)
            | TxExtraField::PqcLeafEntries(b)
            | TxExtraField::ArchivalAttestation(b)
                if b.len() > READ_LEN_CAP =>
            {
                return Err(io::Error::other(format!(
                    "tx_extra: field blob {} exceeds cap {READ_LEN_CAP}",
                    b.len()
                )));
            }
            _ => {}
        }
        write_field(&mut out, field).expect("Vec write is infallible");
    }
    // Future-proofing (debug/test only, compiled out in release): the emitted blob must
    // parse back identically — catches a new field kind whose cap check was forgotten.
    debug_assert!(
        parse(&out).map(|p| p == fields).unwrap_or(false),
        "tx_extra: serialize/parse asymmetry — a field kind is missing its up-front cap check"
    );
    Ok(out)
}

fn write_field<W: Write>(w: &mut W, field: &TxExtraField) -> io::Result<()> {
    match field {
        TxExtraField::Padding(n) => {
            // `n` zero bytes total (the tag is the first padding byte). Stream them
            // from a fixed stack buffer — no heap allocation, even though `n` is
            // attacker-influenceable via the public `TxExtraField`.
            const ZEROS: [u8; 64] = [0u8; 64];
            let mut remaining = *n;
            while remaining > 0 {
                let chunk = remaining.min(ZEROS.len());
                w.write_all(&ZEROS[..chunk])?;
                remaining -= chunk;
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
        TxExtraField::PqcKemCiphertext(blob) => {
            write_blob(w, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT, blob)
        }
        TxExtraField::PqcLeafEntries(blob) => write_blob(w, TX_EXTRA_TAG_PQC_LEAF_ENTRIES, blob),
        TxExtraField::ArchivalAttestation(blob) => {
            write_blob(w, TX_EXTRA_TAG_ARCHIVAL_ATTESTATION, blob)
        }
        TxExtraField::DrawCommitment(commitment) => {
            w.write_all(&[TX_EXTRA_TAG_DRAW_COMMITMENT])?;
            w.write_all(commitment.as_bytes())
        }
        TxExtraField::PqcMultisig(entries) => write_blob(
            w,
            TX_EXTRA_TAG_PQC_MULTISIG,
            &multisig_entries_bytes(entries),
        ),
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
            let mut ml_kem = [0u8; ML_KEM_768_CT_BYTES];
            ml_kem.copy_from_slice(&chunk[X25519_CT_BYTES..]);
            KemCiphertext { x25519, ml_kem }
        })
        .collect())
}

/// Split a `0x07` blob into per-output leaf entries (`CM ‖ record`, §9.6a).
/// Errors if the blob is not a whole number of `PQC_LEAF_ENTRY_LEN`-sized
/// entries. Shape only — content admission is [`check_pqc_leaf_entries`].
pub fn pqc_leaf_entries_per_output(blob: &[u8]) -> io::Result<Vec<[u8; PQC_LEAF_ENTRY_LEN]>> {
    if !blob.len().is_multiple_of(PQC_LEAF_ENTRY_LEN) {
        return Err(io::Error::other(format!(
            "tx_extra: 0x07 blob len {} not a multiple of {PQC_LEAF_ENTRY_LEN}",
            blob.len()
        )));
    }
    Ok(blob
        .chunks_exact(PQC_LEAF_ENTRY_LEN)
        .map(|chunk| {
            let mut h = [0u8; PQC_LEAF_ENTRY_LEN];
            h.copy_from_slice(chunk);
            h
        })
        .collect())
}

/// Which of the two CEN-I19 fields a shape verdict is about.
///
/// The verdict names the field, not a raw tag, so a match on it is total
/// over the two fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcExtraField {
    /// `0x06`, [`HYBRID_KEM_CT_BYTES`] bytes per output.
    Kem,
    /// `0x07`, [`PQC_LEAF_ENTRY_LEN`] bytes per output.
    Leaf,
}

impl PqcExtraField {
    /// The tag byte of this field.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Kem => TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT,
            Self::Leaf => TX_EXTRA_TAG_PQC_LEAF_ENTRIES,
        }
    }

    /// Payload bytes of one output's field.
    #[must_use]
    pub const fn stride(self) -> usize {
        match self {
            Self::Kem => HYBRID_KEM_CT_BYTES,
            Self::Leaf => PQC_LEAF_ENTRY_LEN,
        }
    }
}

/// Why a `0x06` / `0x07` field is refused (§9.6a as ruled 2026-09-05; CEN-I19).
///
/// Every variant names its field, and every variant whose defect is a count
/// or a length names those numbers — a rejected transaction says what was
/// expected. Its [`Display`](std::fmt::Display) is that sentence, so a log
/// line and a port's error read the same. The coinbase grammar is
/// [`CoinbaseGrammarError`], not a reuse of these variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcFieldShapeError {
    /// A tagged field is present on a transaction with no outputs.
    PresentWithoutOutputs {
        /// Which field.
        field: PqcExtraField,
    },
    /// The transaction has outputs but no field carrying this tag.
    /// `expected` is the length the single field would have had.
    Missing {
        /// Which field.
        field: PqcExtraField,
        /// `stride · n_outputs`.
        expected: usize,
    },
    /// More than one field carries this tag: the bytes admit two readings
    /// (first-match, last-match, reject) and a port may pick a different one.
    Duplicate {
        /// Which field.
        field: PqcExtraField,
        /// How many times it appeared.
        count: usize,
    },
    /// The single field's length is not `stride · n_outputs`.
    Length {
        /// Which field.
        field: PqcExtraField,
        /// The length that was present.
        got: usize,
        /// `stride · n_outputs`.
        expected: usize,
    },
    /// The `0x07` entry at `index` does not begin with a canonical, prime-order,
    /// non-identity Ed25519 point — the leaf commitment content rule (`PL-D3`).
    LeafPointInvalid {
        /// Index of the entry that failed.
        index: usize,
    },
    /// The `0x07` blob handed to the content rule is not a whole, non-zero
    /// number of `PQC_LEAF_ENTRY_LEN`-byte entries. The content rule enforces
    /// its own precondition rather than trusting the caller to have run the
    /// shape rule first: a trailing remainder would otherwise pass unchecked
    /// (`chunks_exact` silently drops it), and an empty blob would pass
    /// vacuously — no conforming field is empty (the shape rule admits a
    /// `0x07` field only with `n_outputs > 0`).
    LeafBlobLength {
        /// The blob length that was handed over.
        got: usize,
    },
    /// More than one `0x0D` field. One field holds every entry.
    MultisigDuplicate {
        /// How many `0x0D` fields appeared.
        count: usize,
    },
    /// A `0x0D` field with no entries.
    MultisigEmpty,
    /// The entry at `position` does not name a later output than the entry
    /// before it. Entries are strictly ascending by output index, which also
    /// makes a duplicate index unrepresentable.
    MultisigOrder {
        /// Position of the entry in the field.
        position: usize,
    },
    /// An entry names an output the transaction does not have.
    MultisigOutputIndex {
        /// The output index the entry named.
        out_idx: u8,
        /// The transaction's output count.
        n_outputs: usize,
    },
}

impl std::fmt::Display for PqcFieldShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PresentWithoutOutputs { field } => {
                write!(
                    f,
                    "tx_extra {:#04x} present on a transaction with no outputs",
                    field.tag()
                )
            }
            Self::Missing { field, expected } => write!(
                f,
                "tx_extra {:#04x} missing on a transaction with outputs; {expected} bytes required",
                field.tag()
            ),
            Self::Duplicate { field, count } => {
                write!(
                    f,
                    "tx_extra {:#04x} appears {count} times; exactly one is admitted",
                    field.tag()
                )
            }
            Self::Length {
                field,
                got,
                expected,
            } => write!(
                f,
                "tx_extra {:#04x} is {got} bytes; {expected} required for this output count",
                field.tag()
            ),
            Self::LeafPointInvalid { index } => write!(
                f,
                "tx_extra 0x07 entry {index}: leaf commitment is not a canonical prime-order point"
            ),
            Self::LeafBlobLength { got } => write!(
                f,
                "tx_extra 0x07 content check: blob is {got} bytes; a whole, non-zero \
                 multiple of {PQC_LEAF_ENTRY_LEN} required"
            ),
            Self::MultisigDuplicate { count } => write!(
                f,
                "tx_extra 0x0d appears {count} times; at most one is admitted"
            ),
            Self::MultisigEmpty => write!(f, "tx_extra 0x0d is present with no entries"),
            Self::MultisigOrder { position } => write!(
                f,
                "tx_extra 0x0d entry {position} does not follow the entry before it; \
                 entries are strictly ascending by output index"
            ),
            Self::MultisigOutputIndex { out_idx, n_outputs } => write!(
                f,
                "tx_extra 0x0d entry names output {out_idx}; the transaction has {n_outputs}"
            ),
        }
    }
}

impl std::error::Error for PqcFieldShapeError {}

/// Why a parsed `extra` is refused at admission: CEN-I19, the coinbase
/// grammar, or a `0x02` on a transaction that is not a coinbase.
///
/// One type so the daemon logs one [`Display`] and a caller matches once. The variants do not overlap: a missing pubkey is
/// [`CoinbaseGrammarError::PubkeyMissing`], never [`PqcFieldShapeError::Missing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraShapeError {
    /// CEN-I19, including the leaf-point content rule.
    Pqc(PqcFieldShapeError),
    /// The closed coinbase grammar.
    Coinbase(CoinbaseGrammarError),
    /// A `0x02` nonce on a non-coinbase transaction. The nonce exists for
    /// template search, which only the coinbase does.
    NonceOutsideCoinbase,
    /// A `0x0C` draw commitment on a non-coinbase transaction. A block
    /// commits to one seed, in its coinbase.
    DrawCommitmentOutsideCoinbase,
}

impl std::fmt::Display for ExtraShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pqc(err) => write!(f, "{err}"),
            Self::Coinbase(err) => write!(f, "{err}"),
            Self::NonceOutsideCoinbase => write!(
                f,
                "tx_extra 0x02 nonce on a non-coinbase transaction; the nonce is coinbase-only"
            ),
            Self::DrawCommitmentOutsideCoinbase => write!(
                f,
                "tx_extra 0x0c draw commitment on a non-coinbase transaction; it is coinbase-only"
            ),
        }
    }
}

impl std::error::Error for ExtraShapeError {}

/// The PQC field shape rule: with `n = n_outputs`, a transaction carries
/// **exactly one** `0x06` of `HYBRID_KEM_CT_BYTES · n` and **exactly one**
/// `0x07` of `PQC_LEAF_ENTRY_LEN · n` when `n > 0`, and **neither** when
/// `n == 0`.
///
/// `kem_lens` / `leaf_lens` are the byte lengths of every `0x06` / `0x07`
/// field [`parse`] found, in order. [`check_pqc_field_shape_of`] is that
/// extraction. The daemon does not parse `extra` and does not hand lengths
/// across the FFI; `shekyl_tx_extra_shape_of` parses and calls
/// [`check_tx_extra_shape`]. The zero-output arm is what keeps serve-credit
/// transactions (no outputs, empty `extra`) admissible: they are the
/// must-accept control.
///
/// Consensus, not policy (Rick, 2026-09-05): `0x07` carries the commitment
/// whose x-coordinate is the fourth scalar of every leaf these outputs become
/// — a short or missing field used to be zero-filled into the tree, a leaf
/// set a faithful port would not store; and a short or missing `0x06` leaves
/// the recipient unable to ever see or spend the payment, which a relay-only
/// rule would still let a miner commit.
///
/// Shape only. The content rule on the same field — every entry's commitment
/// point must be admissible — is [`check_pqc_leaf_entries`]; both run at
/// admission through [`check_pqc_field_shape_of`].
pub fn check_pqc_field_shape(
    n_outputs: usize,
    kem_lens: &[usize],
    leaf_lens: &[usize],
) -> Result<(), PqcFieldShapeError> {
    check_one(PqcExtraField::Kem, n_outputs, kem_lens)?;
    check_one(PqcExtraField::Leaf, n_outputs, leaf_lens)
}

fn check_one(
    field: PqcExtraField,
    n_outputs: usize,
    lens: &[usize],
) -> Result<(), PqcFieldShapeError> {
    if n_outputs == 0 {
        return if lens.is_empty() {
            Ok(())
        } else {
            Err(PqcFieldShapeError::PresentWithoutOutputs { field })
        };
    }
    // `n_outputs` is a vout count the caller already parsed, so this product
    // cannot overflow in practice; saturating keeps the arithmetic total
    // without inventing a variant for a state no transaction can reach.
    let expected = field.stride().saturating_mul(n_outputs);
    match lens {
        [] => Err(PqcFieldShapeError::Missing { field, expected }),
        [got] if *got == expected => Ok(()),
        [got] => Err(PqcFieldShapeError::Length {
            field,
            got: *got,
            expected,
        }),
        many => Err(PqcFieldShapeError::Duplicate {
            field,
            count: many.len(),
        }),
    }
}

/// The `0x07` content rule (`PL-D3` §6.2, admission at relay and connect):
/// each `PQC_LEAF_ENTRY_LEN` entry's first 32 bytes must decompress to a
/// canonical, prime-order, non-identity Ed25519 point. A value that fails this
/// is not a leaf any prover can open, and the tree must not store it. The
/// record half is opaque here (checked by nothing live).
///
/// The blob must be a whole, non-zero number of entries
/// ([`PqcFieldShapeError::LeafBlobLength`] otherwise) — enforced here, not
/// assumed from the shape rule, so a caller that skips the shape rule cannot
/// get a vacuous pass on a trailing remainder or an empty blob.
pub fn check_pqc_leaf_entries(blob: &[u8]) -> Result<(), PqcFieldShapeError> {
    if blob.is_empty() || !blob.len().is_multiple_of(PQC_LEAF_ENTRY_LEN) {
        return Err(PqcFieldShapeError::LeafBlobLength { got: blob.len() });
    }
    for (index, entry) in blob.chunks_exact(PQC_LEAF_ENTRY_LEN).enumerate() {
        let mut point = [0u8; PQC_LEAF_POINT_BYTES];
        point.copy_from_slice(&entry[..PQC_LEAF_POINT_BYTES]);
        if shekyl_curve_generators::pqc_leaf_point_valid(&point).is_none() {
            return Err(PqcFieldShapeError::LeafPointInvalid { index });
        }
    }
    Ok(())
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

/// [`check_pqc_field_shape`], [`check_pqc_leaf_entries`] and
/// [`check_pqc_multisig_shape`] over parsed fields.
pub fn check_pqc_field_shape_of(
    fields: &[TxExtraField],
    n_outputs: usize,
) -> Result<(), PqcFieldShapeError> {
    let kem: Vec<usize> = fields
        .iter()
        .filter_map(|f| match f {
            TxExtraField::PqcKemCiphertext(b) => Some(b.len()),
            _ => None,
        })
        .collect();
    let leaf: Vec<&[u8]> = fields
        .iter()
        .filter_map(|f| match f {
            TxExtraField::PqcLeafEntries(b) => Some(b.as_slice()),
            _ => None,
        })
        .collect();
    let leaf_lens: Vec<usize> = leaf.iter().map(|b| b.len()).collect();
    check_pqc_field_shape(n_outputs, &kem, &leaf_lens)?;
    // The shape rule admitted exactly one field (or none, with no outputs).
    if let [blob] = leaf.as_slice() {
        check_pqc_leaf_entries(blob)?;
    }
    check_pqc_multisig_shape(fields, n_outputs)
}

/// The `0x07` blob a passing [`check_tx_extra_shape`] admitted.
///
/// Empty when `n_outputs == 0` and no leaf field is present. Any other
/// disagreement — a leaf on a leafless transaction, none where one is
/// required, more than one — is the shape error, not an empty buffer. An
/// empty buffer is what the curve-tree collector used to zero-fill from.
pub fn admitted_leaf_blob(
    fields: &[TxExtraField],
    n_outputs: usize,
) -> Result<Vec<u8>, PqcFieldShapeError> {
    let mut found: Option<&[u8]> = None;
    let mut count = 0usize;
    for field in fields {
        if let TxExtraField::PqcLeafEntries(bytes) = field {
            count += 1;
            found = Some(bytes);
        }
    }
    match (n_outputs == 0, count, found) {
        (true, 0, _) => Ok(Vec::new()),
        (false, 1, Some(bytes)) => Ok(bytes.to_vec()),
        (true, _, _) => Err(PqcFieldShapeError::PresentWithoutOutputs {
            field: PqcExtraField::Leaf,
        }),
        (false, 0, _) => Err(PqcFieldShapeError::Missing {
            field: PqcExtraField::Leaf,
            expected: PqcExtraField::Leaf.stride().saturating_mul(n_outputs),
        }),
        (false, count, _) => Err(PqcFieldShapeError::Duplicate {
            field: PqcExtraField::Leaf,
            count,
        }),
    }
}

/// A conforming `0x07` entry for fixtures and tests: a valid commitment point
/// (the `J` generator — any prime-order non-identity point admits) followed by
/// an opaque record. Test fixtures must be valid in every respect but the one
/// their test is about; a random-byte filler is not a leaf.
#[must_use]
pub fn conforming_pqc_leaf_entry() -> [u8; PQC_LEAF_ENTRY_LEN] {
    let mut e = [0x7bu8; PQC_LEAF_ENTRY_LEN];
    e[..PQC_LEAF_POINT_BYTES].copy_from_slice(
        &shekyl_curve_generators::PQC_LEAF_COMMITMENT_J
            .compress()
            .to_bytes(),
    );
    e
}

/// The `0x0C` draw commitment every fixture coinbase carries: a fixed value
/// with no opening, so a fixture block commits to a seed nobody reveals and
/// issues no draw. Not zero, so a fixture cannot pass for the genesis
/// block's commitment by accident. One constant for every crate's fixtures,
/// as [`conforming_pqc_leaf_entry`] is for the leaf entry.
pub const CONFORMING_DRAW_COMMITMENT: DrawCommitment =
    DrawCommitment::from_bytes([0xDC; DRAW_COMMITMENT_LEN]);

/// `n` conforming `0x07` entries, concatenated.
#[must_use]
pub fn conforming_pqc_leaf_blob(n_outputs: usize) -> Vec<u8> {
    conforming_pqc_leaf_entry().repeat(n_outputs)
}

#[cfg(test)]
mod pqc_field_shape {
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

    const K: usize = HYBRID_KEM_CT_BYTES;
    const L: usize = PQC_LEAF_ENTRY_LEN;

    #[test]
    fn conforming_shapes_pass() {
        assert_eq!(check_pqc_field_shape(1, &[K], &[L]), Ok(()));
        assert_eq!(check_pqc_field_shape(5, &[5 * K], &[5 * L]), Ok(()));
        // The serve-credit control: no outputs, no fields.
        assert_eq!(check_pqc_field_shape(0, &[], &[]), Ok(()));
    }

    #[test]
    fn rick_s_vectors_are_refused() {
        use PqcFieldShapeError as E;
        assert_eq!(
            check_pqc_field_shape(1, &[K], &[L, L]),
            Err(E::Duplicate {
                field: PqcExtraField::Leaf,
                count: 2
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[K, K], &[L]),
            Err(E::Duplicate {
                field: PqcExtraField::Kem,
                count: 2
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[K], &[2 * L]),
            Err(E::Length {
                field: PqcExtraField::Leaf,
                got: 2 * L,
                expected: L
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[K], &[0]),
            Err(E::Length {
                field: PqcExtraField::Leaf,
                got: 0,
                expected: L
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[2 * K], &[L]),
            Err(E::Length {
                field: PqcExtraField::Kem,
                got: 2 * K,
                expected: K
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[0], &[L]),
            Err(E::Length {
                field: PqcExtraField::Kem,
                got: 0,
                expected: K
            })
        );
        assert_eq!(
            check_pqc_field_shape(1, &[], &[]),
            Err(E::Missing {
                field: PqcExtraField::Kem,
                expected: K
            })
        );
        assert_eq!(
            check_pqc_field_shape(2, &[2 * K], &[]),
            Err(E::Missing {
                field: PqcExtraField::Leaf,
                expected: 2 * L
            })
        );
        // The sentences themselves: the daemon logs these verbatim, so a
        // message that stopped naming its numbers would fail here.
        assert_eq!(
            check_pqc_field_shape(2, &[2 * K], &[])
                .unwrap_err()
                .to_string(),
            "tx_extra 0x07 missing on a transaction with outputs; 128 bytes required"
        );
        assert_eq!(
            check_pqc_field_shape(1, &[K], &[2 * L])
                .unwrap_err()
                .to_string(),
            "tx_extra 0x07 is 128 bytes; 64 required for this output count"
        );
        assert_eq!(
            check_pqc_field_shape(0, &[], &[L]),
            Err(E::PresentWithoutOutputs {
                field: PqcExtraField::Leaf
            })
        );
        assert_eq!(
            check_pqc_field_shape(0, &[K], &[]),
            Err(E::PresentWithoutOutputs {
                field: PqcExtraField::Kem
            })
        );
    }

    /// The content rule enforces its own precondition: a blob that is not a
    /// whole, non-zero number of entries is refused, never vacuously passed.
    /// 63 bytes yields zero `chunks_exact(64)` chunks (the whole blob is the
    /// remainder) and 65 bytes silently drops its last byte — both were
    /// previously `Ok`.
    #[test]
    fn content_rule_rejects_partial_and_empty_blobs() {
        use PqcFieldShapeError as E;
        assert_eq!(
            check_pqc_leaf_entries(&[0x7bu8; 63]),
            Err(E::LeafBlobLength { got: 63 })
        );
        let mut oversize = conforming_pqc_leaf_blob(1);
        oversize.push(0x7b);
        assert_eq!(
            check_pqc_leaf_entries(&oversize),
            Err(E::LeafBlobLength { got: 65 })
        );
        assert_eq!(
            check_pqc_leaf_entries(&[]),
            Err(E::LeafBlobLength { got: 0 })
        );
        // The sentence names its numbers (the daemon logs it verbatim).
        assert_eq!(
            check_pqc_leaf_entries(&[0x7bu8; 63]).unwrap_err().to_string(),
            "tx_extra 0x07 content check: blob is 63 bytes; a whole, non-zero multiple of 64 required"
        );
        // Control: the conforming whole-entry blob still passes.
        assert_eq!(check_pqc_leaf_entries(&conforming_pqc_leaf_blob(2)), Ok(()));
    }

    #[test]
    fn over_parsed_fields_the_same_rule() {
        let ok = [
            TxExtraField::PubKey([1u8; 32]),
            TxExtraField::PqcKemCiphertext(vec![0; 2 * K]),
            TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(2)),
        ];
        assert_eq!(check_pqc_field_shape_of(&ok, 2), Ok(()));
        // Content: a zero-filled field of the right length is not a leaf.
        let zeros = vec![
            TxExtraField::PqcKemCiphertext(vec![0; 2 * K]),
            TxExtraField::PqcLeafEntries(vec![0; 2 * L]),
        ];
        assert_eq!(
            check_pqc_field_shape_of(&zeros, 2),
            Err(PqcFieldShapeError::LeafPointInvalid { index: 0 })
        );
        // Content: the second entry carries a small-order point.
        let mut torsion = conforming_pqc_leaf_blob(2);
        torsion[L..L + 32].copy_from_slice(&[0u8; 32]); // y = 0: an 8-torsion point
        let bad = vec![
            TxExtraField::PqcKemCiphertext(vec![0; 2 * K]),
            TxExtraField::PqcLeafEntries(torsion),
        ];
        assert_eq!(
            check_pqc_field_shape_of(&bad, 2),
            Err(PqcFieldShapeError::LeafPointInvalid { index: 1 })
        );
        let dup = [
            TxExtraField::PqcKemCiphertext(vec![0; K]),
            TxExtraField::PqcLeafEntries(vec![0; L]),
            TxExtraField::PqcLeafEntries(vec![0; L]),
        ];
        assert_eq!(
            check_pqc_field_shape_of(&dup, 1),
            Err(PqcFieldShapeError::Duplicate {
                field: PqcExtraField::Leaf,
                count: 2
            })
        );
    }
}
