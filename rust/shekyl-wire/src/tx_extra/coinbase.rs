// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The coinbase `extra` grammar (CEN-I20, `TXE-Q6′`).
//!
//! A coinbase extra is one layout:
//! `[0x01 pubkey, 0x02 nonce of [`COINBASE_NONCE_BYTES`], 0x06 KEM(1120·n), 0x07 leaf(64·n)]`,
//! or `[0x01, 0x02]` when the coinbase has no outputs. Acceptance is a match
//! on that slice. [`build_coinbase_extra`] is the only constructor: the
//! daemon (through `shekyl_coinbase_extra`), the genesis tool, and the
//! fixtures all call it, so the layout cannot be reassembled by hand.
//!
//! The whitelist is the consensus rule. Admitting another tag — the `0x0B`
//! attestation producer, when it exists — is an amendment of the match in
//! [`canonical_nonce`] and of [`COINBASE_TAGS`], together, not a line in
//! the producer's PR.

use std::io;

use super::{
    check_pqc_field_shape_of, serialize, ExtraShapeError, PqcFieldShapeError, TxExtraField,
    TX_EXTRA_PUBKEY_LEN, TX_EXTRA_TAG_NONCE, TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT,
    TX_EXTRA_TAG_PQC_LEAF_ENTRIES, TX_EXTRA_TAG_PUBKEY,
};

/// Fixed width of the coinbase `0x02` nonce (`TXE-Q6′`).
///
/// The header nonce is 32 bits: `2^32 / 120 s ≈ 36 MH/s` exhausts a template
/// inside one target interval, which is why an extra nonce exists at all.
/// Each byte here multiplies that by 256 — 9.2 GH/s at one byte, 2.3 TH/s at
/// two, `1.5 × 10^17 H/s` at four — so 8 never binds, and 8 is the width the
/// pool convention (`reserve_size: 8`) already uses. Fixed rather than
/// bounded, because a chosen length is itself a signal. Genesis carries eight
/// zero bytes: genesis was not nonce-searched, and zero says so.
pub const COINBASE_NONCE_BYTES: usize = 8;

/// Width of the varint that encodes [`COINBASE_NONCE_BYTES`]. One byte while
/// the nonce stays below 128. The offset test reads a built extra and fails
/// if a wider varint moves the payload.
const COINBASE_NONCE_LENGTH_WIDTH: usize = 1;

/// A tag byte.
const TAG_LEN: usize = 1;

/// Bytes from the first byte of the `0x01` pubkey to the first nonce payload
/// byte. The grammar fixes it: the key, the `0x02` tag, and the one-byte
/// length of [`COINBASE_NONCE_BYTES`]. The block template adds this to the
/// pubkey's offset in the block blob; it does not re-encode the tag and the
/// length byte.
pub const COINBASE_NONCE_OFFSET_FROM_PUBKEY: usize =
    TX_EXTRA_PUBKEY_LEN + TAG_LEN + COINBASE_NONCE_LENGTH_WIDTH;

/// Tags the grammar admits, in canonical order. The leafless layout is the
/// prefix (pubkey, nonce); an output-bearing coinbase is the whole array.
const COINBASE_TAGS: [u8; 4] = [
    TX_EXTRA_TAG_PUBKEY,
    TX_EXTRA_TAG_NONCE,
    TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT,
    TX_EXTRA_TAG_PQC_LEAF_ENTRIES,
];

/// Which transaction the shape rule is admitting.
///
/// The C ABI still passes a `bool` (`is_coinbase`); the FFI converts it
/// here so the Rust rule is not a mode flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraSubject {
    /// The closed coinbase grammar.
    Coinbase,
    /// Every other transaction: CEN-I19, and no `0x02`.
    General,
}

/// Why a coinbase extra is not the grammar's one layout.
///
/// Distinct from [`PqcFieldShapeError`]. A missing pubkey is not "a field
/// missing on a transaction with outputs", and its sentence must not say so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinbaseGrammarError {
    /// No `0x01` field.
    PubkeyMissing,
    /// More than one `0x01` field.
    PubkeyDuplicate {
        /// How many `0x01` fields were present.
        count: usize,
    },
    /// No `0x02` field.
    NonceMissing,
    /// The `0x02` payload is not [`COINBASE_NONCE_BYTES`] long.
    NonceLength {
        /// The payload length that was present.
        got: usize,
    },
    /// More than one `0x02` field.
    NonceDuplicate {
        /// How many `0x02` fields were present.
        count: usize,
    },
    /// A tag outside [`COINBASE_TAGS`].
    ForeignTag {
        /// The tag that is not in the grammar.
        tag: u8,
    },
    /// The right tags in a different order, or a length the counts did not
    /// already explain. `expected` is the tag required at `position` —
    /// `None` when the extra should already have ended — so a leafless
    /// coinbase names `0x01` or `0x02`, not a canned four-tag string.
    FieldOrder {
        /// Index of the first disagreement.
        position: usize,
        /// The tag found there. `None` when the extra ended early.
        found: Option<u8>,
        /// The tag required there. `None` when the grammar has no further tag.
        expected: Option<u8>,
    },
}

impl std::fmt::Display for CoinbaseGrammarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PubkeyMissing => {
                write!(f, "coinbase tx_extra has no 0x01 pubkey; exactly one is required")
            }
            Self::PubkeyDuplicate { count } => write!(
                f,
                "coinbase tx_extra 0x01 appears {count} times; exactly one is admitted"
            ),
            Self::NonceMissing => write!(
                f,
                "coinbase tx_extra has no 0x02 nonce; exactly one of {COINBASE_NONCE_BYTES} bytes required"
            ),
            Self::NonceLength { got } => write!(
                f,
                "coinbase tx_extra 0x02 nonce is {got} bytes; exactly {COINBASE_NONCE_BYTES} required"
            ),
            Self::NonceDuplicate { count } => write!(
                f,
                "coinbase tx_extra 0x02 appears {count} times; exactly one is admitted"
            ),
            Self::ForeignTag { tag } => write!(
                f,
                "coinbase tx_extra carries {tag:#04x}; only 0x01, 0x02, 0x06, 0x07 are admitted"
            ),
            Self::FieldOrder {
                position,
                found: Some(found),
                expected: Some(expected),
            } => write!(
                f,
                "coinbase tx_extra field {position} is {found:#04x}; {expected:#04x} is required there"
            ),
            Self::FieldOrder {
                position,
                found: None,
                expected: Some(expected),
            } => write!(
                f,
                "coinbase tx_extra ended at field {position}; {expected:#04x} is required there"
            ),
            Self::FieldOrder {
                position,
                found: Some(found),
                expected: None,
            } => write!(
                f,
                "coinbase tx_extra field {position} is {found:#04x}; the extra should have ended"
            ),
            Self::FieldOrder {
                position,
                found: None,
                expected: None,
            } => write!(
                f,
                "coinbase tx_extra layout is not the grammar at field {position}"
            ),
        }
    }
}

impl std::error::Error for CoinbaseGrammarError {}

/// [`build_coinbase_extra`] refused the inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinbaseBuildError {
    /// The fields the constructor laid out do not pass the grammar
    /// (including CEN-I19 on the KEM and leaf blobs).
    Shape(ExtraShapeError),
    /// The grammar accepted the fields and [`serialize`] still refused them
    /// — a blob past the codec's length cap. Nothing was returned.
    Unserializable,
}

impl std::fmt::Display for CoinbaseBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape(err) => write!(f, "{err}"),
            Self::Unserializable => {
                write!(f, "coinbase tx_extra exceeded a codec length cap")
            }
        }
    }
}

impl std::error::Error for CoinbaseBuildError {}

/// The tag list a coinbase of `n_outputs` must carry, in order.
fn canonical_tags(n_outputs: usize) -> &'static [u8] {
    if n_outputs == 0 {
        &COINBASE_TAGS[..2]
    } else {
        &COINBASE_TAGS
    }
}

fn admits(tag: u8) -> bool {
    COINBASE_TAGS.contains(&tag)
}

/// The nonce payload when `fields` is exactly the canonical layout for
/// `n_outputs`. Length of the nonce is not part of the match: a short nonce
/// in the right place is [`CoinbaseGrammarError::NonceLength`], not a
/// layout failure.
fn canonical_nonce(fields: &[TxExtraField], n_outputs: usize) -> Option<&[u8]> {
    match (n_outputs == 0, fields) {
        (true, [TxExtraField::PubKey(_), TxExtraField::Nonce(nonce)])
        | (
            false,
            [TxExtraField::PubKey(_), TxExtraField::Nonce(nonce), TxExtraField::PqcKemCiphertext(_), TxExtraField::PqcLeafEntries(_)],
        ) => Some(nonce),
        _ => None,
    }
}

/// The coinbase extra grammar.
///
/// CEN-I19 runs on the parsed fields either way, so a wrong KEM or leaf is
/// that verdict. The layout itself is [`canonical_nonce`]: the success arm
/// is the slice match, and everything else is named by [`diagnose`].
pub fn check_coinbase_extra_shape(
    fields: &[TxExtraField],
    n_outputs: usize,
) -> Result<(), ExtraShapeError> {
    if let Some(nonce) = canonical_nonce(fields, n_outputs) {
        check_pqc_field_shape_of(fields, n_outputs)?;
        if nonce.len() != COINBASE_NONCE_BYTES {
            return Err(CoinbaseGrammarError::NonceLength { got: nonce.len() }.into());
        }
        return Ok(());
    }
    Err(diagnose(fields, n_outputs))
}

/// The shape rule for any transaction: the coinbase grammar, or CEN-I19
/// plus "no `0x02`".
pub fn check_tx_extra_shape(
    fields: &[TxExtraField],
    n_outputs: usize,
    subject: ExtraSubject,
) -> Result<(), ExtraShapeError> {
    match subject {
        ExtraSubject::Coinbase => check_coinbase_extra_shape(fields, n_outputs),
        ExtraSubject::General => {
            check_pqc_field_shape_of(fields, n_outputs)?;
            if fields.iter().any(|f| matches!(f, TxExtraField::Nonce(_))) {
                return Err(ExtraShapeError::NonceOutsideCoinbase);
            }
            Ok(())
        }
    }
}

/// Name the first grammar defect. CEN-I19 first, then a tag outside the
/// whitelist, then pubkey cardinality, then nonce cardinality and width,
/// then the full tag sequence — length included, so a trailing field is
/// not invisible the way a `zip` against a shorter slice would make it.
fn diagnose(fields: &[TxExtraField], n_outputs: usize) -> ExtraShapeError {
    if let Err(err) = check_pqc_field_shape_of(fields, n_outputs) {
        return err.into();
    }
    for field in fields {
        let tag = field.tag();
        if !admits(tag) {
            return CoinbaseGrammarError::ForeignTag { tag }.into();
        }
    }
    let pubkeys = fields
        .iter()
        .filter(|field| matches!(field, TxExtraField::PubKey(_)))
        .count();
    match pubkeys {
        1 => {}
        0 => return CoinbaseGrammarError::PubkeyMissing.into(),
        count => return CoinbaseGrammarError::PubkeyDuplicate { count }.into(),
    }
    let nonces: Vec<&[u8]> = fields
        .iter()
        .filter_map(|field| match field {
            TxExtraField::Nonce(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .collect();
    match nonces.as_slice() {
        [] => return CoinbaseGrammarError::NonceMissing.into(),
        [nonce] if nonce.len() != COINBASE_NONCE_BYTES => {
            return CoinbaseGrammarError::NonceLength { got: nonce.len() }.into();
        }
        [_] => {}
        many => return CoinbaseGrammarError::NonceDuplicate { count: many.len() }.into(),
    }
    let want = canonical_tags(n_outputs);
    let found: Vec<u8> = fields.iter().map(TxExtraField::tag).collect();
    let shared = found.len().min(want.len());
    for position in 0..shared {
        if found[position] != want[position] {
            return CoinbaseGrammarError::FieldOrder {
                position,
                found: Some(found[position]),
                expected: Some(want[position]),
            }
            .into();
        }
    }
    // The prefix matched and the lengths differ, or the sequence is the
    // canonical one (which [`canonical_nonce`] would already have taken).
    // Either way this is not an acceptance: a trailing or missing field
    // names the tag that was there and the tag that was required, with
    // `None` when that side has ended.
    CoinbaseGrammarError::FieldOrder {
        position: shared,
        found: found.get(shared).copied(),
        expected: want.get(shared).copied(),
    }
    .into()
}

/// Build a coinbase `extra` in the grammar's one layout and refuse it here
/// if admission would.
///
/// `nonce` is exactly [`COINBASE_NONCE_BYTES`]. The KEM blob is
/// `1120 · n_outputs` bytes and the leaf blob `64 · n_outputs`. A leafless
/// coinbase (`n_outputs == 0`) is pubkey and nonce only; bytes handed in
/// anyway are pushed and then refused by the grammar, not dropped.
pub fn build_coinbase_extra(
    tx_pubkey: [u8; TX_EXTRA_PUBKEY_LEN],
    nonce: &[u8; COINBASE_NONCE_BYTES],
    n_outputs: usize,
    kem: &[u8],
    leaf: &[u8],
) -> Result<Vec<u8>, CoinbaseBuildError> {
    let mut fields = Vec::with_capacity(if n_outputs == 0 { 2 } else { 4 });
    fields.push(TxExtraField::PubKey(tx_pubkey));
    fields.push(TxExtraField::Nonce(nonce.to_vec()));
    if n_outputs > 0 || !kem.is_empty() || !leaf.is_empty() {
        fields.push(TxExtraField::PqcKemCiphertext(kem.to_vec()));
        fields.push(TxExtraField::PqcLeafEntries(leaf.to_vec()));
    }
    check_coinbase_extra_shape(&fields, n_outputs).map_err(CoinbaseBuildError::Shape)?;
    serialize(&fields).map_err(|_err: io::Error| CoinbaseBuildError::Unserializable)
}

impl From<PqcFieldShapeError> for ExtraShapeError {
    fn from(err: PqcFieldShapeError) -> Self {
        Self::Pqc(err)
    }
}

impl From<CoinbaseGrammarError> for ExtraShapeError {
    fn from(err: CoinbaseGrammarError) -> Self {
        Self::Coinbase(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_extra::{
        admitted_leaf_blob, conforming_pqc_leaf_blob, PqcExtraField, PqcFieldShapeError,
        HYBRID_KEM_CT_BYTES, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, TX_EXTRA_TAG_ARCHIVAL_ATTESTATION,
        TX_EXTRA_TAG_PADDING, TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS, TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS,
    };

    fn conforming(n: usize) -> Vec<TxExtraField> {
        let kem = vec![0x44u8; HYBRID_KEM_CT_BYTES * n];
        let leaf = if n == 0 {
            Vec::new()
        } else {
            conforming_pqc_leaf_blob(n)
        };
        let bytes = build_coinbase_extra(
            [0x11; TX_EXTRA_PUBKEY_LEN],
            &[0; COINBASE_NONCE_BYTES],
            n,
            &kem,
            &leaf,
        )
        .unwrap_or_else(|err| panic!("conforming coinbase extra for n={n}: {err}"));
        crate::tx_extra::parse(&bytes).expect("the constructor's bytes parse")
    }

    fn grammar(err: ExtraShapeError) -> CoinbaseGrammarError {
        match err {
            ExtraShapeError::Coinbase(err) => err,
            other => panic!("expected a grammar error, got {other}"),
        }
    }

    #[test]
    fn the_canonical_layout_is_admitted_for_every_output_count() {
        for n in [0usize, 1, 2, 7] {
            let fields = conforming(n);
            let tags: Vec<u8> = fields.iter().map(TxExtraField::tag).collect();
            assert_eq!(tags, canonical_tags(n), "n = {n}");
            assert_eq!(check_coinbase_extra_shape(&fields, n), Ok(()), "n = {n}");
            assert_eq!(
                check_tx_extra_shape(&fields, n, ExtraSubject::Coinbase),
                Ok(()),
                "n = {n}"
            );
            let leaf = admitted_leaf_blob(&fields, n).expect("the check admitted the leaf");
            if n == 0 {
                assert!(leaf.is_empty());
            } else {
                assert_eq!(leaf.len(), n * crate::tx_extra::PQC_LEAF_ENTRY_LEN);
            }
        }
    }

    #[test]
    fn the_nonce_payload_begins_at_the_grammar_offset() {
        let bytes = build_coinbase_extra(
            [0x11; TX_EXTRA_PUBKEY_LEN],
            &[0xA5; COINBASE_NONCE_BYTES],
            0,
            &[],
            &[],
        )
        .expect("leafless coinbase");
        // The `0x01` tag is the byte before the pubkey the offset is measured from.
        let nonce_at = TAG_LEN + COINBASE_NONCE_OFFSET_FROM_PUBKEY;
        assert_eq!(
            bytes[nonce_at - TAG_LEN - COINBASE_NONCE_LENGTH_WIDTH],
            TX_EXTRA_TAG_NONCE
        );
        assert_eq!(
            bytes[nonce_at - COINBASE_NONCE_LENGTH_WIDTH] as usize,
            COINBASE_NONCE_BYTES
        );
        assert_eq!(
            &bytes[nonce_at..nonce_at + COINBASE_NONCE_BYTES],
            &[0xA5; COINBASE_NONCE_BYTES]
        );
    }

    #[test]
    fn the_nonce_is_exactly_eight_bytes_and_exactly_one() {
        let mut fields = conforming(1);
        fields.remove(1);
        assert_eq!(
            grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
            CoinbaseGrammarError::NonceMissing
        );
        for got in [0usize, 7, 9, 255] {
            let mut fields = conforming(1);
            fields[1] = TxExtraField::Nonce(vec![0xAB; got]);
            assert_eq!(
                grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
                CoinbaseGrammarError::NonceLength { got },
                "got = {got}"
            );
        }
        let mut fields = conforming(1);
        fields.insert(2, TxExtraField::Nonce(vec![0; COINBASE_NONCE_BYTES]));
        assert_eq!(
            grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
            CoinbaseGrammarError::NonceDuplicate { count: 2 }
        );
    }

    #[test]
    fn every_tag_outside_the_whitelist_is_refused() {
        let foreign = [
            (TxExtraField::Padding(1), TX_EXTRA_TAG_PADDING),
            (
                TxExtraField::AdditionalPubKeys(vec![[0x22; TX_EXTRA_PUBKEY_LEN]]),
                TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
            ),
            (
                TxExtraField::PqcViewTagHints(vec![1]),
                TX_EXTRA_TAG_PQC_VIEW_TAG_HINTS,
            ),
            (
                TxExtraField::PqcSpendAuthPubkeys(vec![1]),
                TX_EXTRA_TAG_PQC_SPEND_AUTH_PUBKEYS,
            ),
            (
                TxExtraField::ArchivalAttestation(Vec::new()),
                TX_EXTRA_TAG_ARCHIVAL_ATTESTATION,
            ),
        ];
        for (field, tag) in foreign {
            let mut fields = conforming(1);
            fields.push(field);
            assert_eq!(
                grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
                CoinbaseGrammarError::ForeignTag { tag },
                "tag {tag:#04x}"
            );
        }
    }

    #[test]
    fn exactly_one_pubkey_and_the_sentence_does_not_talk_about_outputs() {
        let mut fields = conforming(1);
        fields.remove(0);
        let err = check_coinbase_extra_shape(&fields, 1).unwrap_err();
        assert_eq!(grammar(err), CoinbaseGrammarError::PubkeyMissing);
        assert_eq!(
            err.to_string(),
            "coinbase tx_extra has no 0x01 pubkey; exactly one is required"
        );
        // The same defect on a leafless coinbase is the same sentence.
        let leafless = vec![TxExtraField::Nonce(vec![0; COINBASE_NONCE_BYTES])];
        let err = check_coinbase_extra_shape(&leafless, 0).unwrap_err();
        assert_eq!(grammar(err), CoinbaseGrammarError::PubkeyMissing);
        assert!(
            !err.to_string().contains("outputs"),
            "a leafless coinbase has no outputs: {err}"
        );

        let mut fields = conforming(1);
        fields.push(TxExtraField::PubKey([0x12; TX_EXTRA_PUBKEY_LEN]));
        assert_eq!(
            grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
            CoinbaseGrammarError::PubkeyDuplicate { count: 2 }
        );
    }

    #[test]
    fn the_order_is_part_of_the_grammar_and_names_the_tag_required_there() {
        let mut fields = conforming(1);
        fields.swap(0, 1);
        assert_eq!(
            grammar(check_coinbase_extra_shape(&fields, 1).unwrap_err()),
            CoinbaseGrammarError::FieldOrder {
                position: 0,
                found: Some(TX_EXTRA_TAG_NONCE),
                expected: Some(TX_EXTRA_TAG_PUBKEY),
            }
        );
        let mut fields = conforming(2);
        fields.swap(2, 3);
        let err = check_coinbase_extra_shape(&fields, 2).unwrap_err();
        assert_eq!(
            grammar(err),
            CoinbaseGrammarError::FieldOrder {
                position: 2,
                found: Some(TX_EXTRA_TAG_PQC_LEAF_ENTRIES),
                expected: Some(TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT),
            }
        );
        assert_eq!(
            err.to_string(),
            "coinbase tx_extra field 2 is 0x07; 0x06 is required there"
        );
        // Leafless, swapped: the sentence names 0x01, not the four-tag layout.
        let swapped = vec![
            TxExtraField::Nonce(vec![0; COINBASE_NONCE_BYTES]),
            TxExtraField::PubKey([0x11; TX_EXTRA_PUBKEY_LEN]),
        ];
        let err = check_coinbase_extra_shape(&swapped, 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "coinbase tx_extra field 0 is 0x02; 0x01 is required there"
        );
    }

    #[test]
    fn the_pqc_rule_is_applied_first_and_unchanged() {
        let mut fields = conforming(2);
        fields[2] = TxExtraField::PqcKemCiphertext(vec![0x44; HYBRID_KEM_CT_BYTES]);
        assert_eq!(
            check_coinbase_extra_shape(&fields, 2),
            Err(ExtraShapeError::Pqc(PqcFieldShapeError::Length {
                field: PqcExtraField::Kem,
                got: HYBRID_KEM_CT_BYTES,
                expected: 2 * HYBRID_KEM_CT_BYTES,
            }))
        );
    }

    #[test]
    fn a_non_coinbase_transaction_carries_no_nonce() {
        let mut fields = conforming(1);
        fields.remove(1);
        assert_eq!(
            check_tx_extra_shape(&fields, 1, ExtraSubject::General),
            Ok(())
        );
        let fields = conforming(1);
        assert_eq!(
            check_tx_extra_shape(&fields, 1, ExtraSubject::General),
            Err(ExtraShapeError::NonceOutsideCoinbase)
        );
        assert_eq!(check_tx_extra_shape(&[], 0, ExtraSubject::General), Ok(()));
    }

    #[test]
    fn the_sentences_name_the_width_and_the_whitelist() {
        assert_eq!(
            CoinbaseGrammarError::NonceLength { got: 3 }.to_string(),
            "coinbase tx_extra 0x02 nonce is 3 bytes; exactly 8 required"
        );
        assert_eq!(
            ExtraShapeError::from(CoinbaseGrammarError::NonceLength { got: 3 }).to_string(),
            "coinbase tx_extra 0x02 nonce is 3 bytes; exactly 8 required"
        );
        assert_eq!(
            CoinbaseGrammarError::ForeignTag { tag: 0x0B }.to_string(),
            "coinbase tx_extra carries 0x0b; only 0x01, 0x02, 0x06, 0x07 are admitted"
        );
    }

    #[test]
    fn bytes_past_the_codec_cap_are_unserializable_not_a_shape_error() {
        // A length the shape rule accepts (1120 · n) and the codec's cap
        // refuses. n is far past any block, which is the point of the arm.
        let n = (crate::READ_LEN_CAP / HYBRID_KEM_CT_BYTES) + 1;
        let kem = vec![0x44u8; HYBRID_KEM_CT_BYTES * n];
        let leaf = conforming_pqc_leaf_blob(n);
        let err = build_coinbase_extra(
            [0x11; TX_EXTRA_PUBKEY_LEN],
            &[0; COINBASE_NONCE_BYTES],
            n,
            &kem,
            &leaf,
        )
        .expect_err("over the cap");
        assert_eq!(err, CoinbaseBuildError::Unserializable);
    }
}
