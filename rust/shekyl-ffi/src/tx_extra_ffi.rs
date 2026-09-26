// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The `tx_extra` shape rule's FFI code table and message helpers
//! ([`shekyl_wire::tx_extra::check_tx_extra_shape`]: CEN-I19 —
//! `GENESIS_TX_WIRE_FORMAT.md` §9.6a as ruled 2026-09-05 — plus the coinbase
//! grammar, `TX_EXTRA_RUST_CUTOVER.md` TXE-Q6′), shared with the codec
//! surface in `tx_extra_codec_ffi`, which is where the daemon calls in
//! (`shekyl_tx_extra_shape_of`, `shekyl_tx_extra_leaf_entries`,
//! `shekyl_coinbase_extra`).
//!
//! History, because the codes' numbering shows it: this file first exported
//! a lengths-taking form, `shekyl_tx_extra_pqc_field_shape`, to which the
//! daemon's own C++ parser handed the byte length of every `0x06` / `0x07`
//! it had found. Two parsers over one consensus grammar was the divergence
//! class CEN-I19 had been routed through Rust to close (TXE-F3); the codec
//! cutover deleted the C++ parser and with it that form. Codes `1..=10` are
//! the verdicts it minted and are returned unchanged by the bytes-taking
//! successor; `11` (`ERR_MARSHALLING`, a lengths/blob disagreement that can
//! no longer occur) is retired and not re-minted; `12..=17` are the coinbase
//! grammar's.
//!
//! The daemon receives the error enum flattened to a code (`0` is
//! conformant) and the error's own sentence in a caller-owned buffer, and
//! logs that sentence verbatim rather than formatting a second one from the
//! code: two formatters producing "the same message" is a synchronisation
//! promise nobody can keep, and the rule's words belong to the crate that
//! owns the rule. The code is what the daemon branches on; the string is
//! what it prints.

use std::os::raw::c_char;

use shekyl_wire::tx_extra::{
    CoinbaseGrammarError, ExtraShapeError, PqcExtraField, PqcFieldShapeError,
};

/// Conformant.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_OK: i32 = 0;
/// A null pointer with a non-zero count.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR: i32 = 1;
/// `0x06` present on a transaction with no outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS: i32 = 2;
/// `0x06` missing on a transaction with outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING: i32 = 3;
/// More than one `0x06` field.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE: i32 = 4;
/// The `0x06` field is not `1120 · n_outputs` bytes.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH: i32 = 5;
/// `0x07` present on a transaction with no outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS: i32 = 6;
/// `0x07` missing on a transaction with outputs.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING: i32 = 7;
/// More than one `0x07` field.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE: i32 = 8;
/// The `0x07` field is not `64 · n_outputs` bytes.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH: i32 = 9;
/// A `0x07` entry's leaf commitment is not a canonical prime-order point
/// (`PL-D3` content rule).
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT: i32 = 10;
// 11 was ERR_MARSHALLING — the lengths-taking form's "declared leaf length
// disagrees with the handed-over blob". Retired with that form (the codec
// parses the extra itself, so there is no declared length to disagree with);
// not re-minted, so an old log line is never misread as a new verdict.
/// Coinbase grammar (`TXE-Q6′`): no `0x02` nonce in a coinbase extra.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING: i32 = 12;
/// Coinbase grammar: the `0x02` nonce is not exactly `COINBASE_NONCE_BYTES`.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH: i32 = 13;
/// Coinbase grammar: more than one `0x02` nonce.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_DUPLICATE: i32 = 14;
/// Coinbase grammar: a tag outside `[0x01, 0x02, 0x06, 0x07]`.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG: i32 = 15;
/// Coinbase grammar: the fields are out of canonical order, or the `0x01`
/// pubkey is missing or duplicated.
pub const SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT: i32 = 16;
/// A `0x02` nonce on a non-coinbase transaction.
pub const SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE: i32 = 17;

/// Buffer size the caller must provide for the message, NUL included. The
/// longest sentence this type produces is well under half of it; a message
/// that would not fit is truncated on a character boundary, never unterminated.
pub const SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP: usize = 256;

/// The flattened code for a shape verdict; shared with the codec surface
/// (`tx_extra_codec_ffi`), which returns these unchanged.
pub(crate) fn shape_code(err: ExtraShapeError) -> i32 {
    use CoinbaseGrammarError as Grammar;
    use ExtraShapeError as Shape;
    use PqcExtraField as Field;
    use PqcFieldShapeError as Pqc;
    match err {
        Shape::Pqc(Pqc::PresentWithoutOutputs { field: Field::Kem }) => {
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        }
        Shape::Pqc(Pqc::PresentWithoutOutputs { field: Field::Leaf }) => {
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS
        }
        Shape::Pqc(Pqc::Missing {
            field: Field::Kem, ..
        }) => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING,
        Shape::Pqc(Pqc::Missing {
            field: Field::Leaf, ..
        }) => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING,
        Shape::Pqc(Pqc::Duplicate {
            field: Field::Kem, ..
        }) => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE,
        Shape::Pqc(Pqc::Duplicate {
            field: Field::Leaf, ..
        }) => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE,
        Shape::Pqc(Pqc::Length {
            field: Field::Kem, ..
        }) => SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH,
        // `LeafBlobLength` is the content rule's own precondition
        // (`check_pqc_leaf_entries` on a blob that is not a whole, non-zero
        // number of 64-byte entries). Unreachable through this FFI — the
        // shape rule has already pinned the single field to `64 · n_outputs`
        // before the content rule runs — but mapped to the length-family
        // code (fail-closed) rather than dropped, so a future reordering
        // can never turn it into an "OK".
        Shape::Pqc(
            Pqc::Length {
                field: Field::Leaf, ..
            }
            | Pqc::LeafBlobLength { .. },
        ) => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH,
        Shape::Pqc(Pqc::LeafPointInvalid { .. }) => SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT,
        Shape::Coinbase(
            Grammar::PubkeyMissing | Grammar::PubkeyDuplicate { .. } | Grammar::FieldOrder { .. },
        ) => SHEKYL_TX_EXTRA_SHAPE_COINBASE_LAYOUT,
        Shape::Coinbase(Grammar::NonceMissing) => SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_MISSING,
        Shape::Coinbase(Grammar::NonceLength { .. }) => SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_LENGTH,
        Shape::Coinbase(Grammar::NonceDuplicate { .. }) => {
            SHEKYL_TX_EXTRA_SHAPE_COINBASE_NONCE_DUPLICATE
        }
        Shape::Coinbase(Grammar::ForeignTag { .. }) => SHEKYL_TX_EXTRA_SHAPE_COINBASE_FOREIGN_TAG,
        Shape::NonceOutsideCoinbase => SHEKYL_TX_EXTRA_SHAPE_NONCE_OUTSIDE_COINBASE,
    }
}

/// Write `msg` NUL-terminated into a caller-owned buffer, truncating on a
/// character boundary. A null buffer or a zero capacity writes nothing.
pub(crate) unsafe fn write_msg(out: *mut c_char, cap: usize, msg: &str) {
    if out.is_null() || cap == 0 {
        return;
    }
    let mut n = msg.len().min(cap - 1);
    while n > 0 && !msg.is_char_boundary(n) {
        n -= 1;
    }
    // SAFETY: `out` is writable for `cap` bytes per the caller's contract and
    // `n < cap`, so the bytes and the terminator both land inside it. The
    // regions cannot overlap: `msg` is Rust-owned.
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr().cast::<c_char>(), out, n);
        *out.add(n) = 0;
    }
}

/// Write the conforming 64-byte `0x07` leaf entry
/// ([`shekyl_wire::tx_extra::conforming_pqc_leaf_entry`]) to `out`: the
/// compressed `PQC_LEAF_COMMITMENT_J` generator followed by the fixed opaque
/// record. Exists for the C++ unit-test fixtures
/// (`tests/unit_tests/pqc_spend_fixture.h`), which previously hand-copied the
/// point's bytes — one code path on both sides makes drift impossible.
/// Test-support surface, not consensus: production callers derive real
/// entries via `shekyl_derive_pqc_leaf_entry`.
///
/// # Safety
/// `out` must point to 64 writable bytes; null is tolerated (no write).
#[no_mangle]
pub unsafe extern "C" fn shekyl_test_conforming_pqc_leaf_entry(out: *mut u8) {
    if out.is_null() {
        return;
    }
    let entry = shekyl_wire::tx_extra::conforming_pqc_leaf_entry();
    // SAFETY: caller contract — 64 writable bytes behind a non-null `out`.
    unsafe { std::ptr::copy_nonoverlapping(entry.as_ptr(), out, entry.len()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_extra_codec_ffi::{shekyl_tx_extra_shape_of, SHEKYL_TX_EXTRA_OK};
    use shekyl_wire::tx_extra::{
        conforming_pqc_leaf_blob, serialize, TxExtraField, HYBRID_KEM_CT_BYTES, PQC_LEAF_ENTRY_LEN,
    };

    /// Judge `fields` as a non-coinbase transaction with `n` outputs through
    /// the bytes-taking form, the only one the daemon has.
    fn call(n: usize, fields: &[TxExtraField], msg: &mut [c_char]) -> i32 {
        let extra = serialize(fields).expect("test fields serialize");
        unsafe {
            shekyl_tx_extra_shape_of(
                if extra.is_empty() {
                    std::ptr::null()
                } else {
                    extra.as_ptr()
                },
                extra.len(),
                n,
                false,
                msg.as_mut_ptr(),
                msg.len(),
            )
        }
    }

    fn kem(n: usize) -> TxExtraField {
        TxExtraField::PqcKemCiphertext(vec![0x44; HYBRID_KEM_CT_BYTES * n])
    }

    fn leaf(n: usize) -> TxExtraField {
        TxExtraField::PqcLeafEntries(conforming_pqc_leaf_blob(n))
    }

    /// The message the call wrote, as the daemon would read it. `CStr` keeps
    /// this portable across platforms where `c_char` is unsigned.
    fn text(msg: &[c_char]) -> String {
        // SAFETY: every path through the call under test NUL-terminates
        // inside the buffer, which is what this asserts about.
        unsafe { std::ffi::CStr::from_ptr(msg.as_ptr()) }
            .to_str()
            .expect("the message is UTF-8")
            .to_owned()
    }

    /// Every CEN-I19 code has a case, and each carries the rule's own
    /// sentence — the KATs the census cites for the code table.
    #[test]
    fn codes_follow_the_rule() {
        let mut msg = [0 as c_char; SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP];
        let pk = TxExtraField::PubKey([0x11; 32]);

        assert_eq!(
            call(1, &[pk.clone(), kem(1), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_OK
        );
        assert_eq!(text(&msg), "", "a conformant shape leaves no message");
        assert_eq!(call(0, &[], &mut msg), SHEKYL_TX_EXTRA_OK);

        assert_eq!(
            call(1, &[pk.clone(), kem(1), leaf(1), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 appears 2 times; exactly one is admitted"
        );
        assert_eq!(
            call(1, &[pk.clone(), kem(1), kem(1), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_DUPLICATE
        );

        assert_eq!(
            call(1, &[pk.clone(), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_MISSING
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x06 missing on a transaction with outputs; 1120 bytes required"
        );
        assert_eq!(
            call(1, &[pk.clone(), kem(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING
        );

        assert_eq!(
            call(2, &[pk.clone(), kem(1), leaf(2)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_LENGTH
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x06 is 1120 bytes; 2240 required for this output count"
        );
        assert_eq!(
            call(2, &[pk.clone(), kem(2), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH
        );

        assert_eq!(
            call(0, &[pk.clone(), kem(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_KEM_PRESENT_WITHOUT_OUTPUTS
        );
        assert_eq!(
            call(0, &[pk.clone(), leaf(1)], &mut msg),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_PRESENT_WITHOUT_OUTPUTS
        );

        // A null extra with a nonzero length is refused, not dereferenced.
        assert_eq!(
            unsafe {
                shekyl_tx_extra_shape_of(std::ptr::null(), 4, 1, false, msg.as_mut_ptr(), msg.len())
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_ERR_NULL_PTR
        );

        // A buffer too small truncates and still terminates; a null buffer is
        // tolerated for a caller that wants only the code.
        let mut small = [0 as c_char; 8];
        assert_eq!(
            call(1, &[pk.clone(), kem(1), leaf(1), leaf(1)], &mut small),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_DUPLICATE
        );
        assert_eq!(text(&small), "tx_extr");
        let extra = serialize(&[pk, kem(1)]).unwrap();
        assert_eq!(
            unsafe {
                shekyl_tx_extra_shape_of(
                    extra.as_ptr(),
                    extra.len(),
                    1,
                    false,
                    std::ptr::null_mut(),
                    0,
                )
            },
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_MISSING
        );
    }

    /// The `0x07` content rule (PL-D3) runs after the shape rule admits a
    /// single correctly-sized field: a zero-filled entry and a small-order
    /// point are refused with the point code, naming the entry; a valid blob
    /// passes; a wrong length is the shape rule's verdict first.
    #[test]
    fn leaf_point_content_rule() {
        let mut msg = [0 as c_char; SHEKYL_TX_EXTRA_PQC_SHAPE_MSG_CAP];
        let pk = TxExtraField::PubKey([0x11; 32]);
        let good = conforming_pqc_leaf_blob(2);
        assert_eq!(
            call(
                2,
                &[
                    pk.clone(),
                    kem(2),
                    TxExtraField::PqcLeafEntries(good.clone())
                ],
                &mut msg
            ),
            SHEKYL_TX_EXTRA_OK
        );
        let zeros = vec![0u8; 2 * PQC_LEAF_ENTRY_LEN];
        assert_eq!(
            call(
                2,
                &[pk.clone(), kem(2), TxExtraField::PqcLeafEntries(zeros)],
                &mut msg
            ),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 entry 0: leaf commitment is not a canonical prime-order point"
        );
        let mut torsion = good.clone();
        torsion[PQC_LEAF_ENTRY_LEN..PQC_LEAF_ENTRY_LEN + 32].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            call(
                2,
                &[pk.clone(), kem(2), TxExtraField::PqcLeafEntries(torsion)],
                &mut msg
            ),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_POINT
        );
        assert_eq!(
            text(&msg),
            "tx_extra 0x07 entry 1: leaf commitment is not a canonical prime-order point"
        );
        // The shape rule still fires first on a wrong length.
        assert_eq!(
            call(
                1,
                &[pk, kem(1), TxExtraField::PqcLeafEntries(good)],
                &mut msg
            ),
            SHEKYL_TX_EXTRA_PQC_SHAPE_LEAF_LENGTH
        );
    }
}
