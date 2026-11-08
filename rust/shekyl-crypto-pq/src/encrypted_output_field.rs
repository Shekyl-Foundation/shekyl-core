// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Nine-byte encrypted wire field: 8 ciphertext bytes plus its 1-byte
//! HKDF-derived tag, in the order the transaction serializer writes them.
//!
//! Re-exported from [`crate::output`] so existing `output::EncryptedOutputField`
//! paths stay valid.

/// A per-output encrypted wire field: 8 ciphertext bytes plus its 1-byte
/// HKDF-derived tag, in the order the transaction serializer writes them.
///
/// **This type exists to make one thing unrepresentable: nine bytes that never
/// went through encryption.** Both fields it models are XOR ciphertexts under a
/// one-time per-output key, so any value written by hand is a constant on the
/// wire rather than a ciphertext. For `enc_label` that is a privacy defect and
/// a silent one — an unencrypted label is identical across every output that
/// carries it, which marks exactly those outputs and breaks the §5.7.10
/// indistinguishability invariant (`SUBADDRESS_UNDER_PQC.md`). For `enc_amount`
/// it fails loudly instead, at the recipient, whose commitment will not open to
/// the decrypted value — but the assembly is the same five lines, so both are
/// typed rather than leaving the copy-paste template alive beside the field
/// just protected.
///
/// **Deliberately not built with the `shekyl-types` newtype macro.** That
/// convention gives every newtype an open `from_bytes` edge constructor, which
/// is precisely the forgery path this type exists to remove.
///
/// **Every way to obtain one, stated exhaustively** — a guarantee doc that
/// omits a path is worse than none:
///
/// 1. [`crate::output::OutputData::enc_label_wire`] /
///    [`crate::output::OutputData::enc_amount_wire`], which return the
///    [`EncryptedOutputField`] values `construct_output` assembled at the
///    moment of encryption.
///
/// That is the whole list: a value cannot exist without a derivation behind
/// it. There is deliberately **no** test-only byte
/// constructor: `feature = "test-utils"` would not gate one, because
/// `shekyl-p-serve`'s `test-signer` feature forwards it on a *normal*
/// dependency edge and cargo unifies features across a build that includes an
/// enabler (`scripts/ci/check_test_only_features.py` lists them; FOLLOWUPS F-7
/// tracks the structural fix). A constructor behind it would have shipped in the
/// production archive, which is exactly the state this type exists to prevent.
/// Tests build fixtures through `construct_output`, the production path.
///
/// `OutputData` stores this type, not an 8+1 pair that a late accessor
/// re-assembles. The pairing cannot drift, and a downstream crate that
/// somehow obtained the ciphertext bytes still cannot wrap them: there is
/// no public assembler. The `pub(crate)` on those `OutputData` fields
/// additionally stops a value taken from one output being written onto
/// another. Widening them is pinned by
/// `tests/trybuild/` — a comment cannot fail.
///
/// The bytes are public wire data — ciphertext, not key material — so this is
/// deliberately not `Zeroize`; the secrets it is derived from are wiped by
/// [`crate::output::OutputData`]'s own `ZeroizeOnDrop`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct EncryptedOutputField([u8; 9]);

impl EncryptedOutputField {
    /// Borrow the nine wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 9] {
        &self.0
    }

    /// Copy out the nine wire bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 9] {
        self.0
    }

    /// Borrow the 8-byte ciphertext prefix (serializer order: ciphertext, then tag).
    #[must_use]
    pub const fn ciphertext(&self) -> &[u8; 8] {
        match self.0.first_chunk::<8>() {
            Some(chunk) => chunk,
            None => panic!("9-byte field always has an 8-byte prefix"),
        }
    }

    /// The HKDF-derived tag byte (serializer order: last).
    #[must_use]
    pub const fn tag(&self) -> u8 {
        self.0[8]
    }

    /// Assemble from a ciphertext and its tag. `pub(crate)` on purpose: the
    /// only production caller is `construct_output`, so the value cannot exist
    /// without a derivation behind it. Not `const`: no caller is, and
    /// `copy_from_slice` is the assembly every other site already writes.
    pub(crate) fn assemble(ciphertext: [u8; 8], tag: u8) -> Self {
        let mut buf = [0u8; 9];
        buf[..8].copy_from_slice(&ciphertext);
        buf[8] = tag;
        Self(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::EncryptedOutputField;

    #[test]
    fn assemble_is_ciphertext_then_tag() {
        let f = EncryptedOutputField::assemble([1, 2, 3, 4, 5, 6, 7, 8], 0x9a);
        assert_eq!(
            f.as_bytes(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 0x9a],
            "serializer order is eight ciphertext bytes, then the tag"
        );
        assert_eq!(f.ciphertext(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(f.tag(), 0x9a);
    }
}
