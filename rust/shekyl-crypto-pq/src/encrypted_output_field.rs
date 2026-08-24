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
///    moment of encryption. This is the only path open to in-process Rust.
/// 2. `Deserialize`, which exists solely because
///    `shekyl_sign_fcmp_transaction` takes its outputs as JSON and the far
///    side computed the encryption. Its byte constructor is private to this
///    module, so deserializing is the *only* way to spend that path, and it is
///    a visibly deliberate act rather than a constructor call. Its only
///    non-test caller is the C++ `construct_tx*` chain, which has had no
///    production caller since `wallet2` was deleted and dies with the
///    consensus-oracle harness; this impl dies with it.
///
/// That is the whole list. There is deliberately **no** test-only byte
/// constructor: `feature = "test-utils"` would not have gated one, because
/// `shekyl-ffi` enables that feature in its *normal* dependency graph and
/// cargo unifies features across it — this crate's own `Cargo.toml` says so
/// and adds "do not treat this feature flag as the gate" (FOLLOWUPS F-7 tracks
/// the structural fix). A constructor behind it would have shipped in the
/// production archive, which is exactly the state this type exists to prevent.
/// Tests build fixtures through `Deserialize`, so they can do nothing a C++
/// caller could not.
///
/// `OutputData` stores this type, not an 8+1 pair that a late accessor
/// re-assembles. The pairing cannot drift, and a downstream crate that
/// somehow obtained the ciphertext bytes still cannot wrap them: there is
/// no public assembler. The `pub(crate)` on those `OutputData` fields
/// additionally stops a deserialized (FFI-boundary) value being written
/// onto a derived output. Widening them is pinned by
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

    /// Rebuild from bytes that arrived over the FFI JSON boundary, where the
    /// caller — not this crate — computed the encryption.
    ///
    /// **Private on purpose.** It was `pub` in the first cut of this type,
    /// which made the guarantee above false: a `#[doc(hidden)]` public
    /// constructor is still a public constructor. Confining it to this module
    /// leaves `Deserialize` as the only way to spend it, so the escape is one
    /// visible act at a boundary rather than a function any crate can call.
    const fn from_ffi_json_unverified(bytes: [u8; 9]) -> Self {
        Self(bytes)
    }
}

/// Wire encoding is the 18-character lowercase hex string the FFI JSON contract
/// already spoke when this field was a plain `[u8; 9]` — moving the codec into
/// this crate changed no bytes.
impl serde::Serialize for EncryptedOutputField {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = [0u8; 18];
        hex::encode_to_slice(self.0, &mut buf).map_err(serde::ser::Error::custom)?;
        // `encode_to_slice` writes only ASCII hex.
        serializer.serialize_str(std::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?)
    }
}

/// **This impl is the FFI JSON trust boundary**, and the only way to reach
/// `from_ffi_json_unverified`. See the type docs for why it exists and when it
/// goes away.
///
/// Deliberately not an intra-doc link: that constructor is private, and
/// rustdoc rejects a public doc linking a private item
/// (`rustdoc::private_intra_doc_links`).
///
/// The FFI contract is an unescaped 18-character hex string. Decoding
/// borrows that string from the deserializer (`&str`) and writes straight
/// into a `[u8; 9]` — no intermediate `Vec`, and no heap `String` on the
/// JSON path `shekyl_sign_fcmp_transaction` actually speaks. A deserializer
/// that cannot lend a borrowed string is refused rather than allocated for.
impl<'de> serde::Deserialize<'de> for EncryptedOutputField {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = <&str as serde::Deserialize>::deserialize(deserializer)?;
        let mut bytes = [0u8; 9];
        if s.len() != 18 {
            return Err(D::Error::custom(format!(
                "expected 18 hex characters (9 bytes), got {}",
                s.len()
            )));
        }
        hex::decode_to_slice(s, &mut bytes).map_err(D::Error::custom)?;
        Ok(Self::from_ffi_json_unverified(bytes))
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

    #[test]
    fn encrypted_field_json_is_the_same_18_char_hex_the_ffi_already_spoke() {
        // The codec moved from tx-builder's `hex_bytes9` helper into this type,
        // so "the FFI contract is untouched" is a claim about bytes and is
        // pinned here rather than asserted. `shekyl_sign_fcmp_transaction`
        // parses this from C++-produced JSON; a changed encoding would be a
        // silent break of a live boundary.
        // Private constructor, reachable here because `mod tests` is a child
        // of this module — not an API any other crate can call.
        let f = EncryptedOutputField::from_ffi_json_unverified([
            0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xab, 0xfe, 0xff,
        ]);
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(
            json, "\"00010f107f80abfeff\"",
            "18 lowercase hex characters, no separators"
        );

        let back: EncryptedOutputField = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_bytes(), f.to_bytes(), "round-trip must be exact");

        // Both malformed directions are refused rather than truncated or padded.
        assert!(
            serde_json::from_str::<EncryptedOutputField>("\"00010f107f80abfe\"").is_err(),
            "16 hex characters (8 bytes) must be refused"
        );
        assert!(
            serde_json::from_str::<EncryptedOutputField>("\"00010f107f80abfeffff\"").is_err(),
            "20 hex characters (10 bytes) must be refused"
        );
        assert!(
            serde_json::from_str::<EncryptedOutputField>("\"zz010f107f80abfeff\"").is_err(),
            "non-hex characters must be refused"
        );
    }
}
