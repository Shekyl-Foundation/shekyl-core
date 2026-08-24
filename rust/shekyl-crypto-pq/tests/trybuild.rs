// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Regression guard for this crate's central claim: an
//! [`EncryptedOutputField`](shekyl_crypto_pq::output::EncryptedOutputField)
//! holding bytes that never met the encryption must be unrepresentable by
//! downstream code, not merely discouraged.
//!
//! That guarantee rests entirely on four `pub(crate)` fields of
//! `OutputData` — the ciphertext/tag pairs the wire accessors read. If a
//! future edit widens any of them back to `pub`, every existing test still
//! passes and the guarantee silently evaporates: the type's doc comment
//! ("Do not widen these back to `pub`") is a comment, and a comment cannot
//! fail. This test can.
//!
//! `trybuild` compiles the fixture as a *separate crate* linking this one,
//! so it sees exactly what a downstream crate sees — which is the only
//! vantage point from which the question means anything.

#[test]
fn an_unencrypted_output_field_cannot_be_constructed_downstream() {
    let t = trybuild::TestCases::new();
    // Two fixtures, not one: a field-privacy error aborts the compilation
    // before later bodies are type-checked, so the two routes mask each
    // other if they share a file (observed — the literal error vanished
    // from the snapshot entirely).
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_overwritten.rs");
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_literal_constructed.rs");
}
