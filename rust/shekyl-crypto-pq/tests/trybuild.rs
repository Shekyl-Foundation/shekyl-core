// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Regression guard for this crate's central claim: an
//! [`EncryptedOutputField`](shekyl_crypto_pq::output::EncryptedOutputField)
//! holding bytes that never met the encryption must be unrepresentable by
//! downstream code, not merely discouraged.
//!
//! The type has no public byte constructor. `OutputData` stores it (not an
//! 8+1 pair a late accessor could re-wrap), and those fields are `pub(crate)`
//! so a deserialized FFI-boundary value cannot be written onto a derived
//! output. If a future edit opens any of those, every existing runtime test
//! still passes and the guarantee silently evaporates: a comment cannot fail.
//! This test can.
//!
//! `trybuild` compiles each fixture as a *separate crate* linking this one,
//! so it sees exactly what a downstream crate sees — which is the only
//! vantage point from which the question means anything. One fixture per
//! route: a field-privacy error aborts compilation before later bodies are
//! type-checked, so sharing a file lets routes mask each other.

#[test]
fn an_unencrypted_output_field_cannot_be_constructed_downstream() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_overwritten.rs");
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_literal_constructed.rs");
    t.compile_fail("tests/trybuild/encrypted_field_has_no_byte_constructor.rs");
}
