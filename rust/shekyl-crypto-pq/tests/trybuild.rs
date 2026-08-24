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

//! # Reading a failure in `encrypted_field_has_no_byte_constructor.stderr`
//!
//! That snapshot contains rustc's `help:` block, which lists the associated
//! functions a caller might have meant — currently `assemble` and
//! `from_ffi_json_unverified`. Trybuild compares stderr whole and offers no
//! wildcards, so the snapshot cannot be trimmed to the error line alone.
//! A mismatch there therefore means one of two things, and they are worth
//! telling apart before reaching for `TRYBUILD=overwrite`:
//!
//! - **The constructor surface changed** — a new associated function on
//!   `EncryptedOutputField`. That is exactly what this suite exists to notice,
//!   because a new way to build the type is a new way to forge one. Read it
//!   before regenerating.
//! - **The toolchain moved** and reworded its suggestion. Nothing about the
//!   invariant changed; regenerate.
//!
//! The other two fixtures carry no suggestion block and are immune to both.

#[test]
fn an_unencrypted_output_field_cannot_be_constructed_downstream() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_overwritten.rs");
    t.compile_fail("tests/trybuild/enc_fields_cannot_be_literal_constructed.rs");
    t.compile_fail("tests/trybuild/encrypted_field_has_no_byte_constructor.rs");
}
