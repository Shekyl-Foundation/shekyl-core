// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! MSW-1 cross-crate consistency: shekyl-wire's PQC blob constants are retyped
//! twins of `shekyl-crypto-pq`'s canonical values.
//!
//! shekyl-wire keeps a minimal *runtime* dependency surface (crypto-hash only;
//! crypto-pq is a dev-dependency, by deliberate design — see `Cargo.toml`), so
//! it cannot import the canonical constants at build time the way
//! `shekyl-archival-retention` does. Instead the values are pinned equal here.
//!
//! For a boundary two units are deliberately kept from sharing at compile
//! time, a "read both, assert equal" test is the only mechanism that catches
//! them drifting — which is exactly what F-1 was (each side internally
//! consistent, disagreeing with the container). The canonical source is
//! `shekyl-crypto-pq` (`CANONICAL_LEN` on the type, `expected_*_len`, the
//! `const` ceiling asserts). This file pins both twins to it: shekyl-wire's
//! constants, and the C++ definitions in `src/cryptonote_config.h`, which the
//! daemon serializer still enforces. The header is read here so the pin does
//! not need an FFI export.

use shekyl_crypto_pq::multisig::{
    MAX_MULTISIG_PARTICIPANTS, PQC_MAX_PUBLIC_KEY_BLOB as CANON_MAX_KEY_BLOB,
    PQC_MAX_SIGNATURE_BLOB as CANON_MAX_SIG_BLOB, SINGLE_KEY_CANONICAL_LEN,
    SINGLE_SIG_CANONICAL_LEN, SPEND_AUTH_PUBKEY_LEN,
};
use shekyl_wire::transaction::{
    PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN, PQC_MAX_PUBLIC_KEY_BLOB,
    PQC_MAX_SIGNATURE_BLOB,
};

#[test]
fn wire_pqc_consts_equal_crypto_pq_canonical() {
    assert_eq!(
        PQC_HYBRID_SINGLE_KEY_LEN, SINGLE_KEY_CANONICAL_LEN,
        "shekyl-wire single hybrid-key length drifted from crypto-pq canonical"
    );
    assert_eq!(
        PQC_HYBRID_SINGLE_SIG_LEN, SINGLE_SIG_CANONICAL_LEN,
        "shekyl-wire single hybrid-signature length drifted from crypto-pq canonical"
    );
    assert_eq!(
        PQC_MAX_PUBLIC_KEY_BLOB, CANON_MAX_KEY_BLOB,
        "shekyl-wire key-blob DoS ceiling drifted from crypto-pq"
    );
    assert_eq!(
        PQC_MAX_SIGNATURE_BLOB, CANON_MAX_SIG_BLOB,
        "shekyl-wire signature-blob DoS ceiling drifted from crypto-pq"
    );
}

/// The C++ header, compiled into this test. One definition per name.
const CPP_PQC_CONFIG: &str = include_str!("../../../src/cryptonote_config.h");

/// The integer assigned to `name` in [`CPP_PQC_CONFIG`].
///
/// A definition is a `const` or `constexpr` line whose identifier is `name`
/// and whose initializer is a bare decimal integer (`= 1996` or `{5}`).
/// Zero matches means the subject left the header. Two matches means the
/// pin no longer knows which one the serializer uses.
fn assigned_usize(header: &str, name: &str) -> usize {
    let mut found = Vec::new();
    for (line_no, line) in header.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("const ") && !trimmed.starts_with("constexpr ") {
            continue;
        }
        let Some(at) = trimmed.find(name) else {
            continue;
        };
        let before = trimmed[..at].chars().next_back();
        if before.is_some_and(|c| c == '_' || c.is_ascii_alphanumeric()) {
            continue;
        }
        let after = &trimmed[at + name.len()..];
        if after.starts_with(|c: char| c == '_' || c.is_ascii_alphanumeric()) {
            continue;
        }
        let after = after.trim_start();
        let Some(after) = after.strip_prefix('=').or_else(|| after.strip_prefix('{')) else {
            continue;
        };
        let after = after.trim_start();
        let digits = after.chars().take_while(char::is_ascii_digit).count();
        assert!(
            digits > 0,
            "line {}: {name} has no integer initializer",
            line_no + 1
        );
        let tail = after[digits..].trim_start();
        assert!(
            tail.starts_with(';') || tail.starts_with('}'),
            "line {}: {name} initializer is not a bare integer",
            line_no + 1
        );
        found.push(after[..digits].parse::<usize>().expect("digits"));
    }
    assert_eq!(
        found.len(),
        1,
        "{name} must be defined once in cryptonote_config.h, found {found:?}"
    );
    found[0]
}

#[test]
fn cpp_header_pqc_consts_equal_crypto_pq_canonical() {
    let canonical = [
        ("PQC_HYBRID_SINGLE_KEY_LEN", SINGLE_KEY_CANONICAL_LEN),
        ("PQC_HYBRID_SINGLE_SIG_LEN", SINGLE_SIG_CANONICAL_LEN),
        ("PQC_SPEND_AUTH_PUBKEY_LEN", SPEND_AUTH_PUBKEY_LEN),
        (
            "MAX_MULTISIG_PARTICIPANTS",
            usize::from(MAX_MULTISIG_PARTICIPANTS),
        ),
        ("PQC_MAX_PUBLIC_KEY_BLOB", CANON_MAX_KEY_BLOB),
        ("PQC_MAX_SIGNATURE_BLOB", CANON_MAX_SIG_BLOB),
    ];
    for (name, value) in canonical {
        assert_eq!(
            assigned_usize(CPP_PQC_CONFIG, name),
            value,
            "cryptonote_config.h {name} drifted from shekyl-crypto-pq"
        );
    }
}
