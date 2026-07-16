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
//! This is the Rust↔Rust analog of the C++↔Rust cross-language KAT: for a
//! boundary two units are deliberately kept from sharing at compile time, a
//! "read both, assert equal" test is the only mechanism that catches them
//! drifting from each other — which is exactly what F-1 was (each side
//! internally consistent, disagreeing with the container). The canonical source
//! is `shekyl-crypto-pq` (`CANONICAL_LEN` on the type, `expected_*_len`, the
//! `const` ceiling asserts); this test is the pin that keeps the wire twin honest.

use shekyl_crypto_pq::multisig::{
    PQC_MAX_PUBLIC_KEY_BLOB as CANON_MAX_KEY_BLOB, PQC_MAX_SIGNATURE_BLOB as CANON_MAX_SIG_BLOB,
    SINGLE_KEY_CANONICAL_LEN, SINGLE_SIG_CANONICAL_LEN,
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
