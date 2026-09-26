// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! KAT: `shekyl_types::CurveTreeRoot::EMPTY` is `SELENE_HASH_INIT`'s encoding.
//!
//! The constant is pinned as bytes in `shekyl-types` so the chain store can
//! name the empty tree — the state at chain height 0 — without depending on
//! the crate that computes generators (S-CHAIN-W §3.4). A constant pinned in
//! one crate and defined in another is exactly the shape that drifts
//! silently; this test is the thing that stops it, and it lives in the
//! defining crate's suite so a change to the generator or its encoding turns
//! it red here, where the change is made.

use shekyl_fcmp::tree::selene_hash_init;
use shekyl_types::CurveTreeRoot;

#[test]
fn empty_root_is_selene_hash_init() {
    assert_eq!(
        *CurveTreeRoot::EMPTY.as_bytes(),
        selene_hash_init(),
        "CurveTreeRoot::EMPTY drifted from SELENE_HASH_INIT — re-pin the bytes in shekyl-types"
    );
}

/// The absent-key substitute the daemon's LMDB reader returns for a missing
/// per-height root (32 zero bytes, `db_lmdb.cpp:9757`) is **not** the empty
/// tree's root — it decodes to the identity point (CEN-I12's absent-key
/// walk). Pinned so nobody "simplifies" `EMPTY` to zeros.
#[test]
fn empty_root_is_not_the_zero_encoding() {
    assert_ne!(*CurveTreeRoot::EMPTY.as_bytes(), [0u8; 32]);
}
