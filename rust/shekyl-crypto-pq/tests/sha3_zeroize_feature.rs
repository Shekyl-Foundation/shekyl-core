// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Plumbing-level smoke test for `sha3`'s `zeroize` feature.
//!
//! `Sha3State` (the type that gains `Zeroize + ZeroizeOnDrop` when
//! `sha3`'s `zeroize` feature is enabled) is `pub(crate)` to `sha3`,
//! so `assert_impl_all!(Sha3State, Zeroize, ZeroizeOnDrop)` is not
//! buildable from this crate. The end-to-end behavioral verification
//! — that `derive_output_handle`'s `CShake256` invocation produces
//! the `STAGE_1_PR_3_KEY_ENGINE.md` §7.12 documented outputs and the
//! sponge state wipes on drop via the Drop-glue cascade through
//! `Sha3State` — lives in `derive_output_handle`'s known-answer
//! tests once that primitive lands.
//!
//! What this file gates: `CShake256` is constructible and produces
//! non-trivial output through the `digest` ExtendableOutput surface.
//! That alone catches the bug class "the dep was removed or
//! downgraded below `CShake256` availability" before any downstream
//! M3a code relies on it. Asserting specific output bytes would be
//! a re-implementation of `sha3`'s own KAT suite, which the M3a
//! migration plan §3.1 explicitly forbids.
//!
//! Stale-doc note (resolved at M3a docs-update task): the migration
//! plan §3.1 success criterion 4 originally read "compilation check
//! that `Sha3State: Zeroize` is satisfied," which is unimplementable
//! given `Sha3State`'s `pub(crate)` visibility. The corrected
//! criterion: "the `zeroize` feature flag is set on `sha3`'s direct
//! dep in `shekyl-crypto-pq/Cargo.toml`, with end-to-end verification
//! deferred to `derive_output_handle`'s KAT once that primitive
//! lands."

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

#[test]
fn cshake256_constructible_and_produces_output() {
    let core = CShake256Core::new(b"shekyl/m3a-feature-flag-smoke-v0");
    let mut hasher = CShake256::from_core(core);
    hasher.update(b"feature-flag plumbing test");
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 16];
    reader.read(&mut out);
    assert!(
        out.iter().any(|&b| b != 0),
        "cSHAKE256 produced all-zero output for non-empty input; the \
         `sha3` dep is wired but the algorithm is not behaving",
    );
}
