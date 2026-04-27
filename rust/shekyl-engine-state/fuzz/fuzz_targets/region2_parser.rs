// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! cargo-fuzz harness for the region-2 payload parser.
//!
//! Runs [`WalletLedger::from_postcard_bytes`] against libFuzzer-
//! generated input. The property under test is the same as the
//! proptest harness in `tests/fuzz_region2.rs`: the parser must
//! never panic on any byte input. libFuzzer's advantage is
//! coverage-guided corpus evolution — the harness discovers inputs
//! that reach more of the parser's internal branches than random
//! or mutation-of-valid strategies alone would.
//!
//! # Local-only
//!
//! This crate is excluded from the parent workspace (see
//! `rust/Cargo.toml`) because `libfuzzer-sys` requires nightly Rust
//! and the sanitizer runtime. The harness runs under
//! `cargo +nightly fuzz run region2_parser` from inside this
//! directory. See `README.md` for the full invocation, the reasons
//! it is not integrated into CI yet, and the graduation plan.

#![no_main]

use libfuzzer_sys::fuzz_target;
use shekyl_engine_state::WalletLedger;

fuzz_target!(|data: &[u8]| {
    // The parser's return type already enforces "no panic, typed
    // error on failure" at the type system level. The fuzz target
    // asserts the runtime side: that no input causes an abort,
    // infinite loop (libFuzzer enforces a per-case timeout), or
    // sanitizer violation (UBSan / ASan / MSan catch memory and
    // undefined-behaviour bugs on nightly). Discarding the result
    // is deliberate — the oracle is libFuzzer's exit status, not a
    // value comparison.
    let _ = WalletLedger::from_postcard_bytes(data);
});
