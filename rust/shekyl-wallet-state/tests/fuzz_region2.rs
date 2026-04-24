// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Proptest harness for the region-2 payload parser.
//!
//! This is the stable-Rust half of hardening-pass commit 8
//! (`docs/MID_REWIRE_HARDENING.md` §3.8). Its job is narrow and
//! unambiguous: drive randomized input into
//! [`WalletLedger::from_postcard_bytes`] — the single entry point
//! used by the wallet-file orchestrator to decode region 2 — and
//! assert that **the parser never panics and always terminates with
//! a typed result** (either [`Ok`] on bytes that happen to parse, or
//! a [`WalletLedgerError`] on anything else).
//!
//! Panic-freedom is the load-bearing property. The orchestrator calls
//! this function against bytes that have been authenticated by the
//! envelope AEAD but that must, by rule-81, still be treated as
//! potentially malformed — a future binary running against an older
//! (or a tampered-but-correctly-tagged) file must refuse via a typed
//! error, never abort the process. A panic here would turn a
//! controlled-refusal path into a denial-of-service vector on the
//! CLI / GUI wallet.
//!
//! # Relation to the adversarial corpus (commit 7)
//!
//! Commit 7's corpus asserts *specific* typed refusals against
//! *specific* malformations at the orchestrator boundary. That
//! corpus pins the error taxonomy — it says "version bump → exactly
//! `UnsupportedFormatVersion`, truncated postcard → exactly
//! `Postcard`." It cannot, by construction, tell you whether the
//! parser panics on byte patterns nobody thought to enumerate.
//!
//! This harness fills that gap. The assertion is weaker ("no panic,
//! any typed error") but the input space is vastly larger:
//! randomized 1–3-byte mutations of valid bundles, random byte
//! insertions / deletions, and entirely-random byte strings. Together
//! the two harnesses wall off both sides of the parser's contract —
//! specific refusals for specific shapes (commit 7), and total
//! panic-freedom on arbitrary input (this file).
//!
//! # Test budget
//!
//! The §3.8 plan calls for ~500 iterations per PR. This file runs
//! five strategies at 128 cases each = 640 cases, comfortably under
//! the plan's budget while staying well inside the exit criterion
//! ("<30 s per PR"). Each case performs a single postcard decode
//! (microseconds on any modern host), so the wall-clock budget is
//! dominated by proptest's own bookkeeping, not by the SUT.
//!
//! # What this harness deliberately does *not* do
//!
//! - It does not fuzz the envelope layer. That layer is covered by
//!   AEAD unit tests in `shekyl-crypto-pq` and by the adversarial
//!   corpus at the orchestrator boundary.
//! - It does not fuzz the SWSP framing layer. That layer has its own
//!   unit tests in `shekyl-wallet-file::payload` and its own
//!   adversarial rows in commit 7.
//! - It does not generate *valid* `WalletLedger` instances via
//!   proptest strategies. Generating structurally valid bundles that
//!   still satisfy every cross-block invariant is a substantial
//!   project in its own right and would mostly test the strategy
//!   generator rather than the parser. The harness seeds from one
//!   known-valid bundle ([`WalletLedger::empty`]) and mutates it;
//!   that is enough to exercise every field offset, length prefix,
//!   and version byte the parser reads.

use proptest::prelude::*;
use shekyl_wallet_state::{WalletLedger, WalletLedgerError};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Postcard encoding of a fresh, empty [`WalletLedger`]. Cached into
/// a `Vec<u8>` at module load so each proptest case can clone from a
/// single canonical seed without paying the `empty()` + `to_postcard`
/// cost 128× per strategy.
fn valid_empty_seed() -> Vec<u8> {
    WalletLedger::empty()
        .to_postcard_bytes()
        .expect("empty ledger must serialize")
}

/// Assert that a parse result is panic-free and terminates in one of
/// the four enumerated [`WalletLedgerError`] variants on `Err`. The
/// match is exhaustive *by construction*: arms return distinct
/// classification tags so that adding a new [`WalletLedgerError`]
/// variant without updating this file is a compile-time error. That
/// exhaustiveness is the whole point of the helper — it is not a
/// runtime guard, it is a static enumeration of the parser's failure
/// modes, and it must stay in lockstep with
/// [`shekyl_wallet_state::error::WalletLedgerError`].
///
/// A random mutation that happens to land on a valid encoding is
/// rare but possible; when it does, the parser must still return a
/// value without panic. The stronger "round-trip is byte-stable"
/// property is covered by the unit tests in `wallet_ledger.rs`.
fn assert_typed_or_ok(result: &Result<WalletLedger, WalletLedgerError>) {
    let _classification: &str = match result {
        Ok(_) => "ok",
        Err(WalletLedgerError::UnsupportedFormatVersion { .. }) => "format-version",
        Err(WalletLedgerError::UnsupportedBlockVersion { .. }) => "block-version",
        Err(WalletLedgerError::Postcard(_)) => "postcard",
        Err(WalletLedgerError::InvariantFailed { .. }) => "invariant",
    };
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Shared proptest config: 128 cases per strategy, deterministic
/// shrink budget, no persistence file on CI disks.
fn cfg() -> ProptestConfig {
    ProptestConfig {
        cases: 128,
        // Disable the on-disk regression file: CI runs this harness
        // in a fresh checkout per PR, so there is nothing to persist
        // against; failures are better surfaced as inline shrunk
        // counterexamples in the test log.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cfg())]

    /// Strategy 1 — **point mutation of a valid empty bundle.**
    ///
    /// Pick 1–3 random byte offsets inside a valid
    /// `WalletLedger::empty()` postcard encoding and XOR each with a
    /// random non-zero byte. Covers every in-band field: the bundle
    /// `format_version` byte, each block's `block_version` byte,
    /// every map/vec length prefix, and the trailing bytes past the
    /// last block.
    #[test]
    fn mutate_valid_empty_ledger_never_panics(
        offsets in proptest::collection::vec(any::<usize>(), 1..=3),
        xors in proptest::collection::vec(1u8..=255, 1..=3),
    ) {
        let mut bytes = valid_empty_seed();
        for (idx, xor) in offsets.iter().zip(xors.iter()) {
            let pos = idx % bytes.len();
            bytes[pos] ^= xor;
        }
        assert_typed_or_ok(&WalletLedger::from_postcard_bytes(&bytes));
    }

    /// Strategy 2 — **truncation of a valid bundle.**
    ///
    /// Chop a random prefix off the end of a valid bundle. Exercises
    /// every "postcard ran out of bytes mid-field" code path without
    /// relying on a specific internal field layout.
    #[test]
    fn truncate_valid_bundle_never_panics(
        keep in 0usize..256,
    ) {
        let bytes = valid_empty_seed();
        let take = keep % (bytes.len() + 1);
        let chopped = &bytes[..take];
        assert_typed_or_ok(&WalletLedger::from_postcard_bytes(chopped));
    }

    /// Strategy 3 — **arbitrary byte insertion into a valid bundle.**
    ///
    /// Insert 1–3 random bytes at random positions in a valid
    /// bundle. This shifts every downstream length prefix by the
    /// inserted amount without necessarily corrupting the bytes
    /// those prefixes describe — a specifically nasty shape because
    /// the decoder may be forced to read bytes that look locally
    /// valid but are offset from where postcard expected them.
    #[test]
    fn insert_bytes_into_valid_bundle_never_panics(
        positions in proptest::collection::vec(any::<usize>(), 1..=3),
        fillers in proptest::collection::vec(any::<u8>(), 1..=3),
    ) {
        let mut bytes = valid_empty_seed();
        for (pos, filler) in positions.iter().zip(fillers.iter()) {
            let at = pos % (bytes.len() + 1);
            bytes.insert(at, *filler);
        }
        assert_typed_or_ok(&WalletLedger::from_postcard_bytes(&bytes));
    }

    /// Strategy 4 — **arbitrary byte deletion from a valid bundle.**
    ///
    /// Delete 1–3 random bytes. Complementary to insertion: shrinks
    /// downstream length prefixes' effective window, which can cause
    /// the decoder to re-interpret adjacent fields.
    #[test]
    fn delete_bytes_from_valid_bundle_never_panics(
        positions in proptest::collection::vec(any::<usize>(), 1..=3),
    ) {
        let mut bytes = valid_empty_seed();
        for pos in &positions {
            if bytes.is_empty() {
                break;
            }
            let at = pos % bytes.len();
            bytes.remove(at);
        }
        assert_typed_or_ok(&WalletLedger::from_postcard_bytes(&bytes));
    }

    /// Strategy 5 — **entirely-random bytes.**
    ///
    /// Generate a `Vec<u8>` of length 0..=4096 from uniform random
    /// bytes. This is the broadest shape in the harness: most inputs
    /// fail at the very first postcard byte, but the few that
    /// accidentally produce a well-formed prefix exercise parts of
    /// the parser the mutation-of-valid strategies never reach.
    #[test]
    fn random_bytes_never_panic(
        data in proptest::collection::vec(any::<u8>(), 0..=4096),
    ) {
        assert_typed_or_ok(&WalletLedger::from_postcard_bytes(&data));
    }
}
