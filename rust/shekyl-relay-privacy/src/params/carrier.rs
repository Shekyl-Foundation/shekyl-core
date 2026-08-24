// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The carrier's two **derived** sizes — the emission window and the fragment
//! cap.
//!
//! # Not `inherited`, and the distinction is the point
//!
//! [`super::inherited`] is the single Rust mirror of the `cryptonote_config.h`
//! relay block. These two are **not** mirrors: they replace
//! `CRYPTONOTE_NOISE_BYTES` (3 KiB) and `CRYPTONOTE_MAX_FRAGMENTS` (20), both
//! of which are deleted from C++ by the same change that adds this module —
//! discharging the FOLLOWUP `levin_notify.cpp` recorded beside its own guard
//! ("*the constants should cross to Rust and `NoiseQueues`' window should be
//! derived from them, at which point this assertion moves with them*").
//!
//! # Why the inherited pair could not stay
//!
//! Neither had a derivation. The 3 KiB window was a Monero cadence artifact,
//! and **`CRYPTONOTE_MAX_FRAGMENTS` was set equal to
//! [`super::inherited::noise_windows_in_epoch`]`(300)`** — the epoch *ceiling*
//! on the cap rather than a cap derived from the transactions it has to carry.
//! It was a number satisfying a constraint nobody had connected to its
//! subject, so it was unattached rather than wrong.

/// Bytes in one noise emission — every send, real fragment and dummy alike.
///
/// # A construction parameter, NOT a runtime reference
///
/// This sizes the dummy a caller hands to `NoiseQueues::new`. The queue's
/// own `window()` is `dummy.len()` **and nothing else**, deliberately: one
/// source of truth inside the queue is what makes the length property
/// checkable there. **Nothing may read this constant at send time.** If a
/// caller ever compares `queue.window()` against this value, the duplicate
/// that design removed is back — and the two can then disagree, which is
/// the length leak the invariant exists to prevent.
///
/// # Derivation
///
/// The modal transaction whole at **every** tree depth, plus its levin
/// envelope, plus margin:
///
/// | term | bytes |
/// | --- | --- |
/// | modal tx (1-in/2-out) at `MAX_TREE_DEPTH`, widest fee varint | 17,015 |
/// | `NOTIFY_NEW_TRANSACTIONS` envelope | 77 |
/// | **required** | **17,092** |
/// | this window | 20,480 |
/// | margin | 3,388 (19.8 %) |
///
/// The envelope is **not** a constant: it steps 74 → 75 → 77 B as the
/// blob's length varint widens, and gains ~2 B per additional transaction
/// in a batch. 77 is its value for one transaction anywhere above the
/// 16 KiB varint boundary, which covers this whole range — but the test
/// measures it rather than assuming it, because a single reading at one
/// blob size would have embedded a shape into a shape-independent number.
///
/// Sized at *max* depth rather than genesis depth so the fragment count
/// cannot flip from 1 to 2 as the curve tree deepens: a hop that doubles on
/// a chain-state threshold is exactly the timing-observable drift a fixed
/// window exists to avoid.
///
/// **Not sized to hold the largest admissible transaction.** That is the
/// fragment cap's job ([`MAX_FRAGMENTS`]); conflating the two forces a
/// ~98 KiB window, which at any usable cadence breaches the pre-registered
/// 8 KiB/s bandwidth ceiling (`COVER_TRAFFIC_RESTORATION.md` §1.7 axis 2).
///
/// The derivation is **enforced, not performed** — `tests/carrier_window.rs`
/// builds a real `NOTIFY_NEW_TRANSACTIONS` at the predicted size and
/// asserts it fits, so a proof-size change reds a test naming this constant
/// instead of silently eroding the margin. Both numbers above are read back
/// from `predict_size_and_weight` and `notify` there; neither is a literal
/// the test could agree with by construction.
pub const WINDOW_BYTES: usize = 20_480;

/// The most windows one real notification may occupy on a noise channel.
///
/// # Derived, and comfortable
///
/// A correctness bound: `ceil(S_max / WINDOW_BYTES)`, where `S_max` is the
/// **structural** maximum message — the largest transaction the wire admits
/// (8-in/16-out at `MAX_TREE_DEPTH`) plus its levin envelope, which is
/// `ceil(98_046 / 20_480) = 5`.
///
/// The transaction alone is **97,964 B at a realistic fee and 97,969 B at
/// `u64::MAX`** — the fee is a varint, so its width moves with its value.
/// Both figures appear in this round's notes and they are the same
/// transaction. The bound is taken at the wider one, because a bound
/// evaluated at a plausible fee is one a large fee can cross.
///
/// The structural max is the right basis *here*, where it is a correctness
/// bound that does not drift as the tree deepens — unlike the window, which
/// is sized for the latency of the common case.
///
/// Two ceilings sit above it and neither binds: the epoch affords
/// [`super::inherited::noise_windows_in_epoch`]`(300) = 20` windows, and the
/// levin packet limit affords far more. Both are asserted in
/// `tests/carrier_window.rs` against the real constants. The derivation itself
/// is `ceil(S_max / WINDOW_BYTES)`, pinned as equality there — the inherited
/// 20 sat in `[ceil, epoch-ceiling]` and would still go green under a
/// one-sided bound.
pub const MAX_FRAGMENTS: u32 = 5;
