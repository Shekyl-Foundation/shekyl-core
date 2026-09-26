// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Per-output key image — public on-chain double-spend identifier.
//!
//! `KeyImage` is the 32-byte canonical encoding of `I = x · H_p(O)`,
//! where `x` is the per-output spend secret derivative and `H_p(O)`
//! is the deterministic hash-to-point of the output's one-time
//! public key. Under a well-formed spend, the key image is the
//! consensus-visible primitive that prevents double-spending: a
//! second transaction reusing the same output produces the same
//! `I`, and the consensus layer rejects it.
//!
//! # Type-placement disposition
//!
//! The **computation** `I = x · H_p(O)` is transform-shaped and lives in
//! this crate's [`output`](crate::output) module
//! ([`scan_output_recover`](crate::output::scan_output_recover)). The
//! **name** lives in [`shekyl_types`] (`docs/design/CHAIN_RULES_CRATE.md`
//! §3.4) so the consensus-validation crate can mention a key image without
//! acquiring this crate's dependency graph; two same-named newtypes in two
//! crates are an unchecked drift source. That is a consumer-graph
//! placement, not a reclassification of the derivation as state-shaped.
//! This module re-exports the type so every existing
//! `shekyl_crypto_pq::key_image::KeyImage` path, every
//! [`KeyImage::from_canonical_bytes`] and every [`KeyImage::as_bytes`] call
//! resolves unchanged.
//!
//! The privacy-correlation discipline (truncated `Debug`, **no `Display`**,
//! `Zeroize` without `ZeroizeOnDrop`) and the `#[serde(transparent)]` wire
//! form are documented on the type itself; they moved with it, unchanged.

pub use shekyl_types::KeyImage;
