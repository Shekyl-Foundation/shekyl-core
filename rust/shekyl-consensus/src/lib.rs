// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shekyl's output lock windows, the consensus constants the tree, the
//! validator and the wallet read from one place.
//!
//! Consensus is proof of work with one proof type (rule
//! `70-modular-consensus`): there is no proof trait or registry here, and
//! one is added only with an accepted design for a second proof type.

#![deny(unsafe_code)]

/// The minimum number of blocks a non-coinbase output is locked for before it is
/// spendable.
///
/// Under Shekyl's FCMP++ design, outputs are proven against the full UTXO curve tree
/// rather than individual decoy rings. This lock window prevents chain reorganizations
/// from invalidating proofs that reference recently-added outputs. Brought native off
/// the vendored `shekyl-oxide` in the un-vendor slice-2 dissolve.
pub const DEFAULT_LOCK_WINDOW: usize = 10;

/// The minimum number of blocks a coinbase output is locked for (coinbase maturity).
pub const COINBASE_LOCK_WINDOW: usize = 60;
