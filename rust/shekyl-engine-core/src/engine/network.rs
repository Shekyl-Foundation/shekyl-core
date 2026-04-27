// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Network discriminant for the wallet orchestrator.
//!
//! Re-exports [`shekyl_address::Network`] verbatim so the `wallet`
//! module's surface and the address-parsing layer agree on a single
//! closed enum. Cross-cutting lock 5 in the rewrite plan requires:
//!
//! > `Network` is a closed enum, no Cargo feature flags excluding
//! > variants at compile time, and a daemon-network mismatch is a typed
//! > error (`OpenError::NetworkMismatch`), never a warning.
//!
//! The current address-layer enum has three variants
//! (`Mainnet | Testnet | Stagenet`); the plan additionally calls out a
//! `Fakechain` variant for regtest / dev. Adding `Fakechain` is a
//! workspace-wide change (HRP tables, `NetworkSafetyConstants`,
//! `DerivationNetwork`, wallet-file region-1 byte parse) and is
//! deliberately scheduled as a separate commit on this same Phase 1
//! branch, so this commit's diff stays scoped to the wallet-core
//! skeleton. See `docs/V3_WALLET_DECISION_LOG.md`.

pub use shekyl_address::Network;
