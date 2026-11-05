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
//! The network is the network table's (`shekyl-network`, four networks,
//! regtest included; `NETWORK_IDENTITY.md`).

pub use shekyl_address::Network;
