// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet capability mode (full / view-only / hardware-offload).
//!
//! Re-exports [`shekyl_wallet_file::Capability`]. The wallet-file layer
//! decodes the envelope's `capability_mode` byte into this typed enum;
//! the wallet-core orchestrator consumes it without ever pattern-matching
//! on the raw byte. The plan refers to this concept as
//! "`CapabilityMode`"; the canonical type-system spelling is
//! [`Capability`] (already established in [`shekyl-wallet-file`] before
//! the orchestrator existed).
//!
//! Use [`Capability::can_spend_locally`] for the
//! "should I offer the 'send' button?" check rather than a raw
//! `matches!(cap, Capability::Full)`. The predicate is stable across
//! future capability variants in a way the open-coded match is not.

pub use shekyl_wallet_file::Capability;
