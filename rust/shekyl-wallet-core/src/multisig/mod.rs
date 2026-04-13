// Copyright (c) 2025-2026, The Shekyl Foundation
// All rights reserved. BSD-3-Clause

//! FROST multisig wallet orchestration.
//!
//! Provides wallet-level abstractions for FROST threshold signing:
//!
//! - [`MultisigGroup`] -- M-of-N group metadata and key material.
//! - [`MultisigDkgSession`] -- Drives the DKG protocol rounds and
//!   serializes/deserializes round messages for file-based transport.
//! - [`MultisigSigningSession`] -- Drives the FROST signing protocol,
//!   collecting nonce commitments and partial shares from M signers,
//!   then aggregating into a complete FCMP++ proof.

pub mod dkg;
pub mod group;
pub mod signing;

pub use dkg::MultisigDkgSession;
pub use group::MultisigGroup;
pub use signing::MultisigSigningSession;

#[cfg(test)]
mod tests;
