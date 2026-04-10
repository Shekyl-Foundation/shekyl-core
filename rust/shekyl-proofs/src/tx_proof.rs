// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Outbound and inbound transaction proofs.
//!
//! Outbound: sender reveals tx_key; verifier re-derives combined_ss
//! internally, projects to ProofSecrets, verifies O and amount.
//!
//! Inbound: recipient decapsulates KEM CT, derives ProofSecrets,
//! signs with view_secret_key.
