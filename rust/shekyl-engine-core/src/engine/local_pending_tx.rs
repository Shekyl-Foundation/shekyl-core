// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Compatibility path for the transfer / pending-tx implementor.
//!
//! Implementation lives in [`crate::engine::transfer`]. This module re-exports
//! the surface that other engine modules historically imported as
//! `crate::engine::local_pending_tx::{…}`.

pub use super::transfer::LocalPendingTx;

pub(crate) use super::transfer::{ConsumerHeldEntry, RescanRequest};
