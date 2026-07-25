// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Compatibility path for the **transfer / pending-tx workflow**.
//!
//! Implementation lives in [`crate::engine::transfer`]. That module *is*
//! the transfer workflow (`LocalPendingTx` + `PendingTxEngine`); this file
//! only re-exports the surface other engine modules historically imported
//! as `crate::engine::local_pending_tx::{…}`.
//!
//! See `docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md` §Transfer workflow
//! ownership. Do not add multi-step send logic here — only re-exports.

pub use super::transfer::LocalPendingTx;

pub(crate) use super::transfer::{ConsumerHeldEntry, RescanRequest};
