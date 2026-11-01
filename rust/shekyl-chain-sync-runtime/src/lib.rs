// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's runtime half (CS-3, `P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q8):
//! everything around the model in `shekyl-chain-sync`.
//!
//! - [`router`]: the seam's post sink. Pass-through in the daemon until the
//!   cutover attaches the owner.
//! - [`owner`]: the one [`shekyl_chain_sync::Sync`] on its own `chain-sync`
//!   runtime row.
//! - [`executor`]: the model's prove jobs under the hasher budget.
//! - [`serve`]: 2011 and 2013 answered from the store.
//! - [`chain_entry`]: the 2007 chain entry and the handler's other sync
//!   reads. CS-5 deletes that caller; the reads stay with the responder.
//!
//! The model crate takes none of this crate's dependencies (tokio, the
//! store, ingest, the seam, RandomX), so ingest and the node depend on the
//! model and this crate depends on them (Rick, 2026-10-23: the layering).

#![deny(unsafe_code)]

pub mod chain_entry;
pub mod executor;
pub mod owner;
pub mod router;
pub mod serve;

mod relay;
mod session;
