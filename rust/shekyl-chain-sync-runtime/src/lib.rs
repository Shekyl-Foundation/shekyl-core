// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chain sync's runtime half (CS-3, `P2P_3_CHAIN_SYNC_BRIEF.md` CS-Q8):
//! everything around the model in `shekyl-chain-sync`.
//!
//! - [`port`]: the owner's seat on the session layer's dispatch table
//!   (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1): the `SyncOwner` the
//!   composition hands the layer, forwarding into the owner's inbox.
//! - [`owner`]: the one [`shekyl_chain_sync::Sync`] on its own `chain-sync`
//!   runtime row.
//! - [`executor`]: the model's prove jobs under the hasher budget.
//! - [`serve`]: 2011, 2013 and a peer's 2009 answered from the store: the
//!   one responder.
//!
//! The model crate takes none of this crate's dependencies (tokio, the
//! store, ingest, the session layer, RandomX), so ingest and the node
//! depend on the model and this crate depends on them (Rick, 2026-10-23:
//! the layering).

#![deny(unsafe_code)]

pub mod executor;
pub mod owner;
pub mod port;
pub mod serve;

mod outcome;
mod relay;
mod session;
mod transit;
