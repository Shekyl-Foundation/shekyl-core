// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon's transaction pool (DRS-E5 PR-b, `DRS_E5_POOL_ALT_PRUNE.md`
//! §2.2), staged for the DRS-X store flip.
//!
//! # This crate holds no rule
//!
//! **`E5-Q2`, ruled 2026-10-10 with a condition: `shekyl-mempool` holds the
//! state machine and the store wiring, never a rule.** G10 forbids a second
//! admission function. A transaction is admitted by the validator's own
//! judgement — `shekyl_chain_rules::judge_slot_stateless` at
//! `TxSlot::Lone`, the function `form` runs per slot, then
//! `shekyl_chain_rules::tx_against` over [`PoolView`], then
//! `shekyl_chain_rules::policy_form` — and by nothing written here. No
//! proof, signature or range proof is verified in this crate, and no
//! consensus or policy predicate is restated in it. If a change here needs
//! to decide whether a transaction is valid, the decision belongs in
//! `shekyl-chain-rules` and this crate calls it.
//!
//! What this crate owns: which transactions the pool holds, the key images
//! they spend ([`KeyImages`], CEN-M7's map), whether each is public yet
//! (D++ acceptance criterion 2: the relay's fluff event sets the bit, and a
//! block having carried the transaction does; [`shown`] is the one read),
//! when one leaves (CEN-M10), which go into a template, and the pool file
//! (S-POOL) with its reconcile at open.
//!
//! # Policy without the store
//!
//! [`policy`] is CEN-M10's arithmetic and orders with nothing stored: the
//! fee per weight, the eviction and template orders, the weight limit and
//! the two eviction walks. It builds without the `pool` feature (the
//! default), which carries the store, the network and the wire, so the
//! economics sim calls the pool's policy without taking a store.
//!
//! # The door's caller
//!
//! The pool's door is the ingest service in `shekyl-chain-ingest`
//! (DX-Q5), which runs the pool's steps beside its cache slots.
#![deny(unsafe_code)]

#[cfg(feature = "pool")]
mod block;
#[cfg(feature = "pool")]
mod door;
#[cfg(feature = "pool")]
mod evict;
pub mod policy;
#[cfg(feature = "pool")]
mod pool;
#[cfg(feature = "pool")]
mod reconcile;
#[cfg(feature = "pool")]
mod relay;
#[cfg(feature = "pool")]
mod resolve;
#[cfg(feature = "pool")]
mod template;
#[cfg(all(test, feature = "pool"))]
mod test_paths;
#[cfg(feature = "pool")]
mod view;

#[cfg(feature = "pool")]
pub use block::Offers;
#[cfg(feature = "pool")]
pub use door::{judge, stateless, DoorFault, Judged};
#[cfg(feature = "pool")]
pub use evict::Evicted;
pub use policy::Limits;
#[cfg(feature = "pool")]
pub use pool::{Admission, Duplicate, Pool, PoolFault};
#[cfg(feature = "pool")]
pub use reconcile::{Reconciled, Removed};
#[cfg(feature = "pool")]
pub use relay::{shown, Entry, Listed, RelayView};
#[cfg(feature = "pool")]
pub use resolve::resolve_shown;
#[cfg(feature = "pool")]
pub use template::{select, select_admitting, select_shown, ListedTx, Selected, ShownBody};
#[cfg(feature = "pool")]
pub use view::{KeyImages, PoolView};
