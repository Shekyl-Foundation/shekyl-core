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
//! (the relay's fluff event sets the bit; D++ acceptance criterion 2),
//! when one leaves (CEN-M10), which go into a template, and the pool file
//! (S-POOL) with its reconcile at open.
//!
//! # Nothing here is wired live
//!
//! The C++ `tx_memory_pool` is the daemon's pool until the DRS-X flip,
//! which wires this crate in and deletes the C++ (`DEL-010`). No FFI crate
//! depends on this one (DX-Q5, DX-Q7).

mod view;

pub use view::{KeyImages, PoolView};
