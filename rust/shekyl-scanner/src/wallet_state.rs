// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Re-export shim for the live-mutating wallet state type.
//!
//! The canonical type lives in [`shekyl_wallet_state::runtime_state`] under the name
//! `RuntimeWalletState`. Within this crate (and its reverse dependencies) the
//! transitional alias `WalletState` keeps the 2b diff surgical — every call site
//! continues to read `WalletState::new()`, `ws.balance(…)`, `ws.process_scanned_outputs(…)`.
//!
//! The scanner-specific methods (`process_scanned_outputs`, `balance`,
//! `claimable_rewards_summary`) are provided by [`crate::runtime_ext::WalletStateExt`]
//! and require the trait to be in scope at the call site. Both the alias and the trait
//! disappear in Commit 2n once every caller has been audited and updated to use
//! `RuntimeWalletState` / `WalletStateExt` directly.

pub use shekyl_wallet_state::runtime_state::RuntimeWalletState as WalletState;
