// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`LedgerReadGuard`]: the RAII read guard [`Engine::ledger`] returns.
//! Its own module so `engine/mod.rs` stays a module index (the engine
//! decomposition ratchet); re-exported as `engine::LedgerReadGuard`.
//!
//! [`Engine::ledger`]: super::Engine::ledger

use shekyl_engine_state::WalletLedger;

use super::local_ledger::LedgerState;

/// RAII guard returned by [`Engine::ledger`]: holds a read lock on
/// the wallet's [`LocalLedger`] and derefs transparently to
/// [`WalletLedger`].
///
/// The guard is opaque: external callers cannot observe the
/// crate-private `LedgerState` aggregate or the `LedgerIndexes`
/// half — the [`Deref`] impl projects to `WalletLedger`, the only
/// type the public surface exposes. The `inner` field is private,
/// so even though its type names the `pub(crate)` `LedgerState`,
/// the `private_interfaces` lint does not fire (the type only
/// appears in private positions). The lint *would* fire if the
/// field were `pub`; it is deliberately not. Source compatibility
/// with the pre-Stage-1 `&WalletLedger` accessor is preserved by
/// the [`Deref`] impl, so calls of the form
/// `engine.ledger().some_wallet_ledger_method()` continue to compile
/// and behave identically.
///
/// A future refactor may project directly to `WalletLedger` via
/// `std::sync::RwLockReadGuard::map` (currently
/// `mapped_lock_guards`-feature-gated) or `parking_lot::RwLock`,
/// which would remove `LedgerState` from the field type entirely
/// and eliminate the rustdoc "private item" warning on the doc
/// comment below. Tracked under V3.x in `docs/FOLLOWUPS.md` →
/// "`LedgerReadGuard` field type leaks crate-private `LedgerState`".
///
/// Hold the guard for the minimum span necessary; concurrent writers
/// (`apply_scan_result` and the [`pending`]-module mutators) cannot
/// acquire the write lock while any reader is live.
///
/// [`Deref`]: std::ops::Deref
pub struct LedgerReadGuard<'a> {
    pub(super) inner: std::sync::RwLockReadGuard<'a, LedgerState>,
}

impl std::ops::Deref for LedgerReadGuard<'_> {
    type Target = WalletLedger;

    fn deref(&self) -> &WalletLedger {
        &self.inner.ledger
    }
}
