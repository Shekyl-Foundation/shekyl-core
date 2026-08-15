// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Lifecycle methods for [`Engine`](super::Engine).
//!
//! Split by workflow so the former `lifecycle.rs` god-file is gone:
//!
//! - [`types`] — credentials, create params, open outcome
//! - [`open`] — [`Engine::create`] / [`Engine::open_full`] and the
//!   capability stubs
//! - [`assemble`] — the single field-assembly + SP-R0 reconcile
//! - [`session`] — [`Engine::change_password`] / [`Engine::close`]
//! - [`support`] — network mapping, error translation, persistence drive
//!
//! This module implements the six methods that produce, mutate, and
//! consume a `Engine<S>` handle: [`Engine::create`], [`Engine::open_full`],
//! [`Engine::open_view_only`], [`Engine::open_hardware_offload`],
//! [`Engine::change_password`], and [`Engine::close`].
//!
//! # V3.0 capability scope
//!
//! Cross-cutting decision γ (recorded in `docs/V3_WALLET_DECISION_LOG.md`)
//! locks scope: only [`Engine::open_full`] and [`Engine::create`] ship with
//! end-to-end bodies. The two non-FULL openers carry the locked
//! signatures so call-site code is forward-compatible, and they return
//! [`OpenError::CapabilityNotYetImplemented`] until the
//! `shekyl-crypto-pq` view-only / hardware-offload `AllKeysBlob`
//! constructors land. That variant is transient — its declaration in
//! [`super::error`] names the deletion target.
//!
//! # Synchronous IO
//!
//! Lifecycle methods are synchronous (`fn`, not `async fn`). The cost
//! center is Argon2id under the wallet-file envelope; that work is
//! CPU-bound with no upstream async ceremony to compose with. Callers
//! that want non-blocking semantics from an async runtime wrap each
//! call in [`tokio::task::spawn_blocking`]. Per cross-cutting lock 1,
//! [`Engine::refresh`](super::Engine) is the only async lifecycle
//! surface (lands in the refresh commit).
//!
//! # Credentials shape
//!
//! Every lifecycle method takes [`&Credentials<'_>`](Credentials), not
//! `&[u8]` directly. V3.0 has only password-based credentials, but the
//! struct gives V3.1's hardware-token integration (FIDO2 hmac-secret →
//! KEK derivation) a forward-compatible parameter shape: V3.1 adds
//! `Credentials::password_with_authenticator(...)` as a sibling and
//! existing `password_only` call sites continue to work unchanged.
//! The Decision Log entry "V3.0 ships password-only" records the
//! choice; the FOLLOWUPS entry under V3.1 names the recovery model
//! (seed-phrase restoration is the canonical recovery path).
//!
//! # Lost-state surfacing
//!
//! [`Engine::open_full`] returns an [`OpenedEngine`] sum rather than a
//! plain `Engine<S>` so the rebuilt-state recovery path
//! ([`OpenOutcome::StateLost`](shekyl_engine_file::OpenOutcome::StateLost))
//! is a typed branch the call site cannot accidentally ignore.

mod assemble;
mod open;
mod session;
mod support;
mod types;

pub(crate) use support::{drive_persistence, network_to_derivation};
pub(crate) use types::FirstStakeIntent;
pub use types::{CapabilityInput, Credentials, EngineCreateParams, OpenedEngine};

// Names the `#[path]` suite reaches via `use super::*`. Kept at this
// facade so the test file does not grow a parallel import table.
#[cfg(test)]
use crate::engine::error::{IoError, OpenError};
#[cfg(test)]
use crate::engine::{Capability, DaemonClient, Engine, SoloSigner};
#[cfg(test)]
use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
#[cfg(test)]
use shekyl_engine_file::{SafetyOverrides, WalletFile};

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
