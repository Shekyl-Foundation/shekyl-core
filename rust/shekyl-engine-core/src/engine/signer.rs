// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Signer-kind type parameter for the [`Engine`](super::Engine)
//! orchestrator.
//!
//! The Phase 1 plan locks the wallet's solo / multisig dispatch into the
//! type system: `Engine<S: EngineSignerKind>`, with `S` ranging over
//! [`SoloSigner`] (V3.0 default) and `MultisigSigner<N, K>` (V3.1, lands
//! behind the `multisig` Cargo feature). Choosing the dispatch axis at
//! compile time means the V3.1 enablement is a feature flip on call
//! sites, not a refactor.
//!
//! [`EngineSignerKind`] is sealed: only this crate may add variants.
//! Downstream code parameterizes `Engine<S>` with `SoloSigner` (or, in
//! V3.1, the multisig type), but cannot introduce a third kind. Sealing
//! preserves the audit guarantee that every wallet operation knows which
//! of the two well-defined signing paths it is on.

mod private {
    pub trait Sealed {}
}

/// Marker trait gating the type parameter on
/// [`Engine`](super::Engine). Sealed: see module docs.
///
/// # Why a sealed trait, not an enum?
///
/// An enum would force every method that depends on signer kind to
/// `match` at runtime, which produces unreachable arms in V3.0 (where
/// only `SoloSigner` exists) and reintroduces the runtime-mode-flag
/// pattern the rewrite plan rejects. A trait with associated items lets
/// each kind name its own associated types (e.g., the eventual
/// `SignaturePayload`, `SigningCeremony`) and lets the type system
/// statically prove that solo and multisig code paths never share a
/// runtime branch.
pub trait EngineSignerKind: private::Sealed + 'static {}

/// V3.0 default: this wallet holds the spend secret directly and signs
/// transactions in-process.
///
/// Zero-sized; the actual key material lives in
/// [`shekyl_crypto_pq::account::AllKeysBlob`] on the [`Engine`](super::Engine)
/// itself, not on the signer marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct SoloSigner;

impl private::Sealed for SoloSigner {}
impl EngineSignerKind for SoloSigner {}
