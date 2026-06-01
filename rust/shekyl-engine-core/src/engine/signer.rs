// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Signer-kind type parameter for the [`Engine`](super::Engine)
//! orchestrator, plus the PR 5 [`Signer`] trait surface used by
//! `LocalPendingTx` (the C5 `PendingTxEngine` impl).
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
//!
//! # PR 5 [`Signer`] trait (this commit, C4α)
//!
//! Separately from `EngineSignerKind`, PR 5 introduces the
//! [`Signer`] trait that the C5 `LocalPendingTx` impl consumes. The
//! trait isolates spend-key access from the build pipeline so the
//! V3.x HW-wallet / `SigningActor` integration plugs in as an
//! alternative [`Signer`] impl without re-opening the trait
//! surface. The default V3.0 impl is [`LocalSigner`] (synchronous,
//! in-process). Since Stage 2 (`STAGE_2_KEY_ENGINE_ACTOR.md` §6
//! step 4) the spend material lives in the `KeyActor`, not in the
//! signer: [`LocalSigner`] holds a [`KeyEngineHandle`] and routes the
//! future signing path through the actor's `SignTransaction` message,
//! so neither `LocalPendingTx` nor the signer ever touches the
//! `AllKeysBlob` directly.
//!
//! The two surfaces ([`EngineSignerKind`] and [`Signer`]) are
//! orthogonal: `EngineSignerKind` parameterizes the orchestrator
//! over solo-vs-multisig dispatch; [`Signer`] parameterizes the
//! pending-tx engine over the secret-holding signer instance. They
//! share a name family but are layered, not overlapping.

use super::error::SignerError;
use super::key_actor::KeyEngineHandle;

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

// ----------------------------------------------------------------------------
// PR 5 — `Signer` trait surface (R11 (b), Phase 0h)
// ----------------------------------------------------------------------------
//
// Phase 0h binding form per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4.
// C4α lands the trait + the V3.0 `LocalSigner` impl. The V3.x
// `SigningActor` / HW-wallet impls plug in additively via the
// `#[non_exhaustive]` discipline on `SignerError` (the Phase 0h
// pinned-error surface from C2α).

/// Context passed to [`Signer::sign_transfer`] describing the
/// transfer to be signed.
///
/// **Phase 1 stub.** V3.0 ships a placeholder shell with no
/// public construction or accessor surface; the actual fields
/// (FCMP++ membership-proof witness; hybrid-PQC signing context;
/// the pre-signing transaction skeleton; …) land in Phase 2a
/// when `shekyl-tx-builder` integration replaces the current
/// `build_pending_tx_in_state` stub body. The opaque-newtype
/// shape lets C4α's trait surface land without committing to the
/// final field set before Phase 2a's tx-builder integration
/// settles them.
///
/// The Phase-1-stub posture is what
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 Phase 0h's "Phase 1
/// deferral" explicitly authorizes — the trait-existence and the
/// spend-secret-locality contract are the segment-2g pin; the
/// precise method signature is finalized at Phase 1 commit-
/// decomposition (i.e., here / now).
#[derive(Debug)]
pub struct TransferSigningContext {
    /// Phase 1 stub field. Phase 2a fills the context shape; for
    /// now the type carries a unit placeholder so the newtype is
    /// constructible without exposing a public init surface.
    pub(crate) _phase1_stub: (),
}

impl TransferSigningContext {
    /// Construct a Phase 1 stub context. Crate-internal only —
    /// `LocalPendingTx::build_sync` is the production caller.
    pub(crate) fn phase1_stub() -> Self {
        Self { _phase1_stub: () }
    }
}

/// Result of a successful [`Signer::sign_transfer`] call —
/// the signed transfer body ready for daemon submission.
///
/// **Phase 1 stub.** Like [`TransferSigningContext`], V3.0
/// ships a placeholder shell; Phase 2a replaces the empty
/// body bytes with the actual signed-tx serialization. The
/// opaque-newtype shape lets C5β's `submit` body land without
/// the body-shape needing to be settled before Phase 2a.
#[derive(Debug)]
pub struct SignedTransfer {
    /// Serialized signed-transaction bytes. Phase 1 stub
    /// matches the existing
    /// [`build_pending_tx_in_state`](super::pending::build_pending_tx_in_state)
    /// behavior (`tx_bytes: Vec::new()`); Phase 2a's tx-builder
    /// integration replaces this with the actual on-wire body.
    pub(crate) tx_bytes: Vec<u8>,
}

impl SignedTransfer {
    /// Construct an empty Phase 1 stub. The `_context` parameter
    /// is unused at V3.0; Phase 2a's tx-builder will consume it.
    /// Crate-internal only.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn empty_phase1_stub(_context: &TransferSigningContext) -> Self {
        Self {
            tx_bytes: Vec::new(),
        }
    }

    /// Borrow the serialized signed-transaction bytes. Crate-
    /// internal accessor; C5β's `submit` body forwards them to
    /// `DaemonEngine::submit_tx`.
    #[allow(dead_code)]
    pub(crate) fn tx_bytes(&self) -> &[u8] {
        &self.tx_bytes
    }
}

/// Trait isolating spend-key access from the `PendingTxEngine`
/// build / submit pipeline.
///
/// Phase 0h binding form per
/// `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §4 (R11 (b) segment-2b
/// closure). [`LocalSigner`] is the V3.0 default implementor;
/// V3.x adds [`Signer`] impls additively (HW-wallet adapter
/// landing as `HardwareSigner` per the segment-2b FOLLOWUPS
/// entry; the eventual `SigningActor` plugs in behind an
/// `ActorRef`-delegating impl — substitution-not-refactor at
/// the Stage 4 migration).
///
/// # Secret-locality contract (R11 (b) per `36-secret-locality.mdc`)
///
/// The [`Signer`] instance is the **sole holder** of spend
/// material at runtime. `LocalPendingTx` never touches the
/// `AllKeysBlob` directly — the build pipeline calls
/// [`sign_transfer`](Self::sign_transfer) with a context that
/// carries the structural pre-signing inputs (no secrets), and
/// the signer projects the signed output. This isolates spend-
/// key access from the rest of the pipeline so memory-disclosure
/// at any layer above the signer cannot reveal spend material.
///
/// # F3 sensitive-material discipline pin
///
/// Per `STAGE_1_PR_5_PENDING_TX_ENGINE.md` §5.6.5 F3 closure,
/// **[`Signer::Error`] and its `Debug` / `Display` projections
/// MUST NOT carry sensitive material** — spend-secret bytes,
/// intermediate signing scalars, partial-signature material,
/// HW-wallet device-side attestation challenges, or any
/// intermediate state that downstream review would classify as
/// `Zeroize`-required. Implementors structure their error types
/// so `Debug` projects only the discriminant plus non-sensitive
/// context; sensitive material returned by HW devices is wiped
/// from the `Error` structure (via `Zeroizing<…>` wrapping that
/// is consumed during `Error` construction, leaving the
/// outward-facing error free of secret material).
///
/// The trait bounds cannot syntactically enforce this — the
/// discipline is a documentation pin per §3.1 / F3 that
/// downstream `Signer` implementors MUST audit. Standard
/// `tracing` / `log` infrastructure routinely projects `Debug` /
/// `Display` to logs; an implementor whose error structure
/// carries device-side attestation challenges leaks via standard
/// logging.
///
/// # Trait bounds
///
/// - `Send + Sync + 'static`: matches the engine-trait pattern
///   so a `Signer` impl can be held behind `Arc<dyn Signer<Error
///   = E>>` if needed. The lifetime bound is uniform across PR
///   3 / PR 4 / PR 5's trait surfaces.
/// - `type Error: Into<SignerError>`: the implementor's local
///   error converts to the engine-wide [`SignerError`]
///   discriminant set (Phase 0h pinned by C2α). The orchestrator
///   sees `SignerError`; the implementor names its own type and
///   the `.into()` impl projects across the boundary.
pub trait Signer: Send + Sync + 'static {
    /// Implementor-specific error type that converts into the
    /// engine-wide [`SignerError`].
    ///
    /// **F3 sensitive-material discipline applies.** See the
    /// trait-level documentation. Audit each `Signer` impl's
    /// error type's `Debug` / `Display` projections — they MUST
    /// NOT carry spend-secret bytes, intermediate signing
    /// scalars, partial-signature material, or any other
    /// `Zeroize`-required state.
    type Error: Into<SignerError>;

    /// Sign the transfer described by `context`, returning the
    /// signed transfer body.
    ///
    /// **Phase 1 stub.** V3.0's [`LocalSigner`] impl returns
    /// an empty `SignedTransfer` regardless of context — matches
    /// the current `build_pending_tx_in_state` stub (the
    /// crate-internal free function in `engine::pending` that
    /// sets `tx_bytes: Vec::new()`). Phase 2a wires the actual
    /// `shekyl-tx-builder` integration against the implementor's
    /// key material.
    ///
    /// # Errors
    ///
    /// Returns the implementor's local `Error` type. The
    /// orchestrator converts via `.into()` to the engine-wide
    /// [`SignerError`]. Per F3, the projection MUST NOT carry
    /// sensitive material.
    fn sign_transfer(
        &self,
        context: &TransferSigningContext,
    ) -> Result<SignedTransfer, Self::Error>;
}

/// V3.0 default [`Signer`] implementor: a handle to the wallet's
/// `KeyActor`, which signs on the orchestrator's behalf.
///
/// Phase 0h binding form per `STAGE_1_PR_5_PENDING_TX_ENGINE.md`
/// §4 segment-2g closure, **as amended by Stage 2**
/// (`STAGE_2_KEY_ENGINE_ACTOR.md` §6 step 4). The signer no longer
/// holds `Arc<AllKeysBlob>`: the blob lives inside the
/// [`KeyActor`](super::key_actor::KeyActor), and the signer carries a
/// [`KeyEngineHandle`] clone. When Phase 2a wires real signing, the
/// body routes through the actor's `SignTransaction` message rather
/// than reaching into a local blob — the `SigningActor` substitution
/// the original Stage-1 note anticipated is now structural.
///
/// # Secret-locality
///
/// The `key: KeyEngineHandle` field is `pub(crate)`. The handle
/// reaches secret material only by message-passing to the actor;
/// there is no `&AllKeysBlob` reachable through it. This is a
/// strictly stronger secret-locality posture than the Stage-1
/// `Arc<AllKeysBlob>` field (which exposed the blob to anything
/// holding the signer): the spend secret is confined to the actor
/// task per `36-secret-locality.mdc` and the engine-isolation
/// property of `16-architectural-inheritance.mdc`.
///
/// # Not `Debug`
///
/// [`LocalSigner`] does NOT derive `Debug`. The held
/// [`KeyEngineHandle`] transitively reaches the actor's
/// `AllKeysBlob` and a view-secret projection; neither implements
/// `Debug`, per
/// [`35-secure-memory.mdc`](https://github.com/shekyl/shekyl-core/blob/dev/.cursor/rules/35-secure-memory.mdc).
/// Wrapping orchestrator types (the engine top-level struct;
/// `LocalPendingTx`'s eventual Debug impl) project the signer
/// as a redacted placeholder rather than including its `Debug`
/// transitively.
pub struct LocalSigner {
    /// Handle to the wallet's `KeyActor`. `KeyEngineHandle` is
    /// `Clone` (it wraps an `ActorRef` plus `Arc`'d public/secret
    /// projections), so the engine shares the one actor with the
    /// signer by cloning the handle — no secret bytes are copied and
    /// no `&AllKeysBlob` is exposed.
    //
    // `#[allow(dead_code)]`: the `sign_transfer` body is a Phase 1 stub
    // that does not yet read the handle. Phase 2a routes real signing
    // through `self.key`'s `SignTransaction` message; the allow is
    // reopened for deletion then, per `21-reversion-clause-discipline.mdc`.
    #[allow(dead_code)]
    pub(crate) key: KeyEngineHandle,
}

impl LocalSigner {
    /// Construct a [`LocalSigner`] from a clone of the engine's
    /// [`KeyEngineHandle`]. Crate-internal: only the engine's open /
    /// construct pipeline calls this; external `Signer` impls are
    /// independent.
    pub(crate) fn new(key: KeyEngineHandle) -> Self {
        Self { key }
    }
}

impl Signer for LocalSigner {
    type Error = SignerError;

    fn sign_transfer(
        &self,
        context: &TransferSigningContext,
    ) -> Result<SignedTransfer, Self::Error> {
        // Phase 1 stub: returns SignedTransfer with empty body
        // bytes. Matches existing build_pending_tx_in_state
        // which sets tx_bytes: Vec::new() per the existing
        // pending.rs stub. Phase 2a routes real signing through
        // `self.key`'s actor `SignTransaction` message.
        Ok(SignedTransfer::empty_phase1_stub(context))
    }
}

#[cfg(test)]
mod tests {
    //! `Signer` / `LocalSigner` regression tests, as amended by
    //! Stage 2 (`STAGE_2_KEY_ENGINE_ACTOR.md` §6 step 4).
    //!
    //! Coverage scope:
    //!
    //! - `local_signer_holds_handle_not_blob` — replaces the Stage-1
    //!   `local_signer_holds_keys` `Arc<AllKeysBlob>` refcount test.
    //!   The secret-locality invariant is now structural: the signer
    //!   holds a [`KeyEngineHandle`], and dropping the engine's own
    //!   handle clone does **not** stop the actor while the signer's
    //!   clone is alive. Liveness is asserted via an actor-routed
    //!   `sign_transaction` `ask` (not `account_public_address`, which
    //!   is projection-served and would pass even after actor stop).
    //! - `local_signer_phase1_stub_succeeds` — the Phase 1 stub
    //!   returns `Ok` for any well-formed context.
    //!
    //! Each test spawns a real [`KeyActor`](super::super::key_actor::KeyActor)
    //! over a real [`AllKeysBlob`]. `KeyEngineHandle::spawn` is require-ambient
    //! (§4.2 — a [`KeyActor`] is an async task and must be spawned inside a
    //! runtime), so these are `#[tokio::test]`s; the default current-thread
    //! runtime hosts the actor task fine (`kameo`'s spawn is `tokio::spawn`).
    use super::*;
    use crate::engine::error::KeyEngineError;
    use crate::engine::traits::key::{FcmpPlusPlusContext, KeyEngine, TxToSign};
    use shekyl_crypto_pq::account::{
        rederive_account, AllKeysBlob, DerivationNetwork, SeedFormat, MASTER_SEED_BYTES,
    };

    /// Deterministic test seed. Distinct from
    /// `DEFAULT_TEST_SEED` (daemon-side, 32 bytes) and from
    /// `PROPERTY_TEST_MASTER_SEED` (`local_refresh` producer-side)
    /// so signer-side tests do not share derivation state with
    /// other fixtures. `seed[i] = (i * 11) ^ 0x9E` deterministic.
    const SIGNER_TEST_MASTER_SEED: [u8; MASTER_SEED_BYTES] = {
        let mut seed = [0u8; MASTER_SEED_BYTES];
        let mut i: u8 = 0;
        while (i as usize) < MASTER_SEED_BYTES {
            seed[i as usize] = i.wrapping_mul(11) ^ 0x9E;
            i += 1;
        }
        seed
    };

    fn deterministic_keys() -> AllKeysBlob {
        rederive_account(
            &SIGNER_TEST_MASTER_SEED,
            DerivationNetwork::Fakechain,
            SeedFormat::Raw32,
        )
        .expect("rederive_account against fakechain raw32 seed")
    }

    fn empty_tx_to_sign() -> TxToSign {
        TxToSign {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fcmp_plus_plus_context: FcmpPlusPlusContext {},
        }
    }

    #[tokio::test]
    async fn local_signer_holds_handle_not_blob() {
        // The engine builds the handle, then hands the signer a clone
        // (mirrors `assemble`: `LocalSigner::new(key.clone())`).
        let engine_handle = KeyEngineHandle::spawn(deterministic_keys());
        let signer = LocalSigner::new(engine_handle.clone());

        // Dropping the engine's own clone must NOT stop the actor: the
        // signer's clone keeps it alive. Use an actor-routed `ask`
        // (`sign_transaction`), not `account_public_address` (projection-
        // served and would still resolve after actor stop).
        drop(engine_handle);
        let err = signer
            .key
            .sign_transaction(&empty_tx_to_sign())
            .await
            .expect_err("live actor must return the stub error, not transport failure");
        assert!(
            matches!(err, KeyEngineError::SignTransactionTraitSurfaceIncomplete),
            "expected stub error from live actor, got {err:?}",
        );
    }

    #[tokio::test]
    async fn local_signer_phase1_stub_succeeds() {
        let signer = LocalSigner::new(KeyEngineHandle::spawn(deterministic_keys()));
        let context = TransferSigningContext::phase1_stub();
        let result = signer.sign_transfer(&context);
        let signed = result.expect("Phase 1 stub returns Ok unconditionally");
        // Phase 1 stub invariant: body bytes are empty (matches
        // build_pending_tx_in_state's tx_bytes: Vec::new()).
        assert!(signed.tx_bytes().is_empty());
    }
}
