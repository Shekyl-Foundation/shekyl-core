// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`StakeEngine`]: the `kameo` actor that owns the wallet's `master_seed_64`
//! and the archival staking personas (`P`) derived from it, plus
//! [`StakeEngineHandle`], the `Clone` handle held in place of the actor.
//!
//! Per [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`] §10/§10.1, the StakeEngine
//! actor *is* the gate-6 firewall realized as actor isolation: it is the sole
//! owner of `P`'s secret key material, structurally disjoint from the
//! `LedgerEngine` transfer pipeline. The three properties below are what make
//! that isolation hold rather than merely declare it.
//!
//! # Secret-locality (`36-secret-locality.mdc`, `16-architectural-inheritance.mdc`)
//!
//! The actor owns the load-bearing root ([`StakeMasterSeed`]) and the active
//! persona bundle ([`ArchivalPKeys`], `!Clone` + per-field `ZeroizeOnDrop`)
//! privately. The message protocol is **operation-shaped, never key-shaped**:
//! requests name an operation ("activate slot N", and in PR 2c "sign this bond
//! preimage"), and replies carry **public** results ([`PersonaIdentity`] holds
//! the typed [`HybridPublicKey`] that rides the wire as `P_pubkey` — a type
//! with no secret field to leak). Nothing in the protocol can request the
//! bundle and nothing can `Clone` it out, so the secret cannot escape the
//! actor (§10.1 robustness #1).
//!
//! # Lazy derivation off the async hot path (§10.1 efficiency)
//!
//! `derive_archival_p_keys` is dominated by PQ keygen (ML-DSA-65 + ML-KEM-768).
//! A multi-`P` whale deriving `N` bundles inline in an `async` handler would
//! stall the Tokio worker for tens of ms at wallet open. So personas are
//! derived **lazily, per-`P`, on first activation**, and the derivation runs on
//! [`tokio::task::spawn_blocking`] rather than inline. An idle actor holds **no
//! persona** (`active == None`): no secret key material exists until a caller
//! asks for one.
//!
//! # Atomic rotation, re-derive-on-restart (§10.1 robustness #2/#3)
//!
//! `p_slot` rotation is a **single state transition**: the new bundle is
//! derived into a local, then a single assignment installs it and drops (wipes)
//! the old. There is never a window with two live personas (the §10.9
//! co-activation hazard) and never a gap with none. The bundle is **not
//! persisted**; the actor re-derives deterministically from `master_seed_64` on
//! every (re-)spawn, which is why the seed must outlive the actor and carries
//! the same wipe discipline — pinned cross-arch by the `ARCHIVAL_P_DERIVE_V1`
//! KAT (`shekyl-crypto-pq`).
//!
//! # Fail-stop, not supervised
//!
//! Like [`KeyActor`](super::key_actor::KeyActor), the StakeEngine is the
//! wallet's secret owner and is **not** restart-supervised: a handler panic
//! runs [`Actor::on_panic`] returning [`ControlFlow::Break`], so the actor
//! stops rather than restarts. After a stop, every handle call collapses to the
//! terminal [`StakeEngineError::StakeActorUnavailable`]; recovery is a full
//! wallet close + re-open, which re-derives every `P` deterministically.
//!
//! # Status: inert (PR 2b)
//!
//! This module is **not yet wired into [`Engine`](super::Engine)**. PR 2b lands
//! the actor, its handle, and its lifecycle, exercised by tests only; the live
//! spawn (plumbing `master_seed_64` into the open/create lifecycle) lands in
//! PR 2c with the first consumer (the JoinMarket bond request), so no
//! seed-holding actor comes into existence until something uses it. Each inert
//! item carries its own `#[allow(dead_code)]` (rather than a module-level
//! blanket) so the dead-code check stays effective: a *new* item added later
//! without a use is still flagged, and the allows fall away as PR 2c wires each
//! item in — making the wiring visible in that PR's diff.
//!
//! [`docs/design/ARCHIVAL_BOND_CONSTRUCTION.md`]: ../../../../../docs/design/ARCHIVAL_BOND_CONSTRUCTION.md
//! [`ArchivalPKeys`]: shekyl_crypto_pq::archival_p::ArchivalPKeys

use std::ops::ControlFlow;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::{derive_archival_p_keys, ArchivalPKeys};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_crypto_pq::CryptoError;

// ---------------------------------------------------------------------------
// Typed domain values
// ---------------------------------------------------------------------------

/// Archival persona slot index.
///
/// A newtype over `u32` so a persona slot cannot be confused at a call site
/// with any other index (an output index, a subaddress index, …). The
/// `derive_archival_p_keys` boundary takes a raw `u32`; the conversion is
/// explicit via [`PSlot::index`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct PSlot(pub u32);

#[allow(dead_code)] // inert until PR 2c wiring
impl PSlot {
    /// The raw slot index, for the `derive_archival_p_keys` boundary.
    #[must_use]
    pub(crate) fn index(self) -> u32 {
        self.0
    }
}

/// The wallet's 64-byte master seed — the load-bearing root the entire `P`
/// firewall derives from (§10.1 robustness #3).
///
/// Wrapped in a newtype so (a) the wipe-on-drop discipline lives on the type
/// rather than on every holder, and (b) the seed cannot be confused with any
/// other `[u8; 64]` buffer. `Debug` is hand-written to redact the bytes; the
/// type is intentionally **not** `Clone` (mirroring `AllKeysBlob`'s not-clone
/// discipline — the only copy taken is the explicit, `Zeroizing`-wrapped one
/// handed to the derivation task).
#[derive(Zeroize, ZeroizeOnDrop)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct StakeMasterSeed {
    seed: [u8; MASTER_SEED_BYTES],
}

#[allow(dead_code)] // inert until PR 2c wiring
impl StakeMasterSeed {
    /// Wrap a normalized 64-byte master seed.
    #[must_use]
    pub(crate) fn new(seed: [u8; MASTER_SEED_BYTES]) -> Self {
        Self { seed }
    }

    /// Borrow the raw bytes for derivation.
    fn as_bytes(&self) -> &[u8; MASTER_SEED_BYTES] {
        &self.seed
    }
}

impl std::fmt::Debug for StakeMasterSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StakeMasterSeed")
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// The public identity of an activated persona `P`.
///
/// Carries **only public material** — the typed [`HybridPublicKey`] that rides
/// the wire as `P_pubkey`, plus the slot it was derived for. Returning the
/// typed key (rather than raw bytes, and never the secret bundle) makes "no
/// secret crosses the actor boundary" a property the type system checks:
/// `HybridPublicKey` has no secret field. `Clone + Debug` is sound for the same
/// reason.
#[derive(Clone, Debug)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct PersonaIdentity {
    /// The slot this persona was derived for.
    pub p_slot: PSlot,
    /// The persona's public bond identity key (= `hybrid_bond_id`, `P_pubkey`).
    pub bond_id: HybridPublicKey,
}

#[allow(dead_code)] // inert until PR 2c wiring
impl PersonaIdentity {
    /// Project the public identity out of a (secret) persona bundle.
    fn from_keys(keys: &ArchivalPKeys) -> Self {
        Self {
            p_slot: PSlot(keys.p_slot),
            bond_id: keys.hybrid_bond_id().clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by the StakeEngine handle.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) enum StakeEngineError {
    /// The StakeEngine actor has stopped (fail-stop after a handler panic, or a
    /// clean stop). Terminal and non-retryable — the persona secrets went with
    /// the task. Recovery is a full wallet close + re-open, which re-derives
    /// every `P` deterministically from `master_seed_64`. The message is
    /// user-facing: it names the recovery action.
    #[error(
        "stake engine unavailable: the staking actor has stopped; \
         close and reopen the wallet to recover"
    )]
    StakeActorUnavailable,

    /// Persona derivation failed — e.g. an impermissible `(network, seed-format)`
    /// pair. Carries the underlying crypto error.
    #[error("archival persona derivation failed: {0}")]
    Derivation(CryptoError),

    /// The off-thread derivation task (`spawn_blocking`) was **cancelled**
    /// before producing a result (e.g. runtime shutdown). A *panic* in the
    /// derivation is deliberately not mapped here: it re-raises on the actor
    /// task and fail-stops the engine (§10.1), so this variant is reserved for
    /// the non-fatal cancellation case.
    #[error("archival persona derivation task was cancelled")]
    DerivationTaskFailed,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Construction arguments moved into the actor task at spawn.
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct StakeEngineArgs {
    /// The wallet's master seed (the derivation root; outlives the actor).
    pub master_seed: StakeMasterSeed,
    /// Derivation network (mainnet / testnet / …).
    pub network: DerivationNetwork,
    /// Seed format (must be permitted for `network`).
    pub seed_format: SeedFormat,
}

/// The `kameo` actor owning `master_seed_64` and the active archival persona.
///
/// The single-threaded message loop serializes access to `active`, so the
/// rotation swap (derive-into-local, then a single assignment) is atomic with
/// respect to other messages.
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct StakeEngine {
    /// Derivation root. Held with wipe-on-drop; the only copy leaves via the
    /// explicit `Zeroizing` clone handed to `spawn_blocking`.
    master_seed: StakeMasterSeed,
    network: DerivationNetwork,
    seed_format: SeedFormat,
    /// The currently-active persona, or `None` when idle. Lazily derived on
    /// first [`ActivatePersona`]; rotation replaces it in a single transition.
    /// `ArchivalPKeys` is `!Clone` + per-field `ZeroizeOnDrop`, so the bundle
    /// cannot be copied out and the old persona wipes the instant a new one is
    /// installed.
    active: Option<ArchivalPKeys>,
}

impl Actor for StakeEngine {
    type Args = StakeEngineArgs;
    type Error = Infallible;

    /// Build the actor from the moved-in seed + derivation context. Idle: no
    /// persona is derived until the first activation.
    async fn on_start(
        args: StakeEngineArgs,
        _actor_ref: ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            master_seed: args.master_seed,
            network: args.network,
            seed_format: args.seed_format,
            active: None,
        })
    }

    /// Fail-stop on panic. The kameo default, locked explicitly so the
    /// secret-owner's no-restart posture is pinned at the type layer rather than
    /// inherited from a framework default that could change under a dependency
    /// bump (mirrors [`KeyActor`](super::key_actor::KeyActor)).
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Defense-in-depth wipe at stop. The active persona's per-field
    /// `ZeroizeOnDrop` and the seed's `ZeroizeOnDrop` also run at task-end drop;
    /// the explicit wipe here makes the zeroization observable at fail-stop and
    /// is idempotent with the drop-glue wipe.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        // Dropping the taken bundle runs each secret field's `ZeroizeOnDrop`.
        drop(self.active.take());
        self.master_seed.zeroize();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Activate (lazily derive) persona slot `p_slot`, returning its public
/// identity. If a different slot is active this is a **rotation**: the new
/// bundle is derived first, then swapped in by a single assignment that drops
/// (wipes) the old — never a window with two live personas, never a gap with
/// none (§10.1 robustness #2 / §10.9).
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct ActivatePersona {
    pub p_slot: PSlot,
}

impl Message<ActivatePersona> for StakeEngine {
    type Reply = Result<PersonaIdentity, StakeEngineError>;

    async fn handle(
        &mut self,
        msg: ActivatePersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Idempotent: already active for this slot → return its identity without
        // re-deriving.
        if let Some(active) = &self.active {
            if PSlot(active.p_slot) == msg.p_slot {
                return Ok(PersonaIdentity::from_keys(active));
            }
        }

        // Derive off the async hot path: PQ keygen is CPU-bound and would
        // otherwise stall the Tokio worker for a multi-`P` open (§10.1). The
        // only copy of the seed leaves here, `Zeroizing`-wrapped, and is wiped
        // when the blocking closure ends.
        let seed_copy: Zeroizing<[u8; MASTER_SEED_BYTES]> =
            Zeroizing::new(*self.master_seed.as_bytes());
        let network = self.network;
        let seed_format = self.seed_format;
        let p_slot = msg.p_slot;

        let derived = match tokio::task::spawn_blocking(move || {
            derive_archival_p_keys(&seed_copy, network, seed_format, p_slot.index())
        })
        .await
        {
            Ok(result) => result.map_err(StakeEngineError::Derivation)?,
            Err(join_error) if join_error.is_panic() => {
                // The derivation panicked — an unexpected invariant violation in
                // a secret-owning path. Re-raise the panic on the actor task so
                // kameo's `on_panic` fail-stops the engine, identical to an
                // in-handler panic. A secret path that panicked is not a state
                // we keep the actor alive through.
                std::panic::resume_unwind(join_error.into_panic());
            }
            // Cancellation (the blocking task was aborted, e.g. runtime
            // shutdown) — not a panic and not fatal to the actor; report it.
            Err(_) => return Err(StakeEngineError::DerivationTaskFailed),
        };

        // Single atomic transition. The new bundle was computed in `derived`
        // above and is not the *active* persona until this assignment, so there
        // is never a moment with two live personas; the old stayed active until
        // now, so there is no gap with none. The assignment drops the old
        // bundle, running its per-field `ZeroizeOnDrop`.
        let identity = PersonaIdentity::from_keys(&derived);
        self.active = Some(derived);
        Ok(identity)
    }
}

/// Report the public identity of the currently-active persona, or `None` when
/// idle. Inspection only — never the secret bundle.
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct ActivePersona;

impl Message<ActivePersona> for StakeEngine {
    type Reply = Result<Option<PersonaIdentity>, StakeEngineError>;

    async fn handle(
        &mut self,
        _msg: ActivePersona,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.active.as_ref().map(PersonaIdentity::from_keys))
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// `Clone` handle the orchestrator holds in place of an inline `StakeEngine`.
///
/// **Capability object.** Holding a `StakeEngineHandle` *is* the authority to
/// drive the staking actor. It is `pub(crate)` and never exported to the RPC
/// tier; that confinement is the control, made a compile-time guarantee by the
/// visibility bound (mirrors [`KeyEngineHandle`](super::key_actor::KeyEngineHandle)).
#[derive(Clone)]
#[allow(dead_code)] // inert until PR 2c wiring
pub(crate) struct StakeEngineHandle {
    /// Strong reference to the stake actor's mailbox.
    actor: ActorRef<StakeEngine>,
}

#[allow(dead_code)] // inert until PR 2c wiring
impl StakeEngineHandle {
    /// Spawn the StakeEngine over the moved-in seed + derivation context.
    ///
    /// **Runtime hosting — require-ambient.** A [`StakeEngine`] is an async
    /// task; spawning one *requires* a Tokio runtime. `spawn` asserts an ambient
    /// runtime is present rather than hosting an engine-owned nested runtime
    /// (the drop-panic / abandoned-task hazard documented for
    /// [`KeyEngineHandle::spawn`](super::key_actor::KeyEngineHandle::spawn)).
    ///
    /// # Panics
    ///
    /// Panics if called with no ambient Tokio runtime; the message names the fix.
    pub(crate) fn spawn(
        master_seed: StakeMasterSeed,
        network: DerivationNetwork,
        seed_format: SeedFormat,
    ) -> Self {
        assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "StakeEngineHandle::spawn requires an ambient Tokio runtime: the \
             StakeEngine is an async task and must be spawned inside a runtime. \
             Tests must use #[tokio::test] (or wrap the call in one). See \
             ARCHIVAL_BOND_CONSTRUCTION.md §10.1."
        );

        let actor = StakeEngine::spawn(StakeEngineArgs {
            master_seed,
            network,
            seed_format,
        });
        Self { actor }
    }

    /// Activate (lazily derive) persona slot `p_slot` and return its public
    /// identity. Rotation when a different slot is active.
    pub(crate) async fn activate_persona(
        &self,
        p_slot: PSlot,
    ) -> Result<PersonaIdentity, StakeEngineError> {
        self.actor
            .ask(ActivatePersona { p_slot })
            .await
            .map_err(collapse_send_error)
    }

    /// The public identity of the currently-active persona, or `None` when idle.
    pub(crate) async fn active_persona(&self) -> Result<Option<PersonaIdentity>, StakeEngineError> {
        self.actor
            .ask(ActivePersona)
            .await
            .map_err(collapse_send_error)
    }
}

/// Collapse a kameo `ask` [`SendError`] into a [`StakeEngineError`].
///
/// A `HandlerError` carries the real derivation error the handler returned and
/// is surfaced as-is. `ActorNotRunning` / `ActorStopped` are exactly the
/// fail-stop / closed-actor states the terminal
/// [`StakeEngineError::StakeActorUnavailable`] names.
///
/// `MailboxFull` and `Timeout` are present only for match exhaustiveness and are
/// **unreachable on this path**: the actor uses kameo's default *unbounded*
/// mailbox (so the awaiting `ask` back-pressures the sender rather than
/// returning `MailboxFull`, mirroring [`KeyEngine`](super::key_actor)) and the
/// handle sets no `ask` timeout (so no `Timeout` is produced). Collapsing them
/// to the terminal error is therefore a dead arm, not a misclassification of a
/// live transient. **Reversion clause:** if PR 2c+ introduces a bounded mailbox
/// or an ask-timeout, that arm becomes reachable and must split into its own
/// *retryable* `StakeEngineError` variant rather than collapse here.
#[allow(dead_code)] // inert until PR 2c wiring
fn collapse_send_error<M>(err: SendError<M, StakeEngineError>) -> StakeEngineError {
    match err {
        SendError::HandlerError(e) => e,
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => StakeEngineError::StakeActorUnavailable,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Lifecycle contract tests for [`StakeEngine`] / [`StakeEngineHandle`]
    //! (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.1). Every test runs a real actor over
    //! a real seed and exercises it through real messages — no mocks. The
    //! `derive_archival_p_keys` oracle is rerun directly to confirm the actor
    //! returns the genesis-frozen identity bytes.

    use super::*;

    use shekyl_crypto_pq::archival_p::derive_archival_p_keys;

    /// Deterministic test seed (matches the `archival_p` module's KAT fixture).
    const TEST_SEED: [u8; MASTER_SEED_BYTES] = [0x33u8; MASTER_SEED_BYTES];

    /// Spawn a handle over `TEST_SEED` on mainnet/bip39 (a permitted pair).
    fn spawn_handle() -> StakeEngineHandle {
        StakeEngineHandle::spawn(
            StakeMasterSeed::new(TEST_SEED),
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
        )
    }

    /// The genesis-frozen `hybrid_bond_id` canonical bytes for a slot, computed
    /// directly via the derivation oracle.
    fn oracle_bond_id(p_slot: u32) -> Vec<u8> {
        derive_archival_p_keys(
            &TEST_SEED,
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
            p_slot,
        )
        .expect("oracle derivation succeeds for mainnet/bip39")
        .hybrid_bond_id()
        .to_canonical_bytes()
        .expect("derived bond id is canonical")
    }

    fn bond_id_bytes(identity: &PersonaIdentity) -> Vec<u8> {
        identity
            .bond_id
            .to_canonical_bytes()
            .expect("persona bond id is canonical")
    }

    // §10.1 — an idle actor holds no persona ("no keys when idle").
    #[tokio::test]
    async fn idle_actor_has_no_active_persona() {
        let handle = spawn_handle();
        let active = handle
            .active_persona()
            .await
            .expect("active query succeeds");
        assert!(active.is_none(), "a freshly spawned actor must be idle");
    }

    // §10.1 — first activation derives lazily and returns the public identity;
    // the identity matches the genesis-frozen derivation oracle.
    #[tokio::test]
    async fn activate_derives_lazily_and_returns_public_identity() {
        let handle = spawn_handle();

        let identity = handle
            .activate_persona(PSlot(0))
            .await
            .expect("activation derives the persona");
        assert_eq!(identity.p_slot, PSlot(0));
        assert_eq!(
            bond_id_bytes(&identity),
            oracle_bond_id(0),
            "actor returns the genesis-frozen bond identity"
        );

        let active = handle
            .active_persona()
            .await
            .expect("active query succeeds");
        let active = active.expect("persona is active after activation");
        assert_eq!(active.p_slot, PSlot(0));
        assert_eq!(bond_id_bytes(&active), oracle_bond_id(0));
    }

    // §10.1 robustness #3 — re-derivation is deterministic across a respawn: a
    // fresh actor over the same seed produces byte-identical identities. This is
    // the runtime consumer of the `ARCHIVAL_P_DERIVE_V1` cross-arch freeze.
    #[tokio::test]
    async fn activation_is_deterministic_across_respawn() {
        let first = {
            let handle = spawn_handle();
            let id = handle
                .activate_persona(PSlot(0))
                .await
                .expect("first activation");
            bond_id_bytes(&id)
            // handle (and its actor) drop here
        };

        let second = {
            let handle = spawn_handle();
            let id = handle
                .activate_persona(PSlot(0))
                .await
                .expect("second activation");
            bond_id_bytes(&id)
        };

        assert_eq!(
            first, second,
            "re-deriving the same slot from the same seed must be byte-identical"
        );
    }

    // §10.1 robustness #2 — rotation replaces the active persona in a single
    // transition: after rotating to slot 1, slot 1 is the *only* active persona,
    // and rotating back to slot 0 re-derives the original identity.
    #[tokio::test]
    async fn rotation_replaces_active_persona() {
        let handle = spawn_handle();

        let id0 = handle.activate_persona(PSlot(0)).await.expect("activate 0");
        let id1 = handle
            .activate_persona(PSlot(1))
            .await
            .expect("rotate to 1");

        assert_ne!(
            bond_id_bytes(&id0),
            bond_id_bytes(&id1),
            "distinct slots derive distinct personas"
        );
        assert_eq!(id1.p_slot, PSlot(1));

        // Only slot 1 is active now — the old persona was replaced.
        let active = handle
            .active_persona()
            .await
            .expect("active query")
            .expect("a persona is active");
        assert_eq!(active.p_slot, PSlot(1));
        assert_eq!(bond_id_bytes(&active), bond_id_bytes(&id1));

        // Rotating back re-derives the original deterministically.
        let id0_again = handle
            .activate_persona(PSlot(0))
            .await
            .expect("rotate back to 0");
        assert_eq!(bond_id_bytes(&id0_again), bond_id_bytes(&id0));
    }

    // Activating the already-active slot is idempotent (same identity, no error).
    #[tokio::test]
    async fn activate_same_slot_is_idempotent() {
        let handle = spawn_handle();
        let a = handle.activate_persona(PSlot(2)).await.expect("activate 2");
        let b = handle
            .activate_persona(PSlot(2))
            .await
            .expect("re-activate 2");
        assert_eq!(bond_id_bytes(&a), bond_id_bytes(&b));
    }

    // An impermissible (network, seed-format) pair surfaces a `Derivation`
    // error — and the actor survives it (a derivation error is not a panic).
    #[tokio::test]
    async fn impermissible_seed_format_surfaces_derivation_error() {
        // Mainnet does not permit raw32 (see `archival_p` tests).
        let handle = StakeEngineHandle::spawn(
            StakeMasterSeed::new(TEST_SEED),
            DerivationNetwork::Mainnet,
            SeedFormat::Raw32,
        );

        let err = handle
            .activate_persona(PSlot(0))
            .await
            .expect_err("mainnet/raw32 must be rejected by derivation");
        assert!(
            matches!(err, StakeEngineError::Derivation(_)),
            "expected Derivation error, got {err:?}"
        );

        // The actor is still alive: a subsequent query resolves (still idle).
        let active = handle
            .active_persona()
            .await
            .expect("actor survives a derivation error");
        assert!(
            active.is_none(),
            "a failed activation leaves the actor idle"
        );
    }

    // Require-ambient spawn contract: without an ambient Tokio runtime, `spawn`
    // panics with the contract message. Plain `#[test]` precisely *because* it
    // must run with no ambient runtime.
    #[test]
    #[should_panic(expected = "requires an ambient Tokio runtime")]
    fn spawn_without_ambient_runtime_panics() {
        let _handle = StakeEngineHandle::spawn(
            StakeMasterSeed::new(TEST_SEED),
            DerivationNetwork::Mainnet,
            SeedFormat::Bip39,
        );
    }

    // Mailbox `Send` contract (structural): message + reply types are `Send` as
    // kameo requires.
    #[test]
    fn message_and_reply_types_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ActivatePersona>();
        assert_send::<ActivePersona>();
        assert_send::<PersonaIdentity>();
        assert_send::<StakeEngineError>();
    }

    /// Test-only message whose handler panics, to exercise the fail-stop path.
    struct InjectPanic;

    impl Message<InjectPanic> for StakeEngine {
        type Reply = ();

        async fn handle(
            &mut self,
            _msg: InjectPanic,
            _ctx: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            panic!("test-injected panic: exercise fail-stop");
        }
    }

    // Panic → fail-stop → terminal, non-retryable `StakeActorUnavailable`.
    // Injects a panic; asserts the actor dies and that *repeated* calls all
    // collapse to the terminal error (a retry never recovers).
    #[tokio::test]
    async fn panic_fail_stops_and_calls_are_terminally_unavailable() {
        let handle = spawn_handle();

        // Sanity: a live activation works before the panic.
        assert!(handle.activate_persona(PSlot(0)).await.is_ok());

        // Inject the panic; on_panic → Break (fail-stop). The panicking ask
        // resolves to a transport error as the actor dies.
        let panic_ask = handle.actor.ask(InjectPanic).await;
        assert!(
            panic_ask.is_err(),
            "a panicking handler resolves to an error"
        );
        handle.actor.wait_for_shutdown().await;
        assert!(!handle.actor.is_alive(), "panic fail-stops the actor");

        // Terminal + non-retryable across both message types.
        for attempt in 0..3 {
            let err = handle
                .activate_persona(PSlot(0))
                .await
                .expect_err("post-death activation fails");
            assert!(
                matches!(err, StakeEngineError::StakeActorUnavailable),
                "attempt {attempt}: expected StakeActorUnavailable, got {err:?}"
            );
        }
        let err = handle
            .active_persona()
            .await
            .expect_err("post-death query fails");
        assert!(matches!(err, StakeEngineError::StakeActorUnavailable));
    }
}
