// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`KeyActor`]: the Stage 2 `kameo`-actor [`KeyEngine`] implementor, and
//! [`KeyEngineHandle`]: the `Clone` handle the orchestrator holds in place of
//! a `K: KeyEngine` field.
//!
//! Per [`docs/design/STAGE_2_KEY_ENGINE_ACTOR.md`], this module migrates the
//! wallet's key material + signing operations out of the in-process
//! [`LocalKeys`](super::local_keys::LocalKeys) composition and into a true
//! actor with its own `tokio` task and message protocol. The actor owns
//! [`AllKeysBlob`] privately; no `&AllKeysBlob` escapes its task. The trait
//! surface ([`KeyEngine`]) is unchanged — Stage 2 swaps the dispatcher, not the
//! method signatures.
//!
//! # Two-projection handle (§2.4 / §3.1)
//!
//! The handle-resolved methods ([`KeyEngine::account_public_address`],
//! [`KeyEngine::derive_subaddress`]) do not round-trip the actor. They are
//! served from two construction-time projections held by the handle:
//!
//! - [`KeyPublicProjection`] — `Clone + Debug` *because* it is public-only:
//!   the account public address (for the `&`-returning
//!   `account_public_address`) and the bare account `spend_pk`/`view_pk` (for
//!   the **primary** audit-subaddress branch, which returns them verbatim).
//! - [`AuditSubaddressSecret`] — secret-bearing, non-`Clone`, `Zeroizing`,
//!   wipe-on-drop, no `Debug` (the [`ViewMaterial`](super::view_material::ViewMaterial)
//!   discipline). It carries the view secret scalar `a` and the base spend
//!   point `D`, which the **non-primary** audit branch (`idx >= 1`) feeds to
//!   [`subaddress_keys`]. Non-primary audit derivation is *secret-touching*
//!   (the `m_i = H(domain || a_le || idx_le)` subaddress scalar is keyed by the
//!   view secret), so it cannot be served from public material alone — the
//!   reason the projection split is load-bearing, not cosmetic.
//!
//! Both projections are `Arc`-shared so [`KeyEngineHandle`] stays `Clone`; the
//! secret allocation is wiped when the last handle clone drops.
//!
//! **Registry drops on the handle path.** Stage-1 `LocalKeys::derive_subaddress`
//! also inserts the derived subaddress into a reverse-lookup registry under a
//! write lock. The handle-resolved path deliberately does **not** maintain a
//! registry: the actor owns the registry, and the registry only feeds
//! [`KeyEngine::try_claim_output`], which is cold in Stage 2 (zero production
//! callers, §3.5). Handle-side audit derivation is therefore a side-effect-free
//! read of the secret projection — an accepted Stage-2 narrowing, not a
//! regression on any live path. The deeper "subaddress mechanism under PQC"
//! question this surfaces is filed as a dedicated design round in
//! `docs/FOLLOWUPS.md` and is **out of scope** here.
//!
//! # Fail-stop, not supervised (§4.5)
//!
//! [`KeyActor`] is the wallet's secret owner; it is **not** restart-supervised.
//! A panic in a handler runs [`Actor::on_panic`], which returns
//! [`ControlFlow::Break`] (the kameo default, locked explicitly here) so the
//! actor stops rather than restarts. [`Actor::on_stop`] wipes the blob as
//! defense-in-depth (its `ZeroizeOnDrop` also runs at task-end drop). After a
//! stop, every [`KeyEngineHandle`] `ask` collapses the kameo transport failure
//! into [`KeyEngineError::KeyActorUnavailable`] — terminal and non-retryable
//! (§2.6). The only recovery is a full wallet close + re-open.
//!
//! # Integration (Stage 2 landed)
//!
//! This module is wired into production: [`Engine`](super::Engine) holds a
//! [`KeyEngineHandle`] (the `key` field, replacing `keys: Arc<AllKeysBlob>` per
//! `STAGE_2_KEY_ENGINE_ACTOR.md` §6), [`LocalSigner`](super::signer::LocalSigner)
//! holds a handle clone, and the merge post-pass reads
//! [`HandleDerivationViewSecret`] (the 6-i construction-time projection). The
//! `#[allow(dead_code)]` on [`SignTransaction`] and related items marks surfaces
//! that remain cold until PR 5 / signing-engine work — not "unwired."
//!
//! [`docs/design/STAGE_2_KEY_ENGINE_ACTOR.md`]: ../../../../../docs/design/STAGE_2_KEY_ENGINE_ACTOR.md
//! [`AllKeysBlob`]: shekyl_crypto_pq::account::AllKeysBlob
//! [`subaddress_keys`]: shekyl_crypto_pq::subaddress::subaddress_keys

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::Arc;

use curve25519_dalek::{edwards::CompressedEdwardsY, EdwardsPoint, Scalar};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use kameo::actor::{Actor, ActorRef, Spawn, WeakActorRef};
use kameo::error::{ActorStopReason, Infallible, PanicError, SendError};
use kameo::message::{Context, Message};

use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::keys::{SpendPublicKey, ViewPublicKey};
use shekyl_crypto_pq::output::{compute_output_key_image, scan_output_recover};
use shekyl_crypto_pq::subaddress::subaddress_keys;
use shekyl_engine_state::SubaddressIndex;
use shekyl_oxide::generators::hash_to_point;

use super::error::KeyEngineError;
use super::traits::key::{
    AccountPublicAddress, KeyEngine, OutputClaim, OutputClaimResult, OutputDetectionInput,
    SubaddressFor, SubaddressKeyPair, SubaddressPurpose, TxSignatures, TxToSign,
};

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// The Stage 2 `kameo` actor that owns the wallet's [`AllKeysBlob`] and serves
/// the actor-dispatched [`KeyEngine`] operations ([`ClaimOutput`],
/// [`SignTransaction`]).
///
/// Mirrors [`LocalKeys`](super::local_keys::LocalKeys)'s internal state, with
/// the `RwLock` removed: the actor's single-threaded message loop provides the
/// serialization the lock used to, so the registry is a plain `HashMap` mutated
/// behind `&mut self`. In Stage 2 the registry is never mutated by a message
/// (subaddress registration happens on the handle path, which intentionally
/// drops it — see the module docstring); it is pre-populated with the primary
/// entry at [`Actor::on_start`] and only read by the cold
/// [`ClaimOutput`] handler.
#[allow(dead_code)] // Stage 2 wires the handle into Engine in a later step; today: tests only.
pub(crate) struct KeyActor {
    /// Wallet key material. `AllKeysBlob` is `ZeroizeOnDrop`, wiped when the
    /// actor task ends (and explicitly in `on_stop` as defense-in-depth).
    keys: AllKeysBlob,

    /// View scalar `a`, pre-computed from `keys.view_sk` (canonical bytes are
    /// reduced mod the Ed25519 order). `Zeroizing` so the cached copy wipes on
    /// drop alongside the blob's own wipe path.
    view_scalar: Zeroizing<Scalar>,

    /// Base spend point `B = b*G`, decompressed from `keys.spend_pk`. Public
    /// material; no zeroize discipline required.
    spend_public: EdwardsPoint,

    /// Reverse-lookup table `B' -> SubaddressIndex`. Pre-populated with the
    /// primary entry; only read by [`ClaimOutput`]. See the module docstring
    /// for why the handle path does not feed this in Stage 2.
    subaddress_registry: HashMap<SpendPublicKey, SubaddressIndex>,
}

impl KeyActor {
    /// Reverse-lookup helper mirroring
    /// [`LocalKeys::lookup_subaddress`](super::local_keys::LocalKeys), minus the
    /// `RwLock` read — the actor's message loop already serializes access.
    fn lookup_subaddress(&self, recovered_spend: &SpendPublicKey) -> Option<SubaddressIndex> {
        self.subaddress_registry.get(recovered_spend).copied()
    }
}

impl Actor for KeyActor {
    type Args = AllKeysBlob;
    type Error = Infallible;

    /// Build the actor from the moved-in [`AllKeysBlob`].
    ///
    /// Pre-computes the view scalar and base spend point and pre-registers the
    /// primary subaddress, exactly as
    /// [`LocalKeys::from_keys_blob`](super::local_keys::LocalKeys) does.
    ///
    /// # Panics
    ///
    /// Panics if `keys.spend_pk` does not decompress — wallet-state corruption,
    /// which is a fail-stop event per §4.1 (a panic in `on_start` stops the
    /// actor before it serves any message; the same `.expect()` discipline
    /// `LocalKeys` uses for the identical invariant).
    async fn on_start(keys: AllKeysBlob, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *keys.view_sk.as_canonical_bytes(),
        ));
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses (rederive_account guarantees canonicity)");

        let mut subaddress_registry = HashMap::new();
        subaddress_registry.insert(keys.spend_pk, SubaddressIndex::PRIMARY);

        Ok(Self {
            keys,
            view_scalar,
            spend_public,
            subaddress_registry,
        })
    }

    /// Fail-stop on panic. This is the kameo default behavior, overridden
    /// explicitly so the secret-owner's no-restart posture (§4.5) is locked at
    /// the type layer rather than inherited from a framework default that could
    /// change under a dependency bump.
    async fn on_panic(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        err: PanicError,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        Ok(ControlFlow::Break(ActorStopReason::Panicked(err)))
    }

    /// Defense-in-depth wipe at stop. The blob's `ZeroizeOnDrop` also runs when
    /// the actor struct drops at task-end; the explicit wipe here makes the
    /// zeroization point observable at fail-stop and is idempotent with the
    /// drop-glue wipe (the standard double-wipe pattern, harmless on already-
    /// zero bytes).
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        self.keys.zeroize();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Actor message for [`KeyEngine::try_claim_output`].
///
/// Carries the owned per-output detection context. The handle clones the
/// trait's `&OutputDetectionInput` into this owned message (the input is all
/// public on-chain data; the clone is cheap and secret-free).
#[allow(dead_code)] // constructed by the handle; today exercised by tests only.
pub(crate) struct ClaimOutput {
    pub input: OutputDetectionInput,
}

/// Actor message for [`KeyEngine::sign_transaction`].
///
/// **Stage 2 carries no payload.** The Stage-1 `sign_transaction` is a stub
/// (`TxToSign`'s field shape is PR-5-pinned, and the handler returns
/// [`KeyEngineError::SignTransactionTraitSurfaceIncomplete`] without reading
/// the transaction), so there is nothing to send across the mailbox.
/// `TxToSign` is not `Clone` and the trait hands a `&TxToSign`; how an owned
/// transaction crosses the mailbox is a PR-5 decision pinned alongside
/// `TxToSign`'s final shape. Until then the message is an empty marker — a
/// faithful representation of the current stub behavior.
#[allow(dead_code)] // constructed by the handle; today exercised by tests only.
pub(crate) struct SignTransaction;

impl Message<ClaimOutput> for KeyActor {
    type Reply = Result<OutputClaimResult, KeyEngineError>;

    /// Replicates [`LocalKeys::try_claim_output`](super::local_keys::LocalKeys)
    /// verbatim against actor-owned state. The crypto body is intentionally
    /// duplicated rather than factored into a shared free function so
    /// `LocalKeys` survives as an equivalence oracle for the Stage-2 tests
    /// (§5.2 test 1/3); the bodies diverge only in registry access (`&self`
    /// field vs `RwLock` read).
    async fn handle(
        &mut self,
        msg: ClaimOutput,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let input = &msg.input;

        // Stage 1: hybrid decap + amount recovery + B' computation. Every
        // cryptographic-level rejection maps to `NotMine` per the trait
        // contract, not to a structural error.
        let Ok(recovered) = scan_output_recover(
            self.keys.view_sk.as_canonical_bytes(),
            self.keys.ml_kem_dk.as_canonical_bytes(),
            &input.ciphertext.x25519,
            &input.ciphertext.ml_kem,
            &input.output_key,
            &input.commitment,
            &input.enc_amount,
            input.amount_tag_on_chain,
            input.view_tag.0[0],
            input.output_index,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };

        // Stage 2: subaddress lookup via recovered spend key `B'`. A miss means
        // the recovered key matches no derived subaddress (the wallet only
        // claims outputs sent to subaddresses it has derived).
        let recovered_spend_pk =
            SpendPublicKey::from_canonical_bytes(recovered.recovered_spend_key);
        if self.lookup_subaddress(&recovered_spend_pk).is_none() {
            return Ok(OutputClaimResult::NotMine);
        }

        // Stage 3: key image `KI = x * Hp(O)` where `x = ho + b`. A failure is
        // a malformed `output_key`, surfaced as `NotMine`.
        let hp_of_o = hash_to_point(input.output_key);
        let hp_bytes = hp_of_o.compress().to_bytes();

        let Ok(ki_result) = compute_output_key_image(
            &recovered.combined_ss,
            input.output_index,
            self.keys.spend_sk.as_canonical_bytes(),
            &hp_bytes,
        ) else {
            return Ok(OutputClaimResult::NotMine);
        };
        let key_image = ki_result.key_image;

        // Stage 4: deterministic OutputHandle derivation (cSHAKE256 keyed by the
        // view secret; same `(view_secret, tx_hash, output_index)` -> same
        // handle).
        let handle = derive_output_handle(
            self.keys.view_sk.as_canonical_bytes(),
            &input.tx_hash,
            input.output_index,
        );

        Ok(OutputClaimResult::Mine(OutputClaim {
            handle,
            key_image,
            amount_atomic_units: recovered.amount,
        }))
    }
}

impl Message<SignTransaction> for KeyActor {
    type Reply = Result<TxSignatures, KeyEngineError>;

    /// Stage 2 stub, equivalent to
    /// [`LocalKeys::sign_transaction`](super::local_keys::LocalKeys): the
    /// PR-5-pinned `TxToSign` shape does not yet carry the public per-input
    /// data and FCMP++ branch context the signing pass needs, so this surface
    /// is recognized-but-not-bridgeable.
    async fn handle(
        &mut self,
        _msg: SignTransaction,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Err(KeyEngineError::SignTransactionTraitSurfaceIncomplete)
    }
}

// ---------------------------------------------------------------------------
// Handle projections
// ---------------------------------------------------------------------------

/// Public-only projection held by [`KeyEngineHandle`] for the handle-resolved
/// methods. `Clone + Debug` is sound precisely because it carries no secret
/// bytes (the contract is enforced syntactically by this being a dedicated
/// type, not a bare field).
///
/// Field set is pinned by what the **primary** audit branch and
/// `account_public_address` read; the non-primary audit branch is *not* served
/// from here (it is secret-touching — see [`AuditSubaddressSecret`]).
#[derive(Clone, Debug)]
#[allow(dead_code)] // read by the handle; today exercised by tests only.
pub(crate) struct KeyPublicProjection {
    /// Cached account-level public address material; the source of the
    /// `&`-return from [`KeyEngine::account_public_address`].
    account_public_address: AccountPublicAddress,
    /// Bare account spend public key `D` — returned verbatim for primary audit.
    spend_pk: SpendPublicKey,
    /// Bare account view public key — returned verbatim for primary audit.
    view_pk: ViewPublicKey,
}

/// Secret-bearing projection held by [`KeyEngineHandle`] solely to serve
/// **non-primary** audit-subaddress derivation (`idx >= 1`), which is
/// secret-touching (§2.4).
///
/// Deliberately a distinct type from
/// [`ViewMaterial`](super::view_material::ViewMaterial) and the (later-landing)
/// merge view-secret projection, so the type system forbids the "it's just a
/// view secret, I'll clone/reuse it" mistake. Non-`Clone`, no `Debug`, wipe-on-
/// drop — the `ViewMaterial` discipline.
#[derive(Zeroize)]
#[allow(dead_code)] // read by the handle; today exercised by tests only.
pub(crate) struct AuditSubaddressSecret {
    /// View secret scalar `a` — the secret input to [`subaddress_keys`].
    view_scalar: Zeroizing<Scalar>,
    /// Base spend point `D`. Public material; wiped on drop as defense in depth
    /// (the `curve25519-dalek/zeroize` feature provides the impl).
    spend_public: EdwardsPoint,
}

impl Drop for AuditSubaddressSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuditSubaddressSecret {}

/// Construction-time view-secret projection for the **merge post-pass**
/// (§6 option 6-i). `Engine::apply_scan_result` (`merge.rs`) must derive the
/// deterministic per-output `OutputHandle` from the wallet's view secret, but
/// after Stage 2 the full [`AllKeysBlob`] lives only in the [`KeyActor`] task —
/// no `&AllKeysBlob` is reachable from the synchronous, `RwLock`-write-guarded
/// merge path. Routing the post-pass through the actor (6-ii) would await an
/// `ask` inside that guard (the forbidden pattern, §6); it is foreclosed until
/// the Ledger actor lands (§8.1). So the merge owner holds this narrow
/// projection instead.
///
/// **Distinct type by intent.** It carries *only* the view-secret canonical
/// bytes the handle-derivation needs — narrower than
/// [`ViewMaterial`](super::view_material::ViewMaterial) (a five-field
/// view-and-spend bundle for refresh scanning) and distinct from it and from
/// [`AuditSubaddressSecret`], so the type system forbids the "it's just a view
/// secret, I'll clone/reuse it" mistake. Non-`Clone`, no `Debug`, wipe-on-drop.
#[derive(Zeroize)]
#[allow(dead_code)] // read by `Engine::apply_scan_result`; today exercised by tests only.
pub(crate) struct HandleDerivationViewSecret {
    /// View secret `view_sk` canonical bytes, fed to `populate_engine_handle_fields`.
    view_sk: Zeroizing<[u8; 32]>,
}

impl HandleDerivationViewSecret {
    /// Project the merge view-secret out of `&keys` at construction time,
    /// before the blob is consumed by [`KeyEngineHandle::spawn`].
    #[allow(dead_code)] // constructed in `assemble`; today exercised by tests only.
    pub(crate) fn from_keys(keys: &AllKeysBlob) -> Self {
        Self {
            view_sk: Zeroizing::new(*keys.view_sk.as_canonical_bytes()),
        }
    }

    /// Borrow the view-secret canonical bytes for handle derivation.
    #[allow(dead_code)] // read by `Engine::apply_scan_result`; today: tests only.
    pub(crate) fn as_canonical_bytes(&self) -> &[u8; 32] {
        &self.view_sk
    }
}

impl Drop for HandleDerivationViewSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HandleDerivationViewSecret {}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// `Clone` handle the orchestrator holds in place of an inline `K: KeyEngine`
/// field. Wraps the actor's [`ActorRef`] plus the two construction-time
/// projections (§3.1). Implements the same `pub(crate) trait` [`KeyEngine`]
/// that [`LocalKeys`](super::local_keys::LocalKeys) implements, so the swap is
/// transparent to the trait's callers.
///
/// **Capability object.** Holding a `KeyEngineHandle` *is* the authority to
/// query the key actor (`account_public_address`, `derive_subaddress`,
/// `try_claim_output` as a per-input ownership oracle). It is `pub(crate)` and
/// never exported to the RPC tier; that confinement is the control (§3.2 / §7
/// T9), made a compile-time guarantee by the visibility bound.
#[derive(Clone)]
#[allow(dead_code)] // constructed once Engine wiring lands; today: tests only.
pub(crate) struct KeyEngineHandle {
    /// Strong reference to the key actor's mailbox. `Clone + Send + Sync`.
    actor: ActorRef<KeyActor>,
    /// Public-only projection (account address + primary audit keys).
    public: Arc<KeyPublicProjection>,
    /// Secret projection for non-primary audit derivation (§2.4).
    audit_secret: Arc<AuditSubaddressSecret>,
}

impl KeyEngineHandle {
    /// Derive the handle's projections from `&keys`, then spawn the actor
    /// (consuming `keys` so no `&AllKeysBlob` escapes the actor task).
    ///
    /// **Runtime hosting — require-ambient (§4.2).** A [`KeyActor`] is an async
    /// task; spawning one *requires* a Tokio runtime, full stop. Introducing the
    /// actor therefore forecloses the lifecycle layer's prior runtime-agnosticism
    /// for the open path — it does not preserve it. Rather than hide that behind
    /// an engine-owned nested runtime (which would be a drop-panic landmine the
    /// moment an `Engine` owning it is dropped inside the production async server,
    /// and which would abandon the actor task via `shutdown_background` —
    /// skipping the `on_stop` blob wipe), `spawn` makes the requirement explicit:
    /// it asserts an ambient runtime is present. Production satisfies this by
    /// construction (the wallet-RPC server, async CLI, and GUI all call into
    /// `Engine::create` from inside their runtime); tests satisfy it with
    /// `#[tokio::test]` (any flavor — `kameo`'s spawn is `tokio::spawn`, which a
    /// current-thread runtime hosts fine).
    ///
    /// # Panics
    ///
    /// - Panics if called with **no ambient Tokio runtime**. This is the
    ///   require-ambient contract: the panic message names the fix
    ///   (`#[tokio::test]` / run inside a runtime) so a missing-runtime caller
    ///   fails loudly at the call site rather than via `kameo`'s lower-level
    ///   "no reactor running" panic.
    /// - Panics if `keys.spend_pk` does not decompress (wallet-state corruption);
    ///   the same fail-closed `.expect()` discipline as
    ///   [`LocalKeys::from_keys_blob`](super::local_keys::LocalKeys) and
    ///   [`KeyActor::on_start`]. The decompression is performed once here for the
    ///   audit projection and once in `on_start` for the actor; both share the
    ///   invariant.
    #[allow(dead_code)] // Stage 2 wires this into Engine in a later step; today: tests only.
    pub(crate) fn spawn(keys: AllKeysBlob) -> Self {
        assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "KeyEngineHandle::spawn requires an ambient Tokio runtime: the \
             KeyActor is an async task and must be spawned inside a runtime. \
             Production (wallet-RPC / async CLI / GUI) calls Engine::create from \
             inside its runtime; tests must use #[tokio::test] (or wrap the call \
             in one). See STAGE_2_KEY_ENGINE_ACTOR.md §4.2."
        );

        // Derive projections from `&keys` BEFORE moving it into the actor.
        let public = Arc::new(KeyPublicProjection {
            account_public_address: AccountPublicAddress {
                pqc_public_key: keys.pqc_public_key.to_vec(),
                classical_address_bytes: keys.classical_address_bytes.to_vec(),
            },
            spend_pk: keys.spend_pk,
            view_pk: keys.view_pk,
        });

        let view_scalar = Zeroizing::new(Scalar::from_bytes_mod_order(
            *keys.view_sk.as_canonical_bytes(),
        ));
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses (rederive_account guarantees canonicity)");
        let audit_secret = Arc::new(AuditSubaddressSecret {
            view_scalar,
            spend_public,
        });

        // Ambient runtime asserted above; `KeyActor::spawn` (kameo) schedules the
        // actor task via `tokio::spawn` onto it. The blob moves into the actor
        // here — no `&AllKeysBlob` escapes (the §binding-constraint by-
        // construction property).
        let actor = KeyActor::spawn(keys);

        Self {
            actor,
            public,
            audit_secret,
        }
    }
}

/// Collapse a kameo `ask` [`SendError`] into a [`KeyEngineError`].
///
/// A `HandlerError` carries the real crypto/engine error the handler returned.
/// Every other variant is a transport failure against a stopped actor and maps
/// to the terminal [`KeyEngineError::KeyActorUnavailable`] (§2.5/§2.6).
/// `MailboxFull` is included for exhaustiveness but is unreachable on the
/// awaiting `ask` path — the `ask` future provides backpressure by blocking the
/// sender until capacity frees rather than returning `MailboxFull` (§4.4 T4).
fn collapse_send_error<M>(err: SendError<M, KeyEngineError>) -> KeyEngineError {
    match err {
        SendError::HandlerError(e) => e,
        SendError::ActorNotRunning(_)
        | SendError::ActorStopped
        | SendError::MailboxFull(_)
        | SendError::Timeout(_) => KeyEngineError::KeyActorUnavailable,
    }
}

impl KeyEngine for KeyEngineHandle {
    type Error = KeyEngineError;

    fn account_public_address(&self) -> &AccountPublicAddress {
        &self.public.account_public_address
    }

    fn derive_subaddress(
        &self,
        idx: SubaddressIndex,
        purpose: SubaddressPurpose,
    ) -> Result<SubaddressFor, Self::Error> {
        match purpose {
            SubaddressPurpose::Audit => {
                // PRIMARY returns the bare account keys verbatim (consistent
                // with the encoded `classical_address_bytes`); `idx >= 1`
                // follows the per-index derivation `D + m_i*G`, which is
                // secret-touching and served from the secret projection (§2.4).
                let (spend_pk, view_pk) = if idx.is_primary() {
                    (self.public.spend_pk, self.public.view_pk)
                } else {
                    let (spend_point, view_point) = subaddress_keys(
                        &self.audit_secret.view_scalar,
                        &self.audit_secret.spend_public,
                        &idx.to_canonical_bytes(),
                    );
                    (
                        SpendPublicKey::from_canonical_bytes(spend_point.compress().to_bytes()),
                        ViewPublicKey::from_canonical_bytes(view_point.compress().to_bytes()),
                    )
                };

                // No registry mutation on the handle path (§2.4): the actor owns
                // the registry, which only feeds the cold `try_claim_output`.

                Ok(SubaddressFor::Audit(SubaddressKeyPair {
                    spend_pk,
                    view_pk,
                }))
            }
            // `Recipient` (and any future recipient-shaped variant) needs
            // per-subaddress hybrid KEM keygen, not yet implemented. Mirrors
            // `LocalKeys`. The broader "subaddress mechanism under PQC"
            // question is a FOLLOWUPS design round.
            _ => Err(KeyEngineError::RecipientSubaddressKemKeygenNotImplemented),
        }
    }

    async fn try_claim_output(
        &self,
        input: &OutputDetectionInput,
    ) -> Result<OutputClaimResult, Self::Error> {
        self.actor
            .ask(ClaimOutput {
                input: input.clone(),
            })
            .await
            .map_err(collapse_send_error)
    }

    async fn sign_transaction(&self, _tx: &TxToSign) -> Result<TxSignatures, Self::Error> {
        self.actor
            .ask(SignTransaction)
            .await
            .map_err(collapse_send_error)
    }
}

// ---------------------------------------------------------------------------
// Tests (§5.2)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    //! Stage-2 Step-1 contract tests for [`KeyActor`] / [`KeyEngineHandle`],
    //! per `STAGE_2_KEY_ENGINE_ACTOR.md` §5.2. No mocks: every test runs a real
    //! [`KeyActor`] over a real [`AllKeysBlob`] (`generate_account_from_raw_seed`
    //! against a deterministic testnet seed — the same fixture shape
    //! `LocalKeys` tests use) and exercises it through real messages.
    //!
    //! `AllKeysBlob` is not `Clone` (V3.0 not-clone discipline), so tests that
    //! need the *same* key material on both the actor side and the `LocalKeys`
    //! oracle side build **two** blobs from the **same** seed; rederivation is
    //! deterministic, so the two blobs are byte-identical. The detection input
    //! is built from the actor-side blob's public keys and is valid for both.
    //!
    //! ## Zeroize observability
    //!
    //! The actor owns a real `AllKeysBlob` directly (not a test fixture
    //! wrapper), so the byte-level wipe-on-drop is owned by `shekyl-crypto-pq`'s
    //! `AllKeysBlob` tests, not re-tested here. What these tests pin is (a) the
    //! *type-level* wipe contract ([`zeroize_on_drop_contract`]); (b) the
    //! *lifecycle* behavior that triggers the drop — clean stop and
    //! panic-fail-stop both terminate the actor task, at which point
    //! `AllKeysBlob`'s `ZeroizeOnDrop` (plus the explicit `on_stop` wipe) runs;
    //! and (c) the *reply-path* wipe ([`reply_path_wipes_on_drop`]), the
    //! Stage-2-specific surface where a secret-bearing reply traverses kameo's
    //! channel and must wipe when the channel drops it (e.g. ask-cancellation).
    //! A fixture-drop-counter that observed the *blob* wipe firing at actor-stop
    //! would require making `KeyActor` generic over the blob type, distorting
    //! the production shape for a property the dependency already tests; that is
    //! deliberately not done. The reply-path observation does *not* need that —
    //! it routes a dedicated instrumented `ZeroizeOnDrop` reply through the
    //! mailbox without touching `KeyActor`'s production shape.

    use super::*;

    use std::sync::atomic::{AtomicBool, Ordering};

    use shekyl_crypto_pq::account::{generate_account_from_raw_seed, DerivationNetwork};
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::output::construct_output;

    use crate::engine::local_keys::LocalKeys;
    use crate::engine::traits::key::ViewTag;

    /// Deterministic seed shared by the actor side and the `LocalKeys` oracle.
    const TEST_SEED: [u8; 32] = [7u8; 32];
    /// A different wallet's seed — used to build an output the test wallet does
    /// not own (the `NotMine` case).
    const STRANGER_SEED: [u8; 32] = [9u8; 32];
    /// Sender-side tx-key secret for `construct_output`; its value does not
    /// affect receiver-side recovery (the recipient only sees the ciphertext).
    const TEST_TX_KEY_SECRET: [u8; 32] = [11u8; 32];

    /// Rederive a fresh [`AllKeysBlob`] from `seed` (testnet, raw32).
    fn make_blob(seed: [u8; 32]) -> AllKeysBlob {
        let (_master_seed, blob) =
            generate_account_from_raw_seed(&seed, DerivationNetwork::Testnet)
                .expect("test rederivation succeeds for raw32 testnet seeds");
        blob
    }

    /// Build a synthetic on-chain output paid to `recipient`'s primary address,
    /// packaged as the `OutputDetectionInput` the trait surface consumes.
    fn build_output_paid_to(
        recipient: &AllKeysBlob,
        output_index: u64,
        amount: u64,
        tx_hash: [u8; 32],
    ) -> OutputDetectionInput {
        let constructed = construct_output(
            &TEST_TX_KEY_SECRET,
            &recipient.x25519_pk,
            &recipient.ml_kem_ek,
            recipient.spend_pk.as_canonical_bytes(),
            amount,
            output_index,
        )
        .expect("construct_output succeeds for synthetic output");

        OutputDetectionInput {
            ciphertext: HybridCiphertext {
                x25519: constructed.kem_ciphertext_x25519,
                ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
            },
            output_key: constructed.output_key,
            commitment: constructed.commitment,
            view_tag: ViewTag([constructed.view_tag_x25519]),
            enc_amount: constructed.enc_amount,
            amount_tag_on_chain: constructed.amount_tag,
            output_index,
            tx_hash,
        }
    }

    /// Unwrap an `OutputClaimResult::Mine`, panicking with context otherwise.
    fn expect_mine(result: OutputClaimResult) -> OutputClaim {
        match result {
            OutputClaimResult::Mine(claim) => claim,
            OutputClaimResult::NotMine => panic!("expected Mine, got NotMine"),
        }
    }

    // §5.2 test 1 — Equivalence: actor-via-`ask` == direct `LocalKeys`, Mine case.
    #[tokio::test]
    async fn try_claim_output_mine_equivalent_to_local_keys() {
        let tx_hash = [3u8; 32];
        let actor_blob = make_blob(TEST_SEED);
        let input = build_output_paid_to(&actor_blob, 0, 1_337, tx_hash);

        // Oracle: direct LocalKeys over the same (deterministic) seed.
        let local = LocalKeys::from_test_seed(TEST_SEED);
        let local_claim = expect_mine(
            local
                .try_claim_output(&input)
                .await
                .expect("LocalKeys claim succeeds"),
        );

        // Actor: same input, reached through the mailbox.
        let handle = KeyEngineHandle::spawn(actor_blob);
        let actor_claim = expect_mine(
            handle
                .try_claim_output(&input)
                .await
                .expect("actor claim succeeds"),
        );

        assert_eq!(
            actor_claim.handle, local_claim.handle,
            "actor and LocalKeys derive the same OutputHandle"
        );
        assert_eq!(
            actor_claim.key_image, local_claim.key_image,
            "actor and LocalKeys derive the same key image"
        );
        assert_eq!(
            actor_claim.amount_atomic_units, local_claim.amount_atomic_units,
            "actor and LocalKeys recover the same amount"
        );
        assert_eq!(actor_claim.amount_atomic_units, 1_337);
    }

    // §5.2 test 1 — Equivalence: actor-via-`ask` == direct `LocalKeys`, NotMine.
    #[tokio::test]
    async fn try_claim_output_not_mine_equivalent_to_local_keys() {
        let tx_hash = [4u8; 32];
        // Output paid to a *stranger* — neither wallet claims it.
        let stranger = make_blob(STRANGER_SEED);
        let input = build_output_paid_to(&stranger, 0, 42, tx_hash);

        let local = LocalKeys::from_test_seed(TEST_SEED);
        let local_result = local
            .try_claim_output(&input)
            .await
            .expect("LocalKeys claim succeeds");
        assert!(matches!(local_result, OutputClaimResult::NotMine));

        let handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));
        let actor_result = handle
            .try_claim_output(&input)
            .await
            .expect("actor claim succeeds");
        assert!(matches!(actor_result, OutputClaimResult::NotMine));
    }

    // §4.2 — require-ambient spawn contract. Without an ambient Tokio runtime,
    // `KeyEngineHandle::spawn` panics with the contract message (rather than
    // hosting an engine-owned runtime, the rejected `shutdown_background`/drop-
    // panic path). This is a plain `#[test]` precisely *because* it must run
    // with no ambient runtime; the panic is the asserted behavior.
    #[test]
    #[should_panic(expected = "requires an ambient Tokio runtime")]
    fn spawn_without_ambient_runtime_panics() {
        // No `#[tokio::test]` here: no ambient runtime → the assert in `spawn`
        // fires before any actor task is scheduled.
        let _handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));
    }

    // §5.2 test 2 — No-secret-crosses (structural): the message + reply types
    // are `Send` (kameo requires it) and carry only public/opaque material.
    #[test]
    fn message_and_reply_types_are_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ClaimOutput>();
        assert_send::<OutputClaimResult>();
        assert_send::<OutputClaim>();
        assert_send::<SignTransaction>();
    }

    // §5.2 (zeroize observability, type layer) — the actor's secret-bearing
    // owned types satisfy the wipe-on-drop contract at compile time.
    #[test]
    fn zeroize_on_drop_contract() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<AllKeysBlob>();
        assert_zeroize_on_drop::<AuditSubaddressSecret>();
        // Finding 4: the `try_claim_output` reply carries the decrypted amount
        // (a secret) plus per-output privacy-linkable identifiers across the
        // actor channel. The wipe-on-drop contract is what makes a
        // channel-internal drop (cancelled `ask`) safe.
        assert_zeroize_on_drop::<OutputClaim>();
    }

    // §5.2 test 3 — Handle-resolved methods resolve *after the actor is stopped*
    // (no actor interaction). Covers `account_public_address`, primary +
    // non-primary `derive_subaddress(Audit)`, and the `Recipient` stub. The
    // non-primary branch is the secret-touching Option-(a) path (§2.4); its
    // output is pinned byte-equal to the `LocalKeys` oracle.
    #[tokio::test]
    async fn handle_resolved_methods_resolve_after_stop() {
        let handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));
        let oracle = LocalKeys::from_test_seed(TEST_SEED);
        let non_primary = SubaddressIndex::new(1);

        // Capture oracle outputs while everything is live.
        let oracle_addr = oracle.account_public_address().clone();
        let oracle_primary = audit_pair(
            oracle
                .derive_subaddress(SubaddressIndex::PRIMARY, SubaddressPurpose::Audit)
                .expect("oracle primary audit"),
        );
        let oracle_sub = audit_pair(
            oracle
                .derive_subaddress(non_primary, SubaddressPurpose::Audit)
                .expect("oracle non-primary audit"),
        );

        // Stop the actor; the handle-resolved methods must still work.
        handle
            .actor
            .stop_gracefully()
            .await
            .expect("graceful stop signalled");
        handle.actor.wait_for_shutdown().await;
        assert!(!handle.actor.is_alive(), "actor is stopped");

        // account_public_address — served from the public projection, no `ask`.
        let addr = handle.account_public_address();
        assert_eq!(addr.pqc_public_key, oracle_addr.pqc_public_key);
        assert_eq!(
            addr.classical_address_bytes,
            oracle_addr.classical_address_bytes
        );

        // Primary audit — bare account keys, served from the public projection.
        let primary = audit_pair(
            handle
                .derive_subaddress(SubaddressIndex::PRIMARY, SubaddressPurpose::Audit)
                .expect("handle primary audit resolves post-stop"),
        );
        assert_eq!(primary, oracle_primary, "primary audit matches LocalKeys");

        // Non-primary audit — secret-touching, served from AuditSubaddressSecret.
        let sub = audit_pair(
            handle
                .derive_subaddress(non_primary, SubaddressPurpose::Audit)
                .expect("handle non-primary audit resolves post-stop"),
        );
        assert_eq!(sub, oracle_sub, "non-primary audit matches LocalKeys");
        assert_ne!(
            sub, primary,
            "non-primary subaddress is a distinct key pair from primary"
        );

        // Recipient — the unimplemented stub (FOLLOWUPS design round).
        let err = handle
            .derive_subaddress(SubaddressIndex::PRIMARY, SubaddressPurpose::Recipient)
            .expect_err("Recipient subaddress is a stub");
        assert!(matches!(
            err,
            KeyEngineError::RecipientSubaddressKemKeygenNotImplemented
        ));
    }

    /// Build an empty [`TxToSign`]. `sign_transaction` ignores the transaction
    /// entirely (Stage-2 stub), so the empty shape suffices to exercise the
    /// dispatch + error path.
    fn dummy_tx_to_sign() -> TxToSign {
        use crate::engine::traits::key::FcmpPlusPlusContext;
        TxToSign {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fcmp_plus_plus_context: FcmpPlusPlusContext {},
        }
    }

    /// Extract the `(spend_pk, view_pk)` pair from an audit subaddress result.
    fn audit_pair(sub: SubaddressFor) -> (SpendPublicKey, ViewPublicKey) {
        match sub {
            SubaddressFor::Audit(pair) => (pair.spend_pk, pair.view_pk),
            other => panic!("expected SubaddressFor::Audit, got {other:?}"),
        }
    }

    /// Test-only message whose handler panics, to exercise the §4.5 fail-stop
    /// path. Not gated out of the production surface beyond `#[cfg(test)]`.
    struct InjectPanic;

    impl Message<InjectPanic> for KeyActor {
        type Reply = ();

        async fn handle(
            &mut self,
            _msg: InjectPanic,
            _ctx: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            panic!("test-injected panic: exercise fail-stop");
        }
    }

    // --- Finding 4 reply-path wipe probe ---------------------------------
    //
    // The Stage-2-specific zeroization surface is the reply channel: a
    // secret-bearing reply moved through kameo's bounded mailbox / oneshot can
    // leave a copy in a freed channel allocation if the type does not wipe on
    // drop. `OutputClaim: ZeroizeOnDrop` (asserted in `zeroize_on_drop_contract`)
    // guarantees the wipe; this harness proves the *mechanism* the channel
    // relies on — that routing a `ZeroizeOnDrop` reply through the actor and
    // dropping it (exactly what the channel does to an un-taken reply on
    // ask-cancellation) runs the zeroizing `Drop`.
    static PROBE_REPLY_WIPED: AtomicBool = AtomicBool::new(false);

    /// Observable stand-in for `OutputClaim`'s secret fields: its `Zeroize`
    /// flips the global flag, so the derived `ZeroizeOnDrop` `Drop` is visible.
    struct ProbeDropFlag;
    impl Zeroize for ProbeDropFlag {
        fn zeroize(&mut self) {
            PROBE_REPLY_WIPED.store(true, Ordering::SeqCst);
        }
    }

    #[derive(ZeroizeOnDrop)]
    struct ProbeReplyVal {
        // The `ZeroizeOnDrop` derive's `Drop` calls `flag.zeroize()`.
        flag: ProbeDropFlag,
    }

    struct ProbeReply;
    impl Message<ProbeReply> for KeyActor {
        // `Result<T, E>` is `kameo::Reply` for any `T: Send + 'static`, so the
        // probe reply need not implement `Reply` itself — mirroring the
        // `Result<OutputClaimResult, _>` shape of the real claim reply.
        type Reply = Result<ProbeReplyVal, KeyEngineError>;

        async fn handle(
            &mut self,
            _msg: ProbeReply,
            _ctx: &mut Context<Self, Self::Reply>,
        ) -> Self::Reply {
            Ok(ProbeReplyVal {
                flag: ProbeDropFlag,
            })
        }
    }

    // §5.2 test 4 (Finding 4) — the actor reply path wipes on drop. Routes a
    // `ZeroizeOnDrop` reply through the mailbox, confirms it is intact while the
    // caller holds it, then drops it (modelling the channel dropping an un-taken
    // reply on `ask`-cancellation) and asserts the zeroizing `Drop` ran.
    #[tokio::test]
    async fn reply_path_wipes_on_drop() {
        PROBE_REPLY_WIPED.store(false, Ordering::SeqCst);
        let handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));

        let reply = handle
            .actor
            .ask(ProbeReply)
            .await
            .expect("probe reply resolves");
        assert!(
            !PROBE_REPLY_WIPED.load(Ordering::SeqCst),
            "reply must not be wiped while the caller still holds it"
        );

        drop(reply);
        assert!(
            PROBE_REPLY_WIPED.load(Ordering::SeqCst),
            "dropping the reply runs its zeroizing Drop — the same Drop the \
             channel runs on an un-taken reply at ask-cancellation"
        );
    }

    // §5.2 test 4 — Panic → fail-stop → terminal, non-retryable
    // `KeyActorUnavailable`. Injects a panic in a handler; asserts the actor
    // dies and that *repeated* asks all collapse to the terminal error (a retry
    // never recovers), pinning the §2.6 "abort, don't retry" contract.
    #[tokio::test]
    async fn panic_fail_stops_and_asks_are_terminally_unavailable() {
        let handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));
        let input = build_output_paid_to(&make_blob(TEST_SEED), 0, 7, [5u8; 32]);

        // Sanity: a live ask works before the panic.
        assert!(handle.try_claim_output(&input).await.is_ok());

        // Inject the panic. kameo catches it via on_panic → Break (fail-stop);
        // the panicking ask itself resolves to a transport error (the reply
        // channel is dropped as the actor dies). The contract under test is
        // what happens *after* death.
        let panic_ask = handle.actor.ask(InjectPanic).await;
        assert!(
            panic_ask.is_err(),
            "ask whose handler panics resolves to a transport error"
        );
        handle.actor.wait_for_shutdown().await;
        assert!(!handle.actor.is_alive(), "panic fail-stops the actor");

        // Terminal + non-retryable: every subsequent ask returns the same
        // KeyActorUnavailable, no matter how many times we retry.
        for attempt in 0..3 {
            let err = handle
                .try_claim_output(&input)
                .await
                .expect_err("post-death ask fails");
            assert!(
                matches!(err, KeyEngineError::KeyActorUnavailable),
                "attempt {attempt}: expected KeyActorUnavailable, got {err:?}"
            );
        }

        // sign_transaction against the dead actor is likewise unavailable
        // (not the stub error — the actor never runs the handler).
        let sign_err = handle
            .sign_transaction(&dummy_tx_to_sign())
            .await
            .expect_err("post-death sign fails");
        assert!(matches!(sign_err, KeyEngineError::KeyActorUnavailable));
    }

    // §5.2 test 3 (continued) — sign_transaction on a *live* actor returns the
    // PR-5 stub error (the actor runs the handler; the surface is incomplete).
    #[tokio::test]
    async fn sign_transaction_live_returns_stub_error() {
        let handle = KeyEngineHandle::spawn(make_blob(TEST_SEED));
        let err = handle
            .sign_transaction(&dummy_tx_to_sign())
            .await
            .expect_err("sign_transaction is a stub");
        assert!(matches!(
            err,
            KeyEngineError::SignTransactionTraitSurfaceIncomplete
        ));
    }
}
