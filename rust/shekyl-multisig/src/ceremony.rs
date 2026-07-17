// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Option E′ spend ceremony: the FROST [`FrostCeremony`] FSM (the
//! `SigningCeremony` type for `MultisigSignerV2`), the two nonce shapes, the
//! [`ConsumedNonce`] persist-before-use typestate, and the [`SpendRequest`] /
//! [`SpendResponse`] blob newtypes.
//!
//! # Four blobs, two round-trips, pqc-last
//!
//! `pqc-last` — a hybrid `scheme_id=2` sig signs over the *finished* SAL proof
//! (the daemon's anti-substitution binding, `tx_pqc_verify.cpp`) — forces **two**
//! round-trips: a cosigner's hybrid sig cannot exist until the SAL is aggregated,
//! which needs the cosigner's FROST share first. So one spend is:
//!
//! - **RT1 (FROST).** A→B (blob 1): A's nonce commitment — A now *holds* a nonce
//!   across the gap. B→A (blob 2): B's commitment + share — B's nonce is born and
//!   dies inside one call. A aggregates → SAL, consuming its held nonce.
//! - **RT2 (pqc-last).** A→B (blob 3): the finalized SAL/tx context. B→A (blob 4):
//!   B's hybrid sig over `pqc_signing_payload_hashes(i)` (which embeds the SAL). A
//!   produces its own hybrid sig locally and assembles. No FROST nonces here.
//!
//! The (D) two-leg binding is *already* welded in the solo path (the pqc payload
//! embeds the SAL via `prunable_hash`; the curve-tree leaf `h_pqc = H(pqc_pk)`
//! binds the SAL to the key, and the multisig key *container* hashes to that
//! leaf). MS-5 extends it with **no new primitive** — it only forces the pqc-last
//! order above. B's two transitions stay welded to one intent because B's blob-4
//! sig is over the payload embedding B's own blob-2 FROST contribution, and B
//! rejects a blob 3 whose intent differs from what it committed.
//!
//! # The nonce rule (two shapes — the danger is scoped to one role)
//!
//! - **B's nonce (the safe key): ephemeral, `!Clone`** ([`EphemeralNonce`]).
//!   Born, used, and dropped inside one call — never persisted, never returned.
//!   B is protected by the *ceremony's shape*, not by disk discipline.
//! - **A's nonce (online): held across RT1, under three guards** ([`HeldNonce`]):
//!   1. **Containment** — reachable only from inside the same protected container
//!      as A's `y_group` share. A nonce disclosure then costs the same breach as a
//!      share disclosure; and disclosure alone leaks the share via `x = (s−k)/e`,
//!      so confidentiality parity is exactly the bar.
//!   2. **Consume-once** — via the [`ConsumedNonce`] typestate, minted only after
//!      [`NonceCounterSink::persist_nonce_counter`] commits the durable monotonic
//!      counter *first* (persist-before-use). Stops the two-signature `x=(s−k)/e`
//!      extraction — **key theft**.
//!   3. **Intent-binding** — the token is bound to one `intent_hash`; a response
//!      for another intent is rejected. Stops a cosigner inducing A to sign one
//!      nonce against two challenges — **fund theft**. Distinct from consume-once.
//!
//! `!Serialize` is *not* used as a guard: it is unprovable (a foreign `derive`
//! lands in six months). "Restart forfeits the round" is dropped too: it is
//! incompatible with the walk to the safe, which the transport decision made
//! mandatory. What survives is consume-once + containment + intent-binding — and
//! the reason it is not just `!Serialize` is two dead rules and an `x = (s−k)/e`.
//!
//! # No live crypto in this slice (MS-5 S1)
//!
//! The FROST rounds, the SAL aggregation, the `y_kem` tweak, and the hybrid sigs
//! land in S2/S3. Here the crypto-producing transitions return
//! [`CeremonyError::NotYetImplemented`] (no `todo!()`). What S1 ships is the
//! *type structure* — the clean build is the proof: `EphemeralNonce`/`HeldNonce`/
//! `ConsumedNonce` cannot gain `Clone` (the `AmbiguousIfImpl` guard below), and
//! the share-releasing path ([`release_spend_share`]) is unreachable without a
//! `ConsumedNonce`, which is unreachable without the sink's durable `Ok`.

// ===========================================================================
// Blob newtypes — the engine boundary is bytes in / bytes out. This crate owns
// no transport; the wallet moves these over any channel (file, animated QR, …).
// ===========================================================================

/// A ceremony blob emitted by the proposer (A → cosigner). Opaque bytes, moved
/// over a bring-your-own channel. Phase context lives in the ceremony state, not
/// in this wrapper; the bytes themselves are self-authenticating (S3).
#[derive(Clone, Debug)]
pub struct SpendRequest(Vec<u8>);

/// A ceremony blob emitted by a cosigner (B → proposer).
#[derive(Clone, Debug)]
pub struct SpendResponse(Vec<u8>);

impl SpendRequest {
    /// Wrap raw bytes received over a channel.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Borrow the bytes for transmission / rendering.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Take the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl SpendResponse {
    /// Wrap raw bytes received over a channel.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Borrow the bytes for transmission / rendering.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Take the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

// ===========================================================================
// Nonce shapes
// ===========================================================================

/// The cosigner (B)'s FROST nonce. **Ephemeral by construction**: created, used,
/// and dropped inside a single [`FrostCeremony::cosigner_round1`] call — never
/// persisted, never returned, never cloned. `!Clone` is compile-enforced (the
/// `AmbiguousIfImpl` guard at the bottom of this module); duplicating it would
/// let one nonce sign twice (key theft via `x = (s−k)/e`).
///
/// S2 replaces the stub with the real `modular_frost` nonce (commitment + scalar)
/// plus `ZeroizeOnDrop`. Inert until then.
#[allow(dead_code)] // constructed + used once the FROST round-1 crypto lands (S2)
struct EphemeralNonce {
    /// Placeholder so the type carries the `!Clone` discipline before S2's scalar.
    _private: (),
}

impl EphemeralNonce {
    /// Generate a fresh ephemeral nonce. Callers must use and drop it within one
    /// function — it is `!Clone` and never returned.
    #[allow(dead_code)] // called from cosigner_round1 once the crypto lands (S2)
    fn generate() -> Self {
        Self { _private: () }
    }
}

/// The proposer (A)'s FROST nonce, **held across round-trip 1** (the walk to the
/// safe — hours, days). Reachable only from inside the same protected container
/// as A's `y_group` share (**containment**). Consumed exactly once, bound to one
/// intent, released to the share-producing path only through a [`ConsumedNonce`].
/// Not `Serialize`: persistence rides the same sealed container as the share,
/// never this type by itself.
///
/// S2 replaces the stub with the real held nonce scalar. Inert until then.
#[allow(dead_code)] // constructed by proposer_round1 once the FROST crypto lands (S2)
struct HeldNonce {
    /// The intent this nonce is committed to (the intent-binding guard: a
    /// response for a different intent cannot consume it).
    intent_hash: [u8; 32],
    /// Placeholder for the real held nonce scalar (S2), which lives behind the
    /// share's container.
    _private: (),
}

// ===========================================================================
// ConsumedNonce — the persist-before-use typestate (the PersistedBondTicket
// mechanism with a different payload; here it spans the crate boundary).
// ===========================================================================

/// Witness that A's held nonce for a specific `intent_hash` was consumed exactly
/// once, with the durable monotonic counter advanced **first** (persist-before-
/// use). The share-releasing path ([`release_spend_share`]) takes one **by
/// value**; there is no public constructor, so "release the share before the
/// counter is durable" has no expressible form.
///
/// `!Clone`: one persist authorizes one sign (mirrors `PersistedBondTicket` and
/// the `AllKeysBlob` not-`Clone` discipline). Bound to `intent_hash` so a token
/// minted for intent X cannot release a share for intent Y.
///
/// Unlike `PersistedBondTicket` — whose producer and consumer both live in
/// engine-core — this token spans the crate boundary: `shekyl-multisig` owns no
/// ledger, so the durable write is an *injected* capability ([`NonceCounterSink`],
/// impl'd by engine-core), and the token is minted by the ceremony **gated on
/// that capability's `Ok`**. Same guarantee — no durable persist → no token → no
/// share released.
///
/// Both fields are private, so the only `ConsumedNonce` values are those minted
/// inside this module after the sink's durable `Ok` — external code cannot name
/// the fields to construct one.
#[derive(Debug)]
pub struct ConsumedNonce {
    intent_hash: [u8; 32],
    counter: u64,
}

impl ConsumedNonce {
    /// The intent this consumption authorizes.
    #[must_use]
    pub fn intent_hash(&self) -> [u8; 32] {
        self.intent_hash
    }
    /// The durable counter value that was committed *before* this token existed.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }
}

/// The persist-before-use capability the ceremony needs but does not own:
/// durably advance A's monotonic nonce counter and commit it to disk **before**
/// the FROST share is released. Impl'd by engine-core (which owns the wallet
/// ledger); the ceremony calls it and mints a [`ConsumedNonce`] only on `Ok`.
///
/// This crate-boundary inversion is what keeps `shekyl-multisig` free of any
/// ledger / I/O edge (the "no transport / no I/O" ban) while still binding the
/// nonce consumption to a durable, crash-atomic commit.
pub trait NonceCounterSink {
    /// Durably advance the counter for `intent_hash` to `counter` and commit.
    ///
    /// On `Ok`, the advance is crash-atomic on disk; on `Err`, no
    /// [`ConsumedNonce`] is produced, so the ceremony fails **closed** — it
    /// cannot proceed to release the share.
    fn persist_nonce_counter(
        &mut self,
        intent_hash: [u8; 32],
        counter: u64,
    ) -> Result<(), NonceCounterError>;
}

/// Failure of the durable nonce-counter advance. Opaque to the ceremony (it only
/// needs to know persistence failed → fail closed).
#[derive(Debug, thiserror::Error)]
#[error("durable nonce-counter persist failed: {0}")]
pub struct NonceCounterError(pub String);

// ===========================================================================
// The ceremony FSM
// ===========================================================================

/// Errors from a [`FrostCeremony`] transition.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// A transition was called in the wrong phase.
    #[error("ceremony transition called out of order (phase: {phase})")]
    WrongPhase {
        /// The phase the ceremony was actually in.
        phase: &'static str,
    },
    /// A blob's intent does not match the intent this ceremony is bound to
    /// (the intent-binding / anti-splice check).
    #[error("blob intent does not match the ceremony's committed intent")]
    IntentMismatch,
    /// The live FROST / pqc crypto is not implemented in this slice (MS-5 S1).
    #[error("live FROST/pqc crypto is not implemented in this slice (MS-5 S1)")]
    NotYetImplemented,
    /// The durable nonce-counter persist failed; the ceremony fails closed.
    #[error(transparent)]
    Persist(#[from] NonceCounterError),
}

/// The Option E′ signing ceremony — the `SigningCeremony` type for
/// `MultisigSignerV2`. Drives one spend from intent to assembled transaction
/// across four blobs / two round-trips, in the (D)-forced **pqc-last** order.
///
/// Asymmetric roles: the **proposer** (A — the online wallet whose share is on
/// that disk anyway, where containment is a tautology) holds a nonce across
/// round-trip 1; the **cosigner** (B — the safe key) is nearly stateless, its
/// nonce ephemeral. Not `Clone`, not `Serialize`: it holds nonce material.
pub struct FrostCeremony {
    /// The intent every blob in this ceremony must agree on.
    intent_hash: [u8; 32],
    phase: Phase,
}

/// The FSM phases, in the four-blob / two-round-trip / pqc-last order.
///
/// The proposer and cosigner walk disjoint phase sequences; a single wallet is
/// one or the other per ceremony (decided by whether it proposes or responds).
#[allow(dead_code)] // phases past the constructors are reached once the crypto lands (S2)
enum Phase {
    // --- proposer (A) ---
    /// A drafted the intent; nothing emitted.
    ProposerDrafted,
    /// A emitted blob 1 (its FROST nonce commitment) and **holds** its nonce
    /// across the RT1 gap.
    ProposerHoldingNonce { nonce: HeldNonce },
    /// A ingested blob 2, aggregated the SAL (consuming its nonce), and emitted
    /// blob 3 — RT2 (pqc) pending.
    ProposerAwaitingPqc,
    /// A ingested blob 4 and assembled the transaction. Terminal.
    ProposerAssembled,

    // --- cosigner (B) ---
    /// B awaits blob 1.
    CosignerAwaitingRequest,
    /// B emitted blob 2 (its FROST commitment + share; ephemeral nonce already
    /// dropped) and awaits blob 3 — its hybrid sig (blob 4) is pqc-last.
    CosignerAwaitingPqc,
    /// B emitted blob 4. Terminal.
    CosignerDone,
}

impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Phase::ProposerDrafted => "proposer-drafted",
            Phase::ProposerHoldingNonce { .. } => "proposer-holding-nonce",
            Phase::ProposerAwaitingPqc => "proposer-awaiting-pqc",
            Phase::ProposerAssembled => "proposer-assembled",
            Phase::CosignerAwaitingRequest => "cosigner-awaiting-request",
            Phase::CosignerAwaitingPqc => "cosigner-awaiting-pqc",
            Phase::CosignerDone => "cosigner-done",
        }
    }
}

impl FrostCeremony {
    /// Begin a ceremony as **proposer** (A) for `intent_hash`.
    #[must_use]
    pub fn propose(intent_hash: [u8; 32]) -> Self {
        Self {
            intent_hash,
            phase: Phase::ProposerDrafted,
        }
    }

    /// Begin a ceremony as **cosigner** (B) for `intent_hash`.
    #[must_use]
    pub fn cosign(intent_hash: [u8; 32]) -> Self {
        Self {
            intent_hash,
            phase: Phase::CosignerAwaitingRequest,
        }
    }

    /// The intent this ceremony is bound to.
    #[must_use]
    pub fn intent_hash(&self) -> [u8; 32] {
        self.intent_hash
    }

    /// A, RT1 out: generate the held FROST nonce and emit blob 1 (its commitment).
    ///
    /// *S2 supplies the real nonce + commitment.*
    pub fn proposer_round1(&mut self) -> Result<SpendRequest, CeremonyError> {
        match self.phase {
            Phase::ProposerDrafted => Err(CeremonyError::NotYetImplemented),
            ref other => Err(CeremonyError::WrongPhase {
                phase: other.name(),
            }),
        }
    }

    /// B, RT1: ingest blob 1, emit blob 2 (commitment + share). The ephemeral
    /// FROST nonce is **born, used, and dropped inside this call**.
    ///
    /// *S2 supplies the real FROST round-1/round-2 math.*
    pub fn cosigner_round1(
        &mut self,
        _request: &SpendRequest,
    ) -> Result<SpendResponse, CeremonyError> {
        match self.phase {
            Phase::CosignerAwaitingRequest => Err(CeremonyError::NotYetImplemented),
            ref other => Err(CeremonyError::WrongPhase {
                phase: other.name(),
            }),
        }
    }

    /// A, RT1 in + RT2 out: ingest blob 2, aggregate the SAL, **consume the held
    /// nonce** (persist-before-use via `sink`), and emit blob 3.
    ///
    /// The persist-before-use gate is the load-bearing part and is wired here in
    /// full: the durable counter advance commits *first*; only then can a
    /// [`ConsumedNonce`] exist; and [`release_spend_share`] — the path that
    /// produces A's FROST share — cannot be reached without one. *S2 supplies the
    /// real counter value and the SAL aggregation.*
    pub fn proposer_round2(
        &mut self,
        _response: &SpendResponse,
        sink: &mut impl NonceCounterSink,
    ) -> Result<SpendRequest, CeremonyError> {
        let Phase::ProposerHoldingNonce { nonce } = &self.phase else {
            return Err(CeremonyError::WrongPhase {
                phase: self.phase.name(),
            });
        };
        // Persist-before-use: the durable monotonic counter advance MUST commit
        // before any share leaves. S2 supplies the real counter; the ordering
        // here is the guarantee.
        let counter = 0u64;
        sink.persist_nonce_counter(nonce.intent_hash, counter)?;
        // Only now can a ConsumedNonce exist — minted gated on the sink's Ok.
        let consumed = ConsumedNonce {
            intent_hash: nonce.intent_hash,
            counter,
        };
        // The share-releasing path is unreachable without this token.
        release_spend_share(consumed)?;
        Err(CeremonyError::NotYetImplemented)
    }

    /// B, RT2: ingest blob 3, verify its intent matches what B committed in blob
    /// 2 (anti-splice), and emit blob 4 (B's hybrid `scheme_id=2` sig over the
    /// SAL-embedding payload — pqc-last). No FROST nonce here.
    ///
    /// *S3 supplies the hybrid-sig production.*
    pub fn cosigner_round2(
        &mut self,
        _request: &SpendRequest,
    ) -> Result<SpendResponse, CeremonyError> {
        match self.phase {
            Phase::CosignerAwaitingPqc => Err(CeremonyError::NotYetImplemented),
            ref other => Err(CeremonyError::WrongPhase {
                phase: other.name(),
            }),
        }
    }

    /// A, RT2 in: ingest blob 4, assemble the final transaction bytes.
    ///
    /// *S3 supplies the assembly.*
    pub fn proposer_assemble(
        &mut self,
        _response: &SpendResponse,
    ) -> Result<Vec<u8>, CeremonyError> {
        match self.phase {
            Phase::ProposerAwaitingPqc => Err(CeremonyError::NotYetImplemented),
            ref other => Err(CeremonyError::WrongPhase {
                phase: other.name(),
            }),
        }
    }
}

/// The proposer's FROST share-releasing step. Reachable **only** with a
/// [`ConsumedNonce`] — the compile-time witness that the durable counter was
/// advanced first. This function's signature is the persist-before-use guarantee:
/// there is no way to call it without a token, and no way to make a token without
/// the sink's durable `Ok`. *S2 fills the real SAL aggregation under `Y_group`.*
fn release_spend_share(_consumed: ConsumedNonce) -> Result<(), CeremonyError> {
    Err(CeremonyError::NotYetImplemented)
}

// ===========================================================================
// Compile-time guard: the single-use nonce/token types must never gain `Clone`.
// Duplicating any of them would let one nonce sign twice (key theft via
// `x = (s−k)/e`) or one persist authorize two signs. Mirrors the `stake_engine`
// AmbiguousIfImpl guard. Zero-cost; no runtime, no dependency.
// ===========================================================================
const _: fn() = || {
    trait AmbiguousIfImpl<A> {
        fn token_must_stay_single_use() {}
    }
    impl<T> AmbiguousIfImpl<()> for T {}
    #[allow(dead_code)]
    struct Invalid;
    impl<T: Clone> AmbiguousIfImpl<Invalid> for T {}

    // Each resolves uniquely iff the type is NOT `Clone`; ambiguous (compile
    // error) if a `Clone`/`Copy` impl is ever added.
    let _ = <EphemeralNonce as AmbiguousIfImpl<_>>::token_must_stay_single_use;
    let _ = <HeldNonce as AmbiguousIfImpl<_>>::token_must_stay_single_use;
    let _ = <ConsumedNonce as AmbiguousIfImpl<_>>::token_must_stay_single_use;
};
