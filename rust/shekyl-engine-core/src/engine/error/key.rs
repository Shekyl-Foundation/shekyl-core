// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Key (de)derivation and `KeyEngine` runtime error vocabulary.

// --- Key (de)derivation ----------------------------------------------------

/// Failures while (re)deriving wallet key material from a master seed,
/// or while loading / sealing the keys-file payload. Wraps
/// [`shekyl_crypto_pq::CryptoError`] (lands as `#[from]` alongside the
/// `open_full` / `change_password` lifecycle commit).
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Re-derivation produced material whose public bytes do not match
    /// the keys-file's stored `account_public_address`. Indicates either
    /// disk corruption, a wallet-file format bug, or a mismatched
    /// derivation salt — never a normal-operation outcome.
    #[error("rederived public material does not match keys-file declaration")]
    PublicBytesMismatch,

    /// The keys file declared a `(network, seed_format)` pair that the
    /// derivation layer rejects as not permitted (e.g., mainnet with a
    /// raw 32-byte seed). The keys-file integrity check should have
    /// rejected this earlier; this variant is the defensive path.
    #[error("keys file declares unsupported (network, seed_format) pair")]
    UnsupportedDerivationPair,

    /// HKDF expand, scalar reduction, or ML-KEM seed expansion produced
    /// an invalid intermediate value. Almost certainly indicates a bug
    /// in `shekyl-crypto-pq`; the variant exists so a future audit can
    /// distinguish "unreachable in practice" failure paths from disk-
    /// corruption ones.
    #[error("crypto primitive failure during key derivation: {detail}")]
    Primitive {
        /// Human-readable description of which primitive failed
        /// (named at the call site, not synthesized).
        detail: &'static str,
    },
}

// --- KeyEngine runtime ops -------------------------------------------------

/// Failures during runtime
/// [`KeyEngine`](crate::engine::traits::key::KeyEngine) operations (signing,
/// hybrid decapsulation, ECDH, subaddress derivation). Distinct from
/// [`KeyError`], which scopes wallet-open / derivation failures.
///
/// Cross-trait coordination failures (e.g., concurrent key rotation
/// invalidating an in-progress signing attempt) do **not** appear
/// here per the §3.2 negative-space framing in
/// `docs/design/STAGE_1_PR_3_KEY_ENGINE.md` — they accumulate on a
/// future cross-trait error type when concrete triggers materialize.
///
/// # Variant accretion
///
/// Per §7.2 of `STAGE_1_PR_3_KEY_ENGINE.md`, this mirrors PR 2's
/// `LedgerError` introduction: variants land at implementation
/// time, not speculatively in the spec round. The variants below
/// were surfaced by M3a Commit 4b's `LocalKeys` impl; further
/// variants accrete as later trait surfaces (M3b–M3e, PR 5+) reveal
/// additional failure modes.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyEngineError {
    /// The deterministic-handle re-decap path (`LocalKeys::derive_primary_source_secrets_bundle`,
    /// Layer 2 of M3b D1 per `STAGE_1_PR_3_M3B_PREFLIGHT.md` §2)
    /// failed to recover `combined_ss` from the persisted
    /// [`shekyl_crypto_pq::kem::HybridCiphertext`] using the wallet's
    /// view material.
    ///
    /// The expected operational case for this variant is **none**: the
    /// re-decap path is invoked only on outputs the wallet has already
    /// scanned and persisted as its own, so the ciphertext, view
    /// secret, and ML-KEM decap key all came from the same wallet's
    /// own state. A failure here implies storage corruption (the
    /// `TransferDetails.source_ciphertext` no longer matches the bytes
    /// originally written), key-engine state corruption (the wallet's
    /// view material has drifted), or — in the worst case — a
    /// malicious local actor who tampered with the persisted ledger.
    /// The variant is **loud, not silent**: surfaces as a typed error
    /// so the caller can refuse to construct a `TxToSign` against the
    /// affected output rather than silently fall back to derivation
    /// from suspect intermediate state.
    ///
    /// Carries the inner [`shekyl_crypto_pq::CryptoError`] so the
    /// caller (and audit logs) can see whether the failure was a
    /// low-order Montgomery rejection
    /// ([`shekyl_crypto_pq::CryptoError::LowOrderPoint`]),
    /// an invalid decap-key length
    /// ([`shekyl_crypto_pq::CryptoError::InvalidKeyMaterial`]), or
    /// an ML-KEM-768 decap rejection
    /// ([`shekyl_crypto_pq::CryptoError::DecapsulationFailed`]).
    /// All three indicate the same operational class (corrupted /
    /// tampered persisted state) but the inner detail names which
    /// step rejected the input.
    #[error("source ciphertext re-decapsulation failed: {0}")]
    SourceCiphertextDecapsulationFailed(#[from] shekyl_crypto_pq::CryptoError),

    /// The key actor task has stopped — clean shutdown, panic, or
    /// fail-stop (`on_panic` → `ControlFlow::Break`). Surfaced by
    /// [`KeyEngineHandle`](crate::engine::key_actor::KeyEngineHandle) when a
    /// `kameo` `ask` against the actor returns a transport failure
    /// (`SendError::ActorNotRunning` / `ActorStopped` / `Timeout`, and
    /// — though unreachable on the awaiting `ask` path —
    /// `MailboxFull`), as opposed to a `HandlerError` carrying a real
    /// crypto/engine failure.
    ///
    /// **Terminal and non-retryable.** The actor is fail-stop by
    /// construction (`STAGE_2_KEY_ENGINE_ACTOR.md` §4.5): a stopped key
    /// actor is unrecoverable in-session because its `AllKeysBlob` is
    /// already zeroized. The only recovery is a full wallet close +
    /// re-open (`open_full` re-derives the blob from the encrypted
    /// envelope). Callers must **propagate**, not retry: every
    /// subsequent `ask` on the same handle returns this same error, so
    /// a retry loop against a dead actor spins forever. This is the
    /// inverse of the live-actor bounded-mailbox backpressure case,
    /// where the `ask` future simply blocks the sender until capacity
    /// frees (recoverable, and never surfaces as this variant).
    ///
    /// Distinguishable from crypto faults by being its own variant
    /// (not folded into a `CryptoError` wrapper), so the refresh/RPC
    /// tier can branch on "session-ended" vs "operation-failed." Per
    /// `35-secure-memory.mdc`, the variant carries only a discriminant
    /// — no secret material in its `Debug`/`Display`.
    #[error(
        "key actor unavailable: the key actor task has stopped (terminal, non-retryable; recover via wallet close + re-open)"
    )]
    KeyActorUnavailable,

    /// Dust-fold pre-prove variant selection failed (§3.8.2 F4/F8).
    #[error("insufficient funds for fee variant: shortfall {shortfall} atomic units")]
    InsufficientFunds { shortfall: u64 },

    /// Spendable input lacks a canonical key image at assembly time (C7 PF8).
    #[error("missing key image for spend input at output index {output_index}")]
    MissingKeyImage { output_index: u64 },

    /// Handle does not match `derive_output_handle(view_sk, tx_hash, index)` (PF2).
    #[error("output handle mismatch for spend input at output index {output_index}")]
    HandleMismatch { output_index: u64 },

    /// Non-crypto structural failure during signing (address decode, wire encode, …).
    #[error("key engine primitive failure: {detail}")]
    Primitive { detail: &'static str },

    /// Proof generation failed inside the key actor (WI-RPC-3 inbound
    /// tx proofs / reserve proofs). Wraps [`shekyl_proofs::error::ProofError`]
    /// so the proofs workflow keeps the typed proof failure: its
    /// `From<KeyEngineError> for ProofsError` maps this variant to
    /// `ProofsError::Generate` — the proof-generation error class,
    /// which the RPC layer reports as a generation failure — instead
    /// of flattening it into the stringified key-engine class like
    /// every other actor failure. The generation inputs are the
    /// wallet's own persisted state, so — as with
    /// [`Self::SourceCiphertextDecapsulationFailed`] — the expected
    /// operational frequency is zero; the variant is loud, not silent.
    #[error("proof generation failure: {0}")]
    Proof(#[from] shekyl_proofs::error::ProofError),
}
