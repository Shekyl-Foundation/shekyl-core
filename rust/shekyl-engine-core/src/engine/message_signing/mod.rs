// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Wallet message signing workflow (PR-SM-1, A2 /
//! `WALLET_MESSAGE_SIGNING.md` SM-R-4/R-6).
//!
//! # Decomposition shape (`ENGINE_COMPOSITION_DECOMPOSITION.md` §4)
//!
//! Workflow functions take an explicit [`MessageSignCtx`], never
//! `&Engine`: the data dependencies (key handle, wallet file, network)
//! are visible in the ctx fields, and a new dependency is a reviewable
//! ctx-field addition rather than a silent `self.foo`. The `Engine`
//! method in this module is a thin delegator that assembles the ctx and
//! forwards.
//!
//! # Secret locality
//!
//! Both postures preserved: the **master seed** is transiently borrowed
//! from the open `WalletFile` envelope (`extract_rederivation_inputs`)
//! and never reaches the key actor; the **spend scalar** never leaves
//! the actor — it signs the public outer bytes (`preimage ‖ σ_pq`) via
//! [`KeyEngineHandle::sign_message_outer`](super::key_actor::KeyEngineHandle::sign_message_outer).
//! The SLH identity is derived on demand and its secret half
//! drops-and-wipes when the PQ half returns (SM-R-4: derived on demand,
//! zeroized, never persisted, no wallet-file schema change).
//!
//! # This work does not run on the executor
//!
//! The PQ half is a full SLH-DSA-192s keygen plus sign — ~4.3 s on the
//! Pi-4 provisioning floor (rule 76), and CPU-bound throughout. It goes
//! to [`tokio::task::spawn_blocking`], the same disposition Argon2 gets
//! at wallet open. Running it inline would park the runtime that also
//! drives the key actor's mailbox and the refresh loop, so on the
//! single-threaded runtime the engine explicitly supports, signing one
//! message would freeze the wallet and spuriously time out any
//! concurrent daemon poll. `block_in_place` is *not* the alternative:
//! it panics outright on a current-thread runtime.
//!
//! The blocking job is also **single-flight per wallet**: the PQ half
//! acquires the key handle's `sign_permit` and carries it into the
//! blocking task, so a burst of concurrent `sign_message` calls queues
//! FIFO instead of stacking multi-second CPU-bound jobs — see the
//! `sign_permit` field docs on
//! [`KeyEngineHandle`](super::key_actor::KeyEngineHandle).
//!
//! # Verify is here, and is not an `Engine` method
//!
//! [`verify_message`] is session-less (SM-R-6): no wallet, no daemon, no
//! `&Engine`. It still lives in this module so the transcript is scoped
//! by the same address-network → derivation-network mapping sign uses —
//! the RPC crate must not re-derive that byte. The crypto crate's
//! [`shekyl_crypto_pq::message_signing::verify_message`] stays the AND
//! of the two halves; this function is the address + network assembly
//! in front of it. Verify takes the address's [`BoundClassicalSegment`]
//! — keys and bound bytes are the same object.

use shekyl_address::{BoundClassicalSegment, ShekylAddress};
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat};
use shekyl_crypto_pq::message_signing::{self, MessageSigError};
use shekyl_engine_file::secrets_transitional::ExtractRederivationInputsError;
use shekyl_engine_file::WalletFile;

use super::error::KeyEngineError;
use super::key_actor::KeyEngineHandle;
use super::lifecycle::network_to_derivation;
use super::local_ledger::LocalLedger;
use super::signer::EngineSignerKind;
use super::traits::key::KeyEngine;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Explicit data dependencies of the message-signing workflow.
///
/// Mirrors [`super::proofs::ProofsCtx`]: workflow code names what it
/// needs, and `Engine` only assembles this bag.
pub(crate) struct MessageSignCtx<'a> {
    /// Key-actor handle — classical half of the nested hybrid.
    pub key: &'a KeyEngineHandle,
    /// Open wallet file — transient master-seed borrow for the PQ half,
    /// and the declared seed format the identity derivation is scoped by.
    pub file: &'a WalletFile,
    /// Wallet network. Resolved to a [`DerivationNetwork`] here so the
    /// signing identity and the signing transcript are scoped by the
    /// same value rather than by two independently-derived bytes.
    pub network: shekyl_address::Network,
}

/// Refusals and failures of [`sign_message`] / [`Engine::sign_message`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SignMessageError {
    /// View-only wallets hold no master seed — there is no signing
    /// identity to derive (SM-R-3: the deleted view-tier is
    /// structurally unbuildable, and this is where that surfaces).
    #[error("view-only wallet cannot sign messages")]
    ViewOnly,
    /// Hardware-offload wallets sign elsewhere; the local envelope has
    /// no seed to derive from.
    #[error("hardware-offload wallet cannot sign messages locally")]
    HardwareOffload,
    /// The key actor has stopped: terminal and non-retryable, because
    /// its key blob is already zeroized. Its own variant rather than a
    /// rendered string because it is the one key-engine failure with a
    /// *different user action* attached — close and reopen, not "try
    /// again" (rule 82).
    #[error("wallet session ended — close and reopen the wallet, then sign again")]
    WalletSessionEnded,
    /// Any other key-actor refusal, carried as its rendered message
    /// (`KeyEngineError` is crate-private, the same disposition
    /// [`super::proofs::ProofsError`] uses).
    #[error("key engine: {0}")]
    Key(String),
    /// The crypto layer refused.
    #[error("signing failed: {0}")]
    Crypto(#[from] MessageSigError),
    /// Address-material assembly or wallet-state read failed —
    /// wallet-state corruption class, surfaced loudly rather than
    /// papered over.
    #[error("internal: {0}")]
    Internal(String),
}

impl From<KeyEngineError> for SignMessageError {
    fn from(e: KeyEngineError) -> Self {
        match e {
            KeyEngineError::KeyActorUnavailable => Self::WalletSessionEnded,
            other => Self::Key(other.to_string()),
        }
    }
}

/// Refusals of the session-less [`verify_message`].
///
/// Address-shape failures stay distinct from the crypto taxonomy so the
/// RPC projection can keep SM-R-6's shape-first `-32602` on a bad or
/// classical-only address without collapsing it into
/// [`MessageSigError::Malformed`] (which is about the *signature*
/// string).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyMessageError {
    /// The address string is not a valid Shekyl address for this network.
    #[error("address is not a valid Shekyl address for this network")]
    InvalidAddress,
    /// Classical-only display form: the bound segment (including
    /// `ek_bind_tag`) cannot be reconstructed, so there is nothing
    /// honest to verify against.
    #[error("verify_message requires the full address, not the classical-only form")]
    ClassicalOnly,
    /// Crypto-layer taxonomy (malformed / corrupted / unsupported
    /// scheme / unbound identity / verify-failed).
    #[error(transparent)]
    Crypto(#[from] MessageSigError),
}

/// Map the wallet-file seed-extractor refusal into the workflow's typed
/// errors. Pure so the capability gate is unit-testable without a full
/// view-only open path (that open path is still NotYetImplemented).
fn map_extract_error(e: ExtractRederivationInputsError) -> SignMessageError {
    match e {
        ExtractRederivationInputsError::ViewOnly => SignMessageError::ViewOnly,
        ExtractRederivationInputsError::HardwareOffload => SignMessageError::HardwareOffload,
    }
}

/// The `(network, seed_format)` pair the signing identity is scoped by —
/// read from the same places wallet open reads them, so a message
/// signature is derived under the identical scoping as every other key
/// this wallet holds.
fn derivation_scope(
    ctx: &MessageSignCtx<'_>,
) -> Result<(DerivationNetwork, SeedFormat), SignMessageError> {
    let declared = ctx.file.opened_keys().seed_format;
    let seed_format = SeedFormat::from_u8(declared).ok_or_else(|| {
        SignMessageError::Internal(format!(
            "wallet file declares unknown seed format {declared:#04x}"
        ))
    })?;
    Ok((network_to_derivation(ctx.network), seed_format))
}

/// Assemble the bound classical segment this wallet's signatures bind
/// (SM-R-3): the same bytes `ShekylAddress::encode` puts in the address,
/// by construction — `BoundClassicalSegment` owns that layout.
fn bound_segment(ctx: &MessageSignCtx<'_>) -> Result<BoundClassicalSegment, SignMessageError> {
    let addr = ctx.key.account_public_address();
    let ml_kem_ek = addr.ml_kem_encap_key().ok_or_else(|| {
        SignMessageError::Internal("pqc_public_key shorter than the x25519 prefix".into())
    })?;
    BoundClassicalSegment::from_address_parts(&addr.classical_address_bytes, ml_kem_ek)
        .map_err(|e| SignMessageError::Internal(format!("bound-segment assembly: {e}")))
}

/// Sign `message` under the ctx's wallet (spend-tier): the ratified
/// nested hybrid, returned as the armored `shekylmsgsig1.` string.
///
/// Multi-second by design — see the module docs for where that work
/// runs and why. Callers presenting UX should say so rather than hide
/// it.
///
/// # Errors
///
/// See [`SignMessageError`]: capability refusals, key-actor failures,
/// crypto refusals, and wallet-state corruption.
pub(crate) async fn sign_message(
    ctx: &MessageSignCtx<'_>,
    message: &[u8],
) -> Result<String, SignMessageError> {
    let (network, seed_format) = derivation_scope(ctx)?;
    let segment = bound_segment(ctx)?;

    // Single-flight: one multi-second PQ job per wallet at a time
    // (the handle's `sign_permit`). The permit is acquired here (queued
    // FIFO under load) and MOVES INTO the blocking closure below —
    // `spawn_blocking` work keeps running after its awaiting future is
    // dropped, so releasing on this future's drop would admit the next
    // job while the abandoned one still burns a blocking-pool thread.
    // Acquired BEFORE the seed borrow: a queued call must wait empty-
    // handed, not sit on a master-seed copy for seconds (rule 35).
    let permit = ctx
        .key
        .sign_permit()
        .clone()
        .acquire_owned()
        .await
        .expect("sign permit is never closed");

    // Transient seed borrow — the same envelope read the open path
    // performs; FULL capability enforced by the extractor itself.
    let inputs = ctx
        .file
        .extract_rederivation_inputs()
        .map_err(map_extract_error)?;

    // CPU-bound multi-second work leaves the executor (module docs).
    // The seed moves into the blocking task and its `Zeroizing` drop
    // wipes it there; only public bytes come back.
    let owned_message = message.to_vec();
    let (preimage, sig_pq) = tokio::task::spawn_blocking(move || {
        let _held_until_the_job_exits = permit;
        message_signing::sign_message_pq_half(
            &inputs.master_seed_64,
            network,
            seed_format,
            &segment,
            &owned_message,
        )
    })
    .await
    .map_err(|e| SignMessageError::Internal(format!("message-signing task failed: {e}")))??;

    let outer = message_signing::outer_bytes(&preimage, &sig_pq);
    let sig_cl = ctx.key.sign_message_outer(outer).await?;
    Ok(message_signing::assemble_armored(&sig_pq, &sig_cl))
}

/// Session-less verify (SM-R-6): public inputs only, no wallet, no daemon.
///
/// The signature string is judged **before** the address so the paste
/// taxonomy (corruption / unknown scheme) stays reachable as a
/// property of the paste alone. The transcript is scoped by the same network mapping
/// [`sign_message`] uses, so a produced signature is verified against
/// the same network byte the signer bound.
///
/// # Errors
///
/// See [`VerifyMessageError`].
pub fn verify_message(
    network: shekyl_address::Network,
    address: &str,
    message: &[u8],
    armored: &str,
) -> Result<(), VerifyMessageError> {
    // Taxonomy-first: a damaged paste is judged before the address.
    // This is the ONE decode — the crypto verify below consumes the
    // decoded value rather than re-running the base64 + checksum
    // pipeline on the same ~21.7 KB string.
    let sig = message_signing::ArmoredSignature::decode(armored)?;

    let address = decode_signer_address(address, network)?;
    let segment = address.bound_classical_segment();

    message_signing::verify_message(&segment, network_to_derivation(network), message, &sig)?;
    Ok(())
}

/// Full hybrid address only: the signature binds the bound classical
/// segment, which the classical-only display form cannot reconstruct.
fn decode_signer_address(
    s: &str,
    network: shekyl_address::Network,
) -> Result<ShekylAddress, VerifyMessageError> {
    let address = ShekylAddress::decode_for_network(s, network).map_err(|e| {
        tracing::warn!(detail = %e, "verify_message address decode failed");
        VerifyMessageError::InvalidAddress
    })?;
    if !address.has_pqc_segment() {
        return Err(VerifyMessageError::ClassicalOnly);
    }
    Ok(address)
}

// ── Engine delegator (thin shell; assemble the ctx and forward) ─────

// `L = LocalLedger` and `F = WalletFile`: the workflow reads the open
// file and the key handle (same specialization shape as `proofs` and
// `staking_read`).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P, WalletFile>
{
    /// Assemble the message-signing workflow context from engine caps.
    fn message_sign_ctx(&self) -> MessageSignCtx<'_> {
        MessageSignCtx {
            key: &self.key,
            file: self.file(),
            network: self.network(),
        }
    }

    /// Sign `message` as this wallet (spend-tier). See
    /// [`sign_message`] for the construction, the cost, and the errors.
    ///
    /// # Errors
    ///
    /// Propagates [`sign_message`].
    pub async fn sign_message(&self, message: &[u8]) -> Result<String, SignMessageError> {
        sign_message(&self.message_sign_ctx(), message).await
    }
}

#[cfg(test)]
#[path = "message_signing_tests.rs"]
mod tests;
