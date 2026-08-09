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
//! `&Engine`: the data dependencies (key handle, wallet file, network
//! id) are visible in the ctx fields, and a new dependency is a
//! reviewable ctx-field addition rather than a silent `self.foo`. The
//! `Engine` method in this module is a thin delegator that assembles
//! the ctx and forwards.
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
//! Verification is deliberately **not** here: it is session-less
//! (SM-R-6), a pure function in
//! [`shekyl_crypto_pq::message_signing::verify_message`] — refusing a
//! public operation for lack of a wallet session is a rule-82 lie.

use shekyl_crypto_pq::message_signing::{self, MessageSigError};
use shekyl_engine_file::secrets_transitional::ExtractRederivationInputsError;
use shekyl_engine_file::WalletFile;

use super::error::KeyEngineError;
use super::key_actor::KeyEngineHandle;
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
    /// Open wallet file — transient master-seed borrow for the PQ half.
    pub file: &'a WalletFile,
    /// Network discriminant bound into the preimage.
    pub network_id: u8,
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
    /// The key actor refused or is unavailable
    /// (`KeyEngineError` is crate-private; carried here as its
    /// rendered message).
    #[error("key engine: {0}")]
    Key(String),
    /// The crypto layer refused (key material shape).
    #[error("signing failed: {0}")]
    Crypto(#[from] MessageSigError),
    /// Address-material assembly failed — wallet-state corruption
    /// class, surfaced loudly rather than papered over.
    #[error("internal: {0}")]
    Internal(String),
}

impl From<KeyEngineError> for SignMessageError {
    fn from(e: KeyEngineError) -> Self {
        Self::Key(e.to_string())
    }
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

/// Sign `message` under the ctx's wallet (spend-tier): the ratified
/// nested hybrid, returned as the armored `shekylmsgsig1.` string.
///
/// On the Pi-4 floor this is a multi-second operation by design (the
/// round priced ~4.3 s per signing session, derive + keygen + sign);
/// callers presenting UX should say so rather than hide it.
pub(crate) async fn sign_message(
    ctx: &MessageSignCtx<'_>,
    message: &[u8],
) -> Result<String, SignMessageError> {
    // Transient seed borrow — the same envelope read the open path
    // performs; FULL capability enforced by the extractor itself.
    let inputs = ctx
        .file
        .extract_rederivation_inputs()
        .map_err(map_extract_error)?;

    let addr = ctx.key.account_public_address();
    // `pqc_public_key` is `x25519_pk(32) || ml_kem_ek(1184)` — same
    // layout `primary_address` already documents and slices.
    let ml_kem_ek = addr.pqc_public_key.get(32..).ok_or_else(|| {
        SignMessageError::Internal("pqc_public_key shorter than the x25519 prefix".into())
    })?;
    let segment = shekyl_address::classical_bound_segment_from_parts(
        &addr.classical_address_bytes,
        ml_kem_ek,
    )
    .map_err(|e| SignMessageError::Internal(format!("bound-segment assembly: {e}")))?;

    let (preimage, sig_pq) = message_signing::sign_message_pq_half(
        &inputs.master_seed_64,
        ctx.network_id,
        &segment,
        message,
    )?;
    // The seed borrow ends here (Zeroizing drop); only public bytes
    // travel to the actor.
    drop(inputs);

    let outer = message_signing::outer_bytes(&preimage, &sig_pq);
    let sig_cl = ctx.key.sign_message_outer(outer).await?;
    Ok(message_signing::assemble_armored(&sig_pq, &sig_cl))
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
            network_id: self.network().as_u8(),
        }
    }

    /// Sign `message` as this wallet (spend-tier): the ratified nested
    /// hybrid, returned as the armored `shekylmsgsig1.` string.
    ///
    /// On the Pi-4 floor this is a multi-second operation by design
    /// (the round priced ~4.3 s per signing session, derive + keygen +
    /// sign); callers presenting UX should say so rather than hide it.
    pub async fn sign_message(&self, message: &[u8]) -> Result<String, SignMessageError> {
        sign_message(&self.message_sign_ctx(), message).await
    }
}

#[cfg(test)]
#[path = "message_signing_tests.rs"]
mod tests;
