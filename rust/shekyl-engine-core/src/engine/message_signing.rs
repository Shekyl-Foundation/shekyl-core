// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Engine::sign_message` — the A2 engine surface (PR-SM-1,
//! `WALLET_MESSAGE_SIGNING.md` SM-R-4/R-6).
//!
//! Secret-locality split, both postures preserved: the **master seed** is
//! transiently borrowed from the open `WalletFile` envelope
//! (`extract_rederivation_inputs`, the same borrow the open path uses)
//! and never reaches the key actor; the **spend scalar** never leaves the
//! actor — it signs the public outer bytes (`preimage ‖ σ_pq`) via the
//! [`SignMessageOuter`](super::key_actor) message. The SLH identity is
//! derived on demand and its secret half drops-and-wipes when the PQ
//! half returns (SM-R-4: derived on demand, zeroized, never persisted,
//! no wallet-file schema change).
//!
//! Verification is deliberately **not** here: it is session-less
//! (SM-R-6), a pure function in
//! [`shekyl_crypto_pq::message_signing::verify_message`] — refusing a
//! public operation for lack of a wallet session is a rule-82 lie.

use shekyl_crypto_pq::message_signing::{self, MessageSigError};
use shekyl_engine_file::secrets_transitional::ExtractRederivationInputsError;

use super::error::KeyEngineError;
use super::local_ledger::LocalLedger;
use super::signer::EngineSignerKind;
use super::traits::key::KeyEngine;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// Refusals and failures of [`Engine::sign_message`].
#[derive(Debug, thiserror::Error)]
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

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P, shekyl_engine_file::WalletFile>
{
    /// Sign `message` as this wallet (spend-tier): the ratified nested
    /// hybrid, returned as the armored `shekylmsgsig1.` string.
    ///
    /// On the Pi-4 floor this is a multi-second operation by design
    /// (the round priced ~4.3 s per signing session, derive + keygen +
    /// sign); callers presenting UX should say so rather than hide it.
    pub async fn sign_message(&self, message: &[u8]) -> Result<String, SignMessageError> {
        // Transient seed borrow — the same envelope read the open path
        // performs; FULL capability enforced by the extractor itself.
        let inputs = self
            .file()
            .extract_rederivation_inputs()
            .map_err(|e| match e {
                ExtractRederivationInputsError::ViewOnly => SignMessageError::ViewOnly,
                ExtractRederivationInputsError::HardwareOffload => {
                    SignMessageError::HardwareOffload
                }
            })?;

        let addr = self.key.account_public_address();
        // `pqc_public_key` is `x25519_pk(32) || ml_kem_ek(1184)`.
        let ml_kem_ek = addr.pqc_public_key.get(32..).ok_or_else(|| {
            SignMessageError::Internal("pqc_public_key shorter than the x25519 prefix".into())
        })?;
        let segment = shekyl_address::classical_bound_segment_from_parts(
            &addr.classical_address_bytes,
            ml_kem_ek,
        )
        .map_err(|e| SignMessageError::Internal(format!("bound-segment assembly: {e}")))?;

        let network_id = self.network().as_u8();
        let (preimage, sig_pq) = message_signing::sign_message_pq_half(
            &inputs.master_seed_64[..],
            network_id,
            &segment,
            message,
        )?;
        // The seed borrow ends here (Zeroizing drop); only public bytes
        // travel to the actor.
        drop(inputs);

        let outer = message_signing::outer_bytes(&preimage, &sig_pq);
        let sig_cl = self.key.sign_message_outer(outer).await?;
        Ok(message_signing::assemble_armored(&sig_pq, &sig_cl))
    }
}
