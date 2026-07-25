// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Proof-generation bridge: the crypto bodies behind the [`KeyActor`]'s
//! inbound-tx-proof and reserve-proof messages (WI-RPC-3, Phase 2c).
//!
//! Both proof kinds sign with actor-owned key material (view secret for
//! INBOUND tx proofs, spend secret for reserve proofs), so generation runs
//! *inside* the key actor: the request carries only public on-chain data
//! (stored source ciphertexts, key images, output keys) and the reply is
//! the sealed proof blob — no scalar crosses the mailbox in either
//! direction (rule 36 secret-locality; `STAGE_2_KEY_ENGINE_ACTOR.md` §3.2).
//!
//! OUTBOUND tx proofs are deliberately **not** here: they sign with the
//! retained per-tx secret (`TxMetaBlock.tx_keys`), which is engine-state,
//! not actor key material — the proofs workflow calls
//! [`shekyl_proofs::tx_proof::generate_outbound_proof`] directly.
//!
//! Unlike the `ClaimOutput` handler (which duplicates the `LocalKeys`
//! crypto body so `LocalKeys` survives as an equivalence oracle), these
//! bodies are shared free functions over `&LocalKeys`: there is no
//! pre-existing `LocalKeys` proof path to hold as an oracle, so tests
//! exercise the same body directly against a `LocalKeys::from_test_seed`
//! fixture and through the actor mailbox.

use shekyl_crypto_pq::kem::HybridCiphertext;
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::output::{derive_proof_secrets, recover_combined_ss};
use shekyl_proofs::reserve_proof::{self, ReserveOutputEntry};
use shekyl_proofs::tx_proof;

use super::error::KeyEngineError;
use super::local_keys::LocalKeys;

/// One owned output an INBOUND tx proof discloses: its position in the
/// containing tx plus the stored hybrid KEM ciphertext the scan path
/// persisted for it (`TransferDetails::source_ciphertext` — present on
/// every incoming transfer by the scanner invariant the contract cites).
pub(crate) struct InboundProofOutput {
    /// The output's vout position in the containing transaction
    /// (`TransferDetails::internal_output_index`, narrowed).
    pub vout_index: u32,
    /// The on-chain hybrid KEM ciphertext for this output.
    pub ciphertext: HybridCiphertext,
}

/// Actor request for an INBOUND tx proof: "this wallet received the named
/// outputs of `txid`". Carries public data only; the actor re-derives the
/// per-output proof secrets from its view material and signs with the
/// view secret ([`tx_proof::generate_inbound_proof`]).
pub(crate) struct InboundProofRequest {
    /// Hash of the transaction being proven.
    pub txid: [u8; 32],
    /// Canonical address bytes the proof binds to (the wallet's own
    /// primary address; the workflow builds the canonical form).
    pub address_bytes: Vec<u8>,
    /// Caller-supplied challenge message sealed into the Schnorr challenge.
    pub message: Vec<u8>,
    /// The owned outputs to disclose, in strictly increasing `vout_index`
    /// order (the proofs wire format enforces the order; the workflow
    /// sorts before building the request).
    pub outputs: Vec<InboundProofOutput>,
}

/// One unspent output a reserve proof discloses.
pub(crate) struct ReserveProofOutput {
    /// The output's vout position in its containing transaction — the
    /// per-output secret-derivation index (`derive_proof_secrets`).
    pub vout_index: u64,
    /// The stored hybrid KEM ciphertext (`TransferDetails::source_ciphertext`).
    pub ciphertext: HybridCiphertext,
    /// The output's canonical key image (disclosed by the proof — the
    /// permanent spend-detection beacon the contract's DISCLOSURE
    /// SEMANTICS block wargames).
    pub key_image: KeyImage,
    /// The on-chain output key `O` (compressed), checked by the verifier.
    pub output_key: [u8; 32],
}

/// Actor request for a reserve proof: "this wallet controls the named
/// unspent outputs". The actor re-derives per-output proof secrets from
/// view material and signs with the **spend** secret
/// ([`reserve_proof::generate_reserve_proof`]) — the FULL-capability gate
/// is enforced by the engine delegator before the request is built.
pub(crate) struct ReserveProofRequest {
    /// Canonical address bytes the proof binds to.
    pub address_bytes: Vec<u8>,
    /// Caller-supplied challenge message.
    pub message: Vec<u8>,
    /// The outputs to disclose (selection — largest-first, amount-bounded
    /// or prove-all — is workflow policy, done before the request).
    pub outputs: Vec<ReserveProofOutput>,
}

/// Re-derive the per-output [`shekyl_crypto_pq::output::ProofSecrets`]
/// for one stored ciphertext via the recipient-side hybrid decap path.
///
/// A failure is loud, not silent: the ciphertext came from this wallet's
/// own persisted state, so a decap rejection means storage corruption or
/// tampering (the same contract as
/// [`KeyEngineError::SourceCiphertextDecapsulationFailed`]).
fn rederive_proof_secrets(
    local: &LocalKeys,
    ciphertext: &HybridCiphertext,
    vout_index: u64,
) -> Result<shekyl_crypto_pq::output::ProofSecrets, KeyEngineError> {
    let combined_ss = recover_combined_ss(
        local.keys.view_sk.as_canonical_bytes(),
        local.keys.ml_kem_dk.as_canonical_bytes(),
        &ciphertext.x25519,
        &ciphertext.ml_kem,
    )?;
    Ok(derive_proof_secrets(&combined_ss.0, vout_index))
}

/// Generate an INBOUND tx proof over the request's outputs. Returns the
/// raw `shekyl-proofs` wire blob (the workflow adds the direction byte
/// and Bech32m framing).
pub(crate) fn generate_inbound_proof(
    local: &LocalKeys,
    req: &InboundProofRequest,
) -> Result<Vec<u8>, KeyEngineError> {
    let mut per_output = Vec::with_capacity(req.outputs.len());
    for out in &req.outputs {
        let ps = rederive_proof_secrets(local, &out.ciphertext, u64::from(out.vout_index))?;
        per_output.push((out.vout_index, ps));
    }
    Ok(tx_proof::generate_inbound_proof(
        local.keys.view_sk.as_canonical_bytes(),
        &req.txid,
        &req.address_bytes,
        &req.message,
        &per_output,
    )?)
}

/// Generate a reserve proof over the request's outputs. Returns the raw
/// `shekyl-proofs` wire blob (the workflow prepends the locator section
/// and Bech32m framing).
pub(crate) fn generate_reserve_proof(
    local: &LocalKeys,
    req: &ReserveProofRequest,
) -> Result<Vec<u8>, KeyEngineError> {
    let mut entries = Vec::with_capacity(req.outputs.len());
    for out in &req.outputs {
        let proof_secrets = rederive_proof_secrets(local, &out.ciphertext, out.vout_index)?;
        entries.push(ReserveOutputEntry {
            proof_secrets,
            key_image: out.key_image,
            output_key: out.output_key,
        });
    }
    Ok(reserve_proof::generate_reserve_proof(
        local.keys.spend_sk.as_canonical_bytes(),
        &req.address_bytes,
        &req.message,
        &entries,
    )?)
}
