// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Tx-proof / reserve-proof workflows (WI-RPC-3, Phase 2c).
//!
//! Implements the four `docs/api/wallet_rpc.yaml` proof methods over the
//! `rust/shekyl-proofs` primitives:
//!
//! - **`get_tx_proof`** — direction by decoded-address ownership (own
//!   primary address ⇒ INBOUND, anything else ⇒ OUTBOUND). INBOUND signs
//!   inside the key actor over per-output secrets re-derived from stored
//!   source ciphertexts; OUTBOUND signs with the retained per-tx secret
//!   (`TxMetaBlock.tx_keys`) engine-side — see
//!   [`super::proof_bridge`]'s module docs for the split rationale.
//! - **`get_reserve_proof`** — FULL-capability-gated; selects unspent
//!   matured outputs (largest-first — the contract's fewest-beacons
//!   choice) and signs inside the key actor.
//! - **`check_tx_proof` / `check_reserve_proof`** — WALLET-LESS: free
//!   functions over any [`Rpc`] implementor, no `Engine` in sight. They
//!   fetch on-chain data from the verifier's daemon and verify the
//!   decoded proof against it.
//!
//! # Decomposition shape (`ENGINE_COMPOSITION_DECOMPOSITION.md` §4)
//!
//! Workflow functions take an explicit `ProofsCtx`, never `&Engine`:
//! the data dependencies (key handle, daemon, ledger, capability,
//! primary address) are visible in the ctx fields, and a new dependency
//! is a reviewable ctx-field addition rather than a silent `self.foo`.
//! The `Engine` methods in this file are thin delegators that assemble
//! the ctx and forward.
//!
//! # Wire framing (contract "Proofs" section)
//!
//! ```text
//! tx proof       Bech32m HRP "shekyltxproof"
//!                payload: direction[1] ‖ proof_bytes
//! reserve proof  Bech32m HRP "shekylreserveproof"
//!                payload: count[u32 LE]
//!                         ‖ (txid[32] ‖ vout_index[u32 LE]) × count
//!                         ‖ proof_bytes
//! ```
//!
//! Size caps ([`MAX_RESERVE_PROOF_LOCATORS`], [`MAX_DECODED_PROOF_BYTES`])
//! are enforced **before any daemon fetch** — the u32 locator count
//! otherwise admits four billion tx fetches against the verifier's
//! daemon off one hostile string.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use shekyl_address::ShekylAddress;
use shekyl_crypto_pq::kem::{HybridCiphertext, SharedSecret};
use shekyl_crypto_pq::key_image::KeyImage;
use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
use shekyl_crypto_pq::output::rederive_combined_ss;
use shekyl_encoding::{decode_blob, encode_blob, HRP_RESERVE_PROOF, HRP_TX_PROOF};
use shekyl_proofs::error::ProofError;
use shekyl_proofs::reserve_proof::{verify_reserve_proof, ReserveOnChainOutput};
use shekyl_proofs::tx_proof::{
    generate_outbound_proof_with_secrets, verify_inbound_proof, verify_outbound_proof,
    OnChainOutput,
};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_types::TxHash;
use shekyl_units::AtomicUnits;

use super::error::KeyEngineError;
use super::key_actor::KeyEngineHandle;
use super::local_ledger::LocalLedger;
use super::proof_bridge::{
    InboundProofOutput, InboundProofRequest, ReserveProofOutput, ReserveProofRequest,
};
use super::proofs_chain_facts::{
    confirmations_of, fetch_proof_tx, fetch_proof_txs, on_chain_outputs_of,
};
use super::signer::EngineSignerKind;
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::{Capability, Engine};
use shekyl_rpc_types::{IsKeyImageSpentRequest, IsKeyImageSpentResponse, KeyImageStatus};

// ── Wire-framing constants (contract "Proofs" section) ──────────────

/// Direction byte for an OUTBOUND tx proof (prover = sender).
const DIRECTION_OUTBOUND: u8 = 0x01;
/// Direction byte for an INBOUND tx proof (prover = recipient).
const DIRECTION_INBOUND: u8 = 0x02;

/// Maximum locator count a reserve proof may carry (contract size cap;
/// rhymes with `MAX_HOLDINGS_SHARDS`). Enforced by the generator (never
/// emits more) and by the verifier **before any daemon fetch**.
pub const MAX_RESERVE_PROOF_LOCATORS: usize = 4096;

/// Maximum decoded Bech32m payload either check method accepts, in bytes
/// (contract size cap: 1 MiB; a 4096-locator reserve proof decodes to
/// 933,961 bytes, so the caps are mutually consistent).
pub const MAX_DECODED_PROOF_BYTES: usize = 1_048_576;

/// One reserve-proof locator on the wire: `txid[32] ‖ vout_index[u32 LE]`.
const LOCATOR_BYTES: usize = 32 + 4;

// ── Errors ───────────────────────────────────────────────────────────

/// Failures across the four proof workflows. Variants map one-to-one
/// onto the contract's error codes (`docs/api/wallet_rpc.yaml` §error
/// registry); the RPC layer performs that mapping.
#[derive(Debug, thiserror::Error)]
pub enum ProofsError {
    /// The proof string failed Bech32m decode, carried the wrong HRP,
    /// its wire framing did not parse, or it exceeds the size caps.
    /// Contract `-29300 PROOF_MALFORMED`. Distinct from a valid framing
    /// that fails cryptographic verification — that is `valid: false`,
    /// not an error.
    #[error("malformed proof: {0}")]
    Malformed(String),

    /// `get_tx_proof` OUTBOUND: this wallet holds no retained per-tx
    /// secret for the txid (it did not send the tx, or another wallet
    /// copy sent it). Contract `-29301 PROOF_TX_SECRET_UNAVAILABLE`.
    #[error("no retained tx secret for this transaction (not sent by this wallet)")]
    TxSecretUnavailable,

    /// Nothing to prove: INBOUND with no owned outputs in the tx,
    /// OUTBOUND where no output derives to the given address under the
    /// retained tx key, or a reserve request with zero eligible outputs
    /// / unspent total below the requested amount. Contract
    /// `-29302 PROOF_NO_PROVABLE_OUTPUTS`.
    #[error("no provable outputs: {0}")]
    NoProvableOutputs(String),

    /// A txid named by the request (or embedded in a reserve proof's
    /// locators) is unknown to the daemon. Contract
    /// `-29303 PROOF_TX_NOT_FOUND`. Carries the hex txid.
    #[error("transaction {0} is unknown to the daemon")]
    TxNotFound(String),

    /// `get_reserve_proof` on a non-FULL wallet (the proof signs with
    /// the spend key). Contract `-29005`.
    #[error("reserve proofs require an open FULL wallet")]
    NotFullWallet,

    /// The counterparty address carries non-canonical key material (its
    /// Ed25519 view key does not map to an X25519 point). Contract
    /// `-29100 INVALID_RECIPIENT`.
    #[error("invalid recipient address key material")]
    InvalidRecipient,

    /// Money-sum overflow while totalling selected/verified outputs.
    #[error("amount sum overflow")]
    AmountOverflow,

    /// Daemon RPC failure (tx-body fetch, height query, spent-set
    /// query). Contract `-29201 DAEMON_UNREACHABLE`.
    #[error("daemon RPC failure: {0}")]
    Daemon(#[from] RpcError),

    /// Key-engine failure during actor-side proof generation. Carries
    /// the rendered [`KeyEngineError`] (that type is crate-private).
    #[error("key engine failure: {0}")]
    Key(String),

    /// `shekyl-proofs` refused generation (engine-side OUTBOUND path).
    #[error("proof generation failed: {0}")]
    Generate(#[from] ProofError),

    /// Bech32m encoding failed (generation side; HRPs are compile-time
    /// constants, so this is effectively unreachable).
    #[error("bech32m encoding failed: {0}")]
    Encoding(#[from] shekyl_encoding::EncodingError),
}

impl From<KeyEngineError> for ProofsError {
    /// Actor-side proof generation keeps its typed [`ProofError`]
    /// (mapped to [`ProofsError::Generate`], the proof-generation error
    /// class) so structural rejections stay discriminable from crypto
    /// failures — the promise documented on `KeyEngineError::Proof`.
    /// Every other key-engine failure is rendered into the opaque
    /// [`ProofsError::Key`] string (that type is crate-private).
    fn from(e: KeyEngineError) -> Self {
        match e {
            KeyEngineError::Proof(p) => ProofsError::Generate(p),
            other => ProofsError::Key(other.to_string()),
        }
    }
}

// ── Result types ─────────────────────────────────────────────────────

/// Which side of the payment the proof attests. On the wire this is the
/// payload's leading direction byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxProofDirection {
    /// Prover = sender (`0x01`). The proof carries the tx key in
    /// plaintext — see the contract's DISCLOSURE SEMANTICS block.
    Outbound,
    /// Prover = recipient (`0x02`). Scoped to the disclosed outputs.
    Inbound,
}

impl TxProofDirection {
    /// The contract's enum string (`OUTBOUND` / `INBOUND`).
    pub fn as_contract_str(self) -> &'static str {
        match self {
            Self::Outbound => "OUTBOUND",
            Self::Inbound => "INBOUND",
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::Outbound => DIRECTION_OUTBOUND,
            Self::Inbound => DIRECTION_INBOUND,
        }
    }

    fn from_byte(b: u8) -> Result<Self, ProofsError> {
        match b {
            DIRECTION_OUTBOUND => Ok(Self::Outbound),
            DIRECTION_INBOUND => Ok(Self::Inbound),
            other => Err(ProofsError::Malformed(format!(
                "unknown tx-proof direction byte 0x{other:02x}"
            ))),
        }
    }
}

/// `get_tx_proof` result (contract `GetTxProofResult`).
#[derive(Debug)]
pub struct GeneratedTxProof {
    /// Bech32m string, HRP `shekyltxproof`. A disclosure artifact —
    /// OUTBOUND strings carry the tx key in signed plaintext.
    pub proof: String,
    /// Which direction was selected by address ownership.
    pub direction: TxProofDirection,
}

/// `get_reserve_proof` result (contract `GetReserveProofResult`).
#[derive(Debug)]
pub struct GeneratedReserveProof {
    /// Bech32m string, HRP `shekylreserveproof`. A disclosure artifact —
    /// holders learn amounts and gain permanent spend-detection on the
    /// disclosed outputs.
    pub proof: String,
    /// Sum of the amounts the proof actually discloses (≥ the requested
    /// bound; amount-bounding is output selection).
    pub total: AtomicUnits,
    /// Number of outputs disclosed.
    pub output_count: usize,
}

/// One verified output in a valid tx-proof check.
#[derive(Debug, Clone, Copy)]
pub struct CheckedTxOutput {
    /// The output's vout position in the proven transaction.
    pub output_index: u64,
    /// The output's decrypted amount.
    pub amount: AtomicUnits,
}

/// `check_tx_proof` outcome (contract `CheckTxProofResult`). `Invalid`
/// means the proof parsed but its cryptographic content does not verify
/// against the (txid, address, message) triple — the method succeeded
/// at answering the question. Framing failures are [`ProofsError::Malformed`]
/// instead.
#[derive(Debug)]
pub enum CheckedTxProof {
    /// Parsed but cryptographically refused.
    Invalid,
    /// Verified.
    Valid {
        /// Direction read from the proof payload (never guessed).
        direction: TxProofDirection,
        /// Sum of the verified outputs' decrypted amounts.
        received: AtomicUnits,
        /// Per-output verification detail.
        outputs: Vec<CheckedTxOutput>,
        /// Whether the tx is still in the mempool.
        in_pool: bool,
        /// Daemon chain height (block COUNT) minus the tx's block height
        /// (0-based index): a tx in the tip block reports 1; 0 is
        /// reported only while the tx is pool-only.
        confirmations: u64,
    },
}

/// `check_reserve_proof` outcome (contract `CheckReserveProofResult`).
/// Same valid/invalid contract as [`CheckedTxProof`]; the provable live
/// reserve is `total - spent`.
#[derive(Debug)]
pub enum CheckedReserveProof {
    /// Parsed but cryptographically refused.
    Invalid,
    /// Verified.
    Valid {
        /// Sum of all verified outputs in the proof.
        total: AtomicUnits,
        /// Portion of `total` whose key images the daemon reports spent
        /// at verification time.
        spent: AtomicUnits,
        /// Number of outputs the proof discloses.
        output_count: usize,
    },
}

// ── Canonical address bytes ──────────────────────────────────────────

/// The canonical decoded-address byte form both proof sides bind to:
/// `network[1] ‖ spend_key[32] ‖ view_key[32] ‖ ml_kem_encap_key`.
///
/// This is **payment identity**, not the full address string.
/// `msg_sign_pk` is the message-signing anchor (SM-R-8); it is not a
/// payment key. Honest derivation ties it to the same seed as
/// spend/view, so two addresses that differ only there cannot arise
/// from one wallet. An adversarially constructed string with the same
/// spend/view/ek and a foreign `msg_sign_pk` is the same payment
/// destination — proofs correctly treat it as such. Binding the
/// signing key here would be a proof-wire change with no payment-
/// security content.
///
/// Deliberately the **decoded** form, never the Bech32m string — the
/// contract pins the ownership comparison and proof binding to decoded
/// addresses because Bech32m admits an all-uppercase encoding of the
/// same address (a string binding would let re-encodings break
/// verification of an honest proof).
pub fn canonical_address_bytes(address: &ShekylAddress) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 32 + address.ml_kem_encap_key.len());
    out.push(address.network.as_u8());
    out.extend_from_slice(&address.spend_key);
    out.extend_from_slice(&address.view_key);
    out.extend_from_slice(&address.ml_kem_encap_key);
    out
}

/// Derive the recipient's X25519 view public key from the decoded
/// address's Ed25519 view key (RFC 7748 birational map — the address
/// format carries the Ed25519 form only).
fn address_x25519_pk(address: &ShekylAddress) -> Result<[u8; 32], ProofsError> {
    ed25519_pk_to_x25519_pk(&address.view_key).map_err(|_| ProofsError::InvalidRecipient)
}

// ── Workflow context (ENGINE_COMPOSITION_DECOMPOSITION.md §4) ────────

/// Explicit context for the proof-generation workflows. Fields are the
/// complete dependency set; a new dependency is a new field, not a
/// reach into `Engine`.
pub(crate) struct ProofsCtx<'a, D> {
    /// Key-actor handle: INBOUND/reserve proofs sign inside the actor.
    pub key: &'a KeyEngineHandle,
    /// Daemon RPC: OUTBOUND generation fetches the tx body to enumerate
    /// outputs.
    pub daemon: &'a D,
    /// Wallet ledger: owned-output enumeration, retained tx secrets,
    /// reserve selection.
    pub ledger: &'a LocalLedger,
    /// Wallet capability mode (the reserve FULL gate).
    pub capability: Capability,
    /// The wallet's own primary address (INBOUND binding + direction
    /// selection).
    pub primary_address: ShekylAddress,
}

// ── get_tx_proof workflow ────────────────────────────────────────────

/// Generate a payment proof for `txid` bound to `counterparty`.
/// Direction is selected by decoded-address ownership: the wallet's own
/// primary address ⇒ INBOUND, anything else ⇒ OUTBOUND (contract
/// `GetTxProofParams`).
pub(crate) async fn get_tx_proof<D: Rpc>(
    ctx: &ProofsCtx<'_, D>,
    txid: TxHash,
    counterparty: &ShekylAddress,
    message: &str,
) -> Result<GeneratedTxProof, ProofsError> {
    if *counterparty == ctx.primary_address {
        generate_inbound(ctx, txid, message).await
    } else {
        generate_outbound(ctx, txid, counterparty, message).await
    }
}

/// INBOUND: enumerate this wallet's owned outputs in `txid` from the
/// ledger (stored source ciphertexts), then sign inside the key actor
/// with view material. Permitted on VIEW_ONLY wallets (the
/// auditor-wallet use case, deliberate per the contract).
async fn generate_inbound<D: Rpc>(
    ctx: &ProofsCtx<'_, D>,
    txid: TxHash,
    message: &str,
) -> Result<GeneratedTxProof, ProofsError> {
    // Collect under a short read guard, dropped before the actor await.
    let mut outputs: Vec<InboundProofOutput> = {
        let state = ctx.ledger.read();
        state
            .ledger
            .ledger
            .transfers
            .iter()
            .filter(|td| td.tx_hash == txid)
            .filter_map(|td| {
                // Scanner invariant: every recorded incoming transfer
                // carries a source ciphertext (merge.rs populates it on
                // every incoming path); a vout above u32::MAX cannot
                // occur in a canonical tx.
                let ciphertext = td.source_ciphertext.clone()?;
                let vout_index = u32::try_from(td.internal_output_index).ok()?;
                Some(InboundProofOutput {
                    vout_index,
                    ciphertext,
                })
            })
            .collect()
    };
    if outputs.is_empty() {
        return Err(ProofsError::NoProvableOutputs(
            "this wallet owns no outputs in the named transaction".into(),
        ));
    }
    // The proofs wire format requires strictly increasing vout order.
    outputs.sort_by_key(|o| o.vout_index);

    let proof_bytes = ctx
        .key
        .generate_inbound_proof(InboundProofRequest {
            txid: txid.to_bytes(),
            address_bytes: canonical_address_bytes(&ctx.primary_address),
            message: message.as_bytes().to_vec(),
            outputs,
        })
        .await?;

    Ok(GeneratedTxProof {
        proof: encode_tx_proof(TxProofDirection::Inbound, &proof_bytes)?,
        direction: TxProofDirection::Inbound,
    })
}

/// OUTBOUND: read the retained per-tx secret from `tx_meta.tx_keys`
/// (`-29301` when absent — this wallet did not send the tx, or it
/// predates retention), fetch the tx body from the daemon to enumerate
/// outputs, discover which outputs derive to `counterparty` under the
/// tx key, and sign engine-side (the secret is engine state, not actor
/// key material).
async fn generate_outbound<D: Rpc>(
    ctx: &ProofsCtx<'_, D>,
    txid: TxHash,
    counterparty: &ShekylAddress,
    message: &str,
) -> Result<GeneratedTxProof, ProofsError> {
    // Short read guard; the secret is copied into a Zeroizing buffer
    // so the guard is not held across the daemon fetch.
    let tx_key: Zeroizing<[u8; 32]> = {
        let state = ctx.ledger.read();
        match state.ledger.tx_meta.tx_keys.get(txid.as_bytes()) {
            Some(keys) => Zeroizing::new(*keys.primary.as_bytes()),
            None => return Err(ProofsError::TxSecretUnavailable),
        }
    };

    let fetched = fetch_proof_tx(ctx.daemon, txid.to_bytes()).await?;
    let on_chain = on_chain_outputs_of(&fetched.tx)?;

    let recipient_x25519 = address_x25519_pk(counterparty)?;
    let recipient_outputs = discover_recipient_outputs(
        &tx_key,
        &recipient_x25519,
        &counterparty.ml_kem_encap_key,
        &on_chain,
    );
    if recipient_outputs.is_empty() {
        return Err(ProofsError::NoProvableOutputs(
            "no output of the named transaction pays the given address under the retained tx key"
                .into(),
        ));
    }

    let proof_bytes = generate_outbound_proof_with_secrets(
        &tx_key,
        &txid.to_bytes(),
        &canonical_address_bytes(counterparty),
        message.as_bytes(),
        &recipient_outputs,
    )?;

    Ok(GeneratedTxProof {
        proof: encode_tx_proof(TxProofDirection::Outbound, &proof_bytes)?,
        direction: TxProofDirection::Outbound,
    })
}

/// Which outputs of `on_chain` derive to the recipient under `tx_key` —
/// exactly the verifier's KEM re-derivation check
/// (`verify_outbound_proof` compares the re-derived ephemeral key and
/// ML-KEM ciphertext against chain data), run generator-side so the
/// proof names precisely the outputs that will verify.
///
/// Returns `(vout_index, combined_ss)` pairs (strictly increasing by
/// index, by construction) so generation can reuse the derived shared
/// secrets via [`generate_outbound_proof_with_secrets`] instead of
/// running the hybrid KEM a second time per output. Each returned
/// `SharedSecret` is `ZeroizeOnDrop`; non-matching derivations drop —
/// and wipe — inside the loop.
fn discover_recipient_outputs(
    tx_key: &[u8; 32],
    recipient_x25519_pk: &[u8; 32],
    recipient_ml_kem_ek: &[u8],
    on_chain: &[OnChainOutput],
) -> Vec<(u64, SharedSecret)> {
    let mut recipient_outputs = Vec::new();
    for (i, out) in on_chain.iter().enumerate() {
        let idx = i as u64;
        let Ok((ss, eph_pk, ml_kem_ct)) =
            rederive_combined_ss(tx_key, recipient_x25519_pk, recipient_ml_kem_ek, idx)
        else {
            continue;
        };
        if eph_pk == out.x25519_eph_pk && ml_kem_ct == out.ml_kem_ct {
            recipient_outputs.push((idx, ss));
        }
    }
    recipient_outputs
}

fn encode_tx_proof(direction: TxProofDirection, proof_bytes: &[u8]) -> Result<String, ProofsError> {
    let mut payload = Vec::with_capacity(1 + proof_bytes.len());
    payload.push(direction.byte());
    payload.extend_from_slice(proof_bytes);
    Ok(encode_blob(HRP_TX_PROOF, &payload)?)
}

// ── get_reserve_proof workflow ───────────────────────────────────────

/// One eligible unspent output, projected out of the ledger for
/// selection. Pure data so the selection policy is unit-testable.
struct ReserveCandidate {
    txid: [u8; 32],
    vout: u32,
    amount: AtomicUnits,
    ciphertext: HybridCiphertext,
    key_image: KeyImage,
    output_key: [u8; 32],
}

/// Prove control of unspent balance (contract `GetReserveProofParams`).
/// `amount = None` proves every eligible output (prove-all, capped at
/// [`MAX_RESERVE_PROOF_LOCATORS`] largest); `Some` selects a minimal
/// largest-first subset covering at least that amount.
pub(crate) async fn get_reserve_proof<D: Rpc>(
    ctx: &ProofsCtx<'_, D>,
    amount: Option<AtomicUnits>,
    message: &str,
) -> Result<GeneratedReserveProof, ProofsError> {
    if ctx.capability != Capability::Full {
        return Err(ProofsError::NotFullWallet);
    }

    // Project candidates under a short read guard.
    let candidates: Vec<ReserveCandidate> = {
        let state = ctx.ledger.read();
        let height = state.ledger.ledger.tip.synced_height;
        state
            .ledger
            .spendable_outputs(height, None)
            .into_iter()
            .filter_map(|(_, td)| {
                // key_image and source_ciphertext are populated on every
                // claimed spendable output; rows missing either cannot be
                // disclosed and are skipped rather than failing the proof.
                Some(ReserveCandidate {
                    txid: td.tx_hash.to_bytes(),
                    vout: u32::try_from(td.internal_output_index).ok()?,
                    amount: td.amount(),
                    ciphertext: td.source_ciphertext.clone()?,
                    key_image: td.key_image?,
                    output_key: td.key.compress().to_bytes(),
                })
            })
            .collect()
    };

    let (selected, total) = select_reserve_outputs(candidates, amount)?;

    let proof_bytes = ctx
        .key
        .generate_reserve_proof(ReserveProofRequest {
            address_bytes: canonical_address_bytes(&ctx.primary_address),
            message: message.as_bytes().to_vec(),
            outputs: selected
                .iter()
                .map(|c| ReserveProofOutput {
                    vout_index: u64::from(c.vout),
                    ciphertext: c.ciphertext.clone(),
                    key_image: c.key_image,
                    output_key: c.output_key,
                })
                .collect(),
        })
        .await?;

    // Locator section, in the exact per-output order of the proof
    // entries (the verifier's fetch order is the positional map).
    let mut payload = Vec::with_capacity(4 + selected.len() * LOCATOR_BYTES + proof_bytes.len());
    let count = u32::try_from(selected.len())
        .expect("selection is capped at MAX_RESERVE_PROOF_LOCATORS (4096) which fits u32");
    payload.extend_from_slice(&count.to_le_bytes());
    for c in &selected {
        payload.extend_from_slice(&c.txid);
        payload.extend_from_slice(&c.vout.to_le_bytes());
    }
    payload.extend_from_slice(&proof_bytes);

    Ok(GeneratedReserveProof {
        proof: encode_blob(HRP_RESERVE_PROOF, &payload)?,
        total,
        output_count: selected.len(),
    })
}

/// Largest-first selection (the contract's deliberate fewest-beacons
/// policy: every disclosed output is a permanent spend-detection
/// beacon, so beacon COUNT is minimized). Deterministic tie-break on
/// `(txid, vout)`. Prove-all is capped at
/// [`MAX_RESERVE_PROOF_LOCATORS`] largest outputs; an amount that the
/// cap-largest outputs cannot cover is unprovable within the locator
/// cap and refuses `-29302`.
fn select_reserve_outputs(
    mut candidates: Vec<ReserveCandidate>,
    target: Option<AtomicUnits>,
) -> Result<(Vec<ReserveCandidate>, AtomicUnits), ProofsError> {
    if candidates.is_empty() {
        return Err(ProofsError::NoProvableOutputs(
            "the wallet has no eligible unspent outputs".into(),
        ));
    }
    candidates.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| (a.txid, a.vout).cmp(&(b.txid, b.vout)))
    });
    candidates.truncate(MAX_RESERVE_PROOF_LOCATORS);

    let mut selected = Vec::new();
    let mut total = AtomicUnits::ZERO;
    for c in candidates {
        let covered = target.is_some_and(|t| total >= t);
        if covered {
            break;
        }
        total = total
            .checked_add(c.amount)
            .ok_or(ProofsError::AmountOverflow)?;
        selected.push(c);
    }
    if let Some(t) = target {
        if total < t {
            return Err(ProofsError::NoProvableOutputs(
                "unspent total below the requested amount".into(),
            ));
        }
    }
    // A zero target is "covered" before anything is selected. An empty
    // selection proves nothing and the key actor would reject the empty
    // entry set as an internal error, so refuse with the contract's
    // no-provable-outputs shape here regardless of caller-side
    // validation (the RPC params surface refuses `amount = "0"` too).
    if selected.is_empty() {
        return Err(ProofsError::NoProvableOutputs(
            "a zero requested amount selects no outputs".into(),
        ));
    }
    Ok((selected, total))
}

// ── Wallet-less check workflows ──────────────────────────────────────

/// WALLET-LESS verification of a `shekyltxproof` string against the
/// chain (contract `CheckTxProofParams`). `rpc` is the verifier's
/// daemon; no wallet state is touched.
pub async fn check_tx_proof<R: Rpc>(
    rpc: &R,
    txid: [u8; 32],
    address: &ShekylAddress,
    message: &str,
    proof: &str,
) -> Result<CheckedTxProof, ProofsError> {
    let payload = decode_proof_payload(proof, HRP_TX_PROOF)?;
    let (&direction_byte, proof_bytes) = payload
        .split_first()
        .ok_or_else(|| ProofsError::Malformed("empty tx-proof payload".into()))?;
    let direction = TxProofDirection::from_byte(direction_byte)?;

    let fetched = fetch_proof_tx(rpc, txid).await?;
    let on_chain = on_chain_outputs_of(&fetched.tx)?;
    let address_bytes = canonical_address_bytes(address);

    let verify_result = match direction {
        TxProofDirection::Outbound => {
            let recipient_x25519 = address_x25519_pk(address)?;
            verify_outbound_proof(
                proof_bytes,
                &txid,
                &address_bytes,
                message.as_bytes(),
                &address.spend_key,
                &recipient_x25519,
                &address.ml_kem_encap_key,
                &on_chain,
            )
        }
        TxProofDirection::Inbound => verify_inbound_proof(
            proof_bytes,
            &txid,
            &address_bytes,
            message.as_bytes(),
            &address.view_key,
            &address.spend_key,
            &on_chain,
        ),
    };
    let verified = match verify_result {
        Ok(v) => v,
        // Framing failures inside proof_bytes are -29300; every other
        // refusal is the cryptographic verdict the method exists to give.
        Err(ProofError::InvalidFormat(m)) => return Err(ProofsError::Malformed(m)),
        Err(_) => return Ok(CheckedTxProof::Invalid),
    };

    let mut received = AtomicUnits::ZERO;
    let mut outputs = Vec::with_capacity(verified.len());
    for v in &verified {
        let amount = AtomicUnits::from_raw(v.amount);
        received = received
            .checked_add(amount)
            .ok_or(ProofsError::AmountOverflow)?;
        outputs.push(CheckedTxOutput {
            output_index: v.output_index as u64,
            amount,
        });
    }

    let (in_pool, confirmations) = confirmations_of(rpc, &fetched).await?;

    Ok(CheckedTxProof::Valid {
        direction,
        received,
        outputs,
        in_pool,
        confirmations,
    })
}

/// WALLET-LESS verification of a `shekylreserveproof` string (contract
/// `CheckReserveProofParams`). Size caps are enforced before any daemon
/// traffic; the spent-set query forwards the proof's key images to the
/// verifier's daemon (the standard remote-daemon caveat).
pub async fn check_reserve_proof<R: Rpc>(
    rpc: &R,
    address: &ShekylAddress,
    message: &str,
    proof: &str,
) -> Result<CheckedReserveProof, ProofsError> {
    let payload = decode_proof_payload(proof, HRP_RESERVE_PROOF)?;
    let (locators, proof_bytes) = parse_reserve_locators(&payload)?;

    // Fetch each locator-named tx once, in chunked batched calls
    // (pruned bodies carry everything a reserve verification needs),
    // then resolve the named outputs per locator from the map. Unique
    // txids are collected in first-seen locator order so error
    // surfacing tracks the proof's own ordering.
    let unique_txids: Vec<[u8; 32]> = {
        let mut seen = BTreeSet::new();
        locators
            .iter()
            .filter_map(|&(txid, _)| seen.insert(txid).then_some(txid))
            .collect()
    };
    let bodies = fetch_proof_txs(rpc, &unique_txids).await?;
    let mut tx_outputs: BTreeMap<[u8; 32], Vec<OnChainOutput>> = BTreeMap::new();
    for (txid, tx) in unique_txids.iter().zip(&bodies) {
        tx_outputs.insert(*txid, on_chain_outputs_of(tx)?);
    }

    let mut on_chain = Vec::with_capacity(locators.len());
    for &(txid, vout) in &locators {
        let outputs = &tx_outputs[&txid];
        let out = outputs.get(vout as usize).ok_or_else(|| {
            ProofsError::Malformed(format!(
                "locator names output {vout} of a transaction with {} outputs",
                outputs.len()
            ))
        })?;
        on_chain.push(ReserveOnChainOutput {
            output_key: out.output_key,
            commitment: out.commitment,
            enc_amount: out.enc_amount,
        });
    }

    let address_bytes = canonical_address_bytes(address);
    let verified = match verify_reserve_proof(
        proof_bytes,
        &address_bytes,
        message.as_bytes(),
        &address.spend_key,
        &on_chain,
    ) {
        Ok(v) => v,
        Err(ProofError::InvalidFormat(m)) => return Err(ProofsError::Malformed(m)),
        Err(_) => return Ok(CheckedReserveProof::Invalid),
    };

    // Cross-entry key-image uniqueness: each entry verifies
    // independently, so a proof listing the same output N times would
    // sum its amount N times — for an UNSPENT output the spent-set
    // subtraction never corrects it, and the proven reserve inflates
    // N-fold, which is exactly the claim a reserve proof exists to
    // refute. The key image is the dedup key (it is what makes an
    // entry economically distinct and what the spent set is keyed
    // on); a duplicate-bearing proof is malformed by construction —
    // the honest generator selects each output at most once.
    let mut seen_key_images = BTreeSet::new();
    for v in &verified {
        if !seen_key_images.insert(*v.key_image.as_bytes()) {
            return Err(ProofsError::Malformed(
                "reserve proof lists the same output (key image) more than once".into(),
            ));
        }
    }

    // Spent-set query: a proof over spent outputs verifies
    // cryptographically, but the spent portion is reported so the
    // verifier can subtract it.
    let key_images_hex: Vec<String> = verified
        .iter()
        .map(|v| hex::encode(v.key_image.as_bytes()))
        .collect();
    let resp: IsKeyImageSpentResponse = rpc
        .rpc_call(
            "is_key_image_spent",
            Some(
                serde_json::to_value(IsKeyImageSpentRequest {
                    key_images: key_images_hex,
                })
                .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
            ),
        )
        .await?;
    // A refusal carrying one plausible-length `spent_status` array would
    // change this proof's reported total, so the status is read first.
    super::block_fetch::refuse_unless_ok(&resp.status, "is_key_image_spent")
        .map_err(ProofsError::Daemon)?;
    let statuses = &resp.spent_status;
    if statuses.len() != verified.len() {
        return Err(ProofsError::Daemon(RpcError::InvalidNode(
            "is_key_image_spent returned a different count than requested".to_string(),
        )));
    }

    let mut total = AtomicUnits::ZERO;
    let mut spent = AtomicUnits::ZERO;
    for (v, status) in verified.iter().zip(statuses) {
        let amount = AtomicUnits::from_raw(v.amount);
        total = total
            .checked_add(amount)
            .ok_or(ProofsError::AmountOverflow)?;
        // Typed: a fourth value is a malformed reply refused at the boundary,
        // not an integer this comparison has to guess about.
        if *status != KeyImageStatus::Unspent {
            spent = spent
                .checked_add(amount)
                .ok_or(ProofsError::AmountOverflow)?;
        }
    }

    Ok(CheckedReserveProof::Valid {
        total,
        spent,
        output_count: verified.len(),
    })
}

// ── Framing helpers ──────────────────────────────────────────────────

/// Bech32m-decode a proof string, pin the HRP (case-insensitively —
/// Bech32m admits an all-uppercase encoding), and enforce the decoded
/// payload size cap before anything downstream runs.
fn decode_proof_payload(proof: &str, expected_hrp: &str) -> Result<Vec<u8>, ProofsError> {
    let (hrp, data) = decode_blob(proof)
        .map_err(|e| ProofsError::Malformed(format!("bech32m decode failed: {e}")))?;
    if !hrp.eq_ignore_ascii_case(expected_hrp) {
        return Err(ProofsError::Malformed(format!(
            "wrong HRP '{hrp}', expected '{expected_hrp}'"
        )));
    }
    if data.len() > MAX_DECODED_PROOF_BYTES {
        return Err(ProofsError::Malformed(format!(
            "decoded payload {} bytes exceeds the {MAX_DECODED_PROOF_BYTES}-byte cap",
            data.len()
        )));
    }
    Ok(data)
}

/// One reserve-proof locator: `(txid, vout_index)`.
type ReserveLocator = ([u8; 32], u32);

/// Parse the reserve-proof locator section
/// (`count[u32 LE] ‖ (txid[32] ‖ vout[u32 LE]) × count`), enforcing the
/// locator-count cap **before any daemon fetch**, and return the
/// locators plus the trailing `shekyl-proofs` wire blob.
fn parse_reserve_locators(payload: &[u8]) -> Result<(Vec<ReserveLocator>, &[u8]), ProofsError> {
    if payload.len() < 4 {
        return Err(ProofsError::Malformed(
            "reserve payload too short for the locator count".into(),
        ));
    }
    let count = u32::from_le_bytes(payload[..4].try_into().expect("4-byte slice")) as usize;
    if count == 0 {
        return Err(ProofsError::Malformed(
            "reserve proof discloses zero outputs".into(),
        ));
    }
    if count > MAX_RESERVE_PROOF_LOCATORS {
        return Err(ProofsError::Malformed(format!(
            "locator count {count} exceeds the {MAX_RESERVE_PROOF_LOCATORS} cap"
        )));
    }
    let locator_section = count * LOCATOR_BYTES;
    let Some(proof_bytes) = payload.get(4 + locator_section..) else {
        return Err(ProofsError::Malformed(
            "reserve payload too short for its locator section".into(),
        ));
    };
    let mut locators = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * LOCATOR_BYTES;
        let txid: [u8; 32] = payload[off..off + 32].try_into().expect("32-byte slice");
        let vout = u32::from_le_bytes(
            payload[off + 32..off + 36]
                .try_into()
                .expect("4-byte slice"),
        );
        locators.push((txid, vout));
    }
    Ok((locators, proof_bytes))
}

// ── Engine delegators (thin shell; assemble the ctx and forward) ─────

// `L = LocalLedger` and `F = WalletFile`: the workflows read through
// `LocalLedger`'s lock (the same specialization as `Engine::ledger` and
// the `staking_read` impl block, which also pins this `allow` shape —
// the engine-composition traits are deliberately crate-private).
#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
    > Engine<S, D, LocalLedger, E, R, P, shekyl_engine_file::WalletFile>
{
    /// Assemble the proofs workflow context from engine capabilities.
    fn proofs_ctx(&self) -> ProofsCtx<'_, D> {
        ProofsCtx {
            key: &self.key,
            daemon: &self.daemon,
            ledger: self.ledger.as_ref(),
            capability: self.capability,
            primary_address: self.primary_address(),
        }
    }

    /// Generate a payment proof for `txid` bound to `counterparty`
    /// (contract `get_tx_proof`). Direction is selected by
    /// decoded-address ownership — the wallet's own primary address
    /// selects INBOUND, anything else OUTBOUND. See [`ProofsError`] for
    /// the refusal cases and their contract codes.
    pub async fn get_tx_proof(
        &self,
        txid: TxHash,
        counterparty: &ShekylAddress,
        message: &str,
    ) -> Result<GeneratedTxProof, ProofsError> {
        get_tx_proof(&self.proofs_ctx(), txid, counterparty, message).await
    }

    /// Prove control of unspent balance (contract `get_reserve_proof`).
    /// FULL wallets only; `amount = None` proves the full eligible
    /// balance. The proof string is a permanent disclosure artifact —
    /// see the contract's DISCLOSURE SEMANTICS block.
    pub async fn get_reserve_proof(
        &self,
        amount: Option<AtomicUnits>,
        message: &str,
    ) -> Result<GeneratedReserveProof, ProofsError> {
        get_reserve_proof(&self.proofs_ctx(), amount, message).await
    }
}

#[cfg(test)]
#[path = "proofs_tests.rs"]
mod tests;
