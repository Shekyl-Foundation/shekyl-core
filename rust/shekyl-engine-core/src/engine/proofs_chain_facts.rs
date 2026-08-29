// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The on-chain facts a proof is checked against — the daemon-facing half of
//! [`proofs`](super::proofs).
//!
//! Split from `proofs` by responsibility rather than by size: everything here
//! answers "what does the chain say about this transaction?", and answers it
//! across an **untrusted boundary**. A daemon may lie, omit, reorder, or return
//! a body for a hash nobody asked about, so these functions parse defensively
//! and re-associate replies to requests (reusing
//! [`block_fetch`](super::block_fetch)'s adversarial-daemon checks). The proof
//! generation and verification in `proofs` is cryptographic work over facts
//! already established — a different job, with a different failure mode.
//!
//! The seam is deliberately narrow: four functions — [`fetch_proof_tx`],
//! [`fetch_proof_txs`], [`confirmations_of`], [`on_chain_outputs_of`] — plus
//! [`FetchedTx`], the record two of them return. The not-found reporter stays
//! private, because a caller that needed it would be doing this module's job
//! somewhere else.

use shekyl_crypto_pq::kem::{HYBRID_KEM_CT_LEN, X25519_KEM_CT_LEN};
use shekyl_proofs::tx_proof::OnChainOutput;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{GetTransactionsRequest, GetTransactionsResponse, TxLocation};
use shekyl_scanner::extra::Extra;
use shekyl_wire::{Ct, Transaction};

use super::block_fetch::{parse_tx_batch, refuse_unless_ok, TxBodyForm, TXS_PER_REQUEST};
use super::proofs::ProofsError;

/// A proof-relevant tx fetched from the daemon: the parsed pruned body
/// plus the daemon-reported inclusion metadata.
pub(crate) struct FetchedTx {
    pub(crate) tx: Transaction,
    pub(crate) in_pool: bool,
    /// The daemon's 0-based block height for the tx; meaningless while
    /// `in_pool`.
    pub(crate) block_height: Option<u64>,
}

/// Fetch one tx by hash in the **pruned** body form (everything the
/// proof verifications need — output keys, commitments, encrypted
/// amounts, `tx_extra` KEM ciphertexts — lives in the pruned section,
/// and pruned fetches work against storage-pruned daemons). Reuses
/// `block_fetch`'s adversarial-daemon parse/association checks.
pub(crate) async fn fetch_proof_tx<R: Rpc>(
    rpc: &R,
    txid: [u8; 32],
) -> Result<FetchedTx, ProofsError> {
    let txid_hex = hex::encode(txid);
    let resp: GetTransactionsResponse = rpc
        .rpc_call(
            "get_transactions",
            Some(
                serde_json::to_value(GetTransactionsRequest {
                    txs_hashes: vec![txid_hex],
                    decode_as_json: false,
                    prune: true,
                    split: false,
                })
                .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
            ),
        )
        .await
        .map_err(|e| match e {
            RpcError::TransactionsNotFound(_) => ProofsError::TxNotFound(hex::encode(txid)),
            other => ProofsError::Daemon(other),
        })?;
    refuse_unless_ok(&resp.status, "get_transactions").map_err(ProofsError::Daemon)?;

    if !resp.missed_tx.is_empty() {
        return Err(ProofsError::TxNotFound(hex::encode(txid)));
    }

    let txs = &resp.txs;
    // Where it was found comes from the arm, not from two independently
    // optional fields: `block_height` cannot be read off a pooled entry
    // because a pooled entry does not carry one.
    let (in_pool, block_height) = match txs.first().map(|t| &t.location) {
        Some(TxLocation::Mined { block_height, .. }) => (false, Some(*block_height)),
        Some(TxLocation::Pooled { .. }) => (true, None),
        None => (false, None),
    };

    let mut parsed =
        parse_tx_batch(&[txid], txs, TxBodyForm::Pruned).map_err(ProofsError::Daemon)?;
    let tx = parsed
        .pop()
        .expect("parse_tx_batch returns exactly one tx per requested hash");

    Ok(FetchedTx {
        tx,
        in_pool,
        block_height,
    })
}

/// Fetch the pruned bodies of `txids` (unique, in first-seen order) in
/// batched `get_transactions` calls of [`TXS_PER_REQUEST`] hashes — the
/// daemon's restricted-RPC cap, the same chunking `block_fetch` uses —
/// rather than one round trip per txid (a 4096-locator reserve proof
/// would otherwise cost up to 4096 sequential daemon calls). Returns
/// the parsed bodies positionally aligned with `txids`.
///
/// Error semantics match [`fetch_proof_tx`]: a txid the daemon does not
/// know is [`ProofsError::TxNotFound`] carrying the first missing txid
/// in request order; a malformed body or batch is
/// [`ProofsError::Daemon`].
pub(crate) async fn fetch_proof_txs<R: Rpc>(
    rpc: &R,
    txids: &[[u8; 32]],
) -> Result<Vec<Transaction>, ProofsError> {
    let mut bodies = Vec::with_capacity(txids.len());
    for batch in txids.chunks(TXS_PER_REQUEST) {
        let hashes_hex: Vec<String> = batch.iter().map(hex::encode).collect();
        let resp: GetTransactionsResponse = rpc
            .rpc_call(
                "get_transactions",
                Some(
                    serde_json::to_value(GetTransactionsRequest {
                        txs_hashes: hashes_hex,
                        decode_as_json: false,
                        prune: true,
                        split: false,
                    })
                    .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
                ),
            )
            .await
            .map_err(|e| match e {
                RpcError::TransactionsNotFound(missed) => {
                    tx_not_found_in_request_order(batch, &missed)
                }
                other => ProofsError::Daemon(other),
            })?;
        refuse_unless_ok(&resp.status, "get_transactions").map_err(ProofsError::Daemon)?;

        if !resp.missed_tx.is_empty() {
            let missed_hashes: Vec<[u8; 32]> = resp
                .missed_tx
                .iter()
                .copied()
                .map(shekyl_rpc_types::HashHex::to_bytes)
                .collect();
            return Err(tx_not_found_in_request_order(batch, &missed_hashes));
        }
        bodies.extend(
            parse_tx_batch(batch, &resp.txs, TxBodyForm::Pruned).map_err(ProofsError::Daemon)?,
        );
    }
    Ok(bodies)
}

/// [`ProofsError::TxNotFound`] for the first txid of `batch` (request
/// order) that the daemon reported missing — the same txid the
/// sequential per-tx fetch this batching replaced would have named.
fn tx_not_found_in_request_order(batch: &[[u8; 32]], missed: &[[u8; 32]]) -> ProofsError {
    let first = batch
        .iter()
        .find(|txid| missed.contains(txid))
        .or_else(|| missed.first())
        .expect("callers pass a non-empty missed set");
    ProofsError::TxNotFound(hex::encode(first))
}

/// The contract's confirmations pin: daemon chain height (block COUNT)
/// minus the tx's block height (0-based index) — tip block reports 1;
/// 0 only while pool-only.
pub(crate) async fn confirmations_of<R: Rpc>(
    rpc: &R,
    fetched: &FetchedTx,
) -> Result<(bool, u64), ProofsError> {
    if fetched.in_pool {
        return Ok((true, 0));
    }
    let block_height = fetched.block_height.ok_or_else(|| {
        RpcError::InvalidNode("confirmed tx response missing block_height".to_string())
    })?;
    let chain_height = rpc.get_height().await? as u64;
    Ok((false, chain_height.saturating_sub(block_height)))
}

/// Project a parsed transaction into the per-output on-chain data the
/// proof verifications consume, in vout order: output key, commitment,
/// the 8-byte encrypted-amount value (the 9th byte is the scanner's
/// amount tag, not part of the proof contract), and the per-output
/// hybrid KEM ciphertext sliced from `tx_extra` at the scanner's
/// offsets.
pub(crate) fn on_chain_outputs_of(tx: &Transaction) -> Result<Vec<OnChainOutput>, ProofsError> {
    // `Null` (coinbase) never reaches here in practice, but the base
    // section reads identically, so take it rather than panic.
    let base = match &tx.ct {
        Ct::Fcmp { base, .. } | Ct::Null(base) => base,
    };
    let n = tx.prefix.outputs.len();
    if base.enc_amounts.len() != n || base.commitments.len() != n {
        return Err(ProofsError::Daemon(RpcError::InvalidNode(
            "transaction ct arrays disagree with its output count".to_string(),
        )));
    }

    let extra = Extra::read(&mut tx.prefix.extra.as_slice())
        .expect("Extra::read on an in-memory slice is infallible by construction");
    let kem_ct_blob = extra.pqc_kem_ciphertext();

    let mut out = Vec::with_capacity(n);
    for (o, output) in tx.prefix.outputs.iter().enumerate() {
        let mut enc_amount = [0u8; 8];
        enc_amount.copy_from_slice(&base.enc_amounts[o][..8]);

        // A canonical Shekyl tx carries one hybrid KEM ciphertext per
        // output; tolerate absence with zeroed fields — only OUTBOUND
        // verification consumes them, and it will (correctly) refuse.
        let (x25519_eph_pk, ml_kem_ct) = match kem_ct_blob {
            Some(blob) if blob.len() >= (o + 1) * HYBRID_KEM_CT_LEN => {
                let ct = &blob[o * HYBRID_KEM_CT_LEN..(o + 1) * HYBRID_KEM_CT_LEN];
                let mut eph = [0u8; 32];
                eph.copy_from_slice(&ct[..X25519_KEM_CT_LEN]);
                (eph, ct[X25519_KEM_CT_LEN..].to_vec())
            }
            _ => ([0u8; 32], Vec::new()),
        };

        out.push(OnChainOutput {
            output_key: output.key,
            commitment: base.commitments[o],
            enc_amount,
            x25519_eph_pk,
            ml_kem_ct,
        });
    }
    Ok(out)
}
