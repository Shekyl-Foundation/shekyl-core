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
//! The seam is deliberately narrow. [`ProofChainView`] is the only door a
//! verification may use: it is minted from a synchronized daemon, and every
//! tx read and spent-set read takes one. [`fetch_proof_tx`] stays available
//! to outbound generation, which reads a body the wallet authored and does
//! not return a chain verdict. [`confirmations_of`] and
//! [`on_chain_outputs_of`] project a reply the view has already admitted.
//! The not-found reporter stays private, because a caller that needed it
//! would be doing this module's job somewhere else.

use shekyl_crypto_pq::kem::{HYBRID_KEM_CT_LEN, X25519_KEM_CT_LEN};
use shekyl_proofs::tx_proof::OnChainOutput;
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{
    GetTransactionsRequest, GetTransactionsResponse, IsKeyImageSpentRequest,
    IsKeyImageSpentResponse, KeyImageStatus, TxLocation,
};
use shekyl_scanner::extra::Extra;
use shekyl_wire::{Ct, Transaction};

use super::block_fetch::{parse_tx_batch, refuse_unless_ok, TxBodyForm, TXS_PER_REQUEST};
use super::daemon::synced_chain_facts::{fetch_synced_chain_facts, SyncedChainFacts};
use super::proofs::ProofsError;
use shekyl_types::TxHash;

/// Where the daemon found a transaction, and the depth that goes with
/// it. An arm rather than a `bool` beside an `Option`, for the reason
/// stated at the read below: a pooled entry has no depth, so a shape
/// that can express "pooled at 12 confirmations" is a shape a caller
/// has to remember not to build.
pub(crate) enum TxChainState {
    Pooled,
    /// `confirmations` as the daemon computed it, against the same
    /// locked chain snapshot as the rest of the entry -- not
    /// recomputed here from a later tip, which would pair a height
    /// from one request with a block from another.
    ///
    /// `block_height` is the 0-based index reported beside that count.
    /// Verification keeps both so it can relate the reply to the
    /// witness without recomputing the count.
    Mined {
        block_height: u64,
        confirmations: u64,
    },
}

/// A proof-relevant tx fetched from the daemon: the parsed pruned body
/// plus where the daemon found it.
pub(crate) struct FetchedTx {
    pub(crate) tx: Transaction,
    pub(crate) state: TxChainState,
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
    let state = match txs.first().map(|t| &t.location) {
        Some(TxLocation::Mined {
            block_height,
            confirmations,
            ..
        }) => TxChainState::Mined {
            block_height: *block_height,
            confirmations: *confirmations,
        },
        // No entry is not "pooled", but `parse_tx_batch` below refuses an
        // empty batch for a requested hash, so this arm never reaches a
        // caller; it is written as the pooled shape rather than a panic.
        Some(TxLocation::Pooled { .. }) | None => TxChainState::Pooled,
    };

    // Proof payloads carry txids as bytes (their own format); the typed world
    // starts at the batch parser.
    let mut parsed = parse_tx_batch(&[TxHash::from_bytes(txid)], txs, TxBodyForm::Pruned)
        .map_err(ProofsError::Daemon)?;
    let tx = parsed
        .pop()
        .expect("parse_tx_batch returns exactly one tx per requested hash");

    Ok(FetchedTx { tx, state })
}

/// Fetch the pruned bodies of `txids` (unique, in first-seen order) in
/// batched `get_transactions` calls of [`TXS_PER_REQUEST`] hashes — the
/// daemon's restricted-RPC cap, the same chunking `block_fetch` uses —
/// rather than one round trip per txid (a 4096-locator reserve proof
/// would otherwise cost up to 4096 sequential daemon calls). Returns
/// the parsed bodies positionally aligned with `txids`.
///
/// Error semantics match [`fetch_proof_tx`] with one deliberate
/// addition: a txid the daemon does not know is
/// [`ProofsError::TxNotFound`] carrying the first missing txid in
/// request order; a malformed body or batch is [`ProofsError::Daemon`];
/// and a txid the daemon serves **from its pool** is
/// [`ProofsError::TxUnconfirmed`]. The single-tx fetch above accepts
/// pooled entries because its consumers (the tx-proof checks) report
/// `in_pool` / `confirmations` honestly in their result; this batch
/// fetch serves the reserve-proof check, whose result is a bare
/// `total - spent` with no pool dimension — an unconfirmed output
/// counted there presents mempool money, which a competing spend can
/// still erase, as live confirmed reserve. Reserve is a claim about
/// the chain, so a locator naming a pooled tx refuses loudly (naming
/// the txid, so an honest-but-early prover knows to wait for
/// confirmation) rather than quietly shrinking the total.
async fn fetch_proof_txs<R: Rpc>(
    witness: &SyncedChainFacts,
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
        // Refuse pooled entries before parsing. `resp.txs` is indexed by
        // request position (RK-4c's export), so `batch[i]` names the tx the
        // verifier asked about at slot `i` — the honest name for the error.
        // A daemon lying about `location` can only cause a spurious refusal
        // here, never a false acceptance.
        for (requested, entry) in batch.iter().zip(&resp.txs) {
            match &entry.location {
                TxLocation::Pooled { .. } => {
                    return Err(ProofsError::TxUnconfirmed(hex::encode(requested)));
                }
                TxLocation::Mined {
                    block_height,
                    confirmations,
                    ..
                } => admit_mined_against_witness(witness, *block_height, *confirmations)?,
            }
        }
        let typed: Vec<TxHash> = batch.iter().copied().map(TxHash::from_bytes).collect();
        bodies.extend(
            parse_tx_batch(&typed, &resp.txs, TxBodyForm::Pruned).map_err(ProofsError::Daemon)?,
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
///
/// **Read, not recomputed.** The daemon already answers this: the native
/// handler derives `confirmations` as `chain_height - block_height`
/// against the tip it read once for the whole gather, which is the same
/// arithmetic this function used to perform. Doing it again here meant a
/// second `get_height`, and subtracting a block height captured in the
/// *earlier* `get_transactions` from a tip read *later* — two snapshots
/// for one answer, so a block arriving between them inflated the count
/// and a reorg could make it describe a chain the block is no longer on.
/// The one-lock gather exists precisely so that pairing cannot happen;
/// carrying its number forward is what makes the guarantee reach the
/// caller instead of stopping at the daemon.
///
/// Taking the daemon's value is no more trusting than the arithmetic was:
/// both operands were always its to choose. It is strictly better only in
/// being self-consistent, and one round trip cheaper.
pub(crate) fn confirmations_of(state: &TxChainState) -> (bool, u64) {
    match state {
        TxChainState::Pooled => (true, 0),
        TxChainState::Mined { confirmations, .. } => (false, *confirmations),
    }
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
        .map_err(|e| RpcError::InvalidNode(format!("transaction extra unparseable: {e}")))?;
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

/// The chain count a mined reply's own arithmetic implies.
///
/// The daemon's contract is `confirmations = chain_count - block_height`
/// (the tip block reports 1), so the count is the sum. Overflow is a reply
/// that does not obey its own formula.
fn gather_chain_count(block_height: u64, confirmations: u64) -> Result<u64, ProofsError> {
    block_height.checked_add(confirmations).ok_or_else(|| {
        ProofsError::Daemon(RpcError::InvalidNode(
            "mined transaction's block height and confirmations overflow".into(),
        ))
    })
}

/// Refuse a mined reply gathered below the witness count.
///
/// That relation is the rollback half of [`SyncedChainFacts`]'s chain view:
/// the witness was read first, and a later tx reply whose implied count sits
/// below it was gathered on a chain that had already moved down. Ordinary
/// advance (gather at or above the witness) is kept, and the confirmation
/// count is still the daemon's number — this does not recompute it.
///
/// # Errors
///
/// [`ProofsError::Daemon`] when the arithmetic overflows or the gather sits
/// below the witness. Both are "do not turn this reply into a verdict".
fn admit_mined_against_witness(
    witness: &SyncedChainFacts,
    block_height: u64,
    confirmations: u64,
) -> Result<(), ProofsError> {
    let gather = gather_chain_count(block_height, confirmations)?;
    if gather < witness.chain_height().to_raw() {
        Err(ProofsError::Daemon(RpcError::InvalidNode(
            "transaction was read below the synchronized chain count".into(),
        )))
    } else {
        Ok(())
    }
}

/// A synchronized chain a proof may be checked against.
///
/// [`Self::open`] is the only constructor. It consumes
/// [`fetch_synced_chain_facts`], so "synced" stays the witness type the
/// watchdog and the tip gate already ask for. Tx fetches and the spent-set
/// query are methods: a check cannot issue them without holding a view.
/// Outbound generation does not use this type.
///
/// The witness is not discarded. A mined reply is admitted against it, so a
/// rollback between `get_info` and `get_transactions` cannot become a
/// verdict. A daemon that lies `synchronized` is outside what the witness
/// proves; that limit is the type's own.
pub(crate) struct ProofChainView {
    witness: SyncedChainFacts,
}

impl ProofChainView {
    /// Open a view on `rpc`.
    ///
    /// A transport or contract fault stays [`ProofsError::Daemon`]. An
    /// unsynchronized daemon is [`ProofsError::DaemonSyncing`]
    /// (`-29305`). The two send a caller to different remedies.
    ///
    /// # Errors
    ///
    /// [`ProofsError::DaemonSyncing`] when the daemon is not synchronized.
    /// [`ProofsError::Daemon`] when `get_info` could not be read.
    pub(crate) async fn open<R: Rpc>(rpc: &R) -> Result<Self, ProofsError> {
        match fetch_synced_chain_facts(rpc).await {
            Ok(Some(witness)) => Ok(Self { witness }),
            Ok(None) => Err(ProofsError::DaemonSyncing),
            Err(error) => Err(ProofsError::Daemon(error)),
        }
    }

    /// One pruned tx, admitted against this view when it is mined.
    ///
    /// # Errors
    ///
    /// The [`fetch_proof_tx`] errors, plus [`ProofsError::Daemon`] when a
    /// mined reply sits below the witness.
    pub(crate) async fn tx<R: Rpc>(
        &self,
        rpc: &R,
        txid: [u8; 32],
    ) -> Result<FetchedTx, ProofsError> {
        let fetched = fetch_proof_tx(rpc, txid).await?;
        if let TxChainState::Mined {
            block_height,
            confirmations,
        } = fetched.state
        {
            admit_mined_against_witness(&self.witness, block_height, confirmations)?;
        }
        Ok(fetched)
    }

    /// The pruned bodies of `txids`, each mined reply admitted against
    /// this view. Pooled entries refuse as [`ProofsError::TxUnconfirmed`].
    ///
    /// # Errors
    ///
    /// The batch-fetch errors, plus [`ProofsError::Daemon`] when a mined
    /// reply sits below the witness.
    pub(crate) async fn txs<R: Rpc>(
        &self,
        rpc: &R,
        txids: &[[u8; 32]],
    ) -> Result<Vec<Transaction>, ProofsError> {
        fetch_proof_txs(&self.witness, rpc, txids).await
    }

    /// `is_key_image_spent` for `key_images`, in request order.
    ///
    /// The receiver is the opened view, so this query cannot be issued
    /// before [`Self::open`]. The spent set is not a height; the witness
    /// is not re-checked here.
    ///
    /// A reply whose status array is a different length is refused before
    /// any amount is summed: one plausible array would change the reported
    /// reserve.
    ///
    /// # Errors
    ///
    /// [`ProofsError::Daemon`] on transport failure, a non-OK status, or a
    /// length mismatch.
    pub(crate) async fn key_image_status<R: Rpc>(
        &self,
        rpc: &R,
        key_images: Vec<String>,
    ) -> Result<Vec<KeyImageStatus>, ProofsError> {
        let asked = key_images.len();
        let resp: IsKeyImageSpentResponse = rpc
            .rpc_call(
                "is_key_image_spent",
                Some(
                    serde_json::to_value(IsKeyImageSpentRequest { key_images })
                        .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
                ),
            )
            .await?;
        refuse_unless_ok(&resp.status, "is_key_image_spent").map_err(ProofsError::Daemon)?;
        if resp.spent_status.len() != asked {
            return Err(ProofsError::Daemon(RpcError::InvalidNode(
                "is_key_image_spent returned a different count than requested".to_string(),
            )));
        }
        Ok(resp.spent_status)
    }
}

#[cfg(test)]
mod witness_admission {
    use super::super::daemon::synced_chain_facts::SyncedChainFacts;
    use super::admit_mined_against_witness;
    use super::ProofsError;
    use shekyl_types::{BlockHash, ChainCount};

    const BLOCK_HEIGHT: u64 = 3;
    const CONFIRMATIONS: u64 = 5;
    /// `confirmations = chain_count - block_height`, so the gather is the sum.
    const GATHER: u64 = BLOCK_HEIGHT + CONFIRMATIONS;

    fn witness_at(count: u64) -> SyncedChainFacts {
        SyncedChainFacts::new(
            ChainCount::from_raw(count),
            0,
            true,
            BlockHash::from_bytes([0x11; 32]),
        )
        .expect("target 0 with the flag set is synchronized")
    }

    /// Bites against rejecting an equal gather. Does not cover the sync
    /// predicate; that lives on `SyncedChainFacts::new`.
    #[test]
    fn a_gather_at_the_witness_count_is_admitted() {
        admit_mined_against_witness(&witness_at(GATHER), BLOCK_HEIGHT, CONFIRMATIONS)
            .expect("equal counts are one snapshot");
    }

    /// Bites against rejecting ordinary advance. Does not recompute the
    /// confirmation count the caller will report.
    #[test]
    fn ordinary_advance_above_the_witness_is_admitted() {
        admit_mined_against_witness(&witness_at(GATHER), BLOCK_HEIGHT, CONFIRMATIONS + 1)
            .expect("one block of advance stays the daemon's count");
    }

    /// Bites against dropping the comparison. A gather below the witness
    /// is the rollback direction and must not become a verdict.
    #[test]
    fn a_gather_below_the_witness_is_not_a_chain_verdict() {
        let err = admit_mined_against_witness(&witness_at(GATHER + 1), BLOCK_HEIGHT, CONFIRMATIONS)
            .expect_err("rollback between the two reads");
        assert!(
            matches!(err, ProofsError::Daemon(_)),
            "expected Daemon, got {err:?}"
        );
    }

    /// Bites against a wrapping add. Does not cover a short confirmation
    /// count, which is a successful gather below the witness.
    #[test]
    fn an_overflowing_confirmation_arithmetic_is_a_daemon_fault() {
        let err =
            admit_mined_against_witness(&witness_at(1), u64::MAX, 1).expect_err("the sum must fit");
        assert!(
            matches!(err, ProofsError::Daemon(_)),
            "expected Daemon, got {err:?}"
        );
    }
}
