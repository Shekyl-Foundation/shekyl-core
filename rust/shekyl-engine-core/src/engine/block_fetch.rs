// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Native `ScannableBlock` fetch over the `shekyl-wire` parse.
//!
//! This is the engine-side replacement for the legacy
//! `shekyl_rpc_client::Rpc::get_scannable_block_by_*` path. The transport
//! (`get_block` / `get_transactions` JSON-RPC, `get_o_indexes` binary RPC) is
//! still the vendored [`shekyl_rpc_client::Rpc`] surface, but **parsing moves to the
//! canonical [`shekyl_wire`] crate**: [`shekyl_wire::Block::from_bytes`] and
//! [`shekyl_wire::Transaction::from_bytes`].
//!
//! # Why this exists (the coinbase `Null` parse fix)
//!
//! The legacy `shekyl-oxide` block parse dropped the committed base
//! (`enc_amounts` / `enc_labels` / `outPk`) for the coinbase `Null`
//! confidential-transaction section, so live daemon coinbase blocks were
//! rejected as `RpcError::InvalidNode("invalid block")` and refresh could not
//! scan coinbase balances. `shekyl_wire` parses the coinbase `Null` base
//! per `GENESIS_TX_WIRE_FORMAT.md` §9.6/§9.9 (the committed base is present
//! for both the coinbase `Ct::Null` and spends' `Ct::Fcmp`), so the scanner
//! recovers coinbase outputs correctly. [`parse_block_blob`] is the regression
//! anchor for that fix.
//!
//! # First global output index
//!
//! `ScannableBlock::first_output_index` is the global output index of the
//! first output in the block (the same role the legacy
//! `output_index_for_first_ringct_output` played). It is requested once via
//! [`shekyl_rpc_client::Rpc::get_o_indexes`] for the first transaction that has
//! outputs (the coinbase, in practice); the scanner advances the running
//! index itself, so per-output index requests (a privacy leak) are avoided.
//!
//! # One body form (`SB-Q2`)
//!
//! Every wallet fetch asks for `prune` and receives the **skeleton**: the
//! pruned segment with the three txid operands the daemon's store holds
//! (`prunable_hash`, `pqc_auth_hash`, `archival_len`). The daemon is
//! untrusted, so each body is **bound** to the txid the wallet asked for by
//! recomputing it from the bytes and the operands
//! ([`shekyl_wire::SkeletonTx::bind`]); the label beside it proves nothing.
//! What leaves this module is a [`shekyl_wire::BoundTx`], a body carrying the
//! identity it was bound to, so the P-scan's exhaustiveness gate
//! (`pscan::exhaustiveness`) reads that identity instead of re-hashing bytes a
//! pruned body cannot be re-hashed from. Refresh, the proofs workflow and the
//! P-scan all take this one path; there is no whole-body form, and a daemon
//! that answers a `prune` request with a whole body, an `archived` slot, or a
//! skeleton missing an operand is refused as an invalid node.
//!
//! # Ingestion validation (untrusted daemon)
//!
//! Every block- and transaction-blob is run through the canonical
//! context-free validator for its form: the coinbase and every skeleton take
//! [`shekyl_wire::Transaction::validate_context_free_pruned`] — the
//! consensus-parity reject set (resource bounds, the §2.5 coinbase shape +
//! arm-mixing matrix, the §12 key-image canonical form, block-height-only
//! `unlock_time`, committed-base arity) minus the prunable-coupled checks,
//! which cannot run on a body whose prunable region the chain has discarded.
//! This is the single ingestion gate; it replaces the scattered ad-hoc checks
//! (the standalone `unlock_time` reject, etc.) that accumulated here.
//!
//! On top of the validator, [`parse_tx_batch`] rejects a coinbase-shaped tx in
//! a `get_transactions` response ([`shekyl_wire::Transaction::is_coinbase`]) —
//! the coinbase is embedded in the block blob and parsed there, never served
//! as a non-miner tx — and the transport-shape checks guard the framing:
//! oversized-hex DoS pre-bounds (ahead of the `MAX_BLOCK_BLOB_SIZE` /
//! `MAX_TX_SIZE` guards in [`shekyl_wire::Block::from_bytes`] /
//! [`shekyl_wire::Transaction::from_pruned_bytes`]), reordered / mismatched
//! batches, and malformed `missed_tx` entries. Retiring the scanner's
//! now-redundant defense-in-depth gates (`scan_transaction_with_cancel`'s
//! `MAX_OUTPUTS` / timestamp-form gates) to true belt-and-suspenders is a
//! shekyl-oxide-cutover follow-up tracked in `docs/FOLLOWUPS.md`.

use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{
    GetBlockRequest, GetBlockResponse, GetTransactionsRequest, GetTransactionsResponse, RpcStatus,
    TxEntry,
};
use shekyl_scanner::ScannableBlock;
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash, TxHash};
use shekyl_wire::{
    block::MAX_BLOCK_BLOB_SIZE, transaction::MAX_TX_SIZE, Block, BoundTx, SkeletonTx,
};

/// Monero restricts `get_transactions` to 100 hashes per call on the
/// restricted RPC (`core_rpc_server.cpp`); batch accordingly. Shared
/// with the proofs workflow's batched locator-tx fetch.
pub(crate) const TXS_PER_REQUEST: usize = 100;

/// The one scannable-block fetch, and `DaemonEngine::fetch_scannable_block`'s
/// default: one `get_block`, the non-miner bodies as bound skeletons, and the
/// first global output index. Also the body behind the `DaemonClient`
/// inherent method and the remote-posture `PBlockSource`, which carry a bare
/// `Rpc` rather than a `DaemonEngine`.
pub(crate) async fn default_fetch_scannable_block<R: Rpc>(
    rpc: &R,
    number: usize,
) -> Result<ScannableBlock, RpcError> {
    // The shared wire types, like the `get_transactions` fetch below. This was
    // an RK-3b leftover: `get_block` migrated to Rust in that slice and the
    // typed request/response landed with it, but this caller kept hand-rolling
    // the params and walking the reply. Two definitions of one shape, and the
    // one the daemon cannot see is the one that drifts.
    let height = u64::try_from(number)
        .map_err(|_| RpcError::InternalError(format!("block height {number} does not fit u64")))?;
    let res: GetBlockResponse = rpc
        .json_rpc_call(
            "get_block",
            Some(
                serde_json::to_value(GetBlockRequest {
                    hash: String::new(),
                    height,
                    fill_pow_hash: false,
                })
                .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
            ),
        )
        .await?;
    refuse_unless_ok(&res.status, "get_block")?;
    let block = parse_block_blob(&res.blob, number)?;

    let transactions = fetch_transactions(rpc, &block.transaction_hashes).await?;
    let first_output_index = compute_first_output_index(rpc, &block, &transactions).await?;

    Ok(ScannableBlock {
        block,
        transactions,
        first_output_index,
    })
}

/// Hex-decode and parse a block blob, requiring exact consumption (the
/// `shekyl_wire` canonical-encoding invariant) and that the coinbase `gen`
/// input's height matches the requested `number`.
fn parse_block_blob(blob_hex: &str, expected_number: usize) -> Result<Block, RpcError> {
    // DoS pre-bound (mirrors `decode_tx_hex`): bound the hex *input* before
    // `hex::decode` allocates ~half its length, otherwise a hostile daemon could
    // force a large allocation that `Block::from_bytes`'s own
    // `MAX_BLOCK_BLOB_SIZE` guard only catches after the decode. A block blob is
    // at most `MAX_BLOCK_BLOB_SIZE` bytes ⇒ `2 * MAX_BLOCK_BLOB_SIZE` hex chars.
    if blob_hex.len() > MAX_BLOCK_BLOB_SIZE.saturating_mul(2) {
        return Err(RpcError::InvalidNode("block blob too large".to_string()));
    }
    let bytes = hex::decode(blob_hex)
        .map_err(|_| RpcError::InvalidNode("block blob wasn't hex".to_string()))?;
    let block = Block::from_bytes(&bytes)
        .map_err(|_| RpcError::InvalidNode("invalid block".to_string()))?;
    // The daemon must have returned the block we asked for. `Block::from_bytes`
    // already enforces the coinbase shape (sole `gen` input, `Null` ct), so
    // `number()` is the `gen` height.
    if block.number() != Some(expected_number as u64) {
        return Err(RpcError::InvalidNode(
            "different block than requested (number)".to_string(),
        ));
    }
    // Canonical-shape gate for the embedded coinbase, via the same pruned-safe
    // context-free validator used for non-miner txs. `Block::from_bytes` already pins
    // the gen/Null coinbase shape; this adds the field-level canonical checks
    // (block-height-only `unlock_time`, output count, committed-base arity).
    block
        .miner_transaction
        .validate_context_free_pruned()
        .map_err(|_| RpcError::InvalidNode("non-canonical coinbase".to_string()))?;
    Ok(block)
}

/// Bind one served skeleton to the txid it was requested as, and gate its
/// shape.
///
/// [`SkeletonTx::bind`] parses the unprunable bytes via the canonical
/// [`shekyl_wire::Transaction::from_pruned_bytes`], which rejects blobs
/// larger than `MAX_TX_SIZE` up front (the untrusted-daemon DoS bound) and
/// requires exact consumption of the pruned segment (`SB-Q2`: bytes after
/// the base would read as authentications and proof data that the
/// skeleton's txid ignores), then recomputes the txid from the bytes and
/// the three served operands and refuses anything but `expected`. The
/// body it returns is then held to the pruned-safe context-free validator
/// (`validate()`'s prunable-coupled branch cannot run without the prunable
/// region — see [`shekyl_wire::Transaction::validate_context_free_pruned`])
/// and refused if coinbase-shaped: `get_transactions` returns only
/// NON-miner txs — the coinbase is embedded in the block blob and parsed
/// there — so a coinbase here is the daemon serving something it never
/// should, and a misplaced coinbase (with its cleartext `gen` reward
/// output) must never be fed to the scanner.
fn bind_skeleton(
    skeleton: &SkeletonTx,
    expected: TxHash,
    tx_hash_hex: &str,
) -> Result<BoundTx, RpcError> {
    let bound = skeleton.bind(expected).map_err(|fault| {
        RpcError::InvalidNode(format!(
            "daemon served a body that does not bind to {tx_hash_hex}: {fault} — a label \
             is not an identity"
        ))
    })?;
    bound
        .validate_context_free_pruned()
        .map_err(|_| invalid_tx_error(tx_hash_hex))?;
    if bound.is_coinbase() {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    Ok(bound)
}

/// Hex-decode one body under the untrusted-daemon DoS bound.
///
/// `hex::decode` allocates ~`blob_hex.len() / 2` bytes, so the *input*
/// length is bounded before decoding — otherwise a hostile daemon could
/// force a large allocation that the parser's own `MAX_TX_SIZE` guard only
/// catches after the decode. A pruned segment is at most a full tx
/// (`MAX_TX_SIZE` bytes ⇒ `2 * MAX_TX_SIZE` hex chars).
fn decode_tx_hex(blob_hex: &str, tx_hash_hex: &str) -> Result<Vec<u8>, RpcError> {
    if blob_hex.len() > MAX_TX_SIZE.saturating_mul(2) {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    hex::decode(blob_hex).map_err(|_| RpcError::InvalidNode("tx blob wasn't hex".to_string()))
}

/// Build the error for a tx-body parse failure, preferring the daemon-named
/// hash ([`RpcError::InvalidTransaction`]) when it decodes.
fn invalid_tx_error(tx_hash_hex: &str) -> RpcError {
    match hex::decode(tx_hash_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    {
        Some(hash) => RpcError::InvalidTransaction(hash),
        None => RpcError::InvalidNode("invalid pruned transaction".to_string()),
    }
}

/// Fetch the non-miner transactions named by `hashes` as skeletons and bind
/// each, batching by [`TXS_PER_REQUEST`].
async fn fetch_transactions<R: Rpc>(rpc: &R, hashes: &[TxHash]) -> Result<Vec<BoundTx>, RpcError> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let mut transactions = Vec::with_capacity(hashes.len());
    for batch in hashes.chunks(TXS_PER_REQUEST) {
        let hashes_hex: Vec<String> = batch.iter().map(hex::encode).collect();
        // The request and the reply are the shared wire types (RK-4c), so the
        // shape lives in one place. A malformed `missed_tx` entry is refused by
        // `HashHex`'s deserializer at the boundary rather than by a walk here —
        // same rejection, one fewer copy of what a hash looks like.
        let resp: GetTransactionsResponse = rpc
            .rpc_call(
                "get_transactions",
                Some(
                    serde_json::to_value(GetTransactionsRequest {
                        txs_hashes: hashes_hex,
                        prune: true,
                    })
                    .map_err(|e| RpcError::InternalError(format!("encode request: {e}")))?,
                ),
            )
            .await?;
        refuse_unless_ok(&resp.status, "get_transactions")?;

        if !resp.missed_tx.is_empty() {
            return Err(RpcError::TransactionsNotFound(
                resp.missed_tx
                    .iter()
                    .copied()
                    .map(shekyl_rpc_types::HashHex::to_bytes)
                    .collect(),
            ));
        }
        // Not found is an answer; unavailable is none.
        if !resp.unavailable_tx.is_empty() {
            return Err(RpcError::TransactionsUnavailable(
                resp.unavailable_tx
                    .iter()
                    .copied()
                    .map(shekyl_rpc_types::HashHex::to_bytes)
                    .collect(),
            ));
        }
        transactions.extend(parse_tx_batch(batch, &resp)?);
    }

    Ok(transactions)
}

/// Refuse a daemon reply whose `status` is not OK, **before any other field is
/// read**.
///
/// `Rpc::rpc_call` and `json_rpc_call` only deserialize: they do not enforce
/// the wire's `status`, so a daemon is free to answer a refusal and a
/// valid-looking body in the same document. Nothing in that document is then
/// evidence — the entries, the missed list, the spent flags are all chosen by
/// whoever sent it — and a consumer that reads a field before the status has
/// already treated a refusal as data.
///
/// It matters most where the reply feeds a *judgement* rather than a display: a
/// refusal carrying one plausible-length `spent_status` array changes a reserve
/// proof's total, and one carrying a plausible entry lets a proof verify
/// against a transaction the daemon just declined to vouch for. The own-node
/// default narrows who can send such a document; it does not make it evidence.
///
/// One function rather than a check at each call site, so the refusal reads the
/// same way everywhere and a sixth typed consumer has something to reach for.
pub(crate) fn refuse_unless_ok(status: &RpcStatus, method: &'static str) -> Result<(), RpcError> {
    if status.is_ok() {
        return Ok(());
    }
    Err(RpcError::InvalidNode(format!(
        "{method} refused with status {}; its body is not evidence",
        status.0
    )))
}

/// Validate one `get_transactions` reply to a `prune` request against the
/// `batch` of requested hashes (in order) and bind each served skeleton.
///
/// Pure (no transport) so the adversarial-daemon checks are unit-testable
/// without an RPC mock. Every requested tx must be present (the caller turns a
/// non-empty `missed_tx` into [`RpcError::TransactionsNotFound`], and a
/// non-empty `unavailable_tx` into [`RpcError::TransactionsUnavailable`],
/// before calling here), and the daemon echoes present txs in request order —
/// so the count must match and each entry's claimed `tx_hash` must equal the
/// requested hash for its slot. That label check is the cheap failure, not
/// the association: the daemon chooses the label as freely as the body, so
/// every body is then **bound** — the skeleton it is ([`SkeletonTx::bind`]:
/// the pruned segment with the reply's `pqc_auth_hash`, `prunable_hash` and
/// `archival_len` as the operands §11 requires, `SB-Q2`) recomputed to the
/// requested txid. An unchecked reorder or substitution would otherwise
/// mis-assign the running global output index (assigned by walking txs in
/// block order) and record wrong txids — exactly the failure the
/// untrusted-node model must reject. Per-batch equality also makes the
/// caller's total length exact, so no separate cardinality check is needed
/// after batching.
///
/// A reply that does not conform to the `prune` contract is refused as an
/// invalid node (`SB-Q2` item 10): an `archived` slot (the full form's
/// answer, never the skeleton's — every transaction has a skeleton), a body
/// in `as_hex` (the whole body, which a `prune` request never asks for and
/// whose `pqc_auths` bytes the wallet must never have to parse), or a
/// skeleton missing its pruned segment. A `pqc_auth_hash` the skeleton's
/// prefix cannot carry is refused by the binding.
pub(crate) fn parse_tx_batch(
    batch: &[TxHash],
    reply: &GetTransactionsResponse,
) -> Result<Vec<BoundTx>, RpcError> {
    if !reply.archived.is_empty() {
        return Err(RpcError::InvalidNode(
            "daemon answered a prune request with an archived slot: every transaction has a \
             skeleton, so the archive is never the pruned form's answer"
                .to_string(),
        ));
    }
    let txs: &[TxEntry] = &reply.txs;
    if txs.len() != batch.len() {
        return Err(RpcError::InvalidNode(
            "daemon returned a different number of transactions than requested".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(batch.len());
    for (expected_hash, t) in batch.iter().zip(txs) {
        // `HashHex` already refused anything that is not 32 bytes of hex, so
        // the label is well-formed. Checking it against the request is worth
        // doing first — it names the cheap failure — but it proves nothing on
        // its own: the daemon chooses the label as freely as it chooses the
        // body, so a matching label is only evidence that it wanted to match.
        if TxHash::from_bytes(t.tx_hash.to_bytes()) != *expected_hash {
            return Err(RpcError::InvalidNode(
                "daemon returned a transaction whose hash did not match the request".to_string(),
            ));
        }
        let tx_hash_hex = t.tx_hash.to_string();
        if !t.as_hex.is_empty() {
            return Err(RpcError::InvalidNode(format!(
                "daemon answered a prune request for {tx_hash_hex} with a whole body: the \
                 pruned form is the skeleton alone"
            )));
        }
        if t.pruned_as_hex.is_empty() {
            return Err(RpcError::InvalidNode(format!(
                "transaction response for {tx_hash_hex} is missing pruned_as_hex"
            )));
        }
        // The skeleton as served: the operands travel with the bytes they
        // were served with, and the binding hashes the skeleton, not a body.
        let skeleton = SkeletonTx {
            unprunable: decode_tx_hex(&t.pruned_as_hex, &tx_hash_hex)?,
            prunable_hash: PrunableHash::from_bytes(t.prunable_hash.to_bytes()),
            pqc_auth_hash: t
                .pqc_auth_hash
                .into_option()
                .map(|hash| PqcAuthHash::from_bytes(hash.to_bytes())),
            archival_len: ArchivalLength::from_raw(t.archival_len),
        };

        // **Bind the body to the request, not the label to the request.**
        //
        // Every field above is the daemon's to choose, so a canonical
        // transaction under a borrowed label passes every check so far — and a
        // proof consumer then verifies outputs belonging to a transaction that
        // may not be on this chain at all. Recomputing the identity from the
        // bytes closes it: to substitute a body the daemon would have to find
        // one whose hash is a txid someone else named first.
        //
        // The three operands are also the daemon's to choose — and it gains
        // nothing by it. Choosing them freely leaves it solving
        // `H(prefix ‖ base ‖ P ‖ X ‖ len) = txid` for `P`, `X` and `len`, a
        // keccak preimage, not a substitution. An arity the prefix needs and
        // was not given hashes to another identity and is refused the same
        // way; one the prefix cannot carry is refused outright.
        out.push(bind_skeleton(&skeleton, *expected_hash, &tx_hash_hex)?);
    }
    Ok(out)
}

/// Request the global output index of the block's first output (the coinbase's,
/// in practice). `None` only if no transaction in the block has any output.
async fn compute_first_output_index<R: Rpc>(
    rpc: &R,
    block: &Block,
    transactions: &[BoundTx],
) -> Result<Option<u64>, RpcError> {
    let miner_hash = block.miner_transaction.hash();
    // Each bound body carries the txid it was bound to, which `parse_tx_batch`
    // held equal to its slot in `block.transaction_hashes`.
    let candidates = core::iter::once((miner_hash, &block.miner_transaction))
        .chain(transactions.iter().map(|tx| (tx.txid(), tx.tx())));
    for (hash, tx) in candidates {
        if tx.prefix.outputs.is_empty() {
            continue;
        }
        // The RPC client trait is a wire boundary and takes the txid as bytes
        // (RTN-7 §3.2; RPC DTOs stay raw).
        let index = *rpc
            .get_o_indexes(hash.to_bytes())
            .await?
            .first()
            .ok_or_else(|| {
                RpcError::InvalidNode(
                    "requested output indexes for a TX with outputs and got none".to_string(),
                )
            })?;
        return Ok(Some(index));
    }
    Ok(None)
}

#[cfg(test)]
#[path = "block_fetch_tests.rs"]
mod tests;
