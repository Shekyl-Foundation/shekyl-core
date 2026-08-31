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
//! # Ingestion validation (untrusted daemon)
//!
//! The daemon is untrusted, so this boundary rejects non-canonical responses
//! rather than forwarding them to the scanner. Every block- and transaction-blob
//! is run through the canonical context-free validator matching its fetched
//! body form ([`TxBodyForm`]). Pruned bodies (the refresh path) take
//! [`shekyl_wire::Transaction::validate_context_free_pruned`] — the consensus-parity
//! reject set (resource bounds, the §2.5 coinbase shape + arm-mixing matrix, the §12
//! key-image canonical form, block-height-only `unlock_time`, committed-base arity)
//! minus the prunable-coupled checks, which cannot run on a *pruned* transaction
//! (the prunable proof is dropped, and the full
//! [`shekyl_wire::Transaction::validate`] rejects a key-image-bearing spend without it
//! by design). Full bodies (the P-scan path, which must re-hash each body for
//! the SP-6 exhaustiveness gate) take the complete
//! [`shekyl_wire::Transaction::validate`]. This is the single ingestion gate; it
//! replaces the scattered ad-hoc checks (the standalone `unlock_time` reject,
//! etc.) that accumulated here.
//!
//! On top of the validator, [`parse_tx_blob`] rejects a coinbase-shaped tx in a
//! `get_transactions` response ([`shekyl_wire::Transaction::is_coinbase`]) — the
//! coinbase is embedded in the block blob and parsed there, never served as a
//! non-miner tx — and the transport-shape checks guard the framing: oversized-hex
//! DoS pre-bounds (ahead of the `MAX_BLOCK_BLOB_SIZE` / `MAX_TX_SIZE` guards in
//! [`shekyl_wire::Block::from_bytes`] / [`shekyl_wire::Transaction::from_bytes`]),
//! reordered / mismatched batches ([`parse_tx_batch`]), and malformed `missed_tx`
//! entries. Retiring the scanner's now-redundant defense-in-depth gates
//! (`scan_transaction_with_cancel`'s `MAX_OUTPUTS` / timestamp-form gates) to true
//! belt-and-suspenders is a shekyl-oxide-cutover follow-up tracked in
//! `docs/FOLLOWUPS.md`.

use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_rpc_types::{
    GetBlockRequest, GetBlockResponse, GetTransactionsRequest, GetTransactionsResponse, RpcStatus,
    TxEntry,
};
use shekyl_scanner::ScannableBlock;
use shekyl_wire::{block::MAX_BLOCK_BLOB_SIZE, transaction::MAX_TX_SIZE, Block, Transaction};

/// Monero restricts `get_transactions` to 100 hashes per call on the
/// restricted RPC (`core_rpc_server.cpp`); batch accordingly. Shared
/// with the proofs workflow's batched locator-tx fetch.
pub(crate) const TXS_PER_REQUEST: usize = 100;

/// Which transaction-body form a scannable-block fetch requests from the
/// daemon, and therefore which parse/validation path each body takes.
///
/// The two forms exist because two wallet consumers have different
/// verification obligations:
///
/// - [`Pruned`](Self::Pruned) — the refresh path. The prunable proof is
///   dropped by the daemon (`prune: true`), so the body does not hash to its
///   committed tx hash on its own (`GENESIS_TX_WIRE_FORMAT.md` §11 — the
///   pruned form mixes a *supplied* prunable digest). Association is still by
///   recomputed identity, not by the daemon's label:
///   [`Transaction::hash_with_supplied_prunable`] takes the reply's
///   `prunable_hash` as that operand. Validation is the pruned-safe
///   context-free subset.
/// - [`Full`](Self::Full) — the P-scan path. SP-6's exhaustiveness gate
///   recomputes every body's hash from received material
///   (`pscan::exhaustiveness`), which **requires** the prunable section: a
///   storage-pruned FCMP++ spend hashes with the null prunable component and
///   can never equal its committed hash, so a pruned fetch would halt the scan
///   at the first spend-bearing block as a forged-absence refusal. Full bodies
///   also unlock the full context-free validator (the prunable-coupled
///   checks).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxBodyForm {
    Pruned,
    Full,
}

/// Convenience wrapper over [`fetch_scannable_block_with_form`] for callers
/// outside the `DaemonEngine` trait (the `DaemonClient` inherent method):
/// the refresh-path pruned form.
pub(crate) async fn default_fetch_scannable_block<R: Rpc>(
    rpc: &R,
    number: usize,
) -> Result<ScannableBlock, RpcError> {
    fetch_scannable_block_with_form(rpc, number, TxBodyForm::Pruned).await
}

/// As [`default_fetch_scannable_block`] with **full** (unpruned) non-miner
/// bodies — the form the P-scan's SP-6 per-body verification consumes (see
/// [`TxBodyForm::Full`]). Used where a bare `Rpc` (not a `DaemonEngine`)
/// carries the fetch (the remote-posture `PBlockSource`).
pub(crate) async fn default_fetch_scannable_block_full<R: Rpc>(
    rpc: &R,
    number: usize,
) -> Result<ScannableBlock, RpcError> {
    fetch_scannable_block_with_form(rpc, number, TxBodyForm::Full).await
}

/// The single fetch body — and `DaemonEngine::fetch_scannable_block_in_form`'s
/// default: one `get_block`, the non-miner bodies in `form`, and the first
/// global output index.
pub(crate) async fn fetch_scannable_block_with_form<R: Rpc>(
    rpc: &R,
    number: usize,
    form: TxBodyForm,
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

    let transactions = fetch_transactions(rpc, &block.transaction_hashes, form).await?;
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
    // DoS pre-bound (mirrors `parse_pruned_tx`): bound the hex *input* before
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

/// Hex-decode and parse one pruned transaction blob via the canonical
/// [`shekyl_wire::Transaction::from_bytes`], which rejects blobs larger than
/// `MAX_TX_SIZE` up front (the untrusted-daemon DoS bound) and requires exact
/// consumption (`GENESIS_TX_WIRE_FORMAT.md` §12 — trailing bytes rejected).
/// This parses and validates shape only. Identity is [`parse_tx_batch`]'s job:
/// it checks each returned `tx_hash` against the requested hash in order AND
/// recomputes the body's own hash, mixing the reply's `prunable_hash` as the
/// operand §11 says the pruned form needs. The label alone is not an
/// association — the daemon chooses it.
fn parse_pruned_tx(pruned_hex: &str, tx_hash_hex: &str) -> Result<Transaction, RpcError> {
    parse_tx_blob(pruned_hex, tx_hash_hex, TxBodyForm::Pruned)
}

/// As [`parse_pruned_tx`], for a **full** (unpruned) body: the same DoS bound,
/// exact-consumption parse, and coinbase rejection, but the canonical-shape
/// gate is the *complete* context-free validator
/// ([`shekyl_wire::Transaction::validate`]) — the prunable section is present,
/// so the prunable-coupled checks (including "a key-image-bearing spend must
/// carry its proof") run, and a daemon that answers a full-body request with a
/// storage-pruned spend is rejected here rather than surviving to a bogus
/// hash downstream.
fn parse_full_tx(full_hex: &str, tx_hash_hex: &str) -> Result<Transaction, RpcError> {
    parse_tx_blob(full_hex, tx_hash_hex, TxBodyForm::Full)
}

/// Shared parse body behind [`parse_pruned_tx`] / [`parse_full_tx`]; `form`
/// selects the canonical-shape validator matching the body form requested.
fn parse_tx_blob(
    blob_hex: &str,
    tx_hash_hex: &str,
    form: TxBodyForm,
) -> Result<Transaction, RpcError> {
    // DoS pre-bound: `hex::decode` allocates ~`blob_hex.len() / 2` bytes, so
    // bound the *input* length before decoding — otherwise a hostile daemon
    // could force a large allocation that `from_bytes`'s own `MAX_TX_SIZE`
    // guard only catches after the decode. A pruned blob is at most a full tx
    // (`MAX_TX_SIZE` bytes ⇒ `2 * MAX_TX_SIZE` hex chars).
    if blob_hex.len() > MAX_TX_SIZE.saturating_mul(2) {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    let bytes = hex::decode(blob_hex)
        .map_err(|_| RpcError::InvalidNode("tx blob wasn't hex".to_string()))?;
    let tx = Transaction::from_bytes(&bytes).map_err(|_| invalid_tx_error(tx_hash_hex))?;
    // Canonical-shape gate: the daemon is untrusted, so reject any tx that is not a
    // well-formed, block-height-only Shekyl transaction before it reaches the scanner.
    // Pruned bodies take the pruned-safe context-free subset (`validate()`'s
    // prunable-coupled branch cannot run without the prunable section — see
    // `shekyl_wire::Transaction::validate_context_free_pruned`); full bodies take the
    // complete consensus-parity validator.
    match form {
        TxBodyForm::Pruned => tx
            .validate_context_free_pruned()
            .map_err(|_| invalid_tx_error(tx_hash_hex))?,
        TxBodyForm::Full => tx.validate().map_err(|_| {
            // A body that is a perfectly canonical PRUNED spend — prunable
            // section absent but everything else valid — is not a hostile
            // daemon inventing garbage: it is what a **storage-pruned**
            // daemon (a supported mode) serves for every historical spend.
            // The P-scan cannot run against one (SP-6's exhaustiveness gate
            // re-hashes full bodies), so name the cause and the remedy
            // instead of a generic invalid-transaction verdict that reads
            // as "your trusted node is serving corrupt data" (rule 82).
            if is_storage_pruned_spend(&tx) {
                RpcError::InvalidNode(format!(
                    "the daemon served a storage-pruned body for a full-body request \
                     (tx {tx_hash_hex}): the persona scan requires an UNPRUNED node — \
                     point the wallet at a daemon running without --prune-blockchain"
                ))
            } else {
                invalid_tx_error(tx_hash_hex)
            }
        })?,
    }
    // `get_transactions` returns only NON-miner txs — the coinbase is embedded in the
    // block blob and parsed there. A coinbase-shaped tx in this response is the daemon
    // serving something it never should; reject it so a misplaced coinbase (with its
    // cleartext `gen` reward output) can never be fed to the scanner.
    if tx.is_coinbase() {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    Ok(tx)
}

/// Whether a full-form body that failed the complete validator is exactly a
/// **storage-pruned spend**: the prunable section is absent but the body is
/// otherwise a canonical pruned transaction (it passes the pruned-safe
/// context-free subset). This is the shape a storage-pruned daemon serves
/// for every historical spend — the diagnosable operator state, as opposed
/// to a genuinely malformed body.
fn is_storage_pruned_spend(tx: &Transaction) -> bool {
    matches!(&tx.ct, shekyl_wire::Ct::Fcmp { prunable: None, .. })
        && tx.validate_context_free_pruned().is_ok()
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

/// Fetch and parse the non-miner transactions named by `hashes` in the body
/// `form`, batching by [`TXS_PER_REQUEST`].
async fn fetch_transactions<R: Rpc>(
    rpc: &R,
    hashes: &[[u8; 32]],
    form: TxBodyForm,
) -> Result<Vec<Transaction>, RpcError> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let prune = form == TxBodyForm::Pruned;
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
                        decode_as_json: false,
                        prune,
                        split: false,
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
        transactions.extend(parse_tx_batch(batch, &resp.txs, form)?);
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

/// Validate one `get_transactions` batch response against the `batch` of
/// requested hashes (in order) and parse each tx in the requested `form`.
///
/// Pure (no transport) so the adversarial-daemon checks are unit-testable
/// without an RPC mock. Every requested tx must be present (the caller turns a
/// non-empty `missed_tx` into [`RpcError::TransactionsNotFound`] before calling
/// here), and the daemon echoes present txs in request order — so the count
/// must match and each entry's claimed `tx_hash` must equal the requested hash
/// for its slot. That label check is the cheap failure, not the association:
/// the daemon chooses the label as freely as the body, so every body is then
/// **re-hashed and compared** — the pruned form through
/// [`Transaction::hash_with_supplied_prunable`], which takes the reply's
/// `prunable_hash` as the operand §11 requires, and the full form through
/// `hash()` directly. An unchecked reorder or substitution would otherwise
/// mis-assign the running global output index (assigned by walking txs in
/// block order) and record wrong txids — exactly the failure the untrusted-node
/// model must reject. (The P-scan's SP-6 exhaustiveness gate recomputes full
/// bodies again downstream — for it the label check is the
/// fast-fail, not the last line.) Per-batch equality also makes the caller's
/// total length exact, so no separate cardinality check is needed after
/// batching.
///
/// Body-field selection: a pruned request answers in the split form
/// (`pruned_as_hex`). A full request answers in the **non-split** form
/// (`as_hex`) — except that the daemon falls back to the split form when the
/// prunable section is empty, in which case the pruned body *is* the full
/// body, so `pruned_as_hex` is accepted as the fallback. A body served
/// through the fallback still passes [`parse_full_tx`]'s complete validator,
/// so a hostile daemon cannot use the fallback to smuggle a
/// prunable-stripped spend.
pub(crate) fn parse_tx_batch(
    batch: &[[u8; 32]],
    txs: &[TxEntry],
    form: TxBodyForm,
) -> Result<Vec<Transaction>, RpcError> {
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
        if t.tx_hash.to_bytes() != *expected_hash {
            return Err(RpcError::InvalidNode(
                "daemon returned a transaction whose hash did not match the request".to_string(),
            ));
        }
        let tx_hash_hex = t.tx_hash.to_string();
        let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        let parsed = match form {
            TxBodyForm::Pruned => {
                let pruned_hex = non_empty(&t.pruned_as_hex).ok_or_else(|| {
                    RpcError::InvalidNode("transaction response missing pruned_as_hex".to_string())
                })?;
                parse_pruned_tx(&pruned_hex, &tx_hash_hex)?
            }
            TxBodyForm::Full => {
                let full_hex = non_empty(&t.as_hex)
                    .or_else(|| non_empty(&t.pruned_as_hex))
                    .ok_or_else(|| {
                        RpcError::InvalidNode("transaction response missing as_hex".to_string())
                    })?;
                parse_full_tx(&full_hex, &tx_hash_hex)?
            }
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
        // The pruned form takes its prunable digest from the reply, which is
        // also the daemon's to choose — and gains nothing by it. Choosing the
        // digest freely leaves it solving `H(prefix ‖ base ‖ pqc ‖ X) = txid`
        // for `X`, a keccak preimage, not a substitution.
        let recomputed = match form {
            TxBodyForm::Pruned => parsed.hash_with_supplied_prunable(t.prunable_hash.to_bytes()),
            TxBodyForm::Full => parsed.hash(),
        };
        if recomputed != *expected_hash {
            return Err(RpcError::InvalidNode(format!(
                "daemon served a transaction body that is not {tx_hash_hex}: the bytes \
                 hash to {} — a label is not an identity",
                hex::encode(recomputed)
            )));
        }
        out.push(parsed);
    }
    Ok(out)
}

/// Request the global output index of the block's first output (the coinbase's,
/// in practice). `None` only if no transaction in the block has any output.
async fn compute_first_output_index<R: Rpc>(
    rpc: &R,
    block: &Block,
    transactions: &[Transaction],
) -> Result<Option<u64>, RpcError> {
    let miner_hash = block.miner_transaction.hash();
    let candidates = core::iter::once((miner_hash, &block.miner_transaction))
        .chain(block.transaction_hashes.iter().copied().zip(transactions));
    for (hash, tx) in candidates {
        if tx.prefix.outputs.is_empty() {
            continue;
        }
        let index = *rpc.get_o_indexes(hash).await?.first().ok_or_else(|| {
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
