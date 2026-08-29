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
///   dropped by the daemon (`prune: true`), so the body cannot be re-hashed to
///   its committed tx hash (`GENESIS_TX_WIRE_FORMAT.md` §11 — the pruned form
///   hashes differently); association is by the daemon-echoed `tx_hash` label,
///   and validation is the pruned-safe context-free subset.
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
/// The pruned form is not re-hashed (it hashes differently — §11); association
/// to a block hash is pinned by [`parse_tx_batch`], which checks each returned
/// `tx_hash` against the requested hash, in order.
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
/// for its slot. The pruned blob is not re-hashed (it hashes differently —
/// `GENESIS_TX_WIRE_FORMAT.md` §11), so the `tx_hash` label is the only
/// association handle; an unchecked reorder or substitution would mis-assign
/// the running global output index (assigned by walking txs in block order)
/// and record wrong txids — exactly the failure the untrusted-node model must
/// reject. (Full-form consumers additionally recompute each body's hash — the
/// P-scan's SP-6 exhaustiveness gate — so for them the label check is the
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
        // what is left to check is the association: the label must be the one
        // this slot asked for.
        if t.tx_hash.to_bytes() != *expected_hash {
            return Err(RpcError::InvalidNode(
                "daemon returned a transaction whose hash did not match the request".to_string(),
            ));
        }
        let tx_hash_hex = t.tx_hash.to_string();
        let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        match form {
            TxBodyForm::Pruned => {
                let pruned_hex = non_empty(&t.pruned_as_hex).ok_or_else(|| {
                    RpcError::InvalidNode("transaction response missing pruned_as_hex".to_string())
                })?;
                out.push(parse_pruned_tx(&pruned_hex, &tx_hash_hex)?);
            }
            TxBodyForm::Full => {
                let full_hex = non_empty(&t.as_hex)
                    .or_else(|| non_empty(&t.pruned_as_hex))
                    .ok_or_else(|| {
                        RpcError::InvalidNode("transaction response missing as_hex".to_string())
                    })?;
                out.push(parse_full_tx(&full_hex, &tx_hash_hex)?);
            }
        }
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
mod tests {
    use super::*;
    use core::future::Future;
    use shekyl_rpc_types::HashHex;

    use shekyl_wire::transaction::UNLOCK_TIME_BLOCK_SENTINEL;
    use shekyl_wire::{BlockHeader, Ct, CtBase, Input, Output, TxPrefix};

    /// A daemon that answers every route with one fixed document, so a test
    /// can hand the consumer a reply the wire permits but the contract does
    /// not — here, a refusal carrying a body.
    #[derive(Clone)]
    struct CannedDaemon(std::sync::Arc<Vec<u8>>);

    impl Rpc for CannedDaemon {
        fn post(
            &self,
            _route: &str,
            _body: Vec<u8>,
        ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
            let doc = self.0.clone();
            async move { Ok(doc.as_ref().clone()) }
        }
    }

    /// **A refusal is not evidence, even when it comes with a body.**
    ///
    /// `rpc_call` only deserializes, so a daemon may answer a non-OK `status`
    /// *and* a complete, plausible entry in one document. The body here is
    /// built to clear every check downstream of the status — the count
    /// matches, the entry's `tx_hash` equals the requested hash (the blob is
    /// deliberately not re-hashed, see `parse_tx_batch`), and the pruned blob
    /// is a transaction `parse_pruned_tx` accepts. So without the status check
    /// this call **succeeds** and hands back a transaction the daemon declined
    /// to vouch for; that is the hazard, not a parse error arriving late.
    #[tokio::test]
    async fn a_refusal_carrying_a_body_is_refused_not_parsed() {
        let txid = [0x31u8; 32];
        let mut body = Vec::new();
        pruned_spend_tx(0)
            .write(&mut body)
            .expect("Vec write is infallible");
        let reply = shekyl_rpc_types::GetTransactionsResponse {
            status: shekyl_rpc_types::RpcStatus("Failed".to_owned()),
            txs: vec![TxEntry {
                tx_hash: HashHex::from_bytes(txid),
                as_hex: String::new(),
                pruned_as_hex: hex::encode(&body),
                prunable_as_hex: String::new(),
                prunable_hash: HashHex::from_bytes([0x5A; 32]),
                as_json: String::new(),
                pruned: false,
                double_spend_seen: false,
                location: shekyl_rpc_types::TxLocation::Mined {
                    block_height: 3,
                    block_timestamp: 1_700_000_000,
                    confirmations: 1,
                    output_indices: vec![1],
                },
            }],
            missed_tx: Vec::new(),
        };
        let rpc = CannedDaemon(std::sync::Arc::new(
            serde_json::to_vec(&reply).expect("wire type serializes"),
        ));

        let err = fetch_transactions(&rpc, &[txid], TxBodyForm::Pruned)
            .await
            .expect_err("a refusal must not be accepted as transactions");
        let text = format!("{err}");
        assert!(
            text.contains("get_transactions refused") && text.contains("not evidence"),
            "the refusal must name itself rather than surface as some later \
             failure: {text}"
        );
    }

    /// A coinbase-only block at `number` with one tagged-key output whose
    /// `Null` ct carries a committed base (the shape the legacy parse dropped).
    fn coinbase_block(number: u64) -> Block {
        Block {
            header: BlockHeader {
                major_version: 1,
                minor_version: 0,
                timestamp: 1,
                previous: [0u8; 32],
                nonce: 0,
                curve_tree_root: [0u8; 32],
                attestation_root: shekyl_archival_retention::empty_attestation_root(),
            },
            miner_transaction: Transaction {
                prefix: TxPrefix {
                    unlock_time: 0,
                    inputs: vec![Input::Gen(number)],
                    outputs: vec![Output {
                        amount: 0,
                        key: [1u8; 32],
                        view_tag: 0,
                    }],
                    extra: vec![],
                },
                ct: Ct::Null(CtBase {
                    enc_amounts: vec![[7u8; 9]],
                    enc_labels: vec![[9u8; 9]],
                    commitments: vec![[2u8; 32]],
                }),
            },
            transaction_hashes: vec![],
        }
    }

    #[test]
    fn parse_block_blob_accepts_coinbase_null_with_committed_base() {
        // Regression anchor for the shekyl-oxide → shekyl-wire migration: a
        // coinbase whose `Null` ct carries a committed base (enc_amounts /
        // enc_labels / outPk per GENESIS §9.6) must parse. The legacy
        // shekyl-oxide `Block::read` dropped the coinbase committed base and
        // rejected live daemon blocks as `InvalidNode("invalid block")`.
        let block = coinbase_block(5);
        let blob = hex::encode(block.serialize());
        let parsed = parse_block_blob(&blob, 5).expect("coinbase-with-base parses");
        assert_eq!(parsed.number(), Some(5));
        match &parsed.miner_transaction.ct {
            Ct::Null(base) => {
                assert_eq!(base.commitments.len(), 1, "committed base preserved");
                assert_eq!(base.enc_amounts.len(), 1);
                assert_eq!(base.enc_labels.len(), 1);
            }
            other => panic!("coinbase ct must be Null, got {other:?}"),
        }
    }

    #[test]
    fn parse_block_blob_rejects_height_mismatch() {
        let block = coinbase_block(5);
        let blob = hex::encode(block.serialize());
        assert!(matches!(
            parse_block_blob(&blob, 6),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_block_blob_rejects_non_hex_and_garbage() {
        assert!(matches!(
            parse_block_blob("zz", 0),
            Err(RpcError::InvalidNode(_))
        ));
        assert!(matches!(
            parse_block_blob("00ff", 0),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_pruned_tx_round_trips_and_rejects_trailing() {
        // A pruned non-miner spend: ToKey (key-image) input, 2 outputs (the anti-deanon
        // minimum), prunable proof + pqc_auths dropped — round-trips through from_bytes.
        let tx = pruned_spend_tx(0);
        let mut bytes = Vec::new();
        tx.write(&mut bytes).expect("Vec write is infallible");
        let hexed = hex::encode(&bytes);
        let parsed = parse_pruned_tx(&hexed, "").expect("pruned tx round trips");
        assert_eq!(parsed.prefix.outputs.len(), 2);

        let mut trailing = bytes.clone();
        trailing.push(0xAB);
        assert!(matches!(
            parse_pruned_tx(&hex::encode(&trailing), ""),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_pruned_tx_rejects_non_hex() {
        assert!(matches!(
            parse_pruned_tx("zz", ""),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_pruned_tx_rejects_coinbase_shaped() {
        // `get_transactions` returns only non-miner txs (the coinbase is embedded in
        // the block blob and parsed there). A coinbase served here — whether a clean
        // `[gen] + Null` coinbase or the non-canonical `gen + Fcmp` mix — must be
        // rejected, never fed to the scanner (it would otherwise carry a cleartext
        // `gen` reward output the wallet has no business ingesting from this path).
        let real_coinbase = Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(7)],
                outputs: vec![Output {
                    amount: 0,
                    key: [1u8; 32],
                    view_tag: 0,
                }],
                extra: vec![],
            },
            ct: Ct::Null(CtBase {
                enc_amounts: vec![[0u8; 9]],
                enc_labels: vec![[0u8; 9]],
                commitments: vec![[2u8; 32]],
            }),
        };
        // A valid coinbase passes the context-free validator, then is_coinbase rejects it.
        assert!(real_coinbase.validate_context_free_pruned().is_ok());
        assert!(matches!(
            parse_pruned_tx(&hex::encode(real_coinbase.serialize()), ""),
            Err(RpcError::InvalidNode(_))
        ));

        // The non-canonical `gen + Fcmp` mix is rejected by the validator itself
        // (a coinbase must carry a Null ct, §2.5).
        let gen_fcmp = Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(7)],
                outputs: vec![Output {
                    amount: 0,
                    key: [1u8; 32],
                    view_tag: 0,
                }],
                extra: vec![],
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: [0u8; 32],
                base: CtBase {
                    enc_amounts: vec![[0u8; 9]],
                    enc_labels: vec![[0u8; 9]],
                    commitments: vec![[2u8; 32]],
                },
                pqc_auths: vec![],
                prunable: None,
            },
        };
        assert!(gen_fcmp.validate_context_free_pruned().is_err());
        assert!(matches!(
            parse_pruned_tx(&hex::encode(gen_fcmp.serialize()), ""),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_pruned_tx_rejects_single_output_spend() {
        // A non-miner spend (key-image input) must have >= 2 outputs (anti-deanon,
        // GENESIS §10); a 1-output spend is non-canonical, so the untrusted-daemon
        // ingestion boundary rejects it rather than handing the scanner phantom state.
        let mut tx = pruned_spend_tx(0);
        tx.prefix.outputs.truncate(1);
        if let Ct::Fcmp { base, .. } = &mut tx.ct {
            base.enc_amounts.truncate(1);
            base.enc_labels.truncate(1);
            base.commitments.truncate(1);
        }
        assert!(matches!(
            parse_pruned_tx(&hex::encode(tx.serialize()), ""),
            Err(RpcError::InvalidNode(_))
        ));
    }

    /// A valid pruned non-miner spend: a `ToKey` key-image input, **2 outputs** (the
    /// anti-deanonymization minimum the ingestion validator enforces), with the prunable
    /// proof + pqc_auths dropped. The shared fixture for the `parse_pruned_tx` /
    /// `parse_tx_batch` tests; `unlock_time` is varied for the block-height-only gate.
    fn pruned_spend_tx(unlock_time: u64) -> Transaction {
        Transaction {
            prefix: TxPrefix {
                unlock_time,
                inputs: vec![Input::ToKey {
                    amount: 0,
                    key_offsets: vec![],
                    key_image: [0x42u8; 32],
                }],
                outputs: vec![
                    Output {
                        amount: 0,
                        key: [1u8; 32],
                        view_tag: 0,
                    },
                    Output {
                        amount: 0,
                        key: [3u8; 32],
                        view_tag: 1,
                    },
                ],
                extra: vec![],
            },
            ct: Ct::Fcmp {
                fee: 0,
                reference_block: [0u8; 32],
                base: CtBase {
                    enc_amounts: vec![[0u8; 9], [0u8; 9]],
                    enc_labels: vec![[0u8; 9], [0u8; 9]],
                    commitments: vec![[2u8; 32], [3u8; 32]],
                },
                pqc_auths: vec![],
                prunable: None,
            },
        }
    }

    /// Hex of a valid pruned non-miner tx that `parse_pruned_tx` accepts; its hash is
    /// irrelevant to the batch tests (the pruned form is associated by the requested
    /// `tx_hash` label, not by re-hashing).
    fn pruned_tx_hex() -> String {
        hex::encode(pruned_spend_tx(0).serialize())
    }

    /// A **full** (unpruned) non-miner spend: [`pruned_spend_tx`] with the
    /// prunable-coupled sections restored — one aggregated Bp+, one pseudo-out per
    /// `ToKey` input, one `pqc_auths` slot per input — so it passes the complete
    /// [`shekyl_wire::Transaction::validate`]. Proof bytes are zeroed placeholders:
    /// the context-free validator checks structure (counts/arities), not proof math.
    fn full_spend_tx() -> Transaction {
        use shekyl_wire::transaction::{PQC_HYBRID_SINGLE_KEY_LEN, PQC_HYBRID_SINGLE_SIG_LEN};
        use shekyl_wire::{BpPlus, PqcAuth, Prunable};

        let mut tx = pruned_spend_tx(0);
        let Ct::Fcmp {
            pqc_auths,
            prunable,
            ..
        } = &mut tx.ct
        else {
            unreachable!("pruned_spend_tx is Fcmp by construction");
        };
        *pqc_auths = vec![PqcAuth {
            auth_version: 1,
            scheme_id: 1,
            flags: 0,
            hybrid_public_key: vec![0u8; PQC_HYBRID_SINGLE_KEY_LEN],
            hybrid_signature: vec![0u8; PQC_HYBRID_SINGLE_SIG_LEN],
        }];
        *prunable = Some(Prunable {
            // Spend fixture: no pass records (RF-D1).
            serve_credit_pruned: Vec::new(),
            bulletproofs: vec![BpPlus {
                a: [0; 32],
                a1: [0; 32],
                b: [0; 32],
                r1: [0; 32],
                s1: [0; 32],
                d1: [0; 32],
                l: vec![[0; 32]; 7],
                r: vec![[0; 32]; 7],
            }],
            tree_depth: 1,
            fcmp_proof: vec![0u8; 8],
            pseudo_outs: vec![[0; 32]],
        });
        tx
    }

    /// A reply entry built from the wire type rather than a JSON literal, so
    /// the double cannot describe a shape the daemon does not produce (RK-D1).
    /// The mined arm, because these fixtures stand in for confirmed txs.
    fn tx_entry_with(tx_hash: [u8; 32], as_hex: &str, pruned_as_hex: &str) -> TxEntry {
        TxEntry {
            tx_hash: HashHex::from_bytes(tx_hash),
            as_hex: as_hex.to_owned(),
            pruned_as_hex: pruned_as_hex.to_owned(),
            prunable_as_hex: String::new(),
            prunable_hash: HashHex::from_bytes([0u8; 32]),
            as_json: String::new(),
            pruned: false,
            double_spend_seen: false,
            location: shekyl_rpc_types::TxLocation::Mined {
                block_height: 1,
                confirmations: 1,
                block_timestamp: 0,
                output_indices: Vec::new(),
            },
        }
    }

    fn tx_entry(tx_hash_hex: &str, pruned_hex: &str) -> TxEntry {
        let bytes: [u8; 32] = hex::decode(tx_hash_hex)
            .expect("test hash is hex")
            .try_into()
            .expect("test hash is 32 bytes");
        tx_entry_with(bytes, "", pruned_hex)
    }

    #[test]
    fn parse_tx_batch_accepts_in_order() {
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let blob = pruned_tx_hex();
        let txs = vec![
            tx_entry(&hex::encode(h0), &blob),
            tx_entry(&hex::encode(h1), &blob),
        ];
        let out =
            parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned).expect("in-order batch parses");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn parse_tx_batch_rejects_reordered_hashes() {
        // The daemon returns both requested txs but with their `tx_hash` labels
        // in swapped slots. Running global-output-index assignment depends on
        // block order, so a reorder must be rejected even though each tx is
        // individually valid (the adversarial-daemon mis-association case).
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let blob = pruned_tx_hex();
        let txs = vec![
            tx_entry(&hex::encode(h1), &blob),
            tx_entry(&hex::encode(h0), &blob),
        ];
        assert!(matches!(
            parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_rejects_count_mismatch() {
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let blob = pruned_tx_hex();
        let txs = vec![tx_entry(&hex::encode(h0), &blob)];
        assert!(matches!(
            parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Pruned),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn a_reply_without_a_tx_hash_label_is_refused_at_the_boundary() {
        // No `tx_hash` → no association handle → a daemon that omits the label
        // cannot be order-pinned. This used to be `parse_tx_batch`'s rejection;
        // with the shared wire type the field is required, so the refusal now
        // happens when the reply decodes and the malformed entry never reaches
        // the batch check. The guard moved — this test moved with it rather
        // than being dropped as "covered elsewhere".
        let blob = pruned_tx_hex();
        let doc = serde_json::json!({
            "status": "OK",
            "txs": [{
                "as_hex": "", "pruned_as_hex": blob, "prunable_as_hex": "",
                "prunable_hash": "00".repeat(32), "as_json": "",
                "in_pool": false, "double_spend_seen": false,
                "block_height": 1, "confirmations": 1, "block_timestamp": 0
            }]
        })
        .to_string();
        assert!(
            serde_json::from_str::<shekyl_rpc_types::GetTransactionsResponse>(&doc).is_err(),
            "an entry with no tx_hash must not decode"
        );
    }

    #[test]
    fn parse_tx_batch_rejects_missing_pruned_blob() {
        let h0 = [3u8; 32];
        let txs = vec![tx_entry_with(h0, "", "")];
        assert!(matches!(
            parse_tx_batch(&[h0], &txs, TxBodyForm::Pruned),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_empty_is_ok() {
        let out = parse_tx_batch(&[], &[], TxBodyForm::Pruned).expect("empty batch parses");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_tx_batch_full_form_reads_as_hex_with_pruned_fallback() {
        // The full form's primary field is the non-split `as_hex`; when the
        // daemon answers in the split form because the prunable section is
        // empty, `pruned_as_hex` IS the full body, so it is the accepted
        // fallback. (Our fixture's pruned form is a stripped spend, which the
        // full validator rejects — so the fallback leg uses the full blob under
        // the `pruned_as_hex` key, exactly the daemon's empty-prunable shape.)
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let full_hex = hex::encode(full_spend_tx().serialize());
        let txs = vec![
            tx_entry_with(h0, &full_hex, ""),
            tx_entry_with(h1, "", &full_hex),
        ];
        let out = parse_tx_batch(&[h0, h1], &txs, TxBodyForm::Full).expect("full batch parses");
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|tx| matches!(&tx.ct, Ct::Fcmp { prunable, .. } if prunable.is_some())),
            "full-form bodies carry their prunable section"
        );
    }

    #[test]
    fn parse_full_tx_rejects_a_prunable_stripped_spend_naming_the_pruned_daemon() {
        // The fallback tripwire: a daemon answering a full-body request with
        // a storage-pruned spend (key-image inputs, prunable dropped) is
        // rejected at the ingestion boundary — it cannot survive to a bogus
        // null-prunable hash downstream. And because this exact shape is
        // what a storage-pruned daemon (a supported mode) serves for every
        // historical spend, the refusal must NAME that cause and its remedy
        // (rule 82) — a generic "invalid transaction" would tell the
        // operator their trusted node is corrupt, with no path out.
        let stripped_hex = pruned_tx_hex();
        match parse_full_tx(&stripped_hex, "") {
            Err(RpcError::InvalidNode(msg)) => {
                assert!(
                    msg.contains("storage-pruned") && msg.contains("UNPRUNED"),
                    "the refusal must name the pruned-daemon cause and remedy: {msg}"
                );
            }
            other => panic!("expected a cause-naming InvalidNode, got {other:?}"),
        }
        // The same blob is fine on the pruned path — the split is the form, not
        // the tx.
        parse_pruned_tx(&stripped_hex, "").expect("pruned form accepts the stripped spend");

        // A body that is malformed BEYOND the missing prunable section (a
        // single-output spend violates the anti-deanon minimum) keeps the
        // generic verdict — the pruned-daemon message must not blanket
        // genuinely invalid bodies.
        let mut malformed = pruned_spend_tx(0);
        malformed.prefix.outputs.truncate(1);
        if let Ct::Fcmp { base, .. } = &mut malformed.ct {
            base.enc_amounts.truncate(1);
            base.enc_labels.truncate(1);
            base.commitments.truncate(1);
        }
        match parse_full_tx(&hex::encode(malformed.serialize()), "") {
            Err(RpcError::InvalidNode(msg)) => {
                assert!(
                    !msg.contains("storage-pruned"),
                    "a malformed body must not draw the pruned-daemon verdict: {msg}"
                );
            }
            other => panic!("expected generic InvalidNode, got {other:?}"),
        }
    }

    #[test]
    fn parse_tx_batch_full_form_requires_a_body_field() {
        let h0 = [3u8; 32];
        let txs = vec![tx_entry_with(h0, "", "")];
        assert!(matches!(
            parse_tx_batch(&[h0], &txs, TxBodyForm::Full),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_empty_is_ok_full_form_too() {
        let out = parse_tx_batch(&[], &[], TxBodyForm::Full).expect("empty batch parses");
        assert!(out.is_empty());
    }

    /// Hex of a valid pruned non-miner spend with the given `unlock_time` — for the
    /// block-height-only ingestion gate tests.
    fn pruned_tx_hex_with_unlock_time(unlock_time: u64) -> String {
        hex::encode(pruned_spend_tx(unlock_time).serialize())
    }

    #[test]
    fn parse_pruned_tx_rejects_timestamp_form_unlock_time() {
        // A structurally valid pruned tx whose `unlock_time` is the timestamp
        // form is non-canonical (consensus rejects it — GENESIS §9 creation
        // cut); ingestion must refuse it so the scanner never sees it.
        let bad = pruned_tx_hex_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL);
        assert!(matches!(
            parse_pruned_tx(&bad, ""),
            Err(RpcError::InvalidNode(_))
        ));
        // The largest block-form value still parses.
        let ok = pruned_tx_hex_with_unlock_time(UNLOCK_TIME_BLOCK_SENTINEL - 1);
        assert!(parse_pruned_tx(&ok, "").is_ok());
    }

    #[test]
    fn parse_pruned_tx_rejects_oversized_hex_before_decode() {
        // DoS pre-bound: a hex string longer than `2 * MAX_TX_SIZE` is rejected
        // by length before `hex::decode` allocates. All-hex chars of even
        // length, so only the length gate (not a decode error) can fire.
        let oversized = "0".repeat(MAX_TX_SIZE * 2 + 2);
        assert!(parse_pruned_tx(&oversized, "").is_err());
    }

    #[test]
    fn parse_block_blob_rejects_oversized_hex_before_decode() {
        // DoS pre-bound: a hex string longer than `2 * MAX_BLOCK_BLOB_SIZE` is
        // rejected by length before `hex::decode` allocates. All-hex chars of
        // even length, so only the length gate (not a decode error) can fire.
        let oversized = "0".repeat(MAX_BLOCK_BLOB_SIZE * 2 + 2);
        assert!(matches!(
            parse_block_blob(&oversized, 0),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_block_blob_rejects_timestamp_form_coinbase() {
        // Defense-in-depth: a canonical coinbase is `height + 60` (block form);
        // the timestamp form is rejected at ingestion too.
        let mut block = coinbase_block(5);
        block.miner_transaction.prefix.unlock_time = UNLOCK_TIME_BLOCK_SENTINEL;
        let blob = hex::encode(block.serialize());
        assert!(matches!(
            parse_block_blob(&blob, 5),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn missed_tx_hashes_survive_the_typed_reply() {
        // `missed_tx` used to be walked entry-by-entry by `parse_missed_tx`.
        // It is `Vec<HashHex>` on the shared reply type now, so the walk is
        // gone — but the two properties it existed for are not, and they are
        // asserted here against the type that replaced it: valid hashes come
        // through in order, and a malformed entry is refused rather than
        // silently dropped, which would shrink the reported missing set and
        // misreport which transactions are absent.
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let doc = |entries: String| format!(r#"{{"status":"OK","missed_tx":[{entries}]}}"#);
        let ok = doc(format!("\"{}\",\"{}\"", hex::encode(h0), hex::encode(h1)));
        let parsed: shekyl_rpc_types::GetTransactionsResponse =
            serde_json::from_str(&ok).expect("valid hashes decode");
        assert_eq!(
            parsed
                .missed_tx
                .iter()
                .copied()
                .map(shekyl_rpc_types::HashHex::to_bytes)
                .collect::<Vec<_>>(),
            vec![h0, h1]
        );

        for bad in ["\"zz\"", "\"00\"", "7", "null"] {
            let malformed = doc(format!("\"{}\",{bad}", hex::encode(h0)));
            assert!(
                serde_json::from_str::<shekyl_rpc_types::GetTransactionsResponse>(&malformed)
                    .is_err(),
                "a malformed missed_tx entry ({bad}) must be refused, not dropped"
            );
        }
    }
}
