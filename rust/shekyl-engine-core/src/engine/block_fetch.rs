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
//! is run through the canonical, pruned-safe context-free validator
//! [`shekyl_wire::Transaction::validate_context_free_pruned`] — the consensus-parity
//! reject set (resource bounds, the §2.5 coinbase shape + arm-mixing matrix, the §12
//! key-image canonical form, block-height-only `unlock_time`, committed-base arity)
//! minus the prunable-coupled checks, which cannot run on the *pruned* transactions
//! the wallet ingests (the prunable proof is dropped, and the full
//! [`shekyl_wire::Transaction::validate`] rejects a key-image-bearing spend without it
//! by design). This is the single ingestion gate; it replaces the scattered ad-hoc
//! checks (the standalone `unlock_time` reject, etc.) that accumulated here.
//!
//! On top of the validator, [`parse_pruned_tx`] rejects a coinbase-shaped tx in a
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

use serde_json::{json, Value};
use shekyl_rpc_client::{Rpc, RpcError};
use shekyl_scanner::ScannableBlock;
use shekyl_wire::{block::MAX_BLOCK_BLOB_SIZE, transaction::MAX_TX_SIZE, Block, Transaction};

/// Monero restricts `get_transactions` to 100 hashes per call on the
/// restricted RPC (`core_rpc_server.cpp`); batch accordingly.
const TXS_PER_REQUEST: usize = 100;

/// Default body for `DaemonEngine::fetch_scannable_block`: fetch the block at
/// `number`, its pruned non-miner transactions, and the first global output
/// index, parsing everything through [`shekyl_wire`].
pub(crate) async fn default_fetch_scannable_block<R: Rpc>(
    rpc: &R,
    number: usize,
) -> Result<ScannableBlock, RpcError> {
    let res: Value = rpc
        .json_rpc_call("get_block", Some(json!({ "height": number })))
        .await?;
    let blob = res
        .get("blob")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidNode("get_block response missing blob".to_string()))?;
    let block = parse_block_blob(blob, number)?;

    let transactions = fetch_pruned_transactions(rpc, &block.transaction_hashes).await?;
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
    // DoS pre-bound: `hex::decode` allocates ~`pruned_hex.len() / 2` bytes, so
    // bound the *input* length before decoding — otherwise a hostile daemon
    // could force a large allocation that `from_bytes`'s own `MAX_TX_SIZE`
    // guard only catches after the decode. A pruned blob is at most a full tx
    // (`MAX_TX_SIZE` bytes ⇒ `2 * MAX_TX_SIZE` hex chars).
    if pruned_hex.len() > MAX_TX_SIZE.saturating_mul(2) {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    let bytes = hex::decode(pruned_hex)
        .map_err(|_| RpcError::InvalidNode("pruned tx blob wasn't hex".to_string()))?;
    let tx = Transaction::from_bytes(&bytes).map_err(|_| invalid_tx_error(tx_hash_hex))?;
    // Canonical-shape gate: the daemon is untrusted, so reject any tx that is not a
    // well-formed, block-height-only Shekyl transaction before it reaches the scanner.
    // This is the pruned-safe context-free subset of the consensus-parity validator
    // (the wallet ingests pruned txs, so `validate()`'s prunable-coupled branch cannot
    // run — see `shekyl_wire::Transaction::validate_context_free_pruned`).
    tx.validate_context_free_pruned()
        .map_err(|_| invalid_tx_error(tx_hash_hex))?;
    // `get_transactions` returns only NON-miner txs — the coinbase is embedded in the
    // block blob and parsed there. A coinbase-shaped tx in this response is the daemon
    // serving something it never should; reject it so a misplaced coinbase (with its
    // cleartext `gen` reward output) can never be fed to the scanner.
    if tx.is_coinbase() {
        return Err(invalid_tx_error(tx_hash_hex));
    }
    Ok(tx)
}

/// Build the error for a pruned-tx parse failure, preferring the daemon-named
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

/// Fetch and parse the pruned non-miner transactions named by `hashes`,
/// batching by [`TXS_PER_REQUEST`].
async fn fetch_pruned_transactions<R: Rpc>(
    rpc: &R,
    hashes: &[[u8; 32]],
) -> Result<Vec<Transaction>, RpcError> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }
    let mut transactions = Vec::with_capacity(hashes.len());
    for batch in hashes.chunks(TXS_PER_REQUEST) {
        let hashes_hex: Vec<String> = batch.iter().map(hex::encode).collect();
        let resp: Value = rpc
            .rpc_call(
                "get_transactions",
                Some(json!({ "txs_hashes": hashes_hex, "prune": true })),
            )
            .await?;

        if let Some(missed) = resp.get("missed_tx").and_then(Value::as_array) {
            if let Some(missed_hashes) = parse_missed_tx(missed)? {
                return Err(RpcError::TransactionsNotFound(missed_hashes));
            }
        }

        let txs = resp.get("txs").and_then(Value::as_array).ok_or_else(|| {
            RpcError::InvalidNode("get_transactions response missing txs".to_string())
        })?;
        transactions.extend(parse_tx_batch(batch, txs)?);
    }

    Ok(transactions)
}

/// Validate one `get_transactions` batch response against the `batch` of
/// requested hashes (in order) and parse each pruned tx.
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
/// reject. Per-batch equality also makes the caller's total length exact, so no
/// separate cardinality check is needed after batching.
fn parse_tx_batch(batch: &[[u8; 32]], txs: &[Value]) -> Result<Vec<Transaction>, RpcError> {
    if txs.len() != batch.len() {
        return Err(RpcError::InvalidNode(
            "daemon returned a different number of transactions than requested".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(batch.len());
    for (expected_hash, t) in batch.iter().zip(txs) {
        let tx_hash_hex = t.get("tx_hash").and_then(Value::as_str).unwrap_or("");
        let claimed = hex::decode(tx_hash_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok());
        if claimed.as_ref() != Some(expected_hash) {
            return Err(RpcError::InvalidNode(
                "daemon returned a transaction whose hash did not match the request".to_string(),
            ));
        }
        let pruned_hex = t
            .get("pruned_as_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                RpcError::InvalidNode("transaction response missing pruned_as_hex".to_string())
            })?;
        out.push(parse_pruned_tx(pruned_hex, tx_hash_hex)?);
    }
    Ok(out)
}

/// Strictly parse a `get_transactions` `missed_tx` array into the missing-hash
/// set. `Ok(None)` when nothing is missing; `Ok(Some(hashes))` when one or more
/// requested txs are absent.
///
/// Pure (no transport) so the strictness is unit-testable. Every entry must be
/// a 32-byte hex hash: a `filter_map` chain would silently drop malformed
/// entries, shrinking (or emptying) the reported set and misrepresenting which
/// txs are missing. A malformed entry is a daemon protocol violation, not a
/// missing tx, so it surfaces as [`RpcError::InvalidNode`] rather than a
/// truncated [`RpcError::TransactionsNotFound`].
fn parse_missed_tx(missed: &[Value]) -> Result<Option<Vec<[u8; 32]>>, RpcError> {
    if missed.is_empty() {
        return Ok(None);
    }
    let mut hashes = Vec::with_capacity(missed.len());
    for m in missed {
        let hash = m
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| {
                RpcError::InvalidNode(
                    "get_transactions returned a malformed missed_tx hash".to_string(),
                )
            })?;
        hashes.push(hash);
    }
    Ok(Some(hashes))
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

    use shekyl_wire::transaction::UNLOCK_TIME_BLOCK_SENTINEL;
    use shekyl_wire::{BlockHeader, Ct, CtBase, Input, Output, TxPrefix};

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

    fn tx_entry(tx_hash_hex: &str, pruned_hex: &str) -> Value {
        json!({ "tx_hash": tx_hash_hex, "pruned_as_hex": pruned_hex })
    }

    #[test]
    fn parse_tx_batch_accepts_in_order() {
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let blob = pruned_tx_hex();
        let txs = vec![
            tx_entry(&hex::encode(h0), &blob),
            tx_entry(&hex::encode(h1), &blob),
        ];
        let out = parse_tx_batch(&[h0, h1], &txs).expect("in-order batch parses");
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
            parse_tx_batch(&[h0, h1], &txs),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_rejects_count_mismatch() {
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let blob = pruned_tx_hex();
        let txs = vec![tx_entry(&hex::encode(h0), &blob)];
        assert!(matches!(
            parse_tx_batch(&[h0, h1], &txs),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_rejects_absent_or_unparseable_hash() {
        // No `tx_hash` field → no association handle → reject (a daemon that
        // omits the label cannot be order-pinned).
        let h0 = [3u8; 32];
        let blob = pruned_tx_hex();
        let txs = vec![json!({ "pruned_as_hex": blob })];
        assert!(matches!(
            parse_tx_batch(&[h0], &txs),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_rejects_missing_pruned_blob() {
        let h0 = [3u8; 32];
        let txs = vec![json!({ "tx_hash": hex::encode(h0) })];
        assert!(matches!(
            parse_tx_batch(&[h0], &txs),
            Err(RpcError::InvalidNode(_))
        ));
    }

    #[test]
    fn parse_tx_batch_empty_is_ok() {
        let out = parse_tx_batch(&[], &[]).expect("empty batch parses");
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
    fn parse_missed_tx_empty_is_none() {
        assert!(parse_missed_tx(&[]).expect("empty is ok").is_none());
    }

    #[test]
    fn parse_missed_tx_parses_valid_hashes() {
        let (h0, h1) = ([3u8; 32], [4u8; 32]);
        let missed = vec![json!(hex::encode(h0)), json!(hex::encode(h1))];
        let parsed = parse_missed_tx(&missed)
            .expect("valid hashes parse")
            .expect("non-empty");
        assert_eq!(parsed, vec![h0, h1]);
    }

    #[test]
    fn parse_missed_tx_rejects_malformed_entry() {
        // Each entry must be a 32-byte hex hash. A non-hex string, a short
        // hash, a non-string, or null is a protocol violation — not a silently
        // dropped missing tx.
        let h0 = [3u8; 32];
        for bad in [json!("zz"), json!("00"), json!(7), json!(null)] {
            let missed = vec![json!(hex::encode(h0)), bad];
            assert!(matches!(
                parse_missed_tx(&missed),
                Err(RpcError::InvalidNode(_))
            ));
        }
    }
}
