// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Native `ScannableBlock` fetch over the `shekyl-wire` parse.
//!
//! This is the engine-side replacement for the legacy
//! `shekyl_rpc::Rpc::get_scannable_block_by_*` path. The transport
//! (`get_block` / `get_transactions` JSON-RPC, `get_o_indexes` binary RPC) is
//! still the vendored [`shekyl_rpc::Rpc`] surface, but **parsing moves to the
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
//! [`shekyl_rpc::Rpc::get_o_indexes`] for the first transaction that has
//! outputs (the coinbase, in practice); the scanner advances the running
//! index itself, so per-output index requests (a privacy leak) are avoided.

use serde_json::{json, Value};
use shekyl_rpc::{Rpc, RpcError};
use shekyl_scanner::ScannableBlock;
use shekyl_wire::{Block, Transaction};

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
    let bytes = hex::decode(pruned_hex)
        .map_err(|_| RpcError::InvalidNode("pruned tx blob wasn't hex".to_string()))?;
    Transaction::from_bytes(&bytes).map_err(|_| invalid_tx_error(tx_hash_hex))
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
            if !missed.is_empty() {
                let missed_hashes = missed
                    .iter()
                    .filter_map(Value::as_str)
                    .filter_map(|s| hex::decode(s).ok())
                    .filter_map(|v| <[u8; 32]>::try_from(v).ok())
                    .collect();
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
        // Fee-only Fcmp = the pruned spend shape: version · prefix · ct(0x01 fee
        // referenceBlock base) then EOF (empty pqc_auths, no prunable).
        let tx = Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(0)],
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
        let mut bytes = Vec::new();
        tx.write(&mut bytes).expect("Vec write is infallible");
        let hexed = hex::encode(&bytes);
        let parsed = parse_pruned_tx(&hexed, "").expect("pruned tx round trips");
        assert_eq!(parsed.prefix.outputs.len(), 1);

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

    /// Hex of a valid pruned tx (fee-only Fcmp shape) that `parse_pruned_tx`
    /// accepts; its hash is irrelevant to these batch tests (the pruned form is
    /// associated by the requested `tx_hash` label, not by re-hashing).
    fn pruned_tx_hex() -> String {
        let tx = Transaction {
            prefix: TxPrefix {
                unlock_time: 0,
                inputs: vec![Input::Gen(0)],
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
        hex::encode(tx.serialize())
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
}
