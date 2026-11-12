// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Native `ScannableBlock` fetch over the `shekyl-wire` parse.
//!
//! One `block_show` by height under `prune` carries everything a scan needs:
//! the block's bytes, its non-miner transactions as skeletons, and the global
//! index of its first output. **Parsing is the canonical [`shekyl_wire`]
//! crate's**: [`shekyl_wire::Block::from_bytes`] and
//! [`shekyl_wire::SkeletonTx::bind`].
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
//! `output_index_for_first_ringct_output` played). The block's reply carries
//! it as `output_index`: the coinbase's first output's, which every block
//! pays (RW-Q5). The scanner advances the running index itself, so
//! per-output index requests (a privacy leak) are never made.
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
//! that answers a `prune` request with a whole body (it does not bind), an
//! `archived` slot, or a skeleton missing an operand is refused as an invalid
//! node.
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
//! On top of the validator, [`bind_served`] rejects a coinbase-shaped tx among
//! a block's `tx` or a `tx_list` reply ([`shekyl_wire::Transaction::is_coinbase`])
//! — the coinbase is embedded in the block's bytes and parsed there, never
//! served as a non-miner tx — and [`bind_block_txs`] guards the framing:
//! reordered or miscounted transactions, and an `archived` slot where a
//! skeleton was asked for. The size bounds are `MAX_BLOCK_BLOB_SIZE` /
//! `MAX_TX_SIZE` in [`shekyl_wire::Block::from_bytes`] /
//! [`shekyl_wire::Transaction::from_pruned_bytes`], behind the transport's
//! reply cap. Retiring the scanner's
//! now-redundant defense-in-depth gates (`scan_transaction_with_cancel`'s
//! `MAX_OUTPUTS` / timestamp-form gates) to true belt-and-suspenders is a
//! shekyl-oxide-cutover follow-up tracked in `docs/FOLLOWUPS.md`.

use shekyl_rpc_client::{wire, Rpc, RpcError};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::kinds::{Asked, Bytes, Height, Size};
use shekyl_rpc_types::nullable::Nullable;
use shekyl_rpc_types::wire::block::{BlockSelect, BlockShowSelect, BlockTx};
use shekyl_rpc_types::wire::shared::{OrArchived, Selector};
use shekyl_scanner::ScannableBlock;
use shekyl_types::{ArchivalLength, PqcAuthHash, PrunableHash, TxHash};
use shekyl_wire::{Block, BoundTx, SkeletonTx};

/// The daemon's cap on `tx_list` for a caller that is not the host
/// (`bound.tx`); the proofs workflow's batched locator-tx fetch asks in
/// chunks of this many.
pub(crate) const TXS_PER_REQUEST: usize = 100;

/// The one scannable-block fetch, and `DaemonEngine::fetch_scannable_block`'s
/// default: one `block_show` by height under `prune`, which carries the
/// block's bytes, its non-miner transactions as skeletons with their txid
/// operands, and the global index of its first output (RW-Q5). Also the
/// body behind the `DaemonClient` inherent method and the remote-posture
/// `PBlockSource`, which carry a bare `Rpc` rather than a `DaemonEngine`.
pub(crate) async fn default_fetch_scannable_block<R: Rpc>(
    rpc: &R,
    number: usize,
) -> Result<ScannableBlock, RpcError> {
    let height = u64::try_from(number)
        .map_err(|_| RpcError::InternalError(format!("block height {number} does not fit u64")))?;
    let reply = rpc
        .call::<wire::BlockShow>(BlockShowSelect(BlockSelect {
            select: Selector::Height(Height(height)),
            pow: false,
            prune: Some(true),
        }))
        .await?;
    let block = parse_block_blob(&reply.body.0, number)?;
    let transactions = bind_block_txs(&block.transaction_hashes, &reply.tx)?;

    Ok(ScannableBlock {
        block,
        transactions,
        first_output_index: Some(reply.output_index.0),
    })
}

/// Parse a block's bytes, requiring exact consumption (the `shekyl_wire`
/// canonical-encoding invariant) and that the coinbase `gen` input's height
/// matches the requested `number`.
///
/// `Block::from_bytes` refuses more than `MAX_BLOCK_BLOB_SIZE` bytes up
/// front; the transport's reply cap bounds what the decode of the reply
/// could allocate before that.
fn parse_block_blob(bytes: &[u8], expected_number: usize) -> Result<Block, RpcError> {
    let block =
        Block::from_bytes(bytes).map_err(|_| RpcError::InvalidNode("invalid block".to_string()))?;
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
/// skeleton's txid ignores, so a whole body served where the skeleton was
/// asked for is refused here), then recomputes the txid from the bytes and
/// the three served operands and refuses anything but `expected`. The
/// body it returns is then held to the pruned-safe context-free validator
/// (`validate()`'s prunable-coupled branch cannot run without the prunable
/// region — see [`shekyl_wire::Transaction::validate_context_free_pruned`])
/// and refused if coinbase-shaped: a block's `tx` and `tx_list` carry only
/// NON-miner txs — the coinbase is embedded in the block's bytes and parsed
/// there — so a coinbase here is the daemon serving something it never
/// should, and a misplaced coinbase (with its cleartext `gen` reward
/// output) must never be fed to the scanner.
fn bind_skeleton(skeleton: &SkeletonTx, expected: TxHash) -> Result<BoundTx, RpcError> {
    let bound = skeleton.bind(expected).map_err(|fault| {
        RpcError::InvalidNode(format!(
            "daemon served a body that does not bind to {}: {fault} — a label is not an \
             identity",
            hex::encode(expected.to_bytes())
        ))
    })?;
    bound
        .tx()
        .validate_context_free_pruned()
        .map_err(|_| RpcError::InvalidTransaction(expected.to_bytes()))?;
    if bound.tx().is_coinbase() {
        return Err(RpcError::InvalidTransaction(expected.to_bytes()));
    }
    Ok(bound)
}

/// One transaction as the daemon served it under `prune`: the label, the
/// pruned segment, and the txid's three operands (`SB-Q2`). The same
/// fields on a block's `tx` and on a `tx_list` entry.
pub(crate) struct Served<'a> {
    pub(crate) id: &'a HashHex,
    pub(crate) body: &'a Bytes,
    pub(crate) prunable_hash: &'a HashHex,
    pub(crate) pqc_auth_hash: &'a Nullable<HashHex>,
    pub(crate) archival_size: Size,
}

impl<'a> Served<'a> {
    /// The served transaction, from its fields. Every fetch here asks for
    /// `prune`, so the txid's operands are required: a reply without them
    /// answered a request this client did not send (RW-Q4).
    fn of(
        id: &'a HashHex,
        body: &'a Bytes,
        prunable_hash: &'a Asked<HashHex>,
        pqc_auth_hash: &'a Asked<Nullable<HashHex>>,
        archival_size: Asked<Size>,
    ) -> Result<Self, RpcError> {
        let missing = || {
            RpcError::InvalidNode(
                "daemon answered a prune request without the txid's operands".to_string(),
            )
        };
        let (
            Asked::Present(prunable_hash),
            Asked::Present(pqc_auth_hash),
            Asked::Present(archival_size),
        ) = (prunable_hash, pqc_auth_hash, archival_size)
        else {
            return Err(missing());
        };
        Ok(Self {
            id,
            body,
            prunable_hash,
            pqc_auth_hash,
            archival_size,
        })
    }
}

impl<'a> TryFrom<&'a BlockTx> for Served<'a> {
    type Error = RpcError;
    fn try_from(tx: &'a BlockTx) -> Result<Self, RpcError> {
        Self::of(
            &tx.id,
            &tx.body,
            &tx.prunable_hash,
            &tx.pqc_auth_hash,
            tx.archival_size,
        )
    }
}

impl<'a> TryFrom<&'a wire::tx::TxEntry> for Served<'a> {
    type Error = RpcError;
    fn try_from(tx: &'a wire::tx::TxEntry) -> Result<Self, RpcError> {
        Self::of(
            &tx.id,
            &tx.body,
            &tx.prunable_hash,
            &tx.pqc_auth_hash,
            tx.archival_size,
        )
    }
}

/// Bind one served transaction to the txid asked for.
///
/// The label is checked first — it names the cheap failure — but proves
/// nothing on its own: the daemon chooses the label as freely as the body,
/// so a matching label is only evidence that it wanted to match. The body
/// is then **bound**: the skeleton it is, with the served operands,
/// recomputed to the requested txid.
pub(crate) fn bind_served(expected: TxHash, served: &Served<'_>) -> Result<BoundTx, RpcError> {
    if TxHash::from_bytes(served.id.to_bytes()) != expected {
        return Err(RpcError::InvalidNode(
            "daemon returned a transaction whose hash did not match the request".to_string(),
        ));
    }
    // The skeleton as served: the operands travel with the bytes they
    // were served with, and the binding hashes the skeleton, not a body.
    //
    // **Bind the body to the request, not the label to the request.**
    // Every field is the daemon's to choose, so a canonical transaction
    // under a borrowed label passes every check before this one — and a
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
    let skeleton = SkeletonTx {
        unprunable: served.body.0.clone(),
        prunable_hash: PrunableHash::from_bytes(served.prunable_hash.to_bytes()),
        pqc_auth_hash: served
            .pqc_auth_hash
            .0
            .map(|hash| PqcAuthHash::from_bytes(hash.to_bytes())),
        archival_len: ArchivalLength::from_raw(served.archival_size.0),
    };
    bind_skeleton(&skeleton, expected)
}

/// Bind a block's non-miner transactions, as `block_show` served them under
/// `prune`, to the ids the block's own bytes list.
///
/// Pure (no transport) so the adversarial-daemon checks are unit-testable
/// without an RPC mock. The count must match and each slot binds to the id
/// at its position — an unchecked reorder or substitution would otherwise
/// mis-assign the running global output index (assigned by walking txs in
/// block order) and record wrong txids, exactly the failure the
/// untrusted-node model must reject.
///
/// An `archived` slot is refused as an invalid node (`SB-Q2` item 10): it
/// is the whole form's answer, never the skeleton's — every transaction has
/// a skeleton.
pub(crate) fn bind_block_txs(
    expected: &[TxHash],
    served: &[OrArchived<BlockTx>],
) -> Result<Vec<BoundTx>, RpcError> {
    if served.len() != expected.len() {
        return Err(RpcError::InvalidNode(
            "daemon returned a different number of transactions than the block lists".to_string(),
        ));
    }
    expected
        .iter()
        .zip(served)
        .map(|(id, slot)| match slot {
            OrArchived::Item(tx) => bind_served(*id, &Served::try_from(tx)?),
            OrArchived::Archived(_) => Err(RpcError::InvalidNode(
                "daemon answered a prune request with an archived slot: every transaction has \
                 a skeleton, so the archive is never the pruned form's answer"
                    .to_string(),
            )),
        })
        .collect()
}

#[cfg(test)]
#[path = "block_fetch_tests.rs"]
mod tests;
