// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona body-store fill for one shard (`WSS-Q4`,
//! `docs/design/WALLET_SIDE_STORE.md` §6.5).
//!
//! The persona scan has already verified the chain and sealed, for each
//! closed shard, where it closed and the digest of its in-domain
//! transactions' rows ([`ShardClose`]). The fill re-reads the shard's blocks
//! from the wallet's own daemon, pins both ends of that walk to the seal,
//! asks for each member transaction's whole body (`tx_list` without
//! `prune`), checks every body against the txid-bound parts the walk
//! placed, frames the shard, checks the frame's rows digest against the
//! seal, and hands the frame to the body-store actor, which writes it in one
//! transaction. Nothing here takes a block, a total or a body on the
//! daemon's word: a reply that does not agree with the seal is a
//! [`FillMismatch`], loud and nothing written.
//!
//! The store never talks to the daemon (`R1`, `WSS-17`); this module is the
//! one place that reads a daemon for it, on the persona's loopback
//! transport.

use shekyl_engine_state::pscan_cursor::ShardSpan;
use shekyl_rpc_client::{wire, Rpc, RpcError};
use shekyl_rpc_types::hash::HashHex;
use shekyl_rpc_types::wire::shared::{Slot, SlotState};
use shekyl_rpc_types::wire::tx::TxListQuery;
use shekyl_types::{
    ArchivalLength, BlockCount, BlockHash, BlockHeight, ShardId, ShardRowsDigest, TxHash,
};
use shekyl_wire::shard_frame::{
    encode_frame, frame_rows_digest, rows_digest_step, rows_of_parts, FrameTx,
};
use shekyl_wire::{Ct, Transaction, TxSegments, TxidParts};

use super::body_store_actor::BodyStoreHandle;
use crate::engine::block_fetch::{default_fetch_scannable_block, TXS_PER_REQUEST};
use crate::engine::pscan::exhaustiveness::domain_shard;

/// What the daemon said that the persona scan's seal says otherwise.
///
/// Every arm means the daemon's reply is not the chain the scan verified
/// (or, for [`Self::FrameDisagrees`], that the frame built from verified
/// bodies does not reproduce the sealed digest). The fill writes nothing,
/// and the operator is told: bonding against a body the daemon got wrong is
/// how a persona is slashed (`WALLET_SIDE_STORE.md` §6.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FillMismatch {
    /// A block of the walk is not the block the scan verified at that height:
    /// an end whose hash is not the sealed close's, or a link that does not
    /// chain.
    #[error("block {height} is not the block the persona scan verified")]
    OffTheScannedChain { height: BlockHeight },
    /// The daemon's running archival total, or the total the walk reaches at
    /// the shard's closing block, disagrees with the transactions' bound
    /// lengths and the seal.
    #[error("block {height}'s archival total disagrees with its transactions")]
    TotalsDisagree { height: BlockHeight },
    /// The daemon says it holds no such transaction, though its own block
    /// lists it.
    #[error("the daemon has no transaction {txid}, which its own block lists")]
    Missing { txid: TxHash },
    /// The daemon answered from its pool for a transaction of a closed shard.
    #[error("the daemon serves {txid} from its pool, not from the chain")]
    Pooled { txid: TxHash },
    /// The whole body served does not parse, or is not the transaction its
    /// txid binds.
    #[error("the body served for {txid} is not that transaction")]
    NotItsTxid { txid: TxHash },
    /// The frame built from verified bodies does not reproduce the sealed
    /// rows digest or the member count.
    #[error("the frame built from the bodies does not match the persona scan's rows digest")]
    FrameDisagrees,
}

/// Why one shard's fill did not complete. Nothing was written for it.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ShardFillError {
    /// The daemon could not be read (transport, or a reply this build
    /// cannot decode). Retryable.
    #[error("shard {shard}: the daemon could not be read: {source}")]
    Daemon {
        shard: ShardId,
        #[source]
        source: RpcError,
    },
    /// The daemon has discarded the shard's bodies at its horizon
    /// (`PDM-Q2`) and answers `archived` (`SB-Q2`). The bodies come back
    /// only through the recovery fetch (`WSS-Q9`), which is not built, so
    /// the shard cannot be filled from this read.
    #[error("shard {shard}: the daemon has discarded this shard's bodies")]
    Discarded { shard: ShardId },
    /// The daemon's reply is not the chain the persona scan verified.
    #[error("shard {shard}: {kind}")]
    Mismatch { shard: ShardId, kind: FillMismatch },
    /// The body store could not write the frame.
    #[error("shard {shard}: {detail}")]
    Store { shard: ShardId, detail: String },
}

/// Fill `shard`, whose blocks are `span`, from the daemon behind `rpc` into
/// `bodies`.
///
/// # Errors
///
/// [`ShardFillError`]; nothing is written for `shard` unless this returns
/// `Ok`.
pub(crate) async fn fill_shard<R: Rpc>(
    rpc: &R,
    bodies: &BodyStoreHandle,
    shard: ShardId,
    span: ShardSpan,
) -> Result<(), ShardFillError> {
    let members = walk_span(rpc, shard, span).await?;
    let frame = frame_members(rpc, shard, span, &members).await?;
    bodies
        .put(shard, frame)
        .await
        .map_err(|detail| ShardFillError::Store { shard, detail })
}

/// Walk the shard's blocks and return its in-domain transactions' bound
/// parts, in storage order.
///
/// The walk starts at the block that closed the shard before (or at
/// genesis for shard 0) and ends at the shard's own closing block. Both ends
/// are pinned to the seal by hash, and every block in between chains to the
/// one before it, so the walk is the scanned chain; each block's bodies are
/// bound to its listed ids by the fetch. Placement starts from the sealed
/// total entering the first block and must land exactly on the sealed total
/// entering the last.
async fn walk_span<R: Rpc>(
    rpc: &R,
    shard: ShardId,
    span: ShardSpan,
) -> Result<Vec<TxidParts>, ShardFillError> {
    let mismatch = |kind| ShardFillError::Mismatch { shard, kind };
    let (first, mut entering) = match span.opens {
        Some(opens) => (opens.height, opens.before),
        None => (BlockHeight::ZERO, ArchivalLength::ZERO),
    };
    let last = span.closes.height;
    let mut previous: Option<BlockHash> = None;
    let mut members = Vec::new();
    let mut height = first;
    loop {
        let number = usize::try_from(height.to_raw()).map_err(|_| off_chain(shard, height))?;
        let sb = default_fetch_scannable_block(rpc, number)
            .await
            .map_err(|source| ShardFillError::Daemon { shard, source })?;
        let hash = sb.block.hash();
        let links = match (previous, span.opens) {
            (Some(prior), _) => sb.block.header.previous == prior,
            (None, Some(opens)) => hash.to_bytes() == opens.hash,
            (None, None) => {
                height == BlockHeight::ZERO && sb.block.header.previous == BlockHash::NULL
            }
        };
        if !links || (height == last && hash.to_bytes() != span.closes.hash) {
            return Err(off_chain(shard, height));
        }
        if height == last && entering != span.closes.before {
            return Err(mismatch(FillMismatch::TotalsDisagree { height }));
        }
        let placements = sb
            .archival_placements(entering)
            .ok_or_else(|| mismatch(FillMismatch::TotalsDisagree { height }))?;
        members.extend(
            placements
                .into_iter()
                .filter(|(cum_before, parts)| domain_shard(*cum_before, parts) == Some(shard))
                .map(|(_, parts)| parts),
        );
        entering = sb
            .archival_increment()
            .and_then(|step| entering.checked_add(step))
            .ok_or_else(|| mismatch(FillMismatch::TotalsDisagree { height }))?;
        if sb.archival_cumulative != entering {
            return Err(mismatch(FillMismatch::TotalsDisagree { height }));
        }
        if height == last {
            return Ok(members);
        }
        previous = Some(hash);
        height = height
            .checked_add(BlockCount::ONE)
            .ok_or_else(|| off_chain(shard, height))?;
    }
}

fn off_chain(shard: ShardId, height: BlockHeight) -> ShardFillError {
    ShardFillError::Mismatch {
        shard,
        kind: FillMismatch::OffTheScannedChain { height },
    }
}

/// Read each member's whole body, check it against its bound parts, and
/// build the shard's frame; the frame's rows digest must be the sealed one.
async fn frame_members<R: Rpc>(
    rpc: &R,
    shard: ShardId,
    span: ShardSpan,
    members: &[TxidParts],
) -> Result<Vec<u8>, ShardFillError> {
    let mismatch = |kind| ShardFillError::Mismatch { shard, kind };
    // The walk's members against the seal before any body is asked for: the
    // ends are pinned, so a difference here is this build's, not the daemon's.
    let expected = members.iter().fold(ShardRowsDigest::EMPTY, |rows, parts| {
        rows_digest_step(shard, rows, rows_of_parts(parts))
    });
    if expected != span.closes.rows {
        return Err(mismatch(FillMismatch::FrameDisagrees));
    }
    let mut entries: Vec<(u64, TxSegments)> = Vec::with_capacity(members.len());
    for batch in members.chunks(TXS_PER_REQUEST) {
        let reply = rpc
            .call::<wire::TxList>(TxListQuery {
                id: batch
                    .iter()
                    .map(|parts| HashHex::from_bytes(parts.hash.to_bytes()))
                    .collect(),
                prune: false,
            })
            .await
            .map_err(|source| ShardFillError::Daemon { shard, source })?;
        if reply.len() != batch.len() {
            return Err(ShardFillError::Daemon {
                shard,
                source: RpcError::InvalidNode(
                    "daemon returned a different number of transactions than requested".to_string(),
                ),
            });
        }
        for (parts, slot) in batch.iter().zip(reply) {
            let txid = parts.hash;
            let entry = match slot {
                Slot::Item(entry) => entry,
                Slot::State(SlotState::Archived(_)) => {
                    return Err(ShardFillError::Discarded { shard })
                }
                Slot::State(SlotState::Missing(_)) => {
                    return Err(mismatch(FillMismatch::Missing { txid }))
                }
                Slot::Unasked => {
                    return Err(ShardFillError::Daemon {
                        shard,
                        source: RpcError::TransactionsUnavailable(vec![txid.to_bytes()]),
                    })
                }
            };
            if entry.pooled {
                return Err(mismatch(FillMismatch::Pooled { txid }));
            }
            let tx = Transaction::from_bytes(&entry.body.0)
                .map_err(|_| mismatch(FillMismatch::NotItsTxid { txid }))?;
            if tx.txid_parts() != *parts {
                return Err(mismatch(FillMismatch::NotItsTxid { txid }));
            }
            let segments = tx
                .write_segments()
                .map_err(|_| mismatch(FillMismatch::NotItsTxid { txid }))?;
            entries.push((pqc_auth_count(&tx), segments));
        }
    }
    let frame = encode_frame(
        &entries
            .iter()
            .map(|(count, segments)| FrameTx {
                pqc_auth_count: *count,
                pqc_auths: &segments.pqc_auths,
                prunable: &segments.prunable,
            })
            .collect::<Vec<_>>(),
    );
    let digest =
        frame_rows_digest(shard, &frame).map_err(|_| mismatch(FillMismatch::FrameDisagrees))?;
    let count = u64::try_from(members.len()).map_err(|_| mismatch(FillMismatch::FrameDisagrees))?;
    if digest.rows != span.closes.rows || digest.tx_count != count {
        return Err(mismatch(FillMismatch::FrameDisagrees));
    }
    Ok(frame)
}

/// How many authorizations a body's `pqc_auths` segment holds: the frame
/// entry's count, which its retained `pqc_auth_hash` mixes in.
fn pqc_auth_count(tx: &Transaction) -> u64 {
    match &tx.ct {
        Ct::Fcmp { pqc_auths, .. } => {
            u64::try_from(pqc_auths.len()).expect("an authorization count fits u64")
        }
        _ => 0,
    }
}
