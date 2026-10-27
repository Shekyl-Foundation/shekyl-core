// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool methods (`DRS_X_STORE_FLIP.md` DX-Q3, Q10), over the node's one
//! pool through [`PoolFacts`]. **Built and not routed**, like
//! [`crate::mining_methods`].
//!
//! Who asks decides what is listed: any caller sees the entries the node
//! shows; the host's administrator also sees those in their stem phase
//! (`RPC_CHANNEL.md` RT-O9.3). The caller says whether it is the host
//! through [`scope_for`]; nothing here lists a stem entry to anyone else.

use std::collections::BTreeMap;

use shekyl_rpc_types::errors::RpcError;
use shekyl_rpc_types::mining::StatusOnlyResponse;
use shekyl_rpc_types::pool::{
    FlushTxpoolRequest, GetTransactionPoolHashesResponse, GetTransactionPoolResponse,
    GetTransactionPoolStatsResponse, GetTxpoolBacklogResponse, PoolTxInfo, RelayTxRequest,
    SpentKeyImageInfo, TxpoolBacklogEntry, TxpoolStats,
};
use shekyl_rpc_types::{HashHex, RpcStatus};
use shekyl_types::TxHash;

use crate::handles::{PoolEntryFacts, PoolFacts};
use crate::info_facts::PoolScope;

/// The pool `host` may see. Entries not yet broadcast are host-only data
/// (`RPC_CHANNEL.md` §6.1, RT-O9.3): the host's administrator sees them,
/// and everyone else sees the broadcast set.
#[must_use]
pub const fn scope_for(host: bool) -> PoolScope {
    if host {
        PoolScope::WithUnbroadcast
    } else {
        PoolScope::Broadcast
    }
}

fn hex_of(id: TxHash) -> HashHex {
    HashHex::from_bytes(id.to_bytes())
}

/// The ids a request names; the wire has already refused one that is not
/// 64 hexadecimal characters.
fn ids_of(given: &[HashHex]) -> Vec<TxHash> {
    given
        .iter()
        .map(|id| TxHash::from_bytes(id.to_bytes()))
        .collect()
}

fn listed(pool: &dyn PoolFacts, scope: PoolScope) -> Result<Vec<PoolEntryFacts>, RpcError> {
    let mut entries = pool.entries(scope)?;
    entries.sort_by_key(|entry| entry.id.to_bytes());
    Ok(entries)
}

/// `/get_transaction_pool`: the entries `scope` may see, and the key
/// images they spend.
///
/// # Errors
///
/// The handle's fault.
pub fn get_transaction_pool(
    pool: &dyn PoolFacts,
    scope: PoolScope,
) -> Result<GetTransactionPoolResponse, RpcError> {
    let entries = listed(pool, scope)?;
    let mut spenders: BTreeMap<[u8; 32], Vec<HashHex>> = BTreeMap::new();
    for entry in &entries {
        for image in &entry.key_images {
            spenders
                .entry(*image.as_bytes())
                .or_default()
                .push(hex_of(entry.id));
        }
    }
    Ok(GetTransactionPoolResponse {
        status: RpcStatus::ok(),
        transactions: entries
            .iter()
            .map(|entry| PoolTxInfo {
                id_hash: hex_of(entry.id),
                blob_size: u64::try_from(entry.blob.len()).unwrap_or(u64::MAX),
                weight: entry.weight,
                fee: entry.fee,
                relayed: entry.shown,
                tx_blob: hex::encode(&entry.blob),
            })
            .collect(),
        spent_key_images: spenders
            .into_iter()
            .map(|(image, txs_hashes)| SpentKeyImageInfo {
                id_hash: HashHex::from_bytes(image),
                txs_hashes,
            })
            .collect(),
    })
}

/// `/get_transaction_pool_hashes`: the ids `scope` may see.
///
/// # Errors
///
/// The handle's fault.
pub fn get_transaction_pool_hashes(
    pool: &dyn PoolFacts,
    scope: PoolScope,
) -> Result<GetTransactionPoolHashesResponse, RpcError> {
    Ok(GetTransactionPoolHashesResponse {
        status: RpcStatus::ok(),
        tx_hashes: listed(pool, scope)?
            .iter()
            .map(|entry| hex_of(entry.id))
            .collect(),
    })
}

/// `/get_transaction_pool_stats`: the figures over what `scope` may see.
///
/// # Errors
///
/// The handle's fault.
pub fn get_transaction_pool_stats(
    pool: &dyn PoolFacts,
    scope: PoolScope,
) -> Result<GetTransactionPoolStatsResponse, RpcError> {
    let entries = listed(pool, scope)?;
    let mut sizes: Vec<u32> = entries
        .iter()
        .map(|entry| u32::try_from(entry.blob.len()).unwrap_or(u32::MAX))
        .collect();
    sizes.sort_unstable();
    let stats = TxpoolStats {
        bytes_total: sizes.iter().map(|size| u64::from(*size)).sum(),
        bytes_min: sizes.first().copied().unwrap_or(0),
        bytes_max: sizes.last().copied().unwrap_or(0),
        bytes_med: sizes.get(sizes.len() / 2).copied().unwrap_or(0),
        fee_total: entries
            .iter()
            .map(|entry| entry.fee)
            .fold(0, u64::saturating_add),
        txs_total: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        num_not_relayed: u32::try_from(entries.iter().filter(|entry| !entry.shown).count())
            .unwrap_or(u32::MAX),
    };
    Ok(GetTransactionPoolStatsResponse {
        status: RpcStatus::ok(),
        pool_stats: stats,
    })
}

/// `get_txpool_backlog`: each entry's weight and fee.
///
/// # Errors
///
/// The handle's fault.
pub fn get_txpool_backlog(
    pool: &dyn PoolFacts,
    scope: PoolScope,
) -> Result<GetTxpoolBacklogResponse, RpcError> {
    Ok(GetTxpoolBacklogResponse {
        status: RpcStatus::ok(),
        backlog: listed(pool, scope)?
            .iter()
            .map(|entry| TxpoolBacklogEntry {
                weight: entry.weight,
                fee: entry.fee,
            })
            .collect(),
    })
}

/// `flush_txpool { txids }`, host only: remove those entries, or every one
/// when none is named. The removals are tagged flushed, not refused.
///
/// # Errors
///
/// The handle's fault: `NotReady` once the pool is retired, a store fault
/// when the pool file faults (which retires it).
pub async fn flush_txpool(
    pool: &dyn PoolFacts,
    request: &FlushTxpoolRequest,
) -> Result<StatusOnlyResponse, RpcError> {
    pool.flush(ids_of(&request.txids)).await?;
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

/// `relay_tx { txids }`, host only: offer the node's own entries to the
/// relay again.
///
/// # Errors
///
/// `NotReady` until the relay driver is wired (RD).
pub fn relay_tx(
    pool: &dyn PoolFacts,
    request: &RelayTxRequest,
) -> Result<StatusOnlyResponse, RpcError> {
    pool.relay(&ids_of(&request.txids))?;
    Ok(StatusOnlyResponse {
        status: RpcStatus::ok(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use shekyl_types::KeyImage;

    use super::*;
    use crate::chain_facts::FactsFault;

    /// A pool of one shown entry and one stem entry spending the same key
    /// image, filtered as the node's pool filters.
    struct Pool {
        entries: Vec<PoolEntryFacts>,
        flushed: Mutex<Vec<TxHash>>,
    }

    fn pool() -> Pool {
        let image = KeyImage::from_bytes([9; 32]);
        let entry = |n: u8, shown: bool, size: usize| PoolEntryFacts {
            id: TxHash::from_bytes([n; 32]),
            blob: vec![n; size],
            weight: u64::from(n) * 100,
            fee: u64::from(n) * 10,
            shown,
            key_images: vec![image],
        };
        Pool {
            entries: vec![entry(1, true, 10), entry(2, false, 30)],
            flushed: Mutex::new(Vec::new()),
        }
    }

    impl PoolFacts for Pool {
        fn broadcast_count(&self) -> Result<u64, FactsFault> {
            Ok(1)
        }

        fn entries(&self, scope: PoolScope) -> Result<Vec<PoolEntryFacts>, FactsFault> {
            Ok(self
                .entries
                .iter()
                .filter(|entry| entry.shown || scope == PoolScope::WithUnbroadcast)
                .cloned()
                .collect())
        }

        fn flush(&self, ids: Vec<TxHash>) -> crate::mining_facts::Pending<'_, Vec<TxHash>> {
            self.flushed.lock().expect("lock").extend_from_slice(&ids);
            Box::pin(async move { Ok(ids) })
        }
    }

    /// A caller who is not the host is never shown the stem entry; the
    /// host's administrator is (RT-O9.3).
    #[test]
    fn a_stem_entry_reaches_the_host_and_no_one_else() {
        assert_eq!(scope_for(false), PoolScope::Broadcast);
        assert_eq!(scope_for(true), PoolScope::WithUnbroadcast);
        let pool = pool();
        let anyone = get_transaction_pool(&pool, scope_for(false)).expect("listing");
        assert_eq!(anyone.transactions.len(), 1);
        assert!(anyone.transactions[0].relayed);
        let host = get_transaction_pool(&pool, scope_for(true)).expect("listing");
        assert_eq!(host.transactions.len(), 2);
        assert_eq!(host.spent_key_images.len(), 1, "one image, two spenders");
        assert_eq!(host.spent_key_images[0].txs_hashes.len(), 2);
        let hashes = get_transaction_pool_hashes(&pool, scope_for(false)).expect("hashes");
        assert_eq!(hashes.tx_hashes, vec![HashHex::from_bytes([1; 32])]);
    }

    #[test]
    fn the_stats_are_over_what_the_caller_may_see() {
        let pool = pool();
        let anyone = get_transaction_pool_stats(&pool, PoolScope::Broadcast)
            .expect("stats")
            .pool_stats;
        assert_eq!(
            anyone,
            TxpoolStats {
                bytes_total: 10,
                bytes_min: 10,
                bytes_max: 10,
                bytes_med: 10,
                fee_total: 10,
                txs_total: 1,
                num_not_relayed: 0,
            }
        );
        let host = get_transaction_pool_stats(&pool, PoolScope::WithUnbroadcast)
            .expect("stats")
            .pool_stats;
        assert_eq!(
            (host.bytes_total, host.bytes_max, host.txs_total),
            (40, 30, 2)
        );
        assert_eq!(host.num_not_relayed, 1);
        let backlog = get_txpool_backlog(&pool, PoolScope::Broadcast).expect("backlog");
        assert_eq!(
            backlog.backlog,
            vec![TxpoolBacklogEntry {
                weight: 100,
                fee: 10
            }]
        );
    }

    /// `flush_txpool` hands its ids to the pool's remove verb; `relay_tx`
    /// is not ready until a relay driver is supplied.
    #[tokio::test]
    async fn flush_names_its_ids_and_relay_waits_for_a_driver() {
        let pool = pool();
        flush_txpool(
            &pool,
            &FlushTxpoolRequest {
                txids: vec![HashHex::from_bytes([2; 32])],
            },
        )
        .await
        .expect("flushed");
        assert_eq!(
            *pool.flushed.lock().expect("lock"),
            vec![TxHash::from_bytes([2; 32])]
        );
        let refused = relay_tx(&pool, &RelayTxRequest::default()).expect_err("no driver");
        assert_eq!(
            refused.class,
            shekyl_rpc_types::errors::ErrorClass::NotReady
        );
    }
}
