// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool methods (`DRS_X_STORE_FLIP.md` DX-Q3, Q10), over the node's one
//! pool through [`PoolFacts`].
//!
//! Who asks decides what the pool is: any caller sees the entries the node
//! shows; the host's administrator also sees those in their stem phase
//! (`RPC_CHANNEL.md` RT-O9.3). The caller says whether it is the host
//! through [`scope_for`]. To anyone else an entry not yet public is not in
//! the pool: it is not listed, counted, removed or re-offered, and an id
//! naming it answers `{"missing": null}`, the same as an id the pool does
//! not hold (`INPUT_GRAMMAR.md` IG-Q89).

use std::collections::BTreeSet;

use shekyl_rpc_types::errors::RpcError;
use shekyl_rpc_types::kinds::{Count, Size};
use shekyl_rpc_types::wire::{shared, tx};
use shekyl_rpc_types::HashHex;
use shekyl_types::TxHash;
use shekyl_units::{wire::AtomicUnitsString, AtomicUnits};

use crate::handles::{PoolEntryFacts, PoolFacts};
use crate::info_facts::PoolScope;
pub use crate::reads::scope_for;

fn hex_of(id: TxHash) -> HashHex {
    HashHex::from_bytes(id.to_bytes())
}

fn amount(raw: u64) -> AtomicUnitsString {
    AtomicUnitsString::from(AtomicUnits::from_raw(raw))
}

fn listed(pool: &dyn PoolFacts, scope: PoolScope) -> Result<Vec<PoolEntryFacts>, RpcError> {
    let mut entries = pool.entries(scope)?;
    entries.sort_by_key(|entry| entry.id.to_bytes());
    Ok(entries)
}

/// `txpool_list`: the entries the caller may see, each its id, weight and
/// fee (IG-Q57). The body is `tx_show`'s.
///
/// # Errors
///
/// The handle's fault; `txpool.retired` while the pool is retired.
pub fn txpool_list(pool: &dyn PoolFacts, scope: PoolScope) -> Result<Vec<tx::PoolEntry>, RpcError> {
    Ok(listed(pool, scope)?
        .iter()
        .map(|entry| tx::PoolEntry {
            id: hex_of(entry.id),
            weight: Size(entry.weight),
            fee: amount(entry.fee),
        })
        .collect())
}

/// `txpool_stats`: the counts and weights over what the caller may see. The
/// count of entries not yet public is the host's alone (RT-O9.3).
///
/// # Errors
///
/// The handle's fault.
pub fn txpool_stats(pool: &dyn PoolFacts, scope: PoolScope) -> Result<tx::TxpoolStats, RpcError> {
    let entries = listed(pool, scope)?;
    let mut weights: Vec<u64> = entries.iter().map(|entry| entry.weight).collect();
    weights.sort_unstable();
    Ok(tx::TxpoolStats {
        count: Count(u64::try_from(entries.len()).unwrap_or(u64::MAX)),
        weight_total: Size(weights.iter().copied().fold(0, u64::saturating_add)),
        weight_min: Size(weights.first().copied().unwrap_or(0)),
        weight_max: Size(weights.last().copied().unwrap_or(0)),
        weight_median: Size(weights.get(weights.len() / 2).copied().unwrap_or(0)),
        fee_total: amount(
            entries
                .iter()
                .map(|entry| entry.fee)
                .fold(0, u64::saturating_add),
        ),
        private_count: match scope {
            PoolScope::WithUnbroadcast => shekyl_rpc_types::kinds::Withheld::Shown(Count(
                u64::try_from(entries.iter().filter(|entry| !entry.shown).count())
                    .unwrap_or(u64::MAX),
            )),
            PoolScope::Broadcast => shekyl_rpc_types::kinds::Withheld::Withheld,
        },
    })
}

/// The named ids the caller's pool holds, and every id's slot to come: the
/// id once acted on, `{"missing": null}` otherwise.
fn visible(
    pool: &dyn PoolFacts,
    scope: PoolScope,
    named: Option<&[HashHex]>,
) -> Result<(Vec<TxHash>, Vec<TxHash>), RpcError> {
    let seen: BTreeSet<[u8; 32]> = pool
        .entries(scope)?
        .iter()
        .map(|entry| entry.id.to_bytes())
        .collect();
    let asked: Vec<TxHash> = match named {
        Some(ids) => ids
            .iter()
            .map(|id| TxHash::from_bytes(id.to_bytes()))
            .collect(),
        None => seen.iter().copied().map(TxHash::from_bytes).collect(),
    };
    let held = asked
        .iter()
        .copied()
        .filter(|id| seen.contains(&id.to_bytes()))
        .collect();
    Ok((asked, held))
}

fn slots(asked: &[TxHash], acted: &[TxHash]) -> tx::Acted {
    let acted: BTreeSet<[u8; 32]> = acted.iter().map(|id| id.to_bytes()).collect();
    asked
        .iter()
        .map(|id| {
            if acted.contains(&id.to_bytes()) {
                shared::Slot::Item(hex_of(*id))
            } else {
                shared::Slot::State(shared::SlotState::Missing(shared::Null))
            }
        })
        .collect()
}

/// `txpool_flush { id }`: remove the named entries the caller may see, or
/// every one it may see when none is named; each id's slot is the id
/// removed or `{"missing": null}` (IG-Q89).
///
/// # Errors
///
/// The handle's fault: `txpool.retired` once the pool is retired, a store
/// fault when its file faults (which retires it).
pub async fn txpool_flush(
    pool: &dyn PoolFacts,
    request: &tx::FlushIds,
    scope: PoolScope,
) -> Result<tx::Acted, RpcError> {
    let (asked, held) = visible(pool, scope, request.id.as_deref())?;
    let removed = if held.is_empty() {
        Vec::new()
    } else {
        pool.flush(held).await?
    };
    Ok(slots(&asked, &removed))
}

/// `tx_relay { id }`: offer the named entries the caller may see to the
/// relay again, through the entry a fresh local submission takes, so a
/// re-offer enters the stem as a new submission would. Each id's slot is
/// the id offered or `{"missing": null}` (IG-Q89).
///
/// # Errors
///
/// The handle's fault.
pub fn tx_relay(
    pool: &dyn PoolFacts,
    request: &tx::RelayIds,
    scope: PoolScope,
) -> Result<tx::Acted, RpcError> {
    let (asked, held) = visible(pool, scope, Some(&request.id))?;
    let offered = if held.is_empty() {
        Vec::new()
    } else {
        pool.relay(&held)?
    };
    Ok(slots(&asked, &offered))
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
        offered: Mutex<Vec<TxHash>>,
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
            offered: Mutex::new(Vec::new()),
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

        fn relay(&self, ids: &[TxHash]) -> Result<Vec<TxHash>, FactsFault> {
            self.offered.lock().expect("lock").extend_from_slice(ids);
            Ok(ids.to_vec())
        }
    }

    fn id(n: u8) -> HashHex {
        HashHex::from_bytes([n; 32])
    }

    fn missing() -> shared::Slot<HashHex> {
        shared::Slot::State(shared::SlotState::Missing(shared::Null))
    }

    /// A caller who is not the host is never shown the stem entry; the host
    /// is (RT-O9.3). Each entry is its id, weight and fee, never a receive
    /// time (IG-Q57).
    #[test]
    fn a_stem_entry_reaches_the_host_and_no_one_else() {
        assert_eq!(scope_for(false), PoolScope::Broadcast);
        assert_eq!(scope_for(true), PoolScope::WithUnbroadcast);
        let pool = pool();
        let anyone = txpool_list(&pool, scope_for(false)).expect("listing");
        assert_eq!(
            anyone,
            vec![tx::PoolEntry {
                id: id(1),
                weight: Size(100),
                fee: amount(10),
            }]
        );
        let host = txpool_list(&pool, scope_for(true)).expect("listing");
        assert_eq!(host.len(), 2);
    }

    /// The stats are over what the caller may see; the count not yet public
    /// is the host's alone, withheld from anyone else.
    #[test]
    fn the_stats_are_over_what_the_caller_may_see() {
        let pool = pool();
        let anyone = txpool_stats(&pool, PoolScope::Broadcast).expect("stats");
        assert_eq!(anyone.count, Count(1));
        assert_eq!(anyone.weight_total, Size(100));
        assert_eq!(anyone.fee_total, amount(10));
        assert!(anyone.private_count.is_withheld());
        let host = txpool_stats(&pool, PoolScope::WithUnbroadcast).expect("stats");
        assert_eq!(
            (host.count, host.weight_total, host.weight_max),
            (Count(2), Size(300), Size(200))
        );
        assert_eq!(
            host.private_count,
            shekyl_rpc_types::kinds::Withheld::Shown(Count(1))
        );
    }

    /// **The visible set** (IG-Q89): `txpool_flush` removes only the ids the
    /// caller may see; a stem entry named by anyone but the host is
    /// `{"missing": null}` and stays. With no ids it flushes everything the
    /// caller may see. Red edit: hand the pool every named id.
    #[tokio::test]
    async fn flush_acts_on_the_visible_set_alone() {
        let pool = pool();
        let named = tx::FlushIds {
            id: Some(vec![id(2), id(1), id(7)]),
        };
        let out = txpool_flush(&pool, &named, PoolScope::Broadcast)
            .await
            .expect("flushed");
        assert_eq!(out, vec![missing(), shared::Slot::Item(id(1)), missing()]);
        assert_eq!(
            *pool.flushed.lock().expect("lock"),
            vec![TxHash::from_bytes([1; 32])]
        );
        let all = txpool_flush(
            &pool,
            &tx::FlushIds { id: None },
            PoolScope::WithUnbroadcast,
        )
        .await
        .expect("flushed");
        assert_eq!(all.len(), 2);
    }

    /// `tx_relay` offers only what the caller may see; an id it may not
    /// is `{"missing": null}` and reaches no relay (IG-Q89). The host sees
    /// and offers every entry; each slot is the id offered, in the order
    /// asked. Red edit: offer `held` before `visible` filters it.
    #[test]
    fn relay_offers_the_visible_set_and_nothing_else() {
        let pool = pool();
        let unseen = tx_relay(
            &pool,
            &tx::RelayIds {
                id: vec![id(2), id(7)],
            },
            PoolScope::Broadcast,
        )
        .expect("nothing to offer");
        assert_eq!(unseen, vec![missing(), missing()]);
        assert!(
            pool.offered.lock().expect("lock").is_empty(),
            "a stem entry the caller may not see reaches no relay"
        );
        let host = tx_relay(
            &pool,
            &tx::RelayIds {
                id: vec![id(2), id(7), id(1)],
            },
            PoolScope::WithUnbroadcast,
        )
        .expect("offered");
        assert_eq!(
            host,
            vec![
                shared::Slot::Item(id(2)),
                missing(),
                shared::Slot::Item(id(1))
            ]
        );
        assert_eq!(
            *pool.offered.lock().expect("lock"),
            vec![TxHash::from_bytes([2; 32]), TxHash::from_bytes([1; 32])]
        );
    }
}
