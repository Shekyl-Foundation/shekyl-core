// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! redb-backed `LeafStore` tables and transactional operations.

use std::path::Path;

use redb::backends::InMemoryBackend;
use redb::{Database, ReadableTable, TableDefinition};

use crate::segment::{leaves_per_segment, segment_freeze_eligible, SegmentId};
use crate::store::ops::{full_build_root, mixed_composition_root, recompute_segment_r_k};
use crate::types::{LeafEntry, TargetKind, TreePosition};
use shekyl_fcmp::tree::selene_hash_init;

const LEAVES_TABLE: TableDefinition<u64, &[u8; 128]> = TableDefinition::new("leaves");
const LEAF_META_TABLE: TableDefinition<u64, &[u8; 192]> = TableDefinition::new("leaf_meta");
const FROZEN_SEGMENTS_TABLE: TableDefinition<u32, &[u8; 56]> =
    TableDefinition::new("frozen_segments");
const OWNED_IDENTITIES_TABLE: TableDefinition<u64, &[u8; 128]> =
    TableDefinition::new("owned_identities");
const PINNED_SEGMENTS_TABLE: TableDefinition<u32, u32> = TableDefinition::new("pinned_segments");
const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta");

const META_LEAF_COUNT: &str = "leaf_count";
const META_SYNC_TIP: &str = "sync_tip_height";

/// On-disk record for a frozen segment (`CT1_ROUND1_PINS.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrozenSegmentRecord {
    pub r_k: [u8; 32],
    pub end_tree_pos: u64,
    pub end_block_height: u64,
    pub frozen_at_height: u64,
}

/// Persistent curve-tree leaf store (redb).
pub struct LeafStore {
    db: Database,
}

impl std::fmt::Debug for LeafStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeafStore").finish_non_exhaustive()
    }
}

/// Store operation error.
#[derive(Debug)]
pub enum StoreError {
    /// redb failure.
    Redb(Box<redb::Error>),
    /// Leaf meta decode failure.
    CorruptMeta(&'static str),
    /// Truncation position exceeds the stored leaf count.
    InvalidTruncate { pos: u64, leaf_count: u64 },
}

impl From<redb::Error> for StoreError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(Box::new(e))
    }
}

impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::from(redb::Error::from(e))
    }
}

impl LeafStore {
    /// Open (or create) a persistent store at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(StoreError::from)?;
        let store = Self { db };
        store.init_tables()?;
        Ok(store)
    }

    /// Ephemeral in-memory store (tests and default client).
    pub fn open_ephemeral() -> Result<Self, StoreError> {
        let db = Database::builder()
            .create_with_backend(InMemoryBackend::new())
            .map_err(StoreError::from)?;
        let store = Self { db };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.open_table(LEAVES_TABLE)?;
        txn.open_table(LEAF_META_TABLE)?;
        txn.open_table(FROZEN_SEGMENTS_TABLE)?;
        txn.open_table(OWNED_IDENTITIES_TABLE)?;
        txn.open_table(PINNED_SEGMENTS_TABLE)?;
        {
            let mut meta = txn.open_table(META_TABLE)?;
            if meta.get(META_LEAF_COUNT)?.is_none() {
                meta.insert(META_LEAF_COUNT, &0u64)?;
            }
            if meta.get(META_SYNC_TIP)?.is_none() {
                meta.insert(META_SYNC_TIP, &0u64)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Wipe all leaves and metadata (full chain replay / reorg rebuild).
    pub fn clear(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        txn.delete_table(LEAVES_TABLE)?;
        txn.delete_table(LEAF_META_TABLE)?;
        txn.delete_table(FROZEN_SEGMENTS_TABLE)?;
        txn.delete_table(OWNED_IDENTITIES_TABLE)?;
        txn.delete_table(PINNED_SEGMENTS_TABLE)?;
        txn.delete_table(META_TABLE)?;
        txn.commit()?;
        self.init_tables()
    }

    /// Drained leaf count in the store.
    pub fn leaf_count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META_TABLE)?;
        Ok(meta.get(META_LEAF_COUNT)?.map(|v| v.value()).unwrap_or(0))
    }

    /// Synced chain tip height last written by the client.
    pub fn sync_tip_height(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META_TABLE)?;
        Ok(meta.get(META_SYNC_TIP)?.map(|v| v.value()).unwrap_or(0))
    }

    /// Append newly drained leaves and advance sync tip in one ACID write txn.
    ///
    /// When `entries` is empty, still updates `META_SYNC_TIP` and re-evaluates
    /// segment-freeze eligibility so height-lagged freezes advance on blocks
    /// where no new leaves drain.
    pub fn append_drained(&self, entries: &[LeafEntry], tip_height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        let mut leaf_count = {
            let meta = txn.open_table(META_TABLE)?;
            let v = meta.get(META_LEAF_COUNT)?;
            v.map(|g| g.value()).unwrap_or(0)
        };
        if !entries.is_empty() {
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            for entry in entries {
                let pos = leaf_count;
                leaves.insert(pos, &entry.leaf)?;
                leaf_meta.insert(pos, &encode_leaf_meta(entry))?;
                leaf_count += 1;
            }
        }
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_LEAF_COUNT, &leaf_count)?;
            meta.insert(META_SYNC_TIP, &tip_height)?;
        }
        Self::maybe_freeze_segments_in_txn(&txn, tip_height, leaf_count)?;
        txn.commit()?;
        Ok(())
    }

    fn maybe_freeze_segments_in_txn(
        txn: &redb::WriteTransaction,
        tip_height: u64,
        leaf_count: u64,
    ) -> Result<(), StoreError> {
        let e = leaves_per_segment() as u64;
        let complete_segments = leaf_count / e;
        for seg_k in 0..complete_segments {
            let segment_id = u32::try_from(seg_k).expect("segment id fits u32");
            {
                let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
                if frozen.get(segment_id)?.is_some() {
                    continue;
                }
            }
            let end_tree_pos = (seg_k + 1) * e - 1;
            let end_block_height = read_drain_height(txn, end_tree_pos)?;
            if !segment_freeze_eligible(tip_height, end_block_height) {
                continue;
            }
            let start = seg_k * e;
            let seg_leaves = read_leaf_bytes_range(txn, start, end_tree_pos + 1)?;
            let r_k = recompute_segment_r_k(&seg_leaves);
            let record = FrozenSegmentRecord {
                r_k,
                end_tree_pos,
                end_block_height,
                frozen_at_height: tip_height,
            };
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            frozen.insert(segment_id, &encode_frozen_segment(&record))?;
        }
        Ok(())
    }

    /// Freeze any newly eligible complete segments at `tip_height`.
    pub fn maybe_freeze_segments(&self, tip_height: u64) -> Result<(), StoreError> {
        let leaf_count = self.leaf_count()?;
        let txn = self.db.begin_write()?;
        Self::maybe_freeze_segments_in_txn(&txn, tip_height, leaf_count)?;
        txn.commit()?;
        Ok(())
    }

    /// Curve-tree root for the first `leaf_count` drained leaves (hot path).
    pub fn root_at_count(&self, leaf_count: u64) -> Result<[u8; 32], StoreError> {
        if leaf_count == 0 {
            return Ok(selene_hash_init());
        }
        let e = leaves_per_segment() as u64;
        let complete = leaf_count / e;
        let txn = self.db.begin_read()?;
        let mut frozen_r: Vec<[u8; 32]> = Vec::new();
        {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            for k in 0..complete {
                if let Some(v) = frozen.get(u32::try_from(k).expect("segment key fits u32"))? {
                    frozen_r.push(decode_frozen_segment(v.value()).r_k);
                } else {
                    let start = k * e;
                    let end = start + e;
                    let seg_leaves = read_leaf_bytes_range_read(&txn, start, end)?;
                    frozen_r.push(recompute_segment_r_k(&seg_leaves));
                }
            }
        }
        let tail_start = complete * e;
        let tail = read_leaf_bytes_range_read(&txn, tail_start, leaf_count)?;
        match mixed_composition_root(leaf_count, &frozen_r, &tail) {
            Ok(root) => Ok(root),
            Err(_) if tail_start == 0 => Ok(full_build_root(&tail)),
            Err(_) => match read_leaf_bytes_range_read(&txn, 0, leaf_count) {
                Ok(all_leaves) => Ok(full_build_root(&all_leaves)),
                Err(_) => Err(StoreError::CorruptMeta(
                    "mixed root failed with incomplete leaf range (post-prune)",
                )),
            },
        }
    }

    /// Truncate leaves and metadata at `pos` (ACID reorg).
    pub fn truncate_from_tree_position(&self, pos: TreePosition) -> Result<(), StoreError> {
        let pos = pos.0;
        let current_leaf_count = self.leaf_count()?;
        if pos > current_leaf_count {
            return Err(StoreError::InvalidTruncate {
                pos,
                leaf_count: current_leaf_count,
            });
        }
        let txn = self.db.begin_write()?;
        {
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            let to_remove: Vec<u64> = leaves
                .range(pos..)?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?;
            for key in to_remove {
                leaves.remove(key)?;
                drop(leaf_meta.remove(key)?);
            }
        }
        {
            let mut frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            let e = leaves_per_segment() as u64;
            if pos == 0 {
                let to_remove: Vec<u32> = frozen
                    .iter()?
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for key in to_remove {
                    frozen.remove(key)?;
                }
            } else {
                let max_segment = (pos - 1) / e;
                let to_remove: Vec<u32> = frozen
                    .range(u32::try_from(max_segment + 1).expect("segment range fits u32")..)?
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for key in to_remove {
                    frozen.remove(key)?;
                }
                // Drop frozen segment that partially overlaps the truncation boundary.
                if !pos.is_multiple_of(e) {
                    let partial_id = (pos - 1) / e;
                    frozen.remove(u32::try_from(partial_id).expect("segment id fits u32"))?;
                }
            }
        }
        {
            let mut owned = txn.open_table(OWNED_IDENTITIES_TABLE)?;
            let to_remove: Vec<u64> = owned
                .range(pos..)?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?;
            for key in to_remove {
                owned.remove(key)?;
            }
        }
        {
            let mut pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            let e = leaves_per_segment() as u64;
            if pos == 0 {
                let to_remove: Vec<u32> = pinned
                    .iter()?
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for key in to_remove {
                    pinned.remove(key)?;
                }
            } else {
                let max_segment = (pos - 1) / e;
                let to_remove: Vec<u32> = pinned
                    .range(u32::try_from(max_segment + 1).expect("segment range fits u32")..)?
                    .map(|r| r.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for key in to_remove {
                    pinned.remove(key)?;
                }
                if !pos.is_multiple_of(e) {
                    let partial_id = (pos - 1) / e;
                    pinned.remove(u32::try_from(partial_id).expect("segment id fits u32"))?;
                }
            }
        }
        {
            let mut meta = txn.open_table(META_TABLE)?;
            meta.insert(META_LEAF_COUNT, &pos)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Pin segment `id` so `prune_frozen` retains its full leaf bytes.
    pub fn pin_segment(&self, id: SegmentId) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            pinned.insert(id.0, &1u32)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Prune non-owned leaves of frozen segments to `R_k`, retaining owned chunks.
    pub fn prune_frozen(&self, owned_positions: &[TreePosition]) -> Result<(), StoreError> {
        let owned: std::collections::BTreeSet<u64> = owned_positions.iter().map(|p| p.0).collect();
        let txn = self.db.begin_write()?;
        let e = leaves_per_segment() as u64;
        let frozen_ids: Vec<u32> = {
            let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
            frozen
                .iter()?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<Vec<_>, _>>()?
        };
        let pinned: std::collections::BTreeSet<u32> = {
            let pinned = txn.open_table(PINNED_SEGMENTS_TABLE)?;
            pinned
                .iter()?
                .map(|r| r.map(|(k, _)| k.value()))
                .collect::<Result<std::collections::BTreeSet<_>, _>>()?
        };
        for seg_id in frozen_ids {
            if pinned.contains(&seg_id) {
                continue;
            }
            let start = u64::from(seg_id) * e;
            let end = start + e;
            let mut leaves = txn.open_table(LEAVES_TABLE)?;
            let mut leaf_meta = txn.open_table(LEAF_META_TABLE)?;
            let mut owned_tbl = txn.open_table(OWNED_IDENTITIES_TABLE)?;
            for pos in start..end {
                let leaf_bytes = match leaves.get(pos)? {
                    Some(leaf) => *leaf.value(),
                    None => continue,
                };
                if owned.contains(&pos) {
                    owned_tbl.insert(pos, &leaf_bytes)?;
                }
                leaves.remove(pos)?;
                drop(leaf_meta.remove(pos)?);
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Read frozen segment record, if present.
    pub fn frozen_segment(&self, id: SegmentId) -> Result<Option<FrozenSegmentRecord>, StoreError> {
        let txn = self.db.begin_read()?;
        let frozen = txn.open_table(FROZEN_SEGMENTS_TABLE)?;
        Ok(frozen.get(id.0)?.map(|v| decode_frozen_segment(v.value())))
    }
}

fn read_drain_height(txn: &redb::WriteTransaction, tree_pos: u64) -> Result<u64, StoreError> {
    let meta = txn.open_table(LEAF_META_TABLE)?;
    let m = meta
        .get(tree_pos)?
        .ok_or(StoreError::CorruptMeta("missing leaf meta"))?;
    let entry = decode_leaf_meta(m.value())?;
    Ok(entry.maturity.saturating_add(1))
}

fn read_leaf_bytes_range(
    txn: &redb::WriteTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    let leaves = txn.open_table(LEAVES_TABLE)?;
    let cap = usize::try_from(end - start).expect("leaf range fits usize");
    let mut out = Vec::with_capacity(cap);
    for pos in start..end {
        let leaf = leaves
            .get(pos)?
            .ok_or(StoreError::CorruptMeta("missing leaf"))?;
        out.push(*leaf.value());
    }
    Ok(out)
}

fn read_leaf_bytes_range_read(
    txn: &redb::ReadTransaction,
    start: u64,
    end: u64,
) -> Result<Vec<[u8; 128]>, StoreError> {
    let leaves = txn.open_table(LEAVES_TABLE)?;
    let cap = usize::try_from(end - start).expect("leaf range fits usize");
    let mut out = Vec::with_capacity(cap);
    for pos in start..end {
        let leaf = leaves
            .get(pos)?
            .ok_or(StoreError::CorruptMeta("missing leaf"))?;
        out.push(*leaf.value());
    }
    Ok(out)
}

fn encode_frozen_segment(rec: &FrozenSegmentRecord) -> [u8; 56] {
    let mut buf = [0u8; 56];
    buf[..32].copy_from_slice(&rec.r_k);
    buf[32..40].copy_from_slice(&rec.end_tree_pos.to_be_bytes());
    buf[40..48].copy_from_slice(&rec.end_block_height.to_be_bytes());
    buf[48..56].copy_from_slice(&rec.frozen_at_height.to_be_bytes());
    buf
}

fn decode_frozen_segment(buf: &[u8; 56]) -> FrozenSegmentRecord {
    let mut r_k = [0u8; 32];
    r_k.copy_from_slice(&buf[..32]);
    FrozenSegmentRecord {
        r_k,
        end_tree_pos: u64::from_be_bytes(buf[32..40].try_into().expect("8 bytes")),
        end_block_height: u64::from_be_bytes(buf[40..48].try_into().expect("8 bytes")),
        frozen_at_height: u64::from_be_bytes(buf[48..56].try_into().expect("8 bytes")),
    }
}

fn encode_leaf_meta(entry: &LeafEntry) -> [u8; 192] {
    let mut buf = [0u8; 192];
    buf[0..8].copy_from_slice(&entry.gindex.to_be_bytes());
    buf[8..16].copy_from_slice(&entry.maturity.to_be_bytes());
    buf[16..48].copy_from_slice(&entry.identity.output_key);
    match entry.identity.commitment {
        Some(c) => {
            buf[48] = 1;
            buf[49..81].copy_from_slice(&c);
        }
        None => buf[48] = 0,
    }
    buf[81..113].copy_from_slice(&entry.identity.h_pqc);
    buf[113] = encode_target(&entry.identity.target);
    if let TargetKind::StakedKey { lock_blocks } = entry.identity.target {
        buf[114..122].copy_from_slice(&lock_blocks.to_be_bytes());
    }
    buf
}

fn decode_leaf_meta(buf: &[u8; 192]) -> Result<LeafEntry, StoreError> {
    let gindex = u64::from_be_bytes(buf[0..8].try_into().expect("8 bytes"));
    let maturity = u64::from_be_bytes(buf[8..16].try_into().expect("8 bytes"));
    let mut output_key = [0u8; 32];
    output_key.copy_from_slice(&buf[16..48]);
    let commitment = if buf[48] == 1 {
        let mut c = [0u8; 32];
        c.copy_from_slice(&buf[49..81]);
        Some(c)
    } else {
        None
    };
    let mut h_pqc = [0u8; 32];
    h_pqc.copy_from_slice(&buf[81..113]);
    let target = decode_target(buf[113], &buf[114..122])?;
    Ok(LeafEntry {
        gindex,
        maturity,
        leaf: [0u8; 128],
        identity: crate::types::OutputIdentity {
            output_key,
            commitment,
            h_pqc,
            target,
        },
    })
}

fn encode_target(target: &TargetKind) -> u8 {
    match target {
        TargetKind::TaggedKey => 0,
        TargetKind::Key => 1,
        TargetKind::StakedKey { .. } => 2,
        TargetKind::Other => 3,
    }
}

fn decode_target(tag: u8, extra: &[u8]) -> Result<TargetKind, StoreError> {
    Ok(match tag {
        0 => TargetKind::TaggedKey,
        1 => TargetKind::Key,
        2 => {
            let lock_blocks = u64::from_be_bytes(extra[..8].try_into().expect("8 bytes"));
            TargetKind::StakedKey { lock_blocks }
        }
        3 => TargetKind::Other,
        _ => return Err(StoreError::CorruptMeta("bad target tag")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::leaves_per_segment;
    use crate::types::OutputIdentity;

    fn sample_entry(gindex: u64, maturity: u64) -> LeafEntry {
        LeafEntry {
            gindex,
            maturity,
            leaf: [1u8; 128],
            identity: OutputIdentity {
                output_key: [1u8; 32],
                commitment: Some([2u8; 32]),
                h_pqc: [3u8; 32],
                target: TargetKind::TaggedKey,
            },
        }
    }

    #[test]
    fn append_and_truncate_round_trip() {
        let store = LeafStore::open_ephemeral().unwrap();
        store
            .append_drained(&[sample_entry(0, 0), sample_entry(1, 0)], 1)
            .unwrap();
        assert_eq!(store.leaf_count().unwrap(), 2);
        store.truncate_from_tree_position(TreePosition(1)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 1);
    }

    #[test]
    fn pin_and_prune_smoke() {
        let store = LeafStore::open_ephemeral().unwrap();
        store.pin_segment(SegmentId(0)).unwrap();
        store.prune_frozen(&[]).unwrap();
    }

    #[test]
    fn truncate_to_zero_clears_frozen_segments() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, 10_000).unwrap();
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
        store.truncate_from_tree_position(TreePosition(0)).unwrap();
        assert_eq!(store.leaf_count().unwrap(), 0);
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_none());
    }

    #[test]
    fn append_empty_still_advances_sync_tip_and_freeze() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, 100).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), 100);
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_none());
        store.append_drained(&[], 10_000).unwrap();
        assert_eq!(store.sync_tip_height().unwrap(), 10_000);
        assert!(store.frozen_segment(SegmentId(0)).unwrap().is_some());
    }

    #[test]
    fn truncate_to_zero_clears_stale_pins() {
        let store = LeafStore::open_ephemeral().unwrap();
        let e = leaves_per_segment();
        let entries: Vec<_> = (0..e)
            .map(|i| sample_entry(u64::try_from(i).expect("index fits u64"), 0))
            .collect();
        store.append_drained(&entries, 10_000).unwrap();
        store.pin_segment(SegmentId(0)).unwrap();
        store.truncate_from_tree_position(TreePosition(0)).unwrap();
        store.append_drained(&entries, 20_000).unwrap();
        store.prune_frozen(&[]).unwrap();
        let txn = store.db.begin_read().unwrap();
        let leaves = txn.open_table(LEAVES_TABLE).unwrap();
        assert!(
            leaves.get(0).unwrap().is_none(),
            "stale pin must not block prune"
        );
    }

    #[test]
    fn truncate_beyond_leaf_count_rejects() {
        let store = LeafStore::open_ephemeral().unwrap();
        store.append_drained(&[sample_entry(0, 0)], 1).unwrap();
        let err = store
            .truncate_from_tree_position(TreePosition(2))
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::InvalidTruncate {
                pos: 2,
                leaf_count: 1
            }
        ));
        assert_eq!(store.leaf_count().unwrap(), 1);
    }
}
