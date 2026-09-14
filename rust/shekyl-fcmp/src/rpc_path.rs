// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Daemon RPC membership-path byte layout (`get_curve_tree_path`).
//!
//! This is **not** [`shekyl_curve_tree::CurveTreeClient::assemble_path`].
//! That function rebuilds layers from a wallet-held leaf stream via
//! `build_layers`. This function walks a live consensus store that already
//! holds layer hashes, and `hash_trim`s a boundary chunk that grew after
//! the reference height. Sharing the wallet assembler would drop the trim
//! and require the daemon to hold the wallet's entry stream.
//!
//! What is shared: [`chunk_width`], [`hash_trim_selene`] /
//! [`hash_trim_helios`], [`key_image_generator`], [`SCALARS_PER_LEAF`].
//! The C++ daemon is a store-callback shim over [`assemble_rpc_path`].

use crate::tree::{
    chunk_width, hash_trim_helios, hash_trim_selene, key_image_generator, layer_is_selene,
    SCALARS_PER_LEAF,
};

/// 4-scalar leaf: `{O.x, I.x, C.x, h_pqc}`.
pub const LEAF_BYTES: usize = 128;

/// Fail-closed store reads the assembler needs. The daemon implements this
/// over `BlockchainDB`; tests implement it over a map.
pub trait PathStore {
    fn leaf(&self, pos: u64) -> Result<[u8; LEAF_BYTES], PathAssembleError>;
    fn layer_hash(&self, layer: u8, chunk: u64) -> Result<[u8; 32], PathAssembleError>;
    /// Compressed Ed25519 `(O, C)` for `chunk_outputs`. Distinct from the
    /// leaf's Wei25519 x-coords; a missing row is the same class as a missing
    /// leaf (PDM-Q-F9).
    fn output_oc(&self, pos: u64) -> Result<([u8; 32], [u8; 32]), PathAssembleError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathAssembleError {
    #[error("Failed to read leaf at tree position {0}")]
    MissingLeaf(u64),
    #[error("Internal error: missing layer hash at layer {layer} chunk {chunk}")]
    MissingLayerHash { layer: u8, chunk: u64 },
    #[error("Failed to read output key at tree position {0}")]
    MissingOutputKey(u64),
    #[error("Internal error: boundary-chunk trim failed at layer {layer} chunk {chunk}")]
    TrimFailed { layer: u8, chunk: u64 },
}

/// The two byte strings `get_curve_tree_path` returns per output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledRpcPath {
    /// `[leaf_pos u16 LE][leaf 128 B]*` then per layer `1..=depth`:
    /// `[pos_in_parent u16 LE][sibling hash 32 B]*chunk_width`.
    pub path: Vec<u8>,
    /// Per leaf in the layer-0 chunk: `O(32) ‖ I(32) ‖ C(32) ‖ h_pqc(32)`.
    pub chunk_outputs: Vec<u8>,
}

fn push_u16_le(buf: &mut Vec<u8>, x: u16) {
    buf.extend_from_slice(&x.to_le_bytes());
}

fn width(layer: u8) -> u64 {
    u64::try_from(chunk_width(layer)).expect("chunk width fits u64")
}

fn div_ceil(n: u64, d: u64) -> u64 {
    n.div_ceil(d)
}

fn append_layer0(
    store: &impl PathStore,
    output_idx: u64,
    ref_leaf_count: u64,
    selene_cw: u64,
    out: &mut AssembledRpcPath,
) -> Result<u64, PathAssembleError> {
    let chunk_idx = output_idx / selene_cw;
    let chunk_start = chunk_idx * selene_cw;
    let chunk_end = (chunk_start + selene_cw).min(ref_leaf_count);
    let pos_in_chunk = u16::try_from(output_idx - chunk_start).expect("selene width fits u16");
    push_u16_le(&mut out.path, pos_in_chunk);

    for pos in chunk_start..chunk_end {
        let leaf = store.leaf(pos)?;
        out.path.extend_from_slice(&leaf);

        let (o, c) = store.output_oc(pos)?;
        let i = key_image_generator(&o);
        out.chunk_outputs.extend_from_slice(&o);
        out.chunk_outputs.extend_from_slice(&i);
        out.chunk_outputs.extend_from_slice(&c);
        out.chunk_outputs.extend_from_slice(&leaf[96..LEAF_BYTES]);
    }
    Ok(chunk_idx)
}

#[derive(Clone, Copy)]
struct BoundaryTrim {
    layer: u8,
    sibling_chunk: u64,
    last_ref_chunk_below: u64,
    ref_nodes: u64,
    cur_nodes: u64,
    prev_cw: u64,
}

/// If this sibling is the boundary chunk that grew after the reference
/// height, trim it back to the hash it had with only the reference-state
/// entries. Returns the (possibly trimmed) hash.
fn maybe_trim_boundary(
    store: &impl PathStore,
    t: BoundaryTrim,
    hash: [u8; 32],
) -> Result<[u8; 32], PathAssembleError> {
    if t.sibling_chunk != t.last_ref_chunk_below
        || t.ref_nodes == t.cur_nodes
        || t.ref_nodes.is_multiple_of(t.prev_cw)
    {
        return Ok(hash);
    }

    let ref_in_chunk = t.ref_nodes - t.sibling_chunk * t.prev_cw;
    let cur_in_chunk = (t.cur_nodes - t.sibling_chunk * t.prev_cw).min(t.prev_cw);
    if cur_in_chunk <= ref_in_chunk {
        return Ok(hash);
    }

    let scalars_per_entry = if t.layer == 1 {
        u64::try_from(SCALARS_PER_LEAF).expect("SCALARS_PER_LEAF fits u64")
    } else {
        1
    };
    let trim_offset =
        usize::try_from(ref_in_chunk * scalars_per_entry).expect("trim offset fits usize");

    let extra_start = t.sibling_chunk * t.prev_cw + ref_in_chunk;
    let extra_end = t.sibling_chunk * t.prev_cw + cur_in_chunk;
    let mut extra: Vec<[u8; 32]> = Vec::new();
    for li in extra_start..extra_end {
        if t.layer == 1 {
            let leaf = store.leaf(li)?;
            for chunk in leaf.chunks_exact(32) {
                extra.push(chunk.try_into().expect("32-byte leaf scalar"));
            }
        } else {
            extra.push(store.layer_hash(t.layer - 2, li)?);
        }
    }

    let zero = [0u8; 32];
    let trimmed = if layer_is_selene(t.layer - 1) {
        hash_trim_selene(&hash, trim_offset, &extra, &zero)
    } else {
        hash_trim_helios(&hash, trim_offset, &extra, &zero)
    };
    match trimmed {
        Some(h) => Ok(h),
        None => Err(PathAssembleError::TrimFailed {
            layer: t.layer - 1,
            chunk: t.sibling_chunk,
        }),
    }
}

/// Assemble the RPC membership-path bytes for `output_idx` against a store
/// that currently holds `tip_leaf_count` leaves, as the tree stood with
/// `ref_leaf_count` leaves.
///
/// `depth` is the caller's snapshot (the same value published as
/// `tree_depth`). The assembler does not re-read depth from the store.
///
/// Precondition (caller-checked): `output_idx < ref_leaf_count <= tip_leaf_count`
/// and the tree is non-empty.
pub fn assemble_rpc_path(
    store: &impl PathStore,
    output_idx: u64,
    ref_leaf_count: u64,
    tip_leaf_count: u64,
    depth: u8,
) -> Result<AssembledRpcPath, PathAssembleError> {
    let selene_cw = width(0);
    let mut out = AssembledRpcPath {
        path: Vec::new(),
        chunk_outputs: Vec::new(),
    };

    let mut child_chunk = append_layer0(store, output_idx, ref_leaf_count, selene_cw, &mut out)?;
    let mut ref_nodes = ref_leaf_count;
    let mut cur_nodes = tip_leaf_count;

    for layer in 1..=depth {
        let prev_cw = width(layer - 1);
        let cw = width(layer);
        let ref_chunks_below = div_ceil(ref_nodes, prev_cw);
        let cur_chunks_below = div_ceil(cur_nodes, prev_cw);
        let last_ref_chunk_below = ref_chunks_below.saturating_sub(1);

        let parent_chunk = child_chunk / cw;
        let sib_start = parent_chunk * cw;
        let pos_in_parent = u16::try_from(child_chunk - sib_start).expect("chunk width fits u16");
        push_u16_le(&mut out.path, pos_in_parent);

        for c in 0..cw {
            let sibling_chunk = sib_start + c;
            let hash = if sibling_chunk < ref_chunks_below {
                let raw = store.layer_hash(layer - 1, sibling_chunk)?;
                maybe_trim_boundary(
                    store,
                    BoundaryTrim {
                        layer,
                        sibling_chunk,
                        last_ref_chunk_below,
                        ref_nodes,
                        cur_nodes,
                        prev_cw,
                    },
                    raw,
                )?
            } else {
                [0u8; 32]
            };
            out.path.extend_from_slice(&hash);
        }

        ref_nodes = ref_chunks_below;
        cur_nodes = cur_chunks_below;
        child_chunk = parent_chunk;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::HELIOS_CHUNK_WIDTH;
    use std::collections::{HashMap, HashSet};

    struct MapStore {
        leaves: HashMap<u64, [u8; LEAF_BYTES]>,
        hashes: HashMap<(u8, u64), [u8; 32]>,
        ocs: HashMap<u64, ([u8; 32], [u8; 32])>,
        missing_leaves: HashSet<u64>,
        missing_hashes: HashSet<(u8, u64)>,
        missing_ocs: HashSet<u64>,
    }

    impl MapStore {
        fn filled(n: u64) -> Self {
            let mut s = Self {
                leaves: HashMap::new(),
                hashes: HashMap::new(),
                ocs: HashMap::new(),
                missing_leaves: HashSet::new(),
                missing_hashes: HashSet::new(),
                missing_ocs: HashSet::new(),
            };
            for pos in 0..n {
                let mut leaf = [0u8; LEAF_BYTES];
                let fill = u8::try_from(pos + 1).expect("test leaf count fits u8");
                leaf.fill(fill);
                s.leaves.insert(pos, leaf);
                s.ocs.insert(pos, ([0u8; 32], [0u8; 32]));
            }
            let mut hash = [0u8; 32];
            hash.fill(0xA0);
            s.hashes.insert((0, 0), hash);
            s
        }
    }

    impl PathStore for MapStore {
        fn leaf(&self, pos: u64) -> Result<[u8; LEAF_BYTES], PathAssembleError> {
            if self.missing_leaves.contains(&pos) {
                return Err(PathAssembleError::MissingLeaf(pos));
            }
            self.leaves
                .get(&pos)
                .copied()
                .ok_or(PathAssembleError::MissingLeaf(pos))
        }
        fn layer_hash(&self, layer: u8, chunk: u64) -> Result<[u8; 32], PathAssembleError> {
            if self.missing_hashes.contains(&(layer, chunk)) {
                return Err(PathAssembleError::MissingLayerHash { layer, chunk });
            }
            self.hashes
                .get(&(layer, chunk))
                .copied()
                .ok_or(PathAssembleError::MissingLayerHash { layer, chunk })
        }
        fn output_oc(&self, pos: u64) -> Result<([u8; 32], [u8; 32]), PathAssembleError> {
            if self.missing_ocs.contains(&pos) {
                return Err(PathAssembleError::MissingOutputKey(pos));
            }
            self.ocs
                .get(&pos)
                .copied()
                .ok_or(PathAssembleError::MissingOutputKey(pos))
        }
    }

    #[test]
    fn missing_leaf_in_chunk_refuses_and_names_position() {
        let mut db = MapStore::filled(3);
        db.missing_leaves.insert(1);
        let err = assemble_rpc_path(&db, 0, 3, 3, 1).unwrap_err();
        assert_eq!(err, PathAssembleError::MissingLeaf(1));
        assert!(err.to_string().contains("tree position 1"));
    }

    #[test]
    fn missing_layer_hash_refuses_and_names_chunk() {
        let mut db = MapStore::filled(3);
        db.missing_hashes.insert((0, 0));
        let err = assemble_rpc_path(&db, 0, 3, 3, 1).unwrap_err();
        assert_eq!(
            err,
            PathAssembleError::MissingLayerHash { layer: 0, chunk: 0 }
        );
        assert!(err.to_string().contains("layer 0 chunk 0"));
    }

    #[test]
    fn missing_leaf_in_boundary_trim_refuses() {
        let mut db = MapStore::filled(3);
        db.missing_leaves.insert(2);
        let err = assemble_rpc_path(&db, 0, 2, 3, 1).unwrap_err();
        assert_eq!(err, PathAssembleError::MissingLeaf(2));
    }

    #[test]
    fn missing_output_key_refuses_and_names_position() {
        let mut db = MapStore::filled(3);
        db.missing_ocs.insert(1);
        let err = assemble_rpc_path(&db, 0, 3, 3, 1).unwrap_err();
        assert_eq!(err, PathAssembleError::MissingOutputKey(1));
        assert!(err.to_string().contains("tree position 1"));
    }

    #[test]
    fn invalid_boundary_hash_trim_refuses() {
        let db = MapStore::filled(3);
        // ref < tip so the boundary trim runs; 0xA0-fill is not a Selene point.
        let err = assemble_rpc_path(&db, 0, 2, 3, 1).unwrap_err();
        assert_eq!(err, PathAssembleError::TrimFailed { layer: 0, chunk: 0 });
    }

    #[test]
    fn complete_store_yields_expected_shape() {
        let db = MapStore::filled(3);
        let out = assemble_rpc_path(&db, 1, 3, 3, 1).expect("complete store");
        let layer1_cw = HELIOS_CHUNK_WIDTH;
        assert_eq!(out.path.len(), 2 + 3 * 128 + 2 + layer1_cw * 32);
        assert_eq!(out.path[0], 1);
        assert_eq!(out.path[1], 0);
        let sib0 = 2 + 3 * 128 + 2;
        assert_eq!(out.path[sib0], 0xA0);
        assert_eq!(out.path[sib0 + 32], 0);
        assert_eq!(out.chunk_outputs.len(), 3 * 128);
    }

    #[test]
    fn published_depth_governs_layer_count() {
        let db = MapStore::filled(3);
        let d1 = assemble_rpc_path(&db, 0, 3, 3, 1).expect("depth 1");
        let mut db2 = MapStore::filled(3);
        db2.hashes.insert((1, 0), [0xB0; 32]);
        let d2 = assemble_rpc_path(&db2, 0, 3, 3, 2).expect("depth 2");
        assert!(d2.path.len() > d1.path.len());
        // One extra [u16][selene_cw * 32] for layer 2.
        let extra = 2 + usize::try_from(width(2)).expect("chunk width fits usize") * 32;
        assert_eq!(d2.path.len(), d1.path.len() + extra);
    }
}
