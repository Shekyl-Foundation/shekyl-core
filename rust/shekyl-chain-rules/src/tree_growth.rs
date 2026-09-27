// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The curve tree's growth, derived here — DRS-E3 (`DRS_E3_CURVE_WRITER.md`
//! §3.1, `CTW-Q1` RULED): the root determines future validity (every later
//! CEN-I12 resolves `root_at(ref_height)` against it), so the authority over
//! validity computes it; the store persists what it is handed and computes
//! no root (C2-R8 principle 3). This module is the arithmetic and nothing
//! else: no view, no store, no fault type of its own beyond the one input
//! it can refuse.
//!
//! # What grows, and from what
//!
//! A [`TreeFrontier`] is everything the next grow needs to know about the
//! tree as it stands: the leaf count and, per layer, the hash of the
//! **last** chunk — the only chunk a grow can change (CTW-8: `hash_grow`
//! takes one chunk hash and the child it replaces; a filled chunk below the
//! frontier is never an input). [`grow`] appends leaves and returns a
//! [`TreeGrowth`]: every `(layer, chunk)` hash the grow produced, the new
//! root, the new leaf count and depth.
//!
//! # Incremental, and equal to the rebuild
//!
//! The C++ (`db_lmdb.cpp:8403–8615`) grows the leaf layer incrementally and
//! then **recomposes every upper layer from all layer-0 chunks** — because
//! its earlier incremental deepening "built a newly-created parent chunk
//! from only the deepening child and dropped the pre-existing sibling" (the
//! depth-3 consensus divergence). Here every layer is incremental, and the
//! property the C++ lost is the test: for any sequence of grows, the
//! accumulated writes and the root equal `shekyl_fcmp::tree::try_build_layers`
//! over the whole leaf set. Per layer `L ≥ 1`, the parent chunks that can
//! change are those over the changed children of `L − 1`; a parent that
//! existed is grown from its frontier hash with `existing_child` = the old
//! x-coordinate of the one child that already sat in it (the previously
//! last, partial chunk), and a parent that did not exist is grown from the
//! layer's `hash_init` with `existing_child = 0`. The root-stop is the
//! library's: the tree has `layer_count_for_leaves(n)` layers, and the top
//! layer has one chunk.
//!
//! # What this is not
//!
//! Not a rule and not a coverage row (`DRS_E3_CURVE_WRITER.md` §3.1, RULED):
//! growth refuses no block, it propagates faults. It is the operand F17,
//! I12, I13 and I15 read. A frontier whose shape does not match its leaf
//! count, or a chunk hash off its curve, is [`FrontierFault`] — the view
//! could not describe the tree, which the caller raises as `Corrupt`.
//! [`GrowFault::NoLeaves`] is the caller's empty batch, not a property of
//! stored bytes, and does not become that `Corrupt`.

use shekyl_fcmp::tree::{
    chunk_width, hash_grow_helios, hash_grow_selene, helios_hash_init,
    helios_point_to_selene_scalar, layer_count_for_leaves, layer_is_selene, selene_hash_init,
    selene_point_to_helios_scalar, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};
use shekyl_types::{CurveTreeRoot, TreeLeaf};

/// A 32-byte layer-chunk hash as the tree stores it (a Selene point on even
/// layers, a Helios point on odd ones).
pub type ChunkHash = [u8; 32];

const ZERO_SCALAR: [u8; 32] = [0; 32];

/// The tree as the next grow needs it: the leaf count and, per layer from
/// 0 upward, the hash of that layer's **last** chunk. `last_chunks` is
/// empty for the empty tree and has `layer_count_for_leaves(leaf_count)`
/// entries otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeFrontier {
    /// Leaves in the tree.
    pub leaf_count: u64,
    /// `last_chunks[L]` — the hash of the last chunk at layer `L`.
    pub last_chunks: Vec<ChunkHash>,
}

impl TreeFrontier {
    /// The empty tree.
    pub const EMPTY: Self = Self {
        leaf_count: 0,
        last_chunks: Vec::new(),
    };

    /// The number of layers this frontier describes (`0` for the empty
    /// tree; otherwise `depth + 1`).
    #[must_use]
    pub fn layer_count(&self) -> u8 {
        if self.leaf_count == 0 {
            0
        } else {
            layer_count_for_leaves(self.leaf_count)
        }
    }

    /// Where a frontier's chunks live in a tree of `leaf_count` leaves:
    /// `(layer, index)` of every layer's last chunk, layer 0 first. The
    /// store reads exactly these rows to assemble the frontier
    /// (`curve_tree_layers[(layer, index)]`, DRS-E3 §3.1); the arithmetic
    /// lives here so the reader and [`grow`] cannot disagree about which
    /// chunk is last. Empty for an empty tree.
    #[must_use]
    pub fn last_chunk_indices(leaf_count: u64) -> Vec<(u8, u64)> {
        if leaf_count == 0 {
            return Vec::new();
        }
        (0..layer_count_for_leaves(leaf_count))
            .map(|layer| (layer, chunk_count(leaf_count, layer) - 1))
            .collect()
    }
}

/// One `(layer, chunk)` hash a grow produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerWrite {
    /// The layer (`0` is the leaf-chunk layer).
    pub layer: u8,
    /// The chunk index within the layer.
    pub chunk: u64,
    /// The chunk's hash after the grow.
    pub hash: ChunkHash,
}

/// What a grow produced: the writes, and the tree after them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeGrowth {
    /// The leaf count before the grow — the position the first new leaf took.
    pub leaf_count_before: u64,
    /// The leaves appended, in drain order; leaf `i` sits at position
    /// `leaf_count_before + i`.
    pub leaves: Vec<TreeLeaf>,
    /// Every layer chunk the grow wrote, layer-major then chunk order.
    pub layer_writes: Vec<LayerWrite>,
    /// The root after the grow.
    pub root: CurveTreeRoot,
    /// Layers above the leaf layer after the grow (`fcmp_layers = depth + 1`).
    pub depth: u8,
}

impl TreeGrowth {
    /// The leaf count after the grow.
    #[must_use]
    pub fn leaf_count_after(&self) -> u64 {
        self.leaf_count_before + self.leaves.len() as u64
    }

    /// The frontier after this grow: the last chunk of every layer, read off
    /// the writes (every layer's last chunk is written by every grow).
    #[must_use]
    pub fn frontier_after(&self) -> TreeFrontier {
        let layers = layer_count_for_leaves(self.leaf_count_after());
        let mut last_chunks = Vec::with_capacity(usize::from(layers));
        for layer in 0..layers {
            let last = self
                .layer_writes
                .iter()
                .filter(|w| w.layer == layer)
                .max_by_key(|w| w.chunk)
                .expect("every grow writes every layer's last chunk");
            last_chunks.push(last.hash);
        }
        TreeFrontier {
            leaf_count: self.leaf_count_after(),
            last_chunks,
        }
    }
}

/// A frontier the view served cannot be grown. Both arms are properties of
/// stored bytes, so the store halts and names the cell. [`GrowFault::NoLeaves`]
/// is not one of them: an empty batch is the caller's, and the drain does
/// not ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierFault {
    /// `last_chunks` is not the layer count `leaf_count` implies.
    Shape {
        /// What the frontier carried.
        layers: usize,
        /// What its leaf count implies.
        expected: u8,
    },
    /// A stored chunk hash or a leaf scalar is not a point or a field
    /// element of its layer's curve.
    NotOnCurve {
        /// The layer whose input failed (`0` for a leaf scalar).
        layer: u8,
    },
}

impl core::fmt::Display for FrontierFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Shape { layers, expected } => write!(
                f,
                "the tree frontier carries {layers} layer(s) but its leaf count implies {expected}"
            ),
            Self::NotOnCurve { layer } => write!(
                f,
                "a stored chunk hash or leaf scalar at layer {layer} is not a point or field element of that layer's curve"
            ),
        }
    }
}

/// Why [`grow`] could not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrowFault {
    /// The frontier the caller served cannot be grown ([`FrontierFault`]).
    Frontier(FrontierFault),
    /// Nothing to append. Callers skip the grow at a height that drained
    /// nothing; asking anyway is a caller bug, named rather than a no-op,
    /// and it is not a corrupt table.
    NoLeaves,
}

impl core::fmt::Display for GrowFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frontier(fault) => fault.fmt(f),
            Self::NoLeaves => f.write_str("grow called with no leaves to append"),
        }
    }
}

fn off_curve(layer: u8) -> GrowFault {
    GrowFault::Frontier(FrontierFault::NotOnCurve { layer })
}

/// The chunk count of layer `layer` in a tree of `leaf_count` leaves, or
/// `0` if the layer does not exist in that tree.
fn chunk_count(leaf_count: u64, layer: u8) -> u64 {
    if leaf_count == 0 || layer >= layer_count_for_leaves(leaf_count) {
        return 0;
    }
    let mut nodes = leaf_count.div_ceil(SELENE_CHUNK_WIDTH as u64);
    for l in 1..=layer {
        nodes = nodes.div_ceil(chunk_width(l) as u64);
    }
    nodes
}

fn init_for(layer: u8) -> ChunkHash {
    if layer_is_selene(layer) {
        selene_hash_init()
    } else {
        helios_hash_init()
    }
}

/// A child's scalar in layer `parent`'s curve, from the hash of a chunk at
/// `parent − 1`.
fn child_scalar(parent: u8, chunk_hash: &ChunkHash) -> Option<[u8; 32]> {
    if layer_is_selene(parent) {
        helios_point_to_selene_scalar(chunk_hash)
    } else {
        selene_point_to_helios_scalar(chunk_hash)
    }
}

fn grow_chunk(
    layer: u8,
    existing: &ChunkHash,
    offset: usize,
    existing_child: &[u8; 32],
    children: &[[u8; 32]],
) -> Option<ChunkHash> {
    if layer_is_selene(layer) {
        hash_grow_selene(existing, offset, existing_child, children)
    } else {
        hash_grow_helios(existing, offset, existing_child, children)
    }
}

/// A chunk the grow changed at one layer, with the hash it had before if
/// it existed (only the layer's previously-last chunk can). `Copy`: a
/// parent collects its children by value, including one unchanged sibling
/// copied off the frontier.
#[derive(Clone, Copy)]
struct Changed {
    chunk: u64,
    /// Hash before this grow, when the chunk already existed.
    old: Option<ChunkHash>,
    new: ChunkHash,
}

/// The child layer's old last chunk, when this grow did not rewrite it.
///
/// A full chunk is absent from `changed`. A **new** parent that spans it
/// must hash it — it is the pre-existing sibling a parent built from
/// `hash_init` would otherwise drop. An existing parent already has that
/// sibling in its hash and must not see it again. `None` when the chunk
/// was rewritten or the child layer was empty.
fn unchanged_old_last(
    changed: &[Changed],
    frontier: &TreeFrontier,
    child_layer: u8,
    old_leaf_count: u64,
) -> Option<Changed> {
    let below = chunk_count(old_leaf_count, child_layer);
    if below == 0 {
        return None;
    }
    let chunk = below - 1;
    if changed.iter().any(|c| c.chunk == chunk) {
        return None;
    }
    Some(Changed {
        chunk,
        old: None,
        new: frontier.last_chunks[usize::from(child_layer)],
    })
}

/// Append `leaves` to the tree `frontier` describes.
///
/// # Errors
///
/// [`GrowFault`] — a frontier whose shape contradicts its count, bytes that
/// are not on their layer's curve, or no leaves. The first two are
/// [`FrontierFault`]; the third is the caller's empty batch.
pub fn grow(frontier: &TreeFrontier, leaves: &[TreeLeaf]) -> Result<TreeGrowth, GrowFault> {
    if leaves.is_empty() {
        return Err(GrowFault::NoLeaves);
    }
    let expected = frontier.layer_count();
    if frontier.last_chunks.len() != usize::from(expected) {
        return Err(GrowFault::Frontier(FrontierFault::Shape {
            layers: frontier.last_chunks.len(),
            expected,
        }));
    }
    let old = frontier.leaf_count;
    let new = old + leaves.len() as u64;
    let new_layers = layer_count_for_leaves(new);
    let width0 = SELENE_CHUNK_WIDTH as u64;
    let mut writes = Vec::new();

    // ---- layer 0: leaf scalars into leaf chunks -----------------------
    let mut changed: Vec<Changed> = Vec::new();
    let first_chunk = if old == 0 { 0 } else { (old - 1) / width0 };
    let last_chunk = (new - 1) / width0;
    for chunk in first_chunk..=last_chunk {
        let chunk_start = chunk * width0;
        let first_new = old.max(chunk_start) - chunk_start;
        let chunk_end = ((chunk + 1) * width0).min(new);
        if chunk_start + first_new >= chunk_end {
            // The old last chunk was full: nothing new lands in it.
            continue;
        }
        let existed = old > chunk_start;
        let existing = if existed {
            frontier.last_chunks[0]
        } else {
            init_for(0)
        };
        let from = usize::try_from(chunk_start + first_new - old).expect("in-batch index");
        let to = usize::try_from(chunk_end - old).expect("in-batch index");
        let scalars: Vec<[u8; 32]> = leaves[from..to]
            .iter()
            .flat_map(|leaf| {
                let bytes = leaf.as_bytes();
                (0..SCALARS_PER_LEAF).map(move |i| {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
                    s
                })
            })
            .collect();
        let offset = usize::try_from(first_new).expect("chunk offset") * SCALARS_PER_LEAF;
        // A fresh leaf position's prior scalar is zero even inside an
        // existing chunk: scalars below `offset` are already in the hash.
        let hash = grow_chunk(0, &existing, offset, &ZERO_SCALAR, &scalars).ok_or(off_curve(0))?;
        writes.push(LayerWrite {
            layer: 0,
            chunk,
            hash,
        });
        changed.push(Changed {
            chunk,
            old: existed.then_some(existing),
            new: hash,
        });
    }

    // ---- layers 1..: parents of the changed chunks --------------------
    for layer in 1..new_layers {
        let width = chunk_width(layer) as u64;
        let old_count = chunk_count(old, layer);
        // Resolved once per layer. Included only by a new parent whose span
        // covers it; sorted into place so the order is the chunk index.
        let unchanged = unchanged_old_last(&changed, frontier, layer - 1, old);
        let p_first = changed.first().expect("a changed chunk").chunk / width;
        let p_last = changed.last().expect("a changed chunk").chunk / width;
        let mut next: Vec<Changed> = Vec::new();
        for parent in p_first..=p_last {
            let existed = parent < old_count;
            // An existing parent is the layer's old last chunk (the only
            // one a change can reach), so its hash is the frontier's.
            let existing = if existed {
                frontier.last_chunks[usize::from(layer)]
            } else {
                init_for(layer)
            };
            let mut children: Vec<Changed> = changed
                .iter()
                .copied()
                .filter(|c| c.chunk / width == parent)
                .collect();
            if !existed {
                if let Some(sibling) = unchanged {
                    if sibling.chunk / width == parent {
                        children.push(sibling);
                    }
                }
            }
            children.sort_by_key(|c| c.chunk);
            let first = children.first().expect("a parent has a changed child");
            let offset = usize::try_from(first.chunk - parent * width).expect("chunk offset");
            // The one child that already sat in this parent is the one that
            // had an old hash; a fresh position's prior child is zero.
            let existing_child = match (existed, first.old) {
                (true, Some(old_hash)) => child_scalar(layer, &old_hash).ok_or(off_curve(layer))?,
                _ => ZERO_SCALAR,
            };
            let scalars = children
                .iter()
                .map(|c| child_scalar(layer, &c.new).ok_or(off_curve(layer)))
                .collect::<Result<Vec<_>, _>>()?;
            let hash = grow_chunk(layer, &existing, offset, &existing_child, &scalars)
                .ok_or(off_curve(layer))?;
            writes.push(LayerWrite {
                layer,
                chunk: parent,
                hash,
            });
            next.push(Changed {
                chunk: parent,
                old: existed.then_some(existing),
                new: hash,
            });
        }
        changed = next;
    }

    debug_assert_eq!(changed.len(), 1, "the top layer has one chunk");
    debug_assert_eq!(changed[0].chunk, 0, "the root chunk is chunk 0");
    let root = CurveTreeRoot::from_bytes(changed[0].new);
    Ok(TreeGrowth {
        leaf_count_before: old,
        leaves: leaves.to_vec(),
        layer_writes: writes,
        root,
        depth: new_layers - 1,
    })
}

#[cfg(test)]
#[path = "tree_growth_tests.rs"]
mod tree_growth_tests;
