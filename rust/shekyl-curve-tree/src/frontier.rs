// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CT-6 increment 4 — the incremental curve-tree frontier.
//!
//! [`Frontier`] carries, per layer, the children of the node that layer is
//! **currently** building: the leaf scalars not yet hashed into a layer-0
//! node, and at each layer `k` the layer-`k` nodes not yet hashed into their
//! layer-`k + 1` parent. Everything to the left of those partial chunks has
//! already been folded upward, so the whole of a tree's history costs
//! `O(depth)` node hashes to carry and `O(depth)` to close.
//!
//! ## Why this is a second composition, and why that is allowed
//!
//! [`shekyl_fcmp::tree::try_build_layers`] is the canonical *batch*
//! composition, and its module doc says the wallet does not reimplement it —
//! otherwise "two implementations must agree" reopens. This module is the
//! stateful half of that same pair, which the daemon has always had
//! (`hash_grow` / `hash_trim`) and the wallet did not: every fold here is a
//! call into the canonical primitives ([`hash_grow_selene`] for a leaf chunk,
//! [`try_promote_to_layer`] for one layer step, [`try_build_upper_layers`] for
//! the closure and its "single node at layer >= 1" stop condition), so the
//! agreement is not a hope about two transcriptions. It is nonetheless a
//! *reachable* disagreement — a mis-sized chunk or a skipped fold would
//! produce a frontier that composes to the wrong root — so it is graded
//! against the batch oracle at every leaf count in this module's tests and,
//! height by height, by CT-6's Q2 examiner.
//!
//! ## Sizing
//!
//! [`Frontier::max_encoded_len`] is computed from the chunk widths rather than
//! written down: a partial chunk holds at most `capacity - 1` children (at
//! `capacity` it folds), so the bound follows from
//! [`shekyl_fcmp::tree::chunk_width`] and the depth the tree can reach.

use shekyl_fcmp::tree::{
    chunk_width, hash_grow_selene, layer_count_for_leaves, selene_hash_init,
    try_build_upper_layers, try_promote_to_layer, LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF,
    SELENE_CHUNK_WIDTH,
};

use crate::segment::LEAF_BYTES;

/// Zero scalar for a fresh chunk position (`hash_grow`'s "no old child").
const ZERO: [u8; 32] = [0u8; 32];

/// Deepest layer index a frontier carries a partial chunk for.
///
/// The curve tree over `u64::MAX` leaves is shallower than this; the cap
/// exists so a corrupt decode cannot ask for an unbounded allocation, and
/// [`Frontier::push_leaf`] refuses rather than growing past it.
const MAX_PARTIAL_LAYERS: usize = 16;

/// Why a frontier could not advance, close, or decode.
///
/// Every variant is a refusal. A frontier that cannot advance refuses its
/// block; a frontier that cannot close refuses its read. There is no
/// degraded answer, because a degraded answer here is a wrong root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrontierError {
    /// A leaf's bytes are not `SCALARS_PER_LEAF` deserializable Selene
    /// scalars, or an internal node failed its point/scalar conversion.
    InvalidNodeScalars,
    /// The tree grew past [`MAX_PARTIAL_LAYERS`] partial chunks.
    TooDeep,
    /// A non-empty frontier held no pending children at any layer — a state
    /// the advance cannot produce, so the bytes are corrupt.
    EmptyWithLeaves,
    /// Encoded bytes ended early or carried trailing bytes.
    ///
    /// The layout is a pure function of `leaf_count`, so a body whose length
    /// is not that function's is this variant. There is no separate shape
    /// error: the encoding stores no widths that could disagree with the count.
    Malformed,
}

/// The per-layer partial chunks of an append-only curve tree.
///
/// `leaf_count` is intrinsic: it is advanced by [`Self::push_leaf`] and is
/// what [`Self::depth`] is taken from, so a frontier cannot be paired with
/// someone else's count (C3 pins root and depth to one `n`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Frontier {
    /// Leaf scalars of the layer-0 node currently being built; folds at
    /// [`LEAF_CHUNK_SCALARS`].
    leaf_chunk: Vec<[u8; 32]>,
    /// `partial[k]` holds the layer-`k` nodes of the layer-`k + 1` node
    /// currently being built; folds at `chunk_width(k + 1)`.
    partial: Vec<Vec<[u8; 32]>>,
    leaf_count: u64,
}

impl Frontier {
    /// Children a layer-`k` partial chunk holds before it folds.
    ///
    /// The chunk at `partial[k]` is the child set of a layer-`k + 1` node,
    /// so its capacity is that layer's width — not layer `k`'s.
    fn partial_capacity(k: usize) -> usize {
        chunk_width(u8::try_from(k + 1).expect("frontier layer index fits u8"))
    }

    /// The chunk shape a frontier holding `leaf_count` leaves must have:
    /// `(leaf-chunk scalars, one width per partial layer)`.
    ///
    /// [`Self::push_leaf`] folds deterministically, so the shape is a pure
    /// function of the count: the leaf chunk holds the leaves since the last
    /// fold, and the partial widths are `leaf_count / SELENE_CHUNK_WIDTH`
    /// written in the mixed radix of the parent widths. The digit count is
    /// the layer count, because a layer exists exactly once something has
    /// been carried into it.
    ///
    /// [`Self::encode`] writes the scalars and nodes in this order and stores
    /// no widths. A stored width would be a second copy of this function, and
    /// a second copy is a framing a decoder would then have to police.
    /// [`Self::decode`] reads exactly this layout. Graded in this module's
    /// tests against frontiers [`Self::push_leaf`] actually built.
    fn expected_shape(leaf_count: u64) -> Result<(usize, Vec<usize>), FrontierError> {
        let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("Selene chunk width fits u64");
        let leaf_scalars = usize::try_from(leaf_count % selene)
            .expect("a remainder below the chunk width fits usize")
            * SCALARS_PER_LEAF;
        let mut widths = Vec::new();
        let mut nodes = leaf_count / selene;
        while nodes > 0 {
            if widths.len() == MAX_PARTIAL_LAYERS {
                return Err(FrontierError::TooDeep);
            }
            let capacity = u64::try_from(Self::partial_capacity(widths.len()))
                .expect("a chunk width fits u64");
            widths.push(
                usize::try_from(nodes % capacity).expect("a remainder below a width fits usize"),
            );
            nodes /= capacity;
        }
        Ok((leaf_scalars, widths))
    }

    /// Largest [`Self::encode`] output, in bytes.
    ///
    /// Derived, not written: each partial chunk holds at most `capacity - 1`
    /// children, because reaching `capacity` folds it in the same call, and
    /// the capacities come from [`chunk_width`] rather than from a second
    /// copy of the widths.
    #[must_use]
    pub fn max_encoded_len() -> usize {
        let mut total = Self::HEADER_LEN + (LEAF_CHUNK_SCALARS - 1) * 32;
        for k in 0..MAX_PARTIAL_LAYERS {
            total += (Self::partial_capacity(k) - 1) * 32;
        }
        total
    }

    /// Little-endian `leaf_count`. Chunk widths are [`Self::expected_shape`].
    const HEADER_LEN: usize = 8;

    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Leaves folded in so far — the `n` [`Self::root`] and [`Self::depth`]
    /// are both taken over (C3).
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Curve-tree depth at this frontier's own leaf count.
    #[must_use]
    pub fn depth(&self) -> u8 {
        layer_count_for_leaves(self.leaf_count)
    }

    /// Append one stored leaf (`SCALARS_PER_LEAF` packed Selene scalars).
    ///
    /// # Errors
    ///
    /// [`FrontierError::InvalidNodeScalars`] if the leaf or an internal node
    /// fails hash growth; [`FrontierError::TooDeep`] past
    /// [`MAX_PARTIAL_LAYERS`].
    pub fn push_leaf(&mut self, leaf: &[u8; LEAF_BYTES]) -> Result<(), FrontierError> {
        for chunk in leaf.chunks_exact(32) {
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(chunk);
            self.leaf_chunk.push(scalar);
        }
        self.leaf_count = self.leaf_count.checked_add(1).expect("leaf count fits u64");
        if self.leaf_chunk.len() < LEAF_CHUNK_SCALARS {
            return Ok(());
        }
        let node = hash_leaf_chunk(&self.leaf_chunk)?;
        self.leaf_chunk.clear();
        self.carry(0, node)
    }

    /// Fold `node` into `partial[k]`, cascading while chunks fill.
    fn carry(&mut self, mut k: usize, mut node: [u8; 32]) -> Result<(), FrontierError> {
        loop {
            if k >= MAX_PARTIAL_LAYERS {
                return Err(FrontierError::TooDeep);
            }
            if self.partial.len() <= k {
                self.partial.resize(k + 1, Vec::new());
            }
            self.partial[k].push(node);
            if self.partial[k].len() < Self::partial_capacity(k) {
                return Ok(());
            }
            let full = std::mem::take(&mut self.partial[k]);
            node = promote_one(full, k)?;
            k += 1;
        }
    }

    /// The root of the tree this frontier has accumulated.
    ///
    /// Closes a *copy* upward — the frontier itself is unchanged, so a read
    /// at a height never mutates the state the next block advances.
    ///
    /// # Errors
    ///
    /// [`FrontierError::InvalidNodeScalars`] on a hash failure,
    /// [`FrontierError::EmptyWithLeaves`] on bytes the advance cannot produce.
    pub fn root(&self) -> Result<[u8; 32], FrontierError> {
        if self.leaf_count == 0 {
            // The empty tree is the `selene_hash_init` sentinel, not
            // `build_layers(&[])` (`CT2_DRAIN_ORDER.md` §5).
            return Ok(selene_hash_init());
        }
        let mut carry: Option<[u8; 32]> = if self.leaf_chunk.is_empty() {
            None
        } else {
            Some(hash_leaf_chunk(&self.leaf_chunk)?)
        };
        let top = self
            .partial
            .iter()
            .rposition(|layer| !layer.is_empty())
            .unwrap_or(0);
        for k in 0..=top {
            let mut combined = self.partial.get(k).cloned().unwrap_or_default();
            combined.extend(carry.take());
            if k == top {
                if combined.is_empty() {
                    return Err(FrontierError::EmptyWithLeaves);
                }
                // At the topmost non-empty layer `combined` IS that whole
                // layer, so the batch composition's own stop condition
                // decides the root rather than a second copy of it.
                let layers = try_build_upper_layers(
                    combined,
                    u8::try_from(k).expect("frontier layer index fits u8"),
                )
                .ok_or(FrontierError::InvalidNodeScalars)?;
                return layers
                    .last()
                    .and_then(|layer| layer.first().copied())
                    .ok_or(FrontierError::EmptyWithLeaves);
            }
            if !combined.is_empty() {
                carry = Some(promote_one(combined, k)?);
            }
        }
        Err(FrontierError::EmptyWithLeaves)
    }

    /// Serialize for the snapshot ring.
    ///
    /// Little-endian `leaf_count`, then the leaf scalars, then each partial
    /// layer's nodes. Widths are not stored: [`Self::expected_shape`] is the
    /// layout, and a stored width would be a second copy of it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.leaf_chunk.len() * 32);
        out.extend_from_slice(&self.leaf_count.to_le_bytes());
        for scalar in &self.leaf_chunk {
            out.extend_from_slice(scalar);
        }
        for layer in &self.partial {
            for node in layer {
                out.extend_from_slice(node);
            }
        }
        out
    }

    /// Parse [`Self::encode`]'s output.
    ///
    /// The chunk shape comes from [`Self::expected_shape`] of the count, and
    /// the body must be exactly that many scalars and nodes. A short or long
    /// body is [`FrontierError::Malformed`]. There is no width field to
    /// disagree with the count: the layout admits one shape per count.
    ///
    /// # Errors
    ///
    /// [`FrontierError::Malformed`] on a short or over-long input;
    /// [`FrontierError::TooDeep`] past [`MAX_PARTIAL_LAYERS`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FrontierError> {
        let mut cursor = Cursor { bytes, at: 0 };
        let leaf_count = u64::from_le_bytes(cursor.take_array::<8>()?);
        let (scalars, widths) = Self::expected_shape(leaf_count)?;
        let mut leaf_chunk = Vec::with_capacity(scalars);
        for _ in 0..scalars {
            leaf_chunk.push(cursor.take_array::<32>()?);
        }
        let mut partial = Vec::with_capacity(widths.len());
        for width in &widths {
            let mut layer = Vec::with_capacity(*width);
            for _ in 0..*width {
                layer.push(cursor.take_array::<32>()?);
            }
            partial.push(layer);
        }
        if cursor.at != bytes.len() {
            return Err(FrontierError::Malformed);
        }
        Ok(Self {
            leaf_chunk,
            partial,
            leaf_count,
        })
    }
}

/// One layer-`k` chunk hashed into its single layer-`k + 1` parent.
fn promote_one(nodes: Vec<[u8; 32]>, k: usize) -> Result<[u8; 32], FrontierError> {
    let from = u8::try_from(k).map_err(|_| FrontierError::TooDeep)?;
    let to = from.checked_add(1).ok_or(FrontierError::TooDeep)?;
    let promoted =
        try_promote_to_layer(nodes, from, to).ok_or(FrontierError::InvalidNodeScalars)?;
    match promoted.as_slice() {
        [node] => Ok(*node),
        // A chunk at or under its layer's width promotes to exactly one
        // node; anything else means the capacity and the width disagree.
        _ => Err(FrontierError::InvalidNodeScalars),
    }
}

fn hash_leaf_chunk(scalars: &[[u8; 32]]) -> Result<[u8; 32], FrontierError> {
    hash_grow_selene(&selene_hash_init(), 0, &ZERO, scalars)
        .ok_or(FrontierError::InvalidNodeScalars)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], FrontierError> {
        let end = self.at.checked_add(N).ok_or(FrontierError::Malformed)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(FrontierError::Malformed)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        self.at = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_fcmp::tree::{try_build_layers, HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH};

    /// Distinct, valid leaf bytes: four copies of a Selene scalar derived
    /// from `i`. Canonical by construction (the high byte stays clear).
    fn leaf(i: u64) -> [u8; LEAF_BYTES] {
        let mut out = [0u8; LEAF_BYTES];
        for (s, slot) in out.chunks_exact_mut(32).enumerate() {
            let index = u64::try_from(s).expect("scalar index fits u64");
            let mixed = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(index);
            slot[..8].copy_from_slice(&mixed.to_le_bytes());
            slot[8] = u8::try_from(s).expect("scalar index fits u8");
        }
        out
    }

    fn oracle_root(n: u64) -> [u8; 32] {
        if n == 0 {
            return selene_hash_init();
        }
        let mut scalars = Vec::new();
        for i in 0..n {
            for chunk in leaf(i).chunks_exact(32) {
                let mut s = [0u8; 32];
                s.copy_from_slice(chunk);
                scalars.push(s);
            }
        }
        let layers = try_build_layers(&scalars).expect("oracle builds");
        *layers.last().unwrap().first().unwrap()
    }

    fn frontier_through(n: u64) -> Frontier {
        let mut f = Frontier::new();
        for i in 0..n {
            f.push_leaf(&leaf(i)).expect("advance");
        }
        f
    }

    /// The derivation in [`Frontier::expected_shape`] is written from the
    /// fold rule, so it is graded against frontiers the fold actually built
    /// — never against a second copy of the same reasoning.
    #[test]
    fn expected_shape_matches_every_frontier_the_advance_builds() {
        let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
        let helios = u64::try_from(HELIOS_CHUNK_WIDTH).expect("width fits u64");
        // Both layer-count discontinuities (`0 -> 1` and the first cascade),
        // their neighbours, and a dense run that crosses the leaf fold many
        // times. A flat region alone cannot see a shape error.
        let mut counts: Vec<u64> = (0..=(selene * 3)).collect();
        for edge in [selene * helios, selene * helios * selene] {
            counts.extend([edge - 1, edge, edge + 1]);
        }
        for n in counts {
            let f = frontier_through(n);
            let (scalars, widths) =
                Frontier::expected_shape(n).expect("production counts are in range");
            assert_eq!(
                scalars,
                f.leaf_chunk.len(),
                "leaf-chunk scalars disagree at n = {n}"
            );
            assert_eq!(
                widths,
                f.partial.iter().map(Vec::len).collect::<Vec<_>>(),
                "partial widths disagree at n = {n}"
            );
        }
    }

    /// The body length is the shape of the count. Rewriting the count over a
    /// body built for a different count is a short or long buffer, which is
    /// [`FrontierError::Malformed`]. There is no width byte that could keep
    /// the old boundaries under the new count.
    #[test]
    fn decode_refuses_a_count_whose_body_belongs_to_another_shape() {
        let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
        let n = selene * 3;
        let bytes = frontier_through(n).encode();
        assert_eq!(
            Frontier::decode(&bytes).expect("the unmutated encoding decodes"),
            frontier_through(n),
            "the control must decode before a mutation of it means anything"
        );
        let (scalars, widths) = Frontier::expected_shape(n).expect("production count is in range");
        let implied = Frontier::HEADER_LEN
            + scalars * 32
            + widths.iter().map(|width| width * 32).sum::<usize>();
        assert_eq!(
            bytes.len(),
            implied,
            "encode wrote a length the shape does not name"
        );

        let successor = n + 1;
        let (next_scalars, next_widths) =
            Frontier::expected_shape(successor).expect("the successor is in range");
        let successor_len = Frontier::HEADER_LEN
            + next_scalars * 32
            + next_widths.iter().map(|width| width * 32).sum::<usize>();
        assert_ne!(
            bytes.len(),
            successor_len,
            "this count's successor must change the layout, or the mutation below is a no-op"
        );
        let mut forged = bytes.clone();
        forged[..Frontier::HEADER_LEN].copy_from_slice(&successor.to_le_bytes());
        assert_eq!(Frontier::decode(&forged), Err(FrontierError::Malformed));
    }

    /// A chunk at capacity folds in the same [`Frontier::push_leaf`], so no
    /// reachable count has a full leaf chunk or a full partial chunk. The
    /// encoding has no way to claim one: the layout never asks for it.
    #[test]
    fn a_reachable_shape_never_holds_a_full_chunk() {
        let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
        let helios = u64::try_from(HELIOS_CHUNK_WIDTH).expect("width fits u64");
        let mut counts: Vec<u64> = (0..=(selene * 3)).collect();
        for edge in [selene * helios, selene * helios * selene] {
            counts.extend([edge - 1, edge, edge + 1]);
        }
        for n in counts {
            let (scalars, widths) =
                Frontier::expected_shape(n).expect("production counts are in range");
            assert!(
                scalars < LEAF_CHUNK_SCALARS,
                "n = {n} asks for a full leaf chunk, which push_leaf folds away"
            );
            for (k, width) in widths.iter().enumerate() {
                assert!(
                    *width < Frontier::partial_capacity(k),
                    "n = {n} layer {k} asks for a full chunk, which the carry folds away"
                );
            }
        }
    }

    #[test]
    fn partial_capacity_is_the_parent_layers_width() {
        // `partial[0]` holds layer-0 nodes chunked into a layer-1 (Helios)
        // parent, so its capacity is the parent's width. Reading layer 0's
        // own width here is the off-by-one this asserts against.
        assert_eq!(Frontier::partial_capacity(0), HELIOS_CHUNK_WIDTH);
        assert_ne!(HELIOS_CHUNK_WIDTH, SELENE_CHUNK_WIDTH);
        assert_eq!(Frontier::partial_capacity(1), SELENE_CHUNK_WIDTH);
    }

    #[test]
    fn root_matches_the_batch_oracle_across_every_fold_boundary() {
        // Graded at every count through the first two leaf-chunk folds, and
        // then at the three counts around the first *cascade* — where a full
        // Helios chunk of layer-0 nodes folds into a layer-1 node. The dense
        // low range catches a partial-chunk error; the cascade triple catches
        // the carry. Re-deriving the oracle at all 684 counts is quadratic in
        // curve hashes and buys no case these do not cover.
        let selene = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
        let cascade =
            u64::try_from(SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH).expect("boundary fits u64");
        // Past the first cascade the layer-0 fold has to happen REPEATEDLY
        // for the root to stay right, and `folded` is the first count at
        // which a partial chunk sized by the WRONG layer's width stops being
        // invisible: the closure computes the correct root from an unfolded
        // chunk, so an over-wide chunk agrees with the oracle until it
        // finally fills and promotes to more than one node. `selene * selene`
        // is where a chunk sized by layer 0's own width (38) would fill;
        // correct code has folded twice by then, at 18 and 36 layer-0 nodes.
        let folded = selene * selene + 1;
        let dense_through = selene * 2 + 1;
        let graded: Vec<u64> = (0..=dense_through)
            .chain([cascade - 1, cascade, cascade + 1, folded])
            .collect();

        let mut f = Frontier::new();
        let mut next = 0u64;
        let mut folds = 0usize;
        let mut cascades = 0usize;
        for n in graded {
            while next < n {
                f.push_leaf(&leaf(next)).expect("advance");
                next += 1;
            }
            assert_eq!(f.leaf_count(), n, "leaf count at n={n}");
            assert_eq!(
                f.root().expect("close"),
                oracle_root(n),
                "frontier root disagrees with build_layers at n={n}"
            );
            assert_eq!(f.depth(), layer_count_for_leaves(n), "depth at n={n}");
            if n > 0 && n.is_multiple_of(selene) {
                folds += 1;
            }
            if n == cascade {
                cascades += 1;
            }
        }
        assert!(folds > 1, "no leaf-chunk fold was graded");
        assert_eq!(cascades, 1, "the layer-1 cascade was not graded");
        assert!(
            folded > cascade * 2,
            "the graded range never reaches a second layer-1 fold, so a partial chunk \
             sized by the wrong layer's width would agree with the oracle at every \
             count here — the closure computes the right root from an unfolded chunk"
        );
        // The two depths in the graded set differ, so a depth taken from the
        // wrong leaf count is visible rather than coincidentally equal.
        assert_ne!(
            layer_count_for_leaves(1),
            layer_count_for_leaves(cascade + 1),
            "the graded range spans no depth step"
        );
    }

    #[test]
    fn closing_does_not_consume_the_frontier() {
        let mut f = frontier_through(5);
        let before = f.clone();
        let first = f.root().expect("close");
        assert_eq!(f, before, "root() mutated the frontier");
        assert_eq!(f.root().expect("close"), first, "root() is not idempotent");
        f.push_leaf(&leaf(5)).expect("advance");
        assert_ne!(f.root().expect("close"), first, "advance changed no root");
    }

    #[test]
    fn encode_round_trips_at_each_shape() {
        let boundary =
            u64::try_from(SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH).expect("boundary fits u64");
        let selene_width = u64::try_from(SELENE_CHUNK_WIDTH).expect("width fits u64");
        for n in [
            0,
            1,
            selene_width - 1,
            selene_width,
            selene_width + 1,
            boundary,
            boundary + 1,
        ] {
            let f = frontier_through(n);
            let bytes = f.encode();
            assert!(
                bytes.len() <= Frontier::max_encoded_len(),
                "n={n} encodes to {} bytes, past the derived bound {}",
                bytes.len(),
                Frontier::max_encoded_len()
            );
            let back = Frontier::decode(&bytes).expect("round trip");
            assert_eq!(back, f, "round trip at n={n}");
            assert_eq!(back.root().expect("close"), f.root().expect("close"));
        }
    }

    #[test]
    fn decode_refuses_trailing_bytes_and_short_input() {
        let bytes = frontier_through(3).encode();
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(Frontier::decode(&longer), Err(FrontierError::Malformed));
        assert_eq!(
            Frontier::decode(&bytes[..bytes.len() - 1]),
            Err(FrontierError::Malformed)
        );
    }
}

#[cfg(test)]
mod sizing {
    use super::*;
    use crate::segment::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;

    /// Layers the production target tree reaches — `WALLET_SIDE_STORE.md`
    /// §6.3.2 row 4, and the depth `WSS_Q1B_BENCH_SPEC.md` grades at.
    const PRODUCTION_DEPTH: usize = 6;

    /// §6.3.2 row 4's **path** size, in bytes: a `38 x 128` leaf chunk, then
    /// one chunk per layer above it — `3 x 576` Helios and `2 x 1216` Selene
    /// at the production depth, in that proportion because the widths
    /// alternate `38, 18, ...` upward from the leaf layer.
    ///
    /// Quoted as the **bound** this implementation must fit inside, never as
    /// its size: a frontier is not a path — it holds each partial chunk one
    /// child short of folding and carries the leaf count — so the two differ,
    /// and the frontier's own size is derived from [`chunk_width`].
    ///
    /// This constant read `3 * 1216 + 2 * 576` until 2026-09-29, which
    /// inverted the Selene and Helios counts and so permitted regressions up
    /// to 9 664 B.
    const DESIGN_FRONTIER_BYTES: usize = 38 * 128 + 3 * 576 + 2 * 1216;

    /// Encoded size of a frontier whose every partial chunk is one child
    /// short of folding — the largest a frontier of this depth can be.
    ///
    /// The leaf count, then the scalars and nodes. No width bytes: the shape
    /// is [`Frontier::expected_shape`].
    fn full_frontier_bytes(partial_layers: usize) -> usize {
        Frontier::HEADER_LEN
            + (LEAF_CHUNK_SCALARS - 1) * 32
            + (0..partial_layers)
                .map(|k| (Frontier::partial_capacity(k) - 1) * 32)
                .sum::<usize>()
    }

    #[test]
    fn a_full_production_depth_frontier_fits_the_design_sizing() {
        // A depth-`d` tree has partial chunks at layers `0..d - 1`: the top
        // layer is the root, which has no parent to be a partial child of.
        let measured = full_frontier_bytes(PRODUCTION_DEPTH - 1);
        assert!(
            measured <= DESIGN_FRONTIER_BYTES,
            "a full depth-{PRODUCTION_DEPTH} frontier encodes to {measured} B, past §6.3.2 row 4's {DESIGN_FRONTIER_BYTES} B"
        );
        assert!(
            measured <= Frontier::max_encoded_len(),
            "the derived bound {} is below a shape the advance can reach ({measured} B)",
            Frontier::max_encoded_len()
        );
        // Pinned against a literal, not against `DESIGN_FRONTIER_BYTES`:
        // a bound derived the same way as the measurement is green by
        // construction, and this is the figure the round doc quotes.
        assert_eq!(
            measured, 8_840,
            "the frontier's encoded size is quoted in CT6_PROVING_STATE.md §9.4 and §10.1"
        );
        // The ring retains `[h - horizon, h]` — a CLOSED interval, so
        // `horizon + 1` rows. The horizon is cited rather than restated (C4);
        // the `+ 1` is the fencepost this increment corrected.
        let rows =
            usize::try_from(SEGMENT_FREEZE_REORG_MARGIN_BLOCKS).expect("horizon fits usize") + 1;
        assert_eq!(
            measured * rows,
            6_373_640,
            "the ring's whole cost is quoted in CT6_PROVING_STATE.md §9.4"
        );
    }
}
