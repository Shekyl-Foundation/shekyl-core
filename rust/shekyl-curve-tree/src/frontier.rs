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
    chunk_width, hash_grow_selene, layer_count_for_leaves, outputs_per_node, selene_hash_init,
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

/// A chunk that **finalized** during a push: the complete child set of a node
/// that just closed, with the coordinates that identify it.
///
/// A chunk is final once its last child has arrived, and from that moment its
/// contents never change — which is what makes it capturable. Before that it
/// is the rightmost partial chunk at its layer, which is what the frontier
/// itself holds.
///
/// # The two shapes, and why layer 0 is reported anyway
///
/// At `layer >= 1` the children are tree **nodes**, and they are everything a
/// membership path needs at that layer.
///
/// At `layer == 0` the children are leaf **scalars** — four per leaf. A path
/// needs the siblings as compressed *points* (`O`, `I`, `C`) beside `CM.x`,
/// and `O.x` is a one-way projection of `O`, so the points cannot be
/// recovered from here. Layer 0 is still reported, because the *event* is what
/// a capturing caller needs: it says which leaf chunk closed and at which
/// index, and the caller assembles the identities from the leaf entries it
/// already holds.
#[derive(Clone, Copy, Debug)]
pub struct FoldedChunk<'a> {
    /// Absolute tree layer of the node whose children these are.
    pub layer: u8,
    /// That node's index within its layer.
    pub index: u64,
    /// Inclusive leaf position at which the chunk closed — its **finality
    /// coordinate**.
    ///
    /// A truncation un-finalizes this chunk when its **first removed leaf
    /// position** is `<= end_leaf`; the chunk survives when that position is
    /// `> end_leaf`. The store's truncation takes exactly that quantity
    /// (`delete_pos_keys_batched` deletes `range(start..)`, so `start` is the
    /// first removed position), and it is also the surviving leaf **count**,
    /// because positions `0..start` are what remain.
    ///
    /// So one comparison serves twice, and the units cannot be mixed:
    /// `end_leaf < surviving_leaf_count` is both *"this chunk survived the
    /// cut"* and *"this chunk is usable at that tip"* — the same test the
    /// reference-height rule applies as `end_leaf < drained_leaf_count_at(h)`.
    ///
    /// Stated this precisely because the coordinate is where a fencepost
    /// hides: "a rollback at this position" is ambiguous between the first
    /// removed leaf and the new leaf count, and the ring's own
    /// `(h - horizon, h]` boundary was found in that kind of seam. What
    /// matters is the chunk's own end, never the owned leaf's position — leaf
    /// 100 survives a cut to 150 while its layer-1 chunk (`0..683`) does not.
    pub end_leaf: u64,
    /// The children, in order. Scalars at layer 0, nodes above it.
    pub children: &'a [[u8; 32]],
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
        self.push_leaf_observed(leaf, &mut |_| {})
    }

    /// [`Self::push_leaf`], reporting every chunk that **finalized** during
    /// the push.
    ///
    /// Zero, one, or several chunks close on a single leaf: none for most
    /// pushes, and a cascade when a leaf completes a run of nested chunks at
    /// once. They are reported bottom-up, in the order they closed.
    ///
    /// The observer takes a borrow of the chunk the frontier is about to
    /// consume, so a caller that wants to keep it copies it; one that does not
    /// pays nothing. [`Self::push_leaf`] passes a no-op, which is why adding
    /// this did not move any of its callers — and why the fold logic stays in
    /// one place rather than being duplicated into a capturing variant.
    ///
    /// # Errors
    ///
    /// As [`Self::push_leaf`].
    pub fn push_leaf_observed(
        &mut self,
        leaf: &[u8; LEAF_BYTES],
        observe: &mut impl FnMut(FoldedChunk<'_>),
    ) -> Result<(), FrontierError> {
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
        observe(FoldedChunk {
            layer: 0,
            index: Self::closed_node_index(self.leaf_count, 0),
            end_leaf: self.leaf_count - 1,
            children: &self.leaf_chunk,
        });
        self.leaf_chunk.clear();
        self.carry(0, node, observe)
    }

    /// Index of the layer-`layer` node that closes when the tree reaches
    /// `leaf_count` leaves.
    ///
    /// Each node at that layer covers [`outputs_per_node`] leaves and they
    /// fill left to right, so the one that just closed is the last complete
    /// one. Derived rather than counted: a running tally would be a second
    /// copy of the fold schedule.
    fn closed_node_index(leaf_count: u64, layer: u8) -> u64 {
        let covered = u64::try_from(outputs_per_node(layer)).expect("node capacity fits u64");
        leaf_count / covered - 1
    }

    /// Fold `node` into `partial[k]`, cascading while chunks fill.
    fn carry(
        &mut self,
        mut k: usize,
        mut node: [u8; 32],
        observe: &mut impl FnMut(FoldedChunk<'_>),
    ) -> Result<(), FrontierError> {
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
            // `partial[k]` is the child set of a layer-`k + 1` node, so that
            // is the node which just closed. Reported before `promote_one`
            // consumes the chunk.
            let layer = u8::try_from(k + 1).expect("frontier layer fits u8");
            observe(FoldedChunk {
                layer,
                index: Self::closed_node_index(self.leaf_count, layer),
                end_leaf: self.leaf_count - 1,
                children: &full,
            });
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
        let branches = self.open_branches()?;
        let top = branches.len() - 1;
        let combined = branches
            .into_iter()
            .last()
            .ok_or(FrontierError::EmptyWithLeaves)?;
        if combined.is_empty() {
            return Err(FrontierError::EmptyWithLeaves);
        }
        // At the topmost non-empty layer `combined` IS that whole layer, so
        // the batch composition's own stop condition decides the root rather
        // than a second copy of it.
        let layers = try_build_upper_layers(
            combined,
            u8::try_from(top).expect("frontier layer index fits u8"),
        )
        .ok_or(FrontierError::InvalidNodeScalars)?;
        layers
            .last()
            .and_then(|layer| layer.first().copied())
            .ok_or(FrontierError::EmptyWithLeaves)
    }

    /// The children of the rightmost — still **open** — node at every layer
    /// above the leaves, bottom-up: entry `k` is the child set of the
    /// layer-`k + 1` node currently being built.
    ///
    /// This is what a membership path needs wherever its chunk has *not*
    /// closed: a closed chunk's children are fixed and captured, an open
    /// chunk's are exactly these. Each entry is `partial[k]` — the closed
    /// layer-`k` nodes carried so far — followed by the node of the open
    /// chunk below it, hashed as it stands, because that node is a child of
    /// this one too even though it is not final. [`Self::root`] is this
    /// vector's last entry composed upward; the two share one computation so
    /// a path's open branch and the root it must hash to cannot be read from
    /// different states.
    ///
    /// Layer 0 is **not** here. The open leaf chunk holds scalars, and a path
    /// needs its siblings as points; those come from the leaf rows.
    ///
    /// The last entry is never empty on a non-empty frontier; lower entries
    /// can be — a layer whose open node has no children yet, because the
    /// chunk below it is also just starting. A reader that consults an empty
    /// entry is asking about a chunk that has closed, and should have read
    /// the capture.
    ///
    /// # Errors
    ///
    /// [`FrontierError::InvalidNodeScalars`] on a hash failure;
    /// [`FrontierError::EmptyWithLeaves`] on bytes the advance cannot
    /// produce.
    pub fn open_branches(&self) -> Result<Vec<Vec<[u8; 32]>>, FrontierError> {
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
        let mut branches = Vec::with_capacity(top + 1);
        for k in 0..=top {
            let mut combined = self.partial.get(k).cloned().unwrap_or_default();
            combined.extend(carry.take());
            if k < top && !combined.is_empty() {
                carry = Some(promote_one(combined.clone(), k)?);
            }
            branches.push(combined);
        }
        if self.leaf_count > 0 && branches.last().is_none_or(Vec::is_empty) {
            return Err(FrontierError::EmptyWithLeaves);
        }
        Ok(branches)
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
mod tests;

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
