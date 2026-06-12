// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Membership-path assembly (CT-4).
//!
//! Given a drained leaf and the reconstructed tree layers, produce the
//! [`AssembledPath`] that an FCMP++ membership proof consumes (the full child
//! chunk of each path node from leaf to root at the reference height). Gated
//! behind a correct root at the reference height: a path assembled against a
//! wrong tree is a wrong proof, so assembly applies the integrity gate (§3.3)
//! before building. The gate uses the store-backed [`CurveTreeClient::root_at`]
//! hot path (CT-1); branch extraction rebuilds layers from replay-held
//! [`CurveTreeClient::entries`] via [`assemble_leaf_stream`] (CT-4), because
//! pruned frozen segments may not retain a complete drained byte stream.
//!
//! ## Path layout (pinned to the FCMP++ prover at source)
//!
//! Matches `shekyl-oxide/crypto/fcmps/src/prover/mod.rs`'s `Path`
//! (`C::C1 = Selene`, `C::C2 = Helios`, `C::OC = Ed25519`):
//!
//! - The leaf chunk hashes to a **C1 (Selene)** point; its x-coordinates feed
//!   a **C2 (Helios)** node; that feeds C1; alternating upward. So the odd
//!   tree layers (1, 3, …) are Helios → [`AssembledPath::c2_layers`], and the
//!   even internal layers (2, 4, …) are Selene → [`AssembledPath::c1_layers`].
//! - Each branch is the **full child chunk** of the path node (siblings are
//!   not excluded); the prover pads each chunk to the layer width, so only the
//!   real children are emitted here.
//! - The topmost branch is the root node's children; the root *point* itself
//!   is excluded (it is supplied separately as [`TreeContext::tree_root`], the
//!   prover's `TreeRoot`). The C3 invariant
//!   `c1_layers.len() + c2_layers.len() + 1 == tree_depth` then holds (the
//!   leaf layer is the `+1`).
//!
//! See `docs/design/CURVE_TREE_CLIENT.md` §3.5 / §5.

use crate::client::{ClientError, CurveTreeClient};
use crate::recon::{assemble_leaf_stream, drained_sorted};
use crate::types::{AssembledPath, ChunkLeaf, OutputIdentity, ReferenceBlock, TreeContext};
use shekyl_fcmp::tree::{
    build_layers, chunk_width, helios_point_to_selene_scalar, key_image_generator, layer_is_selene,
    selene_point_to_helios_scalar, SELENE_CHUNK_WIDTH,
};

impl CurveTreeClient {
    /// Assemble the FCMP++ membership path for one owned output at a
    /// reference block.
    ///
    /// `id` is matched against the drained leaves by output key (`O`,
    /// primary) and commitment (`C`, disambiguation), per §4.3.
    /// `reference_block_hash` is the hash of the block at `reference.height`
    /// (held by the caller from the synced header); it is threaded into
    /// [`TreeContext::reference_block`] for the eventual
    /// `rctSig.referenceBlock`. (`select_reference_block`, §5, will later
    /// bundle the hash with the reference so this argument folds in; it is
    /// explicit here while that horizon logic is deferred.)
    ///
    /// Runs the integrity gate first: returns [`ClientError::RootMismatch`]
    /// if the reconstructed root does not match `reference.curve_tree_root`,
    /// and [`ClientError::OutputNotDrained`] if `id` is not a drained leaf at
    /// the reference height.
    pub fn assemble_path(
        &self,
        id: &OutputIdentity,
        reference: &ReferenceBlock,
        reference_block_hash: [u8; 32],
    ) -> Result<AssembledPath, ClientError> {
        let cutoff = Self::drained_through(reference.height.0);

        // Two mechanisms by design: (1) integrity gate — store-backed `root_at`
        // (CT-1), no replay-oracle fallback; (2) path branches — replay
        // `entries` + `build_layers(assemble_leaf_stream(...))` (CT-4), because
        // `prune_frozen` may drop non-owned leaf bytes from frozen segments.
        let got = self.root_at(reference.height.0)?;
        if got != reference.curve_tree_root {
            return Err(ClientError::RootMismatch {
                height: reference.height.0,
                expected: reference.curve_tree_root,
                got,
            });
        }

        let stream = assemble_leaf_stream(&self.entries, cutoff);
        let layers = build_layers(&stream);

        // One drain-order definition shared with the scalar stream, so a
        // leaf's index here equals its index in `stream` (recon §S2).
        let drained = drained_sorted(&self.entries, cutoff);
        let leaf_pos = drained
            .iter()
            .position(|e| {
                e.identity.output_key == id.output_key && e.identity.commitment == id.commitment
            })
            .ok_or(ClientError::OutputNotDrained {
                output_key: id.output_key,
            })?;

        let depth = u8::try_from(layers.len()).expect("curve-tree depth fits u8");

        // Leaf chunk: the SELENE_CHUNK_WIDTH outputs of the path's layer-0
        // node, as compressed-point tuples (the prover's `Path.leaves`).
        let leaf_node_idx = leaf_pos / SELENE_CHUNK_WIDTH;
        let leaf_start = leaf_node_idx * SELENE_CHUNK_WIDTH;
        let leaf_end = (leaf_start + SELENE_CHUNK_WIDTH).min(drained.len());
        let leaf_chunk: Vec<ChunkLeaf> = drained[leaf_start..leaf_end]
            .iter()
            .map(|e| ChunkLeaf {
                output_key: e.identity.output_key,
                key_image_gen: key_image_generator(&e.identity.output_key),
                // A drained leaf always has a commitment (try_build_leaf
                // required `i < outPk.size()`), so this never fires.
                commitment: e
                    .identity
                    .commitment
                    .expect("drained leaf has a commitment"),
                h_pqc: e.identity.h_pqc,
            })
            .collect();

        // Branch for each path node at layers 1..=depth-1 (the topmost is the
        // root node's children). The conversions are total for valid
        // consensus nodes (asserted by `node_conversions_are_total` in
        // shekyl-fcmp), and assembly runs only after verify_root succeeds.
        let mut c1_layers: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut c2_layers: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut child_node_idx = leaf_node_idx;
        for layer in 1..depth {
            let width = chunk_width(layer);
            let node_idx = child_node_idx / width;
            let prev = &layers[usize::from(layer) - 1];
            let start = node_idx * width;
            let end = (start + width).min(prev.len());
            if layer_is_selene(layer) {
                // Even layer (Selene node): children are x-coords of the
                // Helios points below → Selene scalars (C1).
                let scalars = prev[start..end]
                    .iter()
                    .map(|p| helios_point_to_selene_scalar(p).expect("helios->selene"))
                    .collect();
                c1_layers.push(scalars);
            } else {
                // Odd layer (Helios node): children are x-coords of the
                // Selene points below → Helios scalars (C2).
                let scalars = prev[start..end]
                    .iter()
                    .map(|p| selene_point_to_helios_scalar(p).expect("selene->helios"))
                    .collect();
                c2_layers.push(scalars);
            }
            child_node_idx = node_idx;
        }

        // C3 self-check (the leaf layer is the `+1`; the root point is
        // excluded). Holds by construction; a violation is a logic bug.
        debug_assert_eq!(
            c1_layers.len() + c2_layers.len() + 1,
            usize::from(depth),
            "assembled path depth must match the tree depth"
        );

        Ok(AssembledPath {
            leaf_chunk,
            c1_layers,
            c2_layers,
            tree: TreeContext {
                reference_block: reference_block_hash,
                // Equals our reconstruction (verify_root just confirmed it);
                // carry the consensus value.
                tree_root: reference.curve_tree_root,
                tree_depth: depth,
            },
        })
    }
}
