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

use std::collections::HashMap;

use crate::types::Gindex;

use crate::client::{ClientError, CurveTreeClient};
use crate::recon::{assemble_leaf_stream, drained_sorted};
use crate::types::{AssembleInput, AssembledPath, ChunkLeaf, ReferenceBlock, TreeContext};
use shekyl_fcmp::tree::{
    build_layers, chunk_width, helios_point_to_selene_scalar, key_image_generator, layer_is_selene,
    selene_point_to_helios_scalar, SELENE_CHUNK_WIDTH,
};

impl CurveTreeClient {
    /// Assemble the FCMP++ membership path for one owned output at a
    /// reference block.
    ///
    /// `input` resolves the owned leaf by its **`gindex`** — the tree's unique
    /// key, equal to the wallet's `TransferDetails.global_output_index` (X3,
    /// CT-5c). Resolution by `gindex` is total (an owned output is always a
    /// drained leaf), so there is no `(output_key, commitment)` collision case;
    /// the carried `(output_key, commitment)` is used only to *verify* the
    /// resolution after the fact ([`ClientError::IdentityMismatch`]), catching
    /// a tree-vs-scanner numbering desync rather than performing the lookup.
    ///
    /// The block hash threaded into [`TreeContext::reference_block`] (for the
    /// eventual `CtSig.referenceBlock`) is [`ReferenceBlock::block_hash`] — the
    /// caller supplies the full consensus anchor (height, root, hash) as one
    /// value. Reference-block *selection* (the validity-horizon arithmetic in
    /// [`crate::reference`], e.g. [`crate::reference::select_reference_height`])
    /// is the caller's, against its own chain view; it is landed and pure
    /// height arithmetic, not a `ReferenceBlock` constructor (§5).
    ///
    /// Runs the integrity gate first: returns [`ClientError::RootMismatch`]
    /// if the reconstructed root does not match `reference.curve_tree_root`,
    /// [`ClientError::OutputNotDrained`] if `input.gindex` is not a drained
    /// leaf at the reference height, and [`ClientError::IdentityMismatch`] if
    /// the leaf at `input.gindex` does not carry the expected `(output_key,
    /// commitment)`.
    pub fn assemble_path(
        &self,
        input: &AssembleInput,
        reference: &ReferenceBlock,
    ) -> Result<AssembledPath, ClientError> {
        let mut paths = self.assemble_paths(std::slice::from_ref(input), reference)?;
        Ok(paths.pop().expect("one input yields one path"))
    }

    /// Assemble every membership path for one transaction, reconstructing the
    /// tree **once** for the batch (`CT-6` increment 3, closeout row (a)).
    ///
    /// # Why this is the primitive and `assemble_path` the special case
    ///
    /// Each path needs the same three things: the drained leaves at the
    /// reference cutoff, the layers built over them, and the position of one
    /// `gindex` among those leaves. Only the third is per-input. Assembling
    /// per input therefore paid `build_layers` and `drained_sorted` over the
    /// **whole** drained stream once per input — `k · n` where `k` is the
    /// input count and `n` the drained leaf count (765 600 at the graded
    /// worst case). Hoisting them makes it `n + k`.
    ///
    /// **The integrity gate runs once, before any input work**, and a mismatch
    /// returns with **no** paths assembled rather than a partial batch. Every
    /// path below is then derived from the same `layers` that gate approved,
    /// which is what makes `curve_tree_actor`'s *"every input shares one tree
    /// context"* true of the values and not merely of the `reference`.
    ///
    /// # Duplicate inputs are not refused here
    ///
    /// Two inputs naming one `gindex` assemble two identical paths, exactly as
    /// the per-input loop did. Spending one output twice is caught by the
    /// key-image check at consensus, not by path assembly, and minting a
    /// second refusal here would put the same rule in two places.
    ///
    /// # Errors
    ///
    /// [`ClientError::RootMismatch`] if the reconstructed root does not match
    /// `reference.curve_tree_root`; [`ClientError::OutputNotDrained`] if a
    /// `gindex` is not a drained leaf at the reference height;
    /// [`ClientError::IdentityMismatch`] if the leaf at a `gindex` does not
    /// carry the expected `(output_key, commitment)`.
    pub fn assemble_paths(
        &self,
        inputs: &[AssembleInput],
        reference: &ReferenceBlock,
    ) -> Result<Vec<AssembledPath>, ClientError> {
        let cutoff = Self::drained_through(reference.height);

        // Two mechanisms by design: (1) integrity gate — store-backed `root_at`
        // (CT-1), no replay-oracle fallback; (2) path branches — replay
        // `entries` + `build_layers(assemble_leaf_stream(...))` (CT-4), because
        // `prune_frozen` may drop non-owned leaf bytes from frozen segments.
        let got = self.root_at(reference.height)?;
        if got != reference.curve_tree_root {
            return Err(ClientError::RootMismatch {
                height: reference.height,
                expected: reference.curve_tree_root,
                got,
            });
        }

        let stream = assemble_leaf_stream(&self.entries, cutoff);
        let layers = build_layers(&stream);

        // One drain-order definition shared with the scalar stream, so a
        // leaf's index here equals its index in `stream` (recon §S2).
        let drained = drained_sorted(&self.entries, cutoff);
        // X3: resolve by `gindex`, the tree's unique key, not by `(O, C)`
        // content. The owned output's gindex is always present among drained
        // leaves, so this is total — no collision case.
        //
        // `drained` is sorted by `(maturity, gindex)`, so `gindex` is not
        // monotonic and a binary search does not apply. With the reconstruction
        // hoisted, a linear scan per input would be the remaining `k · n` term,
        // so the positions are indexed once instead: `n` inserts against `k`
        // lookups, where `k <= shekyl_fcmp::MAX_INPUTS` (8) and `n` is the
        // drained leaf count (765 600 at the graded worst case). `Gindex` is
        // `Hash + Eq` from `scalar_u64!`, so this needs nothing from
        // `shekyl-types`.
        let positions: HashMap<Gindex, usize> = drained
            .iter()
            .enumerate()
            .map(|(pos, e)| (e.gindex, pos))
            .collect();

        let mut paths = Vec::with_capacity(inputs.len());
        for input in inputs {
            let leaf_pos = *positions
                .get(&input.gindex)
                .ok_or(ClientError::OutputNotDrained {
                    gindex: input.gindex,
                    output_key: input.output_key,
                })?;
            // Post-resolution consistency check (X3): the leaf at `gindex` must be
            // the output the caller expected. A mismatch means the tree's
            // `next_output_seq` numbering and the wallet's `global_output_index`
            // have diverged (or the store/scanner desynced) — refuse rather than
            // assemble a wrong-leaf proof. This is the only runtime guard of that
            // inter-component invariant (no single component owns it).
            let resolved = &drained[leaf_pos];
            if resolved.identity.output_key != input.output_key
                || resolved.identity.commitment != Some(input.commitment)
            {
                return Err(ClientError::IdentityMismatch {
                    gindex: input.gindex,
                    expected_output_key: input.output_key,
                    got_output_key: resolved.identity.output_key,
                    commitment_matched: resolved.identity.commitment == Some(input.commitment),
                });
            }

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
                    key_image_gen: key_image_generator(e.identity.output_key.as_bytes()),
                    // A drained leaf always has a commitment (try_build_leaf
                    // required `i < outPk.size()`), so this never fires.
                    commitment: e
                        .identity
                        .commitment
                        .expect("drained leaf has a commitment"),
                    // The 4th scalar as the leaf holds it — `CM.x`, already
                    // extracted by `construct_leaf` — not the published point.
                    cm_x: {
                        let mut x = [0u8; 32];
                        x.copy_from_slice(&e.leaf[96..128]);
                        x
                    },
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

            paths.push(AssembledPath {
                leaf_chunk,
                c1_layers,
                c2_layers,
                tree: TreeContext {
                    reference_block: reference.block_hash,
                    // Equals our reconstruction (verify_root just confirmed it);
                    // carry the consensus value.
                    tree_root: reference.curve_tree_root,
                    tree_depth: depth,
                },
            });
        }

        Ok(paths)
    }
}
