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
//! `CurveTreeClient::entries` via [`assemble_leaf_stream`] (CT-4), because
//! pruned frozen segments may not retain a complete drained byte stream.
//! The gate does not see those branches. `verify_path_against_its_branches`
//! folds each assembled path onto the root it claims and refuses a path
//! whose branches came from somewhere else.
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

use crate::client::{ClientError, CurveTreeClient, CAPTURED_IDENTITY_BYTES};
use crate::store::StoreError;
use crate::types::{
    AssembleInput, AssembledPath, ChunkLeaf, CommitmentBytes, LeafEntry, OneTimePubkey,
    ReferenceBlock, TreeContext, TreePosition,
};
use shekyl_fcmp::tree::{
    chunk_width, hash_grow_helios, hash_grow_selene, helios_hash_init,
    helios_point_to_selene_scalar, key_image_generator, layer_is_selene, selene_hash_init,
    selene_point_to_helios_scalar, SCALARS_PER_LEAF, SELENE_CHUNK_WIDTH,
};

/// Which step `verify_path_against_its_branches` refused.
///
/// The branch hash does not take the child as an input.
/// [`Self::ChildAbsent`] is the link that binds this leaf chunk to these
/// branches. [`Self::RootDisagrees`] is the comparison with
/// [`TreeContext::tree_root`]. The other arms are a path the fold cannot
/// walk: a point that does not convert, a hash that does not land, or a
/// branch count that is not `tree_depth`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathRootFault {
    /// A leaf in the chunk does not convert to scalars.
    LeafRejected,
    /// The leaf chunk does not hash.
    LeafChunkRejected,
    /// Fewer branch layers than `tree_depth` accounts for.
    ShortPath,
    /// A path node does not convert to the scalar its parent stores.
    ChildRejected,
    /// A path node's scalar is not in its parent's branch.
    ChildAbsent,
    /// A branch does not hash.
    BranchRejected,
    /// More branch layers than `tree_depth` accounts for.
    LongPath,
    /// The folded root is not the root the path claims.
    RootDisagrees,
}

/// Fold an assembled path's own branches onto the root it claims.
///
/// The store gate compares [`CurveTreeClient::root_at`] with the reference.
/// The branches come from replay-held `entries`, and
/// [`TreeContext::tree_root`] is copied from that reference, so the gate
/// cannot see them. [`CurveTreeClient::root_and_depth_at`] would not either:
/// both of its answers come from the store. This fold reads the path.
///
/// Hash the leaf chunk to a Selene point. At each layer, convert that point
/// to the child scalar its parent stores, require the scalar to be present
/// in the branch, then hash the branch to the next point. Compare the last
/// point with `tree_root`.
///
/// Membership is the binding step. The branch hash does not take the child
/// as an input, so a correct root over another leaf's branches passes
/// without [`PathRootFault::ChildAbsent`]. The one-leaf replay fails at
/// [`PathRootFault::RootDisagrees`]: its own branch contains its leaf, and
/// the folded root is not the one the path claims.
///
/// Each node is `shekyl-fcmp`'s `hash_grow_*` at offset 0 from the layer's
/// init point, the same call [`shekyl_fcmp::tree::try_build_layers`] makes
/// per node. This is the path-shaped fold. It does not rebuild the tree,
/// and nothing else folds a path.
///
/// `O(depth)`, against the `O(n)` rebuild above it.
///
/// # Errors
///
/// [`PathRootFault`] names the step that refused. The caller reports it as
/// [`ClientError::PathRootMismatch`].
pub(crate) fn verify_path_against_its_branches(path: &AssembledPath) -> Result<(), PathRootFault> {
    const ZERO: [u8; 32] = [0u8; 32];

    // Layer 0: the leaf chunk hashes to a Selene point.
    let mut leaf_scalars: Vec<[u8; 32]> =
        Vec::with_capacity(path.leaf_chunk.len() * SCALARS_PER_LEAF);
    for leaf in &path.leaf_chunk {
        let scalars = leaf.scalars().ok_or(PathRootFault::LeafRejected)?;
        leaf_scalars.extend_from_slice(&scalars);
    }
    let mut point = hash_grow_selene(&selene_hash_init(), 0, &ZERO, &leaf_scalars)
        .ok_or(PathRootFault::LeafChunkRejected)?;

    // Layers 1..depth: the child must be in its parent's branch, and the
    // branch hashes to the parent.
    let mut c1 = path.c1_layers.iter();
    let mut c2 = path.c2_layers.iter();
    for layer in 1..path.tree.tree_depth {
        let selene = layer_is_selene(layer);
        let branch = if selene { c1.next() } else { c2.next() }.ok_or(PathRootFault::ShortPath)?;

        let child = if selene {
            helios_point_to_selene_scalar(&point)
        } else {
            selene_point_to_helios_scalar(&point)
        }
        .ok_or(PathRootFault::ChildRejected)?;

        if !branch.contains(&child) {
            return Err(PathRootFault::ChildAbsent);
        }

        point = if selene {
            hash_grow_selene(&selene_hash_init(), 0, &ZERO, branch)
        } else {
            hash_grow_helios(&helios_hash_init(), 0, &ZERO, branch)
        }
        .ok_or(PathRootFault::BranchRejected)?;
    }

    if c1.next().is_some() || c2.next().is_some() {
        return Err(PathRootFault::LongPath);
    }
    if point != path.tree.tree_root.to_bytes() {
        return Err(PathRootFault::RootDisagrees);
    }
    Ok(())
}

/// One drained leaf as a path carries it.
///
/// The one construction, used by the capture path's open-tail read and by
/// the rebuild alike, so the two cannot build the tuple differently.
fn chunk_leaf(entry: &LeafEntry) -> ChunkLeaf {
    ChunkLeaf {
        output_key: entry.identity.output_key,
        key_image_gen: key_image_generator(entry.identity.output_key.as_bytes()),
        // A drained leaf always has a commitment (try_build_leaf required
        // `i < outPk.size()`), so this never fires.
        commitment: entry
            .identity
            .commitment
            .expect("drained leaf has a commitment"),
        // `CM.x` as the leaf holds it, not the published point.
        cm_x: entry.cm_x(),
    }
}

/// Decode a layer-0 capture body — `O ‖ C ‖ CM.x` per sibling — into the
/// chunk leaves a path carries, deriving `I` as `Hp(O)`.
///
/// The consumer's side of the encoder in `client.rs`; written out rather
/// than shared with it, so the two can disagree and a pass can notice.
fn decode_captured_leaf_chunk(body: &[u8]) -> Result<Vec<ChunkLeaf>, ClientError> {
    if body.is_empty()
        || !body.len().is_multiple_of(CAPTURED_IDENTITY_BYTES)
        || body.len() > SELENE_CHUNK_WIDTH * CAPTURED_IDENTITY_BYTES
    {
        return Err(StoreError::CorruptMeta("captured leaf chunk is not whole identities").into());
    }
    Ok(body
        .chunks_exact(CAPTURED_IDENTITY_BYTES)
        .map(|row| {
            let mut o = [0u8; 32];
            let mut c = [0u8; 32];
            let mut cm_x = [0u8; 32];
            o.copy_from_slice(&row[0..32]);
            c.copy_from_slice(&row[32..64]);
            cm_x.copy_from_slice(&row[64..96]);
            ChunkLeaf {
                output_key: OneTimePubkey::from_bytes(o),
                key_image_gen: key_image_generator(&o),
                commitment: CommitmentBytes::from_bytes(c),
                cm_x,
            }
        })
        .collect())
}

/// Convert one layer's children to the scalars its parent's curve takes and
/// push them on the branch list for that curve.
///
/// Even layers are Selene nodes whose children are Helios points → Selene
/// scalars (C1); odd layers are Helios nodes whose children are Selene
/// points → Helios scalars (C2). The conversions are total for valid
/// consensus nodes (`node_conversions_are_total` in shekyl-fcmp), and a path
/// is only assembled after the root gate has passed.
fn push_branch(
    layer: u8,
    children: &[[u8; 32]],
    c1_layers: &mut Vec<Vec<[u8; 32]>>,
    c2_layers: &mut Vec<Vec<[u8; 32]>>,
) {
    if layer_is_selene(layer) {
        c1_layers.push(
            children
                .iter()
                .map(|p| helios_point_to_selene_scalar(p).expect("helios->selene"))
                .collect(),
        );
    } else {
        c2_layers.push(
            children
                .iter()
                .map(|p| selene_point_to_helios_scalar(p).expect("selene->helios"))
                .collect(),
        );
    }
}

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
    /// This is [`Self::assemble_paths`] of one input. The gate, what `n`
    /// counts, and the errors are that function's.
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
    /// input count and `n` the drained leaf count. Hoisting them makes it
    /// `n + k`.
    ///
    /// `n` is every drained leaf since genesis. `entries` only grows (`extend`
    /// on ingest, replaced wholesale by a rollback's rebuild), and a resume
    /// from a pruned store is refused ([`ClientError::ResumeFromPrunedStore`],
    /// F5). The 725-block replay window is a different quantity. The chain-age
    /// cost, and why no figure is stated here, is `CT6_PROVING_STATE.md` §11.2.
    ///
    /// Hoisting fixed the `k` factor. Capture removes the `n`, by reading an
    /// owned output's stored path material. Until that lands, assembly reads
    /// every drained leaf. The structural pin is
    /// `ct6_oracle::assembly_today_depends_on_every_foreign_leaf`, in three
    /// states. State 2, today: foreign leaves removed, the call refuses with
    /// [`ClientError::PathRootMismatch`] { [`PathRootFault::RootDisagrees`] }.
    /// State 3, capture: that call succeeds and the path equals the full-tree
    /// path.
    ///
    /// # Integrity
    ///
    /// Two checks, in order.
    ///
    /// The store gate runs once, before any input work, and a mismatch
    /// returns no paths. It compares [`Self::root_at`] at `reference.height`
    /// with `reference.curve_tree_root` ([`ClientError::RootMismatch`]).
    /// [`Self::root_and_depth_at`] is not consulted.
    ///
    /// The branches are rebuilt from replay-held `entries`, and every path
    /// in the batch shares that one layer stack. That is what makes
    /// `curve_tree_actor`'s *"every input shares one tree context"* true of
    /// the values and not merely of the `reference`. The store gate does not
    /// look at the stack. [`TreeContext::tree_root`] is copied from the
    /// gated reference. `verify_path_against_its_branches` then folds each
    /// assembled path onto that root and refuses with
    /// [`ClientError::PathRootMismatch`] (`CT6_PROVING_STATE.md` §11.6).
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
    /// [`ClientError::RootMismatch`] if [`Self::root_at`] at
    /// `reference.height` does not match `reference.curve_tree_root`.
    /// [`ClientError::PathRootMismatch`] if the assembled path's own branches
    /// do not commit to the root it claims; [`PathRootFault`] names the step.
    /// [`ClientError::OutputNotDrained`] if a `gindex` is not a drained leaf
    /// at the reference height. [`ClientError::IdentityMismatch`] if the leaf
    /// at a `gindex` does not carry the expected `(output_key, commitment)`.
    pub fn assemble_paths(
        &self,
        inputs: &[AssembleInput],
        reference: &ReferenceBlock,
    ) -> Result<Vec<AssembledPath>, ClientError> {
        // The integrity gate and the depth from ONE dispatcher: the ring
        // snapshot where it covers the height, the count-keyed store path
        // otherwise. Reading depth beside it from a second derivation would
        // let the two describe different tree states.
        let (got, depth) = self.root_and_depth_at(reference.height)?;
        if got != reference.curve_tree_root {
            return Err(ClientError::RootMismatch {
                height: reference.height,
                expected: reference.curve_tree_root,
                got,
            });
        }

        // State 3, total: every path comes from the captures over its
        // input and the frontier snapshot, and nothing here reads `entries`.
        // There is no rebuild to fall back to. An input reaches this
        // registered — the curve-tree actor syncs a batch's inputs before
        // assembling — or it is refused by name.
        self.assemble_from_captures(inputs, reference, depth)
    }

    /// Assemble a batch from the **captured** chunks over each input and the
    /// frontier snapshot at the reference height — reading no drained leaf
    /// beyond the open leaf chunk's own tail.
    ///
    /// Every shortfall is a named refusal. The one that used to be a
    /// fallback — an input with no resolved owned position — is
    /// [`ClientError::OutputNotRegistered`]: the rebuild it fell back to was
    /// the `O(chain)` pass capture exists to remove, and keeping it would
    /// have left a door nothing closed.
    ///
    /// # Each layer, from one of two places
    ///
    /// A layer-`L` chunk over position `p` is **closed** at the reference
    /// height iff its end is strictly below the drained count — the one
    /// comparison the capture key, the rollback and the backfill share — and
    /// then its contents are fixed and come from the table. Otherwise it is
    /// the rightmost chunk at its layer, still open, and its children are the
    /// snapshot's [`Frontier::open_branches`] entry for that layer. Layer 0
    /// is the exception in the open case: the frontier holds leaf *scalars*
    /// and a path needs sibling *points*, so the open leaf chunk's identities
    /// come from a ranged read of its own positions — at most
    /// `SELENE_CHUNK_WIDTH - 1` rows, the bounded identity tail increment 7
    /// retires with `entries`.
    ///
    /// Positions are permanent once assigned, so `position < drained count`
    /// is both "drained at this height" and "every closed chunk over it has
    /// a key below the count".
    ///
    /// # Errors
    ///
    /// [`ClientError::OutputNotRegistered`] if an input has no resolved
    /// owned position; [`ClientError::OutputNotDrained`] if that position is
    /// at or above the drained count at the reference height;
    /// [`ClientError::ReferenceOutsideSnapshotRing`] if the ring has no row
    /// there; [`ClientError::SnapshotLeafCountMismatch`] if the row's count
    /// is not the height's (C3); [`ClientError::CaptureMissing`] if a closed
    /// chunk's row lacks the layer; [`ClientError::IdentityMismatch`] if the
    /// leaf at the position does not carry the input's `(O, C)`;
    /// [`ClientError::PathRootMismatch`] from the artifact check;
    /// [`ClientError::Store`] on a read failure.
    fn assemble_from_captures(
        &self,
        inputs: &[AssembleInput],
        reference: &ReferenceBlock,
        depth: u8,
    ) -> Result<Vec<AssembledPath>, ClientError> {
        let mut positions = Vec::with_capacity(inputs.len());
        for input in inputs {
            match self
                .owned_positions
                .iter()
                .find(|(_, gindex)| **gindex == input.gindex)
            {
                Some((position, _)) => positions.push(*position),
                // No resolved position. Two different states, told apart by
                // the registry: a pair that IS held has simply not drained
                // (the fold resolves a position at the drain, and a batch's
                // sync reconciles anything held-and-drained before this is
                // called), which is the §4.3 lookup miss; a pair that is not
                // held was never registered, or the sync reported it stale.
                None if self.owned_outputs.get(&input.gindex) == Some(&input.output_key) => {
                    return Err(ClientError::OutputNotDrained {
                        gindex: input.gindex,
                        output_key: input.output_key,
                    })
                }
                None => {
                    return Err(ClientError::OutputNotRegistered {
                        gindex: input.gindex,
                        output_key: input.output_key,
                    })
                }
            }
        }

        let cutoff = Self::drained_through(reference.height);
        let drained_count = self.drained_leaf_count_at(cutoff);
        for (input, position) in inputs.iter().zip(&positions) {
            if *position >= drained_count {
                return Err(ClientError::OutputNotDrained {
                    gindex: input.gindex,
                    output_key: input.output_key,
                });
            }
        }

        let snapshot = self.snapshot_at(reference.height)?.ok_or(
            ClientError::ReferenceOutsideSnapshotRing {
                height: reference.height,
            },
        )?;
        if snapshot.leaf_count() != drained_count {
            return Err(ClientError::SnapshotLeafCountMismatch {
                height: reference.height,
                snapshot: snapshot.leaf_count(),
                expected: drained_count,
            });
        }
        let open = snapshot
            .open_branches()
            .map_err(|source| ClientError::Frontier {
                height: reference.height,
                source,
            })?;

        let mut paths = Vec::with_capacity(inputs.len());
        for (input, position) in inputs.iter().zip(positions) {
            let leaf_chunk = self.leaf_chunk_at(position, drained_count)?;
            let chunk_start = position / SELENE_CHUNK_WIDTH as u64 * SELENE_CHUNK_WIDTH as u64;
            let offset = usize::try_from(position - chunk_start).expect("an offset fits usize");
            let resolved = leaf_chunk.get(offset).ok_or(ClientError::CaptureMissing {
                end_leaf: chunk_start + SELENE_CHUNK_WIDTH as u64 - 1,
                layer: 0,
            })?;
            // The same X3 guard the rebuild applies, on the leaf the capture
            // holds at the position the fold resolved.
            if resolved.output_key != input.output_key || resolved.commitment != input.commitment {
                return Err(ClientError::IdentityMismatch {
                    gindex: input.gindex,
                    expected_output_key: input.output_key,
                    got_output_key: resolved.output_key,
                    commitment_matched: resolved.commitment == input.commitment,
                });
            }

            let mut c1_layers: Vec<Vec<[u8; 32]>> = Vec::new();
            let mut c2_layers: Vec<Vec<[u8; 32]>> = Vec::new();
            for layer in 1..depth {
                let children = match Self::due_chunk_end(position, layer, drained_count) {
                    Some(end_leaf) => self.captured_children(end_leaf, layer)?,
                    None => open
                        .get(usize::from(layer) - 1)
                        .filter(|branch| !branch.is_empty())
                        .cloned()
                        // The depth says this layer's chunk over the position
                        // is open, and the frontier has nothing open there: a
                        // state the advance cannot produce.
                        .ok_or(ClientError::Frontier {
                            height: reference.height,
                            source: crate::frontier::FrontierError::EmptyWithLeaves,
                        })?,
                };
                push_branch(layer, &children, &mut c1_layers, &mut c2_layers);
            }

            let assembled = AssembledPath {
                leaf_chunk,
                c1_layers,
                c2_layers,
                tree: TreeContext {
                    reference_block: reference.block_hash,
                    tree_root: reference.curve_tree_root,
                    tree_depth: depth,
                },
            };
            verify_path_against_its_branches(&assembled).map_err(|fault| {
                ClientError::PathRootMismatch {
                    claimed: assembled.tree.tree_root,
                    fault,
                }
            })?;
            paths.push(assembled);
        }
        Ok(paths)
    }

    /// The leaf chunk over `position` at a height with `drained_count`
    /// leaves: from the capture if it has closed, from the leaf rows' tail if
    /// it is still open.
    fn leaf_chunk_at(
        &self,
        position: u64,
        drained_count: u64,
    ) -> Result<Vec<ChunkLeaf>, ClientError> {
        let width = SELENE_CHUNK_WIDTH as u64;
        let chunk_start = position / width * width;
        match Self::due_chunk_end(position, 0, drained_count) {
            Some(end_leaf) => {
                let body = self.captured_body(end_leaf, 0)?;
                decode_captured_leaf_chunk(&body)
            }
            None => {
                let entries = self.store.read_drained_range(
                    TreePosition::from_raw(chunk_start),
                    TreePosition::from_raw(drained_count - 1),
                )?;
                Ok(entries.iter().map(chunk_leaf).collect())
            }
        }
    }

    /// The children of the closed layer-`layer` chunk that ended at
    /// `end_leaf`, from the capture table.
    fn captured_children(&self, end_leaf: u64, layer: u8) -> Result<Vec<[u8; 32]>, ClientError> {
        let body = self.captured_body(end_leaf, layer)?;
        let width = chunk_width(layer);
        if body.len() != width * 32 {
            return Err(
                StoreError::CorruptMeta("captured node chunk is not one full width").into(),
            );
        }
        Ok(body
            .chunks_exact(32)
            .map(|node| {
                let mut word = [0u8; 32];
                word.copy_from_slice(node);
                word
            })
            .collect())
    }

    /// The captured body at `(end_leaf, layer)`, or [`ClientError::CaptureMissing`].
    fn captured_body(&self, end_leaf: u64, layer: u8) -> Result<Vec<u8>, ClientError> {
        self.store
            .captured_chunks(TreePosition::from_raw(end_leaf))?
            .into_iter()
            .find(|chunk| chunk.layer == layer)
            .map(|chunk| chunk.bytes)
            .ok_or(ClientError::CaptureMissing { end_leaf, layer })
    }
}
