// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Membership-path assembly (CT-4).
//!
//! Given a drained leaf, produce the [`AssembledPath`] an FCMP++ membership
//! proof consumes (the full child chunk of each path node from leaf to root
//! at the reference height). Gated behind a correct root at the reference
//! height: a path assembled against a wrong tree is a wrong proof, so
//! assembly applies the integrity gate (§3.3) before building. The gate is
//! [`CurveTreeClient::root_and_depth_at`]: one reading supplies the root and
//! the depth both routes stamp. A registered batch reads its branches from
//! the capture table and the frontier snapshot. An unregistered batch
//! rebuilds layers from replay-held `CurveTreeClient::entries` via
//! [`assemble_leaf_stream`] (CT-4). Pruned frozen segments may not retain a
//! complete drained byte stream, and the engine registrant is not yet the
//! caller of registration, so that rebuild is the route production batches
//! take. The gate does not see those branches.
//! `verify_path_against_its_branches` folds each assembled path onto the
//! root it claims and refuses a path whose branches came from somewhere else.
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

use crate::client::{
    ChunkSpan, ClientError, CurveTreeClient, CAPTURED_IDENTITY_BYTES, CAPTURED_IDENTITY_CM_X_AT,
    CAPTURED_IDENTITY_COMMITMENT_AT, CAPTURED_IDENTITY_OUTPUT_KEY_AT, CURVE_ELEMENT_BYTES,
    NODE_CHILD_BYTES,
};
use crate::recon::{assemble_leaf_stream, drained_sorted};
use crate::store::StoreError;
use crate::types::{
    AssembleInput, AssembledPath, ChunkLeaf, CommitmentBytes, LeafEntry, OneTimePubkey,
    ReferenceBlock, TreeContext, TreePosition,
};
use shekyl_fcmp::tree::{
    build_layers, chunk_width, hash_grow_helios, hash_grow_selene, helios_hash_init,
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
/// The store gate is [`CurveTreeClient::root_and_depth_at`]: it checks the
/// reference's root and supplies the depth. The branches come from the route
/// that assembled the path — the capture table and the frontier snapshot, or
/// the rebuild of replay-held `entries`. [`TreeContext::tree_root`] is copied
/// from the reference, so the gate's two answers do not see the branches.
/// This fold reads the path.
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

/// One curve element at a named offset in a capture row.
///
/// The encoder in `client::capture` writes the same offsets into a fixed
/// row. This read is written out beside it, so the two can disagree and a
/// pass can see it. A swapped offset moves both; a disagreement with
/// [`chunk_leaf`], which does not use the offsets, still fails the oracle.
fn curve_element_at(row: &[u8], at: usize) -> [u8; CURVE_ELEMENT_BYTES] {
    let mut word = [0u8; CURVE_ELEMENT_BYTES];
    word.copy_from_slice(&row[at..at + CURVE_ELEMENT_BYTES]);
    word
}

/// Decode a closed layer-0 capture body into the chunk leaves a path carries,
/// deriving `I` as `Hp(O)`.
///
/// A closed layer-0 chunk is exactly [`SELENE_CHUNK_WIDTH`] siblings of
/// `O ‖ C ‖ CM.x`. A shorter body is a row the merge should never have
/// stored: the fold and the backfill both refuse a short read before they
/// write. Open leaf chunks are not decoded here; they are leaf rows, via
/// [`chunk_leaf`].
fn decode_captured_leaf_chunk(body: &[u8]) -> Result<Vec<ChunkLeaf>, ClientError> {
    let full = SELENE_CHUNK_WIDTH * CAPTURED_IDENTITY_BYTES;
    if body.len() != full {
        return Err(StoreError::CorruptMeta("captured leaf chunk is not one full width").into());
    }
    Ok(body
        .chunks_exact(CAPTURED_IDENTITY_BYTES)
        .map(|row| {
            let output_key = curve_element_at(row, CAPTURED_IDENTITY_OUTPUT_KEY_AT);
            let commitment = curve_element_at(row, CAPTURED_IDENTITY_COMMITMENT_AT);
            let cm_x = curve_element_at(row, CAPTURED_IDENTITY_CM_X_AT);
            ChunkLeaf {
                output_key: OneTimePubkey::from_bytes(output_key),
                key_image_gen: key_image_generator(&output_key),
                commitment: CommitmentBytes::from_bytes(commitment),
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
/// consensus nodes (`node_conversions_are_total` in shekyl-fcmp) — but the
/// capture route hands this **persisted** bytes that were only
/// length-checked, and a 32-byte string that is not a point is a corrupt
/// row, not a programming error. So this is fallible, and an unconvertible
/// child is [`StoreError::CorruptMeta`]: a refusal the caller can classify
/// as a corrupt store, where an `expect` would have taken the wallet down
/// with it.
///
/// # Errors
///
/// [`StoreError::CorruptMeta`] if a child does not decode as a point of the
/// layer's curve.
fn push_branch(
    layer: u8,
    children: &[[u8; 32]],
    c1_layers: &mut Vec<Vec<[u8; 32]>>,
    c2_layers: &mut Vec<Vec<[u8; 32]>>,
) -> Result<(), StoreError> {
    if layer_is_selene(layer) {
        let scalars = children
            .iter()
            .map(|p| {
                helios_point_to_selene_scalar(p).ok_or(StoreError::CorruptMeta(
                    "captured child is not a Helios point",
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        c1_layers.push(scalars);
    } else {
        let scalars = children
            .iter()
            .map(|p| {
                selene_point_to_helios_scalar(p).ok_or(StoreError::CorruptMeta(
                    "captured child is not a Selene point",
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        c2_layers.push(scalars);
    }
    Ok(())
}

/// What [`CurveTreeClient::assemble_from_captures`] decided.
///
/// [`Self::Paths`] is a batch whose every input resolved to an owned
/// position. [`Self::Unregistered`] is a batch the registrant has not named,
/// and the caller rebuilds it. A hole in a registered batch is an error on
/// the `Result`, so it cannot fall through into that rebuild.
enum CaptureAssembly {
    /// Every input resolved, and each path is sealed.
    Paths(Vec<AssembledPath>),
    /// An input has no owned position. Production batches take this arm
    /// until the engine registrant names what the wallet holds.
    Unregistered,
}

/// The X3 check both routes apply after resolving a leaf.
///
/// The capture route compares the chunk leaf it decoded. The rebuild
/// compares the drained entry, after unwrapping the commitment a drained
/// leaf carries — the same unwrap [`chunk_leaf`] uses — so the two checks
/// cannot drift into `Option` on one side and a point on the other.
fn refuse_identity_mismatch(
    input: &AssembleInput,
    output_key: OneTimePubkey,
    commitment: CommitmentBytes,
) -> Result<(), ClientError> {
    if output_key != input.output_key || commitment != input.commitment {
        return Err(ClientError::IdentityMismatch {
            gindex: input.gindex,
            expected_output_key: input.output_key,
            got_output_key: output_key,
            commitment_matched: commitment == input.commitment,
        });
    }
    Ok(())
}

/// Stamp the dispatcher's depth, then fold the path onto the root it claims.
///
/// One seal for both routes. The artifact check is
/// [`verify_path_against_its_branches`]; a fault is
/// [`ClientError::PathRootMismatch`].
fn seal_path(
    leaf_chunk: Vec<ChunkLeaf>,
    c1_layers: Vec<Vec<[u8; 32]>>,
    c2_layers: Vec<Vec<[u8; 32]>>,
    reference: &ReferenceBlock,
    depth: u8,
) -> Result<AssembledPath, ClientError> {
    // C3: the leaf layer is the `+1`; the root point is excluded. Holds by
    // construction of the walk `1..depth`. A violation is a logic bug.
    debug_assert_eq!(
        c1_layers.len() + c2_layers.len() + 1,
        usize::from(depth),
        "assembled path depth must match the tree depth"
    );
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
    Ok(assembled)
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

    /// Assemble every membership path for one transaction (`CT-6` increment 3,
    /// closeout row (a), with increment 5's capture route).
    ///
    /// # Why this is the primitive and `assemble_path` the special case
    ///
    /// Each path needs the position of one `gindex` and the branch at every
    /// layer above it. Only the position is per-input, so the batch is one
    /// gate and then one route. Assembling per input used to pay the rebuild
    /// once per input — `k · n`, where `k` is the input count and `n` the
    /// drained leaf count. The rebuild route pays `n` once. The capture
    /// route pays the chunks the paths actually touch.
    ///
    /// # The two routes
    ///
    /// [`Self::root_and_depth_at`] runs once, before any input work. It
    /// supplies the root the reference is checked against
    /// ([`ClientError::RootMismatch`] returns no paths) and the depth both
    /// routes stamp on [`TreeContext::tree_depth`].
    ///
    /// When every input has a resolved owned position, the batch is assembled
    /// from the capture table and the frontier snapshot at the reference
    /// height. A closed chunk is the table row. An open chunk at layer 1 and
    /// above is the snapshot's open branch. An open layer-0 chunk is a ranged
    /// read of its own tail, at most `SELENE_CHUNK_WIDTH - 1` rows. Each path
    /// carries its own branches, and `seal_path` folds them onto the root the
    /// path claims ([`ClientError::PathRootMismatch`], `CT6_PROVING_STATE.md`
    /// §11.6).
    ///
    /// When any input is unregistered, the batch is rebuilt from replay-held
    /// `entries`. That is the route
    /// production spends take until the engine registrant names each owned
    /// output on open. The state-3 oracle
    /// `capture::a_path_from_captures_equals_the_rebuilt_one_with_every_foreign_leaf_gone`
    /// grades the registered route, and it is green. The rebuild stays until
    /// that registrant lands: the passes that exercise it
    /// (`batched_assembly_keeps_each_input_its_own_path`,
    /// `a_root_mismatch_refuses_the_whole_batch`,
    /// `a_mutated_leaf_chunk_is_absent_from_its_branch`) move onto registered
    /// fixtures with it, and the function is deleted then. On this route `n`
    /// is every drained leaf since genesis. `entries` only grows (`extend` on
    /// ingest, replaced wholesale by a rollback's rebuild), and a resume from
    /// a pruned store is refused ([`ClientError::ResumeFromPrunedStore`],
    /// F5). The 725-block replay window is a different quantity. The chain-age
    /// cost is `CT6_PROVING_STATE.md` §11.2.
    ///
    /// The structural pin is
    /// `ct6_oracle::capture::a_path_from_captures_equals_the_rebuilt_one_with_every_foreign_leaf_gone`:
    /// with the foreign leaves removed from `entries`, a registered batch
    /// assembles and the path equals the full-tree path. (Its predecessor,
    /// which asserted the refusal an unregistered batch meets on that shape,
    /// was retired when the equality became assertable.)
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
    /// [`ClientError::RootMismatch`] if the root at `reference.height` does
    /// not match `reference.curve_tree_root`.
    /// [`ClientError::PathRootMismatch`] if the assembled path's own branches
    /// do not commit to the root it claims, or if the rebuild's layer count
    /// disagrees with the dispatcher's depth; [`PathRootFault`] names the
    /// step. [`ClientError::OutputNotDrained`] if a `gindex` is not a drained
    /// leaf at the reference height. [`ClientError::IdentityMismatch`] if the
    /// leaf at a `gindex` does not carry the expected `(output_key, commitment)`.
    /// The capture route also returns [`ClientError::ReferenceOutsideSnapshotRing`],
    /// [`ClientError::SnapshotLeafCountMismatch`], [`ClientError::CaptureMissing`],
    /// and [`ClientError::Frontier`] when the snapshot or the table cannot
    /// serve the path.
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

        match self.assemble_from_captures(inputs, reference, depth)? {
            CaptureAssembly::Paths(paths) => Ok(paths),
            CaptureAssembly::Unregistered => self.assemble_by_rebuild(inputs, reference, depth),
        }
    }

    /// Assemble a batch from the **captured** chunks over each input and the
    /// frontier snapshot at the reference height — reading no drained leaf
    /// beyond the open leaf chunk's own tail.
    ///
    /// Returns [`CaptureAssembly::Unregistered`] when an input has no resolved
    /// owned position; the caller rebuilds that batch. Every other shortfall
    /// is a named refusal, because a silent fallback from here would serve
    /// the spend while hiding a hole in the mechanism it relies on.
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
    /// [`ClientError::OutputNotDrained`] if a resolved position is at or
    /// above the drained count at the reference height;
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
    ) -> Result<CaptureAssembly, ClientError> {
        let mut positions = Vec::with_capacity(inputs.len());
        for input in inputs {
            match self
                .owned_positions
                .iter()
                .find(|(_, gindex)| **gindex == input.gindex)
            {
                Some((position, _)) => positions.push(*position),
                None => return Ok(CaptureAssembly::Unregistered),
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
            let leaf_span = ChunkSpan::covering(position, 0);
            let leaf_chunk = self.leaf_chunk_at(leaf_span, drained_count)?;
            let offset =
                usize::try_from(position - leaf_span.start()).expect("an offset fits usize");
            let resolved = leaf_chunk.get(offset).ok_or(ClientError::CaptureMissing {
                end_leaf: leaf_span.end_leaf(),
                layer: 0,
            })?;
            refuse_identity_mismatch(input, resolved.output_key, resolved.commitment)?;

            let mut c1_layers: Vec<Vec<[u8; 32]>> = Vec::new();
            let mut c2_layers: Vec<Vec<[u8; 32]>> = Vec::new();
            for layer in 1..depth {
                let children = match ChunkSpan::due(position, layer, drained_count) {
                    Some(span) => self.captured_children(span.end_leaf(), layer)?,
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
                push_branch(layer, &children, &mut c1_layers, &mut c2_layers)?;
            }

            paths.push(seal_path(
                leaf_chunk, c1_layers, c2_layers, reference, depth,
            )?);
        }
        Ok(CaptureAssembly::Paths(paths))
    }

    /// The leaf chunk over `span` at a height with `drained_count` leaves:
    /// from the capture when the span has closed, from the leaf rows' tail
    /// while it is still open.
    fn leaf_chunk_at(
        &self,
        span: ChunkSpan,
        drained_count: u64,
    ) -> Result<Vec<ChunkLeaf>, ClientError> {
        if span.is_closed(drained_count) {
            let body = self.captured_body(span.end_leaf(), 0)?;
            decode_captured_leaf_chunk(&body)
        } else {
            // The tail is at most one short of a closed chunk. A hole in
            // that range is the store's own read, and the artifact check
            // refuses the path it produces.
            let entries = self.store.read_drained_range(
                TreePosition::from_raw(span.start()),
                TreePosition::from_raw(drained_count - 1),
            )?;
            Ok(entries.iter().map(chunk_leaf).collect())
        }
    }

    /// The children of the closed layer-`layer` chunk that ended at
    /// `end_leaf`, from the capture table.
    fn captured_children(&self, end_leaf: u64, layer: u8) -> Result<Vec<[u8; 32]>, ClientError> {
        let body = self.captured_body(end_leaf, layer)?;
        let width = chunk_width(layer);
        if body.len() != width * NODE_CHILD_BYTES {
            return Err(
                StoreError::CorruptMeta("captured node chunk is not one full width").into(),
            );
        }
        Ok(body
            .chunks_exact(NODE_CHILD_BYTES)
            .map(|node| curve_element_at(node, 0))
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

    /// Assemble a batch by rebuilding the layer stack from every drained
    /// leaf in `entries`.
    ///
    /// The route for a batch with an unregistered input. `depth` is the
    /// value [`Self::root_and_depth_at`] already returned. The walk is
    /// `1..depth`. A rebuilt stack of a different length is the same fault
    /// a branch count that is not `tree_depth` already names
    /// ([`PathRootFault::ShortPath`], [`PathRootFault::LongPath`]), reported
    /// before the walk so a short stack is not indexed off its end.
    fn assemble_by_rebuild(
        &self,
        inputs: &[AssembleInput],
        reference: &ReferenceBlock,
        depth: u8,
    ) -> Result<Vec<AssembledPath>, ClientError> {
        let cutoff = Self::drained_through(reference.height);
        let stream = assemble_leaf_stream(&self.entries, cutoff);
        let layers = build_layers(&stream);
        let built = u8::try_from(layers.len()).expect("curve-tree depth fits u8");
        if built != depth {
            return Err(ClientError::PathRootMismatch {
                claimed: reference.curve_tree_root,
                fault: if built < depth {
                    PathRootFault::ShortPath
                } else {
                    PathRootFault::LongPath
                },
            });
        }

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
        // drained leaf count — every leaf since genesis, not a window (see
        // the method docstring). `Gindex` is `Hash + Eq` from `scalar_u64!`,
        // so this needs nothing from `shekyl-types`.
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
            // A drained leaf carries a commitment (`try_build_leaf` required
            // it). Unwrapping here is the same expectation `chunk_leaf`
            // makes, so the shared check compares two points.
            let commitment = resolved
                .identity
                .commitment
                .expect("a drained leaf carries a commitment");
            refuse_identity_mismatch(input, resolved.identity.output_key, commitment)?;

            // Leaf chunk: the SELENE_CHUNK_WIDTH outputs of the path's layer-0
            // node, as compressed-point tuples (the prover's `Path.leaves`).
            let leaf_node_idx = leaf_pos / SELENE_CHUNK_WIDTH;
            let leaf_start = leaf_node_idx * SELENE_CHUNK_WIDTH;
            let leaf_end = (leaf_start + SELENE_CHUNK_WIDTH).min(drained.len());
            let leaf_chunk: Vec<ChunkLeaf> = drained[leaf_start..leaf_end]
                .iter()
                .map(|e| chunk_leaf(e))
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
                push_branch(layer, &prev[start..end], &mut c1_layers, &mut c2_layers)?;
                child_node_idx = node_idx;
            }

            paths.push(seal_path(
                leaf_chunk, c1_layers, c2_layers, reference, depth,
            )?);
        }

        Ok(paths)
    }
}
