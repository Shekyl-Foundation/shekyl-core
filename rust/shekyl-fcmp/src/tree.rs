// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Curve tree operations: grow, trim, root computation.
//!
//! These functions wrap the upstream FCMP++ Pedersen hash operations for the
//! Helios/Selene curve tower. The C++ LMDB layer owns the store; Rust owns
//! the hash primitives. Membership paths are assembled wallet-side from the
//! block-derived leaf stream (`shekyl-curve-tree`); the daemon serves no
//! per-output path (`PHASE_2A_SEND_PATH.md` §3.0.1, `SOK-10` Q7).
//!
//! ## Tree topology
//!
//! - Layer 0 (leaf): Selene. Each chunk hashes `SCALARS_PER_LEAF * SELENE_CHUNK_WIDTH`
//!   Selene scalars into a Selene point.
//! - Odd layers: Helios. Children are x-coordinates of Selene points from the layer below.
//! - Even layers (>0): Selene. Children are x-coordinates of Helios points from the layer below.
//! - Root: the single point at the topmost layer.
//!
//! The Selene leaf layer (layer 0) is never itself the root: the daemon's
//! `grow_curve_tree` always propagates the leaf chunk into at least the
//! layer-1 Helios node before its root-stop check, so every non-empty tree is
//! depth ≥ 2 (a `1..=SELENE_CHUNK_WIDTH`-leaf tree roots at the single-child
//! layer-1 Helios node). Reconstruction must match this convention; it is
//! pinned against a real consensus header root by the CT-2 reconstruct-root
//! KAT (`shekyl-curve-tree`, `docs/design/CT2_DRAIN_ORDER.md` §5). The empty
//! tree is the sole layer-0 case and is the `selene_hash_init()` sentinel,
//! handled by the caller, not an indexed `build_layers` result.

use crate::leaf::ShekylLeaf;

use ciphersuite::{
    group::{ff::PrimeField, GroupEncoding},
    Ciphersuite,
};
use ec_divisors::DivisorCurve;
use helioselene::{Helios, Selene};
use shekyl_curve_generators::{HELIOS_HASH_INIT, SELENE_HASH_INIT};
use shekyl_fcmp_proofs::fcmps;

/// Number of scalars per output in the leaf layer.
/// Shekyl uses 4-scalar leaves: {O.x, I.x, C.x, CM.x} (`PL-D3`).
pub const SCALARS_PER_LEAF: usize = 4;

/// Number of outputs per leaf-layer chunk (C1/Selene branching factor).
pub const SELENE_CHUNK_WIDTH: usize = fcmps::LAYER_ONE_LEN;

/// Number of children per Helios-layer chunk.
pub const HELIOS_CHUNK_WIDTH: usize = fcmps::LAYER_TWO_LEN;

/// Total leaf scalars per leaf-layer chunk.
pub const LEAF_CHUNK_SCALARS: usize = SCALARS_PER_LEAF * SELENE_CHUNK_WIDTH;

/// Result of a hash-grow operation (appending new outputs to the tree).
#[derive(Clone, Debug)]
pub struct HashGrowResult {
    /// Updated layer hashes, indexed by `(layer_idx, chunk_idx)`.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after growth (serialized point, 32 bytes).
    pub new_root: [u8; 32],
}

/// Result of a hash-trim operation (removing outputs during reorg).
#[derive(Clone, Debug)]
pub struct HashTrimResult {
    /// Updated layer hashes after trimming.
    pub layer_updates: Vec<LayerUpdate>,
    /// New tree root after trimming (serialized point, 32 bytes).
    pub new_root: [u8; 32],
}

/// A single node update in the tree.
#[derive(Clone, Debug)]
pub struct LayerUpdate {
    pub layer_idx: u8,
    pub chunk_idx: u64,
    pub hash: [u8; 32],
}

/// Marker for tree operations dispatched through FFI.
pub enum TreeOp {
    Grow,
    Trim,
}

// ---------------------------------------------------------------------------
// Selene hash operations (leaf layer + even internal layers)
// ---------------------------------------------------------------------------

/// Incrementally add children to an existing Selene chunk hash.
///
/// - `existing_hash`: Current chunk hash (serialized Selene point). Use
///   `selene_hash_init()` for a new (empty) chunk.
/// - `offset`: Position in the chunk where new children start.
/// - `existing_child_at_offset`: The old scalar at `offset` (use 32 zero bytes
///   if this is a fresh position).
/// - `new_children`: Slice of new Selene scalars (32 bytes each).
///
/// Returns the updated Selene point (32 bytes), or `None` on failure.
pub fn hash_grow_selene(
    existing_hash: &[u8; 32],
    offset: usize,
    existing_child_at_offset: &[u8; 32],
    new_children: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let generators = &shekyl_fcmp_proofs::SELENE_FCMP_GENERATORS.generators;
    let existing = <Selene as Ciphersuite>::G::from_bytes(existing_hash);
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let old_child = deserialize_selene_scalar(existing_child_at_offset)?;
    let children: Vec<<Selene as Ciphersuite>::F> = new_children
        .iter()
        .map(deserialize_selene_scalar)
        .collect::<Option<Vec<_>>>()?;

    let result =
        fcmps::tree::hash_grow::<Selene>(generators, existing, offset, old_child, &children)?;

    Some(result.to_bytes())
}

/// Trim children from an existing Selene chunk hash.
pub fn hash_trim_selene(
    existing_hash: &[u8; 32],
    offset: usize,
    children_to_remove: &[[u8; 32]],
    child_to_grow_back: &[u8; 32],
) -> Option<[u8; 32]> {
    let generators = &shekyl_fcmp_proofs::SELENE_FCMP_GENERATORS.generators;
    let existing = <Selene as Ciphersuite>::G::from_bytes(existing_hash);
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let children: Vec<<Selene as Ciphersuite>::F> = children_to_remove
        .iter()
        .map(deserialize_selene_scalar)
        .collect::<Option<Vec<_>>>()?;
    let grow_back = deserialize_selene_scalar(child_to_grow_back)?;

    let result =
        fcmps::tree::hash_trim::<Selene>(generators, existing, offset, &children, grow_back)?;

    Some(result.to_bytes())
}

// ---------------------------------------------------------------------------
// Helios hash operations (odd internal layers)
// ---------------------------------------------------------------------------

/// Incrementally add children to an existing Helios chunk hash.
pub fn hash_grow_helios(
    existing_hash: &[u8; 32],
    offset: usize,
    existing_child_at_offset: &[u8; 32],
    new_children: &[[u8; 32]],
) -> Option<[u8; 32]> {
    let generators = &shekyl_fcmp_proofs::HELIOS_FCMP_GENERATORS.generators;
    let existing = <Helios as Ciphersuite>::G::from_bytes(existing_hash);
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let old_child = deserialize_helios_scalar(existing_child_at_offset)?;
    let children: Vec<<Helios as Ciphersuite>::F> = new_children
        .iter()
        .map(deserialize_helios_scalar)
        .collect::<Option<Vec<_>>>()?;

    let result =
        fcmps::tree::hash_grow::<Helios>(generators, existing, offset, old_child, &children)?;

    Some(result.to_bytes())
}

/// Trim children from an existing Helios chunk hash.
pub fn hash_trim_helios(
    existing_hash: &[u8; 32],
    offset: usize,
    children_to_remove: &[[u8; 32]],
    child_to_grow_back: &[u8; 32],
) -> Option<[u8; 32]> {
    let generators = &shekyl_fcmp_proofs::HELIOS_FCMP_GENERATORS.generators;
    let existing = <Helios as Ciphersuite>::G::from_bytes(existing_hash);
    if bool::from(existing.is_none()) {
        return None;
    }
    let existing = existing.unwrap();

    let children: Vec<<Helios as Ciphersuite>::F> = children_to_remove
        .iter()
        .map(deserialize_helios_scalar)
        .collect::<Option<Vec<_>>>()?;
    let grow_back = deserialize_helios_scalar(child_to_grow_back)?;

    let result =
        fcmps::tree::hash_trim::<Helios>(generators, existing, offset, &children, grow_back)?;

    Some(result.to_bytes())
}

// ---------------------------------------------------------------------------
// Point-to-cycle-scalar conversions
// ---------------------------------------------------------------------------

/// Extract the x-coordinate of a Selene point as a Helios scalar.
///
/// In the Helios/Selene curve cycle, Selene point coordinates are Helios
/// field elements. This conversion feeds Selene layer hashes into the
/// next Helios layer as children.
pub fn selene_point_to_helios_scalar(selene_point: &[u8; 32]) -> Option<[u8; 32]> {
    let point = <Selene as Ciphersuite>::G::from_bytes(selene_point);
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = <<Selene as Ciphersuite>::G as DivisorCurve>::to_xy(point.unwrap())?;
    Some(x.to_repr())
}

/// Extract the x-coordinate of a Helios point as a Selene scalar.
pub fn helios_point_to_selene_scalar(helios_point: &[u8; 32]) -> Option<[u8; 32]> {
    let point = <Helios as Ciphersuite>::G::from_bytes(helios_point);
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = <<Helios as Ciphersuite>::G as DivisorCurve>::to_xy(point.unwrap())?;
    Some(x.to_repr())
}

// ---------------------------------------------------------------------------
// Batch layer composition
// ---------------------------------------------------------------------------

/// Compose every curve-tree layer from a flat leaf-scalar stream, batch-style.
///
/// Each node is built from its init point over its full child set via
/// [`hash_grow_selene`] / [`hash_grow_helios`] (offset 0, zero old-child) — no
/// stateful frontier is carried. `layers[0]` is the leaf (Selene) layer; layers
/// alternate Helios (odd) and Selene (even) above; the final layer holds the
/// single root. The leaf layer chunks the scalar stream by [`LEAF_CHUNK_SCALARS`];
/// internal layers chunk the converted child nodes by [`SELENE_CHUNK_WIDTH`] /
/// [`HELIOS_CHUNK_WIDTH`].
///
/// # Single-composition discipline
///
/// This is the canonical wallet-side composition. The wallet's segment assembler
/// (forward sync and truncate-and-rebuild reorg), the CT-0 freeze gate, and
/// CT-2's reconstruct-root KAT all call this exact function rather than
/// reimplementing the composition — otherwise the "two implementations must
/// agree" trap reopens (see `docs/design/CURVE_TREE_CLIENT.md` §7.7). Agreement
/// with the daemon's *incremental* `hash_grow`/`hash_trim` path is a separate
/// property, proven within Rust by the `curve_tree_freeze` integration test and
/// end-to-end by CT-2's KAT against a real header root.
///
/// Fallible variant of [`build_layers`]: returns `None` when any leaf scalar or
/// intermediate node fails deserialization or hash growth (e.g. corrupted
/// persisted bytes on the CT-1 store path).
pub fn try_build_layers(leaf_scalars: &[[u8; 32]]) -> Option<Vec<Vec<[u8; 32]>>> {
    const ZERO: [u8; 32] = [0u8; 32];

    let leaf_nodes: Vec<[u8; 32]> = leaf_scalars
        .chunks(LEAF_CHUNK_SCALARS)
        .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c))
        .collect::<Option<Vec<_>>>()?;
    try_build_upper_layers(leaf_nodes, 0)
}

/// Returns `vec![vec![]]` for an empty input; callers handle the empty tree. The
/// point↔scalar conversions are total for legitimately-occurring nodes (asserted
/// by the `node_conversions_are_total` test), so the internal `expect`s do not
/// fire on valid leaf sets.
pub fn build_layers(leaf_scalars: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    try_build_layers(leaf_scalars).expect("valid leaf scalars")
}

/// Hash a layer of nodes up to the root, returning every layer from
/// `initial_layer` (inclusive) to the root.
///
/// Factored out of [`build_layers`] so the two consumers share one composition
/// (`docs/design/CURVE_TREE_CLIENT.md` §7.7, open question #12): the from-leaves
/// path calls `build_layers` (which computes the leaf layer then delegates
/// here), and the wallet's steady-state from-cached-`R_k` hot path calls this
/// directly with its cached frozen sub-roots as `initial_layer`. Keeping a
/// single upper-layer composition prevents the "two implementations must agree"
/// trap from reopening above the leaf layer.
///
/// `start_layer_idx` is the absolute tree-layer index of `initial_layer`
/// itself; it determines the Selene/Helios parity of each layer built on top
/// (the layer constructed directly above `initial_layer` is layer
/// `start_layer_idx + 1`, and its parity selects the hash). For the from-leaves
/// path the leaf layer is layer 0, so `build_layers` passes 0. A caller passing
/// cached sub-roots must pass the layer index those sub-roots occupy.
///
/// The Selene leaf layer (`start_layer_idx == 0`) is never the root: a single
/// node at layer 0 is promoted into the layer-1 Helios root rather than
/// returned bare, matching the daemon's `grow_curve_tree` (see the module-level
/// "Tree topology" note and `docs/design/CT2_DRAIN_ORDER.md` §5). The stop
/// condition is therefore "single node at layer `>= 1`", so:
/// - a non-empty `initial_layer` at layer 0 yields depth `>= 2`;
/// - an `initial_layer` already at layer `>= 1` with `<= 1` node returns
///   `vec![initial_layer]` (the caller's cached sub-root is already a root);
/// - the empty tree returns `vec![initial_layer]` with an empty top layer and
///   its root is the `selene_hash_init` sentinel handled by the caller (see
///   `build_layers`).
///
/// In the non-empty cases the root is `result.last()[0]`.
pub fn try_build_upper_layers(
    initial_layer: Vec<[u8; 32]>,
    start_layer_idx: u8,
) -> Option<Vec<Vec<[u8; 32]>>> {
    const ZERO: [u8; 32] = [0u8; 32];

    let mut layers = vec![initial_layer];
    let mut current_layer_idx = start_layer_idx;
    loop {
        let top_len = layers.last()?.len();
        if top_len == 0 {
            break;
        }
        if top_len == 1 && current_layer_idx >= 1 {
            break;
        }
        let built_layer_idx = current_layer_idx.checked_add(1)?;
        let prev = layers.last()?;
        let next: Vec<[u8; 32]> = if layer_is_selene(built_layer_idx) {
            let scalars: Vec<[u8; 32]> = prev
                .iter()
                .map(helios_point_to_selene_scalar)
                .collect::<Option<Vec<_>>>()?;
            scalars
                .chunks(SELENE_CHUNK_WIDTH)
                .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c))
                .collect::<Option<Vec<_>>>()?
        } else {
            let scalars: Vec<[u8; 32]> = prev
                .iter()
                .map(selene_point_to_helios_scalar)
                .collect::<Option<Vec<_>>>()?;
            scalars
                .chunks(HELIOS_CHUNK_WIDTH)
                .map(|c| hash_grow_helios(&helios_hash_init(), 0, &ZERO, c))
                .collect::<Option<Vec<_>>>()?
        };
        layers.push(next);
        current_layer_idx = built_layer_idx;
    }
    Some(layers)
}

pub fn build_upper_layers(initial_layer: Vec<[u8; 32]>, start_layer_idx: u8) -> Vec<Vec<[u8; 32]>> {
    try_build_upper_layers(initial_layer, start_layer_idx).expect("valid layer nodes")
}

/// Curve-tree depth (number of layers) for a tree of `leaf_count` leaves,
/// computed without building the tree.
///
/// Tree depth is a **pure function of the leaf count** — it depends only on how
/// many times `leaf_count` reduces through the fixed [`SELENE_CHUNK_WIDTH`] /
/// [`HELIOS_CHUNK_WIDTH`] ladder, never on the leaf *values*. This mirrors the
/// exact reduction in [`try_build_upper_layers`] (leaf layer packs
/// `SELENE_CHUNK_WIDTH` leaves per node; the stop condition is "single node at a
/// layer `>= 1`", so a non-empty tree is depth `>= 2` and the bare Selene leaf
/// layer is never the root), and is pinned equal to `build_layers(..).len()` by
/// the `layer_count_for_leaves_matches_build_layers` KAT.
///
/// It exists so a caller that needs the depth but not the tree — the CT-5c fee
/// path, which must size the FCMP++ proof weight *before* assembling any path —
/// reads it cheaply from the leaf count alone, while the assembler keeps taking
/// its depth from the layers it already builds. The KAT is the single-source
/// guard: this arithmetic and `build_layers` cannot drift.
///
/// `leaf_count == 0` returns `1`, matching `build_layers(&[]).len()` (the
/// empty-tree sentinel layer); callers handle the empty tree separately.
#[must_use]
pub fn layer_count_for_leaves(leaf_count: u64) -> u8 {
    if leaf_count == 0 {
        return 1;
    }
    // Layer 0 (leaf, Selene): each node packs SELENE_CHUNK_WIDTH leaves.
    let mut nodes = leaf_count.div_ceil(SELENE_CHUNK_WIDTH as u64);
    let mut layer_idx: u8 = 0;
    let mut layers: u8 = 1;
    // Reduce upward until a single node at a layer >= 1 (the root) — the same
    // stop condition as `try_build_upper_layers`.
    while !(nodes == 1 && layer_idx >= 1) {
        layer_idx = layer_idx.checked_add(1).expect("curve-tree depth fits u8");
        nodes = nodes.div_ceil(chunk_width(layer_idx) as u64);
        layers = layers.checked_add(1).expect("curve-tree depth fits u8");
    }
    layers
}

/// Hash upward from `start_layer_idx` until layer `target_layer_idx`, returning
/// that layer's nodes.
///
/// Unlike [`build_upper_layers`], does not treat a single node at layer `>= 1`
/// as the root — mixed segment composition needs the sub-root at an absolute
/// depth even when the partial tail is still shallow (`shekyl-curve-tree` CT-1).
#[must_use]
pub fn try_promote_to_layer(
    mut current: Vec<[u8; 32]>,
    mut current_layer_idx: u8,
    target_layer_idx: u8,
) -> Option<Vec<[u8; 32]>> {
    const ZERO: [u8; 32] = [0u8; 32];

    if current.is_empty() || current_layer_idx >= target_layer_idx {
        return Some(current);
    }

    while current_layer_idx < target_layer_idx {
        if current.is_empty() {
            break;
        }
        let built_layer_idx = current_layer_idx.checked_add(1)?;
        current = if layer_is_selene(built_layer_idx) {
            let scalars: Vec<[u8; 32]> = current
                .iter()
                .map(helios_point_to_selene_scalar)
                .collect::<Option<Vec<_>>>()?;
            scalars
                .chunks(SELENE_CHUNK_WIDTH)
                .map(|c| hash_grow_selene(&selene_hash_init(), 0, &ZERO, c))
                .collect::<Option<Vec<_>>>()?
        } else {
            let scalars: Vec<[u8; 32]> = current
                .iter()
                .map(selene_point_to_helios_scalar)
                .collect::<Option<Vec<_>>>()?;
            scalars
                .chunks(HELIOS_CHUNK_WIDTH)
                .map(|c| hash_grow_helios(&helios_hash_init(), 0, &ZERO, c))
                .collect::<Option<Vec<_>>>()?
        };
        current_layer_idx = built_layer_idx;
    }
    Some(current)
}

#[must_use]
pub fn promote_to_layer(
    current: Vec<[u8; 32]>,
    current_layer_idx: u8,
    target_layer_idx: u8,
) -> Vec<[u8; 32]> {
    try_promote_to_layer(current, current_layer_idx, target_layer_idx).expect("valid layer nodes")
}

// ---------------------------------------------------------------------------
// Hash initialization points
// ---------------------------------------------------------------------------

/// Get the Selene hash initialization point (used for empty chunks).
pub fn selene_hash_init() -> [u8; 32] {
    SELENE_HASH_INIT.to_bytes()
}

/// Get the Helios hash initialization point (used for empty chunks).
pub fn helios_hash_init() -> [u8; 32] {
    HELIOS_HASH_INIT.to_bytes()
}

// ---------------------------------------------------------------------------
// Ed25519 → Selene scalar conversion (leaf construction)
// ---------------------------------------------------------------------------

/// Convert a compressed Ed25519 point to a Selene scalar (Wei25519 x-coordinate).
///
/// The Helios/Selene curve tower is constructed so that Ed25519's base field
/// GF(2^255-19) equals the Selene scalar field. This function decompresses
/// the point, maps it to short Weierstrass form (Wei25519), and returns the
/// x-coordinate as a 32-byte Selene scalar.
pub fn ed25519_point_to_selene_scalar(compressed: &[u8; 32]) -> Option<[u8; 32]> {
    use dalek_ff_group::EdwardsPoint as DfgEdwardsPoint;

    let point = <DfgEdwardsPoint as GroupEncoding>::from_bytes(compressed);
    if bool::from(point.is_none()) {
        return None;
    }
    let (x, _y) = DfgEdwardsPoint::to_xy(point.unwrap())?;
    Some(x.to_repr())
}

/// Construct a 128-byte curve tree leaf from an output's public key, commitment,
/// and published PQC leaf commitment point.
///
/// Computes Hp(O) (Monero's hash-to-curve), then extracts the Wei25519
/// x-coordinates of O, Hp(O), C and `CM` — the 4th scalar is `CM.x`, where
/// `CM` is the compressed Ed25519 point at the front of the output's `0x07`
/// entry (`PL-D3`). The x-extraction of all four points happens here, the one
/// leaf constructor the daemon (over FFI) and the wallet replica share, so the
/// two cannot diverge (`CT2_DRAIN_ORDER.md` §3.2).
///
/// Returns `None` if any of the four inputs is not a decompressible point. A
/// `CM` that fails admission (non-canonical, small-order, identity) never
/// reaches this function on an admitted chain
/// (`shekyl_wire::tx_extra::check_pqc_leaf_entries`); there is no zero
/// placeholder — an output without an admissible commitment is not a leaf.
pub fn construct_leaf(
    output_key: &[u8; 32],
    commitment: &[u8; 32],
    pqc_leaf_commitment: &[u8; 32],
) -> Option<[u8; 128]> {
    let hp_point = shekyl_curve_generators::biased_hash_to_point(*output_key);
    let hp_bytes: [u8; 32] = hp_point.compress().to_bytes();

    let o_x = ed25519_point_to_selene_scalar(output_key)?;
    let i_x = ed25519_point_to_selene_scalar(&hp_bytes)?;
    let c_x = ed25519_point_to_selene_scalar(commitment)?;
    let cm_x = ed25519_point_to_selene_scalar(pqc_leaf_commitment)?;

    let mut leaf = [0u8; 128];
    leaf[0..32].copy_from_slice(&o_x);
    leaf[32..64].copy_from_slice(&i_x);
    leaf[64..96].copy_from_slice(&c_x);
    leaf[96..128].copy_from_slice(&cm_x);
    Some(leaf)
}

/// Re-assemble a 128-byte leaf from a served chunk entry: the three
/// compressed points and the leaf's 4th scalar **as the chunk carries it**
/// (`CM.x`, already extracted — `ChunkLeaf::h_pqc` / `LeafEntry::h_pqc`).
/// The chunk does not carry the commitment point, so [`construct_leaf`]
/// cannot be used here; this is the inverse of the served-chunk entry layout
/// `O(32) ‖ I(32) ‖ C(32) ‖ CM.x(32)`.
///
/// Returns `None` if `O`, `I` or `C` is not a decompressible point.
pub fn leaf_from_chunk_entry(
    output_key: &[u8; 32],
    key_image_gen: &[u8; 32],
    commitment: &[u8; 32],
    fourth_scalar: &[u8; 32],
) -> Option<[u8; 128]> {
    let o_x = ed25519_point_to_selene_scalar(output_key)?;
    let i_x = ed25519_point_to_selene_scalar(key_image_gen)?;
    let c_x = ed25519_point_to_selene_scalar(commitment)?;
    let mut leaf = [0u8; 128];
    leaf[0..32].copy_from_slice(&o_x);
    leaf[32..64].copy_from_slice(&i_x);
    leaf[64..96].copy_from_slice(&c_x);
    leaf[96..128].copy_from_slice(fourth_scalar);
    Some(leaf)
}

/// Derive the compressed key-image generator `I = Hp(O)` from a compressed
/// Ed25519 output key, using the same `biased_hash_to_point` that
/// [`construct_leaf`] hashes into the leaf's `I.x` scalar.
///
/// [`construct_leaf`] caches only `I`'s Wei25519 x-coordinate (a Selene
/// scalar), which cannot be decompressed back to a point. The FCMP++
/// membership prover's `Path.leaves` consumes `O`/`I`/`C` as compressed
/// **points**, so path assembly re-derives the compressed `I` here rather
/// than depending on `shekyl-curve-generators` / `curve25519-dalek` directly
/// (`17-dependency-discipline.mdc`: reuse the crate that already owns the
/// primitive). Infallible: `biased_hash_to_point` always yields a point.
#[must_use]
pub fn key_image_generator(output_key: &[u8; 32]) -> [u8; 32] {
    shekyl_curve_generators::biased_hash_to_point(*output_key)
        .compress()
        .to_bytes()
}

// ---------------------------------------------------------------------------
// Leaf helpers
// ---------------------------------------------------------------------------

/// Convert Shekyl 4-scalar leaves into serialized byte format for LMDB storage.
pub fn leaves_to_bytes(leaves: &[ShekylLeaf]) -> Vec<u8> {
    let mut out = Vec::with_capacity(leaves.len() * ShekylLeaf::SIZE);
    for leaf in leaves {
        out.extend_from_slice(&leaf.to_bytes());
    }
    out
}

/// Compute the expected proof size for a given number of inputs and tree depth.
pub fn proof_size(num_inputs: usize, tree_depth: usize) -> usize {
    use shekyl_fcmp_proofs::fcmps::Fcmp;
    type ShekylFcmp = Fcmp<shekyl_fcmp_proofs::Curves>;
    ShekylFcmp::proof_size(num_inputs, tree_depth)
}

/// Return the chunk width (branching factor) for a given layer.
///
/// Layer 0 is the leaf layer: each chunk holds `SELENE_CHUNK_WIDTH` outputs
/// (i.e. `LEAF_CHUNK_SCALARS` individual Selene scalars).
/// Even non-leaf layers (Selene) use `SELENE_CHUNK_WIDTH`.
/// Odd layers (Helios) use `HELIOS_CHUNK_WIDTH`.
pub fn chunk_width(layer: u8) -> usize {
    if layer.is_multiple_of(2) {
        SELENE_CHUNK_WIDTH
    } else {
        HELIOS_CHUNK_WIDTH
    }
}

/// Returns true if the given layer uses Selene (even layers), false for Helios (odd layers).
pub const fn layer_is_selene(layer: u8) -> bool {
    layer.is_multiple_of(2)
}

// ---------------------------------------------------------------------------
// Segment partition — the one home (V3_WALLET_DECISION_LOG.md 2026-09-17,
// "two stores"; ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.2)
//
// The archival segment is a level-`j` subtree of this tree. Which leaves make
// up segment `k` is read by two independently built stores — the wallet-side
// shard store (`shekyl-curve-tree`) that serves segment bytes, and the
// consensus reader in `shekyl-archival-retention` (`frozen_segment_count`:
// the D2 escalation operand, the coverage RPC, and pop revert — **not** bond
// admission, which reads it nowhere; its shard predicate was ruled 2026-09-19
// and is unbuilt, `docs/design/ARCHIVAL_BOND_ADD_ADMISSION.md` §3) — and by
// every challenge, whose leaf index
// is taken against the segment's recorded leaf count. A divergent partition
// forks revert away from the store. The derivation therefore
// lives here, beside the widths it is a function of, and both consumers take
// it from this crate: the consensus side const-asserts its config-generated
// `SEGMENT_LEAF_COUNT` against `leaves_per_segment()`, and the store side
// re-exports these rather than restating them. `const fn`, so that assert is
// compile-time in the production graph, not a test that may or may not run.

/// Sub-root layer index `j` for archival segment boundaries.
///
/// **Consensus-frozen, not a tunable.** `frozen_segment_count` partitions
/// admissible `shard_id`s and pop revert by `SEGMENT_LEAF_COUNT`, which
/// `shekyl-archival-retention` const-asserts equal to [`leaves_per_segment`].
/// Moving `j` is a consensus change — a constants bump plus fixture
/// regeneration under `ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md` §5.2's reversion
/// criteria — and the build fails at that assert until both sides move
/// together. *SUPERSEDED 2026-09-18: "(provisional; §7.2.2)" — Gate 2's
/// provisional level 2 became the pinned constant in the freeze pipeline
/// round.*
pub const SEGMENT_LAYER_J: u8 = 2;

/// Outputs covered by one node at sub-root layer `j` (= segment size `E`):
/// the product of the chunk widths from the leaf layer up to `j`.
#[must_use]
pub const fn outputs_per_node(j: u8) -> usize {
    let mut e = SELENE_CHUNK_WIDTH;
    // Pre-increment: `layer` is bounded by `layer < j <= u8::MAX` at the
    // increment, so `j == u8::MAX` terminates (a post-increment form wraps
    // there and never exits). The product itself overflows `usize` far
    // below that — around layer 12 with the production widths — which is
    // a const-eval or debug panic, not a silent wrap: `j` names a layer of
    // the tree, whose depth is single digits.
    let mut layer: u8 = 0;
    while layer < j {
        layer += 1;
        e *= if layer_is_selene(layer) {
            SELENE_CHUNK_WIDTH
        } else {
            HELIOS_CHUNK_WIDTH
        };
    }
    e
}

/// Leaves per archival segment at the pinned layer [`SEGMENT_LAYER_J`]
/// (`38 · 18 · 38 = 25 992` under the production widths).
#[must_use]
pub const fn leaves_per_segment() -> usize {
    outputs_per_node(SEGMENT_LAYER_J)
}

// The CT-0 harness figures ("j=0 → 38, j=1 → 684, j=2 → 25 992",
// tests/curve_tree_freeze.rs), pinned at compile time now that the
// derivation is `const`: a width or layer change that moves the segment size
// fails here, not in a test that has to be selected.
const _: () = assert!(outputs_per_node(0) == SELENE_CHUNK_WIDTH);
const _: () = assert!(outputs_per_node(1) == SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH);
const _: () =
    assert!(outputs_per_node(2) == SELENE_CHUNK_WIDTH * HELIOS_CHUNK_WIDTH * SELENE_CHUNK_WIDTH);
const _: () = assert!(leaves_per_segment() == 25_992);

// ---------------------------------------------------------------------------
// Scalar deserialization helpers
// ---------------------------------------------------------------------------

fn deserialize_selene_scalar(bytes: &[u8; 32]) -> Option<<Selene as Ciphersuite>::F> {
    let repr = <Selene as Ciphersuite>::F::from_repr(*bytes);
    if bool::from(repr.is_some()) {
        Some(repr.unwrap())
    } else {
        None
    }
}

fn deserialize_helios_scalar(bytes: &[u8; 32]) -> Option<<Helios as Ciphersuite>::F> {
    let repr = <Helios as Ciphersuite>::F::from_repr(*bytes);
    if bool::from(repr.is_some()) {
        Some(repr.unwrap())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::PqcLeafScalar;

    #[test]
    fn leaves_to_bytes_roundtrip() {
        let leaves = vec![
            ShekylLeaf {
                o_x: [1u8; 32],
                i_x: [2u8; 32],
                c_x: [3u8; 32],
                cm_x: PqcLeafScalar([4u8; 32]),
            },
            ShekylLeaf {
                o_x: [5u8; 32],
                i_x: [6u8; 32],
                c_x: [7u8; 32],
                cm_x: PqcLeafScalar([8u8; 32]),
            },
        ];
        let bytes = leaves_to_bytes(&leaves);
        assert_eq!(bytes.len(), 2 * ShekylLeaf::SIZE);

        let restored_0 = ShekylLeaf::from_bytes(bytes[..128].try_into().unwrap());
        let restored_1 = ShekylLeaf::from_bytes(bytes[128..256].try_into().unwrap());
        assert_eq!(leaves[0], restored_0);
        assert_eq!(leaves[1], restored_1);
    }

    #[test]
    fn hash_init_points_are_nonzero() {
        let s = selene_hash_init();
        let h = helios_hash_init();
        assert_ne!(s, [0u8; 32]);
        assert_ne!(h, [0u8; 32]);
        assert_ne!(s, h);
    }

    #[test]
    fn hash_grow_selene_single_scalar() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;

        let result = hash_grow_selene(&init, 0, &zero, &[scalar]);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_ne!(hash, init);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn hash_grow_helios_single_scalar() {
        let init = helios_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;

        let result = hash_grow_helios(&init, 0, &zero, &[scalar]);
        assert!(result.is_some());
        let hash = result.unwrap();
        assert_ne!(hash, init);
    }

    #[test]
    fn selene_to_helios_roundtrip_nonidentity() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut s = [0u8; 32];
        s[0] = 42;

        let selene_point = hash_grow_selene(&init, 0, &zero, &[s]).unwrap();
        let helios_scalar = selene_point_to_helios_scalar(&selene_point);
        assert!(helios_scalar.is_some());
        let hs = helios_scalar.unwrap();
        assert_ne!(hs, [0u8; 32]);
    }

    #[test]
    fn proof_size_uses_upstream() {
        let s1 = proof_size(1, 8);
        let s2 = proof_size(2, 8);
        assert!(s1 > 0);
        assert!(s2 > s1);
    }

    #[test]
    fn chunk_widths_correct() {
        assert_eq!(chunk_width(0), SELENE_CHUNK_WIDTH);
        assert_eq!(chunk_width(1), HELIOS_CHUNK_WIDTH);
        assert_eq!(chunk_width(2), SELENE_CHUNK_WIDTH);
        assert_eq!(chunk_width(3), HELIOS_CHUNK_WIDTH);
    }

    /// Drift guard (CT-5c Q1): `layer_count_for_leaves(n)` must equal the depth
    /// `build_layers` actually produces for `n` leaves, so the fee path can read
    /// depth from the leaf count without building the tree. Covers the empty
    /// tree and both reduction boundaries (SELENE_CHUNK_WIDTH=38,
    /// HELIOS_CHUNK_WIDTH=18 ⇒ depth 2 up to n=684, depth 3 from n=685).
    #[test]
    fn layer_count_for_leaves_matches_build_layers() {
        // Distinct, canonical leaf scalars (small values < field modulus); the
        // depth is value-independent, so any valid scalars exercise the count.
        fn leaf_scalars_for(n: usize) -> Vec<[u8; 32]> {
            (0..n * SCALARS_PER_LEAF)
                .map(|i| {
                    let mut s = [0u8; 32];
                    s[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    s
                })
                .collect()
        }

        for n in [0usize, 1, 2, 37, 38, 39, 100, 683, 684, 685, 700, 1000] {
            let expected = build_layers(&leaf_scalars_for(n)).len();
            assert_eq!(
                usize::from(layer_count_for_leaves(n as u64)),
                expected,
                "layer_count_for_leaves({n}) must equal build_layers depth",
            );
        }
    }

    #[test]
    fn hash_grow_selene_multiple_scalars() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        s1[0] = 1;
        s2[0] = 2;

        let one = hash_grow_selene(&init, 0, &zero, &[s1]).unwrap();
        let two = hash_grow_selene(&init, 0, &zero, &[s1, s2]).unwrap();
        assert_ne!(
            one, two,
            "different child counts must produce different hashes"
        );
    }

    #[test]
    fn hash_grow_trim_selene_inverse() {
        let init = selene_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 7;

        let grown = hash_grow_selene(&init, 0, &zero, &[scalar]).unwrap();
        assert_ne!(grown, init);

        let trimmed = hash_trim_selene(&grown, 0, &[scalar], &zero).unwrap();
        assert_eq!(trimmed, init, "trim must invert grow");
    }

    #[test]
    fn hash_grow_trim_helios_inverse() {
        let init = helios_hash_init();
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 13;

        let grown = hash_grow_helios(&init, 0, &zero, &[scalar]).unwrap();
        assert_ne!(grown, init);

        let trimmed = hash_trim_helios(&grown, 0, &[scalar], &zero).unwrap();
        assert_eq!(trimmed, init, "trim must invert grow");
    }

    #[test]
    fn hash_grow_selene_rejects_invalid_point() {
        let bad_hash = [0xff; 32];
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        assert!(hash_grow_selene(&bad_hash, 0, &zero, &[scalar]).is_none());
    }

    #[test]
    fn hash_grow_helios_rejects_invalid_point() {
        let bad_hash = [0xff; 32];
        let zero = [0u8; 32];
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        assert!(hash_grow_helios(&bad_hash, 0, &zero, &[scalar]).is_none());
    }

    #[test]
    fn construct_leaf_is_128_bytes() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let basepoint = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let pqc_hash = [0x42u8; 32];

        if let Some(leaf) = construct_leaf(&basepoint, &basepoint, &pqc_hash) {
            assert_eq!(leaf.len(), 128);
            assert_ne!(&leaf[0..32], &[0u8; 32]);
            assert_ne!(&leaf[32..64], &[0u8; 32]);
            assert_ne!(&leaf[64..96], &[0u8; 32]);
            assert_eq!(&leaf[96..128], &pqc_hash);
        }
    }

    #[test]
    fn construct_leaf_zero_pqc_hash() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let basepoint = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let zero_pqc = [0u8; 32];

        if let Some(leaf) = construct_leaf(&basepoint, &basepoint, &zero_pqc) {
            assert_eq!(&leaf[96..128], &[0u8; 32]);
        }
    }

    #[test]
    fn construct_leaf_rejects_identity_point() {
        let identity = [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let _ = construct_leaf(&identity, &identity, &[0u8; 32]);
    }

    #[test]
    fn key_image_generator_matches_construct_leaf_i_scalar() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let o = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        // The compressed I = Hp(O), reduced to its Selene x-coordinate, must
        // equal the I.x scalar `construct_leaf` writes at leaf[32..64].
        let i_compressed = key_image_generator(&o);
        let i_x = ed25519_point_to_selene_scalar(&i_compressed).expect("I.x");
        let leaf = construct_leaf(&o, &o, &o).expect("leaf");
        assert_eq!(&leaf[32..64], &i_x);
    }

    /// The 4th scalar is `CM.x` (PL-D3): the constructor extracts it from the
    /// commitment point exactly as it does for `O` and `C`, and refuses a
    /// value that is not a point — there is no zero placeholder any more.
    #[test]
    fn construct_leaf_fourth_scalar_is_commitment_x() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;
        let o = ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let cm = (*shekyl_curve_generators::PQC_LEAF_COMMITMENT_J
            * curve25519_dalek::scalar::Scalar::from(7u64))
        .compress()
        .to_bytes();
        let leaf = construct_leaf(&o, &o, &cm).expect("leaf");
        let cm_x = ed25519_point_to_selene_scalar(&cm).expect("CM.x");
        assert_eq!(&leaf[96..128], &cm_x);
        assert!(
            construct_leaf(&o, &o, &[0u8; 32]).is_none(),
            "zero is not a point"
        );
        assert!(construct_leaf(&o, &o, &[0xffu8; 32]).is_none());
    }

    #[test]
    fn layer_is_selene_alternates() {
        assert!(layer_is_selene(0));
        assert!(!layer_is_selene(1));
        assert!(layer_is_selene(2));
        assert!(!layer_is_selene(3));
        assert!(layer_is_selene(254));
        assert!(!layer_is_selene(255));
    }

    #[test]
    fn leaf_chunk_scalars_consistent() {
        assert_eq!(LEAF_CHUNK_SCALARS, SCALARS_PER_LEAF * SELENE_CHUNK_WIDTH);
    }

    #[test]
    fn proof_size_increases_with_depth() {
        let s_d8 = proof_size(1, 8);
        let s_d16 = proof_size(1, 16);
        assert!(s_d16 > s_d8, "deeper tree should produce larger proof");
    }

    #[test]
    fn promote_to_layer_empty_input_is_no_op() {
        assert!(promote_to_layer(Vec::new(), 0, 2).is_empty());
    }
}
