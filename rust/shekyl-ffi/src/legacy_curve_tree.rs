// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Curve-tree hash grow/trim and leaf construction FFI.

// ─── FCMP++: Curve Tree Hash Operations ─────────────────────────────────────

/// Incrementally grow a Selene-layer chunk hash with new children.
///
/// Used for the leaf layer (layer 0) and even-numbered internal layers.
///
/// - `existing_hash_ptr`: 32 bytes, current Selene point (use hash_init for new chunk)
/// - `offset`: position in chunk where new children start
/// - `existing_child_at_offset_ptr`: 32 bytes, old Selene scalar at offset (zero for fresh)
/// - `new_children_ptr`: `num_children * 32` bytes, new Selene scalars
/// - `out_hash_ptr`: 32 bytes output buffer for the new Selene point
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_grow_selene(
    existing_hash_ptr: *const u8,
    offset: u64,
    existing_child_at_offset_ptr: *const u8,
    new_children_ptr: *const u8,
    num_children: u64,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || existing_child_at_offset_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && new_children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let existing_child: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_child_at_offset_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_selene(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &existing_child,
        &children,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Incrementally grow a Helios-layer chunk hash with new children.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_grow_helios(
    existing_hash_ptr: *const u8,
    offset: u64,
    existing_child_at_offset_ptr: *const u8,
    new_children_ptr: *const u8,
    num_children: u64,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || existing_child_at_offset_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && new_children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let existing_child: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_child_at_offset_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(new_children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_grow_helios(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &existing_child,
        &children,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Trim children from a Selene-layer chunk hash.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_trim_selene(
    existing_hash_ptr: *const u8,
    offset: u64,
    children_ptr: *const u8,
    num_children: u64,
    child_to_grow_back_ptr: *const u8,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || child_to_grow_back_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let grow_back: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(child_to_grow_back_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_selene(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &children,
        &grow_back,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Trim children from a Helios-layer chunk hash.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_hash_trim_helios(
    existing_hash_ptr: *const u8,
    offset: u64,
    children_ptr: *const u8,
    num_children: u64,
    child_to_grow_back_ptr: *const u8,
    out_hash_ptr: *mut u8,
) -> bool {
    if existing_hash_ptr.is_null()
        || child_to_grow_back_ptr.is_null()
        || out_hash_ptr.is_null()
        || (num_children > 0 && children_ptr.is_null())
    {
        return false;
    }

    let existing_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(existing_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let grow_back: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(child_to_grow_back_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let n = usize::try_from(num_children).unwrap_or(0);
    let children: Vec<[u8; 32]> = (0..n)
        .map(|i| unsafe {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(children_ptr.add(i * 32), buf.as_mut_ptr(), 32);
            buf
        })
        .collect();

    match shekyl_fcmp::tree::hash_trim_helios(
        &existing_hash,
        usize::try_from(offset).unwrap_or(0),
        &children,
        &grow_back,
    ) {
        Some(result) => {
            std::ptr::copy_nonoverlapping(result.as_ptr(), out_hash_ptr, 32);
            true
        }
        None => false,
    }
}

/// Convert a Selene point to a Helios scalar (x-coordinate extraction).
///
/// Used when propagating Selene layer hashes up to the next Helios layer.
/// Writes 32 bytes to `out_scalar_ptr`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_selene_to_helios_scalar(
    selene_point_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if selene_point_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }
    let point: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(selene_point_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    match shekyl_fcmp::tree::selene_point_to_helios_scalar(&point) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

/// Convert a Helios point to a Selene scalar (x-coordinate extraction).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_helios_to_selene_scalar(
    helios_point_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if helios_point_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }
    let point: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(helios_point_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    match shekyl_fcmp::tree::helios_point_to_selene_scalar(&point) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

/// Get the Selene hash initialization point (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_selene_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::selene_hash_init();
    std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32);
    true
}

/// Get the Helios hash initialization point (32 bytes).
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_helios_hash_init(out_ptr: *mut u8) -> bool {
    if out_ptr.is_null() {
        return false;
    }
    let init = shekyl_fcmp::tree::helios_hash_init();
    std::ptr::copy_nonoverlapping(init.as_ptr(), out_ptr, 32);
    true
}

/// Return the number of scalars per leaf (4 for Shekyl: O.x, I.x, C.x, H(pqc_pk)).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_scalars_per_leaf() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::SCALARS_PER_LEAF as u32
    }
}

/// Return the Selene-layer chunk width (branching factor = LAYER_ONE_LEN = 38).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_selene_chunk_width() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::SELENE_CHUNK_WIDTH as u32
    }
}

/// Return the Helios-layer chunk width (branching factor = LAYER_TWO_LEN = 18).
#[no_mangle]
pub extern "C" fn shekyl_curve_tree_helios_chunk_width() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        shekyl_fcmp::HELIOS_CHUNK_WIDTH as u32
    }
}

/// Compose every curve-tree layer **above the leaf layer** from the leaf-chunk
/// layer, the narrow way [`shekyl_fcmp::tree::build_layers`] does — the correct
/// producer-side grow that telescopes to the reference root.
///
/// This is the consensus fix for the depth-3 layer-2 divergence: the daemon's
/// in-place incremental deepening built a newly-created parent chunk from only the
/// deepening child (db_lmdb.cpp `grow_curve_tree`), dropping the pre-existing
/// sibling. The daemon keeps maintaining the **leaf** layer with
/// [`shekyl_curve_tree_hash_grow_selene`] (which telescopes — proven), then calls
/// this to recompose every layer above it and obtain the consensus root, retiring
/// the C++ upper-layer propagation entirely.
///
/// Output sizes are deterministic from `num_leaf_chunks` via the
/// SELENE/HELIOS chunk-width ladder, so the caller pre-allocates:
/// - `out_chunks_ptr` / `out_chunks_capacity`: capacity is a **count of 32-byte
///   chunks** (not bytes); upper-layer chunk hashes are written layer 1 first then
///   layer 2…, 32B each;
/// - `out_layer_sizes_ptr` / `out_layer_sizes_capacity`: capacity is a **count of
///   `u64` entries**; one chunk-count per upper layer (`*out_num_upper_layers` total);
/// - `out_num_upper_layers`: number of upper layers written;
/// - `out_root_ptr`: the 32B consensus root.
///
/// Returns false on null pointers, insufficient output capacity, or a malformed
/// leaf node (a node that fails the cycle-scalar conversion).
///
/// # Safety
/// Caller must ensure every pointer is valid for its declared length/capacity.
#[no_mangle]
pub unsafe extern "C" fn shekyl_curve_tree_grow_upper_layers(
    leaf_chunks_ptr: *const u8,
    num_leaf_chunks: u64,
    out_chunks_ptr: *mut u8,
    out_chunks_capacity: u64,
    out_layer_sizes_ptr: *mut u64,
    out_layer_sizes_capacity: u64,
    out_num_upper_layers: *mut u64,
    out_root_ptr: *mut u8,
) -> bool {
    if out_chunks_ptr.is_null()
        || out_layer_sizes_ptr.is_null()
        || out_num_upper_layers.is_null()
        || out_root_ptr.is_null()
        || (num_leaf_chunks > 0 && leaf_chunks_ptr.is_null())
    {
        return false;
    }

    // Every count must fit usize, and the input byte length must not overflow —
    // fail closed rather than silently treating overflow as 0 (this is an exported,
    // untrusted-caller boundary).
    let (Ok(n), Ok(out_chunks_cap), Ok(out_sizes_cap)) = (
        usize::try_from(num_leaf_chunks),
        usize::try_from(out_chunks_capacity),
        usize::try_from(out_layer_sizes_capacity),
    ) else {
        return false;
    };
    let Some(in_bytes) = n.checked_mul(32) else {
        return false;
    };

    // Read the leaf-chunk layer through a slice — no raw pointer arithmetic, and no
    // `from_raw_parts` on a null pointer when `n == 0`.
    let leaf_chunks: Vec<[u8; 32]> = if n == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(leaf_chunks_ptr, in_bytes) }
            .chunks_exact(32)
            .map(|c| {
                let mut b = [0u8; 32];
                b.copy_from_slice(c);
                b
            })
            .collect()
    };

    let Some(layers) = shekyl_fcmp::tree::try_build_upper_layers(leaf_chunks, 0) else {
        return false;
    };
    // `layers[0]` is the leaf layer the caller passed; the upper layers are `[1..]`.
    // The root is the top layer's sole node (or the empty-tree leaf-init sentinel
    // `build_layers` defines).
    let root = layers
        .last()
        .and_then(|l| l.first())
        .copied()
        .unwrap_or_else(shekyl_fcmp::tree::selene_hash_init);
    let upper = &layers[1..];
    let total: usize = upper.iter().map(Vec::len).sum();
    let Some(out_bytes) = total.checked_mul(32) else {
        return false;
    };
    // Capacities are counts (32-byte chunks / u64 entries), validated before writing.
    if total > out_chunks_cap || upper.len() > out_sizes_cap {
        return false;
    }

    // Write outputs through slices (the out pointers are non-null per the guard
    // above; a zero-length slice on a non-null pointer is well-defined).
    let sizes_out = unsafe { std::slice::from_raw_parts_mut(out_layer_sizes_ptr, upper.len()) };
    let chunks_out = unsafe { std::slice::from_raw_parts_mut(out_chunks_ptr, out_bytes) };
    let mut written = 0usize;
    for (li, layer) in upper.iter().enumerate() {
        // Fail closed on the (practically impossible) usize->u64 overflow rather than
        // emitting a sentinel size at this fallible FFI boundary. layer.len() <= total
        // <= num_leaf_chunks (all derived from a u64), so this never trips in practice.
        let Ok(layer_len) = u64::try_from(layer.len()) else {
            return false;
        };
        sizes_out[li] = layer_len;
        for node in layer {
            chunks_out[written * 32..written * 32 + 32].copy_from_slice(node);
            written += 1;
        }
    }
    // Same fail-closed discipline for the upper-layer count out-param.
    let Ok(num_upper) = u64::try_from(upper.len()) else {
        return false;
    };
    unsafe {
        *out_num_upper_layers = num_upper;
        std::slice::from_raw_parts_mut(out_root_ptr, 32).copy_from_slice(&root);
    }
    true
}

// ─── FCMP++: Ed25519 → Selene scalar conversion ────────────────────────────

/// Convert a compressed Ed25519 point (32 bytes) to a Selene scalar
/// (Wei25519 x-coordinate, 32 bytes).
///
/// Returns true on success (writes 32 bytes to `out_scalar_ptr`).
/// Returns false if the point cannot be decompressed or is the identity.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_ed25519_to_selene_scalar(
    compressed_ptr: *const u8,
    out_scalar_ptr: *mut u8,
) -> bool {
    if compressed_ptr.is_null() || out_scalar_ptr.is_null() {
        return false;
    }

    let compressed: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(compressed_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    match shekyl_fcmp::tree::ed25519_point_to_selene_scalar(&compressed) {
        Some(scalar) => {
            std::ptr::copy_nonoverlapping(scalar.as_ptr(), out_scalar_ptr, 32);
            true
        }
        None => false,
    }
}

// ─── FCMP++: Leaf construction ──────────────────────────────────────────────

/// Construct a 128-byte curve tree leaf from an output public key and commitment.
///
/// - `output_key_ptr`: 32 bytes, compressed Ed25519 output public key (O)
/// - `commitment_ptr`: 32 bytes, compressed Ed25519 amount commitment (C)
/// - `h_pqc_ptr`: 32 bytes, H(pqc_pk) scalar (or 32 zero bytes if unavailable)
/// - `leaf_out_ptr`: 128 bytes output buffer for {O.x, I.x, C.x, H(pqc_pk)}
///
/// Internally computes I = Hp(O) via Monero's biased hash-to-point, then
/// extracts Wei25519 x-coordinates for O, Hp(O), C. The 4th scalar comes
/// from `h_pqc_ptr`.
///
/// Returns true on success, false on decompression failure.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_curve_tree_leaf(
    output_key_ptr: *const u8,
    commitment_ptr: *const u8,
    h_pqc_ptr: *const u8,
    leaf_out_ptr: *mut u8,
) -> bool {
    if output_key_ptr.is_null()
        || commitment_ptr.is_null()
        || h_pqc_ptr.is_null()
        || leaf_out_ptr.is_null()
    {
        return false;
    }

    let output_key: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(output_key_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let commitment: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(commitment_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let h_pqc: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(h_pqc_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    match shekyl_fcmp::tree::construct_leaf(&output_key, &commitment, &h_pqc) {
        Some(leaf) => {
            std::ptr::copy_nonoverlapping(leaf.as_ptr(), leaf_out_ptr, 128);
            true
        }
        None => false,
    }
}

// ─── Transaction Builder (shekyl-tx-builder) ────────────────────────────────
