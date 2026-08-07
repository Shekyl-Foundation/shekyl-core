// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Transaction sign, construct-output, scan, key-image, cache FFI.

use super::legacy_types::*;
use super::legacy_util::*;

/// Generate FCMP++ transaction proofs in a single call (BP+, FCMP++, ECDH,
/// pseudo-outs).
///
/// This replaces the old C++ → Rust → C++ → Rust round-trip through
/// `genRctFcmpPlusPlus` + `shekyl_fcmp_prove` + `shekyl_pqc_sign` with a
/// single FFI entry point.
///
/// # Parameters
///
/// - `tx_prefix_hash_ptr`: Pointer to exactly 32 bytes — the Keccak-256 hash
///   of the serialized transaction prefix.
/// - `inputs_json_ptr` / `inputs_json_len`: JSON-encoded array of `SpendInput`.
/// - `outputs_json_ptr` / `outputs_json_len`: JSON-encoded array of `OutputInfo`.
/// - `fee`: Transaction fee in atomic units.
/// - `reference_block_ptr`: Pointer to exactly 32 bytes — block hash.
/// - `tree_root_ptr`: Pointer to exactly 32 bytes — Selene curve tree root.
///   **This is NOT the block hash.** Passing the block hash produces invalid proofs.
/// - `tree_depth`: Number of tree layers (must be >= 1).
///
/// # Return value
///
/// [`ShekylSignResult`] with JSON-encoded `SignedProofs` on success, or a
/// structured error code and message on failure.
///
/// # Error codes
///
/// - `-1`: Null pointer argument
/// - `-2`: JSON parse error
/// - `-10` through `-29`: `TxBuilderError` variant (message has details)
///
/// # Memory
///
/// The caller owns both `proofs_json` and `error_message` buffers and must
/// free them via `shekyl_buffer_free`.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_transaction(
    tx_prefix_hash_ptr: *const u8,
    inputs_json_ptr: *const u8,
    inputs_json_len: usize,
    outputs_json_ptr: *const u8,
    outputs_json_len: usize,
    fee: u64,
    reference_block_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylSignResult {
    // Null checks
    if tx_prefix_hash_ptr.is_null()
        || inputs_json_ptr.is_null()
        || outputs_json_ptr.is_null()
        || reference_block_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return ShekylSignResult::err(-1, "null pointer argument".into());
    }

    let tx_prefix_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tx_prefix_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let reference_block: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(reference_block_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs_json) = (unsafe { slice_from_ptr(inputs_json_ptr, inputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = (unsafe { slice_from_ptr(outputs_json_ptr, outputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid outputs_json pointer".into());
    };

    let inputs: Vec<shekyl_tx_builder::SpendInput> = match serde_json::from_slice(inputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("inputs JSON parse error: {e}")),
    };
    let outputs: Vec<shekyl_tx_builder::OutputInfo> = match serde_json::from_slice(outputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("outputs JSON parse error: {e}")),
    };

    let tree = shekyl_tx_builder::TreeContext {
        reference_block,
        tree_root,
        tree_depth,
    };

    match shekyl_tx_builder::sign_transaction(
        tx_prefix_hash,
        &inputs,
        &outputs,
        shekyl_units::AtomicUnits::from_raw(fee),
        &tree,
    ) {
        Ok(proofs) => match serde_json::to_vec(&proofs) {
            Ok(json) => ShekylSignResult::ok(json),
            Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
        },
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    }
}

fn tx_builder_error_code(e: &shekyl_tx_builder::TxBuilderError) -> i32 {
    use shekyl_tx_builder::TxBuilderError;
    match e {
        TxBuilderError::NoInputs => -10,
        TxBuilderError::TooManyInputs(_) => -11,
        TxBuilderError::NoOutputs => -12,
        TxBuilderError::TooManyOutputs(_) => -13,
        TxBuilderError::ZeroInputAmount { .. } => -14,
        TxBuilderError::ZeroOutputAmount { .. } => -15,
        TxBuilderError::InputAmountOverflow => -16,
        TxBuilderError::OutputAmountOverflow => -17,
        TxBuilderError::InsufficientFunds { .. } => -18,
        TxBuilderError::EmptyLeafChunk { .. } => -19,
        TxBuilderError::LeafChunkTooLarge { .. } => -20,
        TxBuilderError::ZeroTreeDepth => -21,
        TxBuilderError::BranchLayerMismatch { .. } => -22,
        TxBuilderError::InvalidCombinedSsLength { .. } => -23,
        TxBuilderError::BulletproofError(_) => -24,
        TxBuilderError::FcmpProveError(_) => -25,
        TxBuilderError::PqcSignError { .. } => -26,
        TxBuilderError::TreeDepthTooLarge(_) => -27,
        TxBuilderError::WireError(_) => -28,
        // Appended (codes are a stable C++-facing contract; never renumber).
        TxBuilderError::TreeTooShallow { .. } => -29,
        TxBuilderError::BalanceSelfCheck(_) => -30,
    }
}

// ─── Collapsed FCMP++ Signing (PR-wallet Phase 1b) ───────────────────────────

/// Input struct for collapsed signing. C++ passes `combined_ss` + `output_index`
/// instead of `spend_key_x` / `spend_key_y`. Rust derives those internally.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct FcmpSignInput {
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    ki: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_blob")]
    combined_ss: Vec<u8>,
    output_index: u64,
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    #[allow(non_snake_case)]
    hp_of_O: [u8; 32],
    amount: u64,
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment_mask: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    commitment: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    output_key: [u8; 32],
    #[serde(with = "shekyl_tx_builder::types::hex_bytes32")]
    h_pqc: [u8; 32],
    leaf_chunk: Vec<shekyl_tx_builder::LeafEntry>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c1_layers: Vec<Vec<[u8; 32]>>,
    #[serde(with = "shekyl_tx_builder::types::hex_layers")]
    c2_layers: Vec<Vec<[u8; 32]>>,
}

impl Drop for FcmpSignInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.combined_ss.zeroize();
        self.commitment_mask.zeroize();
    }
}

/// Collapsed FCMP++ signing: Rust owns all witness assembly.
///
/// C++ passes the wallet master spend key `b` (one value) plus per-input data
/// that includes `combined_ss` + `output_index`. Rust derives `ho` from HKDF,
/// computes `x = ho + b` and `y` internally, then builds `SpendInput` and
/// calls `sign_transaction`. C++ never touches `x`.
///
/// # Safety
/// - `spend_secret_ptr`, `tx_prefix_hash_ptr`: 32 bytes each.
/// - `reference_block_ptr`, `tree_root_ptr`: 32 bytes each.
/// - JSON pointers: valid for their documented lengths.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_fcmp_transaction(
    spend_secret_ptr: *const u8,
    tx_prefix_hash_ptr: *const u8,
    inputs_json_ptr: *const u8,
    inputs_json_len: usize,
    outputs_json_ptr: *const u8,
    outputs_json_len: usize,
    fee: u64,
    reference_block_ptr: *const u8,
    tree_root_ptr: *const u8,
    tree_depth: u8,
) -> ShekylSignResult {
    if spend_secret_ptr.is_null()
        || tx_prefix_hash_ptr.is_null()
        || inputs_json_ptr.is_null()
        || outputs_json_ptr.is_null()
        || reference_block_ptr.is_null()
        || tree_root_ptr.is_null()
    {
        return ShekylSignResult::err(-1, "null pointer argument".into());
    }

    let spend_secret: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(spend_secret_ptr, buf.as_mut_ptr(), 32);
        buf
    });
    let tx_prefix_hash: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tx_prefix_hash_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let reference_block: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(reference_block_ptr, buf.as_mut_ptr(), 32);
        buf
    };
    let tree_root: [u8; 32] = unsafe {
        let mut buf = [0u8; 32];
        std::ptr::copy_nonoverlapping(tree_root_ptr, buf.as_mut_ptr(), 32);
        buf
    };

    let Some(inputs_json) = (unsafe { slice_from_ptr(inputs_json_ptr, inputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid inputs_json pointer".into());
    };
    let Some(outputs_json) = (unsafe { slice_from_ptr(outputs_json_ptr, outputs_json_len) }) else {
        return ShekylSignResult::err(-1, "invalid outputs_json pointer".into());
    };

    let collapsed_inputs: Vec<FcmpSignInput> = match serde_json::from_slice(inputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("inputs JSON parse error: {e}")),
    };
    let outputs: Vec<shekyl_tx_builder::OutputInfo> = match serde_json::from_slice(outputs_json) {
        Ok(v) => v,
        Err(e) => return ShekylSignResult::err(-2, format!("outputs JSON parse error: {e}")),
    };

    use shekyl_crypto_pq::derivation::derive_output_secrets;
    use zeroize::Zeroize;

    let Some(mut b_scalar) = curve25519_scalar_from_bytes(&spend_secret) else {
        return ShekylSignResult::err(-5, "invalid spend secret key".into());
    };

    let mut spend_inputs: Vec<shekyl_tx_builder::SpendInput> =
        Vec::with_capacity(collapsed_inputs.len());
    for inp in &collapsed_inputs {
        if inp.combined_ss.len() != 64 {
            drop(spend_inputs);
            return ShekylSignResult::err(
                -5,
                format!(
                    "combined_ss must be 64 bytes, got {}",
                    inp.combined_ss.len()
                ),
            );
        }
        let mut ss = [0u8; 64];
        ss.copy_from_slice(&inp.combined_ss);
        let secrets = derive_output_secrets(&ss, inp.output_index);
        ss.zeroize();

        let Some(ho_scalar) = curve25519_scalar_from_bytes(&secrets.ho) else {
            drop(spend_inputs);
            return ShekylSignResult::err(-5, "invalid ho scalar".into());
        };
        let x = ho_scalar + b_scalar;
        let mut x_bytes = x.to_bytes();

        spend_inputs.push(shekyl_tx_builder::SpendInput {
            output_key: inp.output_key,
            commitment: inp.commitment,
            amount: shekyl_units::AtomicUnits::from_raw(inp.amount),
            spend_key_x: x_bytes,
            spend_key_y: secrets.y,
            commitment_mask: inp.commitment_mask,
            h_pqc: inp.hp_of_O,
            combined_ss: inp.combined_ss.clone(),
            output_index: inp.output_index,
            leaf_chunk: inp.leaf_chunk.clone(),
            c1_layers: inp.c1_layers.clone(),
            c2_layers: inp.c2_layers.clone(),
        });

        x_bytes.zeroize();
    }

    // C++ wallet passes LMDB depth; convert to upstream layers (depth + 1).
    let layers = tree_depth.saturating_add(1);
    let tree = shekyl_tx_builder::TreeContext {
        reference_block,
        tree_root,
        tree_depth: layers,
    };

    let result = match shekyl_tx_builder::sign_transaction(
        tx_prefix_hash,
        &spend_inputs,
        &outputs,
        shekyl_units::AtomicUnits::from_raw(fee),
        &tree,
    ) {
        Ok(proofs) => match serde_json::to_vec(&proofs) {
            Ok(json) => ShekylSignResult::ok(json),
            Err(e) => ShekylSignResult::err(-3, format!("result serialization error: {e}")),
        },
        Err(e) => {
            let code = tx_builder_error_code(&e);
            ShekylSignResult::err(code, e.to_string())
        }
    };

    drop(spend_inputs);
    b_scalar.zeroize();
    result
}

fn curve25519_scalar_from_bytes(bytes: &[u8; 32]) -> Option<curve25519_dalek::Scalar> {
    Option::from(curve25519_dalek::Scalar::from_canonical_bytes(*bytes))
}

// ─── Output Construction / Scanning / PQC Signing ────────────────────────────

/// Build the 256-byte witness header from a typed struct.
///
/// # Safety
/// - `input` must point to a valid `ProveInputFields`.
/// - `out_buf` must point to at least 256 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_fcmp_build_witness_header(
    input: *const ProveInputFields,
    out_buf: *mut u8,
) -> bool {
    if input.is_null() || out_buf.is_null() {
        return false;
    }
    let inp = &*input;
    let buf = std::slice::from_raw_parts_mut(out_buf, SHEKYL_PROVE_WITNESS_HEADER_BYTES);
    buf[0..32].copy_from_slice(&inp.output_key);
    buf[32..64].copy_from_slice(&inp.key_image_gen);
    buf[64..96].copy_from_slice(&inp.commitment);
    buf[96..128].copy_from_slice(&inp.h_pqc);
    buf[128..160].copy_from_slice(&inp.spend_key_x);
    buf[160..192].copy_from_slice(&inp.spend_key_y);
    buf[192..224].copy_from_slice(&inp.commitment_mask);
    buf[224..256].copy_from_slice(&inp.pseudo_out_blind);
    true
}

/// Construct a two-component output via the unified HKDF path.
///
/// # Safety
/// - `tx_key_secret_ptr` must point to 32 bytes (sender's tx secret key).
/// - `x25519_pk` must point to 32 bytes.
/// - `ml_kem_ek` must point to `ml_kem_ek_len` bytes (expected: 1184).
/// - `spend_key` must point to 32 bytes (compressed Edwards point B).
/// - The returned `ShekylOutputData` owns its buffer fields; free them
///   with `shekyl_buffer_free` when done.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_output(
    tx_key_secret_ptr: *const u8,
    x25519_pk: *const u8,
    ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    spend_key: *const u8,
    amount: u64,
    output_index: u64,
) -> ShekylOutputData {
    let fail = ShekylOutputData {
        output_key: [0; 32],
        commitment: [0; 32],
        enc_amount: [0; 8],
        amount_tag: 0,
        enc_label: [0; 8],
        label_tag: 0,
        view_tag_prefilter: 0,
        kem_ciphertext_x25519: [0; 32],
        kem_ciphertext_ml_kem: ShekylBuffer::null(),
        pqc_public_key: ShekylBuffer::null(),
        h_pqc: [0; 32],
        y: [0; 32],
        z: [0; 32],
        k_amount: [0; 32],
        success: false,
    };

    let Some(tx_key) = arr32_from_ptr(tx_key_secret_ptr) else {
        return fail;
    };
    let Some(x_pk) = arr32_from_ptr(x25519_pk) else {
        return fail;
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return fail;
    };
    let Some(ek) = (unsafe { slice_from_ptr(ml_kem_ek, ml_kem_ek_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::construct_output;
    match construct_output(&tx_key, &x_pk, ek, &sk, amount, output_index) {
        Ok(mut out) => {
            let kem_ciphertext_ml_kem = std::mem::take(&mut out.kem_ciphertext_ml_kem);
            let pqc_public_key = std::mem::take(&mut out.pqc_public_key);
            ShekylOutputData {
                output_key: out.output_key,
                commitment: out.commitment,
                enc_amount: out.enc_amount,
                amount_tag: out.amount_tag,
                enc_label: out.enc_label,
                label_tag: out.label_tag,
                view_tag_prefilter: out.view_tag_prefilter,
                kem_ciphertext_x25519: out.kem_ciphertext_x25519,
                kem_ciphertext_ml_kem: ShekylBuffer::from_vec(kem_ciphertext_ml_kem),
                pqc_public_key: ShekylBuffer::from_vec(pqc_public_key),
                h_pqc: out.h_pqc,
                y: out.y,
                z: out.z,
                k_amount: out.k_amount,
                success: true,
            }
        }
        Err(_) => fail,
    }
}

/// Like [`shekyl_construct_output`] but encrypts the supplied 8-byte label plaintext.
///
/// # Safety
/// Same as `shekyl_construct_output`; `label_plaintext` must point to 8 bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_construct_output_labeled(
    tx_key_secret_ptr: *const u8,
    x25519_pk: *const u8,
    ml_kem_ek: *const u8,
    ml_kem_ek_len: usize,
    spend_key: *const u8,
    amount: u64,
    output_index: u64,
    label_plaintext: *const u8,
) -> ShekylOutputData {
    let fail = ShekylOutputData {
        output_key: [0; 32],
        commitment: [0; 32],
        enc_amount: [0; 8],
        amount_tag: 0,
        enc_label: [0; 8],
        label_tag: 0,
        view_tag_prefilter: 0,
        kem_ciphertext_x25519: [0; 32],
        kem_ciphertext_ml_kem: ShekylBuffer::null(),
        pqc_public_key: ShekylBuffer::null(),
        h_pqc: [0; 32],
        y: [0; 32],
        z: [0; 32],
        k_amount: [0; 32],
        success: false,
    };

    let Some(tx_key) = arr32_from_ptr(tx_key_secret_ptr) else {
        return fail;
    };
    let Some(x_pk) = arr32_from_ptr(x25519_pk) else {
        return fail;
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return fail;
    };
    let Some(ek) = (unsafe { slice_from_ptr(ml_kem_ek, ml_kem_ek_len) }) else {
        return fail;
    };
    let Some(label_slice) = (unsafe { slice_from_ptr(label_plaintext, 8) }) else {
        return fail;
    };
    let mut label_pt = [0u8; 8];
    label_pt.copy_from_slice(label_slice);

    use shekyl_crypto_pq::output::construct_output_with_label_plaintext;
    match construct_output_with_label_plaintext(
        &tx_key,
        &x_pk,
        ek,
        &sk,
        amount,
        output_index,
        &label_pt,
    ) {
        Ok(mut out) => {
            let kem_ciphertext_ml_kem = std::mem::take(&mut out.kem_ciphertext_ml_kem);
            let pqc_public_key = std::mem::take(&mut out.pqc_public_key);
            ShekylOutputData {
                output_key: out.output_key,
                commitment: out.commitment,
                enc_amount: out.enc_amount,
                amount_tag: out.amount_tag,
                enc_label: out.enc_label,
                label_tag: out.label_tag,
                view_tag_prefilter: out.view_tag_prefilter,
                kem_ciphertext_x25519: out.kem_ciphertext_x25519,
                kem_ciphertext_ml_kem: ShekylBuffer::from_vec(kem_ciphertext_ml_kem),
                pqc_public_key: ShekylBuffer::from_vec(pqc_public_key),
                h_pqc: out.h_pqc,
                y: out.y,
                z: out.z,
                k_amount: out.k_amount,
                success: true,
            }
        }
        Err(_) => fail,
    }
}

/// Select the 8-byte `enc_label` plaintext for a payment URI.
///
/// Echoes the `rid` REQUEST tag when the `shekyl:` URI carries a valid
/// (u48-encodable) `rid`; a missing or out-of-range `rid` falls back to the
/// sentinel plaintext. Ungated: the `enc_label` indistinguishability
/// invariant (`SUBADDRESS_UNDER_PQC.md` §5.7.10) makes the real-label wire
/// octets indistinguishable from the sentinel to any non-recipient, so there is
/// no privacy/consensus gate — emitting a `rid` URI (a GUI/product choice) is
/// the only feature boundary. (The R2-F8 `cooperative_enabled` flag was retired
/// 2026-06-15.)
///
/// Returns `0` on success and writes plaintext to `out_plaintext` (8 bytes).
/// Returns `-4` on null pointer (output untouched). On all other returns the
/// output is the sentinel plaintext so C callers never read uninitialized bytes.
/// Returns `-3` on UTF-8 / URI parse failure.
///
/// # Safety
/// `uri` must be a valid pointer to a NUL-terminated C string (readable
/// through the NUL); `out_plaintext` must point to 8 writable bytes. UTF-8 is
/// **not** a safety precondition — a non-UTF-8 `uri` is a normal `-3` return
/// (with the sentinel already written), not undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn shekyl_label_plaintext_for_payment_uri(
    uri: *const std::ffi::c_char,
    out_plaintext: *mut u8,
) -> i32 {
    if uri.is_null() || out_plaintext.is_null() {
        return -4;
    }
    use shekyl_crypto_pq::label::{encode_request_plaintext, sentinel_plaintext};
    let sentinel = sentinel_plaintext();
    unsafe {
        std::ptr::copy_nonoverlapping(sentinel.as_ptr(), out_plaintext, 8);
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(uri) };
    let Ok(uri_str) = cstr.to_str() else {
        return -3;
    };
    let parsed = match shekyl_address::parse_payment_uri(uri_str) {
        Ok(p) => p,
        Err(_) => return -3,
    };
    let pt = parsed
        .rid
        .and_then(encode_request_plaintext)
        .unwrap_or_else(sentinel_plaintext);
    unsafe {
        std::ptr::copy_nonoverlapping(pt.as_ptr(), out_plaintext, 8);
    }
    0
}

/// Free a ShekylOutputData's heap-allocated buffer fields.
///
/// # Safety
/// Only call once per ShekylOutputData returned from `shekyl_construct_output`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_output_data_free(data: *mut ShekylOutputData) {
    if data.is_null() {
        return;
    }
    let d = &mut *data;
    // Wipe secret fields
    use zeroize::Zeroize;
    d.y.zeroize();
    d.z.zeroize();
    d.k_amount.zeroize();
    if !d.kem_ciphertext_ml_kem.ptr.is_null() {
        shekyl_buffer_free(d.kem_ciphertext_ml_kem.ptr, d.kem_ciphertext_ml_kem.len);
        d.kem_ciphertext_ml_kem = ShekylBuffer::null();
    }
    if !d.pqc_public_key.ptr.is_null() {
        shekyl_buffer_free(d.pqc_public_key.ptr, d.pqc_public_key.len);
        d.pqc_public_key = ShekylBuffer::null();
    }
}

/// Scan an output: KEM decap + HKDF derivation + verification.
///
/// # Safety
/// - Pointer parameters must be valid and sized as documented.
/// - `y_out`, `z_out`, `k_amount_out` must each point to 32 writable bytes
///   (caller-owned secret buffers; caller is responsible for wiping).
#[no_mangle]
pub unsafe extern "C" fn shekyl_scan_output(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    enc_label: *const u8,
    label_tag_on_chain: u8,
    view_tag_on_chain: u8,
    spend_key: *const u8,
    output_index: u64,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let el = match unsafe { slice_from_ptr(enc_label, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let Some(sk) = arr32_from_ptr(spend_key) else {
        return false;
    };

    if y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output;
    match scan_output(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        &el,
        label_tag_on_chain,
        view_tag_on_chain,
        &sk,
        output_index,
    ) {
        Ok(scanned) => {
            std::ptr::copy_nonoverlapping(scanned.y.as_ptr(), y_out, 32);
            std::ptr::copy_nonoverlapping(scanned.z.as_ptr(), z_out, 32);
            std::ptr::copy_nonoverlapping(scanned.k_amount.as_ptr(), k_amount_out, 32);
            *amount_out = scanned.amount;
            *pqc_pk_out = ShekylBuffer::from_vec(scanned.pqc_public_key.clone());
            *pqc_sk_out = ShekylBuffer::from_vec(scanned.pqc_secret_key.clone());
            *h_pqc_out = scanned.h_pqc;
            // scanned drops here — ZeroizeOnDrop wipes y, z, k_amount, pqc_secret_key
            true
        }
        Err(_) => false,
    }
}

/// Scan an output recovering the spend key B' = O - ho*G - y*T.
///
/// Unlike `shekyl_scan_output`, this function does NOT take a `spend_key`
/// parameter. Instead, it returns the recovered spend key so the caller
/// can compare against the account primary spend public key (FA-2).
///
/// # Safety
/// - Same pointer requirements as `shekyl_scan_output`.
/// - `recovered_spend_key_out`, `ho_out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_scan_output_recover(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    enc_label: *const u8,
    label_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
    ho_out: *mut u8,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    recovered_spend_key_out: *mut u8,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let el = match unsafe { slice_from_ptr(enc_label, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };

    if ho_out.is_null()
        || y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || recovered_spend_key_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }

    use shekyl_crypto_pq::output::scan_output_recover;
    match scan_output_recover(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        &el,
        label_tag_on_chain,
        view_tag_on_chain,
        output_index,
    ) {
        Ok(recovered) => {
            std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
            std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
            std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
            std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
            *amount_out = recovered.amount;
            std::ptr::copy_nonoverlapping(
                recovered.recovered_spend_key.as_ptr(),
                recovered_spend_key_out,
                32,
            );
            *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
            *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
            *h_pqc_out = recovered.h_pqc;
            true
        }
        Err(_) => false,
    }
}

/// Sign a message using the HKDF-derived hybrid PQC keypair for an output.
/// ML-DSA secret key never crosses this boundary — it lives and dies in Rust.
///
/// # Safety
/// - `combined_ss` must point to 64 bytes.
/// - `message` must point to `message_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn shekyl_sign_pqc_auth(
    combined_ss: *const u8,
    output_index: u64,
    message: *const u8,
    message_len: usize,
) -> ShekylPqcAuthResult {
    let fail = ShekylPqcAuthResult {
        hybrid_public_key: ShekylBuffer::null(),
        signature: ShekylBuffer::null(),
        success: false,
    };

    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return fail,
    };
    let Some(msg) = (unsafe { slice_from_ptr(message, message_len) }) else {
        return fail;
    };

    use shekyl_crypto_pq::output::sign_pqc_auth_for_output;
    match sign_pqc_auth_for_output(&ss, output_index, msg) {
        Ok(auth) => ShekylPqcAuthResult {
            hybrid_public_key: ShekylBuffer::from_vec(auth.hybrid_public_key),
            signature: ShekylBuffer::from_vec(auth.signature),
            success: true,
        },
        Err(_) => fail,
    }
}

/// Free a ShekylPqcAuthResult's heap-allocated fields.
///
/// # Safety
/// Caller must ensure all pointer arguments are valid or null.
#[no_mangle]
pub unsafe extern "C" fn shekyl_pqc_auth_result_free(result: *mut ShekylPqcAuthResult) {
    if result.is_null() {
        return;
    }
    let r = &mut *result;
    if !r.hybrid_public_key.ptr.is_null() {
        shekyl_buffer_free(r.hybrid_public_key.ptr, r.hybrid_public_key.len);
        r.hybrid_public_key = ShekylBuffer::null();
    }
    if !r.signature.ptr.is_null() {
        shekyl_buffer_free(r.signature.ptr, r.signature.len);
        r.signature = ShekylBuffer::null();
    }
}

// ─── PR-wallet Phase 1b: Merged scan, key image, proofs, cache crypto ────────

/// Merged scan + key image computation.
///
/// Scans an output (KEM decap, HKDF derivation, amount decryption) and computes
/// the key image in a single call. All secret outputs are written directly into
/// caller-provided destination addresses (transfer_details fields). No
/// intermediate scratch buffers are created on the C++ stack.
///
/// # Safety
/// - All pointer parameters must be valid for reads/writes of their documented sizes.
/// - `ho_out`, `y_out`, `z_out`, `k_amount_out`: 32 writable bytes each.
/// - `key_image_out`: 32 writable bytes.
/// - `recovered_spend_key_out`: 32 writable bytes.
/// - `combined_ss_out`: 64 writable bytes if `persist_combined_ss` is true, or nullptr.
/// - `spend_secret_key`: 32 bytes (wallet master spend key `b`).
/// - `hp_of_O`: 32 bytes (hash_to_ec of the output key, precomputed by C++).
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_scan_and_recover(
    x25519_sk: *const u8,
    ml_kem_dk: *const u8,
    ml_kem_dk_len: usize,
    kem_ct_x25519: *const u8,
    kem_ct_ml_kem: *const u8,
    kem_ct_ml_kem_len: usize,
    output_key: *const u8,
    commitment: *const u8,
    enc_amount: *const u8,
    amount_tag_on_chain: u8,
    enc_label: *const u8,
    label_tag_on_chain: u8,
    view_tag_on_chain: u8,
    output_index: u64,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    persist_combined_ss: bool,
    ho_out: *mut u8,
    y_out: *mut u8,
    z_out: *mut u8,
    k_amount_out: *mut u8,
    amount_out: *mut u64,
    recovered_spend_key_out: *mut u8,
    key_image_out: *mut u8,
    combined_ss_out: *mut u8,
    pqc_pk_out: *mut ShekylBuffer,
    pqc_sk_out: *mut ShekylBuffer,
    h_pqc_out: *mut [u8; 32],
) -> bool {
    let Some(x_sk) = arr32_from_ptr(x25519_sk) else {
        return false;
    };
    let Some(dk) = (unsafe { slice_from_ptr(ml_kem_dk, ml_kem_dk_len) }) else {
        return false;
    };
    let Some(ct_x) = arr32_from_ptr(kem_ct_x25519) else {
        return false;
    };
    let Some(ct_ml) = (unsafe { slice_from_ptr(kem_ct_ml_kem, kem_ct_ml_kem_len) }) else {
        return false;
    };
    let Some(o) = arr32_from_ptr(output_key) else {
        return false;
    };
    let Some(c) = arr32_from_ptr(commitment) else {
        return false;
    };
    let ea = match unsafe { slice_from_ptr(enc_amount, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let el = match unsafe { slice_from_ptr(enc_label, 8) } {
        Some(v) => {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let have_spend_key = !spend_secret_key.is_null() && !hp_of_O.is_null();

    if ho_out.is_null()
        || y_out.is_null()
        || z_out.is_null()
        || k_amount_out.is_null()
        || amount_out.is_null()
        || recovered_spend_key_out.is_null()
        || key_image_out.is_null()
        || pqc_pk_out.is_null()
        || pqc_sk_out.is_null()
        || h_pqc_out.is_null()
    {
        return false;
    }
    if persist_combined_ss && combined_ss_out.is_null() {
        return false;
    }

    use shekyl_crypto_pq::output::{compute_output_key_image_from_ho, scan_output_recover};

    let Ok(recovered) = scan_output_recover(
        &x_sk,
        dk,
        &ct_x,
        ct_ml,
        &o,
        &c,
        &ea,
        amount_tag_on_chain,
        &el,
        label_tag_on_chain,
        view_tag_on_chain,
        output_index,
    ) else {
        return false;
    };

    std::ptr::copy_nonoverlapping(recovered.ho.as_ptr(), ho_out, 32);
    std::ptr::copy_nonoverlapping(recovered.y.as_ptr(), y_out, 32);
    std::ptr::copy_nonoverlapping(recovered.z.as_ptr(), z_out, 32);
    std::ptr::copy_nonoverlapping(recovered.k_amount.as_ptr(), k_amount_out, 32);
    *amount_out = recovered.amount;
    std::ptr::copy_nonoverlapping(
        recovered.recovered_spend_key.as_ptr(),
        recovered_spend_key_out,
        32,
    );
    *pqc_pk_out = ShekylBuffer::from_vec(recovered.pqc_public_key.clone());
    *pqc_sk_out = ShekylBuffer::from_vec(recovered.pqc_secret_key.clone());
    *h_pqc_out = recovered.h_pqc;

    if have_spend_key {
        let b_key = &*(spend_secret_key as *const [u8; 32]);
        let hp = &*(hp_of_O as *const [u8; 32]);
        let Ok(ki_result) = compute_output_key_image_from_ho(&recovered.ho, b_key, hp) else {
            return false;
        };
        std::ptr::copy_nonoverlapping(ki_result.key_image.as_bytes().as_ptr(), key_image_out, 32);
    } else {
        std::ptr::write_bytes(key_image_out, 0, 32);
    }

    if persist_combined_ss {
        std::ptr::copy_nonoverlapping(recovered.combined_ss.as_ptr(), combined_ss_out, 64);
    }

    true
}

/// Compute key image from persisted `combined_ss` + `output_index`.
///
/// Derives `ho` from HKDF, computes `KI = (ho + b) * Hp(O)`.
/// Used at stake claim (1 site).
///
/// # Safety
/// - `combined_ss`: 64 bytes. `spend_secret_key`, `hp_of_O`, `out_ki`: 32 bytes each.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_compute_output_key_image(
    combined_ss: *const u8,
    output_index: u64,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    out_ki: *mut u8,
) -> bool {
    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    let Some(b) = arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(hp) = arr32_from_ptr(hp_of_O) else {
        return false;
    };
    if out_ki.is_null() {
        return false;
    }

    match shekyl_crypto_pq::output::compute_output_key_image(&ss, output_index, &b, &hp) {
        Ok(result) => {
            std::ptr::copy_nonoverlapping(result.key_image.as_bytes().as_ptr(), out_ki, 32);
            true
        }
        Err(_) => false,
    }
}

/// Compute key image from pre-derived `ho` scalar.
///
/// Computes `KI = (ho + b) * Hp(O)`.
/// Used at `tx_source_entry` boundary (1 site).
///
/// # Safety
/// - `ho`, `spend_secret_key`, `hp_of_O`, `out_ki`: 32 bytes each.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn shekyl_compute_output_key_image_from_ho(
    ho: *const u8,
    spend_secret_key: *const u8,
    hp_of_O: *const u8,
    out_ki: *mut u8,
) -> bool {
    let Some(ho_arr) = arr32_from_ptr(ho) else {
        return false;
    };
    let Some(b) = arr32_from_ptr(spend_secret_key) else {
        return false;
    };
    let Some(hp) = arr32_from_ptr(hp_of_O) else {
        return false;
    };
    if out_ki.is_null() {
        return false;
    }

    match shekyl_crypto_pq::output::compute_output_key_image_from_ho(&ho_arr, &b, &hp) {
        Ok(result) => {
            std::ptr::copy_nonoverlapping(result.key_image.as_bytes().as_ptr(), out_ki, 32);
            true
        }
        Err(_) => false,
    }
}

/// Derive the ProofSecrets projection from `combined_ss`.
///
/// Writes `ho`, `y`, `z`, `k_amount` directly to caller-provided destination
/// addresses (no scratch buffers).
///
/// # Safety
/// - `combined_ss`: 64 bytes.
/// - `out_ho`, `out_y`, `out_z`, `out_k_amount`: 32 writable bytes each.
#[no_mangle]
pub unsafe extern "C" fn shekyl_derive_proof_secrets(
    combined_ss: *const u8,
    output_index: u64,
    out_ho: *mut u8,
    out_y: *mut u8,
    out_z: *mut u8,
    out_k_amount: *mut u8,
) -> bool {
    let ss = match unsafe { slice_from_ptr(combined_ss, 64) } {
        Some(v) => {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(v);
            arr
        }
        None => return false,
    };
    if out_ho.is_null() || out_y.is_null() || out_z.is_null() || out_k_amount.is_null() {
        return false;
    }

    let secrets = shekyl_crypto_pq::output::derive_proof_secrets(&ss, output_index);
    std::ptr::copy_nonoverlapping(secrets.ho.as_ptr(), out_ho, 32);
    std::ptr::copy_nonoverlapping(secrets.y.as_ptr(), out_y, 32);
    std::ptr::copy_nonoverlapping(secrets.z.as_ptr(), out_z, 32);
    std::ptr::copy_nonoverlapping(secrets.k_amount.as_ptr(), out_k_amount, 32);
    true
}

// ─── Engine cache AEAD encryption ────────────────────────────────────────────

/// Encrypt wallet cache plaintext with XChaCha20-Poly1305 AEAD.
///
/// `cache_format_version` is bound into the Poly1305 AAD. Version changes
/// invalidate existing ciphertext. The output format is:
/// `[version_byte][nonce(24)][ciphertext][tag(16)]`.
///
/// # Safety
/// - `plaintext`: `plaintext_len` readable bytes.
/// - `password_derived_key`: 32 bytes.
/// - `out_buf`: pointer to writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_encrypt_wallet_cache(
    plaintext: *const u8,
    plaintext_len: usize,
    cache_format_version: u8,
    password_derived_key: *const u8,
    out_buf: *mut ShekylBuffer,
) -> bool {
    let Some(pt) = (unsafe { slice_from_ptr(plaintext, plaintext_len) }) else {
        return false;
    };
    let Some(key) = arr32_from_ptr(password_derived_key) else {
        return false;
    };
    if out_buf.is_null() {
        return false;
    }

    let aad = [cache_format_version];
    let encrypted = shekyl_chacha::encrypt_with_aad(&key, &aad, pt);

    let mut output = Vec::with_capacity(1 + encrypted.len());
    output.push(cache_format_version);
    output.extend_from_slice(&encrypted);

    *out_buf = ShekylBuffer::from_vec(output);
    true
}

/// Decrypt wallet cache ciphertext with XChaCha20-Poly1305 AEAD.
///
/// Returns 0 on success, negative on error:
///   -1: version mismatch (first byte != expected_version)
///   -2: authentication failure (AAD/tag mismatch)
///   -3: invalid format (too short)
///   -4: null pointer argument
///
/// # Safety
/// - `ciphertext`: `ciphertext_len` readable bytes.
/// - `password_derived_key`: 32 bytes.
/// - `out_buf`: pointer to writable `ShekylBuffer`.
#[no_mangle]
pub unsafe extern "C" fn shekyl_decrypt_wallet_cache(
    ciphertext: *const u8,
    ciphertext_len: usize,
    expected_version: u8,
    password_derived_key: *const u8,
    out_buf: *mut ShekylBuffer,
) -> i32 {
    if ciphertext.is_null() || password_derived_key.is_null() || out_buf.is_null() {
        return -4;
    }
    let Some(ct) = (unsafe { slice_from_ptr(ciphertext, ciphertext_len) }) else {
        return -4;
    };
    let Some(key) = arr32_from_ptr(password_derived_key) else {
        return -4;
    };

    if ct.is_empty() {
        return -3;
    }

    let on_disk_version = ct[0];
    if on_disk_version != expected_version {
        return -1;
    }

    let aead_data = &ct[1..];
    let aad = [on_disk_version];

    match shekyl_chacha::decrypt_with_aad(&key, &aad, aead_data) {
        Ok(plaintext) => {
            *out_buf = ShekylBuffer::from_vec(plaintext);
            0
        }
        Err(_) => -2,
    }
}
