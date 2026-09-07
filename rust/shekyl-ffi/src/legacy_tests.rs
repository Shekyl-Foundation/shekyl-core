// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the legacy monofile FFI surface.

use super::*;

/// **Leg 1 preserved across the boundary: the escalated share cannot reach
/// miner income.** Sweeping `n` across the whole domain, `miner_fee_income`
/// is invariant while value moves between `staker_pool_amount` and
/// `actually_destroyed`. This is the structural unreachability
/// (§12.11.1 Leg 1) asserted at the surface C++ actually calls, not inferred
/// from the formula.
#[test]
fn escalating_the_share_never_touches_miner_income() {
    const FEES: u64 = 1_000_000_000;
    const BURN_PCT: u64 = 500_000;

    let baseline = shekyl_compute_burn_split_escalated(FEES, BURN_PCT, 0);
    for n in [0u64, 1, 1_000, 50_000, 100_000, 1_000_000, u64::MAX] {
        let split = shekyl_compute_burn_split_escalated(FEES, BURN_PCT, n);
        assert_eq!(
            split.miner_fee_income, baseline.miner_fee_income,
            "n={n} moved miner income — the security-budget channel must be \
                 structurally unreachable from the staker share"
        );
        // Conservation: the three legs still partition the fees exactly.
        assert_eq!(
            split.miner_fee_income + split.staker_pool_amount + split.actually_destroyed,
            FEES,
            "n={n} broke the three-way partition"
        );
    }
}

/// **The genesis-neutral property, end to end.** At the shipped
/// parameterization (`asymptote == staker_pool_share`) the escalated entry
/// is bit-identical to the flat one at every `n`, so landing the frozen
/// shape changes no consensus output until the ceremony raises the
/// asymptote.
#[test]
fn escalated_split_is_bit_identical_to_flat_at_the_genesis_parameterization() {
    let params = shekyl_economics::params::EconomicParams::default();
    assert_eq!(
        params.escalation_asymptote_share, params.staker_pool_share,
        "this test asserts the NEUTRAL default; if the ceremony has pinned a \
             real asymptote, this test must be replaced by one that pins the \
             pinned value, not deleted"
    );

    for fees in [0u64, 1, 1_000_000_000, u64::MAX / 4] {
        for burn_pct in [0u64, 250_000, 500_000, 900_000] {
            let flat = shekyl_compute_burn_split(fees, burn_pct, params.staker_pool_share);
            for n in [0u64, 1, 100_000, u64::MAX] {
                let esc = shekyl_compute_burn_split_escalated(fees, burn_pct, n);
                assert_eq!(esc.miner_fee_income, flat.miner_fee_income);
                assert_eq!(esc.staker_pool_amount, flat.staker_pool_amount);
                assert_eq!(esc.actually_destroyed, flat.actually_destroyed);
            }
        }
    }
}

/// The observability entry agrees with what the split actually applied.
#[test]
fn exposed_share_matches_the_share_the_split_used() {
    use shekyl_economics::{staker_pool_share_at, EconomicParams, FrozenSegmentCount};
    let params = EconomicParams::default();
    for n in [0u64, 1, 100_000, u64::MAX] {
        assert_eq!(
            shekyl_staker_pool_share_at(n),
            staker_pool_share_at(FrozenSegmentCount::new(n), &params.escalation()).to_raw()
        );
    }
}

/// Escalated FFI is a pure packing of the canonical Rust entry — no second formula.
#[test]
fn escalated_ffi_matches_compute_burn_split_at() {
    use shekyl_economics::{compute_burn_split_at, EconomicParams, FrozenSegmentCount};
    let params = EconomicParams::default();
    for n in [0u64, 1, 100_000, u64::MAX] {
        let rust =
            compute_burn_split_at(1_000_000_000, 500_000, FrozenSegmentCount::new(n), &params);
        let c = shekyl_compute_burn_split_escalated(1_000_000_000, 500_000, n);
        assert_eq!(c.miner_fee_income, rust.miner_fee_income);
        assert_eq!(c.staker_pool_amount, rust.staker_pool_amount);
        assert_eq!(c.actually_destroyed, rust.actually_destroyed);
    }
}

#[test]
fn test_version() {
    let ptr = shekyl_rust_version();
    let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
    assert_eq!(s.to_str().unwrap(), "2.0.0");
}

#[test]
fn test_release_multiplier_ffi() {
    let m = shekyl_calc_release_multiplier(100, 100, 800_000, 1_300_000);
    assert_eq!(m, 1_000_000);
}

// ---- PR-E1: reward-emission membership-only primitives ----
// (The per-auth hybrid gate FFI was retired: C-1 verifies auth via the coarse
// shekyl_emission_vin_verify, whose Rust body emission_vin_verify_auth pins the
// leaf-gate-first order and per-role domains — see emission_verify_kat.rs.)

/// The full-path FFI shares the membership-only hardening: matched-but-huge
/// or over-cap counts reject with code 1 before any slice/allocation.
#[test]
fn full_verify_ffi_rejects_hostile_counts() {
    let root = [0u8; 32];
    let txh = [0u8; 32];
    let proof = [0u8; 8];
    let b32 = [1u8; 32];

    // usize::MAX matched counts: rejected by the arity cap, pointers never
    // dereferenced (small buffers are safe to pass).
    let r = unsafe {
        shekyl_fcmp_verify(
            proof.as_ptr(),
            proof.len(),
            b32.as_ptr(),
            usize::MAX,
            b32.as_ptr(),
            usize::MAX,
            b32.as_ptr(),
            usize::MAX,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(
        r, 1,
        "hostile matched counts must reject without dereferencing"
    );

    // MAX_INPUTS + 1, buffers sized to the declared count.
    let over = shekyl_fcmp::MAX_INPUTS + 1;
    let big = vec![2u8; over * 32];
    let r = unsafe {
        shekyl_fcmp_verify(
            proof.as_ptr(),
            proof.len(),
            big.as_ptr(),
            over,
            big.as_ptr(),
            over,
            big.as_ptr(),
            over,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 1, "count over MAX_INPUTS must reject via the arity cap");
}

#[test]
fn membership_only_verify_rejects_malformed_and_mismatched_inputs() {
    let root = [0u8; 32];
    let txh = [0u8; 32];

    // Null proof pointer with a nonzero length -> DeserializationFailed (1).
    let po1 = [1u8; 32];
    let ph1 = [2u8; 32];
    let r = unsafe {
        shekyl_fcmp_membership_only_verify(
            std::ptr::null(),
            8,
            po1.as_ptr(),
            1,
            ph1.as_ptr(),
            1,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 1, "null proof must reject");

    // Count mismatch po_count != pqc_hash_count -> 8 (InputCountMismatch). Buffers
    // sized to the declared counts (po = 2×32, ph = 1×32) so no out-of-bounds read.
    let po2 = [1u8; 64];
    let proof = [0u8; 8];
    let r = unsafe {
        shekyl_fcmp_membership_only_verify(
            proof.as_ptr(),
            proof.len(),
            po2.as_ptr(),
            2,
            ph1.as_ptr(),
            1,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(
        r, 8,
        "po/pqc count mismatch must reject as InputCountMismatch"
    );

    // A huge (matched) count must reject BEFORE any slice read or allocation — no panic
    // across the FFI. `usize::MAX` is caught by the MAX_INPUTS arity cap (which fires ahead
    // of the checked_mul defense-in-depth). The pointer is never dereferenced on this path.
    let r = unsafe {
        shekyl_fcmp_membership_only_verify(
            proof.as_ptr(),
            proof.len(),
            po1.as_ptr(),
            usize::MAX,
            ph1.as_ptr(),
            usize::MAX,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 1, "oversized count must reject without dereferencing");

    // Boundary: a within-`usize`, matched count just over MAX_INPUTS must reject via the
    // arity cap before allocating the per-input Vecs. Buffers
    // are sized to the declared count so there is no out-of-bounds read on the reject path.
    let over = shekyl_fcmp::MAX_INPUTS + 1;
    let big = vec![3u8; over * 32];
    let r = unsafe {
        shekyl_fcmp_membership_only_verify(
            proof.as_ptr(),
            proof.len(),
            big.as_ptr(),
            over,
            big.as_ptr(),
            over,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 1, "count over MAX_INPUTS must reject via the arity cap");

    // Well-formed call over junk proof bytes must NEVER vacuously verify.
    let junk = vec![0xABu8; 512];
    let r = unsafe {
        shekyl_fcmp_membership_only_verify(
            junk.as_ptr(),
            junk.len(),
            po1.as_ptr(),
            1,
            ph1.as_ptr(),
            1,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_ne!(r, 0, "junk membership-only proof must never verify");
}

#[test]
fn grow_upper_layers_ffi_equals_build_layers() {
    // The producer-side fix: the FFI grow over the leaf-chunk layer reproduces
    // build_layers' upper layers + root EXACTLY, including the depth-3 layer-2
    // Selene root the daemon's incremental deepening gets wrong. Sizes span
    // depth-1 (≤38), depth-2 (39..684) and depth-3 (685, 701).
    use shekyl_fcmp::tree::{build_layers, SCALARS_PER_LEAF};
    for &n_outputs in &[1usize, 38, 39, 684, 685, 701] {
        // Small little-endian integers are canonical Selene field elements.
        let leaf_scalars: Vec<[u8; 32]> = (0..n_outputs * SCALARS_PER_LEAF)
            .map(|i| {
                let mut b = [0u8; 32];
                let v = u64::try_from(i % 251).unwrap() + 1;
                b[..8].copy_from_slice(&v.to_le_bytes());
                b
            })
            .collect();
        let reference = build_layers(&leaf_scalars);
        let leaf_layer = &reference[0];
        let leaf_flat: Vec<u8> = leaf_layer.iter().flatten().copied().collect();

        let upper_total: usize = reference[1..].iter().map(Vec::len).sum();
        let mut out_chunks = vec![0u8; (upper_total + 1) * 32];
        let mut out_sizes = vec![0u64; 16];
        let mut num_upper = 0u64;
        let mut root = [0u8; 32];
        let ok = unsafe {
            shekyl_curve_tree_grow_upper_layers(
                leaf_flat.as_ptr(),
                u64::try_from(leaf_layer.len()).unwrap(),
                out_chunks.as_mut_ptr(),
                u64::try_from(out_chunks.len() / 32).unwrap(),
                out_sizes.as_mut_ptr(),
                u64::try_from(out_sizes.len()).unwrap(),
                std::ptr::addr_of_mut!(num_upper),
                root.as_mut_ptr(),
            )
        };
        assert!(ok, "FFI grow returned false at n={n_outputs}");

        let mut got: Vec<Vec<[u8; 32]>> = Vec::new();
        let mut off = 0usize;
        for &sz in out_sizes.iter().take(usize::try_from(num_upper).unwrap()) {
            let sz = usize::try_from(sz).unwrap();
            let layer: Vec<[u8; 32]> = (0..sz)
                .map(|k| {
                    let mut b = [0u8; 32];
                    b.copy_from_slice(&out_chunks[(off + k) * 32..(off + k + 1) * 32]);
                    b
                })
                .collect();
            off += sz;
            got.push(layer);
        }
        assert_eq!(
            got,
            reference[1..],
            "FFI upper layers != build_layers at n={n_outputs}"
        );
        assert_eq!(
            &root,
            reference.last().unwrap().first().unwrap(),
            "FFI root != build_layers root at n={n_outputs}"
        );
    }
}

#[test]
fn test_burn_split_ffi() {
    let split = shekyl_compute_burn_split(1_000_000_000, 400_000, 200_000);
    assert_eq!(split.miner_fee_income, 600_000_000);
    assert_eq!(split.staker_pool_amount, 80_000_000);
    assert_eq!(split.actually_destroyed, 320_000_000);
}

#[test]
fn test_emission_share_genesis() {
    let share = shekyl_calc_emission_share(0, 0, 150_000, 900_000, 262_800);
    assert_eq!(share, 150_000);
}

#[test]
fn test_emission_share_year_1() {
    let share = shekyl_calc_emission_share(262_800, 0, 150_000, 900_000, 262_800);
    assert_eq!(share, 135_000);
}

#[test]
fn test_emission_split_ffi() {
    let split = shekyl_split_block_emission(1_000_000_000, 150_000);
    assert_eq!(split.staker_emission, 150_000_000);
    assert_eq!(split.miner_emission, 850_000_000);
}

#[test]
fn test_burn_pct_ffi_matches_rust_impl() {
    let cases = [
        (
            50u64,
            50u64,
            1_000_000u64,
            4_294_967_296_000_000_000u64,
            500_000u64,
            900_000u64,
        ),
        (
            200,
            50,
            2_000_000_000_000_000_000,
            4_294_967_296_000_000_000,
            500_000,
            900_000,
        ),
        (
            500,
            50,
            3_000_000_000_000_000_000,
            4_294_967_296_000_000_000,
            500_000,
            900_000,
        ),
    ];
    for (txv, base, circ, total, rate, cap) in cases {
        let ffi = shekyl_calc_burn_pct(txv, base, circ, total, rate, cap);
        let direct = shekyl_economics::burn::calc_burn_pct(txv, base, circ, total, rate, cap);
        assert_eq!(ffi, direct);
    }
}

#[test]
fn test_emission_share_ffi_matches_rust_impl() {
    let cases = [
        (0u64, 0u64, 150_000u64, 900_000u64, 262_800u64),
        (262_800, 0, 150_000, 900_000, 262_800),
        (2 * 262_800, 0, 150_000, 900_000, 262_800),
        (10 * 262_800, 0, 150_000, 900_000, 262_800),
    ];
    for (height, genesis, initial, decay, bpy) in cases {
        let ffi = shekyl_calc_emission_share(height, genesis, initial, decay, bpy);
        let direct = shekyl_economics::emission_share::calc_effective_emission_share(
            height, genesis, initial, decay, bpy,
        );
        assert_eq!(ffi, direct);
    }
}

#[test]
fn test_pqc_keygen_sign_verify_ffi() {
    unsafe {
        let kp = shekyl_pqc_keypair_generate();
        assert!(kp.success);
        assert!(!kp.public_key.ptr.is_null());
        assert!(!kp.secret_key.ptr.is_null());

        let msg = b"ffi hybrid pq signature";
        let sig = shekyl_pqc_sign(
            kp.secret_key.ptr,
            kp.secret_key.len,
            msg.as_ptr(),
            msg.len(),
        );
        assert!(sig.success);
        assert!(!sig.signature.ptr.is_null());

        let result = shekyl_pqc_verify(
            1,
            kp.public_key.ptr,
            kp.public_key.len,
            sig.signature.ptr,
            sig.signature.len,
            msg.as_ptr(),
            msg.len(),
        );
        assert_eq!(result, 0, "expected success (0), got error code {result}");

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
    }
}

#[test]
fn test_ssl_cert_generation_ecdsa() {
    unsafe {
        let mut key_pem = ShekylBuffer::null();
        let mut cert_pem = ShekylBuffer::null();
        let ok = shekyl_generate_ssl_certificate(&raw mut key_pem, &raw mut cert_pem);
        assert!(ok);
        assert!(!key_pem.ptr.is_null());
        assert!(!cert_pem.ptr.is_null());
        let key_str =
            std::str::from_utf8(std::slice::from_raw_parts(key_pem.ptr, key_pem.len)).unwrap();
        let cert_str =
            std::str::from_utf8(std::slice::from_raw_parts(cert_pem.ptr, cert_pem.len)).unwrap();
        assert!(key_str.contains("BEGIN PRIVATE KEY"));
        assert!(cert_str.contains("BEGIN CERTIFICATE"));
        shekyl_buffer_free(key_pem.ptr, key_pem.len);
        shekyl_buffer_free(cert_pem.ptr, cert_pem.len);
    }
}

#[test]
fn test_memwipe_zeroes_buffer() {
    let mut buf = vec![0xABu8; 64];
    unsafe { shekyl_memwipe(buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn test_page_size_nonzero() {
    let ps = unsafe { shekyl_page_size() };
    assert!(ps > 0, "page size should be > 0, got {ps}");
    assert!(ps.is_power_of_two(), "page size should be power of 2");
}

#[test]
fn test_pqc_verify_rejects_modified_signature() {
    unsafe {
        let kp = shekyl_pqc_keypair_generate();
        let msg = b"ffi hybrid pq signature";
        let sig = shekyl_pqc_sign(
            kp.secret_key.ptr,
            kp.secret_key.len,
            msg.as_ptr(),
            msg.len(),
        );
        assert!(sig.success);

        let mut sig_bytes =
            std::slice::from_raw_parts(sig.signature.ptr, sig.signature.len).to_vec();
        let last = sig_bytes.len() - 1;
        sig_bytes[last] ^= 0x01;

        let result = shekyl_pqc_verify(
            1,
            kp.public_key.ptr,
            kp.public_key.len,
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            msg.as_ptr(),
            msg.len(),
        );
        assert_ne!(result, 0, "corrupted signature should not verify");

        shekyl_buffer_free(kp.public_key.ptr, kp.public_key.len);
        shekyl_buffer_free(kp.secret_key.ptr, kp.secret_key.len);
        shekyl_buffer_free(sig.signature.ptr, sig.signature.len);
    }
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_keys_import_null_returns_null() {
    let handle = unsafe { shekyl_frost_keys_import(std::ptr::null(), 0) };
    assert!(handle.is_null());
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_keys_import_invalid_data_returns_null() {
    let garbage = [0xDE, 0xAD, 0xBE, 0xEF];
    let handle = unsafe { shekyl_frost_keys_import(garbage.as_ptr(), garbage.len()) };
    assert!(handle.is_null());
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_keys_validate_null_returns_false() {
    let valid = unsafe { shekyl_frost_keys_validate(std::ptr::null(), 2, 3) };
    assert!(!valid);
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_keys_group_key_null_returns_false() {
    let mut out = [0u8; 32];
    let ok = unsafe { shekyl_frost_keys_group_key(std::ptr::null(), out.as_mut_ptr()) };
    assert!(!ok);
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_keys_free_null_is_safe() {
    unsafe { shekyl_frost_keys_free(std::ptr::null_mut()) };
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_sal_session_new_null_returns_null() {
    let session = unsafe {
        shekyl_frost_sal_session_new(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    };
    assert!(session.is_null());
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_sal_session_free_null_is_safe() {
    unsafe { shekyl_frost_sal_session_free(std::ptr::null_mut()) };
}

#[cfg(feature = "multisig")]
#[test]
fn test_frost_sal_get_rerand_null_returns_empty() {
    let buf = unsafe { shekyl_frost_sal_get_rerand(std::ptr::null()) };
    assert!(buf.ptr.is_null());
    assert_eq!(buf.len, 0);
}

// ── Witness header round-trip tests ──────────────────────────────────
//
// Verifies that shekyl_fcmp_build_witness_header (writer) and
// parse_prove_witness (reader) agree byte-for-byte on all 8 header
// fields, using locked vectors from docs/test_vectors/WITNESS_HEADER.json.

#[cfg(feature = "multisig")]
#[derive(serde::Deserialize)]
struct WitnessHeaderVector {
    output_key: String,
    key_image_gen: String,
    commitment: String,
    h_pqc: String,
    spend_key_x: String,
    spend_key_y: String,
    commitment_mask: String,
    pseudo_out_blind: String,
}

#[cfg(feature = "multisig")]
#[derive(serde::Deserialize)]
struct WitnessHeaderFile {
    vectors: Vec<WitnessHeaderVector>,
}

#[cfg(feature = "multisig")]
fn decode_32(hex_str: &str, label: &str, vec_idx: usize) -> [u8; 32] {
    let bytes = hex::decode(hex_str)
        .unwrap_or_else(|_| panic!("vector {vec_idx}: invalid hex for {label}"));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("vector {vec_idx}: {label} not 32 bytes"))
}

#[cfg(feature = "multisig")]
#[test]
fn witness_header_build_then_parse_roundtrip() {
    let json = include_str!("../../../docs/test_vectors/WITNESS_HEADER.json");
    let file: WitnessHeaderFile =
        serde_json::from_str(json).expect("failed to parse WITNESS_HEADER.json");
    assert!(
        !file.vectors.is_empty(),
        "no vectors in WITNESS_HEADER.json"
    );

    for (i, v) in file.vectors.iter().enumerate() {
        let fields = ProveInputFields {
            output_key: decode_32(&v.output_key, "output_key", i),
            key_image_gen: decode_32(&v.key_image_gen, "key_image_gen", i),
            commitment: decode_32(&v.commitment, "commitment", i),
            h_pqc: decode_32(&v.h_pqc, "h_pqc", i),
            spend_key_x: decode_32(&v.spend_key_x, "spend_key_x", i),
            spend_key_y: decode_32(&v.spend_key_y, "spend_key_y", i),
            commitment_mask: decode_32(&v.commitment_mask, "commitment_mask", i),
            pseudo_out_blind: decode_32(&v.pseudo_out_blind, "pseudo_out_blind", i),
        };

        // Build: typed struct → 256-byte blob (same path as C++ FFI)
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        let ok = unsafe { shekyl_fcmp_build_witness_header(&raw const fields, blob.as_mut_ptr()) };
        assert!(
            ok,
            "vector {i}: shekyl_fcmp_build_witness_header returned false"
        );
        assert_eq!(blob.len(), 256, "vector {i}: blob not 256 bytes");

        // Verify raw byte layout matches the field offsets
        assert_eq!(
            &blob[0..32],
            fields.output_key.as_slice(),
            "vector {i}: O mismatch in blob"
        );
        assert_eq!(
            &blob[32..64],
            fields.key_image_gen.as_slice(),
            "vector {i}: I mismatch in blob"
        );
        assert_eq!(
            &blob[64..96],
            fields.commitment.as_slice(),
            "vector {i}: C mismatch in blob"
        );
        assert_eq!(
            &blob[96..128],
            fields.h_pqc.as_slice(),
            "vector {i}: h_pqc mismatch in blob"
        );
        assert_eq!(
            &blob[128..160],
            fields.spend_key_x.as_slice(),
            "vector {i}: x mismatch in blob"
        );
        assert_eq!(
            &blob[160..192],
            fields.spend_key_y.as_slice(),
            "vector {i}: y mismatch in blob"
        );
        assert_eq!(
            &blob[192..224],
            fields.commitment_mask.as_slice(),
            "vector {i}: z mismatch in blob"
        );
        assert_eq!(
            &blob[224..256],
            fields.pseudo_out_blind.as_slice(),
            "vector {i}: a mismatch in blob"
        );

        // Parse: 256-byte blob → ProveInput (same path as Rust FFI verifier).
        // parse_prove_witness expects a full witness (header + leaf + branch data).
        // We append a minimal valid trailer: 1 leaf entry + 0 branch layers.
        let mut witness = blob.clone();
        // leaf chunk_count = 1 (must have at least 1 to parse)
        witness.extend_from_slice(&1u32.to_le_bytes());
        // one leaf entry: 4 x 32 bytes (O, I, C, h_pqc)
        witness.extend_from_slice(&fields.output_key);
        witness.extend_from_slice(&fields.key_image_gen);
        witness.extend_from_slice(&fields.commitment);
        witness.extend_from_slice(&fields.h_pqc);
        // c1_layer_count = 0
        witness.extend_from_slice(&0u32.to_le_bytes());
        // c2_layer_count = 0
        witness.extend_from_slice(&0u32.to_le_bytes());

        let parsed = parse_prove_witness(&witness, 1);
        assert!(
            parsed.is_some(),
            "vector {i}: parse_prove_witness returned None"
        );
        let inputs = parsed.unwrap();
        assert_eq!(inputs.len(), 1, "vector {i}: expected 1 input");
        let pi = &inputs[0];

        assert_eq!(
            pi.output_key, fields.output_key,
            "vector {i}: parsed O mismatch"
        );
        assert_eq!(
            pi.key_image_gen, fields.key_image_gen,
            "vector {i}: parsed I mismatch"
        );
        assert_eq!(
            pi.commitment, fields.commitment,
            "vector {i}: parsed C mismatch"
        );
        assert_eq!(
            pi.h_pqc.0, fields.h_pqc,
            "vector {i}: parsed h_pqc mismatch"
        );
        assert_eq!(
            pi.spend_key_x, fields.spend_key_x,
            "vector {i}: parsed x mismatch"
        );
        assert_eq!(
            pi.spend_key_y, fields.spend_key_y,
            "vector {i}: parsed y mismatch"
        );
        assert_eq!(
            pi.commitment_mask, fields.commitment_mask,
            "vector {i}: parsed z mismatch"
        );
        assert_eq!(
            pi.pseudo_out_blind, fields.pseudo_out_blind,
            "vector {i}: parsed a mismatch"
        );
    }
}

#[test]
fn label_plaintext_for_payment_uri_null_out_returns_minus_four() {
    let uri = std::ffi::CString::new("shekyl:addr?rid=1").unwrap();
    // SAFETY: valid uri; out is null (the case under test).
    let rc = unsafe { shekyl_label_plaintext_for_payment_uri(uri.as_ptr(), std::ptr::null_mut()) };
    assert_eq!(rc, -4);
}

#[test]
fn label_plaintext_for_payment_uri_null_uri_leaves_out_untouched() {
    // The "-4 on null pointer, output untouched" contract is only
    // observable when a real out buffer is passed: a null `uri` must
    // return -4 before any write, so the caller's buffer is preserved.
    let mut out = [0x42u8; 8];
    // SAFETY: out is a valid 8-byte buffer; uri is null (the case under test).
    let rc = unsafe { shekyl_label_plaintext_for_payment_uri(std::ptr::null(), out.as_mut_ptr()) };
    assert_eq!(rc, -4);
    assert_eq!(out, [0x42; 8], "output untouched on -4 (null uri)");
}

#[test]
fn label_plaintext_for_payment_uri_no_rid_writes_sentinel() {
    use shekyl_crypto_pq::label::sentinel_plaintext;
    let mut out = [0u8; 8];
    let uri = std::ffi::CString::new("shekyl:addr1abc?amount=1").unwrap();
    // SAFETY: valid pointers.
    let rc = unsafe { shekyl_label_plaintext_for_payment_uri(uri.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert_eq!(out, sentinel_plaintext());
}

#[test]
fn label_plaintext_for_payment_uri_rid_echo() {
    use shekyl_crypto_pq::label::encode_request_plaintext;
    let rid = 0x1234_u64;
    let uri = std::ffi::CString::new(format!("shekyl:addr1abc?rid={rid}")).unwrap();
    let mut out = [0u8; 8];
    let rc = unsafe { shekyl_label_plaintext_for_payment_uri(uri.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert_eq!(out, encode_request_plaintext(rid).unwrap());
}

#[test]
fn label_plaintext_for_payment_uri_parse_fail_writes_sentinel() {
    use shekyl_crypto_pq::label::sentinel_plaintext;
    let uri = std::ffi::CString::new("shekyl:").unwrap();
    let mut out = [0u8; 8];
    let rc = unsafe { shekyl_label_plaintext_for_payment_uri(uri.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, -3);
    assert_eq!(out, sentinel_plaintext());
}

// ─── shekyl_block_reward — the boundary contract ────────────────────────────
//
// `block_reward_with_penalty`'s own tests cover the arithmetic. None of them
// can cover what this entry point ADDS: the status mapping, the out-pointer
// writes, and the null checks. Those only exist at the boundary, so they are
// tested at the boundary — the gap Copilot raised on PR #518.

/// The zone C++ passes in (`CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5`).
const ZONE: u64 = 300_000;
/// A value no computed reward can equal, so "untouched" is distinguishable
/// from "written with something plausible".
const SENTINEL: u64 = 0xDEAD_BEEF_DEAD_BEEF;

/// Baseline volume (M_r = 1): the M_r-neutral vector set below stays pinned
/// to the pre-FL-R12′ values through the composition change.
fn baseline_v() -> u64 {
    shekyl_economics::EconomicParams::default().tx_volume_baseline
}

#[test]
fn block_reward_ok_writes_both_out_params() {
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;
    // Below the effective median: no penalty, so the base subsidy is returned.
    let status = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            0,
            ZONE,
            baseline_v(),
            &raw mut reward,
            &raw mut limit,
        )
    };

    assert_eq!(status, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, shekyl_base_block_reward(0));
    assert_eq!(limit, 2 * ZONE, "the limit is the doubled EFFECTIVE median");
}

#[test]
fn block_reward_accepts_the_inclusive_limit_and_pays_zero() {
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;
    // Exactly 2 * median is ACCEPTED, earning zero — the boundary the C++
    // rejection message describes, which is why that message says "at most".
    let status = unsafe {
        shekyl_block_reward(
            0,
            2 * ZONE,
            0,
            ZONE,
            baseline_v(),
            &raw mut reward,
            &raw mut limit,
        )
    };

    assert_eq!(status, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, 0);
    assert_eq!(limit, 2 * ZONE);
}

#[test]
fn block_reward_too_big_writes_the_limit_and_leaves_the_reward_untouched() {
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;
    let status = unsafe {
        shekyl_block_reward(
            0,
            2 * ZONE + 1,
            0,
            ZONE,
            baseline_v(),
            &raw mut reward,
            &raw mut limit,
        )
    };

    assert_eq!(status, SHEKYL_BLOCK_REWARD_BLOCK_TOO_BIG);
    assert!(status > 0, "rejection is positive; misuse is negative");
    assert_eq!(
        reward, SENTINEL,
        "the reward must not be written on the reject path — C++ reads it \
         only after checking the status, and a partial write would be a trap \
         for any caller that does not"
    );
    assert_eq!(
        limit,
        2 * ZONE,
        "the limit IS written on the reject path — it is the whole reason the \
         out-param exists, so C++ can name the bound without recomputing the \
         clamp that produced it"
    );
}

#[test]
fn block_reward_null_out_pointers_return_invalid_without_writing() {
    // Each pointer null separately: a check that only covers the first
    // argument passes while the second is still dereferenced.
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;

    let status = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            0,
            ZONE,
            baseline_v(),
            std::ptr::null_mut(),
            &raw mut limit,
        )
    };
    assert_eq!(status, SHEKYL_BLOCK_REWARD_INVALID);
    assert!(
        status < 0,
        "caller misuse is negative; rejection is positive"
    );
    assert_eq!(
        limit, SENTINEL,
        "no write through the non-null pointer either"
    );

    let status = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            0,
            ZONE,
            baseline_v(),
            &raw mut reward,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, SHEKYL_BLOCK_REWARD_INVALID);
    assert_eq!(
        reward, SENTINEL,
        "no write through the non-null pointer either"
    );

    let status = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            0,
            ZONE,
            baseline_v(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, SHEKYL_BLOCK_REWARD_INVALID);
}

#[test]
fn block_reward_beyond_the_exact_domain_is_invalid_not_wrapped() {
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;
    // A median around 2^48 puts `base * multiplicand` past 128 bits. The
    // crate reports Overflow; the boundary maps it to INVALID and the block is
    // rejected. Before this was checked it panicked across the FFI.
    let m: u64 = 1 << 48;
    let status = unsafe {
        shekyl_block_reward(
            m,
            m + m / 2,
            0,
            ZONE,
            baseline_v(),
            &raw mut reward,
            &raw mut limit,
        )
    };

    assert_eq!(status, SHEKYL_BLOCK_REWARD_INVALID);
    assert_eq!(
        reward, SENTINEL,
        "no reward is written for an out-of-domain input"
    );
}

#[test]
fn block_reward_past_the_asymptote_pays_the_tail() {
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;
    // A past-asymptote accumulator is a legitimate perpetual-tail state,
    // not a clamp and not an error (FL-R16a).
    let status = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            u64::MAX,
            ZONE,
            baseline_v(),
            &raw mut reward,
            &raw mut limit,
        )
    };

    assert_eq!(status, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, shekyl_base_block_reward(u64::MAX));
}

/// The signed composition through the marshal, with M_r ≠ 1 (dormancy pins
/// the multiplier at 0.8) and both tail-boundary values — the only test that
/// would catch a marshal bug now that C++ computes nothing (FL-R12′).
#[test]
fn block_reward_marshals_the_signed_composition() {
    let p = shekyl_economics::EconomicParams::default();
    let s = p.money_supply;
    let tail = shekyl_economics::tail_subsidy_per_block(&p).unwrap();
    let mut reward = SENTINEL;
    let mut limit = SENTINEL;

    // Tail boundary under dormancy, no penalty: the floor pays TAIL whole
    // (the pre-implementation red was 480,000,000 — M_r on the floored base).
    let st = unsafe {
        shekyl_block_reward(
            0,
            ZONE / 2,
            s - tail + 1,
            ZONE,
            0,
            &raw mut reward,
            &raw mut limit,
        )
    };
    assert_eq!(st, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, tail);

    // Past the asymptote with x = 1/2: penalty AFTER the floor ⇒ TAIL·3/4
    // (the pre-implementation reds were an error arm and 360,000,000).
    let st = unsafe {
        shekyl_block_reward(
            ZONE,
            ZONE + ZONE / 2,
            s + tail,
            ZONE,
            0,
            &raw mut reward,
            &raw mut limit,
        )
    };
    assert_eq!(st, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, tail / 4 * 3);

    // Mid-curve dormancy: the paid quantity carries M_r.
    let st = unsafe {
        shekyl_block_reward(0, ZONE / 2, s / 2, ZONE, 0, &raw mut reward, &raw mut limit)
    };
    assert_eq!(st, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(
        reward,
        shekyl_economics::effective_emission(s / 2, 0, &p).unwrap()
    );
}

#[test]
fn advance_already_generated_passes_the_asymptote() {
    assert_eq!(shekyl_advance_already_generated(0, 100), 100);
    // FL-R12′: through the asymptote (perpetual tail keeps accruing);
    // the only saturation is the u64 rail, which keeps `remaining`
    // floored at zero rather than un-saturated by a wrap (FL-R14).
    let s = shekyl_economics::params::MONEY_SUPPLY;
    assert_eq!(shekyl_advance_already_generated(s, 1), s + 1);
    assert_eq!(
        shekyl_advance_already_generated(u64::MAX, u64::MAX),
        u64::MAX
    );
}

// ─── shekyl_corrected_fee_ladder / shekyl_fee_correction_quantized ──────────
//
// Same boundary rationale as `shekyl_block_reward` above: the crate tests
// own the ladder arithmetic (shekyl-economics `fee.rs`); what only exists
// here is the null check, the four out-writes, and the fact that the
// marshal reaches the crate function unchanged. Written under the
// no-test-exists-means-write-the-test rule: these exports crossed with the
// FL-R12′ bundle and had no boundary pin of their own.

#[test]
fn corrected_fee_ladder_null_out_returns_minus_one() {
    let st = unsafe {
        shekyl_corrected_fee_ladder(
            10_000_000_000,
            300_000,
            300_000,
            300_000,
            3_000,
            shekyl_economics::params::SCALE,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        st, -1,
        "caller misuse is negative, mirroring the reward FFI"
    );
}

#[test]
fn corrected_fee_ladder_marshals_the_heritage_vector() {
    // 10 SKL reward, Mnw = Mlw = zone, C_q = 1: the FL-R17 signed shape over
    // the heritage values — the same vector scaling_2021.cpp pins from the
    // C++ side, so a drift in either marshal direction fails one of the two.
    let mut fees = [SENTINEL; 4];
    let st = unsafe {
        shekyl_corrected_fee_ladder(
            10_000_000_000,
            300_000,
            300_000,
            300_000,
            3_000,
            shekyl_economics::params::SCALE,
            fees.as_mut_ptr(),
        )
    };
    assert_eq!(st, 0);
    assert_eq!(fees, [340, 1400, 1400, 67_000]);
}

#[test]
fn fee_correction_quantized_ffi_matches_the_crate() {
    let p = shekyl_economics::EconomicParams::default();
    let scale = shekyl_economics::params::SCALE;
    // A decisive surge state (M_r pinned at 1.3, no sigma/burn, no previous
    // value): C = 1.3 snaps up to the C_q = 2 step.
    let v = 2 * p.tx_volume_baseline;
    let got = shekyl_fee_correction_quantized(v, 0, 0, 0);
    assert_eq!(
        got,
        shekyl_economics::fee_correction_quantized(v, 0, 0, 0, &p)
    );
    assert_eq!(got, 2 * scale);
    // And the hysteresis argument is threaded, not dropped — asserted at a
    // probe where held and fresh DIFFER (v = baseline + 1 puts raw C just
    // past the 2^0 boundary, inside the 3% band): with the previous step it
    // holds, without it it snaps up. A probe where both paths agree could
    // not fail on a dropped argument.
    let boundary_v = p.tx_volume_baseline + 1;
    assert_eq!(
        shekyl_fee_correction_quantized(boundary_v, 0, 0, scale),
        scale
    );
    assert_eq!(
        shekyl_fee_correction_quantized(boundary_v, 0, 0, 0),
        2 * scale
    );
}
