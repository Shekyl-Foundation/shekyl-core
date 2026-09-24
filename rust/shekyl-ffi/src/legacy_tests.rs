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
    let m = shekyl_calc_release_multiplier(100, 1, 100, 800_000, 1_300_000);
    assert_eq!(m, 1_000_000);
}

// ---- PR-E1: reward-emission membership-only primitives ----
// (The per-auth hybrid gate FFI was retired: C-1 verifies auth via the coarse
// shekyl_emission_vin_verify, whose Rust body emission_vin_verify_auth pins the
// leaf-gate-first order and per-role domains — see emission_verify_kat.rs.)

/// The census `d-12` split crosses the FFI: a PQC key-scalar count that
/// disagrees with the key-image count returns 9 (`PqcKeyCountMismatch`)
/// from the pre-slicing check — the code the entry point advertises —
/// while a pseudo-out mismatch keeps the invalid-parameters code (1).
#[test]
fn full_verify_ffi_distinguishes_pqc_count_mismatch() {
    let root = [0u8; 32];
    let txh = [0u8; 32];
    let proof = [0u8; 8];
    let two = [1u8; 64];

    // 2 key images, 2 pseudo-outs, 1 PQC scalar: the d-12 discriminant.
    let r = unsafe {
        shekyl_fcmp_verify(
            proof.as_ptr(),
            proof.len(),
            two.as_ptr(),
            2,
            two.as_ptr(),
            2,
            two.as_ptr(),
            1,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 9, "PQC key count mismatch must surface as 9, not 1");

    // 2 key images, 1 pseudo-out, 2 PQC scalars: still invalid parameters.
    let r = unsafe {
        shekyl_fcmp_verify(
            proof.as_ptr(),
            proof.len(),
            two.as_ptr(),
            2,
            two.as_ptr(),
            1,
            two.as_ptr(),
            2,
            root.as_ptr(),
            1,
            txh.as_ptr(),
        )
    };
    assert_eq!(r, 1, "pseudo-out count mismatch keeps code 1");
}

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
        let ffi = shekyl_calc_burn_pct(txv, 1, base, circ, total, rate, cap);
        let direct = shekyl_economics::burn::calc_burn_pct(
            shekyl_economics::TxVolume::per_block(txv),
            base,
            circ,
            total,
            rate,
            cap,
        );
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
// parse_prove_witness (reader) agree byte-for-byte on all 9 header
// fields, using locked vectors from docs/test_vectors/WITNESS_HEADER.json.

#[cfg(feature = "multisig")]
#[derive(serde::Deserialize)]
struct WitnessHeaderVector {
    output_key: String,
    key_image_gen: String,
    commitment: String,
    pqc_leaf_commitment: String,
    pqc_leaf_blind: String,
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
            pqc_leaf_commitment: decode_32(&v.pqc_leaf_commitment, "pqc_leaf_commitment", i),
            pqc_leaf_blind: decode_32(&v.pqc_leaf_blind, "pqc_leaf_blind", i),
            spend_key_x: decode_32(&v.spend_key_x, "spend_key_x", i),
            spend_key_y: decode_32(&v.spend_key_y, "spend_key_y", i),
            commitment_mask: decode_32(&v.commitment_mask, "commitment_mask", i),
            pseudo_out_blind: decode_32(&v.pseudo_out_blind, "pseudo_out_blind", i),
        };

        // Build: typed struct → 288-byte blob (the multisig witness seam)
        let mut blob = vec![0u8; SHEKYL_PROVE_WITNESS_HEADER_BYTES];
        let ok = unsafe { shekyl_fcmp_build_witness_header(&raw const fields, blob.as_mut_ptr()) };
        assert!(
            ok,
            "vector {i}: shekyl_fcmp_build_witness_header returned false"
        );
        assert_eq!(blob.len(), 288, "vector {i}: blob not 288 bytes");

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
            fields.pqc_leaf_commitment.as_slice(),
            "vector {i}: CM mismatch in blob"
        );
        assert_eq!(
            &blob[128..160],
            fields.pqc_leaf_blind.as_slice(),
            "vector {i}: r mismatch in blob"
        );
        assert_eq!(
            &blob[160..192],
            fields.spend_key_x.as_slice(),
            "vector {i}: x mismatch in blob"
        );
        assert_eq!(
            &blob[192..224],
            fields.spend_key_y.as_slice(),
            "vector {i}: y mismatch in blob"
        );
        assert_eq!(
            &blob[224..256],
            fields.commitment_mask.as_slice(),
            "vector {i}: z mismatch in blob"
        );
        assert_eq!(
            &blob[256..288],
            fields.pseudo_out_blind.as_slice(),
            "vector {i}: a mismatch in blob"
        );

        // Parse: 288-byte blob → ProveInput (same path as the multisig prover).
        // parse_prove_witness expects a full witness (header + leaf + branch data).
        // We append a minimal valid trailer: 1 leaf entry + 0 branch layers.
        let mut witness = blob.clone();
        // leaf chunk_count = 1 (must have at least 1 to parse)
        witness.extend_from_slice(&1u32.to_le_bytes());
        // one leaf entry: 4 x 32 bytes (O, I, C, CM.x) — layout only here
        witness.extend_from_slice(&fields.output_key);
        witness.extend_from_slice(&fields.key_image_gen);
        witness.extend_from_slice(&fields.commitment);
        witness.extend_from_slice(&fields.pqc_leaf_commitment);
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
            pi.pqc_leaf_commitment, fields.pqc_leaf_commitment,
            "vector {i}: parsed CM mismatch"
        );
        assert_eq!(
            pi.pqc_leaf_blind, fields.pqc_leaf_blind,
            "vector {i}: parsed r mismatch"
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

// ─── shekyl_block_reward — the boundary contract ────────────────────────────
//
// `block_reward_with_penalty`'s own tests cover the arithmetic. None of them
// can cover what this entry point ADDS: the status mapping, the out-pointer
// writes, and the null checks. Those only exist at the boundary, so they are
// tested at the boundary — the gap Copilot raised on PR #518.

/// Penalty-free zone the block-reward vectors below are denominated in.
/// Generated from `block_weight_full_reward_zone_bytes`. `shekyl-wire`
/// reads the same key into `MIN_BLOCK_WEIGHT`; [`the_zone_readers_agree`]
/// fails if one generator reads a different key.
const ZONE: u64 = shekyl_economics::FULL_REWARD_ZONE;
#[test]
fn the_zone_readers_agree() {
    assert_eq!(
        shekyl_economics::EconomicParams::default().full_reward_zone,
        ZONE
    );
    assert_eq!(shekyl_wire::transaction::MIN_BLOCK_WEIGHT as u64, ZONE);
}
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
            baseline_v(),
            1,
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
    let s = p.emission_curve_asymptote;
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
            0,
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
            0,
            0,
            &raw mut reward,
            &raw mut limit,
        )
    };
    assert_eq!(st, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(reward, tail / 4 * 3);

    // Mid-curve dormancy: the paid quantity carries M_r.
    let st =
        unsafe { shekyl_block_reward(0, ZONE / 2, s / 2, 0, 0, &raw mut reward, &raw mut limit) };
    assert_eq!(st, SHEKYL_BLOCK_REWARD_OK);
    assert_eq!(
        reward,
        shekyl_economics::effective_emission(s / 2, shekyl_economics::TxVolume::ZERO, &p).unwrap()
    );
}

#[test]
fn advance_already_generated_passes_the_asymptote() {
    assert_eq!(shekyl_advance_already_generated(0, 100), 100);
    // FL-R12′: through the asymptote (perpetual tail keeps accruing);
    // the only saturation is the u64 rail, which keeps `remaining`
    // floored at zero rather than un-saturated by a wrap (FL-R14).
    let s = shekyl_economics::params::EMISSION_CURVE_ASYMPTOTE;
    assert_eq!(shekyl_advance_already_generated(s, 1), s + 1);
    assert_eq!(
        shekyl_advance_already_generated(u64::MAX, u64::MAX),
        u64::MAX
    );
}

#[test]
fn effective_block_weight_median_matches_the_crate() {
    let zone = 300_000u64;
    for st in [0, zone / 10, zone, zone * 2, zone * 100, u64::MAX] {
        assert_eq!(
            shekyl_effective_block_weight_median(zone, st),
            shekyl_economics::effective_median(zone, st),
            "st={st}"
        );
    }
    assert_eq!(
        shekyl_effective_block_weight_median(zone, zone * 100),
        4 * zone
    );
}

#[test]
fn long_term_block_weight_matches_the_crate() {
    let zone = 300_000u64;
    for w in [0, zone / 10, zone, zone * 2, 1_000_000, u64::MAX] {
        assert_eq!(
            shekyl_long_term_block_weight(zone, w),
            shekyl_economics::long_term_weight(zone, w),
            "w={w}"
        );
    }
    assert_eq!(shekyl_long_term_block_weight(zone, 100_000), 176_470);
    assert_eq!(shekyl_long_term_block_weight(zone, 1_000_000), 510_000);
}

// ─── shekyl_corrected_fee_ladder / shekyl_relay_fee_floor ────────────────────
//
// Crate tests own the arithmetic. These pin the marshal: null check, the
// out-writes, domain refusal, and that G/slack cross the ABI from the
// Rust owner.

#[test]
fn corrected_fee_ladder_null_out_returns_minus_one() {
    let st = unsafe {
        shekyl_corrected_fee_ladder(
            10_000_000_000,
            ZONE,
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
fn corrected_fee_ladder_refuses_out_of_domain_scalars() {
    let mut fees = [SENTINEL; 3];
    for (base, median, w, c) in [
        (u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        (u64::MAX, ZONE, 3_000, u64::MAX),
        (u64::MAX, ZONE, u64::MAX, 1_000_000),
        (1, u64::MAX, 3_000, 1_000_000),
        // Priority is `2·R·C` and does not carry `w_ref`: a zero `w_ref`
        // zeroes every other product, so a domain check written against a
        // `w_ref`-bearing product would miss this overflow.
        (u64::MAX, ZONE, 0, u64::MAX),
    ] {
        let st = unsafe { shekyl_corrected_fee_ladder(base, median, w, c, fees.as_mut_ptr()) };
        assert_eq!(
            st, -2,
            "out-of-domain scalars must be refused, not computed \
             (base={base}, median={median}, w={w}, c={c})"
        );
        assert_eq!(fees, [SENTINEL; 3], "a refused call must not write");
    }

    let st = unsafe {
        shekyl_corrected_fee_ladder(
            10_000_000_000,
            ZONE,
            3_000,
            shekyl_economics::params::SCALE,
            fees.as_mut_ptr(),
        )
    };
    assert_eq!(st, 0);
    assert_eq!(fees, [333, 1332, 66_666]);
}

#[test]
fn corrected_fee_ladder_marshals_the_heritage_vector() {
    let mut fees = [SENTINEL; 3];
    let st = unsafe {
        shekyl_corrected_fee_ladder(
            10_000_000_000,
            ZONE,
            3_000,
            shekyl_economics::params::SCALE,
            fees.as_mut_ptr(),
        )
    };
    assert_eq!(st, 0);
    assert_eq!(fees, [333, 1332, 66_666]);
}

#[test]
fn relay_constants_cross_the_abi_from_the_rust_owner() {
    assert_eq!(
        shekyl_relay_floor_lookback(),
        u64::try_from(shekyl_economics::RELAY_FLOOR_LOOKBACK).expect("G fits u64")
    );
    assert_eq!(
        shekyl_relay_admission_slack_bp(),
        shekyl_economics::RELAY_ADMISSION_SLACK_BP
    );
}

// --- the composed fee-burn / emission-split boundary (E6 slice 4 precursor) -----
//
// `compute_fee_burn` / `compute_emission_split` own their arithmetic and are
// tested in shekyl-economics. What only exists at THIS boundary: the supply
// derivation from the two store facts, the invariant status, the null
// check, and the out-pointer write.

/// The fee burn at the boundary equals the crate's composition over the
/// derived supply, for a non-trivial fee and a burned total below emission.
#[test]
fn compute_fee_burn_ffi_derives_the_supply_and_matches_the_crate() {
    use shekyl_economics::{
        compute_fee_burn, CirculatingSupply, EconomicParams, FrozenSegmentCount, TxVolume,
    };
    use shekyl_units::AtomicUnits;
    let p = EconomicParams::default();
    let (fees, sum, blocks, generated, burned, n) = (
        1_000_000_000u64,
        29_160u64,
        720u64,
        p.emission_curve_asymptote / 2,
        1_000_000u64,
        3u64,
    );
    let mut out = ShekylBurnSplit {
        miner_fee_income: 0xDEAD,
        staker_pool_amount: 0xDEAD,
        actually_destroyed: 0xDEAD,
    };
    let st =
        unsafe { shekyl_compute_fee_burn(fees, sum, blocks, generated, burned, n, &raw mut out) };
    assert_eq!(st, SHEKYL_ECONOMICS_OK);
    let supply = CirculatingSupply::derive(
        AtomicUnits::from_raw(generated),
        AtomicUnits::from_raw(burned),
    )
    .expect("burned < generated");
    let want = compute_fee_burn(
        fees,
        TxVolume::window(sum, blocks),
        supply,
        FrozenSegmentCount::new(n),
        &p,
    );
    assert_eq!(out.miner_fee_income, want.miner_fee_income);
    assert_eq!(out.staker_pool_amount, want.staker_pool_amount);
    assert_eq!(out.actually_destroyed, want.actually_destroyed);
}

/// `total_burned > coins_generated` is a store-invariant violation: the
/// status says so and NOTHING is written — the caller halts rather than
/// proceeding on a zero that `calc_burn_pct` would read as "nothing
/// emitted" (FL-R16c; supply.rs module docs).
#[test]
fn compute_fee_burn_ffi_refuses_a_supply_underflow_and_writes_nothing() {
    let mut out = ShekylBurnSplit {
        miner_fee_income: 0xDEAD,
        staker_pool_amount: 0xDEAD,
        actually_destroyed: 0xDEAD,
    };
    let st = unsafe { shekyl_compute_fee_burn(1_000, 1, 1, 100, 101, 0, &raw mut out) };
    assert_eq!(st, SHEKYL_ECONOMICS_SUPPLY_INVARIANT);
    assert_eq!(out.miner_fee_income, 0xDEAD, "untouched");
    let mut pct = 0xDEADu64;
    let st = unsafe { shekyl_calc_burn_pct_at(1, 1, 100, 101, &raw mut pct) };
    assert_eq!(st, SHEKYL_ECONOMICS_SUPPLY_INVARIANT);
    assert_eq!(pct, 0xDEAD, "untouched");
}

#[test]
fn fee_burn_ffi_null_out_is_refused() {
    let st = unsafe { shekyl_compute_fee_burn(1, 1, 1, 10, 0, 0, std::ptr::null_mut()) };
    assert_eq!(st, SHEKYL_ECONOMICS_NULL_OUT);
    let st = unsafe { shekyl_calc_burn_pct_at(1, 1, 10, 0, std::ptr::null_mut()) };
    assert_eq!(st, SHEKYL_ECONOMICS_NULL_OUT);
}

/// The percentage at the boundary equals the crate's over the derived supply.
#[test]
fn calc_burn_pct_at_ffi_matches_the_crate() {
    use shekyl_economics::{calc_burn_pct_at, CirculatingSupply, EconomicParams, TxVolume};
    use shekyl_units::AtomicUnits;
    let p = EconomicParams::default();
    let (generated, burned) = (p.emission_curve_asymptote / 3, 5_000_000u64);
    let mut pct = 0u64;
    let st = unsafe { shekyl_calc_burn_pct_at(29_160, 720, generated, burned, &raw mut pct) };
    assert_eq!(st, SHEKYL_ECONOMICS_OK);
    let supply = CirculatingSupply::derive(
        AtomicUnits::from_raw(generated),
        AtomicUnits::from_raw(burned),
    )
    .expect("burned < generated");
    assert_eq!(
        pct,
        calc_burn_pct_at(TxVolume::window(29_160, 720), supply, &p)
    );
}

/// The emission split at the boundary is the crate's, including the zero arm.
#[test]
fn compute_emission_split_ffi_matches_the_crate() {
    for (emission, height) in [
        (0u64, 5u64),
        (1_638_400_000_000, 1),
        (1_000_000_000, 3_000_000),
    ] {
        let ffi = shekyl_compute_emission_split(emission, height, 1);
        let want = shekyl_economics::compute_emission_split(emission, height, 1);
        assert_eq!(ffi.miner_emission, want.miner_emission);
        assert_eq!(ffi.staker_emission, want.staker_emission);
    }
}
