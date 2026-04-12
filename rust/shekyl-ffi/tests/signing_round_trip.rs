//! FFI integration test: construct output -> scan -> build tree -> sign -> verify.
//!
//! Exercises the full `shekyl_sign_fcmp_transaction` -> `shekyl_fcmp_verify` cycle
//! through C-ABI FFI calls, following the same pattern as `cache_ffi_round_trip.rs`.

use shekyl_ffi::{
    shekyl_buffer_free, shekyl_construct_curve_tree_leaf, shekyl_construct_output,
    shekyl_curve_tree_hash_grow_selene, shekyl_fcmp_verify, shekyl_kem_keypair_generate,
    shekyl_output_data_free, shekyl_scan_and_recover, shekyl_sign_fcmp_transaction,
    ShekylBuffer, ShekylOutputData,
};

use ciphersuite::group::GroupEncoding;
use curve25519_dalek::Scalar;
use rand_core::OsRng;
use shekyl_generators::SELENE_HASH_INIT;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct WalletKeys {
    spend_secret: [u8; 32],
    spend_public: [u8; 32],
    x25519_pk: [u8; 32],
    x25519_sk: [u8; 32],
    ml_kem_ek: Vec<u8>,
    ml_kem_dk: Vec<u8>,
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.spend_secret.zeroize();
        self.x25519_sk.zeroize();
        self.ml_kem_dk.zeroize();
    }
}

fn generate_wallet_keys() -> WalletKeys {
    let b = Scalar::random(&mut OsRng);
    let big_b =
        (curve25519_dalek::constants::ED25519_BASEPOINT_POINT * b)
            .compress()
            .to_bytes();

    let kem = shekyl_kem_keypair_generate();
    assert!(kem.success, "KEM keypair generation failed");

    let pk_bytes =
        unsafe { std::slice::from_raw_parts(kem.public_key.ptr, kem.public_key.len) }.to_vec();
    let sk_bytes =
        unsafe { std::slice::from_raw_parts(kem.secret_key.ptr, kem.secret_key.len) }.to_vec();

    assert_eq!(
        pk_bytes.len(),
        1216,
        "KEM pk: expected x25519(32) + ml_kem_ek(1184) = 1216, got {}",
        pk_bytes.len()
    );
    assert_eq!(
        sk_bytes.len(),
        2432,
        "KEM sk: expected x25519(32) + ml_kem_dk(2400) = 2432, got {}",
        sk_bytes.len()
    );

    let mut x25519_pk = [0u8; 32];
    x25519_pk.copy_from_slice(&pk_bytes[..32]);
    let ml_kem_ek = pk_bytes[32..].to_vec();

    let mut x25519_sk = [0u8; 32];
    x25519_sk.copy_from_slice(&sk_bytes[..32]);
    let ml_kem_dk = sk_bytes[32..].to_vec();

    shekyl_buffer_free(kem.public_key.ptr, kem.public_key.len);
    shekyl_buffer_free(kem.secret_key.ptr, kem.secret_key.len);

    WalletKeys {
        spend_secret: b.to_bytes(),
        spend_public: big_b,
        x25519_pk,
        x25519_sk,
        ml_kem_ek,
        ml_kem_dk,
    }
}

#[allow(dead_code)]
struct ConstructedOutput {
    output_key: [u8; 32],
    commitment: [u8; 32],
    enc_amount: [u8; 8],
    amount_tag: u8,
    view_tag: u8,
    kem_ct_x25519: [u8; 32],
    kem_ct_ml_kem: Vec<u8>,
    h_pqc: [u8; 32],
    y: [u8; 32],
    z: [u8; 32],
}

fn construct_output_ffi(
    tx_secret: &[u8; 32],
    recipient: &WalletKeys,
    amount: u64,
    output_index: u64,
) -> ConstructedOutput {
    let mut data: ShekylOutputData = unsafe {
        shekyl_construct_output(
            tx_secret.as_ptr(),
            recipient.x25519_pk.as_ptr(),
            recipient.ml_kem_ek.as_ptr(),
            recipient.ml_kem_ek.len(),
            recipient.spend_public.as_ptr(),
            amount,
            output_index,
        )
    };
    assert!(data.success, "shekyl_construct_output failed");

    let kem_ct_ml_kem =
        unsafe { std::slice::from_raw_parts(data.kem_ciphertext_ml_kem.ptr, data.kem_ciphertext_ml_kem.len) }
            .to_vec();

    let result = ConstructedOutput {
        output_key: data.output_key,
        commitment: data.commitment,
        enc_amount: data.enc_amount,
        amount_tag: data.amount_tag,
        view_tag: data.view_tag_x25519,
        kem_ct_x25519: data.kem_ciphertext_x25519,
        kem_ct_ml_kem,
        h_pqc: data.h_pqc,
        y: data.y,
        z: data.z,
    };

    unsafe { shekyl_output_data_free(&mut data) };
    result
}

#[allow(dead_code)]
struct ScannedSecrets {
    ho: [u8; 32],
    y: [u8; 32],
    z: [u8; 32],
    amount: u64,
    key_image: [u8; 32],
    combined_ss: [u8; 64],
    h_pqc: [u8; 32],
    pqc_pk: Vec<u8>,
    pqc_sk: Vec<u8>,
}

impl Drop for ScannedSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.ho.zeroize();
        self.combined_ss.zeroize();
        self.pqc_sk.zeroize();
    }
}

fn scan_output_ffi(
    wallet: &WalletKeys,
    out: &ConstructedOutput,
    output_index: u64,
) -> ScannedSecrets {
    let hp_point = shekyl_generators::biased_hash_to_point(out.output_key);
    let hp_of_o: [u8; 32] = hp_point.compress().to_bytes();

    let mut ho = [0u8; 32];
    let mut y = [0u8; 32];
    let mut z = [0u8; 32];
    let mut k_amount = [0u8; 32];
    let mut amount: u64 = 0;
    let mut recovered_spend_key = [0u8; 32];
    let mut key_image = [0u8; 32];
    let mut combined_ss = [0u8; 64];
    let mut pqc_pk_buf = ShekylBuffer { ptr: std::ptr::null_mut(), len: 0 };
    let mut pqc_sk_buf = ShekylBuffer { ptr: std::ptr::null_mut(), len: 0 };
    let mut h_pqc = [0u8; 32];

    let ok = unsafe {
        shekyl_scan_and_recover(
            wallet.x25519_sk.as_ptr(),
            wallet.ml_kem_dk.as_ptr(),
            wallet.ml_kem_dk.len(),
            out.kem_ct_x25519.as_ptr(),
            out.kem_ct_ml_kem.as_ptr(),
            out.kem_ct_ml_kem.len(),
            out.output_key.as_ptr(),
            out.commitment.as_ptr(),
            out.enc_amount.as_ptr(),
            out.amount_tag,
            out.view_tag,
            output_index,
            wallet.spend_secret.as_ptr(),
            hp_of_o.as_ptr(),
            true,
            ho.as_mut_ptr(),
            y.as_mut_ptr(),
            z.as_mut_ptr(),
            k_amount.as_mut_ptr(),
            &mut amount,
            recovered_spend_key.as_mut_ptr(),
            key_image.as_mut_ptr(),
            combined_ss.as_mut_ptr(),
            &mut pqc_pk_buf,
            &mut pqc_sk_buf,
            &mut h_pqc,
        )
    };
    assert!(ok, "shekyl_scan_and_recover failed");

    let pqc_pk =
        unsafe { std::slice::from_raw_parts(pqc_pk_buf.ptr, pqc_pk_buf.len) }.to_vec();
    let pqc_sk =
        unsafe { std::slice::from_raw_parts(pqc_sk_buf.ptr, pqc_sk_buf.len) }.to_vec();
    shekyl_buffer_free(pqc_pk_buf.ptr, pqc_pk_buf.len);
    shekyl_buffer_free(pqc_sk_buf.ptr, pqc_sk_buf.len);

    ScannedSecrets {
        ho,
        y,
        z,
        amount,
        key_image,
        combined_ss,
        h_pqc,
        pqc_pk,
        pqc_sk,
    }
}

fn build_leaf_and_root(
    output_key: &[u8; 32],
    commitment: &[u8; 32],
    h_pqc: &[u8; 32],
) -> ([u8; 128], [u8; 32]) {
    let mut leaf = [0u8; 128];
    let ok = shekyl_construct_curve_tree_leaf(
        output_key.as_ptr(),
        commitment.as_ptr(),
        h_pqc.as_ptr(),
        leaf.as_mut_ptr(),
    );
    assert!(ok, "shekyl_construct_curve_tree_leaf failed");

    // tree_depth=1: the root IS the Selene hash of the single leaf chunk.
    // No branch layers above it (c1=0, c2=0).
    let init_bytes: [u8; 32] = SELENE_HASH_INIT.to_bytes().into();
    let zero_scalar = [0u8; 32];
    let mut root = [0u8; 32];
    let ok = shekyl_curve_tree_hash_grow_selene(
        init_bytes.as_ptr(),
        0,
        zero_scalar.as_ptr(),
        leaf.as_ptr(),
        4,
        root.as_mut_ptr(),
    );
    assert!(ok, "shekyl_curve_tree_hash_grow_selene failed");

    (leaf, root)
}

fn build_test_case(iteration: u32) {
    eprintln!("  [signing_round_trip] iteration {iteration}: setting up keys...");

    let wallet = generate_wallet_keys();

    let mut tx_secret = [0u8; 32];
    tx_secret[0] = (iteration & 0xFF) as u8;
    tx_secret[1] = ((iteration >> 8) & 0xFF) as u8;
    tx_secret[31] = 0xFE;
    let tx_secret_scalar = Scalar::from_bytes_mod_order(tx_secret);
    let tx_secret_bytes = tx_secret_scalar.to_bytes();

    let input_amount: u64 = 1_000_000_000; // 1 SHEKYL
    let fee: u64 = 1_000_000;
    let output_amount: u64 = input_amount - fee;
    let input_output_index: u64 = 0;

    eprintln!("  [signing_round_trip] iteration {iteration}: constructing input output...");
    let input_out = construct_output_ffi(&tx_secret_bytes, &wallet, input_amount, input_output_index);

    eprintln!("  [signing_round_trip] iteration {iteration}: scanning input output...");
    let scanned = scan_output_ffi(&wallet, &input_out, input_output_index);
    assert_eq!(
        scanned.amount, input_amount,
        "iteration {iteration}: scanned amount mismatch"
    );

    eprintln!("  [signing_round_trip] iteration {iteration}: building curve tree...");
    let (_leaf, tree_root) =
        build_leaf_and_root(&input_out.output_key, &input_out.commitment, &scanned.h_pqc);

    let hp_of_o_point = shekyl_generators::biased_hash_to_point(input_out.output_key);
    let hp_of_o: [u8; 32] = hp_of_o_point.compress().to_bytes();

    eprintln!("  [signing_round_trip] iteration {iteration}: constructing change output...");
    let change_wallet = generate_wallet_keys();
    let mut change_tx_secret = [0u8; 32];
    change_tx_secret[0] = 0x42;
    change_tx_secret[31] = 0x01;
    let change_tx_scalar = Scalar::from_bytes_mod_order(change_tx_secret);
    let change_out = construct_output_ffi(
        &change_tx_scalar.to_bytes(),
        &change_wallet,
        output_amount,
        0,
    );

    let leaf_entry_json = serde_json::json!({
        "output_key": hex_encode(&input_out.output_key),
        "key_image_gen": hex_encode(&hp_of_o),
        "commitment": hex_encode(&input_out.commitment),
        "h_pqc": hex_encode(&scanned.h_pqc),
    });

    let inputs_json = serde_json::json!([{
        "ki": hex_encode(&scanned.key_image),
        "combined_ss": hex_encode(&scanned.combined_ss),
        "output_index": input_output_index,
        "hp_of_O": hex_encode(&scanned.h_pqc),
        "amount": input_amount,
        "commitment_mask": hex_encode(&scanned.z),
        "commitment": hex_encode(&input_out.commitment),
        "output_key": hex_encode(&input_out.output_key),
        "h_pqc": hex_encode(&scanned.h_pqc),
        "leaf_chunk": [leaf_entry_json],
        "c1_layers": [],
        "c2_layers": [],
    }]);

    let mut enc_amount_9 = [0u8; 9];
    enc_amount_9[..8].copy_from_slice(&change_out.enc_amount);
    enc_amount_9[8] = change_out.amount_tag;

    let outputs_json = serde_json::json!([{
        "dest_key": hex_encode(&change_out.output_key),
        "amount": output_amount,
        "commitment_mask": hex_encode(&change_out.z),
        "enc_amount": hex_encode(&enc_amount_9),
    }]);

    let inputs_bytes = serde_json::to_vec(&inputs_json).unwrap();
    let outputs_bytes = serde_json::to_vec(&outputs_json).unwrap();

    let mut tx_prefix_hash = [0u8; 32];
    tx_prefix_hash[0] = 0xAA;
    tx_prefix_hash[1] = (iteration & 0xFF) as u8;
    tx_prefix_hash[31] = 0xBB;

    let mut reference_block = [0u8; 32];
    reference_block[0] = 0xCC;
    reference_block[31] = 0xDD;

    let tree_depth: u8 = 1;

    eprintln!("  [signing_round_trip] iteration {iteration}: calling shekyl_sign_fcmp_transaction...");
    eprintln!("    inputs_json ({} bytes): {}", inputs_bytes.len(), std::str::from_utf8(&inputs_bytes).unwrap_or("<invalid utf8>"));
    eprintln!("    outputs_json ({} bytes): {}", outputs_bytes.len(), std::str::from_utf8(&outputs_bytes).unwrap_or("<invalid utf8>"));

    let result = shekyl_sign_fcmp_transaction(
        wallet.spend_secret.as_ptr(),
        tx_prefix_hash.as_ptr(),
        inputs_bytes.as_ptr(),
        inputs_bytes.len(),
        outputs_bytes.as_ptr(),
        outputs_bytes.len(),
        fee,
        reference_block.as_ptr(),
        tree_root.as_ptr(),
        tree_depth,
    );

    if !result.success {
        let err_msg = if !result.error_message.ptr.is_null() && result.error_message.len > 0 {
            let s = unsafe {
                std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                    result.error_message.ptr,
                    result.error_message.len,
                ))
            };
            s.to_string()
        } else {
            "(no message)".to_string()
        };
        shekyl_buffer_free(result.error_message.ptr, result.error_message.len);
        shekyl_buffer_free(result.proofs_json.ptr, result.proofs_json.len);
        panic!(
            "iteration {iteration}: shekyl_sign_fcmp_transaction failed (code={}): {err_msg}",
            result.error_code
        );
    }

    assert!(
        !result.proofs_json.ptr.is_null() && result.proofs_json.len > 0,
        "iteration {iteration}: proofs_json is empty on success"
    );

    let proofs_json_str = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(
            result.proofs_json.ptr,
            result.proofs_json.len,
        ))
        .expect("proofs_json is not valid UTF-8")
    };
    eprintln!(
        "  [signing_round_trip] iteration {iteration}: sign succeeded, proofs_json len={}",
        result.proofs_json.len
    );

    let proofs_val: serde_json::Value =
        serde_json::from_str(proofs_json_str).expect("proofs_json is not valid JSON");

    let fcmp_proof_hex = proofs_val["fcmp_proof"]
        .as_str()
        .expect("missing fcmp_proof field");
    let fcmp_proof = hex_decode(fcmp_proof_hex);

    let pseudo_outs_arr = proofs_val["pseudo_outs"]
        .as_array()
        .expect("missing pseudo_outs field");
    assert_eq!(
        pseudo_outs_arr.len(),
        1,
        "iteration {iteration}: expected 1 pseudo-out"
    );
    let pseudo_out = hex_decode(pseudo_outs_arr[0].as_str().unwrap());
    assert_eq!(pseudo_out.len(), 32);

    shekyl_buffer_free(result.proofs_json.ptr, result.proofs_json.len);
    shekyl_buffer_free(result.error_message.ptr, result.error_message.len);

    eprintln!("  [signing_round_trip] iteration {iteration}: verifying proof...");

    let verified = shekyl_fcmp_verify(
        fcmp_proof.as_ptr(),
        fcmp_proof.len(),
        scanned.key_image.as_ptr(),
        1,
        pseudo_out.as_ptr(),
        1,
        scanned.h_pqc.as_ptr(),
        1,
        tree_root.as_ptr(),
        tree_depth,
        tx_prefix_hash.as_ptr(),
    );
    assert!(
        verified,
        "iteration {iteration}: shekyl_fcmp_verify returned false for a valid proof"
    );

    eprintln!("  [signing_round_trip] iteration {iteration}: sign+verify OK");
}

#[test]
fn signing_ffi_round_trip_10_iterations() {
    for i in 0..10 {
        build_test_case(i);
    }
}
