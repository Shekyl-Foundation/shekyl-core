use shekyl_fcmp::proof::{self, PqcLeafScalar, ShekylFcmpProof};
use shekyl_tx_builder::types::{LeafEntry, OutputInfo, SpendInput, TreeContext};
use shekyl_tx_builder::sign::sign_transaction;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::EdwardsPoint;

use rand_core::OsRng;

fn random_scalar() -> Scalar {
    Scalar::random(&mut OsRng)
}

fn build_test_case(iteration: u32) {
    use ciphersuite::{Ciphersuite, group::GroupEncoding};
    use ec_divisors::DivisorCurve;
    use multiexp::multiexp_vartime;
    use shekyl_generators::{SELENE_HASH_INIT, SELENE_FCMP_GENERATORS};

    type Selene = ciphersuite::Selene;

    let tree_depth: u8 = 1;
    let tx_prefix_hash = {
        let mut h = [0u8; 32];
        h[0] = (iteration & 0xFF) as u8;
        h[1] = ((iteration >> 8) & 0xFF) as u8;
        h[31] = 0xAB;
        h
    };

    let x = random_scalar();
    let y = random_scalar();
    let z = random_scalar(); // commitment mask for input
    let amount: u64 = 1_000_000 + (iteration as u64 * 100);
    let fee: u64 = 10_000;

    let b = random_scalar(); // spend secret key
    let ho = x - b; // ho = x - b, so x = ho + b

    let T = shekyl_generators::T();
    let O = (EdwardsPoint::mul_base(&x)) + (EdwardsPoint::from(*T) * y);
    let O_bytes = O.compress().to_bytes();

    let I = shekyl_generators::biased_hash_to_point(O_bytes);
    let I_bytes = I.compress().to_bytes();

    // Key image: L = I * x
    let L = I * x;
    let L_bytes = L.compress().to_bytes();

    // Commitment: C = z*G + amount*H
    use shekyl_primitives::Commitment;
    let commitment = Commitment::new(z, amount);
    let C = commitment.calculate().mul_by_cofactor();
    let C_bytes = C.compress().to_bytes();

    // PQC leaf scalar
    let h_pqc_field = <Selene as Ciphersuite>::F::random(&mut OsRng);
    let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr().into();

    // Compute tree root: single-leaf Selene Pedersen commitment
    let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
    let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
        + multiexp_vartime(&[
            (<EdwardsPoint as DivisorCurve>::to_xy(O).unwrap().0, generators[0]),
            (<EdwardsPoint as DivisorCurve>::to_xy(I).unwrap().0, generators[1]),
            (<EdwardsPoint as DivisorCurve>::to_xy(
                // Use the pre-cofactor commitment for the leaf
                commitment.calculate(),
            ).unwrap().0, generators[2]),
            (h_pqc_field, generators[3]),
        ]);
    let tree_root: [u8; 32] = tree_root_point.to_bytes().into();

    let reference_block = [0xBBu8; 32];

    // Build output info (single output = input - fee)
    let out_amount = amount - fee;
    let out_mask = random_scalar();
    let out_mask_bytes = out_mask.to_bytes();
    let out_enc_amount = [0u8; 9]; // placeholder encrypted amount

    // Output destination key (random for test)
    let out_dest_scalar = random_scalar();
    let out_dest = EdwardsPoint::mul_base(&out_dest_scalar);
    let out_dest_bytes = out_dest.compress().to_bytes();

    let combined_ss = {
        let mut ss = vec![0u8; 64];
        let r = random_scalar();
        ss[..32].copy_from_slice(&r.to_bytes());
        let r2 = random_scalar();
        ss[32..].copy_from_slice(&r2.to_bytes());
        ss
    };

    let leaf_entry = LeafEntry {
        output_key: O_bytes,
        key_image_gen: I_bytes,
        commitment: C_bytes,
        h_pqc: h_pqc_bytes,
    };

    let spend_input = SpendInput {
        output_key: O_bytes,
        commitment: C_bytes,
        amount,
        spend_key_x: x.to_bytes(),
        spend_key_y: y.to_bytes(),
        commitment_mask: z.to_bytes(),
        h_pqc: h_pqc_bytes,
        combined_ss,
        output_index: 0,
        leaf_chunk: vec![leaf_entry],
        c1_layers: vec![vec![]], // depth 1: one c1 layer with no siblings
        c2_layers: vec![],
    };

    let output_info = OutputInfo {
        dest_key: out_dest_bytes,
        amount: out_amount,
        commitment_mask: out_mask_bytes,
        enc_amount: out_enc_amount,
    };

    let tree_ctx = TreeContext {
        reference_block,
        tree_root,
        tree_depth,
    };

    let result = sign_transaction(tx_prefix_hash, &[spend_input], &[output_info], fee, &tree_ctx);

    match result {
        Ok(signed) => {
            assert!(!signed.fcmp_proof.is_empty(), "iteration {iteration}: FCMP proof is empty");
            assert!(!signed.bulletproof_plus.is_empty(), "iteration {iteration}: BP+ proof is empty");
            assert_eq!(signed.pseudo_outs.len(), 1, "iteration {iteration}: expected 1 pseudo-output");
            assert_eq!(signed.commitments.len(), 1, "iteration {iteration}: expected 1 commitment");

            let fcmp_proof = ShekylFcmpProof::from_bytes(&signed.fcmp_proof)
                .unwrap_or_else(|e| panic!("iteration {iteration}: failed to parse FCMP proof: {e}"));

            let verify_ok = proof::verify(
                &fcmp_proof,
                &[L_bytes],
                &signed.pseudo_outs,
                &[PqcLeafScalar(h_pqc_bytes)],
                &tree_root,
                tree_depth,
                tx_prefix_hash,
            );

            match verify_ok {
                Ok(true) => {} // success
                Ok(false) => panic!("iteration {iteration}: FCMP verify returned false"),
                Err(e) => panic!("iteration {iteration}: FCMP verify error: {e}"),
            }

            eprintln!("  [signing_round_trip] iteration {iteration}: prove+verify OK");
        }
        Err(e) => {
            panic!("iteration {iteration}: sign_transaction failed: {e}");
        }
    }
}

#[test]
fn signing_round_trip_100_iterations() {
    for i in 0..100 {
        build_test_case(i);
    }
}
