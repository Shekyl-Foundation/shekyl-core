use shekyl_fcmp::proof::{self, ProveInput};
use shekyl_fcmp::PqcLeafScalar;

use dalek_ff_group::{EdwardsPoint, FieldElement};
use curve25519_dalek::Scalar;

use ciphersuite::Ciphersuite;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::group::ff::PrimeField;
use ec_divisors::DivisorCurve;
use multiexp::multiexp_vartime;
use shekyl_generators::SELENE_HASH_INIT;
use shekyl_fcmp_plus_plus::SELENE_FCMP_GENERATORS;
use helioselene::Selene;

use rand_core::{OsRng, RngCore};

fn random_selene_scalar() -> FieldElement {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    FieldElement::wide_reduce(bytes)
}

fn build_test_case(iteration: u32) {
    let tree_depth: u8 = 1;
    let signable_tx_hash = {
        let mut h = [0u8; 32];
        h[0] = (iteration & 0xFF) as u8;
        h[1] = ((iteration >> 8) & 0xFF) as u8;
        h[31] = 0xAB;
        h
    };

    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);
    let z = Scalar::random(&mut OsRng);
    let a = Scalar::random(&mut OsRng);

    let t_point = EdwardsPoint(*shekyl_generators::T);
    let o_point = (EdwardsPoint::generator() * x) + (t_point * y);

    let i_point = EdwardsPoint::random(&mut OsRng);
    let c_point = EdwardsPoint::random(&mut OsRng);

    let key_image = i_point * x;

    let h_pqc_field: <Selene as Ciphersuite>::F = random_selene_scalar();
    let h_pqc_bytes: [u8; 32] = h_pqc_field.to_repr().into();

    let generators = SELENE_FCMP_GENERATORS.generators.g_bold_slice();
    let tree_root_point: <Selene as Ciphersuite>::G = *SELENE_HASH_INIT
        + multiexp_vartime(&[
            (<EdwardsPoint as DivisorCurve>::to_xy(o_point).unwrap().0, generators[0]),
            (<EdwardsPoint as DivisorCurve>::to_xy(i_point).unwrap().0, generators[1]),
            (<EdwardsPoint as DivisorCurve>::to_xy(c_point).unwrap().0, generators[2]),
            (h_pqc_field, generators[3]),
        ]);
    let tree_root: [u8; 32] = tree_root_point.to_bytes().into();

    let o_bytes: [u8; 32] = o_point.to_bytes().into();
    let i_bytes: [u8; 32] = i_point.to_bytes().into();
    let c_bytes: [u8; 32] = c_point.to_bytes().into();

    let input = ProveInput {
        output_key: o_bytes,
        key_image_gen: i_bytes,
        commitment: c_bytes,
        h_pqc: PqcLeafScalar(h_pqc_bytes),
        spend_key_x: x.to_bytes(),
        spend_key_y: y.to_bytes(),
        commitment_mask: z.to_bytes(),
        pseudo_out_blind: a.to_bytes(),
        leaf_chunk_outputs: vec![(o_bytes, i_bytes, c_bytes)],
        leaf_chunk_h_pqc: vec![h_pqc_bytes],
        c1_branch_layers: vec![],
        c2_branch_layers: vec![],
    };

    let result = proof::prove(&[input], &tree_root, tree_depth, signable_tx_hash)
        .unwrap_or_else(|e| panic!("iteration {iteration}: prove failed: {e}"));

    assert!(!result.proof.data.is_empty(), "iteration {iteration}: proof data is empty");
    assert_eq!(result.pseudo_outs.len(), 1, "iteration {iteration}: expected 1 pseudo-out");

    let ki_bytes: [u8; 32] = key_image.to_bytes().into();
    let verify_ok = proof::verify(
        &result.proof,
        &[ki_bytes],
        &result.pseudo_outs,
        &[PqcLeafScalar(h_pqc_bytes)],
        &tree_root,
        tree_depth,
        signable_tx_hash,
    )
    .unwrap_or_else(|e| panic!("iteration {iteration}: verify error: {e}"));

    assert!(verify_ok, "iteration {iteration}: valid proof must verify");
    eprintln!("  [signing_round_trip] iteration {iteration}: prove+verify OK");
}

#[test]
fn signing_round_trip_100_iterations() {
    for i in 0..100 {
        build_test_case(i);
    }
}
