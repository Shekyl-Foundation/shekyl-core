use rand_core::OsRng;

use transcript::{RecommendedTranscript, Transcript};

use ciphersuite::group::Group;
use dalek_ff_group::{EdwardsPoint, Scalar};
use multiexp::BatchVerifier;

use modular_frost::tests::{algorithm_machines, key_gen, sign};

use crate::{
    sal::{multisig::*, *},
    Output,
};

#[test]
fn test_sal_multisig() {
    let x = Scalar::random(&mut OsRng);

    let mut keys = key_gen::<_, Ed25519T>(&mut OsRng);

    let O = (EdwardsPoint::generator() * x) + keys.values().next().unwrap().group_key();
    let I = EdwardsPoint::random(&mut OsRng);
    let C = EdwardsPoint::random(&mut OsRng);

    let L = I * x;

    let rerandomized_output = RerandomizedOutput::new(&mut OsRng, Output::new(O, I, C).unwrap());
    let input = rerandomized_output.input();

    let algorithm = SalAlgorithm::new(
        OsRng,
        RecommendedTranscript::new(b"SpendAuthAndLinkability Multisig Test"),
        shekyl_types::TxSignableHash::from_bytes([0; 32]),
        rerandomized_output.clone(),
        x,
    );

    for keys in keys.values_mut() {
        let new_keys = keys.clone().offset(-rerandomized_output.o_blind());
        *keys = new_keys;
    }

    let sig = sign(
        &mut OsRng,
        &algorithm,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algorithm, &keys),
        &[],
    );

    let mut verifier = BatchVerifier::new(1);
    sig.verify(
        &mut OsRng,
        &mut verifier,
        shekyl_types::TxSignableHash::from_bytes([0; 32]),
        &input,
        L,
    );
    assert!(verifier.verify_vartime());
}

/// `CHAIN_FORGE.md` `CF-R12`, condition (a) on the SAL multisig site (G3):
/// `sign_share` derives α, β, δ, μ, r_z, r_p and r_r_p from the
/// transcript's `deterministic_nonces` stream, and the threshold secret
/// `y`'s nonce must never come from it. Two algorithms built from the same
/// inputs hold the same transcript, so they derive the same stream. Signing
/// a share on each with the same view and nonce sums and different FROST
/// nonces must then give shares that differ by exactly the nonce
/// difference: the share is `e·y_i + r_y`, `r_y` the FROST nonce. Were
/// `r_y` drawn from the deterministic stream, the two shares would be equal.
#[test]
fn the_y_share_takes_its_nonce_from_frost_never_from_the_transcript() {
    use modular_frost::{algorithm::Algorithm, Participant};
    use zeroize::Zeroizing;

    let x = Scalar::random(&mut OsRng);
    let keys = key_gen::<_, Ed25519T>(&mut OsRng);
    let any = keys.values().next().unwrap();
    let O = (EdwardsPoint::generator() * x) + any.group_key();
    let I = EdwardsPoint::random(&mut OsRng);
    let C = EdwardsPoint::random(&mut OsRng);
    let rerandomized_output = RerandomizedOutput::new(&mut OsRng, Output::new(O, I, C).unwrap());
    let build = || {
        SalAlgorithm::new(
            OsRng,
            RecommendedTranscript::new(b"SpendAuthAndLinkability Multisig Test"),
            shekyl_types::TxSignableHash::from_bytes([0; 32]),
            rerandomized_output.clone(),
            x,
        )
    };
    let included: Vec<Participant> = keys.keys().copied().collect();
    let view = any.view(included).unwrap();
    let nonce_sums = vec![vec![EdwardsPoint::random(&mut OsRng)]];
    let (n1, n2) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
    assert_ne!(n1, n2);

    let share = |nonce: Scalar| {
        let mut algorithm = build();
        algorithm.sign_share(&view, &nonce_sums, vec![Zeroizing::new(nonce)], &[])
    };
    let (s1, s1_again, s2) = (share(n1), share(n1), share(n2));
    assert_eq!(
        s1, s1_again,
        "the same transcript and nonce sign the same share"
    );
    assert_eq!(
        s1 - s2,
        n1 - n2,
        "the y share moves with the FROST nonce, one for one: its nonce is FROST's"
    );
    assert_ne!(
        s1, s2,
        "a y nonce from the deterministic stream would make these equal"
    );
}
