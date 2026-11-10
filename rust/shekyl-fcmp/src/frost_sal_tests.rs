// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The FROST SAL layer over synthetic outputs: the dealer and loader, the
//! machines end to end, and each way a signing session must fail. The
//! end-to-end spend of real slice-1 outputs from member files is
//! `shekyl-multisig/tests/frost_spend.rs`.

// CLIPPY(non_snake_case): `O`, `C`, `L` are the FCMP++ / SAL notation.
#![allow(non_snake_case)]

use super::*;

use multiexp::BatchVerifier;
use shekyl_curve_generators::T;

const SIGNABLE: TxSignableHash = TxSignableHash::from_bytes([0x5A; 32]);

/// A split group, every member's keys loaded through [`threshold_keys`].
struct SplitGroup {
    split: DealerSplit,
    keys: HashMap<Participant, ThresholdKeys<Ed25519T>>,
}

fn group(n: u8, m: u8) -> SplitGroup {
    let split = dealer_split(n, m, &mut OsRng).expect("a valid shape");
    let keys = (0..n)
        .map(|i| {
            let keys = threshold_keys(
                n,
                m,
                i,
                &split.shares[usize::from(i)],
                &split.verification_shares,
                &split.y_group,
            )
            .expect("the dealer's own split loads");
            (participant(i), keys)
        })
        .collect();
    SplitGroup { split, keys }
}

/// An output to `g` with random `x` and `y_kem`:
/// `O = x·G + Y_group + y_kem·T`.
fn params_for(g: &SplitGroup) -> SalSigningParams {
    let x = Scalar::random(&mut OsRng);
    let y_kem = Scalar::random(&mut OsRng);
    let y_group = decode_point(&g.split.y_group).unwrap();
    let O = EdwardsPoint::generator() * x + y_group + EdwardsPoint(*T) * y_kem;
    let C = EdwardsPoint::random(&mut OsRng);
    SalSigningParams::propose(
        &mut OsRng,
        &O.to_bytes(),
        &C.to_bytes(),
        SIGNABLE,
        &x.to_repr(),
        &y_kem.to_repr(),
    )
    .unwrap()
}

/// Every signer in `signers` runs both rounds and completes; each signer's
/// result, by participant. `params(p)` is what signer `p` signs from.
fn run<'a>(
    g: &SplitGroup,
    signers: &[Participant],
    params: impl Fn(Participant) -> &'a SalSigningParams,
) -> HashMap<Participant, Result<SpendAuthAndLinkability, FrostError>> {
    let (machines, preprocesses): (HashMap<_, _>, HashMap<_, _>) = signers
        .iter()
        .map(|&p| {
            let (machine, pre) = preprocess(params(p), g.keys[&p].clone(), &mut OsRng).unwrap();
            ((p, machine), (p, pre))
        })
        .unzip();
    sign_and_complete(signers, machines, &preprocesses)
}

fn others<V: Clone>(map: &HashMap<Participant, V>, me: Participant) -> HashMap<Participant, V> {
    map.iter()
        .filter(|(p, _)| **p != me)
        .map(|(p, v)| (*p, v.clone()))
        .collect()
}

fn sign_and_complete(
    signers: &[Participant],
    mut machines: HashMap<Participant, SalSignMachine>,
    preprocesses: &HashMap<Participant, SalPreprocess>,
) -> HashMap<Participant, Result<SpendAuthAndLinkability, FrostError>> {
    let (machines, shares): (HashMap<_, _>, HashMap<_, _>) = signers
        .iter()
        .map(|&p| {
            let machine = machines.remove(&p).unwrap();
            let (machine, share) = sign(machine, others(preprocesses, p)).unwrap();
            ((p, machine), (p, share))
        })
        .unzip();
    machines
        .into_iter()
        .map(|(p, machine)| (p, complete(machine, others(&shares, p))))
        .collect()
}

/// The SAL verifies for `params`' input and key image.
fn sal_verifies(sal: &SpendAuthAndLinkability, params: &SalSigningParams) -> bool {
    let L = params.output.I() * params.x;
    let mut verifier = BatchVerifier::new(1);
    sal.verify(
        &mut OsRng,
        &mut verifier,
        SIGNABLE,
        &params.rerandomized.input(),
        L,
    );
    verifier.verify_vartime()
}

fn ps(indices: &[u8]) -> Vec<Participant> {
    indices.iter().map(|&i| participant(i)).collect()
}

// ---------------------------------------------------------------------------
// Dealer and loader
// ---------------------------------------------------------------------------

/// The loader's constructors are dkg 0.6.1's `ThresholdParams::new` and
/// `ThresholdKeys::new` under `Interpolation::Lagrange`; a crate bump that
/// moves them, or the 0-based → 1-based conversion, shows here.
#[test]
fn every_member_of_a_split_loads_as_its_participant() {
    for (n, m) in [(3, 2), (5, 3), (1, 1), (5, 5)] {
        let g = group(n, m);
        for i in 0..n {
            let keys = &g.keys[&participant(i)];
            let params = keys.params();
            assert_eq!(u16::from(params.i()), u16::from(i) + 1);
            assert_eq!((params.t(), params.n()), (u16::from(m), u16::from(n)));
            assert!(matches!(keys.interpolation(), Interpolation::Lagrange));
            assert_eq!(keys.group_key().to_bytes(), g.split.y_group);
        }
    }
}

#[test]
fn a_share_loaded_at_the_wrong_index_is_refused() {
    let g = group(3, 2);
    // Member 1's share filed as member 0 (an off-by-one in a writer).
    let refused = threshold_keys(
        3,
        2,
        0,
        &g.split.shares[1],
        &g.split.verification_shares,
        &g.split.y_group,
    );
    assert_eq!(refused.err(), Some(FrostKeyError::ShareMismatch));
}

#[test]
fn no_split_exists_for_a_shape_no_address_carries() {
    for (n, m) in [(0, 0), (3, 0), (3, 4), (6, 3)] {
        assert_eq!(
            dealer_split(n, m, &mut OsRng).err(),
            Some(FrostKeyError::GroupShape { n, m })
        );
    }
}

#[test]
fn the_loader_refuses_each_bad_input_by_name() {
    let g = group(5, 3);
    let s = &g.split;
    let load = |n: u8, m: u8, i: u8, share: &[u8; 32], vs: &[[u8; 32]], y: &[u8; 32]| {
        threshold_keys(n, m, i, share, vs, y).err()
    };

    assert_eq!(
        load(5, 6, 0, &s.shares[0], &s.verification_shares, &s.y_group),
        Some(FrostKeyError::GroupShape { n: 5, m: 6 })
    );
    assert_eq!(
        load(5, 3, 5, &s.shares[0], &s.verification_shares, &s.y_group),
        Some(FrostKeyError::MemberIndex { index: 5, n: 5 })
    );
    assert_eq!(
        load(
            5,
            3,
            0,
            &s.shares[0],
            &s.verification_shares[..4],
            &s.y_group
        ),
        Some(FrostKeyError::VerificationShareCount {
            expected: 5,
            got: 4
        })
    );
    assert_eq!(
        load(5, 3, 0, &[0xFF; 32], &s.verification_shares, &s.y_group),
        Some(FrostKeyError::NonCanonicalShare)
    );

    let identity = EdwardsPoint::identity().to_bytes();
    let torsion = curve25519_dalek::constants::EIGHT_TORSION[1]
        .compress()
        .to_bytes();
    // y = p (non-canonical spelling of y = 0... with the sign bit clear).
    let mut non_canonical = [0xFF; 32];
    non_canonical[0] = 0xED;
    non_canonical[31] = 0x7F;
    for bad in [identity, torsion, non_canonical] {
        let mut vs = s.verification_shares.clone();
        vs[2] = bad;
        assert_eq!(
            load(5, 3, 0, &s.shares[0], &vs, &s.y_group),
            Some(FrostKeyError::VerificationShare { member: 2 })
        );
    }

    let other = EdwardsPoint::random(&mut OsRng).to_bytes();
    assert_eq!(
        load(5, 3, 0, &s.shares[0], &s.verification_shares, &other),
        Some(FrostKeyError::GroupKeyMismatch)
    );
    // A share inside the first window moves the group key.
    let mut vs = s.verification_shares.clone();
    vs[1] = other;
    assert_eq!(
        load(5, 3, 0, &s.shares[0], &vs, &s.y_group),
        Some(FrostKeyError::GroupKeyMismatch)
    );
    // A share past it is off the polynomial, and named.
    for member in [3u8, 4] {
        let mut vs = s.verification_shares.clone();
        vs[usize::from(member)] = other;
        assert_eq!(
            load(5, 3, 0, &s.shares[0], &vs, &s.y_group),
            Some(FrostKeyError::OffPolynomial { member })
        );
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

#[test]
fn any_m_members_sign_a_sal_that_verifies() {
    for (n, m, signers) in [
        (3, 2, ps(&[0, 2])),
        (5, 3, ps(&[1, 3, 4])),
        (5, 5, ps(&[0, 1, 2, 3, 4])),
    ] {
        let g = group(n, m);
        let params = params_for(&g);
        let results = run(&g, &signers, |_| &params);
        let sals: Vec<_> = results.into_values().map(Result::unwrap).collect();
        assert!(
            sals.windows(2).all(|w| w[0] == w[1]),
            "every signer completes the same SAL"
        );
        assert!(sal_verifies(&sals[0], &params), "{m}-of-{n}");
    }
}

#[test]
fn a_cached_preprocess_resumes_the_same_session() {
    let g = group(3, 2);
    let params = params_for(&g);
    let [a, b] = [participant(0), participant(1)];
    let (machine_a, pre_a) = preprocess(&params, g.keys[&a].clone(), &mut OsRng).unwrap();
    let (machine_b, pre_b) = preprocess(&params, g.keys[&b].clone(), &mut OsRng).unwrap();

    let (resumed_a, again_a) = from_cache(&params, g.keys[&a].clone(), cache(machine_a)).unwrap();
    assert!(again_a == pre_a, "the seed rebuilds the preprocess it sent");

    let machines = HashMap::from([(a, resumed_a), (b, machine_b)]);
    let preprocesses = HashMap::from([(a, pre_a), (b, pre_b)]);
    for (_, sal) in sign_and_complete(&[a, b], machines, &preprocesses) {
        assert!(sal_verifies(&sal.unwrap(), &params));
    }
}

/// The nonces are a function of the seed and the share (hedged): the same
/// seed with the same keys replays; another seed, or the same seed with
/// another member's share, does not.
#[test]
fn a_preprocess_depends_on_its_seed_and_its_share() {
    let g = group(3, 2);
    let params = params_for(&g);
    let seeded = |p: u8, seed: u8| {
        let cached = CachedPreprocess(Zeroizing::new([seed; 32]));
        from_cache(&params, g.keys[&participant(p)].clone(), cached)
            .unwrap()
            .1
    };
    assert!(seeded(0, 1) == seeded(0, 1));
    assert!(seeded(0, 1) != seeded(0, 2));
    assert!(seeded(0, 1) != seeded(1, 1));
}

#[test]
fn keys_for_another_output_cannot_preprocess() {
    let g = group(3, 2);
    let params = params_for(&g);
    let keys = g.keys[&participant(0)].clone();

    let mut wrong_tweak = params.clone();
    wrong_tweak.y_kem = Scalar::ZERO;
    let mut wrong_x = params.clone();
    wrong_x.x += Scalar::ONE;
    let other_group = group(3, 2).keys[&participant(0)].clone();

    for (params, keys) in [
        (&wrong_tweak, keys.clone()),
        (&wrong_x, keys),
        (&params, other_group),
    ] {
        assert_eq!(
            preprocess(params, keys.clone(), &mut OsRng).err(),
            Some(FrostSalError::KeysDoNotOpenOutput)
        );
        assert_eq!(
            from_cache(params, keys, CachedPreprocess(Zeroizing::new([7; 32]))).err(),
            Some(FrostSalError::KeysDoNotOpenOutput)
        );
    }
}

/// The `y_kem` tweak is load-bearing. Past the layer (keys offset by the
/// rerandomization alone), every share verifies against the keys it was
/// made with, yet the aggregate is not a SAL for the output: `complete`
/// finds no signer to blame.
#[test]
fn without_the_y_kem_offset_the_aggregate_does_not_verify() {
    let g = group(3, 2);
    let params = params_for(&g);
    let signers = ps(&[0, 1]);
    let (machines, preprocesses): (HashMap<_, _>, HashMap<_, _>) = signers
        .iter()
        .map(|&p| {
            let keys = g.keys[&p].clone().offset(-params.rerandomized.o_blind());
            let (machine, pre) =
                AlgorithmMachine::new(params.algorithm(), keys).preprocess(&mut OsRng);
            ((p, machine), (p, pre))
        })
        .unzip();
    for (_, result) in sign_and_complete(&signers, machines, &preprocesses) {
        assert!(
            matches!(result, Err(FrostError::InternalError(_))),
            "{result:?}"
        );
    }
}

/// Every signer must sign one rerandomization: a signer with its own has
/// another transcript and another offset, and every other signer blames it.
#[test]
fn a_signer_with_another_rerandomization_is_blamed() {
    let g = group(5, 3);
    let params = params_for(&g);
    let mut stray = params.clone();
    stray.rerandomized = RerandomizedOutput::new(&mut OsRng, params.output);
    let signers = ps(&[0, 2, 4]);
    let odd = participant(2);
    let results = run(&g, &signers, |p| if p == odd { &stray } else { &params });
    for (p, result) in results {
        if p != odd {
            assert_eq!(result.err(), Some(FrostError::InvalidShare(odd)));
        }
    }
}

/// A preprocess from another session (the signer's nonces are elsewhere)
/// changes every binding factor. `modular_frost` has nothing to check a
/// single-generator preprocess against at `sign`; the signer is caught at
/// `complete`, by name.
#[test]
fn a_preprocess_from_another_session_is_blamed() {
    let g = group(3, 2);
    let params = params_for(&g);
    let signers = ps(&[0, 1]);
    let swapped = participant(1);
    let (mut machines, mut preprocesses): (HashMap<_, _>, HashMap<_, _>) = signers
        .iter()
        .map(|&p| {
            let (machine, pre) = preprocess(&params, g.keys[&p].clone(), &mut OsRng).unwrap();
            ((p, machine), (p, pre))
        })
        .unzip();
    let (_, foreign) = preprocess(&params, g.keys[&swapped].clone(), &mut OsRng).unwrap();
    // The others see the foreign preprocess; the signer signs from its own.
    let own = preprocesses.insert(swapped, foreign).unwrap();
    let honest = participant(0);
    let (honest_machine, _) = sign(
        machines.remove(&honest).unwrap(),
        others(&preprocesses, honest),
    )
    .unwrap();
    let mut seen_by_swapped = preprocesses.clone();
    seen_by_swapped.insert(swapped, own);
    let (_, swapped_share) = sign(
        machines.remove(&swapped).unwrap(),
        others(&seen_by_swapped, swapped),
    )
    .unwrap();
    assert_eq!(
        complete(honest_machine, HashMap::from([(swapped, swapped_share)])).err(),
        Some(FrostError::InvalidShare(swapped))
    );
}

#[test]
fn fewer_than_m_signers_cannot_sign() {
    let g = group(5, 3);
    let params = params_for(&g);
    let (machine, _) = preprocess(&params, g.keys[&participant(0)].clone(), &mut OsRng).unwrap();
    let (_, pre) = preprocess(&params, g.keys[&participant(1)].clone(), &mut OsRng).unwrap();
    assert_eq!(
        sign(machine, HashMap::from([(participant(1), pre)])).err(),
        Some(FrostError::InvalidSigningSet("not enough signers"))
    );
}

#[test]
fn the_proposal_refuses_each_bad_value_by_name() {
    let good = EdwardsPoint::random(&mut OsRng).to_bytes();
    let scalar = Scalar::random(&mut OsRng).to_repr();
    let identity = EdwardsPoint::identity().to_bytes();
    let propose = |o: &[u8; 32], c: &[u8; 32], x: &[u8; 32], y: &[u8; 32]| {
        SalSigningParams::propose(&mut OsRng, o, c, SIGNABLE, x, y).err()
    };
    assert_eq!(
        propose(&identity, &good, &scalar, &scalar),
        Some(FrostSalError::OutputKey)
    );
    assert_eq!(
        propose(&good, &identity, &scalar, &scalar),
        Some(FrostSalError::Commitment)
    );
    assert_eq!(
        propose(&good, &good, &[0xFF; 32], &scalar),
        Some(FrostSalError::SpendScalar)
    );
    assert_eq!(
        propose(&good, &good, &scalar, &[0xFF; 32]),
        Some(FrostSalError::OutputTweak)
    );
}
