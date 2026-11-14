// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The FROST SAL layer over synthetic outputs: the dealer and loader, the
//! machines end to end, and each way a signing session must fail. The
//! end-to-end spend of real slice-1 outputs from member files is
//! `rust/shekyl-fcmp/tests/frost_spend.rs`.

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

/// An output to a group, as every member knows it from its own scan, with
/// the input's pseudo-out blind and rerandomization seed: everything
/// [`SalSigningParams::new`] reads.
struct SpendFixture {
    output_key: [u8; 32],
    commitment: [u8; 32],
    x: [u8; 32],
    y_kem: [u8; 32],
    z: [u8; 32],
    a: [u8; 32],
    seed: [u8; RERANDOMIZATION_SEED_LEN],
}

impl SpendFixture {
    /// An output to `g` with random `x` and `y_kem`:
    /// `O = x·G + Y_group + y_kem·T`.
    fn new(g: &SplitGroup) -> Self {
        let x = Scalar::random(&mut OsRng);
        let y_kem = Scalar::random(&mut OsRng);
        let y_group = decode_point(&g.split.y_group).unwrap();
        let O = EdwardsPoint::generator() * x + y_group + EdwardsPoint(*T) * y_kem;
        let mut seed = [0u8; RERANDOMIZATION_SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        Self {
            output_key: O.to_bytes(),
            commitment: EdwardsPoint::random(&mut OsRng).to_bytes(),
            x: x.to_repr(),
            y_kem: y_kem.to_repr(),
            z: Scalar::random(&mut OsRng).to_repr(),
            a: Scalar::random(&mut OsRng).to_repr(),
            seed,
        }
    }

    /// The parameters one member builds from this fixture, under `seed`.
    fn params_with_seed(&self, seed: &[u8; RERANDOMIZATION_SEED_LEN]) -> SalSigningParams {
        let spent = SpentOutput {
            output_key: &self.output_key,
            commitment: &self.commitment,
            spend_scalar: &self.x,
            y_kem: &self.y_kem,
            commitment_mask: &self.z,
        };
        SalSigningParams::new(seed, &spent, &self.a, SIGNABLE).unwrap()
    }

    fn params(&self) -> SalSigningParams {
        self.params_with_seed(&self.seed)
    }
}

/// One member's parameters for a new output to `g`.
fn params_for(g: &SplitGroup) -> SalSigningParams {
    SpendFixture::new(g).params()
}

/// `params` with another rerandomization, `x` or `y_kem` (the type is not
/// `Clone`; the tests build each variant field by field).
fn variant(
    params: &SalSigningParams,
    rerandomized: Option<RerandomizedOutput>,
    x: Option<Scalar>,
    y_kem: Option<Scalar>,
) -> SalSigningParams {
    SalSigningParams {
        output: params.output,
        rerandomized: rerandomized.unwrap_or_else(|| params.rerandomized.clone()),
        signable: params.signable,
        x: x.unwrap_or(params.x),
        y_kem: y_kem.unwrap_or(params.y_kem),
    }
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
    for (n, m) in [(3, 2), (5, 3), (2, 2), (5, 5)] {
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
    for (n, m) in [(0, 0), (3, 0), (1, 1), (3, 1), (3, 4), (6, 3)] {
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
fn a_held_session_resumes_the_same_session() {
    let g = group(3, 2);
    let fixture = SpendFixture::new(&g);
    let params = fixture.params();
    let [a, b] = [participant(0), participant(1)];
    let (held_a, pre_a) = hold(fixture.params(), g.keys[&a].clone(), &mut OsRng).unwrap();
    let (machine_b, pre_b) = preprocess(&params, g.keys[&b].clone(), &mut OsRng).unwrap();

    let (resumed_a, again_a) = held_a.resume().unwrap();
    assert!(again_a == pre_a, "the seed rebuilds the preprocess it sent");

    let machines = HashMap::from([(a, resumed_a), (b, machine_b)]);
    let preprocesses = HashMap::from([(a, pre_a), (b, pre_b)]);
    for (_, sal) in sign_and_complete(&[a, b], machines, &preprocesses) {
        assert!(sal_verifies(&sal.unwrap(), &params));
    }
}

/// The nonces are a function of the seed and the share, not of the
/// parameters: `modular_frost` would rebuild the same preprocess for a seed
/// under any parameters. That is why [`HeldSession`] owns its parameters.
#[test]
fn a_preprocess_depends_on_its_seed_and_share_but_not_its_params() {
    let g = group(3, 2);
    let one = params_for(&g);
    let other = params_for(&g);
    let seeded = |params: &SalSigningParams, p: u8, seed: u8| {
        let keys = params.offset_keys(g.keys[&participant(p)].clone()).unwrap();
        let cached = CachedPreprocess(Zeroizing::new([seed; 32]));
        SalSignMachine::from_cache(params.algorithm(), keys, cached).1
    };
    assert!(seeded(&one, 0, 1) == seeded(&one, 0, 1));
    assert!(seeded(&one, 0, 1) != seeded(&one, 0, 2));
    assert!(seeded(&one, 0, 1) != seeded(&one, 1, 1));
    assert!(
        seeded(&one, 0, 1) == seeded(&other, 0, 1),
        "the seed's nonces do not depend on the parameters"
    );
}

#[test]
fn keys_for_another_output_cannot_preprocess() {
    let g = group(3, 2);
    let params = params_for(&g);
    let keys = g.keys[&participant(0)].clone();

    let wrong_tweak = variant(&params, None, None, Some(Scalar::ZERO));
    let wrong_x = variant(&params, None, Some(params.x + Scalar::ONE), None);
    let other_group = group(3, 2).keys[&participant(0)].clone();

    for (params, keys) in [
        (&wrong_tweak, keys.clone()),
        (&wrong_x, keys),
        (&params, other_group),
    ] {
        assert_eq!(
            preprocess(params, keys, &mut OsRng).err(),
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
    let stray = variant(
        &params,
        Some(RerandomizedOutput::new(&mut OsRng, params.output)),
        None,
        None,
    );
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
    let bad = [0xFF; 32];
    let propose =
        |o: &[u8; 32], c: &[u8; 32], x: &[u8; 32], y: &[u8; 32], z: &[u8; 32], a: &[u8; 32]| {
            let spent = SpentOutput {
                output_key: o,
                commitment: c,
                spend_scalar: x,
                y_kem: y,
                commitment_mask: z,
            };
            SalSigningParams::new(&[0x5E; RERANDOMIZATION_SEED_LEN], &spent, a, SIGNABLE).err()
        };
    let s = &scalar;
    assert_eq!(
        propose(&identity, &good, s, s, s, s),
        Some(FrostSalError::OutputKey)
    );
    assert_eq!(
        propose(&good, &identity, s, s, s, s),
        Some(FrostSalError::Commitment)
    );
    assert_eq!(
        propose(&good, &good, &bad, s, s, s),
        Some(FrostSalError::SpendScalar)
    );
    assert_eq!(
        propose(&good, &good, s, &bad, s, s),
        Some(FrostSalError::OutputTweak)
    );
    assert_eq!(
        propose(&good, &good, s, s, &bad, s),
        Some(FrostSalError::CommitmentMask)
    );
    assert_eq!(
        propose(&good, &good, s, s, s, &bad),
        Some(FrostSalError::PseudoOutBlind)
    );
}

/// R-7: no member sends the signing parameters. Each signer builds its own
/// from the intent, and the same seed gives the same rerandomized input,
/// so independently built parameters run one transcript and complete one
/// SAL, which verifies.
#[test]
fn members_building_their_own_params_complete_one_sal() {
    let g = group(5, 3);
    let fixture = SpendFixture::new(&g);
    let signers = ps(&[0, 2, 4]);
    let own: HashMap<Participant, SalSigningParams> =
        signers.iter().map(|&p| (p, fixture.params())).collect();
    let results = run(&g, &signers, |p| &own[&p]);
    let sals: Vec<SpendAuthAndLinkability> = results.into_values().map(Result::unwrap).collect();
    assert!(sals.windows(2).all(|w| w[0] == w[1]));
    assert!(sal_verifies(&sals[0], &own[&signers[0]]));
}

/// A signer whose seed differs builds another rerandomized input: the
/// signing session does not complete for it, and the others name it.
#[test]
fn a_signer_with_another_seed_does_not_complete_one_sal() {
    let g = group(3, 2);
    let fixture = SpendFixture::new(&g);
    let signers = ps(&[0, 1]);
    let honest = fixture.params();
    let other = fixture.params_with_seed(&[0xEE; RERANDOMIZATION_SEED_LEN]);
    assert_ne!(honest.rerandomized().input(), other.rerandomized().input());
    let results = run(
        &g,
        &signers,
        |p| {
            if p == signers[0] {
                &honest
            } else {
                &other
            }
        },
    );
    assert!(results.values().all(Result::is_err));
}

/// The seed's expansion is protocol: every member must derive the same
/// three blinds from it. The rerandomized input for fixed values is pinned,
/// so a change to the stream, the order the blinds are drawn in, or the
/// constructor moves it. Recorded from this construction (a regression pin,
/// not an independent vector: the inputs are curve points).
#[test]
fn the_rerandomization_is_pinned() {
    let x = Scalar::from(7u64);
    let y_kem = Scalar::from(11u64);
    let O = EdwardsPoint::generator() * Scalar::from(5u64);
    let C = EdwardsPoint::generator() * Scalar::from(13u64);
    let spent = SpentOutput {
        output_key: &O.to_bytes(),
        commitment: &C.to_bytes(),
        spend_scalar: &x.to_repr(),
        y_kem: &y_kem.to_repr(),
        commitment_mask: &Scalar::from(17u64).to_repr(),
    };
    let params = SalSigningParams::new(
        &[0x42; RERANDOMIZATION_SEED_LEN],
        &spent,
        &Scalar::from(19u64).to_repr(),
        SIGNABLE,
    )
    .unwrap();
    let input = params.rerandomized().input();
    let hex =
        |p: EdwardsPoint| -> String { p.to_bytes().iter().map(|b| format!("{b:02x}")).collect() };
    let got = [
        hex(input.O_tilde()),
        hex(input.I_tilde()),
        hex(input.R()),
        hex(input.C_tilde()),
    ];
    // The pseudo-out is not drawn from the seed: C~ = C + (a − z)·G, here
    // (13 + 19 − 17)·G.
    assert_eq!(
        input.C_tilde(),
        EdwardsPoint::generator() * Scalar::from(15u64)
    );
    let pinned: [&str; 4] = PINNED_RERANDOMIZATION;
    assert_eq!(got, pinned.map(String::from), "{got:?}");
}

const PINNED_RERANDOMIZATION: [&str; 4] = [
    "ccc7efd8f5a126b863eee86e8b74fbfda67a657d865e65862046ee1fdf146224",
    "6201c93718c73988f995b6b6d4109c0da157721da77b01058e4c8abce9fdc2b2",
    "e73f786b2732bcca2588b686cbc0570cfb08af0e388034be0b77da3bf56ff32b",
    "df5c2eadc44c6d94a19a9aa118afe5ac3193d26401f76251f522ff042dfbcb92",
];
