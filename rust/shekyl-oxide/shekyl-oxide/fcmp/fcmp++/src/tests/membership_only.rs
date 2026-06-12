//! Tests for `FcmpMembershipOnly` / `MembershipSpendAuth`.
//!
//! Test map (`docs/design/FCMP_MEMBERSHIP_ONLY.md`):
//! - roundtrips (1 and 2 inputs) with wire-size assertions, incl. the §10.1 3× bound
//! - cross-type rejection at the deserialization seam, both directions
//! - F-6 privacy: rerandomization freshness, ZeroRng synthesis, degeneracy guard
//! - F-7: mixed-type batches reject in both polarities
//! - E-class: empty-input rejection, index binding, blob-swap rejection
//! - replay (wrong tx hash), wrong root, byte tampering

use rand_core::{CryptoRng, OsRng, RngCore};

use ciphersuite::{
    group::{ff::Field, Group, GroupEncoding},
    Ciphersuite,
};
use dalek_ff_group::{Ed25519, EdwardsPoint, Scalar};
use ec_divisors::{DivisorCurve, ScalarDecomposition};
use helioselene::{Helios, Selene};
use multiexp::multiexp_vartime;

use shekyl_generators::{FCMP_PLUS_PLUS_U, FCMP_PLUS_PLUS_V, T};

use crate::{
    fcmps::{Branches, CBlind, Fcmp, IBlind, IBlindBlind, OBlind, OutputBlinds, Path, TreeRoot},
    sal::membership_only::{
        check_nondegenerate, membership_only_rerandomize, MembershipOnlyError, MembershipSpendAuth,
    },
    sal::*,
    FcmpMembershipOnly, FcmpPlusPlus, FcmpPlusPlusError, Output, FCMP_PARAMS,
    HELIOS_FCMP_GENERATORS, SELENE_FCMP_GENERATORS, SELENE_HASH_INIT,
};

/// An RNG returning all zeroes: the degraded-RNG seam for the F-6 synthesis tests.
struct ZeroRng;
impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}
impl CryptoRng for ZeroRng {}

struct Leaf {
    x: Scalar,
    y: Scalar,
    output: Output,
    h_pqc: <Selene as Ciphersuite>::F,
}

fn make_leaf() -> Leaf {
    let x = Scalar::random(&mut OsRng);
    let y = Scalar::random(&mut OsRng);
    let O = (EdwardsPoint::generator() * x) + (EdwardsPoint(*T) * y);
    let I = EdwardsPoint::random(&mut OsRng);
    let C = EdwardsPoint::random(&mut OsRng);
    Leaf {
        x,
        y,
        output: Output::new(O, I, C).unwrap(),
        h_pqc: <Selene as Ciphersuite>::F::random(&mut OsRng),
    }
}

/// Build a single-layer tree over the given leaves and prove the Fcmp leg for the
/// given rerandomizations (one per leaf, in order).
fn tree_and_fcmp(
    leaves: &[&Leaf],
    rerandomized: &[RerandomizedOutput],
) -> (TreeRoot<Selene, Helios>, Fcmp<crate::Curves>) {
    assert_eq!(leaves.len(), rerandomized.len());

    let leaf_outputs: Vec<Output> = leaves.iter().map(|leaf| leaf.output).collect();
    let leaves_extra_scalars: Vec<Vec<<Selene as Ciphersuite>::F>> =
        leaves.iter().map(|leaf| vec![leaf.h_pqc]).collect();

    let mut hash_scalars = vec![];
    for leaf in leaves {
        hash_scalars.push(
            <Ed25519 as Ciphersuite>::G::to_xy(leaf.output.O())
                .unwrap()
                .0,
        );
        hash_scalars.push(
            <Ed25519 as Ciphersuite>::G::to_xy(leaf.output.I())
                .unwrap()
                .0,
        );
        hash_scalars.push(
            <Ed25519 as Ciphersuite>::G::to_xy(leaf.output.C())
                .unwrap()
                .0,
        );
        hash_scalars.push(leaf.h_pqc);
    }
    let tree = TreeRoot::<Selene, Helios>::C1(
        *SELENE_HASH_INIT
            + multiexp_vartime(
                &hash_scalars
                    .into_iter()
                    .zip(
                        SELENE_FCMP_GENERATORS
                            .generators
                            .g_bold_slice()
                            .iter()
                            .copied(),
                    )
                    .collect::<Vec<_>>(),
            ),
    );

    let mut paths = vec![];
    let mut blinds = vec![];
    for (leaf, rerandomized) in leaves.iter().zip(rerandomized) {
        paths.push(Path {
            output: leaf.output,
            output_extra_scalars: vec![leaf.h_pqc],
            leaves: leaf_outputs.clone(),
            leaves_extra_scalars: leaves_extra_scalars.clone(),
            curve_2_layers: vec![],
            curve_1_layers: vec![],
        });
        blinds.push(OutputBlinds::new(
            OBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerandomized.o_blind()).unwrap(),
            ),
            IBlind::new(
                EdwardsPoint(*FCMP_PLUS_PLUS_U),
                EdwardsPoint(*FCMP_PLUS_PLUS_V),
                ScalarDecomposition::new(rerandomized.i_blind()).unwrap(),
            ),
            IBlindBlind::new(
                EdwardsPoint(*T),
                ScalarDecomposition::new(rerandomized.i_blind_blind()).unwrap(),
            ),
            CBlind::new(
                EdwardsPoint::generator(),
                ScalarDecomposition::new(rerandomized.c_blind()).unwrap(),
            ),
        ));
    }

    let branches = Branches::new(paths).unwrap();
    let blinded_branches = branches.blind(blinds, vec![], vec![]).unwrap();
    (
        tree,
        Fcmp::prove(&mut OsRng, &*FCMP_PARAMS, blinded_branches).unwrap(),
    )
}

/// Build a complete membership-only proof over the given leaves (one input per leaf,
/// through the production rerandomization seam).
fn membership_only_proof(
    tx_hash: [u8; 32],
    context: &[u8],
    leaves: &[&Leaf],
) -> (TreeRoot<Selene, Helios>, FcmpMembershipOnly) {
    let mut rerandomized = vec![];
    let mut inputs = vec![];
    for (index, leaf) in leaves.iter().enumerate() {
        let r = membership_only_rerandomize(&mut OsRng, leaf.output, &leaf.x, context).unwrap();
        let opening = OpenedInputTuple::open(&r, &leaf.x, &leaf.y).unwrap();
        let msa = MembershipSpendAuth::prove(
            &mut OsRng,
            tx_hash,
            u32::try_from(index).unwrap(),
            &opening,
        );
        inputs.push((r.input(), msa));
        rerandomized.push(r);
    }
    let (tree, fcmp) = tree_and_fcmp(leaves, &rerandomized);
    (tree, FcmpMembershipOnly::new(inputs, fcmp))
}

struct Verifiers {
    ed: multiexp::BatchVerifier<(), <Ed25519 as Ciphersuite>::G>,
    c1: generalized_bulletproofs::BatchVerifier<Selene>,
    c2: generalized_bulletproofs::BatchVerifier<Helios>,
}

impl Verifiers {
    fn new() -> Self {
        Verifiers {
            ed: multiexp::BatchVerifier::new(8),
            c1: generalized_bulletproofs::Generators::batch_verifier(),
            c2: generalized_bulletproofs::Generators::batch_verifier(),
        }
    }

    fn all_valid(self) -> bool {
        self.ed.verify_vartime()
            && SELENE_FCMP_GENERATORS.generators.verify(self.c1)
            && HELIOS_FCMP_GENERATORS.generators.verify(self.c2)
    }
}

#[test]
fn membership_only_roundtrip() {
    let leaf = make_leaf();
    let tx_hash = [1; 32];
    let (tree, proof) = membership_only_proof(tx_hash, b"test reference root", &[&leaf]);

    let mut verifiers = Verifiers::new();
    proof
        .verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            tree,
            1,
            tx_hash,
            vec![leaf.h_pqc],
        )
        .unwrap();
    assert!(verifiers.all_valid());

    // Wire roundtrip.
    let mut buf = vec![];
    proof.write(&mut buf).unwrap();
    assert_eq!(FcmpMembershipOnly::proof_size(1, 1), buf.len());

    // §10.1 sizing caveat: membership-only was provisionally sized at 1-input
    // FcmpPlusPlus order, with a 3x-overrun reversion trigger. It proves strictly
    // less and must stay strictly smaller, let alone within 3x.
    assert!(buf.len() < FcmpPlusPlus::proof_size(1, 1));
    assert!(buf.len() <= 3 * FcmpPlusPlus::proof_size(1, 1));

    let pseudo_outs = [proof.inputs[0].0.C_tilde().to_bytes()];
    let read_proof = FcmpMembershipOnly::read(&pseudo_outs, 1, &mut buf.as_slice()).unwrap();

    let mut verifiers = Verifiers::new();
    read_proof
        .verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            tree,
            1,
            tx_hash,
            vec![leaf.h_pqc],
        )
        .unwrap();
    assert!(verifiers.all_valid());
}

#[test]
fn membership_only_multi_input_roundtrip() {
    let leaf_a = make_leaf();
    let leaf_b = make_leaf();
    let tx_hash = [2; 32];
    let (tree, proof) = membership_only_proof(tx_hash, b"multi", &[&leaf_a, &leaf_b]);

    let mut verifiers = Verifiers::new();
    proof
        .verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            tree,
            1,
            tx_hash,
            vec![leaf_a.h_pqc, leaf_b.h_pqc],
        )
        .unwrap();
    assert!(verifiers.all_valid());

    let mut buf = vec![];
    proof.write(&mut buf).unwrap();
    assert_eq!(FcmpMembershipOnly::proof_size(2, 1), buf.len());
}

/// §10.1 sizing gauge: the membership-only proof must stay within the
/// REWARD_EMISSION_LEG.md §10.1 reversion trigger (3x the 1-input FcmpPlusPlus
/// estimate it was provisionally sized at) — and, proving strictly less, must in fact
/// be strictly smaller.
#[test]
fn membership_only_proof_size() {
    for (inputs, layers) in [(1, 1), (2, 1), (1, 8), (4, 8)] {
        let mo = FcmpMembershipOnly::proof_size(inputs, layers);
        let full = FcmpPlusPlus::proof_size(inputs, layers);
        eprintln!("inputs={inputs} layers={layers}: membership-only {mo} B, full {full} B");
        assert!(mo < full);
        assert!(mo <= 3 * full);
        // The SAL-replacement saves exactly 288 B per input (96 B vs 384 B).
        assert_eq!(full - mo, inputs * 288);
    }
}

/// Direction A (load-bearing, deserialization seam): the bytes of a valid
/// membership-only proof must not be accepted by the full-proof path. The FFI-seam
/// variant of this test belongs to the emission vin PR, where that boundary is built.
#[test]
fn membership_only_bytes_rejected_by_full_path() {
    let leaf = make_leaf();
    let tx_hash = [3; 32];
    let (tree, proof) = membership_only_proof(tx_hash, b"dir-a", &[&leaf]);

    let mut buf = vec![];
    proof.write(&mut buf).unwrap();
    let pseudo_outs = [proof.inputs[0].0.C_tilde().to_bytes()];

    match FcmpPlusPlus::read(&pseudo_outs, 1, &mut buf.as_slice()) {
        // The structural mismatch (a 96-byte SAL-replacement where a 384-byte SAL is
        // expected) is caught at read.
        Err(_) => {}
        // If a parse ever survives, the proof must still fail verification: the
        // challenge transcripts are domain-separated by proof type.
        Ok(parsed) => {
            let mut verifiers = Verifiers::new();
            let key_image = EdwardsPoint::random(&mut OsRng);
            let result = parsed.verify(
                &mut OsRng,
                &mut verifiers.ed,
                &mut verifiers.c1,
                &mut verifiers.c2,
                tree,
                1,
                tx_hash,
                vec![key_image],
                vec![leaf.h_pqc],
            );
            assert!(
                result.is_err() || !verifiers.all_valid(),
                "membership-only bytes verified under the full path"
            );
        }
    }
}

/// Direction B: full-proof bytes must not be accepted by the membership-only path.
#[test]
fn full_proof_bytes_rejected_by_membership_only_path() {
    let leaf = make_leaf();
    let tx_hash = [4; 32];

    let rerandomized = RerandomizedOutput::new(&mut OsRng, leaf.output);
    let opening = OpenedInputTuple::open(&rerandomized, &leaf.x, &leaf.y).unwrap();
    let (_, sal) = SpendAuthAndLinkability::prove(&mut OsRng, tx_hash, &opening);
    let (tree, fcmp) = tree_and_fcmp(&[&leaf], core::slice::from_ref(&rerandomized));
    let full = FcmpPlusPlus::new(vec![(rerandomized.input(), sal)], fcmp);

    let mut buf = vec![];
    full.write(&mut buf).unwrap();
    let pseudo_outs = [rerandomized.input().C_tilde().to_bytes()];

    match FcmpMembershipOnly::read(&pseudo_outs, 1, &mut buf.as_slice()) {
        Err(_) => {}
        Ok(parsed) => {
            let mut verifiers = Verifiers::new();
            let result = parsed.verify(
                &mut OsRng,
                &mut verifiers.ed,
                &mut verifiers.c1,
                &mut verifiers.c2,
                tree,
                1,
                tx_hash,
                vec![leaf.h_pqc],
            );
            assert!(
                result.is_err() || !verifiers.all_valid(),
                "full-proof bytes verified under the membership-only path"
            );
        }
    }
}

/// F-6 freshness: two membership-only proofs of the same leaf must rerandomize to
/// pairwise-distinct tuples, each distinct from the base. Deterministic
/// point-inequality assertions (failure probability ~2^-252 each), not statistics.
#[test]
fn membership_only_rerandomization_freshness() {
    let leaf = make_leaf();
    let context = b"same context both times";

    let a = membership_only_rerandomize(&mut OsRng, leaf.output, &leaf.x, context).unwrap();
    let b = membership_only_rerandomize(&mut OsRng, leaf.output, &leaf.x, context).unwrap();
    let (a, b) = (a.input(), b.input());

    // Pairwise distinct across proofs: O~ equality is exactly the linkability failure.
    assert_ne!(a.O_tilde(), b.O_tilde());
    assert_ne!(a.I_tilde(), b.I_tilde());
    assert_ne!(a.R(), b.R());
    assert_ne!(a.C_tilde(), b.C_tilde());

    // Distinct from the base leaf (the guard enforces this; assert it held).
    for input in [&a, &b] {
        assert_ne!(input.O_tilde(), leaf.output.O());
        assert_ne!(input.I_tilde(), leaf.output.I());
        assert_ne!(input.C_tilde(), leaf.output.C());
        assert!(!bool::from(input.R().is_identity()));
    }
}

/// F-6 RNG seam: under a totally degraded (all-zero) RNG, synthesis must still
/// produce non-degenerate rerandomizations, distinct per context. (Same context +
/// dead RNG is deterministic by design — the documented RFC-6979-style residual.)
#[test]
fn membership_only_zero_rng_synthesis() {
    let leaf = make_leaf();

    let a = membership_only_rerandomize(&mut ZeroRng, leaf.output, &leaf.x, b"context A").unwrap();
    let b = membership_only_rerandomize(&mut ZeroRng, leaf.output, &leaf.x, b"context B").unwrap();

    // Non-degenerate even with zero entropy (the unwraps above already prove the
    // guard passed; check distance from base explicitly).
    assert_ne!(a.input().O_tilde(), leaf.output.O());
    assert_ne!(b.input().O_tilde(), leaf.output.O());

    // Distinct contexts give distinct rerandomizations.
    assert_ne!(a.input().O_tilde(), b.input().O_tilde());

    // Documented residual: same context + dead RNG is deterministic.
    let a2 = membership_only_rerandomize(&mut ZeroRng, leaf.output, &leaf.x, b"context A").unwrap();
    assert_eq!(a.input().O_tilde(), a2.input().O_tilde());

    // Schnorr nonces synthesize nonzero under a dead RNG too: prove and verify.
    let opening = OpenedInputTuple::open(&a, &leaf.x, &leaf.y).unwrap();
    let tx_hash = [5; 32];
    let msa = MembershipSpendAuth::prove(&mut ZeroRng, tx_hash, 0, &opening);
    let mut verifier = multiexp::BatchVerifier::new(1);
    msa.verify(&mut OsRng, &mut verifier, tx_hash, 0, &a.input());
    assert!(verifier.verify_vartime());
}

/// F-6 guard: a degenerate rerandomization (zero blinds) must be rejected loudly.
#[test]
fn membership_only_degeneracy_guard() {
    let leaf = make_leaf();
    let degenerate = RerandomizedOutput::with_blinds(
        leaf.output,
        Scalar::ZERO,
        Scalar::ZERO,
        Scalar::ZERO,
        Scalar::ZERO,
    );
    assert_eq!(
        check_nondegenerate(&degenerate.input(), &leaf.output),
        Err(MembershipOnlyError::DegenerateRerandomization)
    );
}

/// F-7 mixed-type batch verification, both polarities: a valid proof of one type must
/// not carry an invalid proof of the other when they share batch verifiers — the §7.1
/// step-6/step-7 co-occurrence consensus actually runs.
#[test]
fn mixed_type_batch_rejects() {
    // One full proof (with key image), one membership-only proof, separate trees.
    let full_leaf = make_leaf();
    let mo_leaf = make_leaf();
    let tx_hash = [6; 32];

    let full_rerandomized = RerandomizedOutput::new(&mut OsRng, full_leaf.output);
    let full_opening =
        OpenedInputTuple::open(&full_rerandomized, &full_leaf.x, &full_leaf.y).unwrap();
    let (key_image, sal) = SpendAuthAndLinkability::prove(&mut OsRng, tx_hash, &full_opening);
    let (full_tree, full_fcmp) =
        tree_and_fcmp(&[&full_leaf], core::slice::from_ref(&full_rerandomized));
    let full = FcmpPlusPlus::new(vec![(full_rerandomized.input(), sal)], full_fcmp);

    let (mo_tree, mo) = membership_only_proof(tx_hash, b"mixed", &[&mo_leaf]);

    // Tamper a proof by flipping a byte in its serialized SAL-leg scalar region, then
    // re-reading. The flip stays within a canonical scalar encoding w.h.p.
    let tamper_mo = |proof: &FcmpMembershipOnly| {
        let mut buf = vec![];
        proof.write(&mut buf).unwrap();
        // Input partial (96) + R_O (32): first byte of s_alpha.
        buf[96 + 32] ^= 1;
        FcmpMembershipOnly::read(
            &[proof.inputs[0].0.C_tilde().to_bytes()],
            1,
            &mut buf.as_slice(),
        )
        .unwrap()
    };
    let tamper_full = |proof: &FcmpPlusPlus| {
        let mut buf = vec![];
        proof.write(&mut buf).unwrap();
        // Input partial (96) + P, A, B, R_O, R_P, R_L (192): first byte of s_alpha.
        buf[96 + 192] ^= 1;
        FcmpPlusPlus::read(
            &[proof.inputs[0].0.C_tilde().to_bytes()],
            1,
            &mut buf.as_slice(),
        )
        .unwrap()
    };

    // Polarity 1: valid full + invalid membership-only -> the shared batch rejects.
    {
        let mut verifiers = Verifiers::new();
        full.verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            full_tree,
            1,
            tx_hash,
            vec![key_image],
            vec![full_leaf.h_pqc],
        )
        .unwrap();
        tamper_mo(&mo)
            .verify(
                &mut OsRng,
                &mut verifiers.ed,
                &mut verifiers.c1,
                &mut verifiers.c2,
                mo_tree,
                1,
                tx_hash,
                vec![mo_leaf.h_pqc],
            )
            .unwrap();
        assert!(
            !verifiers.all_valid(),
            "invalid membership-only proof borrowed slack from a valid full proof"
        );
    }

    // Polarity 2: invalid full + valid membership-only -> the shared batch rejects.
    {
        let mut verifiers = Verifiers::new();
        tamper_full(&full)
            .verify(
                &mut OsRng,
                &mut verifiers.ed,
                &mut verifiers.c1,
                &mut verifiers.c2,
                full_tree,
                1,
                tx_hash,
                vec![key_image],
                vec![full_leaf.h_pqc],
            )
            .unwrap();
        mo.verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            mo_tree,
            1,
            tx_hash,
            vec![mo_leaf.h_pqc],
        )
        .unwrap();
        assert!(
            !verifiers.all_valid(),
            "invalid full proof borrowed slack from a valid membership-only proof"
        );
    }

    // Control: both valid in one batch passes.
    {
        let mut verifiers = Verifiers::new();
        full.verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            full_tree,
            1,
            tx_hash,
            vec![key_image],
            vec![full_leaf.h_pqc],
        )
        .unwrap();
        mo.verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            mo_tree,
            1,
            tx_hash,
            vec![mo_leaf.h_pqc],
        )
        .unwrap();
        assert!(verifiers.all_valid());
    }
}

/// E-class: an empty input set rejects, never verifies vacuously-true.
#[test]
fn membership_only_empty_inputs_reject() {
    let leaf = make_leaf();
    let (tree, proof) = membership_only_proof([7; 32], b"empty", &[&leaf]);

    let empty = FcmpMembershipOnly::new(vec![], proof.fcmp.clone());
    let mut verifiers = Verifiers::new();
    let result = empty.verify(
        &mut OsRng,
        &mut verifiers.ed,
        &mut verifiers.c1,
        &mut verifiers.c2,
        tree,
        1,
        [7; 32],
        vec![],
    );
    assert!(matches!(result, Err(FcmpPlusPlusError::EmptyInputs)));
}

/// E-class index binding, component level: a MembershipSpendAuth proven for one input
/// index must not verify at another, even over the identical input tuple.
#[test]
fn membership_spend_auth_index_binding() {
    let leaf = make_leaf();
    let tx_hash = [8; 32];
    let rerandomized =
        membership_only_rerandomize(&mut OsRng, leaf.output, &leaf.x, b"index").unwrap();
    let opening = OpenedInputTuple::open(&rerandomized, &leaf.x, &leaf.y).unwrap();

    let msa = MembershipSpendAuth::prove(&mut OsRng, tx_hash, 0, &opening);

    let mut verifier = multiexp::BatchVerifier::new(1);
    msa.verify(&mut OsRng, &mut verifier, tx_hash, 1, &rerandomized.input());
    assert!(
        !verifier.verify_vartime(),
        "index binding failed: slot transplant verified"
    );
}

/// E-class blob swap, composition level: swapping two inputs' MembershipSpendAuth
/// blobs must fail verification.
#[test]
fn membership_only_blob_swap_rejects() {
    let leaf_a = make_leaf();
    let leaf_b = make_leaf();
    let tx_hash = [9; 32];
    let (tree, proof) = membership_only_proof(tx_hash, b"swap", &[&leaf_a, &leaf_b]);

    let mut inputs = proof.inputs.clone();
    let (msa_0, msa_1) = (inputs[0].1.clone(), inputs[1].1.clone());
    inputs[0].1 = msa_1;
    inputs[1].1 = msa_0;
    let swapped = FcmpMembershipOnly::new(inputs, proof.fcmp.clone());

    let mut verifiers = Verifiers::new();
    swapped
        .verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            tree,
            1,
            tx_hash,
            vec![leaf_a.h_pqc, leaf_b.h_pqc],
        )
        .unwrap();
    assert!(!verifiers.all_valid(), "blob swap verified");
}

/// Replay: a proof for one tx hash must not verify under another.
#[test]
fn membership_only_replay_rejects() {
    let leaf = make_leaf();
    let (tree, proof) = membership_only_proof([10; 32], b"replay", &[&leaf]);

    let mut verifiers = Verifiers::new();
    proof
        .verify(
            &mut OsRng,
            &mut verifiers.ed,
            &mut verifiers.c1,
            &mut verifiers.c2,
            tree,
            1,
            [11; 32],
            vec![leaf.h_pqc],
        )
        .unwrap();
    assert!(
        !verifiers.all_valid(),
        "proof verified under a different tx hash"
    );
}

/// Wrong root: a proof against one tree must not verify against another.
#[test]
fn membership_only_wrong_root_rejects() {
    let leaf = make_leaf();
    let tx_hash = [12; 32];
    let (_, proof) = membership_only_proof(tx_hash, b"root", &[&leaf]);

    let other_leaf = make_leaf();
    let other_rerandomized = RerandomizedOutput::new(&mut OsRng, other_leaf.output);
    let (other_tree, _) = tree_and_fcmp(&[&other_leaf], core::slice::from_ref(&other_rerandomized));

    let mut verifiers = Verifiers::new();
    let result = proof.verify(
        &mut OsRng,
        &mut verifiers.ed,
        &mut verifiers.c1,
        &mut verifiers.c2,
        other_tree,
        1,
        tx_hash,
        vec![leaf.h_pqc],
    );
    assert!(
        result.is_err() || !verifiers.all_valid(),
        "proof verified against the wrong tree root"
    );
}

/// Tamper: flipping a byte anywhere in the SAL-replacement region must fail.
#[test]
fn membership_only_tamper_rejects() {
    let leaf = make_leaf();
    let tx_hash = [13; 32];
    let (tree, proof) = membership_only_proof(tx_hash, b"tamper", &[&leaf]);
    let pseudo_outs = [proof.inputs[0].0.C_tilde().to_bytes()];

    let mut buf = vec![];
    proof.write(&mut buf).unwrap();

    // One byte in each of: O~, R_O, s_alpha, s_y.
    for index in [0, 96, 96 + 32, 96 + 64] {
        let mut tampered = buf.clone();
        tampered[index] ^= 1;
        match FcmpMembershipOnly::read(&pseudo_outs, 1, &mut tampered.as_slice()) {
            // A flip may produce a non-canonical point/scalar encoding.
            Err(_) => {}
            Ok(parsed) => {
                let mut verifiers = Verifiers::new();
                let result = parsed.verify(
                    &mut OsRng,
                    &mut verifiers.ed,
                    &mut verifiers.c1,
                    &mut verifiers.c2,
                    tree,
                    1,
                    tx_hash,
                    vec![leaf.h_pqc],
                );
                assert!(
                    result.is_err() || !verifiers.all_valid(),
                    "tampered proof (byte {index}) verified"
                );
            }
        }
    }
}
