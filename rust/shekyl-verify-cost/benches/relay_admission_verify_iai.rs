// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The **drift gate** for pool admission (BA-T1): the door's verification
//! sequence at the modal shape, measured as Callgrind instruction counts.
//!
//! The wall-clock instruments time the same work term by term:
//! `relay_admission_verify.rs` the masks and the proof over 64 cells, and
//! `block_connect_verify.rs`'s `block_connect_terms` group the hybrid
//! signature and the lone range proof. They are different instruments
//! serving different purposes (§72.6) and must not be conflated:
//!
//! - **Wall clock** is the `hop` input. It is hardware-dependent *on
//!   purpose*: the quantile is over the node population, so it is run on the
//!   reference machine **and** on the slow one, and the constant derives
//!   from the slow end.
//! - **Instruction counts** (here) are hardware-independent, so they fire
//!   from any runner. This is what makes *"`hop` moves when the door's
//!   verification moves"* an enforced invariant rather than a comment
//!   someone can miss: a change to any of the door's verifications shifts
//!   this count and trips the CI threshold, and the embargo re-derivation is
//!   then owed before the change lands.
//!
//! **What it times** is [`door_verify`]: CEN-H17's mask check, CEN-I18's
//! hybrid signature for the one input, CEN-I15's FCMP++ proof and CEN-H19's
//! range proof as a batch of one, in the door's order. Those are the three
//! terms of each `SPEC_VERIFY_COST` cell (BA-Q9, `DAEMON_RELAY_PRIVACY.md`
//! §72.2). CEN-I17's keccak derivation of the signing hash is not among
//! them: the fixture has no finished transaction to hash
//! (`shekyl_verify_cost::door`'s module docs).
//!
//! **Where that enforcement lives, because a gate nobody runs is a comment
//! with a harness.** This target is registered as an iai-only row in
//! `scripts/bench/capture_rust_baseline.sh`, which `ci/benchmarks` runs on
//! every PR; `scripts/bench/compare.py` gates on the `instructions` metric.
//! Its wall-clock twins are deliberately NOT registered: the admission
//! sweep is 64 cells measured on the reference machine and on the Pi, not a
//! per-PR job.
//!
//! **And how the gate finds this bench, because registration alone is not
//! routing.** `compare.py` routes each entry by function-name prefix; a name
//! outside its three classes is `unrouted` — reported, never failed — and the
//! paragraph above becomes a comment with a harness after all. The function
//! below is therefore named into the `crypto_bench_*` class
//! (`docs/benchmarks/shekyl_rust_v0.manifest.md` §11), and that class rather
//! than slowdown-only `hot_path_bench_*` **because its threshold is
//! bidirectional**: the failure mode `modal_shape` documents — a fixture that
//! stops verifying — presents as a dramatic instruction-count *drop*, which a
//! slowdown-only class would wave through as a pleasant result.
//!
//! Conflating them would give either a gate that flaps with runner hardware or
//! a number that cannot be gated.
//!
//! **Pinned to the admission path, not to a primitive.** The quantity is what
//! pool admission costs; a primitive-level gate drifts from it the moment the
//! calling code changes — `peers`' mirrored `#define` is the same failure
//! (§70.3).
//!
//! **One shape, deliberately.** The gate answers *"did the cost of verifying a
//! transaction move?"*, which needs a fixed workload, not a surface. The
//! surface is the wall-clock bench's job. `1-in / 2-out` is the modal shape and
//! the cheapest cell, so the gate is sensitive to the per-transaction floor
//! rather than to a tail cell nobody's traffic occupies.
//!
//! Requires `cargo install gungraun-runner` and a working Valgrind. Not run on
//! aarch64 — the slow arm is wall clock only.

// gungraun's `setup` hands the fixture in **by value** — that is the harness's
// contract, not a style choice: taking it by reference would put the fixture's
// construction inside the measured region and gate on the prover.
#![allow(clippy::needless_pass_by_value)]

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use shekyl_crypto_pq::kem::{SharedSecret, SHARED_SECRET_LEN};
use shekyl_crypto_pq::output::sign_pqc_auth_for_output_with_ml_dsa_seed;
use shekyl_crypto_pq::signature::{ML_DSA_SIGNING_SEED_LEN, SCHEME_DOMAIN_PQC_AUTH_TX};
use shekyl_types::SigningPayloadHash;
use shekyl_verify_cost::connect::{PqcAuthFixture, PQC_AUTH_FIXTURE_OUTPUT_INDEX};
use shekyl_verify_cost::door::{build_door_fixture_with, door_verify, DoorFixture, DoorStatus};
use shekyl_verify_cost::relay::ChunkLayout;

/// Fixed seed for the gate fixture's derivation. Its value has no cryptographic
/// meaning; it is pinned so the fixture — the FCMP++ proof included, which
/// `prove` would otherwise draw from `OsRng` — is **byte-identical** every run.
/// Callgrind instruction counts are deterministic only for identical inputs, so
/// without this the gate carried the proof's run-to-run variance (~0.19%,
/// measured on `dev` — #405 Finding C) as noise against its ±5%/±15% thresholds.
/// Mirrors the pinned-seed convention of
/// `shekyl-tx-builder/benches/transfer_e2e_iai.rs`, on [`ChaCha20Rng`] rather
/// than `rand`'s `StdRng`: `StdRng`'s algorithm is not promised across `rand`
/// releases, and a dependency bump that changed it would move the fixture and
/// with it the gate.
///
/// Pinning the fixture pins the whole verified input. `verify`'s batch
/// weights are derived from the values it reads (`shekyl-fcmp`
/// `batch_weights.rs`, ruling R3), and so are the range proof's
/// (`shekyl-bulletproofs` `derived.rs`), not drawn from the node's entropy,
/// so the variable-time multiexps inside the measured region see the same
/// scalars every run.
const BENCH_SEED: [u8; 32] = [
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
    0xBE, 0xEF, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE, //
];

/// The ML-DSA signing nonce. Production signing is hedged (`OsRng`), so a
/// signature made that way differs every run, and the Ed25519 half's
/// variable-time verify with it. Passed to
/// [`sign_pqc_auth_for_output_with_ml_dsa_seed`], the wallet signer's
/// assembly with a fixed nonce. `transfer_e2e_iai` fixes a nonce the same
/// way, through `sign_with_ml_dsa_seed`, on a key that bench draws itself.
/// The seeded entry is `shekyl-crypto-pq`'s `test-utils` surface, on this
/// crate's dev-dependency edge only.
const ML_DSA_SIGNING_SEED: [u8; ML_DSA_SIGNING_SEED_LEN] = [0x5e; ML_DSA_SIGNING_SEED_LEN];

/// The gate's one cell. One input and two outputs is the modal transaction
/// and the cheapest cell, so the count moves when the per-transaction floor
/// moves.
const MODAL_N_IN: usize = 1;
const MODAL_N_OUT: usize = 2;
/// Production's shallowest tree: a non-empty tree yields depth of at least 2.
const MODAL_TREE_DEPTH: u8 = 2;
const MODAL_LAYOUT: ChunkLayout = ChunkLayout::Shared;

/// One input's hybrid signature: the wallet signer's key, with the ML-DSA
/// nonce fixed. The combined shared secret is drawn from `rng`, so the key
/// is the seed's too. The signer wipes the derived key; the
/// [`SharedSecret`] wipes the shared secret when this returns.
fn seeded_auth(rng: &mut ChaCha20Rng, message: SigningPayloadHash) -> PqcAuthFixture {
    let mut combined_ss = SharedSecret([0u8; SHARED_SECRET_LEN]);
    rng.fill_bytes(&mut combined_ss.0);
    let signed = sign_pqc_auth_for_output_with_ml_dsa_seed(
        &combined_ss.0,
        PQC_AUTH_FIXTURE_OUTPUT_INDEX,
        SCHEME_DOMAIN_PQC_AUTH_TX,
        message.as_bytes(),
        &ML_DSA_SIGNING_SEED,
    )
    .expect("seeded hybrid sign");
    PqcAuthFixture {
        public_key: signed.hybrid_public_key,
        signature: signed.signature,
        message,
    }
}

// The gate's fixed shape.
fn modal_shape() -> DoorFixture {
    let mut rng = ChaCha20Rng::from_seed(BENCH_SEED);
    // `build_door_fixture_with` draws the admission fixture first on this
    // rng, then the signature, then the range proof. The admission operands
    // are the ones the gate timed when it counted those two alone.
    let fixture = build_door_fixture_with(
        &mut rng,
        MODAL_N_IN,
        MODAL_N_OUT,
        MODAL_TREE_DEPTH,
        MODAL_LAYOUT,
        seeded_auth,
    );
    // Self-witness, asserted HERE because setup is outside the measured region.
    // Without it, a fixture that stopped verifying would still produce a
    // plausible instruction count -- the early-return reject path, an order of
    // magnitude cheaper -- and the gate would present that as "verification got
    // dramatically faster", which is the shape a maintainer re-baselines rather
    // than investigates. Once re-baselined the gate measures the reject path
    // forever and can never again see a real change in verification cost.
    let status = door_verify(&fixture);
    assert!(
        status.verified(),
        "gate fixture must VERIFY, or the drift gate counts the reject path: {status:?}"
    );
    fixture
}

// Setup is excluded from the measured region: `prove` is orders of magnitude
// more expensive than `verify`, and it is not on the relay path at all. A
// bench that folded it in would gate on the prover and call it verification.
//
// The fixture is RETURNED rather than dropped here, for the same reason: a
// by-value fixture dropped inside the body charges its heap deallocations to
// the measured region, so the gate would move whenever the fixture's shape
// changed rather than when verification's cost did. Same artifact
// `shekyl-engine-state/benches/balance_iai.rs` documents at its own
// `-> (BalanceSummary, Vec<TransferDetails>)`, where the by-value drop was
// ~95 % of the count; there it was `zeroize`, here it would be `free`.
#[library_benchmark]
#[bench::modal(setup = modal_shape)]
fn crypto_bench_relay_admission_verify(fixture: DoorFixture) -> (DoorFixture, DoorStatus) {
    let status = black_box(door_verify(black_box(&fixture)));
    (fixture, status)
}

library_benchmark_group!(
    name = relay_admission_verify_group;
    benchmarks = crypto_bench_relay_admission_verify
);

main!(library_benchmark_groups = relay_admission_verify_group);
