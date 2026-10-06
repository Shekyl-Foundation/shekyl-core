// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `BA-T3`: what one served shard response costs `P`, as Callgrind
//! instruction counts — the per-PR drift gate on the archival serve path.
//!
//! The quantity is the work the serve loop does for one `GET /shard/{id}`:
//! parse, the anchor gate, every read of the body, every digest pass over
//! it, the countersignature, and the bytes written. It is pinned to the
//! serve's own steps rather than to the digest or the signer so that a
//! change in how many times the body is read or hashed moves this count;
//! that is the change this gate exists to see (the `SF-D8` v3 path reads
//! and digests each shard twice; `BA-Q3` rules a single pass that signs
//! last).
//!
//! Three shard sizes, because the cost has a fixed part (parse, gate, sign)
//! and a part linear in the body (read, digest, write), and a change to
//! either should show as such: one leaf, one eighth of a segment, and a full
//! segment, which is the size a bonded shard is served at.
//!
//! The store is in memory ([`ShardBody::flat`]). Store I/O is the floor
//! device's cost to measure (`BA-T5`); this gate is for what the serve loop
//! itself does per byte, and an on-disk store would put redb's read path
//! inside the count and make every store change a serve regression.
//!
//! **On the calling thread, into a buffer.** The endpoint runs its hops on
//! tokio's blocking pool, and Callgrind keeps one collection state per
//! thread: the pool's own idle work drifted the per-thread counts by up to
//! 14 % between runs of the same input, which no ±5 % threshold survives.
//! So the measured function is [`serve_one_in_memory`], the endpoint's own
//! steps composed in the endpoint's order on one thread, with no runtime
//! and no socket. `serve_tests.rs` asserts that composition and the live
//! endpoint produce the same bytes, so the glue cannot drift silently.
//!
//! Named into the `crypto_bench_*` class, so `scripts/bench/compare.py`
//! routes it to a bidirectional threshold: a serve that stops hashing or
//! stops signing presents as a dramatic instruction-count drop, which a
//! slowdown-only class would wave through.
//!
//! **Seeded, end to end.** The shard bytes, the persona key and the ML-DSA
//! signing nonce all come from one fixed seed. A fresh key or a hedged
//! signature moves ML-DSA's rejection-sampling trajectory, and with it the
//! count by tens of millions of instructions between runs of the same input
//! (measured: 14 M against 45 M for one leaf). The production signer is
//! hedged, as it should be; the gate pins one trajectory so that what moves
//! the count is the serve.
//!
//! Requires `cargo install gungraun-runner` and a working Valgrind. x86
//! only; the floor device is wall clock (`BA-T5`).

// gungraun's `setup` hands the fixture in by value; taking it by reference
// would put the fixture's construction inside the measured region.
#![allow(clippy::needless_pass_by_value)]

use std::hint::black_box;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH};
use fips204::ml_dsa_65;
use fips204::traits::SerDes as _;
use gungraun::{library_benchmark, library_benchmark_group, main};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use shekyl_archival_retention::pass_anchor::{pass_request_header_bytes, PASS_ANCHOR_DEPTH_BLOCKS};
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridSecretKey, HybridSignature, SCHEME_DOMAIN_ATTESTATION,
};
use shekyl_curve_tree::serving_route::encode_request_header;
use shekyl_curve_tree::{leaves_per_segment, LEAF_BYTES};
use shekyl_p_serve::{
    serve_one_in_memory, InMemoryServe, PassKey, PassSigner, ProviderError, ShardBody,
    ShardProvider, SignRefused, PASS_COUNTERSIGNATURE_MESSAGE_LEN, REQUEST_HEADER_NAME,
    SIGNATURE_ENVELOPE_LEN,
};
use shekyl_types::BlockHeight;

const OWN_HEIGHT: u64 = 10_000;
const SHARD_ID: u64 = 7;
const NONCE: [u8; 32] = [0x5a; 32];
const ANCHOR_HASH: [u8; 32] = [0xa5; 32];
const BENCH_SEED: [u8; 32] = [
    0x5e, 0x12, 0xa7, 0x03, 0xd4, 0x88, 0x3b, 0xc9, 0x61, 0xf0, 0x2e, 0x9d, 0x4a, 0xb6, 0x07,
    0xcc, //
    0x19, 0xe3, 0x7f, 0x50, 0xa2, 0x0b, 0xd8, 0x6c, 0x34, 0xf9, 0x81, 0x1d, 0xe6, 0x45, 0x9a,
    0x28, //
];
const ML_DSA_SEED: [u8; 32] = [0xa5; 32];

/// A persona signer whose key and ML-DSA nonce are fixed by [`BENCH_SEED`].
///
/// Same byte layout as `generate_ephemeral_keypair_for_tests` emits, built
/// the way `shekyl-tx-builder`'s seeded signing state is. Bench only: a
/// deterministic signature never reaches a wallet or a persona.
struct SeededSigner {
    secret: HybridSecretKey,
}

impl SeededSigner {
    fn new() -> Self {
        let mut rng = StdRng::from_seed(BENCH_SEED);
        let mut ed25519 = [0u8; ED25519_SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut ed25519);
        debug_assert_eq!(SigningKey::from_bytes(&ed25519).to_bytes(), ed25519);
        let (_public, ml_dsa) = ml_dsa_65::try_keygen_with_rng(&mut rng).expect("seeded keygen");
        Self {
            secret: HybridSecretKey {
                ed25519: ed25519.to_vec(),
                ml_dsa: ml_dsa.into_bytes().to_vec(),
            },
        }
    }
}

impl PassKey for SeededSigner {
    fn ready(&self, _shard_id: u64, _anchor_height: BlockHeight) -> Result<(), SignRefused> {
        Ok(())
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        HybridEd25519MlDsa
            .sign_with_ml_dsa_seed(
                &self.secret,
                SCHEME_DOMAIN_ATTESTATION,
                message,
                &ML_DSA_SEED,
            )
            .map_err(|e| SignRefused::new(e.to_string()))
    }
}

impl PassSigner for SeededSigner {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

/// One shard, in memory, at the leaf count the fixture asked for.
struct OneShard {
    bytes: Arc<[u8]>,
}

impl ShardProvider for OneShard {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        if shard_id != SHARD_ID {
            return Ok(None);
        }
        Ok(ShardBody::flat(Arc::clone(&self.bytes)))
    }
}

/// The provider, the signer, one request head, and a buffer sized for the
/// response, built in `setup` outside the measured region.
struct Fixture {
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    head: Vec<u8>,
    out: Vec<u8>,
    expected_len: usize,
}

fn fixture(leaf_count: usize) -> Fixture {
    let mut body = vec![0u8; leaf_count * LEAF_BYTES];
    StdRng::from_seed(BENCH_SEED).fill_bytes(&mut body);
    let provider: Arc<dyn ShardProvider> = Arc::new(OneShard {
        bytes: Arc::from(body.into_boxed_slice()),
    });
    let signer: Arc<dyn PassSigner> = Arc::new(SeededSigner::new());
    let anchor = BlockHeight::from_raw(OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw());
    let header = pass_request_header_bytes(&NONCE, anchor, &ANCHOR_HASH);
    let head = format!(
        "GET /shard/{SHARD_ID} HTTP/1.1\r\nhost: x\r\n{REQUEST_HEADER_NAME}: {}\r\n\r\n",
        encode_request_header(&header)
    )
    .into_bytes();
    // Self-witness, asserted here because setup is outside the measured
    // region: the fixture must SERVE, or the gate counts the 404 path and a
    // serve that stopped working reads as a large speed-up.
    let mut witness = Vec::new();
    let outcome = serve_one_in_memory(&*provider, &*signer, &head, &mut witness);
    assert_eq!(
        outcome,
        InMemoryServe::Served,
        "gate fixture must serve, or the drift gate counts the miss path"
    );
    assert!(
        witness.starts_with(b"HTTP/1.1 200 OK\r\n")
            && witness.len() > leaf_count * LEAF_BYTES + SIGNATURE_ENVELOPE_LEN,
        "a served response is a 200 carrying the frame, the body and the envelope"
    );
    let expected_len = witness.len();
    Fixture {
        provider,
        signer,
        head,
        // Pre-sized so the buffer's growth is not what the gate measures.
        out: Vec::with_capacity(expected_len),
        expected_len,
    }
}

fn one_leaf() -> Fixture {
    fixture(1)
}

fn eighth_segment() -> Fixture {
    fixture(leaves_per_segment() / 8)
}

fn full_segment() -> Fixture {
    fixture(leaves_per_segment())
}

// The fixture is returned rather than dropped inside the body, so that
// freeing the shard, the key and the response buffer is not charged to the
// serve.
#[library_benchmark]
#[bench::one_leaf(setup = one_leaf)]
#[bench::eighth_segment(setup = eighth_segment)]
#[bench::full_segment(setup = full_segment)]
fn crypto_bench_serve_response(mut fx: Fixture) -> Fixture {
    let outcome = serve_one_in_memory(
        black_box(&*fx.provider),
        black_box(&*fx.signer),
        black_box(&fx.head),
        &mut fx.out,
    );
    assert_eq!(
        black_box(outcome),
        InMemoryServe::Served,
        "the serve must complete"
    );
    assert_eq!(fx.out.len(), fx.expected_len, "the serve must be whole");
    fx
}

library_benchmark_group!(
    name = serve_response_group;
    benchmarks = crypto_bench_serve_response
);

main!(library_benchmark_groups = serve_response_group);
