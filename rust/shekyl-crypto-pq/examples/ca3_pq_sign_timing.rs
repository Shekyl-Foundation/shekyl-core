// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CA-3, ML-DSA-65 and SLH-DSA-SHA2-192s: does the signing time of
//! Shekyl's transaction authorisation and message signature depend on the
//! secret they sign under? (`docs/design/CRYPTO_AUDIT.md` §3.2, §3.3.)
//!
//! # What is timed: the shipped entries, derivation included
//!
//! - `ml-dsa`: `sign_pqc_auth_for_output`, through its seeded twin
//!   `sign_pqc_auth_for_output_with_ml_dsa_seed`. One call derives the
//!   output's hybrid key from the transaction's combined shared secret, signs
//!   the input's payload hash under `SCHEME_DOMAIN_PQC_AUTH_TX` and wipes the
//!   key. The secret is the combined shared secret. The seeded twin differs
//!   from the wallet's entry only in where the 32-byte ML-DSA nonce comes
//!   from, so that every entry's nonce is drawn alike in both classes.
//! - `slh-dsa`: `sign_message_pq_half`, as the wallet calls it. One call
//!   derives the message-signing identity from the master seed and makes a
//!   hedged SLH-DSA signature with the OS's randomness, as shipped. The
//!   secret is the master seed. The message is fixed (one network, one
//!   bound segment, one message), so the only per-signature variation is
//!   the hedge's `opt_rand`.
//!
//! Both entries derive their key on every call, so a fixed class and a
//! varied class write the same amount of key material to the same places;
//! they differ only in its value.
//!
//! # Method (after `dudect`, as RT-P4 and CA-3's FN-DSA run)
//!
//! Two classes are interleaved by a coin drawn before the loop, each
//! signature is timed alone, and the two timing distributions are compared
//! with Welch's t on the raw samples and below each of 100 cut-offs placed
//! from a discarded calibration batch (1 % of the samples). A cut-off counts
//! when both classes keep more than 1 % of the samples below it. The
//! reported figure is the largest `|t|`.
//!
//! ML-DSA's rejection loop restarts a signature a varying number of times
//! (about 5 attempts on average at ML-DSA-65), and the count cannot be read
//! from outside the crate. Its distribution is the same in both classes
//! unless it depends on the key. A key-dependent count moves the raw mean
//! and the upper quantiles; a key-dependent attempt moves the low cut-offs,
//! which keep mostly single-attempt signatures. Both are read.
//!
//! # The lines
//!
//! - `fixed-vs-varied`: one secret against a fresh secret per entry.
//! - `fixed-a-vs-fixed-b`: two fixed secrets.
//!
//! **Nulls:** `fixed-a-vs-fixed-a` and `varied-vs-varied` (both classes
//! fresh per entry, from one distribution). **Control:** the first null
//! with work of [`CONTROL_LEAK_FRACTION`] of a signature's median time
//! planted in class 1, on a null so no real effect adds to or cancels it. **Checks:** every timed call
//! returned a signature, and every kept signature verifies under its key
//! (every signature for `slh-dsa`; one in [`KEEP_EVERY`] for `ml-dsa`,
//! whose signatures are too many to hold).
//!
//! Run: `cargo run --release --locked -p shekyl-crypto-pq --example
//! ca3_pq_sign_timing -- MODE [SAMPLES [SEED]]`, MODE `ml-dsa` or
//! `slh-dsa`.

// Statistics over sample counts and nanosecond timings: every value is far
// below 2^52, so the float conversions lose nothing, and the truncations are
// of non-negative quantities already bounded by the sample count.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::time::Instant;

use fips205::traits::Verifier as _;
use shekyl_address::{BoundClassicalSegment, ADDRESS_VERSION_V1, PQC_PAYLOAD_LEN};
use shekyl_crypto_pq::account::{Network, MASTER_SEED_BYTES};
use shekyl_crypto_pq::kem::SHARED_SECRET_LEN;
use shekyl_crypto_pq::message_signing::{
    derive_message_signing_identity, message_preimage, sign_message_pq_half, SLH_192S_PK_LEN,
};
use shekyl_crypto_pq::output::sign_pqc_auth_for_output_with_ml_dsa_seed;
use shekyl_crypto_pq::signature::{
    HybridEd25519MlDsa, HybridPublicKey, HybridSignature, SignatureScheme as _,
    ML_DSA_SIGNING_SEED_LEN, SCHEME_DOMAIN_PQC_AUTH_TX,
};

/// `|t|` below this on every cut-off is "no evidence of a leak"; dudect's
/// own bound.
const T_PASS: f64 = 4.5;
/// `|t|` above this is a leak beyond reasonable doubt; the control must
/// exceed it.
const T_LEAK: f64 = 10.0;
/// The planted leak, as a fraction of one signature's median time.
const CONTROL_LEAK_FRACTION: f64 = 0.005;
/// Cut-offs, as in dudect: `1 - 0.5^(10 (i + 1) / CROPS)` quantiles.
const CROPS: usize = 100;
/// The least a cut-off must keep per class, as a divisor of the sample
/// count (1 %).
const CROPPED_FLOOR_DIVISOR: usize = 100;
/// The discarded calibration batch that places the cut-offs, as a divisor
/// of the sample count: 1 % for `ml-dsa`; 10 % for `slh-dsa`, whose 2,000
/// samples would leave 20, too few to place 100 cut-offs (ruled 2026-11-21).
const ML_DSA_CALIBRATION_DIVISOR: usize = 100;
const SLH_DSA_CALIBRATION_DIVISOR: usize = 10;
/// `slh-dsa`'s registered size: 1,000 signatures per class (ruled
/// 2026-11-21; the registration's Assumption gives the basis).
const SLH_DSA_SAMPLES: usize = 2_000;
/// The noise calibration's size, `slh-dsa-noise`: the a/a null alone.
const SLH_DSA_NOISE_SAMPLES: usize = 200;
/// The control the noise calibration recommends: δ = 15 · σ · √(2/1000).
const SLH_DSA_CONTROL_SIGMAS: f64 = 15.0;
const SLH_DSA_CLASS_SIZE: f64 = 1_000.0;
/// `ml-dsa` keeps one signature in this many for verification after the
/// loop. Every signature is checked to have been returned.
const KEEP_EVERY: usize = 64;
/// The input seed of the registered runs. No run before the registration
/// drew from it.
const REGISTERED_SEED: u64 = 0x4341_335f_4d4c_534c;
/// The payload hash a transaction input signs (`SigningPayloadHash`).
const PAYLOAD_HASH_LEN: usize = 32;
/// The message the `slh-dsa` mode signs, fixed for every entry.
const SLH_MESSAGE: &[u8] = b"CA-3 SLH-DSA timing: one fixed message";

/// SplitMix64: test inputs only, reproducible from a seed.
struct Inputs(u64);

impl Inputs {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        out
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    MlDsa,
    SlhDsa,
    /// `slh-dsa`'s per-device noise calibration: the a/a null alone.
    SlhDsaNoise,
    /// Diagnostic, not a registered line: ML-DSA's matched pair with key
    /// generation alone timed (the output's seed derivation and
    /// `keygen_from_seed`).
    MlDsaKeygen,
    /// Diagnostic, not a registered line: ML-DSA's matched pair with signing
    /// alone timed (fips204's `try_sign_with_seed` on keys generated before
    /// the loop).
    MlDsaSign,
}

/// A class's secrets: one secret for every entry, or a fresh one per entry.
#[derive(Clone, Copy)]
enum Secrets<const S: usize> {
    Fixed(&'static str, [u8; S]),
    Varied(&'static str),
}

impl<const S: usize> Secrets<S> {
    fn name(&self) -> &'static str {
        match self {
            Self::Fixed(name, _) | Self::Varied(name) => name,
        }
    }

    fn draw(&self, inputs: &mut Inputs) -> [u8; S] {
        match self {
            Self::Fixed(_, secret) => *secret,
            Self::Varied(_) => inputs.array(),
        }
    }
}

/// One entry: its class, its secret, and the per-signature inputs.
struct Entry<const S: usize> {
    class: u8,
    secret: [u8; S],
    message: [u8; PAYLOAD_HASH_LEN],
    nonce_seed: [u8; ML_DSA_SIGNING_SEED_LEN],
}

/// Online mean and variance.
#[derive(Clone, Copy, Default)]
struct Moments {
    n: f64,
    mean: f64,
    m2: f64,
}

impl Moments {
    fn push(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        self.m2 += delta * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        if self.n < 2.0 {
            0.0
        } else {
            self.m2 / (self.n - 1.0)
        }
    }
}

fn welch_t(a: &Moments, b: &Moments) -> f64 {
    let spread = a.variance() / a.n + b.variance() / b.n;
    if a.n < 2.0 || b.n < 2.0 || spread <= 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / spread.sqrt()
}

/// One comparison's sample count, discarded calibration batch, and the
/// least a cut-off must keep per class.
#[derive(Clone, Copy)]
struct Sizing {
    samples: usize,
    calibration: usize,
    min_cropped: usize,
}

impl Sizing {
    fn new(samples: usize, calibration_divisor: usize) -> Self {
        Sizing {
            samples,
            calibration: samples / calibration_divisor,
            min_cropped: samples / CROPPED_FLOOR_DIVISOR,
        }
    }
}

struct Outcome {
    /// The standard deviation of the measured per-signature times, both
    /// classes together (the `slh-dsa-noise` calibration reads it).
    raw_sd_ns: f64,
    max_t: f64,
    median_ns: f64,
    samples: [f64; 2],
    checks_hold: bool,
}

/// The fixed message's bound segment: a v1 classical segment with every key
/// field drawn, and a drawn encapsulation key. Public data; it only frames
/// the preimage.
fn segment(inputs: &mut Inputs) -> BoundClassicalSegment {
    let mut classical = vec![ADDRESS_VERSION_V1];
    classical.extend_from_slice(&inputs.array::<32>());
    classical.extend_from_slice(&inputs.array::<32>());
    classical.extend_from_slice(&inputs.array::<SLH_192S_PK_LEN>());
    let mut ek = vec![0u8; PQC_PAYLOAD_LEN];
    for chunk in ek.chunks_mut(8) {
        let bytes = inputs.next().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    BoundClassicalSegment::from_address_parts(&classical, &ek)
        .expect("a v1 segment of the right lengths assembles")
}

/// Statistics over the loop's times, read as RT-P4 reads them.
fn statistics(which: &[u8], times: &[u64], sizing: Sizing) -> (f64, f64, [f64; 2]) {
    let calibration_len = sizing.calibration;
    let min_cropped = sizing.min_cropped as f64;
    let mut calibration: Vec<f64> = times[..calibration_len].iter().map(|&t| t as f64).collect();
    calibration.sort_by(f64::total_cmp);
    let median_ns = calibration[calibration_len / 2];
    let cutoffs: Vec<f64> = (0..CROPS)
        .map(|i| {
            let quantile = 1.0 - 0.5f64.powf(10.0 * (i as f64 + 1.0) / CROPS as f64);
            let index = ((quantile * calibration_len as f64) as usize).min(calibration_len - 1);
            calibration[index]
        })
        .collect();
    let mut raw = [Moments::default(); 2];
    let mut cropped = vec![[Moments::default(); 2]; CROPS];
    let mut by_class: [Vec<u64>; 2] = [Vec::new(), Vec::new()];
    for index in calibration_len..times.len() {
        let class = usize::from(which[index]);
        let ns = times[index] as f64;
        raw[class].push(ns);
        by_class[class].push(times[index]);
        for (cutoff, moments) in cutoffs.iter().zip(cropped.iter_mut()) {
            if ns < *cutoff {
                moments[class].push(ns);
            }
        }
    }
    by_class[0].sort_unstable();
    by_class[1].sort_unstable();
    for q in [1usize, 5, 10, 25, 50, 75, 90, 95, 99] {
        let a = by_class[0][by_class[0].len() * q / 100];
        let b = by_class[1][by_class[1].len() * q / 100];
        println!(
            "  quantile={q} class0={a} class1={b} diff={}",
            i128::from(a) - i128::from(b)
        );
    }
    println!(
        "  crop=raw n0={:.0} n1={:.0} mean0={:.1} mean1={:.1} diff={:.1} t={:.2}",
        raw[0].n,
        raw[1].n,
        raw[0].mean,
        raw[1].mean,
        raw[0].mean - raw[1].mean,
        welch_t(&raw[0], &raw[1])
    );
    let mut max_t = welch_t(&raw[0], &raw[1]).abs();
    let mut at = usize::MAX;
    for (i, moments) in cropped.iter().enumerate() {
        let enough = moments[0].n > min_cropped && moments[1].n > min_cropped;
        let t = welch_t(&moments[0], &moments[1]);
        if enough && t.abs() > max_t {
            max_t = t.abs();
            at = i;
        }
    }
    if at == usize::MAX {
        println!("  max_at_crop=raw");
    } else {
        let m = &cropped[at];
        println!(
            "  max_at_crop={at} cutoff={:.0} n0={:.0} n1={:.0} diff={:.1} t={:.2}",
            cutoffs[at],
            m[0].n,
            m[1].n,
            m[0].mean - m[1].mean,
            welch_t(&m[0], &m[1])
        );
    }
    (max_t, median_ns, [raw[0].n, raw[1].n])
}

/// One `ml-dsa` comparison. Inputs are prepared before the loop; the loop
/// times the shipped entry and nothing else.
fn compare_ml_dsa(
    classes: [Secrets<SHARED_SECRET_LEN>; 2],
    sizing: Sizing,
    inputs: &mut Inputs,
    planted: Option<u64>,
) -> Outcome {
    let total = sizing.samples + sizing.calibration;
    let entries: Vec<Entry<SHARED_SECRET_LEN>> = (0..total)
        .map(|_| {
            let class = u8::from(inputs.next() & 1 == 1);
            Entry {
                class,
                secret: classes[usize::from(class)].draw(inputs),
                message: inputs.array(),
                nonce_seed: inputs.array(),
            }
        })
        .collect();
    let mut times = vec![0u64; total];
    let mut returned = 0usize;
    let mut kept = Vec::with_capacity(total / KEEP_EVERY + 1);
    for (index, entry) in entries.iter().enumerate() {
        let start = Instant::now();
        let result = sign_pqc_auth_for_output_with_ml_dsa_seed(
            black_box(&entry.secret),
            0,
            SCHEME_DOMAIN_PQC_AUTH_TX,
            &entry.message,
            &entry.nonce_seed,
        );
        if let Some(iterations) = planted {
            if entry.class == 1 {
                spin(iterations);
            }
        }
        times[index] = start.elapsed().as_nanos() as u64;
        if let Ok(signature) = result {
            returned += 1;
            if index % KEEP_EVERY == 0 {
                kept.push((index, signature));
            }
        }
    }
    let scheme = HybridEd25519MlDsa;
    let verified = kept
        .iter()
        .filter(|(index, signature)| {
            let public = HybridPublicKey::from_canonical_bytes(&signature.hybrid_public_key);
            let sig = HybridSignature::from_canonical_bytes(&signature.signature);
            matches!((public, sig), (Ok(public), Ok(sig))
                if scheme.verify(&public, SCHEME_DOMAIN_PQC_AUTH_TX, &entries[*index].message, &sig).is_ok())
        })
        .count();
    let checks_hold = returned == total && verified == kept.len();
    println!(
        "  check entries={total} returned={returned} kept={} verified={verified} verdict={}",
        kept.len(),
        if checks_hold { "as-intended" } else { "FAILED" }
    );
    let which: Vec<u8> = entries.iter().map(|e| e.class).collect();
    let (max_t, median_ns, n) = statistics(&which, &times, sizing);
    Outcome {
        raw_sd_ns: raw_sd(&times[sizing.calibration..]),
        max_t,
        median_ns,
        samples: n,
        checks_hold,
    }
}

/// One `slh-dsa` comparison, as [`compare_ml_dsa`], over the master seed.
fn compare_slh_dsa(
    classes: [Secrets<MASTER_SEED_BYTES>; 2],
    sizing: Sizing,
    inputs: &mut Inputs,
    segment: &BoundClassicalSegment,
    planted: Option<u64>,
) -> Outcome {
    const NETWORK: Network = Network::Testnet;
    let total = sizing.samples + sizing.calibration;
    let entries: Vec<(u8, [u8; MASTER_SEED_BYTES])> = (0..total)
        .map(|_| {
            let class = u8::from(inputs.next() & 1 == 1);
            (class, classes[usize::from(class)].draw(inputs))
        })
        .collect();
    let mut times = vec![0u64; total];
    let mut signatures = Vec::with_capacity(total);
    for (index, (class, seed)) in entries.iter().enumerate() {
        let start = Instant::now();
        let result = sign_message_pq_half(black_box(seed), NETWORK, segment, SLH_MESSAGE);
        if let Some(iterations) = planted {
            if *class == 1 {
                spin(iterations);
            }
        }
        times[index] = start.elapsed().as_nanos() as u64;
        signatures.push(result.ok());
    }
    let preimage = message_preimage(NETWORK, segment.as_bytes(), SLH_MESSAGE);
    let mut returned = 0usize;
    let mut verified = 0usize;
    for ((_, seed), result) in entries.iter().zip(&signatures) {
        let Some((framed, signature)) = result else {
            continue;
        };
        returned += 1;
        let Ok((public, _)) = derive_message_signing_identity(seed, NETWORK) else {
            continue;
        };
        if framed.as_bytes() == preimage.as_bytes()
            && public.verify(preimage.as_bytes(), signature, b"")
        {
            verified += 1;
        }
    }
    let checks_hold = returned == total && verified == total;
    println!(
        "  check entries={total} returned={returned} verified={verified} verdict={}",
        if checks_hold { "as-intended" } else { "FAILED" }
    );
    let which: Vec<u8> = entries.iter().map(|(class, _)| *class).collect();
    let (max_t, median_ns, n) = statistics(&which, &times, sizing);
    Outcome {
        raw_sd_ns: raw_sd(&times[sizing.calibration..]),
        max_t,
        median_ns,
        samples: n,
        checks_hold,
    }
}

/// The sample standard deviation of `times`, in nanoseconds.
fn raw_sd(times: &[u64]) -> f64 {
    let mut moments = Moments::default();
    for &t in times {
        moments.push(t as f64);
    }
    moments.variance().sqrt()
}

/// Burn roughly `iterations` steps of work the optimizer cannot remove.
fn spin(iterations: u64) {
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..iterations {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        black_box(x);
    }
}

/// How many `spin` iterations take `target_ns`.
fn calibrate_spin(target_ns: f64) -> u64 {
    let probe = 1_000_000u64;
    let start = Instant::now();
    spin(probe);
    let per_iteration = start.elapsed().as_nanos() as f64 / probe as f64;
    ((target_ns / per_iteration).round() as u64).max(1)
}

/// The word a comparison's `|t|` earns against the lines.
fn verdict(t: f64) -> &'static str {
    if t < T_PASS {
        "no-evidence"
    } else if t > T_LEAK {
        "LEAK"
    } else {
        "INCONCLUSIVE"
    }
}

/// ML-DSA-65's matched pair (ruled 2026-11-21): a replica of the work
/// fips204 0.5.0's key generation does by design, so two keys can be chosen
/// that do the same amount of it.
///
/// Shekyl's call generates the key inside every signature, so ExpandS
/// (`hashing.rs:313-335`, rejection-sampling the secret coefficients from
/// ρ′) and ExpandA (`hashing.rs:286-300`, from the public ρ) run inside the
/// timed operation. Two keys consume different numbers of ExpandS bytes and
/// reject different numbers of ExpandA triples. That difference is by
/// design and carries nothing about the key's kept coefficients, but it is
/// a constant per key, and a fixed pair would read it at enough samples.
/// The pass line's two keys are therefore matched on both counts.
mod ml_dsa_replica {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::{Shake128, Shake256};

    use shekyl_crypto_pq::derivation::keygen_from_seed;
    use shekyl_crypto_pq::kem::SHARED_SECRET_LEN;
    use shekyl_crypto_pq::output::output_ml_dsa_seed_for_tests;
    use shekyl_crypto_pq::seeded_rng::SeededRng;

    use fips204::traits::SerDes as _;
    use rand::RngCore as _;

    /// ML-DSA-65's (k, ℓ) and η (FIPS 204 Table 1).
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i64 = 4;
    const N: usize = 256;
    const Q: i64 = 8_380_417;
    /// ζ, the 512th root of unity mod q (FIPS 204 §7.5).
    const ZETA: i64 = 1753;
    /// 256⁻¹ mod q, the inverse NTT's final factor (FIPS 204 Alg 42).
    const N_INV: i64 = 8_347_681;
    /// Power2Round's d.
    const D: u32 = 13;
    /// t1's packed width, bits per coefficient (FIPS 204 Alg 22).
    const T1_BITS: usize = 10;
    const RHO_LEN: usize = 32;
    /// ρ, K and tr precede s1 in the secret-key encoding (FIPS 204 Alg 24).
    const SK_S1_OFFSET: usize = 32 + 32 + 64;
    /// One η = 4 polynomial packed at 4 bits a coefficient.
    const SK_POLY_LEN: usize = N / 2;

    /// What one key's generation does by design, and whether the replica
    /// agrees with fips204's own key.
    pub struct KeyWork {
        /// Bytes ExpandS consumed, summed over s1 and s2's 11 polynomials.
        pub expand_s_bytes: usize,
        /// Triples ExpandA rejected, summed over Â's 30 entries.
        pub expand_a_rejected: usize,
        /// The replica's ρ and K are the key's, its s1 and s2 are the key's
        /// encoded ones, and the t1 it recomputes is the public key's.
        pub replicates: bool,
    }

    /// The replica over the output key `sign_pqc_auth_for_output` derives
    /// from `combined_ss` at output 0, checked against fips204's own.
    pub fn key_work(combined_ss: &[u8; SHARED_SECRET_LEN]) -> KeyWork {
        let seed = output_ml_dsa_seed_for_tests(combined_ss, 0);
        // ξ: fips204 draws 32 bytes from the RNG (`ml_dsa.rs:51-52`), and
        // Shekyl's RNG is the ChaCha20 stream over the seed
        // (`derivation.rs:44-45`).
        let mut xi = [0u8; 32];
        SeededRng::from_seed(&seed).fill_bytes(&mut xi);
        // (ρ, ρ′, K) ← H(ξ ‖ k ‖ ℓ, 128) (`ml_dsa.rs:79-83`).
        let mut expanded = [0u8; 128];
        let mut h = Shake256::default();
        h.update(&xi);
        h.update(&[K as u8, L as u8]);
        h.finalize_xof().read(&mut expanded);
        let (rho, rest) = expanded.split_at(RHO_LEN);
        let (rho_prime, cap_k) = rest.split_at(64);

        let (expand_s_bytes, nibbles) = expand_s(rho_prime);
        let (expand_a_rejected, a_hat) = expand_a(rho);

        let replicates = match keygen_from_seed(&seed) {
            Ok((pk, sk)) => {
                let (pk, sk) = (pk.into_bytes(), sk.into_bytes());
                let s_encoded = &sk[SK_S1_OFFSET..SK_S1_OFFSET + (K + L) * SK_POLY_LEN];
                pk[..RHO_LEN] == *rho
                    && sk[RHO_LEN..2 * RHO_LEN] == *cap_k
                    && packed_nibbles(&nibbles) == s_encoded
                    && t1_packed(&a_hat, &nibbles) == pk[RHO_LEN..]
            }
            Err(_) => false,
        };
        KeyWork {
            expand_s_bytes,
            expand_a_rejected,
            replicates,
        }
    }

    /// ExpandS (`hashing.rs:313-335`) through RejBoundedPoly
    /// (`hashing.rs:205-262`): per polynomial r, SHAKE256(ρ′ ‖ r ‖ 0), one
    /// byte at a time, its low then high nibble kept if below 9 (η = 4,
    /// `conversion.rs:80-95`), the high one only while fewer than 256 are
    /// kept. Returns the bytes consumed and every kept nibble, s1's five
    /// polynomials then s2's six.
    fn expand_s(rho_prime: &[u8]) -> (usize, Vec<[u8; N]>) {
        let mut consumed = 0;
        let mut polys = Vec::with_capacity(K + L);
        for r in 0..(K + L) {
            let mut h = Shake256::default();
            h.update(rho_prime);
            h.update(&[r as u8, 0]);
            let mut reader = h.finalize_xof();
            let mut kept = [0u8; N];
            let mut j = 0;
            while j < N {
                let mut z = [0u8; 1];
                reader.read(&mut z);
                consumed += 1;
                for nibble in [z[0] & 0x0f, z[0] >> 4] {
                    if nibble < 9 && j < N {
                        kept[j] = nibble;
                        j += 1;
                    }
                }
            }
            polys.push(kept);
        }
        (consumed, polys)
    }

    /// ExpandA (`hashing.rs:286-300`) through RejNTTPoly
    /// (`hashing.rs:153-190`): per entry (r, s), SHAKE128(ρ ‖ s ‖ r), three
    /// bytes at a time, the top bit of the third cleared, kept if below q
    /// (`conversion.rs:40-52`). Returns the triples rejected and Â.
    fn expand_a(rho: &[u8]) -> (usize, Vec<Vec<[i64; N]>>) {
        let mut rejected = 0;
        let mut a_hat = Vec::with_capacity(K);
        for r in 0..K {
            let mut row = Vec::with_capacity(L);
            for s in 0..L {
                let mut h = Shake128::default();
                h.update(rho);
                h.update(&[s as u8, r as u8]);
                let mut reader = h.finalize_xof();
                let mut poly = [0i64; N];
                let mut j = 0;
                while j < N {
                    let mut b = [0u8; 3];
                    reader.read(&mut b);
                    let z =
                        (i64::from(b[2] & 0x7f) << 16) | (i64::from(b[1]) << 8) | i64::from(b[0]);
                    if z < Q {
                        poly[j] = z;
                        j += 1;
                    } else {
                        rejected += 1;
                    }
                }
                row.push(poly);
            }
            a_hat.push(row);
        }
        (rejected, a_hat)
    }

    /// The kept nibbles as the secret key packs them: two a byte, the
    /// first in the low half. A kept nibble b is the coefficient η − b, and
    /// BitPack stores η − coefficient (FIPS 204 Alg 17), which is b again.
    fn packed_nibbles(polys: &[[u8; N]]) -> Vec<u8> {
        polys
            .iter()
            .flat_map(|poly| poly.chunks(2).map(|pair| pair[0] | (pair[1] << 4)))
            .collect()
    }

    fn zetas() -> [i64; N] {
        let mut zetas = [0i64; N];
        for (k, zeta) in zetas.iter_mut().enumerate() {
            let exponent = (k as u8).reverse_bits();
            *zeta = (0..exponent).fold(1i64, |acc, _| acc * ZETA % Q);
        }
        zetas
    }

    /// FIPS 204 Alg 41.
    fn ntt(w: &mut [i64; N], zetas: &[i64; N]) {
        let (mut m, mut len) = (0, 128);
        while len >= 1 {
            let mut start = 0;
            while start < N {
                m += 1;
                let z = zetas[m];
                for j in start..start + len {
                    let t = z * w[j + len] % Q;
                    w[j + len] = (w[j] - t).rem_euclid(Q);
                    w[j] = (w[j] + t) % Q;
                }
                start += 2 * len;
            }
            len /= 2;
        }
    }

    /// FIPS 204 Alg 42.
    fn ntt_inverse(w: &mut [i64; N], zetas: &[i64; N]) {
        let (mut m, mut len) = (N, 1);
        while len < N {
            let mut start = 0;
            while start < N {
                m -= 1;
                let z = Q - zetas[m];
                for j in start..start + len {
                    let t = w[j];
                    w[j] = (t + w[j + len]) % Q;
                    w[j + len] = (t - w[j + len]).rem_euclid(Q) * z % Q;
                }
                start += 2 * len;
            }
            len *= 2;
        }
        for c in w.iter_mut() {
            *c = *c * N_INV % Q;
        }
    }

    /// t = NTT⁻¹(Â ∘ NTT(s1)) + s2, then t1 from Power2Round (FIPS 204 Alg
    /// 6 steps 5-6, Alg 35), packed at 10 bits a coefficient as the public
    /// key holds it (Alg 22).
    fn t1_packed(a_hat: &[Vec<[i64; N]>], nibbles: &[[u8; N]]) -> Vec<u8> {
        let zetas = zetas();
        let coefficients = |poly: &[u8; N]| -> [i64; N] {
            let mut c = [0i64; N];
            for (out, b) in c.iter_mut().zip(poly) {
                *out = (ETA - i64::from(*b)).rem_euclid(Q);
            }
            c
        };
        let s1_hat: Vec<[i64; N]> = nibbles[..L]
            .iter()
            .map(|poly| {
                let mut c = coefficients(poly);
                ntt(&mut c, &zetas);
                c
            })
            .collect();
        let mut bits = Vec::with_capacity(K * N * T1_BITS);
        for (r, row) in a_hat.iter().enumerate() {
            let mut t = [0i64; N];
            for (entry, s) in row.iter().zip(&s1_hat) {
                for i in 0..N {
                    t[i] = (t[i] + entry[i] * s[i]) % Q;
                }
            }
            ntt_inverse(&mut t, &zetas);
            let s2 = coefficients(&nibbles[L + r]);
            for i in 0..N {
                let plus = (t[i] + s2[i]) % Q;
                let mut low = plus % (1 << D);
                if low > 1 << (D - 1) {
                    low -= 1 << D;
                }
                let t1 = (plus - low) >> D;
                for bit in 0..T1_BITS {
                    bits.push(((t1 >> bit) & 1) as u8);
                }
            }
        }
        bits.chunks(8)
            .map(|byte| {
                byte.iter()
                    .enumerate()
                    .fold(0u8, |acc, (i, b)| acc | (b << i))
            })
            .collect()
    }
}

/// Draw candidate secrets from `inputs` until two do the same by-design
/// work; return the first such pair in draw order and the number drawn.
fn matched_ml_dsa_pair(
    inputs: &mut Inputs,
) -> (
    [u8; SHARED_SECRET_LEN],
    [u8; SHARED_SECRET_LEN],
    ml_dsa_replica::KeyWork,
    ml_dsa_replica::KeyWork,
    usize,
) {
    let mut seen: Vec<([u8; SHARED_SECRET_LEN], ml_dsa_replica::KeyWork)> = Vec::new();
    loop {
        let candidate: [u8; SHARED_SECRET_LEN] = inputs.array();
        let work = ml_dsa_replica::key_work(&candidate);
        if let Some(index) = seen.iter().position(|(_, earlier)| {
            earlier.expand_s_bytes == work.expand_s_bytes
                && earlier.expand_a_rejected == work.expand_a_rejected
        }) {
            let drawn = seen.len() + 1;
            let (a, a_work) = seen.swap_remove(index);
            return (a, candidate, a_work, work, drawn);
        }
        seen.push((candidate, work));
    }
}

/// One diagnostic comparison: `op` timed alone on class `which`'s key, the
/// classes interleaved by a coin drawn before the loop, as every comparison
/// here is. Each entry draws a fresh 32-byte nonce seed and 64-byte message.
fn compare_op<K>(
    keys: [&K; 2],
    sizing: Sizing,
    inputs: &mut Inputs,
    planted: Option<u64>,
    mut op: impl FnMut(&K, &[u8; 32], &[u8; 64]) -> bool,
) -> Outcome {
    let total = sizing.samples + sizing.calibration;
    let entries: Vec<(u8, [u8; 32], [u8; 64])> = (0..total)
        .map(|_| {
            (
                u8::from(inputs.next() & 1 == 1),
                inputs.array(),
                inputs.array(),
            )
        })
        .collect();
    let mut times = vec![0u64; total];
    let mut returned = 0usize;
    for (index, (class, nonce, message)) in entries.iter().enumerate() {
        let start = Instant::now();
        let ok = op(
            keys[usize::from(*class)],
            black_box(nonce),
            black_box(message),
        );
        if let Some(iterations) = planted {
            if *class == 1 {
                spin(iterations);
            }
        }
        times[index] = start.elapsed().as_nanos() as u64;
        returned += usize::from(ok);
    }
    let checks_hold = returned == total;
    println!(
        "  check entries={total} returned={returned} verdict={}",
        if checks_hold { "as-intended" } else { "FAILED" }
    );
    let which: Vec<u8> = entries.iter().map(|e| e.0).collect();
    let (max_t, median_ns, n) = statistics(&which, &times, sizing);
    Outcome {
        raw_sd_ns: raw_sd(&times[sizing.calibration..]),
        max_t,
        median_ns,
        samples: n,
        checks_hold,
    }
}

/// The localisation of ML-DSA's matched-pair crossing (CRYPTO_AUDIT.md
/// §3.2): the same matched pair the `ml-dsa` mode draws for this seed, with
/// key generation alone or signing alone timed. Diagnostic: it reads no
/// registered line and prints no verdict, only the figures.
fn ml_dsa_localisation(mode: Mode, sizing: Sizing, inputs: &mut Inputs, seed: u64) -> ! {
    use fips204::traits::Signer as _;
    use shekyl_crypto_pq::derivation::keygen_from_seed;
    use shekyl_crypto_pq::output::output_ml_dsa_seed_for_tests;

    let (a, b, a_work, b_work, drawn) = matched_ml_dsa_pair(inputs);
    let half = if mode == Mode::MlDsaKeygen {
        "key generation alone (seed derivation + keygen_from_seed)"
    } else {
        "signing alone (fips204 try_sign_with_seed, keys generated before the loop)"
    };
    println!("CA-3 ML-DSA localisation, diagnostic (no registered line): {half}");
    println!(
        "arch={} os={} samples_per_comparison={} seed={seed} matched-pair candidates_drawn={drawn} \
         expand_s_bytes={}/{} expand_a_rejected={}/{} replicates={}/{}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        sizing.samples,
        a_work.expand_s_bytes,
        b_work.expand_s_bytes,
        a_work.expand_a_rejected,
        b_work.expand_a_rejected,
        a_work.replicates,
        b_work.replicates,
    );
    let report = |label: &str, o: &Outcome| {
        println!(
            "{label} max_abs_t={:.2} median_ns={:.0} raw_sd_ns={:.0} n0={:.0} n1={:.0}",
            o.max_t, o.median_ns, o.raw_sd_ns, o.samples[0], o.samples[1]
        );
    };
    let (pair, null, control) = if mode == Mode::MlDsaKeygen {
        let keygen = |ss: &[u8; SHARED_SECRET_LEN], _: &[u8; 32], _: &[u8; 64]| {
            let seed = output_ml_dsa_seed_for_tests(black_box(ss), 0);
            black_box(keygen_from_seed(&seed)).is_ok()
        };
        let pair = compare_op([&a, &b], sizing, inputs, None, keygen);
        let null = compare_op([&a, &a], sizing, inputs, None, keygen);
        let iterations = calibrate_spin(null.median_ns * CONTROL_LEAK_FRACTION);
        let control = compare_op([&a, &a], sizing, inputs, Some(iterations), keygen);
        (pair, null, control)
    } else {
        let key = |ss: &[u8; SHARED_SECRET_LEN]| {
            keygen_from_seed(&output_ml_dsa_seed_for_tests(ss, 0))
                .expect("a derived seed generates")
                .1
        };
        let (sk_a, sk_b) = (key(&a), key(&b));
        let sign = |sk: &fips204::ml_dsa_65::PrivateKey, nonce: &[u8; 32], message: &[u8; 64]| {
            black_box(sk.try_sign_with_seed(nonce, message, &[])).is_ok()
        };
        let pair = compare_op([&sk_a, &sk_b], sizing, inputs, None, sign);
        let null = compare_op([&sk_a, &sk_a], sizing, inputs, None, sign);
        let iterations = calibrate_spin(null.median_ns * CONTROL_LEAK_FRACTION);
        let control = compare_op([&sk_a, &sk_a], sizing, inputs, Some(iterations), sign);
        (pair, null, control)
    };
    report("diagnostic=fixed-a-vs-fixed-b", &pair);
    report("null=fixed-a-vs-fixed-a", &null);
    report("control=fixed-a-vs-fixed-a(planted 0.5%)", &control);
    std::process::exit(i32::from(
        !(pair.checks_hold && null.checks_hold && control.checks_hold),
    ));
}

fn usage() -> ! {
    eprintln!(
        "usage: ca3_pq_sign_timing ml-dsa [SAMPLES [SEED]]\n       \
         ca3_pq_sign_timing slh-dsa PLANT_NS [SEED]\n       \
         ca3_pq_sign_timing slh-dsa-noise SEED"
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| args.get(i).map(String::as_str);
    let parse_seed =
        |text: Option<&str>| text.map_or(REGISTERED_SEED, |s| s.parse().expect("SEED is a number"));
    let (mode, sizing, seed, plant_ns) = match arg(1) {
        Some("ml-dsa") => {
            let samples = arg(2).map_or(1_000_000, |s| s.parse().expect("SAMPLES is a number"));
            (
                Mode::MlDsa,
                Sizing::new(samples, ML_DSA_CALIBRATION_DIVISOR),
                parse_seed(arg(3)),
                None,
            )
        }
        Some("slh-dsa") => {
            let Some(plant) = arg(2) else { usage() };
            (
                Mode::SlhDsa,
                Sizing::new(SLH_DSA_SAMPLES, SLH_DSA_CALIBRATION_DIVISOR),
                parse_seed(arg(3)),
                Some(plant.parse::<f64>().expect("PLANT_NS is a number")),
            )
        }
        Some(name @ ("ml-dsa-keygen" | "ml-dsa-sign")) => {
            let samples = arg(2).map_or(50_000, |s| s.parse().expect("SAMPLES is a number"));
            (
                if name == "ml-dsa-keygen" {
                    Mode::MlDsaKeygen
                } else {
                    Mode::MlDsaSign
                },
                Sizing::new(samples, ML_DSA_CALIBRATION_DIVISOR),
                parse_seed(arg(3)),
                None,
            )
        }
        Some("slh-dsa-noise") => {
            let Some(seed) = arg(2) else { usage() };
            (
                Mode::SlhDsaNoise,
                Sizing::new(SLH_DSA_NOISE_SAMPLES, SLH_DSA_CALIBRATION_DIVISOR),
                parse_seed(Some(seed)),
                None,
            )
        }
        _ => usage(),
    };
    let mut inputs = Inputs(seed);
    if matches!(mode, Mode::MlDsaKeygen | Mode::MlDsaSign) {
        ml_dsa_localisation(mode, sizing, &mut inputs, seed);
    }

    println!(
        "CA-3 {} signing timing (the shipped entry, derivation included), inputs prepared before the loop",
        match mode {
            Mode::MlDsa => "ML-DSA-65 transaction authorisation (fips204 0.5.0)",
            Mode::SlhDsa | Mode::SlhDsaNoise =>
                "SLH-DSA-SHA2-192s message signature (fips205 0.5.0)",
            Mode::MlDsaKeygen | Mode::MlDsaSign => unreachable!("handled above"),
        }
    );
    println!(
        "arch={} os={} mode={} samples_per_comparison={} calibration={} crops={CROPS} inputs={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        arg(1).unwrap_or(""),
        sizing.samples,
        sizing.calibration,
        if seed == REGISTERED_SEED {
            "registered"
        } else {
            "NOT-REGISTERED"
        }
    );
    println!(
        "pass: |t| < {T_PASS} on fixed-a-vs-fixed-b; null comparisons: |t| < {T_PASS}; control: \
         |t| > {T_LEAK}; fixed-vs-varied is information (ruled 2026-11-21)"
    );

    let mut checks_hold = true;
    // The ML-DSA replica's check, which only that mode makes.
    let mut replica_holds = true;
    let mut report = |label: &str, names: [&str; 2], outcome: &Outcome| {
        checks_hold &= outcome.checks_hold;
        let word = match label {
            "control" => "control",
            "information" => "information",
            _ => verdict(outcome.max_t),
        };
        println!(
            "{label}={}-vs-{} max_abs_t={:.2} median_ns={:.0} raw_sd_ns={:.0} n0={:.0} n1={:.0} \
             verdict={word}",
            names[0],
            names[1],
            outcome.max_t,
            outcome.median_ns,
            outcome.raw_sd_ns,
            outcome.samples[0],
            outcome.samples[1],
        );
    };

    let (information, fixed_pair, nulls, control, planted_ns) = match mode {
        Mode::MlDsa => {
            // Every secret this mode uses is drawn before any comparison.
            let (a, b, a_work, b_work, drawn) = matched_ml_dsa_pair(&mut inputs);
            println!(
                "matched-pair candidates_drawn={drawn} \
                 fixed-a expand_s_bytes={} expand_a_rejected={} replicates={} \
                 fixed-b expand_s_bytes={} expand_a_rejected={} replicates={}",
                a_work.expand_s_bytes,
                a_work.expand_a_rejected,
                a_work.replicates,
                b_work.expand_s_bytes,
                b_work.expand_a_rejected,
                b_work.replicates,
            );
            let replicated = a_work.replicates && b_work.replicates;
            println!(
                "check=replica replicated={replicated} verdict={}",
                if replicated { "as-intended" } else { "FAILED" }
            );
            replica_holds = replicated;
            let a = Secrets::Fixed("fixed-a", a);
            let b = Secrets::Fixed("fixed-b", b);
            let varied = Secrets::Varied("varied");
            let other = Secrets::Varied("other-varied");
            let mut run = |classes: [Secrets<SHARED_SECRET_LEN>; 2],
                           label: &str,
                           inputs: &mut Inputs,
                           planted| {
                let outcome = compare_ml_dsa(classes, sizing, inputs, planted);
                report(label, [classes[0].name(), classes[1].name()], &outcome);
                outcome
            };
            let information = run([a, varied], "information", &mut inputs, None);
            let fixed_pair = run([a, b], "pass-line", &mut inputs, None);
            let null_fixed = run([a, a], "null", &mut inputs, None);
            let null_varied = run([varied, other], "null", &mut inputs, None);
            // Planted on the first null, so no real effect adds to or
            // cancels it.
            let planted_ns = null_fixed.median_ns * CONTROL_LEAK_FRACTION;
            let control = run(
                [a, a],
                "control",
                &mut inputs,
                Some(calibrate_spin(planted_ns)),
            );
            (
                Some(information),
                Some(fixed_pair),
                vec![null_fixed, null_varied],
                Some(control),
                planted_ns,
            )
        }
        Mode::MlDsaKeygen | Mode::MlDsaSign => unreachable!("handled above"),
        Mode::SlhDsa | Mode::SlhDsaNoise => {
            let segment = segment(&mut inputs);
            let a = Secrets::Fixed("fixed-a", inputs.array());
            let b = Secrets::Fixed("fixed-b", inputs.array());
            let mut run = |classes: [Secrets<MASTER_SEED_BYTES>; 2],
                           label: &str,
                           inputs: &mut Inputs,
                           planted| {
                let outcome = compare_slh_dsa(classes, sizing, inputs, &segment, planted);
                report(label, [classes[0].name(), classes[1].name()], &outcome);
                outcome
            };
            if mode == Mode::SlhDsaNoise {
                // The noise calibration: the a/a null alone. Information,
                // kept with the captures; it sets the device's control.
                let null = run([a, a], "null", &mut inputs, None);
                let delta =
                    SLH_DSA_CONTROL_SIGMAS * null.raw_sd_ns * (2.0 / SLH_DSA_CLASS_SIZE).sqrt();
                println!(
                    "noise-calibration sigma_ns={:.0} delta_ns={delta:.0} \
                     (delta = {SLH_DSA_CONTROL_SIGMAS} * sigma * sqrt(2/{SLH_DSA_CLASS_SIZE}))",
                    null.raw_sd_ns
                );
                std::process::exit(i32::from(!checks_hold));
            }
            let fixed_pair = run([a, b], "pass-line", &mut inputs, None);
            let null_fixed = run([a, a], "null", &mut inputs, None);
            let planted_ns = plant_ns.unwrap_or_else(|| usage());
            let control = run(
                [a, a],
                "control",
                &mut inputs,
                Some(calibrate_spin(planted_ns)),
            );
            (
                None,
                Some(fixed_pair),
                vec![null_fixed],
                Some(control),
                planted_ns,
            )
        }
    };
    let (Some(fixed_pair), Some(control)) = (fixed_pair, control) else {
        unreachable!("every timed mode runs the pass line and the control")
    };

    println!(
        "control=planted-leak planted_ns={planted_ns:.0} max_abs_t={:.2} verdict={}",
        control.max_t,
        if control.max_t > T_LEAK {
            "detected"
        } else {
            "NOT-DETECTED"
        }
    );
    // A run whose calls did not sign, that could not have seen a leak, or
    // that sees one where there is none, is void before the pass line is
    // read at all.
    let checks_hold = checks_hold && replica_holds;
    let detected = control.max_t > T_LEAK;
    let worst_null = nulls.iter().map(|n| n.max_t).fold(0.0, f64::max);
    let unbiased = worst_null < T_PASS;
    let pass_figure = fixed_pair.max_t;
    let passed = checks_hold && detected && unbiased && pass_figure < T_PASS;
    println!(
        "result={} fixed_pair={pass_figure:.2} worst_null={worst_null:.2} control={:.2}{}",
        if !checks_hold {
            "VOID (a check failed, so the comparisons did not time what they claim)"
        } else if !detected {
            "VOID (the control was not detected, so a pass would mean nothing)"
        } else if !unbiased {
            "VOID (a null comparison is over the line, so the harness is biased)"
        } else if passed {
            "PASS"
        } else if pass_figure > T_LEAK {
            "FAIL"
        } else {
            "INCONCLUSIVE"
        },
        control.max_t,
        information.map_or(String::new(), |i| format!(
            " information_fixed_vs_varied={:.2}",
            i.max_t
        )),
    );
    std::process::exit(i32::from(!passed));
}
