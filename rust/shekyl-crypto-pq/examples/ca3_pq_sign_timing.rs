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
//! **Nulls:** `fixed-a-vs-fixed-a` and `varied-vs-varied`. **Control:**
//! `fixed-vs-varied` with work of [`CONTROL_LEAK_FRACTION`] of a
//! signature's median time planted in class 1. **Checks:** every timed call
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
/// The calibration batch and the least a cut-off must keep per class, each
/// as a divisor of the sample count (1 %).
const CALIBRATION_DIVISOR: usize = 100;
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

struct Outcome {
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
fn statistics(which: &[u8], times: &[u64], samples: usize) -> (f64, f64, [f64; 2]) {
    let calibration_len = samples / CALIBRATION_DIVISOR;
    let min_cropped = (samples / CALIBRATION_DIVISOR) as f64;
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
    samples: usize,
    inputs: &mut Inputs,
    planted: Option<u64>,
) -> Outcome {
    let total = samples + samples / CALIBRATION_DIVISOR;
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
    let (max_t, median_ns, n) = statistics(&which, &times, samples);
    Outcome {
        max_t,
        median_ns,
        samples: n,
        checks_hold,
    }
}

/// One `slh-dsa` comparison, as [`compare_ml_dsa`], over the master seed.
fn compare_slh_dsa(
    classes: [Secrets<MASTER_SEED_BYTES>; 2],
    samples: usize,
    inputs: &mut Inputs,
    segment: &BoundClassicalSegment,
    planted: Option<u64>,
) -> Outcome {
    const NETWORK: Network = Network::Testnet;
    let total = samples + samples / CALIBRATION_DIVISOR;
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
    let (max_t, median_ns, n) = statistics(&which, &times, samples);
    Outcome {
        max_t,
        median_ns,
        samples: n,
        checks_hold,
    }
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

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        Some("ml-dsa") => Mode::MlDsa,
        Some("slh-dsa") => Mode::SlhDsa,
        _ => {
            eprintln!("usage: ca3_pq_sign_timing ml-dsa|slh-dsa [SAMPLES [SEED]]");
            std::process::exit(2);
        }
    };
    let samples: usize = std::env::args()
        .nth(2)
        .map(|arg| arg.parse().expect("SAMPLES is a number"))
        .unwrap_or(match mode {
            Mode::MlDsa => 1_000_000,
            Mode::SlhDsa => 2_000,
        });
    // A seed given here is for checking that the harness runs without
    // drawing the registered inputs.
    let seed = std::env::args().nth(3).map_or(REGISTERED_SEED, |arg| {
        arg.parse().expect("SEED is a number")
    });
    let mut inputs = Inputs(seed);

    println!(
        "CA-3 {} signing timing (the shipped entry, derivation included), inputs prepared before the loop",
        match mode {
            Mode::MlDsa => "ML-DSA-65 transaction authorisation (fips204 0.5.0)",
            Mode::SlhDsa => "SLH-DSA-SHA2-192s message signature (fips205 0.5.0)",
        }
    );
    println!(
        "arch={} os={} samples_per_comparison={samples} calibration={} crops={CROPS} inputs={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        samples / CALIBRATION_DIVISOR,
        if seed == REGISTERED_SEED {
            "registered"
        } else {
            "NOT-REGISTERED"
        }
    );
    println!(
        "pass: |t| < {T_PASS} on fixed-vs-varied and on fixed-a-vs-fixed-b; null comparisons: \
         |t| < {T_PASS}; control: |t| > {T_LEAK}"
    );

    let mut checks_hold = true;
    let mut report = |label: &str, names: [&str; 2], outcome: &Outcome| {
        checks_hold &= outcome.checks_hold;
        let word = if label == "control" {
            "control"
        } else {
            verdict(outcome.max_t)
        };
        println!(
            "{label}={}-vs-{} max_abs_t={:.2} median_ns={:.0} n0={:.0} n1={:.0} verdict={word}",
            names[0],
            names[1],
            outcome.max_t,
            outcome.median_ns,
            outcome.samples[0],
            outcome.samples[1],
        );
    };

    let (fixed_varied, fixed_pair, null_fixed, null_varied, control) = match mode {
        Mode::MlDsa => {
            let a = Secrets::Fixed("fixed-a", inputs.array());
            let b = Secrets::Fixed("fixed-b", inputs.array());
            let varied = Secrets::Varied("varied");
            let other = Secrets::Varied("other-varied");
            let mut run = |classes: [Secrets<SHARED_SECRET_LEN>; 2],
                           label: &str,
                           inputs: &mut Inputs,
                           planted| {
                let outcome = compare_ml_dsa(classes, samples, inputs, planted);
                report(label, [classes[0].name(), classes[1].name()], &outcome);
                outcome
            };
            let fixed_varied = run([a, varied], "pass-line", &mut inputs, None);
            let fixed_pair = run([a, b], "pass-line", &mut inputs, None);
            let null_fixed = run([a, a], "null", &mut inputs, None);
            let null_varied = run([varied, other], "null", &mut inputs, None);
            let iterations = calibrate_spin(fixed_varied.median_ns * CONTROL_LEAK_FRACTION);
            let control = run([a, varied], "control", &mut inputs, Some(iterations));
            (fixed_varied, fixed_pair, null_fixed, null_varied, control)
        }
        Mode::SlhDsa => {
            let segment = segment(&mut inputs);
            let a = Secrets::Fixed("fixed-a", inputs.array());
            let b = Secrets::Fixed("fixed-b", inputs.array());
            let varied = Secrets::Varied("varied");
            let other = Secrets::Varied("other-varied");
            let mut run = |classes: [Secrets<MASTER_SEED_BYTES>; 2],
                           label: &str,
                           inputs: &mut Inputs,
                           planted| {
                let outcome = compare_slh_dsa(classes, samples, inputs, &segment, planted);
                report(label, [classes[0].name(), classes[1].name()], &outcome);
                outcome
            };
            let fixed_varied = run([a, varied], "pass-line", &mut inputs, None);
            let fixed_pair = run([a, b], "pass-line", &mut inputs, None);
            let null_fixed = run([a, a], "null", &mut inputs, None);
            let null_varied = run([varied, other], "null", &mut inputs, None);
            let iterations = calibrate_spin(fixed_varied.median_ns * CONTROL_LEAK_FRACTION);
            let control = run([a, varied], "control", &mut inputs, Some(iterations));
            (fixed_varied, fixed_pair, null_fixed, null_varied, control)
        }
    };

    let planted_ns = fixed_varied.median_ns * CONTROL_LEAK_FRACTION;
    println!(
        "control=planted-leak fraction={CONTROL_LEAK_FRACTION} planted_ns={planted_ns:.0} \
         max_abs_t={:.2} verdict={}",
        control.max_t,
        if control.max_t > T_LEAK {
            "detected"
        } else {
            "NOT-DETECTED"
        }
    );
    // A run whose calls did not sign, that could not have seen a leak, or
    // that sees one where there is none, is void before the pass lines are
    // read at all.
    let detected = control.max_t > T_LEAK;
    let worst_null = null_fixed.max_t.max(null_varied.max_t);
    let unbiased = worst_null < T_PASS;
    let worst_pass = fixed_varied.max_t.max(fixed_pair.max_t);
    let passed = checks_hold && detected && unbiased && worst_pass < T_PASS;
    println!(
        "result={} fixed_vs_varied={:.2} fixed_pair={:.2} worst_null={worst_null:.2} control={:.2}",
        if !checks_hold {
            "VOID (a check failed, so the comparisons did not time what they claim)"
        } else if !detected {
            "VOID (the control was not detected, so a pass would mean nothing)"
        } else if !unbiased {
            "VOID (a null comparison is over the line, so the harness is biased)"
        } else if passed {
            "PASS"
        } else if worst_pass > T_LEAK {
            "FAIL"
        } else {
            "INCONCLUSIVE"
        },
        fixed_varied.max_t,
        fixed_pair.max_t,
        control.max_t
    );
    std::process::exit(i32::from(!passed));
}
