// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! RT-P4: is ML-KEM-768 decapsulation constant-time with respect to the
//! ciphertext, including the implicit-rejection path?
//! (`docs/design/RPC_CHANNEL.md` §4.3, §9.)
//!
//! The RPC channel's daemon decapsulates an attacker-chosen ciphertext with
//! its long-term key before anything has authenticated. A timing difference
//! there is a remote oracle on that key. This program measures whether the
//! pinned crate (`fips203`) shows one.
//!
//! # Method (after `dudect`)
//!
//! Two classes of ciphertext are interleaved at random and each
//! decapsulation is timed. If the two timing distributions differ, the
//! implementation is telling the classes apart. The difference is tested
//! with Welch's t, on the raw samples and on the samples below each of a
//! ladder of cut-offs (slow outliers are interrupts and cache misses, not
//! the code under test). The reported figure is the largest `|t|`.
//!
//! Four comparisons:
//!
//! - `fixed-vs-valid`: one fixed valid ciphertext against fresh valid ones.
//! - `fixed-vs-invalid`: the fixed valid ciphertext against random bytes,
//!   which decapsulate by implicit rejection.
//! - `fixed-vs-bitflip`: the fixed valid ciphertext against itself with one
//!   bit flipped, a near-valid input that is still rejected.
//! - `valid-vs-invalid`: fresh valid against random bytes, so that validity
//!   is the only thing that differs between two equally varied classes.
//!
//! # The control
//!
//! A timing test that never reports a leak has not been shown able to. So
//! the same harness is run on a deliberately leaky wrapper: after a
//! `fixed-vs-invalid` decapsulation it spends a little extra time only on
//! rejected ciphertexts. The extra is calibrated to a stated fraction of
//! one decapsulation, and the harness must report it. The fraction is the
//! sensitivity of the whole probe: a leak smaller than that is not excluded
//! by a pass.
//!
//! Run: `cargo run --release -p shekyl-rpc-channel --example rt_p4_decaps_timing -- [SAMPLES]`
//! (default 1,000,000 samples per comparison).

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

use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// `|t|` below this on every cut-off is "no evidence of a leak"; dudect's
/// own bound.
const T_PASS: f64 = 4.5;
/// `|t|` above this is a leak beyond reasonable doubt; the control must
/// exceed it.
const T_LEAK: f64 = 10.0;
/// The planted leak, as a fraction of one decapsulation's median time.
const CONTROL_LEAK_FRACTION: f64 = 0.005;
const DEFAULT_SAMPLES: usize = 1_000_000;
/// Samples used to place the cut-offs before any statistic is accumulated.
const CALIBRATION: usize = 10_000;
/// Cut-offs, as in dudect: `1 - 0.5^(10 (i + 1) / CROPS)` quantiles.
const CROPS: usize = 100;
const CT_LEN: usize = 1088;

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

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Class {
    Fixed,
    Valid,
    Invalid,
    Bitflip,
}

impl Class {
    fn name(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Bitflip => "bitflip",
        }
    }
}

struct Subject {
    dk: ml_kem_768::DecapsKey,
    ek: ml_kem_768::EncapsKey,
    fixed: [u8; CT_LEN],
}

impl Subject {
    fn new(inputs: &mut Inputs) -> Self {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        inputs.fill(&mut d);
        inputs.fill(&mut z);
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(d, z);
        let mut seed = [0u8; 32];
        inputs.fill(&mut seed);
        let (_, ct) = ek.encaps_from_seed(&seed);
        Self {
            dk,
            ek,
            fixed: ct.into_bytes(),
        }
    }

    /// The ciphertext for one sample.
    ///
    /// Every candidate is built every time, whatever the class, and the
    /// class only selects one. Building just the one needed would give each
    /// class its own work before the timed region -- an encapsulation for
    /// one, a copy for another -- and so its own cache and predictor state
    /// inside it. The harness would then measure itself.
    fn ciphertext(&self, class: Class, inputs: &mut Inputs) -> [u8; CT_LEN] {
        let mut seed = [0u8; 32];
        inputs.fill(&mut seed);
        let valid = self.ek.encaps_from_seed(&seed).1.into_bytes();
        let mut invalid = [0u8; CT_LEN];
        inputs.fill(&mut invalid);
        let mut bitflip = self.fixed;
        let bit = usize::try_from(inputs.next() % (CT_LEN as u64 * 8)).unwrap_or(0);
        bitflip[bit / 8] ^= 1 << (bit % 8);
        let fixed = self.fixed;
        match class {
            Class::Fixed => black_box(fixed),
            Class::Valid => black_box(valid),
            Class::Invalid => black_box(invalid),
            Class::Bitflip => black_box(bitflip),
        }
    }
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
}

/// One comparison: `samples` timed decapsulations, the two classes chosen by
/// a coin. `extra` is the control's planted work, run inside the timed
/// region; the real comparisons pass a no-op.
fn compare(
    subject: &Subject,
    classes: [Class; 2],
    samples: usize,
    inputs: &mut Inputs,
    extra: &dyn Fn(Class),
) -> Outcome {
    let measure = |inputs: &mut Inputs| -> (usize, f64) {
        let which = usize::from(inputs.next() & 1 == 1);
        let class = classes[which];
        let bytes = subject.ciphertext(class, inputs);
        let ct = ml_kem_768::CipherText::try_from_bytes(bytes)
            .expect("every 1088-byte string is a well-formed ML-KEM-768 ciphertext");
        let start = Instant::now();
        let shared = subject.dk.try_decaps(black_box(&ct));
        extra(class);
        let elapsed = start.elapsed();
        black_box(shared.is_ok());
        (which, elapsed.as_nanos() as f64)
    };

    // Place the cut-offs from a first batch, which is then discarded.
    let mut calibration: Vec<f64> = (0..CALIBRATION).map(|_| measure(inputs).1).collect();
    calibration.sort_by(f64::total_cmp);
    let median_ns = calibration[CALIBRATION / 2];
    let cutoffs: Vec<f64> = (0..CROPS)
        .map(|i| {
            let quantile = 1.0 - 0.5f64.powf(10.0 * (i as f64 + 1.0) / CROPS as f64);
            let index = ((quantile * CALIBRATION as f64) as usize).min(CALIBRATION - 1);
            calibration[index]
        })
        .collect();

    let mut raw = [Moments::default(); 2];
    let mut cropped = vec![[Moments::default(); 2]; CROPS];
    for _ in 0..samples {
        let (which, ns) = measure(inputs);
        raw[which].push(ns);
        for (cutoff, moments) in cutoffs.iter().zip(cropped.iter_mut()) {
            if ns < *cutoff {
                moments[which].push(ns);
            }
        }
    }

    let mut max_t = welch_t(&raw[0], &raw[1]).abs();
    for moments in &cropped {
        // A cut-off that leaves too few samples says nothing.
        if moments[0].n > 10_000.0 && moments[1].n > 10_000.0 {
            max_t = max_t.max(welch_t(&moments[0], &moments[1]).abs());
        }
    }
    Outcome {
        max_t,
        median_ns,
        samples: [raw[0].n, raw[1].n],
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

fn main() {
    let samples = std::env::args()
        .nth(1)
        .map(|arg| arg.parse().expect("SAMPLES is a number"))
        .unwrap_or(DEFAULT_SAMPLES);
    let mut inputs = Inputs(0x5348_454b_594c_5254);
    let subject = Subject::new(&mut inputs);

    println!("RT-P4 ML-KEM-768 decapsulation timing (fips203)");
    println!(
        "arch={} os={} samples_per_comparison={samples} calibration={CALIBRATION} crops={CROPS}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!("pass: |t| < {T_PASS} on every real comparison; control: |t| > {T_LEAK}");

    let real = [
        [Class::Fixed, Class::Valid],
        [Class::Fixed, Class::Invalid],
        [Class::Fixed, Class::Bitflip],
        [Class::Valid, Class::Invalid],
    ];
    let mut worst: f64 = 0.0;
    let mut median_ns: f64 = 0.0;
    for classes in real {
        let outcome = compare(&subject, classes, samples, &mut inputs, &|_| {});
        worst = worst.max(outcome.max_t);
        median_ns = outcome.median_ns;
        println!(
            "comparison={}-vs-{} max_abs_t={:.2} median_ns={:.0} n0={:.0} n1={:.0} verdict={}",
            classes[0].name(),
            classes[1].name(),
            outcome.max_t,
            outcome.median_ns,
            outcome.samples[0],
            outcome.samples[1],
            if outcome.max_t < T_PASS {
                "no-evidence"
            } else if outcome.max_t > T_LEAK {
                "LEAK"
            } else {
                "INCONCLUSIVE"
            }
        );
    }

    let leak_ns = median_ns * CONTROL_LEAK_FRACTION;
    let iterations = calibrate_spin(leak_ns);
    let control = compare(
        &subject,
        [Class::Fixed, Class::Invalid],
        samples,
        &mut inputs,
        &|class| {
            if class == Class::Invalid {
                spin(iterations);
            }
        },
    );
    println!(
        "control=planted-leak fraction={CONTROL_LEAK_FRACTION} planted_ns={leak_ns:.0} \
         max_abs_t={:.2} verdict={}",
        control.max_t,
        if control.max_t > T_LEAK {
            "detected"
        } else {
            "NOT-DETECTED"
        }
    );

    let passed = worst < T_PASS && control.max_t > T_LEAK;
    println!(
        "result={} worst_real_abs_t={worst:.2} control_abs_t={:.2}",
        if passed {
            "PASS"
        } else if control.max_t <= T_LEAK {
            "VOID (the control was not detected, so a pass would mean nothing)"
        } else if worst > T_LEAK {
            "FAIL"
        } else {
            "INCONCLUSIVE"
        },
        control.max_t
    );
    std::process::exit(i32::from(!passed));
}
