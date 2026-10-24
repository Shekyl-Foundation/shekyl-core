// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Dynamic timing test for the CA-1 field operations (dudect's method).
//!
//! Two input classes, fixed and random, are interleaved at random; each
//! sample times a batch of `BATCH` operations. Two harness rules, each
//! learnt on 2026-10-24 from a false "class difference" on operations
//! BINSEC had proved branchless: every input of every sample is generated
//! BEFORE the timing loop (generating the random class's inputs right
//! before its batch hands the two classes different cache and predictor
//! state); and no value repeats inside a timed batch (a value repeated
//! back-to-back runs measurably faster through the short HelioseleneField
//! operations, whatever the value is). So the fixed class is a SET of
//! `BATCH` distinct values drawn once and reused in every fixed batch, and
//! the random class draws fresh values per element. A null control (both
//! classes fresh) must show no difference, or the threshold is not
//! meaningful on this device. Every test row has a `[fixed-pair]` companion
//! (two different fixed sets, so both classes are equally familiar to the
//! CPU): on 2026-10-24 the short HelioseleneField mul/square showed a
//! fixed-against-fresh difference that grew with the sample while the
//! fixed-pair row stayed flat, i.e. the CPU runs a familiar operand stream
//! faster; that is not operand-dependent timing of the operation. Welch's t-statistic between
//! the two classes' timings is reported for every operation, on the full
//! sample and on the sample with its slowest 1 % removed (dudect crops the
//! tail, where interrupts live). dudect's threshold is `|t| > 4.5`: a
//! constant-time operation stays well under it however many samples are
//! taken, a leaking one grows past it. The positive controls at the end of
//! the table must exceed it, or the run says nothing.
//!
//! This is evidence of a different kind from the static BINSEC verdicts:
//! it sees this device, this binary and this run, and it cannot prove the
//! absence of a branch, only fail to observe one. Record its rows as
//! `dynamic`, never as a checkct pass.
//!
//! Usage: `ct-dynamic [samples-per-class] [name-filter]`. A t just past the
//! threshold at the default sample size is settled by growing the sample:
//! a leak's |t| grows with the square root of the sample, noise does not.

use core::hint::black_box;
use ff::{Field, PrimeField};
use std::time::Instant;

use crypto_bigint::{impl_modulus, modular::constant_mod::Residue, U256};
use dalek_ff_group::FieldElement as Field25519;
use helioselene::HelioseleneField;

const DEFAULT_SAMPLES: usize = 20_000;
const BATCH: usize = 32;

impl_modulus!(
    P25519,
    U256,
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);
type R = Residue<P25519, { U256::LIMBS }>;

/// xorshift64*, seeded once from the OS through `RandomState`; the inputs
/// only need to be unpredictable to the code under test, not secret.
struct Rng(u64);
impl Rng {
    fn new() -> Self {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(0x5eed);
        Rng(h.finish() | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b[31] &= 0x3f;
        b
    }
    fn bytes64(&mut self) -> [u8; 64] {
        let mut b = [0u8; 64];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        b
    }
}

/// Welch's t between two timing samples.
fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var = |x: &[f64], m: f64| {
        x.iter().map(|v| (v - m) * (v - m)).sum::<f64>() / (x.len() as f64 - 1.0)
    };
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

fn cropped(x: &[f64], keep: f64) -> Vec<f64> {
    let mut v = x.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v.truncate((v.len() as f64 * keep) as usize);
    v
}

/// Time `op` on `BATCH` inputs per sample, `samples` samples per class.
/// `gen` builds one input. Class 0 (fixed) is a set of `BATCH` distinct
/// values drawn once from `gen` and reused in every fixed batch; class 1
/// (random) draws fresh values per element. With `null`, class 0 also
/// draws fresh values: the null control. All inputs are built first, in a
/// random class order; only then is each batch timed.
/// How the two classes are built: `Fixed` is the test (fixed set against
/// fresh values); `Null` draws both fresh; `FixedPair` reuses two different
/// fixed sets, one per class, so both are equally familiar to the CPU and
/// only operand-dependent timing can separate them; `Constant(v)` makes
/// class 0 the one value `v` repeated, for the positive controls, whose
/// effect must be an extreme against the random class (a fixed SET of
/// random loop lengths has the same mean as fresh ones and shows nothing).
#[derive(Clone, PartialEq)]
enum Mode<I> {
    Fixed,
    Null,
    FixedPair,
    Constant(I),
    /// Class 0 is built by `gen` (a structured generator, fresh per element);
    /// class 1 by the plain random generator the harness keeps per field.
    Structured,
}

fn measure<I: Clone + RandomInput, F: FnMut(&I) -> u64>(
    run: &Run,
    name: &str,
    mode: Mode<I>,
    mut gen: impl FnMut(&mut Rng) -> I,
    mut op: F,
) {
    if let Some(f) = &run.filter {
        if !name.contains(f.as_str()) {
            return;
        }
    }
    let samples = run.samples;
    let mut rng = Rng::new();
    // The fixed classes are not kept as tables: each fixed batch regenerates
    // its values from a fixed seed through the same `gen` path and a fresh
    // allocation the random class uses, so the two classes differ in their
    // values only, not in how their memory was built or where it sits.
    let fixed_seed = rng.next() | 1;
    let other_seed = rng.next() | 1;
    let regen = |seed: u64, gen: &mut dyn FnMut(&mut Rng) -> I| -> Vec<I> {
        let mut r = Rng(seed);
        (0..BATCH).map(|_| gen(&mut r)).collect()
    };
    let mut order: Vec<usize> = Vec::with_capacity(2 * samples);
    order.extend(std::iter::repeat_n(0, samples));
    order.extend(std::iter::repeat_n(1, samples));
    for i in (1..order.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let inputs: Vec<Vec<I>> = order
        .iter()
        .map(|&class| match (&mode, class) {
            (Mode::Null, _) => (0..BATCH).map(|_| gen(&mut rng)).collect(),
            (Mode::Structured, 0) => (0..BATCH).map(|_| gen(&mut rng)).collect(),
            (Mode::Structured, _) => (0..BATCH).map(|_| I::random(&mut rng)).collect(),
            (Mode::Constant(v), 0) => vec![v.clone(); BATCH],
            (_, 0) => regen(fixed_seed, &mut gen),
            (Mode::FixedPair, _) => regen(other_seed, &mut gen),
            (Mode::Fixed | Mode::Constant(_), _) => (0..BATCH).map(|_| gen(&mut rng)).collect(),
        })
        .collect();
    let mut t0 = Vec::with_capacity(samples);
    let mut t1 = Vec::with_capacity(samples);
    let mut sink = 0u64;
    for (class, batch) in order.iter().zip(&inputs) {
        if run.only.is_some_and(|c| c != *class) {
            continue;
        }
        let start = Instant::now();
        for i in batch {
            sink = sink.wrapping_add(op(black_box(i)));
        }
        let ns = start.elapsed().as_nanos() as f64;
        if *class == 0 {
            t0.push(ns)
        } else {
            t1.push(ns)
        }
    }
    black_box(sink);
    if run.only.is_some() {
        println!(
            "{name:<34} only one class run; batches {}",
            t0.len() + t1.len()
        );
        return;
    }
    let t_all = welch_t(&t0, &t1);
    let t_crop = welch_t(&cropped(&t0, 0.99), &cropped(&t1, 0.99));
    let verdict = if t_all.abs() > 4.5 || t_crop.abs() > 4.5 {
        "CLASS DIFFERENCE"
    } else {
        "no difference seen"
    };
    println!(
        "{name:<34} t={t_all:>8.2}  t(crop 1%)={t_crop:>8.2}  mean ns fixed/random {:>9.0}/{:>9.0}  {verdict}",
        t0.iter().sum::<f64>() / t0.len() as f64,
        t1.iter().sum::<f64>() / t1.len() as f64,
    );
}

/// A fresh uniformly random value of the type, for the random class of a
/// `Structured` row (the structured generator builds class 0).
trait RandomInput: Sized {
    fn random(r: &mut Rng) -> Self;
}
impl RandomInput for HelioseleneField {
    fn random(r: &mut Rng) -> Self {
        fehelio(r.bytes32())
    }
}
impl RandomInput for Field25519 {
    fn random(r: &mut Rng) -> Self {
        fe25519(r.bytes32())
    }
}
impl RandomInput for u8 {
    fn random(r: &mut Rng) -> Self {
        (r.next() & 0xff) as u8
    }
}
impl RandomInput for [u8; 32] {
    fn random(r: &mut Rng) -> Self {
        r.bytes32()
    }
}
impl RandomInput for [u8; 64] {
    fn random(r: &mut Rng) -> Self {
        r.bytes64()
    }
}
impl<A: RandomInput, B: RandomInput> RandomInput for (A, B) {
    fn random(r: &mut Rng) -> Self {
        (A::random(r), B::random(r))
    }
}
impl RandomInput for (R, U256) {
    fn random(r: &mut Rng) -> Self {
        (
            R::new(&U256::from_be_slice(&r.bytes32())),
            U256::from_be_slice(&r.bytes32()),
        )
    }
}

/// Samples per class and an optional entrypoint-name filter, from argv.
struct Run {
    samples: usize,
    filter: Option<String>,
    /// `Some(0)` / `Some(1)`: run only that class's batches (for `perf stat`
    /// over one class at a time); the t statistics are then meaningless.
    only: Option<usize>,
}

fn fe25519(b: [u8; 32]) -> Field25519 {
    Field25519::from_repr(b).unwrap_or(Field25519::ZERO)
}
fn fehelio(b: [u8; 32]) -> HelioseleneField {
    HelioseleneField::from_repr(b).unwrap_or(HelioseleneField::ZERO)
}
fn low64<F: PrimeField<Repr = [u8; 32]>>(f: &F) -> u64 {
    u64::from_le_bytes(f.to_repr()[..8].try_into().unwrap())
}

/// Every test row twice: dudect's fixed-against-fresh, and the fixed-pair
/// companion whose two classes are equally familiar to the CPU. A row that
/// differs in the first and not in the second is familiarity, not operands.
macro_rules! both {
    ($run:expr, $name:literal, $gen:expr, $op:expr $(,)?) => {
        measure($run, $name, Mode::Fixed, $gen, $op);
        measure(
            $run,
            concat!($name, " [fixed-pair]"),
            Mode::FixedPair,
            $gen,
            $op,
        );
    };
}

fn main() {
    let run = Run {
        samples: std::env::args()
            .nth(1)
            .and_then(|a| a.parse().ok())
            .unwrap_or(DEFAULT_SAMPLES),
        filter: std::env::args().nth(2),
        only: match std::env::args().nth(3).as_deref() {
            Some("only-fixed") => Some(0),
            Some("only-random") => Some(1),
            _ => None,
        },
    };
    println!(
        "ct-dynamic: {} samples/class x {BATCH} ops; dudect threshold |t| > 4.5; target {}",
        run.samples,
        std::env::consts::ARCH
    );
    let mut seed = Rng::new();
    println!("-- null control (both classes fresh; must show no difference)");
    measure(
        &run,
        "null: fe25519 mul",
        Mode::Null,
        |r| (fe25519(r.bytes32()), fe25519(r.bytes32())),
        |(a, b)| low64(&(*a * *b)),
    );
    measure(
        &run,
        "null: helio square",
        Mode::Null,
        |r| fehelio(r.bytes32()),
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "null: helio mul",
        Mode::Null,
        |r| (fehelio(r.bytes32()), fehelio(r.bytes32())),
        |(a, b)| low64(&(*a * *b)),
    );

    println!("-- helioselene::Field25519 (dalek_ff_group::FieldElement)");
    let pair = |r: &mut Rng| (fe25519(r.bytes32()), fe25519(r.bytes32()));
    let one = |r: &mut Rng| fe25519(r.bytes32());
    both!(&run, "fe25519 add", pair, |(a, b)| { low64(&(*a + *b)) });
    both!(&run, "fe25519 sub", pair, |(a, b)| { low64(&(*a - *b)) });
    both!(&run, "fe25519 mul", pair, |(a, b)| { low64(&(*a * *b)) });
    both!(&run, "fe25519 square", one, |a| { low64(&a.square()) });
    both!(&run, "fe25519 invert", one, |a| {
        low64(&a.invert().unwrap_or(Field25519::ZERO))
    });
    both!(&run, "fe25519 sqrt", one, |a| {
        low64(&a.sqrt().unwrap_or(Field25519::ZERO))
    });
    both!(&run, "fe25519 pow (secret exponent)", pair, |(a, e)| low64(
        &a.pow(*e)
    ),);
    both!(&run, "fe25519 from_repr", |r| r.bytes32(), |b| low64(
        &fe25519(*b)
    ),);
    both!(&run, "fe25519 wide_reduce", |r| r.bytes64(), |b| low64(
        &Field25519::wide_reduce(*b)
    ),);

    println!("-- helioselene::HelioseleneField");
    let hpair = |r: &mut Rng| (fehelio(r.bytes32()), fehelio(r.bytes32()));
    let hone = |r: &mut Rng| fehelio(r.bytes32());
    both!(&run, "helio add", hpair, |(a, b)| { low64(&(*a + *b)) });
    both!(&run, "helio sub", hpair, |(a, b)| { low64(&(*a - *b)) });
    both!(&run, "helio mul", hpair, |(a, b)| { low64(&(*a * *b)) });
    both!(&run, "helio square", hone, |a| { low64(&a.square()) });
    both!(&run, "helio invert", hone, |a| {
        low64(&a.invert().unwrap_or(HelioseleneField::ZERO))
    });
    both!(&run, "helio sqrt", hone, |a| {
        low64(&a.sqrt().unwrap_or(HelioseleneField::ZERO))
    });
    both!(&run, "helio pow (secret exponent)", hpair, |(a, e)| low64(
        &a.pow(*e)
    ),);
    both!(&run, "helio from_repr", |r| r.bytes32(), |b| low64(
        &fehelio(*b)
    ),);
    both!(&run, "helio wide_reduce", |r| r.bytes64(), |b| low64(
        &HelioseleneField::wide_reduce(*b)
    ),);

    println!("-- constant-value control (class 0: one value, allocated fresh per batch; class 1: fresh values)");
    let hc = fehelio(seed.bytes32());
    let hc2 = fehelio(seed.bytes32());
    let fc = fe25519(seed.bytes32());
    let fc2 = fe25519(seed.bytes32());
    measure(
        &run,
        "constant: helio square",
        Mode::Constant(hc),
        |r| fehelio(r.bytes32()),
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "constant: helio mul",
        Mode::Constant((hc, hc2)),
        |r| (fehelio(r.bytes32()), fehelio(r.bytes32())),
        |(a, b)| low64(&(*a * *b)),
    );
    measure(
        &run,
        "constant: helio sqrt",
        Mode::Constant(hc),
        |r| fehelio(r.bytes32()),
        |a| low64(&a.sqrt().unwrap_or(HelioseleneField::ZERO)),
    );
    measure(
        &run,
        "constant: fe25519 mul",
        Mode::Constant((fc, fc2)),
        |r| (fe25519(r.bytes32()), fe25519(r.bytes32())),
        |(a, b)| low64(&(*a * *b)),
    );

    println!("-- operand property (class 0: structured values, regenerated per batch; class 1: random) — which property moves the time?");
    // Low Hamming weight: one random byte set per limb.
    let sparse_h = |r: &mut Rng| {
        let mut b = [0u8; 32];
        for l in 0..4 {
            b[l * 8 + (r.next() % 8) as usize] = (r.next() & 0xff) as u8;
        }
        b[31] &= 0x3f;
        fehelio(b)
    };
    // High limbs zero: a value below 2^64.
    let small_h = |r: &mut Rng| {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&r.next().to_le_bytes());
        fehelio(b)
    };
    // Dense: all bytes 0xff except the top bits (near the modulus).
    let dense_h = |_r: &mut Rng| {
        let mut b = [0xffu8; 32];
        b[31] = 0x3f;
        fehelio(b)
    };
    measure(
        &run,
        "property: helio square sparse",
        Mode::Structured,
        sparse_h,
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "property: helio square small",
        Mode::Structured,
        small_h,
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "property: helio square dense",
        Mode::Structured,
        dense_h,
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "property: fe25519 square sparse",
        Mode::Structured,
        |r| {
            let mut b = [0u8; 32];
            for l in 0..4 {
                b[l * 8 + (r.next() % 8) as usize] = (r.next() & 0xff) as u8;
            }
            b[31] &= 0x3f;
            fe25519(b)
        },
        |a| low64(&a.square()),
    );
    measure(
        &run,
        "property: fe25519 square small",
        Mode::Structured,
        |r| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&r.next().to_le_bytes());
            fe25519(b)
        },
        |a| low64(&a.square()),
    );

    println!("-- crypto-bigint 0.5.5 Residue::pow with a secret exponent (BINSEC found a branch; unreached by our code)");
    both!(
        &run,
        "residue pow (secret exponent)",
        |r| {
            (
                R::new(&U256::from_be_slice(&r.bytes32())),
                U256::from_be_slice(&r.bytes32()),
            )
        },
        |(a, e)| a.pow(e).retrieve().as_limbs()[0].0,
    );

    println!("-- positive controls (must show a class difference)");
    measure(
        &run,
        "control: branch on a byte",
        Mode::Constant(0u8),
        |r| (r.next() & 0xff) as u8,
        |b| {
            let mut s = 0u64;
            for i in 0..64u64 {
                if (*b as u64 + i).is_multiple_of(7) {
                    s = black_box(s.wrapping_mul(3))
                } else {
                    s = black_box(s + 1)
                }
            }
            s
        },
    );
    measure(
        &run,
        "control: data-dependent loop",
        Mode::Constant(1u8),
        |r| (r.next() & 0xff) as u8 | 1,
        |b| {
            let mut s = 0u64;
            for _ in 0..(*b as u64) {
                s = black_box(s.wrapping_mul(6364136223846793005).wrapping_add(1))
            }
            s
        },
    );
}
