// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The rounding blocks against both oracles, per operation and mode,
//! over random bits, hand-picked edges, cancellation, the RandomX
//! register domains, and operands near overflow and underflow; then
//! the same blocks under a caller whose word has flush-to-zero on.
//!
//! The quick tier runs in every `cargo test`. The long tier
//! (`blocks_match_both_oracles_long`, `--ignored`) is the nightly's,
//! sized by `RANDOMX_FP_FUZZ_N`.

use super::oracle::{self, Impl, Op, OPS};
use super::*;

/// Every packed operation through a block, nearest included.
fn blocks_only() -> FpEnv {
    FpEnv {
        plain_nearest: false,
        ..FpEnv::capture()
    }
}

fn block(env: &FpEnv, op: Op, a: [f64; 2], b: [f64; 2], mode: u32) -> [f64; 2] {
    match op {
        Op::Add => env.add(a, b, mode),
        Op::Sub => env.sub(a, b, mode),
        Op::Mul => env.mul(a, b, mode),
        Op::Div => env.div(a, b, mode),
        Op::Sqrt => env.sqrt(a, mode),
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The low 32 bits as an `i32`: a RandomX integer register's
    /// low half.
    fn int32(&mut self) -> i32 {
        let [b0, b1, b2, b3, ..] = self.next().to_le_bytes();
        i32::from_le_bytes([b0, b1, b2, b3])
    }
}

fn same(x: f64, y: f64) -> bool {
    x.to_bits() == y.to_bits() || (x.is_nan() && y.is_nan())
}

fn edges() -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        f64::MAX,
        -f64::MAX,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        f64::from_bits(1),
        -f64::from_bits(1),
        f64::from_bits((1u64 << 52) - 1),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::EPSILON,
        1.0 + f64::EPSILON,
        1.0 - f64::EPSILON / 2.0,
        2f64.powi(1023),
        1.5 * 2f64.powi(1023),
        2f64.powi(-1022) * 1.5,
        2f64.powi(-1000),
        2f64.powi(511),
        2f64.powi(512),
        2f64.powi(-511),
        3.0,
        0.1,
        f64::MAX.sqrt(),
        2f64.sqrt(),
    ];
    let more: Vec<f64> = v
        .iter()
        .flat_map(|&x| [x.next_up(), x.next_down()])
        .collect();
    v.extend(more);
    v
}

/// RandomX F group operand: an int32 converted exactly, an A value
/// `1.fraction * 2^(0..=31)`, or a mid-program F value, possibly
/// FSCAL'd.
fn rx_f(r: &mut Rng) -> f64 {
    match r.next() % 3 {
        0 => f64::from(r.int32()),
        1 => f64::from_bits(crate::vm::get_small_positive_float_bits(r.next())),
        _ => {
            let x = f64::from(r.int32())
                + f64::from_bits(crate::vm::get_small_positive_float_bits(r.next()));
            if r.next() & 1 == 0 {
                f64::from_bits(x.to_bits() ^ 0x80F0_0000_0000_0000)
            } else {
                x
            }
        }
    }
}

/// RandomX E group operand: an int32 converted and masked to exponent
/// -255..=0, or an A value.
fn rx_e(r: &mut Rng) -> f64 {
    let mask = crate::vm::get_float_mask(r.next());
    let raw = f64::from(r.int32());
    let masked =
        crate::vm::mask_register_exponent_mantissa(crate::vm::F128([raw, raw]), [mask, mask]);
    if r.next() & 1 == 0 {
        masked[0]
    } else {
        f64::from_bits(crate::vm::get_small_positive_float_bits(r.next()))
    }
}

/// The operand pairs: edges × edges, then `n_random` rounds of each
/// class.
fn pairs(seed: u64, n_random: u64, mut each: impl FnMut(f64, f64)) {
    let e = edges();
    for &a in &e {
        for &b in &e {
            each(a, b);
        }
    }
    let mut r = Rng(seed);
    for _ in 0..n_random {
        each(f64::from_bits(r.next()), f64::from_bits(r.next()));
        // close magnitudes: cancellation and ties
        let a = f64::from_bits(r.next() >> 2 | 0x3000_0000_0000_0000);
        let b = f64::from_bits(a.to_bits() ^ (r.next() & 0xFFFF_FFFF));
        each(a, -b);
        each(rx_f(&mut r), rx_f(&mut r));
        each(rx_e(&mut r), rx_e(&mut r));
        // near overflow, near underflow, subnormal operands
        let big = f64::from_bits(0x7FE0_0000_0000_0000 | (r.next() >> 12));
        let small = f64::from_bits(r.next() >> 12 | 0x0010_0000_0000_0000);
        each(
            big,
            f64::from_bits(0x3FF0_0000_0000_0000 | (r.next() >> 12)),
        );
        each(
            small,
            f64::from_bits(0x3FE0_0000_0000_0000 | (r.next() >> 12)),
        );
        each(small, f64::from_bits(r.next() >> 13));
    }
}

fn cross_check(n_random: u64) {
    let env = blocks_only();
    let mut cases = 0u64;
    pairs(0x5EED_0B10, n_random, |a, b| {
        for &op in &OPS {
            for mode in 0..4 {
                let got = block(&env, op, [a, b], [b, a], mode);
                for imp in [Impl::C, Impl::CInt] {
                    let want = oracle::op(imp, op, [a, b], [b, a], mode);
                    for lane in 0..2 {
                        assert!(
                            same(got[lane], want[lane]),
                            "{op:?} mode {mode} lane {lane}: block {:e} ({:#x}), {imp:?} {:e} ({:#x}); a={:#x} b={:#x}",
                            got[lane],
                            got[lane].to_bits(),
                            want[lane],
                            want[lane].to_bits(),
                            [a, b][lane].to_bits(),
                            [b, a][lane].to_bits(),
                        );
                    }
                }
            }
        }
        cases += 1;
    });
    eprintln!("cross-checked {cases} operand pairs x 5 operations x 4 modes x 2 lanes");
}

#[test]
fn blocks_match_both_oracles_every_op_and_mode() {
    cross_check(20_000);
}

#[test]
#[ignore = "long: RANDOMX_FP_FUZZ_N rounds per operand class (default 20 million); the nightly runs it"]
fn blocks_match_both_oracles_long() {
    let n = std::env::var("RANDOMX_FP_FUZZ_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000_000);
    cross_check(n);
}

/// The blocks run under the fixed word, not the caller's: with the
/// caller's flush-to-zero (and denormals-are-zero) on, every
/// operation in every mode still gives the IEEE result, subnormal
/// operands and results included, and the caller's word comes back.
#[test]
fn blocks_ignore_the_callers_flush_to_zero() {
    // Operands and the oracle's answers first, under the default word:
    // plain Rust arithmetic would itself flush under the caller's.
    let mut cases = Vec::new();
    pairs(0x05EE_DF72, 2_000, |a, b| {
        for &op in &OPS {
            for mode in 0..4 {
                cases.push((
                    op,
                    mode,
                    [a, b],
                    [b, a],
                    oracle::op(Impl::CInt, op, [a, b], [b, a], mode),
                ));
            }
        }
    });
    assert!(
        cases.iter().any(|c| c.4.iter().any(|x| x.is_subnormal())),
        "the cases must include subnormal results for this test to mean anything"
    );
    let (got, word_after) = with_caller_word(FLUSH_TO_ZERO_WORD, || {
        let env = FpEnv::capture();
        assert!(
            !env.plain_nearest,
            "a flush-to-zero caller must send nearest through the blocks too"
        );
        let got: Vec<[f64; 2]> = cases
            .iter()
            .map(|&(op, mode, a, b, _)| block(&env, op, a, b, mode))
            .collect();
        (got, control_bits())
    });
    assert_eq!(
        word_after, FLUSH_TO_ZERO_WORD,
        "the caller's word must come back"
    );
    for ((op, mode, a, b, want), got) in cases.iter().zip(&got) {
        for lane in 0..2 {
            assert!(
                same(got[lane], want[lane]),
                "{op:?} mode {mode} lane {lane} under the caller's flush-to-zero: block {:#x}, IEEE {:#x}; a={:#x} b={:#x}",
                got[lane].to_bits(),
                want[lane].to_bits(),
                a[lane].to_bits(),
                b[lane].to_bits(),
            );
        }
    }
}

/// Every block leaves the caller's control bits as it found them, in
/// every mode, under the default word and under a flush-to-zero one.
#[test]
fn blocks_restore_the_callers_word() {
    for word in [FIXED_WORDS[0], FLUSH_TO_ZERO_WORD] {
        with_caller_word(word, || {
            let env = blocks_only();
            for mode in 0..4 {
                for &op in &OPS {
                    let _ = block(&env, op, [1.0, 3.0], [3.0, 7.0], mode);
                    assert_eq!(control_bits(), word, "{op:?} mode {mode} under {word:#x}");
                }
            }
        });
    }
}
