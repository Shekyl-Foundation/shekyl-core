// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! (c) against the hardware: every op, every mode, inputs from random
//! bits, hand-picked edges, and the RandomX register domains. (b) runs
//! the hardware instruction under the mode, so it is the oracle.

use super::*;

const OPS: [Op; 5] = [Op::Add, Op::Sub, Op::Mul, Op::Div, Op::Sqrt];

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
    let more: Vec<f64> = v.iter().flat_map(|&x| [x.next_up(), x.next_down()]).collect();
    v.extend(more);
    v
}

/// RandomX F group operand: an int32 converted exactly, or an A value
/// `1.fraction * 2^(0..=31)`.
fn rx_f(r: &mut Rng) -> f64 {
    match r.next() % 3 {
        0 => f64::from(r.next() as i32),
        1 => f64::from_bits(crate::vm::get_small_positive_float_bits(r.next())),
        _ => {
            // an F register mid-program: a sum, possibly FSCAL'd
            let x = f64::from(r.next() as i32) + f64::from_bits(crate::vm::get_small_positive_float_bits(r.next()));
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
    let raw = f64::from(r.next() as i32);
    let masked = crate::vm::mask_register_exponent_mantissa(crate::vm::F128([raw, raw]), [mask, mask]);
    if r.next() & 1 == 0 {
        masked[0]
    } else {
        f64::from_bits(crate::vm::get_small_positive_float_bits(r.next()))
    }
}

fn check(imp: Impl, a: f64, b: f64, tally: &mut [[u64; 4]; 5]) {
    for (oi, &o) in OPS.iter().enumerate() {
        for mode in 0..4 {
            let want = op(Impl::B, o, [a, b], [b, a], mode);
            let got = op(imp, o, [a, b], [b, a], mode);
            for l in 0..2 {
                assert!(
                    same(want[l], got[l]),
                    "{imp:?} {o:?} mode {mode}: lane {l} a={:e} ({:#x}) b={:e} ({:#x}): hw {:e} ({:#x}) vs {:e} ({:#x})",
                    [a, b][l],
                    [a, b][l].to_bits(),
                    [b, a][l],
                    [b, a][l].to_bits(),
                    want[l],
                    want[l].to_bits(),
                    got[l],
                    got[l].to_bits()
                );
            }
            tally[oi][mode as usize] += 1;
        }
    }
}

fn run(imp: Impl, n_random: u64) {
    let mut tally = [[0u64; 4]; 5];
    let e = edges();
    for &a in &e {
        for &b in &e {
            check(imp, a, b, &mut tally);
        }
    }
    let mut r = Rng(0x5EED_0000 + imp as u64);
    for _ in 0..n_random {
        // random bits, both operands
        let (a, b) = (f64::from_bits(r.next()), f64::from_bits(r.next()));
        check(imp, a, b, &mut tally);
        // close magnitudes (cancellation, ties)
        let a = f64::from_bits(r.next() >> 2 | 0x3000_0000_0000_0000);
        let b = f64::from_bits(a.to_bits() ^ (r.next() & 0xFFFF_FFFF));
        check(imp, a, -b, &mut tally);
        // the RandomX domains
        check(imp, rx_f(&mut r), rx_f(&mut r), &mut tally);
        check(imp, rx_e(&mut r), rx_e(&mut r), &mut tally);
        // near overflow and near underflow
        let big = f64::from_bits(0x7FE0_0000_0000_0000 | (r.next() >> 12));
        let small = f64::from_bits(r.next() >> 12 | 0x0010_0000_0000_0000);
        check(imp, big, f64::from_bits(0x3FF0_0000_0000_0000 | (r.next() >> 12)), &mut tally);
        check(imp, small, f64::from_bits(0x3FE0_0000_0000_0000 | (r.next() >> 12)), &mut tally);
        check(imp, small, f64::from_bits(r.next() >> 13), &mut tally);
    }
    eprintln!("{imp:?}: op x mode cases (lanes x2) = {tally:?}");
}

/// Quick tier for `cargo test`; the long run is `--ignored`.
#[test]
fn c_matches_hardware_every_op_and_mode() {
    run(Impl::C, 20_000);
}

#[test]
fn c_int_matches_hardware_every_op_and_mode() {
    run(Impl::CInt, 20_000);
}

#[test]
#[ignore = "long: PROTO_FUZZ_N cases per class (default 20 million)"]
fn c_and_c_int_match_hardware_long() {
    let n = std::env::var("PROTO_FUZZ_N").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000_000);
    run(Impl::C, n);
    run(Impl::CInt, n);
}

/// (b) leaves the control word as it found it, in every mode.
#[test]
fn b_restores_the_control_word() {
    let before = control_word();
    for mode in 0..4 {
        for &o in &OPS {
            let _ = op(Impl::B, o, [1.0, 3.0], [3.0, 7.0], mode);
            assert_eq!(control_word(), before, "{o:?} mode {mode}");
        }
    }
}
