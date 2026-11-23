// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A reference ML-KEM-768 K-PKE (FIPS 203 Algorithms 4–15) for building
//! RT-P4's inputs, never timed.
//!
//! RT-P4's message-only comparison (`docs/benchmarks/rt_p4_mlkem_decaps_timing_20261121_message.md`)
//! needs invalid ciphertexts whose decryptions are a chosen message: K-PKE
//! encryption with coins the caller picks, and K-PKE decryption to check the
//! result. `fips203` exposes neither (its `encaps_from_seed` derives the
//! coins from the message, and decryption is internal), so they are written
//! here from the standard. This code builds and checks inputs before any
//! loop; the decapsulation that is timed is `fips203`'s.
//!
//! It is held to `fips203` by the harness's self-check, which can fail:
//! encrypting `m` with the coins ML-KEM.Encaps derives must give the very
//! ciphertext `fips203`'s `encaps_from_seed(m)` gives, and decrypting it must
//! give `m`.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

pub const Q: i32 = 3329;
const N: usize = 256;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: u32 = 10;
const DV: u32 = 4;
pub const EK_LEN: usize = 384 * K + 32;
pub const CT_LEN: usize = 32 * (DU as usize * K + DV as usize);
/// ζ = 17, a primitive 256th root of unity mod q.
const ZETA: i64 = 17;

type Poly = [i32; N];

fn bitrev7(i: usize) -> usize {
    let mut r = 0;
    for b in 0..7 {
        r |= ((i >> b) & 1) << (6 - b);
    }
    r
}

fn pow_mod(base: i64, exp: usize) -> i32 {
    let mut result = 1i64;
    for _ in 0..exp {
        result = result * base % i64::from(Q);
    }
    result as i32
}

/// ζ^BitRev7(i), the NTT's twiddles, and ζ^(2·BitRev7(i)+1), the base-case
/// multiplications' γ.
pub struct Tables {
    zetas: [i32; 128],
    gammas: [i32; 128],
}

impl Tables {
    pub fn new() -> Self {
        let mut zetas = [0; 128];
        let mut gammas = [0; 128];
        for i in 0..128 {
            zetas[i] = pow_mod(ZETA, bitrev7(i));
            gammas[i] = pow_mod(ZETA, 2 * bitrev7(i) + 1);
        }
        Self { zetas, gammas }
    }
}

fn reduce(x: i64) -> i32 {
    x.rem_euclid(i64::from(Q)) as i32
}

/// Algorithm 9.
fn ntt(t: &Tables, f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = i64::from(t.zetas[i]);
            i += 1;
            for j in start..start + len {
                let x = reduce(zeta * i64::from(f[j + len]));
                f[j + len] = reduce(i64::from(f[j]) - i64::from(x));
                f[j] = reduce(i64::from(f[j]) + i64::from(x));
            }
        }
        len /= 2;
    }
}

/// Algorithm 10.
fn ntt_inv(t: &Tables, f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            let zeta = i64::from(t.zetas[i]);
            i -= 1;
            for j in start..start + len {
                let x = f[j];
                f[j] = reduce(i64::from(x) + i64::from(f[j + len]));
                f[j + len] = reduce(zeta * (i64::from(f[j + len]) - i64::from(x)));
            }
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = reduce(i64::from(*c) * 3303);
    }
}

/// Algorithms 11 and 12: the product of two polynomials in the NTT domain.
fn multiply_ntts(t: &Tables, f: &Poly, g: &Poly) -> Poly {
    let mut h = [0; N];
    for i in 0..128 {
        let (a0, a1) = (i64::from(f[2 * i]), i64::from(f[2 * i + 1]));
        let (b0, b1) = (i64::from(g[2 * i]), i64::from(g[2 * i + 1]));
        let gamma = i64::from(t.gammas[i]);
        h[2 * i] = reduce(a0 * b0 + i64::from(reduce(a1 * b1)) * gamma);
        h[2 * i + 1] = reduce(a0 * b1 + a1 * b0);
    }
    h
}

fn add(f: &Poly, g: &Poly) -> Poly {
    let mut h = [0; N];
    for i in 0..N {
        h[i] = reduce(i64::from(f[i]) + i64::from(g[i]));
    }
    h
}

/// Algorithm 5 for one polynomial, `d` bits a coefficient, bits little-endian.
fn byte_encode(d: u32, f: &Poly, out: &mut [u8]) {
    out.fill(0);
    for (i, &c) in f.iter().enumerate() {
        let mut a = c as u32;
        for j in 0..d as usize {
            let bit = i * d as usize + j;
            out[bit / 8] |= ((a & 1) as u8) << (bit % 8);
            a >>= 1;
        }
    }
}

/// Algorithm 6 for one polynomial: mod 2^d for d < 12, mod q for d = 12.
fn byte_decode(d: u32, bytes: &[u8]) -> Poly {
    let mut f = [0; N];
    for (i, c) in f.iter_mut().enumerate() {
        let mut a = 0u32;
        for j in 0..d as usize {
            let bit = i * d as usize + j;
            a |= u32::from((bytes[bit / 8] >> (bit % 8)) & 1) << j;
        }
        let a = if d == 12 { a % Q.unsigned_abs() } else { a };
        *c = i32::try_from(a).expect("a coefficient of at most 12 bits fits i32");
    }
    f
}

/// Compress_d, (4.7): ⌈(2^d / q) · x⌋ mod 2^d.
fn compress(d: u32, f: &Poly) -> Poly {
    let mut g = [0; N];
    for (out, &x) in g.iter_mut().zip(f.iter()) {
        let scaled = ((x as u64) << d) + (Q as u64) / 2;
        *out = ((scaled / Q as u64) % (1u64 << d)) as i32;
    }
    g
}

/// Decompress_d, (4.8): ⌈(q / 2^d) · y⌋, halves rounded up.
fn decompress(d: u32, f: &Poly) -> Poly {
    let mut g = [0; N];
    for (out, &y) in g.iter_mut().zip(f.iter()) {
        *out = ((Q as u64 * y as u64 + (1u64 << (d - 1))) >> d) as i32;
    }
    g
}

/// Algorithm 7: a polynomial in the NTT domain from SHAKE128(ρ ‖ j ‖ i).
fn sample_ntt(rho: &[u8], j: u8, i: u8) -> Poly {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[j, i]);
    let mut reader = xof.finalize_xof();
    let mut a = [0; N];
    let mut filled = 0;
    while filled < N {
        let mut c = [0u8; 3];
        reader.read(&mut c);
        let d1 = i32::from(c[0]) + 256 * (i32::from(c[1]) % 16);
        let d2 = i32::from(c[1]) / 16 + 16 * i32::from(c[2]);
        if d1 < Q {
            a[filled] = d1;
            filled += 1;
        }
        if d2 < Q && filled < N {
            a[filled] = d2;
            filled += 1;
        }
    }
    a
}

/// Algorithm 8 over PRF_η(s, b) = SHAKE256(s ‖ b), 64η bytes.
fn sample_cbd(eta: usize, s: &[u8; 32], b: u8) -> Poly {
    let mut xof = Shake256::default();
    xof.update(s);
    xof.update(&[b]);
    let mut bytes = vec![0u8; 64 * eta];
    xof.finalize_xof().read(&mut bytes);
    let bit = |k: usize| i32::from((bytes[k / 8] >> (k % 8)) & 1);
    let mut f = [0; N];
    for (i, c) in f.iter_mut().enumerate() {
        let x: i32 = (0..eta).map(|j| bit(2 * i * eta + j)).sum();
        let y: i32 = (0..eta).map(|j| bit(2 * i * eta + eta + j)).sum();
        *c = reduce(i64::from(x - y));
    }
    f
}

/// Algorithm 14: K-PKE.Encrypt(ek, m, r), with the coins `r` the caller picks.
pub fn encrypt(t: &Tables, ek: &[u8; EK_LEN], m: &[u8; 32], r: &[u8; 32]) -> [u8; CT_LEN] {
    let t_hat: Vec<Poly> = (0..K)
        .map(|i| byte_decode(12, &ek[384 * i..384 * (i + 1)]))
        .collect();
    let rho = &ek[384 * K..];
    let mut a_hat = vec![vec![[0; N]; K]; K];
    for (i, row) in a_hat.iter_mut().enumerate() {
        for (j, entry) in row.iter_mut().enumerate() {
            *entry = sample_ntt(rho, j as u8, i as u8);
        }
    }
    let mut counter = 0u8;
    let mut y_hat = Vec::with_capacity(K);
    for _ in 0..K {
        let mut y = sample_cbd(ETA1, r, counter);
        counter += 1;
        ntt(t, &mut y);
        y_hat.push(y);
    }
    let mut e1 = Vec::with_capacity(K);
    for _ in 0..K {
        e1.push(sample_cbd(ETA2, r, counter));
        counter += 1;
    }
    let e2 = sample_cbd(ETA2, r, counter);

    let mut ct = [0u8; CT_LEN];
    let c1_len = 32 * DU as usize;
    for i in 0..K {
        // (Â^T ∘ ŷ)[i] = Σ_j Â[j][i] ∘ ŷ[j]
        let mut acc = [0; N];
        for j in 0..K {
            acc = add(&acc, &multiply_ntts(t, &a_hat[j][i], &y_hat[j]));
        }
        ntt_inv(t, &mut acc);
        let u = add(&acc, &e1[i]);
        byte_encode(DU, &compress(DU, &u), &mut ct[c1_len * i..c1_len * (i + 1)]);
    }
    let mut acc = [0; N];
    for j in 0..K {
        acc = add(&acc, &multiply_ntts(t, &t_hat[j], &y_hat[j]));
    }
    ntt_inv(t, &mut acc);
    let mu = decompress(1, &byte_decode(1, m));
    let v = add(&add(&acc, &e2), &mu);
    byte_encode(DV, &compress(DV, &v), &mut ct[c1_len * K..]);
    ct
}

/// Algorithm 15: K-PKE.Decrypt(dk_PKE, c), `dk_pke` the first 384k bytes of
/// the ML-KEM decapsulation key.
pub fn decrypt(t: &Tables, dk_pke: &[u8], ct: &[u8; CT_LEN]) -> [u8; 32] {
    let c1_len = 32 * DU as usize;
    let mut s_u = [0; N];
    for i in 0..K {
        let mut u = decompress(DU, &byte_decode(DU, &ct[c1_len * i..c1_len * (i + 1)]));
        ntt(t, &mut u);
        let s_hat = byte_decode(12, &dk_pke[384 * i..384 * (i + 1)]);
        s_u = add(&s_u, &multiply_ntts(t, &s_hat, &u));
    }
    ntt_inv(t, &mut s_u);
    let v = decompress(DV, &byte_decode(DV, &ct[c1_len * K..]));
    let mut w = [0; N];
    for i in 0..N {
        w[i] = reduce(i64::from(v[i]) - i64::from(s_u[i]));
    }
    let mut m = [0u8; 32];
    byte_encode(1, &compress(1, &w), &mut m);
    m
}

/// ML-KEM.Encaps_internal's coins for message `m` (Algorithm 17, line 1):
/// (K, r) = G(m ‖ H(ek)); returns (K, r).
pub fn encaps_coins(ek: &[u8; EK_LEN], m: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let h = Sha3_256::digest(ek);
    let mut g = Sha3_512::new();
    Digest::update(&mut g, m);
    Digest::update(&mut g, h);
    let out = g.finalize();
    let mut key = [0u8; 32];
    let mut r = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    r.copy_from_slice(&out[32..]);
    (key, r)
}

/// J(z ‖ c) = SHAKE256(z ‖ c, 32): the implicit-rejection key decapsulation
/// returns for a ciphertext that fails re-encryption.
pub fn rejection_key(z: &[u8], ct: &[u8; CT_LEN]) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(z);
    xof.update(ct);
    let mut key = [0u8; 32];
    xof.finalize_xof().read(&mut key);
    key
}
