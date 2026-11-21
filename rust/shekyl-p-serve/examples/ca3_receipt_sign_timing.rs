// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! CA-3, FN-DSA: is the receipt countersignature's signing time independent
//! of the persona's receipt key? (`docs/design/CRYPTO_AUDIT.md` §3.)
//!
//! A persona countersigns every pass it serves with its long-lived receipt
//! key (Ed25519 + FN-DSA-1024, `ARCHIVAL_SERVE_CREDIT_SPEC.md` §6), and
//! anyone fetching a shard from its onion can ask for one. If the time a
//! signature takes depends on the key, every fetch is a sample of that
//! dependence. This program measures whether the signer as it ships shows
//! one.
//!
//! # What is timed
//!
//! The held signer the serve path signs with (`FnDsaHybridSigner`, decoded
//! once and kept, as `HeldReceiptKey` keeps it), signing a pass transcript
//! (`PassTranscript::message`, the bytes `sign_receipt_transcript` signs)
//! under `SCHEME_DOMAIN_RECEIPT`. The serve path draws FN-DSA's seed from
//! the OS; this program draws it from `sign_with_rng_seed`'s seeded stream
//! instead, so that each entry's seed is known and its restart count can be
//! recovered (below). Everything after the seed is drawn is the same code.
//!
//! # Method (after `dudect`, as RT-P4)
//!
//! Two classes are interleaved by a coin drawn before the loop, each
//! signature is timed alone, and the two timing distributions are compared
//! with Welch's t on the raw samples and below each of 100 cut-offs placed
//! from a discarded calibration batch. The reported figure is the largest
//! `|t|`. Every input is prepared before the loop; the loop reads entry
//! `i`, times the signature and nothing else, and stores the time and the
//! signature. Nothing is checked until the loop is over.
//!
//! # The secret is the key; everything else is drawn alike
//!
//! A class is a set of key slots, and the classes differ only in which keys
//! their slots hold. Each entry draws a fresh transcript and a fresh
//! 32-byte RNG seed, the same way in both classes. Holding the message or
//! the seed fixed would not make two keys' computations alike: FN-DSA
//! hedges the seed with the hashed signing key and the message
//! representative with the hashed verifying key, so the sampler's stream is
//! the key's whatever is passed in. A fixed message and seed would instead
//! make one class a single computation repeated against a varied one.
//!
//! **Equal footprint.** Each class holds [`SLOTS`] decoded keys (118,640
//! bytes each), and each entry signs from a slot drawn uniformly. In the
//! `fixed` class every slot holds the same key; in the `varied` class each
//! slot holds its own. Both classes therefore touch the same amount of
//! memory in the same pattern, and neither has its key warmer in the cache
//! than the other.
//!
//! **Restarts.** FN-DSA's signing loop restarts when a candidate signature
//! is too long (about 1 in 820 at n = 1024), and a restart repeats almost
//! the whole signature. Which entries restart is a function of the key, the
//! message and the seed, so it is not the same across classes. The
//! signature's 40-byte nonce is the first output of the sampler's stream
//! for `seed ‖ counter`, so after the loop the restart count of every entry
//! is recovered from its signature, and only entries that did not restart
//! enter the timing statistics. Leaving them out would hide a restart
//! rate that depends on the key, which is itself a timing difference an
//! observer sees (a restart roughly doubles a signature), so the classes'
//! restart rates are compared too (a pooled two-proportion `z`), and the
//! lines read the larger of `|t|` and `|z|`.
//!
//! # The lines
//!
//! - `fixed-vs-varied`: one key in every slot against a key per slot.
//! - `fixed-pair`: key A in every slot against key B in every slot. Two
//!   fixed keys: a key-dependent time with nothing for familiarity to act
//!   on, which separates the two where `fixed-vs-varied` cannot (CA-2).
//!
//! # Checks, nulls and the control
//!
//! **Checks**, each able to fail and each voiding the run: every key the
//! program replicates from its seed gives the public key the scheme gives;
//! every timed signature returned `Ok` and verifies; every signature's
//! nonce is the one its key, transcript and seed derive for some counter.
//!
//! **Nulls.** Key A in two disjoint sets of slots, and the varied class's
//! 256 keys in two disjoint sets of slots. The keys are the same on both
//! sides, so nothing differs, and whatever they report is the harness or
//! the machine. (Two different key sets would not be a null: under a key
//! dependence they differ too.)
//!
//! **A planted leak.** The first null again, with extra work inside the
//! timed region for one class, calibrated to
//! [`CONTROL_LEAK_FRACTION`] of one signature's median time. It must be
//! detected; a pass excludes a leak of that size or more, and nothing
//! smaller.
//!
//! Run: `cargo run --release --locked -p shekyl-p-serve --example
//! ca3_receipt_sign_timing -- [SAMPLES [SEED]]` (default 1,000,000 samples
//! per comparison). x86_64 dispatches to the crate's AVX2 path at run time
//! on a CPU that has it; the baseline (SSE2) path is measured by a build with
//! `--features fn-dsa-sign/no_avx2`, as the CI step that runs the vectors on
//! it does. Memory: about 1.4 GB at 1,000,000 samples, most of it the
//! signatures kept for verification after the loop.

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

use fn_dsa::{
    compute_mu, sign_key_size, KeyPairGenerator as _, KeyPairGenerator1024, DOMAIN_NONE,
    FN_DSA_LOGN_1024, HASH_ID_RAW, SHAKE256,
};
use rand::RngCore as _;
use shekyl_archival_retention::pass_anchor::{
    PassRequestHeader, PassTranscript, PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_DELIVERY_DIGEST_LEN,
    PASS_REQUEST_HEADER_LEN,
};
use shekyl_crypto_pq::fn_dsa_hybrid::{
    FnDsaHybridPublicKey, FnDsaHybridSecretKey, FnDsaHybridSignature, FnDsaHybridSigner,
    HybridEd25519FnDsa, FN_DSA_1024_PUBLIC_KEY_LENGTH, FN_DSA_1024_SECRET_KEY_LENGTH,
    FN_DSA_1024_SIGNATURE_LENGTH,
};
use shekyl_crypto_pq::seeded_rng::SeededRng;
use shekyl_crypto_pq::signature::{
    SignatureScheme as _, HYBRID_SCHEME_ID_ED25519_FN_DSA_1024, SCHEME_DOMAIN_RECEIPT,
};

/// `|t|` below this on every cut-off is "no evidence of a leak"; dudect's
/// own bound, as RT-P4.
const T_PASS: f64 = 4.5;
/// `|t|` above this is a leak beyond reasonable doubt; the control must
/// exceed it.
const T_LEAK: f64 = 10.0;
/// The planted leak, as a fraction of one signature's median time.
const CONTROL_LEAK_FRACTION: f64 = 0.005;
const DEFAULT_SAMPLES: usize = 1_000_000;
/// Samples used to place the cut-offs before any statistic is accumulated.
const CALIBRATION: usize = 10_000;
/// Cut-offs, as in dudect: `1 - 0.5^(10 (i + 1) / CROPS)` quantiles.
const CROPS: usize = 100;
/// A cut-off counts only when both classes keep more samples than this.
const MIN_CROPPED: f64 = 10_000.0;
/// Decoded keys per class. 256 slots of 118,640 bytes is 30 MB a class,
/// more than any last-level cache the run's devices have, so neither
/// class's keys sit in the cache by being few.
const SLOTS: usize = 256;
/// The input seed of the registered run. No run before the registration
/// drew from it.
const REGISTERED_SEED: u64 = 0x4341_335f_464e_4453;
/// XORed into the seed for the slot-placement stream, so placement draws
/// nothing from the stream the keys and entries come from.
const PLACEMENT_STREAM: u64 = 0x504c_4143_454d_454e;

/// FN-DSA's per-signature seed, drawn from the caller's RNG and hedged
/// (`fn-dsa-sign` 0.4.0, `lib.rs`, `SigningKey::sign`).
const FN_DSA_SEED_LEN: usize = 40;
/// The nonce a signature carries after its header byte, the first output
/// of the sampler's stream (`fn-dsa-sign` 0.4.0, `sign_inner`).
const FN_DSA_NONCE_LEN: usize = 40;
/// The signing loop's bound (`sign_inner`: `for counter in 0..27u8`).
const FN_DSA_MAX_ATTEMPTS: u8 = 27;
/// The hashed verifying key at the tail of an encoded signing key.
const FN_DSA_HASHED_VRFY_KEY_LEN: usize = 64;
/// The hashed signing key the crate hedges each seed with.
const FN_DSA_HASHED_SIGN_KEY_LEN: usize = 40;

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

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

/// One receipt key: what the scheme makes of two seeds, and the two hashes
/// the crate derives from its FN-DSA half, which the nonce check needs.
struct Key {
    seeds: ([u8; 32], [u8; 32]),
    secret: FnDsaHybridSecretKey,
    public: FnDsaHybridPublicKey,
    hashed_sign_key: [u8; FN_DSA_HASHED_SIGN_KEY_LEN],
    hashed_vrfy_key: [u8; FN_DSA_HASHED_VRFY_KEY_LEN],
    /// The replicated FN-DSA public key equals the scheme's.
    replicates: bool,
}

impl Key {
    fn new(inputs: &mut Inputs) -> Self {
        let ed25519_seed: [u8; 32] = inputs.array();
        let fn_dsa_seed: [u8; 32] = inputs.array();
        Self::from_seeds(ed25519_seed, fn_dsa_seed)
    }

    /// The same key again, generated afresh from its seeds.
    fn again(&self) -> Self {
        Self::from_seeds(self.seeds.0, self.seeds.1)
    }

    fn from_seeds(ed25519_seed: [u8; 32], fn_dsa_seed: [u8; 32]) -> Self {
        let (public, secret) = HybridEd25519FnDsa::keypair_from_seeds(&ed25519_seed, &fn_dsa_seed)
            .expect("key generation from two seeds is infallible");
        // The scheme keeps its FN-DSA secret to itself, so the encoded key
        // is regenerated the way the scheme generates it
        // (`fn_dsa_hybrid.rs`, `fn_dsa_keygen`) and held to its public half.
        let mut rng = SeededRng::from_seed(&fn_dsa_seed);
        let mut encoded = [0u8; FN_DSA_1024_SECRET_KEY_LENGTH];
        let mut vrfy = [0u8; FN_DSA_1024_PUBLIC_KEY_LENGTH];
        KeyPairGenerator1024::default().keygen(FN_DSA_LOGN_1024, &mut rng, &mut encoded, &mut vrfy);
        let canonical = public.to_canonical_bytes();
        let replicates = canonical.ends_with(&vrfy);
        // The encoded key is `header ‖ f ‖ g ‖ F ‖ H(vk)`, F one byte a
        // coefficient; the crate hashes `f ‖ g` (`decode_inner`).
        let n = 1usize << FN_DSA_LOGN_1024;
        let fg_end = sign_key_size(FN_DSA_LOGN_1024) - n - FN_DSA_HASHED_VRFY_KEY_LEN;
        let mut hashed_sign_key = [0u8; FN_DSA_HASHED_SIGN_KEY_LEN];
        let mut sh = SHAKE256::new();
        sh.inject(&encoded[1..fg_end]);
        sh.flip();
        sh.extract(&mut hashed_sign_key);
        let mut hashed_vrfy_key = [0u8; FN_DSA_HASHED_VRFY_KEY_LEN];
        hashed_vrfy_key.copy_from_slice(&encoded[encoded.len() - FN_DSA_HASHED_VRFY_KEY_LEN..]);
        Self {
            seeds: (ed25519_seed, fn_dsa_seed),
            secret,
            public,
            hashed_sign_key,
            hashed_vrfy_key,
            replicates,
        }
    }

    /// The attempt at which FN-DSA's loop stopped for this key's signature
    /// over `message` with its seed drawn from `rng_seed`: the counter whose
    /// nonce is `observed`. `None` if no attempt's nonce is.
    fn attempt(&self, message: &[u8], rng_seed: &[u8; 32], observed: &[u8]) -> Option<u8> {
        let mut framed = Vec::with_capacity(1 + message.len());
        framed.push(HYBRID_SCHEME_ID_ED25519_FN_DSA_1024);
        framed.extend_from_slice(message);
        let inner = shekyl_crypto_hash::cshake256_64(SCHEME_DOMAIN_RECEIPT, &framed);
        let mu = compute_mu(&self.hashed_vrfy_key, &DOMAIN_NONE, &HASH_ID_RAW, &inner);
        let mut drawn = [0u8; FN_DSA_SEED_LEN];
        SeededRng::from_seed(rng_seed).fill_bytes(&mut drawn);
        let mut seed = [0u8; FN_DSA_SEED_LEN];
        let mut sh = SHAKE256::new();
        sh.inject(&self.hashed_sign_key);
        sh.inject(&mu);
        sh.inject(&drawn);
        sh.flip();
        sh.extract(&mut seed);
        (0..FN_DSA_MAX_ATTEMPTS).find(|&counter| {
            let mut sh = SHAKE256::new();
            sh.inject(&seed);
            sh.inject(&[counter]);
            sh.flip();
            let mut nonce = [0u8; FN_DSA_NONCE_LEN];
            sh.extract(&mut nonce);
            nonce == observed
        })
    }
}

/// A class: [`SLOTS`] held signers and the key each holds.
struct Class {
    name: &'static str,
    keys: Vec<Key>,
    slots: Vec<(FnDsaHybridSigner, usize)>,
}

impl Class {
    /// Every slot holds `key`. The slots are decoded by [`decode_interleaved`].
    fn fixed(name: &'static str, key: Key) -> Self {
        Self {
            name,
            keys: vec![key],
            slots: Vec::with_capacity(SLOTS),
        }
    }

    /// Each slot holds its own key, generated from `seeds` (one pair per
    /// slot, drawn once for the whole run, so every comparison and every
    /// device uses the same keys).
    fn varied(name: &'static str, seeds: &[([u8; 32], [u8; 32])]) -> Self {
        let keys: Vec<Key> = seeds
            .iter()
            .map(|(ed25519, fn_dsa)| Key::from_seeds(*ed25519, *fn_dsa))
            .collect();
        Self {
            name,
            keys,
            slots: Vec::with_capacity(SLOTS),
        }
    }

    /// The key slot `slot` holds: the one key, or the slot's own.
    fn key_index(&self, slot: usize) -> usize {
        if self.keys.len() == 1 {
            0
        } else {
            slot
        }
    }

    fn replicates(&self) -> bool {
        self.keys.iter().all(|key| key.replicates)
    }
}

/// Decode both classes' slots in a shuffled order, so that which addresses
/// each class's slots get is random, as which class each entry belongs to is
/// random in time.
///
/// The allocator places blocks in the order they are asked for. Decoded one
/// class after the other, the second class's 30 MB had a region of its own;
/// decoded alternately, each class had a fixed alignment pattern (118,640
/// bytes is 128 short of 29 pages, so the classes took the even and the odd
/// 128-byte offsets). The development runs measured both: a null of one key
/// set in two slot sets read `|t|` 11.94 and then 37.69 at 200,000 samples,
/// with the second class slower by 0.15 % and 0.3 % of a signature at every
/// quantile. `placement` is a stream of its own, so the keys and the entries
/// are what they would be without it.
fn decode_shuffled(classes: &mut [Class; 2], placement: &mut Inputs) {
    let mut order: Vec<(usize, usize)> =
        (0..SLOTS).flat_map(|slot| [(0, slot), (1, slot)]).collect();
    for i in (1..order.len()).rev() {
        let j = (placement.next() % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let mut decoded: [Vec<Option<(FnDsaHybridSigner, usize)>>; 2] = [
        (0..SLOTS).map(|_| None).collect(),
        (0..SLOTS).map(|_| None).collect(),
    ];
    for (class, slot) in order {
        let key = classes[class].key_index(slot);
        let signer = FnDsaHybridSigner::new(&classes[class].keys[key].secret).expect("decodes");
        decoded[class][slot] = Some((signer, key));
    }
    for (class, slots) in classes.iter_mut().zip(decoded) {
        class.slots = slots
            .into_iter()
            .map(|slot| slot.expect("every slot is decoded once"))
            .collect();
    }
}

/// A pass transcript with every field drawn: the bytes the serve path signs.
fn transcript(inputs: &mut Inputs) -> [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN] {
    let mut header: [u8; PASS_REQUEST_HEADER_LEN] = inputs.array();
    // The stream byte: economy or support, as a request names one.
    header[0] = (inputs.next() & 1) as u8;
    let header = PassRequestHeader::from_bytes(&header).expect("a stream byte of 0 or 1 parses");
    let digest: [u8; PASS_DELIVERY_DIGEST_LEN] = inputs.array();
    PassTranscript::new(header, inputs.next(), digest).message()
}

struct Entry {
    class: u8,
    slot: u16,
    message: [u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    rng_seed: [u8; 32],
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

/// The checks of one comparison, made after its loop.
#[derive(Default)]
struct Checks {
    entries: usize,
    failed: usize,
    not_verified: usize,
    nonce_unmatched: usize,
    /// Measured entries (after the calibration batch) that signed, per class.
    measured: [usize; 2],
    /// Of those, the ones that restarted at least once, per class.
    restarted: [usize; 2],
}

impl Checks {
    fn hold(&self) -> bool {
        self.failed == 0 && self.not_verified == 0 && self.nonce_unmatched == 0
    }

    /// The two-proportion z of the classes' restart rates, pooled. A
    /// restarted entry is left out of the timing statistics, so a restart
    /// rate that depends on the key would not show in `t`; this is where it
    /// shows. Zero when neither class restarted.
    fn restart_z(&self) -> f64 {
        let [n0, n1] = self.measured.map(|n| n as f64);
        let [r0, r1] = self.restarted.map(|r| r as f64);
        if n0 < 1.0 || n1 < 1.0 {
            return 0.0;
        }
        let pooled = (r0 + r1) / (n0 + n1);
        let spread = pooled * (1.0 - pooled) * (1.0 / n0 + 1.0 / n1);
        if spread <= 0.0 {
            return 0.0;
        }
        (r0 / n0 - r1 / n1) / spread.sqrt()
    }
}

struct Outcome {
    max_t: f64,
    median_ns: f64,
    samples: [f64; 2],
    checks: Checks,
}

impl Outcome {
    /// What the lines read: the larger of the timing `|t|` and the restart
    /// rates' `|z|`.
    fn figure(&self) -> f64 {
        self.max_t.max(self.checks.restart_z().abs())
    }
}

/// One comparison. Every input is generated before the loop, the two
/// classes interleaved by a coin drawn then. The loop reads entry `i`,
/// times the signature and nothing else, and stores the time and the
/// result. `planted` is the control's extra work for class 1, inside the
/// timed region; the real comparisons pass `None`.
fn compare(
    classes: &mut [Class; 2],
    samples: usize,
    inputs: &mut Inputs,
    planted: Option<u64>,
) -> Outcome {
    let total = samples + CALIBRATION;
    let entries: Vec<Entry> = (0..total)
        .map(|_| Entry {
            class: u8::from(inputs.next() & 1 == 1),
            slot: (inputs.next() % SLOTS as u64) as u16,
            message: transcript(inputs),
            rng_seed: inputs.array(),
        })
        .collect();
    let mut times = vec![0u64; total];
    let mut results: Vec<Option<FnDsaHybridSignature>> = Vec::with_capacity(total);

    for (index, entry) in entries.iter().enumerate() {
        let (signer, _) = &mut classes[usize::from(entry.class)].slots[usize::from(entry.slot)];
        let start = Instant::now();
        let signature = signer.sign_with_rng_seed(
            SCHEME_DOMAIN_RECEIPT,
            black_box(&entry.message),
            &entry.rng_seed,
        );
        if let Some(iterations) = planted {
            if entry.class == 1 {
                spin(iterations);
            }
        }
        let elapsed = start.elapsed();
        times[index] = elapsed.as_nanos() as u64;
        results.push(signature.ok());
    }

    // The checks, and each entry's restart count, after the loop.
    let mut checks = Checks {
        entries: total,
        ..Checks::default()
    };
    let mut restarts = vec![0u8; total];
    let fn_dsa_start = FnDsaHybridSignature::CANONICAL_LEN - FN_DSA_1024_SIGNATURE_LENGTH;
    let scheme = HybridEd25519FnDsa;
    for (index, (entry, result)) in entries.iter().zip(&results).enumerate() {
        let class = &classes[usize::from(entry.class)];
        let key = &class.keys[class.slots[usize::from(entry.slot)].1];
        let Some(signature) = result else {
            checks.failed += 1;
            continue;
        };
        let measured = index >= CALIBRATION;
        if measured {
            checks.measured[usize::from(entry.class)] += 1;
        }
        if scheme
            .verify(
                &key.public,
                SCHEME_DOMAIN_RECEIPT,
                &entry.message,
                signature,
            )
            .is_err()
        {
            checks.not_verified += 1;
        }
        let canonical = signature.to_canonical_bytes();
        let nonce = &canonical[fn_dsa_start + 1..fn_dsa_start + 1 + FN_DSA_NONCE_LEN];
        match key.attempt(&entry.message, &entry.rng_seed, nonce) {
            Some(counter) => {
                restarts[index] = counter;
                if measured && counter > 0 {
                    checks.restarted[usize::from(entry.class)] += 1;
                }
            }
            None => checks.nonce_unmatched += 1,
        }
    }

    let mut calibration: Vec<f64> = times[..CALIBRATION].iter().map(|&t| t as f64).collect();
    calibration.sort_by(f64::total_cmp);
    let median_ns = calibration[CALIBRATION / 2];
    let cutoffs: Vec<f64> = (0..CROPS)
        .map(|i| {
            let quantile = 1.0 - 0.5f64.powf(10.0 * (i as f64 + 1.0) / CROPS as f64);
            let index = ((quantile * CALIBRATION as f64) as usize).min(CALIBRATION - 1);
            calibration[index]
        })
        .collect();

    // Only entries that signed at the first attempt are compared.
    let counted = |index: usize| results[index].is_some() && restarts[index] == 0;
    let mut raw = [Moments::default(); 2];
    let mut cropped = vec![[Moments::default(); 2]; CROPS];
    let mut by_class: [Vec<u64>; 2] = [Vec::new(), Vec::new()];
    for index in CALIBRATION..total {
        if !counted(index) {
            continue;
        }
        let class = usize::from(entries[index].class);
        let ns = times[index] as f64;
        raw[class].push(ns);
        by_class[class].push(times[index]);
        for (cutoff, moments) in cutoffs.iter().zip(cropped.iter_mut()) {
            if ns < *cutoff {
                moments[class].push(ns);
            }
        }
    }

    // Quantiles of the measured run itself, per class.
    by_class[0].sort_unstable();
    by_class[1].sort_unstable();
    if !by_class[0].is_empty() && !by_class[1].is_empty() {
        for q in [1usize, 5, 10, 25, 50, 75, 90, 95, 99] {
            let a = by_class[0][by_class[0].len() * q / 100];
            let b = by_class[1][by_class[1].len() * q / 100];
            println!(
                "  quantile={q} class0={a} class1={b} diff={}",
                i128::from(a) - i128::from(b)
            );
        }
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
        let enough = moments[0].n > MIN_CROPPED && moments[1].n > MIN_CROPPED;
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
    println!(
        "  check entries={} failed={} not_verified={} nonce_unmatched={} measured0={} restarted0={} \
         measured1={} restarted1={} restart_z={:.2} verdict={}",
        checks.entries,
        checks.failed,
        checks.not_verified,
        checks.nonce_unmatched,
        checks.measured[0],
        checks.restarted[0],
        checks.measured[1],
        checks.restarted[1],
        checks.restart_z(),
        if checks.hold() { "as-intended" } else { "FAILED" }
    );
    Outcome {
        max_t,
        median_ns,
        samples: [raw[0].n, raw[1].n],
        checks,
    }
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

/// Whether the CPU offers AVX2. The path a build runs is set by the build:
/// with `fn-dsa-sign/no_avx2` the AVX2 code is not compiled in at all.
fn cpu_avx2() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            "yes"
        } else {
            "no"
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        "n/a"
    }
}

fn main() {
    let samples = std::env::args()
        .nth(1)
        .map(|arg| arg.parse().expect("SAMPLES is a number"))
        .unwrap_or(DEFAULT_SAMPLES);
    // A seed given here is for checking that the harness runs without
    // drawing the registered inputs.
    let seed = std::env::args().nth(2).map_or(REGISTERED_SEED, |arg| {
        arg.parse().expect("SEED is a number")
    });
    let mut inputs = Inputs(seed);

    println!("CA-3 FN-DSA receipt countersignature timing (fn-dsa 0.4.0, held signer), inputs prepared before the loop");
    println!(
        "arch={} os={} cpu_avx2={} samples_per_comparison={samples} calibration={CALIBRATION} \
         crops={CROPS} slots={SLOTS} inputs={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        cpu_avx2(),
        if seed == REGISTERED_SEED {
            "registered"
        } else {
            "NOT-REGISTERED"
        }
    );
    println!(
        "pass: |t| and restart |z| < {T_PASS} on fixed-vs-varied and on fixed-pair; null comparisons: \
         both < {T_PASS}; control: |t| > {T_LEAK}"
    );

    // Every key is drawn here, before any comparison, so the keys do not
    // depend on the sample count: every device signs with the same keys.
    let key_a = Key::new(&mut inputs);
    let key_b = Key::new(&mut inputs);
    let pool: Vec<([u8; 32], [u8; 32])> = (0..SLOTS)
        .map(|_| (inputs.array(), inputs.array()))
        .collect();

    // Slot placement draws from its own stream (see `decode_shuffled`).
    let mut placement = Inputs(seed ^ PLACEMENT_STREAM);
    let mut replicated = true;
    let mut checked = true;
    let mut run = |label: &str, classes: [Class; 2], inputs: &mut Inputs, planted: Option<u64>| {
        replicated &= classes.iter().all(Class::replicates);
        let mut classes = classes;
        decode_shuffled(&mut classes, &mut placement);
        let outcome = compare(&mut classes, samples, inputs, planted);
        checked &= outcome.checks.hold();
        let word = if planted.is_some() {
            "control"
        } else if label == "null" || label == "pass-line" {
            verdict(outcome.figure())
        } else {
            "information"
        };
        println!(
            "{label}={}-vs-{} max_abs_t={:.2} restart_abs_z={:.2} median_ns={:.0} n0={:.0} n1={:.0} \
             verdict={word}",
            classes[0].name,
            classes[1].name,
            outcome.max_t,
            outcome.checks.restart_z().abs(),
            outcome.median_ns,
            outcome.samples[0],
            outcome.samples[1],
        );
        outcome
    };

    // Pass line 1: one key in every slot against a key per slot.
    let fixed_varied = run(
        "pass-line",
        [
            Class::fixed("fixed", key_a.again()),
            Class::varied("varied", &pool),
        ],
        &mut inputs,
        None,
    );
    // Pass line 2: key A against key B, each in every slot of its class.
    let fixed_pair = run(
        "pass-line",
        [
            Class::fixed("fixed-a", key_a.again()),
            Class::fixed("fixed-b", key_b),
        ],
        &mut inputs,
        None,
    );
    // Nulls: nothing differs between the classes.
    let null_fixed = run(
        "null",
        [
            Class::fixed("fixed-a", key_a.again()),
            Class::fixed("fixed-a-other-slots", key_a.again()),
        ],
        &mut inputs,
        None,
    );
    // The same 256 keys decoded into two sets of slots: under a key
    // dependence two different key sets would differ, and a null that can
    // cross on the effect under test would void a run that should fail.
    let null_varied = run(
        "null",
        [
            Class::varied("varied", &pool),
            Class::varied("varied-other-slots", &pool),
        ],
        &mut inputs,
        None,
    );
    let worst_null = null_fixed.figure().max(null_varied.figure());
    // The control is planted on a null, so no real effect adds to or
    // cancels it: key A in two slot sets, class 1 with the planted work.
    let leak_ns = null_fixed.median_ns * CONTROL_LEAK_FRACTION;
    let iterations = calibrate_spin(leak_ns);
    let control = run(
        "control",
        [
            Class::fixed("fixed-a", key_a.again()),
            Class::fixed("fixed-a-other-slots", key_a),
        ],
        &mut inputs,
        Some(iterations),
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
    println!(
        "check=keys replicated={replicated} verdict={}",
        if replicated { "as-intended" } else { "FAILED" }
    );

    // A run whose inputs are not what they claim, that could not have seen
    // a leak, or that sees one where there is none, is void before the
    // pass lines are read at all.
    let checks_hold = replicated && checked;
    let detected = control.max_t > T_LEAK;
    let unbiased = worst_null < T_PASS;
    let worst_pass = fixed_varied.figure().max(fixed_pair.figure());
    let passed = checks_hold && detected && unbiased && worst_pass < T_PASS;
    println!(
        "result={} fixed_vs_varied={:.2} fixed_pair={:.2} worst_null={worst_null:.2} \
         control_abs_t={:.2}",
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
        fixed_varied.figure(),
        fixed_pair.figure(),
        control.max_t
    );
    std::process::exit(i32::from(!passed));
}
