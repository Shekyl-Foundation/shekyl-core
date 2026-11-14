// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Phase 3a Hole-1 gate: the C library's **full-dataset** hash
//! against the Rust verifier's **light-cache** hash
//! (`RANDOMX_V2_PHASE3_PLAN.md` §7).
//!
//! The daemon verifies with the Rust light cache (256 MiB); miners hash
//! with the C library's full dataset (~2 080 MiB, fast mode). RandomX
//! promises the two agree for every `(seedhash, blob)`; the light
//! differential harness compares Rust-light against C-light only, so this
//! is the check that blocks real miners produce verify under the daemon.
//!
//! The C side is `full_dataset::FullDatasetVm`, compiled with the
//! `full-dataset` feature: one cache, one dataset filled on every core,
//! then a fast-mode VM. The light build leaves that feature off, so this
//! module names no miner symbol. The Rust side is the verifier itself
//! ([`shekyl_pow_randomx::PreparedCache::derive`] and
//! [`shekyl_pow_randomx::compute_hash`]), not a wrapper.
//!
//! One dataset per process: each mode builds exactly one, so peak memory
//! is one dataset and the gate's runner can schedule the modes as
//! separate invocations (`src/bin/full_parity.rs`).
//!
//! # Halt on red
//!
//! A light/full mismatch is not a test bug (§7.3): it means the light
//! verifier cannot validate full-dataset-mined blocks. [`Verdict`] keeps
//! it apart from a pin drift (the two sides agree with each other but not
//! with a committed pin), which is an audit, not an architecture finding.

#[cfg(feature = "full-dataset")]
use shekyl_pow_randomx::{compute_hash, PreparedCache, Seedhash};

use crate::canonical_outputs::CANONICAL_RANDOM_HASHES;
use crate::corpus_random::{
    generate_random_corpus, NIGHTLY_DATA_PER_SEEDHASH, NIGHTLY_SEEDHASH_COUNT,
};

/// The Phase 3a canonical known answer: seed `0x01..=0x20` over
/// [`KAT_BLOB`] hashes to this under the C library's full dataset, and
/// the Rust verifier reproduces it (`shekyl-pow-randomx`'s
/// `the_verifier_reproduces_the_canonical_known_answer`).
pub const FROZEN_KAT: [u8; 32] = [
    0x34, 0xf8, 0xb0, 0x17, 0x91, 0x59, 0xd8, 0x37, 0xe4, 0x63, 0xc1, 0x7c, 0x86, 0x92, 0xc1, 0x06,
    0xd2, 0xd3, 0x53, 0x6f, 0x7d, 0xa3, 0x25, 0xae, 0xef, 0xeb, 0x3e, 0x22, 0xa1, 0x36, 0xb6, 0x51,
];

/// The known answer's blob.
pub const KAT_BLOB: &[u8] = b"Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)";

/// The known answer's seed, `0x01..=0x20`.
#[must_use]
pub fn canonical_seed() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i + 1).expect("32 fits u8"))
}

/// One `(seed, blob)` under test.
#[derive(Clone, Debug)]
pub struct Case {
    /// What the line of output calls it.
    pub label: String,
    /// The blob.
    pub blob: Vec<u8>,
    /// A committed hash the C full-dataset result must also equal.
    pub pin: Option<[u8; 32]>,
}

/// One mode's corpus: a seed and its cases (one dataset per seed).
#[derive(Clone, Debug)]
pub struct Corpus {
    /// The seed every case hashes under.
    pub seed: [u8; 32],
    /// The cases.
    pub cases: Vec<Case>,
}

/// `n` bytes of the fixed pattern the extra blob-shaped cases use.
fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 131 + 7) & 0xff).expect("masked to a byte"))
        .collect()
}

/// The genesis case: the mainnet genesis block as the daemon assembles it
/// (the network table's genesis transaction under the genesis tool's
/// fixed header), its hash as the seed and its PoW blob, plus a
/// blob-shaped input under the same seed.
///
/// # Errors
///
/// The table's genesis does not decode, assemble, or hash to its pin.
pub fn genesis_corpus() -> Result<Corpus, String> {
    let block = shekyl_genesis_tool::builder::pinned_genesis(shekyl_network::Network::Mainnet)
        .map_err(|error| error.to_string())?;
    let seed = block.hash().to_bytes();
    Ok(Corpus {
        seed,
        cases: vec![
            Case {
                label: "genesis".into(),
                blob: block.pow_blob(),
                pin: None,
            },
            Case {
                label: "genesis_seed/blob76".into(),
                blob: pattern(76),
                pin: None,
            },
        ],
    })
}

/// The canonical case: the frozen known answer, plus a blob-shaped input
/// under the same independent seed.
#[must_use]
pub fn canonical_corpus() -> Corpus {
    Corpus {
        seed: canonical_seed(),
        cases: vec![
            Case {
                label: "canonical/kat".into(),
                blob: KAT_BLOB.to_vec(),
                pin: Some(FROZEN_KAT),
            },
            Case {
                label: "canonical/blob200".into(),
                blob: pattern(200),
                pin: None,
            },
        ],
    }
}

/// One seed group of the nightly random corpus, every case pinned to its
/// committed canonical hash, so the run re-checks those pins under the
/// mode miners run. The corpus is generated in-process from its pinned
/// stream; `seed_index` names the group.
///
/// # Errors
///
/// `seed_index` is past the corpus's seed count.
pub fn random_corpus_group(seed_index: usize) -> Result<Corpus, String> {
    if seed_index >= NIGHTLY_SEEDHASH_COUNT {
        return Err(format!(
            "seed index {seed_index} out of range (the corpus has {NIGHTLY_SEEDHASH_COUNT})"
        ));
    }
    let corpus = generate_random_corpus(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH);
    if corpus.len() != CANONICAL_RANDOM_HASHES.len() {
        return Err("the corpus and its canonical pins differ in size".into());
    }
    let first = seed_index * NIGHTLY_DATA_PER_SEEDHASH;
    let group = &corpus[first..first + NIGHTLY_DATA_PER_SEEDHASH];
    let seed = *group[0].seedhash.as_bytes();
    let cases = group
        .iter()
        .enumerate()
        .map(|(j, pair)| {
            if *pair.seedhash.as_bytes() == seed {
                Ok(Case {
                    label: format!("corpus/{j} (pin {})", first + j),
                    blob: pair.data.clone(),
                    pin: Some(CANONICAL_RANDOM_HASHES[first + j]),
                })
            } else {
                Err(format!(
                    "corpus record {} is not in its group's seed",
                    first + j
                ))
            }
        })
        .collect::<Result<_, _>>()?;
    Ok(Corpus { seed, cases })
}

/// One case's result.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The case.
    pub label: String,
    /// The C full-dataset hash.
    pub c_full: [u8; 32],
    /// The Rust light-cache hash.
    pub rust_light: [u8; 32],
    /// The committed pin, when the case has one.
    pub pin: Option<[u8; 32]>,
}

impl Outcome {
    /// Light and full agree.
    #[must_use]
    pub fn parity(&self) -> bool {
        self.c_full == self.rust_light
    }

    /// The pin, if any, holds.
    #[must_use]
    pub fn pinned(&self) -> bool {
        self.pin.is_none_or(|pin| pin == self.c_full)
    }
}

/// The verdict over one corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every case agrees light to full and with its pin.
    Pass,
    /// Light and full diverge: halt the cutover (§7.3).
    Divergence,
    /// Light and full agree, a pin does not.
    PinDrift,
}

/// The verdict over `outcomes`; a divergence outranks a pin drift.
#[must_use]
pub fn verdict(outcomes: &[Outcome]) -> Verdict {
    if outcomes.iter().any(|o| !o.parity()) {
        Verdict::Divergence
    } else if outcomes.iter().any(|o| !o.pinned()) {
        Verdict::PinDrift
    } else {
        Verdict::Pass
    }
}

/// Hash every case under the C full dataset and the Rust light cache.
///
/// Compiled only with the `full-dataset` feature. The light differential
/// build does not construct a dataset.
///
/// # Errors
///
/// The C full dataset could not be built.
#[cfg(feature = "full-dataset")]
pub fn run(corpus: &Corpus) -> Result<Vec<Outcome>, crate::full_dataset::BuildError> {
    let c_full = crate::full_dataset::FullDatasetVm::build(&corpus.seed)?;
    let light = PreparedCache::derive(Seedhash::from_bytes(corpus.seed));
    Ok(corpus
        .cases
        .iter()
        .map(|case| Outcome {
            label: case.label.clone(),
            c_full: c_full.hash(&case.blob),
            rust_light: compute_hash(&light, &case.blob),
            pin: case.pin,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(c_full: u8, rust_light: u8, pin: Option<u8>) -> Outcome {
        Outcome {
            label: "x".into(),
            c_full: [c_full; 32],
            rust_light: [rust_light; 32],
            pin: pin.map(|p| [p; 32]),
        }
    }

    #[test]
    fn a_divergence_outranks_a_pin_drift() {
        assert_eq!(verdict(&[outcome(1, 1, None)]), Verdict::Pass);
        assert_eq!(verdict(&[outcome(1, 1, Some(1))]), Verdict::Pass);
        assert_eq!(verdict(&[outcome(1, 1, Some(2))]), Verdict::PinDrift);
        assert_eq!(
            verdict(&[outcome(1, 1, Some(2)), outcome(1, 2, None)]),
            Verdict::Divergence
        );
    }

    #[test]
    fn the_canonical_corpus_carries_the_frozen_known_answer() {
        let corpus = canonical_corpus();
        assert_eq!(corpus.seed, canonical_seed());
        assert_eq!(corpus.cases[0].pin, Some(FROZEN_KAT));
        assert_eq!(corpus.cases[0].blob, KAT_BLOB);
    }

    #[test]
    fn the_genesis_corpus_is_the_tables_pinned_block() {
        let corpus = genesis_corpus().expect("mainnet's genesis assembles to its pin");
        assert_eq!(
            corpus.seed,
            shekyl_network::Network::Mainnet.genesis().hash()
        );
        assert!(!corpus.cases[0].blob.is_empty());
    }

    #[test]
    fn every_random_group_is_one_seed_with_its_pins() {
        for index in [0, NIGHTLY_SEEDHASH_COUNT - 1] {
            let group = random_corpus_group(index).expect("in range");
            assert_eq!(group.cases.len(), NIGHTLY_DATA_PER_SEEDHASH);
            assert!(group.cases.iter().all(|c| c.pin.is_some()));
        }
        assert!(random_corpus_group(NIGHTLY_SEEDHASH_COUNT).is_err());
    }
}
