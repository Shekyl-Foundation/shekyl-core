// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Parity-corpus file writer — the transport that carries the nightly
//! random corpus and its §4.6 M1 canonical pins to the Phase 3a
//! Hole-1 C++ parity gate (`tests/randomx_v2_parity/`).
//!
//! ## Why a file, not a checked-in table
//!
//! The Phase 3a gate re-checks the committed canonical pins
//! ([`crate::canonical_outputs::CANONICAL_RANDOM_HASHES`]) under the
//! C reference's **full-dataset** fast mode (the mode miners run),
//! closing the loop the Phase 2g harness leaves open (light-vs-light
//! only, per `RANDOMX_V2_PHASE3_PLAN.md` §7.1). The corpus data
//! itself is ~150 MiB (1024 blobs, bimodal 64 B–600 KiB per R1-D4),
//! so it cannot be committed; it is instead re-derived from the
//! deterministic [`crate::corpus_random`] stream at CI time by the
//! `gen-parity-corpus` binary and handed to the C++ harness as a
//! self-describing binary file. Determinism (T9 + R6-D1: fixed
//! ChaCha20 seed, platform-independent stream) makes the file
//! byte-identical on every regeneration at the same corpus revision;
//! the [`tests::parity_corpus_file_sha256_pin`] pin makes any drift
//! (generator, canonicals, or format) fire per-PR in the structural
//! gate rather than a day later in the parity cron.
//!
//! ## File format (v1, all integers little-endian `u32`)
//!
//! ```text
//! [ 8] magic  = "SKLPRTY1"
//! [ 4] seedhash_count        (== NIGHTLY_SEEDHASH_COUNT)
//! [ 4] data_per_seedhash     (== NIGHTLY_DATA_PER_SEEDHASH)
//! then seedhash_count groups, in nightly emission order:
//!   [32] seedhash
//!   data_per_seedhash records:
//!     [ 4] canonical_index   (== group_index * data_per_seedhash + j;
//!                             the index into CANONICAL_RANDOM_HASHES)
//!     [32] canonical_hash    (CANONICAL_RANDOM_HASHES[canonical_index])
//!     [ 4] data_len
//!     [data_len] data
//! ```
//!
//! The redundant `canonical_index` is deliberate: the C++ reader
//! re-derives `group_index * data_per_seedhash + j` and rejects a
//! mismatch, so a truncated or interleaved write cannot silently
//! shift every downstream pin by one record. The sole consumer of
//! this format is `tests/randomx_v2_parity/randomx_v2_full_parity.cpp`
//! (`corpus` mode); any layout change here must change the magic and
//! the C++ parser in the same commit.

use std::io::{self, Write};

use crate::canonical_outputs::CANONICAL_RANDOM_HASHES;
use crate::corpus_random::{
    generate_random_corpus, NIGHTLY_DATA_PER_SEEDHASH, NIGHTLY_SEEDHASH_COUNT,
};

/// Format magic; the trailing `1` is the format version.
pub const PARITY_CORPUS_MAGIC: [u8; 8] = *b"SKLPRTY1";

/// Serialize the full nightly corpus + canonical pins in the v1
/// format above.
///
/// # Errors
///
/// Propagates any `io::Error` from the underlying writer.
///
/// # Panics
///
/// Panics if the committed canonical-pin table does not cover the
/// nightly corpus (a broken-substrate state the structural gate's
/// canonical-shape tests also reject).
pub fn write_parity_corpus<W: Write>(out: &mut W) -> io::Result<()> {
    let corpus = generate_random_corpus(NIGHTLY_SEEDHASH_COUNT, NIGHTLY_DATA_PER_SEEDHASH);
    assert_eq!(
        corpus.len(),
        CANONICAL_RANDOM_HASHES.len(),
        "nightly corpus size and canonical-pin table size diverged"
    );

    let seedhash_count = u32::try_from(NIGHTLY_SEEDHASH_COUNT).expect("corpus sizing fits u32");
    let data_per_seedhash =
        u32::try_from(NIGHTLY_DATA_PER_SEEDHASH).expect("corpus sizing fits u32");

    out.write_all(&PARITY_CORPUS_MAGIC)?;
    out.write_all(&seedhash_count.to_le_bytes())?;
    out.write_all(&data_per_seedhash.to_le_bytes())?;

    for (flat_index, pair) in corpus.iter().enumerate() {
        // First record of a group carries the group's seedhash.
        if flat_index % NIGHTLY_DATA_PER_SEEDHASH == 0 {
            out.write_all(pair.seedhash.as_bytes())?;
        } else {
            // Emission order is seed-major: every record in a group
            // shares the group's seedhash by construction.
            debug_assert_eq!(
                pair.seedhash.as_bytes(),
                corpus[flat_index - flat_index % NIGHTLY_DATA_PER_SEEDHASH]
                    .seedhash
                    .as_bytes()
            );
        }
        let canonical_index = u32::try_from(flat_index).expect("corpus sizing fits u32");
        out.write_all(&canonical_index.to_le_bytes())?;
        out.write_all(&CANONICAL_RANDOM_HASHES[flat_index])?;
        let data_len = u32::try_from(pair.data.len()).expect("R1-D4 data lengths fit u32");
        out.write_all(&data_len.to_le_bytes())?;
        out.write_all(&pair.data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    /// Whole-file SHA-256 pin over the v1 parity-corpus serialization.
    ///
    /// This is a substrate pin in the [`crate::canonical_outputs`]
    /// sense (and the fork-pin-sha sense): it fires per-PR when the
    /// corpus generator, the canonical-pin table, or this format
    /// change — all events that require regenerating the C++ gate's
    /// input and reviewing the parity contract. On an intentional
    /// change, update the pin from the test's failure output (and
    /// bump the format magic if the layout changed).
    const PARITY_CORPUS_FILE_SHA256: &str =
        "713d570225de869c6ded6fd4e7e4a8d720505af869f5668bcfa432090d7d03ba";

    #[test]
    fn parity_corpus_file_sha256_pin() {
        let mut bytes = Vec::new();
        write_parity_corpus(&mut bytes).expect("Vec writer cannot fail");

        // Structural floor: header + at least one full group.
        assert_eq!(&bytes[..8], &PARITY_CORPUS_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes")),
            u32::try_from(NIGHTLY_SEEDHASH_COUNT).expect("fits u32"),
        );
        assert_eq!(
            u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
            u32::try_from(NIGHTLY_DATA_PER_SEEDHASH).expect("fits u32"),
        );

        let got = hex_lower(&Sha256::digest(&bytes));
        assert_eq!(
            got, PARITY_CORPUS_FILE_SHA256,
            "parity-corpus serialization drifted; if intentional, update \
             PARITY_CORPUS_FILE_SHA256 (and the format magic + C++ parser \
             on a layout change)"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").expect("String write cannot fail");
        }
        s
    }
}
