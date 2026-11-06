// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `keccak256` against the 321 Keccak-256 vectors the C++ `hash-tests`
//! ran as `hash-fast` (`tests/hash/tests-fast.txt`).
//!
//! `vectors/keccak256.txt` is that file, byte for byte: one vector per line,
//! the expected hash then the input, both in hex, and `x` for the empty
//! input. The C++ hash and its test are deleted with the C++ tree; this is
//! where the vectors stay. Original Keccak padding (`0x01`), not SHA3's
//! (`0x06`): the empty-input vector is the one that tells them apart.

use shekyl_crypto_hash::keccak256;

const VECTORS: &str = include_str!("vectors/keccak256.txt");

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd-length hex: {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn keccak256_matches_every_vector() {
    let mut count = 0usize;
    let mut longest = 0usize;
    for (line_no, line) in VECTORS.lines().enumerate() {
        let mut fields = line.split_whitespace();
        let (Some(expected), Some(input), None) = (fields.next(), fields.next(), fields.next())
        else {
            panic!("line {}: not `<hash> <input>`: {line:?}", line_no + 1);
        };
        let input = if input == "x" {
            Vec::new()
        } else {
            unhex(input)
        };
        longest = longest.max(input.len());
        assert_eq!(
            keccak256(&input).to_vec(),
            unhex(expected),
            "line {}: keccak256 of {} bytes",
            line_no + 1,
            input.len()
        );
        count += 1;
    }
    // The subject (rule 47): the whole file was read, and it reaches past
    // one Keccak-256 rate block (136 bytes), where padding spans blocks.
    assert_eq!(count, 321, "the vector count");
    assert!(longest > 136, "a vector longer than one rate block");
}
