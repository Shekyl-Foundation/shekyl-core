// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause
//
// The oracle below is a transliteration of `LWMA1_` from zawy12's
// difficulty-algorithms issue #3, original work copyright (c) Zawy et al.,
// used under the MIT License
// (https://github.com/zawy12/difficulty-algorithms/blob/master/LICENSE).

//! `lwma1_next` against an independent oracle: zawy12's published LWMA-1
//! reference, transliterated from the pinned capture of his issue #3, not
//! from our implementation.
//!
//! The §8.1 vectors of `DAA_LWMA1.md` are pinned as outputs in
//! `spec_vectors.rs`; this test runs the reference itself, so the vectors'
//! values are checked by a second implementation that shares no code and no
//! author with ours. Vectors 1–5 (monotonic timestamps): the oracle, the
//! expected value and `lwma1_next` agree three ways. Vectors 6–7 (out of
//! sequence): the oracle gives zawy12's value and `lwma1_next` must differ
//! from it, because Shekyl's running-max clamp is deliberately stricter
//! there (zawy12 issue #24 item 14); Shekyl's own value on those two is
//! pinned in `spec_vectors.rs`.
//!
//! Provenance is checked when the test runs, not claimed here: the capture
//! (`docs/design/refs/zawy12_issue_3_lwma1.md`) must hash to the SHA-256
//! its anchors file pins, and the function the oracle was transliterated
//! from must open and close on the anchors' first and last lines at the
//! pinned byte range. Until the C++ tree went, the same reference ran as
//! C++ in `tests/difficulty`; this replaces it.

use sha2::{Digest, Sha256};
use shekyl_difficulty::{lwma1_next, CumulativeDifficulty, GENESIS_DIFFICULTY, N, T_SECONDS};
use shekyl_types::{BlockHeight, Timestamp};

const CAPTURE: &[u8] = include_bytes!("../../../docs/design/refs/zawy12_issue_3_lwma1.md");
const ANCHORS: &str = include_str!("../../../docs/design/refs/zawy12_issue_3_lwma1.anchors.json");

/// zawy12's `LWMA1_`, line for line. `difficulty_type` is `uint64_t`, as
/// the reference expects its host to define it; every operation wraps, as
/// C++ unsigned arithmetic does, so the oracle computes what the reference
/// computes even where an input would overflow (none of the vectors does).
#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn zawy12_lwma1(
    timestamps: &[u64],
    cumulative_difficulties: &[u64],
    t: u64,
    n: u64,
    height: u64,
    fork_height: u64,
    difficulty_guess: u64,
) -> u64 {
    // Genesis should be the only time sizes are < N+1.
    assert!(
        timestamps.len() == cumulative_difficulties.len()
            && timestamps.len() as u64 <= n.wrapping_add(1)
    );

    // Hard code D if there are not at least N+1 BLOCKS after fork (or genesis)
    if height >= fork_height && height < fork_height.wrapping_add(n) {
        return difficulty_guess;
    }
    assert!(timestamps.len() as u64 == n.wrapping_add(1));

    let mut l: u64 = 0;
    let mut this_timestamp: u64;
    let mut previous_timestamp: u64 = timestamps[0].wrapping_sub(t);
    for i in 1..=n {
        // Safely prevent out-of-sequence timestamps
        let ts = timestamps[i as usize];
        if ts > previous_timestamp {
            this_timestamp = ts;
        } else {
            this_timestamp = previous_timestamp.wrapping_add(1);
        }
        l = l.wrapping_add(
            i.wrapping_mul(
                6u64.wrapping_mul(t)
                    .min(this_timestamp.wrapping_sub(previous_timestamp)),
            ),
        );
        previous_timestamp = this_timestamp;
    }
    let l_floor = n.wrapping_mul(n).wrapping_mul(t) / 20;
    if l < l_floor {
        l = l_floor;
    }
    let avg_d = cumulative_difficulties[n as usize].wrapping_sub(cumulative_difficulties[0]) / n;

    // Prevent round off error for small D and overflow for large D.
    let mut next_d = if avg_d > 2_000_000u64.wrapping_mul(n).wrapping_mul(n).wrapping_mul(t) {
        (avg_d / 200u64.wrapping_mul(l)).wrapping_mul(
            n.wrapping_mul(n.wrapping_add(1))
                .wrapping_mul(t)
                .wrapping_mul(99),
        )
    } else {
        avg_d
            .wrapping_mul(n)
            .wrapping_mul(n.wrapping_add(1))
            .wrapping_mul(t)
            .wrapping_mul(99)
            / 200u64.wrapping_mul(l)
    };

    // Optional. Make all insignificant digits zero for easy reading.
    let mut i: u64 = 1_000_000_000;
    while i > 1 {
        if next_d > i.wrapping_mul(100) {
            next_d = (next_d.wrapping_add(i / 2) / i).wrapping_mul(i);
            break;
        } else {
            i /= 10;
        }
    }
    next_d
}

const B: u64 = 1_700_000_000;
const AVG_D: u64 = 1_000_000;

/// The oracle at the cross-check's operating point: chain height N (past
/// the genesis window), fork height 0, the genesis difficulty as the guess.
fn oracle(ts: &[u64]) -> u64 {
    let cd: Vec<u64> = (0..=N).map(|i| i * AVG_D).collect();
    let guess = u64::try_from(GENESIS_DIFFICULTY).expect("the genesis difficulty fits u64");
    zawy12_lwma1(ts, &cd, T_SECONDS, N, N, 0, guess)
}

fn ours(ts: &[u64]) -> u64 {
    let ts: Vec<Timestamp> = ts.iter().copied().map(Timestamp::from_raw).collect();
    let cd: Vec<CumulativeDifficulty> = (0..=N)
        .map(|i| CumulativeDifficulty::from_raw(u128::from(i * AVG_D)))
        .collect();
    let next = lwma1_next(BlockHeight::from_raw(N), &ts, &cd).expect("a full window computes");
    u64::try_from(next.to_raw()).expect("no §8.1 vector overflows u64")
}

fn stepped(step: u64) -> Vec<u64> {
    (0..=N).map(|i| B + i * step).collect()
}

/// Vectors 1–5, monotonic: the reference, the expected value and ours.
fn agree(name: &str, ts: &[u64], expected: u64) {
    let (zawy, rust) = (oracle(ts), ours(ts));
    assert_eq!(zawy, expected, "{name}: zawy12's reference");
    assert_eq!(rust, expected, "{name}: lwma1_next");
}

/// Vectors 6–7, out of sequence: the reference gives its own value, and
/// ours must not equal it.
fn diverge(name: &str, ts: &[u64], expected_zawy: u64, expected_ours: u64) {
    let (zawy, rust) = (oracle(ts), ours(ts));
    assert_eq!(zawy, expected_zawy, "{name}: zawy12's reference");
    assert_eq!(rust, expected_ours, "{name}: lwma1_next");
    assert_ne!(
        rust, zawy,
        "{name}: the clamp must diverge from LWMA-1 here"
    );
}

#[test]
fn the_capture_is_the_pinned_reference() {
    let anchors: serde_json::Value = serde_json::from_str(ANCHORS).expect("anchors parse");
    let field = |k: &str| anchors[k].clone();
    let digest: String = Sha256::digest(CAPTURE)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        field("pinned_body_sha256").as_str().expect("a hex digest"),
        "the capture's SHA-256"
    );
    let start = usize::try_from(
        field("lwma1_byte_offset_start")
            .as_u64()
            .expect("an offset"),
    )
    .expect("fits");
    let end =
        usize::try_from(field("lwma1_byte_offset_end").as_u64().expect("an offset")).expect("fits");
    let function = std::str::from_utf8(&CAPTURE[start..end]).expect("the range is UTF-8");
    let lines: Vec<&str> = function.lines().map(str::trim_end).collect();
    assert_eq!(
        lines.first().copied(),
        field("lwma1_first_line").as_str(),
        "the range opens on LWMA1_'s signature"
    );
    assert_eq!(
        lines.last().copied(),
        field("lwma1_last_line").as_str(),
        "the range closes on its brace"
    );
}

#[test]
fn vector_1_stable() {
    agree("1-stable", &stepped(T_SECONDS), 990_000);
}

#[test]
fn vector_2_twice_the_hashrate() {
    agree("2-2x-up", &stepped(T_SECONDS / 2), 1_980_000);
}

#[test]
fn vector_3_half_the_hashrate() {
    agree("3-2x-down", &stepped(2 * T_SECONDS), 495_000);
}

#[test]
fn vector_4_the_six_t_clamp() {
    let mut ts = stepped(T_SECONDS);
    let n = N as usize;
    ts[n] = ts[n - 1] + 100 * T_SECONDS;
    agree("4-clamp", &ts, 892_000);
}

#[test]
fn vector_5_the_l_floor() {
    agree("5-L-floor", &stepped(1), 10_000_000);
}

#[test]
fn vector_6_a_back_step_diverges() {
    let mut ts = stepped(T_SECONDS);
    let n = N as usize;
    ts[n] = B + (N - 2) * T_SECONDS;
    diverge("6-oos-back-step", &ts, 1_010_000, 1_040_000);
}

#[test]
fn vector_7_a_selfish_mine_diverges() {
    let mut ts = stepped(T_SECONDS);
    let n = N as usize;
    ts[n - 1] = B + (N - 2) * T_SECONDS + 1000 * T_SECONDS;
    ts[n] = B + (N - 2) * T_SECONDS + T_SECONDS;
    diverge("7-selfish-mine", &ts, 911_000, 1_040_000);
}
