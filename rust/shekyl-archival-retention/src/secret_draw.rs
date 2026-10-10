// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The secret draw: selection, the `0x0C` commitment, the challenge nonce,
//! and the serve-credit batch commitment.
//!
//! Design: [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
//! §4 (the draw), §5.2 (the nonce), §7.3 (the set commitment). All four
//! hashes are consensus: every node must pick the same pair, recompute
//! the same nonce, and fold the same carrier. The witness key and the
//! receipt scheme are Slice C's FN-DSA increment; this module is the
//! hash side, which that increment does not move.

use shekyl_curve_io::write_varint;
use shekyl_types::BlockHeight;

use crate::hash::cshake256_32;

/// cSHAKE256 customization for [`select_draw`] (rule 30: one label, one
/// function, versioned).
pub const DRAW_CUSTOMIZATION: &[u8] = b"shekyl/archival-draw-v1";

/// cSHAKE256 customization for [`draw_commit`].
pub const DRAW_COMMIT_CUSTOMIZATION: &[u8] = b"shekyl/archival-draw-commit-v1";

/// cSHAKE256 customization for [`challenge_nonce`].
pub const CHALLENGE_NONCE_CUSTOMIZATION: &[u8] = b"shekyl/archival-challenge-nonce-v1";

/// cSHAKE256 customization for [`serve_credit_batch_commitment`].
pub const SERVE_CREDIT_BATCH_CUSTOMIZATION: &[u8] = b"shekyl/archival-serve-credit-batch-v1";

/// Attempts at one draw before the candidate in hand is accepted.
/// [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
/// §4.4: the 256th attempt selects whatever its weight, so the loop is total.
pub const DRAW_ATTEMPTS: u32 = 256;

/// Floor on the count-rule horizon `H`, in blocks.
/// [`ARCHIVAL_SERVE_CREDIT_SPEC.md`](../../../docs/design/ARCHIVAL_SERVE_CREDIT_SPEC.md)
/// §4.3.
pub const DRAW_HORIZON_FLOOR: u64 = 200;

/// A pair's index in the epoch's static drawable set, and how many
/// attempts the selection took (1 through [`DRAW_ATTEMPTS`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedDraw {
    /// `index(P, s)` in canonical order.
    pub index: u64,
    /// Attempts consumed, one-based. The cap vector is 256.
    pub attempts: u32,
}

/// Draw `j` at `h`: one pair, with replacement, weight 16 : 1 for a
/// visibly-short index.
///
/// `None` when the set is empty — a producer issues no draws then, and
/// no record names a `j`. `short(i)` is whether index `i` is visibly
/// short at `h`.
///
/// ```text
/// zone = (2^64 − 1) − ((2^64 − 1) mod D)
/// for attempt = 0, 1, …, 255
///     x = cSHAKE256_32(DRAW_CUSTOMIZATION,
///                      seed ‖ block_hash(h) ‖ j_le[4] ‖ attempt_le[4])
///     v = LE64(x[0..8])
///     if attempt < 255 and v ≥ zone:   continue
///     i = v mod D
///     if attempt = 255:                select i
///     if short(i):                     select i
///     if x[8] & 0x0F = 0:              select i
///     otherwise continue
/// ```
#[must_use]
pub fn select_draw(
    seed: &[u8; 32],
    block_hash: &[u8; 32],
    draw: u32,
    set_size: u64,
    short: impl Fn(u64) -> bool,
) -> Option<SelectedDraw> {
    if set_size == 0 {
        return None;
    }
    let zone = u64::MAX - (u64::MAX % set_size);
    for attempt in 0..DRAW_ATTEMPTS {
        let x = stream(seed, block_hash, draw, attempt);
        let value = u64::from_le_bytes(x[..8].try_into().expect("8 bytes"));
        if attempt + 1 < DRAW_ATTEMPTS && value >= zone {
            continue;
        }
        let index = value % set_size;
        let accept = attempt + 1 == DRAW_ATTEMPTS || short(index) || x[8] & 0x0F == 0;
        if accept {
            return Some(SelectedDraw {
                index,
                attempts: attempt + 1,
            });
        }
    }
    unreachable!("the last attempt always selects");
}

/// The `0x0C` commitment: `cSHAKE256_32` over the witness public key
/// concatenated with the draw seed.
///
/// `witness_pk` is the canonical encoding (1,837 bytes once scheme 3
/// lands). The hash does not check the length: the admission row that
/// parses the key does.
#[must_use]
pub fn draw_commit(witness_pk: &[u8], seed: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(witness_pk.len().saturating_add(seed.len()));
    input.extend_from_slice(witness_pk);
    input.extend_from_slice(seed);
    cshake256_32(DRAW_COMMIT_CUSTOMIZATION, &input)
}

/// A challenge read's nonce, bound to `(seed, block_hash(h), j, attempt)`.
///
/// `attempt` is the read's index, from 0. Admission refuses
/// `attempt ≥ K` (`K = 3`).
#[must_use]
pub fn challenge_nonce(seed: &[u8; 32], block_hash: &[u8; 32], draw: u32, attempt: u8) -> [u8; 32] {
    let mut input = [0u8; 32 + 32 + 4 + 1];
    input[..32].copy_from_slice(seed);
    input[32..64].copy_from_slice(block_hash);
    input[64..68].copy_from_slice(&draw.to_le_bytes());
    input[68] = attempt;
    cshake256_32(CHALLENGE_NONCE_CUSTOMIZATION, &input)
}

/// The witness signature's preimage: seed, `h`, then each record framed
/// as `varint(len) ‖ bytes`, in input order.
///
/// `None` when there are no members (`n ≥ 1` is a structural check).
#[must_use]
pub fn serve_credit_batch_commitment(
    seed: &[u8; 32],
    height: BlockHeight,
    members: &[&[u8]],
) -> Option<[u8; 32]> {
    if members.is_empty() {
        return None;
    }
    let mut input = Vec::new();
    input.extend_from_slice(seed);
    input.extend_from_slice(&height.to_raw().to_le_bytes());
    for member in members {
        write_varint(&member.len(), &mut input).expect("a Vec write is infallible");
        input.extend_from_slice(member);
    }
    Some(cshake256_32(SERVE_CREDIT_BATCH_CUSTOMIZATION, &input))
}

/// The count-rule horizon `H` at epoch-relative height `r`.
///
/// `H = max(200, 0.7·SEB − r)` while `r < 0.7·SEB`, and
/// `H = max(200, SEB − W₂ − r)` after.
#[must_use]
pub fn draw_horizon(r: u64, seb: u64, response_window: u64) -> u64 {
    let early_end = seb.saturating_mul(7) / 10;
    let span = if r < early_end {
        early_end - r
    } else {
        seb.saturating_sub(response_window).saturating_sub(r)
    };
    span.max(DRAW_HORIZON_FLOOR)
}

/// One block's draw count and the 32-bit fractional carry it leaves.
///
/// ```text
/// t      = ( min(D·H + SEB·u, 9·D·H) << 32 ) / (SEB·H)
/// acc    = carry(h − 1) + t
/// count  = acc >> 32
/// carry  = acc & (2^32 − 1)
/// ```
///
/// `None` when `SEB` or `H` is zero — neither is in production; the
/// genesis schedule pins both well above.
#[must_use]
pub fn draw_count(
    set_size: u64,
    shortfall: u64,
    horizon: u64,
    seb: u64,
    prev_carry: u32,
) -> Option<(u64, u32)> {
    if seb == 0 || horizon == 0 {
        return None;
    }
    let d = u128::from(set_size);
    let h = u128::from(horizon);
    let epoch = u128::from(seb);
    let u = u128::from(shortfall);
    let weighted = d.saturating_mul(h).saturating_add(epoch.saturating_mul(u));
    let cap = d.saturating_mul(h).saturating_mul(9);
    let numer = weighted.min(cap).checked_shl(32)?;
    let t = numer / epoch.saturating_mul(h);
    let acc = u128::from(prev_carry).saturating_add(t);
    let count = u64::try_from(acc >> 32).unwrap_or(u64::MAX);
    let carry = u32::try_from(acc & 0xffff_ffff).expect("a 32-bit mask fits a u32");
    Some((count, carry))
}

fn stream(seed: &[u8; 32], block_hash: &[u8; 32], draw: u32, attempt: u32) -> [u8; 32] {
    let mut input = [0u8; 32 + 32 + 4 + 4];
    input[..32].copy_from_slice(seed);
    input[32..64].copy_from_slice(block_hash);
    input[64..68].copy_from_slice(&draw.to_le_bytes());
    input[68..].copy_from_slice(&attempt.to_le_bytes());
    cshake256_32(DRAW_CUSTOMIZATION, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x11; 32];
    const HASH: [u8; 32] = [0x22; 32];

    fn pick(set_size: u64, short_through: Option<u64>, draw: u32) -> SelectedDraw {
        select_draw(&SEED, &HASH, draw, set_size, |i| {
            short_through.is_some_and(|end| i <= end)
        })
        .expect("a non-empty set selects")
    }

    fn none_short(set_size: u64, draw: u32) -> SelectedDraw {
        select_draw(&SEED, &HASH, draw, set_size, |_| false).expect("a non-empty set selects")
    }

    /// The vectors of the specification's §4.5.
    #[test]
    fn the_selection_matches_the_specifications_vectors() {
        // D = 8, indices 0 to 3 short.
        let half = Some(3);
        assert_eq!(
            pick(8, half, 0),
            SelectedDraw {
                index: 3,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, half, 1),
            SelectedDraw {
                index: 2,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, half, 2),
            SelectedDraw {
                index: 3,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, half, 3),
            SelectedDraw {
                index: 2,
                attempts: 5
            }
        );
        assert_eq!(
            pick(8, half, 4),
            SelectedDraw {
                index: 0,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, half, 5),
            SelectedDraw {
                index: 2,
                attempts: 2
            }
        );

        // D = 8, none short.
        assert_eq!(
            none_short(8, 0),
            SelectedDraw {
                index: 3,
                attempts: 6
            }
        );
        assert_eq!(
            none_short(8, 1),
            SelectedDraw {
                index: 4,
                attempts: 5
            }
        );
        assert_eq!(
            none_short(8, 2),
            SelectedDraw {
                index: 1,
                attempts: 18
            }
        );
        assert_eq!(
            none_short(8, 3),
            SelectedDraw {
                index: 2,
                attempts: 7
            }
        );
        assert_eq!(
            none_short(8, 4),
            SelectedDraw {
                index: 7,
                attempts: 9
            }
        );
        assert_eq!(
            none_short(8, 5),
            SelectedDraw {
                index: 4,
                attempts: 7
            }
        );

        // D = 8, all short.
        let all = Some(7);
        assert_eq!(
            pick(8, all, 0),
            SelectedDraw {
                index: 3,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, all, 1),
            SelectedDraw {
                index: 2,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, all, 2),
            SelectedDraw {
                index: 3,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, all, 3),
            SelectedDraw {
                index: 4,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, all, 4),
            SelectedDraw {
                index: 0,
                attempts: 1
            }
        );
        assert_eq!(
            pick(8, all, 5),
            SelectedDraw {
                index: 5,
                attempts: 1
            }
        );
    }

    /// The cap: at `j = 28_409_462`, D = 8, none short, attempts 0..254
    /// refuse, so the 256th selects index 1. Without the cap the draw
    /// would run to attempt 284 and select index 5.
    #[test]
    fn the_two_hundred_fifty_sixth_attempt_selects() {
        assert_eq!(
            none_short(8, 28_409_462),
            SelectedDraw {
                index: 1,
                attempts: 256
            }
        );
    }

    #[test]
    fn an_empty_set_selects_nothing() {
        assert_eq!(select_draw(&SEED, &HASH, 0, 0, |_| true), None);
    }

    /// The vectors of the specification's §5.2.
    #[test]
    fn the_nonce_matches_the_specifications_vectors() {
        assert_eq!(
            hex(&challenge_nonce(&SEED, &HASH, 0, 0)),
            "b9601207ca7b74d36da0ee2402b83418e94408a7815e33d318db0ff783da45dc"
        );
        assert_eq!(
            hex(&challenge_nonce(&SEED, &HASH, 0, 1)),
            "61a3796f42ab53642e53458b5b6012c6102aacbce03c9ea20796407776df2248"
        );
        assert_eq!(
            hex(&challenge_nonce(&SEED, &HASH, 0, 2)),
            "f8bfae392e076cf3415bd37f1584a48abefbae56cb6fe89329b98955cc1b76d4"
        );
        assert_eq!(
            hex(&challenge_nonce(&SEED, &HASH, 1, 0)),
            "65bf6d43f77b2e7f71e2ff7a5e3a570257be3ce73f8760a76152f92773bdb31b"
        );
    }

    /// The vectors of the specification's §7.3.
    #[test]
    fn the_batch_commitment_matches_the_specifications_vectors() {
        let h = BlockHeight::from_raw(1_000_000);
        let first: Vec<u8> = (0x00..=0x3f).collect();
        let second: Vec<u8> = (0x40..=0x9f).collect();
        let a: Vec<u8> = (0x00..=0x0f).collect();
        let b: Vec<u8> = (0x10..=0x3f).collect();
        let c: Vec<u8> = (0x00..=0x1f).collect();
        let d: Vec<u8> = (0x20..=0x3f).collect();
        let long_a = vec![0xa5; 127];
        let long_b = vec![0x5a; 128];

        assert_eq!(
            hex(&serve_credit_batch_commitment(&SEED, h, &[&first]).expect("n ≥ 1")),
            "a75502337d8e6b440413009dcc6a96650354ab194abfe1289dbc0f685a6cf14b"
        );
        assert_eq!(
            hex(&serve_credit_batch_commitment(&SEED, h, &[&first, &second]).expect("n ≥ 1")),
            "cd10b6b4cb65ee0028868f2a62e7b0b5df85b1d6f6ea6d3ff88b680c15053c0b"
        );
        assert_eq!(
            hex(&serve_credit_batch_commitment(&SEED, h, &[&a, &b]).expect("n ≥ 1")),
            "f32bddca0eb179ed027b4421d5cff58a707b03b140ec54b0161dc57932f2fd6d"
        );
        assert_eq!(
            hex(&serve_credit_batch_commitment(&SEED, h, &[&c, &d]).expect("n ≥ 1")),
            "91f5ca7a11d3b1120206fb683655ee379b3c69153f6e14d7c859fbae185056ac"
        );
        assert_eq!(
            hex(&serve_credit_batch_commitment(&SEED, h, &[&long_a, &long_b]).expect("n ≥ 1")),
            "47d951c68a20dda3111eab91a320338f0c9adde3319bbda4450ad6d784f7a782"
        );
        assert_eq!(
            hex(&serve_credit_batch_commitment(
                &SEED,
                BlockHeight::from_raw(1_000_001),
                &[&first, &second]
            )
            .expect("n ≥ 1")),
            "b1d20f8af7d47aa5ea0b046e84c7d655d2a61314badba546f2840e7a7e4807c4"
        );
    }

    #[test]
    fn an_empty_carrier_has_no_commitment() {
        assert_eq!(
            serve_credit_batch_commitment(&SEED, BlockHeight::from_raw(1), &[]),
            None
        );
    }

    #[test]
    fn the_horizon_never_drops_below_the_floor() {
        let seb = 10_000;
        let w2 = 500;
        assert_eq!(draw_horizon(0, seb, w2), 7_000);
        assert_eq!(draw_horizon(6_999, seb, w2), 200);
        assert_eq!(draw_horizon(7_000, seb, w2), 2_500);
        assert_eq!(draw_horizon(9_999, seb, w2), 200);
    }

    #[test]
    fn the_count_carries_the_fraction_and_caps_at_nine_times_base() {
        // D = SEB, u = 0, H = 200: t = (D·H << 32) / (SEB·H) = 1 << 32,
        // so count = 1 + (carry == 0).
        let (count, carry) = draw_count(10_000, 0, 200, 10_000, 0).expect("H and SEB");
        assert_eq!((count, carry), (1, 0));

        // Half a draw per block: D = SEB/2. First block count 0, carry
        // 2^31; the next adds another half and issues one.
        let (count, carry) = draw_count(5_000, 0, 200, 10_000, 0).expect("H and SEB");
        assert_eq!((count, carry), (0, 1 << 31));
        let (count, carry) = draw_count(5_000, 0, 200, 10_000, carry).expect("H and SEB");
        assert_eq!((count, carry), (1, 0));

        // The 9× cap: a huge shortfall cannot push t above 9·D/SEB.
        let (count, _) = draw_count(10_000, u64::MAX, 200, 10_000, 0).expect("H and SEB");
        assert_eq!(count, 9);
    }

    #[test]
    fn draw_commit_moves_when_either_half_moves() {
        let pk = [0x33u8; 16];
        let a = draw_commit(&pk, &SEED);
        let mut other_pk = pk;
        other_pk[0] ^= 1;
        assert_ne!(a, draw_commit(&other_pk, &SEED));
        assert_ne!(a, draw_commit(&pk, &[0x12; 32]));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
