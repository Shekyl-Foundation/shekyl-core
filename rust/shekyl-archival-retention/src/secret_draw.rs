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

/// Reads of one draw before the challenger abandons it. Admission
/// refuses `attempt ≥ K` (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.3, `SCS-P13`).
pub const CHALLENGE_READS: u8 = 3;

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
/// `Ok(None)` when the set is empty — a producer issues no draws then,
/// and no record names a `j`. `short` is not called.
///
/// `short(i)` is whether index `i` is visibly short at `h`. `Err` is
/// that read failing: the draw selects nothing, and the error is the
/// return. A short answer is never invented in its place. The 256th
/// attempt selects without asking, as the specification has it, so a
/// fault cannot arise on the attempt that would have selected anyway.
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
pub fn select_draw<E>(
    seed: &[u8; 32],
    block_hash: &[u8; 32],
    draw: u32,
    set_size: u64,
    mut short: impl FnMut(u64) -> Result<bool, E>,
) -> Result<Option<SelectedDraw>, E> {
    if set_size == 0 {
        return Ok(None);
    }
    let zone = u64::MAX - (u64::MAX % set_size);
    // Attempts 0 to 254 may refuse: a value outside the zone, or a full
    // pair the fifth nibble does not accept.
    for attempt in 0..DRAW_ATTEMPTS - 1 {
        let x = stream(seed, block_hash, draw, attempt);
        let value = u64::from_le_bytes(x[..8].try_into().expect("8 bytes"));
        if value >= zone {
            continue;
        }
        let index = value % set_size;
        if short(index)? || x[8] & 0x0F == 0 {
            return Ok(Some(SelectedDraw {
                index,
                attempts: attempt + 1,
            }));
        }
    }
    // The 256th attempt selects its candidate whatever the zone and
    // whatever its weight (§4.4). It is its own arm, after the loop, so
    // the loop has no fall-through: the cap is this return, and `short`
    // is not in it — a fault cannot refuse the attempt the specification
    // accepts outright.
    let x = stream(seed, block_hash, draw, DRAW_ATTEMPTS - 1);
    let value = u64::from_le_bytes(x[..8].try_into().expect("8 bytes"));
    Ok(Some(SelectedDraw {
        index: value % set_size,
        attempts: DRAW_ATTEMPTS,
    }))
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

/// One block's draw target before the carry, and which side of the cap
/// it came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrawTarget {
    /// `t`: the target in draws, with 32 fractional bits.
    pub fixed: u128,
    /// Whether the cap bound: `D·H + SEB·u > 9·D·H`, strictly. A target
    /// that lands exactly on the cap is not capped; nothing was held down.
    /// Exact for every input: see [`draw_target`].
    pub capped: bool,
}

/// The count rule's target at one block: base plus top-up, under the cap.
///
/// ```text
/// t      = ( min(D·H + SEB·u, 9·D·H) << 32 ) / (SEB·H)      (u128, floor)
/// capped = D·H + SEB·u > 9·D·H
/// ```
///
/// `shortfall` is `u`: the visible shortfall less what is in flight. This
/// is the only place the cap is computed; [`draw_count`] adds the carry to
/// `t` and nothing else. `capped` is not consensus state. It exists so a
/// caller that reports on the cap asks the rule, and does not keep a second
/// copy of it.
///
/// **`capped` is exact, and is not read off the target's arithmetic.**
/// `D·H + SEB·u > 9·D·H` is `SEB·u > 8·D·H`, with no division on either
/// side. `SEB·u` and `D·H` are each a product of two `u64`s and fit a
/// `u128`. `8·D·H` may not; when it does not it is at least `2^128` and so
/// above any `SEB·u`, which is strictly below `2^128`, and the block is
/// not capped. The predicate is
/// computed from those operands before the target is, so the saturation
/// below cannot reach it.
///
/// **`t` is exact or absent.** The fixed-point numerator is
/// `min(D·H + SEB·u, 9·D·H) · 2^32`, which fits a `u128` only while the
/// minimum is below `2^96`. At or above that the function returns `None`
/// and never a truncated value: a saturated sum or cap is itself at least
/// `2^96`, so every inexact case lands there. The schedule cannot reach
/// it: with `SEB = 10,000` and `H ≤ SEB`, `9·D·H` is below `2^81` for
/// every `u64` `D`.
///
/// `None` when `SEB` or `H` is zero, or when the target does not fit —
/// none of which is in production; the genesis schedule pins `SEB` and
/// `H` well above zero and the target well below the limit.
#[must_use]
pub fn draw_target(set_size: u64, shortfall: u64, horizon: u64, seb: u64) -> Option<DrawTarget> {
    if seb == 0 || horizon == 0 {
        return None;
    }
    let d = u128::from(set_size);
    let h = u128::from(horizon);
    let epoch = u128::from(seb);
    let u = u128::from(shortfall);
    // Neither product can overflow: each is two `u64`s in a `u128`.
    let base = d * h;
    let top_up = epoch * u;
    let capped = cap_binds(base, top_up);
    let weighted = base.saturating_add(top_up);
    let cap = base.saturating_mul(9);
    // `checked_shl` checks the shift amount, not the bits shifted out; a
    // multiplication refuses a numerator that does not fit.
    let numer = weighted.min(cap).checked_mul(1 << 32)?;
    Some(DrawTarget {
        fixed: numer / epoch.saturating_mul(h),
        capped,
    })
}

/// Whether the cap bound: `SEB·u > 8·D·H`, exactly, from `base = D·H` and
/// `top_up = SEB·u`. An `8·D·H` that does not fit a `u128` is at least
/// `2^128`, and every `SEB·u` is strictly below that, so it is not capped.
///
/// Its own function so the predicate is defined on every input, including
/// those whose target does not fit and for which [`draw_target`] has no
/// value to return.
const fn cap_binds(base: u128, top_up: u128) -> bool {
    match base.checked_mul(8) {
        Some(room) => top_up > room,
        None => false,
    }
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
/// `t` is [`draw_target`]'s.
///
/// `None` when `SEB` or `H` is zero or the target does not fit — none of
/// which is in production; see [`draw_target`].
#[must_use]
pub fn draw_count(
    set_size: u64,
    shortfall: u64,
    horizon: u64,
    seb: u64,
    prev_carry: u32,
) -> Option<(u64, u32)> {
    let t = draw_target(set_size, shortfall, horizon, seb)?.fixed;
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
            Ok::<_, ()>(short_through.is_some_and(|end| i <= end))
        })
        .expect("the short predicate does not fail")
        .expect("a non-empty set selects")
    }

    fn none_short(set_size: u64, draw: u32) -> SelectedDraw {
        select_draw(&SEED, &HASH, draw, set_size, |_| Ok::<_, ()>(false))
            .expect("the short predicate does not fail")
            .expect("a non-empty set selects")
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
    fn an_empty_set_selects_nothing_and_does_not_ask() {
        let mut asked = false;
        assert_eq!(
            select_draw(&SEED, &HASH, 0, 0, |_| {
                asked = true;
                Ok::<_, &str>(true)
            }),
            Ok(None)
        );
        assert!(!asked, "an empty set has no index to read");
    }

    /// A short-read fault on an attempt that consults it is the return,
    /// not an index. The attempt the cap selects does not consult it:
    /// once every earlier read has answered, one more faulting read is
    /// never made. Red edit: map `Err` to `Ok(false)` and continue, or
    /// call `short` on the 256th attempt.
    #[test]
    fn a_short_fault_is_not_a_selection_and_the_cap_does_not_ask() {
        let err = select_draw(&SEED, &HASH, 0, 8, |_| Err("unreadable")).expect_err("asked");
        assert_eq!(err, "unreadable");

        // `j = 28_409_462`, D = 8, none short: the in-zone attempts before
        // the cap refuse, and the 256th selects index 1. Count those
        // reads, then fault on any read past them.
        let mut asked = 0u32;
        let selected = select_draw(&SEED, &HASH, 28_409_462, 8, |_| {
            asked += 1;
            Ok::<_, &str>(false)
        })
        .expect("a false answer is not a fault")
        .expect("a non-empty set selects");
        assert_eq!(
            selected,
            SelectedDraw {
                index: 1,
                attempts: DRAW_ATTEMPTS
            }
        );
        let consulted = asked;
        assert!(consulted < DRAW_ATTEMPTS, "the cap is not one of the reads");

        let mut asked = 0u32;
        let selected = select_draw(&SEED, &HASH, 28_409_462, 8, |_| {
            asked += 1;
            if asked > consulted {
                Err("the cap asked")
            } else {
                Ok(false)
            }
        })
        .expect("the cap does not ask")
        .expect("a non-empty set selects");
        assert_eq!(selected.attempts, DRAW_ATTEMPTS);
        assert_eq!(asked, consulted);
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

    /// The specification's negative control (§5.2): a nonce computed
    /// **without** the `attempt` byte — `seed ‖ block_hash(h) ‖ j_le[4]`,
    /// 68 bytes under the nonce label — is `87ade5ae…03adc456` for `j = 0`
    /// and matches no row of the table. The specification publishes only
    /// the first and last four bytes of that value, so this asserts the
    /// prefix and the suffix and does not invent the middle. It is what goes
    /// red if `challenge_nonce` drops the byte: the four rows above would
    /// then collapse onto this value. Red edit: remove `input[68] = attempt`
    /// and shorten the preimage; the `j = 0` rows all read this hash.
    #[test]
    fn a_nonce_without_the_attempt_byte_matches_no_row() {
        let mut preimage = [0u8; 32 + 32 + 4];
        preimage[..32].copy_from_slice(&SEED);
        preimage[32..64].copy_from_slice(&HASH);
        preimage[64..68].copy_from_slice(&0u32.to_le_bytes());
        let without_attempt = hex(&cshake256_32(CHALLENGE_NONCE_CUSTOMIZATION, &preimage));
        assert!(
            without_attempt.starts_with("87ade5ae"),
            "prefix of the specification's control"
        );
        assert!(
            without_attempt.ends_with("03adc456"),
            "suffix of the specification's control"
        );
        for (draw, attempt) in [(0, 0), (0, 1), (0, 2), (1, 0)] {
            assert_ne!(
                hex(&challenge_nonce(&SEED, &HASH, draw, attempt)),
                without_attempt,
                "j = {draw}, attempt = {attempt}: the attempt byte is in the preimage"
            );
        }
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

    /// Independent oracle: the comparison `D·H + SEB·u > 9·D·H` done by
    /// hand at D = SEB = 10,000 and H = 200, where it reads
    /// `2,000,000 + 10,000·u > 18,000,000`, so the two sides meet at
    /// u = 1,600.
    ///
    /// Bites against: a `capped` that is `>=`, a `capped` inferred from the
    /// target (1,600 and 1,601 give the same target), and a cap that is not
    /// nine times the base.
    /// Does NOT cover: the count and the carry; the next test and
    /// `the_count_carries_the_fraction_and_caps_at_nine_times_base` do.
    #[test]
    fn the_cap_binds_only_when_the_uncapped_side_exceeds_it() {
        let nine = 9u128 << 32;
        let at = |u| draw_target(10_000, u, 200, 10_000).expect("H and SEB");
        // One below: 17,990,000 / 2,000,000 = 1799/200 = 8.995 draws,
        // floored at 32 fractional bits. Under the cap.
        let below = at(1_599);
        assert!(!below.capped);
        assert_eq!(below.fixed, (1_799u128 << 32) / 200);
        assert!(below.fixed < nine);
        // Exactly on the cap: nine draws, and nothing was held down.
        assert_eq!(
            at(1_600),
            DrawTarget {
                fixed: nine,
                capped: false
            }
        );
        // One above: the same nine draws, and now the cap is why.
        assert_eq!(
            at(1_601),
            DrawTarget {
                fixed: nine,
                capped: true
            }
        );
        assert_eq!(
            at(u64::MAX),
            DrawTarget {
                fixed: nine,
                capped: true
            }
        );
        // No shortfall is the base alone, a ninth of the cap.
        assert_eq!(
            at(0),
            DrawTarget {
                fixed: 1u128 << 32,
                capped: false
            }
        );
        // An empty set draws nothing and is not capped: 0 > 0 is false.
        assert_eq!(
            draw_target(0, 0, 200, 10_000),
            Some(DrawTarget {
                fixed: 0,
                capped: false
            })
        );
        assert_eq!(draw_target(10_000, 0, 0, 10_000), None);
        assert_eq!(draw_target(10_000, 0, 200, 0), None);
    }

    /// The predicate where the target's own arithmetic saturates. Each
    /// expected value is reasoned from the inequality `SEB·u > 8·D·H` by a
    /// route that shares nothing with the function: with
    /// `SEB = u = H = m` it divides by `m` to `m > 8·D`, which is `u64`
    /// arithmetic.
    ///
    /// Bites against: `capped: weighted > cap` on the saturated operands
    /// (the red edit; both sides are `u128::MAX` on the first input and
    /// the comparison is false where the inequality is true), and an
    /// overflowing `8·D·H` read as zero or as capped.
    /// Also holds: on these inputs the target does not fit, and both
    /// `draw_target` and `draw_count` say so with `None`. Before, a shift
    /// that dropped the high bits returned a truncated value. Red edit:
    /// `checked_shl(32)` in place of the multiplication.
    #[test]
    fn the_cap_predicate_is_exact_where_the_target_s_arithmetic_saturates() {
        let m = u64::MAX;
        let capped = |d: u64, u: u64, h: u64, seb: u64| {
            cap_binds(
                u128::from(d) * u128::from(h),
                u128::from(seb) * u128::from(u),
            )
        };

        // The review's input: D = (2^64 − 1) / 8 = 2^61 − 1, and
        // SEB = u = H = m. m·m > 8·D·m is m > 8·D, and 8·D = 2^64 − 8.
        let d = m / 8;
        assert_eq!(d, (1 << 61) - 1);
        assert!(m > 8 * d, "the inequality holds, in u64");
        assert!(capped(d, m, m, m));
        // D·H + SEB·u and 9·D·H are both past u128 here: the comparison
        // this replaces saw two saturated values and said "not capped".
        let (d128, m128) = (u128::from(d), u128::from(m));
        assert_eq!((d128 * m128).checked_add(m128 * m128), None);
        assert_eq!((d128 * m128).checked_mul(9), None);
        assert_eq!((d128 * m128).checked_mul(8), Some(8 * d128 * m128));

        // One more pair: 8·D = 2^64 > m, so not capped. 8·D·H still fits.
        let d = 1u64 << 61;
        assert_eq!(8 * u128::from(d), u128::from(m) + 1);
        assert!(!capped(d, m, m, m));
        // And the edge between them moves with u alone: at D = 2^61 − 1,
        // m·u > (2^64 − 8)·m is u > 2^64 − 8.
        let d = m / 8;
        assert!(!capped(d, m - 7, m, m), "u = 8·D is equality");
        assert!(capped(d, m - 6, m, m), "u = 8·D + 1");

        // 8·D·H past u128: D = H = m gives 8·m·m, and SEB·u is at most
        // m·m, so the inequality is false whatever u is.
        assert_eq!((m128 * m128).checked_mul(8), None);
        assert!(!capped(m, m, m, m));
        assert!(!capped(m, m, m, 1));

        // The target does not fit on the review's input, and neither
        // function invents one. `checked_shl` returned a truncated 1 here.
        assert_eq!(draw_target(m / 8, m, m, m), None);
        assert_eq!(draw_count(m / 8, m, m, m, 0), None);
        // One below the limit fits; the limit does not. D = 2^95 / H with
        // u = 0: the minimum is D·H itself.
        let fits = draw_target(1 << 63, 0, 1 << 32, 1 << 20).expect("D·H = 2^95 fits");
        assert_eq!(fits.fixed, (1u128 << 127) / (1u128 << 52));
        assert_eq!(
            draw_target(1 << 63, 0, 1 << 33, 1 << 20),
            None,
            "D·H = 2^96"
        );
    }

    /// A large case the arithmetic holds exactly: powers of two, so every
    /// value is read off the exponents. D = 2^40, H = 2^20, SEB = 2^30:
    /// D·H = 2^60, 8·D·H = 2^63, and SEB·u reaches 2^63 at u = 2^33.
    ///
    /// Bites against: a predicate or a target that is right only at small
    /// operands, and `>=` at a second boundary.
    #[test]
    fn the_cap_and_the_target_hold_at_a_large_unsaturated_input() {
        let at = |u| draw_target(1 << 40, u, 1 << 20, 1 << 30).expect("H and SEB");
        // The cap is 9·D/SEB = 9·2^10 draws: 9·2^42 with 32 fractional bits.
        let cap = 9u128 << 42;
        assert_eq!(
            at(1 << 33),
            DrawTarget {
                fixed: cap,
                capped: false
            }
        );
        assert_eq!(
            at((1 << 33) + 1),
            DrawTarget {
                fixed: cap,
                capped: true
            }
        );
        // One below: (2^60 + 2^63 − 2^30) · 2^32 / 2^50 = 9·2^42 − 2^12.
        assert_eq!(
            at((1 << 33) - 1),
            DrawTarget {
                fixed: cap - (1 << 12),
                capped: false
            }
        );
        // No shortfall: the base, D/SEB = 2^10 draws.
        assert_eq!(
            at(0),
            DrawTarget {
                fixed: 1 << 42,
                capped: false
            }
        );
    }

    /// Bites against: a `draw_count` whose target is not `draw_target`'s,
    /// or a carry step other than add, shift and mask.
    /// Does NOT cover: whether the target is the specification's; the
    /// hand-checked values above and in
    /// `the_count_carries_the_fraction_and_caps_at_nine_times_base` do.
    #[test]
    fn the_count_is_the_target_plus_the_carry() {
        let mask = u128::from(u32::MAX);
        for set_size in [1, 4_096, 5_000, 10_000, 324_000] {
            for shortfall in [0, 1, 1_599, 1_600, 1_601, 7_000, 972_000, u64::MAX] {
                for horizon in [200, 2_500, 7_000] {
                    for carry in [0, 1, 1 << 31, u32::MAX] {
                        let target =
                            draw_target(set_size, shortfall, horizon, 10_000).expect("H and SEB");
                        let acc = target.fixed + u128::from(carry);
                        let expected = (
                            u64::try_from(acc >> 32).expect("nine draws a pair at most"),
                            u32::try_from(acc & mask).expect("masked"),
                        );
                        assert_eq!(
                            draw_count(set_size, shortfall, horizon, 10_000, carry),
                            Some(expected),
                            "D = {set_size}, u = {shortfall}, H = {horizon}, carry = {carry}"
                        );
                        // The target never exceeds the cap, capped or not.
                        assert!(target.fixed <= ((9 * u128::from(set_size)) << 32) / 10_000);
                    }
                }
            }
        }
        assert_eq!(draw_count(10_000, 0, 0, 10_000, 0), None);
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
