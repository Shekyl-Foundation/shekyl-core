// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The vanguard rotation manager — supervisor-scoped state that outlives Tor
//! incarnations, so a Tor **restart never causes a rotation** (PR-C3 core).
//!
//! # The load-bearing invariant
//!
//! Persisted state is authoritative. An incarnation **restores and applies**
//! the current set; it never re-selects. Only the wall clock expires a node.
//! Get this wrong and every supervisor restart re-draws the set — which is
//! exactly vanguards-lite's weakness (its guard topology resets when Tor
//! restarts), so we would have paid for full vanguards' complexity while
//! reimplementing lite's flaw. Our backoff starts at 1 s, so a flapping Tor
//! could re-draw many times an hour: the over-rotation failure at its worst.
//! [`RotationState::restore`] therefore keeps every surviving node's identity
//! **and its expiry timestamp** untouched.
//!
//! # Lifetimes (spec-pinned; prop-333 / guard-spec)
//!
//! - **L2:** uniform over [30, 60] days (mean 45). Implementations *may*
//!   expose L2 as a user pinning option.
//! - **L3:** `max(X, X)` over [1, 48] hours inclusive (mean 31.5 h), and
//!   **not** user-pinnable. The skew is deliberate: some chance of a very
//!   short rotation to deter compromise/coercion, biased toward longer
//!   periods so a Sybil attack must be sustained.
//!
//! **Recorded divergence:** the spec *text* gives L2 a uniform distribution,
//! but notes the reference implementation uses `max(X, X)` for *both* layers
//! "for simplicity." We follow the spec text (the analyzed version): L2
//! uniform, L3 `max(X, X)`.
//!
//! # Replacement policy on restore
//!
//! A persisted fingerprint may have left the consensus, and pinning a dead
//! relay breaks circuits. Restore reconciles against the consensus and
//! **replaces only the missing nodes, never the set** — every replacement is
//! a fresh draw and therefore an adversary opportunity, so it is minimized.
//! **Flag-loss is deliberately *not* a replacement trigger here:**
//! vanguards-lite replaces a vanguard that loses `Fast`/`Stable`, but the
//! proposal explicitly notes the design did not have to be that way. Treating
//! flag-loss as a rotation is a separate, argued decision — not inherited.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::collections::HashSet;

use crate::control::consensus::ConsensusRelay;
use crate::control::vanguards::{
    draw_replacement, select_disjoint, HsLayerPins, RelayFingerprint, VanguardRng,
    NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS,
};

/// L2 lifetime bounds (spec): uniform over [30, 60] days.
const L2_LIFETIME_MIN: Duration = Duration::from_secs(30 * 86_400);
const L2_LIFETIME_MAX: Duration = Duration::from_secs(60 * 86_400);
/// L3 lifetime bounds (spec): `max(X, X)` over [1, 48] hours inclusive.
const L3_LIFETIME_MIN: Duration = Duration::from_secs(3_600);
const L3_LIFETIME_MAX: Duration = Duration::from_secs(48 * 3_600);

/// Which layer a node sits in — its lifetime distribution differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// Second-level guard (L2): uniform 30–60 day lifetime.
    Two,
    /// Third-level guard (L3): `max(X, X)` 1–48 hour lifetime.
    Three,
}

/// One pinned vanguard: its identity and the instant it expires.
///
/// Expiry is an absolute wall-clock time (persisted as Unix seconds) so it
/// survives process restarts — the whole point is that the clock, not a
/// restart, drives rotation. Each node's expiry is tracked **independently**
/// (the spec keeps per-node rotation times so the primary and second-level
/// guards' rotations are not disclosed together).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VanguardNode {
    /// The pinned relay.
    pub fingerprint: RelayFingerprint,
    /// Wall-clock instant at which this node rotates out.
    pub expires_at: SystemTime,
}

/// The full rotation state: the L2 and L3 node sets with their timers.
///
/// Supervisor-scoped and persisted; incarnations read it to apply pins, the
/// rotation loop mutates it as nodes expire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationState {
    /// Layer-2 nodes (`NUM_LAYER2_GUARDS` of them once initialized).
    pub layer2: Vec<VanguardNode>,
    /// Layer-3 nodes (`NUM_LAYER3_GUARDS`).
    pub layer3: Vec<VanguardNode>,
}

impl RotationState {
    /// Draw a fresh state from the consensus — the first-ever selection, when
    /// no persisted state exists. Every node gets an independent lifetime
    /// from its layer's distribution.
    ///
    /// # Errors
    ///
    /// [`RotationError::TooFewEligible`] if the consensus cannot fill
    /// `NUM_LAYER2_GUARDS + NUM_LAYER3_GUARDS` disjoint seats.
    pub fn select_fresh(
        consensus: &[ConsensusRelay],
        now: SystemTime,
        rng: &mut impl VanguardRng,
    ) -> Result<Self, RotationError> {
        let (l2_fps, l3_fps) =
            select_disjoint(consensus, NUM_LAYER2_GUARDS, NUM_LAYER3_GUARDS, rng)
                .ok_or(RotationError::TooFewEligible)?;
        Ok(Self {
            layer2: l2_fps
                .into_iter()
                .map(|fp| VanguardNode {
                    fingerprint: fp,
                    expires_at: now + sample_lifetime(Layer::Two, rng),
                })
                .collect(),
            layer3: l3_fps
                .into_iter()
                .map(|fp| VanguardNode {
                    fingerprint: fp,
                    expires_at: now + sample_lifetime(Layer::Three, rng),
                })
                .collect(),
        })
    }

    /// The pins an incarnation applies via `SETCONF` — the current node set,
    /// unchanged. `None` only if a layer is empty (an uninitialized state).
    #[must_use]
    pub fn to_pins(&self) -> Option<HsLayerPins> {
        HsLayerPins::new(
            self.layer2.iter().map(|n| n.fingerprint).collect(),
            self.layer3.iter().map(|n| n.fingerprint).collect(),
        )
    }

    /// **Restore** persisted state against the current consensus: keep every
    /// node whose relay is still present (identity **and** expiry untouched —
    /// the load-bearing invariant), and replace **only** nodes whose relay
    /// has left the consensus with a fresh draw disjoint from all survivors.
    ///
    /// This does not expire anything — that is [`Self::expire_due`]'s job,
    /// which the caller runs after restore. A restart alone must not rotate.
    ///
    /// # Errors
    ///
    /// [`RotationError::TooFewEligible`] if replacements cannot be drawn.
    pub fn restore(
        mut self,
        consensus: &[ConsensusRelay],
        rng: &mut impl VanguardRng,
    ) -> Result<Self, RotationError> {
        // "Present" = appears in the consensus **at all**, regardless of
        // flags. Flag-loss is deliberately NOT a replacement trigger (see the
        // module doc); only a relay that has left the consensus entirely is
        // swapped, because pinning a dead relay breaks circuits.
        let present: HashSet<RelayFingerprint> = consensus.iter().map(|r| r.fingerprint).collect();

        // Exclusion base: the survivors (relay still present). Replacements
        // are drawn disjoint from these and from each other.
        let mut in_use: Vec<RelayFingerprint> = self
            .layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.fingerprint)
            .filter(|fp| present.contains(fp))
            .collect();

        swap_absent(&mut self.layer2, &present, consensus, &mut in_use, rng)?;
        swap_absent(&mut self.layer3, &present, consensus, &mut in_use, rng)?;
        Ok(self)
    }

    /// Rotate out every node whose expiry is at or before `now`, replacing
    /// each with a fresh draw (disjoint from all current nodes) and a new
    /// lifetime. Returns the fingerprints actually rotated (for logging /
    /// re-`SETCONF` decisions). Only the clock drives this.
    ///
    /// # Errors
    ///
    /// [`RotationError::TooFewEligible`] if a replacement cannot be drawn.
    pub fn expire_due(
        &mut self,
        consensus: &[ConsensusRelay],
        now: SystemTime,
        rng: &mut impl VanguardRng,
    ) -> Result<Vec<RelayFingerprint>, RotationError> {
        let mut in_use: Vec<RelayFingerprint> = self
            .layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.fingerprint)
            .collect();
        let mut rotated = Vec::new();
        rotate_expired(
            &mut self.layer2,
            Layer::Two,
            consensus,
            now,
            &mut in_use,
            &mut rotated,
            rng,
        )?;
        rotate_expired(
            &mut self.layer3,
            Layer::Three,
            consensus,
            now,
            &mut in_use,
            &mut rotated,
            rng,
        )?;
        Ok(rotated)
    }

    /// The earliest expiry across all nodes — the deadline the supervisor's
    /// rotation `select!` arm sleeps until. `None` for an empty state.
    #[must_use]
    pub fn next_expiry(&self) -> Option<SystemTime> {
        self.layer2
            .iter()
            .chain(&self.layer3)
            .map(|n| n.expires_at)
            .min()
    }

    /// Serialize to the persisted text form: one `L2|L3 $fp <unix-secs>` line
    /// per node. Hand-rolled (no serde dep); round-trips through
    /// [`Self::deserialize`].
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for (tag, nodes) in [("L2", &self.layer2), ("L3", &self.layer3)] {
            for node in nodes {
                let secs = node
                    .expires_at
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                out.push_str(tag);
                out.push(' ');
                out.push_str(&node.fingerprint.to_specifier());
                out.push(' ');
                out.push_str(&secs.to_string());
                out.push('\n');
            }
        }
        out
    }

    /// Parse the persisted text form. `None` on any malformed line — a
    /// corrupt state file is treated as "no state" by the caller (re-select),
    /// never as a partial set that would silently under-pin.
    #[must_use]
    pub fn deserialize(text: &str) -> Option<Self> {
        let mut layer2 = Vec::new();
        let mut layer3 = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split(' ');
            let tag = parts.next()?;
            let fingerprint = RelayFingerprint::parse(parts.next()?)?;
            let secs: u64 = parts.next()?.parse().ok()?;
            if parts.next().is_some() {
                return None; // trailing garbage
            }
            let node = VanguardNode {
                fingerprint,
                expires_at: UNIX_EPOCH + Duration::from_secs(secs),
            };
            match tag {
                "L2" => layer2.push(node),
                "L3" => layer3.push(node),
                _ => return None,
            }
        }
        Some(Self { layer2, layer3 })
    }
}

/// Swap, in `set`, every node whose relay is **absent from the consensus**
/// (`present`) for a fresh bandwidth-weighted draw disjoint from `in_use`.
/// The slot **keeps its existing expiry timer** — swapping a dead relay for a
/// live one is a repair, not a rotation, so a fresh timer here would be a
/// hidden rotation. Surviving nodes are left entirely untouched (the
/// load-bearing invariant).
fn swap_absent(
    set: &mut [VanguardNode],
    present: &HashSet<RelayFingerprint>,
    consensus: &[ConsensusRelay],
    in_use: &mut Vec<RelayFingerprint>,
    rng: &mut impl VanguardRng,
) -> Result<(), RotationError> {
    for node in set.iter_mut() {
        if !present.contains(&node.fingerprint) {
            let fresh =
                draw_replacement(consensus, in_use, rng).ok_or(RotationError::TooFewEligible)?;
            in_use.push(fresh);
            node.fingerprint = fresh;
        }
    }
    Ok(())
}

/// Rotate, in `set`, every node whose expiry is at or before `now`: a fresh
/// bandwidth-weighted draw disjoint from `in_use` **and a new lifetime** for
/// its layer. `in_use` is kept current so two expiries in one pass cannot
/// draw the same replacement.
#[allow(clippy::too_many_arguments)]
fn rotate_expired(
    set: &mut [VanguardNode],
    layer: Layer,
    consensus: &[ConsensusRelay],
    now: SystemTime,
    in_use: &mut [RelayFingerprint],
    rotated: &mut Vec<RelayFingerprint>,
    rng: &mut impl VanguardRng,
) -> Result<(), RotationError> {
    for node in set.iter_mut() {
        if node.expires_at <= now {
            let old = node.fingerprint;
            let fresh =
                draw_replacement(consensus, in_use, rng).ok_or(RotationError::TooFewEligible)?;
            if let Some(slot) = in_use.iter_mut().find(|f| **f == old) {
                *slot = fresh;
            }
            node.fingerprint = fresh;
            node.expires_at = now + sample_lifetime(layer, rng);
            rotated.push(fresh);
        }
    }
    Ok(())
}

/// Sample a node's lifetime from its layer's distribution.
fn sample_lifetime(layer: Layer, rng: &mut impl VanguardRng) -> Duration {
    match layer {
        // L2: uniform over [min, max].
        Layer::Two => uniform_between(L2_LIFETIME_MIN, L2_LIFETIME_MAX, rng),
        // L3: max(X, X) — draw two uniforms, take the longer. Skews toward
        // longer lifetimes (spec).
        Layer::Three => {
            let a = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng);
            let b = uniform_between(L3_LIFETIME_MIN, L3_LIFETIME_MAX, rng);
            a.max(b)
        }
    }
}

/// A uniform `Duration` in `[min, max]` inclusive.
fn uniform_between(min: Duration, max: Duration, rng: &mut impl VanguardRng) -> Duration {
    let span = max.as_secs() - min.as_secs();
    let offset = if span == 0 {
        0
    } else {
        rng.next_u64() % (span + 1)
    };
    min + Duration::from_secs(offset)
}

/// Why a rotation operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    /// The consensus lacks enough eligible relays to fill or replace the set.
    TooFewEligible,
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewEligible => write!(f, "too few eligible relays for the vanguard set"),
        }
    }
}

impl std::error::Error for RotationError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeded SplitMix64 (the crate's test-RNG shape, no `rand` dep).
    struct SeededRng(u64);
    impl VanguardRng for SeededRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    fn pool(n: u8) -> Vec<ConsensusRelay> {
        (1..=n)
            .map(|b| ConsensusRelay {
                fingerprint: RelayFingerprint::from_bytes([b; 20]),
                bandwidth: 1000,
                eligible: true,
            })
            .collect()
    }

    fn t0() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    #[test]
    fn fresh_selection_fills_both_layers_disjoint() {
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(1)).unwrap();
        assert_eq!(state.layer2.len(), NUM_LAYER2_GUARDS);
        assert_eq!(state.layer3.len(), NUM_LAYER3_GUARDS);
        // All ten expiries are in the future.
        for n in state.layer2.iter().chain(&state.layer3) {
            assert!(n.expires_at > t0());
        }
    }

    #[test]
    fn restore_with_all_relays_present_is_a_no_op_the_invariant() {
        // THE load-bearing test: a restart (restore) with every relay still
        // in the consensus and nothing expired must NOT change the set or any
        // timer. Only the clock rotates.
        let consensus = pool(30);
        let original = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(9)).unwrap();
        let restored = original
            .clone()
            .restore(&consensus, &mut SeededRng(123)) // different rng seed
            .unwrap();
        assert_eq!(
            restored, original,
            "restore must preserve identities AND expiry timers"
        );
    }

    #[test]
    fn restore_replaces_only_missing_relays_and_keeps_survivor_timers() {
        let consensus = pool(30);
        let original = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(5)).unwrap();

        // Drop exactly one L2 relay from the consensus.
        let dropped = original.layer2[0].fingerprint;
        let shrunk: Vec<ConsensusRelay> = consensus
            .iter()
            .filter(|r| r.fingerprint != dropped)
            .copied()
            .collect();

        let restored = original
            .clone()
            .restore(&shrunk, &mut SeededRng(77))
            .unwrap();

        // The dropped node was replaced; every other node (identity + timer)
        // is byte-identical to before.
        assert_ne!(restored.layer2[0].fingerprint, dropped);
        assert_eq!(
            restored.layer2[0].expires_at, original.layer2[0].expires_at,
            "a swapped-dead-relay slot keeps its timer (not a rotation)"
        );
        for i in 1..NUM_LAYER2_GUARDS {
            assert_eq!(restored.layer2[i], original.layer2[i]);
        }
        assert_eq!(restored.layer3, original.layer3);
        // Replacement is disjoint from the rest.
        let all: Vec<_> = restored
            .layer2
            .iter()
            .chain(&restored.layer3)
            .map(|n| n.fingerprint)
            .collect();
        let mut dedup = all.clone();
        dedup.sort_by_key(|fp| fp.to_specifier());
        dedup.dedup();
        assert_eq!(all.len(), dedup.len(), "no duplicate after replacement");
    }

    #[test]
    fn only_the_clock_expires_nodes() {
        let consensus = pool(30);
        let mut state = RotationState::select_fresh(&consensus, t0(), &mut SeededRng(2)).unwrap();
        let before = state.clone();

        // Nothing is due yet.
        let rotated = state
            .expire_due(&consensus, t0(), &mut SeededRng(3))
            .unwrap();
        assert!(rotated.is_empty());
        assert_eq!(state, before, "no expiry => no change");

        // Advance past the earliest expiry: exactly the due node(s) rotate.
        let earliest = state.next_expiry().unwrap();
        let due_count = state
            .layer2
            .iter()
            .chain(&state.layer3)
            .filter(|n| n.expires_at <= earliest)
            .count();
        let rotated = state
            .expire_due(&consensus, earliest, &mut SeededRng(4))
            .unwrap();
        assert_eq!(rotated.len(), due_count);
        // Rotated nodes now expire in the future again.
        for n in state.layer2.iter().chain(&state.layer3) {
            assert!(n.expires_at > earliest || n.expires_at > t0());
        }
    }

    #[test]
    fn l3_lifetimes_fall_in_the_spec_band_and_skew_long() {
        // Sample many L3 lifetimes; every one is within [1h, 48h], and the
        // mean is above the midpoint (24.5h) because of the max(X,X) skew.
        let mut rng = SeededRng(11);
        let mut total = 0u64;
        let n = 500;
        for _ in 0..n {
            let d = sample_lifetime(Layer::Three, &mut rng);
            assert!(d >= L3_LIFETIME_MIN && d <= L3_LIFETIME_MAX);
            total += d.as_secs();
        }
        let mean_hours = (total / n) / 3600;
        assert!(
            mean_hours >= 25,
            "max(X,X) must skew long; mean was {mean_hours}h"
        );
    }

    #[test]
    fn persistence_round_trips() {
        let state = RotationState::select_fresh(&pool(30), t0(), &mut SeededRng(8)).unwrap();
        let text = state.serialize();
        let back = RotationState::deserialize(&text).expect("valid");
        assert_eq!(back, state);
    }

    #[test]
    fn corrupt_state_is_rejected_whole_not_partially_loaded() {
        assert!(RotationState::deserialize("L2 $notahex 123").is_none());
        assert!(RotationState::deserialize("L2 $AA 123").is_none()); // short fp
        assert!(
            RotationState::deserialize("LX $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1").is_none()
        );
        assert!(
            RotationState::deserialize("L2 $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1 extra")
                .is_none()
        );
    }
}
