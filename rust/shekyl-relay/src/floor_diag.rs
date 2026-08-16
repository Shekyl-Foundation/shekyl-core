// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The D9 below-floor **diagnostic** (`Q12_D6A_PEER_DISCOVERY_RUN.md` §18.4).
//!
//! §18 ruled: the achieved outbound-connection count may change what the
//! **operator** sees, never what the **network** sees. This module is the
//! operator half — transition detection for the warn log and the admin-only
//! snapshot field — and it is built so the network half cannot grow out of it.
//!
//! # Why [`AchievedOutConnections`] is diagnostic-only, structurally
//!
//! No `Ord`, no arithmetic, no public accessor a relay decision could branch
//! on: the raw value is reachable only through [`FloorWatch::note`] (the
//! logging path) and [`FloorWatch::snapshot`] (the admin surface). "No
//! consumer on the wire paths" held at §18.4 only because nothing plumbed the
//! count; once it is plumbed, a type that refuses comparison is what keeps
//! that structural rather than disciplinary. A future wire consumer needs a
//! visible edit HERE, to a type whose docs say why it exists — which converts
//! §18.5's refusal from prose into something the compiler reads.

/// An achieved outbound anonymity-connection count — **connections, not
/// peers** (§16.6: the floor counts addresses; nothing on an anonymity zone
/// can certify distinctness), and **diagnostic-only** (§18.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AchievedOutConnections(u32);

impl AchievedOutConnections {
    #[must_use]
    pub const fn new(count: u32) -> Self {
        Self(count)
    }
}

/// What a [`FloorWatch::note`] observed. `WentBelow` / `Recovered` are the
/// two warn-log moments; `Steady` is everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FloorTransition {
    Steady = 0,
    WentBelow = 1,
    Recovered = 2,
}

/// Admin-surface state for one zone (`/get_stem_tallies`, AdminOnly — a
/// below-floor bit on the public listener would be a free targeting oracle,
/// §16.3, and a census input, §16.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorSnapshot {
    pub achieved: u32,
    pub floor: u32,
    pub below: bool,
}

/// Per-zone transition tracker. The floor comparison lives HERE and nowhere
/// else — this is "the logging path" §18.4 scopes the comparison to.
#[derive(Debug)]
pub struct FloorWatch {
    floor: u32,
    last: Option<(u32, bool)>,
}

impl FloorWatch {
    #[must_use]
    pub const fn new(floor: u32) -> Self {
        Self { floor, last: None }
    }

    /// Record the current achieved count; report the transition, if any.
    ///
    /// The first observation reports `WentBelow` if it starts below — a node
    /// that boots into the degraded state must say so once, not stay silent
    /// until it first recovers.
    pub fn note(&mut self, achieved: AchievedOutConnections) -> FloorTransition {
        let below = achieved.0 < self.floor;
        let was_below = self.last.map(|(_, b)| b);
        self.last = Some((achieved.0, below));
        match (was_below, below) {
            (None | Some(false), true) => FloorTransition::WentBelow,
            (Some(true), false) => FloorTransition::Recovered,
            _ => FloorTransition::Steady,
        }
    }

    /// The admin-surface view. `None` until the first `note` — an unreported
    /// zone is "no data", never a fabricated zero.
    #[must_use]
    pub fn snapshot(&self) -> Option<FloorSnapshot> {
        self.last.map(|(achieved, below)| FloorSnapshot {
            achieved,
            floor: self.floor,
            below,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_fire_on_edges_and_first_observation() {
        let mut w = FloorWatch::new(12);
        assert_eq!(
            w.note(AchievedOutConnections::new(8)),
            FloorTransition::WentBelow
        );
        assert_eq!(
            w.note(AchievedOutConnections::new(9)),
            FloorTransition::Steady
        );
        assert_eq!(
            w.note(AchievedOutConnections::new(12)),
            FloorTransition::Recovered
        );
        assert_eq!(
            w.note(AchievedOutConnections::new(13)),
            FloorTransition::Steady
        );
        assert_eq!(
            w.note(AchievedOutConnections::new(11)),
            FloorTransition::WentBelow
        );

        // Booting healthy is Steady, not a phantom recovery.
        let mut h = FloorWatch::new(12);
        assert_eq!(
            h.note(AchievedOutConnections::new(12)),
            FloorTransition::Steady
        );
        assert!(
            h.snapshot()
                == Some(FloorSnapshot {
                    achieved: 12,
                    floor: 12,
                    below: false
                })
        );
    }

    #[test]
    fn no_data_is_none_not_zero() {
        assert_eq!(FloorWatch::new(12).snapshot(), None);
    }
}
