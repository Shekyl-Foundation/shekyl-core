// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Dandelion++ stem map — which outbound peer a given source's stem
//! traffic is pinned to for the current epoch.
//!
//! A port of `net::dandelionpp::connection_map` (`src/net/dandelionpp.cpp`)
//! with the sentinel removed. The C++ uses `boost::uuids::nil_uuid()` in three
//! distinct roles — "this node is the source", "this stem slot is dead", and
//! "no stem is available" — and every caller has to know which one it is
//! looking at. Here each of those is an [`Option`] in a distinct position:
//!
//! - `source: Option<ConnectionId>` — `None` means the transaction originated
//!   locally. That is a *key* in the map, exactly as `nil_uuid` is in C++.
//! - `Vec<Option<ConnectionId>>` — `None` means the slot's peer disconnected
//!   and has not been backfilled.
//! - `stem_for(..) -> Option<ConnectionId>` — `None` means no stem is
//!   currently routable, and the caller must fall back to fluff.
//!
//! The routing behaviour is otherwise intended to be identical: same partial
//! Fisher-Yates on construction, same lowest-usage-with-random-tiebreak
//! selection, same backfill-on-disconnect. Anything that differs is a bug in
//! this file, not an improvement.

use std::collections::BTreeMap;

use crate::rng::{bounded_uniform, RelayRng};

/// A peer connection identity. Sixteen bytes, matching the `boost::uuids::uuid`
/// the daemon's connection table is keyed by, so a future FFI cut is a memcpy
/// rather than a conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(pub [u8; 16]);

impl ConnectionId {
    /// Construct from raw bytes as delivered by the C++ connection table.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw bytes, for handing back across an FFI boundary.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The outcome of [`StemMap::update`] — whether the live stem set changed.
///
/// This is a *specific* predicate: a stem slot was dropped/emptied, or the map
/// grew to fill under-capacity. It is **not** "the connection set differed."
/// `levin_notify` gates its channel **re-arm** on exactly this signal
/// (DAEMON_RELAY_PRIVACY.md §16.1), so the distinction is load-bearing, and the
/// `#[must_use]` makes a dropped re-arm signal a compile-time warning rather
/// than a silent one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum StemSetChange {
    /// No live stem changed; the caller need not re-point channels.
    Unchanged,
    /// The live stem set changed; the caller must re-point channels.
    Changed,
}

impl StemSetChange {
    /// Whether the caller must re-arm downstream channels — the C++
    /// `connection_map::update` bool, carried faithfully to the FFI boundary.
    #[must_use]
    pub fn needs_rearm(self) -> bool {
        matches!(self, Self::Changed)
    }
}

/// Maps transaction sources to stem peers for one Dandelion++ epoch.
///
/// The map is rebuilt from scratch at each epoch boundary (that is the point
/// of an epoch); [`StemMap::update`] handles churn *within* an epoch as peers
/// come and go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemMap {
    /// Stem slots. `None` is a slot whose peer disconnected.
    out: Vec<Option<ConnectionId>>,
    /// Source -> stem slot index. `None` key = locally originated.
    inbound: BTreeMap<Option<ConnectionId>, usize>,
    /// Per-slot count of sources currently routed through it. Length is the
    /// configured stem count, which is `>= out.len()` at all times.
    usage: Vec<usize>,
}

impl StemMap {
    /// An empty map that can route nothing. Equivalent to the C++
    /// default-constructed `connection_map`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            out: Vec::new(),
            inbound: BTreeMap::new(),
            usage: Vec::new(),
        }
    }

    /// Build a map over `out_connections`, keeping at most `stems` of them.
    ///
    /// When there are more candidates than stem slots, a partial Fisher-Yates
    /// selects `stems` of them uniformly; when there are fewer, all are kept
    /// and shuffled. Both branches mirror the C++ constructor.
    pub fn new<R: RelayRng + ?Sized>(
        mut out_connections: Vec<ConnectionId>,
        stems: usize,
        rng: &mut R,
    ) -> Self {
        if stems < out_connections.len() {
            // Partial Fisher-Yates: draw `stems` distinct elements into the
            // prefix, then truncate.
            for i in 0..stems {
                let remaining = out_connections.len() - i;
                let pick = i + usize_from_u64(bounded_uniform(rng, (remaining - 1) as u64));
                out_connections.swap(i, pick);
            }
            out_connections.truncate(stems);
        } else {
            // Full shuffle so slot order carries no information about the
            // order the connection table happened to enumerate peers in.
            let len = out_connections.len();
            for i in (1..len).rev() {
                let pick = usize_from_u64(bounded_uniform(rng, i as u64));
                out_connections.swap(i, pick);
            }
        }

        Self {
            out: out_connections.into_iter().map(Some).collect(),
            inbound: BTreeMap::new(),
            usage: vec![0; stems],
        }
    }

    /// Merge the current outbound connection set into the map.
    ///
    /// Slots whose peer has gone are emptied and backfilled from peers not
    /// already in use; empty stem slots are filled if candidates remain.
    /// Returns [`StemSetChange::Changed`] if the set of live stem peers changed,
    /// which is the signal the caller uses to decide whether downstream channels
    /// need re-pointing.
    pub fn update<R: RelayRng + ?Sized>(
        &mut self,
        current: Vec<ConnectionId>,
        rng: &mut R,
    ) -> StemSetChange {
        // Candidates not already serving as a stem.
        let mut candidates: Vec<ConnectionId> = current;
        candidates.sort_unstable();
        candidates.dedup();

        let mut replaced = false;
        for slot in &mut self.out {
            match slot {
                Some(id) => {
                    if let Ok(pos) = candidates.binary_search(id) {
                        // Still connected; take it out of the candidate pool so
                        // it cannot also be used to backfill another slot.
                        candidates.remove(pos);
                    } else {
                        *slot = None;
                        replaced = true;
                    }
                }
                // A slot left empty by an earlier update still needs backfilling.
                // The C++ `connection_map::update` re-marks nil slots (setting
                // `replace = true`); mirror that, so the early-return below does
                // not skip a fillable empty slot and `update` reports the change
                // once the slot is filled.
                None => replaced = true,
            }
        }

        if !replaced && self.out.len() == self.usage.len() {
            // Every slot is live and the map is at full width: nothing to do.
            return StemSetChange::Unchanged;
        }

        let existing_outs = self.out.len();
        for i in 0..self.usage.len() {
            if candidates.is_empty() {
                break;
            }
            let growing = self.out.len() <= i;
            if growing || self.out[i].is_none() {
                // Draw a uniformly random candidate by swapping it to the back
                // and popping — same trick the C++ uses.
                let last = candidates.len() - 1;
                let pick = usize_from_u64(bounded_uniform(rng, last as u64));
                candidates.swap(last, pick);
                let chosen = candidates.pop().expect("candidates is non-empty");
                if growing {
                    self.out.push(Some(chosen));
                } else {
                    self.out[i] = Some(chosen);
                }
            }
        }

        if replaced || existing_outs < self.out.len() {
            StemSetChange::Changed
        } else {
            StemSetChange::Unchanged
        }
    }

    /// The stem slots in index order, `None` for an emptied slot.
    ///
    /// This is the ordering the daemon's noise-channel iteration indexes **by
    /// position** (`levin_notify` computes `i = id - begin()` and posts to
    /// `channels[i]`), so the FFI snapshot must preserve it, nils included —
    /// see DAEMON_RELAY_PRIVACY.md §16.1. Length is the live-or-emptied slot
    /// count, which can be below [`StemMap::width`] when the map is
    /// under-filled; it mirrors the C++ `connection_map` iterator span, not
    /// `size()`.
    #[must_use]
    pub fn slots(&self) -> &[Option<ConnectionId>] {
        &self.out
    }

    /// Number of stem slots currently backed by a live peer.
    #[must_use]
    pub fn live_stems(&self) -> usize {
        self.out.iter().filter(|s| s.is_some()).count()
    }

    /// Configured stem width (live or not).
    #[must_use]
    pub fn width(&self) -> usize {
        self.usage.len()
    }

    /// Per-slot source counts. Exposed for measurement: an uneven usage
    /// distribution is the observable that says stem selection is not
    /// balancing, which is one of the properties this crate exists to grade.
    #[must_use]
    pub fn usage(&self) -> &[usize] {
        &self.usage
    }

    /// The stem peer for `source`, assigning one if this source has not been
    /// seen this epoch.
    ///
    /// `source` is `None` for locally originated transactions. Returns `None`
    /// when no stem slot is routable, in which case the caller must fluff.
    pub fn stem_for<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        match self.inbound.get(&source).copied() {
            None => {
                let index = self.select_slot(rng)?;
                self.inbound.insert(source, index);
                self.usage[index] += 1;
                self.out[index]
            }
            Some(index) => {
                if self.out[index].is_some() {
                    return self.out[index];
                }
                // The peer this source was pinned to disconnected. Release the
                // old slot and re-pin. Re-pinning is not free — it moves this
                // source's stem traffic to a different peer mid-epoch — but
                // the alternative is dropping to fluff, which is strictly more
                // revealing.
                self.usage[index] -= 1;
                match self.select_slot(rng) {
                    Some(next) => {
                        self.inbound.insert(source, next);
                        self.usage[next] += 1;
                        self.out[next]
                    }
                    None => {
                        self.inbound.remove(&source);
                        None
                    }
                }
            }
        }
    }

    /// Pick the live slot with the fewest sources routed through it, breaking
    /// ties uniformly at random.
    ///
    /// The balancing matters: a slot that accumulates sources becomes a better
    /// guess for an adversary correlating stem traffic, and the random
    /// tiebreak is what stops the first slot from winning every tie.
    fn select_slot<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Option<usize> {
        let mut lowest = usize::MAX;
        // Stem width is 1 or 2 in practice; a Vec here is not a hot path.
        let mut choices: Vec<usize> = Vec::with_capacity(self.out.len());
        for (i, slot) in self.out.iter().enumerate() {
            if slot.is_none() {
                continue;
            }
            let used = self.usage[i];
            if used < lowest {
                lowest = used;
                choices.clear();
                choices.push(i);
            } else if used == lowest {
                choices.push(i);
            }
        }

        match choices.len() {
            0 => None,
            1 => Some(choices[0]),
            n => Some(choices[usize_from_u64(bounded_uniform(rng, (n - 1) as u64))]),
        }
    }
}

/// Narrow a draw that is already bounded by a `usize`-derived range.
///
/// Every call site passes a bound computed from a container length, so the
/// value round-trips exactly on any target where `usize` is at least 32 bits.
fn usize_from_u64(v: u64) -> usize {
    usize::try_from(v).expect("draw was bounded by a usize-derived range")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;

    fn ids(n: u8) -> Vec<ConnectionId> {
        (0..n)
            .map(|i| {
                let mut b = [0_u8; 16];
                b[0] = i + 1;
                ConnectionId::from_bytes(b)
            })
            .collect()
    }

    #[test]
    fn empty_map_routes_nothing() {
        let mut rng = SplitMix64::new(1);
        let mut m = StemMap::empty();
        assert_eq!(m.stem_for(None, &mut rng), None);
        assert_eq!(m.live_stems(), 0);
    }

    #[test]
    fn zero_stems_routes_nothing() {
        let mut rng = SplitMix64::new(2);
        let mut m = StemMap::new(ids(5), 0, &mut rng);
        assert_eq!(m.width(), 0);
        assert_eq!(m.stem_for(None, &mut rng), None);
        assert_eq!(m.stem_for(Some(ids(1)[0]), &mut rng), None);
    }

    #[test]
    fn construction_truncates_to_the_stem_count() {
        let mut rng = SplitMix64::new(3);
        let m = StemMap::new(ids(10), 2, &mut rng);
        assert_eq!(m.live_stems(), 2);
        assert_eq!(m.width(), 2);
    }

    #[test]
    fn construction_keeps_all_when_fewer_peers_than_stems() {
        let mut rng = SplitMix64::new(4);
        let m = StemMap::new(ids(1), 3, &mut rng);
        assert_eq!(m.live_stems(), 1);
        assert_eq!(m.width(), 3, "width is the configured stem count");
    }

    #[test]
    fn a_source_is_pinned_to_one_stem_for_the_epoch() {
        let mut rng = SplitMix64::new(5);
        let peers = ids(8);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        let source = Some(peers[0]);
        let first = m.stem_for(source, &mut rng).expect("a stem is available");
        for _ in 0..64 {
            assert_eq!(m.stem_for(source, &mut rng), Some(first));
        }
    }

    #[test]
    fn distinct_sources_spread_across_stems() {
        let mut rng = SplitMix64::new(6);
        let peers = ids(20);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        for p in &peers {
            let _ = m.stem_for(Some(*p), &mut rng);
        }
        // Lowest-usage selection must keep the two slots within one of each
        // other after an even number of assignments.
        let usage = m.usage();
        let spread = usage.iter().max().unwrap() - usage.iter().min().unwrap();
        assert!(spread <= 1, "stem usage unbalanced: {usage:?}");
        assert_eq!(usage.iter().sum::<usize>(), peers.len());
    }

    #[test]
    fn local_source_is_a_key_like_any_other() {
        let mut rng = SplitMix64::new(7);
        let mut m = StemMap::new(ids(4), 2, &mut rng);
        let local = m.stem_for(None, &mut rng).expect("stem available");
        assert_eq!(m.stem_for(None, &mut rng), Some(local));
        assert_eq!(m.usage().iter().sum::<usize>(), 1);
    }

    #[test]
    fn dropped_stem_is_backfilled_by_update() {
        let mut rng = SplitMix64::new(8);
        let peers = ids(6);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        assert_eq!(m.live_stems(), 2);

        // Drop every peer currently serving as a stem by presenting a set that
        // excludes them.
        let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
        let survivors: Vec<ConnectionId> = peers
            .iter()
            .filter(|p| !live.contains(p))
            .copied()
            .collect();
        assert_eq!(
            m.update(survivors, &mut rng),
            StemSetChange::Changed,
            "update should report change"
        );
        assert_eq!(m.live_stems(), 2, "slots backfilled from survivors");
        for slot in m.out.iter().flatten() {
            assert!(!live.contains(slot), "a dead peer was reused");
        }
    }

    #[test]
    fn a_slot_emptied_by_an_earlier_update_is_backfilled_later() {
        // Regression: an empty slot left by a prior update (no candidate to fill
        // it then) must be backfilled by a *later* update that offers one, even
        // if that later update disconnects nothing else. The early-return must
        // not treat "nothing disconnected this call" as "every slot is live".
        let mut rng = SplitMix64::new(11);
        let peers = ids(3); // 3 peers, 2 stems → exactly one spare
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        assert_eq!(m.live_stems(), 2);

        let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
        let spare: ConnectionId = *peers.iter().find(|p| !live.contains(p)).unwrap();

        // Call 1: drop one live stem, offering only the other — no candidate to
        // backfill, so a slot goes empty and stays empty.
        assert_eq!(m.update(vec![live[1]], &mut rng), StemSetChange::Changed);
        assert_eq!(
            m.live_stems(),
            1,
            "one slot left empty (no candidate to fill)"
        );

        // Call 2: the surviving stem stays and a fresh candidate appears. The
        // empty slot must be backfilled — and the change must be reported.
        assert_eq!(
            m.update(vec![live[1], spare], &mut rng),
            StemSetChange::Changed,
            "backfilling a previously-emptied slot is a reportable change"
        );
        assert_eq!(
            m.live_stems(),
            2,
            "the empty slot was backfilled from the new candidate"
        );
    }

    #[test]
    fn update_is_a_no_op_when_nothing_changed() {
        let mut rng = SplitMix64::new(9);
        let peers = ids(5);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        assert_eq!(m.update(peers, &mut rng), StemSetChange::Unchanged);
    }

    #[test]
    fn losing_all_peers_falls_back_to_no_stem() {
        let mut rng = SplitMix64::new(10);
        let peers = ids(4);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);
        let source = Some(peers[0]);
        assert!(m.stem_for(source, &mut rng).is_some());

        assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 0);
        assert_eq!(
            m.stem_for(source, &mut rng),
            None,
            "no routable stem must surface as None, not a stale peer"
        );
        // The released slot must not leave a phantom usage count behind.
        assert_eq!(m.usage().iter().sum::<usize>(), 0);
    }

    #[test]
    fn remapped_source_releases_its_old_slot() {
        let mut rng = SplitMix64::new(11);
        let peers = ids(6);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);

        for p in &peers {
            let _ = m.stem_for(Some(*p), &mut rng);
        }
        let before: usize = m.usage().iter().sum();
        assert_eq!(before, peers.len());

        // Kill one slot; every source pinned to it must re-pin exactly once.
        let victim = m.out[0].expect("slot 0 live");
        let survivors: Vec<ConnectionId> =
            peers.iter().filter(|p| **p != victim).copied().collect();
        assert_eq!(m.update(survivors, &mut rng), StemSetChange::Changed);
        for p in &peers {
            let _ = m.stem_for(Some(*p), &mut rng);
        }
        assert_eq!(
            m.usage().iter().sum::<usize>(),
            before,
            "re-pinning must not double-count a source"
        );
    }

    #[test]
    fn update_never_assigns_one_peer_to_two_slots() {
        let mut rng = SplitMix64::new(12);
        let peers = ids(3);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!(m.update(peers, &mut rng), StemSetChange::Unchanged);
        let live: Vec<ConnectionId> = m.out.iter().flatten().copied().collect();
        let mut sorted = live.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), live.len(), "duplicate peer across stem slots");
    }

    // --- Faithful translations of the C++ `dandelionpp_map` gtests (the
    // survivor half of RP-2a's acceptance, DAEMON_RELAY_PRIVACY.md §16). The C++
    // suite runs unchanged against this map as the migration oracle; these keep
    // its coverage once it is retired. `traits` is a C++ STL-iterator-ABI test
    // with no Rust analogue; `empty` and `zero_stems` are covered by
    // `empty_map_routes_nothing` / `zero_stems_routes_nothing` above.

    #[test]
    fn gtest_dropped_connection() {
        // 6 peers / 3 stems: nine inbound sources spread 3-per-stem, then one
        // stem is dropped and backfilled from an unused peer, no dead reuse.
        let mut rng = SplitMix64::new(0xD1);
        let peers = ids(6);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!(m.live_stems(), 3);

        // Nine inbound sources, disjoint from the peer ids.
        let sources: Vec<ConnectionId> = (0u8..9)
            .map(|i| {
                let mut b = [0u8; 16];
                b[0] = 100 + i;
                ConnectionId::from_bytes(b)
            })
            .collect();
        for s in &sources {
            assert!(m.stem_for(Some(*s), &mut rng).is_some());
        }
        assert_eq!(m.usage().len(), 3);
        assert!(
            m.usage().iter().all(|u| *u == 3),
            "nine sources spread 3-per-stem: {:?}",
            m.usage()
        );

        let lost = m
            .slots()
            .iter()
            .flatten()
            .nth(1)
            .copied()
            .expect("a live stem");
        let survivors: Vec<ConnectionId> = peers.iter().filter(|p| **p != lost).copied().collect();
        assert_eq!(m.update(survivors, &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 3, "the dropped slot was backfilled");
        assert!(
            m.slots().iter().flatten().all(|s| *s != lost),
            "the dropped peer was reused"
        );
    }

    #[test]
    fn gtest_dropped_connection_remapped_leaves_a_nil_hole() {
        // 3 peers / 3 stems: dropping a stem with no spare nils the slot *in
        // place* — the iterator span (slots().len()) stays at width while the
        // live count falls. This is the §16.1 snapshot property the FFI relies
        // on for index alignment. A later peer backfills the hole.
        let mut rng = SplitMix64::new(0xD2);
        let peers = ids(3);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!((m.live_stems(), m.slots().len()), (3, 3));

        let dropped = m.slots()[1].expect("slot 1 live");
        let survivors: Vec<ConnectionId> =
            peers.iter().filter(|p| **p != dropped).copied().collect();
        assert_eq!(
            m.update(survivors.clone(), &mut rng),
            StemSetChange::Changed
        );
        assert_eq!(m.slots().len(), 3, "span keeps the nil hole in position");
        assert_eq!(m.live_stems(), 2, "one slot is nil, not compacted away");
        assert_eq!(m.slots().iter().filter(|s| s.is_none()).count(), 1);

        let fresh = ConnectionId::from_bytes([210u8; 16]);
        let mut refill = survivors;
        refill.push(fresh);
        assert_eq!(m.update(refill, &mut rng), StemSetChange::Changed);
        assert_eq!(
            m.live_stems(),
            3,
            "the hole was backfilled from the fresh peer"
        );
        assert!(m.slots().iter().flatten().any(|s| *s == fresh));
    }

    #[test]
    fn gtest_dropped_all_connections() {
        // 8 peers / 3 stems: after every peer is gone the span stays but nothing
        // is routable, and pinned sources surface `None`, not a stale peer.
        let mut rng = SplitMix64::new(0xD3);
        let peers = ids(8);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        let sources = ids(9);
        for s in &sources {
            assert!(m.stem_for(Some(*s), &mut rng).is_some());
        }
        assert_eq!(m.live_stems(), 3);

        assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 0, "no live stem remains");
        assert_eq!(m.slots().len(), 3, "the slots are nil, not removed");
        for s in &sources {
            assert_eq!(
                m.stem_for(Some(*s), &mut rng),
                None,
                "no routable stem must surface as None, not a stale peer"
            );
        }
    }
}
