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
/// One source's routing decision for this epoch, frozen at its first pin.
///
/// **W3c (`DAEMON_RELAY_PRIVACY.md` §19.2).** The set of peers a source may be
/// routed to is fixed when it first pins and **never grows**. That is the whole
/// of the churn-stability property, and it is enforced by this field being
/// append-never rather than by any caller's discipline — callers multiply, and
/// §19.1's C-1 found the clearnet re-roll surface is already two triggers deep.
///
/// The property it replaces was pinning by *slot index*, which re-rolled a
/// source silently: `update()` refilled the churned slot and the next `stem_for`
/// took the `is_some()` fast path and returned whoever now occupied it, with no
/// selection code running at all. Measured at §19.3 — 16 induced re-rolls reached
/// the origin's stem path 91.7 % of the time against 16.7 % here.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    /// Peers this source may be routed to, in walk order. Frozen at first pin.
    candidates: Vec<ConnectionId>,
    /// How far into `candidates` this source has walked. Only ever advances:
    /// a peer that leaves the map does not come back to serve this source, even
    /// if it reconnects, because that would be a post-pin arrival by another name.
    cursor: usize,
    /// The slot this source is currently counted against in `StemMap::usage`.
    ///
    /// Stored rather than re-derived from the current candidate, because the
    /// candidate may have *left the map* — which is exactly when the count needs
    /// releasing. Deriving it there silently skips the decrement and leaves a
    /// phantom usage count, which is what `losing_all_peers_falls_back_to_no_stem`
    /// caught on the first draft of this type.
    counted: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemMap {
    /// Stem slots. `None` is a slot whose peer disconnected.
    out: Vec<Option<ConnectionId>>,
    /// Source -> its frozen routing decision. `None` key = locally originated.
    inbound: BTreeMap<Option<ConnectionId>, Pin>,
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

    /// The slot currently holding `peer`, if any.
    fn slot_of(&self, peer: ConnectionId) -> Option<usize> {
        self.out.iter().position(|s| *s == Some(peer))
    }

    /// The stem peer for `source`, assigning one if this source has not been
    /// seen this epoch.
    ///
    /// `source` is `None` for locally originated transactions. Returns `None`
    /// when no stem slot is routable, in which case the caller must fluff.
    ///
    /// **Churn-stable (§19.2).** A source that has already pinned walks its own
    /// frozen [`Pin::candidates`] and nothing else, so no peer that entered the
    /// map after it pinned can ever serve it. A source whose successor churns
    /// therefore falls back to its *alternate* — a peer that was in its set
    /// before the churn — rather than to a fresh draw, which is what stopped an
    /// adversary from converting induced churn into repeated rolls (§19.3).
    ///
    /// Exhausting the frozen set yields `None` (fluff) rather than a fresh pin.
    /// That is the deliberate half of the trade: re-pinning here would hand back
    /// exactly the post-churn draw the freeze exists to deny, and reaching it
    /// requires churning *every* peer the source started with — the W3
    /// both-slots case, already bounded — not a single induced drop. It is also
    /// bounded in time: `rebuild_stems` re-draws every pin at the epoch
    /// boundary, so a source is unroutable for at most the rest of the epoch.
    pub fn stem_for<R: RelayRng + ?Sized>(
        &mut self,
        source: Option<ConnectionId>,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        if let Some(pin) = self.inbound.get(&source) {
            let previous = pin.candidates.get(pin.cursor).copied();
            // Walk forward over candidates that have left the map. The set never
            // grows, so this can only narrow the source's options.
            let mut cursor = pin.cursor;
            while cursor < pin.candidates.len() && self.slot_of(pin.candidates[cursor]).is_none() {
                cursor += 1;
            }
            let chosen = pin.candidates.get(cursor).copied();

            if chosen != previous {
                // Move this source's usage from the old slot to the new one, so
                // `select_slot` keeps balancing *live* load for later sources.
                let counted = self.inbound.get(&source).and_then(|p| p.counted);
                if let Some(old) = counted {
                    self.usage[old] -= 1;
                }
                let next_counted = chosen.and_then(|p| self.slot_of(p));
                if let Some(new) = next_counted {
                    self.usage[new] += 1;
                }
                if let Some(pin) = self.inbound.get_mut(&source) {
                    pin.cursor = cursor;
                    pin.counted = next_counted;
                }
            }
            return chosen;
        }

        // First pin this epoch. The primary is load-balanced across slots; the
        // rest of the live set follows it, in slot order, as this source's
        // alternates.
        let index = self.select_slot(rng)?;
        let primary = self.out[index]?;
        let mut candidates = Vec::with_capacity(self.out.len());
        candidates.push(primary);
        candidates.extend(self.out.iter().flatten().copied().filter(|p| *p != primary));
        self.inbound.insert(
            source,
            Pin {
                candidates,
                cursor: 0,
                counted: Some(index),
            },
        );
        self.usage[index] += 1;
        Some(primary)
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

    /// **W3c acceptance (§19.2 item 2).** A pinned source must never be routed
    /// to a peer that entered the map *after* it pinned.
    ///
    /// The transition this asserts across is the one where **nothing executes**:
    /// `update()` empties the pinned slot and backfills it, and the old
    /// `stem_for` then took the `self.out[index].is_some()` fast path and
    /// returned the new occupant. There was no selection call to hang a property
    /// on — the re-roll *was the absence of an operation* — which is why the
    /// assertion has to be about the peer that comes back, across the sequence,
    /// rather than about anything the map does.
    ///
    /// Both §19.1 C-1 triggers are represented: two `update` calls in sequence,
    /// as `plan_relay_with_refresh` (on `NoRoute`) and `dandelionpp_notify` (on
    /// send failure) would produce. A per-call property is escaped by exactly
    /// this composition.
    #[test]
    fn a_pinned_source_is_never_routed_to_a_post_pin_arrival() {
        let mut rng = SplitMix64::new(0x9C1);
        // Three peers, two stems: one spare, so a churned slot CAN be backfilled.
        // The inherited `gtest_dropped_connection_remapped` fixture has no spare
        // and therefore never constructs this state at all.
        let peers = ids(3);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);

        let source = Some(ids(1)[0]);
        let first = m.stem_for(source, &mut rng).expect("a stem is available");
        let frozen: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();
        assert_eq!(frozen.len(), 2, "fixture: two live stems at pin time");

        // Trigger 1 — the pinned peer churns; the spare backfills its slot.
        let survivors: Vec<ConnectionId> = peers.iter().copied().filter(|p| *p != first).collect();
        assert_eq!(
            m.update(survivors.clone(), &mut rng),
            StemSetChange::Changed
        );
        let arrival = m
            .slots()
            .iter()
            .flatten()
            .copied()
            .find(|p| !frozen.contains(p))
            .expect("fixture: the backfill brought in a peer that was not frozen");

        let after = m.stem_for(source, &mut rng).expect("the alternate is live");
        assert_ne!(
            after, arrival,
            "the source followed the backfill into its own slot — this is the \
             silent re-roll, and it is the whole of W3c"
        );
        assert!(
            frozen.contains(&after),
            "a pinned source may only be served by peers frozen at its pin"
        );

        // Trigger 2 — a second refresh in the same epoch. The composition is
        // where a per-call property leaks, so the assertion is repeated after it.
        assert_eq!(m.update(survivors, &mut rng), StemSetChange::Unchanged);
        let after_two = m.stem_for(source, &mut rng).expect("still routable");
        assert_eq!(
            after_two, after,
            "a no-op refresh must not move a pinned source"
        );
        assert!(
            frozen.contains(&after_two),
            "the frozen set must survive a SEQUENCE of updates, not just one"
        );
    }

    /// **W3c acceptance (§19.2 item 3) — the negative control, run in-process.**
    ///
    /// Replays the same sequence against the *pre-fix* mechanism (pin by slot
    /// index; follow whoever occupies it) and asserts it lands on the post-pin
    /// arrival. If this ever stops reproducing the defect, the control has gone
    /// blind and the test above is no longer discriminating anything.
    ///
    /// Modelled rather than reached through the real type, because the defect is
    /// the *absence* of the walk — there is no flag to turn off. The model is
    /// three lines and its fidelity is checked by the assertion it makes: the
    /// slot-follower lands on the arrival, which is precisely what
    /// `probe_silent_reroll` observed on the real map before the fix.
    #[test]
    fn negative_control_slot_pinning_follows_the_backfill() {
        let mut rng = SplitMix64::new(0x9C1);
        let peers = ids(3);
        let mut m = StemMap::new(peers.clone(), 2, &mut rng);

        let source = Some(ids(1)[0]);
        let first = m.stem_for(source, &mut rng).expect("a stem is available");
        let pinned_slot = m
            .slots()
            .iter()
            .position(|s| *s == Some(first))
            .expect("the pinned peer occupies a slot");
        let frozen: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();

        let survivors: Vec<ConnectionId> = peers.iter().copied().filter(|p| *p != first).collect();
        assert_eq!(m.update(survivors, &mut rng), StemSetChange::Changed);

        // The pre-fix read: whatever now occupies the pinned SLOT.
        let slot_follower = m.slots()[pinned_slot].expect("the slot was backfilled");
        assert!(
            !frozen.contains(&slot_follower),
            "control: the backfill must be a post-pin arrival, or this proves nothing"
        );
        assert_ne!(
            slot_follower,
            m.stem_for(source, &mut rng).expect("the alternate is live"),
            "control: slot-pinning and the frozen set MUST disagree here — if they \
             agree, the fixture stopped exercising the defect"
        );
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
    // survivor half of RP-2a's acceptance, DAEMON_RELAY_PRIVACY.md §16).
    //
    // The C++ suite (`tests/unit_tests/net.cpp`) stays as the migration oracle
    // through the RP-2a cut and until an explicit retire (here or RP-3). These
    // Rust cases are full outcome-invariant parity with that oracle so we can
    // prove the port matches **before** cutting over. Assertions are
    // RNG-agnostic (membership, counts, pin stability, even load, clone slot
    // identity) — never exact peer draws.
    //
    // `traits` is a C++ STL/move-only ABI test with no Rust analogue
    // (`StemMap` is `Clone` by design; the C++ wrapper deletes shallow copy).

    fn source_ids(n: u8, tag: u8) -> Vec<ConnectionId> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 16];
                b[0] = tag;
                b[1] = i;
                ConnectionId::from_bytes(b)
            })
            .collect()
    }

    /// Live stem slots are unique and drawn from `peers`.
    fn assert_live_slots_subset_of(m: &StemMap, peers: &[ConnectionId]) {
        let mut seen = Vec::new();
        for id in m.slots().iter().flatten() {
            assert!(
                peers.contains(id),
                "stem slot {id:?} is not in the peer set"
            );
            assert!(
                !seen.contains(id),
                "duplicate peer {id:?} across stem slots"
            );
            seen.push(*id);
        }
        assert_eq!(seen.len(), m.live_stems());
    }

    fn assert_clone_slots_equal(m: &StemMap) {
        let cloned = m.clone();
        assert_eq!(cloned.live_stems(), m.live_stems());
        assert_eq!(
            cloned.slots(),
            m.slots(),
            "clone must deep-copy slot layout"
        );
    }

    /// Per-stem source counts from a pin table (C++ `used[out]++` shape).
    fn usage_by_stem(
        mapping: &std::collections::BTreeMap<ConnectionId, ConnectionId>,
    ) -> std::collections::BTreeMap<ConnectionId, usize> {
        let mut used = std::collections::BTreeMap::new();
        for out in mapping.values() {
            *used.entry(*out).or_insert(0) += 1;
        }
        used
    }

    #[test]
    fn gtest_empty() {
        // C++ `dandelionpp_map.empty`: default map has empty span, size 0;
        // clone matches.
        let m = StemMap::empty();
        assert_eq!(m.live_stems(), 0);
        assert!(m.slots().is_empty());
        assert_eq!(m.width(), 0);
        assert_clone_slots_equal(&m);
    }

    #[test]
    fn gtest_zero_stems() {
        // C++ `dandelionpp_map.zero_stems`: stems=0 → empty span, get_stem is
        // always None, update is a no-op, clone stays empty.
        let mut rng = SplitMix64::new(0xD0);
        let peers = ids(6);
        let mut m = StemMap::new(peers.clone(), 0, &mut rng);
        assert_eq!(m.live_stems(), 0);
        assert!(m.slots().is_empty());
        assert_eq!(m.width(), 0);

        for p in &peers {
            assert_eq!(m.stem_for(Some(*p), &mut rng), None);
        }

        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
        assert_eq!(m.live_stems(), 0);
        assert!(m.slots().is_empty());

        for p in &peers {
            assert_eq!(m.stem_for(Some(*p), &mut rng), None);
        }
        assert_clone_slots_equal(&m);
    }

    #[test]
    fn gtest_dropped_connection() {
        // C++ `dandelionpp_map.dropped_connection` (net.cpp ~1833–1956):
        // 6 peers / 3 stems; nine inbound sources at 3-per-stem; drop one stem
        // and backfill from a spare; pins on the lost stem re-point to the
        // replacement in that slot; other pins stay; load stays even; clones
        // match slot layout throughout.
        let mut rng = SplitMix64::new(0xD1);
        let mut peers = ids(6);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!(m.live_stems(), 3);
        assert_eq!(m.slots().len(), 3);
        assert_live_slots_subset_of(&m, &peers);
        assert_clone_slots_equal(&m);

        assert_eq!(
            m.update(peers.clone(), &mut rng),
            StemSetChange::Unchanged,
            "re-presenting the full set must not re-arm"
        );
        assert_eq!(m.live_stems(), 3);
        assert_live_slots_subset_of(&m, &peers);

        let sources = source_ids(9, 100);
        let mut mapping = std::collections::BTreeMap::new();
        let mut inverse: std::collections::BTreeMap<ConnectionId, Vec<ConnectionId>> =
            std::collections::BTreeMap::new();
        for s in &sources {
            let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
            assert!(mapping.insert(*s, out).is_none());
            inverse.entry(out).or_default().push(*s);
        }
        let used = usage_by_stem(&mapping);
        assert_eq!(used.len(), 3);
        assert!(
            used.values().all(|c| *c == 3),
            "nine sources spread 3-per-stem: {used:?}"
        );
        for s in &sources {
            assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
        }

        // The peers live at pin time — every source's frozen set (§19.2). A
        // displaced source may be re-served only from here, never from a peer
        // that arrives afterwards.
        let frozen_at_pin: Vec<ConnectionId> = m.slots().iter().flatten().copied().collect();

        // Drop the middle stem slot's peer (C++: `*(++mapper.begin())`).
        let lost = m.slots()[1].expect("slot 1 live");
        peers.retain(|p| *p != lost);
        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 3, "the dropped slot was backfilled");
        assert_eq!(m.slots().len(), 3);
        for slot in m.slots().iter().flatten() {
            assert_ne!(*slot, lost, "the dropped peer was reused");
        }
        assert_live_slots_subset_of(&m, &peers);

        // **DELIBERATE DIVERGENCE FROM THE PORT (RP-2b, W3c).** The C++ this
        // twin was ported from re-pointed the sources on the lost stem at
        // whatever backfilled its slot, and the twin encoded that by rewriting
        // its own expectation: `mapping.insert(*s, newly_mapped)`. That single
        // line IS the induced-churn amplifier — a peer drawn *after* the churn
        // becoming the source's successor with no selection running (§19.2).
        // §19.3 measured it at 91.7 % exposure over 16 forced re-rolls.
        //
        // So the expectation is no longer rewritten. Displaced sources are
        // tracked instead, and asserted below to land inside their frozen set.
        let newly_mapped = m.slots()[1].expect("slot 1 backfilled");
        assert_ne!(newly_mapped, lost);
        let displaced: std::collections::BTreeSet<ConnectionId> =
            inverse.get(&lost).into_iter().flatten().copied().collect();
        assert!(
            !displaced.is_empty(),
            "fixture: the lost stem carried sources"
        );

        assert_clone_slots_equal(&m);
        assert_live_slots_subset_of(&m, &peers);

        // Pin table and even load hold after the churn.
        let mut used_after = std::collections::BTreeMap::new();
        for s in &sources {
            let out = m
                .stem_for(Some(*s), &mut rng)
                .expect("still routable after backfill");
            if displaced.contains(s) {
                assert!(
                    frozen_at_pin.contains(&out) && out != lost,
                    "a displaced source must re-point inside its frozen set"
                );
                assert_ne!(
                    out, newly_mapped,
                    "a displaced source must NOT follow the backfill — that is W3c"
                );
            } else {
                assert_eq!(out, mapping[s], "an unaffected pin must not move");
            }
            *used_after.entry(out).or_insert(0) += 1;
        }
        // **DIVERGENCE, and the property's cost.** The port re-balanced displaced
        // sources across all three stems, because it re-selected them by
        // least-used slot. Walking a frozen set cannot re-balance: a displaced
        // source goes to *its own* alternate, so the backfilled slot carries no
        // traffic until a source pins there for the first time. Load evens out
        // as new sources arrive and is re-drawn wholesale at the epoch boundary;
        // what is bought for it is that a churn cannot hand a source to a peer
        // chosen after the churn (§19.2).
        assert_eq!(
            used_after.values().sum::<usize>(),
            sources.len(),
            "every source is still routed exactly once"
        );
        assert!(
            used_after.keys().all(|p| frozen_at_pin.contains(p)),
            "post-churn traffic goes only to peers frozen at pin time: {used_after:?}"
        );
        assert_clone_slots_equal(&m);
    }

    #[test]
    fn gtest_dropped_connection_remapped() {
        // C++ `dandelionpp_map.dropped_connection_remapped` (net.cpp ~1958–2095):
        // 3 peers / 3 stems → drop one (nil hole, no spare) → re-pin 9+1
        // sources across 2 stems at 5 each → refill hole without moving existing
        // links → spread 8 more sources to 6-per-stem across 3 stems.
        let mut rng = SplitMix64::new(0xD2);
        let mut peers = ids(3);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!((m.live_stems(), m.slots().len()), (3, 3));
        assert_live_slots_subset_of(&m, &peers);

        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
        assert_eq!(m.live_stems(), 3);
        assert_live_slots_subset_of(&m, &peers);

        let mut sources = source_ids(9, 110);
        let mut mapping = std::collections::BTreeMap::new();
        let mut inverse: std::collections::BTreeMap<ConnectionId, Vec<ConnectionId>> =
            std::collections::BTreeMap::new();
        for s in &sources {
            let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
            assert!(mapping.insert(*s, out).is_none());
            inverse.entry(out).or_default().push(*s);
        }
        let used = usage_by_stem(&mapping);
        assert_eq!(used.len(), 3);
        assert!(
            used.values().all(|c| *c == 3),
            "initial 3-per-stem: {used:?}"
        );
        for s in &sources {
            assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
        }

        // Drop middle stem with no spare → nil hole in place.
        let lost = m.slots()[1].expect("slot 1 live");
        peers.retain(|p| *p != lost);
        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 2, "one slot is nil, not compacted");
        assert_eq!(m.slots().len(), 3, "span keeps the nil hole");
        assert_eq!(m.slots().iter().filter(|s| s.is_none()).count(), 1);
        if let Some(on_lost) = inverse.get(&lost) {
            for s in on_lost {
                // C++ marks these as nil expected until re-pin via get_stem.
                mapping.remove(s);
            }
        }

        // Remap the original 9 plus one new source across the two live stems.
        let extra = ConnectionId::from_bytes({
            let mut b = [0u8; 16];
            b[0] = 110;
            b[1] = 9;
            b
        });
        sources.push(extra);
        let mut used_two = std::collections::BTreeMap::new();
        for s in &sources {
            let out = m
                .stem_for(Some(*s), &mut rng)
                .expect("two live stems remain");
            match mapping.get(s) {
                Some(expected) => assert_eq!(
                    out, *expected,
                    "unaffected sources must keep their pin after the hole"
                ),
                None => {
                    mapping.insert(*s, out);
                }
            }
            *used_two.entry(out).or_insert(0) += 1;
        }
        // **DIVERGENCE (same cost as `gtest_dropped_connection`).** The port
        // re-balanced the displaced sources to 5-per-stem by re-selecting on
        // least-used; a frozen walk sends each to its own alternate instead, so
        // the split follows where sources originally pinned rather than an even
        // spread. The invariant that survives is that every source is routed
        // exactly once, to a live stem.
        assert_eq!(
            used_two.values().sum::<usize>(),
            sources.len(),
            "all ten sources routed exactly once"
        );
        assert!(
            used_two
                .keys()
                .all(|p| m.slots().iter().flatten().any(|q| q == p)),
            "every routed peer is a live stem: {used_two:?}"
        );

        // Refill the hole with a third peer; existing links must not move.
        let fresh = ConnectionId::from_bytes([210u8; 16]);
        peers.push(fresh);
        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 3);
        assert_eq!(m.slots().len(), 3);
        assert!(m.slots().iter().flatten().any(|s| *s == fresh));

        let mut used_after_refill = std::collections::BTreeMap::new();
        for s in &sources {
            let out = m
                .stem_for(Some(*s), &mut rng)
                .expect("still routable after refill");
            assert_eq!(
                out, mapping[s],
                "existing links stay put when a third peer fills the hole"
            );
            *used_after_refill.entry(out).or_insert(0) += 1;
        }
        assert_eq!(
            used_after_refill.len(),
            2,
            "refill must not steal existing pins onto the new stem"
        );
        assert_eq!(
            used_after_refill.values().sum::<usize>(),
            sources.len(),
            "still every source routed exactly once until new sources arrive"
        );

        // 8 more inbound sources → 18 total, even across 3 stems (6 each).
        let more = source_ids(8, 120);
        sources.extend(more);
        let mut used_three = std::collections::BTreeMap::new();
        for s in &sources {
            let out = m.stem_for(Some(*s), &mut rng).expect("three live stems");
            match mapping.get(s) {
                Some(expected) => assert_eq!(out, *expected),
                None => {
                    mapping.insert(*s, out);
                }
            }
            *used_three.entry(out).or_insert(0) += 1;
        }
        assert_eq!(sources.len(), 18);
        assert_eq!(used_three.len(), 3);
        assert!(
            used_three.values().all(|c| *c == 6),
            "18 sources across 3 stems at 6 each: {used_three:?}"
        );
    }

    #[test]
    fn gtest_dropped_all_connections() {
        // C++ `dandelionpp_map.dropped_all_connections` (net.cpp ~2097–2180):
        // 8 peers / 3 stems; 9 sources at 3-per-stem; drop everything (span
        // stays, live=0); first 7 sources re-pin to None; refill from a fresh
        // peer set; all 9 sources re-pin evenly (3-per-stem).
        let mut rng = SplitMix64::new(0xD3);
        let peers = ids(8);
        let mut m = StemMap::new(peers.clone(), 3, &mut rng);
        assert_eq!(m.live_stems(), 3);
        assert_eq!(m.slots().len(), 3);
        assert_live_slots_subset_of(&m, &peers);

        assert_eq!(m.update(peers.clone(), &mut rng), StemSetChange::Unchanged);
        assert_eq!(m.live_stems(), 3);
        assert_live_slots_subset_of(&m, &peers);

        let sources = source_ids(9, 130);
        let mut mapping = std::collections::BTreeMap::new();
        for s in &sources {
            let out = m.stem_for(Some(*s), &mut rng).expect("a stem is available");
            assert!(mapping.insert(*s, out).is_none());
        }
        let used = usage_by_stem(&mapping);
        assert_eq!(used.len(), 3);
        assert!(
            used.values().all(|c| *c == 3),
            "initial 3-per-stem: {used:?}"
        );
        for s in &sources {
            assert_eq!(m.stem_for(Some(*s), &mut rng), Some(mapping[s]));
        }

        assert_eq!(m.update(Vec::new(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 0, "no live stem remains");
        assert_eq!(m.slots().len(), 3, "the slots are nil, not removed");

        // C++ remaps only the first 7 while empty; the last two stay pinned to
        // dead slot indices until the refill (then resolve to the new peers in
        // those slots without a fresh select).
        for s in sources.iter().take(7) {
            assert_eq!(
                m.stem_for(Some(*s), &mut rng),
                None,
                "no routable stem must surface as None, not a stale peer"
            );
        }

        // Fresh peer set (C++: 30 new uuids); only stem-width matters for the
        // even-load assertion after re-pin.
        let refill = ids(30);
        assert_eq!(m.update(refill.clone(), &mut rng), StemSetChange::Changed);
        assert_eq!(m.live_stems(), 3);
        assert_live_slots_subset_of(&m, &refill);

        // **THE DIVERGENCE THAT COSTS SOMETHING, named plainly (RP-2b, W3c).**
        // Every peer this map ever held is gone, so every already-pinned source
        // has an exhausted frozen set and now **fluffs** where the port re-pinned
        // it onto the fresh peers. That is the availability half of the trade,
        // and it was chosen with a measurement rather than a preference: §19.3's
        // third arm allowed a fresh pin on exhaustion and its exposure tracked
        // the *unfixed* baseline (0.75 at k=8 against 0.17), because at
        // `STEMS = 2` a full sweep costs an adversary two churns and hands back
        // two fresh draws. An escape hatch here returns the whole amplifier, so
        // there is no partial version of this property to take.
        //
        // The cost is bounded in time: `rebuild_stems` re-draws every pin at the
        // epoch boundary, so an affected source fluffs for at most the remainder
        // of the epoch. How often honest churn reaches total turnover is the
        // ambient-rate measurement §12.11 still owes.
        for s in &sources {
            assert_eq!(
                m.stem_for(Some(*s), &mut rng),
                None,
                "a source whose entire frozen set churned out must fluff, not \
                 re-pin onto peers that arrived after it pinned"
            );
        }
        // A source that had never pinned still routes: the freeze is per-source,
        // not a frozen map.
        let newcomer = ConnectionId::from_bytes([250u8; 16]);
        let out = m
            .stem_for(Some(newcomer), &mut rng)
            .expect("an unpinned source still routes through the refilled map");
        assert!(
            refill.contains(&out),
            "and it routes to a live, post-refill peer"
        );
        // The port's closing assertion here was "9 sources re-pin evenly across
        // 3 new stems". There are no re-pins to spread now — see above — so what
        // remains to check is that the refilled map is healthy for sources that
        // pin into it, which the newcomer above establishes.
        assert_eq!(m.live_stems(), 3, "the refilled map is fully live");
    }
}
