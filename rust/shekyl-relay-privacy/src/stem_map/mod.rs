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
//! **W3c (`DAEMON_RELAY_PRIVACY.md` §19.2).** A source is pinned to the set of
//! peers live at its first pin, not to a slot index. Mid-epoch churn walks that
//! frozen set and never hands the source a peer drawn after it pinned. That is
//! the only deliberate divergence from the C++ port; everything else is
//! intended to match. Anything else that differs is a bug in this module, not
//! an improvement.

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

/// A transaction source identity for stem routing.
///
/// `None` means the transaction originated on this node — the same role
/// `boost::uuids::nil_uuid()` plays as a map key in the C++ `connection_map`.
/// Typed so the map key is not a bare `Option` at every call site.
pub type SourceId = Option<ConnectionId>;

/// Index into [`StemMap`]'s stem-slot vectors (`out` / `usage`).
///
/// Distinct from a walk cursor into a [`Pin`]'s candidate list so the two
/// integers cannot be silently swapped at the type level.
///
/// **Public since 2026-08-17** because the covert carrier binds channel `i` to
/// stem slot `i` (`DAEMON_RELAY_PRIVACY.md` §20.3), so a caller outside this
/// crate must be able to name the slot a plan chose. It is exported as a
/// newtype rather than a bare `usize` precisely to keep the property above:
/// at a crate boundary a raw index is exactly what gets swapped with a cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotIndex(usize);

impl SlotIndex {
    /// The slot's index, which is also its covert channel (§20.3).
    #[inline]
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
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
    /// Peers this source may be routed to, in walk order. Frozen at first pin;
    /// never appended to after construction.
    candidates: Vec<ConnectionId>,
    /// How far into `candidates` this source has walked. Only ever advances:
    /// once `resolve_pin` observes a candidate missing from the live map, the
    /// cursor steps past it and that peer never serves this source again —
    /// even if it reconnects later. A reconnect of a not-yet-walked-past peer
    /// may re-serve (same frozen identity), but load accounting always re-syncs
    /// against the slot that peer currently occupies.
    cursor: usize,
    /// The slot this source is currently counted against in `StemMap::usage`.
    ///
    /// Stored rather than re-derived only when the candidate is live: when the
    /// candidate has *left* the map, derivation yields `None` and would skip
    /// the decrement — the phantom-count class
    /// `losing_all_peers_falls_back_to_no_stem` caught. On every resolve we
    /// re-sync this against `slot_of(chosen)` so a peer that left and re-entered
    /// a *different* slot cannot leave usage pointing at the old index.
    counted: Option<SlotIndex>,
}

/// Maps transaction sources to stem peers for one Dandelion++ epoch.
///
/// The map is rebuilt from scratch at each epoch boundary (that is the point
/// of an epoch); [`StemMap::update`] handles churn *within* an epoch as peers
/// come and go. Per-source routing decisions are [`Pin`]s: frozen candidate
/// sets that never grow mid-epoch (W3c / §19.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StemMap {
    /// Stem slots. `None` is a slot whose peer disconnected.
    out: Vec<Option<ConnectionId>>,
    /// Source → its frozen routing decision. See [`SourceId`].
    inbound: BTreeMap<SourceId, Pin>,
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
    #[must_use]
    pub fn slot_of(&self, peer: ConnectionId) -> Option<SlotIndex> {
        self.out
            .iter()
            .position(|s| *s == Some(peer))
            .map(SlotIndex)
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
        source: SourceId,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        if self.inbound.contains_key(&source) {
            self.resolve_pin(source)
        } else {
            self.first_pin(source, rng)
        }
    }

    /// Walk an existing [`Pin`]: advance past candidates that have left the
    /// map, re-sync usage against the slot the chosen peer currently occupies,
    /// and return that peer (or `None` if the frozen set is exhausted).
    fn resolve_pin(&mut self, source: SourceId) -> Option<ConnectionId> {
        let pin = self
            .inbound
            .get(&source)
            .expect("resolve_pin is only called for a pinned source");

        // Walk forward over candidates missing from the live map. The set never
        // grows, so this can only narrow the source's options. Once a candidate
        // is observed absent, the cursor steps past it permanently.
        let mut cursor = pin.cursor;
        while cursor < pin.candidates.len() && self.slot_of(pin.candidates[cursor]).is_none() {
            cursor += 1;
        }
        let chosen = pin.candidates.get(cursor).copied();
        let next_counted = chosen.and_then(|p| self.slot_of(p));
        let prev_counted = pin.counted;

        // Always re-sync cursor + usage when either the walk position or the
        // occupied slot changed. Comparing only peer identity would miss a
        // frozen peer that left and re-entered a different slot index between
        // calls — leaving a phantom count on the old index.
        if cursor != pin.cursor || next_counted != prev_counted {
            if let Some(old) = prev_counted {
                debug_assert!(
                    self.usage[old.get()] > 0,
                    "usage underflow releasing slot {}",
                    old.get()
                );
                self.usage[old.get()] -= 1;
            }
            if let Some(new) = next_counted {
                self.usage[new.get()] += 1;
            }
            let pin = self
                .inbound
                .get_mut(&source)
                .expect("pin still present for source under resolve");
            pin.cursor = cursor;
            pin.counted = next_counted;
        }

        chosen
    }

    /// First pin this epoch. The primary is load-balanced across slots; the
    /// rest of the live set follows it, in slot order, as this source's
    /// alternates.
    fn first_pin<R: RelayRng + ?Sized>(
        &mut self,
        source: SourceId,
        rng: &mut R,
    ) -> Option<ConnectionId> {
        let index = self.select_slot(rng)?;
        let primary = self.out[index.get()]?;
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
        self.usage[index.get()] += 1;
        Some(primary)
    }

    /// Pick the live slot with the fewest sources routed through it, breaking
    /// ties uniformly at random.
    ///
    /// The balancing matters: a slot that accumulates sources becomes a better
    /// guess for an adversary correlating stem traffic, and the random
    /// tiebreak is what stops the first slot from winning every tie.
    fn select_slot<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Option<SlotIndex> {
        let mut lowest = usize::MAX;
        // Stem width is 1 or 2 in practice; a Vec here is not a hot path.
        let mut choices: Vec<SlotIndex> = Vec::with_capacity(self.out.len());
        for (i, slot) in self.out.iter().enumerate() {
            if slot.is_none() {
                continue;
            }
            let used = self.usage[i];
            if used < lowest {
                lowest = used;
                choices.clear();
                choices.push(SlotIndex(i));
            } else if used == lowest {
                choices.push(SlotIndex(i));
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
mod tests;
