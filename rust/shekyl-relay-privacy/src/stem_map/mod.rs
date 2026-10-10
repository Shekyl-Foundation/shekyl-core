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
//! the first deliberate divergence from the C++ port.
//!
//! **The reserved slot (`DAEMON_RELAY_PRIVACY.md` §95.3, §98).** The second
//! divergence. [`StemMap<ReservedSlot>`] keeps slot 0 for a class of sessions
//! the caller names at construction and at every merge. [`StemMap<UniformSlots>`]
//! is the paper's map. The mode is the type: [`StemMap::update`] exists only
//! on the uniform map, and [`StemMap::update_with_reserved`] and
//! [`StemMap::route_local_origin`] exist only on the reserved map, so the
//! wrong merge does not compile. Both merges are one function; slot 0's pool
//! is the only difference. The map never learns what the class is. The relay
//! names the address-hiding outbound sessions and routes its own transactions
//! through [`StemMap::route_local_origin`], which fills slot 0 before it
//! walks the pin. Everything else is intended to match the C++. Anything else
//! that differs is a bug in this module, not an improvement.

use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::rng::{bounded_uniform, RelayRng};

/// Slot 0 fills from the same live set as every other slot.
///
/// The type parameter of [`StemMap::new`] and [`StemMap::update`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UniformSlots;

/// Slot 0 is reserved for the class the caller names at each merge.
///
/// The type parameter of [`StemMap::new_with_reserved_slot`],
/// [`StemMap::update_with_reserved`], and [`StemMap::route_local_origin`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReservedSlot;

/// Index of the slot [`ReservedSlot`] keeps for the caller's class.
///
/// The other slots start at the next index. A uniform map has no such slot;
/// its backfill starts at the first index of the range.
const RESERVED_SLOT_INDEX: usize = 0;

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
pub struct StemMap<Mode = UniformSlots> {
    /// Stem slots. `None` is a slot whose peer disconnected.
    out: Vec<Option<ConnectionId>>,
    /// Source → its frozen routing decision. See [`SourceId`].
    inbound: BTreeMap<SourceId, Pin>,
    /// Per-slot count of sources currently routed through it. Length is the
    /// configured stem count, which is `>= out.len()` at all times.
    usage: Vec<usize>,
    /// [`UniformSlots`] or [`ReservedSlot`]. Carries no data: the impl blocks
    /// are what make the wrong merge uncallable.
    _mode: PhantomData<Mode>,
}

impl<Mode> StemMap<Mode> {
    fn from_parts(out: Vec<Option<ConnectionId>>, usage: Vec<usize>) -> Self {
        Self {
            out,
            inbound: BTreeMap::new(),
            usage,
            _mode: PhantomData,
        }
    }
}

impl StemMap<UniformSlots> {
    /// An empty map that can route nothing. Equivalent to the C++
    /// default-constructed `connection_map`.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_parts(Vec::new(), Vec::new())
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

        Self::from_parts(
            out_connections.into_iter().map(Some).collect(),
            vec![0; stems],
        )
    }

    /// Merge `current` into a uniform map.
    ///
    /// Slots whose peer has gone are emptied and backfilled from peers not
    /// already in use; empty stem slots are filled if candidates remain.
    /// Returns [`StemSetChange::Changed`] when the live stem set changed,
    /// which is the signal the caller uses to re-point channels. A reserved
    /// map has no `update`: that call does not compile.
    pub fn update<R: RelayRng + ?Sized>(
        &mut self,
        current: Vec<ConnectionId>,
        rng: &mut R,
    ) -> StemSetChange {
        self.merge_live(None, current, rng)
    }
}

impl<Mode> StemMap<Mode> {
    /// One merge. `class` is slot 0's pool; `None` means slot 0 draws from
    /// `rest` with every other slot. `Some` fills an empty slot 0 from that
    /// class only — the local pin's next live candidate, else a uniform draw,
    /// else the slot stays empty — and the other slots from `class` plus `rest`.
    ///
    /// Peers are never moved between slots. A class member already occupying
    /// another slot is not an unslotted candidate, so the slot-0 fill passes
    /// over it.
    ///
    /// Returns [`StemSetChange::Changed`] when a live peer left or a slot was
    /// filled. An empty slot that stays empty still reports `Changed`, matching
    /// the C++ `connection_map::update` re-mark of a nil slot.
    fn merge_live<R: RelayRng + ?Sized>(
        &mut self,
        class: Option<Vec<ConnectionId>>,
        rest: Vec<ConnectionId>,
        rng: &mut R,
    ) -> StemSetChange {
        if self.usage.is_empty() {
            return StemSetChange::Unchanged;
        }
        let mut class = class;
        if let Some(pool) = class.as_mut() {
            pool.sort_unstable();
            pool.dedup();
        }
        let mut candidates = class.clone().unwrap_or_default();
        candidates.extend(rest);
        candidates.sort_unstable();
        candidates.dedup();

        let mut replaced = false;
        for slot in &mut self.out {
            match slot {
                Some(id) => {
                    if let Ok(pos) = candidates.binary_search(id) {
                        // Still connected; take it out of the pool so it cannot
                        // also backfill another slot.
                        candidates.remove(pos);
                        if let Some(pool) = class.as_mut() {
                            if let Ok(pos) = pool.binary_search(id) {
                                pool.remove(pos);
                            }
                        }
                    } else {
                        *slot = None;
                        replaced = true;
                    }
                }
                // A slot left empty by an earlier merge still needs backfilling.
                // The C++ `connection_map::update` re-marks nil slots (setting
                // `replace = true`); mirror that, so the early-return below does
                // not skip a fillable empty slot.
                None => replaced = true,
            }
        }
        // A reserved slot exists even when nothing has filled it. A uniform
        // map grows from an empty `out` inside the loop below.
        if class.is_some() && self.out.is_empty() {
            self.out.push(None);
            replaced = true;
        }

        if !replaced && self.out.len() == self.usage.len() {
            return StemSetChange::Unchanged;
        }

        let existing_outs = self.out.len();
        let first_shared = if class.is_some() {
            RESERVED_SLOT_INDEX + 1
        } else {
            0
        };
        if let Some(pool) = class.as_mut() {
            if self.out[RESERVED_SLOT_INDEX].is_none() {
                let chosen = self
                    .local_pin_next_among(pool)
                    .or_else(|| match pool.len() {
                        0 => None,
                        n => Some(pool[usize_from_u64(bounded_uniform(rng, (n - 1) as u64))]),
                    });
                if let Some(peer) = chosen {
                    if let Ok(pos) = pool.binary_search(&peer) {
                        pool.remove(pos);
                    }
                    if let Ok(pos) = candidates.binary_search(&peer) {
                        candidates.remove(pos);
                    }
                    self.out[RESERVED_SLOT_INDEX] = Some(peer);
                }
            }
        }
        for i in first_shared..self.usage.len() {
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

    /// The local pin's next candidate, from its cursor, that is in `among`
    /// (sorted). `None` when the local source has no pin or none of its
    /// remaining candidates is there.
    fn local_pin_next_among(&self, among: &[ConnectionId]) -> Option<ConnectionId> {
        let pin = self.inbound.get(&None)?;
        pin.candidates[pin.cursor..]
            .iter()
            .copied()
            .find(|candidate| among.binary_search(candidate).is_ok())
    }

    /// Whether `source` has pinned this epoch.
    #[must_use]
    pub fn is_pinned(&self, source: SourceId) -> bool {
        self.inbound.contains_key(&source)
    }

    /// Pin `source` over `candidates`, frozen as given, and return the
    /// primary. The first pin over a **supplied** list
    /// (`DAEMON_RELAY_PRIVACY.md` §98.3): `candidates[0]` is the primary and
    /// must occupy a slot now; the rest are the alternates the walk falls
    /// back to, in order, and need not be slotted — the relay supplies the
    /// local source's alternates from sessions the map has not slotted
    /// (D-PR1-1 (c′)), and [`Self::update_with_reserved`] moves the next live
    /// one into slot 0 when the primary drops.
    ///
    /// Returns `None` **without pinning** when the list is empty or its head
    /// is not in a slot: an origination that finds nothing to pin leaves the
    /// next one free to pin. A source already pinned is walked instead and
    /// `candidates` is ignored, so the call is total over the epoch.
    pub fn pin_over(
        &mut self,
        source: SourceId,
        candidates: Vec<ConnectionId>,
    ) -> Option<ConnectionId> {
        if self.inbound.contains_key(&source) {
            return self.resolve_pin(source);
        }
        let primary = *candidates.first()?;
        let index = self.slot_of(primary)?;
        debug_assert!(
            candidates
                .iter()
                .enumerate()
                .all(|(i, c)| !candidates[..i].contains(c)),
            "pin candidates must be distinct"
        );
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

    /// The stem slots in index order, `None` for an emptied slot — or, in a
    /// map with a reserved slot, for a slot 0 nothing has filled yet.
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

    /// [`Self::stem_for`] restricted to `allowed`.
    ///
    /// The first pin's frozen set is the allowed peers that occupy a slot
    /// now, not every live slot. A later call walks that set. A peer that
    /// was never allowed is not a candidate, so hop 0 cannot land on a
    /// clearnet slot or on an anonymity peer the map did not slot.
    pub fn stem_for_among<R: RelayRng + ?Sized>(
        &mut self,
        source: SourceId,
        allowed: &[ConnectionId],
        rng: &mut R,
    ) -> Option<ConnectionId> {
        if self.inbound.contains_key(&source) {
            let chosen = self.resolve_pin(source)?;
            allowed.contains(&chosen).then_some(chosen)
        } else {
            self.first_pin_among(source, allowed, rng)
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

    /// [`Self::first_pin`] whose primary and alternates are `allowed` peers
    /// that currently occupy a slot.
    fn first_pin_among<R: RelayRng + ?Sized>(
        &mut self,
        source: SourceId,
        allowed: &[ConnectionId],
        rng: &mut R,
    ) -> Option<ConnectionId> {
        let index = self.select_slot_among(allowed, rng)?;
        let primary = self.out[index.get()]?;
        if !allowed.contains(&primary) {
            return None;
        }
        let mut candidates = Vec::with_capacity(allowed.len());
        candidates.push(primary);
        candidates.extend(
            self.out
                .iter()
                .flatten()
                .copied()
                .filter(|peer| *peer != primary && allowed.contains(peer)),
        );
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

    /// [`Self::select_slot`] over slots whose peer is in `allowed`.
    fn select_slot_among<R: RelayRng + ?Sized>(
        &self,
        allowed: &[ConnectionId],
        rng: &mut R,
    ) -> Option<SlotIndex> {
        let mut lowest = usize::MAX;
        let mut choices: Vec<SlotIndex> = Vec::with_capacity(self.out.len());
        for (i, slot) in self.out.iter().enumerate() {
            let Some(peer) = *slot else {
                continue;
            };
            if !allowed.contains(&peer) {
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

impl StemMap<ReservedSlot> {
    /// Build a map whose slot 0 is reserved for `reserved`.
    ///
    /// The caller names the class here and again at every merge
    /// ([`Self::update_with_reserved`]). The map never learns what the class
    /// is; the relay names the address-hiding outbound sessions
    /// (`DAEMON_RELAY_PRIVACY.md` §98.3).
    ///
    /// Slot 0 is drawn uniformly from `reserved`, and is empty when
    /// `reserved` is empty (D-PR1-2 (i): it stays empty until a merge fills
    /// it). The other slots are [`StemMap::new`] over `rest` plus the reserved
    /// sessions not placed in slot 0, of width `stems − 1`. With `rest` empty
    /// this is the paper's draw over the class (§98.1). `stems == 0` routes
    /// nothing.
    ///
    /// `reserved` and `rest` are a partition. A session in both is a caller
    /// bug.
    pub fn new_with_reserved_slot<R: RelayRng + ?Sized>(
        mut reserved: Vec<ConnectionId>,
        rest: Vec<ConnectionId>,
        stems: usize,
        rng: &mut R,
    ) -> Self {
        assert_partition(&reserved, &rest);
        if stems == 0 {
            return Self::from_parts(Vec::new(), Vec::new());
        }
        let slot0 = if reserved.is_empty() {
            None
        } else {
            let pick = usize_from_u64(bounded_uniform(rng, (reserved.len() - 1) as u64));
            Some(reserved.swap_remove(pick))
        };
        let mut remaining = rest;
        remaining.extend(reserved);
        let others = StemMap::new(remaining, stems - 1, rng).out;
        let mut out = Vec::with_capacity(1 + others.len());
        out.push(slot0);
        out.extend(others);
        Self::from_parts(out, vec![0; stems])
    }

    /// Merge `reserved` into slot 0 and `reserved` plus `rest` into the other
    /// slots. One function serves this and [`StemMap::update`]; slot 0's pool
    /// is the only difference.
    ///
    /// An empty slot 0 is filled from the class only: the local pin's next
    /// live candidate, else a uniform draw from the class members not already
    /// slotted, else the slot stays empty. Peers are never moved between
    /// slots. The [`StemSetChange`] predicate matches [`StemMap::update`].
    pub fn update_with_reserved<R: RelayRng + ?Sized>(
        &mut self,
        reserved: Vec<ConnectionId>,
        rest: Vec<ConnectionId>,
        rng: &mut R,
    ) -> StemSetChange {
        assert_partition(&reserved, &rest);
        self.merge_live(Some(reserved), rest, rng)
    }

    /// The local origin's one route. The fill runs before the pin walk, and
    /// the relay cannot call them in the other order.
    ///
    /// The merge runs only when slot 0's peer is in neither live list, or
    /// slot 0 is empty and a class member occupies no slot. In the stranded
    /// state — slot 0 empty, every class member already slotted — the merge
    /// does not run, so an empty later slot is not backfilled as a side
    /// effect of originating.
    ///
    /// Unpinned: the primary is slot 0's peer when the class contains it,
    /// otherwise a class member occupying a later slot (uniform when several
    /// do). Then `stems − 1` alternates, drawn uniformly from the other class
    /// members live now. Pinned: the walk, and a chosen peer the class does
    /// not contain is not a route. `None` pins nothing.
    #[must_use]
    pub fn route_local_origin<R: RelayRng + ?Sized>(
        &mut self,
        reserved: &[ConnectionId],
        rest: &[ConnectionId],
        rng: &mut R,
    ) -> Option<ConnectionId> {
        assert_partition(reserved, rest);
        let pinned = self.is_pinned(None);
        if self.slot_zero_needs_fill(reserved, rest) {
            let _change = self.merge_live(Some(reserved.to_vec()), rest.to_vec(), rng);
        }
        if pinned {
            let chosen = self.resolve_pin(None)?;
            reserved.contains(&chosen).then_some(chosen)
        } else {
            let candidates = self.local_origin_candidates(reserved, rng);
            self.pin_over(None, candidates)
        }
    }

    /// Slot 0's peer has left the live partition, or the slot is empty and a
    /// class member is still unslotted.
    fn slot_zero_needs_fill(&self, class: &[ConnectionId], rest: &[ConnectionId]) -> bool {
        match self.out.get(RESERVED_SLOT_INDEX).copied().flatten() {
            Some(peer) => !class.contains(&peer) && !rest.contains(&peer),
            None => class.iter().any(|peer| self.slot_of(*peer).is_none()),
        }
    }

    /// The local source's pin: primary, then `stems − 1` alternates drawn by
    /// the same partial Fisher-Yates as [`StemMap::new`].
    ///
    /// Slot 0's peer is the primary only when the class contains it. A peer
    /// sitting there from outside the class is not an origin hop; the draw
    /// falls through to class members in later slots. Empty when no slot
    /// holds a class member, so [`StemMap::pin_over`] pins nothing.
    fn local_origin_candidates<R: RelayRng + ?Sized>(
        &self,
        class_live: &[ConnectionId],
        rng: &mut R,
    ) -> Vec<ConnectionId> {
        let primary = match self.out.get(RESERVED_SLOT_INDEX).copied().flatten() {
            Some(peer) if class_live.contains(&peer) => peer,
            _ => {
                let slotted: Vec<ConnectionId> = self
                    .out
                    .iter()
                    .skip(RESERVED_SLOT_INDEX + 1)
                    .flatten()
                    .copied()
                    .filter(|peer| class_live.contains(peer))
                    .collect();
                match slotted.len() {
                    0 => return Vec::new(),
                    1 => slotted[0],
                    n => slotted[usize_from_u64(bounded_uniform(rng, (n - 1) as u64))],
                }
            }
        };
        let mut alternates: Vec<ConnectionId> = class_live
            .iter()
            .copied()
            .filter(|peer| *peer != primary)
            .collect();
        let take = self.usage.len().saturating_sub(1).min(alternates.len());
        for i in 0..take {
            let remaining = alternates.len() - i;
            let pick = i + usize_from_u64(bounded_uniform(rng, (remaining - 1) as u64));
            alternates.swap(i, pick);
        }
        alternates.truncate(take);
        let mut candidates = Vec::with_capacity(1 + take);
        candidates.push(primary);
        candidates.extend(alternates);
        candidates
    }
}

/// `class` and `rest` name disjoint sessions. Overlap would let one peer
/// fill slot 0 and another slot in the same merge.
fn assert_partition(class: &[ConnectionId], rest: &[ConnectionId]) {
    assert!(
        rest.iter().all(|peer| !class.contains(peer)),
        "a session is in both the reserved class and the rest"
    );
}

/// Narrow a draw that is already bounded by a `usize`-derived range.
///
/// Every call site passes a bound computed from a container length, so the
/// value round-trips exactly on any target where `usize` is at least 32 bits.
fn usize_from_u64(v: u64) -> usize {
    usize::try_from(v).expect("draw was bounded by a usize-derived range")
}

#[cfg(test)]
mod reserved_tests;
#[cfg(test)]
mod tests;
