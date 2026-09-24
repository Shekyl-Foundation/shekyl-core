// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §3.4; `SPL-Q3`,
//! `SPL-Q9` RULED 2026-09-24).
//!
//! The C++ `txpool_tx_meta_t` (`src/blockchain_db/blockchain_db.h:218–348`)
//! is a 192-byte packed struct: two hashes, six `u64`s, three flag bytes, a
//! bit-field, a cache hash and 44 bytes of padding. This is its
//! re-specification — **same semantics, not byte-compatible** — and the
//! re-specification is where five findings land:
//!
//! - **SPL-4 / SPL-14.** The C++ relay class is four bits summed by a
//!   decoder whose `default:` arm returns `fluff` — the broadcast phase.
//!   Here the class is [`RelayPhase`], an enum whose decoder has no default
//!   arm; an unknown tag is a codec error, never a value.
//! - **SPL-5.** `last_relayed_time` meant `u64::MAX` ("never"), a future
//!   embargo deadline (`stem`) or a past relay time, depending on a bit
//!   elsewhere in the record. Each [`RelayPhase`] variant carries the clock
//!   word that phase means; the overload dissolves because no single field
//!   means three things.
//! - **SPL-6.** `pruned`, `do_not_relay` and `padding` are not carried
//!   (unreachable by ruling; rule 60).
//! - **SPL-10.** `fcmp_verified` + `fcmp_verification_hash` are one
//!   [`Option`].
//! - **SPL-18.** `DAEMON_RELAY_PRIVACY.md` §92.4 unbundled `relay_method::local`
//!   into provenance (permanent), re-broadcast responsibility (disarmed by
//!   observation) and a class. They are three fields here — [`Origin`],
//!   [`Responsibility`], [`RelayPhase`] — with three lifetimes, and the
//!   store enforces the seams: [`PoolBatch::update`](crate::pool::PoolBatch::update)
//!   refuses a changed origin, and the codec refuses a record whose fields
//!   disagree (§"Construction checks" below).
//!
//! # Construction checks (`SPL-Q9`)
//!
//! [`PoolRecord::validate`] is the one place the cross-field rules are
//! stated; the codec applies it at decode and the store at write, so a
//! stored row cannot say what a fresh one cannot:
//!
//! - [`RelayPhase::Held`] only with [`Origin::Originated`]; a held entry is
//!   one this node originated and has not yet made public.
//! - [`RelayPhase::Stem`] only with [`Origin::Arrived`]; an originated
//!   entry never walks to `Stem` (the pin, §92.4).
//! - [`Responsibility`] only with [`Origin::Originated`] — **`Arrived` plus a
//!   responsibility is refused**; an arrived transaction cannot believe it
//!   owes a broadcast. Kept as a *separate field*, deliberately not nested
//!   inside `Originated`: `Origin` is permanent and refused-on-change while
//!   `Responsibility` transitions `Armed → Disarmed`, and nesting would make
//!   the permanent field mutable and the update refusal unenforceable. The
//!   unrepresentability nesting would buy is bought by the refusal instead.
//!
//! # The seam
//!
//! [`PoolRecord::relay_method`] derives the FFI byte
//! ([`RelayMethod`]) from `(origin, phase)` where C++ still speaks it, and
//! [`PoolRecord::matches`] is the C++ `matches_category` over that byte. The
//! record persists neither.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{
    BlockHash, BlockHeight, FcmpVerificationHash, NetZone, RelayCategory, RelayMethod, UnixSeconds,
};
use shekyl_units::AtomicUnits;

use super::reader::Reader;

/// Where a pool entry came from — §92.4's first clause, *provenance is
/// permanent*. Written once by `insert`; `update` refuses a record whose
/// origin differs from the stored one ([`PoolCannot::OriginChanged`](crate::store::PoolCannot::OriginChanged)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// This node originated the transaction (the C++ `is_local`). The only
    /// origin that carries a [`Responsibility`] and the only one that can
    /// be [`RelayPhase::Held`].
    Originated,
    /// The transaction arrived from a peer over `zone`
    /// (the C++ `origin_zone`; [`NetZone::Invalid`] is "origin unknown").
    Arrived {
        /// The zone the bytes arrived over. First arrival wins; a later
        /// re-delivery over another zone does not revise it.
        zone: NetZone,
    },
}

/// How the entry is travelling now — the ratchet's domain, with the clock
/// word each phase means (SPL-5). The transitions are
/// [`RelayPhase::upgrade`]'s, and the pin (§92.4) is a rule over
/// [`Origin`] there, not a special case elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayPhase {
    /// Originated here and not yet public (the C++ `local`). `last_attempt`
    /// is the last time this node re-broadcast it on its private request
    /// path, or `None` if it never has — an entry admitted through the
    /// engine's attested path starts at `Some(receive_time)` so the
    /// periodic fallback is eligible; one admitted for dispatch starts at
    /// `None` (`tx_pool.cpp:470`, `:575–589`).
    Held {
        /// Last private re-broadcast, if any.
        last_attempt: Option<UnixSeconds>,
    },
    /// In Dandelion++ stem. `next_attempt` is the **future** instant the
    /// embargo fires — the deadline `set_relayed` draws (`tx_pool.cpp:1298`)
    /// and the relay pass re-draws when it passes (`:1227`).
    Stem {
        /// The embargo deadline.
        next_attempt: UnixSeconds,
    },
    /// Fluffed — public. `last_relayed` is the last broadcast, or `None`
    /// if this node has not relayed it since it became public.
    Fluff {
        /// Last broadcast, if any.
        last_relayed: Option<UnixSeconds>,
    },
    /// Arrived in a block (a pop's re-add, or an alt block's supplement) —
    /// public, backed by proof of work.
    Block {
        /// Last broadcast, if any.
        last_relayed: Option<UnixSeconds>,
    },
}

impl RelayPhase {
    /// The ratchet's order, `Held < Stem < Fluff < Block` — the C++
    /// `none < local < stem < fluff < block` with `none` gone
    /// (`blockchain_db.cpp:210–222`).
    const fn rank(self) -> u8 {
        match self {
            Self::Held { .. } => 0,
            Self::Stem { .. } => 1,
            Self::Fluff { .. } => 2,
            Self::Block { .. } => 3,
        }
    }

    /// Whether `next` may follow `self` for an entry of `origin` — the
    /// ratchet **and the pin** (§92.4) as one rule:
    ///
    /// - the phase never goes backwards, and a re-arrival at the same phase
    ///   is not a transition (the caller keeps its clock);
    /// - an [`Origin::Originated`] entry **never** walks to `Stem` or
    ///   `Fluff` — a peer's assertion cannot move it — and yields only to
    ///   `Block`, which is backed by proof of work;
    /// - an [`Origin::Arrived`] entry is never `Held`.
    ///
    /// Returns the phase to store, or `None` if the transition is refused.
    /// Which arrival *class* a pool maps to which phase is the pool's
    /// decision (E5); this is the type saying what it can hold.
    #[must_use]
    pub const fn upgrade(self, origin: Origin, next: Self) -> Option<Self> {
        if !next.legal_for(origin) {
            return None;
        }
        if next.rank() <= self.rank() {
            return None;
        }
        if matches!(origin, Origin::Originated) && !matches!(next, Self::Block { .. }) {
            return None;
        }
        Some(next)
    }

    /// The construction rule on one field pair: `Held` only with
    /// `Originated`, `Stem` only with `Arrived`, the public phases with
    /// either.
    const fn legal_for(self, origin: Origin) -> bool {
        match self {
            Self::Held { .. } => matches!(origin, Origin::Originated),
            Self::Stem { .. } => matches!(origin, Origin::Arrived { .. }),
            Self::Fluff { .. } | Self::Block { .. } => true,
        }
    }
}

/// Whether this node still owes the network a broadcast of an entry it
/// originated — §92.4's second clause, terminated by observation (F-10's
/// predicate, §92.5c item 1). The C++ `observed_circulating` bit, given the
/// only entry class it is defined for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Responsibility {
    /// The origin still re-broadcasts on its private path.
    Armed,
    /// The transaction was seen arriving from somewhere other than where
    /// it was stemmed; the origin has nothing left to rescue.
    Disarmed,
}

/// A block the pool last validated an entry against, or last saw it fail
/// against — the C++ `max_used_block_{height,id}` / `last_failed_{height,id}`
/// pair, each absent as one `Option` rather than a zero height beside a
/// null hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    /// The block's height.
    pub height: BlockHeight,
    /// The block's identity.
    pub hash: BlockHash,
}

/// The readiness cache `is_transaction_ready_to_go` maintains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Readiness {
    /// The highest block the inputs were last validated against.
    pub max_used: Option<BlockRef>,
    /// The block the inputs last failed against.
    pub last_failed: Option<BlockRef>,
}

/// A refused [`PoolRecord`] construction — the cross-field rules of the
/// module doc, as the type that names which one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordShapeError {
    /// [`RelayPhase::Held`] with an [`Origin::Arrived`] entry.
    HeldButArrived,
    /// [`RelayPhase::Stem`] with an [`Origin::Originated`] entry.
    StemButOriginated,
    /// A [`Responsibility`] on an [`Origin::Arrived`] entry.
    ResponsibilityWithoutOrigin,
    /// No [`Responsibility`] on an [`Origin::Originated`] entry.
    OriginWithoutResponsibility,
}

impl RecordShapeError {
    const fn reason(self) -> &'static str {
        match self {
            Self::HeldButArrived => "a Held phase on an Arrived entry",
            Self::StemButOriginated => "a Stem phase on an Originated entry",
            Self::ResponsibilityWithoutOrigin => "a responsibility on an Arrived entry",
            Self::OriginWithoutResponsibility => "an Originated entry with no responsibility",
        }
    }
}

impl core::fmt::Display for RecordShapeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.reason())
    }
}

impl core::error::Error for RecordShapeError {}

/// One pool entry's metadata — the C++ `txpool_tx_meta_t` re-specified.
/// Built as a struct literal and passed through [`PoolRecord::checked`];
/// the store re-applies [`PoolRecord::validate`] at every write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRecord {
    /// The transaction's weight.
    pub weight: u64,
    /// The fee it pays.
    pub fee: AtomicUnits,
    /// When this node first admitted it (wall clock).
    pub receive_time: UnixSeconds,
    /// Provenance — permanent.
    pub origin: Origin,
    /// How it is travelling now, with that phase's clock.
    pub phase: RelayPhase,
    /// Whether this node still owes a broadcast; `Some` iff
    /// `origin == Originated`.
    pub responsibility: Option<Responsibility>,
    /// Whether this node has relayed it at least once (the C++ `relayed`).
    pub relayed: bool,
    /// Whether a conflicting spend of one of its key images has been seen.
    pub double_spend_seen: bool,
    /// The readiness cache.
    pub readiness: Readiness,
    /// The FCMP++ verification cache (CEN-M8): `Some` iff verified.
    pub fcmp_cache: Option<FcmpVerificationHash>,
}

impl PoolRecord {
    /// Apply the cross-field rules of the module doc to a record built as a
    /// struct literal, returning it if they hold. The one place the rules
    /// are stated; the codec calls it at decode and the store at write.
    ///
    /// # Errors
    ///
    /// [`RecordShapeError`] naming the rule the fields break.
    pub const fn checked(self) -> Result<Self, RecordShapeError> {
        match self.validate() {
            Ok(()) => Ok(self),
            Err(e) => Err(e),
        }
    }

    /// The cross-field rules, as a check on a record in hand.
    ///
    /// # Errors
    ///
    /// [`RecordShapeError`] naming the rule the fields break.
    pub const fn validate(&self) -> Result<(), RecordShapeError> {
        match (self.phase, self.origin) {
            (RelayPhase::Held { .. }, Origin::Arrived { .. }) => {
                return Err(RecordShapeError::HeldButArrived)
            }
            (RelayPhase::Stem { .. }, Origin::Originated) => {
                return Err(RecordShapeError::StemButOriginated)
            }
            _ => {}
        }
        match (self.origin, self.responsibility) {
            (Origin::Arrived { .. }, Some(_)) => Err(RecordShapeError::ResponsibilityWithoutOrigin),
            (Origin::Originated, None) => Err(RecordShapeError::OriginWithoutResponsibility),
            _ => Ok(()),
        }
    }

    /// The FFI seam's byte for this record — what C++ still asks in the
    /// vocabulary of `relay_method`. Derived, never stored:
    /// `Originated + Held → Local`; otherwise the phase's own word.
    /// [`RelayMethod::None`] has no preimage — a stored record is never
    /// that.
    #[must_use]
    pub const fn relay_method(&self) -> RelayMethod {
        match self.phase {
            RelayPhase::Held { .. } => RelayMethod::Local,
            RelayPhase::Stem { .. } => RelayMethod::Stem,
            RelayPhase::Fluff { .. } => RelayMethod::Fluff,
            RelayPhase::Block { .. } => RelayMethod::Block,
        }
    }

    /// The C++ `matches_category` over this record — the pool's classifier
    /// (`DRS_E1_SPOOL.md` §3.3). The store itself never calls it.
    #[must_use]
    pub const fn matches(&self, category: RelayCategory) -> bool {
        self.relay_method().matches(category)
    }
}

// ---- codec ---------------------------------------------------------------

const TAG_ORIGINATED: u8 = 0;
const TAG_ARRIVED: u8 = 1;
const TAG_HELD: u8 = 0;
const TAG_STEM: u8 = 1;
const TAG_FLUFF: u8 = 2;
const TAG_BLOCK: u8 = 3;
const TAG_RESP_NONE: u8 = 0;
const TAG_RESP_ARMED: u8 = 1;
const TAG_RESP_DISARMED: u8 = 2;

fn put_bool(out: &mut Vec<u8>, b: bool) {
    out.push(u8::from(b));
}

fn put_opt_secs(out: &mut Vec<u8>, t: Option<UnixSeconds>) {
    match t {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_raw().to_le_bytes());
        }
    }
}

fn put_opt_block_ref(out: &mut Vec<u8>, r: Option<BlockRef>) {
    match r {
        None => out.push(0),
        Some(r) => {
            out.push(1);
            out.extend_from_slice(&r.height.to_raw().to_le_bytes());
            out.extend_from_slice(r.hash.as_ref());
        }
    }
}

fn take_bool(r: &mut Reader<'_>, what: &'static str) -> Result<bool, CodecError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(r.invalid(what)),
    }
}

fn take_opt_secs(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<UnixSeconds>, CodecError> {
    if take_bool(r, what)? {
        Ok(Some(UnixSeconds::from_raw(r.u64()?)))
    } else {
        Ok(None)
    }
}

fn take_opt_block_ref(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<BlockRef>, CodecError> {
    if take_bool(r, what)? {
        let height = BlockHeight::from_raw(r.u64()?);
        let hash = BlockHash::from_bytes(r.array::<32>("buffer ends inside a block hash")?);
        Ok(Some(BlockRef { height, hash }))
    } else {
        Ok(None)
    }
}

/// Layout (variable width, every count and tag bounded before use):
///
/// ```text
/// weight u64 ‖ fee u64 ‖ receive_time u64
/// ‖ origin: 0 | 1 zone(u8)
/// ‖ phase: 0 (presence u8 ‖ [u64]) | 1 u64 | 2 (presence ‖ [u64]) | 3 (presence ‖ [u64])
/// ‖ responsibility: 0 | 1 | 2
/// ‖ relayed u8 ‖ double_spend_seen u8
/// ‖ max_used: presence ‖ [u64 ‖ hash32] ‖ last_failed: presence ‖ [u64 ‖ hash32]
/// ‖ fcmp_cache: presence ‖ [hash32]
/// ```
///
/// Every tag and presence byte is exhaustive: a value outside its domain is
/// a codec error (SPL-14), and the cross-field rules of [`PoolRecord::validate`]
/// are re-applied so a stored row cannot say what a fresh one cannot.
impl Canonical for PoolRecord {
    const NAME: &'static str = "pool_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.weight.to_le_bytes());
        self.fee.encode_into(out);
        out.extend_from_slice(&self.receive_time.to_raw().to_le_bytes());
        match self.origin {
            Origin::Originated => out.push(TAG_ORIGINATED),
            Origin::Arrived { zone } => {
                out.push(TAG_ARRIVED);
                out.push(zone.to_byte());
            }
        }
        match self.phase {
            RelayPhase::Held { last_attempt } => {
                out.push(TAG_HELD);
                put_opt_secs(out, last_attempt);
            }
            RelayPhase::Stem { next_attempt } => {
                out.push(TAG_STEM);
                out.extend_from_slice(&next_attempt.to_raw().to_le_bytes());
            }
            RelayPhase::Fluff { last_relayed } => {
                out.push(TAG_FLUFF);
                put_opt_secs(out, last_relayed);
            }
            RelayPhase::Block { last_relayed } => {
                out.push(TAG_BLOCK);
                put_opt_secs(out, last_relayed);
            }
        }
        out.push(match self.responsibility {
            None => TAG_RESP_NONE,
            Some(Responsibility::Armed) => TAG_RESP_ARMED,
            Some(Responsibility::Disarmed) => TAG_RESP_DISARMED,
        });
        put_bool(out, self.relayed);
        put_bool(out, self.double_spend_seen);
        put_opt_block_ref(out, self.readiness.max_used);
        put_opt_block_ref(out, self.readiness.last_failed);
        match self.fcmp_cache {
            None => out.push(0),
            Some(h) => {
                out.push(1);
                out.extend_from_slice(h.as_ref());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(Self::NAME, bytes);
        let weight = r.u64()?;
        let fee = AtomicUnits::from_raw(r.u64()?);
        let receive_time = UnixSeconds::from_raw(r.u64()?);
        let origin = match r.u8()? {
            TAG_ORIGINATED => Origin::Originated,
            TAG_ARRIVED => {
                let zone = NetZone::from_byte(r.u8()?)
                    .ok_or_else(|| r.invalid("origin zone byte is not a NetZone"))?;
                Origin::Arrived { zone }
            }
            _ => return Err(r.invalid("origin tag is not Originated or Arrived")),
        };
        let phase = match r.u8()? {
            TAG_HELD => RelayPhase::Held {
                last_attempt: take_opt_secs(&mut r, "Held presence byte is not 0 or 1")?,
            },
            TAG_STEM => RelayPhase::Stem {
                next_attempt: UnixSeconds::from_raw(r.u64()?),
            },
            TAG_FLUFF => RelayPhase::Fluff {
                last_relayed: take_opt_secs(&mut r, "Fluff presence byte is not 0 or 1")?,
            },
            TAG_BLOCK => RelayPhase::Block {
                last_relayed: take_opt_secs(&mut r, "Block presence byte is not 0 or 1")?,
            },
            // SPL-14: no default arm that names a phase. Fluff is tag 2 and
            // nothing else.
            _ => return Err(r.invalid("relay phase tag is not Held, Stem, Fluff or Block")),
        };
        let responsibility = match r.u8()? {
            TAG_RESP_NONE => None,
            TAG_RESP_ARMED => Some(Responsibility::Armed),
            TAG_RESP_DISARMED => Some(Responsibility::Disarmed),
            _ => return Err(r.invalid("responsibility tag is not none, Armed or Disarmed")),
        };
        let relayed = take_bool(&mut r, "relayed byte is not 0 or 1")?;
        let double_spend_seen = take_bool(&mut r, "double_spend_seen byte is not 0 or 1")?;
        let max_used = take_opt_block_ref(&mut r, "max_used presence byte is not 0 or 1")?;
        let last_failed = take_opt_block_ref(&mut r, "last_failed presence byte is not 0 or 1")?;
        let fcmp_cache = if take_bool(&mut r, "fcmp_cache presence byte is not 0 or 1")? {
            Some(FcmpVerificationHash::from_bytes(
                r.array::<32>("buffer ends inside the fcmp cache hash")?,
            ))
        } else {
            None
        };
        if !r.is_empty() {
            return Err(r.invalid("trailing bytes after the pool record"));
        }
        Self {
            weight,
            fee,
            receive_time,
            origin,
            phase,
            responsibility,
            relayed,
            double_spend_seen,
            readiness: Readiness {
                max_used,
                last_failed,
            },
            fcmp_cache,
        }
        .checked()
        .map_err(|e| r.invalid(e.reason()))
    }
}
