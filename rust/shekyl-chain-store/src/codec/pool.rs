// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §3.4; `SPL-Q3`,
//! `SPL-Q9` RULED 2026-09-24, pin made structural the same day on review).
//!
//! The C++ `txpool_tx_meta_t` (`src/blockchain_db/blockchain_db.h:218–348`)
//! is a 192-byte packed struct. This is its re-specification — **same
//! semantics, not byte-compatible** — and the re-specification is where
//! the relay findings land:
//!
//! - **SPL-4 / SPL-14.** The C++ relay class is four bits summed by a
//!   decoder whose `default:` arm returns `fluff`. Here the class is a
//!   [`RelayState`] tag. An unknown tag is a codec error. [`ArrivedPhase::Fluff`]
//!   is tag [`TAG_FLUFF`] and nothing else.
//! - **SPL-5.** `last_relayed_time` meant `u64::MAX` ("never"), a future
//!   embargo deadline, or a past relay time, depending on a bit elsewhere.
//!   Each phase variant carries the one clock that phase means.
//! - **SPL-6.** `pruned`, `do_not_relay` and `padding` are not carried.
//! - **SPL-10.** `fcmp_verified` + `fcmp_verification_hash` are one
//!   [`Option`]. The C++ null hash is absence, so `Some` of that hash is
//!   refused.
//! - **SPL-18 / the pin.** Provenance, phase and re-broadcast responsibility
//!   are three lifetimes. They are one [`RelayState`], so a phase illegal
//!   for its provenance has no value: an originated entry is [`OriginatedPhase`]
//!   (`Held` or `Block`), an arrival is [`ArrivedPhase`] (`Stem`, `Fluff`
//!   or `Block`). Responsibility lives only on the originated arm.
//!   [`RelayState::origin`] is the permanent projection [`PoolBatch::update`](crate::pool::PoolBatch::update)
//!   compares; a phase or responsibility change is not an origin change.
//!   [`RelayState::upgrade`] is the strict forward step, and update stores
//!   a new phase only when the walk is that step or the same phase.
//!
//! # The seam
//!
//! [`RelayState::relay_method`] derives the FFI byte ([`RelayMethod`]) from
//! the phase the state actually holds. [`RelayMethod::None`] has no
//! preimage. [`PoolRecord::matches`] is the C++ `matches_category` over
//! that byte. The record persists neither.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{
    BlockHash, BlockHeight, FcmpVerificationHash, NetZone, RelayCategory, RelayMethod, UnixSeconds,
};
use shekyl_units::AtomicUnits;

use super::reader::Reader;

/// The C++ `null_hash`: the absence sentinel for the FCMP++ verification
/// cache (`tx_pool.cpp:500–501`, SPL-10), not a hash that was verified.
const NULL_VERIFICATION_HASH: [u8; 32] = [0; 32];

/// Wire tags of [`RelayState`]. A zeroed tag is [`TAG_HELD`], which still
/// has to carry a responsibility byte — it is not fluff (SPL-14).
const TAG_HELD: u8 = 0;
const TAG_ORIGINATED_BLOCK: u8 = 1;
const TAG_STEM: u8 = 2;
const TAG_FLUFF: u8 = 3;
const TAG_ARRIVED_BLOCK: u8 = 4;

/// Responsibility tags on an originated entry. Zero is not a value: absence
/// of a responsibility is "this entry is an arrival", which has no byte here.
const TAG_ARMED: u8 = 1;
const TAG_DISARMED: u8 = 2;

/// Where a pool entry came from — §92.4's provenance, permanent.
///
/// This is the projection [`RelayState::origin`] returns. It is not a field
/// that also holds the phase or the responsibility, so comparing two
/// [`Origin`] values is the origin check and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// This node originated the transaction.
    Originated,
    /// The transaction arrived from a peer over `zone`. First arrival wins;
    /// [`NetZone::Invalid`] is "origin unknown".
    Arrived {
        /// The zone the bytes arrived over.
        zone: NetZone,
    },
}

/// How an entry this node originated is travelling.
///
/// `Stem` and `Fluff` are not in this set. "We already sent it" is
/// [`OriginatedPhase::Held::last_attempt`] plus [`PoolRecord::relayed`].
/// The entry yields to proof of work by becoming [`OriginatedPhase::Block`],
/// and provenance stays [`Origin::Originated`] when it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginatedPhase {
    /// Not yet public. `last_attempt` is the last private re-broadcast, or
    /// `None` if there has not been one. An entry admitted on the attested
    /// path starts at `Some(receive_time)`; one admitted for dispatch starts
    /// at `None`.
    Held {
        /// Last private re-broadcast, if any.
        last_attempt: Option<UnixSeconds>,
    },
    /// Seen in a block. Public, because a block is.
    Block {
        /// Last broadcast, if any.
        last_relayed: Option<UnixSeconds>,
    },
}

/// How an entry that arrived from a peer is travelling.
///
/// `Held` is not in this set. The walk is `Stem → Fluff → Block`, and a
/// stem entry may yield straight to a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrivedPhase {
    /// In Dandelion++ stem. `next_attempt` is the future instant the embargo
    /// fires.
    Stem {
        /// The embargo deadline.
        next_attempt: UnixSeconds,
    },
    /// Fluffed — public. `last_relayed` is the last broadcast, if any.
    Fluff {
        /// Last broadcast, if any.
        last_relayed: Option<UnixSeconds>,
    },
    /// Arrived in a block (a pop's re-add, or an alt block's supplement).
    Block {
        /// Last broadcast, if any.
        last_relayed: Option<UnixSeconds>,
    },
}

/// Whether this node still owes the network a broadcast of an entry it
/// originated. The C++ `observed_circulating` bit, on the only entry class
/// it is defined for. F-10's verdict writes [`Responsibility::Disarmed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Responsibility {
    /// The origin still re-broadcasts on its private path.
    Armed,
    /// The transaction was seen arriving from somewhere other than where it
    /// was stemmed.
    Disarmed,
}

/// Provenance, phase and — for an originated entry — responsibility, as one
/// value.
///
/// The phase enum is chosen by the provenance, so the pairs the pin forbids
/// cannot be constructed. [`RelayState::origin`] is what an update compares
/// for permanence. [`RelayState::upgrade`] is a strict forward step;
/// [`RelayState::accepts`] is that step or a rewrite at the same phase
/// (a new clock, a disarmed responsibility, a readiness note).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayState {
    /// Originated here. Responsibility is required, because the arm exists
    /// only for this provenance.
    Originated {
        /// `Held`, or `Block` once the entry has yielded to proof of work.
        phase: OriginatedPhase,
        /// Whether this node still owes a broadcast.
        responsibility: Responsibility,
    },
    /// Arrived over `zone`. No responsibility arm.
    Arrived {
        /// First-arrival zone. A later delivery does not revise it.
        zone: NetZone,
        /// `Stem`, `Fluff`, or `Block`.
        phase: ArrivedPhase,
    },
}

/// What a candidate relay state is, relative to the one stored.
enum PhaseStep {
    /// Same phase. Clocks and responsibility may differ.
    Same,
    /// A forward step on this provenance's walk.
    Forward,
    /// A different provenance, or a phase that is not a forward step.
    Refused,
}

impl RelayState {
    /// The permanent provenance. Phase and responsibility are not part of it.
    #[must_use]
    pub const fn origin(self) -> Origin {
        match self {
            Self::Originated { .. } => Origin::Originated,
            Self::Arrived { zone, .. } => Origin::Arrived { zone },
        }
    }

    /// Re-broadcast responsibility. `Some` exactly when the entry was
    /// originated here.
    #[must_use]
    pub const fn responsibility(self) -> Option<Responsibility> {
        match self {
            Self::Originated { responsibility, .. } => Some(responsibility),
            Self::Arrived { .. } => None,
        }
    }

    /// The FFI seam's byte. Derived, never stored. [`RelayMethod::None`] has
    /// no preimage: a held originated entry is [`RelayMethod::Local`], and
    /// every other phase's word is its own.
    #[must_use]
    pub const fn relay_method(self) -> RelayMethod {
        match self {
            Self::Originated {
                phase: OriginatedPhase::Held { .. },
                ..
            } => RelayMethod::Local,
            Self::Originated {
                phase: OriginatedPhase::Block { .. },
                ..
            }
            | Self::Arrived {
                phase: ArrivedPhase::Block { .. },
                ..
            } => RelayMethod::Block,
            Self::Arrived {
                phase: ArrivedPhase::Stem { .. },
                ..
            } => RelayMethod::Stem,
            Self::Arrived {
                phase: ArrivedPhase::Fluff { .. },
                ..
            } => RelayMethod::Fluff,
        }
    }

    /// The C++ `matches_category` over [`Self::relay_method`].
    #[must_use]
    pub const fn matches(self, category: RelayCategory) -> bool {
        self.relay_method().matches(category)
    }

    /// `next` when it is a strict forward step on the same provenance:
    /// originated `Held → Block`; arrived `Stem → Fluff`, `Stem → Block`,
    /// or `Fluff → Block`. Same phase is not a step — the caller keeps its
    /// own clock. A different zone, a step off that walk, or re-arming a
    /// disarmed responsibility is `None`.
    #[must_use]
    pub const fn upgrade(self, next: Self) -> Option<Self> {
        if self.rearms(next) {
            return None;
        }
        match self.step(next) {
            PhaseStep::Forward => Some(next),
            PhaseStep::Same | PhaseStep::Refused => None,
        }
    }

    /// Whether an update may replace `self` with `next`: the phase follows
    /// ([`Self::phase_follows`]) and the responsibility is not re-armed.
    #[must_use]
    pub const fn accepts(self, next: Self) -> bool {
        self.phase_follows(next) && !self.rearms(next)
    }

    /// Same provenance, and either the same phase or a forward step.
    /// Responsibility is not part of this answer.
    #[must_use]
    pub const fn phase_follows(self, next: Self) -> bool {
        match self.step(next) {
            PhaseStep::Same | PhaseStep::Forward => true,
            PhaseStep::Refused => false,
        }
    }

    /// Whether `next` arms a responsibility `self` has already disarmed.
    /// Observation ends the obligation. An arrival has nothing to re-arm.
    #[must_use]
    pub const fn rearms(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Originated {
                    responsibility: Responsibility::Disarmed,
                    ..
                },
                Self::Originated {
                    responsibility: Responsibility::Armed,
                    ..
                },
            )
        )
    }

    const fn step(self, next: Self) -> PhaseStep {
        match (self, next) {
            (Self::Originated { phase: from, .. }, Self::Originated { phase: to, .. }) => {
                originated_step(from, to)
            }
            (
                Self::Arrived {
                    zone: from_zone,
                    phase: from,
                },
                Self::Arrived {
                    zone: to_zone,
                    phase: to,
                },
            ) => {
                if from_zone.to_byte() != to_zone.to_byte() {
                    PhaseStep::Refused
                } else {
                    arrived_step(from, to)
                }
            }
            _ => PhaseStep::Refused,
        }
    }
}

/// The originated walk. Every pair is an arm, so a new phase does not compile
/// until it says what it follows.
const fn originated_step(from: OriginatedPhase, to: OriginatedPhase) -> PhaseStep {
    match (from, to) {
        (OriginatedPhase::Held { .. }, OriginatedPhase::Block { .. }) => PhaseStep::Forward,
        (OriginatedPhase::Block { .. }, OriginatedPhase::Held { .. }) => PhaseStep::Refused,
        (OriginatedPhase::Held { .. }, OriginatedPhase::Held { .. })
        | (OriginatedPhase::Block { .. }, OriginatedPhase::Block { .. }) => PhaseStep::Same,
    }
}

/// The arrived walk. Stem may skip fluff when the entry shows up in a block.
const fn arrived_step(from: ArrivedPhase, to: ArrivedPhase) -> PhaseStep {
    match (from, to) {
        (ArrivedPhase::Stem { .. }, ArrivedPhase::Fluff { .. })
        | (ArrivedPhase::Stem { .. }, ArrivedPhase::Block { .. })
        | (ArrivedPhase::Fluff { .. }, ArrivedPhase::Block { .. }) => PhaseStep::Forward,
        (ArrivedPhase::Fluff { .. }, ArrivedPhase::Stem { .. })
        | (ArrivedPhase::Block { .. }, ArrivedPhase::Stem { .. })
        | (ArrivedPhase::Block { .. }, ArrivedPhase::Fluff { .. }) => PhaseStep::Refused,
        (ArrivedPhase::Stem { .. }, ArrivedPhase::Stem { .. })
        | (ArrivedPhase::Fluff { .. }, ArrivedPhase::Fluff { .. })
        | (ArrivedPhase::Block { .. }, ArrivedPhase::Block { .. }) => PhaseStep::Same,
    }
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

/// One pool entry's metadata — the C++ `txpool_tx_meta_t` re-specified.
///
/// [`PoolRecord::relay_state`] is the whole relay value. The other fields
/// are the weight, the fee, the admission clock, the relayed flag, the
/// double-spend bit, the readiness cache and the verification cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRecord {
    /// The transaction's weight.
    pub weight: u64,
    /// The fee it pays.
    pub fee: AtomicUnits,
    /// When this node first admitted it (wall clock).
    pub receive_time: UnixSeconds,
    /// Provenance, phase and responsibility. See [`RelayState`].
    pub relay_state: RelayState,
    /// Whether this node has relayed it at least once (the C++ `relayed`).
    pub relayed: bool,
    /// Whether a conflicting spend of one of its key images has been seen.
    pub double_spend_seen: bool,
    /// The readiness cache.
    pub readiness: Readiness,
    /// The FCMP++ verification cache (CEN-M8). `Some` iff verified.
    /// [`NULL_VERIFICATION_HASH`] is not a cache hit; the store and the
    /// decoder both refuse it.
    pub fcmp_cache: Option<FcmpVerificationHash>,
}

impl PoolRecord {
    /// Whether `fcmp_cache` is the C++ null hash. Absence is [`None`].
    #[must_use]
    pub fn has_null_fcmp_cache(self) -> bool {
        match self.fcmp_cache {
            Some(hash) => hash.as_bytes() == &NULL_VERIFICATION_HASH,
            None => false,
        }
    }

    /// Permanent provenance of [`Self::relay_state`].
    #[must_use]
    pub const fn origin(self) -> Origin {
        self.relay_state.origin()
    }

    /// [`RelayState::responsibility`].
    #[must_use]
    pub const fn responsibility(self) -> Option<Responsibility> {
        self.relay_state.responsibility()
    }

    /// [`RelayState::relay_method`].
    #[must_use]
    pub const fn relay_method(self) -> RelayMethod {
        self.relay_state.relay_method()
    }

    /// [`RelayState::matches`].
    #[must_use]
    pub const fn matches(self, category: RelayCategory) -> bool {
        self.relay_state.matches(category)
    }
}

// ---- codec ---------------------------------------------------------------

fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn put_opt_secs(out: &mut Vec<u8>, time: Option<UnixSeconds>) {
    match time {
        None => out.push(0),
        Some(time) => {
            out.push(1);
            out.extend_from_slice(&time.to_raw().to_le_bytes());
        }
    }
}

fn put_opt_block_ref(out: &mut Vec<u8>, block: Option<BlockRef>) {
    match block {
        None => out.push(0),
        Some(block) => {
            out.push(1);
            out.extend_from_slice(&block.height.to_raw().to_le_bytes());
            out.extend_from_slice(block.hash.as_ref());
        }
    }
}

fn put_responsibility(out: &mut Vec<u8>, responsibility: Responsibility) {
    out.push(match responsibility {
        Responsibility::Armed => TAG_ARMED,
        Responsibility::Disarmed => TAG_DISARMED,
    });
}

fn take_bool(reader: &mut Reader<'_>, what: &'static str) -> Result<bool, CodecError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(reader.invalid(what)),
    }
}

fn take_opt_secs(
    reader: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<UnixSeconds>, CodecError> {
    if take_bool(reader, what)? {
        Ok(Some(UnixSeconds::from_raw(reader.u64()?)))
    } else {
        Ok(None)
    }
}

fn take_opt_block_ref(
    reader: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<BlockRef>, CodecError> {
    if take_bool(reader, what)? {
        let height = BlockHeight::from_raw(reader.u64()?);
        let hash = BlockHash::from_bytes(reader.array::<32>("buffer ends inside a block hash")?);
        Ok(Some(BlockRef { height, hash }))
    } else {
        Ok(None)
    }
}

fn take_zone(reader: &mut Reader<'_>) -> Result<NetZone, CodecError> {
    NetZone::from_byte(reader.u8()?)
        .ok_or_else(|| reader.invalid("arrival zone byte is not a NetZone"))
}

fn take_responsibility(reader: &mut Reader<'_>) -> Result<Responsibility, CodecError> {
    match reader.u8()? {
        TAG_ARMED => Ok(Responsibility::Armed),
        TAG_DISARMED => Ok(Responsibility::Disarmed),
        _ => Err(reader.invalid("responsibility tag is not Armed or Disarmed")),
    }
}

fn encode_relay(state: RelayState, out: &mut Vec<u8>) {
    match state {
        RelayState::Originated {
            phase: OriginatedPhase::Held { last_attempt },
            responsibility,
        } => {
            out.push(TAG_HELD);
            put_responsibility(out, responsibility);
            put_opt_secs(out, last_attempt);
        }
        RelayState::Originated {
            phase: OriginatedPhase::Block { last_relayed },
            responsibility,
        } => {
            out.push(TAG_ORIGINATED_BLOCK);
            put_responsibility(out, responsibility);
            put_opt_secs(out, last_relayed);
        }
        RelayState::Arrived {
            zone,
            phase: ArrivedPhase::Stem { next_attempt },
        } => {
            out.push(TAG_STEM);
            out.push(zone.to_byte());
            out.extend_from_slice(&next_attempt.to_raw().to_le_bytes());
        }
        RelayState::Arrived {
            zone,
            phase: ArrivedPhase::Fluff { last_relayed },
        } => {
            out.push(TAG_FLUFF);
            out.push(zone.to_byte());
            put_opt_secs(out, last_relayed);
        }
        RelayState::Arrived {
            zone,
            phase: ArrivedPhase::Block { last_relayed },
        } => {
            out.push(TAG_ARRIVED_BLOCK);
            out.push(zone.to_byte());
            put_opt_secs(out, last_relayed);
        }
    }
}

fn decode_relay(reader: &mut Reader<'_>) -> Result<RelayState, CodecError> {
    match reader.u8()? {
        TAG_HELD => Ok(RelayState::Originated {
            responsibility: take_responsibility(reader)?,
            phase: OriginatedPhase::Held {
                last_attempt: take_opt_secs(reader, "Held presence byte is not 0 or 1")?,
            },
        }),
        TAG_ORIGINATED_BLOCK => Ok(RelayState::Originated {
            responsibility: take_responsibility(reader)?,
            phase: OriginatedPhase::Block {
                last_relayed: take_opt_secs(
                    reader,
                    "originated Block presence byte is not 0 or 1",
                )?,
            },
        }),
        TAG_STEM => Ok(RelayState::Arrived {
            zone: take_zone(reader)?,
            phase: ArrivedPhase::Stem {
                next_attempt: UnixSeconds::from_raw(reader.u64()?),
            },
        }),
        TAG_FLUFF => Ok(RelayState::Arrived {
            zone: take_zone(reader)?,
            phase: ArrivedPhase::Fluff {
                last_relayed: take_opt_secs(reader, "Fluff presence byte is not 0 or 1")?,
            },
        }),
        TAG_ARRIVED_BLOCK => Ok(RelayState::Arrived {
            zone: take_zone(reader)?,
            phase: ArrivedPhase::Block {
                last_relayed: take_opt_secs(reader, "arrived Block presence byte is not 0 or 1")?,
            },
        }),
        // SPL-14: no arm that names fluff except TAG_FLUFF.
        _ => Err(reader.invalid(
            "relay state tag is not held, originated-block, stem, fluff or arrived-block",
        )),
    }
}

/// Layout (variable width; every tag is bounded before use):
///
/// ```text
/// weight u64 ‖ fee u64 ‖ receive_time u64
/// ‖ relay:
///     0  held:              responsibility u8 ‖ presence u8 ‖ [u64]
///     1  originated block:  responsibility u8 ‖ presence u8 ‖ [u64]
///     2  stem:              zone u8 ‖ deadline u64
///     3  fluff:             zone u8 ‖ presence u8 ‖ [u64]
///     4  arrived block:     zone u8 ‖ presence u8 ‖ [u64]
/// ‖ relayed u8 ‖ double_spend_seen u8
/// ‖ max_used: presence ‖ [u64 ‖ hash32] ‖ last_failed: presence ‖ [u64 ‖ hash32]
/// ‖ fcmp_cache: presence ‖ [hash32]
/// ```
///
/// Responsibility is `1` Armed or `2` Disarmed. A tag outside `0..=4`, a
/// zone or responsibility outside its set, a presence byte other than
/// `0` or `1`, or a verification hash of [`NULL_VERIFICATION_HASH`] is a
/// codec error. Trailing bytes are a codec error.
impl Canonical for PoolRecord {
    const NAME: &'static str = "pool_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.weight.to_le_bytes());
        self.fee.encode_into(out);
        out.extend_from_slice(&self.receive_time.to_raw().to_le_bytes());
        encode_relay(self.relay_state, out);
        put_bool(out, self.relayed);
        put_bool(out, self.double_spend_seen);
        put_opt_block_ref(out, self.readiness.max_used);
        put_opt_block_ref(out, self.readiness.last_failed);
        match self.fcmp_cache {
            None => out.push(0),
            Some(hash) => {
                out.push(1);
                out.extend_from_slice(hash.as_ref());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(Self::NAME, bytes);
        let weight = reader.u64()?;
        let fee = AtomicUnits::from_raw(reader.u64()?);
        let receive_time = UnixSeconds::from_raw(reader.u64()?);
        let relay_state = decode_relay(&mut reader)?;
        let relayed = take_bool(&mut reader, "relayed byte is not 0 or 1")?;
        let double_spend_seen = take_bool(&mut reader, "double_spend_seen byte is not 0 or 1")?;
        let max_used = take_opt_block_ref(&mut reader, "max_used presence byte is not 0 or 1")?;
        let last_failed =
            take_opt_block_ref(&mut reader, "last_failed presence byte is not 0 or 1")?;
        let fcmp_cache = if take_bool(&mut reader, "fcmp_cache presence byte is not 0 or 1")? {
            Some(FcmpVerificationHash::from_bytes(
                reader.array::<32>("buffer ends inside the fcmp cache hash")?,
            ))
        } else {
            None
        };
        if !reader.is_empty() {
            return Err(reader.invalid("trailing bytes after the pool record"));
        }
        let record = Self {
            weight,
            fee,
            receive_time,
            relay_state,
            relayed,
            double_spend_seen,
            readiness: Readiness {
                max_used,
                last_failed,
            },
            fcmp_cache,
        };
        if record.has_null_fcmp_cache() {
            return Err(reader.invalid("fcmp cache is the null hash; absence is a missing option"));
        }
        Ok(record)
    }
}
