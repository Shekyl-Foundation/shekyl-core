// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §3.4), reshaped by
//! DRS-E5 PR-b under DX-F6 (2026-10-16) and the review of #1102 (S2, S7).
//!
//! **The pool knows one relay fact: whether a transaction is public yet**
//! (`DAEMON_RELAY_PRIVACY.md` D++ acceptance criterion 2). A transaction
//! that is not public is absent from the pool listing, from peer pool sync
//! and from a block template. The relay's fluff event sets the bit for a
//! relayed transaction; a block carrying a transaction sets it too, because
//! the block published it. Nothing clears it. Stem, fluff, embargo, the
//! arrival connector and the originator's re-broadcast responsibility
//! (F-10's disarm) are `shekyl-relay`'s, which holds `Responsibility` keyed
//! by transaction hash beside its stem watch. A zone is an attribute of a
//! session, never of a pool entry (the no-zones ruling).
//!
//! # The file holds only what the blob cannot say
//!
//! The pool file is not trusted (`shekyl_mempool`'s open re-derives
//! everything it can and judges every entry again), so the record keeps
//! only the facts the transaction's bytes do not carry:
//!
//! - `received` — when this node first held it, **to the hour**
//!   ([`ReceivedHour`]): the reconcile's order (where two entries spend one
//!   key image, the earlier keeps it) and template selection's tie-break,
//!   each then broken by hash. Nothing reads it finer. A stem arrival to the
//!   second is an origin clock: an observer comparing many nodes' records
//!   would find the earliest, the origin or the start of its stem path.
//! - `public` — criterion 2: listing, peer sync and template.
//! - `standing` — template selection takes only [`Standing::Admitted`]
//!   entries; a [`Standing::Kept`] entry carries the height it was
//!   returned at, which CEN-M10 ages it from, in blocks.
//!
//! What the record no longer carries, and why:
//!
//! - **Weight and fee** — functions of the transaction's bytes, derived
//!   from the blob at open. A file that said otherwise would be believed.
//! - **CEN-M8's anchor** — the `(reference, height, root)` the proof was
//!   verified against. Its readers are the pool's in-memory index; its only
//!   use in the file was to let a filed row skip the FCMP++ verify at open,
//!   which an untrusted file must not do. The pool holds it in memory.
//!
//! What the C++ `txpool_tx_meta_t` carries that this record does not, and
//! why nothing here reads it:
//!
//! - **The relay state** (`Origin`, the stem/fluff/block phase with its
//!   clocks, `Responsibility`) — relay's, by DX-F6; the pool reads only
//!   the public bit.
//! - **`relayed`** — "this node relayed it at least once" is a relay fact.
//!   No admission, eviction or template decision reads it.
//! - **`double_spend_seen`** — M7's conflict map refuses the second spend
//!   of a key image at the door, so a pool entry never coexists with its
//!   conflict; the bit was a display flag nothing decides on.
//! - **`Readiness`** (`max_used`, `last_failed`) — the C++ template's
//!   readiness cache. Template selection re-runs `tx_against` at
//!   `TxSlot::Lone` against the template's parent for every transaction it
//!   selects, so there is no cached readiness to consult.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHeight, UnixSeconds};

use shekyl_store_codec::reader::Reader;

/// Wire tags of [`Standing`]. Zero is not a value: a zeroed record does
/// not read as admitted.
const TAG_ADMITTED: u8 = 1;
const TAG_KEPT: u8 = 2;

/// Seconds in the hour [`ReceivedHour`] counts.
const HOUR: u64 = 3_600;

/// When this node first held a transaction, as whole hours since the Unix
/// epoch (module docs: the coarsest clock its readers can use, and no
/// origin clock).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceivedHour(u64);

impl ReceivedHour {
    /// The hour `at` falls in.
    #[must_use]
    pub const fn of(at: UnixSeconds) -> Self {
        Self(at.to_raw() / HOUR)
    }

    /// Hours since the Unix epoch.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }

    /// From hours since the Unix epoch.
    #[must_use]
    pub const fn from_raw(hours: u64) -> Self {
        Self(hours)
    }
}

/// Whether the entry passed the door at the tip it was last judged at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The door admitted it.
    Admitted,
    /// Returned from a block a switch popped and refused by the door's
    /// chain-bound half alone (CEN-K10): kept because a switch back may make
    /// it valid again, never relayed, never selected, and evicted by M10
    /// once the reorg cap has passed since `returned_at` — no switch back
    /// reaches further.
    Kept {
        /// The tip of the chain the switch left.
        returned_at: BlockHeight,
    },
}

/// One pool entry's metadata. See the module docs for why each field is
/// here and what is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRecord {
    /// When this node first held it, to the hour.
    pub received: ReceivedHour,
    /// Whether it is public (criterion 2): set by the relay's fluff event
    /// through [`PoolBatch::publish`](crate::pool::PoolBatch::publish), or by
    /// a block carrying it. Nothing clears it.
    pub public: bool,
    /// Whether the door admitted it or K10 kept it.
    pub standing: Standing,
}

// ---- codec ---------------------------------------------------------------

fn take_bool(reader: &mut Reader<'_>, what: &'static str) -> Result<bool, CodecError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(reader.invalid(what)),
    }
}

/// Layout (variable width; every tag is bounded before use):
///
/// ```text
/// received u64 (hours) ‖ public u8
/// ‖ standing:
///     1  admitted
///     2  kept: returned_at u64
/// ```
///
/// A `public` byte other than `0` or `1`, or a standing tag other than `1`
/// or `2`, is a codec error. Trailing bytes are a codec error.
impl Canonical for PoolRecord {
    const NAME: &'static str = "pool_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.received.to_raw().to_le_bytes());
        out.push(u8::from(self.public));
        match self.standing {
            Standing::Admitted => out.push(TAG_ADMITTED),
            Standing::Kept { returned_at } => {
                out.push(TAG_KEPT);
                out.extend_from_slice(&returned_at.to_raw().to_le_bytes());
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(Self::NAME, bytes);
        let received = ReceivedHour::from_raw(reader.u64()?);
        let public = take_bool(&mut reader, "public byte is not 0 or 1")?;
        let standing = match reader.u8()? {
            TAG_ADMITTED => Standing::Admitted,
            TAG_KEPT => Standing::Kept {
                returned_at: BlockHeight::from_raw(reader.u64()?),
            },
            _ => return Err(reader.invalid("standing tag is not admitted or kept")),
        };
        if !reader.is_empty() {
            return Err(reader.invalid("trailing bytes after the pool record"));
        }
        Ok(Self {
            received,
            public,
            standing,
        })
    }
}
