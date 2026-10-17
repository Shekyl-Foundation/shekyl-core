// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record — DRS-E1 S-POOL (`DRS_E1_SPOOL.md` §3.4), reshaped by
//! DRS-E5 PR-b under DX-F6 (2026-10-16).
//!
//! **The pool knows one relay fact: whether a transaction is public yet**
//! (`DAEMON_RELAY_PRIVACY.md` D++ acceptance criterion 2). A transaction
//! that is not public is absent from the pool listing, from peer pool sync
//! and from a block template. The relay's fluff event sets the bit for a
//! relayed transaction; a transaction returned from a popped block is
//! admitted public, because a block carried it. Nothing clears it. Stem,
//! fluff, embargo, the arrival connector and
//! the originator's re-broadcast responsibility (F-10's disarm) are
//! `shekyl-relay`'s, which holds `Responsibility` keyed by transaction hash
//! beside its stem watch. A zone is an attribute of a session, never of a
//! pool entry (the no-zones ruling).
//!
//! Every other field is kept because admission, eviction or template
//! selection reads it:
//!
//! - `weight` — template selection fills a block by weight and orders by
//!   fee per weight; M10's weight cap evicts by fee per weight.
//! - `fee` — the same two orderings.
//! - `receive_time` — M10's age eviction.
//! - `public` — criterion 2: listing, peer sync and template.
//! - `standing` — template selection takes only [`Standing::Admitted`]
//!   entries, M10 ages a [`Standing::Kept`] entry on the longer lifetime,
//!   and the door re-admitting an entry at open reads M8's anchor from it.
//!
//! What the C++ `txpool_tx_meta_t` carries that this record does not, and
//! why nothing here reads it:
//!
//! - **The relay state** (`Origin`, the stem/fluff/block phase with its
//!   clocks, `Responsibility`) — relay's, by DX-F6; the pool reads only
//!   the public bit the relay's fluff event sets.
//! - **`relayed`** — "this node relayed it at least once" is a relay fact.
//!   No admission, eviction or template decision reads it.
//! - **`double_spend_seen`** — M7's conflict map refuses the second spend
//!   of a key image at the door, so a pool entry never coexists with its
//!   conflict; the bit was a display flag nothing decides on.
//! - **`Readiness`** (`max_used`, `last_failed`) — the C++ template's
//!   readiness cache. Template selection re-runs `tx_against` at
//!   `TxSlot::Lone` against the template's parent for every transaction it
//!   selects, so there is no cached readiness to consult.
//!
//! The FCMP++ verification cache (CEN-M8) is not the C++
//! `H(proof ‖ referenceBlock ‖ key images)` with a null-hash sentinel: it
//! is the `(reference hash, height, root)` triple the transaction's proof
//! was verified against — [`ProvenReference`], the stored form of the
//! validator's `VerifiedReference`. The entry's key is the transaction
//! hash, which commits to the proof's bytes, so the triple is all the
//! cache needs.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, UnixSeconds};
use shekyl_units::AtomicUnits;

use shekyl_store_codec::reader::Reader;

/// Wire tags of [`Standing`]. Zero is not a value: a zeroed record does
/// not read as admitted.
const TAG_ADMITTED: u8 = 1;
const TAG_KEPT: u8 = 2;

/// The reference a pool entry's proof was verified against — CEN-M8's
/// cache, the triple `form` and the pool door verify a proof under
/// (`VerifiedReference`: the reference block's identity, its height and
/// the curve-tree root at that height). Re-admission reads it: a claim at
/// the pool's tip equal to this triple names the anchor the proof was
/// already verified over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenReference {
    /// The `reference_block` the transaction names.
    pub reference: BlockHash,
    /// That block's height on the chain the proof was verified against.
    pub height: BlockHeight,
    /// The curve-tree root at `height` — the anchor the proof verified over.
    pub root: CurveTreeRoot,
}

impl ProvenReference {
    /// The row for what the validator verified.
    #[must_use]
    pub const fn of(verified: shekyl_chain_rules::VerifiedReference) -> Self {
        Self {
            reference: verified.reference,
            height: verified.claim.height,
            root: verified.claim.root,
        }
    }

    /// The row read back, as the rules crate's value.
    #[must_use]
    pub const fn verified(self) -> shekyl_chain_rules::VerifiedReference {
        shekyl_chain_rules::VerifiedReference {
            reference: self.reference,
            claim: shekyl_chain_rules::ReferenceClaim {
                height: self.height,
                root: self.root,
            },
        }
    }
}

/// Whether the entry passed the door at the tip it was last judged at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The door admitted it. `proven` is M8's cache: the reference its
    /// proof verified against, or `None` for a transaction whose judgement
    /// verified no reference.
    Admitted {
        /// The reference the proof verified against, if any.
        proven: Option<ProvenReference>,
    },
    /// Refused by the chain-bound half of the door when judged again — on
    /// return from a popped block (CEN-K10) or at a reconcile: kept because
    /// a further reorg may make it valid again, never relayed, never
    /// selected, and evicted by M10.
    Kept,
}

/// One pool entry's metadata. See the module docs for why each field is
/// here and what the C++ `txpool_tx_meta_t` carried that this does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolRecord {
    /// The transaction's weight.
    pub weight: u64,
    /// The fee it pays.
    pub fee: AtomicUnits,
    /// When this node first held it (wall clock).
    pub receive_time: UnixSeconds,
    /// Whether it is public (criterion 2): set by the relay's fluff event
    /// through [`PoolBatch::publish`](crate::pool::PoolBatch::publish), or at
    /// insert for a transaction a block carried. Nothing clears it.
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

fn encode_standing(standing: Standing, out: &mut Vec<u8>) {
    match standing {
        Standing::Admitted { proven } => {
            out.push(TAG_ADMITTED);
            match proven {
                None => out.push(0),
                Some(proven) => {
                    out.push(1);
                    out.extend_from_slice(proven.reference.as_bytes());
                    out.extend_from_slice(&proven.height.to_raw().to_le_bytes());
                    out.extend_from_slice(proven.root.as_bytes());
                }
            }
        }
        Standing::Kept => out.push(TAG_KEPT),
    }
}

fn decode_standing(reader: &mut Reader<'_>) -> Result<Standing, CodecError> {
    match reader.u8()? {
        TAG_ADMITTED => {
            let proven = if take_bool(reader, "proven presence byte is not 0 or 1")? {
                let reference =
                    BlockHash::from_bytes(reader.array::<32>("buffer ends inside the reference")?);
                let height = BlockHeight::from_raw(reader.u64()?);
                let root =
                    CurveTreeRoot::from_bytes(reader.array::<32>("buffer ends inside the root")?);
                Some(ProvenReference {
                    reference,
                    height,
                    root,
                })
            } else {
                None
            };
            Ok(Standing::Admitted { proven })
        }
        TAG_KEPT => Ok(Standing::Kept),
        _ => Err(reader.invalid("standing tag is not admitted or kept")),
    }
}

/// Layout (variable width; every tag is bounded before use):
///
/// ```text
/// weight u64 ‖ fee u64 ‖ receive_time u64 ‖ public u8
/// ‖ standing:
///     1  admitted:  presence u8 ‖ [reference hash32 ‖ height u64 ‖ root32]
///     2  kept
/// ```
///
/// A `public` or presence byte other than `0` or `1`, or a standing tag
/// other than `1` or `2`, is a codec error. Trailing bytes are a codec
/// error.
impl Canonical for PoolRecord {
    const NAME: &'static str = "pool_record";
    const FIXED_WIDTH: Option<usize> = None;

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.weight.to_le_bytes());
        self.fee.encode_into(out);
        out.extend_from_slice(&self.receive_time.to_raw().to_le_bytes());
        out.push(u8::from(self.public));
        encode_standing(self.standing, out);
    }

    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(Self::NAME, bytes);
        let weight = reader.u64()?;
        let fee = AtomicUnits::from_raw(reader.u64()?);
        let receive_time = UnixSeconds::from_raw(reader.u64()?);
        let public = take_bool(&mut reader, "public byte is not 0 or 1")?;
        let standing = decode_standing(&mut reader)?;
        if !reader.is_empty() {
            return Err(reader.invalid("trailing bytes after the pool record"));
        }
        Ok(Self {
            weight,
            fee,
            receive_time,
            public,
            standing,
        })
    }
}
