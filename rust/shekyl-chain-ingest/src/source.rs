// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where blocks come from, as an ordered event stream (RD-Q13).
//!
//! A height-ordered stream of blocks cannot represent a reorg: the pipeline
//! would have no way to say *pop*. So a source yields [`IngestEvent`]s —
//! `Extend` with a candidate, `Rewind { to }`, or the regtest-only
//! `Inject` — each stamped with a [`SequenceNo`] the source assigns, and
//! the pipeline's contract is stated against that number:
//!
//! - Sequence numbers are **consecutive from [`SequenceNo::FIRST`]**: the
//!   pipeline asserts each event's number as it reads it, so a hole in a
//!   source's numbering is a loud fault at the event, never an item parked
//!   in the sequencer behind a position nothing will ever fill.
//! - The **Sequencer** restores sequence order after parallel formation and
//!   **never reorders across a `Rewind`**: a `Rewind` is a barrier. Formation
//!   of the `Extend`s after it waits for it to commit, because their seed
//!   context (CEN-D3) depends on the post-rewind chain.
//! - The **actor** executes `Rewind { to }` as `pop` until the tip is `to`,
//!   then connects the `Extend`s at `to + 1…`.
//! - The **digest sink** records after each `Rewind` commit — the "digest
//!   after each switch" the reorg fixture family needs.
//!
//! Who *decides* a rewind is the source's business: the reorg fixture scripts
//! it; E3's p2p source computes the heavier-chain switch (the daemon's
//! alt-chain logic) and emits it. The pipeline only executes.
//!
//! **`Inject` is the one out-of-band event** (DRS-E4 §3.8 item 3): a
//! serve-credit bit the regtest injector wrote beside the chain, at its
//! capture position, so a replay of a captured regtest chain reaches the
//! same archival state the daemon held. It is a barrier like `Rewind`,
//! applied in its own store transaction at the committed tip; the store
//! refuses it under any rules but regtest, and a later `Rewind` below the
//! height it was attributed to is a pipeline fault, not a pop (the bit is
//! not block-owned, so no pop can carry it away). The corpus is its sole
//! carrier and the generator's injector its sole producer; it appears in
//! no captured chain but `emission-claim`.
//!
//! The corpus source (E2's first) carries all three kinds; the mutation
//! family is Extend-only; the reorg family and E3's feed emit `Rewind`.

use shekyl_chain_rules::Candidate;
use shekyl_types::{BlockHeight, PCanonicalId, SettlementEpoch, ShardId};

/// A source-assigned position in its event stream. Total order; the
/// sequencer restores it after parallel formation.
///
/// Not a height: two `Extend`s at the same height (before and after a
/// `Rewind`) have different sequence numbers, and a `Rewind` has one too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNo(u64);

impl SequenceNo {
    /// The first event a source emits.
    pub const FIRST: Self = Self(0);

    /// The next position. Sequence numbers strictly increase: exhaustion of
    /// the `u64` space panics rather than wrapping (a restart from zero) or
    /// saturating (two events sharing a number).
    #[must_use]
    pub const fn next(self) -> Self {
        Self(
            self.0
                .checked_add(1)
                .expect("ingest sequence space exhausted"),
        )
    }

    /// The raw position, for logs and artifacts.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }
}

/// One event a [`Source`] emits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestEvent {
    /// Connect this candidate at the tip. The candidate carries its block
    /// and the **full bodies** of its listed transactions in header order —
    /// what the validator consumes (`Candidate`, RD-F8); a corpus source
    /// verified count, order and hash against the header before emitting
    /// it (RD-F15). Boxed: a candidate carries whole bodies and travels
    /// through the stage channels; the variant stays one pointer wide.
    Extend(Box<Candidate>),
    /// Pop until the tip is `to`. The `Extend`s that follow connect at
    /// `to + 1…` and are formed against the post-rewind chain.
    Rewind {
        /// The height the tip must be at when the rewind has committed.
        to: BlockHeight,
    },
    /// Write this serve-credit bit at the committed tip, out of band
    /// (module docs). Regtest-only: the store refuses it under any other
    /// rules. One row kind — a second kind of out-of-band write is a second
    /// variant, never a payload enum here.
    Inject(ServeCredit),
}

/// The one out-of-band write a source may carry: a serve-credit **pass**
/// bit for `persona` on `shard` in `epoch`, keyed at the height the store
/// attributes it to (the tip when it is applied). What the regtest
/// injector wrote beside the chain, so a captured chain's replay reaches
/// the archival state the daemon held (DRS-E4 §3.8 item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServeCredit {
    /// The bonded persona credited.
    pub persona: PCanonicalId,
    /// The shard served.
    pub shard: ShardId,
    /// The settlement epoch the pass counts toward.
    pub epoch: SettlementEpoch,
}

/// A serve credit **with the height the store attributed it to**: the
/// injector's receipt. One shape for its three carriers — the corpus
/// fetch writes the `Inject` record at `at` from it, the pipeline reports
/// each committed `Inject` as one, and a capture's manifest row is one in
/// JSON — so the height cannot be spelled differently at any of them.
///
/// The event itself ([`IngestEvent::Inject`]) carries no height: the
/// pipeline applies it at the committed tip, and the corpus law
/// (`check_inject`) holds the record's `at` to that tip, so the two cannot
/// disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Injection {
    /// The tip the bit was attributed to when it was written.
    pub at: BlockHeight,
    /// The bit.
    pub credit: ServeCredit,
}

/// Why a spelled injection did not parse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InjectionParseError {
    /// Not `<persona-hex>:<shard>:<epoch>@<height>`.
    #[error("an injection is spelled <persona-hex>:<shard>:<epoch>@<height>")]
    Shape,
    /// The persona is not 64 lowercase-or-uppercase hex digits.
    #[error("the persona is 32 bytes as 64 hex digits")]
    Persona,
    /// One of the three numbers did not parse as a `u64`.
    #[error("{what} is not a decimal u64")]
    Number {
        /// Which field.
        what: &'static str,
    },
}

impl core::str::FromStr for Injection {
    type Err = InjectionParseError;

    /// `<persona-hex>:<shard>:<epoch>@<height>` — the spelling
    /// `shekyl-chain-replay fetch --inject` takes, and the generator writes
    /// from the injector's receipt. Every field is required; there is no
    /// default for a height, because a defaulted height is the ARW-26
    /// class (a count where an attributed height belongs).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (credit, at) = s.split_once('@').ok_or(InjectionParseError::Shape)?;
        let mut parts = credit.split(':');
        let (Some(persona), Some(shard), Some(epoch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(InjectionParseError::Shape);
        };
        if persona.len() != 64 || !persona.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(InjectionParseError::Persona);
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&persona[2 * i..2 * i + 2], 16)
                .map_err(|_| InjectionParseError::Persona)?;
        }
        let number = |text: &str, what: &'static str| {
            text.parse::<u64>()
                .map_err(|_| InjectionParseError::Number { what })
        };
        Ok(Self {
            at: BlockHeight::from_raw(number(at, "height")?),
            credit: ServeCredit {
                persona: PCanonicalId::from_bytes(bytes),
                shard: ShardId::from_raw(number(shard, "shard")?),
                epoch: SettlementEpoch::from_raw(number(epoch, "epoch")?),
            },
        })
    }
}

impl core::fmt::Display for Injection {
    /// The spelling `from_str` reads; round-trips.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}:{}:{}@{}",
            self.credit.persona, self.credit.shard, self.credit.epoch, self.at
        )
    }
}

/// In JSON an injection is its one spelling as a string — the manifest
/// row a capture writes is the flag it passed the fetch, byte for byte —
/// so there is no second, field-wise encoding whose `height` could be
/// filled from a different read.
impl serde::Serialize for Injection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Injection {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let spelled = <String as serde::Deserialize>::deserialize(deserializer)?;
        spelled.parse().map_err(serde::de::Error::custom)
    }
}

impl IngestEvent {
    /// Whether the sequencer may reorder formation across this event.
    /// `true` for a `Rewind` and an `Inject`: both are barriers — the
    /// `Extend`s after them are formed against a chain whose state they
    /// changed. Exhaustive so a new variant is a compile error, not a
    /// silent non-barrier.
    #[must_use]
    pub const fn is_barrier(&self) -> bool {
        match self {
            Self::Rewind { .. } | Self::Inject(_) => true,
            Self::Extend(_) => false,
        }
    }
}

/// An event at its position in the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequenced<T> {
    /// The source's position for this event.
    pub seq: SequenceNo,
    /// The event.
    pub event: T,
}

/// A supplier of ordered ingest events.
///
/// Implemented by the corpus reader (E2), the mutation and reorg fixture
/// families, and E3's p2p feed. A source is pulled, not pushed: the
/// pipeline asks for the next event when it has room, so back-pressure is
/// the caller's `next` cadence and no channel is hidden inside the trait.
pub trait Source {
    /// Why the source could not produce its next event: an unreadable
    /// artifact, a refused corpus height, a closed feed. Opaque to the
    /// pipeline, which surfaces it and ends the run — never a verdict.
    type Fault;

    /// The height the source's first `Extend` connects at. An `Extend`
    /// carries no height — the pipeline assigns them from the store's tip —
    /// so this is what the pipeline checks that assignment against before
    /// forming anything: a source that starts elsewhere than `tip + 1`
    /// would be formed at the wrong heights and its refusal recorded as a
    /// consensus verdict instead of the driver fault it is.
    fn first_height(&self) -> BlockHeight;

    /// The next event, `Ok(None)` when the stream is exhausted. Sequence
    /// numbers are consecutive from [`SequenceNo::FIRST`] across the
    /// `Some`s a source yields (module docs).
    ///
    /// # Errors
    ///
    /// The source's own [`Self::Fault`].
    fn next(&mut self) -> Result<Option<Sequenced<IngestEvent>>, Self::Fault>;
}

#[cfg(test)]
#[path = "source_tests.rs"]
mod source_tests;
