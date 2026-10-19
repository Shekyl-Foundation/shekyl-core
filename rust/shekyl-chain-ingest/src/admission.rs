// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What an arrival costs, and who pays (`DRS_X_STORE_FLIP.md` PR2-Q2): the
//! door's two checks before anything is parsed.
//!
//! A light-mode RandomX hash takes about 1.25 s per core on the floor
//! device (#1106's measurement), and a block with junk proof-of-work costs
//! its sender nothing to make: every fresh nonce is a fresh id, and costs
//! this node one hash. Both checks here are derived from the chain, and
//! neither is a verdict: a refused span was never accepted.
//!
//! # Size before parse
//!
//! [`ArrivalBound`]: no valid block's arrival exceeds it, so a larger one
//! is [`Refusal::Oversize`](crate::service::Refusal::Oversize). A block's
//! weight is at least its transactions' serialized size, coinbase
//! included, and is at most the limit in force where it connects. The rest
//! of the block blob is the header, bounded by the wire
//! ([`MAX_BLOCK_HEADER_SIZE`]), and the list of listed hashes, 32 bytes
//! each — no more bytes than the bodies they name, each of which serializes
//! to more than its hash. So an arrival's bytes are at most the header
//! bound plus twice the limit.
//!
//! Which limit: before parse the arrival's height is not known, and a span
//! reaches past the tip's successor. The short-term median can move within
//! a span, but the effective median is clamped to `S · LTEM` (CEN-G6b,
//! `BLOCK_WEIGHT_SURGE_FACTOR`), and the long-term median moves over a
//! 100 000-block window. So the limit at every height a span reaches is at
//! most `2 · S · LTEM` at the tip's successor, and that ceiling is the
//! bound's limit: the limit in force at the connecting height, for every
//! arrival whose height the door cannot know yet. This is CEN-A5's job
//! re-homed as the router's admission, and CEN-A5 is bucket 3: the parse
//! cost bound, not validity, which G6b judges.
//!
//! # Unsolicited arrivals, per session
//!
//! An announcement this node did not ask for takes a token from its
//! session's [`Buckets`]: two per target block interval, at most two
//! held. An honest peer announces each new block once and the network makes
//! one per interval, so an honest session never runs dry. A dry bucket is
//! [`Refusal::Throttled`](crate::service::Refusal::Throttled), before
//! parse; the handler may close the session, which is a close, never a
//! score (CS-Q5 (c): nothing scores). A span this node asked for takes no
//! tokens: chain sync's own requests bound it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use shekyl_chain_rules::{effective_median_at, HeaderView, Tip, ViewRead};
use shekyl_chain_store::store::{ChainStore, SnapshotView, StoreError};
use shekyl_economics::block_weight::BLOCK_WEIGHT_SURGE_FACTOR;
use shekyl_types::BlockHash;
use shekyl_wire::block::MAX_BLOCK_HEADER_SIZE;

use crate::service::SessionId;

/// The largest arrival, in bytes, any valid block can be near this tip
/// (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArrivalBound(pub u64);

impl ArrivalBound {
    /// The bound at `store`'s tip.
    ///
    /// # Errors
    ///
    /// The store's, or a weight window it cannot answer (a hole halts the
    /// writer on its next read; here it is reported).
    pub fn at(store: &ChainStore) -> Result<(Option<BlockHash>, Self), ViewRead<StoreError>> {
        let snap = store.begin_read().map_err(ViewRead::View)?;
        let view = SnapshotView::new(&snap);
        let tip = view.tip().map_err(ViewRead::View)?;
        let connecting = Tip::connecting_height(tip.as_ref());
        let medians = effective_median_at(&view, connecting)?;
        Ok((
            tip.map(|t| t.hash),
            Self::of_long_term(medians.long_term_effective_median.to_raw()),
        ))
    }

    /// The bound for a long-term effective median of `ltem` (module docs):
    /// the header bound plus twice the ceiling limit `2 · S · LTEM`.
    #[must_use]
    pub fn of_long_term(ltem: u64) -> Self {
        let ceiling_limit = ltem
            .saturating_mul(BLOCK_WEIGHT_SURGE_FACTOR)
            .saturating_mul(2);
        Self(
            u64::try_from(MAX_BLOCK_HEADER_SIZE)
                .expect("the header bound fits u64")
                .saturating_add(ceiling_limit.saturating_mul(2)),
        )
    }

    /// Whether an arrival of `bytes` is within it.
    #[must_use]
    pub fn admits(self, bytes: u64) -> bool {
        bytes <= self.0
    }
}

/// Tokens a session's bucket holds at most, and earns per target block
/// interval (module docs).
pub const TOKENS_PER_INTERVAL: u32 = 2;

/// The per-session buckets for unsolicited arrivals (module docs).
///
/// A bucket is kept only while it is below full: a session whose bucket
/// has refilled is the same as one never seen, so its entry is dropped when
/// the table is swept, and a session that announced once and left holds
/// nothing.
pub struct Buckets {
    /// The time one token takes to earn.
    per_token: Duration,
    /// Each session's credit, as earned time capped at a full bucket, and
    /// when it was last read.
    sessions: Mutex<HashMap<SessionId, Credit>>,
}

#[derive(Clone, Copy, Debug)]
struct Credit {
    earned: Duration,
    at: Duration,
}

/// Entries kept before a take sweeps the full ones out.
const SWEEP_AT: usize = 1024;

impl Buckets {
    /// Buckets refilling at [`TOKENS_PER_INTERVAL`] per `interval`.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            per_token: interval / TOKENS_PER_INTERVAL,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn full(&self) -> Duration {
        self.per_token * TOKENS_PER_INTERVAL
    }

    /// Take `n` tokens from `session`'s bucket at `now` (a monotonic
    /// reading), or none: `false` when it holds fewer.
    pub fn take(&self, session: SessionId, n: u32, now: Duration) -> bool {
        if n == 0 {
            return true;
        }
        let full = self.full();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if sessions.len() >= SWEEP_AT {
            sessions.retain(|_, c| c.earned + now.saturating_sub(c.at) < full);
        }
        let credit = sessions
            .get(&session)
            .map_or(full, |c| (c.earned + now.saturating_sub(c.at)).min(full));
        let cost = self.per_token * n;
        if credit < cost {
            sessions.insert(
                session,
                Credit {
                    earned: credit,
                    at: now,
                },
            );
            return false;
        }
        sessions.insert(
            session,
            Credit {
                earned: credit.saturating_sub(cost),
                at: now,
            },
        );
        true
    }

    /// Give `n` tokens back to `session` at `now`. A span that took them
    /// and was then refused did not accept the arrivals, so the bucket is
    /// as it was. A full bucket is the same as one never seen, and is not
    /// stored.
    pub fn give_back(&self, session: SessionId, n: u32, now: Duration) {
        if n == 0 {
            return;
        }
        let full = self.full();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let credit = sessions.get(&session).map_or(full, |credit| {
            (credit.earned + now.saturating_sub(credit.at)).min(full)
        });
        let restored = (credit + self.per_token * n).min(full);
        if restored >= full {
            sessions.remove(&session);
        } else {
            sessions.insert(
                session,
                Credit {
                    earned: restored,
                    at: now,
                },
            );
        }
    }

    /// Forget `session`: its connection closed.
    pub fn forget(&self, session: SessionId) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(120);

    #[test]
    fn two_per_interval_pass_and_the_third_waits_for_the_refill() {
        let buckets = Buckets::new(T);
        let s = SessionId(7);
        assert!(buckets.take(s, 1, Duration::ZERO));
        assert!(buckets.take(s, 1, Duration::ZERO));
        assert!(
            !buckets.take(s, 1, Duration::ZERO),
            "the third is throttled"
        );
        assert!(!buckets.take(s, 1, (T / 2).saturating_sub(Duration::from_millis(1))));
        assert!(
            buckets.take(s, 1, T / 2),
            "one token earned per half interval"
        );
        // A full bucket does not overfill: after a long silence, two again.
        assert!(buckets.take(s, 2, T * 100));
        assert!(!buckets.take(s, 1, T * 100));
        // Another session is its own bucket.
        assert!(buckets.take(SessionId(8), 2, T * 100));
    }

    #[test]
    fn a_refused_span_gives_its_tokens_back() {
        let buckets = Buckets::new(T);
        let s = SessionId(7);
        assert!(buckets.take(s, 2, Duration::ZERO));
        assert!(!buckets.take(s, 1, Duration::ZERO));
        buckets.give_back(s, 2, Duration::ZERO);
        assert!(
            buckets.take(s, 2, Duration::ZERO),
            "the refusal refunded the span"
        );
        assert!(!buckets.take(s, 1, Duration::ZERO));
    }

    #[test]
    fn a_refused_take_takes_nothing() {
        let buckets = Buckets::new(T);
        let s = SessionId(1);
        assert!(!buckets.take(s, 3, Duration::ZERO), "more than a bucket");
        assert!(buckets.take(s, 2, Duration::ZERO), "the refusal kept both");
    }

    #[test]
    fn the_bound_is_the_header_and_twice_the_ceiling_limit() {
        let ltem = 300_000;
        let bound = ArrivalBound::of_long_term(ltem);
        let header = u64::try_from(MAX_BLOCK_HEADER_SIZE).expect("fits");
        assert_eq!(bound.0, header + 2 * (2 * BLOCK_WEIGHT_SURGE_FACTOR * ltem));
        assert!(bound.admits(bound.0));
        assert!(!bound.admits(bound.0 + 1), "one byte over is refused");
    }
}
