// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The operator's link budget.
//!
//! One token bucket per direction, for the whole node, across every
//! connector. The refill is the operator's rate, computed from the
//! clock the caller passes in, so the bucket has no timer. Capacity is
//! one second of that rate, and the bucket starts full. Unlimited is
//! the absence of a bucket.
//!
//! Connections that want a direction are served in turn, one chunk
//! each. An empty bucket pauses that connection. It does not close it,
//! and it does not drop the bytes. [`MessageClass::Session`] is the
//! only class; the argument is what a later class fills.

use std::collections::{HashMap, VecDeque};

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Which way the bytes are moving. Up leaves the node. Down arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    Up,
    Down,
}

/// What a send is, for the writer's schedule.
///
/// One class exists. Naming another fills this argument. It does not
/// replace the bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Session,
}

/// What one connection may do with the direction right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    /// Write or read this many bytes. A short grant is the rest of the
    /// chunk still waiting for a later turn.
    Granted(u64),
    /// The bucket is empty. The connection stays open. `ready_ns` is
    /// when one byte exists on the same clock `take` was given.
    /// [`u64::MAX`] means the rate is zero, so only a new rate wakes it.
    Paused { ready_ns: u64 },
    /// Another connection is ahead in this direction.
    Wait,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Flow {
    bytes: u64,
    packets: u64,
    pace: Pace,
}

/// The recent rate of one direction on one connection.
///
/// The sample is the last gap between chunks: those bytes over that
/// gap. Idle time after the chunk dilutes the same bytes, so a quiet
/// connection falls toward zero when the speed is read. There is no
/// timer and no separate window. One chunk has no gap yet, so its
/// rate is zero until the next one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pace {
    bytes: u64,
    span_ns: u64,
    at_ns: u64,
    started: bool,
    saved: Option<SavedPace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SavedPace {
    bytes: u64,
    span_ns: u64,
    at_ns: u64,
    started: bool,
}

impl Pace {
    fn observe(&mut self, n: u64, now: u64) {
        self.saved = Some(SavedPace {
            bytes: self.bytes,
            span_ns: self.span_ns,
            at_ns: self.at_ns,
            started: self.started,
        });
        if self.started && now > self.at_ns {
            self.span_ns = now - self.at_ns;
            self.bytes = n;
            self.at_ns = now;
        } else if self.started {
            self.bytes = self.bytes.saturating_add(n);
        } else {
            self.bytes = n;
            self.span_ns = 0;
            self.at_ns = now;
            self.started = true;
        }
    }

    fn undo(&mut self) {
        if let Some(saved) = self.saved.take() {
            self.bytes = saved.bytes;
            self.span_ns = saved.span_ns;
            self.at_ns = saved.at_ns;
            self.started = saved.started;
        }
    }

    fn shrink(&mut self, n: u64) {
        self.bytes = self.bytes.saturating_sub(n);
    }

    fn bytes_per_sec(self, now: u64) -> u64 {
        if !self.started || self.span_ns == 0 {
            return 0;
        }
        let denom =
            u128::from(self.span_ns).saturating_add(u128::from(now.saturating_sub(self.at_ns)));
        if denom == 0 {
            return 0;
        }
        let numer = u128::from(self.bytes).saturating_mul(1_000_000_000);
        u64::try_from(numer / denom).unwrap_or(u64::MAX)
    }
}

struct Bucket {
    /// Bytes per second. Also the capacity: one second of the rate.
    rate: u64,
    tokens: u64,
    /// Sub-byte credit, in the numerator of `rate * elapsed / 1e9`.
    residue: u64,
    last: Option<u64>,
}

impl Bucket {
    fn full(rate: u64, now: u64) -> Self {
        Self {
            rate,
            tokens: rate,
            residue: 0,
            last: Some(now),
        }
    }

    fn refill(&mut self, now: u64) {
        let Some(last) = self.last else {
            self.last = Some(now);
            return;
        };
        self.last = Some(now);
        if now <= last || self.tokens >= self.rate {
            if self.tokens >= self.rate {
                self.residue = 0;
            }
            return;
        }
        let elapsed = u128::from(now - last);
        let product = u128::from(self.rate) * elapsed + u128::from(self.residue);
        let add = product / NANOS_PER_SEC;
        self.residue = u64::try_from(product % NANOS_PER_SEC).unwrap_or(0);
        let room = self.rate - self.tokens;
        let add = u64::try_from(add).unwrap_or(u64::MAX).min(room);
        self.tokens += add;
        if self.tokens == self.rate {
            self.residue = 0;
        }
    }

    fn nanos_until_one_byte(&self) -> u64 {
        if self.rate == 0 {
            return u64::MAX;
        }
        let need = NANOS_PER_SEC.saturating_sub(u128::from(self.residue));
        let elapsed = need.div_ceil(u128::from(self.rate));
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }
}

struct Lane {
    bucket: Option<Bucket>,
    queue: VecDeque<u64>,
    total: Flow,
    per: HashMap<u64, Flow>,
}

impl Lane {
    fn new() -> Self {
        Self {
            bucket: None,
            queue: VecDeque::new(),
            total: Flow::default(),
            per: HashMap::new(),
        }
    }

    fn set_rate(&mut self, bytes_per_sec: Option<u64>, now: u64) {
        self.bucket = bytes_per_sec.map(|rate| Bucket::full(rate, now));
    }

    fn rate(&self) -> Option<u64> {
        self.bucket.as_ref().map(|bucket| bucket.rate)
    }

    fn forget_mark(&mut self) {
        if let Some(bucket) = self.bucket.as_mut() {
            bucket.last = None;
        }
    }

    fn join(&mut self, conn: u64) {
        if !self.queue.contains(&conn) {
            self.queue.push_back(conn);
        }
    }

    fn leave(&mut self, conn: u64) {
        self.queue.retain(|id| *id != conn);
    }

    fn note(&mut self, conn: u64, n: u64, now: u64) {
        if n == 0 {
            return;
        }
        self.total.bytes = self.total.bytes.saturating_add(n);
        self.total.packets = self.total.packets.saturating_add(1);
        let flow = self.per.entry(conn).or_default();
        flow.bytes = flow.bytes.saturating_add(n);
        flow.packets = flow.packets.saturating_add(1);
        flow.pace.observe(n, now);
    }

    fn refund(&mut self, conn: u64, n: u64, whole_grant: bool) {
        if n == 0 && !whole_grant {
            return;
        }
        if let Some(bucket) = self.bucket.as_mut() {
            let room = bucket.rate.saturating_sub(bucket.tokens);
            bucket.tokens = bucket.tokens.saturating_add(n.min(room));
        }
        self.total.bytes = self.total.bytes.saturating_sub(n);
        if let Some(flow) = self.per.get_mut(&conn) {
            flow.bytes = flow.bytes.saturating_sub(n);
            if whole_grant {
                flow.packets = flow.packets.saturating_sub(1);
                flow.pace.undo();
            } else {
                flow.pace.shrink(n);
            }
        }
        if whole_grant {
            self.total.packets = self.total.packets.saturating_sub(1);
        }
    }

    fn take(&mut self, conn: u64, class: MessageClass, want: u64, now: u64) -> Turn {
        let _ = class;
        if want == 0 {
            return Turn::Granted(0);
        }
        self.join(conn);
        if self.queue.front() != Some(&conn) {
            return Turn::Wait;
        }
        let Some(bucket) = self.bucket.as_mut() else {
            self.queue.pop_front();
            self.note(conn, want, now);
            return Turn::Granted(want);
        };
        bucket.refill(now);
        if bucket.tokens == 0 {
            let wait = bucket.nanos_until_one_byte();
            let ready_ns = if wait == u64::MAX {
                u64::MAX
            } else {
                now.saturating_add(wait)
            };
            return Turn::Paused { ready_ns };
        }
        let n = want.min(bucket.tokens);
        bucket.tokens -= n;
        self.queue.pop_front();
        self.note(conn, n, now);
        Turn::Granted(n)
    }
}

/// Both directions of the operator's budget.
///
/// A fresh budget is unlimited. [`Self::set`] installs a bucket, or
/// clears it. Bytes already counted stay: they are what moved, not a
/// second limit.
pub struct LinkBudget {
    up: Lane,
    down: Lane,
}

/// Bytes and packets a direction has moved. Observed, not a limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    pub bytes_up: u64,
    pub packets_up: u64,
    pub bytes_down: u64,
    pub packets_down: u64,
}

impl LinkBudget {
    #[must_use]
    pub fn new() -> Self {
        Self {
            up: Lane::new(),
            down: Lane::new(),
        }
    }

    fn lane_mut(&mut self, direction: LinkDirection) -> &mut Lane {
        match direction {
            LinkDirection::Up => &mut self.up,
            LinkDirection::Down => &mut self.down,
        }
    }

    fn lane(&self, direction: LinkDirection) -> &Lane {
        match direction {
            LinkDirection::Up => &self.up,
            LinkDirection::Down => &self.down,
        }
    }

    /// `None` removes the bucket. `Some(0)` is a bucket that grants
    /// nothing. `now` is the clock reading at the change, and the new
    /// bucket starts full.
    pub fn set(&mut self, direction: LinkDirection, bytes_per_sec: Option<u64>, now: u64) {
        self.lane_mut(direction).set_rate(bytes_per_sec, now);
    }

    #[must_use]
    pub fn rate(&self, direction: LinkDirection) -> Option<u64> {
        self.lane(direction).rate()
    }

    /// The next clock reading must not be mixed with the previous
    /// origin. Called when the engine clock replaces the interim one.
    pub fn forget_marks(&mut self) {
        self.up.forget_mark();
        self.down.forget_mark();
    }

    /// One connection asks to move `want` wire bytes.
    ///
    /// `class` is the schedule's input. With one class, the turn is the
    /// schedule.
    pub fn take(
        &mut self,
        direction: LinkDirection,
        conn: u64,
        class: MessageClass,
        want: u64,
        now: u64,
    ) -> Turn {
        self.lane_mut(direction).take(conn, class, want, now)
    }

    /// The connection no longer wants this direction. A paused head
    /// must not keep the turn after it has gone.
    pub fn leave(&mut self, direction: LinkDirection, conn: u64) {
        self.lane_mut(direction).leave(conn);
    }

    /// Give unused tokens back. `whole_grant` means none of that grant
    /// reached the socket, so the packet count comes back with them.
    pub fn refund(&mut self, direction: LinkDirection, conn: u64, bytes: u64, whole_grant: bool) {
        self.lane_mut(direction).refund(conn, bytes, whole_grant);
    }

    #[must_use]
    pub fn totals(&self) -> Observed {
        Observed {
            bytes_up: self.up.total.bytes,
            packets_up: self.up.total.packets,
            bytes_down: self.down.total.bytes,
            packets_down: self.down.total.packets,
        }
    }

    /// Bytes per second on this connection, as of `now`.
    ///
    /// The last gap between chunks, diluted by any idle time since.
    /// A connection with one chunk so far is zero: there is no gap yet.
    #[must_use]
    pub fn speed(&self, conn: u64, now: u64) -> (u64, u64) {
        let up = self
            .up
            .per
            .get(&conn)
            .map(|flow| flow.pace.bytes_per_sec(now))
            .unwrap_or(0);
        let down = self
            .down
            .per
            .get(&conn)
            .map(|flow| flow.pace.bytes_per_sec(now))
            .unwrap_or(0);
        (up, down)
    }

    /// What this connection has moved. Absent means nothing yet.
    #[must_use]
    pub fn connection(&self, conn: u64) -> Observed {
        let up = self.up.per.get(&conn).copied().unwrap_or_default();
        let down = self.down.per.get(&conn).copied().unwrap_or_default();
        Observed {
            bytes_up: up.bytes,
            packets_up: up.packets,
            bytes_down: down.bytes,
            packets_down: down.packets,
        }
    }
}

impl Default for LinkBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkBudget, LinkDirection, MessageClass, Turn};

    const SEC: u64 = 1_000_000_000;

    fn drain(budget: &mut LinkBudget, direction: LinkDirection, conn: u64, end: u64) -> u64 {
        let mut now = 0u64;
        let mut total = 0u64;
        loop {
            match budget.take(direction, conn, MessageClass::Session, 10_000, now) {
                Turn::Granted(n) => total += n,
                Turn::Paused { ready_ns } => {
                    if ready_ns > end || ready_ns <= now {
                        break;
                    }
                    now = ready_ns;
                }
                Turn::Wait => panic!("one connection has the turn"),
            }
        }
        total
    }

    #[test]
    fn a_configured_rate_stays_within_the_burst_plus_the_rate() {
        for direction in [LinkDirection::Up, LinkDirection::Down] {
            let mut budget = LinkBudget::new();
            let rate = 1_000u64;
            let span = 5 * SEC;
            budget.set(direction, Some(rate), 0);
            let total = drain(&mut budget, direction, 1, span);
            let allowance = rate + rate * span / SEC;
            assert!(
                total <= allowance,
                "{direction:?} moved {total}, allowance {allowance}"
            );
            assert!(
                total + rate >= allowance,
                "{direction:?} moved {total}, allowance {allowance}"
            );
        }
    }

    #[test]
    fn two_connections_sharing_a_direction_each_make_progress() {
        for direction in [LinkDirection::Up, LinkDirection::Down] {
            let mut budget = LinkBudget::new();
            budget.set(direction, Some(100), 0);
            let mut sent = [0u64; 2];
            for _ in 0..20 {
                for (i, conn) in [7u64, 8u64].into_iter().enumerate() {
                    match budget.take(direction, conn, MessageClass::Session, 10, 0) {
                        Turn::Granted(n) => sent[i] += n,
                        Turn::Paused { .. } | Turn::Wait => {}
                    }
                }
            }
            assert!(sent[0] > 0, "{direction:?} starved the first");
            assert!(sent[1] > 0, "{direction:?} starved the second");
            assert!(sent[0] + sent[1] <= 100);
            assert!(sent[0].abs_diff(sent[1]) <= 10);
        }
    }

    #[test]
    fn an_empty_bucket_pauses_and_does_not_close() {
        let mut budget = LinkBudget::new();
        budget.set(LinkDirection::Up, Some(4), 0);
        assert_eq!(
            budget.take(LinkDirection::Up, 3, MessageClass::Session, 4, 0),
            Turn::Granted(4)
        );
        match budget.take(LinkDirection::Up, 3, MessageClass::Session, 4, 0) {
            Turn::Paused { ready_ns } => assert!(ready_ns > 0 && ready_ns != u64::MAX),
            other => panic!("empty bucket returned {other:?}"),
        }
        assert_eq!(
            budget.take(LinkDirection::Up, 3, MessageClass::Session, 4, SEC),
            Turn::Granted(4)
        );
        assert_eq!(budget.connection(3).bytes_up, 8);
    }

    #[test]
    fn current_speed_is_the_last_gap_and_idle_time_dilutes_it() {
        let mut budget = LinkBudget::new();
        let conn = 4u64;
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, 1_000, 0),
            Turn::Granted(1_000)
        );
        assert_eq!(budget.speed(conn, 0).0, 0);
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, 1_000, SEC),
            Turn::Granted(1_000)
        );
        assert_eq!(budget.speed(conn, SEC).0, 1_000);
        assert_eq!(budget.speed(conn, 2 * SEC).0, 500);
    }

    #[test]
    fn a_zero_rate_pauses_until_the_rate_changes() {
        let mut budget = LinkBudget::new();
        budget.set(LinkDirection::Down, Some(0), 0);
        match budget.take(LinkDirection::Down, 1, MessageClass::Session, 1, 0) {
            Turn::Paused { ready_ns } => assert_eq!(ready_ns, u64::MAX),
            other => panic!("zero rate returned {other:?}"),
        }
        budget.set(LinkDirection::Down, None, SEC);
        assert_eq!(
            budget.take(LinkDirection::Down, 1, MessageClass::Session, 50, SEC),
            Turn::Granted(50)
        );
    }

    #[test]
    fn unlimited_applies_no_limit() {
        let mut budget = LinkBudget::new();
        assert!(budget.rate(LinkDirection::Up).is_none());
        assert!(budget.rate(LinkDirection::Down).is_none());
        assert_eq!(
            budget.take(LinkDirection::Up, 1, MessageClass::Session, 1_000_000, 0),
            Turn::Granted(1_000_000)
        );
        assert_eq!(
            budget.take(LinkDirection::Down, 1, MessageClass::Session, 1_000_000, 0),
            Turn::Granted(1_000_000)
        );
        budget.set(LinkDirection::Up, Some(8), 0);
        budget.set(LinkDirection::Up, None, 0);
        assert_eq!(
            budget.take(LinkDirection::Up, 2, MessageClass::Session, 1_000_000, 0),
            Turn::Granted(1_000_000)
        );
    }
}
