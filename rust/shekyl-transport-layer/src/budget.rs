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
use std::time::{SystemTime, UNIX_EPOCH};

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// How many slots "recent" covers, and how long each slot is.
///
/// Ten seconds, in one-second slots. That is what an operator means by
/// the speed of a connection right now: long enough that one chunk is
/// not the whole reading, short enough that a connection which stopped
/// reads as stopped. The newest slot weighs [`SPEED_BUCKETS`], the
/// oldest weighs one. The divisor is that weight times the time the
/// slot actually covers, not a full window the connection may not have
/// lived through. Display only. It limits nothing.
const SPEED_BUCKETS: usize = 10;
const SPEED_SLOT_NS: u64 = 1_000_000_000;

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
    /// Unix milliseconds of the last byte this direction granted.
    /// Zero until one moves. The stall check and the operator view
    /// read this. It is not a board field.
    last_ms: u64,
}

/// Unix milliseconds. Zero when the clock is before the epoch.
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The instant a stall check compares, in unix milliseconds.
///
/// `recv_ms` is the last received byte. Zero means none has arrived, and
/// the mark is `started_ms`.
#[must_use]
pub const fn recv_mark_ms(recv_ms: u64, started_ms: u64) -> u64 {
    if recv_ms == 0 {
        started_ms
    } else {
        recv_ms
    }
}

/// Whether `now_ms` is more than `threshold_ms` after [`recv_mark_ms`].
#[must_use]
pub const fn recv_is_stalled(
    now_ms: u64,
    recv_ms: u64,
    started_ms: u64,
    threshold_ms: u64,
) -> bool {
    now_ms.saturating_sub(recv_mark_ms(recv_ms, started_ms)) > threshold_ms
}

/// The recent rate of one direction on one connection.
///
/// [`SPEED_BUCKETS`] slots of [`SPEED_SLOT_NS`]. Index 0 is the oldest
/// and weighs 1; the last index is the newest and weighs
/// [`SPEED_BUCKETS`]. The divisor is the weighted time actually
/// covered: the newest slot only for as much of it as has elapsed, and
/// nothing from before the connection started. Slots move forward from
/// the caller's clock on the next write or report. There is no timer.
/// A quiet connection reaches zero once every slot that held bytes has
/// left the window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pace {
    /// Oldest at index 0, newest at the last index.
    buckets: [u64; SPEED_BUCKETS],
    /// Start of the newest slot, on the caller's clock.
    slot_ns: u64,
    /// The clock reading of the first byte. Slots before this are not
    /// part of the window.
    origin_ns: u64,
    started: bool,
    saved: Option<SavedPace>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SavedPace {
    buckets: [u64; SPEED_BUCKETS],
    slot_ns: u64,
    origin_ns: u64,
    started: bool,
}

impl Pace {
    fn observe(&mut self, n: u64, now: u64) {
        self.saved = Some(SavedPace {
            buckets: self.buckets,
            slot_ns: self.slot_ns,
            origin_ns: self.origin_ns,
            started: self.started,
        });
        self.advance(now);
        let newest = &mut self.buckets[SPEED_BUCKETS - 1];
        *newest = newest.saturating_add(n);
    }

    fn undo(&mut self) {
        if let Some(saved) = self.saved.take() {
            self.buckets = saved.buckets;
            self.slot_ns = saved.slot_ns;
            self.origin_ns = saved.origin_ns;
            self.started = saved.started;
        }
    }

    fn shrink(&mut self, n: u64) {
        let newest = &mut self.buckets[SPEED_BUCKETS - 1];
        *newest = newest.saturating_sub(n);
    }

    /// Move slots forward to `now`. A jump of a whole window or more
    /// empties every slot. A clock reading behind the newest slot
    /// leaves the window where it is.
    fn advance(&mut self, now: u64) {
        if !self.started {
            self.slot_ns = now;
            self.origin_ns = now;
            self.started = true;
            return;
        }
        if now < self.slot_ns {
            return;
        }
        let steps = (now - self.slot_ns) / SPEED_SLOT_NS;
        let Ok(steps_us) = usize::try_from(steps) else {
            self.buckets = [0; SPEED_BUCKETS];
            self.slot_ns = now;
            return;
        };
        if steps_us == 0 {
            return;
        }
        if steps_us >= SPEED_BUCKETS {
            self.buckets = [0; SPEED_BUCKETS];
            self.slot_ns = now;
            return;
        }
        self.buckets.copy_within(steps_us.., 0);
        self.buckets[SPEED_BUCKETS - steps_us..].fill(0);
        self.slot_ns = self
            .slot_ns
            .saturating_add(steps.saturating_mul(SPEED_SLOT_NS));
    }

    fn bytes_per_sec(self, now: u64) -> u64 {
        let mut pace = self;
        pace.advance(now);
        if !pace.started {
            return 0;
        }
        let mut weighted_bytes = 0u128;
        let mut weighted_ns = 0u128;
        for i in 0..SPEED_BUCKETS {
            let Ok(index) = u128::try_from(i) else {
                continue;
            };
            let behind = SPEED_BUCKETS - 1 - i;
            let Some(start) = pace.slot_ns.checked_sub(
                u64::try_from(behind)
                    .unwrap_or(0)
                    .saturating_mul(SPEED_SLOT_NS),
            ) else {
                continue;
            };
            let end = if i + 1 == SPEED_BUCKETS {
                now.max(start)
            } else {
                start.saturating_add(SPEED_SLOT_NS)
            };
            let end = end.min(start.saturating_add(SPEED_SLOT_NS));
            let covered_start = start.max(pace.origin_ns);
            if end <= covered_start {
                continue;
            }
            let covered = u128::from(end - covered_start);
            let weight = index + 1;
            weighted_ns = weighted_ns.saturating_add(weight.saturating_mul(covered));
            weighted_bytes =
                weighted_bytes.saturating_add(weight.saturating_mul(u128::from(pace.buckets[i])));
        }
        if weighted_ns == 0 || weighted_bytes == 0 {
            return 0;
        }
        let numer = weighted_bytes.saturating_mul(NANOS_PER_SEC);
        u64::try_from(numer / weighted_ns).unwrap_or(u64::MAX)
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
        for flow in self.per.values_mut() {
            flow.pace = Pace::default();
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
        let flow = self.per.entry(conn).or_default();
        flow.bytes = flow.bytes.saturating_add(n);
        flow.pace.observe(n, now);
        flow.last_ms = unix_ms();
    }

    /// One message finished. A grant is not a message: a rate-limited
    /// write takes several grants and still counts once.
    fn record_message(&mut self, conn: u64) {
        self.total.packets = self.total.packets.saturating_add(1);
        let flow = self.per.entry(conn).or_default();
        flow.packets = flow.packets.saturating_add(1);
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
                flow.pace.undo();
            } else {
                flow.pace.shrink(n);
            }
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

    /// One message finished on `direction`. A grant is not a message.
    pub fn record_message(&mut self, direction: LinkDirection, conn: u64) {
        self.lane_mut(direction).record_message(conn);
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
    /// reached the socket, so the recent-speed mark for that grant comes
    /// back with the tokens. A message records its packet when it finishes,
    /// so a grant that never completed one has nothing to return.
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
    /// The window is [`SPEED_BUCKETS`] slots of [`SPEED_SLOT_NS`]. The
    /// reading advances to `now` without a timer. A connection with no
    /// bytes in that window is zero.
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

    /// Unix milliseconds of the last granted byte, `(send, recv)`.
    ///
    /// Zero until that direction has moved a byte. Written beside the
    /// tally [`Self::speed`] reads, on each granted chunk.
    #[must_use]
    pub fn activity_ms(&self, conn: u64) -> (u64, u64) {
        let send = self.up.per.get(&conn).map(|flow| flow.last_ms).unwrap_or(0);
        let recv = self
            .down
            .per
            .get(&conn)
            .map(|flow| flow.last_ms)
            .unwrap_or(0);
        (send, recv)
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
    use super::{recv_is_stalled, unix_ms, LinkBudget, LinkDirection, MessageClass, Turn};

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
    fn a_steady_rate_reads_back_as_that_rate() {
        assert_eq!(super::SPEED_BUCKETS, 10);
        assert_eq!(super::SPEED_SLOT_NS, SEC);
        let mut budget = LinkBudget::new();
        let conn = 4u64;
        let rate = 1_000u64;
        let mut now = 0u64;
        for _ in 0..super::SPEED_BUCKETS {
            assert_eq!(
                budget.take(LinkDirection::Up, conn, MessageClass::Session, rate, now),
                Turn::Granted(rate)
            );
            now += SEC;
        }
        assert_eq!(budget.speed(conn, now - SEC).0, rate);
    }

    #[test]
    fn a_steady_rate_mid_slot_and_on_a_young_connection_reads_back_as_that_rate() {
        let mut budget = LinkBudget::new();
        let conn = 9u64;
        let rate = 1_000u64;
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, rate / 2, 0),
            Turn::Granted(rate / 2)
        );
        assert_eq!(budget.speed(conn, SEC / 2).0, rate);
        assert_eq!(
            budget.take(
                LinkDirection::Up,
                conn,
                MessageClass::Session,
                rate / 2,
                SEC / 2
            ),
            Turn::Granted(rate / 2)
        );
        assert_eq!(
            budget.take(
                LinkDirection::Up,
                conn,
                MessageClass::Session,
                rate / 2,
                SEC + SEC / 2
            ),
            Turn::Granted(rate / 2)
        );
        assert_eq!(budget.speed(conn, SEC + SEC / 2).0, rate);
    }

    #[test]
    fn a_burst_lands_in_the_newest_bucket_and_ages_out() {
        let mut budget = LinkBudget::new();
        let conn = 5u64;
        let burst = 5_500u64;
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, burst, 0),
            Turn::Granted(burst)
        );
        assert_eq!(budget.speed(conn, SEC - 1).0, burst);
        assert_eq!(budget.speed(conn, 5 * SEC).0, 785);
        assert_eq!(budget.speed(conn, 0).1, 0);
    }

    #[test]
    fn an_idle_connection_is_zero_once_the_window_has_passed() {
        let mut budget = LinkBudget::new();
        let conn = 6u64;
        let window = super::SPEED_BUCKETS as u64 * SEC;
        assert_eq!(
            budget.take(LinkDirection::Down, conn, MessageClass::Session, 5_500, 0),
            Turn::Granted(5_500)
        );
        assert_eq!(budget.speed(conn, window - 1).1, 100);
        assert_eq!(budget.speed(conn, window).1, 0);
        assert_eq!(budget.speed(conn, window + SEC).1, 0);
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

    #[test]
    fn a_message_split_across_grants_counts_as_one_packet() {
        let mut budget = LinkBudget::new();
        let conn = 1u64;
        budget.set(LinkDirection::Up, Some(4), 0);
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, 10, 0),
            Turn::Granted(4)
        );
        assert_eq!(
            budget.take(LinkDirection::Up, conn, MessageClass::Session, 6, SEC),
            Turn::Granted(4)
        );
        assert_eq!(budget.totals().packets_up, 0);
        assert_eq!(budget.connection(conn).bytes_up, 8);
        budget.record_message(LinkDirection::Up, conn);
        assert_eq!(budget.totals().packets_up, 1);
        assert_eq!(budget.connection(conn).packets_up, 1);
        budget.refund(LinkDirection::Up, conn, 4, true);
        assert_eq!(
            budget.totals().packets_up,
            1,
            "a refund returns bytes, not the message"
        );
    }

    #[test]
    fn a_frame_in_pieces_over_two_seconds_is_not_stalled() {
        let mut budget = LinkBudget::new();
        let conn = 7u64;
        assert_eq!(budget.activity_ms(conn), (0, 0));
        assert!(!recv_is_stalled(1_000, 0, 0, 2_000));
        assert!(!recv_is_stalled(2_000, 0, 1_000, 2_000));
        assert!(recv_is_stalled(3_500, 0, 1_000, 2_000));
        assert_eq!(
            budget.take(LinkDirection::Down, conn, MessageClass::Session, 64, 0),
            Turn::Granted(64)
        );
        let (_, first) = budget.activity_ms(conn);
        assert!(first > 0, "the first piece stamps the receive instant");
        assert!(
            recv_is_stalled(first + 2_500, first, first, 2_000),
            "silence after the first piece is a stall"
        );
        std::thread::sleep(std::time::Duration::from_millis(2_100));
        assert_eq!(
            budget.take(LinkDirection::Down, conn, MessageClass::Session, 64, 1),
            Turn::Granted(64)
        );
        let (_, second) = budget.activity_ms(conn);
        let now = unix_ms();
        assert!(second >= first);
        assert!(
            now.saturating_sub(second) < 2_000,
            "the later piece is the mark, not the first"
        );
        assert!(!recv_is_stalled(now, second, first, 2_000));
    }
}
