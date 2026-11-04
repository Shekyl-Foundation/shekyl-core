// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Records of what is in flight. The owner times its log and its phase
//! profile from them. Nothing it sends or decides reads them.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::session::Session;

/// Header requests, body requests, and seat waits, by the session or tag
/// they belong to.
#[derive(Default)]
pub(crate) struct Transit {
    /// When the session's header request was sent. `Event::Headers` carries
    /// no request id, so the key is the session: a second request sent
    /// before the first is answered times the answer from the later send.
    headers: HashMap<Session, Instant>,
    /// When the session's body request was sent, and how many blocks it named.
    bodies: HashMap<Session, (Instant, usize)>,
    /// Arrivals the door refused for room: when the first refusal came, and
    /// the session that served the body. A span's seat wait is the earliest
    /// of its tags.
    seats: HashMap<u64, (Instant, Session)>,
}

impl Transit {
    /// The session closed. Its requests and its seat waits are gone.
    pub(crate) fn forget_session(&mut self, session: Session) {
        self.headers.remove(&session);
        self.bodies.remove(&session);
        self.seats.retain(|_, (_, served_by)| *served_by != session);
    }

    pub(crate) fn note_headers(&mut self, session: Session, at: Instant) {
        self.headers.insert(session, at);
    }

    pub(crate) fn take_headers(&mut self, session: Session) -> Option<Instant> {
        self.headers.remove(&session)
    }

    pub(crate) fn note_bodies(&mut self, session: Session, at: Instant, blocks: usize) {
        self.bodies.insert(session, (at, blocks));
    }

    pub(crate) fn take_bodies(&mut self, session: Session) -> Option<(Instant, usize)> {
        self.bodies.remove(&session)
    }

    /// Time a seat wait from the first refusal. A body refused again keeps it.
    pub(crate) fn note_seat(&mut self, tag: u64, at: Instant, session: Session) {
        self.seats.entry(tag).or_insert((at, session));
    }

    /// The earliest seat wait among `tags`, removed. `None` when the door
    /// seated the span the first time.
    pub(crate) fn take_seat_wait(
        &mut self,
        tags: impl IntoIterator<Item = u64>,
    ) -> Option<Duration> {
        tags.into_iter()
            .filter_map(|tag| self.seats.remove(&tag))
            .map(|(since, _)| since)
            .min()
            .map(|since| since.elapsed())
    }
}

/// `d` in microseconds, for a log field.
pub(crate) fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}
