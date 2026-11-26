// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Up to `SESSIONS_PER_CLIENT` sessions to one daemon under one grant.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hyper::body::Bytes;
use shekyl_rpc_channel::deadline::HANDSHAKE_DEADLINE;
use shekyl_rpc_channel::SESSIONS_PER_CLIENT;
use shekyl_rpc_grants::GrantSet;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use super::handshake::ChannelTarget;
use super::session::Session;
use super::ChannelFault;

/// How long a pool's extra session may sit idle before the pool closes it.
///
/// **Assumption** (Rick, 2026-11-15). Basis: a session costs each side
/// about 2.16 ms of CPU to open on the floor device (RT-P6), so an extra
/// closed after 30 s of quiet and opened again costs the daemon at most
/// 2.16 ms per 30 s, 0.0072 % of one core, for each extra. RT-P10 measures
/// the pool under load. The kept session idles at the record stream's own
/// limit (`shekyl_rpc_stream::RECORD_IDLE`), as the daemon's side does.
pub const EXTRA_SESSION_IDLE: Duration = Duration::from_secs(30);

/// How often a pool looks at its idle sessions.
const KEEPER_TICK: Duration = Duration::from_secs(1);

/// An idle session and when it became idle.
type Idle = (Session, tokio::time::Instant);

/// Up to `SESSIONS_PER_CLIENT` sessions to one daemon under one grant (§8).
pub struct Pool {
    target: ChannelTarget,
    request: GrantSet,
    slots: Arc<Semaphore>,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    /// The session the pool keeps however long it idles. Filled by the
    /// first session to become idle, and by the oldest extra when this one
    /// has closed.
    kept: Option<Idle>,
    /// Sessions beyond the kept one, oldest first. [`Pool::lend`] takes the
    /// newest. Each is closed after [`EXTRA_SESSION_IDLE`].
    extras: Vec<Idle>,
    /// Whether a session has been held: a refusal at message 3 after one is
    /// a revocation.
    held: bool,
    /// Why the pool stopped; it does not dial again.
    stopped: Option<ChannelFault>,
    /// The grant the daemon gave, once known.
    granted: Option<(GrantSet, GrantSet)>,
}

/// A session lent by the pool; given back with [`Pool::give_back`].
pub struct Lent {
    session: Session,
    _slot: OwnedSemaphorePermit,
}

impl Lent {
    /// The session.
    pub fn session(&mut self) -> &mut Session {
        &mut self.session
    }
}

/// Drop sessions the daemon has closed.
fn drop_closed(state: &mut PoolState) {
    if state
        .kept
        .as_ref()
        .is_some_and(|(session, _)| session.is_closed())
    {
        state.kept = None;
    }
    state.extras.retain(|(session, _)| !session.is_closed());
}

/// The newest extra, or the kept session when no extra is idle.
fn take_idle(state: &mut PoolState) -> Option<Session> {
    drop_closed(state);
    if let Some((session, _)) = state.extras.pop() {
        return Some(session);
    }
    state.kept.take().map(|(session, _)| session)
}

/// Put a live session back. The first idle session is the kept one; every
/// later one is an extra.
fn store_idle(state: &mut PoolState, session: Session) {
    if session.is_closed() {
        return;
    }
    let idle = (session, tokio::time::Instant::now());
    if state.kept.is_none() && state.extras.is_empty() {
        state.kept = Some(idle);
    } else {
        state.extras.push(idle);
    }
}

/// Which idle sessions survive `now`. The kept session stays whatever its
/// age. A missing kept session is filled by the oldest extra, even one
/// past [`EXTRA_SESSION_IDLE`], and every other extra past that limit goes.
/// `fresh` is true for an extra the pool still holds.
fn sweep_idle<T>(
    kept: Option<T>,
    mut extras: Vec<T>,
    fresh: impl Fn(&T) -> bool,
) -> (Option<T>, Vec<T>) {
    let kept = kept.or_else(|| (!extras.is_empty()).then(|| extras.remove(0)));
    extras.retain(|extra| fresh(extra));
    (kept, extras)
}

/// Apply [`sweep_idle`] to the pool's sessions, after dropping closed ones.
fn settle(state: &mut PoolState, now: tokio::time::Instant) {
    drop_closed(state);
    let kept = state.kept.take();
    let extras = std::mem::take(&mut state.extras);
    let (kept, extras) = sweep_idle(kept, extras, |(_, since)| {
        now.duration_since(*since) < EXTRA_SESSION_IDLE
    });
    state.kept = kept;
    state.extras = extras;
}

impl Pool {
    /// A pool to `target` asking for `request` on every session. Nothing is
    /// dialed until [`Self::open_kept`] or the first [`Self::lend`].
    #[must_use]
    pub fn new(target: ChannelTarget, request: GrantSet) -> Arc<Self> {
        Arc::new(Self {
            target,
            request,
            slots: Arc::new(Semaphore::new(SESSIONS_PER_CLIENT)),
            state: Mutex::new(PoolState::default()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The target.
    #[must_use]
    pub fn target(&self) -> &ChannelTarget {
        &self.target
    }

    /// Why the pool stopped, if it has.
    #[must_use]
    pub fn stopped(&self) -> Option<ChannelFault> {
        self.state().stopped.clone()
    }

    /// The ceiling and the grant the daemon gave, once a session opened.
    #[must_use]
    pub fn granted(&self) -> Option<(GrantSet, GrantSet)> {
        self.state().granted
    }

    /// Open the kept session now, so the grant is known and reported at
    /// start (§8, §6.2).
    ///
    /// # Errors
    ///
    /// [`ChannelFault`], as [`Self::lend`].
    pub async fn open_kept(&self) -> Result<(GrantSet, GrantSet), ChannelFault> {
        let mut lent = self.lend().await?;
        // Nothing else will be sent until a caller arrives. The daemon
        // closes a session that sends no record within the handshake
        // deadline, so the kept session confirms itself before it is parked.
        lent.session.confirm().await?;
        let granted = (lent.session.ceiling(), lent.session.granted());
        self.give_back(lent);
        Ok(granted)
    }

    /// A session for one exchange: an idle one, or a new one while the
    /// pool holds fewer than the cap; otherwise wait for one, bounded by
    /// the handshake deadline.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::PoolFull`] when none came free in time; the pool's
    /// stop; or why a new session did not open.
    pub async fn lend(&self) -> Result<Lent, ChannelFault> {
        if let Some(stopped) = self.stopped() {
            return Err(stopped);
        }
        let slot =
            tokio::time::timeout(HANDSHAKE_DEADLINE, Arc::clone(&self.slots).acquire_owned())
                .await
                .map_err(|_| ChannelFault::PoolFull)?
                .map_err(|_| ChannelFault::PoolFull)?;
        // The wait is the window in which a revocation lands. A dial after
        // it would open a session the pool has already stopped.
        if let Some(stopped) = self.stopped() {
            return Err(stopped);
        }
        let idle = {
            let mut state = self.state();
            take_idle(&mut state)
        };
        let session = match idle {
            Some(session) => session,
            None => self.open_session().await?,
        };
        Ok(Lent {
            session,
            _slot: slot,
        })
    }

    /// Give a session back after its exchange. A closed one is dropped.
    pub fn give_back(&self, lent: Lent) {
        let Lent { session, _slot } = lent;
        store_idle(&mut self.state(), session);
    }

    /// A closed exchange can be the first evidence of revocation. Recheck admission
    /// while holding this session's permit. The original call is never resent.
    pub(super) async fn closed_exchange(&self, lent: Lent) -> ChannelFault {
        let Lent { session, _slot } = lent;
        drop(session);
        if let Some(stopped) = self.stopped() {
            return stopped;
        }
        match self.open_session().await {
            Err(fault @ ChannelFault::Revoked { .. }) => fault,
            _ => ChannelFault::Closed,
        }
    }

    async fn open_session(&self) -> Result<Session, ChannelFault> {
        let opened = self.target.open(self.request).await;
        let opened = match opened {
            Ok(opened) => opened,
            Err(ChannelFault::NotEnrolled { fingerprint }) => {
                let mut state = self.state();
                let fault = if state.held {
                    ChannelFault::Revoked { fingerprint }
                } else {
                    ChannelFault::NotEnrolled { fingerprint }
                };
                state.stopped = Some(fault.clone());
                return Err(fault);
            }
            Err(
                fault @ (ChannelFault::NotTheDaemon { .. } | ChannelFault::NotRecognised { .. }),
            ) => {
                self.state().stopped = Some(fault.clone());
                return Err(fault);
            }
            Err(fault) => return Err(fault),
        };
        let session = Session::start(opened, None).await?;
        let mut state = self.state();
        state.held = true;
        state.granted = Some((session.ceiling(), session.granted()));
        Ok(session)
    }

    /// One exchange on a lent session, given back after.
    ///
    /// # Errors
    ///
    /// [`ChannelFault`], from the lending or the exchange.
    pub async fn send(
        &self,
        request: hyper::Request<Bytes>,
    ) -> Result<hyper::Response<Bytes>, ChannelFault> {
        let mut lent = self.lend().await?;
        let response = lent.session.send(request).await;
        self.give_back(lent);
        response
    }

    /// Close extras idle longer than [`EXTRA_SESSION_IDLE`], keeping one,
    /// and open the kept session again when the daemon has closed it.
    ///
    /// When the pool stops, `ended` receives the fault and this returns.
    /// A revocation found here, with no request in flight, is the same
    /// stop a request would report.
    pub async fn keep(self: Arc<Self>, ended: watch::Sender<Option<ChannelFault>>) {
        loop {
            tokio::time::sleep(KEEPER_TICK).await;
            if let Some(fault) = self.stopped() {
                ended.send_replace(Some(fault));
                return;
            }
            let reopen = {
                let mut state = self.state();
                settle(&mut state, tokio::time::Instant::now());
                state.kept.is_none()
                    && state.extras.is_empty()
                    && self.slots.available_permits() == SESSIONS_PER_CLIENT
            };
            if reopen {
                match self.lend().await {
                    Ok(mut lent) => {
                        if let Err(fault) = lent.session.confirm().await {
                            if let Some(stopped) = self.stopped() {
                                ended.send_replace(Some(stopped));
                                return;
                            }
                            tracing::warn!(
                                "the channel's kept session did not open again: {fault}"
                            );
                        } else {
                            self.give_back(lent);
                        }
                    }
                    Err(fault) => {
                        if let Some(stopped) = self.stopped() {
                            ended.send_replace(Some(stopped));
                            return;
                        }
                        tracing::warn!("the channel's kept session did not open again: {fault}");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kept session stays however long it idles. An extra past
    /// [`EXTRA_SESSION_IDLE`] goes, unless it is promoted into the empty
    /// kept slot. Red edit: return `kept` unchanged from `sweep_idle` and
    /// skip `extras.remove(0)`, and a closed kept session takes its oldest
    /// extra with it.
    #[test]
    fn the_kept_session_stays_and_idle_extras_go() {
        let now = tokio::time::Instant::now() + Duration::from_secs(3_600);
        let old = now - EXTRA_SESSION_IDLE - Duration::from_secs(1);
        let fresh = now - Duration::from_secs(1);
        let still = |since: &tokio::time::Instant| now.duration_since(*since) < EXTRA_SESSION_IDLE;

        let (kept, extras) = sweep_idle(Some(old), vec![old, fresh], still);
        assert_eq!(kept, Some(old));
        assert_eq!(extras, vec![fresh]);

        let (kept, extras) = sweep_idle(None, vec![old, fresh], still);
        assert_eq!(kept, Some(old));
        assert_eq!(extras, vec![fresh]);

        let (kept, extras) = sweep_idle(None, Vec::<tokio::time::Instant>::new(), still);
        assert!(kept.is_none());
        assert!(extras.is_empty());
    }
}
