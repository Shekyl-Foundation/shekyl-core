// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The requests the driver runs off the loop (`TOR_SUPERVISOR.md` §4.11;
//! Rick, 2026-11-10: the supervisor never awaits Tor).
//!
//! A request is a control ask, or the launch. The driver sends it and goes
//! back to its inbox; the reply comes later as one more arrival, and its
//! last input is [`Input::Replied`]. So a status question or the stop is
//! taken while Tor is slow to answer, which is when an operator asks.
//!
//! One request is in flight at a time, as when the loop awaited each one:
//! moving the waits off the loop changes no decision. The list is that
//! whole decision, in the order the awaits gave it. The reap of an
//! incarnation that ended goes before the next launch; a launch is followed
//! by the event subscription and then the first sample; a republish is
//! `DEL_ONION` and then `ADD_ONION`. A probe, a route publish, and a
//! progress line ordered after a request stay behind it until the reply is
//! folded. The reply's own decisions join after that request's follower and
//! ahead of the tail ([`Core::begin_reply_fold`]). A request, or a probe,
//! that no longer stands when its turn comes ([`Core::action_stands`]) is
//! withheld there.
//!
//! The reply bound is a deadline here, one bound after the send in the
//! core's clock: awake time, restarted at a wake as every other window is.
//! A reply past it is [`Cause::ReplyLate`], a process fault. Each sent
//! request has a number; a reply names the number it answers, and one that
//! names any other is from a request this core no longer waits on.
//!
//! [`Input::Replied`]: super::Input::Replied
//! [`Cause::ReplyLate`]: super::Cause::ReplyLate

use std::collections::VecDeque;

use super::Action;
use crate::control::RelayFingerprint;

/// An action the loop used to run only after the request it followed.
/// While a request is out, it joins the tail, so a dial, a route publish,
/// or a progress line cannot start on state the reply has not folded.
/// Speech and local bookkeeping do not: an operator hears a cause while
/// Tor is slow.
fn waits_for_reply(action: &Action) -> bool {
    matches!(
        action,
        Action::Probe
            | Action::ProbeAfterJump
            | Action::Publish(_)
            | Action::SayProgress
            | Action::WatchState
            | Action::CheckPin
    )
}

/// A request the driver runs off the loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Request {
    /// Stop and reap the incarnation that ended, keeping its directory for
    /// the next launch ([`Action::Reap`]). It waits Tor's grace for an exit,
    /// so it runs off the loop like any other request.
    Reap,
    /// Launch Tor ([`Action::Spawn`]).
    Launch { fresh_directory: bool },
    /// Subscribe to the supervisor's events ([`Action::SubscribeEvents`]).
    Subscribe,
    /// The sample and the consensus clock ([`Action::Sample`]).
    Sample,
    /// `SETCONF AvoidDiskWrites=1` ([`Action::SetConfAvoidDiskWrites`]).
    DeferDiskWrites,
    /// `DEL_ONION`, the first half of a republish ([`Action::RepublishOnion`]).
    DeleteOnion,
    /// `ADD_ONION`, its second half ([`Action::AddOnion`]).
    AddOnion,
    /// `HSFETCH` of this node's own onion ([`Action::RefetchDescriptor`]).
    Refetch,
    /// The directories to check ([`Action::CheckDirectories`]).
    CheckDirectories,
    /// One directory fetch ([`Action::FetchFromDirectory`]).
    FetchFrom { hsdir: RelayFingerprint },
}

impl Request {
    /// The requests a decision becomes, in the order they are sent. `None`
    /// for an action the driver performs on the loop.
    pub(super) fn of(action: &Action) -> Option<Vec<Self>> {
        Some(match action {
            Action::Reap => vec![Self::Reap],
            Action::Spawn { fresh_directory } => vec![
                Self::Launch {
                    fresh_directory: *fresh_directory,
                },
                Self::Subscribe,
            ],
            Action::Sample => vec![Self::Sample],
            Action::SetConfAvoidDiskWrites => vec![Self::DeferDiskWrites],
            Action::RepublishOnion => vec![Self::DeleteOnion, Self::AddOnion],
            Action::RefetchDescriptor => vec![Self::Refetch],
            Action::CheckDirectories => vec![Self::CheckDirectories],
            Action::FetchFromDirectory { hsdir } => vec![Self::FetchFrom { hsdir: *hsdir }],
            _ => return None,
        })
    }

    /// The action that sends this request.
    pub(super) fn action(&self) -> Action {
        match self {
            Self::Reap => Action::Reap,
            Self::Launch { fresh_directory } => Action::Spawn {
                fresh_directory: *fresh_directory,
            },
            Self::Subscribe => Action::SubscribeEvents,
            Self::Sample => Action::Sample,
            Self::DeferDiskWrites => Action::SetConfAvoidDiskWrites,
            Self::DeleteOnion => Action::RepublishOnion,
            Self::AddOnion => Action::AddOnion,
            Self::Refetch => Action::RefetchDescriptor,
            Self::CheckDirectories => Action::CheckDirectories,
            Self::FetchFrom { hsdir } => Action::FetchFromDirectory { hsdir: *hsdir },
        }
    }

    /// The request that follows this one in the same decision, and goes
    /// only if this one was answered: a refused delete sends no add. A
    /// failed launch ends the incarnation, which clears the queue.
    pub(super) fn follows(&self) -> bool {
        matches!(self, Self::Subscribe | Self::AddOnion)
    }

    /// A read that asks the same question each time. One already waiting
    /// answers a second: a sample deadline can come due while a slow Tor
    /// has not yet answered the last sample, which the awaiting loop never
    /// saw.
    fn repeats(&self) -> bool {
        matches!(self, Self::Sample)
    }
}

/// One entry in the decision list.
#[derive(Debug)]
enum Work {
    /// The driver runs this on the loop. It does not wait on Tor.
    Now(Action),
    /// The driver sends this. Nothing after it runs until the reply is folded.
    Ask(Request),
}

impl Work {
    /// This ask is the second half of the request in flight: the
    /// subscription after a launch, the add after a delete.
    fn is_follower(&self) -> bool {
        matches!(self, Self::Ask(request) if request.follows())
    }

    fn request(&self) -> Option<&Request> {
        match self {
            Self::Ask(request) => Some(request),
            Self::Now(_) => None,
        }
    }
}

/// The request in flight: what it is, its number, and when it was sent.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InFlight {
    request: Request,
    number: u64,
    sent_at: u64,
}

/// The decision list, and the one request in flight.
///
/// `queued` is what has not run. While a reply is being folded,
/// [`Requests::reply_at`] is where that reply's decisions are inserted:
/// after the in-flight request's follower, and ahead of the tail. Any
/// other decision appends, so a deadline that comes due during the wait
/// joins the tail.
#[derive(Debug, Default)]
pub(super) struct Requests {
    queued: VecDeque<Work>,
    in_flight: Option<InFlight>,
    /// The number the next sent request takes.
    next: u64,
    /// The request in flight was refused (a `DEL_ONION` Tor declined):
    /// what follows it in the same decision is not sent.
    refused: bool,
    /// Where the reply being folded inserts its decisions. `None` appends.
    reply_at: Option<usize>,
}

impl Requests {
    fn contains(&self, request: &Request) -> bool {
        self.queued
            .iter()
            .any(|work| work.request() == Some(request))
            || self
                .in_flight
                .as_ref()
                .is_some_and(|flight| flight.request == *request)
    }

    /// A publication (its `DEL_ONION` or its `ADD_ONION`) is queued or in
    /// flight.
    fn publishing(&self) -> bool {
        let publication =
            |request: &Request| matches!(request, Request::DeleteOnion | Request::AddOnion);
        self.queued
            .iter()
            .any(|work| work.request().is_some_and(publication))
            || self
                .in_flight
                .as_ref()
                .is_some_and(|flight| publication(&flight.request))
    }

    /// Join `work` to the list: into the reply being folded, or at the end.
    fn join(&mut self, work: Work) {
        if let Some(cursor) = self.reply_at {
            let at = cursor.min(self.queued.len());
            self.queued.insert(at, work);
            self.reply_at = Some(at + 1);
        } else {
            self.queued.push_back(work);
        }
    }

    fn push_request(&mut self, request: Request) {
        if request.repeats() && self.contains(&request) {
            return;
        }
        self.join(Work::Ask(request));
    }

    fn push_now(&mut self, action: Action) {
        self.join(Work::Now(action));
    }

    /// The driver is folding the in-flight reply. Its decisions join after
    /// that request's follower. A second call in the same fold does nothing.
    fn begin_reply_fold(&mut self) {
        if self.in_flight.is_none() || self.reply_at.is_some() {
            return;
        }
        let at = self
            .queued
            .iter()
            .position(|work| !work.is_follower())
            .unwrap_or(self.queued.len());
        self.reply_at = Some(at);
    }

    /// The next entry, when the caller is ready to run the list.
    fn pop_front(&mut self) -> Option<Work> {
        self.queued.pop_front()
    }

    /// Drop the ask that follows the one just withheld or refused.
    fn drop_follower(&mut self) {
        if self.queued.front().is_some_and(Work::is_follower) {
            self.queued.pop_front();
        }
    }

    /// `request` was sent at `now`.
    fn sent(&mut self, request: Request, now: u64) {
        self.refused = false;
        self.next = self.next.wrapping_add(1);
        self.in_flight = Some(InFlight {
            request,
            number: self.next,
            sent_at: now,
        });
    }

    /// The number of the request in flight. A reply that names another is
    /// not this core's to fold.
    fn in_flight(&self) -> Option<u64> {
        self.in_flight.as_ref().map(|flight| flight.number)
    }

    /// The reply being folded refused its request.
    pub(super) fn refuse(&mut self) {
        if self.in_flight.is_some() {
            self.refused = true;
        }
    }

    /// The request in flight was answered: `false` when `number` is not it.
    /// A refused one drops what follows it. The reply fold ends either way
    /// it matches.
    fn answered(&mut self, number: u64) -> bool {
        if self.in_flight() != Some(number) {
            return false;
        }
        self.in_flight = None;
        self.reply_at = None;
        if std::mem::take(&mut self.refused) {
            self.drop_follower();
        }
        true
    }

    /// When the request in flight is late.
    pub(super) fn due(&self, bound: u64) -> Option<u64> {
        self.in_flight
            .as_ref()
            .map(|flight| flight.sent_at.saturating_add(bound))
    }

    /// The machine woke: the bound starts again from the wake, as every
    /// other window does (`TSR-M8`).
    pub(super) fn restart(&mut self, now: u64) {
        if let Some(flight) = &mut self.in_flight {
            flight.sent_at = now;
        }
    }

    /// The incarnation ended, or the node is stopping: nothing queued is
    /// sent, and a reply still on its way is not folded.
    pub(super) fn clear(&mut self) {
        self.queued.clear();
        self.in_flight = None;
        self.reply_at = None;
        self.refused = false;
    }
}

impl super::Core {
    /// The number of the request in flight. The driver tags the reply with
    /// it: [`super::Input::Replied`] carries it back.
    #[must_use]
    pub fn in_flight(&self) -> Option<u64> {
        self.requests.in_flight()
    }

    /// The driver is about to fold the in-flight request's answer.
    ///
    /// Decisions that fold produces join after that request's follower and
    /// ahead of every decision already waiting. [`super::Input::Replied`]
    /// ends the fold and releases that prefix. A deadline that arrived
    /// before this call stays in the tail.
    pub fn begin_reply_fold(&mut self) {
        self.requests.begin_reply_fold();
    }

    /// Queue `actions` in decision order, then run a prefix: every loop
    /// action up to the first request, then that one request. The tail
    /// waits until the request in flight is answered. While one is in
    /// flight the tail is not run, so a probe or a route publish ordered
    /// after a sample cannot start before the sample is folded.
    pub(super) fn route_requests(&mut self, now: u64, actions: Vec<Action>) -> Vec<Action> {
        let mut immediate = Vec::new();
        for action in actions {
            match Request::of(&action) {
                // One publication at a time. The onion stays owed until the
                // add is answered, so a sample deadline or the endpoint
                // coming back while one is out asks for it again. That ask
                // is already being answered, and a second delete queued
                // behind it would remove the service the first one
                // publishes. A remedial republish folded in here is sent by
                // the publication already out: its answer settles the
                // republish's state as its own.
                Some(_) if action == Action::RepublishOnion && self.requests.publishing() => {}
                Some(requests) => {
                    for request in requests {
                        self.requests.push_request(request);
                    }
                }
                // Speech and bookkeeping run in this step. A dial, a route
                // publish, a progress line, and a pin check keep their place
                // in the list, behind the request they follow.
                None if !waits_for_reply(&action) => immediate.push(action),
                None => self.requests.push_now(action),
            }
        }
        if self.requests.in_flight().is_some() {
            return immediate;
        }
        let mut out = immediate;
        while let Some(work) = self.requests.pop_front() {
            match work {
                Work::Now(action) => {
                    // A probe the reply already stood down is not dialed.
                    if self.action_stands(&action) {
                        out.push(action);
                    }
                }
                Work::Ask(request) => {
                    let action = request.action();
                    if !self.action_stands(&action) {
                        match &request {
                            Request::DeleteOnion => out.extend(self.republish_withheld()),
                            Request::FetchFrom { hsdir } => self.directory_fetch_withheld(*hsdir),
                            _ => {}
                        }
                        self.requests.drop_follower();
                        continue;
                    }
                    if let Request::FetchFrom { hsdir } = &request {
                        self.directory_fetch_sent(now, *hsdir);
                    }
                    self.requests.sent(request, now);
                    out.push(action);
                    break;
                }
            }
        }
        out
    }

    /// The reply to request `number` is folded. The next request goes when
    /// this step routes. A number not in flight is a reply this core no
    /// longer waits on.
    pub(super) fn replied(&mut self, number: u64) -> Vec<Action> {
        self.requests.answered(number);
        Vec::new()
    }

    /// The request in flight is past its bound at `now`.
    pub(super) fn reply_late(&self, now: u64) -> bool {
        self.requests
            .due(super::duration_ns(self.policy.reply_bound))
            .is_some_and(|due| now >= due)
    }
}
