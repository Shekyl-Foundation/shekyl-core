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
//! moving the waits off the loop changes no decision. The order the awaits
//! gave is this queue's order. The reap of an incarnation that ended goes
//! before the next launch; a launch is followed by the event subscription
//! and then the first sample; a republish is `DEL_ONION` and then
//! `ADD_ONION`. A request that no longer stands when its turn comes
//! ([`Core::action_stands`]) is withheld there, as the driver withheld it.
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

/// The request in flight: what it is, its number, and when it was sent.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InFlight {
    request: Request,
    number: u64,
    sent_at: u64,
}

/// The queue, and the one request in flight.
#[derive(Debug, Default)]
pub(super) struct Requests {
    queued: VecDeque<Request>,
    in_flight: Option<InFlight>,
    /// The number the next sent request takes.
    next: u64,
    /// The request in flight was refused (a `DEL_ONION` Tor declined):
    /// what follows it in the same decision is not sent.
    refused: bool,
}

impl Requests {
    pub(super) fn push(&mut self, request: Request) {
        let waiting = self.queued.contains(&request)
            || self
                .in_flight
                .as_ref()
                .is_some_and(|flight| flight.request == request);
        if request.repeats() && waiting {
            return;
        }
        self.queued.push_back(request);
    }

    /// The next request to send, when none is in flight.
    pub(super) fn next_to_send(&mut self) -> Option<Request> {
        if self.in_flight.is_some() {
            return None;
        }
        self.queued.pop_front()
    }

    /// Drop a request that follows the one just withheld or refused.
    pub(super) fn drop_follower(&mut self) {
        if self.queued.front().is_some_and(Request::follows) {
            self.queued.pop_front();
        }
    }

    /// `request` was sent at `now`.
    pub(super) fn sent(&mut self, request: Request, now: u64) {
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
    pub(super) fn in_flight(&self) -> Option<u64> {
        self.in_flight.as_ref().map(|flight| flight.number)
    }

    /// The reply being folded refused its request.
    pub(super) fn refuse(&mut self) {
        if self.in_flight.is_some() {
            self.refused = true;
        }
    }

    /// The request in flight was answered: `false` when `number` is not it.
    /// A refused one drops what follows it.
    pub(super) fn answered(&mut self, number: u64) -> bool {
        if self.in_flight() != Some(number) {
            return false;
        }
        self.in_flight = None;
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
    }
}

impl super::Core {
    /// The number of the request in flight. The driver tags the reply with
    /// it: [`super::Input::Replied`] carries it back.
    #[must_use]
    pub fn in_flight(&self) -> Option<u64> {
        self.requests.in_flight()
    }

    /// Queue the decisions that are requests, then send the next one when
    /// none is in flight. A request that no longer stands is withheld here,
    /// with what follows it: a withheld republish puts its lifetime back.
    pub(super) fn route_requests(&mut self, now: u64, actions: Vec<Action>) -> Vec<Action> {
        let mut out = Vec::with_capacity(actions.len());
        for action in actions {
            match Request::of(&action) {
                Some(requests) => {
                    for request in requests {
                        self.requests.push(request);
                    }
                }
                None => out.push(action),
            }
        }
        while let Some(request) = self.requests.next_to_send() {
            let action = request.action();
            if !self.action_stands(&action) {
                if request == Request::DeleteOnion {
                    out.extend(self.republish_withheld());
                }
                self.requests.drop_follower();
                continue;
            }
            self.requests.sent(request, now);
            out.push(action);
            break;
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
