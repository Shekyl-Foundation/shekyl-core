// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The supervisor's requests to Tor, run off its loop (`TOR_SUPERVISOR.md`
//! §4.11; Rick, 2026-11-10: the supervisor never awaits Tor).
//!
//! The core sends one request at a time and holds its reply bound. The loop
//! hands the request to a task holding a clone of the control actor
//! ([`ControlAsker`]) and goes straight back to its inbox. The task posts
//! the answer as [`Arrival::Reply`], tagged with the number the core gave
//! the request ([`Core::in_flight`]). The loop folds the answer's inputs and
//! then [`Input::Replied`] with that number. An answer whose number the core
//! no longer waits on is from a request the core gave up on; it is not
//! folded, and what it holds is ended: a Tor stopped, a directory retired.
//!
//! The reap and the launch hold a Tor or a directory. Each runs after the
//! one before it has finished ([`Drive::hold_later`]), so a late launch's
//! directory is not swept by the next, and the stop waits for the last of
//! them. A launch waits for Tor's first reply with no clock of its own: the
//! core's bound decides, and when the core gives up on it, or the daemon
//! stops, the driver abandons it ([`Drive::abandon_launch`]).
//!
//! What a request needs from the loop is read when it is sent: the control,
//! the service, the rounds' directories, the CSPRNG draws. A request the loop
//! can answer at once (no control, no forward listener) is answered on the
//! loop, with the same inputs and the same `Replied`.
//!
//! [`Arrival::Reply`]: super::inbox::Arrival::Reply
//! [`Core::in_flight`]: shekyl_tor_control_client::supervisor::Core::in_flight

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::watch;

use shekyl_tor_control_client::control::{
    parse_bootstrap_progress, parse_consensus_valid_after, parse_network_view,
    parse_service_descriptor, parse_socks_listeners, parse_traffic_read, Command, ControlReply,
    RelayFingerprint, ServiceId, UploadRounds,
};
use shekyl_tor_control_client::supervisor::{
    Action, DirectoryAnswer, DirectoryFetch, Input, Launch, LaunchDirectory, REPLY_BOUND,
};
use shekyl_tor_control_daemon::{
    ControlAsker, DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, DaemonTorStartError,
    KeptDataDir, OnionPow, SpawnError,
};

use super::inbox::Arrival;
use super::{
    consensus_sample, incarnation, input_of_ask, sample_keys, say_retirement, space_short,
    sweep_stale_data_dirs, Drive, CONSENSUS_VALID_AFTER, MAX_STREAMS, SOCKS_TIMEOUT,
};

/// A request's answer, posted back to the loop.
pub(super) enum Answer {
    /// Inputs ready to fold.
    Inputs(Vec<Input>),
    /// The reap: the ended incarnation's directory, kept for the next launch.
    Reaped(KeptDataDir),
    /// The launch: the incarnation, or why not, with the directory to keep.
    Launched(Result<DaemonTorControl, (DaemonTorStartError, Option<KeptDataDir>)>),
    /// A launch held back before it started (too little space), with the
    /// kept directory handed back.
    Held {
        input: Input,
        kept: Option<KeptDataDir>,
    },
    /// The sample's reply and, when it was answered, the consensus clock's
    /// with the wall time read beside it.
    Sampled {
        /// Whether the sample asked Tor's network view (Running only).
        reads_network: bool,
        sample: Result<ControlReply, DaemonTorStartError>,
        consensus: Option<(Result<ControlReply, DaemonTorStartError>, Option<u64>)>,
    },
    /// `ADD_ONION`'s outcome, for the forward listener it named.
    Added {
        forward: SocketAddr,
        outcome: Result<ServiceId, DaemonTorPublishError>,
    },
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inputs(_) => "Inputs",
            Self::Reaped(_) => "Reaped",
            Self::Held { .. } => "Held",
            Self::Launched(Ok(_)) => "Launched",
            Self::Launched(Err(_)) => "LaunchFailed",
            Self::Sampled { .. } => "Sampled",
            Self::Added { .. } => "Added",
        })
    }
}

impl Answer {
    /// Whether this answer holds a Tor or a directory.
    fn holds(&self) -> bool {
        matches!(
            self,
            Self::Launched(Ok(_) | Err((_, Some(_))))
                | Self::Reaped(_)
                | Self::Held { kept: Some(_), .. }
        )
    }

    /// End what this answer holds: a Tor is stopped, a directory retired.
    /// For an answer the core no longer waits on, one that cannot be
    /// delivered, and a launch abandoned before it answered.
    pub(super) async fn discard(self) {
        match self {
            Self::Launched(Ok(control)) => {
                tracing::info!(
                    target: "tor",
                    "a Tor launched for a request the supervisor gave up on is stopped"
                );
                if let Some(retirement) = control.shutdown().await.retirement {
                    say_retirement(&retirement);
                }
            }
            Self::Reaped(kept)
            | Self::Held {
                kept: Some(kept), ..
            }
            | Self::Launched(Err((_, Some(kept)))) => say_retirement(&kept.retire().await),
            _ => {}
        }
    }
}

impl Drive {
    /// Send the request `action` names: the core has just put it in flight.
    /// Returns what the loop answers at once, `Replied` last; empty when a
    /// task answers.
    pub(super) fn send(&mut self, action: &Action) -> Vec<Input> {
        // A fault folded between the core sending this request and the loop
        // reaching it has cleared it: there is nothing to send.
        let Some(number) = self.core.in_flight() else {
            return Vec::new();
        };
        let answered = match action {
            Action::Reap => self.send_reap(number),
            Action::Spawn(launch) => self.send_launch(number, launch.clone()),
            Action::SubscribeEvents => self.send_subscribe(number),
            Action::Sample => self.send_sample(number),
            Action::SetConfAvoidDiskWrites => self.send_defer(number),
            Action::RepublishOnion => self.send_delete(number),
            Action::AddOnion => self.send_add(number),
            Action::RefetchDescriptor => self.send_refetch(number),
            Action::CheckDirectories => self.send_check(number),
            Action::FetchFromDirectory { hsdir } => self.send_fetch(number, *hsdir),
            _ => unreachable!("{action:?} is not a request"),
        };
        match answered {
            Some(mut inputs) => {
                inputs.push(Input::Replied { number });
                // The answer's own decisions lead the tail that was waiting
                // on this request. The fold that consumes `inputs` ends
                // with `Replied`.
                self.core.begin_reply_fold();
                inputs
            }
            None => Vec::new(),
        }
    }

    /// Run `ask` off the loop and post its answer for `number`.
    fn answer_later(&self, number: u64, ask: impl Future<Output = Answer> + Send + 'static) {
        let poster = self.poster.clone();
        tokio::spawn(async move {
            let answer = Box::new(ask.await);
            poster.post(Arrival::Reply { number, answer });
        });
    }

    /// Run `work`, which holds a Tor or a directory, once the last such
    /// work has finished, and post its answer for `number`. An answer that
    /// cannot be posted (the loop has gone) is discarded here.
    fn hold_later(&mut self, number: u64, work: impl Future<Output = Answer> + Send + 'static) {
        let poster = self.poster.clone();
        self.hold(async move {
            let answer = Box::new(work.await);
            if let Err(answer) = poster.deliver(number, answer) {
                answer.discard().await;
            }
        });
    }

    /// Run `work` once the last work that holds a Tor or a directory has
    /// finished. The driver keeps this one as the last: the next waits for
    /// it, and so does the stop.
    pub(super) fn hold(&mut self, work: impl Future<Output = ()> + Send + 'static) {
        let before = self.held.take();
        self.held = Some(tokio::spawn(async move {
            if let Some(before) = before {
                if let Err(error) = before.await {
                    tracing::warn!(target: "tor", "Tor's previous process work ended abnormally: {error}");
                }
            }
            work.await;
        }));
    }

    /// Abandon the launch in flight when the core no longer waits on it,
    /// or every launch when `stopping`: its wait for Tor's first reply
    /// ends, and its task stops that Tor and retires its directory.
    pub(super) fn abandon_launch(&mut self, stopping: bool) {
        let waited = self
            .launch
            .as_ref()
            .is_some_and(|(number, _)| !stopping && self.core.in_flight() == Some(*number));
        if waited {
            return;
        }
        if let Some((_, abandon)) = self.launch.take() {
            // Set whether or not the task still listens: it may have finished.
            abandon.send_replace(true);
        }
    }

    fn asker(&self) -> Option<ControlAsker> {
        self.control.as_ref().map(DaemonTorControl::asker)
    }

    /// Stop and reap the incarnation that ended, off the loop: the owning
    /// connection closes and Tor is given its grace to exit (killed past
    /// it), so a frozen Tor holds this task, not the loop. The directory
    /// comes back in the answer, kept for the launch that follows.
    fn send_reap(&mut self, number: u64) -> Option<Vec<Input>> {
        self.cancel_probe();
        let Some(control) = self.control.take() else {
            return Some(Vec::new());
        };
        // The stop's own death is not a second fault.
        self.generation = self.generation.wrapping_add(1);
        self.hold_later(number, async move {
            Answer::Reaped(control.stop_for_respawn().await)
        });
        None
    }

    /// Launch off the loop, once the work before it has finished. The
    /// directory work goes with it: a fresh directory replaces the kept one
    /// (its sweep and retirement), and the free space is read after that. A
    /// launch the space holds back hands the kept directory back with its
    /// answer. The wait for Tor's first reply has no clock: it ends when the
    /// driver abandons the launch, and the task then stops that Tor and
    /// retires its directory itself, so the next launch, which waits for
    /// this task, finds nothing of it.
    fn send_launch(&mut self, number: u64, launch: Launch) -> Option<Vec<Input>> {
        let Launch { binary, directory } = launch;
        // The core reaps an incarnation before the next launch, so none is
        // held here; one that is would be lost by the launch, so it is
        // stopped first, in the same order.
        if let Some(stray) = self.control.take() {
            self.generation = self.generation.wrapping_add(1);
            self.hold(async move {
                say_retirement(&stray.stop_for_respawn().await.retire().await);
            });
        }
        // A fresh launch retires the kept directory; a kept launch reuses it.
        // Either one with nothing kept takes a new directory.
        let (old, kept) = match directory {
            LaunchDirectory::Fresh => (self.kept.take(), None),
            LaunchDirectory::Kept => (None, self.kept.take()),
        };
        let fresh = kept.is_none();
        let events = self.events.clone();
        let data_dir = self.data_dir.clone();
        let (abandon, abandoned) = watch::channel(false);
        self.launch = Some((number, abandon));
        self.hold_later(number, async move {
            let swept = match old {
                Some(old) => {
                    say_retirement(&old.replace().await);
                    true
                }
                None => false,
            };
            if fresh && !swept {
                sweep_stale_data_dirs(&data_dir, None);
            }
            if let Some(input) = space_short(&data_dir, fresh) {
                return Answer::Held { input, kept };
            }
            let mut waiting = abandoned.clone();
            // A driver that has gone abandons the launch too.
            let until = async move {
                drop(waiting.wait_for(|abandon| *abandon).await);
            };
            // The control's own awaiting methods take this bound. The
            // driver asks through `ControlAsker` and calls none of them.
            let launched = match kept {
                Some(directory) => DaemonTorControl::spawn_into(
                    directory,
                    binary,
                    events,
                    REPLY_BOUND,
                    SOCKS_TIMEOUT,
                    until,
                )
                .await
                .map_err(|failure| (failure.error, Some(failure.directory))),
                None => match DaemonTorControl::spawn_keeping(
                    DaemonTorConfig {
                        tor_binary: binary,
                        data_dir_parent: data_dir,
                        events,
                        reply_deadline: REPLY_BOUND,
                        socks_timeout: SOCKS_TIMEOUT,
                    },
                    until,
                )
                .await
                {
                    Ok(up) => Ok(up),
                    Err(SpawnError::DataDir(error)) => {
                        Err((DaemonTorStartError::DataDir(error), None))
                    }
                    Err(SpawnError::Launch(failure)) => {
                        Err((failure.error, Some(failure.directory)))
                    }
                },
            };
            let answer = Answer::Launched(launched);
            if *abandoned.borrow() || abandoned.has_changed().is_err() {
                answer.discard().await;
                return Answer::Inputs(Vec::new());
            }
            answer
        });
        None
    }

    fn send_subscribe(&self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(vec![Input::ControlEnded]);
        };
        self.answer_later(number, async move {
            if let Err(error) = asker.ask(Command::supervisor_events()).await {
                tracing::warn!(target: "global", "Tor events were not subscribed ({error})");
            }
            Answer::Inputs(Vec::new())
        });
        None
    }

    /// The sample, then the consensus clock: `consensus/valid-after` against
    /// this machine's wall time, read beside the reply (§4.2). An ask that
    /// fails is a process fault; Tor having no consensus yet is no input.
    fn send_sample(&self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(vec![Input::ControlEnded]);
        };
        let reads_network = self.core.reads_network();
        self.answer_later(number, async move {
            let sample = asker
                .ask(Command::GetInfo(sample_keys(reads_network)))
                .await;
            let consensus = if sample.is_ok() {
                let asked = asker
                    .ask(Command::GetInfo(vec![CONSENSUS_VALID_AFTER.to_owned()]))
                    .await;
                let wall = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|elapsed| elapsed.as_secs());
                Some((asked, wall))
            } else {
                None
            };
            Answer::Sampled {
                reads_network,
                sample,
                consensus,
            }
        });
        None
    }

    fn send_defer(&self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(Vec::new());
        };
        self.answer_later(number, async move {
            if let Err(error) = asker.defer_disk_writes().await {
                tracing::warn!(target: "global", "leaving Tor writing its state ({error})");
            }
            Answer::Inputs(Vec::new())
        });
        None
    }

    /// `DEL_ONION`, the first half of a (re)publish. No forward listener
    /// means nothing to publish to: the core sends no `ADD_ONION` after it.
    fn send_delete(&self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(vec![Input::ControlEnded]);
        };
        if self.forward.is_none() {
            return Some(vec![Input::ForwardAbsent]);
        }
        tracing::info!(target: "tor", "publishing this node's onion again");
        let onion = Arc::clone(&self.onion);
        self.answer_later(number, async move {
            Answer::Inputs(match asker.delete_onion(&onion).await {
                Ok(()) => Vec::new(),
                Err(error) => {
                    tracing::warn!(target: "global", "the onion was not published ({error})");
                    vec![Input::OnionRejected]
                }
            })
        });
        None
    }

    /// `ADD_ONION`, the second half. The service and a fresh round
    /// tracker are this onion's from the send: Tor uploads as soon as it
    /// takes the service, and its `HS_DESC` events can reach the inbox
    /// before the reply does. A publish starts the rounds afresh, since a
    /// round left open by the deleted service is not this one's. A refused
    /// add publishes nothing, so no event reaches the new tracker.
    pub(super) fn send_add(&mut self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(vec![Input::ControlEnded]);
        };
        let Some(forward) = self.forward else {
            return Some(vec![Input::ForwardAbsent]);
        };
        let service = self.onion.service_id().clone();
        self.rounds = Some(UploadRounds::new(service.clone()));
        self.service = Some(service);
        let onion = Arc::clone(&self.onion);
        let virtual_port = self.virtual_port;
        self.answer_later(number, async move {
            let outcome = asker
                .add_onion(
                    &onion,
                    virtual_port,
                    forward,
                    MAX_STREAMS,
                    OnionPow::Enabled,
                )
                .await;
            Answer::Added { forward, outcome }
        });
        None
    }

    /// `HSFETCH` this node's own onion after a first probe miss: Tor refreshes
    /// its client view of that one address (`TSR-Q14`). Whatever Tor answers,
    /// the second probe follows, a fresh delay later.
    fn send_refetch(&self, number: u64) -> Option<Vec<Input>> {
        let draw = self.network.probe_delay_draw();
        let (Some(asker), Some(service)) = (self.asker(), self.service.clone()) else {
            return Some(vec![Input::DescriptorRefetched { draw }]);
        };
        self.answer_later(number, async move {
            match asker.ask(Command::HsFetch(service)).await {
                Ok(reply) if reply.status() == 250 => tracing::info!(
                    target: "tor",
                    "the onion probe missed; Tor refetches this node's descriptor"
                ),
                Ok(reply) => tracing::info!(
                    target: "tor",
                    status = reply.status(),
                    "the onion probe missed; Tor did not take the refetch"
                ),
                Err(error) => tracing::info!(
                    target: "tor",
                    "the onion probe missed; the refetch was not asked ({error})"
                ),
            }
            Answer::Inputs(vec![Input::DescriptorRefetched { draw }])
        });
        None
    }

    /// A probe's check: the directories the latest round reached, each with
    /// its own CSPRNG draw, read now; this service's current descriptor,
    /// asked off the loop (§4.5). No control, or no service yet, is no
    /// descriptor; an ask that fails is a process fault.
    fn send_check(&self, number: u64) -> Option<Vec<Input>> {
        let fetches: Vec<DirectoryFetch> = self
            .rounds
            .as_ref()
            .map(|rounds| {
                rounds
                    .directories()
                    .iter()
                    .map(|to| DirectoryFetch {
                        hsdir: to.hsdir,
                        descriptor_id: to.descriptor_id.clone(),
                        draw: self.network.probe_delay_draw(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (Some(asker), Some(service)) = (self.asker(), self.service.clone()) else {
            return Some(vec![Input::DirectoriesDrawn {
                fetches,
                ours: None,
            }]);
        };
        self.answer_later(number, async move {
            let key = format!("hs/service/desc/id/{}", service.as_str());
            Answer::Inputs(match asker.ask(Command::GetInfo(vec![key])).await {
                Ok(reply) => {
                    let ours = parse_service_descriptor(&reply);
                    match &ours {
                        Some(ours) => tracing::debug!(
                            target: "tor",
                            descriptor_id = %ours.descriptor_id,
                            revision_counter = ours.revision_counter,
                            "this onion's current descriptor, for the directory check"
                        ),
                        None => tracing::debug!(
                            target: "tor",
                            status = reply.status(),
                            "Tor gave no descriptor for this onion; the check counts nothing and the probe alone decides"
                        ),
                    }
                    vec![Input::DirectoriesDrawn { fetches, ours }]
                }
                Err(error) => {
                    tracing::debug!(target: "tor", "this onion's descriptor was not asked ({error})");
                    vec![input_of_ask(&error)]
                }
            })
        });
        None
    }

    /// `HSFETCH` this node's onion from one directory. Tor accepting it
    /// (`250`) starts that fetch's answer window. A refusal, or no control
    /// or service to ask with, is unusable here, so the check does not wait
    /// on it.
    fn send_fetch(&self, number: u64, hsdir: RelayFingerprint) -> Option<Vec<Input>> {
        let unusable = Input::DirectoryAnswered {
            hsdir,
            descriptor_id: None,
            answer: DirectoryAnswer::Unusable,
        };
        let (Some(asker), Some(service)) = (self.asker(), self.service.clone()) else {
            return Some(vec![unusable]);
        };
        self.answer_later(number, async move {
            Answer::Inputs(vec![
                match asker
                    .ask(Command::HsFetchFrom {
                        service,
                        server: hsdir,
                    })
                    .await
                {
                    Ok(reply) if reply.status() == 250 => Input::DirectoryFetchAccepted { hsdir },
                    Ok(reply) => {
                        tracing::debug!(
                            target: "tor",
                            status = reply.status(),
                            ?hsdir,
                            "Tor did not take the directory fetch"
                        );
                        unusable
                    }
                    Err(error) => {
                        tracing::debug!(target: "tor", ?hsdir, "the directory fetch was not asked ({error})");
                        unusable
                    }
                },
            ])
        });
        None
    }

    /// An answer arrived for request `number`. Folded with `Replied` last
    /// when the core still waits on that number; otherwise dropped, and a
    /// Tor launched for it is stopped so it does not outlive the request.
    pub(super) fn answered(&mut self, number: u64, answer: Answer) -> Vec<Input> {
        if self.core.in_flight() != Some(number) {
            // A request the core gave up on: whatever it holds is ended off
            // the loop, before the next launch's directory work, so no Tor
            // and no directory outlives it.
            if answer.holds() {
                self.hold(answer.discard());
            }
            return Vec::new();
        }
        // Before the fold. The answer's decisions then lead the tail.
        self.core.begin_reply_fold();
        let mut inputs = match answer {
            Answer::Inputs(inputs) => inputs,
            Answer::Reaped(kept) => {
                self.kept = Some(kept);
                Vec::new()
            }
            Answer::Held { input, kept } => {
                self.kept = kept;
                vec![input]
            }
            Answer::Launched(launched) => vec![self.launched(launched)],
            Answer::Sampled {
                reads_network,
                sample,
                consensus,
            } => self.sampled(reads_network, sample, consensus),
            Answer::Added { forward, outcome } => vec![self.added(forward, outcome)],
        };
        inputs.push(Input::Replied { number });
        inputs
    }

    fn launched(
        &mut self,
        launched: Result<DaemonTorControl, (DaemonTorStartError, Option<KeptDataDir>)>,
    ) -> Input {
        match launched {
            Ok(up) => {
                self.generation = self.generation.wrapping_add(1);
                tokio::spawn(incarnation(
                    self.generation,
                    up.death(),
                    up.watch_bootstrap(),
                    self.poster.clone(),
                ));
                self.control = Some(up);
                Input::Spawned
            }
            Err((error, directory)) => {
                if let Some(directory) = directory {
                    self.kept = Some(directory);
                }
                match error {
                    DaemonTorStartError::DataDir(_) => Input::DirectoryUnusable { space: None },
                    _ => Input::SpawnFailed,
                }
            }
        }
    }

    fn sampled(
        &mut self,
        reads_network: bool,
        sample: Result<ControlReply, DaemonTorStartError>,
        consensus: Option<(Result<ControlReply, DaemonTorStartError>, Option<u64>)>,
    ) -> Vec<Input> {
        let reply = match sample {
            Ok(reply) => reply,
            Err(error) => return vec![input_of_ask(&error)],
        };
        let socks = parse_socks_listeners(&reply);
        if let (Some(socks), Some(control)) = (socks, self.control.as_mut()) {
            control.set_socks(socks);
        }
        let mut inputs = vec![Input::DirectorySample {
            progress: parse_bootstrap_progress(&reply),
            socks,
            read: parse_traffic_read(&reply),
        }];
        if reads_network {
            let view = parse_network_view(&reply);
            // Tor's view is what the next blocked-link run records (`TSR-Q14`):
            // said when it changes, not with every sample.
            if view != self.network_view {
                tracing::info!(
                    target: "tor",
                    network_liveness = ?view.liveness,
                    circuit_established = ?view.circuits,
                    "Tor's view of its network"
                );
                self.network_view = view;
            }
            inputs.push(Input::NetworkView(view));
        }
        if let Some((asked, wall)) = consensus {
            let parsed = match &asked {
                Ok(reply) => Ok(parse_consensus_valid_after(reply)),
                Err(error) => Err(error),
            };
            // The directory sample already read is still folded. A fault
            // ends the incarnation after it.
            match consensus_sample(parsed, wall) {
                Ok(Some(clock)) => inputs.push(clock),
                Ok(None) => {}
                Err(fault) => inputs.push(fault),
            }
        }
        inputs
    }

    fn added(
        &mut self,
        forward: SocketAddr,
        outcome: Result<ServiceId, DaemonTorPublishError>,
    ) -> Input {
        match outcome {
            Ok(service) => {
                self.network
                    .note_own_onion(service.as_str(), self.virtual_port);
                tracing::info!(
                    target: "global",
                    "Tor is up: overlay inbound is published at {}.onion:{}, forwarded from {forward}",
                    service.as_str(),
                    self.virtual_port,
                );
                Input::OnionPublished
            }
            Err(error) => {
                tracing::warn!(target: "global", "the onion was not published ({error})");
                Input::OnionRejected
            }
        }
    }
}
