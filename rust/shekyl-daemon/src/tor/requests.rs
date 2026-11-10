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
//! folded, and a Tor it launched is stopped.
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

use shekyl_tor_control_client::control::{
    parse_bootstrap_progress, parse_consensus_valid_after, parse_network_view,
    parse_service_descriptor, parse_socks_listeners, parse_traffic_read, Command, ControlReply,
    RelayFingerprint, ServiceId, UploadRounds,
};
use shekyl_tor_control_client::supervisor::{Action, DirectoryAnswer, DirectoryFetch, Input};
use shekyl_tor_control_daemon::{
    ControlAsker, DaemonTorConfig, DaemonTorControl, DaemonTorPublishError, DaemonTorStartError,
    KeptDataDir, OnionPow, SpawnError,
};

use super::inbox::Arrival;
use super::{
    consensus_sample, incarnation, input_of_ask, sample_keys, say_retirement, space_short,
    sweep_stale_data_dirs, Drive, CONSENSUS_VALID_AFTER, LAUNCH_BOUND, MAX_STREAMS, SOCKS_TIMEOUT,
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
            Action::Spawn { fresh_directory } => self.send_launch(number, *fresh_directory),
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
        self.answer_later(number, async move {
            Answer::Reaped(control.stop_for_respawn().await)
        });
        None
    }

    /// Launch off the loop. The directory work goes with it: a fresh
    /// directory replaces the kept one (its sweep and retirement), and the
    /// free space is read after that. A launch the space holds back hands
    /// the kept directory back with its answer.
    fn send_launch(&mut self, number: u64, fresh_directory: bool) -> Option<Vec<Input>> {
        // The core reaps an incarnation before the next launch, so none is
        // held here; one that is would be lost by the launch, so it is
        // stopped off the loop instead.
        if let Some(stray) = self.control.take() {
            self.generation = self.generation.wrapping_add(1);
            tokio::spawn(async move {
                drop(stray.stop_for_respawn().await.retire().await);
            });
        }
        let Some(binary) = self.pinned.clone() else {
            return Some(vec![Input::PinRefused]);
        };
        let fresh = fresh_directory || self.kept.is_none();
        let old = if fresh_directory {
            self.kept.take()
        } else {
            None
        };
        let kept = self.kept.take();
        let events = self.events.clone();
        let data_dir = self.data_dir.clone();
        self.answer_later(number, async move {
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
            let launched = match kept {
                Some(directory) => DaemonTorControl::spawn_into(
                    directory,
                    binary,
                    events,
                    LAUNCH_BOUND,
                    SOCKS_TIMEOUT,
                )
                .await
                .map_err(|failure| (failure.error, Some(failure.directory))),
                None => match DaemonTorControl::spawn_keeping(DaemonTorConfig {
                    tor_binary: binary,
                    data_dir_parent: data_dir,
                    events,
                    reply_deadline: LAUNCH_BOUND,
                    socks_timeout: SOCKS_TIMEOUT,
                })
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
            Answer::Launched(launched)
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

    fn send_add(&self, number: u64) -> Option<Vec<Input>> {
        let Some(asker) = self.asker() else {
            return Some(vec![Input::ControlEnded]);
        };
        let Some(forward) = self.forward else {
            return Some(vec![Input::ForwardAbsent]);
        };
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
            // the loop, so no Tor and no directory outlives it.
            match answer {
                Answer::Launched(Ok(control)) => {
                    tracing::info!(target: "tor", "a Tor launched after its bound is stopped");
                    tokio::spawn(async move {
                        drop(control.shutdown().await);
                    });
                }
                Answer::Reaped(kept)
                | Answer::Held {
                    kept: Some(kept), ..
                }
                | Answer::Launched(Err((_, Some(kept)))) => {
                    tokio::spawn(async move {
                        say_retirement(&kept.retire().await);
                    });
                }
                _ => {}
            }
            return Vec::new();
        }
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
                    DaemonTorStartError::DataDir(_) => Input::DirectoryUnusable {
                        path: self.data_dir.clone(),
                        space: None,
                    },
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
                // A publish starts the onion's rounds afresh: a round left
                // open by the deleted service is not this one's.
                self.rounds = Some(UploadRounds::new(service.clone()));
                self.service = Some(service.clone());
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
