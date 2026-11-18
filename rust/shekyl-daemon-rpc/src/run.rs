// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The daemon RPC's start and stop (`DAEMON_CONFIG_CUTOVER.md` §2.3).
//!
//! [`start`] binds every `rpc-admin-listen` endpoint at the admin listener
//! and every `rpc-view-listen` endpoint at the view listener, loopback
//! only, with the origin list and the one connection cap, and serves them
//! on a runtime the returned [`Running`] holds. Binding is synchronous, so
//! a refusal or `EADDRINUSE` is the returned error and never a log inside
//! a spawned task. Every route reads the node through the
//! [`Handles`] the composition root supplies; the p2p facts among them
//! are the node's over `shekyl-p2p`'s board
//! (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §2.1). The Tor supervisor is not among
//! them: [`start`] takes its asks beside the handles.
//!
//! [`Running::stop`] stops the server: no new connections, the in-flight
//! handlers drained, the runtime released. It blocks until the drain
//! finishes, because the handlers hold the node's handles, which the
//! caller is about to take down.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use shekyl_daemon_config::sections::Rpc;
use shekyl_runtime::{runtime, Pool, RuntimeBudget, ThreadName};
use tokio::sync::watch;

use crate::bind::{bind_listener, BoundListener};
use crate::conn_limit::ConnLimits;
use crate::handles::Handles;
use crate::options::OptionsHandle;
use crate::server::{serve_listeners, ServerConfig};
use crate::tor_facts::TorHandle;

/// Structural floor, the same pair the transport runtime is built with.
/// Tokio's unset worker count and its 512 blocking cap are the defaults
/// D5 refuses. These are not a measured budget; the D5 pin replaces them.
fn daemon_rpc_budget() -> RuntimeBudget {
    RuntimeBudget {
        workers: NonZeroUsize::new(2).expect("workers"),
        blocking: NonZeroUsize::new(1).expect("blocking"),
    }
}

/// A running server: its level-triggered stop signal, its runtime, its
/// serve task, and the owner's socket with its watch.
pub struct Running {
    shutdown: watch::Sender<bool>,
    rt: Pool,
    serve: tokio::task::JoinHandle<()>,
    owner: Option<Owner>,
    /// A service's published rendezvous record; dropped first on stop.
    service_rendezvous: Option<crate::channel::rendezvous::ServiceRendezvous>,
    /// A service's data directory, whose console leg is removed on stop.
    console_dir: Option<std::path::PathBuf>,
}

/// The server's runtime, and the owner's leg bound on it, before the node
/// opens ([`prepare`]). A pipe registers with the runtime that serves it,
/// so the runtime exists from here.
pub struct Prepared {
    rt: Pool,
    owner: Option<crate::owner::OwnerSocket>,
    channel: Option<std::sync::Arc<crate::channel::Channel>>,
}

/// Why [`prepare`] refused.
#[derive(Debug)]
pub enum PrepareError {
    /// The runtime could not start, in the operator's words.
    Runtime(String),
    /// The owner's leg refused, as a typed refusal.
    Owner(shekyl_options::Diagnostic),
    /// The RPC channel's key or enrolled set could not be used.
    Channel(StartFault),
}

/// Why the RPC's files or listeners could not be set up.
#[derive(Debug)]
pub enum StartFault {
    /// A file could not be replaced: another program held its staged file
    /// open past the wait ([`shekyl_os_account::private_file::REPLACE_WAIT`]).
    /// The daemon names it with its own refusal code.
    HeldOpen(shekyl_os_account::private_file::HeldOpen),
    /// The refusal, in the operator's words.
    Refused(String),
}

impl std::fmt::Display for StartFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeldOpen(held) => held.fmt(f),
            Self::Refused(why) => f.write_str(why),
        }
    }
}

impl From<String> for StartFault {
    fn from(why: String) -> Self {
        Self::Refused(why)
    }
}

impl From<crate::channel::files::FileRefused> for StartFault {
    fn from(error: crate::channel::files::FileRefused) -> Self {
        match error {
            crate::channel::files::FileRefused::HeldOpen(held) => Self::HeldOpen(held),
            other => Self::Refused(other.to_string()),
        }
    }
}

/// The refusal for a file another program held open past the wait
/// (`config.replace.held-open`): the file, the wait, and `dir`, the
/// directory to exclude from scanning (the data directory, or the
/// rendezvous directory for the owner's record).
#[must_use]
pub fn held_open_refusal(
    held: &shekyl_os_account::private_file::HeldOpen,
    dir: &std::path::Path,
) -> shekyl_options::Diagnostic {
    shekyl_options::Diagnostic::new(
        shekyl_options::Code::ReplaceHeldOpen,
        shekyl_options::Source::Machine,
    )
    .param("path", held.held.display().to_string())
    .param(
        "wait",
        shekyl_os_account::private_file::REPLACE_WAIT
            .as_secs()
            .to_string(),
    )
    .param("dir", dir.display().to_string())
}

impl StartFault {
    /// The refusal with `context` before its words; a held file is named
    /// by its own code, so it keeps its own words.
    #[must_use]
    pub fn context(self, context: impl FnOnce() -> String) -> Self {
        match self {
            Self::HeldOpen(held) => Self::HeldOpen(held),
            Self::Refused(why) => Self::Refused(format!("{}: {why}", context())),
        }
    }
}

/// Start the server's runtime and bind the owner's leg on it: the start-up
/// dial, the socket or pipe, and the published rendezvous
/// ([`crate::owner::OwnerSocket::bind`]). Called before the node opens, so a
/// second daemon of this account, network and instance refuses with nothing
/// opened (`RPC_CHANNEL.md` §7.1). `owner` is the walk's plan and the
/// network's name; `None` for a service. `channel` opens the RPC channel's
/// state under the data directory's lock, the daemon's key made on the
/// first start (RT-O34); `None` composes no channel.
///
/// # Errors
///
/// The runtime could not start, the owner's leg refused, or the channel's
/// files could not be used.
pub fn prepare(
    owner: Option<(&shekyl_daemon_config::OwnerSocketPlan, &str)>,
    channel: Option<&crate::channel::ChannelSetup>,
) -> Result<Prepared, PrepareError> {
    let name = ThreadName::new("daemon-rpc")
        .map_err(|e| PrepareError::Runtime(format!("thread name refused: {e}")))?;
    let rt = runtime(daemon_rpc_budget(), &name)
        .map_err(|e| PrepareError::Runtime(format!("the runtime could not start: {e}")))?;
    let owner = match owner {
        Some((plan, network)) => {
            let _in_runtime = rt.enter();
            Some(crate::owner::OwnerSocket::bind(plan, network).map_err(PrepareError::Owner)?)
        }
        None => None,
    };
    let channel = channel
        .map(crate::channel::Channel::open)
        .transpose()
        .map_err(PrepareError::Channel)?;
    Ok(Prepared { rt, owner, channel })
}

impl Prepared {
    /// Where the owner's rendezvous is, for the start line; `None` for a
    /// service.
    #[must_use]
    pub fn owner_path(&self) -> Option<&std::path::Path> {
        self.owner.as_ref().map(crate::owner::OwnerSocket::path)
    }
}

/// The owner's leg while it is served: the rendezvous that removes it, and
/// the watch that stops the daemon if it goes first.
struct Owner {
    rendezvous: crate::owner::Rendezvous,
    watch_stop: watch::Sender<bool>,
    watch: tokio::task::JoinHandle<()>,
}

/// What the daemon does when its owner's socket goes: it stops, the one way
/// a stop is asked for (`RPC_CHANNEL.md` §7.1).
pub type OnRendezvousGone = Arc<dyn Fn() + Send + Sync>;

/// Binds every listener synchronously, then serves them on the node's
/// handles, on the runtime [`prepare`] started, with the owner's leg it
/// bound. `tor` is the daemon's Tor supervisor, as `daemon_status` asks it.
/// `armed` is the node's `dev-rpc` switch (`RPC_CHANNEL.md` §6.1). `gone` is
/// what the daemon does if the owner's rendezvous goes.
///
/// # Errors
///
/// The refusal, in the operator's words: a connection cap the section
/// cannot carry, a runtime that could not start, a bind that failed, or a
/// pool not installed for submit.
pub fn start(
    section: &Rpc,
    options: OptionsHandle,
    handles: Handles,
    tor: TorHandle,
    armed: bool,
    prepared: Prepared,
    gone: OnRendezvousGone,
) -> Result<Running, StartFault> {
    let Prepared { rt, owner, channel } = prepared;
    // The section's one cap; the listeners are loopback only, so the
    // per-address caps the C++ options carried had no population.
    let conn_limits = ConnLimits::checked(u64::from(section.connections_max.get()), 0, 0)?;
    let bind = |endpoints: &[SocketAddr]| -> Result<Vec<BoundListener>, String> {
        let mut bound = Vec::with_capacity(endpoints.len());
        for addr in endpoints {
            bound.push(
                rt.block_on(bind_listener(*addr))
                    .map_err(|e| format!("bind failed on {addr}: {e}"))?,
            );
        }
        Ok(bound)
    };
    let admin = bind(&section.admin_listen)?;
    let view = bind(&section.view_listen)?;
    // The channel's listeners bind any address (RT-14).
    let mut channel_listen = Vec::with_capacity(section.channel_listen.len());
    for addr in &section.channel_listen {
        channel_listen.push(
            rt.block_on(crate::bind::bind_channel_listener(*addr))
                .map_err(|e| format!("bind failed on {addr}: {e}"))?,
        );
    }
    // A service's console leg (RT-O37): bound in this runtime, under the
    // data directory's lock, whether or not it listens on `rpc-listen`.
    let console_dir = channel.as_ref().and_then(|c| c.console_dir.clone());
    let console = match &console_dir {
        Some(dir) => {
            let _runtime = rt.enter();
            Some(crate::channel::console_leg::bind(dir).map_err(|e| {
                e.context(|| format!("the console's leg in {} could not be bound", dir.display()))
            })?)
        }
        None => None,
    };
    // A service publishes its machine-wide rendezvous record once its
    // listeners are bound, whatever it listens on: the channel's address
    // and bundle when the channel is on, the view listener when that is on
    // (`RPC_CHANNEL.md` §7.1; Rick, 2026-11-17).
    let service_rendezvous = match channel
        .as_ref()
        .and_then(|channel| Some((channel, channel.service_rendezvous.as_ref()?)))
    {
        Some((channel, path)) => {
            let bound: Vec<SocketAddr> = channel_listen
                .iter()
                .map(BoundListener::local_addr)
                .collect();
            let bundle = crate::channel::bundle(&channel.key);
            let views: Vec<SocketAddr> = view.iter().map(BoundListener::local_addr).collect();
            Some(
                crate::channel::rendezvous::ServiceRendezvous::publish(
                    path,
                    (!bound.is_empty()).then_some((bound.as_slice(), bundle.as_slice())),
                    &views,
                )
                .map_err(|e| {
                    StartFault::from(e).context(|| {
                        format!(
                            "the service's rendezvous {} could not be published",
                            path.display()
                        )
                    })
                })?,
            )
        }
        None => None,
    };
    crate::handles::publish_live(&handles);
    let config = ServerConfig {
        cors_origins: section.cors_origins.clone(),
        conn_limits,
        options,
        handles,
        tor,
        armed,
        channel,
        ..Default::default()
    };
    let Some(shim) = crate::submit::production() else {
        return Err("the node's pool is not installed for submit"
            .to_owned()
            .into());
    };
    let submit_engine = Arc::new(crate::submit::SubmitEngine::new(
        shim,
        crate::submit::DaemonTxVerifier,
    ));
    // Level-triggered: a stop that lands before any acceptor has polled is
    // still observed by `wait_for`. One sender, cloned into every acceptor.
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (owner, owner_listener) = match owner {
        Some(socket) => {
            let (listener, rendezvous) = socket.into_parts();
            // Into this runtime before the start returns, so the start's
            // `Ok` means the owner's leg will be served: the daemon writes
            // its ready line on that `Ok` (IG-Q106). A refusal drops the
            // rendezvous, which removes the socket.
            let listener = {
                let _runtime = rt.enter();
                crate::owner::serve_ready(listener)
            }
            .map_err(|e| format!("the owner's socket could not be served: {e}"))?;
            let (watch_stop, watch_rx) = watch::channel(false);
            let watch = rt.spawn(crate::owner::watch(rendezvous.place(), gone, watch_rx));
            (
                Some(Owner {
                    rendezvous,
                    watch_stop,
                    watch,
                }),
                Some(listener),
            )
        }
        None => (None, None),
    };
    let serve = rt.spawn(async move {
        if let Err(e) = serve_listeners(
            config,
            submit_engine,
            crate::server::Listeners {
                admin,
                view,
                owner: owner_listener,
                channel_listen,
                console,
            },
            shutdown_rx,
        )
        .await
        {
            tracing::error!("daemon-rpc server error: {e}");
        }
    });
    Ok(Running {
        shutdown,
        rt,
        serve,
        owner,
        service_rendezvous,
        console_dir,
    })
}

impl Running {
    /// Stops the server: no new connections, the in-flight handlers
    /// drained, the runtime released. Blocks until the drain finishes;
    /// `shutdown_background` would free the runtime under a running submit.
    pub fn stop(self) {
        let Self {
            shutdown,
            rt,
            serve,
            owner,
            service_rendezvous,
            console_dir,
        } = self;
        // A service's record first, so no client is pointed at a daemon
        // that is draining (§7.1).
        drop(service_rendezvous);
        // The owner's socket first: the watch stops, so removing the socket
        // is not read as its going, and then the socket is removed, so no
        // client reaches a daemon that is draining (`RPC_CHANNEL.md` §7.1).
        if let Some(Owner {
            rendezvous,
            watch_stop,
            watch,
        }) = owner
        {
            watch_stop.send_replace(true);
            drop(rt.block_on(watch));
            drop(rendezvous);
        }
        // Every acceptor observes this, polled yet or not (`watch` is
        // level-triggered; `notify_waiters` was not and could lose a stop).
        shutdown.send_replace(true);
        drop(rt.block_on(serve));
        // The console's leg after its last connection has ended; a later
        // start replaces a leg a crash left.
        if let Some(dir) = console_dir {
            crate::channel::console_leg::retire(&dir);
        }
        drop(rt);
        drop(shutdown);
    }
}
