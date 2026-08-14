// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The control-port actor — the `tokio` + `kameo` driver that turns the sans-IO
//! pieces ([`framing`], [`safecookie`], [`auth`]) into a live, authenticated
//! control connection.
//!
//! # The shape (read this before adding a second socket actor)
//!
//! This is the **first** shekyl actor to merge a socket into the mailbox, so it
//! establishes a pattern SP-T0b (child management, bootstrap gate) and any future
//! socket actor inherit. Two kameo features carry it:
//!
//! - **Handshake in `on_start`, *then* `attach_stream`.** kameo owns the run loop;
//!   an actor cannot `select!` on its own mailbox and a socket. So the SAFECOOKIE
//!   handshake runs *synchronously* in [`on_start`](TorControl) — reading the
//!   framer by hand, which is safe because no async `650` events can arrive before
//!   `SETEVENTS` is sent — and only *after* `AUTHENTICATE` (and, for a managed child,
//!   `TAKEOWNERSHIP`) succeeds is the read half wrapped as the internal `ReplyStream`
//!   (`Stream<Item = Result<Framed, ControlError>>`) and handed to
//!   [`ActorRef::attach_stream`]. The stream then feeds the mailbox: each reply
//!   arrives as `StreamMessage::Next(Ok(Framed))` whether or not a command is in
//!   flight (so idle async-event drain is automatic), and a framing/socket error as
//!   `Next(Err(..))` so the actor fails with the specific cause. A handshake `Err`
//!   fails the spawn (DQ-T0.6); the ordering matters — the stream can't take the
//!   read half until the handshake's synchronous reads are done.
//! - **One in-flight command, FIFO, via `DelegatedReply` + `pending`/`queue`.** The
//!   control protocol has no request IDs, so a reply is correlated purely by order.
//!   A [`Command`] handler writes the bytes, stashes its [`ReplySender`] in
//!   `pending`, and returns a [`DelegatedReply`] marker *without* replying inline;
//!   the `StreamMessage::Next(Ok(CommandReply))` handler pops `pending` and sends
//!   the reply. Because `DelegatedReply` lets a *second* command's handler run while
//!   `pending` is still set, the slot alone is not enough — a `queue` holds
//!   commands that arrive while one is on the wire, so "two commands on the wire"
//!   is unrepresentable rather than merely avoided by callers.
//!
//! Any framing/socket error or stream close fails the actor rather than
//! reconnecting into the same desync; for a **managed** child, `TAKEOWNERSHIP`
//! (issued first, post-auth) means Tor exits when this connection drops, so a crash
//! one millisecond later is still orphan-protected (an attached tor is not ours, so
//! it is not taken).
//!
//! One property to know (not a defect): kameo runs handlers to completion on a
//! single task, so a slow `write_line` inside a command handler stalls event
//! draining (head-of-line). The loopback transport + tiny command lines make that
//! non-practical here.
//!
//! [`framing`]: super::framing
//! [`safecookie`]: super::safecookie
//! [`auth`]: super::auth
//! [`ActorRef::attach_stream`]: kameo::actor::ActorRef::attach_stream

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures_core::Stream;
use kameo::actor::{ActorRef, WeakActorRef};
use kameo::error::ActorStopReason;
use kameo::message::{Context, Message, StreamMessage};
use kameo::reply::{DelegatedReply, ReplySender};
use kameo::Actor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::auth::{parse_authchallenge, read_cookie_file, AuthError};
use super::bootstrap::{bootstrap_step, parse_bootstrap_progress, BootstrapState, BootstrapStep};
use super::encoding::hex_upper;
use super::framing::{ControlReply, Framed, FramingError, ReplyBudget, ReplyFramer};
use super::onion::{AddOnion, ServiceId};
use super::safecookie::verify_server_hash;
use super::vanguards::HsLayerPins;
use crate::binary::VerifiedTorBinary;

/// Per-read bound on a hung control port — a handshake read that does not complete
/// in this window fails the spawn (DQ-T0.6) rather than hanging the actor.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Read-chunk size for draining the socket into the framer.
const READ_CHUNK: usize = 4096;

/// How long a **managed** `tor` gets to exit on `SIGTERM` before the shutdown escalates
/// to `SIGKILL`. `tor` flushes and exits within ~a second; this is the bound that makes
/// "SIGTERM + wait" a *bounded* wait, never an unbounded hang if `tor` wedges.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How long to wait for a spawned managed `tor` to write its `ControlPort` file before
/// giving up (a `tor` that never opens the control port cannot be driven).
const SPAWN_TIMEOUT: Duration = Duration::from_secs(30);

/// A failure in the control connection — handshake or runtime.
///
/// **Content-free**: every variant carries only a protocol status code, never a
/// fragment of the control-port payload or the cookie (same forensic discipline as
/// [`FramingError`]/[`AuthError`], which it wraps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The TCP connection to the control port could not be established.
    Connect,
    /// A socket read or write failed.
    Io,
    /// The reply stream desynchronised (see [`FramingError`]).
    Framing(FramingError),
    /// The cookie file or `AUTHCHALLENGE` reply was malformed (see [`AuthError`]).
    Auth(AuthError),
    /// A handshake command (`AUTHENTICATE`/`TAKEOWNERSHIP`) returned a non-`250`
    /// status — Tor refused. Carries only the code.
    Rejected {
        /// The non-`250` status Tor returned.
        status: u16,
    },
    /// `SERVERHASH` did not verify — the cookie disagrees (wrong file or an
    /// impostor on the control port). Authentication aborts.
    ServerHashMismatch,
    /// The OS CSPRNG failed to produce the client nonce.
    Nonce,
    /// The connection closed mid-handshake (EOF before a complete reply).
    ConnectionClosed,
    /// A handshake read exceeded `HANDSHAKE_READ_TIMEOUT`.
    Timeout,
    /// A command reply arrived with no command in flight — an unsolicited reply,
    /// i.e. the stream is out of step. The actor fails rather than guess.
    Desync,
    /// The reply stream ended cleanly (EOF / socket close); the connection can no
    /// longer be served.
    StreamClosed,
    /// A command was malformed — an empty token list, an empty token, or a token
    /// with a forbidden character (ASCII control or space). Refused before reaching
    /// the wire, so it cannot send a malformed line, inject an extra control line,
    /// or desync the FIFO reply correlation. A caller error: the command is
    /// rejected, the connection is untouched.
    InvalidCommand,
    /// A **managed** `tor` could not be started or made driveable — every managed-spawn
    /// config/startup failure funnels here: a spawn / `create_dir_all` / stale-port-file
    /// error, `tor` exiting before it becomes driveable, or its `ControlPort` file / cookie
    /// not appearing within the `SPAWN_TIMEOUT` budget.
    /// Carries no path (forensic discipline); `spawn_managed_tor`'s own `--Log` file in the
    /// `DataDirectory` is where the specific cause is diagnosable.
    Spawn,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(f, "control port connection failed"),
            Self::Io => write!(f, "control socket I/O error"),
            Self::Framing(e) => write!(f, "control reply framing error: {e}"),
            Self::Auth(e) => write!(f, "control authentication error: {e}"),
            Self::Rejected { status } => {
                write!(f, "control command rejected with status {status}")
            }
            Self::ServerHashMismatch => write!(f, "SERVERHASH did not verify"),
            Self::Nonce => write!(f, "CSPRNG failed to produce a client nonce"),
            Self::ConnectionClosed => write!(f, "control connection closed mid-handshake"),
            Self::Timeout => write!(f, "control handshake read timed out"),
            Self::Desync => write!(f, "unsolicited control reply (no command in flight)"),
            Self::StreamClosed => write!(f, "control reply stream ended"),
            Self::InvalidCommand => write!(
                f,
                "control command was malformed (empty or forbidden character)"
            ),
            Self::Spawn => write!(f, "managed tor failed to launch or become driveable"),
        }
    }
}

impl std::error::Error for ControlError {}

/// Where asynchronous `650` events (`STREAM`, `STATUS_CLIENT`, …) are routed — the
/// bootstrap gate / measurement consumer. The actor only ever *sends* into it.
///
/// Carries [`ControlReply`]s, a forensic surface, so it is not `Debug`.
///
/// **Unbounded by design:** the actor must never block on its consumer — `route`
/// is non-blocking and drops on a closed receiver, so a slow consumer can't stall
/// the read loop. The deliberate residual is that a *stalled* (alive-but-not-
/// draining) consumer grows memory without bound; this is bounded in practice by
/// the loopback control port's low event rate.
///
/// `Clone` so the §3c supervisor can hand each incarnation the same long-lived
/// sink (the consumer's receiver survives restarts; senders are per-incarnation).
/// **Consequence for consumers:** because the supervisor retains a sender clone
/// across restarts, the events receiver does *not* observe all-senders-dropped
/// when an incarnation dies — a supervised consumer must detect incarnation death
/// via the [`service::TorService`](crate::service::TorService) posture watch, not
/// via `recv() == None` (which is correct only for a directly-spawned, sole-sender
/// actor).
#[derive(Clone)]
pub struct EventSink(mpsc::UnboundedSender<ControlReply>);

impl EventSink {
    /// Wrap the sending half of an event channel; the consumer keeps the receiver.
    #[must_use]
    pub fn new(sender: mpsc::UnboundedSender<ControlReply>) -> Self {
        Self(sender)
    }

    /// A sink with no consumer — **the correct production value today**, and a
    /// place to notice when it stops being one.
    ///
    /// Async `650` events arrive only after a `SETEVENTS`
    /// ([`Command::SetEvents`]), and no production call site issues one: the
    /// DQ-T0.4 `STREAM` measurement is a harness, and §3c's retraction settled
    /// that bootstrap readiness is a `GETINFO` **poll**, not a subscription
    /// ("a `GETINFO` poll is a command, not a subscription, so it never touches
    /// `SETEVENTS`"). So in production this sink receives nothing, ever, and
    /// wiring a consumer to it would be wiring a consumer to silence.
    ///
    /// This exists rather than an inline `let (tx, _rx) = unbounded_channel()`
    /// because that shape is indistinguishable from a caller who dropped the
    /// receiver by accident. Whoever adds the first production `SETEVENTS` has
    /// to replace a call named `unsubscribed`, which is a question a reviewer
    /// can see; deleting an anonymous `_rx` is not.
    ///
    /// The returned sink drops every event, and nothing accumulates: routing
    /// treats a closed receiver as "the consumer is gone" and discards. (Stated
    /// rather than linked — the routing method is private, and a public doc
    /// that links into it fails the crate's `rustdoc -D warnings` gate.)
    #[must_use]
    pub fn unsubscribed() -> Self {
        // The receiver is dropped here on purpose, which is what closes the
        // channel and makes every later send a no-op. Named constructor, so
        // the drop is the documented behaviour rather than a caller's slip.
        let (tx, _rx) = mpsc::unbounded_channel();
        Self(tx)
    }

    /// Route an async event to the consumer. A closed receiver means the consumer
    /// is gone, so dropping the event is correct — not a failure the actor acts on.
    fn route(&self, reply: ControlReply) {
        self.0.send(reply).ok();
    }
}

/// A control command the engine asks the actor to run, **one in flight at a time**.
///
/// The enum extends without reshaping the actor, which is what let the SP-T3
/// onion surface ([`Command::AddOnion`] / [`Command::DelOnion`]) land as two more
/// variants rather than a second actor. `TAKEOWNERSHIP` remains absent by design:
/// it is issued internally as the first command after `AUTHENTICATE`, not
/// engine-driven.
///
/// **Not `Clone`, and not `PartialEq`.** `AddOnion` carries the persona's onion
/// secret key ([`OnionKey`](super::onion::OnionKey)), so the enum inherits that
/// type's discipline: a
/// derived `Clone` would silently duplicate the key outside its `Zeroize`
/// wrapper, and a derived `PartialEq` would compare secret bytes non-constant-time.
/// The `Debug` derive is safe because every secret-bearing member redacts its own.
#[derive(Debug)]
pub enum Command {
    /// `GETINFO <keys>` — e.g. `status/bootstrap-phase`, `version`, circuit info.
    GetInfo(Vec<String>),
    /// `SETEVENTS <events>` — subscribe to async events (`STREAM` for the
    /// DQ-T0.4 measurement).
    SetEvents(Vec<String>),
    /// `ADD_ONION ED25519-V3:<key> …` — publish the persona's v3 onion service
    /// (SP-T3). Built from typed parts, so it cannot render a malformed line;
    /// see [`onion`](super::onion) for why that is a type property here rather
    /// than a validation.
    AddOnion(AddOnion),
    /// `DEL_ONION <service-id>` — tear the service down. Issued on the actor's
    /// shutdown path as well as on demand.
    DelOnion(ServiceId),
    /// `SETCONF HSLayer2Nodes=… HSLayer3Nodes=…` — pin the serving persona's
    /// vanguard layer-2/layer-3 guard sets (VG-1). Built from typed
    /// [`RelayFingerprint`](super::vanguards::RelayFingerprint)s, so — like
    /// `ADD_ONION` — it cannot render a line that injects a second command,
    /// which is what makes it safe to add `SETCONF` (the dangerous verb) to
    /// this surface without a validated-string path.
    SetConf(HsLayerPins),
}

/// The one `GETINFO` key whose reply is legitimately megabytes: the full network
/// status vanguard selection draws from.
///
/// Named here because it is the **whole** justification for
/// [`BULK_REPLY_BYTES`]: the wide framer allowance is granted for this key's
/// round trip and withdrawn again, so adding a second bulk command is a
/// deliberate edit to this list rather than a cap everybody already pays for.
const BULK_REPLY_KEYS: [&str; 1] = ["ns/all"];

impl Command {
    /// Does this command's reply need the [`BULK_REPLY_BYTES`] allowance?
    fn needs_bulk_reply(&self) -> bool {
        match self {
            Self::GetInfo(keys) => keys.iter().any(|k| BULK_REPLY_KEYS.contains(&k.as_str())),
            _ => false,
        }
    }

    /// The wire line (without the trailing CRLF), or [`ControlError::InvalidCommand`]
    /// if a token-list command is empty or any token carries a forbidden character.
    ///
    /// **Two shapes meet here, deliberately.** The token-list commands (`GETINFO`,
    /// `SETEVENTS`) take caller-supplied strings and are therefore *validated*:
    /// an empty list would render as a malformed trailing-space line
    /// (`"GETINFO "`), and a token containing a space (the separator) or an ASCII
    /// control byte — notably `\r`/`\n` — could split into extra control commands
    /// and desync the no-request-ID FIFO correlation. Validating before the line
    /// is built keeps both off the wire.
    ///
    /// The onion commands take **typed arguments that cannot render an invalid
    /// token at all** ([`onion`](super::onion)), so their arms are infallible.
    /// The wider, more attacker-adjacent input (a key blob and flag/port
    /// arguments) is the reason it is worth making the bad state unrepresentable
    /// instead of adding more string checks to the same validator.
    ///
    /// The result is [`Zeroizing`] because the `ADD_ONION` line embeds the
    /// base64-encoded onion secret key; the other arms produce no secret, but a
    /// uniform return type keeps the one secret-bearing line from being the
    /// exceptional path a future edit forgets.
    fn to_wire(&self) -> Result<Zeroizing<String>, ControlError> {
        let (verb, tokens) = match self {
            Self::GetInfo(keys) => ("GETINFO", keys),
            Self::SetEvents(events) => ("SETEVENTS", events),
            // Infallible by construction — no validation step exists to fail.
            Self::AddOnion(add) => return Ok(add.to_wire_line()),
            Self::DelOnion(id) => return Ok(Zeroizing::new(format!("DEL_ONION {}", id.as_str()))),
            // Also infallible: every value is a `$hex` specifier that cannot
            // carry a space or control byte (see `vanguards`).
            Self::SetConf(pins) => return Ok(Zeroizing::new(pins.to_wire_line())),
        };
        if tokens.is_empty() {
            return Err(ControlError::InvalidCommand);
        }
        for token in tokens {
            if token.is_empty() || token.bytes().any(|b| b == b' ' || b.is_ascii_control()) {
                return Err(ControlError::InvalidCommand);
            }
        }
        Ok(Zeroizing::new(format!("{verb} {}", tokens.join(" "))))
    }
}

/// Reply type the caller of a [`Command`] receives.
pub type CommandResult = Result<ControlReply, ControlError>;

/// What the actor owes a reply beyond handing it to the caller.
///
/// The control protocol has no request IDs, so by the time a reply arrives the
/// actor has forgotten which command produced it. Most commands need nothing —
/// but `ADD_ONION`'s reply carries the `ServiceID=` the shutdown path must
/// `DEL_ONION`, so the one bit of "what was this" travels alongside the
/// [`ReplySender`] rather than being re-derived from the reply's shape (which
/// would misfire on any future command whose reply happens to look similar).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingKind {
    /// Forward the reply; nothing else.
    Plain,
    /// An `ADD_ONION`: on success, record the service id for teardown.
    AddOnion,
}

/// Everything the actor must remember about the command currently on the wire:
/// what its reply owes the actor, and how large that reply may be.
///
/// The size axis is separate from [`PendingKind`] because it is answered by a
/// different question — not "what is this reply for" but "how many bytes may the
/// framer buffer while it arrives" — and it travels with the queued line so the
/// allowance is armed when the command reaches the wire, not when it is enqueued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    /// What the reply owes the actor beyond forwarding.
    kind: PendingKind,
    /// `true` for a [`BULK_REPLY_KEYS`] command — the only case that holds the
    /// wide framer allowance, withdrawn the moment its reply lands.
    bulk: bool,
}

/// Spawn-time configuration ([`Actor::Args`]).
pub struct TorControlConfig {
    /// How the actor obtains its control port — spawn-and-own `tor`, or attach to a
    /// running one. The **launch mode** is the thing that varies, not a nullable
    /// address: an attached actor cannot carry a spurious binary path, and a managed
    /// one cannot be missing it.
    pub launch: TorLaunch,
    /// Sink for asynchronous events.
    pub events: EventSink,
    /// Bootstrap-readiness publisher. The actor's poll task drives the
    /// `watch<BootstrapState>`; the consumer holds the receiver (design §3b).
    pub readiness: BootstrapReadiness,
}

/// How the [`TorControl`] actor gets its control port (DQ-T0.1 process ownership).
pub enum TorLaunch {
    /// The actor **spawns and owns** the `tor` process — the production path. It kills
    /// the child on shutdown (`SIGTERM` → bounded wait → `SIGKILL` → reap).
    Managed(ManagedTor),
    /// Connect to an **already-running** control port the actor does *not* own — the
    /// test path (tor spawned externally), and any bring-your-own-`tor` deployment.
    /// Shutdown leaves the process alone; it is not ours to kill.
    Attached {
        /// The loopback control-port address.
        control_addr: SocketAddr,
        /// Path to `DataDirectory/control_auth_cookie`.
        cookie_path: PathBuf,
    },
}

/// How the managed tor's `SocksPort` is chosen — a typed knob (like
/// `disable_network`), not a bare integer with a magic zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksPort {
    /// `SocksPort auto`: tor picks a free port; the caller discovers it post-Ready
    /// via `GETINFO net/listeners/socks`. The production (§3c supervisor) choice —
    /// immune to restart re-bind races by construction.
    Auto,
    /// A caller-chosen fixed port — harnesses and bring-your-own-layout setups.
    Fixed(u16),
}

impl SocksPort {
    /// The `--SocksPort` command-line value.
    fn as_arg(self) -> String {
        match self {
            Self::Auto => "auto".to_owned(),
            Self::Fixed(port) => port.to_string(),
        }
    }
}

/// A managed `tor` to spawn (DQ-T0.1). The actor launches it with a wallet-private
/// `DataDirectory`, a `ControlPort auto` written to a file, cookie authentication, and
/// the given `SocksPort`, then connects to the port it opened.
pub struct ManagedTor {
    /// The `tor` binary to spawn — **only a hash-pin-verified witness is accepted**
    /// (SP-T0c). The sole production mints are `binary::discover_and_verify` /
    /// `binary::discover_and_verify_at`, so a spawn path *cannot* skip verification:
    /// the gate is enforced by this type, not by convention (the same structural
    /// posture as `disable_network` below). Tests inject an unpinned tor via the
    /// loudly-named `VerifiedTorBinary::unchecked_for_test`.
    pub tor_binary: VerifiedTorBinary,
    /// Wallet-private `DataDirectory` — **persistent across wallet sessions**
    /// (DQ-T0.7, decided): the dir carries tor's entry-guard identity (`state`),
    /// and reusing it is what keeps the guard set stable (rotating it per session
    /// would multiply malicious-guard draws and be a deviation-from-defaults
    /// signature). Placement contract: wallet-adjacent, wallet-controlled,
    /// **non-world-writable** (also the SP-T0c TOCTOU layout requirement); tor
    /// tightens it to `0700`. At-rest protection is *inherited* from the storage
    /// the wallet lives on — tor reads plaintext, so the wallet's file envelope
    /// cannot cover it (disclosed in the design doc's DQ-T0.7).
    pub data_dir: PathBuf,
    /// Wallet-private `SocksPort` — SP-T1's `PTorClient`s dial it. Production (the
    /// §3c supervisor) uses [`SocksPort::Auto`] and discovers the bound address via
    /// `GETINFO net/listeners/socks`, publishing it on the posture channel — a fixed
    /// port can race the previous incarnation's dying socket on restart. Harnesses
    /// pick [`SocksPort::Fixed`].
    pub socks_port: SocksPort,
    /// Spawn `tor` with `--DisableNetwork 1` — an offline instance (opens its control port
    /// and SOCKS port, but never touches the network, so it never bootstraps). The
    /// child-lifecycle test sets this to isolate spawn+shutdown from a real bootstrap;
    /// **production always leaves it `false`** (a managed tor must reach the network).
    ///
    /// This is deliberately a *typed knob*, not an arbitrary `extra_args` passthrough: the
    /// managed spawn owns its safety invariants (loopback control port, cookie auth, its
    /// `DataDirectory`/`SocksPort`), and a free-form flag list can smuggle those open —
    /// directly, or indirectly via `-f <torrc>` / `+Option` append / `--defaults-torrc`,
    /// which no denylist reliably covers. Future customization (bridges, an upstream proxy)
    /// is added as further **typed, safe-by-construction** knobs, so the control-plane
    /// invariant stays *structural* rather than validated.
    pub disable_network: bool,
    /// Optional shutdown-outcome observer — the **production telemetry hook**, currently
    /// exercised only by the test. After the bounded shutdown wait, `on_stop` reports how
    /// the child exited ([`TorExit`]); a [`TorExit::Killed`] (an unclean shutdown — tor
    /// wedged and was SIGKILLed, or the grace wait errored) is the signal the
    /// wallet-integration layer will want to surface. `None` today; the lifecycle test
    /// uses it to assert a *real* reap rather than probing a pid.
    pub exit_observer: Option<oneshot::Sender<TorExit>>,
}

/// The control-port actor (one `TorService` actor). Owns the write half and the
/// in-flight bookkeeping; the read half lives in the attached `ReplyStream`, the
/// managed child (if any) in `child`, and the bootstrap poll task in `bootstrap_poll`.
pub struct TorControl {
    /// Write half — commands go out here, one on the wire at a time.
    writer: OwnedWriteHalf,
    /// Async-event sink.
    events: EventSink,
    /// The command currently on the wire, awaiting its reply (`DelegatedReply`),
    /// with what the actor must do with that reply beyond forwarding it.
    pending: Option<(ReplySender<CommandResult>, InFlight)>,
    /// The framer's live reply-size allowance. The actor owns it because only the
    /// actor knows which command is on the wire, and exactly one command
    /// ([`BULK_REPLY_KEYS`]) may buffer megabytes — everything else keeps the
    /// tight bound.
    budget: ReplyBudget,
    /// Commands that arrived while one was on the wire — their **already-validated
    /// wire lines** — drained FIFO as each reply lands, so order (the only reply
    /// correlation there is) is preserved. Storing the rendered line (not the
    /// `Command`) means `to_wire` runs exactly once per command.
    ///
    /// [`Zeroizing`] because a queued `ADD_ONION` line embeds the persona's onion
    /// secret key: a queued command may sit here across several reply round-trips,
    /// so the encoded key must be wiped when the entry is dropped rather than left
    /// in a freed allocation.
    queue: VecDeque<(Zeroizing<String>, ReplySender<CommandResult>, InFlight)>,
    /// Onion services this actor published, torn down with `DEL_ONION` on the
    /// shutdown path.
    ///
    /// **Why the actor tracks them rather than the caller:** the services are
    /// bound to *this control connection* (no `Detach` is expressible — see
    /// [`onion`](super::onion)), so the actor is the only component whose
    /// lifetime matches theirs. A caller-held list would be a second copy of the
    /// same fact, and the shutdown path would depend on the caller still being
    /// alive to hand it over — which on a crash path it is not.
    published_onions: Vec<ServiceId>,
    /// The managed `tor` child, for [`TorLaunch::Managed`]. `None` for
    /// [`TorLaunch::Attached`] — an attached `tor` is not ours to kill. `on_stop` takes
    /// it and runs the bounded shutdown.
    child: Option<TorChild>,
    /// The bootstrap-readiness poll task (design §3b), aborted on drop. Held so the
    /// actor owns its task; the task also self-terminates (`Ready` / actor-death /
    /// no-listeners), so this abort is a prompt-cleanup backstop, not the only exit.
    bootstrap_poll: JoinHandle<()>,
}

/// The managed `tor` child process the actor owns (present only for
/// [`TorLaunch::Managed`]). Spawned with `kill_on_drop`, so even a panic that skips
/// `on_stop` still SIGKILLs it — the last-resort backstop under `TAKEOWNERSHIP`.
struct TorChild {
    child: Child,
    exit_observer: Option<oneshot::Sender<TorExit>>,
}

/// How a managed `tor` child exited at shutdown (observed via [`ManagedTor::exit_observer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorExit {
    /// Exited on its own (`TAKEOWNERSHIP`, or tor dying) or on `SIGTERM` within the
    /// `SHUTDOWN_GRACE` window, and was reaped with this status — the clean path.
    Reaped(std::process::ExitStatus),
    /// Not cleanly reaped with a status: either tor wedged past the `SIGTERM` grace window
    /// and was `SIGKILL`-ed, or the grace `wait` itself errored. Either way the child was
    /// force-killed (best-effort) and reaped — an **unclean** shutdown.
    Killed,
}

impl TorChild {
    /// Shut the child down: **`SIGTERM` → bounded wait → `SIGKILL` → reap**, publishing
    /// the outcome to the observer if one is wired.
    ///
    /// Tolerant of an **already-exited** child by design: on the paths that stop the actor
    /// *because* the control connection dropped (an error-path `ctx.stop`), a managed
    /// tor's `TAKEOWNERSHIP` has already exited it — or tor died on its own — so the
    /// `SIGTERM` is a harmless `ESRCH` and the `wait` reaps immediately. (On a clean
    /// `on_stop` the connection is still open here, so `SIGTERM` is what exits tor;
    /// `TAKEOWNERSHIP` then fires as a backstop when the struct drops.) The `SIGKILL`
    /// escalation is what keeps the wait *bounded* — "SIGTERM + wait" without it would
    /// hang the wallet forever if `tor` ever wedged.
    async fn shutdown(mut self) {
        // Ask tor to exit gracefully (SIGTERM on Unix; DQ-T0.1). No-op if it already
        // exited, and a no-op off Unix — there the timeout → `kill()` escalation is the
        // whole shutdown.
        request_graceful_stop(&self.child);
        let exit = match timeout(SHUTDOWN_GRACE, self.child.wait()).await {
            // Exited within the grace window (SIGTERM or TAKEOWNERSHIP) — reaped cleanly.
            Ok(Ok(status)) => TorExit::Reaped(status),
            // Either the grace `wait` errored, or it timed out (tor wedged): both mean
            // "not cleanly reaped", so SIGKILL and reap unconditionally. `start_kill` kills
            // the process even if the reap can't complete, so neither case leaves a running
            // or zombie tor. (A `wait` error is usually "already reaped", where this is a
            // harmless no-op; but if it isn't, the child is still terminated.)
            Ok(Err(_)) | Err(_) => {
                kill_and_reap(&mut self.child).await;
                TorExit::Killed
            }
        };
        if let Some(tx) = self.exit_observer {
            tx.send(exit).ok();
        }
    }
}

/// Request a graceful stop of a managed `tor` — `SIGTERM` on Unix (DQ-T0.1). Harmless if
/// the child already exited (`ESRCH`).
#[cfg(unix)]
fn request_graceful_stop(child: &Child) {
    if let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) {
        // SAFETY: `kill(2)` with a pid this process owns and a constant signal number; it
        // reads/writes no memory. A stale pid returns `ESRCH`, ignored. (`try_from` guards
        // the u32→pid_t width — unreachable for a real pid, but honest about it.)
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

/// No graceful-stop signal off Unix: the `wait`-timeout → `Child::kill`
/// (`TerminateProcess`) escalation drives shutdown there instead. A graceful non-Unix
/// path — closing the control connection for `TAKEOWNERSHIP`, or a console control event
/// — is a follow-up for when a non-Unix target is real; today the managed launch is Unix.
#[cfg(not(unix))]
fn request_graceful_stop(_child: &Child) {}

/// SIGKILL a managed child and reap it — a best-effort signal, then an **unconditional**
/// `wait`, so no path leaves a running process or a zombie. `start_kill` (not `kill()`)
/// keeps the two separable: even if the signal errors (the child raced to exit), the
/// `wait` still runs. Bounded — SIGKILL is uninterceptable, so the `wait` returns promptly.
async fn kill_and_reap(child: &mut Child) {
    child.start_kill().ok();
    child.wait().await.ok();
}

/// How often the bootstrap poll task asks `GETINFO status/bootstrap-phase`. Bootstrap
/// is a one-time startup event over tens of seconds, so a sub-second poll adds
/// negligible latency to the readiness signal.
const BOOTSTRAP_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The bootstrap-readiness publisher handed to the actor via [`TorControlConfig`].
///
/// Wraps the [`watch`] sender **and owns the channel's creation**, so the initial
/// state is always [`BootstrapState::Connecting`]` { progress: 0 }` — a consumer never
/// names an initial value and so cannot seed a spurious `Ready` before bootstrap even
/// begins. This is one step past [`EventSink`], which takes a pre-made sender: `watch`
/// has an initial-value footgun `mpsc` lacks, so the wrapper closes exactly that gap
/// (the make-bad-states-unrepresentable posture).
pub struct BootstrapReadiness(watch::Sender<BootstrapState>);

impl BootstrapReadiness {
    /// Create the readiness channel. The consumer keeps the returned receiver and
    /// awaits [`BootstrapState::Ready`]; the actor takes `self` in its config.
    #[must_use]
    pub fn new() -> (Self, watch::Receiver<BootstrapState>) {
        let (tx, rx) = watch::channel(BootstrapState::Connecting { progress: 0 });
        (Self(tx), rx)
    }
}

impl Actor for TorControl {
    type Args = TorControlConfig;
    type Error = ControlError;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let TorControlConfig {
            launch,
            events,
            readiness,
        } = args;

        // Managed: spawn tor and connect to the port it opened. Attached: connect to the
        // given one. `connect`, the handshake, and the poll are identical; the only
        // mode-specific steps are the spawn, `TAKEOWNERSHIP` (managed only — see below),
        // and `on_stop`'s kill (managed only).
        let (control_addr, cookie_path, child) = match launch {
            TorLaunch::Managed(managed) => {
                let (child, addr, cookie) = spawn_managed_tor(managed).await?;
                (addr, cookie, Some(child))
            }
            TorLaunch::Attached {
                control_addr,
                cookie_path,
            } => (control_addr, cookie_path, None),
        };

        // Run the handshake, then arm the actor. A **managed** child is reaped explicitly on
        // any handshake failure — uniform with `spawn_managed_tor`, and per tokio's own
        // guidance an explicit `wait` is preferred over `kill_on_drop`'s best-effort reap for
        // a stricter cleanup guarantee. (Attached has no child to reap.)
        let (reader, writer, framer) =
            match handshake(control_addr, &cookie_path, child.is_some()).await {
                Ok(halves) => halves,
                Err(e) => {
                    if let Some(mut c) = child {
                        kill_and_reap(&mut c.child).await;
                    }
                    return Err(e);
                }
            };

        // Handshake done — hand the read half to the stream and let kameo merge it
        // into the mailbox. The budget cell is shared with the stream's framer: the
        // stream charges against it, the actor sets it per command.
        let budget = framer.budget();
        actor_ref.attach_stream(
            ReplyStream {
                read: reader,
                framer,
                done: false,
            },
            (),
            (),
        );

        // Spawn the bootstrap poll task (design §3b): it drives the readiness watch
        // through the public `ask` — a `GETINFO status/bootstrap-phase` poll, *not* a
        // `STATUS_CLIENT` subscription, so it never touches `SETEVENTS`. Its first
        // `ask` queues behind the run loop that begins once `on_start` returns.
        let bootstrap_poll = tokio::spawn(bootstrap_poll_loop(actor_ref.clone(), readiness.0));

        Ok(TorControl {
            writer,
            events,
            pending: None,
            budget,
            queue: VecDeque::new(),
            published_onions: Vec::new(),
            child,
            bootstrap_poll,
        })
    }

    /// Clean shutdown (wallet close): withdraw the persona's onion services, then kill
    /// the managed child. `TAKEOWNERSHIP` (landed in PR-2) is the *crash* backstop — a
    /// panic / SIGKILL sends no `on_stop`, and the control connection dropping then exits
    /// `tor` — but on a clean stop the connection is still open here, so this is the
    /// primary path. Attached mode has no child to kill. (The bootstrap poll task is
    /// aborted in `Drop`.)
    ///
    /// **`DEL_ONION` runs first, and the order is load-bearing.** Killing the child
    /// first would take the services down too, but only for a *managed* tor; against an
    /// **attached** tor (`TorLaunch::Attached` — bring-your-own-`tor`, and every
    /// integration harness) there is no child to kill, so without this step the persona's
    /// services would keep running inside someone else's long-lived tor after the wallet
    /// closed — still publishing descriptors that assert the persona is online while
    /// nothing is left to serve a byte. That is the same orphan-advertisement failure
    /// `Detach` is excluded to prevent, arriving by a different route.
    ///
    /// Failures are swallowed: shutdown is best-effort by nature (the connection may
    /// already be dying, which is *why* we are stopping), and a `DEL_ONION` that cannot
    /// be written is one whose services tor is about to drop anyway when the connection
    /// closes.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        for id in std::mem::take(&mut self.published_onions) {
            let line = Zeroizing::new(format!("DEL_ONION {}", id.as_str()));
            if write_line(&mut self.writer, &line).await.is_err() {
                break;
            }
        }
        if let Some(child) = self.child.take() {
            child.shutdown().await;
        }
        Ok(())
    }
}

impl Drop for TorControl {
    fn drop(&mut self) {
        // Stop the bootstrap poll task when the actor goes away. The managed child (if
        // `on_stop` did not run — a panic path) is SIGKILLed by its `kill_on_drop`.
        self.bootstrap_poll.abort();
    }
}

/// Run the SAFECOOKIE handshake on a fresh control connection: connect, `AUTHCHALLENGE`,
/// verify the server hash, `AUTHENTICATE`, and — for a managed child (`take_ownership`) —
/// `TAKEOWNERSHIP`. Returns the split read/write halves + the framer for the actor to
/// attach. Synchronous request/response: no `650` events can arrive before `SETEVENTS`, so
/// the framer is read by hand here. On any `Err`, the caller reaps a managed child (this
/// function owns no process).
async fn handshake(
    control_addr: SocketAddr,
    cookie_path: &Path,
    take_ownership: bool,
) -> Result<(OwnedReadHalf, OwnedWriteHalf, ReplyFramer), ControlError> {
    let stream = TcpStream::connect(control_addr)
        .await
        .map_err(|_| ControlError::Connect)?;
    let (mut reader, mut writer) = stream.into_split();
    let mut framer = ReplyFramer::default();

    let cookie = read_cookie_file(cookie_path).map_err(ControlError::Auth)?;
    let mut client_nonce = [0u8; 32];
    getrandom::getrandom(&mut client_nonce).map_err(|_| ControlError::Nonce)?;

    write_line(
        &mut writer,
        &format!("AUTHCHALLENGE SAFECOOKIE {}", hex_upper(&client_nonce)),
    )
    .await?;
    let challenge = read_reply(&mut reader, &mut framer).await?;
    let (server_hash, server_nonce) =
        parse_authchallenge(&challenge).map_err(ControlError::Auth)?;
    let verified = verify_server_hash(
        &cookie,
        &client_nonce,
        server_nonce.as_array(),
        server_hash.as_array(),
    )
    .ok_or(ControlError::ServerHashMismatch)?;
    let client_hash = verified.client_hash();

    write_line(
        &mut writer,
        &format!("AUTHENTICATE {}", hex_upper(&client_hash)),
    )
    .await?;
    expect_status(&mut reader, &mut framer, 250).await?;

    // Orphan protection for the **managed** child (DQ-T0.1): `TAKEOWNERSHIP` makes tor exit
    // when this connection drops, so even a crash that skips `on_stop` leaves no orphan.
    // Managed only — it *takes ownership*, and an attached tor is explicitly not ours
    // (`TorLaunch::Attached`); issuing it there would exit a bring-your-own tor on close.
    if take_ownership {
        write_line(&mut writer, "TAKEOWNERSHIP").await?;
        expect_status(&mut reader, &mut framer, 250).await?;
    }

    Ok((reader, writer, framer))
}

/// Spawn a **managed** `tor` (DQ-T0.1): a wallet-private `DataDirectory`, `ControlPort
/// auto` written to a file, cookie auth, and the configured `SocksPort` — all owned by the
/// actor (a caller can only toggle the typed `disable_network` knob, never an arbitrary
/// flag). Waits (bounded) for the control-port file + cookie, then returns the child plus
/// the `(control_addr, cookie_path)` the handshake connects with. `kill_on_drop` is the
/// last-resort backstop.
async fn spawn_managed_tor(
    managed: ManagedTor,
) -> Result<(TorChild, SocketAddr, PathBuf), ControlError> {
    // Ensure the DataDirectory exists so a missing path fails *fast* here (an immediate
    // `Spawn` error) rather than as a silent 30s control-port-file timeout. Idempotent;
    // the actor owns the managed tor's DataDirectory, and tor secures it to 0700 — the
    // brief window before that is an empty dir, no secrets yet.
    tokio::fs::create_dir_all(&managed.data_dir)
        .await
        .map_err(|_| ControlError::Spawn)?;
    let port_file = managed.data_dir.join("control_port");
    // A stale port file from a prior run would be read as *this* run's port — remove it so
    // `wait_for_control_port` can only ever return a fresh value. `NotFound` is the normal
    // case (no prior run); any *other* error means a stale file we could not clear, so fail
    // fast rather than risk connecting to a stale control address. Async fs throughout so
    // the spawn never blocks a runtime worker (this actor is the pattern for future socket
    // actors — the async I/O should be correct, not just fast enough here).
    if let Err(e) = tokio::fs::remove_file(&port_file).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(ControlError::Spawn);
        }
    }

    // The witness type guarantees this path passed the hash-pin gate and is canonical
    // (the file hashed is the file named — no exec-time PATH re-search or cwd drift).
    let mut cmd = tokio::process::Command::new(managed.tor_binary.as_path());
    cmd.arg("--DataDirectory")
        .arg(&managed.data_dir)
        .arg("--ControlPort")
        .arg("auto")
        .arg("--ControlPortWriteToFile")
        .arg(&port_file)
        .arg("--CookieAuthentication")
        .arg("1")
        .arg("--SocksPort")
        .arg(managed.socks_port.as_arg())
        // A file log in the (0700, wallet-private) DataDirectory so a `Spawn` failure is
        // diagnosable — the actor's own errors stay content-free (no paths), but tor's
        // startup log names the cause (bad binary, torrc/CLI error, bind failure). `notice`
        // level carries bootstrap + warnings, not the C6 forensic surface (circuit IDs /
        // targets / SOCKS usernames are info/debug only), so it's safe to persist.
        //
        // The path is passed **unquoted on purpose** — do not "fix" this by quoting it. Tor's
        // `Log <severity> file <FILENAME>` grammar takes the *entire remainder* of the option
        // value as the filename, so an embedded space (a wallet DataDirectory under a spaced
        // user profile — `C:\Users\My Name\…`, `/Users/My Name/…`) is preserved verbatim.
        // Wrapping the path in quotes makes tor treat the literal `"` as part of the filename
        // and write the log to the wrong place. Verified against the bundled tor: unquoted
        // writes to the exact spaced path, quoted does not.
        .arg("--Log")
        .arg(format!(
            "notice file {}",
            managed.data_dir.join("tor.log").display()
        ))
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // ---------------------------------------------------------------------------------
    // NON-ANONYMOUS SERVING IS HELD SHUT HERE, and this is one half of a two-half rule.
    //
    // tor can be put into single-hop / non-anonymous onion mode by *two* independent
    // routes, and they are foreclosed by *different* mechanisms in *different* files:
    //
    //   1. `ADD_ONION`'s `NonAnonymous` flag — foreclosed **by type**: it is not a member
    //      of `control::onion::OnionFlags`, and `onion_line_is_never_non_anonymous`
    //      asserts over every representable flag/PoW combination that it can never reach
    //      the wire.
    //   2. **torrc / config** — `HiddenServiceNonAnonymousMode` (which additionally
    //      requires `SocksPort 0`) — foreclosed **by construction, right here**: the spawn
    //      surface is the six typed options above and nothing else. There is no
    //      `extra_args`, no `-f <torrc>`, no `+Option` append, no `--defaults-torrc`.
    //
    // The two halves cannot see each other, which is the hazard worth naming. The
    // `OnionFlags` test does not fire when someone adds a knob here, and the rationale
    // below is written about *safety invariants* generally, not about this mode
    // specifically. So: **when the anticipated future typed knobs arrive (bridges, an
    // upstream proxy), non-anonymous mode is on the list of things this discipline is
    // holding shut** — a knob that reaches `HiddenServiceNonAnonymousMode` or zeroes the
    // `SocksPort` re-opens route 2 while route 1's test stays green and silent.
    // ---------------------------------------------------------------------------------
    //
    // The one caller-toggleable knob (see `ManagedTor::disable_network`): an offline tor for
    // the child-lifecycle test. Every other flag is actor-owned, so this is the *only* place
    // caller intent reaches the command line — a typed bool, not a flag passthrough.
    if managed.disable_network {
        cmd.arg("--DisableNetwork").arg("1");
    }
    let mut child = cmd.spawn().map_err(|_| ControlError::Spawn)?;

    // Bounded startup: wait for tor to become driveable — its control-port file *and* its
    // auth cookie. Tor writes them at startup but not atomically, so reading the cookie the
    // instant the port file appears can race a partial/absent write (an `AuthError` startup
    // race); waiting for the cookie here means a transient partial write isn't a spurious
    // `Auth` failure that kills the just-spawned tor.
    let cookie_path = managed.data_dir.join("control_auth_cookie");
    // Race the readiness wait against the child's own exit: a tor that dies immediately (bad
    // binary, bind failure, CLI error) must fail *fast*, not wait out `SPAWN_TIMEOUT` for a
    // port/cookie that will never appear. `child.wait()` in the losing arm reaps that case;
    // the unconditional `kill_and_reap` below then covers the readiness-timeout arm (child
    // still running) and is a harmless no-op after an already-reaped exit.
    // One shared deadline across *both* readiness waits — the control-port file, then the
    // cookie. Total startup is bounded by a single `SPAWN_TIMEOUT`, not `SPAWN_TIMEOUT` *per*
    // wait: the cookie lands moments after the port file, so whatever the port poll leaves of
    // the budget is ample for it, and a tor that never becomes driveable fails at the *one*
    // deadline rather than after ~2×. That is what makes "bounded startup" actually bounded.
    let deadline = tokio::time::Instant::now() + SPAWN_TIMEOUT;
    let ready = tokio::select! {
        r = async {
            let control_addr = wait_for_control_port(&port_file, deadline).await?;
            wait_for_cookie(&cookie_path, deadline).await?;
            Ok::<_, ControlError>(control_addr)
        } => r,
        _ = child.wait() => Err(ControlError::Spawn),
    };
    let control_addr = match ready {
        Ok(addr) => addr,
        Err(e) => {
            // Startup failed — terminate + reap the child *here* (not via `kill_on_drop`'s
            // best-effort background reap) so nothing lingers to disturb the next spawn/test.
            // (`kill_on_drop` remains the backstop for a `?`-failure in the *handshake* after
            // this returns Ok, where the child is held in on_start's local.)
            kill_and_reap(&mut child).await;
            return Err(e);
        }
    };
    Ok((
        TorChild {
            child,
            exit_observer: managed.exit_observer,
        },
        control_addr,
        cookie_path,
    ))
}

/// Parse a `ControlPortWriteToFile` `PORT=` value. The usual TCP form is `<addr>:<port>`,
/// but some tor builds/configs write a bare `<port>`; since the actor's `ControlPort auto`
/// binds **loopback**, a port-only value means `127.0.0.1:<port>`. Accepting both keeps the
/// managed spawn from spuriously timing out on a valid-but-shorter format.
fn parse_control_port(value: &str) -> Option<SocketAddr> {
    let value = value.trim();
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr);
    }
    let port: u16 = value.parse().ok()?;
    Some(SocketAddr::from(([127, 0, 0, 1], port)))
}

/// Poll the `ControlPortWriteToFile` until it carries a parseable `PORT=` line, bounded by
/// the shared startup `deadline` (`spawn_managed_tor` gives one budget to this *and* the
/// cookie wait). Async so the backoff yields the runtime rather than blocking a worker thread.
async fn wait_for_control_port(
    port_file: &Path,
    deadline: tokio::time::Instant,
) -> Result<SocketAddr, ControlError> {
    loop {
        if let Ok(contents) = tokio::fs::read_to_string(port_file).await {
            if let Some(addr) = contents
                .lines()
                .find_map(|line| line.strip_prefix("PORT="))
                .and_then(parse_control_port)
            {
                return Ok(addr);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ControlError::Spawn);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll until tor's control-auth cookie is fully written, bounded by the shared startup
/// `deadline` (see [`spawn_managed_tor`] — the same budget the control-port wait draws from).
/// Checks the file **length** via async `metadata` — non-blocking (unlike a `read_cookie_file`
/// poll), and it never reads the secret in a loop. The SAFECOOKIE cookie is exactly 32 bytes,
/// so a shorter file is a partial write to retry past; that is the whole condition of the
/// startup race (tor has written its port file but not yet its complete cookie). The
/// authoritative validated read — the exact 32-byte length gate — happens once, later, in the
/// handshake ([`read_cookie_file`]); this only gates *when* it is safe to attempt. (The
/// cookie's confidentiality rests on the 0700 wallet-private `DataDirectory`, not on a
/// wallet-side permission re-check.)
async fn wait_for_cookie(
    cookie_path: &Path,
    deadline: tokio::time::Instant,
) -> Result<(), ControlError> {
    /// The SAFECOOKIE control-auth cookie (control-spec §3.24) is exactly 32 bytes.
    const COOKIE_LEN: u64 = 32;
    loop {
        if tokio::fs::metadata(cookie_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0)
            == COOKIE_LEN
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ControlError::Spawn);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The bootstrap-readiness poll task (design §3b). Polls `GETINFO
/// status/bootstrap-phase` through the actor's **public `ask`** and publishes
/// [`BootstrapState`] on the watch until Tor reaches 100%, then stops.
///
/// The complete error contract — the task's whole failure surface:
/// - **`ask` fails** → the actor stopped (control connection died mid-bootstrap):
///   publish [`BootstrapState::Failed`] and exit, so a waiter gets a terminal answer
///   instead of hanging to the lifecycle deadline (which is T0b-2 *policy*, not this
///   task's concern).
/// - **no receivers left** → stop **silently**, checked *unconditionally* at the top of
///   each iteration via `tx.is_closed()` — so shutdown never depends on a `send`
///   happening. A run of unparseable replies (parse → `None`, no `send`) must not keep
///   the task polling a channel no one is listening on. Not a Tor failure; never `Failed`.
/// - **100% reached** → publish [`BootstrapState::Ready`] (the gate) and stop.
async fn bootstrap_poll_loop(actor: ActorRef<TorControl>, tx: watch::Sender<BootstrapState>) {
    // The highest progress seen so far; `bootstrap_step` clamps against it so a Tor
    // `PROGRESS=` regression never renders the "Connecting… n%" UX backward.
    let mut peak = 0u8;
    loop {
        // No receivers left — stop quietly (NOT a failure). Checked here so shutdown is
        // *unconditional*, not contingent on a `send`: a run of `None` parses must never
        // keep the task polling a channel no one is listening on.
        if tx.is_closed() {
            return;
        }
        let Ok(reply) = actor
            .ask(Command::GetInfo(vec!["status/bootstrap-phase".to_owned()]))
            .await
        else {
            // Actor gone — the control connection died mid-bootstrap.
            tx.send(BootstrapState::Failed).ok();
            return;
        };
        // The state machine is the pure `bootstrap_step` (KAT'd in `bootstrap`); the loop
        // owns only the I/O. Sends are fire-and-forget — a dropped-receiver failure is
        // handled by the `is_closed()` check at the top, the single shutdown path.
        let (step, new_peak) = bootstrap_step(peak, parse_bootstrap_progress(&reply));
        peak = new_peak;
        match step {
            BootstrapStep::Ready => {
                tx.send(BootstrapState::Ready).ok();
                return;
            }
            BootstrapStep::Progress(progress) => {
                tx.send(BootstrapState::Connecting { progress }).ok();
            }
            BootstrapStep::Skip => {}
        }
        tokio::time::sleep(BOOTSTRAP_POLL_INTERVAL).await;
    }
}

impl TorControl {
    /// Fail every in-flight and queued caller with `err` — the actor is stopping.
    fn fail_all_pending(&mut self, err: &ControlError) {
        if let Some((tx, _in_flight)) = self.pending.take() {
            tx.send(Err(err.clone()));
        }
        for (_line, tx, _in_flight) in self.queue.drain(..) {
            tx.send(Err(err.clone()));
        }
        // Nothing is on the wire, so no reply is entitled to the wide allowance.
        self.budget.restore_ordinary();
    }

    /// Put an already-validated command line on the wire and take ownership of
    /// its reply. The single place a command is dispatched, so the framer's
    /// allowance cannot drift out of step with what is actually in flight.
    ///
    /// **The allowance is armed before the write, not after.** The reply can
    /// begin arriving the instant the bytes land, and the [`ReplyStream`] that
    /// charges against the budget is polled on its own task — so arming
    /// afterwards leaves a window in which the legitimate multi-megabyte
    /// `ns/all` reply is charged against [`ORDINARY_REPLY_BYTES`] and trips
    /// `ReplyTooLarge`, which the actor treats as a desync it will not reconnect
    /// into. Arming first is not merely earlier, it is *provably* before any byte
    /// of that reply can exist: one command is on the wire at a time, so the
    /// reply cannot precede the command that asks for it.
    ///
    /// `Err` means the wire is disturbed and every pending caller has already
    /// been failed (which withdraws the allowance again) — the caller stops the
    /// actor.
    async fn dispatch(
        &mut self,
        line: &str,
        tx: ReplySender<CommandResult>,
        in_flight: InFlight,
    ) -> Result<(), ControlError> {
        if in_flight.bulk {
            self.budget.arm_bulk();
        } else {
            self.budget.restore_ordinary();
        }
        match write_line(&mut self.writer, line).await {
            Ok(()) => {
                self.pending = Some((tx, in_flight));
                Ok(())
            }
            // An Io failure mid-write disturbs the wire; fail the actor.
            Err(e) => {
                tx.send(Err(e.clone()));
                self.fail_all_pending(&e);
                Err(e)
            }
        }
    }
}

impl Message<Command> for TorControl {
    type Reply = DelegatedReply<CommandResult>;

    async fn handle(&mut self, cmd: Command, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let (delegated, reply_sender) = ctx.reply_sender();
        // What this command's reply will owe the actor, and how large it may be —
        // captured before `cmd` is consumed by `to_wire`.
        let in_flight = InFlight {
            kind: match &cmd {
                Command::AddOnion(_) => PendingKind::AddOnion,
                _ => PendingKind::Plain,
            },
            bulk: cmd.needs_bulk_reply(),
        };
        // Commands must be `ask` — a `tell` (no reply channel) would write a
        // command whose reply has nowhere to go and would desync the stream, so a
        // tell is dropped rather than written.
        if let Some(tx) = reply_sender {
            // Render + validate the wire line exactly once, here.
            match cmd.to_wire() {
                // Malformed — reject to the caller without touching the wire or the
                // queue. A caller error, not a connection failure: the actor keeps
                // running (nothing was written, so FIFO stays intact).
                Err(e) => tx.send(Err(e)),
                // One already on the wire — queue the validated line to preserve FIFO
                // + one-on-the-wire.
                Ok(line) if self.pending.is_some() => self.queue.push_back((line, tx, in_flight)),
                // The wire is free — write the line now.
                Ok(line) => {
                    if self.dispatch(&line, tx, in_flight).await.is_err() {
                        ctx.stop();
                    }
                }
            }
        }
        delegated
    }
}

impl Message<StreamMessage<Result<Framed, ControlError>, (), ()>> for TorControl {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Result<Framed, ControlError>, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match msg {
            // Stream just attached — nothing to do (the handshake is already done).
            StreamMessage::Started(()) => {}
            // A framing desync or socket error ended the read stream — fail with the
            // specific cause (DQ-T0.6); no reconnect into the same desync.
            StreamMessage::Next(Err(e)) => {
                self.fail_all_pending(&e);
                ctx.stop();
            }
            // An async event — route to the sink, never to a command (the item-3
            // fork already separated it).
            StreamMessage::Next(Ok(Framed::AsyncEvent(reply))) => self.events.route(reply),
            // A command reply — complete the in-flight command, then put the next
            // queued command (if any) on the wire.
            StreamMessage::Next(Ok(Framed::CommandReply(reply))) => match self.pending.take() {
                Some((tx, in_flight)) => {
                    // The wire is free again: withdraw any bulk allowance now, and
                    // let the next command re-arm it if it earns one.
                    self.budget.restore_ordinary();
                    // An accepted `ADD_ONION` is the one reply the actor reads for
                    // itself: the service id must be recorded *here*, before the
                    // reply is moved to the caller, or shutdown has nothing to
                    // `DEL_ONION`. A non-250 published nothing, so there is nothing
                    // to record — and a 250 whose `ServiceID=` does not parse is
                    // left unrecorded deliberately: sending `DEL_ONION` for an id
                    // this crate could not validate would put an unvalidated string
                    // on the wire, which is exactly what `ServiceId::parse` exists
                    // to prevent. (The service still dies with the connection.)
                    if in_flight.kind == PendingKind::AddOnion && reply.status() == 250 {
                        if let Some(id) = super::onion::parse_service_id(reply.lines()) {
                            self.published_onions.push(id);
                        }
                    }
                    tx.send(Ok(reply));
                    if let Some((next_line, next_tx, next_in_flight)) = self.queue.pop_front() {
                        if self
                            .dispatch(&next_line, next_tx, next_in_flight)
                            .await
                            .is_err()
                        {
                            ctx.stop();
                        }
                    }
                }
                None => {
                    // A reply with nothing pending = unsolicited = desync.
                    self.fail_all_pending(&ControlError::Desync);
                    ctx.stop();
                }
            },
            // The read stream ended cleanly (EOF / socket close) — fail so the
            // supervisor restarts (DQ-T0.6).
            StreamMessage::Finished(()) => {
                self.fail_all_pending(&ControlError::StreamClosed);
                ctx.stop();
            }
        }
    }
}

/// The control read half wrapped as a `Stream<Item = Result<Framed, ControlError>>`
/// for [`ActorRef::attach_stream`]. Owns the read side + framer; each polled item
/// is one already-classified [`Framed`], or the **specific** error that ended the
/// stream — a framing desync ([`ControlError::Framing`]) or a socket error
/// ([`ControlError::Io`]) — so the actor can fail with the right cause rather than
/// flatten everything to "closed". A clean EOF ends the stream with `None`, which
/// kameo delivers as `StreamMessage::Finished` ([`ControlError::StreamClosed`]).
/// After an error the stream is terminal (`done`) and yields `None` thereafter.
struct ReplyStream {
    read: OwnedReadHalf,
    framer: ReplyFramer,
    done: bool,
}

impl Stream for ReplyStream {
    type Item = Result<Framed, ControlError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        loop {
            match this.framer.next_reply() {
                Ok(Some(reply)) => return Poll::Ready(Some(Ok(reply.classify()))),
                // Not enough buffered yet — read more below.
                Ok(None) => {}
                // Framing desync — surface it specifically, then terminate.
                Err(e) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(ControlError::Framing(e))));
                }
            }
            let mut tmp = [0u8; READ_CHUNK];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.read).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // Clean EOF — end with no error (delivered as Finished).
                        this.done = true;
                        return Poll::Ready(None);
                    }
                    this.framer.push_bytes(filled);
                }
                Poll::Ready(Err(_)) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(ControlError::Io)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Write `line` followed by CRLF to the control port.
async fn write_line(writer: &mut OwnedWriteHalf, line: &str) -> Result<(), ControlError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|_| ControlError::Io)?;
    writer
        .write_all(b"\r\n")
        .await
        .map_err(|_| ControlError::Io)?;
    Ok(())
}

/// Read one complete reply, bounded by `HANDSHAKE_READ_TIMEOUT`.
async fn read_reply(
    reader: &mut OwnedReadHalf,
    framer: &mut ReplyFramer,
) -> Result<ControlReply, ControlError> {
    let read = async {
        let mut buf = [0u8; READ_CHUNK];
        loop {
            if let Some(reply) = framer.next_reply().map_err(ControlError::Framing)? {
                return Ok(reply);
            }
            let n = reader.read(&mut buf).await.map_err(|_| ControlError::Io)?;
            if n == 0 {
                return Err(ControlError::ConnectionClosed);
            }
            framer.push_bytes(&buf[..n]);
        }
    };
    match timeout(HANDSHAKE_READ_TIMEOUT, read).await {
        Ok(result) => result,
        Err(_) => Err(ControlError::Timeout),
    }
}

/// Read one reply and require the given status, else [`ControlError::Rejected`].
async fn expect_status(
    reader: &mut OwnedReadHalf,
    framer: &mut ReplyFramer,
    want: u16,
) -> Result<ControlReply, ControlError> {
    let reply = read_reply(reader, framer).await?;
    if reply.status() == want {
        Ok(reply)
    } else {
        Err(ControlError::Rejected {
            status: reply.status(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The actor's I/O paths (handshake, command correlation, event drain) are
    // covered by the live-Tor KATs (item 5); these pin the pure pieces — the wire
    // formatting and the content-free error rendering — in the unit gate.

    #[test]
    fn getinfo_renders_space_separated_keys() {
        let cmd = Command::GetInfo(vec![
            "version".to_owned(),
            "status/bootstrap-phase".to_owned(),
        ]);
        assert_eq!(
            cmd.to_wire().unwrap().as_str(),
            "GETINFO version status/bootstrap-phase"
        );
    }

    #[test]
    fn setevents_renders_space_separated_events() {
        let cmd = Command::SetEvents(vec!["STREAM".to_owned(), "STATUS_CLIENT".to_owned()]);
        assert_eq!(
            cmd.to_wire().unwrap().as_str(),
            "SETEVENTS STREAM STATUS_CLIENT"
        );
    }

    #[test]
    fn to_wire_rejects_injection_and_empty_tokens() {
        // CRLF would split into extra control commands and desync correlation.
        let crlf = Command::GetInfo(vec!["version\r\nQUIT".to_owned()]);
        assert_eq!(crlf.to_wire(), Err(ControlError::InvalidCommand));
        // A space inside a token would be read as two tokens.
        let space = Command::SetEvents(vec!["STREAM STATUS_CLIENT".to_owned()]);
        assert_eq!(space.to_wire(), Err(ControlError::InvalidCommand));
        // Other ASCII control bytes are refused too.
        let nul = Command::GetInfo(vec!["ver\0sion".to_owned()]);
        assert_eq!(nul.to_wire(), Err(ControlError::InvalidCommand));
        // As is an empty token.
        let empty = Command::GetInfo(vec![String::new()]);
        assert_eq!(empty.to_wire(), Err(ControlError::InvalidCommand));
        // And an empty token list — it would render as "GETINFO "/"SETEVENTS ".
        assert_eq!(
            Command::GetInfo(vec![]).to_wire(),
            Err(ControlError::InvalidCommand)
        );
        assert_eq!(
            Command::SetEvents(vec![]).to_wire(),
            Err(ControlError::InvalidCommand)
        );
    }

    #[test]
    fn setconf_renders_the_hslayer_pin_line_infallibly() {
        // The dangerous verb is safe here because the value is typed: a
        // `Command::SetConf` built from fingerprints renders exactly the
        // SETCONF line and can never take the InvalidCommand path.
        use super::super::vanguards::{HsLayerPins, RelayFingerprint};
        let pins = HsLayerPins::new(
            vec![RelayFingerprint::from_bytes([0x11; 20])],
            vec![RelayFingerprint::from_bytes([0x22; 20])],
        )
        .expect("non-empty");
        let wire = Command::SetConf(pins).to_wire().expect("infallible");
        assert_eq!(
            wire.as_str(),
            "SETCONF HSLayer2Nodes=$1111111111111111111111111111111111111111 \
             HSLayer3Nodes=$2222222222222222222222222222222222222222"
        );
    }

    #[test]
    fn only_the_consensus_fetch_earns_the_bulk_reply_allowance() {
        // The wide framer cap exists for `GETINFO ns/all` and nothing else — a
        // second command quietly joining that list is the regression this pins.
        assert!(Command::GetInfo(vec!["ns/all".to_owned()]).needs_bulk_reply());
        assert!(!Command::GetInfo(vec!["status/bootstrap-phase".to_owned()]).needs_bulk_reply());
        assert!(!Command::GetInfo(vec!["net/listeners/socks".to_owned()]).needs_bulk_reply());
        assert!(!Command::SetEvents(vec!["STREAM".to_owned()]).needs_bulk_reply());
    }

    #[test]
    fn control_error_display_is_content_free() {
        // Only the protocol status code, never payload.
        assert_eq!(
            ControlError::Rejected { status: 515 }.to_string(),
            "control command rejected with status 515",
        );
        assert_eq!(
            ControlError::Desync.to_string(),
            "unsolicited control reply (no command in flight)"
        );
    }

    #[test]
    fn parse_control_port_accepts_socketaddr_and_bare_port() {
        use std::net::SocketAddr;
        // The usual `addr:port` form.
        assert_eq!(
            parse_control_port("127.0.0.1:9051"),
            Some(SocketAddr::from(([127, 0, 0, 1], 9051)))
        );
        // A bare port → loopback (the actor's ControlPort binds loopback).
        assert_eq!(
            parse_control_port("9051"),
            Some(SocketAddr::from(([127, 0, 0, 1], 9051)))
        );
        // Surrounding whitespace tolerated; garbage rejected.
        assert_eq!(
            parse_control_port("  127.0.0.1:9051  "),
            Some(SocketAddr::from(([127, 0, 0, 1], 9051)))
        );
        assert_eq!(parse_control_port("not-a-port"), None);
    }
}

/// Live-Tor integration KATs (item 5) — the actor's I/O paths against a real
/// `tor`. `#[ignore]`-gated (off the unit lane); on the integration lane the
/// binary is **required**, so a missing `SHEKYL_TEST_TOR_BINARY` hard-fails rather
/// than letting a read-path test pass by not running.
///
/// This holds the **fast path** (offline `tor` under `DisableNetwork 1`):
/// handshake + command correlation + read loop, no circuits. The bootstrapped
/// `STREAM`/CircID measurement (DQ-T0.4) needs a `DisableNetwork 0` instance with
/// network egress and lands next.
#[cfg(test)]
mod live_tests {
    use super::{
        BootstrapReadiness, Command, EventSink, ManagedTor, TorControl, TorControlConfig, TorExit,
        TorLaunch,
    };
    use kameo::actor::Spawn;
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command as ProcCommand, Stdio};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, oneshot};

    use crate::test_support::tor_binary;

    /// A spawned test `tor` + its temp `DataDirectory`. Kills `tor` and cleans up
    /// on drop (TAKEOWNERSHIP usually exits it first; this is belt-and-braces).
    struct TestTor {
        child: Child,
        _dir: tempfile::TempDir,
        control_addr: SocketAddr,
        cookie_path: PathBuf,
    }

    impl Drop for TestTor {
        fn drop(&mut self) {
            // Best-effort teardown — TAKEOWNERSHIP usually exits tor first.
            self.child.kill().ok();
            self.child.wait().ok();
        }
    }

    /// Kills the wrapped child on drop unless [disarmed](Self::disarm) — guards the
    /// `wait_for_control_port` window so a timeout *panic* kills `tor` on unwind
    /// rather than leaking an orphaned process into CI.
    struct KillOnDrop(Option<Child>);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                child.kill().ok();
                child.wait().ok();
            }
        }
    }

    impl KillOnDrop {
        /// Take the child back once the wait succeeded; the guard's drop is then a
        /// no-op and ownership passes to [`TestTor`].
        fn disarm(mut self) -> Child {
            self.0.take().expect("child present until disarmed")
        }
    }

    /// Spawn an **offline** `tor` (`DisableNetwork 1`) with a cookie-authed control
    /// port on an OS-assigned port written to `ControlPortWriteToFile`.
    async fn spawn_offline_tor() -> TestTor {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let port_file = data_dir.join("control_port");
        let child = ProcCommand::new(tor_binary())
            .arg("--DataDirectory")
            .arg(&data_dir)
            .arg("--ControlPort")
            .arg("auto")
            .arg("--ControlPortWriteToFile")
            .arg(&port_file)
            .arg("--CookieAuthentication")
            .arg("1")
            .arg("--SocksPort")
            .arg("0")
            .arg("--DisableNetwork")
            .arg("1")
            .arg("--Log")
            .arg("warn stderr")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tor");
        // Guard the wait: if wait_for_control_port times out (panics), the child is
        // killed on unwind rather than orphaned. Disarmed once the port is ready.
        let guard = KillOnDrop(Some(child));
        // Same not-yet-written startup race the cookie reader models: poll the
        // control-port file until it parses, with a bounded backoff.
        let control_addr = wait_for_control_port(&port_file, Duration::from_secs(30)).await;
        let child = guard.disarm();
        let cookie_path = data_dir.join("control_auth_cookie");
        TestTor {
            child,
            _dir: dir,
            control_addr,
            cookie_path,
        }
    }

    /// Poll the `ControlPortWriteToFile` until it carries a parseable
    /// `PORT=<addr>:<port>` line. Async so the backoff yields the runtime instead
    /// of blocking a worker thread with `std::thread::sleep`.
    async fn wait_for_control_port(port_file: &Path, timeout: Duration) -> SocketAddr {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = std::fs::read_to_string(port_file) {
                if let Some(addr) = contents
                    .lines()
                    .find_map(|line| line.strip_prefix("PORT="))
                    .and_then(|a| a.trim().parse::<SocketAddr>().ok())
                {
                    return addr;
                }
            }
            assert!(
                Instant::now() < deadline,
                "tor control port file not ready within {timeout:?}",
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY"]
    async fn handshake_and_getinfo_against_offline_tor() {
        let tor = spawn_offline_tor().await;
        let (tx, _rx) = mpsc::unbounded_channel();
        // This test exercises the handshake + command correlation, not bootstrap; the
        // poll task runs harmlessly against `DisableNetwork 1` (never reaches Ready) and
        // is aborted on drop. Keep the receiver alive so the poll task doesn't stop early.
        let (readiness, _ready_rx) = BootstrapReadiness::new();
        let actor = TorControl::spawn(TorControlConfig {
            launch: TorLaunch::Attached {
                control_addr: tor.control_addr,
                cookie_path: tor.cookie_path.clone(),
            },
            events: EventSink::new(tx),
            readiness,
        });

        // GETINFO version: proves the handshake (on_start), the DelegatedReply
        // correlation, and the read loop end-to-end against real Tor.
        let reply = actor
            .ask(Command::GetInfo(vec!["version".to_owned()]))
            .await
            .expect("GETINFO version after a clean handshake");
        assert_eq!(reply.status(), 250);
        assert!(
            reply.lines().iter().any(|l| l.contains("version=")),
            "GETINFO version returns a version= line",
        );

        // SETEVENTS is the subscribe path the measurement rides; a clean 250 here
        // proves a second correlated command after the first.
        let reply = actor
            .ask(Command::SetEvents(vec!["STATUS_CLIENT".to_owned()]))
            .await
            .expect("SETEVENTS");
        assert_eq!(reply.status(), 250);
    }

    /// The onion round-trip against a **bootstrapped** tor: publish the service,
    /// confirm tor is advertising it, then withdraw it.
    ///
    /// Network-requiring (unlike the other two live tests, which run offline):
    /// `ADD_ONION` on a `DisableNetwork 1` instance would be accepted but could
    /// never establish introduction points, so "tor took the key" would pass while
    /// "tor published a reachable service" went untested. Bootstrapping is what
    /// makes `onions/current` a statement about a real service.
    ///
    /// What each assertion is actually for:
    /// - **`ADD_ONION` → 250 with a parseable `ServiceID`** proves the wire line
    ///   this crate renders is one tor accepts — the KATs pin the bytes, but only a
    ///   live tor can say those bytes are *right*. It also proves the key encoding:
    ///   tor derives the service id from the key we supplied, so a service id at
    ///   all means our expanded-key blob was understood as a key.
    /// - **`onions/current` lists it** proves tor considers the service ours and
    ///   live on *this* connection (a detached service would not be listed here),
    ///   which is the property `Detach`'s absence is protecting.
    /// - **`DEL_ONION` → 250 and the id disappears** proves teardown actually
    ///   withdraws rather than merely returning OK.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps, network)"]
    async fn onion_publish_resolve_delete_round_trip() {
        use super::super::onion::{parse_service_id, AddOnion, OnionKey, OnionPort};
        use std::net::{Ipv4Addr, SocketAddr};

        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, _rx) = mpsc::unbounded_channel();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let actor = TorControl::spawn(TorControlConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                // The whole point: a service that can reach the network.
                disable_network: false,
                exit_observer: None,
            }),
            events: EventSink::new(tx),
            readiness,
        });

        // Bootstrap first — intro-point circuits need a working network.
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if matches!(*ready_rx.borrow_and_update(), super::BootstrapState::Ready) {
                break;
            }
            assert!(Instant::now() < deadline, "tor did not bootstrap in 180s");
            tokio::time::timeout(Duration::from_secs(10), ready_rx.changed())
                .await
                .ok();
        }

        // A deterministic, obviously-test key: the *expanded* form tor wants, with
        // the clamp applied so tor and this crate agree on the derived service id.
        let mut expanded = [0u8; super::super::onion::ONION_KEY_BYTES];
        for (i, b) in expanded.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("fits u8");
        }
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
        let port = OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port())))
            .expect("loopback target");
        let reply = actor
            .ask(Command::AddOnion(
                AddOnion::new(OnionKey::from_expanded_bytes(expanded), port, 4)
                    .with_flags(super::super::onion::OnionFlags { discard_pk: true }),
            ))
            .await
            .expect("ADD_ONION reaches tor");
        assert_eq!(reply.status(), 250, "tor accepted the rendered ADD_ONION");
        let service_id = parse_service_id(reply.lines()).expect("reply carries a v3 ServiceID");

        // tor is advertising it, on this connection.
        let listed = actor
            .ask(Command::GetInfo(vec!["onions/current".to_owned()]))
            .await
            .expect("GETINFO onions/current");
        assert_eq!(listed.status(), 250);
        assert!(
            listed
                .lines()
                .iter()
                .any(|l| l.contains(service_id.as_str())),
            "the published service must appear in onions/current"
        );

        // PoW defenses, against a real tor. The KAT pins the bytes; only a live
        // tor says the bytes are *right* — which is exactly the lesson
        // `MaxStreamsCloseCircuit` taught (a 512 for an argument spelling the unit
        // test had happily frozen). Tuned rather than plain `Enabled` so all three
        // arguments and their grammar position are exercised.
        let mut pow_key = [0u8; super::super::onion::ONION_KEY_BYTES];
        for (i, b) in pow_key.iter_mut().enumerate() {
            *b = u8::try_from((i * 7 + 3) % 251).expect("fits u8");
        }
        pow_key[0] &= 248;
        pow_key[31] &= 127;
        pow_key[31] |= 64;
        let pow_port =
            OnionPort::loopback(80, SocketAddr::from((Ipv4Addr::LOCALHOST, free_port())))
                .expect("loopback target");
        let pow_reply = actor
            .ask(Command::AddOnion(
                AddOnion::new(OnionKey::from_expanded_bytes(pow_key), pow_port, 4)
                    .with_flags(super::super::onion::OnionFlags { discard_pk: true })
                    .with_pow(super::super::onion::OnionPow::EnabledTuned {
                        queue_rate: 40,
                        queue_burst: 400,
                    }),
            ))
            .await
            .expect("ADD_ONION with PoW reaches tor");
        assert_eq!(
            pow_reply.status(),
            250,
            "tor accepted the PoW arguments and their grammar position"
        );
        let pow_id = parse_service_id(pow_reply.lines()).expect("PoW service id");
        actor
            .ask(Command::DelOnion(pow_id))
            .await
            .expect("DEL_ONION the PoW service");

        // Withdraw it, and confirm the withdrawal took.
        let deleted = actor
            .ask(Command::DelOnion(service_id.clone()))
            .await
            .expect("DEL_ONION reaches tor");
        assert_eq!(deleted.status(), 250, "tor accepted DEL_ONION");
        let after = actor
            .ask(Command::GetInfo(vec!["onions/current".to_owned()]))
            .await
            .expect("GETINFO onions/current after delete");
        assert!(
            !after
                .lines()
                .iter()
                .any(|l| l.contains(service_id.as_str())),
            "DEL_ONION must actually withdraw the service, not just return 250"
        );

        actor.stop_gracefully().await.expect("graceful stop");
        actor.wait_for_shutdown().await;
    }

    /// Reserve a free loopback port (bind `:0`, read it, drop). A small TOCTOU window
    /// before `tor` binds it remains — acceptable on a test box.
    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local_addr")
            .port()
    }

    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY"]
    async fn managed_tor_is_spawned_and_reaped_on_shutdown() {
        // Managed mode: the *actor* spawns tor. Offline (`DisableNetwork 1`) on purpose —
        // this proves the two things managed mode adds over attached, spawn and kill;
        // everything else (handshake, bootstrap→Ready) is identical code that attached
        // mode + T0b-1 already cover. Pulling the network out isolates the new surface, so
        // a red means "spawn/shutdown broke", never "a relay hiccupped".
        let dir = tempfile::tempdir().expect("tempdir");
        let (exit_tx, exit_rx) = oneshot::channel();
        // Keep the readiness receiver alive so the poll task (harmless on DisableNetwork)
        // doesn't stop early; it is aborted on shutdown regardless.
        let (readiness, _ready_rx) = BootstrapReadiness::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        let actor = TorControl::spawn(TorControlConfig {
            launch: TorLaunch::Managed(ManagedTor {
                // The declared test bypass of the hash-pin gate: this lifecycle
                // test injects an arbitrary tor (any version works — we are
                // proving spawn/shutdown, not the pin).
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                disable_network: true,
                exit_observer: Some(exit_tx),
            }),
            events: EventSink::new(tx),
            readiness,
        });

        // Spawn proof: the handshake connected to a control port the *actor* launched.
        let reply = actor
            .ask(Command::GetInfo(vec!["version".to_owned()]))
            .await
            .expect("GETINFO version against the actor-spawned tor");
        assert_eq!(reply.status(), 250);

        // Shutdown proof: stop → on_stop → SIGTERM + bounded wait → the child is reaped.
        actor.stop_gracefully().await.expect("graceful stop");
        actor.wait_for_shutdown().await;

        // Truthful reap check: a real `wait()`-yielded exit status delivered through the
        // observer, not a pid probe (which races PID reuse). The platform-correct outcome:
        // on Unix a cooperative tor exits on SIGTERM (clean `Reaped`); off Unix there is no
        // graceful signal, so shutdown escalates to the SIGKILL fallback (`Killed`). Both
        // are a *reaped* child delivered through the observer — the point of the test.
        let exit = tokio::time::timeout(Duration::from_secs(10), exit_rx)
            .await
            .expect("on_stop reaped the child within the bound")
            .expect("exit observer delivered the outcome");
        #[cfg(unix)]
        assert!(
            matches!(exit, TorExit::Reaped(_)),
            "on Unix, SIGTERM reaps with a status, not the SIGKILL fallback: {exit:?}"
        );
        #[cfg(not(unix))]
        assert!(
            matches!(exit, TorExit::Killed),
            "off Unix, no graceful signal exists, so shutdown reaps via the SIGKILL fallback: {exit:?}"
        );
    }
}
