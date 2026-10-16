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
//! - **Startup in `on_start`, *then* `attach_stream`.** kameo owns the run loop;
//!   an actor cannot `select!` on its own mailbox and a socket. So the startup
//!   exchange runs *synchronously* in [`on_start`](TorControlClient), reading the
//!   framer by hand, which is safe because no async `650` events can arrive before
//!   `SETEVENTS` is sent. For an attached tor that exchange is the SAFECOOKIE
//!   handshake. A managed tor's connection is inherited and already authenticated
//!   (`TSR-Q7`), so its exchange is one `GETINFO version`, which confirms tor is up.
//!   Only after it succeeds is the read half wrapped as the internal `ReplyStream`
//!   (`Stream<Item = Result<Framed, ControlError>>`) and handed to
//!   [`ActorRef::attach_stream`]. The stream then feeds the mailbox: each reply
//!   arrives as `StreamMessage::Next(Ok(Framed))` whether or not a command is in
//!   flight (so idle async-event drain is automatic), and a framing/socket error as
//!   `Next(Err(..))` so the actor fails with the specific cause. A startup `Err`
//!   fails the spawn (DQ-T0.6); the ordering matters: the stream can't take the
//!   read half until the synchronous reads are done.
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
//! reconnecting into the same desync. A **managed** tor's connection is its owning
//! controller from the moment it starts, so tor exits when the connection closes,
//! including when this process dies: no instant exists in which a crash leaves an
//! orphan. An attached tor is not ours, and the actor never takes ownership of it.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures_core::Stream;
use kameo::actor::{ActorRef, WeakActorRef};
use kameo::error::ActorStopReason;
use kameo::message::{Context, Message, StreamMessage};
use kameo::reply::{DelegatedReply, ReplySender};
use kameo::Actor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::auth::{parse_authchallenge, read_cookie_file, AuthError};
use super::bootstrap::{bootstrap_step, parse_bootstrap_progress, BootstrapState, BootstrapStep};
use super::encoding::hex_upper;
use super::framing::{
    ControlReply, Framed, FramingError, ReplyBudget, ReplyFramer, ORDINARY_REPLY_BYTES,
};
use super::launch;
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

/// The read half of a control connection, whatever carries it: a TCP connection to an
/// attached tor's control port, or the managed tor's inherited socket.
pub(crate) type ControlRead = Pin<Box<dyn AsyncRead + Send>>;

/// The write half of a control connection. See [`ControlRead`].
pub(crate) type ControlWrite = Pin<Box<dyn AsyncWrite + Send>>;

/// How many asynchronous events the [`EventSink`] holds for a consumer that has not
/// read them yet. The next event is dropped and counted, never waited for.
///
/// The memory this bounds: each held event is one framed reply. A status or
/// descriptor event is one line of a few hundred bytes, and a log event carries one
/// tor log message, which tor formats into a buffer of about ten kilobytes. So a full
/// queue of the events the supervisor subscribes to holds at most about 2.5 MiB. The
/// framer's own ceiling per reply ([`ORDINARY_REPLY_BYTES`], 256 KiB) puts the
/// absolute bound at 64 MiB, which only a tor sending replies no subscribed event has
/// could reach. A consumer that keeps up never fills it; one that stalls loses the
/// newest events and can read how many from [`EventReceiver::dropped`].
pub const EVENT_QUEUE_EVENTS: usize = 256;

/// The absolute bound [`EVENT_QUEUE_EVENTS`] states, in bytes.
const _: () = assert!(EVENT_QUEUE_EVENTS * ORDINARY_REPLY_BYTES == 64 * 1024 * 1024);

/// Why the managed tor's Windows system directory could not be read.
///
/// No path and no directory text. [`SystemDirectoryError::Os`] is the code from
/// the failed call. [`SystemDirectoryError::UnusableLength`] is a length the
/// call itself contradicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemDirectoryError {
    /// `GetSystemWindowsDirectoryW` failed. The code was read immediately.
    Os(u32),
    /// The call returned a length that cannot name a directory: nothing
    /// written, or a written length that does not fit the buffer it asked for.
    UnusableLength,
}

impl SystemDirectoryError {
    /// The OS error from the failed call, read before any further call.
    #[cfg(windows)]
    pub(crate) fn from_last_os_error() -> Self {
        let Some(code) = std::io::Error::last_os_error().raw_os_error() else {
            return Self::UnusableLength;
        };
        u32::try_from(code).map_or(Self::UnusableLength, Self::Os)
    }
}

/// A failure in the control connection — handshake or runtime.
///
/// **Content-free**: every variant carries only a protocol status code, or the
/// system-directory failure below, never a fragment of the control-port payload
/// or the cookie (same forensic discipline as [`FramingError`]/[`AuthError`],
/// which it wraps).
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
    /// A startup command (`AUTHENTICATE` for an attached tor, `GETINFO version` for a
    /// managed one) returned a non-`250` status: tor refused. Carries only the code.
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
    /// The managed tor's process exited, as the wait on it reported (`TSR-F16`). The
    /// control connection may still have been open: a leaked copy of tor's end keeps
    /// it so.
    ProcessExited,
    /// A command was malformed — an empty token list, an empty token, or a token
    /// with a forbidden character (ASCII control or space). Refused before reaching
    /// the wire, so it cannot send a malformed line, inject an extra control line,
    /// or desync the FIFO reply correlation. A caller error: the command is
    /// rejected, the connection is untouched.
    InvalidCommand,
    /// A **managed** `tor` could not be started: the data directory, the blank file,
    /// the control socket pair, or the spawn itself failed. A tor that starts and then
    /// exits before it answers is [`Self::ConnectionClosed`] instead, from the startup
    /// `GETINFO version`.
    /// Carries no path (forensic discipline); `spawn_managed_tor`'s own `--Log` file in the
    /// `DataDirectory` is where the specific cause is diagnosable. A failure to read the
    /// Windows system directory is [`Self::SystemDirectory`] instead: it happens before
    /// any tor log exists, and still carries no path.
    Spawn,
    /// The Windows system directory could not be read, so the managed tor was not
    /// started. The code is the OS error, or the call returned a length that cannot
    /// name a directory.
    SystemDirectory(SystemDirectoryError),
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
            Self::ProcessExited => write!(f, "managed tor process exited"),
            Self::InvalidCommand => write!(
                f,
                "control command was malformed (empty or forbidden character)"
            ),
            Self::Spawn => write!(f, "managed tor failed to launch or become driveable"),
            Self::SystemDirectory(SystemDirectoryError::Os(code)) => {
                write!(
                    f,
                    "managed tor system directory could not be read (os error {code})"
                )
            }
            Self::SystemDirectory(SystemDirectoryError::UnusableLength) => {
                write!(f, "managed tor system directory length was unusable")
            }
        }
    }
}

impl std::error::Error for ControlError {}

/// Where asynchronous `650` events (`STREAM`, `STATUS_CLIENT`, …) are routed: the
/// bootstrap gate, the measurement consumer, and the supervisor. The actor only ever
/// *sends* into it.
///
/// Carries [`ControlReply`]s, a forensic surface, so it is not `Debug`.
///
/// **Bounded, and the actor never waits on it** (`TOR_SUPERVISOR.md` `TSR-F2`). It holds
/// [`EVENT_QUEUE_EVENTS`]; an event that arrives while it is full is dropped and counted,
/// and the count is the consumer's to read ([`EventReceiver::dropped`]). Anyone who can
/// make tor log can make events arrive, including a peer misbehaving at our onion, so an
/// unbounded queue would be a memory channel an outsider can fill. Waiting instead of
/// dropping would stall the read loop, and with it every command reply.
///
/// `Clone` so a supervisor can hand each incarnation the same long-lived sink: the
/// consumer's receiver and the drop count survive restarts, and senders are
/// per-incarnation. **Consequence for consumers:** because the supervisor retains a
/// sender clone across restarts, the receiver does *not* observe all-senders-dropped
/// when an incarnation dies. A supervised consumer must detect incarnation death through
/// the supervisor's posture watch (the wallet's `WalletTorControl`, or the daemon's
/// supervisor once it exists), not through `recv() == None`, which is correct only for a
/// directly spawned, sole-sender actor.
#[derive(Clone)]
pub struct EventSink {
    sender: mpsc::Sender<ControlReply>,
    dropped: Arc<AtomicU64>,
}

/// The consumer's end of an [`EventSink`]: the held events, and how many were dropped
/// because the queue was full.
pub struct EventReceiver {
    receiver: mpsc::Receiver<ControlReply>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// A sink holding up to [`EVENT_QUEUE_EVENTS`], and the receiver its consumer keeps.
    #[must_use]
    pub fn bounded() -> (Self, EventReceiver) {
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE_EVENTS);
        let dropped = Arc::new(AtomicU64::new(0));
        (
            Self {
                sender,
                dropped: Arc::clone(&dropped),
            },
            EventReceiver { receiver, dropped },
        )
    }

    /// A sink with no consumer: **the correct production value today**, and a
    /// place to notice when it stops being one.
    ///
    /// Async `650` events arrive only after a `SETEVENTS`
    /// ([`Command::SetEvents`]), and no production call site issues one: the
    /// DQ-T0.4 `STREAM` measurement is a harness, and §3c's retraction settled
    /// that bootstrap readiness is a `GETINFO` **poll**, not a subscription
    /// ("a `GETINFO` poll is a command, not a subscription, so it never touches
    /// `SETEVENTS`"). The daemon's supervisor will subscribe; until it exists, this
    /// sink receives nothing, and wiring a consumer to it would be wiring a consumer
    /// to silence.
    ///
    /// This exists rather than an inline `let (sink, _receiver) = EventSink::bounded()`
    /// because that shape is indistinguishable from a caller who dropped the
    /// receiver by accident. Whoever adds the first production `SETEVENTS` has
    /// to replace a call named `unsubscribed`, which is a question a reviewer
    /// can see; deleting an anonymous `_receiver` is not.
    ///
    /// The returned sink drops every event and counts none: routing treats a
    /// closed receiver as "the consumer is gone", which is not an overflow.
    #[must_use]
    pub fn unsubscribed() -> Self {
        // The receiver is dropped here on purpose, which is what closes the
        // channel and makes every later send a no-op.
        let (sink, _receiver) = Self::bounded();
        sink
    }

    /// Route an async event to the consumer, never waiting. A full queue drops the event
    /// and counts it. A closed receiver means the consumer is gone, so the event is
    /// discarded and not counted: nobody is left to read the count.
    fn route(&self, reply: ControlReply) {
        match self.sender.try_send(reply) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl EventReceiver {
    /// The next held event, or `None` once every sender is gone and the queue is empty.
    pub async fn recv(&mut self) -> Option<ControlReply> {
        self.receiver.recv().await
    }

    /// The next held event if one is waiting.
    ///
    /// # Errors
    ///
    /// [`mpsc::error::TryRecvError::Empty`] when nothing is held, and
    /// [`mpsc::error::TryRecvError::Disconnected`] once every sender is gone and the
    /// queue is empty.
    pub fn try_recv(&mut self) -> Result<ControlReply, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    /// How many events are held now. Never more than [`EVENT_QUEUE_EVENTS`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Whether no event is held now.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    /// How many events were dropped because the queue was full, since the sink was made.
    /// It never decreases, and it counts across every incarnation that shared the sink.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// A control command the engine asks the actor to run, **one in flight at a time**.
///
/// The enum extends without reshaping the actor, which is what let the SP-T3
/// onion surface ([`Command::AddOnion`] / [`Command::DelOnion`]) land as two more
/// variants rather than a second actor. `TAKEOWNERSHIP` is absent by design: a
/// managed tor's inherited connection already owns it, and an attached tor is not
/// ours to own.
///
/// **Not `Clone`, and not `PartialEq`.** `AddOnion` carries an onion
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
    /// `ADD_ONION ED25519-V3:<key> …` — publish a v3 onion service.
    /// Built from typed parts, so it cannot render a malformed line;
    /// see [`onion`](super::onion) for why that is a type property here rather
    /// than a validation.
    AddOnion(AddOnion),
    /// `DEL_ONION <service-id>` — tear the service down. Issued on the actor's
    /// shutdown path as well as on demand.
    DelOnion(ServiceId),
    /// `SETCONF HSLayer2Nodes=… HSLayer3Nodes=…` — pin layer-2/layer-3
    /// vanguard guards (VG-1). The **wallet** supervisor drives this; the
    /// daemon's ephemeral onion has no vanguard state. Built from typed
    /// [`RelayFingerprint`](super::vanguards::RelayFingerprint)s, so — like
    /// `ADD_ONION` — it cannot render a line that injects a second command,
    /// which is what makes it safe to add `SETCONF` (the dangerous verb) to
    /// this surface without a validated-string path.
    SetConf(HsLayerPins),
    /// `SIGNAL <name>` — deliver one of tor's control signals. Typed as a
    /// closed enum ([`Signal`]) so, like the onion commands, the arm cannot
    /// render a token that is not a signal name.
    Signal(Signal),
}

/// A control signal tor accepts on `SIGNAL`. Closed on purpose: only the
/// signals with a named consumer are here, and adding one is a visible edit.
///
/// **Not a per-request isolation mechanism.** [`Self::NewNym`] is
/// process-global — it marks every client circuit dirty and purges the
/// client's onion-service descriptor and intro-point state — so a
/// consumer that wanted *one* stream on a fresh circuit while others keep
/// theirs wants SOCKS isolation (`IsolateSOCKSAuth`), not this. Tor also
/// rate-limits it to one per ten seconds (`MAX_SIGNEWNYM_RATE`); a second
/// within that window is answered `250 OK` and *deferred*, so a caller that
/// needs the rotation to have happened spaces its signals itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `NEWNYM`: switch to clean circuits and forget client-side
    /// onion-service state, so the next request builds everything from
    /// scratch. Consumer: the SP-T3 measurement rig's cold arm
    /// (`shekyl-sp-t3-spike::harness`, `ARCHIVAL_SHARD_FETCH.md` §9.1 (c)),
    /// which models a daemon's first fetch from a persona it has never
    /// dialled.
    NewNym,
}

impl Signal {
    /// The signal's name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewNym => "NEWNYM",
        }
    }
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
    pub(crate) fn to_wire(&self) -> Result<Zeroizing<String>, ControlError> {
        let (verb, tokens) = match self {
            Self::GetInfo(keys) => ("GETINFO", keys),
            Self::SetEvents(events) => ("SETEVENTS", events),
            // Infallible by construction — no validation step exists to fail.
            Self::AddOnion(add) => return Ok(add.to_wire_line()),
            Self::DelOnion(id) => return Ok(Zeroizing::new(format!("DEL_ONION {}", id.as_str()))),
            // Also infallible: every value is a `$hex` specifier that cannot
            // carry a space or control byte (see `vanguards`).
            Self::SetConf(pins) => return Ok(Zeroizing::new(pins.to_wire_line())),
            // A closed enum of signal names: nothing to validate.
            Self::Signal(signal) => {
                return Ok(Zeroizing::new(format!("SIGNAL {}", signal.as_str())))
            }
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
pub struct TorControlClientConfig {
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

/// How the [`TorControlClient`] actor gets its control port (DQ-T0.1 process ownership).
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
    /// A control connection that is already open and authenticated, with no process
    /// behind it the actor owns: the unit tests' fake tor. Test builds only.
    #[cfg(test)]
    Connected {
        /// The fake tor's replies and events.
        read: ControlRead,
        /// Where the actor writes its commands.
        write: ControlWrite,
    },
}

/// How the managed tor's `SocksPort` is chosen — a typed knob (like
/// `disable_network`), not a bare integer with a magic zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksPort {
    /// `SocksPort auto ExtendedErrors`: tor picks a free port; the caller
    /// discovers it post-Ready via `GETINFO net/listeners/socks`. The
    /// production choice — immune to restart re-bind races by construction.
    /// `ExtendedErrors` is fixed on the value so an introduction timeout
    /// is not reported as a missing host.
    Auto,
    /// A caller-chosen fixed port — harnesses and bring-your-own-layout setups.
    Fixed(u16),
}

impl SocksPort {
    /// The `--SocksPort` value.
    ///
    /// `ExtendedErrors` is part of the value, not a separate flag. Tor
    /// 0.4.9.11 leaves it off (`port_cfg_new`), and without it an
    /// introduction timeout and a missing descriptor are both reply 4.
    /// The flag changes only the reply byte our own Tor sends us.
    pub fn as_arg(self) -> String {
        match self {
            Self::Auto => "auto ExtendedErrors".to_owned(),
            Self::Fixed(port) => format!("{port} ExtendedErrors"),
        }
    }
}

/// A managed `tor` to spawn (DQ-T0.1). The actor launches it with the caller's
/// `DataDirectory` and `SocksPort`, and hands it one end of a connected socket pair as
/// its owning, already-authenticated control connection (`TSR-Q7`). Tor opens no
/// control port and writes no cookie.
///
/// **The caller names the instance.** This type does not default, infer, or
/// discover a data directory — that is how wallet P and daemon Principal can
/// share this spawn path without sharing a Tor.
pub struct ManagedTor {
    /// The `tor` binary to spawn — **only a hash-pin-verified witness is accepted**
    /// (SP-T0c). The sole production mints are `binary::discover_and_verify` /
    /// `binary::discover_and_verify_at`, so a spawn path *cannot* skip verification:
    /// the gate is enforced by this type, not by convention (the same structural
    /// posture as `disable_network` below). Tests inject an unpinned tor via the
    /// loudly-named `VerifiedTorBinary::unchecked_for_test` (this crate's own
    /// tests, or a dev-dependency edge enabling `unpinned-tor-for-tests`).
    pub tor_binary: VerifiedTorBinary,
    /// This instance's `DataDirectory`. The caller supplies it; two callers that
    /// pass the same path share an instance, which is the crossover PWD-E9
    /// forbids. Placement (wallet-adjacent and persistent vs daemon-ephemeral)
    /// is the wrapping capability's decision, not this type's. Tor tightens
    /// the directory to `0700`. Non-world-writable is also the SP-T0c TOCTOU
    /// layout requirement.
    pub data_dir: PathBuf,
    /// This instance's `SocksPort`. Production supervisors use [`SocksPort::Auto`]
    /// and discover the bound address via `GETINFO net/listeners/socks` — a fixed
    /// port can race the previous incarnation's dying socket on restart. Harnesses
    /// pick [`SocksPort::Fixed`].
    pub socks_port: SocksPort,
    /// Spawn `tor` with `--DisableNetwork 1` — an offline instance (opens its control port
    /// and SOCKS port, but never touches the network, so it never bootstraps). The
    /// child-lifecycle test sets this to isolate spawn+shutdown from a real bootstrap;
    /// **production always leaves it `false`** (a managed tor must reach the network).
    ///
    /// This is deliberately a *typed knob*, not an arbitrary `extra_args` passthrough: the
    /// managed spawn owns its safety invariants (the inherited control connection, no
    /// control port, its `DataDirectory`/`SocksPort`), and a free-form flag list can
    /// smuggle those open —
    /// directly, or indirectly via `-f <torrc>` / `+Option` append / `--defaults-torrc`,
    /// which no denylist reliably covers. Future customization (bridges, an upstream proxy)
    /// is added as further **typed, safe-by-construction** knobs, so the control-plane
    /// invariant stays *structural* rather than validated.
    pub disable_network: bool,
    /// Optional exit observer — the **production telemetry hook**. Once the child is
    /// reaped, the watcher reports how it ended ([`TorExit`]): a stop the actor asked
    /// for ([`TorExit::Reaped`], or [`TorExit::Killed`] when tor wedged past the grace
    /// window), or a death that came first ([`TorExit::Died`], with the signal that saw
    /// it). The wallet supervisor awaits it before a respawn reuses the directory; the
    /// lifecycle tests use it to assert a *real* reap rather than probing a pid.
    pub exit_observer: Option<oneshot::Sender<TorExit>>,
    /// Test builds only: leak a copy of tor's end of the control connection into a
    /// sleeper process, the residual `TSR-F16` guards against (case C6b). Dependents
    /// never see this field.
    #[cfg(test)]
    pub(crate) leak: Option<launch::LeakTorEnd>,
}

/// The control-port actor. Owns the write half and the
/// in-flight bookkeeping; the read half lives in the attached `ReplyStream`, the
/// managed child (if any) in `child`, and the bootstrap poll task in `bootstrap_poll`.
pub struct TorControlClient {
    /// Write half — commands go out here, one on the wire at a time.
    writer: ControlWrite,
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
    /// [`Zeroizing`] because a queued `ADD_ONION` line embeds the onion
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
    /// The watch on the managed `tor` child, for [`TorLaunch::Managed`]. `None` for
    /// [`TorLaunch::Attached`] — an attached `tor` is not ours to kill. `on_stop` takes
    /// it and has the watcher run the bounded shutdown.
    child: Option<ChildWatch>,
    /// Which of the two death signals reached the actor first, if one did
    /// (`TSR-F16`). `on_stop` hands it to the watcher, which reports it in [`TorExit`].
    death: Option<DeathSignal>,
    /// The bootstrap-readiness poll task (design §3b), aborted on drop. Held so the
    /// actor owns its task; the task also self-terminates (`Ready` / actor-death /
    /// no-listeners), so this abort is a prompt-cleanup backstop, not the only exit.
    bootstrap_poll: JoinHandle<()>,
}

/// The managed `tor` child as the spawn returns it, before the actor arms and hands it
/// to its watcher. Spawned with `kill_on_drop`, so even a panic that skips `on_stop`
/// still kills it; the owning control connection's close is the other backstop.
struct TorChild {
    child: Child,
    exit_observer: Option<oneshot::Sender<TorExit>>,
}

/// How a managed `tor` child ended (observed via [`ManagedTor::exit_observer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorExit {
    /// The actor was asked to stop, and tor exited on `SIGTERM` within the
    /// `SHUTDOWN_GRACE` window and was reaped with this status: the clean path.
    Reaped(std::process::ExitStatus),
    /// The actor was asked to stop, and tor was not cleanly reaped with a status:
    /// either it wedged past the `SIGTERM` grace window and was killed, or the grace
    /// `wait` itself errored. Either way the child was killed and reaped: an
    /// **unclean** shutdown.
    Killed,
    /// Tor died before the actor was asked to stop it. `first` is the signal that
    /// reached the actor first (`TSR-F16`); `status` is the reaped exit status, `None`
    /// when the reap could not report one.
    Died {
        /// The first of the two death signals.
        first: DeathSignal,
        /// The reaped status.
        status: Option<std::process::ExitStatus>,
    },
}

/// The two ways the actor learns a managed tor died (`TOR_SUPERVISOR.md` `TSR-F16`).
///
/// Neither is the sole signal. A copy of tor's end of the control socket leaked into
/// another process keeps the socket open after tor dies, for as long as that process
/// lives (30.3 s measured on Windows, 5.0 s on Linux), so control EOF can come late;
/// the process wait cannot be held up that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeathSignal {
    /// The wait on tor's process returned: the reap on Unix, the process handle on
    /// Windows.
    ProcessExited,
    /// The control connection ended: EOF, a socket error, or a framing desync.
    ControlClosed,
}

/// The actor's handle on the task that watches its managed child.
///
/// The watcher owns the [`Child`] and waits on it beside a stop request. When the
/// process exits first, it tells the actor ([`ChildExited`]), which stops. When the
/// actor stops, `on_stop` sends the request with the death signal it saw first (if
/// any), and the watcher runs the bounded shutdown, reports [`TorExit`] and ends. If
/// the actor goes away without `on_stop` (a kill or a panic), the request's sender is
/// dropped and the watcher kills and reaps the child itself.
struct ChildWatch {
    stop: oneshot::Sender<Option<DeathSignal>>,
    task: JoinHandle<()>,
}

impl ChildWatch {
    /// Start watching `child` on behalf of `actor`.
    fn start(child: TorChild, actor: WeakActorRef<TorControlClient>) -> Self {
        let (stop, requested) = oneshot::channel();
        let task = tokio::spawn(watch_child(child, actor, requested));
        Self { stop, task }
    }

    /// Ask the watcher to finish, with the death signal the actor saw first, and wait
    /// until it has reaped the child and reported. The shutdown it runs is bounded.
    async fn finish(self, death: Option<DeathSignal>) {
        self.stop.send(death).ok();
        self.task.await.ok();
    }
}

/// The child exited, as the watcher's process wait saw it.
struct ChildExited;

/// Watch the managed child until the actor asks to finish (`TSR-F16`).
async fn watch_child(
    child: TorChild,
    actor: WeakActorRef<TorControlClient>,
    mut requested: oneshot::Receiver<Option<DeathSignal>>,
) {
    let TorChild {
        mut child,
        exit_observer,
    } = child;
    let mut exited: Option<Option<std::process::ExitStatus>> = None;
    let death = loop {
        tokio::select! {
            status = child.wait(), if exited.is_none() => {
                exited = Some(status.ok());
                // The actor stops on this and then asks the watcher to finish. An actor
                // already gone has dropped its request, which ends the loop next.
                if let Some(actor) = actor.upgrade() {
                    actor.tell(ChildExited).await.ok();
                }
            }
            // A dropped sender (the actor went away without `on_stop`) is a request with
            // no death signal: kill, reap, report.
            death = &mut requested => break death.ok().flatten(),
        }
    };
    let exit = match exited {
        Some(status) => TorExit::Died {
            first: death.unwrap_or(DeathSignal::ProcessExited),
            status,
        },
        None => {
            let shutdown = shut_down(&mut child).await;
            match death {
                // The connection ended first and the process was still there: a dead tor
                // to the actor, wedged or not, which the shutdown has now reaped.
                Some(first) => TorExit::Died {
                    first,
                    status: match shutdown {
                        TorExit::Reaped(status) => Some(status),
                        _ => None,
                    },
                },
                None => shutdown,
            }
        }
    };
    if let Some(tx) = exit_observer {
        tx.send(exit).ok();
    }
}

/// Shut the child down: **`SIGTERM` → bounded wait → kill → reap**.
///
/// Tolerant of a child that has just exited: the `SIGTERM` is then a harmless `ESRCH`
/// and the wait reaps at once. The kill escalation is what keeps the wait *bounded*:
/// "SIGTERM + wait" without it would hang the wallet forever if `tor` ever wedged.
async fn shut_down(child: &mut Child) -> TorExit {
    // Ask tor to exit gracefully (SIGTERM on Unix; DQ-T0.1). A no-op off Unix, where the
    // timeout → `kill()` escalation is the whole shutdown.
    request_graceful_stop(child);
    match timeout(SHUTDOWN_GRACE, child.wait()).await {
        Ok(Ok(status)) => TorExit::Reaped(status),
        // The grace `wait` errored or timed out (tor wedged): kill and reap
        // unconditionally. `start_kill` kills the process even if the reap can't
        // complete, so neither case leaves a running or zombie tor.
        Ok(Err(_)) | Err(_) => {
            kill_and_reap(child).await;
            TorExit::Killed
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
/// (`TerminateProcess`) escalation drives shutdown there instead. Closing the owning
/// control connection would also exit tor, but an exit by that route does not save
/// tor's `state`; which graceful route the supervisor uses is `TSR-M6`'s question.
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

/// The bootstrap-readiness publisher handed to the actor via [`TorControlClientConfig`].
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

impl Actor for TorControlClient {
    type Args = TorControlClientConfig;
    type Error = ControlError;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let TorControlClientConfig {
            launch,
            events,
            readiness,
        } = args;

        // Managed: spawn tor with its end of the control connection, and confirm it
        // answers. Attached: connect to the given port and authenticate. The poll and
        // every command after that are identical; the mode-specific steps are the
        // spawn and `on_stop`'s kill (managed only).
        let (control_addr, cookie_path) = match launch {
            TorLaunch::Managed(managed) => {
                let (mut child, mut read, mut write) = spawn_managed_tor(managed).await?;
                let mut framer = ReplyFramer::default();
                // A managed child is reaped explicitly on a failed start, uniform with
                // every other failure path; tokio prefers an explicit `wait` to
                // `kill_on_drop`'s best-effort reap.
                if let Err(e) = confirm_driveable(&mut read, &mut write, &mut framer).await {
                    kill_and_reap(&mut child.child).await;
                    return Err(e);
                }
                return Ok(Self::arm(
                    &actor_ref,
                    read,
                    write,
                    framer,
                    events,
                    readiness,
                    Some(child),
                ));
            }
            TorLaunch::Attached {
                control_addr,
                cookie_path,
            } => (control_addr, cookie_path),
            #[cfg(test)]
            TorLaunch::Connected { read, write } => {
                return Ok(Self::arm(
                    &actor_ref,
                    read,
                    write,
                    ReplyFramer::default(),
                    events,
                    readiness,
                    None,
                ));
            }
        };

        let (reader, writer, framer) = handshake(control_addr, &cookie_path).await?;
        Ok(Self::arm(
            &actor_ref, reader, writer, framer, events, readiness, None,
        ))
    }

    /// Clean shutdown: withdraw onions this actor published, then kill the
    /// managed child. `TAKEOWNERSHIP` (landed in PR-2) is the *crash* backstop — a
    /// panic / SIGKILL sends no `on_stop`, and the control connection dropping then exits
    /// `tor` — but on a clean stop the connection is still open here, so this is the
    /// primary path. Attached mode has no child to kill. (The bootstrap poll task is
    /// aborted in `Drop`.)
    ///
    /// **`DEL_ONION` runs first, and the order is load-bearing.** Killing the child
    /// first would take the services down too, but only for a *managed* tor; against an
    /// **attached** tor (`TorLaunch::Attached` — bring-your-own-`tor`, and every
    /// integration harness) there is no child to kill, so without this step the
    /// services would keep running inside someone else's long-lived tor after this
    /// actor closed — still publishing descriptors that assert the service is online
    /// while nothing is left to serve a byte. That is the same orphan-advertisement
    /// failure `Detach` is excluded to prevent, arriving by a different route.
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
        if let Some(watch) = self.child.take() {
            watch.finish(self.death).await;
        }
        Ok(())
    }
}

impl Drop for TorControlClient {
    fn drop(&mut self) {
        // Stop the bootstrap poll task when the actor goes away. The managed child (if
        // `on_stop` did not run — a panic path) is SIGKILLed by its `kill_on_drop`.
        self.bootstrap_poll.abort();
    }
}

/// Run the SAFECOOKIE handshake on a fresh connection to an **attached** tor's control
/// port: connect, `AUTHCHALLENGE`, verify the server hash, `AUTHENTICATE`. Returns the
/// split read/write halves and the framer for the actor to attach. Synchronous
/// request/response: no `650` events can arrive before `SETEVENTS`, so the framer is
/// read by hand here.
///
/// It sends no `TAKEOWNERSHIP`: an attached tor is not ours, and taking ownership would
/// exit a bring-your-own tor when this connection closed. A managed tor needs no
/// handshake at all; its connection is inherited ([`spawn_managed_tor`]).
async fn handshake(
    control_addr: SocketAddr,
    cookie_path: &Path,
) -> Result<(ControlRead, ControlWrite, ReplyFramer), ControlError> {
    let stream = TcpStream::connect(control_addr)
        .await
        .map_err(|_| ControlError::Connect)?;
    let (reader, writer) = stream.into_split();
    let (mut reader, mut writer): (ControlRead, ControlWrite) =
        (Box::pin(reader), Box::pin(writer));
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

    Ok((reader, writer, framer))
}

/// Spawn a **managed** `tor` (DQ-T0.1, as `TSR-Q7` amends it): the caller's
/// `DataDirectory` and `SocksPort`, and its end of a connected socket pair as an owning,
/// already-authenticated control connection. Every option is the actor's; a caller can
/// toggle only the typed `disable_network` knob.
///
/// Returns the child and our end of the connection, which the caller confirms with
/// [`confirm_driveable`] before arming the actor. `kill_on_drop` is the last-resort
/// backstop.
async fn spawn_managed_tor(
    #[cfg_attr(
        not(test),
        allow(unused_mut, reason = "only the test seam takes from it")
    )]
    mut managed: ManagedTor,
) -> Result<(TorChild, ControlRead, ControlWrite), ControlError> {
    // The directory is owner-only on Unix before any file is written, and a symlink
    // at the final component is refused.
    launch::prepare_data_directory(&managed.data_dir).await?;
    // The launch names this file as tor's torrc, defaults torrc and both GeoIP files.
    // Tor refuses a named torrc that does not exist. Rewritten on every spawn, and
    // never by following a symlink or truncating a hard link.
    launch::install_blank_config(&managed.data_dir).await?;

    let environment = launch::LaunchEnvironment::resolve(&managed.tor_binary)?;
    let pair = launch::ControlPair::new()?;
    #[cfg(test)]
    if let Some(leak) = managed.leak.take() {
        pair.leak(leak)?;
    }
    let mut cmd = launch::managed_tor_command(&managed, pair.tor_end(), &environment);
    let (child, read, write) = pair.spawn(&mut cmd)?;
    Ok((
        TorChild {
            child,
            exit_observer: managed.exit_observer,
        },
        read,
        write,
    ))
}

/// Ask the newly launched tor `GETINFO version` on its inherited connection, bounded by
/// `HANDSHAKE_READ_TIMEOUT`, before the actor arms on it.
///
/// This is the managed launch's only startup wait. A tor that exits at startup (a bad
/// argument, a missing library, the Windows environment) closes its end, and the read
/// fails at once with [`ControlError::ConnectionClosed`]; one that refused the
/// connection answers with a non-`250` status. Neither waits out a timeout for a file
/// that will never appear.
async fn confirm_driveable(
    read: &mut ControlRead,
    write: &mut ControlWrite,
    framer: &mut ReplyFramer,
) -> Result<(), ControlError> {
    write_line(write, "GETINFO version").await?;
    expect_status(read, framer, 250).await.map(|_| ())
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
async fn bootstrap_poll_loop(actor: ActorRef<TorControlClient>, tx: watch::Sender<BootstrapState>) {
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

impl TorControlClient {
    /// Arm an actor on a control connection that is open and authenticated: hand the
    /// read half to the stream, so kameo merges it into the mailbox, and start the
    /// bootstrap poll. The budget cell is shared with the stream's framer: the stream
    /// charges against it, the actor sets it per command.
    ///
    /// The bootstrap poll task (design §3b) drives the readiness watch through the
    /// public `ask`: a `GETINFO status/bootstrap-phase` poll, *not* a `STATUS_CLIENT`
    /// subscription, so it never touches `SETEVENTS`. Its first `ask` queues behind
    /// the run loop that begins once `on_start` returns.
    fn arm(
        actor_ref: &ActorRef<Self>,
        read: ControlRead,
        writer: ControlWrite,
        framer: ReplyFramer,
        events: EventSink,
        readiness: BootstrapReadiness,
        child: Option<TorChild>,
    ) -> Self {
        let budget = framer.budget();
        actor_ref.attach_stream(
            ReplyStream {
                read,
                framer,
                done: false,
            },
            (),
            (),
        );
        let bootstrap_poll = tokio::spawn(bootstrap_poll_loop(actor_ref.clone(), readiness.0));
        // The second death signal: the process wait, beside the connection's end.
        let child = child.map(|child| ChildWatch::start(child, actor_ref.downgrade()));
        Self {
            writer,
            events,
            pending: None,
            budget,
            queue: VecDeque::new(),
            published_onions: Vec::new(),
            child,
            death: None,
            bootstrap_poll,
        }
    }

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

impl Message<Command> for TorControlClient {
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

impl Message<StreamMessage<Result<Framed, ControlError>, (), ()>> for TorControlClient {
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
                self.death.get_or_insert(DeathSignal::ControlClosed);
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
                self.death.get_or_insert(DeathSignal::ControlClosed);
                self.fail_all_pending(&ControlError::StreamClosed);
                ctx.stop();
            }
        }
    }
}

impl Message<ChildExited> for TorControlClient {
    type Reply = ();

    /// The process wait saw the managed child exit (`TSR-F16`). The actor fails every
    /// caller and stops, whether or not the control connection has closed: a leaked
    /// copy of tor's end can hold it open for as long as the process holding it lives.
    async fn handle(&mut self, _msg: ChildExited, ctx: &mut Context<Self, Self::Reply>) {
        self.death.get_or_insert(DeathSignal::ProcessExited);
        self.fail_all_pending(&ControlError::ProcessExited);
        ctx.stop();
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
    read: ControlRead,
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
            match this.read.as_mut().poll_read(cx, &mut rb) {
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
async fn write_line(writer: &mut ControlWrite, line: &str) -> Result<(), ControlError> {
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
    reader: &mut ControlRead,
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
    reader: &mut ControlRead,
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
    fn signal_renders_its_closed_name() {
        assert_eq!(
            Command::Signal(Signal::NewNym).to_wire().unwrap().as_str(),
            "SIGNAL NEWNYM"
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
        assert_eq!(
            ControlError::ProcessExited.to_string(),
            "managed tor process exited"
        );
        // An OS code, never a path or a system message.
        const SAMPLE_OS_CODE: u32 = 2;
        assert_eq!(
            ControlError::SystemDirectory(SystemDirectoryError::Os(SAMPLE_OS_CODE)).to_string(),
            "managed tor system directory could not be read (os error 2)",
        );
        assert_eq!(
            ControlError::SystemDirectory(SystemDirectoryError::UnusableLength).to_string(),
            "managed tor system directory length was unusable",
        );
    }
}

/// Covers the `--SocksPort` value `spawn_managed_tor` passes. Does not
/// launch Tor.
#[cfg(test)]
mod socks_port_arg {
    use super::SocksPort;

    #[test]
    fn the_launch_argument_carries_extended_errors() {
        assert_eq!(SocksPort::Auto.as_arg(), "auto ExtendedErrors");
        assert_eq!(SocksPort::Fixed(9050).as_arg(), "9050 ExtendedErrors");
    }
}

/// The actor against a fake tor on an in-memory connection, in the unit gate.
#[cfg(test)]
mod fake_tor {
    use super::{
        BootstrapReadiness, Command, EventSink, TorControlClient, TorControlClientConfig,
        TorLaunch, EVENT_QUEUE_EVENTS,
    };
    use kameo::actor::Spawn;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    /// Bytes the in-memory connection buffers in each direction. A writer that fills
    /// it waits for the reader, as on a socket.
    const PIPE_BYTES: usize = 64 * 1024;

    /// Longer than any step here takes; a wedged actor fails instead of hanging.
    const STEP_BOUND: Duration = Duration::from_secs(10);

    /// A tor that writes `flood` log events before anything else, then answers every
    /// command line with `250 OK`. Every line, because the actor's bootstrap poll asks
    /// too, and an unanswered command would hold every later one behind it.
    async fn flooding_tor(stream: DuplexStream, flood: usize) {
        let (read, mut write) = tokio::io::split(stream);
        for i in 0..flood {
            let event = format!("650 NOTICE flood {i}\r\n");
            if write.write_all(event.as_bytes()).await.is_err() {
                return;
            }
        }
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(_command)) = lines.next_line().await {
            if write.write_all(b"250 OK\r\n").await.is_err() {
                return;
            }
        }
    }

    /// `TSR-F2`: a consumer that reads nothing holds the bound and no more, the rest
    /// are counted, and the read loop is not held up. The reply to a command written
    /// after the flood arrives only once every flood event has been routed, so the
    /// counts are final when it does.
    #[tokio::test]
    async fn a_flood_of_events_is_held_to_the_bound_counted_and_never_stalls_a_reply() {
        const EXCESS: usize = 1000;
        let (ours, theirs) = tokio::io::duplex(PIPE_BYTES);
        let peer = tokio::spawn(flooding_tor(theirs, EVENT_QUEUE_EVENTS + EXCESS));
        let (read, write) = tokio::io::split(ours);
        let (events, mut received) = EventSink::bounded();
        let (readiness, _ready) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Connected {
                read: Box::pin(read),
                write: Box::pin(write),
            },
            events,
            readiness,
        });

        let reply = tokio::time::timeout(
            STEP_BOUND,
            actor.ask(Command::GetInfo(vec!["version".to_owned()])),
        )
        .await
        .expect("a reply arrives while the queue is full")
        .expect("the command is answered");
        assert_eq!(reply.status(), 250);
        assert_eq!(
            received.len(),
            EVENT_QUEUE_EVENTS,
            "held: the bound, no more"
        );
        assert_eq!(
            received.dropped(),
            u64::try_from(EXCESS).expect("small"),
            "every event past the bound is counted"
        );
        // The oldest are kept and the newest dropped.
        let first = received.try_recv().expect("a held event");
        assert_eq!(first.lines(), ["NOTICE flood 0"]);

        actor.stop_gracefully().await.expect("graceful stop");
        actor.wait_for_shutdown().await;
        peer.abort();
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
        BootstrapReadiness, Command, DeathSignal, EventSink, ManagedTor, TorControlClient,
        TorControlClientConfig, TorExit, TorLaunch,
    };
    use kameo::actor::Spawn;
    use std::net::{SocketAddr, TcpListener};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command as ProcCommand, Stdio};
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    use super::super::launch::{self, LoggedFile};
    use crate::test_support::tor_binary;

    /// A spawned test `tor` + its temp `DataDirectory`, attached, not owned: the actor
    /// never takes ownership of an attached tor, so this kills it and cleans up on
    /// drop.
    struct TestTor {
        child: Child,
        _dir: tempfile::TempDir,
        control_addr: SocketAddr,
        cookie_path: PathBuf,
    }

    impl Drop for TestTor {
        fn drop(&mut self) {
            // The only teardown an attached tor gets here.
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
    ///
    /// This is the fixture for the *attached* posture — a tor somebody else runs —
    /// so it does not go through the managed launcher. It still has to start, and
    /// the Expert Bundle's `tor` has no `RPATH`: it finds the libraries shipped
    /// beside it only when the loader is pointed at them. The directory is the
    /// witness's, the same one the managed launcher names, so a symlink resolves
    /// to the target and a path the loader would split fails here instead of
    /// waiting out the control-port timeout.
    async fn spawn_offline_tor() -> TestTor {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let port_file = data_dir.join("control_port");
        let verified = crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary());
        let mut cmd = ProcCommand::new(verified.as_path());
        #[cfg(target_os = "linux")]
        cmd.env("LD_LIBRARY_PATH", verified.library_dir());
        cmd.arg("--DataDirectory")
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
            .stderr(Stdio::null());
        let child = {
            let _spawning = crate::spawn_lock::hold();
            cmd.spawn().expect("spawn tor")
        };
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
        let (events, _events) = EventSink::bounded();
        // This test exercises the handshake + command correlation, not bootstrap; the
        // poll task runs harmlessly against `DisableNetwork 1` (never reaches Ready) and
        // is aborted on drop. Keep the receiver alive so the poll task doesn't stop early.
        let (readiness, _ready_rx) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Attached {
                control_addr: tor.control_addr,
                cookie_path: tor.cookie_path.clone(),
            },
            events,
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
        let (events, _events) = EventSink::bounded();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                // The whole point: a service that can reach the network.
                disable_network: false,
                exit_observer: None,
                leak: None,
            }),
            events,
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

    /// The managed tor reads no configuration but the launcher's own blank file:
    /// no default `torrc`, no default `torrc-defaults`, no default GeoIP file.
    ///
    /// Without `--torrc-file` and `--defaults-torrc`, tor loads both from its
    /// compiled-in `CONFDIR`, which for the pinned Linux bundle is
    /// `/var/tmp/dist/tor/etc/tor` — creatable by any local account. Its GeoIP
    /// files sit beside them under `share/tor`. Command-line options win only
    /// for the keys the launcher names, so whatever else those files say is
    /// merged in.
    ///
    /// The evidence is tor's own startup log, which names every configuration
    /// file it reads or looks for and every GeoIP file it parses. A tor that
    /// read its defaults says so (`Configuration file "…" not present` or
    /// `Read configuration file "…"` naming another path), and that fails here
    /// without planting anything at the host's real default paths. The test
    /// also requires that all four reads are present and name the launcher's
    /// file, so a log that stopped carrying these lines fails instead of
    /// passing empty.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY"]
    async fn managed_tor_reads_no_configuration_but_its_own() {
        // torrc and torrc-defaults; IPv4 and IPv6. Independent of the option
        // list the builder loops: these are what tor's own log must report.
        const OWN_CONFIG_READS: usize = 2;
        const OWN_GEOIP_PARSES: usize = 2;
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().to_path_buf();
        let (readiness, _ready_rx) = BootstrapReadiness::new();
        let (events, _events) = EventSink::bounded();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: data_dir.clone(),
                socks_port: super::SocksPort::Fixed(free_port()),
                disable_network: true,
                exit_observer: None,
                leak: None,
            }),
            events,
            readiness,
        });
        // A handshake means tor has finished reading its configuration.
        let reply = actor
            .ask(Command::GetInfo(vec!["version".to_owned()]))
            .await
            .expect("GETINFO version against the actor-spawned tor");
        assert_eq!(reply.status(), 250);
        actor.stop_gracefully().await.expect("graceful stop");
        actor.wait_for_shutdown().await;

        let ours = launch::blank_config_path(&data_dir);
        let ours = ours.display().to_string();
        let log = std::fs::read_to_string(data_dir.join(launch::LOG_FILE_NAME)).expect("tor's log");
        let mentions = launch::files_named_in_tor_log(&log);
        for mention in &mentions {
            assert_eq!(
                mention.path,
                ours.as_str(),
                "tor named a file the launcher did not"
            );
        }
        let config_reads = mentions
            .iter()
            .filter(|mention| mention.kind == LoggedFile::ConfigRead)
            .count();
        let geoip_parses = mentions
            .iter()
            .filter(|mention| mention.kind == LoggedFile::GeoipParse)
            .count();
        assert_eq!(
            config_reads, OWN_CONFIG_READS,
            "the torrc and the defaults torrc, both ours"
        );
        assert_eq!(
            geoip_parses, OWN_GEOIP_PARSES,
            "the IPv4 and IPv6 GeoIP files, both ours"
        );
    }

    /// The supervisor's subscription against the pinned tor: everything tor sends for
    /// it is one of the events [`super::super::events`] types, and a published onion's
    /// first upload round reaches the trigger (`TSR-Q5`).
    ///
    /// Network-requiring, like the onion round trip: a round needs HSDirs. The KATs pin
    /// lines captured from tor 0.4.9.13; this is where a later tor that writes them
    /// differently fails, with the version printed beside the failure.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY (bootstraps, network)"]
    async fn the_pinned_tors_supervisor_events_parse_and_a_round_triggers() {
        use super::super::events::{
            parse_event, ClientStatus, HsDescAction, RoundMark, TorEvent, UploadRounds,
        };
        use super::super::onion::{parse_service_id, AddOnion, OnionKey, OnionPort};
        use std::net::{Ipv4Addr, SocketAddr};

        /// Bootstrap and the first round together; the capture saw both in under a minute.
        const BOUND: Duration = Duration::from_secs(300);

        let dir = tempfile::tempdir().expect("tempdir");
        let (events, mut received) = EventSink::bounded();
        let (readiness, mut ready_rx) = BootstrapReadiness::new();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                disable_network: false,
                exit_observer: None,
                leak: None,
            }),
            events,
            readiness,
        });
        let version = actor
            .ask(Command::GetInfo(vec!["version".to_owned()]))
            .await
            .expect("GETINFO version");
        let version = version.lines().first().cloned().unwrap_or_default();
        println!("tor under test: {version}");
        let subscribed = actor
            .ask(Command::supervisor_events())
            .await
            .expect("SETEVENTS reaches tor");
        assert_eq!(
            subscribed.status(),
            250,
            "tor knows every event type ({version})"
        );

        let deadline = Instant::now() + BOUND;
        while !matches!(*ready_rx.borrow_and_update(), super::BootstrapState::Ready) {
            assert!(
                Instant::now() < deadline,
                "tor did not bootstrap ({version})"
            );
            tokio::time::timeout(Duration::from_secs(10), ready_rx.changed())
                .await
                .ok();
        }

        let mut expanded = [0u8; super::super::onion::ONION_KEY_BYTES];
        for (i, b) in expanded.iter_mut().enumerate() {
            *b = u8::try_from((i * 11 + 5) % 251).expect("fits u8");
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
        let service_id = parse_service_id(reply.lines()).expect("a v3 ServiceID");
        let mut rounds = UploadRounds::new(service_id.clone());

        let (mut bootstrap, mut circuit, mut notice, mut upload, mut triggered) =
            (false, false, false, false, false);
        while !triggered {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let reply = tokio::time::timeout(remaining, received.recv())
                .await
                .unwrap_or_else(|_| panic!("no upload round triggered in time ({version})"))
                .expect("the actor is alive");
            let parsed = parse_event(&reply).expect("a 650 event");
            match &parsed {
                TorEvent::Unsubscribed => {
                    panic!("an event outside the subscription arrived ({version})")
                }
                TorEvent::Client {
                    status: ClientStatus::Bootstrap(b),
                    ..
                } => bootstrap |= b.progress.is_some(),
                TorEvent::Client {
                    status: ClientStatus::CircuitEstablished,
                    ..
                } => circuit = true,
                TorEvent::Log(_) => notice = true,
                TorEvent::HsDesc(desc) => {
                    if desc.address.as_ref() == Some(&service_id) {
                        upload |= desc.action == HsDescAction::Upload;
                        triggered = rounds.observe(desc).contains(&RoundMark::FirstUploaded);
                    }
                }
                _ => {}
            }
        }
        assert!(bootstrap, "a BOOTSTRAP event with its progress ({version})");
        assert!(circuit, "CIRCUIT_ESTABLISHED ({version})");
        assert!(notice, "a log event ({version})");
        assert!(
            upload,
            "an UPLOAD for our address before the trigger ({version})"
        );
        assert_eq!(received.dropped(), 0, "the test read every event");

        actor.stop_gracefully().await.expect("graceful stop");
        actor.wait_for_shutdown().await;
    }

    /// `TSR-F16`, case C6b: a copy of tor's end leaked into another process does not
    /// hide tor's death. The sleeper holds the socket open for [`LEAK_LIVES`], so
    /// control EOF cannot arrive before then; the process wait reports the death well
    /// inside [`DEATH_BOUND`], first, while the sleeper is still running.
    ///
    /// Before the process wait existed, the death reached the actor only as EOF, when
    /// the sleeper exited: about five seconds here, 30.3 s in the Windows measurement.
    #[tokio::test]
    #[ignore = "requires a Tor binary via SHEKYL_TEST_TOR_BINARY"]
    async fn a_leaked_tor_end_does_not_hide_tors_death() {
        /// How long the leaked copy keeps the socket open.
        const LEAK_LIVES: Duration = Duration::from_secs(5);
        /// Well under that: the process wait answers within milliseconds of the kill.
        const DEATH_BOUND: Duration = Duration::from_secs(2);

        let dir = tempfile::tempdir().expect("tempdir");
        let (exit_tx, exit_rx) = oneshot::channel();
        let (sleeper_tx, sleeper_rx) = oneshot::channel();
        let (readiness, _ready_rx) = BootstrapReadiness::new();
        let (events, _events) = EventSink::bounded();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                disable_network: true,
                exit_observer: Some(exit_tx),
                leak: Some(super::super::launch::LeakTorEnd {
                    lives: LEAK_LIVES,
                    sleeper: sleeper_tx,
                }),
            }),
            events,
            readiness,
        });
        let reply = actor
            .ask(Command::GetInfo(vec!["process/pid".to_owned()]))
            .await
            .expect("GETINFO process/pid");
        let pid: u32 = reply
            .lines()
            .first()
            .and_then(|line| line.strip_prefix("process/pid="))
            .and_then(|pid| pid.parse().ok())
            .expect("tor's pid");
        let mut sleeper = sleeper_rx.await.expect("the sleeper holds tor's end");

        kill_by_pid(pid);
        let started = Instant::now();
        let exit = tokio::time::timeout(DEATH_BOUND, exit_rx)
            .await
            .expect("the death is reported before the leaked end closes")
            .expect("the exit observer reports");
        let took = started.elapsed();
        assert!(
            matches!(
                exit,
                TorExit::Died {
                    first: DeathSignal::ProcessExited,
                    ..
                }
            ),
            "the process wait fired first: {exit:?}"
        );
        assert!(
            sleeper.try_wait().expect("sleeper status").is_none(),
            "the leaked copy was still open when the death was reported ({took:?})"
        );
        tokio::time::timeout(DEATH_BOUND, actor.wait_for_shutdown())
            .await
            .expect("the actor stopped on the death");
        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Kill tor by pid, as a crash would: no signal it can catch.
    fn kill_by_pid(pid: u32) {
        #[cfg(unix)]
        {
            let pid = libc::pid_t::try_from(pid).expect("a pid fits pid_t");
            // SAFETY: `kill(2)` with a constant signal reads and writes no memory.
            assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0, "kill tor");
        }
        #[cfg(windows)]
        {
            let status = crate::spawn_lock::status(std::process::Command::new("taskkill").args([
                "/F",
                "/PID",
                &pid.to_string(),
            ]))
            .expect("taskkill runs");
            assert!(status.success(), "taskkill tor");
        }
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
        let (events, _events) = EventSink::bounded();
        let actor = TorControlClient::spawn(TorControlClientConfig {
            launch: TorLaunch::Managed(ManagedTor {
                // The declared test bypass of the hash-pin gate: this lifecycle
                // test injects an arbitrary tor (any version works — we are
                // proving spawn/shutdown, not the pin).
                tor_binary: crate::binary::VerifiedTorBinary::unchecked_for_test(tor_binary()),
                data_dir: dir.path().to_path_buf(),
                socks_port: super::SocksPort::Fixed(free_port()),
                disable_network: true,
                exit_observer: Some(exit_tx),
                leak: None,
            }),
            events,
            readiness,
        });

        // Spawn proof: the actor drives the tor it launched, over the inherited
        // connection.
        let reply = actor
            .ask(Command::GetInfo(vec!["version".to_owned()]))
            .await
            .expect("GETINFO version against the actor-spawned tor");
        assert_eq!(reply.status(), 250);

        // `TSR-Q7`: the inherited connection is the only control connection. Tor
        // opened no control port another local process could reach.
        let listeners = actor
            .ask(Command::GetInfo(vec!["net/listeners/control".to_owned()]))
            .await
            .expect("GETINFO net/listeners/control");
        assert_eq!(listeners.status(), 250);
        assert_eq!(
            listeners.lines().first().map(String::as_str),
            Some("net/listeners/control="),
            "the managed tor listens on no control port"
        );

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
