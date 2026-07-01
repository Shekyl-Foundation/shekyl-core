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
//!   `SETEVENTS` is sent — and only *after* `AUTHENTICATE` + `TAKEOWNERSHIP`
//!   succeed is the read half wrapped as the internal `ReplyStream`
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
//! reconnecting into the same desync; `TAKEOWNERSHIP` (issued first, post-auth)
//! means Tor exits when this connection drops, so a crash one millisecond later is
//! still orphan-protected.
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
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures_core::Stream;
use kameo::actor::ActorRef;
use kameo::message::{Context, Message, StreamMessage};
use kameo::reply::{DelegatedReply, ReplySender};
use kameo::Actor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::auth::{parse_authchallenge, read_cookie_file, AuthError};
use super::bootstrap::{parse_bootstrap_progress, BootstrapState};
use super::framing::{ControlReply, Framed, FramingError, ReplyFramer};
use super::safecookie::verify_server_hash;

/// Per-read bound on a hung control port — a handshake read that does not complete
/// in this window fails the spawn (DQ-T0.6) rather than hanging the actor.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Read-chunk size for draining the socket into the framer.
const READ_CHUNK: usize = 4096;

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
pub struct EventSink(mpsc::UnboundedSender<ControlReply>);

impl EventSink {
    /// Wrap the sending half of an event channel; the consumer keeps the receiver.
    #[must_use]
    pub fn new(sender: mpsc::UnboundedSender<ControlReply>) -> Self {
        Self(sender)
    }

    /// Route an async event to the consumer. A closed receiver means the consumer
    /// is gone, so dropping the event is correct — not a failure the actor acts on.
    fn route(&self, reply: ControlReply) {
        self.0.send(reply).ok();
    }
}

/// A control command the engine asks the actor to run, **one in flight at a time**.
///
/// `ADD_ONION`/`DEL_ONION` (the SP-T3 onion surface) are intentionally *not* here
/// yet — the enum extends without reshaping the actor, so they land when SP-T3
/// builds them rather than as unused variants now. `TAKEOWNERSHIP` is also absent
/// by design: it is issued internally as the first command after `AUTHENTICATE`,
/// not engine-driven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `GETINFO <keys>` — e.g. `status/bootstrap-phase`, `version`, circuit info.
    GetInfo(Vec<String>),
    /// `SETEVENTS <events>` — subscribe to async events (`STREAM` for the
    /// DQ-T0.4 measurement).
    SetEvents(Vec<String>),
}

impl Command {
    /// The wire line (without the trailing CRLF), or [`ControlError::InvalidCommand`]
    /// if the token list is empty or any token carries a forbidden character.
    ///
    /// Tokens are space-joined into one control line. An **empty** list would render
    /// as a malformed trailing-space line (`"GETINFO "`); a token containing a space
    /// (the separator) or an ASCII control byte — notably `\r`/`\n` — could split
    /// into extra control commands and desync the no-request-ID FIFO correlation.
    /// Validating *before* the line is built keeps both off the wire. (We never
    /// issue an argument-less command, `SETEVENTS`-clear-all included.)
    fn to_wire(&self) -> Result<String, ControlError> {
        let (verb, tokens) = match self {
            Self::GetInfo(keys) => ("GETINFO", keys),
            Self::SetEvents(events) => ("SETEVENTS", events),
        };
        if tokens.is_empty() {
            return Err(ControlError::InvalidCommand);
        }
        for token in tokens {
            if token.is_empty() || token.bytes().any(|b| b == b' ' || b.is_ascii_control()) {
                return Err(ControlError::InvalidCommand);
            }
        }
        Ok(format!("{verb} {}", tokens.join(" ")))
    }
}

/// Reply type the caller of a [`Command`] receives.
pub type CommandResult = Result<ControlReply, ControlError>;

/// Spawn-time configuration ([`Actor::Args`]).
pub struct TorControlConfig {
    /// The loopback control-port address.
    pub control_addr: SocketAddr,
    /// Path to `DataDirectory/control_auth_cookie`.
    pub cookie_path: PathBuf,
    /// Sink for asynchronous events.
    pub events: EventSink,
    /// Bootstrap-readiness publisher. The actor's poll task drives the
    /// `watch<BootstrapState>`; the consumer holds the receiver (design §3b).
    pub readiness: BootstrapReadiness,
}

/// The control-port actor (one `TorService` actor). SP-T0b-1 adds the bootstrap poll
/// task; the `child` field is the remaining seam (managed-vs-attached lifecycle),
/// present now (unused) so SP-T0b-2 adds behaviour without reshaping the struct.
///
/// Owns the write half and the in-flight bookkeeping; the read half lives in the
/// attached `ReplyStream`.
pub struct TorControl {
    /// Write half — commands go out here, one on the wire at a time.
    writer: OwnedWriteHalf,
    /// Async-event sink.
    events: EventSink,
    /// The command currently on the wire, awaiting its reply (`DelegatedReply`).
    pending: Option<ReplySender<CommandResult>>,
    /// Commands that arrived while one was on the wire — their **already-validated
    /// wire lines** — drained FIFO as each reply lands, so order (the only reply
    /// correlation there is) is preserved. Storing the rendered line (not the
    /// `Command`) means `to_wire` runs exactly once per command.
    queue: VecDeque<(String, ReplySender<CommandResult>)>,
    /// SP-T0b-2 seam: the managed `tor` child process. `None` until SP-T0b-2 owns it.
    #[allow(dead_code)]
    child: Option<TorChild>,
    /// The bootstrap-readiness poll task (design §3b), aborted on drop. Held so the
    /// actor owns its task; the task also self-terminates (`Ready` / actor-death /
    /// no-listeners), so this abort is a prompt-cleanup backstop, not the only exit.
    bootstrap_poll: JoinHandle<()>,
}

/// SP-T0b-2 seam — the managed `tor` child process handle (fleshed out by SP-T0b-2).
pub struct TorChild;

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
            control_addr,
            cookie_path,
            events,
            readiness,
        } = args;

        let stream = TcpStream::connect(control_addr)
            .await
            .map_err(|_| ControlError::Connect)?;
        let (mut reader, mut writer) = stream.into_split();
        let mut framer = ReplyFramer::default();

        // SAFECOOKIE handshake — synchronous request/response; no 650 events can
        // arrive before SETEVENTS, so reading the framer by hand is safe here.
        let cookie = read_cookie_file(&cookie_path).map_err(ControlError::Auth)?;
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

        // Orphan protection from millisecond zero: Tor exits when this connection
        // drops, so even an immediate crash leaves no orphaned tor.
        write_line(&mut writer, "TAKEOWNERSHIP").await?;
        expect_status(&mut reader, &mut framer, 250).await?;

        // Handshake done — hand the read half to the stream and let kameo merge it
        // into the mailbox.
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
            queue: VecDeque::new(),
            child: None,
            bootstrap_poll,
        })
    }
}

impl Drop for TorControl {
    fn drop(&mut self) {
        // Stop the bootstrap poll task when the actor goes away. (SP-T0b-2 extends
        // shutdown to the managed `child`, riding the `TAKEOWNERSHIP` already landed.)
        self.bootstrap_poll.abort();
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
/// - **`watch` send fails** → every receiver was dropped (no one is listening): stop
///   **silently**. This is not a Tor failure and must never publish `Failed`.
/// - **100% reached** → publish [`BootstrapState::Ready`] (the gate) and stop.
async fn bootstrap_poll_loop(actor: ActorRef<TorControl>, tx: watch::Sender<BootstrapState>) {
    // The highest progress published so far, so a Tor `PROGRESS=` regression never
    // renders the "Connecting… n%" UX backward (progress is telemetry; monotonicity is
    // cosmetic, not enforced).
    let mut peak = 0u8;
    loop {
        let Ok(reply) = actor
            .ask(Command::GetInfo(vec!["status/bootstrap-phase".to_owned()]))
            .await
        else {
            // Actor gone — the control connection died mid-bootstrap.
            tx.send(BootstrapState::Failed).ok();
            return;
        };
        if let Some(progress) = parse_bootstrap_progress(&reply) {
            if progress >= 100 {
                // `Ready` is the gate; publish and stop. A send error here just means
                // no listeners, and we are stopping regardless.
                tx.send(BootstrapState::Ready).ok();
                return;
            }
            peak = peak.max(progress);
            if tx
                .send(BootstrapState::Connecting { progress: peak })
                .is_err()
            {
                // No receivers left — stop quietly. NOT a failure.
                return;
            }
        }
        // A `None` parse (malformed / absent `PROGRESS=`) is "unknown, skip": hold the
        // last published state and poll again — never publish a spurious `Connecting{0}`.
        tokio::time::sleep(BOOTSTRAP_POLL_INTERVAL).await;
    }
}

impl TorControl {
    /// Fail every in-flight and queued caller with `err` — the actor is stopping.
    fn fail_all_pending(&mut self, err: &ControlError) {
        if let Some(tx) = self.pending.take() {
            tx.send(Err(err.clone()));
        }
        for (_line, tx) in self.queue.drain(..) {
            tx.send(Err(err.clone()));
        }
    }
}

impl Message<Command> for TorControl {
    type Reply = DelegatedReply<CommandResult>;

    async fn handle(&mut self, cmd: Command, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let (delegated, reply_sender) = ctx.reply_sender();
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
                Ok(line) if self.pending.is_some() => self.queue.push_back((line, tx)),
                // The wire is free — write the line now.
                Ok(line) => match write_line(&mut self.writer, &line).await {
                    Ok(()) => self.pending = Some(tx),
                    // An Io failure mid-write disturbs the wire; fail the actor.
                    Err(e) => {
                        tx.send(Err(e.clone()));
                        self.fail_all_pending(&e);
                        ctx.stop();
                    }
                },
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
                Some(tx) => {
                    tx.send(Ok(reply));
                    if let Some((next_line, next_tx)) = self.queue.pop_front() {
                        match write_line(&mut self.writer, &next_line).await {
                            Ok(()) => self.pending = Some(next_tx),
                            Err(e) => {
                                next_tx.send(Err(e.clone()));
                                self.fail_all_pending(&e);
                                ctx.stop();
                            }
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

/// Uppercase hex (Tor's control-port convention) of `bytes`.
fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
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
            cmd.to_wire().unwrap(),
            "GETINFO version status/bootstrap-phase"
        );
    }

    #[test]
    fn setevents_renders_space_separated_events() {
        let cmd = Command::SetEvents(vec!["STREAM".to_owned(), "STATUS_CLIENT".to_owned()]);
        assert_eq!(cmd.to_wire().unwrap(), "SETEVENTS STREAM STATUS_CLIENT");
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
    fn hex_upper_is_fixed_width_uppercase() {
        assert_eq!(hex_upper(&[0x00, 0x0a, 0xff, 0xab]), "000AFFAB");
        // A 32-byte nonce always renders to 64 hex digits.
        assert_eq!(hex_upper(&[0u8; 32]).len(), 64);
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
    use super::{BootstrapReadiness, Command, EventSink, TorControl, TorControlConfig};
    use kameo::actor::Spawn;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command as ProcCommand, Stdio};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;

    /// The bundled `tor` binary path; **hard-fail** (not skip) when the test runs.
    fn tor_binary() -> PathBuf {
        std::env::var("SHEKYL_TEST_TOR_BINARY")
            .map(PathBuf::from)
            .expect("SHEKYL_TEST_TOR_BINARY must point at a tor binary on the integration lane")
    }

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
            control_addr: tor.control_addr,
            cookie_path: tor.cookie_path.clone(),
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
}
