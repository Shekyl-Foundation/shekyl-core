// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona's loopback serve endpoint — production successor of the
//! SP-T3 spike's `serve.rs`, whose inbound-hardening shape (decoupled
//! accept, per-step timeouts, pre-allocation request bound, aggregate-only
//! counters) was validated there and carries forward here. The spike's
//! `x-spike/v0` framing does **not** carry forward; the production route
//! is `GET /shard/{id}` (`RF-R1`).
//!
//! Integration point for the serving host (SH-1): [`PServeEndpoint::bind`]
//! plus [`PServeEndpoint::addr`] as the `ADD_ONION` `Port=` target. This
//! module does not speak Tor.
//!
//! # Why hand-rolled HTTP/1.1 rather than a framework
//!
//! Two personas served from one wallet must be **byte-indistinguishable at
//! the header level**. Every mainstream framework emits at least a `date`
//! header (a clock-skew fingerprint and liveness timestamp), most emit
//! `server`, several add `etag` or range support opportunistically. Those
//! defaults are exactly the fingerprint under discipline here, and they
//! are not reliably removable — so the response is written by hand: a
//! fixed status line, a fixed `content-type`, a computed `content-length`,
//! nothing else. [`RESPONSE_HEADER_NAMES`] is the complete set, asserted
//! by test.
//!
//! # The request header and the countersignature (`SF-D5`, `SF-D8`)
//!
//! Every request carries exactly one [`REQUEST_HEADER_NAME`] header whose
//! value decodes canonically to 72 bytes
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32]`. Missing, duplicate,
//! malformed, or wrong-length values are the identical complete-head 404,
//! and so is an `anchor_height` outside the persona's pre-sign gate
//! ([`anchor_within_gate`]). A servable request is answered with the
//! persona's `HybridSignature` over the 112-byte transcript
//! `nonce[32] ‖ anchor_height_le[8] ‖ anchor_hash[32] ‖ shard_id_le[8] ‖ delivery_digest[32]`
//! — the canonical [`SIGNATURE_ENVELOPE_LEN`] bytes — written **after** the
//! `RF-D4` frame, as
//! the last bytes of the response, both inside one `content-length`. The
//! signer is the host's ([`PassSigner`]); this crate holds no key.
//!
//! **What the signature covers.** `delivery_digest` is
//! [`pass_delivery_digest`](shekyl_archival_retention::pass_delivery_digest):
//! a digest of the framed body this response carries, salted by the
//! request's nonce. The persona streams the body while folding exactly
//! the bytes it writes into that digest, then signs it and sends the
//! signature as the response's last bytes. So the signature commits to the
//! bytes delivered for this request and to no others. It does not show
//! that this persona stores them; the route's topology is what prices a
//! persona that relays.
//!
//! **Why it is last, and why nothing heavy comes first.** A requester
//! holds the signature only once the whole frame has crossed this
//! persona's link, and a transfer that fails mid-body yields none. In the
//! other direction, **`P` does no work that scales with shard size until
//! the requester has received the bytes that work is for** (`SF-D8`,
//! amended 2026-10-06, as an abuse mitigation). Before the 200 head this
//! persona parses, runs the anchor gate, opens the shard — which fixes the
//! frame and `content-length` — and asks the key whether it will sign
//! ([`PassKey::ready`](crate::countersign::PassKey::ready)). Every read,
//! hash and write after the head is paid for by the requester taking the
//! bytes, and the one hybrid sign comes after the last of them. A
//! requester that stops reading stalls this persona within one chunk; one
//! that disconnects stops it after about one socket buffer; neither is
//! signed for. The order is [`admit`] then [`write_response`], and
//! `serve_seal_tests.rs` holds each clause.
//!
//! # No request logging, at any level
//!
//! Not the path, not the peer, not the timing. The only observables are
//! six aggregate monotone counters with no per-request structure:
//! [`PServeEndpoint::served_count`], [`PServeEndpoint::refused_count`],
//! [`PServeEndpoint::lookup_failure_count`],
//! [`PServeEndpoint::sign_failure_count`],
//! [`PServeEndpoint::late_sign_failure_count`],
//! [`PServeEndpoint::accept_error_count`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::countersign::{anchor_within_gate, PassSigner, SIGNATURE_ENVELOPE_LEN};
use crate::provider::{ShardBody, ShardProvider};
use shekyl_archival_retention::{
    PassRequestHeader, PASS_COUNTERSIGNATURE_MESSAGE_LEN, PASS_NONCE_LEN,
};
use shekyl_curve_tree::served_frame::ServedFrameHeader;
use shekyl_types::BlockHeight;

// Sibling of this file, not `serve/delivery.rs`: the endpoint stays one
// module, and the digest type is private to it.
#[path = "delivery.rs"]
mod delivery;
use delivery::FramedDigest;

// The route grammar this endpoint answers — `GET /shard/{id}`, the
// `application/octet-stream` content type, the request header's name and
// textual codec, and the complete response header set — is declared once
// in `shekyl_curve_tree::serving_route` and read by both ends of the route
// (`SF-D4`: the fetch client may not depend on this crate, and one
// constant read twice is the ratification two agreeing constants are
// not). Re-exported so this crate's public surface and its tests are
// unchanged.
pub use shekyl_curve_tree::serving_route::{
    decode_request_header, CONTENT_TYPE, REQUEST_HEADER_NAME, RESPONSE_HEADER_NAMES, ROUTE_PREFIX,
};

/// Cap on the request head, applied **while reading** rather than after —
/// the pre-allocation bound. A shard read's request is a request line plus
/// a handful of headers, well under 1 KiB; 8 KiB leaves room for client
/// noise while bounding what a hostile peer can make the endpoint buffer.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Maximum connections served **at once**; arrivals past the cap are
/// closed, never answered.
///
/// A shard GET carries ~3.33 MB of body. None of the per-connection
/// protections (timeouts, request bound) limits aggregate load; nor does
/// the onion's `MaxStreams`, which is per rendezvous circuit. This cap is
/// that aggregate bound. Over onion the transfer is symmetric (the
/// requester must receive the body), so the cap is concurrent-circuit
/// occupancy, not a one-sided egress tax.
///
/// **Carried placeholder (SPIKE-PIN-2): the value is not a derivation.**
/// The binding resource is *egress*, not memory: a body is streamed in
/// bounded chunks straight from the store ([`ShardBody`]), so concurrency
/// costs descriptors, tasks, and one chunk each — not `N × 3.33 MB`. Keep
/// it that way: a change that materialises whole shards silently
/// reinterprets this constant as a `MAX_INFLIGHT × 3.33 MB` resident-memory
/// budget, which at 64 is 213 MB and does not fit the rule-76 provisioning
/// floor. The W₂ rig derives the real value on that hardware; a rising
/// [`PServeEndpoint::refused_count`] is the operator signal that the
/// placeholder is binding.
pub const MAX_INFLIGHT: usize = 64;

/// Bound on reading the request head from an accepted connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the whole response write (head plus body). Generous because
/// 3.33 MB over a rendezvous circuit *is* the slow path — this is the
/// backstop against a peer that trickles forever, not a latency budget.
const WRITE_TIMEOUT: Duration = Duration::from_secs(600);

/// Bound on **one** write making progress into the socket.
///
/// [`WRITE_TIMEOUT`] alone would let a peer that simply stops reading hold
/// its in-flight slot for ten minutes: 64 such connections, ~100 bytes
/// each, deny every witness the persona is bonded to answer, renewed
/// indefinitely for nothing. A peer that stalls blocks the very next chunk
/// write, so this — not the total — is what a silent connection actually
/// costs. It bounds *stalls*, not slowness: `write_all` returns when the
/// kernel accepts the bytes, and the bound restarts per chunk, so a genuine
/// slow circuit is served for as long as it keeps draining.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Internal read/write granularity for the shard body.
///
/// **Not wire framing.** The frame is `RF-D4`'s, written once ahead of the
/// body; this constant only sets how the already-framed payload is split
/// across reads and writes, and the wire bytes are identical to a single
/// write.
///
/// The loops are chunked for two reasons: peak memory per in-flight
/// connection is one chunk rather than a whole shard — on the digest read
/// and on the sending read alike — and resumability, which `RF-D4` did
/// **not** rule in, so the frame carries no resumption field and adding one
/// is still a future format change, becomes a change of framing on top of an
/// already-incremental reader-writer instead of a rewrite. That is the §9.5
/// discipline that a format property must never be foreclosed by what was
/// convenient to build, and it held: the format round came and went without
/// this loop constraining it.
const WRITE_CHUNK_BYTES: usize = 64 * 1024;

/// Backoff when `accept` fails (e.g. transient FD pressure). Prevents a
/// tight spin without logging or changing response shape.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// Bound on discarding a peer's unread request bytes before close.
///
/// **Time only, deliberately.** The in-flight permit is still held during the
/// drain, so the drain must be bounded — but slot-squatting is a *duration*
/// property, and this is the bound that measures it. A byte bound does not:
/// a peer trickling a few kilobytes slowly squats the full timeout anyway,
/// while a peer that sent one honest large request gets its drain cut short.
///
/// The invariant [`close_gracefully`] is defending is **an empty receive queue
/// at drop**, not EOF as such: Linux sends RST rather than FIN when a socket
/// is dropped with unread bytes queued, and the RST discards the response
/// still in the send buffer. EOF is simply the one condition that *positively*
/// establishes the queue will stay empty, so the loop reads until it.
///
/// Hitting this timeout is therefore a normal outcome, not a failure: a peer
/// that stops sending but holds its write half open leaves `read` pending on
/// an already-drained queue, and dropping there is clean. What is not safe is
/// stopping while bytes remain — which is what a *byte* bound does. An 8 KiB
/// cap guaranteed the reset for every peer that sent more than 8 KiB, the
/// exact failure this drain exists to prevent, reintroduced by its own bound.
/// Do not add one back.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// A running loopback serve endpoint for one persona.
///
/// Dropping it aborts the accept loop; in-flight connection tasks are
/// detached and end at their own timeouts. `shekyl-p-host` keeps that
/// shape and *orders* it: it stops tor first, so the drop happens only
/// once no onion descriptor points at this port.
pub struct PServeEndpoint {
    addr: SocketAddr,
    accept_task: JoinHandle<()>,
    counters: Arc<Counters>,
}

/// The endpoint's aggregate counters, shared by the accept loop and every
/// connection task. Each is documented on the accessor that reads it.
#[derive(Default)]
struct Counters {
    served: AtomicU64,
    refused: AtomicU64,
    lookup_failures: AtomicU64,
    sign_failures: AtomicU64,
    late_sign_failures: AtomicU64,
    accept_errors: AtomicU64,
}

impl PServeEndpoint {
    /// Bind an ephemeral **loopback** port and start answering shard reads
    /// from `provider`, countersigned by `signer`.
    ///
    /// The bind address is `127.0.0.1:0` — never a routable interface,
    /// never a wildcard. A wildcard bind would make the endpoint reachable
    /// without the rendezvous and attributable to the host's IP, the exact
    /// property the onion exists to remove. Enforced here *and*
    /// independently at the `ADD_ONION` target (`OnionPort::loopback`
    /// refuses non-loopback), because the two are separate opportunities
    /// to get it wrong.
    ///
    /// `signer` supplies the persona's height for the `SF-D5` gate and the
    /// `SF-D8` countersignature. A host whose key is not yet resident binds
    /// a signer that refuses (`shekyl-p-host`'s `NoResidentKey`): the
    /// endpoint stays up and answers the identical 404, never an unsigned
    /// body.
    ///
    /// # Errors
    ///
    /// The bind error, verbatim, if the loopback listener cannot be
    /// created.
    pub async fn bind(
        provider: Arc<dyn ShardProvider>,
        signer: Arc<dyn PassSigner>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let addr = listener.local_addr()?;
        let counters = Arc::new(Counters::default());
        let loop_counters = Arc::clone(&counters);
        // Bounds concurrency without queueing: an arrival past the cap is
        // closed immediately rather than parked, so the refusal costs one
        // accept and frees the descriptor at once.
        let permits = Arc::new(Semaphore::new(MAX_INFLIGHT));
        // Decoupled accept loop: its own task, one spawned task per
        // connection, so a stalled rendezvous circuit blocks only itself.
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    // The peer address is deliberately dropped rather than
                    // bound: it is a forensic surface and nothing here may
                    // record it. Back off on accept failure so FD exhaustion
                    // cannot turn this into a tight CPU spin, and count it —
                    // a listener that has become permanently unusable is
                    // otherwise indistinguishable from a quiet epoch, and
                    // the persona would learn about it from a slash.
                    loop_counters.accept_errors.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                };
                // Over capacity: drop the stream, which closes it. Not a
                // 503 — a status code would add a response shape and hand
                // a prober a free capacity oracle; a closed connection is
                // indistinguishable from ordinary circuit failure.
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    loop_counters.refused.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                };
                let provider = Arc::clone(&provider);
                let signer = Arc::clone(&signer);
                let counters = Arc::clone(&loop_counters);
                tokio::spawn(async move {
                    // Errors are swallowed by design: a failed connection
                    // must produce no log line and no differing response,
                    // or the failure itself becomes an observable. `.ok()`
                    // rather than `let _ =` so the discard is explicit.
                    handle_connection(stream, provider, signer, &counters)
                        .await
                        .ok();
                    // Held for the whole connection, so the slot reopens
                    // only once the shard has finished sending. What bounds
                    // that hold against a hostile peer is
                    // WRITE_STALL_TIMEOUT, not WRITE_TIMEOUT: a connection
                    // that stops making progress costs the cap 30 s, not
                    // ten minutes.
                    drop(permit);
                });
            }
        });
        Ok(Self {
            addr,
            accept_task,
            counters,
        })
    }

    /// The bound loopback address — the `ADD_ONION` `Port=` target.
    ///
    /// Bound once per endpoint (`127.0.0.1:0`), so a caller that publishes
    /// an onion against it holds a target that stays valid for as long as
    /// it holds the endpoint. `shekyl-p-host` rests on exactly that.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shard responses fully written — an **aggregate**, no per-request
    /// structure. Exists so a harness can assert the endpoint served what
    /// it believes it served; it carries no path, no peer, no timing.
    #[must_use]
    pub fn served_count(&self) -> u64 {
        self.counters.served.load(Ordering::Relaxed)
    }

    /// Connections refused for exceeding [`MAX_INFLIGHT`] — the operator
    /// signal that the carried placeholder cap is binding and wants its
    /// W₂-rig derivation.
    #[must_use]
    pub fn refused_count(&self) -> u64 {
        self.counters.refused.load(Ordering::Relaxed)
    }

    /// Store faults while answering a parsed shard read.
    ///
    /// Nothing here is a distinct wire outcome: the cases that fail before
    /// a byte is written are the shared 404, and the cases that fail after
    /// the head is out are a closed connection with no countersignature.
    ///
    /// Counted:
    ///
    /// * the tip the anchor gate needs could not be read, so the gate never
    ///   ran, or the shard could not be opened (I/O, or bytes pruned out
    ///   from under a serve-set that was not pinned) — the shared 404;
    /// * after the head, the body failed to read part-way, ran past the
    ///   frame its header declared, or ended short of it — the response
    ///   ends without an envelope.
    ///
    /// An anchor the gate refuses, and every other ordinary miss (unknown
    /// id, unfrozen segment), is the deliberate 404 and is **not** counted.
    /// A key that refuses its pre-flight is [`Self::sign_failure_count`];
    /// one that fails after the body is [`Self::late_sign_failure_count`].
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.counters.lookup_failures.load(Ordering::Relaxed)
    }

    /// Servable requests the key refused at its pre-flight
    /// ([`PassKey::ready`](crate::countersign::PassKey::ready)): the anchor
    /// was inside the gate and the shard was opened, and the key said it
    /// would not sign — not resident, offline, or a host-side policy
    /// refusal. On the wire the identical 404, before any body byte was
    /// read; here, apart from [`Self::lookup_failure_count`]. An unheld
    /// shard never reaches this counter: the key is asked after the open.
    #[must_use]
    pub fn sign_failure_count(&self) -> u64 {
        self.counters.sign_failures.load(Ordering::Relaxed)
    }

    /// Responses whose body went out and whose countersignature then
    /// failed: the key had passed its pre-flight and `sign_pass` failed, or
    /// returned an envelope that is not [`SIGNATURE_ENVELOPE_LEN`] bytes.
    /// The response is a 200 cut short of its envelope — the head was
    /// already out — which is why this is counted apart from
    /// [`Self::sign_failure_count`]: that one is a 404 by policy, this one
    /// is a truncated transfer by cryptographic fault. Under the `ready`
    /// contract it should stay at zero; a persona that sees it move has a
    /// key whose pre-flight says yes to what its signer then refuses.
    #[must_use]
    pub fn late_sign_failure_count(&self) -> u64 {
        self.counters.late_sign_failures.load(Ordering::Relaxed)
    }

    /// `accept` failures. The loop backs off and retries rather than
    /// exiting, so without this a listener that has become permanently
    /// unusable — sustained FD exhaustion, a descriptor that will never
    /// accept again — looks exactly like a quiet epoch: the other
    /// counters simply stop moving. Aggregate and monotone like the rest;
    /// it names no peer and no time.
    #[must_use]
    pub fn accept_error_count(&self) -> u64 {
        self.counters.accept_errors.load(Ordering::Relaxed)
    }
}

impl Drop for PServeEndpoint {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl std::fmt::Debug for PServeEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bound port is the mapping target of a persona's onion;
        // rendering only the shape keeps the type safe in any `{:?}`
        // context.
        f.debug_struct("PServeEndpoint").finish_non_exhaustive()
    }
}

/// Read one request head, answer it, close cleanly.
///
/// No keep-alive: each read is its own connection, which keeps the serve
/// unit unambiguous and removes connection reuse as a cross-persona
/// correlation surface. The close goes through [`close_gracefully`], which
/// is load-bearing rather than tidy — see there.
///
/// # Wire classes (intentionally two, not one)
///
/// * **Complete request head that is non-servable** (wrong path/method,
///   malformed route/id, unknown or unfrozen shard, store failure, a key
///   that is not ready) → the single shared [`render_not_found`] body. A
///   second status (405 vs 404 vs 400) fingerprints the implementation; a
///   distinct store-failure response is a live health oracle. Holdings are
///   chain-public — GET 200 vs 404 is already the availability oracle —
///   and are not what this collapse hides.
/// * **No complete head** (oversized buffer, mid-head EOF, read timeout)
///   or **over capacity** → connection close with no HTTP bytes. Same
///   class as ordinary circuit death; not a status-code oracle. Writing
///   404 after a failed head read would invent a response for peers that
///   never finished speaking HTTP, and would not match the capacity path.
///
/// # The residual: a truncated `200`
///
/// Which response a complete head gets is decided before any byte is
/// written, so the two classes above are not distinguishable by *choice* of
/// response. A body can still be cut short after the head: by a stalled or
/// vanished peer; by a store that fails, or changes length, under a segment
/// whose servability was already established (corruption, or a prune of a
/// segment being served without a pin); or by a key that passed its
/// pre-flight and then failed to sign. The first is indistinguishable from
/// ordinary circuit death. The second is a store fault this crate cannot
/// answer and does not hide from the operator
/// ([`PServeEndpoint::lookup_failure_count`]). The third is a cryptographic
/// fault, counted apart ([`PServeEndpoint::late_sign_failure_count`])
/// because every refusal the key could make on policy was asked for before
/// the head ([`PassKey::ready`]) and rendered as the 404. It is named here
/// so a future change that lets *ordinary* misses truncate — a body that
/// resolves its own servability lazily, a key that leaves a policy refusal
/// to `sign_pass` — is recognised as widening a probe surface rather than
/// as a refactor.
///
/// [`PassKey::ready`]: crate::countersign::PassKey::ready
async fn handle_connection(
    mut stream: TcpStream,
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    counters: &Counters,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    let written = tokio::time::timeout(
        WRITE_TIMEOUT,
        respond(&mut stream, &head, provider, signer, counters),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write"))?;
    // Close cleanly whether or not the response completed: the drain is
    // what keeps a half-read request from turning the bytes already queued
    // into an RST.
    close_gracefully(&mut stream).await;
    written
}

/// Half-close, then discard whatever the peer still had in flight.
///
/// Dropping a socket that still has unread bytes in its receive queue makes
/// Linux send RST rather than FIN, and an RST can destroy response bytes
/// still sitting in the send buffer. Any request with a body — every `POST`
/// on the wrong-method path — or a pipelined second request would otherwise
/// see a reset instead of the shared 404, and a witness that pipelines could
/// see a *truncated shard*, failing content verification on bytes this
/// endpoint sent correctly. `connection: close` would say as much in one
/// header, but [`RESPONSE_HEADER_NAMES`] is the cross-persona fingerprint
/// and is closed; this says it at the socket layer, where it costs no
/// observable at all.
async fn close_gracefully(stream: &mut TcpStream) {
    stream.shutdown().await.ok();
    let mut sink = [0u8; 1024];
    tokio::time::timeout(DRAIN_TIMEOUT, async {
        // Discard until the queue is drained: EOF ends the loop, and a peer
        // that merely stops sending leaves `read` pending on an empty queue
        // until DRAIN_TIMEOUT — both are safe to drop on. Stopping while
        // bytes remain is the RST case. See DRAIN_TIMEOUT.
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .ok();
}

/// Answer one complete request head on `stream`: admission, then the
/// response. Generic over the writer so the `SF-D8` invariant tests can
/// stand a sink in for the socket and say exactly how many bytes a
/// requester took before it stopped.
async fn respond<W: AsyncWrite + Unpin>(
    stream: &mut W,
    head: &[u8],
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    counters: &Counters,
) -> io::Result<()> {
    let admitted = admit(head, provider, &signer, counters).await;
    write_response(stream, admitted, signer, counters).await
}

/// A servable request, admitted: the body to stream and the request fields
/// the transcript will name. No digest and no signature yet — both are
/// made from the bytes that get written.
struct Admitted {
    body: ShardBody,
    shard_id: u64,
    fields: PassRequestHeader,
}

/// What the gate-and-open hop found. `Miss` is the ordinary, uncounted 404
/// (anchor out of window, unknown id, unfrozen segment). `StoreFault` is
/// the serving store failing to answer — the tip height or the shard — and
/// is one of the faults [`PServeEndpoint::lookup_failure_count`] counts.
/// `KeyNotReady` is the pre-flight refusing, which
/// [`PServeEndpoint::sign_failure_count`] counts. The send path counts the
/// rest directly: a mid-stream read error, a body that is not its frame's
/// length, a signing fault after the body.
enum Lookup {
    Held(ShardBody),
    Miss,
    StoreFault,
    KeyNotReady,
}

/// The gate, the open and the pre-flight, as one blocking-pool hop: all of
/// the work `P` does before its first response byte, none of it
/// proportional to the shard.
///
/// `own_height` may be a bounded store read (the host's choice), and the
/// open is one regardless. The gate runs first, so an out-of-window anchor
/// never touches the shard store. The pre-flight runs last, after the open,
/// so a key that is not ready costs `P` the same lookup as a shard it does
/// not hold: the two 404s are identical on the wire and in what they cost.
///
/// A named function and not a closure, like the other hops below, because
/// the serve path's cost is measured per thread
/// (`benches/serve_response_iai.rs`): Callgrind counts a blocking-pool
/// thread's work only inside a function it was told to watch, and a closure
/// has no stable name to watch.
fn gate_and_open(
    signer: &dyn PassSigner,
    provider: &dyn ShardProvider,
    shard_id: u64,
    anchor_height: BlockHeight,
) -> Lookup {
    let Some(own_height) = signer.own_height() else {
        return Lookup::StoreFault;
    };
    if !anchor_within_gate(own_height, anchor_height) {
        return Lookup::Miss;
    }
    let body = match provider.shard_bytes(shard_id) {
        Ok(Some(body)) => body,
        Ok(None) => return Lookup::Miss,
        Err(_) => return Lookup::StoreFault,
    };
    match signer.ready(shard_id, anchor_height) {
        Ok(()) => Lookup::Held(body),
        Err(_) => Lookup::KeyNotReady,
    }
}

/// The countersignature over one transcript, as canonical envelope bytes.
/// `None` when the signer fails or returns an envelope of another length.
fn sign_transcript(
    signer: &dyn PassSigner,
    message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
) -> Option<[u8; SIGNATURE_ENVELOPE_LEN]> {
    let bytes = signer.sign_pass(message).ok()?.to_canonical_bytes().ok()?;
    bytes.try_into().ok()
}

/// The body being streamed and the digest of what has been written so far.
/// They travel together through each read hop, because the fold happens
/// inside it.
struct Streaming {
    body: ShardBody,
    running: FramedDigest,
}

/// What one read of the body produced.
enum Chunk {
    /// Bytes inside the frame, already folded into the digest: write them.
    Bytes(Vec<u8>),
    /// The body ended. Whether it ended at the frame's declared length is
    /// [`FramedDigest::finish`]'s to say.
    End,
    /// The store failed part-way.
    StoreFault,
    /// The store produced a byte past the frame's declared length. Neither
    /// folded nor written.
    PastFrame,
}

/// One chunk of the body for the send loop, folded into the running digest
/// before it is handed back, so that the hash is done on the blocking pool
/// with the read that produced the bytes rather than on an executor
/// thread. The state travels with the result because the hop owns it
/// meanwhile.
fn read_chunk(mut streaming: Streaming) -> (Streaming, Chunk) {
    let chunk = match streaming.body.next_chunk(WRITE_CHUNK_BYTES) {
        Ok(Some(bytes)) => {
            if streaming.running.absorb(&bytes).is_some() {
                Chunk::Bytes(bytes)
            } else {
                Chunk::PastFrame
            }
        }
        Ok(None) => Chunk::End,
        Err(_) => Chunk::StoreFault,
    };
    (streaming, chunk)
}

/// Complete-head admission: parse, gate, open, pre-flight — or the shared
/// miss. The store reads and the pre-flight run on the blocking pool; join,
/// store and key refusals increment their counter and collapse to the same
/// miss as an unknown id.
///
/// Nothing here reads a body byte. That is the `SF-D8` invariant's first
/// half: before the 200 head, `P` does constant work only.
async fn admit(
    head: &[u8],
    provider: Arc<dyn ShardProvider>,
    signer: &Arc<dyn PassSigner>,
    counters: &Counters,
) -> Option<Admitted> {
    let Request::Shard { shard_id, header } = parse_request(head)?;
    let fields = PassRequestHeader::from_bytes(&header);
    let anchor_height = fields.anchor_height();
    let signer = Arc::clone(signer);
    let looked_up = tokio::task::spawn_blocking(move || {
        gate_and_open(&*signer, &*provider, shard_id, anchor_height)
    })
    .await;
    match looked_up {
        Ok(Lookup::Held(body)) => Some(Admitted {
            body,
            shard_id,
            fields,
        }),
        Ok(Lookup::Miss) => None,
        Ok(Lookup::StoreFault) | Err(_) => {
            counters.lookup_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
        Ok(Lookup::KeyNotReady) => {
            counters.sign_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Write the head and the frame header, stream the body chunk by chunk
/// while folding exactly the bytes written into the delivery digest, then
/// sign that digest and write the countersignature — last, and only if the
/// whole frame went out.
///
/// `content-length` is [`ServedFrameHeader::framed_len`] plus
/// [`SIGNATURE_ENVELOPE_LEN`], both exact before a single leaf is read, so
/// the head is committed before the store is touched for a body byte. A
/// store that fails mid-body can only truncate a response, never change
/// which response was chosen.
///
/// The frame header ([`RF-D4`]) is [`ShardBody::header`], fixed when the
/// body was opened. The bytes written are [`FramedDigest::frame_bytes`]: the
/// header the digest absorbed, not a second encoding of it.
///
/// This is the `SF-D8` invariant's second half: every read, hash and write
/// after the head is paid for by the requester taking the bytes. The loop
/// reads one chunk, folds it, writes it, and does not read the next until
/// the write has returned, so a requester that stops taking bytes stalls
/// `P` within one chunk and one that disconnects stops it at the next
/// write. The signature is withheld from any response it does not describe:
/// a body that fails or runs past its frame, or ends short of it, ends the
/// response before the envelope and counts a lookup failure; a key that
/// fails after the body does the same and counts a late sign failure. The
/// requester reads a truncated transfer in every case.
///
/// [`RF-D4`]: shekyl_curve_tree::served_frame
/// [`ServedFrameHeader::framed_len`]: shekyl_curve_tree::served_frame::ServedFrameHeader::framed_len
async fn write_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    admitted: Option<Admitted>,
    signer: Arc<dyn PassSigner>,
    counters: &Counters,
) -> io::Result<()> {
    let Some(Admitted {
        body,
        shard_id,
        fields,
    }) = admitted
    else {
        return write_bounded(stream, render_not_found().as_bytes()).await;
    };
    // One write for the head and the frame header, not two. The wire bytes
    // are identical either way — this is a loopback socket into tor, whose
    // own cell framing quantizes everything downstream, so packet
    // boundaries here are not an observable and no privacy claim rests on
    // this. What it buys is a single commitment point: the status line,
    // the headers and the frame are decided together, before the store is
    // touched for a body byte, leaving no seam between them for a later
    // edit to slip something into.
    let (running, head) = response_head(&body.header(), fields.nonce())
        .ok_or_else(|| io::Error::other("frame digest"))?;
    write_bounded(stream, &head).await?;
    let mut streaming = Streaming { body, running };
    loop {
        // The store read is synchronous redb, so each chunk crosses to the
        // blocking pool, is folded there, and comes back with the state.
        let (returned, chunk) = tokio::task::spawn_blocking(move || read_chunk(streaming))
            .await
            .map_err(|_| io::Error::other("shard body task"))?;
        streaming = returned;
        match chunk {
            Chunk::Bytes(bytes) => write_bounded(stream, &bytes).await?,
            Chunk::End => break,
            Chunk::StoreFault => {
                // The head is already out; all that is left is to close.
                // The counter is the only place this is visible, which is
                // the same discipline as a failed lookup.
                counters.lookup_failures.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::other("shard body read failed mid-stream"));
            }
            Chunk::PastFrame => {
                counters.lookup_failures.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::other("shard body longer than its frame"));
            }
        }
    }
    let Some(digest) = streaming.running.finish() else {
        counters.lookup_failures.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("shard body shorter than its frame"));
    };
    // The one hybrid sign, after the last body byte: over the digest of
    // exactly what was written, for exactly this request.
    let message = fields.transcript(shard_id, &digest);
    let signed = tokio::task::spawn_blocking(move || sign_transcript(&*signer, &message)).await;
    let Ok(Some(signature)) = signed else {
        counters.late_sign_failures.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("countersignature failed after the body"));
    };
    // The seal: released only now, with every body byte written and folded.
    write_bounded(stream, &signature).await?;
    counters.served.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// The committed head of a 200: status line, headers and the `RF-D4` frame
/// header, as one byte string, with the [`FramedDigest`] that has absorbed
/// that frame. `content-length` is the frame's declared length plus the
/// envelope, both exact before a leaf is read. `None` if the length cannot
/// be stated or the frame cannot be digested.
fn response_head(
    frame: &ServedFrameHeader,
    nonce: &[u8; PASS_NONCE_LEN],
) -> Option<(FramedDigest, Vec<u8>)> {
    let content_length = u64::try_from(SIGNATURE_ENVELOPE_LEN)
        .ok()?
        .checked_add(frame.framed_len())?;
    let running = FramedDigest::start(frame, nonce)?;
    let mut head = render_ok(content_length).into_bytes();
    head.extend_from_slice(running.frame_bytes());
    Some((running, head))
}

/// What one in-memory serve produced. Mirrors the wire: a 200 that carried
/// its envelope, the shared 404, or a 200 cut short of its envelope.
#[cfg(any(test, feature = "bench-internals"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InMemoryServe {
    Served,
    NotFound,
    Truncated,
}

/// One served response, composed from the same steps the endpoint runs,
/// on the calling thread, into `out` instead of a socket.
///
/// For the `BA-T3` drift gate (`benches/serve_response_iai.rs`): Callgrind
/// keeps one collection state per thread, and the endpoint's hops run on
/// tokio's blocking pool, whose idle work made the per-thread counts drift
/// between runs. This runs [`gate_and_open`], [`response_head`],
/// [`read_chunk`] and [`sign_transcript`] in the order [`admit`] and
/// [`write_response`] run them, with the same length check before the
/// sign. It is not a second serve path: the steps are the endpoint's own
/// functions, and `serve_tests.rs` asserts that this composition and the
/// live endpoint produce the same bytes for the same request, so the glue
/// here cannot drift from the glue there without a test saying so.
///
/// Not part of the shipped surface: `bench-internals` and tests only.
#[cfg(any(test, feature = "bench-internals"))]
#[doc(hidden)]
pub fn serve_one_in_memory(
    provider: &dyn ShardProvider,
    signer: &dyn PassSigner,
    head: &[u8],
    out: &mut Vec<u8>,
) -> InMemoryServe {
    let not_found = |out: &mut Vec<u8>| {
        out.extend_from_slice(render_not_found().as_bytes());
        InMemoryServe::NotFound
    };
    let Some(Request::Shard { shard_id, header }) = parse_request(head) else {
        return not_found(out);
    };
    let fields = PassRequestHeader::from_bytes(&header);
    let Lookup::Held(body) = gate_and_open(signer, provider, shard_id, fields.anchor_height())
    else {
        return not_found(out);
    };
    let Some((running, response_head)) = response_head(&body.header(), fields.nonce()) else {
        return not_found(out);
    };
    out.extend_from_slice(&response_head);
    let mut streaming = Streaming { body, running };
    loop {
        let (returned, chunk) = read_chunk(streaming);
        streaming = returned;
        match chunk {
            Chunk::Bytes(bytes) => out.extend_from_slice(&bytes),
            Chunk::End => break,
            Chunk::StoreFault | Chunk::PastFrame => return InMemoryServe::Truncated,
        }
    }
    let Some(digest) = streaming.running.finish() else {
        return InMemoryServe::Truncated;
    };
    let Some(signature) = sign_transcript(signer, &fields.transcript(shard_id, &digest)) else {
        return InMemoryServe::Truncated;
    };
    out.extend_from_slice(&signature);
    InMemoryServe::Served
}

/// One write, bounded by [`WRITE_STALL_TIMEOUT`] — see that constant for
/// why the per-write bound, not the total, is what a stalled peer costs.
async fn write_bounded<W: AsyncWrite + Unpin>(stream: &mut W, bytes: &[u8]) -> io::Result<()> {
    tokio::time::timeout(WRITE_STALL_TIMEOUT, stream.write_all(bytes))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write stalled"))?
}

/// Read until the end of the request head (`\r\n\r\n`), bounded by
/// [`MAX_REQUEST_BYTES`] **as the buffer grows**, so an oversized head is
/// refused before it is fully allocated.
///
/// The terminator scan only examines the newly arrived region (plus a
/// three-byte overlap), so cost stays linear in head size.
async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    // Index up to which `buf` has already been scanned for the terminator,
    // excluding a 3-byte overlap so a split `\r\n\r\n` across reads is found.
    let mut scanned = 0usize;
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "closed mid-head",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
        }
        let start = scanned.saturating_sub(3);
        if buf[start..].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
        scanned = buf.len();
    }
}

/// What a parsed request asks for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// `GET /shard/{shard_id}` carrying one decoded [`REQUEST_HEADER_NAME`].
    Shard {
        shard_id: u64,
        header: [u8; shekyl_curve_tree::serving_route::REQUEST_HEADER_BYTES],
    },
}

/// Parse the request line and the one required header. Anything not an
/// exact `GET` on the one route, or any deviation in the header (missing,
/// duplicate, non-canonical, wrong length), is `None`, which renders the
/// single shared 404.
///
/// Header *names* compare ASCII-case-insensitively and the value's
/// surrounding optional whitespace is trimmed — that is HTTP/1.1's own
/// grammar, not a second encoding. The value itself is the canonical
/// lowercase hex `decode_request_header` accepts, and nothing else.
fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.lines();
    let line = lines.next()?;
    let mut parts = line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    let path = parts.next()?;
    // Require a well-formed request line tail (HTTP version token). Absent
    // or extra shape → miss, same as any other non-route.
    let _version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let shard_id = path.strip_prefix(ROUTE_PREFIX)?;
    // Exact decimal id — no path suffix, no query string.
    let shard_id = shard_id.parse::<u64>().ok()?;

    // Exactly one occurrence of the named header; every other header is
    // ignored (presence, absence, value). The blank line ends the head.
    let mut header = None;
    for field in lines.take_while(|l| !l.is_empty()) {
        let (name, value) = field.split_once(':')?;
        if !name.eq_ignore_ascii_case(REQUEST_HEADER_NAME) {
            continue;
        }
        if header.is_some() {
            return None;
        }
        header = Some(decode_request_header(value.trim_matches([' ', '\t']))?);
    }
    Some(Request::Shard {
        shard_id,
        header: header?,
    })
}

/// Status line plus exactly [`RESPONSE_HEADER_NAMES`]. One function so
/// 200 and 404 cannot grow a second fingerprint.
fn render_head(status: &str, len: u64) -> String {
    format!("HTTP/1.1 {status}\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {len}\r\n\r\n")
}

/// The success head. Exactly [`RESPONSE_HEADER_NAMES`], nothing else — no
/// `date` (a clock-skew fingerprint), no `server`, no `etag`, no
/// `accept-ranges`.
fn render_ok(len: u64) -> String {
    render_head("200 OK", len)
}

/// The single error response, byte-identical for every non-servable
/// complete-head outcome. Built from the same header names/values as
/// success so the declared set stays one source of truth.
fn render_not_found() -> String {
    render_head("404 Not Found", 0)
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
