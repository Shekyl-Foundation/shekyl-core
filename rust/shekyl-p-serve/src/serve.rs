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
//! malformed, or wrong-length values are the bare 400, and so is an
//! `anchor_height` outside the persona's gate ([`anchor_within_gate`]).
//! The request is judged before the shard store is consulted, so the 400
//! does not depend on what this persona holds. A valid request for a held
//! shard is answered with the body and then the
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
//! request's nonce. The persona reads the shard once, hashes each chunk
//! as it sends it, and signs the finished digest. So the signature commits
//! to the bytes delivered for this request and to no others. It does not
//! show that this persona stores them; the route's topology is what prices
//! a persona that relays.
//!
//! **Why it is last.** It is computed from the bytes ahead of it. A
//! requester holds the signature only once the whole frame has crossed
//! this persona's link, and a transfer that fails mid-body yields none.
//!
//! # Five answers to a complete head
//!
//! | Response | Meaning |
//! | --- | --- |
//! | `400`, empty | The request is invalid. Decided from the head and the persona's own height; the shard store is not consulted. |
//! | `404`, empty | Not held. Only a valid request reaches this, and nothing else does. |
//! | `503`, empty | The persona cannot serve right now and the fault is its own: an unreadable tip, a store that failed, or no resident key. |
//! | `200`, body, signature | A good read. |
//! | `200`, body, refusal trailer | The signer failed after the body went out. The envelope holds [`REFUSAL_TRAILER_BYTE`] in place of a signature. |
//!
//! A held shard shows a failure and never a 404. Holdings are
//! chain-public, so a 404 for a bonded shard would already tell anyone
//! watching that the persona is failing, and would say it as "not held".
//! The three bare answers are each one fixed byte string, with the same two
//! headers as a 200 and nothing that names which check or which fault.
//!
//! A 200 is always its full declared length. A response that stops short,
//! at any offset, is transport and is retried; only the trailer says the
//! persona refused. A relay can cut a stream at a byte of its choosing and
//! cannot write into it.
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
use shekyl_archival_retention::PassRequestHeader;

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
    decode_request_header, is_refusal_trailer, CONTENT_TYPE, REFUSAL_TRAILER_BYTE,
    REQUEST_HEADER_NAME, RESPONSE_HEADER_NAMES, ROUTE_PREFIX,
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
    served: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
    lookup_failures: Arc<AtomicU64>,
    sign_failures: Arc<AtomicU64>,
    late_sign_failures: Arc<AtomicU64>,
    accept_errors: Arc<AtomicU64>,
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
    /// `SF-D8` countersignature. A signer that refuses the pre-flight (the
    /// key's owner is gone) keeps the endpoint up: a valid request for a
    /// held shard gets the bare 503 before any shard byte, counted in
    /// [`Self::sign_failure_count`].
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
        let served = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));
        let lookup_failures = Arc::new(AtomicU64::new(0));
        let sign_failures = Arc::new(AtomicU64::new(0));
        let late_sign_failures = Arc::new(AtomicU64::new(0));
        let accept_errors = Arc::new(AtomicU64::new(0));
        let served_ctr = Arc::clone(&served);
        let refused_ctr = Arc::clone(&refused);
        let failures_ctr = Arc::clone(&lookup_failures);
        let sign_failures_ctr = Arc::clone(&sign_failures);
        let late_sign_failures_ctr = Arc::clone(&late_sign_failures);
        let accept_errors_ctr = Arc::clone(&accept_errors);
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
                    accept_errors_ctr.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                };
                // Over capacity: drop the stream, which closes it. Not a
                // 503 — a status code would add a response shape and hand
                // a prober a free capacity oracle; a closed connection is
                // indistinguishable from ordinary circuit failure.
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    refused_ctr.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                };
                let provider = Arc::clone(&provider);
                let signer = Arc::clone(&signer);
                let served = Arc::clone(&served_ctr);
                let failures = Arc::clone(&failures_ctr);
                let sign_failures = Arc::clone(&sign_failures_ctr);
                let late_sign_failures = Arc::clone(&late_sign_failures_ctr);
                tokio::spawn(async move {
                    // Errors are swallowed by design: a failed connection
                    // must produce no log line and no differing response,
                    // or the failure itself becomes an observable. `.ok()`
                    // rather than `let _ =` so the discard is explicit.
                    handle_connection(
                        stream,
                        provider,
                        signer,
                        &served,
                        &failures,
                        &sign_failures,
                        &late_sign_failures,
                    )
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
            served,
            refused,
            lookup_failures,
            sign_failures,
            late_sign_failures,
            accept_errors,
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
        self.served.load(Ordering::Relaxed)
    }

    /// Connections refused for exceeding [`MAX_INFLIGHT`] — the operator
    /// signal that the carried placeholder cap is binding and wants its
    /// W₂-rig derivation.
    #[must_use]
    pub fn refused_count(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Store faults while answering a parsed shard read.
    ///
    /// The cases that fail before a byte is written are the 503, shared with
    /// a missing key, and the cases that fail after the head is out are a
    /// connection closed mid-body.
    ///
    /// Counted:
    ///
    /// * the tip the anchor gate needs could not be read, so the gate never
    ///   ran, or the shard could not be opened (I/O, or bytes pruned out
    ///   from under a serve-set that was not pinned) — the 503;
    /// * the body read failed part-way, ran past its frame, or ended short
    ///   of it — a response cut off mid-body.
    ///
    /// An invalid request (the 400) and an ordinary not-held answer (unknown
    /// id, unfrozen segment: the 404) are deliberate and **not** counted.
    /// A key that refuses its pre-flight is [`Self::sign_failure_count`];
    /// a signer that fails after the body is
    /// [`Self::late_sign_failure_count`].
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.lookup_failures.load(Ordering::Relaxed)
    }

    /// Valid requests for a held shard that the key refused at its
    /// pre-flight ([`PassKey::ready`](crate::countersign::PassKey::ready)):
    /// the 503, before any shard byte. This is the bucket a persona with no
    /// resident key accrues, and it costs the persona one shard open per
    /// request. An invalid request and an unheld shard never reach this
    /// counter.
    #[must_use]
    pub fn sign_failure_count(&self) -> u64 {
        self.sign_failures.load(Ordering::Relaxed)
    }

    /// Responses whose whole body went out and whose signer then refused,
    /// or returned an envelope of the wrong length: a 200 whose envelope is
    /// the refusal trailer. Counted apart from [`Self::sign_failure_count`]
    /// because it is a different event at a different price: the pre-flight
    /// said yes, and a whole shard was read, hashed and sent for a response
    /// nobody can use. A persona that sees this move has a key whose
    /// pre-flight says yes to what its signer then refuses.
    #[must_use]
    pub fn late_sign_failure_count(&self) -> u64 {
        self.late_sign_failures.load(Ordering::Relaxed)
    }

    /// `accept` failures. The loop backs off and retries rather than
    /// exiting, so without this a listener that has become permanently
    /// unusable — sustained FD exhaustion, a descriptor that will never
    /// accept again — looks exactly like a quiet epoch: the other
    /// counters simply stop moving. Aggregate and monotone like the rest;
    /// it names no peer and no time.
    #[must_use]
    pub fn accept_error_count(&self) -> u64 {
        self.accept_errors.load(Ordering::Relaxed)
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
/// # Wire classes
///
/// * **Complete head, invalid request** (wrong path or method, malformed
///   id, a request header that is missing, duplicated or does not decode,
///   an anchor outside the gate) → the bare [`render_bad_request`] 400.
///   One response for every such cause: nothing in it names the check that
///   refused. It is decided before the shard store is consulted, so it is
///   the same whether or not the shard is held.
/// * **Complete head, valid request, shard not held** (unknown or unfrozen
///   shard) → the bare [`render_not_found`] 404.
/// * **Complete head, the persona at fault** (the tip could not be read,
///   the store failed to open the shard, or no key is resident) → the bare
///   [`render_unavailable`] 503. One response for all three; which one is
///   the counters' to say, not the wire's.
/// * **No complete head** (oversized buffer, mid-head EOF, read timeout)
///   or **over capacity** → connection close with no HTTP bytes. Same
///   class as ordinary circuit death; not a status-code oracle. Writing a
///   status after a failed head read would invent a response for peers that
///   never finished speaking HTTP, and would not match the capacity path.
///
/// # After the head of a `200`
///
/// Which of 400, 404, 503 and 200 a complete head gets is decided before
/// any byte is written. Two things can still happen to a 200:
///
/// * it ends short, mid-body — a stalled or vanished peer, or a store that
///   changed under a segment whose servability was already established
///   (corruption, or a prune of a segment being served without a pin). The
///   first is indistinguishable from ordinary circuit death; the second is
///   a store fault this crate does not hide from the operator
///   ([`PServeEndpoint::lookup_failure_count`]). Either way the requester
///   reads a stall;
/// * it completes with the refusal trailer where the signature goes — the
///   signer refused after the body
///   ([`PServeEndpoint::late_sign_failure_count`]).
///
/// Named here so a future change that lets an *ordinary* not-held answer
/// truncate — for instance a body that resolves its own servability lazily
/// — is recognised as widening a probe surface rather than as a refactor.
async fn handle_connection(
    mut stream: TcpStream,
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
    sign_failures: &AtomicU64,
    late_sign_failures: &AtomicU64,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    let resolved = resolve(
        &head,
        provider,
        Arc::clone(&signer),
        lookup_failures,
        sign_failures,
    )
    .await;

    let written = tokio::time::timeout(
        WRITE_TIMEOUT,
        write_response(
            &mut stream,
            resolved,
            signer,
            served,
            lookup_failures,
            late_sign_failures,
        ),
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
/// see a reset instead of the bare 400, and a witness that pipelines could
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

/// What a complete request head resolves to, decided before any response
/// byte is written.
enum Resolved {
    /// Not a request this endpoint answers: wrong method or route, a
    /// malformed id, a request header that is missing, duplicated or does
    /// not decode, or an anchor outside the gate. Decided from the head and
    /// the persona's own height, without consulting the shard store. The
    /// bare 400.
    Invalid,
    /// A valid request for a shard this persona does not serve (unknown id,
    /// unfrozen segment). The bare 404, and nothing else is.
    NotHeld,
    /// The persona cannot answer right now and the fault is its own: the
    /// tip the gate needs could not be read, the store failed to open the
    /// shard, or no key is resident to countersign with. The bare 503.
    Unavailable,
    /// A valid request for a held shard, with a signer that says it can
    /// sign: stream it, then countersign.
    Held(Held),
}

/// A held shard and what its countersignature will bind.
struct Held {
    body: ShardBody,
    shard_id: u64,
    fields: PassRequestHeader,
}

/// What the gate-and-lookup hop found, before it is counted.
enum Lookup {
    OutOfGate,
    NotHeld,
    /// The tip or the store could not be read.
    StoreFault,
    /// The shard is held and the signer says it cannot sign.
    NoKey,
    Held(ShardBody),
}

/// Complete-head resolution: parse, gate, look up, ask the signer whether
/// it can sign. The last three run on one blocking-pool hop — `own_height`
/// may be a bounded store read (the host's choice) and opening the shard is
/// one regardless.
///
/// The request is judged first and on its own: an invalid head or an
/// out-of-window anchor is [`Resolved::Invalid`] whether or not the shard
/// is held, and never reaches the shard store. Only a valid request for a
/// shard that is not served is [`Resolved::NotHeld`]. A fault of this
/// persona's own is [`Resolved::Unavailable`], and is never dressed as
/// "not held": holdings are chain-public, so a 404 for a bonded shard
/// would tell a requester the same thing and say it falsely.
///
/// Nothing is signed here. The signature covers the bytes that are sent,
/// so it is made after them ([`write_response`]). What *is* settled here is
/// whether the key will sign at all ([`PassKey::ready`]), because that
/// is known before the first byte and a shard that cannot be countersigned
/// is not worth sending.
///
/// [`PassKey::ready`]: crate::countersign::PassKey::ready
async fn resolve(
    head: &[u8],
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    lookup_failures: &AtomicU64,
    sign_failures: &AtomicU64,
) -> Resolved {
    let Some(Request::Shard { shard_id, header }) = parse_request(head) else {
        return Resolved::Invalid;
    };
    let fields = PassRequestHeader::from_bytes(&header);
    let anchor_height = fields.anchor_height();
    let looked_up = tokio::task::spawn_blocking(move || {
        let Some(own_height) = signer.own_height() else {
            return Lookup::StoreFault;
        };
        if !anchor_within_gate(own_height, anchor_height) {
            return Lookup::OutOfGate;
        }
        match provider.shard_bytes(shard_id) {
            Err(_) => Lookup::StoreFault,
            Ok(None) => Lookup::NotHeld,
            Ok(Some(body)) => match signer.ready(shard_id, anchor_height) {
                Ok(()) => Lookup::Held(body),
                Err(_) => Lookup::NoKey,
            },
        }
    })
    .await;
    match looked_up {
        Ok(Lookup::OutOfGate) => Resolved::Invalid,
        Ok(Lookup::NotHeld) => Resolved::NotHeld,
        Ok(Lookup::Held(body)) => Resolved::Held(Held {
            body,
            shard_id,
            fields,
        }),
        Ok(Lookup::NoKey) => {
            sign_failures.fetch_add(1, Ordering::Relaxed);
            Resolved::Unavailable
        }
        Ok(Lookup::StoreFault) | Err(_) => {
            lookup_failures.fetch_add(1, Ordering::Relaxed);
            Resolved::Unavailable
        }
    }
}

/// Write the response a head resolved to.
///
/// For a held shard: the head and the frame header, the body chunk by
/// chunk as it is read, then the countersignature over what was written.
/// The store is read once. Each chunk is folded into the delivery digest
/// ([`FramedDigest`]) as it goes out, so the digest that is signed is the
/// digest of the bytes on the wire by construction, and no more than one
/// chunk of the shard is resident.
///
/// `content-length` is [`ServedFrameHeader::framed_len`] plus
/// [`SIGNATURE_ENVELOPE_LEN`], both exact before a single leaf is read, so
/// the head is committed before the store is touched. Two things can go
/// wrong after it:
///
/// * the store fails mid-body, or yields a body that is not the length its
///   frame declares — the response ends there, short, counted in
///   [`PServeEndpoint::lookup_failure_count`];
/// * the body completes and the signer refuses, or returns an envelope of
///   the wrong length — the envelope is written as the **refusal trailer**
///   ([`REFUSAL_TRAILER_BYTE`] at the envelope's width), so the response
///   is its full declared length and says in the persona's own bytes that
///   it served and did not sign. Counted in
///   [`PServeEndpoint::late_sign_failure_count`].
///
/// The trailer is why a failure is never inferred from a response that
/// stopped. A relay on the circuit can cut a response at any byte it likes,
/// the frame's end included, and guard pinning puts the same relay on every
/// retry; it cannot write bytes into the stream. So a short response is
/// always transport, and only the persona can say it refused.
///
/// The frame header ([`RF-D4`]) is [`ShardBody::header`], fixed when the
/// body was opened. The bytes written are [`FramedDigest::frame_bytes`]: the
/// header that was hashed, not a second encoding of it.
///
/// Generic over the writer so the invariant tests can stand a sink in for
/// the socket and say exactly how many bytes a requester took before it
/// stopped (`serve_invariant_tests.rs`).
///
/// [`RF-D4`]: shekyl_curve_tree::served_frame
/// [`ServedFrameHeader::framed_len`]: shekyl_curve_tree::served_frame::ServedFrameHeader::framed_len
async fn write_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    resolved: Resolved,
    signer: Arc<dyn PassSigner>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
    late_sign_failures: &AtomicU64,
) -> io::Result<()> {
    let Held {
        mut body,
        shard_id,
        fields,
    } = match resolved {
        Resolved::Invalid => return write_bounded(stream, render_bad_request().as_bytes()).await,
        Resolved::NotHeld => return write_bounded(stream, render_not_found().as_bytes()).await,
        Resolved::Unavailable => {
            return write_bounded(stream, render_unavailable().as_bytes()).await
        }
        Resolved::Held(held) => held,
    };
    // One write for the head and the frame header, not two. The wire bytes
    // are identical either way — this is a loopback socket into tor, whose
    // own cell framing quantizes everything downstream, so packet
    // boundaries here are not an observable and no privacy claim rests on
    // this. What it buys is a single commitment point: the status line,
    // the headers and the frame are decided together, before the store is
    // read, leaving no seam between them for a later edit to slip
    // something into.
    let frame = body.header();
    let content_length = u64::try_from(SIGNATURE_ENVELOPE_LEN)
        .ok()
        .and_then(|sig| sig.checked_add(frame.framed_len()))
        .ok_or_else(|| io::Error::other("content-length overflow"))?;
    let mut running = FramedDigest::start(&frame, fields.nonce())
        .ok_or_else(|| io::Error::other("frame digest"))?;
    let mut head = render_ok(content_length).into_bytes();
    head.extend_from_slice(running.frame_bytes());
    write_bounded(stream, &head).await?;
    loop {
        // The store read is synchronous redb, so each chunk crosses to the
        // blocking pool and the body comes back with it.
        let (returned, chunk) = tokio::task::spawn_blocking(move || {
            let chunk = body.next_chunk(WRITE_CHUNK_BYTES);
            (body, chunk)
        })
        .await
        .map_err(|_| io::Error::other("shard body task"))?;
        body = returned;
        match chunk {
            Ok(Some(bytes)) => {
                // Past the frame: do not write a byte the frame does not
                // describe, and sign nothing.
                if running.absorb(&bytes).is_none() {
                    lookup_failures.fetch_add(1, Ordering::Relaxed);
                    return Err(io::Error::other("shard body longer than its frame"));
                }
                write_bounded(stream, &bytes).await?;
            }
            Ok(None) => break,
            Err(_) => {
                // The head is already out; all that is left is to close.
                // The counter is the only place this is visible.
                lookup_failures.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::other("shard body read failed mid-stream"));
            }
        }
    }
    let Some(digest) = running.finish() else {
        lookup_failures.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::other("shard body shorter than its frame"));
    };
    // Every body byte is written and hashed. Sign for exactly those bytes.
    let message = fields.transcript(shard_id, &digest);
    let signed = tokio::task::spawn_blocking(move || {
        signer
            .sign_pass(&message)
            .ok()
            .and_then(|sig| sig.to_canonical_bytes().ok())
    })
    .await;
    // The length is the type, so a short or long envelope cannot reach the
    // wire.
    let signature: [u8; SIGNATURE_ENVELOPE_LEN] = match signed
        .ok()
        .flatten()
        .map(<[u8; SIGNATURE_ENVELOPE_LEN]>::try_from)
    {
        Some(Ok(signature)) => signature,
        _ => {
            // The body is out and cannot be taken back. Say so, in bytes
            // only this end can write.
            late_sign_failures.fetch_add(1, Ordering::Relaxed);
            write_bounded(stream, &[REFUSAL_TRAILER_BYTE; SIGNATURE_ENVELOPE_LEN]).await?;
            return Ok(());
        }
    };
    write_bounded(stream, &signature).await?;
    served.fetch_add(1, Ordering::Relaxed);
    Ok(())
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
/// bare 400.
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
/// 200 and the bare answers cannot grow a second fingerprint.
fn render_head(status: &str, len: u64) -> String {
    format!("HTTP/1.1 {status}\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {len}\r\n\r\n")
}

/// The success head. Exactly [`RESPONSE_HEADER_NAMES`], nothing else — no
/// `date` (a clock-skew fingerprint), no `server`, no `etag`, no
/// `accept-ranges`.
fn render_ok(len: u64) -> String {
    render_head("200 OK", len)
}

/// The answer to a valid request for a shard this persona does not hold,
/// byte-identical every time. Built from the same header names/values as
/// success so the declared set stays one source of truth.
fn render_not_found() -> String {
    render_head("404 Not Found", 0)
}

/// The answer when this persona cannot serve and the fault is its own,
/// byte-identical whichever fault: same two headers, empty body.
fn render_unavailable() -> String {
    render_head("503 Service Unavailable", 0)
}

/// The answer to a request that is not valid, byte-identical whichever
/// check refused it: same two headers, empty body, nothing that names the
/// check.
fn render_bad_request() -> String {
    render_head("400 Bad Request", 0)
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
