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
//! persona's `HybridSignature` over `header ‖ shard_id_le[8]` — the
//! canonical [`SIGNATURE_ENVELOPE_LEN`] bytes — written ahead of the
//! `RF-D4` frame, both inside one `content-length`. The signer is the
//! host's ([`PassSigner`]); this crate holds no key.
//!
//! # No request logging, at any level
//!
//! Not the path, not the peer, not the timing. The only observables are
//! five aggregate monotone counters with no per-request structure:
//! [`PServeEndpoint::served_count`], [`PServeEndpoint::refused_count`],
//! [`PServeEndpoint::lookup_failure_count`],
//! [`PServeEndpoint::sign_failure_count`],
//! [`PServeEndpoint::accept_error_count`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::countersign::{anchor_within_gate, PassSigner, SIGNATURE_ENVELOPE_LEN};
use crate::provider::{ShardBody, ShardProvider};
use shekyl_archival_retention::PassRequestHeader;

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
/// across writes, and the wire bytes are identical to a single write.
///
/// The loop is chunked for two reasons: peak memory per in-flight
/// connection is one chunk rather than a whole shard, and resumability —
/// which `RF-D4` did **not** rule in, so the frame carries no resumption
/// field and adding one is still a future format change — becomes a change
/// of framing on top of an already-incremental reader-writer instead of a
/// rewrite. That is the §9.5 discipline that a format property must never
/// be foreclosed by what was convenient to build, and it held: the format
/// round came and went without this loop constraining it.
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
        let served = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));
        let lookup_failures = Arc::new(AtomicU64::new(0));
        let sign_failures = Arc::new(AtomicU64::new(0));
        let accept_errors = Arc::new(AtomicU64::new(0));
        let served_ctr = Arc::clone(&served);
        let refused_ctr = Arc::clone(&refused);
        let failures_ctr = Arc::clone(&lookup_failures);
        let sign_failures_ctr = Arc::clone(&sign_failures);
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
                tokio::spawn(async move {
                    // Errors are swallowed by design: a failed connection
                    // must produce no log line and no differing response,
                    // or the failure itself becomes an observable. `.ok()`
                    // rather than `let _ =` so the discard is explicit.
                    handle_connection(stream, provider, signer, &served, &failures, &sign_failures)
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

    /// Lookups that failed for infrastructure reasons — the store could not
    /// report its tip height for the gate, or could not read the shard
    /// (I/O, pruned bytes) — plus bodies that failed part-way through. On
    /// the wire the first render as the same 404 as any miss and the last
    /// as a closed connection; this counter is the only place any of them
    /// is distinguishable, and a nonzero value on a bonded serve-set means
    /// pins are missing — the silent-slash precursor, surfaced. An ordinary
    /// miss (unknown id, unfrozen segment, anchor out of window) is the
    /// deliberate 404 and is **not** counted here.
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.lookup_failures.load(Ordering::Relaxed)
    }

    /// Servable requests the host's [`PassSigner`] refused to sign. On the
    /// wire the identical 404; here, distinguishable from a store fault so
    /// an operator can tell "key not resident" from "store not readable". A
    /// nonzero value on a bonded persona means passes are being lost to a
    /// signer that is down, not to a store that is short.
    #[must_use]
    pub fn sign_failure_count(&self) -> u64 {
        self.sign_failures.load(Ordering::Relaxed)
    }

    /// `accept` failures. The loop backs off and retries rather than
    /// exiting, so without this a listener that has become permanently
    /// unusable — sustained FD exhaustion, a descriptor that will never
    /// accept again — looks exactly like a quiet epoch: the other three
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
/// # Wire classes (intentionally two, not one)
///
/// * **Complete request head that is non-servable** (wrong path/method,
///   malformed route/id, unknown or unfrozen shard, store failure) → the
///   single shared [`render_not_found`] body. A second status (405 vs 404 vs 400)
///   fingerprints the implementation; a distinct store-failure response is
///   a live health oracle. Holdings are chain-public — GET 200 vs 404 is
///   already the availability oracle — and are not what this collapse hides.
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
/// response. A body can still be cut short after the head — a stalled or
/// vanished peer, or a store that changed under a segment whose servability
/// was already established (corruption, or a prune of a segment being served
/// without a pin). The first is indistinguishable from ordinary circuit
/// death; the second is a store fault this crate cannot answer and does not
/// hide from the operator ([`PServeEndpoint::lookup_failure_count`]). It is
/// named here so a future change that lets *ordinary* misses truncate — for
/// instance a body that resolves its own servability lazily — is recognised
/// as widening a probe surface rather than as a refactor.
async fn handle_connection(
    mut stream: TcpStream,
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
    sign_failures: &AtomicU64,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    let resolved = resolve_body(&head, provider, signer, lookup_failures, sign_failures).await;

    let written = tokio::time::timeout(
        WRITE_TIMEOUT,
        write_response(&mut stream, resolved, served, lookup_failures),
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

/// A servable request, resolved: the countersignature's canonical bytes
/// and the body it covers.
struct Resolved {
    signature: Vec<u8>,
    body: ShardBody,
}

/// What the gate-and-lookup hop found. `Miss` is the ordinary, uncounted
/// 404 (anchor out of window, unknown id, unfrozen segment); `StoreFault`
/// is the serving store failing to answer — the tip height or the shard
/// bytes — and is what [`PServeEndpoint::lookup_failure_count`] counts.
enum Lookup {
    Held(ShardBody),
    Miss,
    StoreFault,
}

/// Complete-head resolution: parse, gate, look up, sign — or the shared
/// miss. Store I/O and the hybrid sign run on the blocking pool; join,
/// store, and signer errors increment their counter and collapse to the
/// same miss as an unknown id.
///
/// The order is deliberate. The gate runs before the store is touched so
/// an out-of-window anchor costs no I/O; the sign runs after the lookup so
/// the persona never signs for a shard it does not hold. The transcript
/// covers `shard_id`, so a signature is bound to the body it precedes.
async fn resolve_body(
    head: &[u8],
    provider: Arc<dyn ShardProvider>,
    signer: Arc<dyn PassSigner>,
    lookup_failures: &AtomicU64,
    sign_failures: &AtomicU64,
) -> Option<Resolved> {
    let Request::Shard { shard_id, header } = parse_request(head)?;
    let fields = PassRequestHeader::from_bytes(&header);
    // Gate, then look up, on one blocking-pool hop: `own_height` may be a
    // bounded store read (the host's choice), and the shard read is one
    // regardless. The gate still runs first, so an out-of-window anchor
    // never touches the shard store.
    let gate_signer = Arc::clone(&signer);
    let looked_up = tokio::task::spawn_blocking(move || {
        let Some(own_height) = gate_signer.own_height() else {
            return Lookup::StoreFault;
        };
        if !anchor_within_gate(own_height, fields.anchor_height()) {
            return Lookup::Miss;
        }
        match provider.shard_bytes(shard_id) {
            Ok(Some(body)) => Lookup::Held(body),
            Ok(None) => Lookup::Miss,
            Err(_) => Lookup::StoreFault,
        }
    })
    .await;
    let body = match looked_up {
        Ok(Lookup::Held(body)) => body,
        Ok(Lookup::Miss) => return None,
        Ok(Lookup::StoreFault) | Err(_) => {
            lookup_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    let message = fields.transcript(shard_id);
    let signed = tokio::task::spawn_blocking(move || {
        signer
            .sign_pass(&message)
            .ok()
            .and_then(|sig| sig.to_canonical_bytes().ok())
    })
    .await;
    match signed {
        Ok(Some(signature)) if signature.len() == SIGNATURE_ENVELOPE_LEN => {
            Some(Resolved { signature, body })
        }
        _ => {
            sign_failures.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Write the head, then the countersignature envelope, then the frame
/// header, then stream the body chunk by chunk.
///
/// `content-length` is [`SIGNATURE_ENVELOPE_LEN`] plus
/// [`ServedFrameHeader::framed_len`], both exact before a single leaf is
/// read — so the head is committed before the store is touched, and a
/// store that fails mid-body can only truncate a response, never change
/// which response was chosen.
///
/// The frame header ([`RF-D4`]) is taken from [`ShardBody::header`] — fixed
/// when the body was opened — and written after the signature, ahead of
/// the leaf stream.
///
/// [`RF-D4`]: shekyl_curve_tree::served_frame
/// [`ServedFrameHeader::framed_len`]: shekyl_curve_tree::served_frame::ServedFrameHeader::framed_len
async fn write_response(
    stream: &mut TcpStream,
    resolved: Option<Resolved>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
) -> io::Result<()> {
    let Some(Resolved {
        signature,
        mut body,
    }) = resolved
    else {
        return write_bounded(stream, render_not_found().as_bytes()).await;
    };
    // One write, not three. The wire bytes are identical either way — this
    // is a loopback socket into tor, whose own cell framing quantizes
    // everything downstream, so packet boundaries here are not an
    // observable and no privacy claim rests on this. What it buys is a
    // single commitment point: the status line, the headers, the
    // signature and the frame are decided together, before the store is
    // touched, leaving no seam between them for a later edit to slip
    // something into.
    let frame = body.header();
    let content_length = u64::try_from(SIGNATURE_ENVELOPE_LEN)
        .ok()
        .and_then(|sig| sig.checked_add(frame.framed_len()))
        .ok_or_else(|| io::Error::other("content-length overflow"))?;
    let mut head = render_ok(content_length).into_bytes();
    head.extend_from_slice(&signature);
    head.extend_from_slice(&frame.to_bytes());
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
            Ok(Some(bytes)) => write_bounded(stream, &bytes).await?,
            Ok(None) => break,
            Err(_) => {
                // The head is already out; all that is left is to close.
                // The counter is the only place this is visible, which is
                // the same discipline as a failed lookup.
                lookup_failures.fetch_add(1, Ordering::Relaxed);
                return Err(io::Error::other("shard body read failed mid-stream"));
            }
        }
    }
    served.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// One write, bounded by [`WRITE_STALL_TIMEOUT`] — see that constant for
/// why the per-write bound, not the total, is what a stalled peer costs.
async fn write_bounded(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
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
