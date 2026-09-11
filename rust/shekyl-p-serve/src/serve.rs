// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The persona's loopback serve endpoint — production successor of the
//! SP-T3 spike's `serve.rs`, whose inbound-hardening shape (decoupled
//! accept, per-step timeouts, pre-allocation request bound, aggregate-only
//! counters) was validated there and carries forward here. The spike's
//! `x-spike/v0` framing does **not** carry forward; this crate's
//! `x-provisional/v0` is equally THROWAWAY (crate doc), it is simply the
//! throwaway that serves real shards by id.
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
//! # No request logging, at any level
//!
//! Not the path, not the peer, not the timing. The only observables are
//! four aggregate monotone counters with no per-request structure:
//! [`PServeEndpoint::served_count`], [`PServeEndpoint::refused_count`],
//! [`PServeEndpoint::lookup_failure_count`],
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

use crate::provider::{ShardBody, ShardProvider};

/// The one route this endpoint answers. **Provisional and THROWAWAY** —
/// see the crate doc; nothing about this path is a format-round candidate.
pub const ROUTE_PREFIX: &str = "/x-provisional/v0/shard/";

/// Response content type for shard bytes.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Every header name the endpoint ever emits, in emission order — the
/// **complete** set, asserted by `two_personas_are_header_identical`, so
/// adding a header without updating this constant fails the
/// indistinguishability test rather than silently widening the
/// fingerprint.
pub const RESPONSE_HEADER_NAMES: &[&str] = &["content-type", "content-length"];

/// Cap on the request head, applied **while reading** rather than after —
/// the pre-allocation bound. A shard read's request is a request line plus
/// a handful of headers, well under 1 KiB; 8 KiB leaves room for client
/// noise while bounding what a hostile peer can make the endpoint buffer.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Maximum connections served **at once**; arrivals past the cap are
/// closed, never answered.
///
/// A shard read is a ~100-byte request answered with ~3.33 MB — roughly
/// 33 000× egress amplification with the requester paying only its own
/// circuit — and none of the per-connection protections (timeouts, request
/// bound) limits aggregate load; nor does the onion's `MaxStreams`, which
/// is per rendezvous circuit. This cap is that aggregate bound.
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
    accept_errors: Arc<AtomicU64>,
}

impl PServeEndpoint {
    /// Bind an ephemeral **loopback** port and start answering shard reads
    /// from `provider`.
    ///
    /// The bind address is `127.0.0.1:0` — never a routable interface,
    /// never a wildcard. A wildcard bind would make the endpoint reachable
    /// without the rendezvous and attributable to the host's IP, the exact
    /// property the onion exists to remove. Enforced here *and*
    /// independently at the `ADD_ONION` target (`OnionPort::loopback`
    /// refuses non-loopback), because the two are separate opportunities
    /// to get it wrong.
    ///
    /// # Errors
    ///
    /// The bind error, verbatim, if the loopback listener cannot be
    /// created.
    pub async fn bind(provider: Arc<dyn ShardProvider>) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let addr = listener.local_addr()?;
        let served = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));
        let lookup_failures = Arc::new(AtomicU64::new(0));
        let accept_errors = Arc::new(AtomicU64::new(0));
        let served_ctr = Arc::clone(&served);
        let refused_ctr = Arc::clone(&refused);
        let failures_ctr = Arc::clone(&lookup_failures);
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
                let served = Arc::clone(&served_ctr);
                let failures = Arc::clone(&failures_ctr);
                tokio::spawn(async move {
                    // Errors are swallowed by design: a failed connection
                    // must produce no log line and no differing response,
                    // or the failure itself becomes an observable. `.ok()`
                    // rather than `let _ =` so the discard is explicit.
                    handle_connection(stream, provider, &served, &failures)
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

    /// Lookups that failed for infrastructure reasons (store I/O, pruned
    /// bytes), plus bodies that failed part-way through. On the wire the
    /// first render as the same 404 as any miss and the second as a closed
    /// connection; this counter is the only place any of them is
    /// distinguishable, and a nonzero value on a bonded serve-set means
    /// pins are missing — the silent-slash precursor, surfaced.
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.lookup_failures.load(Ordering::Relaxed)
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
///   single shared [`NOT_FOUND`] body. That is the probe surface for the
///   route table, holdings, and store health — collapsed to one shape.
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
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    let body = resolve_body(&head, provider, lookup_failures).await;

    let written = tokio::time::timeout(
        WRITE_TIMEOUT,
        write_response(&mut stream, body, served, lookup_failures),
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

/// Complete-head resolution: shard lookup or shared miss. Store I/O runs
/// on a blocking pool; join / store errors increment `lookup_failures` and
/// collapse to the same miss as an unknown id.
async fn resolve_body(
    head: &[u8],
    provider: Arc<dyn ShardProvider>,
    lookup_failures: &AtomicU64,
) -> Option<ShardBody> {
    match parse_request(head) {
        Some(Request::Shard(shard_id)) => {
            match tokio::task::spawn_blocking(move || provider.shard_bytes(shard_id)).await {
                Ok(Ok(found)) => found,
                Ok(Err(_)) | Err(_) => {
                    lookup_failures.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        }
        None => None,
    }
}

/// Write the head, then the frame header, then stream the body chunk by
/// chunk.
///
/// `content-length` comes from [`ServedFrameHeader::framed_len`], which is
/// exact before a single leaf is read — so the head is committed before the
/// store is touched, and a store that fails mid-body can only truncate a
/// response, never change which response was chosen.
///
/// The frame header ([`RF-D4`]) is taken from [`ShardBody::header`] — fixed
/// when the body was opened — and written ahead of the leaf stream.
///
/// [`RF-D4`]: shekyl_curve_tree::served_frame
async fn write_response(
    stream: &mut TcpStream,
    body: Option<ShardBody>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
) -> io::Result<()> {
    let Some(mut body) = body else {
        return write_bounded(stream, NOT_FOUND.as_bytes()).await;
    };
    // One write, not two. The wire bytes are identical either way — this is
    // a loopback socket into tor, whose own cell framing quantizes
    // everything downstream, so packet boundaries here are not an
    // observable and no privacy claim rests on this. What it buys is a
    // single commitment point: the status line, the headers and the frame
    // are decided together, before the store is touched, leaving no seam
    // between them for a later edit to slip something into.
    let frame = body.header();
    let mut head = render_ok(frame.framed_len()).into_bytes();
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
    /// `GET /x-provisional/v0/shard/{shard_id}`.
    Shard(u64),
}

/// Parse the request line. Anything not an exact `GET` on the one route is
/// `None`, which renders the single shared 404.
fn parse_request(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
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
    shard_id.parse::<u64>().ok().map(Request::Shard)
}

/// The success head. Exactly [`RESPONSE_HEADER_NAMES`], nothing else — no
/// `date` (a clock-skew fingerprint), no `server`, no `etag`, no
/// `accept-ranges`.
fn render_ok(len: u64) -> String {
    format!("HTTP/1.1 200 OK\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {len}\r\n\r\n")
}

/// The single error response, byte-identical for every non-servable
/// complete-head outcome. Built from the same header names/values as
/// success so the declared set stays one source of truth in tests.
const NOT_FOUND: &str =
    "HTTP/1.1 404 Not Found\r\ncontent-type: application/octet-stream\r\ncontent-length: 0\r\n\r\n";

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
