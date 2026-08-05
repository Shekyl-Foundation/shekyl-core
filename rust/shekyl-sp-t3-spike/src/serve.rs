// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! D3 — the persona's inbound serve endpoint. **Loopback only, one route, no logs.**
//!
//! # `x-spike/v0` — this is not TJ-B's format and is named so it cannot be mistaken for it
//!
//! The route is `GET /x-spike/v0/shard/{index}`. §9.4 records that making the
//! test the read path promotes **response semantics** to consensus-critical, so
//! whatever TJ-B settles on freezes at genesis. This crate must not contribute a
//! candidate. The `x-` prefix (unregistered), the `spike` segment, and the `v0`
//! are three independent signals that this is a measurement placeholder; a
//! reviewer who finds this path in a design doc should treat its appearance there
//! as a bug.
//!
//! What this endpoint is *for* is transport: it must move 3.33 MB over a
//! rendezvous circuit and be timed from the client side. Nothing about the
//! framing is a proposal.
//!
//! # Why it is hand-rolled rather than an HTTP framework
//!
//! Hard invariant 7 requires two personas served from one wallet to be
//! **byte-indistinguishable at the header level**. Every mainstream framework
//! emits at least a `date` header, most emit `server`, and several add `etag` or
//! range support opportunistically. Those defaults are exactly the thing under
//! test, and they are not reliably removable. So the response is written by hand:
//! a fixed status line, a fixed `content-type`, a computed `content-length`, and
//! nothing else — [`RESPONSE_HEADER_NAMES`] is the complete set, asserted by
//! `two_personas_are_header_identical`.
//!
//! **`Date` is omitted entirely.** It is not merely "low variance": a per-response
//! clock reading is a fingerprint (clock skew is a host identifier) and a
//! liveness timestamp, and HTTP does not require it of a server without a clock.
//!
//! # The inbound threat model (`ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §6a)
//!
//! That section pinned three requirements for SP-T3's build, from the observation
//! that an onion service is a *different actor shape* from everything SP-T0/T1/T2
//! built: those are outbound or trusted-loopback, this **accepts connections from
//! untrusted peers over high-latency circuits**. All three are implemented here:
//!
//! - **Decoupled accept loop.** The listener owns a `tokio::spawn`ed task and each
//!   connection is handled on its own spawned task, so one stalled rendezvous
//!   circuit cannot head-of-line-block the service. (This is why the SP-T0a
//!   single-mailbox actor pattern is explicitly *not* inherited.)
//! - **Per-connection timeouts.** Every read step and the whole write are
//!   [`tokio::time::timeout`]-bounded, so a peer that opens a circuit and stops
//!   talking is dropped rather than holding a file descriptor.
//! - **Payload bound.** The request head is capped at [`MAX_REQUEST_BYTES`]
//!   *before* allocation grows, the inbound mirror of the control framer's
//!   `MAX_REPLY_BYTES`.
//!
//! # No request logging, at any level
//!
//! Not the path, not the peer, not the timing, not a counter that could be
//! differenced. The measurement times from the **client** side — which is where a
//! drawn miner would time it anyway, so the server-side log would be redundant as
//! well as dangerous. The only server-side observable this crate exposes is
//! [`ServeEndpoint::request_count`], an aggregate with no per-request structure,
//! used by the harness to assert the apparatus actually served what it thinks it
//! served.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// The one route this endpoint answers. Deliberately un-shippable; see the module
/// doc.
pub const ROUTE_PREFIX: &str = "/x-spike/v0/shard/";

/// Response content type for shard bytes.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Every header name the endpoint ever emits, in emission order.
///
/// The **complete** set — this is the list `two_personas_are_header_identical`
/// asserts against, so adding a header without updating this constant fails the
/// indistinguishability test rather than silently widening the fingerprint.
pub const RESPONSE_HEADER_NAMES: &[&str] = &["content-type", "content-length"];

/// Cap on the request head, applied while reading rather than after.
///
/// A shard read's request is a request line plus a handful of headers — well
/// under 1 KiB. 8 KiB leaves room for a client's `user-agent`/`accept` noise
/// while bounding what a hostile peer can make the endpoint buffer.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Maximum connections served **at once**; further arrivals are refused.
///
/// # The gap this closes
///
/// `ARCHIVAL_BOND_2D2_TRANSPORT_PLAN.md` §6a pins three inbound protections —
/// decoupled accept, per-connection timeouts, and a pre-allocation payload bound
/// — and every one of them is **per connection**. A timeout bounds how long *one*
/// connection lives; the payload cap bounds *one* request's memory; and
/// spawn-per-connection *creates* unbounded concurrency rather than limiting it.
/// **Nothing in §6a bounds aggregate load.**
///
/// Nor does the onion's own stream cap: `MaxStreams`/`MaxStreamsCloseCircuit` is
/// **per rendezvous circuit**, so `N` distinct clients get `N` circuits with one
/// stream each and never approach it. It stops one client hogging; it does
/// nothing about `N` clients.
///
/// That matters because a shard read is a ~100-byte request answered with
/// ~3.33 MB — roughly **33 000× egress amplification**, with the requester paying
/// only its own circuit. A bonded persona's client population is bounded by the
/// challenge draw; a publicly advertised uncompensated one is bounded by nothing.
///
/// **`SPIKE-PIN-2`: the value is a placeholder, not a derivation.** The binding
/// resource is *egress*, not memory (the payload is one shared `Arc`, so
/// concurrency costs file descriptors and tasks, not `N × 3.33 MB`). Deriving it
/// needs SPIKE-F-11's one-persona/many-readers measurement on the hardware that
/// will actually serve.
pub const MAX_INFLIGHT: usize = 64;

/// Bound on reading the request head from an accepted connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on writing the response.
///
/// Generous because the payload is 3.33 MB over a rendezvous circuit, which is
/// the slow path being measured — this is the "peer stopped reading" backstop,
/// not a latency budget.
const WRITE_TIMEOUT: Duration = Duration::from_secs(600);

/// A running loopback serve endpoint for one persona.
///
/// Dropping it aborts the accept loop; in-flight connection tasks are detached
/// and end at their own timeouts.
pub struct ServeEndpoint {
    addr: SocketAddr,
    accept_task: JoinHandle<()>,
    requests: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
}

impl ServeEndpoint {
    /// Bind an ephemeral **loopback** port and start serving `payload`.
    ///
    /// The bind address is `127.0.0.1:0` — never a routable interface, and never
    /// a wildcard. A wildcard bind would make the endpoint reachable without the
    /// rendezvous and attributable to the host's IP, which is the whole property
    /// the onion is providing. This is enforced here *and* independently at the
    /// `ADD_ONION` target ([`shekyl_tor::control::onion::OnionPort::loopback`]),
    /// because the two are separate opportunities to get it wrong.
    ///
    /// `payload` is an [`Arc`] so every connection serves the same in-memory
    /// bytes: the fixture is pre-loaded, so no disk read sits in the timed path
    /// (see [`crate::fixture`]).
    pub async fn bind(payload: Arc<Vec<u8>>) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&requests);
        let refused = Arc::new(AtomicU64::new(0));
        let refused_ctr = Arc::clone(&refused);
        // Bounds concurrency without queueing: an arrival past the cap is closed
        // immediately rather than parked, so the refusal costs one accept and
        // frees the descriptor at once.
        let permits = Arc::new(Semaphore::new(MAX_INFLIGHT));
        // Decoupled accept loop (§6a): its own task, and one spawned task per
        // connection, so a stalled peer blocks only itself.
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    // The peer address is deliberately dropped rather than bound:
                    // it is a forensic surface and there is nothing here that may
                    // record it.
                    continue;
                };
                // Over capacity: drop the stream, which closes it. Deliberately
                // **not** a `503` — inventing a status code would add a response
                // shape to the `x-spike/v0` surface (which §9.4 warns must never be
                // mistaken for TJ-B's) and would hand a prober a free capacity
                // oracle. A closed connection is indistinguishable from ordinary
                // circuit failure, which over Tor is exactly what a client already
                // has to handle.
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    refused_ctr.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                };
                let payload = Arc::clone(&payload);
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    // Errors are swallowed by design: a failed connection must
                    // produce no log line and no differing response, or the
                    // failure itself becomes an observable. `.ok()` rather than
                    // `let _ =` so the discard is explicit at the call site.
                    handle_connection(stream, &payload, &counter).await.ok();
                    // Held for the whole connection; released here so the slot
                    // reopens only once the shard has actually finished sending.
                    drop(permit);
                });
            }
        });
        Ok(Self {
            addr,
            accept_task,
            requests,
            refused,
        })
    }

    /// The bound loopback address, for `ADD_ONION`'s `Port=` target.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connections refused for exceeding [`MAX_INFLIGHT`] — an **aggregate**, no
    /// per-request structure.
    ///
    /// The operator-visible signal that the cap is binding, without a log: a
    /// rising count means the endpoint is shedding load and `SPIKE-PIN-2` wants
    /// re-deriving for this host.
    #[must_use]
    pub fn refused_count(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Total requests answered — an **aggregate**, with no per-request structure.
    ///
    /// Exists so the harness can assert the apparatus served what it believes it
    /// served (a fetch that silently came from somewhere else would otherwise
    /// look like a fast success). It is a monotone counter, not a log: it carries
    /// no path, no peer, and no timing.
    #[must_use]
    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for ServeEndpoint {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

impl std::fmt::Debug for ServeEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The bound port is not sensitive on its own, but it is the mapping
        // target of a persona's onion; rendering only the shape keeps the type
        // safe in any `{:?}` context.
        f.debug_struct("ServeEndpoint").finish_non_exhaustive()
    }
}

/// Read one request head, answer it, close.
///
/// No keep-alive: each fetch is its own connection, which keeps the measurement's
/// unit unambiguous (a request is a connection) and removes connection-reuse as a
/// cross-persona correlation surface.
async fn handle_connection(
    mut stream: TcpStream,
    payload: &[u8],
    counter: &AtomicU64,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    let response = match parse_request(&head) {
        Some(Request::Shard(_index)) => {
            counter.fetch_add(1, Ordering::Relaxed);
            render_ok(payload.len())
        }
        // One route: everything else is the same minimal 404. Identical bytes for
        // "wrong path", "wrong method" and "malformed" so the error response
        // cannot be used to probe what the endpoint supports.
        _ => render_not_found(),
    };

    tokio::time::timeout(WRITE_TIMEOUT, async {
        stream.write_all(response.as_bytes()).await?;
        if matches!(parse_request(&head), Some(Request::Shard(_))) {
            stream.write_all(payload).await?;
        }
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write"))??;
    Ok(())
}

/// Read until the end of the request head (`\r\n\r\n`), bounded by
/// [`MAX_REQUEST_BYTES`].
///
/// The bound is checked **as the buffer grows**, so an oversized head is refused
/// before it is fully allocated rather than after (§6a's payload bound).
async fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
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
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(buf);
        }
    }
}

/// What a parsed request asks for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    /// `GET /x-spike/v0/shard/{index}`.
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
    let index = path.strip_prefix(ROUTE_PREFIX)?;
    index.parse::<u64>().ok().map(Request::Shard)
}

/// The success head. Exactly [`RESPONSE_HEADER_NAMES`], nothing else.
fn render_ok(len: usize) -> String {
    format!("HTTP/1.1 200 OK\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {len}\r\n\r\n")
}

/// The single error response, identical for every non-matching request.
fn render_not_found() -> String {
    "HTTP/1.1 404 Not Found\r\ncontent-type: application/octet-stream\r\ncontent-length: 0\r\n\r\n"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read a whole response (head + body) from a fresh connection to `addr`.
    async fn fetch(addr: SocketAddr, path: &str) -> Vec<u8> {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
            .await
            .expect("write request");
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read response");
        out
    }

    fn head_of(response: &[u8]) -> String {
        let end = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("response has a head");
        String::from_utf8_lossy(&response[..end]).to_string()
    }

    #[tokio::test]
    async fn binds_loopback_only() {
        // Hard invariant 4. A wildcard or routable bind would make the endpoint
        // reachable without the rendezvous and attributable to the host's IP.
        let ep = ServeEndpoint::bind(Arc::new(vec![0u8; 16]))
            .await
            .expect("bind");
        assert!(ep.addr().ip().is_loopback());
        assert_ne!(ep.addr().port(), 0, "an ephemeral port was actually bound");
    }

    #[tokio::test]
    async fn serves_the_payload_on_the_spike_route() {
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let ep = ServeEndpoint::bind(Arc::new(payload.clone()))
            .await
            .expect("bind");
        let response = fetch(ep.addr(), "/x-spike/v0/shard/0").await;
        let head = head_of(&response);
        assert!(head.starts_with("HTTP/1.1 200 OK"));
        assert!(head.contains(&format!("content-length: {}", payload.len())));
        let body = &response[response.len() - payload.len()..];
        assert_eq!(body, &payload[..], "the served bytes are the fixture bytes");
        assert_eq!(ep.request_count(), 1);
    }

    #[tokio::test]
    async fn two_personas_are_header_identical() {
        // Hard invariant 7, as the charter's own test: run both personas, diff the
        // response headers, assert equality.
        //
        // The payloads differ (as two personas' shards would) so the assertion is
        // not vacuously true by serving identical bytes — content-length is
        // deliberately equal-length here because a *length* difference is a
        // payload property, not a header-set property, and conflating them would
        // make this test unable to fail for the reason it exists.
        let a = ServeEndpoint::bind(Arc::new(vec![0xAAu8; 2048]))
            .await
            .expect("bind a");
        let b = ServeEndpoint::bind(Arc::new(vec![0xBBu8; 2048]))
            .await
            .expect("bind b");
        let ha = head_of(&fetch(a.addr(), "/x-spike/v0/shard/0").await);
        let hb = head_of(&fetch(b.addr(), "/x-spike/v0/shard/1").await);
        assert_eq!(ha, hb, "two personas must be header-identical");

        // And the header set is exactly the declared one — no `server`, no `date`,
        // no `etag`, no `accept-ranges`. Checked by name so a future addition
        // fails here instead of quietly widening the fingerprint.
        let names: Vec<String> = ha
            .lines()
            .skip(1)
            .filter(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap_or_default().to_ascii_lowercase())
            .collect();
        assert_eq!(names, RESPONSE_HEADER_NAMES);
        for banned in ["server", "date", "etag", "accept-ranges", "connection"] {
            assert!(
                !ha.to_ascii_lowercase().contains(banned),
                "{banned} must not be emitted: {ha}"
            );
        }
    }

    #[tokio::test]
    async fn every_non_route_gets_one_identical_error() {
        // No index, no health endpoint, no metrics — and crucially the *same*
        // bytes for each miss, so error responses cannot be used to probe which
        // paths exist.
        let ep = ServeEndpoint::bind(Arc::new(vec![7u8; 32]))
            .await
            .expect("bind");
        let mut seen: Vec<String> = Vec::new();
        for path in [
            "/",
            "/health",
            "/metrics",
            "/x-spike/v0/shard/",
            "/x-spike/v0/shard/abc",
            "/x-spike/v1/shard/0",
        ] {
            seen.push(head_of(&fetch(ep.addr(), path).await));
        }
        assert!(
            seen.windows(2).all(|w| w[0] == w[1]),
            "every miss must render identically: {seen:?}"
        );
        assert!(seen[0].starts_with("HTTP/1.1 404"));
        assert_eq!(ep.request_count(), 0, "a miss is not counted as a serve");
    }

    #[tokio::test]
    async fn non_get_methods_are_not_served() {
        let ep = ServeEndpoint::bind(Arc::new(vec![1u8; 8]))
            .await
            .expect("bind");
        let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
        s.write_all(b"POST /x-spike/v0/shard/0 HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .expect("write");
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");
        assert!(head_of(&out).starts_with("HTTP/1.1 404"));
        assert_eq!(ep.request_count(), 0);
    }

    #[tokio::test]
    async fn concurrency_past_the_cap_is_refused_by_close_not_by_a_status_code() {
        // The aggregate bound §6a does not provide. Opens MAX_INFLIGHT + 8
        // connections and holds them open (by never sending a request head, so
        // each occupies a permit until its READ_TIMEOUT), then asserts the
        // endpoint sheds the excess.
        //
        // Two properties, and the second is the one that matters for the
        // `x-spike/v0` surface: the refusal must be a CLOSE, never a new status
        // code, or the response set grows a capacity oracle and a shape TJ-B
        // might inherit.
        let ep = ServeEndpoint::bind(Arc::new(vec![3u8; 64]))
            .await
            .expect("bind");

        let mut held = Vec::new();
        for _ in 0..MAX_INFLIGHT {
            // Connect but send nothing: the connection is accepted, takes a
            // permit, and sits in `read_head` until its timeout.
            held.push(TcpStream::connect(ep.addr()).await.expect("connect"));
        }
        // Give the accept loop time to take all MAX_INFLIGHT permits.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // The next arrivals must be refused.
        let mut refused_bodies = Vec::new();
        for _ in 0..8 {
            let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
            let mut out = Vec::new();
            // A refused connection is closed, so the read returns EOF with no
            // bytes rather than any HTTP response.
            tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
                .await
                .ok();
            refused_bodies.push(out);
        }

        assert!(
            ep.refused_count() > 0,
            "the cap must actually shed load; refused = {}",
            ep.refused_count()
        );
        for body in &refused_bodies {
            assert!(
                !body.starts_with(b"HTTP/"),
                "a refusal must be a close, never a status line: {:?}",
                String::from_utf8_lossy(&body[..body.len().min(32)])
            );
        }
        drop(held);
    }

    #[tokio::test]
    async fn the_cap_does_not_refuse_below_it() {
        // Negative control for the test above: without it, a cap of zero (or an
        // always-failing acquire) would pass "refusals happen" while breaking the
        // endpoint entirely. Serial requests must all succeed and refuse nothing.
        let payload = vec![9u8; 512];
        let ep = ServeEndpoint::bind(Arc::new(payload.clone()))
            .await
            .expect("bind");
        for _ in 0..8 {
            let r = fetch(ep.addr(), "/x-spike/v0/shard/0").await;
            assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
        }
        assert_eq!(ep.refused_count(), 0, "no refusal below the cap");
        assert_eq!(ep.request_count(), 8);
    }

    #[test]
    fn request_parsing_accepts_only_the_spike_route() {
        assert_eq!(
            parse_request(b"GET /x-spike/v0/shard/42 HTTP/1.1\r\n\r\n"),
            Some(Request::Shard(42))
        );
        assert_eq!(parse_request(b"GET /shard/42 HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            parse_request(b"HEAD /x-spike/v0/shard/1 HTTP/1.1\r\n\r\n"),
            None
        );
        // A negative index is not a u64 — rejected rather than wrapped.
        assert_eq!(
            parse_request(b"GET /x-spike/v0/shard/-1 HTTP/1.1\r\n\r\n"),
            None
        );
    }

    #[tokio::test]
    async fn oversized_request_head_is_refused_without_unbounded_buffering() {
        // §6a's payload bound: the cap is enforced while reading. The peer sends a
        // head that never terminates; the endpoint must drop it rather than grow.
        let ep = ServeEndpoint::bind(Arc::new(vec![0u8; 8]))
            .await
            .expect("bind");
        let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
        s.write_all(b"GET /x-spike/v0/shard/0 HTTP/1.1\r\n")
            .await
            .expect("write line");
        // Well past MAX_REQUEST_BYTES, with no terminating blank line.
        let filler = vec![b'x'; MAX_REQUEST_BYTES * 2];
        s.write_all(&filler).await.ok();
        let mut out = Vec::new();
        // The connection is dropped: either EOF with no response, or a write
        // error. Both are "refused"; what must NOT happen is a served payload.
        s.read_to_end(&mut out).await.ok();
        assert!(
            !out.starts_with(b"HTTP/1.1 200"),
            "an oversized head must never be served"
        );
        assert_eq!(ep.request_count(), 0);
    }
}
