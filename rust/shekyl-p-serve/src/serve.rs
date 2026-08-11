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
//! three aggregate monotone counters with no per-request structure:
//! [`PServeEndpoint::served_count`], [`PServeEndpoint::refused_count`],
//! [`PServeEndpoint::lookup_failure_count`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::provider::ShardProvider;

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
/// The binding resource is egress, and the W₂ measurement rig derives the
/// real value on the provisioning-floor hardware (rule 76). A rising
/// [`PServeEndpoint::refused_count`] is the operator signal that the cap
/// is binding.
pub const MAX_INFLIGHT: usize = 64;

/// Bound on reading the request head from an accepted connection.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on the whole response write (head plus body). Generous because
/// 3.33 MB over a rendezvous circuit *is* the slow path — this is the
/// "peer stopped reading" backstop, not a latency budget.
const WRITE_TIMEOUT: Duration = Duration::from_secs(600);

/// Internal write granularity for the shard body.
///
/// Not wire framing — the response is one `content-length` body; the wire
/// bytes are identical to a single write. The loop is chunked so that
/// resumability, if the format round rules it in, is a change of framing
/// on top of an already-incremental writer instead of a rewrite — the
/// §9.5 discipline that a format property must never be foreclosed by
/// what was convenient to build.
const WRITE_CHUNK_BYTES: usize = 64 * 1024;

/// A running loopback serve endpoint for one persona.
///
/// Dropping it aborts the accept loop; in-flight connection tasks are
/// detached and end at their own timeouts.
pub struct PServeEndpoint {
    addr: SocketAddr,
    accept_task: JoinHandle<()>,
    served: Arc<AtomicU64>,
    refused: Arc<AtomicU64>,
    lookup_failures: Arc<AtomicU64>,
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
        let served_ctr = Arc::clone(&served);
        let refused_ctr = Arc::clone(&refused);
        let failures_ctr = Arc::clone(&lookup_failures);
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
                    // record it.
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
                    // Held for the whole connection; the slot reopens only
                    // once the shard has actually finished sending.
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
        })
    }

    /// The bound loopback address, for `ADD_ONION`'s `Port=` target.
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
    /// bytes). On the wire these render as the same 404 as any miss; this
    /// counter is the only place they are distinguishable, and a nonzero
    /// value on a bonded serve-set means pins are missing — the
    /// silent-slash precursor, surfaced.
    #[must_use]
    pub fn lookup_failure_count(&self) -> u64 {
        self.lookup_failures.load(Ordering::Relaxed)
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

/// Read one request head, answer it, close.
///
/// No keep-alive: each read is its own connection, which keeps the serve
/// unit unambiguous and removes connection reuse as a cross-persona
/// correlation surface.
async fn handle_connection(
    mut stream: TcpStream,
    provider: Arc<dyn ShardProvider>,
    served: &AtomicU64,
    lookup_failures: &AtomicU64,
) -> io::Result<()> {
    let head = tokio::time::timeout(READ_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request head"))??;

    // Every non-servable outcome — wrong path, wrong method, malformed,
    // unknown shard, unfrozen shard, store failure — collapses to the one
    // shared 404 below, so neither the route table nor store health is
    // probeable through the rendezvous.
    let body = match parse_request(&head) {
        Some(Request::Shard(shard_id)) => {
            let looked_up =
                tokio::task::spawn_blocking(move || provider.shard_bytes(shard_id)).await;
            match looked_up {
                Ok(Ok(found)) => found,
                Ok(Err(_)) | Err(_) => {
                    lookup_failures.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        }
        None => None,
    };

    tokio::time::timeout(WRITE_TIMEOUT, async {
        match body {
            Some(bytes) => {
                stream.write_all(render_ok(bytes.len()).as_bytes()).await?;
                for chunk in bytes.chunks(WRITE_CHUNK_BYTES) {
                    stream.write_all(chunk).await?;
                }
                stream.flush().await?;
                served.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                stream.write_all(NOT_FOUND.as_bytes()).await?;
                stream.flush().await?;
            }
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "response write"))??;
    Ok(())
}

/// Read until the end of the request head (`\r\n\r\n`), bounded by
/// [`MAX_REQUEST_BYTES`] **as the buffer grows**, so an oversized head is
/// refused before it is fully allocated.
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
    let shard_id = path.strip_prefix(ROUTE_PREFIX)?;
    shard_id.parse::<u64>().ok().map(Request::Shard)
}

/// The success head. Exactly [`RESPONSE_HEADER_NAMES`], nothing else — no
/// `date` (a clock-skew fingerprint), no `server`, no `etag`, no
/// `accept-ranges`.
fn render_ok(len: usize) -> String {
    format!("HTTP/1.1 200 OK\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {len}\r\n\r\n")
}

/// The single error response, byte-identical for every non-servable
/// outcome.
const NOT_FOUND: &str =
    "HTTP/1.1 404 Not Found\r\ncontent-type: application/octet-stream\r\ncontent-length: 0\r\n\r\n";

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::provider::ProviderError;

    /// In-memory provider: the loop's wire behaviour, storeless.
    struct FixtureProvider {
        shards: HashMap<u64, Arc<[u8]>>,
    }

    impl FixtureProvider {
        fn new(shards: impl IntoIterator<Item = (u64, Vec<u8>)>) -> Arc<Self> {
            Arc::new(Self {
                shards: shards
                    .into_iter()
                    .map(|(id, bytes)| (id, Arc::from(bytes.into_boxed_slice())))
                    .collect(),
            })
        }
    }

    impl ShardProvider for FixtureProvider {
        fn shard_bytes(&self, shard_id: u64) -> Result<Option<Arc<[u8]>>, ProviderError> {
            Ok(self.shards.get(&shard_id).cloned())
        }
    }

    /// Provider whose every lookup fails — the store-failure arm.
    struct FailingProvider;

    impl ShardProvider for FailingProvider {
        fn shard_bytes(&self, _shard_id: u64) -> Result<Option<Arc<[u8]>>, ProviderError> {
            Err(ProviderError::new("synthetic store failure"))
        }
    }

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
        // A wildcard or routable bind would make the endpoint reachable
        // without the rendezvous and attributable to the host's IP.
        let ep = PServeEndpoint::bind(FixtureProvider::new([]))
            .await
            .expect("bind");
        assert!(ep.addr().ip().is_loopback());
        assert_ne!(ep.addr().port(), 0, "an ephemeral port was actually bound");
    }

    #[tokio::test]
    async fn serves_each_shard_by_its_own_id() {
        // The capability the spike lacked: the id in the route selects the
        // shard. Two ids must return their own bytes, not a shared buffer.
        let a: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let b: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
        let ep = PServeEndpoint::bind(FixtureProvider::new([(7, a.clone()), (9, b.clone())]))
            .await
            .expect("bind");

        let ra = fetch(ep.addr(), "/x-provisional/v0/shard/7").await;
        assert!(head_of(&ra).starts_with("HTTP/1.1 200 OK"));
        assert_eq!(&ra[ra.len() - a.len()..], &a[..], "shard 7 serves a-bytes");

        let rb = fetch(ep.addr(), "/x-provisional/v0/shard/9").await;
        assert_eq!(&rb[rb.len() - b.len()..], &b[..], "shard 9 serves b-bytes");

        assert_eq!(ep.served_count(), 2);
        assert_eq!(ep.lookup_failure_count(), 0);
    }

    #[tokio::test]
    async fn two_personas_are_header_identical() {
        // Two endpoints (as two personas' loops would be), different
        // payload bytes of equal length so the assertion cannot pass
        // vacuously by serving identical bodies.
        let a = PServeEndpoint::bind(FixtureProvider::new([(0, vec![0xAA; 2048])]))
            .await
            .expect("bind a");
        let b = PServeEndpoint::bind(FixtureProvider::new([(1, vec![0xBB; 2048])]))
            .await
            .expect("bind b");
        let ha = head_of(&fetch(a.addr(), "/x-provisional/v0/shard/0").await);
        let hb = head_of(&fetch(b.addr(), "/x-provisional/v0/shard/1").await);
        assert_eq!(ha, hb, "two personas must be header-identical");

        // The header set is exactly the declared one — checked by name so
        // a future addition fails here instead of widening the
        // fingerprint.
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
    async fn every_non_servable_outcome_renders_one_identical_404() {
        // The full miss set in one sweep: wrong path, wrong prefix,
        // malformed id, UNKNOWN shard id (a valid route to a shard this
        // persona does not hold), and a provider infrastructure failure.
        // All must be byte-identical, or the differences become a probe
        // surface for the route table, the holdings, or store health.
        let ep = PServeEndpoint::bind(FixtureProvider::new([(3, vec![7u8; 32])]))
            .await
            .expect("bind");
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for path in [
            "/",
            "/health",
            "/x-spike/v0/shard/3",
            "/x-provisional/v0/shard/",
            "/x-provisional/v0/shard/abc",
            "/x-provisional/v0/shard/4", // valid route, unheld shard
        ] {
            seen.push(fetch(ep.addr(), path).await);
        }
        let failing = PServeEndpoint::bind(Arc::new(FailingProvider))
            .await
            .expect("bind failing");
        seen.push(fetch(failing.addr(), "/x-provisional/v0/shard/3").await);
        assert_eq!(failing.lookup_failure_count(), 1);

        assert!(
            seen.windows(2).all(|w| w[0] == w[1]),
            "every miss must render byte-identically"
        );
        assert!(head_of(&seen[0]).starts_with("HTTP/1.1 404"));
        assert_eq!(ep.served_count(), 0, "a miss is not counted as a serve");
    }

    #[tokio::test]
    async fn non_get_methods_are_not_served() {
        let ep = PServeEndpoint::bind(FixtureProvider::new([(0, vec![1u8; 8])]))
            .await
            .expect("bind");
        let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
        s.write_all(b"POST /x-provisional/v0/shard/0 HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .expect("write");
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");
        assert!(head_of(&out).starts_with("HTTP/1.1 404"));
        assert_eq!(ep.served_count(), 0);
    }

    #[tokio::test]
    async fn concurrency_past_the_cap_is_refused_by_close_not_by_a_status_code() {
        // Opens MAX_INFLIGHT connections and holds them open (by never
        // sending a request head, so each occupies a permit until its
        // READ_TIMEOUT), then asserts the endpoint sheds the excess by
        // CLOSE — never a new status code, which would add a response
        // shape and a capacity oracle.
        let ep = PServeEndpoint::bind(FixtureProvider::new([(0, vec![3u8; 64])]))
            .await
            .expect("bind");

        let mut held = Vec::new();
        for _ in 0..MAX_INFLIGHT {
            held.push(TcpStream::connect(ep.addr()).await.expect("connect"));
        }
        // Give the accept loop time to take all MAX_INFLIGHT permits.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let mut refused_bodies = Vec::new();
        for _ in 0..8 {
            let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
            let mut out = Vec::new();
            // A refused connection is closed: EOF with no bytes, never an
            // HTTP response.
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
                "a refusal must be a close, never a status line"
            );
        }
        drop(held);
    }

    #[tokio::test]
    async fn the_cap_does_not_refuse_below_it() {
        // Negative control: without it, a cap of zero would pass
        // "refusals happen" while breaking the endpoint entirely.
        let payload = vec![9u8; 512];
        let ep = PServeEndpoint::bind(FixtureProvider::new([(0, payload)]))
            .await
            .expect("bind");
        for _ in 0..8 {
            let r = fetch(ep.addr(), "/x-provisional/v0/shard/0").await;
            assert!(head_of(&r).starts_with("HTTP/1.1 200 OK"));
        }
        assert_eq!(ep.refused_count(), 0, "no refusal below the cap");
        assert_eq!(ep.served_count(), 8);
    }

    #[tokio::test]
    async fn oversized_request_head_is_refused_without_unbounded_buffering() {
        // The pre-allocation bound: the cap is enforced while reading. A
        // head that never terminates is dropped rather than buffered.
        let ep = PServeEndpoint::bind(FixtureProvider::new([(0, vec![0u8; 8])]))
            .await
            .expect("bind");
        let mut s = TcpStream::connect(ep.addr()).await.expect("connect");
        s.write_all(b"GET /x-provisional/v0/shard/0 HTTP/1.1\r\n")
            .await
            .expect("write line");
        let filler = vec![b'x'; MAX_REQUEST_BYTES * 2];
        s.write_all(&filler).await.ok();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.ok();
        assert!(
            !out.starts_with(b"HTTP/1.1 200"),
            "an oversized head must never be served"
        );
        assert_eq!(ep.served_count(), 0);
    }

    #[test]
    fn request_parsing_accepts_only_the_provisional_route() {
        assert_eq!(
            parse_request(b"GET /x-provisional/v0/shard/42 HTTP/1.1\r\n\r\n"),
            Some(Request::Shard(42))
        );
        assert_eq!(parse_request(b"GET /shard/42 HTTP/1.1\r\n\r\n"), None);
        // The spike's route is dead here — its framing did not carry over.
        assert_eq!(
            parse_request(b"GET /x-spike/v0/shard/42 HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_request(b"HEAD /x-provisional/v0/shard/1 HTTP/1.1\r\n\r\n"),
            None
        );
        // A negative id is not a u64 — rejected rather than wrapped.
        assert_eq!(
            parse_request(b"GET /x-provisional/v0/shard/-1 HTTP/1.1\r\n\r\n"),
            None
        );
    }
}
