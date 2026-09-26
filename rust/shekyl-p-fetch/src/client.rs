// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client: one admission path, one dial shape, one request, one
//! response reader, and the two verifications that make a body a
//! [`VerifiedShard`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::verify_pass_transcript;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::serving_route::{
    CONTENT_TYPE, REQUEST_HEADER_NAME, RESPONSE_HEADER_NAMES, ROUTE_PREFIX, SERVING_VIRTUAL_PORT,
};
use shekyl_curve_tree::{leaves_per_segment, LEAF_BYTES};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_socks::tcp::Socks5Stream;

use crate::error::{FetchError, Malformed, Stall};
use crate::header::RequestHeader;
use crate::target::{ContentVerify, FetchTarget, ServingEndpoint, VerifiedShard};

/// Concurrent transfers one client may have outstanding (`SF-D7`): the
/// in-flight cap `N`. Shared by both callers; there is no queue behind
/// it — a scheduler wanting another transfer waits for a slot.
///
/// **8, pinned 2026-09-16** by the §9.1 (c) W₂ run on the production
/// `PFetchClient` (daemon→wallet, one client tor, 3.33 MB shard-0,
/// PR #746). The pin is `min(largest non-churning width, Pi 4 memory)`:
///
/// - **Upper bound (circuit churn).** Widths 1, 2, 4, 8 were all valid
///   (no VOID rows, zero serve-side cap sheds). Circuit-failure rates
///   0.0 / 1.0 / 0.0 / 0.0 %; p50 12.4 → 13.2 s. 8 is the largest
///   width that apparatus could exercise (eight personas); 16 was not
///   measured. Raising above 8 is a new sweep, not a silent bump.
/// - **Upper bound (memory).** The client materialises each body until
///   both verifications finish (`SF-D8`: verified-or-refused, no
///   streaming accept), so `N × max_body_bytes()` is resident in the worst
///   case. At the leaf figure that is `8 × ~6.7 MB ≈ 53 MB` on the Pi 4
///   floor (rule 76) — still well under the placeholder-64 figure
///   `SF-D7` refused (213 MB). Memory does not bind at 8.
/// - **Lower bound (throughput).** Reconstruct is a sustained fill over a
///   single Tor instance whose per-stream throughput, not the client's
///   parallelism, is the ceiling (`SF-D3`: no per-fetch circuit build).
///   The (b) judgement that four outstanding transfers keep the stream
///   busy still holds; eight is that judgement plus the W₂ room.
///
/// **Re-derive under `PDM-Q6`'s unit** once the body is a tx-range's and
/// not a leaf shard's — the memory term changes, the shape does not.
/// Reopen otherwise on `SF-D7`'s criteria: capped reconstruct throughput
/// below TJ-D's chain-growth requirement, or wait-for-a-slot plus transfer
/// for a challenge fetch approaching `CHALLENGE_RESPONSE_BLOCKS`.
pub const MAX_INFLIGHT: usize = 8;

/// Width of the countersignature envelope that leads the body: the
/// canonical `HybridSignature` encoding and nothing else (`SF-D8`). Both
/// ends read `HybridSignature::CANONICAL_LEN`; this name is the
/// fetch-side statement that the body's first bytes are a signature.
pub const SIGNATURE_ENVELOPE_LEN: usize = HybridSignature::CANONICAL_LEN;

/// Ceiling on a response body, applied to `content-length` **before** a
/// body byte is read (`SF-D6`: refused from the HTTP headers).
///
/// `content-length` comes from a potentially adversarial `P`; an
/// unbounded one is a pre-allocation and resource-exhaustion path. The
/// figure is `envelope + frame-header-max + 2 × segment`: the `RF-D4`
/// frame bounds padding at one segment's worth (its
/// `ServedFrameHeader::padding_len` contract), so a well-formed body is
/// never more than twice a segment behind two varint lengths.
///
/// **This is the one leaf-shaped number in the crate, and it is
/// provisional by name.** It is a *resource* bound, not a parse: the crate
/// still hands the bytes to the content-verify hole unparsed. When
/// `PDM-Q6` retires the leaf shard for a tx-range body, this function is
/// re-derived from that unit's maximum (sub-PR 2), and nothing else here
/// moves.
#[must_use]
pub fn max_body_bytes() -> u64 {
    // Two LEB128 `u64` lengths lead the frame; each is at most 10 bytes.
    const FRAME_HEADER_MAX: u64 = 2 * 10;
    let segment = u64::try_from(leaves_per_segment() * LEAF_BYTES).expect("segment fits u64");
    u64::try_from(SIGNATURE_ENVELOPE_LEN).expect("envelope fits u64")
        + FRAME_HEADER_MAX
        + 2 * segment
}

/// Longest head this client will buffer while looking for `\r\n\r\n`. The
/// ruled head is a status line and two headers — well under 200 bytes.
/// A stream that keeps flowing past this without terminating the head is
/// not stalled and is not the contract; it is [`Malformed::HeadTooLong`].
const MAX_HEAD_BYTES: usize = 1024;

/// Largest single read while draining a body.
const BODY_CHUNK: usize = 64 * 1024;

/// Per-step bounds on one fetch. Operational, not contract (`RF-R1`):
/// they decide when an attempt becomes a [`Stall`], never what a
/// completed exchange means.
///
/// The defaults mirror the serve side's own bounds where a client-side
/// counterpart exists, so neither end waits on the other past the point
/// the other has already given up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// SOCKS handshake through to the proxy's CONNECT reply — which, for
    /// an onion target, includes the rendezvous with `P`. Tor's own
    /// client-side rendezvous budget is of this order; a dial that has
    /// not completed in a minute is not about to.
    pub dial: Duration,
    /// From the request's last byte to a complete response head. Mirrors
    /// `shekyl-p-serve`'s `READ_TIMEOUT`.
    pub head: Duration,
    /// Longest a single body read may make no progress. Mirrors the
    /// server's `WRITE_STALL_TIMEOUT`.
    pub body_stall: Duration,
    /// Longest the whole body may take. Mirrors the server's
    /// `WRITE_TIMEOUT`: a body the server would have abandoned is one the
    /// client should not still be waiting on.
    pub body_total: Duration,
}

impl Timeouts {
    /// The production bounds.
    pub const DEFAULT: Self = Self {
        dial: Duration::from_secs(60),
        head: Duration::from_secs(30),
        body_stall: Duration::from_secs(30),
        body_total: Duration::from_secs(600),
    };
}

impl Default for Timeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The shard-fetch client. One per daemon; `Clone`-free by design — the
/// in-flight cap is a property of the process's Tor instance, so a second
/// client would be a second cap.
pub struct PFetchClient {
    proxy: SocketAddr,
    /// `Arc` so a permit can be *owned* and travel into the blocking
    /// verify task — see [`Self::fetch`] on cancellation.
    slots: Arc<Semaphore>,
    timeouts: Timeouts,
}

impl std::fmt::Debug for PFetchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PFetchClient")
            .field("proxy", &self.proxy)
            .field("available_slots", &self.slots.available_permits())
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

impl PFetchClient {
    /// A client dialling through the tor-zone SOCKS5 proxy at `proxy`,
    /// with [`Timeouts::DEFAULT`].
    ///
    /// `proxy` is the daemon's own Tor client's SOCKS port (`SF-D2`), never
    /// the serving instance's (`PWD-E9`). The proxy address is the one
    /// thing here that *is* resolved locally, because it is a loopback
    /// socket, not a name.
    ///
    /// The content-verify hole is per-`fetch`, not per-client: two callers
    /// share this admission path and plug the check for *this* shard.
    #[must_use]
    pub fn new(proxy: SocketAddr) -> Self {
        Self::with_timeouts(proxy, Timeouts::DEFAULT)
    }

    /// [`Self::new`] with explicit per-step bounds.
    #[must_use]
    pub fn with_timeouts(proxy: SocketAddr, timeouts: Timeouts) -> Self {
        Self {
            proxy,
            slots: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            timeouts,
        }
    }

    /// In-flight slots not currently held. Observability for the
    /// scheduler; `0` means the next [`Self::fetch`] waits.
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.slots.available_permits()
    }

    /// Fetch `target.shard_id` from `target.endpoint`, carrying `header`,
    /// and return it only if `P`'s countersignature verifies under
    /// `target.verifying_key` and `verifier` accepts the body.
    ///
    /// Waits for an in-flight slot first; the slot is held until the
    /// result is decided, body included (`SF-D7`: the body is resident
    /// until verify finishes). Both verifications run off the executor
    /// thread — a hybrid verify is CPU, and the hole may be far more.
    ///
    /// Cancellation: dropping the future closes the stream and releases the
    /// slot — **once the fetch is actually over**. A `spawn_blocking` task
    /// does not stop when its handle is dropped, so if the future is
    /// dropped mid-verify the body and the hole keep running to their end;
    /// the slot travels into that task and is released by it, not by the
    /// drop. Otherwise repeated cancellation during verify would let the
    /// next fetch take the slot while the last body is still resident,
    /// and `MAX_INFLIGHT` would bound admissions rather than bodies.
    /// Nothing is decided about `P` by a fetch that was not allowed to
    /// finish.
    ///
    /// # Errors
    ///
    /// The [`FetchError`] taxonomy. [`FetchError::retries_same_p`] is the
    /// one-bit summary a scheduler needs.
    pub async fn fetch(
        &self,
        target: &FetchTarget,
        header: &RequestHeader,
        verifier: Arc<dyn ContentVerify>,
    ) -> Result<VerifiedShard, FetchError> {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("in-flight semaphore is never closed");

        let mut stream = self.dial(&target.endpoint).await?;
        let request = request_bytes(target.shard_id, header);
        timeout(self.timeouts.head, stream.write_all(&request))
            .await
            .map_err(|_| FetchError::Stall(Stall::HeadTimeout))?
            // No complete head: a write error is the same class as a mid-head
            // close, not a short body (`Stall::Io` is body-phase only).
            .map_err(|_| FetchError::Stall(Stall::ClosedBeforeHead))?;

        let (head, mut body) = read_head(&mut stream, self.timeouts.head).await?;
        let head = parse_head(&head)?;
        let held = match head.status {
            404 => {
                if head.content_length != 0 {
                    return Err(FetchError::Malformed(Malformed::ContentLength));
                }
                false
            }
            200 => {
                let declared = head.content_length;
                let envelope = u64::try_from(SIGNATURE_ENVELOPE_LEN).expect("envelope fits u64");
                if declared < envelope {
                    return Err(FetchError::Malformed(Malformed::EnvelopeShort { declared }));
                }
                let max = max_body_bytes();
                if declared > max {
                    return Err(FetchError::Malformed(Malformed::Oversize { declared, max }));
                }
                true
            }
            other => return Err(FetchError::Malformed(Malformed::Status(other))),
        };

        // Both answers are read to the same standard: exactly the declared
        // bytes, then `P`'s close. A 404 is a *completed* exchange only if
        // it completes — a "no" with bytes behind it is not the identical
        // 404, it is a `P` off the contract.
        read_body(&mut stream, &mut body, head.content_length, self.timeouts).await?;
        drop(stream);
        if !held {
            return Err(FetchError::Miss);
        }

        // Off the executor: a hybrid verify is real CPU, and the hole may
        // be much more (today it recomputes a segment root). The slot goes
        // with the body: it is dropped when this closure returns, whether
        // or not anyone is still awaiting the handle.
        let (verifying_key, shard_id, header) =
            (target.verifying_key.clone(), target.shard_id, *header);
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let content = body.split_off(SIGNATURE_ENVELOPE_LEN);
            let signature = HybridSignature::from_canonical_bytes(&body)
                .map_err(|_| FetchError::Malformed(Malformed::Envelope))?;
            verify_pass_transcript(
                &verifying_key,
                header.nonce(),
                header.anchor_height(),
                header.anchor_hash(),
                shard_id,
                &signature,
            )
            .map_err(|_| FetchError::BadCountersignature)?;
            verifier
                .verify(shard_id, &content)
                .map_err(FetchError::ContentRefused)?;
            Ok(VerifiedShard::new(shard_id, signature, content))
        })
        .await
        .expect("verify task does not panic")
    }

    /// SOCKS5h dial: the proxy receives the `.onion` **name** (ATYP=DOMAIN)
    /// and resolves it. Passing a pre-resolved address here is the DNS
    /// leak `SF-D3` exists to close; there is no code path that could,
    /// because an onion has no IP to resolve to — but the shape is kept
    /// deliberately so a future non-onion endpoint would not acquire one.
    async fn dial(
        &self,
        endpoint: &ServingEndpoint,
    ) -> Result<Socks5Stream<tokio::net::TcpStream>, FetchError> {
        let host = endpoint.onion_address();
        let connect = Socks5Stream::connect(self.proxy, (host.as_str(), SERVING_VIRTUAL_PORT));
        match timeout(self.timeouts.dial, connect).await {
            Err(_elapsed) => Err(FetchError::Stall(Stall::DialTimeout)),
            Ok(Err(e)) => Err(FetchError::Stall(Stall::Dial(e.to_string()))),
            Ok(Ok(stream)) => Ok(stream),
        }
    }
}

/// The request: the ruled route, the one required header, nothing else.
/// No `host` (the server ignores it and `P` knows its own name), no
/// `user-agent`, no `accept`. Every requester sends byte-identical lines
/// modulo `{id}` and the header value — that is the `SF-D1` property on
/// the request side.
fn request_bytes(shard_id: u64, header: &RequestHeader) -> Vec<u8> {
    format!(
        "GET {ROUTE_PREFIX}{shard_id} HTTP/1.1\r\n{REQUEST_HEADER_NAME}: {}\r\n\r\n",
        header.wire_value()
    )
    .into_bytes()
}

/// Read until `\r\n\r\n`. Returns the head (without its terminator) and
/// any body bytes that arrived with it.
///
/// The terminator is bounded independently of TCP chunking: a read that
/// jumps `buf` past [`MAX_HEAD_BYTES`] with the terminator still inside
/// that window is `HeadTooLong`, not a successful parse of an oversized
/// head.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    bound: Duration,
) -> Result<(Vec<u8>, Vec<u8>), FetchError> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let read = async {
        loop {
            if let Some(end) = find_head_end(&buf) {
                if end > MAX_HEAD_BYTES {
                    return Err(FetchError::Malformed(Malformed::HeadTooLong));
                }
                let body = buf.split_off(end + 4);
                buf.truncate(end);
                return Ok((buf, body));
            }
            if buf.len() > MAX_HEAD_BYTES {
                return Err(FetchError::Malformed(Malformed::HeadTooLong));
            }
            let mut chunk = [0u8; 256];
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| FetchError::Stall(Stall::ClosedBeforeHead))?;
            if n == 0 {
                return Err(FetchError::Stall(Stall::ClosedBeforeHead));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    };
    timeout(bound, read)
        .await
        .map_err(|_| FetchError::Stall(Stall::HeadTimeout))?
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A parsed, contract-conformant head.
struct Head {
    status: u16,
    content_length: u64,
}

/// Parse a complete head against the ruled response grammar (`RF-R1`):
/// `HTTP/1.x <code> …`, then exactly `RESPONSE_HEADER_NAMES`, each once,
/// `content-type` the ruled type, `content-length` a decimal `u64`.
///
/// Header names compare case-insensitively (HTTP); values do not.
fn parse_head(head: &[u8]) -> Result<Head, FetchError> {
    let text = std::str::from_utf8(head).map_err(|_| Malformed::StatusLine)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(Malformed::StatusLine)?;
    let mut tokens = status_line.split(' ');
    let version = tokens.next().ok_or(Malformed::StatusLine)?;
    let code = tokens.next().ok_or(Malformed::StatusLine)?;
    if !version.starts_with("HTTP/1.") || code.len() != 3 {
        return Err(Malformed::StatusLine.into());
    }
    let status: u16 = code.parse().map_err(|_| Malformed::StatusLine)?;

    let mut content_type = None;
    let mut content_length = None;
    let mut seen = 0usize;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Malformed::HeaderSet)?;
        // Field-name is a token: no whitespace. Trimming would accept
        // `content-length : 10`, a second spelling the contract does not
        // permit. Values still take HTTP OWS.
        if name.as_bytes().iter().any(u8::is_ascii_whitespace) {
            return Err(Malformed::HeaderSet.into());
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if !RESPONSE_HEADER_NAMES.contains(&name.as_str()) {
            return Err(Malformed::HeaderSet.into());
        }
        seen += 1;
        let slot = if name == "content-type" {
            &mut content_type
        } else {
            &mut content_length
        };
        if slot.replace(value).is_some() {
            return Err(Malformed::HeaderSet.into());
        }
    }
    if seen != RESPONSE_HEADER_NAMES.len() {
        return Err(Malformed::HeaderSet.into());
    }
    if content_type != Some(CONTENT_TYPE) {
        return Err(Malformed::ContentType.into());
    }
    let length = content_length.ok_or(Malformed::ContentLength)?;
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Malformed::ContentLength.into());
    }
    let content_length: u64 = length.parse().map_err(|_| Malformed::ContentLength)?;
    Ok(Head {
        status,
        content_length,
    })
}

impl From<Malformed> for FetchError {
    fn from(m: Malformed) -> Self {
        Self::Malformed(m)
    }
}

impl From<Stall> for FetchError {
    fn from(s: Stall) -> Self {
        Self::Stall(s)
    }
}

/// Read exactly `declared` body bytes into `body` (which may already hold
/// the bytes that arrived with the head), then confirm `P` closed — under
/// a per-read stall bound and a whole-body deadline.
///
/// "Exactly" is checked in both directions. Fewer bytes before the close is
/// [`Stall::Truncated`]; more bytes — already buffered behind the head, or
/// arriving on the probe for the close — is [`Malformed::Overlength`]
/// (`SF-D6`: body long of agreed `N` is malformed, not trimmed). The probe
/// is what makes the second direction decidable: `RF-R1` has `P` close
/// after the body, so a conforming `P`'s EOF is already behind the last
/// byte, and a `P` that sends neither EOF nor bytes within the stall bound
/// is [`Stall::NoClose`].
async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    body: &mut Vec<u8>,
    declared: u64,
    timeouts: Timeouts,
) -> Result<(), FetchError> {
    let declared_len = usize::try_from(declared).expect("declared length within the ceiling");
    if body.len() > declared_len {
        return Err(FetchError::Malformed(Malformed::Overlength { declared }));
    }
    body.reserve_exact(declared_len - body.len());
    let drain = async {
        while body.len() < declared_len {
            let want = (declared_len - body.len()).min(BODY_CHUNK);
            let start = body.len();
            body.resize(start + want, 0);
            let n = timeout(timeouts.body_stall, stream.read(&mut body[start..]))
                .await
                .map_err(|_| Stall::BodyTimeout)?
                .map_err(Stall::Io)?;
            body.truncate(start + n);
            if n == 0 {
                return Err(FetchError::Stall(Stall::Truncated {
                    declared,
                    received: u64::try_from(body.len()).expect("received fits u64"),
                }));
            }
        }
        // Exactly `declared` in hand. The next read decides the response:
        // EOF completes it, a byte breaks it, silence is a stall.
        let mut probe = [0u8; 1];
        let n = timeout(timeouts.body_stall, stream.read(&mut probe))
            .await
            .map_err(|_| Stall::NoClose)?
            .map_err(Stall::Io)?;
        if n != 0 {
            return Err(FetchError::Malformed(Malformed::Overlength { declared }));
        }
        Ok(())
    };
    match timeout(timeouts.body_total, drain).await {
        Err(_elapsed) => Err(FetchError::Stall(Stall::BodyTimeout)),
        Ok(outcome) => outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::BlockHeight;

    fn head(s: &str) -> Result<Head, FetchError> {
        parse_head(s.as_bytes())
    }

    fn malformed(r: Result<Head, FetchError>) -> Malformed {
        match r {
            Err(FetchError::Malformed(m)) => m,
            Ok(_) => panic!("head parsed"),
            Err(other) => panic!("not malformed: {other}"),
        }
    }

    #[test]
    fn the_ruled_head_parses_and_names_are_case_insensitive() {
        let h =
            head("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: 42")
                .expect("parses");
        assert_eq!((h.status, h.content_length), (200, 42));
        let h = head(
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nCONTENT-TYPE:application/octet-stream",
        )
        .expect("parses");
        assert_eq!((h.status, h.content_length), (404, 0));
    }

    #[test]
    fn every_departure_from_the_two_header_contract_is_typed() {
        let ok_headers = "content-type: application/octet-stream\r\ncontent-length: 1";
        assert_eq!(
            malformed(head(&format!("HTTP/2 200 OK\r\n{ok_headers}"))),
            Malformed::StatusLine
        );
        assert_eq!(
            malformed(head(&format!("HTTP/1.1 20 OK\r\n{ok_headers}"))),
            Malformed::StatusLine
        );
        assert_eq!(
            malformed(head(&format!("HTTP/1.1 abc OK\r\n{ok_headers}"))),
            Malformed::StatusLine
        );
        assert_eq!(
            malformed(head(&format!(
                "HTTP/1.1 200 OK\r\n{ok_headers}\r\ndate: now"
            ))),
            Malformed::HeaderSet
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length : 1"
            )),
            Malformed::HeaderSet
        );
        assert_eq!(
            malformed(head(&format!(
                "HTTP/1.1 200 OK\r\n{ok_headers}\r\ncontent-length: 1"
            ))),
            Malformed::HeaderSet
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream"
            )),
            Malformed::HeaderSet
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nno-colon"
            )),
            Malformed::HeaderSet
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 1"
            )),
            Malformed::ContentType
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: -1"
            )),
            Malformed::ContentLength
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: "
            )),
            Malformed::ContentLength
        );
        assert_eq!(
            malformed(head(
                "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: 99999999999999999999999"
            )),
            Malformed::ContentLength
        );
    }

    #[test]
    fn the_body_ceiling_is_two_segments_behind_the_envelope_and_frame_header() {
        let segment = u64::try_from(leaves_per_segment() * LEAF_BYTES).unwrap();
        assert_eq!(max_body_bytes(), 3385 + 20 + 2 * segment);
        // The figure the round quoted: ~3.33 MB a segment, so ~6.7 MB ceiling.
        assert_eq!(segment, 3_326_976);
    }

    #[test]
    fn the_request_is_the_route_and_the_one_header() {
        let h = RequestHeader::with_nonce([1; 32], BlockHeight::from_raw(2), [3; 32]);
        let req = String::from_utf8(request_bytes(7, &h)).unwrap();
        assert_eq!(
            req,
            format!(
                "GET /shard/7 HTTP/1.1\r\nshekyl-pass-request: {}\r\n\r\n",
                h.wire_value()
            )
        );
    }
}
