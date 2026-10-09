// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The client: one admission path, one dial shape, one request, and the
//! two verifications that make a body a [`VerifiedShard`]. The streaming
//! body reader — frame walk, delivery digest, envelope, close probe —
//! is the crate's private body module.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::verify_pass_transcript;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::serving_route::{
    is_refusal_trailer, CONTENT_TYPE, REQUEST_HEADER_NAME, RESPONSE_HEADER_NAMES, ROUTE_PREFIX,
    SERVING_VIRTUAL_PORT,
};
use shekyl_socks::{connect as socks_connect, Destination, Isolation};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::body::{read_frame, BodyReader, Checker};
use crate::error::{FetchError, Malformed, Stall};
use crate::header::RequestHeader;
use crate::target::{ExpectedShard, FetchTarget, ServingEndpoint, TxSink, VerifiedShard};

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
/// - **Upper bound (memory).** The body streams: one transaction's two
///   segments are resident per fetch while they are checked and handed to
///   the sink, then dropped (`SF-D8` amendment 2026-10-08). The resident
///   term is `N × (largest archival length of one transaction + a read
///   chunk)`, bounded by consensus (`max_tx_weight`) and not by `W`. At
///   the pin it was `N × max_body_bytes()` with the whole body resident —
///   `8 × ~6.7 MB ≈ 53 MB` on the Pi 4 floor (rule 76), itself well under
///   the placeholder-64 figure `SF-D7` refused (213 MB). Memory did not
///   bind at 8 then and binds less now.
/// - **Lower bound (throughput).** Reconstruct is a sustained fill over a
///   single Tor instance whose per-stream throughput, not the client's
///   parallelism, is the ceiling. That judgement was made when fetches
///   shared circuits. Since 2026-10-07 each read builds a rendezvous
///   circuit of its own (`SF-D3`), and what that does to the right cap is
///   not measured (`BA-T31`, `BA-T6`); the constant is unmeasured either
///   way.
///
/// The body is the tx-range's now (`SHT-Q2`); the memory term moved as
/// above and the churn bound did not, so the pin stands. Reopen on
/// `SF-D7`'s criteria: capped reconstruct throughput
/// below TJ-D's chain-growth requirement, or wait-for-a-slot plus transfer
/// for a challenge fetch approaching `CHALLENGE_RESPONSE_BLOCKS`.
pub const MAX_INFLIGHT: usize = 8;

pub use crate::body::SIGNATURE_ENVELOPE_LEN;

/// Longest head this client will buffer while looking for `\r\n\r\n`. The
/// ruled head is a status line and two headers — well under 200 bytes.
/// A stream that keeps flowing past this without terminating the head is
/// not stalled and is not the contract; it is [`Malformed::HeadTooLong`].
const MAX_HEAD_BYTES: usize = 1024;

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
    /// check tasks — see [`Self::fetch`] on cancellation.
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
    /// The expectation and the sink are per-`fetch`, not per-client: two
    /// callers share this admission path and each names *its* shard.
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

    /// Fetch `expected`'s shard from `target.endpoint`, carrying `header`,
    /// checking the body against `expected` transaction by transaction as
    /// it streams and handing each verified transaction to `sink`; return
    /// the shard's record only if the whole body matched and `P`'s
    /// countersignature verifies under `target.verifying_key`.
    ///
    /// Waits for an in-flight slot first; the slot is held until the
    /// result is decided. The body is never resident whole (`SF-D8`
    /// amendment 2026-10-08): the frame is read as `version ‖ tx_count ‖
    /// per tx (pqc_auth_count, pqc_auths_len, prunable_len, pqc_auths
    /// bytes ‖ prunable bytes)`, each entry's declared lengths are checked
    /// against its retained row **before** its segments are read (a `P`
    /// declaring a length the rows do not allow is refused without the
    /// client allocating for it), and each entry's two segments are hashed
    /// against the rows, folded into the view hash and handed to `sink` on
    /// the blocking pool, then dropped. The delivery digest folds every
    /// body byte, frame bytes included, under this request's nonce.
    ///
    /// Refusal order, by what each outcome is evidence of: a frame that is
    /// not the grammar, or does not end where the envelope begins, is
    /// [`Malformed`] where it is seen — `P` is off the contract. A frame
    /// whose content is not the expectation is remembered, the rest of the
    /// body is drained into the digest, and the envelope is read: a
    /// refusal trailer is [`FetchError::Unsigned`], a signature that does
    /// not verify is [`FetchError::BadCountersignature`], and only a
    /// signature that **does** verify makes the mismatch
    /// [`FetchError::ContentRefused`] — `P`'s own statement that it served
    /// these bytes for this request. A mismatch behind a bad signature says
    /// nothing about `P`'s content.
    ///
    /// Cancellation: dropping the future closes the stream and releases the
    /// slot — **once the fetch is actually over**. A `spawn_blocking` task
    /// does not stop when its handle is dropped, so if the future is
    /// dropped during an entry's check the entry, the sink call and the
    /// final verify run to their end; the slot travels through those tasks
    /// and is released by the last of them, not by the drop. Otherwise
    /// repeated cancellation during a check would let the next fetch take
    /// the slot while the last entry is still resident, and `MAX_INFLIGHT`
    /// would bound admissions rather than resident work. Nothing is decided
    /// about `P` by a fetch that was not allowed to finish.
    ///
    /// # Errors
    ///
    /// The [`FetchError`] taxonomy. [`FetchError::retries_same_p`] is the
    /// one-bit summary a scheduler needs.
    pub async fn fetch(
        &self,
        target: &FetchTarget,
        header: &RequestHeader,
        expected: &ExpectedShard,
        sink: Arc<dyn TxSink>,
    ) -> Result<VerifiedShard, FetchError> {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("in-flight semaphore is never closed");

        let shard_id = expected.shard_id();
        let mut stream = self.dial(&target.endpoint, header).await?;
        let request = request_bytes(shard_id.to_raw(), header);
        timeout(self.timeouts.head, stream.write_all(&request))
            .await
            .map_err(|_| FetchError::Stall(Stall::HeadTimeout))?
            // No complete head: a write error is the same class as a mid-head
            // close, not a short body (`Stall::Io` is body-phase only).
            .map_err(|_| FetchError::Stall(Stall::ClosedBeforeHead))?;

        let (head, carried) = read_head(&mut stream, self.timeouts.head).await?;
        let head = parse_head(&head)?;
        let envelope_len = u64::try_from(SIGNATURE_ENVELOPE_LEN).expect("envelope fits u64");
        // A bare answer's verdict, or `None` for a 200.
        let bare = match head.status {
            400 | 404 | 503 => {
                if head.content_length != 0 {
                    return Err(FetchError::Malformed(Malformed::ContentLength));
                }
                Some(match head.status {
                    400 => FetchError::Rejected,
                    404 => FetchError::Miss,
                    _ => FetchError::Unavailable,
                })
            }
            200 => {
                let declared = head.content_length;
                if declared < envelope_len {
                    return Err(FetchError::Malformed(Malformed::EnvelopeShort { declared }));
                }
                let max = expected.max_response_len();
                if declared > max {
                    return Err(FetchError::Malformed(Malformed::Oversize { declared, max }));
                }
                None
            }
            other => return Err(FetchError::Malformed(Malformed::Status(other))),
        };

        // Every answer is read to the same standard: exactly the declared
        // bytes, then `P`'s close. A bare answer is a *completed* exchange
        // only if it completes — a "no" with bytes behind it is not the
        // bare answer, it is a `P` off the contract. And a 200 that stops
        // short is a stall at every offset: nothing is concluded about `P`
        // from where a stream ended.
        let mut reader = BodyReader::new(
            &mut stream,
            carried,
            head.content_length,
            header,
            self.timeouts.body_stall,
        )?;
        if let Some(verdict) = bare {
            match timeout(self.timeouts.body_total, reader.close_probe()).await {
                Err(_elapsed) => return Err(FetchError::Stall(Stall::BodyTimeout)),
                Ok(probe) => probe?,
            }
            return Err(verdict);
        }

        let checker = Checker::new(slot, shard_id, sink);
        let streamed = async {
            let (checker, mismatch) = read_frame(&mut reader, expected, checker).await?;
            let envelope = reader.envelope().await?;
            reader.close_probe().await?;
            Ok::<_, FetchError>((checker, mismatch, envelope, reader.finish()))
        };
        let (checker, mismatch, envelope, delivery_digest) =
            match timeout(self.timeouts.body_total, streamed).await {
                Err(_elapsed) => return Err(FetchError::Stall(Stall::BodyTimeout)),
                Ok(outcome) => outcome?,
            };
        drop(stream);

        // The envelope is the body's tail. If it is the refusal trailer,
        // `P` has said it served and did not sign. That is read before
        // anything is verified, and the body behind it goes no further.
        if is_refusal_trailer(&envelope) {
            return Err(FetchError::Unsigned);
        }

        // Off the executor: a hybrid verify is real CPU. The slot goes with
        // the checker: it is dropped when this closure returns, whether or
        // not anyone is still awaiting the handle.
        let (verifying_key, header) = (target.verifying_key.clone(), *header);
        let (tx_count, archival_len) = (expected.tx_count(), expected.archival_len());
        tokio::task::spawn_blocking(move || {
            let checker = checker;
            let signature = HybridSignature::from_canonical_bytes(&envelope)
                .map_err(|_| FetchError::Malformed(Malformed::Envelope))?;
            // The digest was recomputed from the bytes as they arrived
            // under this request's own nonce, never taken from `P`: a
            // signature over any other bytes, or over these bytes for
            // another request, fails this check.
            verify_pass_transcript(
                &verifying_key,
                header.nonce(),
                header.anchor_height(),
                header.anchor_hash(),
                shard_id.to_raw(),
                &delivery_digest,
                &signature,
            )
            .map_err(|_| FetchError::BadCountersignature)?;
            if let Some(mismatch) = mismatch {
                return Err(FetchError::ContentRefused(mismatch));
            }
            Ok(VerifiedShard::new(
                shard_id,
                delivery_digest,
                signature,
                checker.finish(),
                tx_count,
                archival_len,
            ))
        })
        .await
        .expect("verify task does not panic")
    }

    /// SOCKS5h dial: the proxy receives the `.onion` **name** (ATYP=DOMAIN)
    /// and resolves it. Passing a pre-resolved address here is the DNS
    /// leak `SF-D2` exists to close; there is no code path that could,
    /// because an onion has no IP to resolve to — but the shape is kept
    /// deliberately so a future non-onion endpoint would not acquire one.
    ///
    /// The dial presents this read's SOCKS credentials, taken from its
    /// header, as [`Isolation::Persona`]. Each read is on a circuit of its
    /// own (`SF-D3`, as ruled 2026-10-07) because the header's nonce is a
    /// username no other read presents. There is no caller argument for
    /// the credentials: challenge and organic reads cannot differ here.
    async fn dial(
        &self,
        endpoint: &ServingEndpoint,
        header: &RequestHeader,
    ) -> Result<TcpStream, FetchError> {
        let host = endpoint.onion_address();
        let credentials = header.socks_credentials();
        let connect = async {
            let mut stream = TcpStream::connect(self.proxy)
                .await
                .map_err(|err| FetchError::Stall(Stall::Dial(err.to_string())))?;
            socks_connect(
                &mut stream,
                Isolation::Persona(&credentials),
                Destination::Name {
                    host: host.as_str(),
                    port: SERVING_VIRTUAL_PORT,
                },
            )
            .await
            .map_err(|err| FetchError::Stall(Stall::Dial(err.to_string())))?;
            Ok(stream)
        };
        match timeout(self.timeouts.dial, connect).await {
            Err(_elapsed) => Err(FetchError::Stall(Stall::DialTimeout)),
            Ok(result) => result,
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

    /// The one-machinery rule (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.1): the
    /// request is a function of the shard and the caller's header and of
    /// nothing else, so a challenge and an organic read of one shard differ
    /// on the wire only where their nonces do. There is no caller kind to
    /// pass, which is the rule's other half and is held by the signature.
    #[test]
    fn a_request_differs_from_another_only_in_its_nonce() {
        let anchor = BlockHeight::from_raw(1_000);
        let organic = RequestHeader::with_nonce([0xa5; 32], anchor, [3; 32]);
        let challenge = RequestHeader::with_nonce([0x5a; 32], anchor, [3; 32]);
        let a = request_bytes(7, &organic);
        let b = request_bytes(7, &challenge);
        assert_eq!(a.len(), b.len());

        // The nonce leads the header, as 64 lowercase hex characters.
        let nonce_hex: String = organic.nonce().iter().map(|x| format!("{x:02x}")).collect();
        let text = String::from_utf8(a.clone()).unwrap();
        let start = text.find(&nonce_hex).expect("the nonce is on the wire");
        let nonce_span = start..start + nonce_hex.len();

        let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        assert!(!differing.is_empty(), "two nonces, one request");
        assert!(
            differing.iter().all(|i| nonce_span.contains(i)),
            "a byte outside the nonce differs: {differing:?} against {nonce_span:?}"
        );
        // Every nonce byte differs here, so the whole span is accounted for.
        assert_eq!(differing.len(), nonce_span.len());

        // The same header is the same request: nothing ambient enters.
        assert_eq!(a, request_bytes(7, &organic));
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
