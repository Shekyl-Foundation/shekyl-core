// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The byte copy and the HTTP/1.1 split for the RT-P5 sizes instrument.
//!
//! A `#[path]` child of the cell runner. The proxy forwards every byte
//! unchanged and keeps a copy. The copy is split into messages only after
//! the traffic has stopped, so a parsing defect cannot disturb what it
//! measures, and every byte belongs to exactly one message.

// The production debug-macro lint treats a file as test code only when the
// file itself carries this attribute. The parent harness is already
// test-only; this sibling has to say so on its own.
#![cfg(test)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

/// The bytes of one proxied connection, each direction as it crossed.
#[derive(Default)]
pub(super) struct Captured {
    to_daemon: Vec<u8>,
    to_wallet: Vec<u8>,
    /// A read or write that failed. Any entry fails the run: a message
    /// cut short by the proxy is not the daemon's message.
    faults: Vec<String>,
}

/// A TCP proxy on loopback that forwards every byte unchanged and keeps a
/// copy, one [`Captured`] per accepted connection.
pub(super) struct CountingProxy {
    pub(super) port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    conns: Arc<Mutex<Vec<Arc<Mutex<Captured>>>>>,
    pumps: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl CountingProxy {
    pub(super) fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let conns: Arc<Mutex<Vec<Arc<Mutex<Captured>>>>> = Arc::default();
        let pumps: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let accept = {
            let stop = stop.clone();
            let conns = conns.clone();
            let pumps = pumps.clone();
            std::thread::spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(wallet_side) = incoming else { continue };
                    let daemon_side = TcpStream::connect(("127.0.0.1", upstream))
                        .expect("the proxy reaches the daemon");
                    let captured = Arc::new(Mutex::new(Captured::default()));
                    conns.lock().expect("conns").push(captured.clone());
                    let up = (
                        wallet_side.try_clone().expect("clone"),
                        daemon_side.try_clone().expect("clone"),
                    );
                    let down = (daemon_side, wallet_side);
                    let c_up = captured.clone();
                    let mut held = pumps.lock().expect("pumps");
                    held.push(std::thread::spawn(move || pump(up.0, up.1, &c_up, true)));
                    held.push(std::thread::spawn(move || {
                        pump(down.0, down.1, &captured, false);
                    }));
                }
            })
        };
        Self {
            port,
            stop,
            accept: Some(accept),
            conns,
            pumps,
        }
    }

    /// Stop accepting, wait for every connection to close, and hand back
    /// what crossed. A connection still open after `wait` fails the run:
    /// its last message may be incomplete.
    pub(super) fn finish(mut self, wait: Duration) -> Vec<Captured> {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept; the flag above makes it exit.
        drop(TcpStream::connect(("127.0.0.1", self.port)));
        if let Some(accept) = self.accept.take() {
            accept.join().expect("the accept thread exits");
        }
        let deadline = Instant::now() + wait;
        loop {
            let open = self
                .pumps
                .lock()
                .expect("pumps")
                .iter()
                .filter(|p| !p.is_finished())
                .count();
            if open == 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{open} proxied directions were still open {wait:?} after the wallets closed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let conns = std::mem::take(&mut *self.conns.lock().expect("conns"));
        conns
            .into_iter()
            .map(|c| {
                let captured = Arc::try_unwrap(c)
                    .ok()
                    .expect("no pump still holds a capture")
                    .into_inner()
                    .expect("capture");
                assert!(
                    captured.faults.is_empty(),
                    "the proxy faulted: {:?}",
                    captured.faults
                );
                captured
            })
            .collect()
    }
}

/// Copy `from` to `to` until `from` closes, recording each chunk before it
/// is forwarded; then close `to`'s write half so the peer sees the end.
fn pump(mut from: TcpStream, mut to: TcpStream, sink: &Mutex<Captured>, to_daemon: bool) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                {
                    let mut c = sink.lock().expect("capture");
                    if to_daemon {
                        c.to_daemon.extend_from_slice(&buf[..n]);
                    } else {
                        c.to_wallet.extend_from_slice(&buf[..n]);
                    }
                }
                if let Err(e) = to.write_all(&buf[..n]) {
                    sink.lock()
                        .expect("capture")
                        .faults
                        .push(format!("write: {e}"));
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // A reset by the closing side after its last message is how a
            // pooled connection ends; whether anything was cut short is the
            // parser's to say, since every byte must belong to a message.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => {
                sink.lock()
                    .expect("capture")
                    .faults
                    .push(format!("read: {e}"));
                break;
            }
        }
    }
    drop(to.shutdown(Shutdown::Write));
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// One HTTP/1.1 message's bytes, by part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Message {
    /// Start line and headers, through the blank line.
    pub(super) head: usize,
    /// The body's content bytes.
    pub(super) body: usize,
    /// Chunked framing: the size lines, their line ends, the last chunk and
    /// any trailers. Zero for a body with a `Content-Length`.
    pub(super) framing: usize,
    /// For a request, the method it calls: the path, or `json_rpc:` and the
    /// JSON-RPC `method` for a call to `/json_rpc`. Empty for a response.
    pub(super) label: String,
}

impl Message {
    pub(super) fn total(&self) -> usize {
        self.head + self.body + self.framing
    }
}

/// Why a stream could not be split into whole messages.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParseFault {
    /// Bytes remained that do not form a whole message.
    Incomplete { offset: usize },
    /// A header line or chunk size that is not well formed.
    Malformed { offset: usize, what: &'static str },
    /// A different number of requests and responses on one connection.
    Unpaired { requests: usize, responses: usize },
}

impl std::fmt::Display for ParseFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete { offset } => write!(f, "an incomplete message at byte {offset}"),
            Self::Malformed { offset, what } => write!(f, "{what} at byte {offset}"),
            Self::Unpaired {
                requests,
                responses,
            } => write!(f, "{requests} requests against {responses} responses"),
        }
    }
}

/// Split one connection into (request, response) pairs, in order, the
/// response labelled as its request.
pub(super) fn pair_messages(captured: &Captured) -> Result<Vec<(Message, Message)>, ParseFault> {
    let requests = split(&captured.to_daemon, true)?;
    let responses = split(&captured.to_wallet, false)?;
    if requests.len() != responses.len() {
        return Err(ParseFault::Unpaired {
            requests: requests.len(),
            responses: responses.len(),
        });
    }
    Ok(requests.into_iter().zip(responses).collect())
}

/// Split a stream into whole messages. Every byte must belong to one.
fn split(stream: &[u8], requests: bool) -> Result<Vec<Message>, ParseFault> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < stream.len() {
        let (message, used) = one_message(&stream[at..], requests).map_err(|f| match f {
            ParseFault::Incomplete { offset } => ParseFault::Incomplete {
                offset: at + offset,
            },
            ParseFault::Malformed { offset, what } => ParseFault::Malformed {
                offset: at + offset,
                what,
            },
            other => other,
        })?;
        out.push(message);
        at += used;
    }
    Ok(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One message from the front of `bytes`, and how many bytes it used.
fn one_message(bytes: &[u8], request: bool) -> Result<(Message, usize), ParseFault> {
    let head = find(bytes, b"\r\n\r\n").ok_or(ParseFault::Incomplete { offset: 0 })? + 4;
    let text = std::str::from_utf8(&bytes[..head]).map_err(|_| ParseFault::Malformed {
        offset: 0,
        what: "a head that is not UTF-8",
    })?;
    let mut lines = text.split("\r\n");
    let start = lines.next().unwrap_or_default();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(ParseFault::Malformed {
            offset: 0,
            what: "a header line without a colon",
        })?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.parse::<usize>().map_err(|_| ParseFault::Malformed {
                offset: 0,
                what: "a Content-Length that is not a number",
            })?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|c| c.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    let (body, framing) = if chunked {
        chunked_body(&bytes[head..]).map_err(|f| match f {
            ParseFault::Incomplete { offset } => ParseFault::Incomplete {
                offset: head + offset,
            },
            ParseFault::Malformed { offset, what } => ParseFault::Malformed {
                offset: head + offset,
                what,
            },
            other => other,
        })?
    } else {
        let n = content_length.unwrap_or(0);
        if bytes.len() < head + n {
            return Err(ParseFault::Incomplete { offset: 0 });
        }
        (n, 0)
    };
    // Requests this harness labels carry `Content-Length`. A chunked
    // `/json_rpc` body has no bytes the label can read; the run refuses
    // the `(unreadable)` that produces.
    let labelled: &[u8] = if request && !chunked {
        &bytes[head..head + body]
    } else {
        b""
    };
    let label = if request {
        request_label(start, labelled)
    } else {
        String::new()
    };
    let used = head + body + framing;
    Ok((
        Message {
            head,
            body,
            framing,
            label,
        },
        used,
    ))
}

/// A chunked body's content bytes and its framing bytes. A zero-length
/// chunk ends the body; trailers, if any, count as framing.
fn chunked_body(bytes: &[u8]) -> Result<(usize, usize), ParseFault> {
    let mut at = 0;
    let mut body = 0;
    let mut framing = 0;
    loop {
        let line_end = find(&bytes[at..], b"\r\n").ok_or(ParseFault::Incomplete { offset: at })?;
        let line =
            std::str::from_utf8(&bytes[at..at + line_end]).map_err(|_| ParseFault::Malformed {
                offset: at,
                what: "a chunk size line that is not UTF-8",
            })?;
        let size_hex = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| ParseFault::Malformed {
            offset: at,
            what: "a chunk size that is not hex",
        })?;
        framing += line_end + 2;
        at += line_end + 2;
        if size == 0 {
            // Trailers, if any, then the blank line.
            loop {
                let end =
                    find(&bytes[at..], b"\r\n").ok_or(ParseFault::Incomplete { offset: at })?;
                framing += end + 2;
                at += end + 2;
                if end == 0 {
                    return Ok((body, framing));
                }
            }
        }
        if bytes.len() < at + size + 2 {
            return Err(ParseFault::Incomplete { offset: at });
        }
        if &bytes[at + size..at + size + 2] != b"\r\n" {
            return Err(ParseFault::Malformed {
                offset: at + size,
                what: "a chunk not followed by a line end",
            });
        }
        body += size;
        framing += 2;
        at += size + 2;
    }
}

/// The method a request calls: its path, or `json_rpc:<method>` for a
/// JSON-RPC call.
fn request_label(start_line: &str, body: &[u8]) -> String {
    let path = start_line.split(' ').nth(1).unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();
    if path == "/json_rpc" {
        let method = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("method").and_then(|m| m.as_str()).map(str::to_owned))
            .unwrap_or_else(|| "(unreadable)".to_owned());
        format!("json_rpc:{method}")
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn captured(to_daemon: &[u8], to_wallet: &[u8]) -> Captured {
        Captured {
            to_daemon: to_daemon.to_vec(),
            to_wallet: to_wallet.to_vec(),
            faults: Vec::new(),
        }
    }

    const REQ: &[u8] = b"POST /json_rpc HTTP/1.1\r\nhost: 127.0.0.1:1\r\ncontent-length: 34\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"get_x\"}";
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";

    /// Every byte is counted once, and the parts add up to the stream.
    #[test]
    fn a_length_delimited_pair_is_counted_whole() {
        let pairs = pair_messages(&captured(REQ, RESP)).expect("parses");
        assert_eq!(pairs.len(), 1);
        let (request, response) = &pairs[0];
        assert_eq!(request.label, "json_rpc:get_x");
        assert_eq!(request.total(), REQ.len());
        assert_eq!(request.body, 34);
        assert_eq!(response.total(), RESP.len());
    }

    /// Two messages back to back on one connection split at the boundary.
    #[test]
    fn pipelined_messages_split_at_their_boundary() {
        let two_req = [REQ, b"GET /get_height HTTP/1.1\r\nhost: a\r\n\r\n"].concat();
        let two_resp = [RESP, RESP].concat();
        let pairs = pair_messages(&captured(&two_req, &two_resp)).expect("parses");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[1].0.label, "/get_height");
        let sum: usize = pairs.iter().map(|(q, _)| q.total()).sum();
        assert_eq!(sum, two_req.len());
    }

    /// Chunked framing is counted as framing, not as body, and in the total.
    #[test]
    fn chunked_framing_is_counted() {
        let resp = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nt: v\r\n\r\n";
        let (message, used) = one_message(resp, false).expect("parses");
        assert_eq!(used, resp.len());
        assert_eq!(message.body, 5);
        assert_eq!(message.total(), resp.len());
        assert_eq!(message.framing, resp.len() - message.head - 5);
    }

    /// A message cut short is a fault, never a smaller message.
    #[test]
    fn a_truncated_body_is_refused() {
        let cut = &REQ[..REQ.len() - 1];
        assert!(matches!(
            pair_messages(&captured(cut, RESP)),
            Err(ParseFault::Incomplete { .. })
        ));
        let no_blank_line = b"POST / HTTP/1.1\r\nhost: a\r\n";
        assert!(matches!(
            split(no_blank_line, true),
            Err(ParseFault::Incomplete { .. })
        ));
    }

    /// A request without its response is refused.
    #[test]
    fn an_unanswered_request_is_refused() {
        assert_eq!(
            pair_messages(&captured(REQ, b"")).unwrap_err(),
            ParseFault::Unpaired {
                requests: 1,
                responses: 0
            }
        );
    }

    /// A query string is not part of the method.
    #[test]
    fn a_rest_path_labels_without_its_query() {
        assert_eq!(
            request_label("POST /get_transactions?x=1 HTTP/1.1", b""),
            "/get_transactions"
        );
    }
}
