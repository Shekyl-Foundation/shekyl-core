// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One HTTP connection over one record stream.

use std::future::Future;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::SubmissionMark;
use shekyl_rpc_types::method::RpcMethod;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use super::handshake::Opened;
use super::ChannelFault;

/// One HTTP connection over one record stream (§13, RT-W11's client
/// contracts): hyper's `client::conn::http1`, never a pooled client.
pub struct Session {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    /// Ends when the task driving the connection drops its half
    /// ([`unless_ended`]).
    connection_end: ConnectionEnd,
    mark: SubmissionMark,
    ceiling: GrantSet,
    granted: GrantSet,
    /// The daemon has opened this session's first record. A session that
    /// will sit idle must send one (`version`) before it is parked; a
    /// session whose caller sends at once uses that request as the record.
    confirmed: bool,
}

/// The session's half of the connection task's lifetime. [`ConnectionEnd::wait`]
/// completes when the task drops [`ConnectionHeld`]. The task holds that half
/// and drops it after the connection future ends, including when the task
/// itself is dropped. A response the connection already delivered is taken
/// first ([`unless_ended`]).
///
/// The watch sender lives here, and the receiver with the task. `closed`
/// waits until every receiver is gone, which is the task's half. A fresh
/// receiver's `changed` completes at once on the value it was created with,
/// so that future cannot mean "the task ended".
struct ConnectionEnd {
    waiter: watch::Sender<()>,
}

/// The task's half. Dropping it is the connection ending.
struct ConnectionHeld {
    _receiver: watch::Receiver<()>,
}

impl ConnectionEnd {
    /// The task keeps `held` until the connection future has ended.
    fn hold() -> (Self, ConnectionHeld) {
        let (waiter, receiver) = watch::channel(());
        (
            Self { waiter },
            ConnectionHeld {
                _receiver: receiver,
            },
        )
    }

    /// Completes once the task has dropped its half. Cancel-safe: dropping
    /// the future leaves the sender as it was.
    fn wait(&self) -> impl Future<Output = ()> + '_ {
        self.waiter.closed()
    }
}

/// `response`, or `None` once the task driving the connection has ended,
/// when no response can come. hyper can report a connection ready as it
/// shuts down, and a request sent in that moment is then never answered: on
/// a session idle for up to an hour, the call would wait that long. A
/// response already here is taken first, so a delivered answer is not lost
/// to a connection that ends in the same poll.
async fn unless_ended<F: Future>(response: F, end: &ConnectionEnd) -> Option<F::Output> {
    tokio::select! {
        biased;
        output = response => Some(output),
        () = end.wait() => None,
    }
}

/// Whether a JSON-RPC body calls `tx_submit`: the one method whose message
/// is padded to the submission's fixed size (RT-O28).
#[must_use]
pub fn is_submission(body: &[u8]) -> bool {
    use shekyl_rpc_types::method::RpcMethod;
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|request| {
            request
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(|method| method == shekyl_rpc_types::wire::TxSubmit::NAME)
        })
        .unwrap_or(false)
}

impl Session {
    /// Start HTTP over `opened`. The first record is not sent here: the
    /// daemon finishes the handshake, and starts the session's idle, only
    /// when that record arrives (`RPC_CHANNEL.md` §4.3). A caller that
    /// sends at once uses its request as the record. A caller that parks
    /// the session sends one first, with [`Self::confirm`].
    ///
    /// `idle` is how long the session may wait between records before the
    /// stream closes it; `None` keeps the stream's own limit.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when hyper cannot start on the stream.
    pub async fn start<S>(opened: Opened<S>, idle: Option<Duration>) -> Result<Self, ChannelFault>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Opened {
            mut stream,
            ceiling,
            granted,
        } = opened;
        if let Some(idle) = idle {
            stream.set_idle(idle);
        }
        let mark = stream.submission_mark();
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ChannelFault::Closed)?;
        let (connection_end, held) = ConnectionEnd::hold();
        tokio::spawn(async move {
            // Dropped when this task ends, after `connection` has. A response
            // it delivered is already there for the biased select.
            let _held = held;
            if let Err(error) = connection.await {
                tracing::debug!("channel session ended: {error}");
            }
        });
        Ok(Self {
            sender,
            connection_end,
            mark,
            ceiling,
            granted,
            confirmed: false,
        })
    }

    /// Send the first record when this session would otherwise sit idle.
    ///
    /// The record is `version`, which every admitted key may call. A
    /// session that has already sent is left as it is. The daemon closes a
    /// session that never sends one, at the handshake deadline, so a parked
    /// session would be opened again forever.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the node drops the session before
    /// `version` is answered. [`ChannelFault::SessionCap`] when that answer
    /// is `bound.sessions`: the session was not admitted.
    /// [`ChannelFault::Local`] when the request cannot be built.
    pub async fn confirm(&mut self) -> Result<(), ChannelFault> {
        if self.confirmed {
            return Ok(());
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": shekyl_rpc_types::wire::Version::NAME,
            "params": {}
        }))
        .map_err(|error| ChannelFault::Local(error.to_string()))?;
        // A close before any answer is `Closed`. A `bound.sessions` answer
        // means this session was not admitted. Any other answer, including
        // a method refusal, means the node admitted the session.
        let response = self.post("json_rpc", body).await?;
        admission(&response)?;
        self.confirmed = true;
        Ok(())
    }

    /// This client's ceiling on the daemon.
    #[must_use]
    pub fn ceiling(&self) -> GrantSet {
        self.ceiling
    }

    /// What this session holds.
    #[must_use]
    pub fn granted(&self) -> GrantSet {
        self.granted
    }

    /// Whether the daemon has closed the session.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Send one request, its body whole, and read its whole response. A
    /// body that calls `tx_submit` is sent with the submission mark armed,
    /// as one complete body (`Full`); the session carries nothing else
    /// until the response.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub async fn send(
        &mut self,
        request: hyper::Request<Bytes>,
    ) -> Result<hyper::Response<Bytes>, ChannelFault> {
        self.sender
            .ready()
            .await
            .map_err(|_| ChannelFault::Closed)?;
        if request.method() == hyper::Method::POST && is_submission(request.body()) {
            self.mark.arm();
        }
        let response = unless_ended(
            self.sender.send_request(request.map(Full::new)),
            &self.connection_end,
        )
        .await
        .ok_or(ChannelFault::Closed)?
        .map_err(|_| ChannelFault::Closed)?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| ChannelFault::Closed)?
            .to_bytes();
        // The first record has been opened. A session-cap refusal is not
        // admission: the node closed this connection, and a later confirm
        // must not treat the session as established.
        if admission(&body).is_ok() {
            self.confirmed = true;
        }
        Ok(hyper::Response::from_parts(parts, body))
    }

    /// POST `body` to `route` and return the response's body.
    ///
    /// # Errors
    ///
    /// [`ChannelFault::Closed`] when the session ends under the request.
    pub async fn post(&mut self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, ChannelFault> {
        let request = hyper::Request::post(format!("/{}", route.trim_start_matches('/')))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .header(hyper::header::HOST, "localhost")
            .body(Bytes::from(body))
            .map_err(|e| ChannelFault::Local(e.to_string()))?;
        Ok(self.send(request).await?.into_body().to_vec())
    }
}

/// The diagnostic a session past its key's cap carries (`IG-Q79`). The
/// daemon spells it `methods::codes::BOUND_SESSIONS`; this is that spelling
/// on the wire.
const BOUND_SESSIONS: &str = "bound.sessions";

/// Whether `body` shows the node admitted the session.
///
/// `bound.sessions` is the one refusal that means it did not: the first
/// request was answered and the connection closed. A result, and every
/// other method refusal, means the session is in the node's index.
fn admission(body: &[u8]) -> Result<(), ChannelFault> {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")?
                .get("data")?
                .get("code")?
                .as_str()
                .map(str::to_owned)
        });
    if code.as_deref() == Some(BOUND_SESSIONS) {
        Err(ChannelFault::SessionCap)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request left on a dead connection must end inside this. The idle
    /// it replaces is an hour.
    const DEAD_CONNECTION_BOUND: Duration = Duration::from_secs(60);

    /// A request ends when its connection does, rather than waiting for a
    /// response nothing will send, and not before the connection does.
    /// Once ended, it stays ended. Red edit: drop the `end.wait()` branch
    /// in `unless_ended`, and this waits out its limit.
    #[tokio::test]
    async fn a_request_ends_when_its_connection_does() {
        let (end, held) = ConnectionEnd::hold();
        let mut waiting = std::pin::pin!(unless_ended(std::future::pending::<u8>(), &end));
        tokio::select! {
            biased;
            _ = &mut waiting => panic!("the request ended before its connection"),
            () = tokio::task::yield_now() => {}
        }
        drop(held);
        let got = tokio::time::timeout(DEAD_CONNECTION_BOUND, waiting).await;
        assert_eq!(got.expect("the request ended with its connection"), None);
        assert_eq!(unless_ended(std::future::pending::<u8>(), &end).await, None);
    }

    /// A response that has arrived is kept when the connection has ended
    /// too. Red edit: drop `biased` in `unless_ended`, and it is lost.
    #[tokio::test]
    async fn a_response_already_here_outlives_its_connection() {
        let (end, held) = ConnectionEnd::hold();
        drop(held);
        assert_eq!(unless_ended(std::future::ready(7_u8), &end).await, Some(7));
    }

    /// A `tx_submit` body is a submission; another method, or a body that
    /// is not JSON-RPC, is not. Red edit: compare against `"tx_relay"` in
    /// `is_submission`, and a submission goes unpadded.
    #[test]
    fn a_submission_is_known_by_its_method() {
        assert!(is_submission(
            br#"{"jsonrpc":"2.0","id":1,"method":"tx_submit","params":{"body":"aa"}}"#
        ));
        assert!(!is_submission(
            br#"{"jsonrpc":"2.0","id":1,"method":"tx_relay","params":{}}"#
        ));
        assert!(!is_submission(b"not json"));
    }

    /// `bound.sessions` is not admission. Another refusal, and a result,
    /// are. Red edit: treat every error object as success in `admission`,
    /// and the cap refusal confirms the session.
    #[test]
    fn a_session_cap_refusal_is_not_admission() {
        let cap = br#"{"jsonrpc":"2.0","id":"1","error":{"code":-32003,"message":"over","data":{"code":"bound.sessions"}}}"#;
        assert_eq!(admission(cap), Err(ChannelFault::SessionCap));
        let unready = br#"{"jsonrpc":"2.0","id":"1","error":{"code":-32001,"message":"not ready","data":{"code":"daemon.unready"}}}"#;
        assert!(admission(unready).is_ok());
        assert!(admission(br#"{"jsonrpc":"2.0","id":"1","result":{"version":1}}"#).is_ok());
    }
}
