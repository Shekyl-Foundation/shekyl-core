// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One HTTP connection over one record stream.

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use shekyl_rpc_grants::GrantSet;
use shekyl_rpc_stream::SubmissionMark;
use tokio::io::{AsyncRead, AsyncWrite};

use super::handshake::Opened;
use super::ChannelFault;

/// One HTTP connection over one record stream (§13, RT-W11's client
/// contracts): hyper's `client::conn::http1`, never a pooled client.
pub struct Session {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    mark: SubmissionMark,
    ceiling: GrantSet,
    granted: GrantSet,
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
    /// Start HTTP over `opened`. `idle` is how long the session may wait
    /// between records before the stream closes it; `None` keeps the
    /// stream's own limit.
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
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("channel session ended: {error}");
            }
        });
        Ok(Self {
            sender,
            mark,
            ceiling,
            granted,
        })
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
        let response = self
            .sender
            .send_request(request.map(Full::new))
            .await
            .map_err(|_| ChannelFault::Closed)?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| ChannelFault::Closed)?
            .to_bytes();
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
