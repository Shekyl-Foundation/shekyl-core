// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A synchronous client for an external wallet RPC listener.

use crate::http_client::{HttpClient, TransportTls};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use zeroize::Zeroizing;

/// Preserve the previous wallet HTTP response limit, including chunked bodies.
const MAX_REPLY: usize = 10 * 1024 * 1024;

/// The HTTP client used by an interactive shell for a separately hosted wallet.
pub struct WalletHttp {
    client: HttpClient,
    uri: hyper::Uri,
    runtime: tokio::runtime::Runtime,
}

impl WalletHttp {
    /// Configure the wallet endpoint and optional remotely resolving SOCKS proxy.
    /// Nothing is sent until the first request.
    pub fn new(endpoint: &str, proxy: Option<&str>) -> Result<Self, String> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(
                "the synchronous wallet client needs a thread outside an async runtime".into(),
            );
        }
        let uri: hyper::Uri = format!(
            "{}{}",
            endpoint.trim_end_matches('/'),
            shekyl_rpc_types::endpoint::JSON_RPC_PATH
        )
        .parse()
        .map_err(|_| "invalid wallet RPC endpoint".to_owned())?;
        if uri.scheme_str() != Some("http") || uri.host().is_none() {
            return Err("use the local wallet RPC listener or an encrypted forward to it".into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let client = HttpClient::new(proxy, TransportTls::Off).map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            uri,
            runtime,
        })
    }

    /// Send the already serialized secret-bearing request. The body owns its
    /// original wiped allocation for as long as hyper can access the bytes.
    pub fn post(&self, body: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, String> {
        let request = hyper::Request::post(&self.uri)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_owner(body)))
            .map_err(|e| e.to_string())?;
        self.runtime.block_on(async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("wallet RPC returned HTTP {}", response.status()));
            }
            let body = Limited::new(response.into_body(), MAX_REPLY)
                .collect()
                .await
                .map_err(|e| format!("reading wallet RPC response: {e}"))?;
            Ok(Zeroizing::new(body.to_bytes().to_vec()))
        })
    }
}
