// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One loopback conversation between [`PServeEndpoint`] and [`PFetchClient`].
//!
//! `SF-D4` cuts the two crates apart on every shipped graph, so neither
//! library can own the harness the other calls. A copied SOCKS5 accept
//! loop had already drifted (different body timeouts, two parsers). This
//! crate is the one copy. It is a dev-dependency of both ends and of the
//! wallet's proving test. Nothing in `cmake/BuildRust.cmake` builds it.
//!
//! The shim accepts the username/password greeting
//! `shekyl_socks::Isolation::Persona` sends and tunnels the CONNECT to the
//! endpoint. It does not read the credentials: isolation is the tor proxy's
//! job, and this stands in for that proxy. The name the client sends is not
//! resolved.
//!
//! The types a caller has to name are re-exported. A proving test then
//! dev-depends on this crate and not on either end.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_archival_retention::{PASS_ANCHOR_HASH_LEN, PASS_NONCE_LEN};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_curve_tree::LEAF_BYTES;
use shekyl_p_fetch::{ContentRefused, ContentVerify};
use shekyl_p_serve::{PassSigner, ProviderError, ShardBody, ShardProvider};
use shekyl_socks::accept_userpass;
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub use shekyl_p_fetch::{
    FetchError, FetchTarget, PFetchClient, RequestHeader, ServingEndpoint, Timeouts,
};
pub use shekyl_p_serve::PServeEndpoint;

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const RSV: u8 = 0x00;
const SUCCEEDED: u8 = 0x00;
const ATYP_V4: u8 = 0x01;
const ATYP_NAME: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const V4_ADDR_LEN: usize = 4;
const V6_ADDR_LEN: usize = 16;
const PORT_LEN: usize = 2;

/// Distinct from the anchor-hash byte, so a swapped header field fails a
/// comparison with a header built here.
const FIXTURE_NONCE_BYTE: u8 = 0xa5;
/// Distinct from the nonce byte. See [`FIXTURE_NONCE_BYTE`].
const FIXTURE_ANCHOR_HASH_BYTE: u8 = 0x5a;
/// Record-column filler. The shim never resolves the onion name these
/// bytes become. The width is what [`ServingEndpoint::from_record_bytes`]
/// takes.
const UNRESOLVED_ENDPOINT: [u8; 32] = [0x42; 32];

/// The shard [`endpoint_and_client`] is usually asked to hold.
///
/// Callers pass it so a second id (`FIXTURE_SHARD_ID + 1`) is a miss against
/// the same endpoint. The value itself is not a protocol constant.
pub const FIXTURE_SHARD_ID: u64 = 3;

/// Bytes that fill one leaf and no more, so a served frame of this body
/// declares `leaf_count == 1`. The modulus keeps the bytes from being a
/// run of zeroes; a swapped envelope and frame fails a comparison with it.
#[must_use]
pub fn one_leaf() -> Arc<[u8]> {
    const DISTINCT: usize = 251;
    let bytes: Vec<u8> = (0..LEAF_BYTES)
        .map(|i| u8::try_from(i % DISTINCT).expect("modulus fits in a byte"))
        .collect();
    Arc::from(bytes)
}

/// A request header with the fixture nonce and anchor hash, at `anchor`.
#[must_use]
pub fn request_header(anchor: BlockHeight) -> RequestHeader {
    RequestHeader::with_nonce(
        [FIXTURE_NONCE_BYTE; PASS_NONCE_LEN],
        anchor,
        [FIXTURE_ANCHOR_HASH_BYTE; PASS_ANCHOR_HASH_LEN],
    )
}

/// A target whose endpoint the shim does not resolve.
///
/// `verifying_key` is the caller's: the bond identity, an ephemeral test
/// key, or a key that must not verify.
#[must_use]
pub fn fetch_target(verifying_key: HybridPublicKey, shard_id: u64) -> FetchTarget {
    FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes(UNRESOLVED_ENDPOINT),
        verifying_key,
        shard_id,
    }
}

/// [`ContentVerify`] that accepts every body. Tests that parse the frame
/// do that on the returned bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct AcceptAny;

impl ContentVerify for AcceptAny {
    fn verify(&self, _shard_id: u64, _body: &[u8]) -> Result<(), ContentRefused> {
        Ok(())
    }
}

struct OneShard {
    shard_id: u64,
    body: Arc<[u8]>,
}

impl ShardProvider for OneShard {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        if shard_id != self.shard_id {
            return Ok(None);
        }
        // A body that is not a whole number of leaves is a miss. Callers
        // that want a served frame pass `one_leaf` or a multiple of it.
        Ok(ShardBody::flat(Arc::clone(&self.body)))
    }
}

/// Bind `signer` over `body` at `shard_id`, and a client aimed at that
/// endpoint through a SOCKS5 no-auth shim.
///
/// # Panics
///
/// Panics if the endpoint or the shim cannot bind a loopback port. Both
/// are local and free; a failure is a broken test host.
pub async fn endpoint_and_client(
    shard_id: u64,
    body: Arc<[u8]>,
    signer: Arc<dyn PassSigner>,
    timeouts: Timeouts,
) -> (PServeEndpoint, PFetchClient) {
    let provider = Arc::new(OneShard { shard_id, body });
    let endpoint = PServeEndpoint::bind(provider, signer)
        .await
        .expect("bind serving endpoint");
    let proxy = spawn_forwarder(endpoint.addr()).await;
    let client = PFetchClient::with_timeouts(proxy, timeouts);
    (endpoint, client)
}

/// SOCKS5 proxy. It accepts the persona greeting, then tunnels every
/// CONNECT to `target`.
///
/// Returns the proxy's loopback address. The accept loop runs until the
/// listener closes, which is process end in a test.
async fn spawn_forwarder(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind socks shim");
    let proxy = listener.local_addr().expect("shim address");
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(tunnel(client, target));
        }
    });
    proxy
}

async fn tunnel(mut client: TcpStream, target: SocketAddr) {
    if handshake(&mut client).await.is_err() {
        return;
    }
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        return;
    };
    // Either side closing ends the conversation. The client has already
    // classified the exchange; the shim has nothing further to report.
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((_from_client, _from_upstream)) => {}
        Err(_error) => {}
    }
}

/// Accept the persona greeting and a CONNECT, and answer success with a
/// zero IPv4 bind address. The client discards that address.
///
/// The credentials drop here. The shim has to speak the greeting so the
/// client will send CONNECT; what the username isolates is Tor's decision.
async fn handshake(client: &mut TcpStream) -> std::io::Result<()> {
    accept_userpass(client)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[1] != CMD_CONNECT || request[2] != RSV {
        return Err(protocol_error("socks connect"));
    }
    let addr_len = match request[3] {
        ATYP_V4 => V4_ADDR_LEN,
        ATYP_V6 => V6_ADDR_LEN,
        ATYP_NAME => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        _ => return Err(protocol_error("socks address type")),
    };
    let mut skip = vec![0u8; addr_len + PORT_LEN];
    client.read_exact(&mut skip).await?;
    // VER, SUCCEEDED, RSV, ATYP_V4, 0.0.0.0, port 0. `shekyl-socks`
    // consumes this bind address and then treats the stream as the tunnel.
    client
        .write_all(&[SOCKS_VERSION, SUCCEEDED, RSV, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await
}

fn protocol_error(detail: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_leaf_is_one_leaf_and_not_a_run_of_zeroes() {
        let body = one_leaf();
        assert_eq!(body.len(), LEAF_BYTES);
        assert!(body.iter().any(|byte| *byte != 0));
    }
}
