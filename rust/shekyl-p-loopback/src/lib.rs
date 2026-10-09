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
//! The shim accepts no-auth CONNECT and tunnels it to the endpoint. The
//! name the client sends is not resolved: that is the daemon's tor-zone
//! proxy's job, and this stands in for the proxy.
//!
//! The types a caller has to name are re-exported. A proving test then
//! dev-depends on this crate and not on either end.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_archival_retention::{PASS_ANCHOR_HASH_LEN, PASS_NONCE_LEN};
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_p_serve::{PassSigner, ProviderError, ShardBody, ShardProvider};
use shekyl_types::{ArchivalLength, BlockHeight, ShardId, TxHash, SHARD_LENGTH};
use shekyl_wire::shard_frame::{encode_frame, rows_of, FrameTx};
use shekyl_wire::TxidParts;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub use shekyl_p_fetch::{
    DiscardTxs, ExpectedShard, FetchError, FetchTarget, PFetchClient, RequestHeader,
    ServingEndpoint, Timeouts, TxSink, VerifiedShard, VerifiedTx,
};
pub use shekyl_p_serve::PServeEndpoint;

const SOCKS_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
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

/// The txid of the one transaction in [`fixture_body`]. Any value: the
/// client checks components against the rows it is handed, and the txid
/// is what the view hash binds them to.
pub const FIXTURE_TXID: TxHash = TxHash::from_bytes([0x7c; 32]);

/// Length of the fixture transaction's prunable region. Short: the serve
/// loop is body-agnostic and the client streams, so the length proves
/// nothing beyond "a body crossed".
const FIXTURE_PRUNABLE_LEN: usize = 128;

/// The fixture transaction's prunable region. The modulus keeps the
/// bytes from being a run of zeroes, so a body swapped with the envelope
/// fails a comparison with it. No `pqc_auths`.
#[must_use]
pub fn fixture_prunable() -> Vec<u8> {
    const DISTINCT: usize = 251;
    (0..FIXTURE_PRUNABLE_LEN)
        .map(|i| u8::try_from(i % DISTINCT).expect("modulus fits in a byte"))
        .collect()
}

fn fixture_frame_tx(prunable: &[u8]) -> FrameTx<'_> {
    FrameTx {
        pqc_auth_count: 0,
        pqc_auths: &[],
        prunable,
    }
}

/// The fixture body as `P` serves it: a one-transaction `shard_frame`
/// over [`fixture_prunable`].
#[must_use]
pub fn fixture_body() -> Arc<[u8]> {
    let prunable = fixture_prunable();
    Arc::from(encode_frame(&[fixture_frame_tx(&prunable)]))
}

/// What a requester expects of [`fixture_body`] at `shard_id`: the one
/// row, placed so the range closes the shard (`cum_before` is the shard's
/// end less the row's length).
///
/// # Panics
///
/// Panics if `shard_id` is the last representable shard, whose end does
/// not fit; no test asks for it.
#[must_use]
pub fn fixture_expectation(shard_id: u64) -> ExpectedShard {
    let prunable = fixture_prunable();
    let (pqc_auth_hash, prunable_hash, archival_len) = rows_of(&fixture_frame_tx(&prunable));
    let row = TxidParts {
        hash: FIXTURE_TXID,
        pqc_auth_hash,
        prunable_hash,
        archival_len,
    };
    let end = (shard_id + 1)
        .checked_mul(SHARD_LENGTH.to_raw())
        .expect("fixture shard end fits");
    let cum_before = ArchivalLength::from_raw(end - archival_len.to_raw());
    ExpectedShard::new(ShardId::from_raw(shard_id), cum_before, vec![row])
        .expect("one row closing its shard")
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
pub fn fetch_target(verifying_key: HybridPublicKey) -> FetchTarget {
    FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes(UNRESOLVED_ENDPOINT),
        verifying_key,
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
        Ok(Some(ShardBody::flat(Arc::clone(&self.body))))
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

/// SOCKS5 no-auth proxy. Every CONNECT is tunneled to `target`.
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

/// Read a no-auth greeting and a CONNECT, and answer success with a
/// zero IPv4 bind address. The client discards that address.
async fn handshake(client: &mut TcpStream) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION {
        return Err(protocol_error("socks version"));
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    client.write_all(&[SOCKS_VERSION, NO_AUTH]).await?;

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
    fn the_fixture_prunable_is_not_a_run_of_zeroes() {
        let prunable = fixture_prunable();
        assert_eq!(prunable.len(), FIXTURE_PRUNABLE_LEN);
        assert!(prunable.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn the_fixture_expectation_is_one_row_closing_its_shard() {
        let expected = fixture_expectation(FIXTURE_SHARD_ID);
        assert_eq!(expected.shard_id().to_raw(), FIXTURE_SHARD_ID);
        assert_eq!(expected.tx_count(), 1);
        assert_eq!(
            expected.archival_len().to_raw(),
            u64::try_from(FIXTURE_PRUNABLE_LEN).unwrap()
        );
        assert_eq!(expected.txs()[0].hash, FIXTURE_TXID);
    }
}
