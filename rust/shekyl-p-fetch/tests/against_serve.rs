// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The two HTTP stacks speaking to each other.
//!
//! `shekyl-p-fetch` cannot depend on `shekyl-p-serve` on the shipped graph
//! (`SF-D4`). This is a *dev* edge: a SOCKS5h shim in front of a real
//! `PServeEndpoint`, so a mismatch in envelope layout, header set, or
//! request grammar fails here instead of in the field.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::signature::HybridPublicKey;
use shekyl_curve_tree::{ServedFrameHeader, LEAF_BYTES};
use shekyl_p_fetch::{
    ContentRefused, ContentVerify, FetchTarget, PFetchClient, RequestHeader, ServingEndpoint,
    Timeouts,
};
use shekyl_p_serve::{
    PServeEndpoint, PassSigner, ProviderError, ShardBody, ShardProvider, TestKeySigner,
};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SHARD: u64 = 3;
const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

struct Fixture {
    shards: HashMap<u64, Arc<[u8]>>,
}

impl ShardProvider for Fixture {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        Ok(self
            .shards
            .get(&shard_id)
            .cloned()
            .and_then(ShardBody::flat))
    }
}

struct Accepting;

impl ContentVerify for Accepting {
    fn verify(&self, _shard_id: u64, _body: &[u8]) -> Result<(), ContentRefused> {
        Ok(())
    }
}

/// SOCKS5 no-auth proxy that CONNECTs by forwarding to `target` regardless
/// of the named destination — the client still has to send ATYP=DOMAIN and
/// the onion name; this shim is the loopback stand-in for the daemon's
/// tor-zone SOCKS, not a second resolver.
async fn socks_forward(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let mut req = [0u8; 4];
                client.read_exact(&mut req).await.ok()?;
                match req[3] {
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await.ok()?;
                        let mut name = vec![0u8; usize::from(len[0])];
                        client.read_exact(&mut name).await.ok()?;
                    }
                    1 => {
                        let mut addr = [0u8; 4];
                        client.read_exact(&mut addr).await.ok()?;
                    }
                    4 => {
                        let mut addr = [0u8; 16];
                        client.read_exact(&mut addr).await.ok()?;
                    }
                    _ => return None,
                }
                let mut port = [0u8; 2];
                client.read_exact(&mut port).await.ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                let mut upstream = TcpStream::connect(target).await.ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut upstream)
                    .await
                    .ok()?;
                Some(())
            });
        }
    });
    proxy
}

#[tokio::test]
async fn fetch_client_accepts_a_real_served_body() {
    let payload: Vec<u8> = (0..LEAF_BYTES)
        .map(|i| u8::try_from(i % 251).expect("modulus"))
        .collect();
    let provider = Arc::new(Fixture {
        shards: HashMap::from([(SHARD, Arc::from(payload.clone().into_boxed_slice()))]),
    });
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let public: HybridPublicKey = signer.public_key().clone();
    let ep = PServeEndpoint::bind(provider, Arc::clone(&signer) as Arc<dyn PassSigner>)
        .await
        .expect("bind");
    let proxy = socks_forward(ep.addr()).await;

    let client = PFetchClient::with_timeouts(
        proxy,
        Timeouts {
            dial: Duration::from_millis(500),
            head: Duration::from_millis(1_000),
            body_stall: Duration::from_millis(1_000),
            body_total: Duration::from_millis(2_000),
        },
    );
    let target = FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes([0x42; 32]),
        verifying_key: public,
        shard_id: SHARD,
    };
    let header = RequestHeader::with_nonce([0xa5; 32], BlockHeight::from_raw(ANCHOR), [0x5a; 32]);
    let shard = client
        .fetch(&target, &header, Arc::new(Accepting))
        .await
        .expect("the two stacks speak the same contract");
    assert_eq!(shard.shard_id(), SHARD);
    // Envelope already stripped; remaining bytes are RF-D4 then the
    // segment. The transport crate does not parse the frame — this test
    // does, so a swapped envelope/frame order fails here.
    let mut rest = shard.body();
    let frame = ServedFrameHeader::read(&mut rest).expect("RF-D4 frame after the envelope");
    assert_eq!(frame.leaf_count(), 1);
    assert_eq!(rest, payload.as_slice());
}
