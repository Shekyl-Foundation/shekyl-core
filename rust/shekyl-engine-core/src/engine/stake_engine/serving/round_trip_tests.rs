// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SH-2's proving test: the persona's **resident** pass key, behind the real
//! `shekyl-p-serve` endpoint, answering the real `shekyl-p-fetch` client,
//! with the countersignature verified under the persona's **bond identity**
//! — the key the bond record publishes and the only key a requester knows.
//!
//! The unit tests in [`super::pass_key`] prove the key signs and verifies
//! in-process. What only this layer can prove is that the signature the
//! wallet produces is the one the daemon's client *accepts*: same
//! transcript bytes, same envelope, same anchor gate, across the two HTTP
//! stacks. A loopback SOCKS5 shim stands in for the daemon's tor-zone
//! SOCKS, so nothing here needs a tor (`SH2_RESIDENT_KEY_AUDIT.md` §3 Q4).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_crypto_pq::signature::HybridSignature;
use shekyl_curve_tree::LEAF_BYTES;
use shekyl_p_fetch::{
    ContentRefused, ContentVerify, FetchError, FetchTarget, PFetchClient, RequestHeader,
    ServingEndpoint, Timeouts,
};
use shekyl_p_host::{PassKey, SignRefused};
use shekyl_p_serve::{
    PServeEndpoint, PassSigner, ProviderError, ShardBody, ShardProvider,
    PASS_COUNTERSIGNATURE_MESSAGE_LEN,
};
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::pass_key::ResidentPassKey;
use crate::engine::test_support::{activate_persona, staker_engine};

const SLOT: u32 = 3;
const SHARD: u64 = 3;
const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

/// The resident key given a chain height, which is the one thing
/// `PassSigner` adds to `PassKey`. Production reads the height from the
/// serving store's daemon tip (`shekyl-p-host`'s `HostSigner`); this test
/// is about the key, so the height is fixed and in-gate.
struct AtHeight(Arc<ResidentPassKey>);

impl PassKey for AtHeight {
    fn ready(&self, shard_id: u64, anchor_height: BlockHeight) -> Result<(), SignRefused> {
        self.0.ready(shard_id, anchor_height)
    }

    fn sign_pass(
        &self,
        message: &[u8; PASS_COUNTERSIGNATURE_MESSAGE_LEN],
    ) -> Result<HybridSignature, SignRefused> {
        self.0.sign_pass(message)
    }
}

impl PassSigner for AtHeight {
    fn own_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight::from_raw(OWN_HEIGHT))
    }
}

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

/// SOCKS5 no-auth proxy that CONNECTs to `target` whatever name it is
/// given — the client still speaks SOCKS5h (ATYP=DOMAIN, the onion name);
/// this is the loopback stand-in for the daemon's tor-zone SOCKS.
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

fn payload() -> Vec<u8> {
    (0..LEAF_BYTES)
        .map(|i| u8::try_from(i % 251).expect("modulus"))
        .collect()
}

async fn stacks(signer: Arc<dyn PassSigner>) -> (PServeEndpoint, PFetchClient) {
    let provider = Arc::new(Fixture {
        shards: HashMap::from([(SHARD, Arc::from(payload().into_boxed_slice()))]),
    });
    let ep = PServeEndpoint::bind(provider, signer).await.expect("bind");
    let proxy = socks_forward(ep.addr()).await;
    let client = PFetchClient::with_timeouts(
        proxy,
        Timeouts {
            dial: Duration::from_millis(500),
            head: Duration::from_millis(2_000),
            // A hybrid sign on the blocking pool sits inside the body
            // window; generous here so a slow CI box is not a false red.
            body_stall: Duration::from_millis(5_000),
            body_total: Duration::from_millis(10_000),
        },
    );
    (ep, client)
}

fn header_at(anchor: u64) -> RequestHeader {
    RequestHeader::with_nonce([0xa5; 32], BlockHeight::from_raw(anchor), [0x5a; 32])
}

/// The wallet's resident key countersigns a real served body, and the
/// daemon's client accepts it **under the bond identity**: the requester
/// holds nothing of the serving role, only the key the bond record names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_client_accepts_a_pass_the_resident_key_signed() {
    let (_tmp, engine) = staker_engine(SLOT, 7);
    activate_persona(&engine, SLOT).await;
    let stake = engine.stake_handle().expect("staker has a StakeEngine");
    let active = stake
        .active_persona()
        .await
        .expect("ask")
        .expect("persona active");

    let key = ResidentPassKey::new(&stake, active.p_slot);
    let (ep, client) = stacks(Arc::new(AtHeight(key)) as Arc<dyn PassSigner>).await;

    let target = FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes([0x42; 32]),
        verifying_key: active.bond_id.clone(),
        shard_id: SHARD,
    };
    let shard = client
        .fetch(&target, &header_at(ANCHOR), Arc::new(Accepting))
        .await
        .expect("the resident key's countersignature verifies under bond_id");
    assert_eq!(shard.shard_id(), SHARD);
    assert_eq!(ep.served_count(), 1);
    assert_eq!(ep.sign_failure_count(), 0);
    assert_eq!(ep.late_sign_failure_count(), 0);
}

/// The other half of the claim: a requester holding some *other* key
/// refuses the same pass. Without this the test above could pass against
/// a client that does not verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_requester_with_the_wrong_key_refuses_the_same_pass() {
    let (_tmp, engine) = staker_engine(SLOT, 7);
    activate_persona(&engine, SLOT).await;
    let stake = engine.stake_handle().expect("staker has a StakeEngine");
    let active = stake
        .active_persona()
        .await
        .expect("ask")
        .expect("persona active");

    let key = ResidentPassKey::new(&stake, active.p_slot);
    let (_ep, client) = stacks(Arc::new(AtHeight(key)) as Arc<dyn PassSigner>).await;

    // A different persona's bond identity: a second wallet from a different
    // seed, so the key is real and simply not the signer's.
    let (_tmp2, other) = staker_engine(SLOT, 11);
    activate_persona(&other, SLOT).await;
    let other_id = other
        .stake_handle()
        .expect("staker")
        .active_persona()
        .await
        .expect("ask")
        .expect("persona active")
        .bond_id;
    assert_ne!(
        other_id.to_canonical_bytes().expect("encode"),
        active.bond_id.to_canonical_bytes().expect("encode"),
        "two wallets, two identities"
    );

    let target = FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes([0x42; 32]),
        verifying_key: other_id,
        shard_id: SHARD,
    };
    let err = client
        .fetch(&target, &header_at(ANCHOR), Arc::new(Accepting))
        .await
        .expect_err("a pass signed by another identity is refused");
    assert!(matches!(err, FetchError::BadCountersignature), "{err}");
}
