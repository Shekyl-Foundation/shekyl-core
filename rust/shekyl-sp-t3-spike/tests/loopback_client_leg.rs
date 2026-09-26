// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The harness's client leg against the production endpoint, **with no tor**.
//!
//! `shekyl-p-fetch`'s own `against_serve` test proves the two HTTP stacks
//! agree. This one proves the *rig's* wiring on top of them: the apparatus
//! anchor passes the persona's `SF-D5` height gate, the fixture provider
//! serves a body the client verifies, the derived expected length is the
//! length that arrives, and a `P` under the wrong key is `Refused` rather
//! than anything Tor could be blamed for. Every one of those is a way a
//! multi-hour live run could produce a file of identical 404s — and the
//! taxonomy would show `refused`, but only after the hours were spent.
//!
//! A SOCKS5h shim stands in for the client tor: it CONNECTs to the endpoint
//! regardless of the onion name the client sends, which is exactly the
//! substitution the live apparatus's tor performs for real.

use std::net::SocketAddr;
use std::sync::Arc;

use shekyl_p_fetch::{FetchTarget, ServingEndpoint};
use shekyl_p_serve::{PServeEndpoint, PassSigner, ShardBody, TestKeySigner};
use shekyl_sp_t3_spike::fixture::{FixtureShardProvider, LEAF_BYTES};
use shekyl_sp_t3_spike::harness::{ClientLeg, APPARATUS_OWN_HEIGHT};
use shekyl_sp_t3_spike::measure::FailureKind;
use shekyl_types::BlockHeight;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// SOCKS5 no-auth proxy that forwards every CONNECT to `target`.
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
                // The production client always sends ATYP=DOMAIN with the
                // onion name; anything else is the shim being driven wrong.
                if req[3] != 3 {
                    return None;
                }
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await.ok()?;
                let mut name = vec![0u8; usize::from(len[0])];
                client.read_exact(&mut name).await.ok()?;
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

/// A payload of exactly four leaves, with structure.
fn payload() -> Arc<[u8]> {
    (0..LEAF_BYTES * 4)
        .map(|i| u8::try_from(i % 251).expect("modulus"))
        .collect::<Vec<u8>>()
        .into()
}

async fn persona(signer: Arc<TestKeySigner>) -> (PServeEndpoint, SocketAddr) {
    let ep = PServeEndpoint::bind(
        Arc::new(FixtureShardProvider::new(payload())),
        signer as Arc<dyn PassSigner>,
    )
    .await
    .expect("bind endpoint");
    let proxy = socks_forward(ep.addr()).await;
    (ep, proxy)
}

fn target_for(signer: &TestKeySigner) -> FetchTarget {
    FetchTarget {
        endpoint: ServingEndpoint::from_record_bytes([0x42; 32]),
        verifying_key: signer.public_key().clone(),
        shard_id: 0,
    }
}

#[tokio::test]
async fn apparatus_anchor_passes_the_gate_and_the_body_verifies() {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(
        APPARATUS_OWN_HEIGHT,
    )));
    let (ep, proxy) = persona(Arc::clone(&signer)).await;
    let leg = ClientLeg::new(proxy, 1);

    let len = leg
        .fetch_once(0, &target_for(&signer))
        .await
        .expect("the apparatus anchor must pass P's height gate and verify");

    // The length the apparatus would derive at bring-up, through the same
    // contract the endpoint writes with.
    let expected = ShardBody::flat(payload())
        .expect("four whole leaves")
        .header()
        .framed_len();
    assert_eq!(u64::try_from(len).expect("fits"), expected);
    assert_eq!(ep.served_count(), 1);
}

#[tokio::test]
async fn a_persona_at_a_far_height_is_refused_not_blamed_on_tor() {
    // A `P` whose own height is a day past the apparatus's anchors sees an
    // anchor outside `[own − 720 − L, own − 720 + L]` and renders the
    // identical 404. The client leg must class that as `Refused`: it is a
    // completed exchange, and the rig — not the network — is what is wrong.
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(
        APPARATUS_OWN_HEIGHT + 720,
    )));
    let (ep, proxy) = persona(Arc::clone(&signer)).await;
    let leg = ClientLeg::new(proxy, 1);

    let outcome = leg.fetch_once(0, &target_for(&signer)).await;

    assert_eq!(outcome, Err(FailureKind::Refused));
    assert_eq!(ep.served_count(), 0, "the identical 404 is not a serve");
}

#[tokio::test]
async fn a_body_under_the_wrong_key_is_refused() {
    // The persona signs under one key; the "bond record" names another. The
    // production client refuses the countersignature, and the leg reports
    // it as `Refused`, distinguishable from a stall.
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(
        APPARATUS_OWN_HEIGHT,
    )));
    let other = TestKeySigner::ephemeral(BlockHeight::from_raw(APPARATUS_OWN_HEIGHT));
    let (_ep, proxy) = persona(signer).await;
    let leg = ClientLeg::new(proxy, 1);

    let outcome = leg.fetch_once(0, &target_for(&other)).await;

    assert_eq!(outcome, Err(FailureKind::Refused));
}
