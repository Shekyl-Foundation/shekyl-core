// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The producer's read against the production serve loop behind the
//! loopback SOCKS shim (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §5.1–§5.3).
//!
//! Every test names the edit that turns it red.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_archival_fetch_sched::{
    BlockSpan, ClosedShard, FactsFault, FetchScheduler, HolderSource, NeedBudget, ShardClose,
    ShardFacts, ShardStanding, Timeouts,
};
use shekyl_archival_retention::{
    challenge_nonce, verify_receipt_transcript, PassStream, PASS_ANCHOR_DEPTH_BLOCKS,
};
use shekyl_p_loopback::{
    client_through, endpoint_and_client, fixture_body, fixture_expectation, FIXTURE_SHARD_ID,
};
use shekyl_p_serve::{
    PassSigner, TestKeySigner, TestReceiptKeySigner, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN,
};
use shekyl_types::{ArchivalLength, BlockHash, BlockHeight, PCanonicalId, ShardId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::outcome::ReadKey;

const OWN_HEIGHT: u64 = 10_000;
const SHARD: ShardId = ShardId::from_raw(FIXTURE_SHARD_ID);

fn timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(2_000),
        body_stall: Duration::from_millis(2_000),
        body_total: Duration::from_millis(5_000),
    }
}

/// One closed shard, the fixture's, under a tip at the serve's height.
struct Facts;

impl ShardFacts for Facts {
    fn tip_height(&self) -> Result<BlockHeight, FactsFault> {
        Ok(BlockHeight::from_raw(OWN_HEIGHT))
    }

    fn block_hash_at(&self, height: BlockHeight) -> Result<Option<BlockHash>, FactsFault> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&height.to_raw().to_le_bytes());
        Ok(Some(BlockHash::from_bytes(bytes)))
    }

    fn shard(&self, shard_id: ShardId) -> Result<ShardStanding, FactsFault> {
        if shard_id == SHARD {
            return Ok(ShardStanding::Closed(Box::new(ClosedShard {
                expected: fixture_expectation(shard_id.to_raw()),
                span: BlockSpan {
                    first: BlockHeight::from_raw(8_990),
                    last: BlockHeight::from_raw(9_000),
                    first_timestamp: 1_700_000_000,
                    last_timestamp: 1_700_001_200,
                    coinbase_outputs: 1,
                    tx_outputs: 1,
                },
                close: ShardClose {
                    height: BlockHeight::from_raw(9_000),
                    hash: BlockHash::from_bytes([0xC1; 32]),
                },
            })));
        }
        Ok(ShardStanding::Open {
            open_shard: shard_id,
            archival_through_tip: ArchivalLength::from_raw(0),
        })
    }
}

/// The drawn holders of the fixture shard: one, under `key`. Only the
/// organic read draws from it.
struct Holders(shekyl_crypto_pq::signature::HybridPublicKey);

impl HolderSource for Holders {
    fn holders_of(
        &self,
        _shard_id: ShardId,
    ) -> Result<Vec<shekyl_archival_fetch_sched::Holder>, FactsFault> {
        Ok(vec![shekyl_archival_fetch_sched::Holder {
            id: PCanonicalId::from_bytes([0x71; 32]),
            target: shekyl_p_loopback::fetch_target(self.0.clone()),
        }])
    }

    fn support_holders_of(
        &self,
        _shard_id: ShardId,
    ) -> Result<Vec<shekyl_archival_fetch_sched::Holder>, FactsFault> {
        Ok(Vec::new())
    }
}

fn due(
    receipt_key: shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridPublicKey,
    stream: PassStream,
) -> DueRead {
    let key = ReadKey {
        h: BlockHeight::from_raw(OWN_HEIGHT - 50),
        stream,
        draw: 2,
        attempt: 1,
    };
    let nonce = match stream {
        PassStream::Economy => challenge_nonce(&[0x11; 32], &[0x22; 32], 2, 1),
        PassStream::Support => {
            shekyl_archival_retention::support_challenge_nonce(&[0x11; 32], &[0x22; 32], 2, 1)
        }
    };
    DueRead {
        key,
        persona: PCanonicalId::from_bytes([0x3C; 32]),
        endpoint: [0xEE; 32],
        receipt_key,
        shard: SHARD,
        nonce,
    }
}

fn identity_key() -> shekyl_crypto_pq::signature::HybridPublicKey {
    TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT))
        .public_key()
        .clone()
}

/// A receipt endpoint's answer is a pass: the record carries the read's
/// attempt, its header's anchor, the body's digest, and a receipt that
/// verifies as the bundle verifier's step 8 opens it, on the draw's
/// stream. Red edit: record attempt 0 for every read — the attempt
/// assertion fails, and admission would recompute another nonce.
#[tokio::test]
async fn a_receipt_endpoint_answers_a_pass_the_verifier_opens() {
    let signer = Arc::new(TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(
        OWN_HEIGHT,
    )));
    let key = signer.public_key().clone();
    let (_endpoint, client) = endpoint_and_client(
        FIXTURE_SHARD_ID,
        fixture_body(),
        signer as Arc<dyn PassSigner<RECEIPT_ENVELOPE_LEN>>,
        timeouts(),
    )
    .await;
    let scheduler = FetchScheduler::new(Arc::new(Facts), Arc::new(Holders(identity_key())), client);
    for stream in [PassStream::Economy, PassStream::Support] {
        let read = due(key.clone(), stream);
        let ReadOutcome::Pass(record) = read_due(&scheduler, &read, NeedBudget::DEFAULT).await
        else {
            panic!("a receipt endpoint answers a pass on {stream:?}");
        };
        assert_eq!(record.attempt, 1);
        assert_eq!(
            record.anchor_height,
            BlockHeight::from_raw(OWN_HEIGHT) - PASS_ANCHOR_DEPTH_BLOCKS
        );
        let anchor_hash = Facts
            .block_hash_at(record.anchor_height)
            .expect("facts")
            .expect("below the tip");
        let receipt = shekyl_crypto_pq::fn_dsa_hybrid::FnDsaHybridSignature::from_canonical_bytes(
            &record.receipt,
        )
        .expect("a scheme-3 receipt");
        verify_receipt_transcript(
            &key,
            stream,
            &read.nonce,
            record.anchor_height,
            anchor_hash.as_bytes(),
            SHARD.to_raw(),
            &record.delivery_digest,
            &receipt,
        )
        .expect("the receipt verifies on the draw's stream");
    }
}

/// The live serving host signs with the identity key. The producer's read
/// of it is one completed exchange that is not a receipt, classified as
/// the serving side's scheme: the bundle files with no passes and the log
/// says why. Red edit: classify it `Refused` — the block's log line never
/// fires.
#[tokio::test]
async fn an_identity_endpoint_is_the_serving_sides_scheme() {
    let signer = Arc::new(TestKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT)));
    let (_endpoint, client) = endpoint_and_client(
        FIXTURE_SHARD_ID,
        fixture_body(),
        Arc::clone(&signer) as Arc<dyn PassSigner<IDENTITY_ENVELOPE_LEN>>,
        timeouts(),
    )
    .await;
    let scheduler = FetchScheduler::new(
        Arc::new(Facts),
        Arc::new(Holders(signer.public_key().clone())),
        client,
    );
    let receipt_key = TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(OWN_HEIGHT))
        .public_key()
        .clone();
    let outcome = read_due(
        &scheduler,
        &due(receipt_key, PassStream::Economy),
        NeedBudget::DEFAULT,
    )
    .await;
    assert_eq!(outcome, ReadOutcome::Answered(Answered::ServingScheme));
}

/// An excess past what an identity envelope can add is not the serving
/// side's scheme, and neither is any other malformation. Red edit: drop
/// the bound on the excess — a hostile oversized reply logs as the
/// identity scheme.
#[test]
fn only_an_identity_envelopes_excess_is_the_serving_sides_scheme() {
    use shekyl_archival_fetch_sched::{
        Attempt, FetchError, Malformed, ReadFailure, IDENTITY_ENVELOPE_LEN, RECEIPT_ENVELOPE_LEN,
    };
    let wider = u64::try_from(IDENTITY_ENVELOPE_LEN - RECEIPT_ENVELOPE_LEN).expect("fits");
    let ended = |error: FetchError| {
        classify(&ReadFailure::Exhausted {
            attempts: vec![Attempt {
                holder: PCanonicalId::from_bytes([1; 32]),
                error,
            }],
        })
    };
    let oversize = |declared: u64| {
        FetchError::Malformed(Malformed::Oversize {
            declared,
            max: 1_000,
        })
    };
    assert_eq!(
        ended(oversize(1_000 + wider)),
        ReadOutcome::Answered(Answered::ServingScheme)
    );
    assert_eq!(
        ended(oversize(1_001 + wider)),
        ReadOutcome::Answered(Answered::Refused)
    );
    assert_eq!(
        ended(FetchError::Malformed(Malformed::FrameLong)),
        ReadOutcome::Answered(Answered::Refused)
    );
    assert_eq!(
        ended(FetchError::Miss),
        ReadOutcome::Answered(Answered::Refused)
    );
}

/// Stall-class failures read again; a requester that could not dial reads
/// again. Red edit: classify an empty attempt list as `Refused` — the
/// draw is lost without a read.
#[test]
fn a_failure_with_no_exchange_is_stall_class() {
    use shekyl_archival_fetch_sched::ReadFailure;
    assert_eq!(
        classify(&ReadFailure::Exhausted {
            attempts: Vec::new()
        }),
        ReadOutcome::Stall
    );
    assert_eq!(
        classify(&ReadFailure::NoAnchor {
            tip: BlockHeight::from_raw(3)
        }),
        ReadOutcome::Stall
    );
    assert_eq!(
        classify(&ReadFailure::Facts(FactsFault::NotReady)),
        ReadOutcome::Stall
    );
}

/// A listener in front of `target` that records the request head of every
/// connection, then forwards the conversation.
async fn tap(target: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tap");
    let addr = listener.local_addr().expect("tap address");
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&heads);
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if client.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                seen.lock().expect("tap log").push(head.clone());
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    return;
                };
                if upstream.write_all(&head).await.is_err() {
                    return;
                }
                drop(tokio::io::copy_bidirectional(&mut client, &mut upstream).await);
            });
        }
    });
    (addr, heads)
}

/// The one-machinery rule end to end through the producer's caller
/// (§5.1): the producer's challenge read and an organic read of the same
/// shard put byte-identical requests on the wire apart from the nonce.
/// The organic read draws an identity holder and the challenge names a
/// receipt-key holder; the request does not carry the scheme. Red edit:
/// give the challenge read a header of its own (another anchor, or a
/// caller tag) — a byte outside the nonce differs.
#[tokio::test]
async fn a_challenge_read_and_an_organic_read_differ_only_in_the_nonce() {
    let signer = Arc::new(TestReceiptKeySigner::ephemeral(BlockHeight::from_raw(
        OWN_HEIGHT,
    )));
    let key = signer.public_key().clone();
    let (endpoint, _direct) = endpoint_and_client(
        FIXTURE_SHARD_ID,
        fixture_body(),
        signer as Arc<dyn PassSigner<RECEIPT_ENVELOPE_LEN>>,
        timeouts(),
    )
    .await;
    let (tapped, heads) = tap(endpoint.addr()).await;
    let client = client_through(tapped, timeouts()).await;
    let scheduler = FetchScheduler::new(Arc::new(Facts), Arc::new(Holders(identity_key())), client);

    let challenge = due(key, PassStream::Economy);
    let ReadOutcome::Pass(_) = read_due(&scheduler, &challenge, NeedBudget::DEFAULT).await else {
        panic!("the challenge read passes");
    };
    // The organic read meets the receipt endpoint under an identity key
    // and fails; its request is on the wire all the same.
    let budget = NeedBudget {
        holders: 1.try_into().expect("one"),
        stall_redials: 0,
    };
    assert!(scheduler
        .read(
            SHARD,
            Arc::new(shekyl_archival_fetch_sched::DiscardTxs),
            budget
        )
        .await
        .is_err());

    let heads = heads.lock().expect("tap log").clone();
    assert_eq!(heads.len(), 2, "one request per read");
    let (a, b) = (&heads[0], &heads[1]);
    assert_eq!(a.len(), b.len());
    let text = String::from_utf8(a.clone()).expect("ascii head");
    let nonce_hex: String = challenge.nonce.iter().map(|x| format!("{x:02x}")).collect();
    let start = text
        .find(&nonce_hex)
        .expect("the challenge nonce is on the wire");
    let span = start..start + nonce_hex.len();
    let differing: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
    assert!(!differing.is_empty(), "two reads, two nonces");
    assert!(
        differing.iter().all(|i| span.contains(i)),
        "a byte outside the nonce differs: {differing:?} against {span:?}"
    );
}
