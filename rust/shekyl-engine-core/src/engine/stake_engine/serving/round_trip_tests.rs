// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! SH-2's proving test: the persona's **resident** pass key, behind the real
//! serving endpoint, answering the real fetch client, with the
//! countersignature verified under the persona's **bond identity** — the key
//! the bond record publishes and the only key a requester knows.
//!
//! The unit tests in [`super::pass_key`] prove the key signs and verifies
//! in-process. What only this layer can prove is that the signature the
//! wallet produces is the one the daemon's client *accepts*: same transcript
//! bytes, same envelope, same anchor gate. The loopback is
//! `shekyl-p-loopback` (`SH2_RESIDENT_KEY_AUDIT.md` §3 Q4). The signer is
//! the host's, over a tip stamped once, not a second height type in front
//! of the key.

use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::PASS_ANCHOR_DEPTH_BLOCKS;
use shekyl_p_host::signer_at_synced_tip;
use shekyl_p_loopback::{
    endpoint_and_client, fetch_target, one_leaf, request_header, AcceptAny, FetchError,
    PFetchClient, PServeEndpoint, Timeouts, FIXTURE_SHARD_ID,
};
use shekyl_types::BlockHeight;
use tempfile::TempDir;

use super::pass_key::ResidentPassKey;
use crate::engine::signer::SoloSigner;
use crate::engine::stake_engine::types::PersonaIdentity;
use crate::engine::test_support::{activate_persona, staker_engine};
use crate::engine::Engine;

const SLOT: u32 = 3;
const SIGNER_SEED: u8 = 7;
const OTHER_SEED: u8 = 11;
const OWN_HEIGHT: u64 = 10_000;
const ANCHOR: u64 = OWN_HEIGHT - PASS_ANCHOR_DEPTH_BLOCKS.to_raw();

/// The daemon tip stays inside the gate for the whole test.
const TIP_MAX_AGE: Duration = Duration::from_secs(120);

/// Bounds for a pass the resident key signs on the actor's blocking pool.
///
/// These are not [`Timeouts::DEFAULT`]. The body window covers one hybrid
/// sign plus the mailbox round-trip on a slow CI host. The ephemeral-signer
/// conversation in `shekyl-p-fetch` uses a shorter body window, because that
/// sign does not leave the process.
fn proving_timeouts() -> Timeouts {
    Timeouts {
        dial: Duration::from_millis(500),
        head: Duration::from_millis(2_000),
        body_stall: Duration::from_millis(5_000),
        body_total: Duration::from_millis(10_000),
    }
}

/// The wallet, its engine, and the loopback conversation its resident key
/// is signing. Dropping the engine drops the actor, and the key then refuses.
struct ResidentServe {
    _wallet: TempDir,
    _engine: Engine<SoloSigner>,
    identity: PersonaIdentity,
    endpoint: PServeEndpoint,
    client: PFetchClient,
}

async fn open_persona(seed: u8) -> (TempDir, Engine<SoloSigner>, PersonaIdentity) {
    let (wallet, engine) = staker_engine(SLOT, seed);
    activate_persona(&engine, SLOT).await;
    let stake = engine.stake_handle().expect("staker has a StakeEngine");
    let identity = stake
        .active_persona()
        .await
        .expect("ask")
        .expect("persona active");
    (wallet, engine, identity)
}

async fn serve_persona(seed: u8) -> ResidentServe {
    let (wallet, engine, identity) = open_persona(seed).await;
    let stake = engine.stake_handle().expect("staker has a StakeEngine");
    let key = ResidentPassKey::new(&stake, identity.p_slot);
    let signer = signer_at_synced_tip(key, BlockHeight::from_raw(OWN_HEIGHT), TIP_MAX_AGE);
    let (endpoint, client) =
        endpoint_and_client(FIXTURE_SHARD_ID, one_leaf(), signer, proving_timeouts()).await;
    ResidentServe {
        _wallet: wallet,
        _engine: engine,
        identity,
        endpoint,
        client,
    }
}

/// The wallet's resident key countersigns a real served body, and the
/// daemon's client accepts it **under the bond identity**: the requester
/// holds nothing of the serving role, only the key the bond record names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemon_client_accepts_a_pass_the_resident_key_signed() {
    let serve = serve_persona(SIGNER_SEED).await;
    let target = fetch_target(serve.identity.bond_id.clone(), FIXTURE_SHARD_ID);
    let shard = serve
        .client
        .fetch(
            &target,
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect("the resident key's countersignature verifies under bond_id");
    assert_eq!(shard.shard_id(), FIXTURE_SHARD_ID);
    assert_eq!(serve.endpoint.served_count(), 1);
    assert_eq!(serve.endpoint.sign_failure_count(), 0);
    assert_eq!(serve.endpoint.late_sign_failure_count(), 0);
}

/// The other half of the claim: a requester holding some *other* key
/// refuses the same pass. Without this the test above could pass against
/// a client that does not verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_requester_with_the_wrong_key_refuses_the_same_pass() {
    let serve = serve_persona(SIGNER_SEED).await;
    let (_other_wallet, _other_engine, other) = open_persona(OTHER_SEED).await;
    assert_ne!(
        other.bond_id.to_canonical_bytes().expect("encode"),
        serve.identity.bond_id.to_canonical_bytes().expect("encode"),
        "two wallets, two identities"
    );

    let target = fetch_target(other.bond_id, FIXTURE_SHARD_ID);
    let err = serve
        .client
        .fetch(
            &target,
            &request_header(BlockHeight::from_raw(ANCHOR)),
            Arc::new(AcceptAny),
        )
        .await
        .expect_err("a pass signed by another identity is refused");
    assert!(matches!(err, FetchError::BadCountersignature), "{err}");
}
