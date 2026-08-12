// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The composition's own axis: where a serve-set may come from, what a pin
//! must establish before serving starts, and the endpoint's lifetime
//! relative to tor's.
//!
//! **No tor binary is needed, and that is deliberate rather than a
//! compromise.** The supervisor is handed a binary that cannot pass the
//! SP-T0c hash gate, so it churns through failed incarnations for the whole
//! test — which is precisely the condition the load-bearing invariant is
//! about. A host that rebound its listener per incarnation would fail these
//! tests; one that binds once passes. The live-tor lane adds the onion leg,
//! not this property.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use shekyl_archival_retention::{ClaimantBondRecord, HoldingsDescriptor, HoldingsKind, ShardSet};
use shekyl_curve_tree::{
    leaves_per_segment, BlockHeight, Gindex, LeafEntry, LeafStore, OutputIdentity, SegmentPin,
    ServingReader, TargetKind,
};
use shekyl_p_host::{
    HostError, PersonaServing, PersonaServingHost, PinError, PinnedServeSet, ServeSet,
    ServeSetPinner,
};
use shekyl_tor::onion_identity::OnionIdentity;
use shekyl_tor::service::{
    ServingPosture, SupervisorPolicy, TorBinarySource, TorPosture, TorServiceConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A full segment of distinct canonical leaves.
fn segment_entries() -> Vec<LeafEntry> {
    (0..leaves_per_segment())
        .map(|i| {
            let gindex = u64::try_from(i).expect("index fits u64");
            let mut leaf = [1u8; 128];
            leaf[..8].copy_from_slice(&(gindex + 1).to_le_bytes());
            LeafEntry {
                gindex: Gindex(gindex),
                maturity: BlockHeight(0),
                creation_height: BlockHeight(0),
                leaf,
                identity: OutputIdentity {
                    output_key: [1u8; 32],
                    commitment: Some([2u8; 32]),
                    h_pqc: [3u8; 32],
                    target: TargetKind::TaggedKey,
                },
            }
        })
        .collect()
}

/// A connected bond record carrying `shard_ids`.
fn holdings(shard_ids: &[u64]) -> HoldingsDescriptor {
    HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(shard_ids.to_vec()).expect("valid shard set"),
    }
}

fn record(holdings: &HoldingsDescriptor) -> ClaimantBondRecord<'_> {
    ClaimantBondRecord {
        join_settlement_epoch: 7,
        holdings,
        claimed_settlement_epochs: &[],
    }
}

/// A pinner over a real store — the production shape, minus the actor hop
/// (which is the wiring slice's, and adds nothing this axis can observe).
struct StorePinner(Arc<LeafStore>);

impl ServeSetPinner for StorePinner {
    async fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, String> {
        self.0
            .pin_serve_set(shard_ids)
            .map_err(|e| format!("{e:?}"))
    }
}

/// A pinner that always fails, for the "the witness is not minted" arm.
struct DeadPinner;

impl ServeSetPinner for DeadPinner {
    async fn pin_serve_set(&self, _shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, String> {
        Err("curve-tree actor unavailable".into())
    }
}

/// A pinner that reports on FEWER members than it was asked about — the
/// shape that used to mint a witness for members nobody pinned.
struct ShortPinner;

impl ServeSetPinner for ShortPinner {
    async fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, String> {
        Ok(shard_ids
            .iter()
            .take(shard_ids.len().saturating_sub(1))
            .map(|&id| (id, SegmentPin::PinnedServable))
            .collect())
    }
}

/// A pinner that reports on the right members in the wrong order. The trait
/// promises the caller's order; nothing verified it.
struct ReorderingPinner;

impl ServeSetPinner for ReorderingPinner {
    async fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, String> {
        let mut out: Vec<(u64, SegmentPin)> = shard_ids
            .iter()
            .map(|&id| (id, SegmentPin::PinnedServable))
            .collect();
        out.reverse();
        Ok(out)
    }
}

/// A pinner that answers about members it was never asked about, with the
/// right COUNT. A length check alone would pass this.
struct SubstitutingPinner;

impl ServeSetPinner for SubstitutingPinner {
    async fn pin_serve_set(&self, shard_ids: &[u64]) -> Result<Vec<(u64, SegmentPin)>, String> {
        Ok(shard_ids
            .iter()
            .map(|&id| (id + 1_000_000, SegmentPin::PinnedServable))
            .collect())
    }
}

/// A supervisor config whose binary cannot pass the gate, with a backoff
/// short enough that several incarnations fail inside a test.
fn churning_tor(dir: &tempfile::TempDir) -> TorServiceConfig {
    let bogus = dir.path().join("not-tor");
    std::fs::write(&bogus, b"not a tor binary").expect("write bogus binary");
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    TorServiceConfig {
        binary: TorBinarySource::At(bogus),
        data_dir: dir.path().join("data"),
        events: shekyl_tor::control::EventSink::new(tx),
        policy: SupervisorPolicy {
            backoff_base: Duration::from_millis(5),
            backoff_cap: Duration::from_millis(20),
            trust_retry: Duration::from_millis(5),
            ..SupervisorPolicy::default()
        },
        disable_network: true,
        // Deliberately wrong: `start` is the sole author of the posture, and
        // this asserts it does not inherit the caller's.
        posture: ServingPosture::Client,
    }
}

fn identity() -> OnionIdentity {
    OnionIdentity::from_hs_id_seed(&[9u8; 32])
}

fn body_of(response: &[u8]) -> &[u8] {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has a head");
    &response[end + 4..]
}

async fn fetch(addr: SocketAddr, path: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("read response");
    out
}

// ---------------------------------------------------------------------------
// Where a serve-set may come from
// ---------------------------------------------------------------------------

#[test]
fn a_serve_set_carries_the_record_it_came_from_and_the_height_it_was_read_at() {
    // §9.6 item 4: the pin set is *derived* from the bond record, never
    // maintained alongside it. The type has no other constructor — and the
    // height stamp is what makes a stale set distinguishable from a current
    // one rather than merely wrong.
    let h = holdings(&[3, 1, 4]);
    let set = ServeSet::from_connected_record(&record(&h), 812_345);

    assert_eq!(
        set.shard_ids(),
        &[3, 1, 4],
        "the record's own order is preserved — it is the wire form"
    );
    assert_eq!(set.as_of_height(), 812_345);
    assert!(!set.is_empty());
}

#[test]
fn an_empty_holdings_set_is_a_legal_serve_set() {
    // A `CompleteTree` node carries no shard ids and an `Unbond` exit
    // empties them, so empty is a state, not a fault.
    let h = HoldingsDescriptor {
        kind: HoldingsKind::CompleteTree,
        shard_ids: ShardSet::empty(),
    };
    let set = ServeSet::from_connected_record(&record(&h), 1);
    assert!(set.is_empty());
    assert_eq!(set.shard_ids(), &[] as &[u64]);
}

// ---------------------------------------------------------------------------
// What the pin must establish
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pruned_member_refuses_the_whole_serve_set_and_names_every_one() {
    // The silent-slash shape: the frozen record survives a prune, so a pin
    // gated on the record alone would report the set healthy and the persona
    // would walk into its challenge epoch unable to answer. Pinning cannot
    // restore bytes, so the host refuses to start — and it lists every
    // pruned member, because the remedy is a chain-replay rebuild and the
    // operator wants its extent in one message.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");
    store.prune_frozen(&[]).expect("prune without pinning");

    let h = holdings(&[0, 1]);
    let set = ServeSet::from_connected_record(&record(&h), 10_000);
    let err = PinnedServeSet::acquire(&StorePinner(Arc::clone(&store)), set)
        .await
        .expect_err("a pruned member must refuse the set");

    assert_eq!(err, PinError::MembersAlreadyPruned { shard_ids: vec![0] });
    // The message names the remedy, not just the fault (rule 82).
    assert!(err.to_string().contains("rebuilt by chain replay"));
}

#[tokio::test]
async fn unfrozen_members_are_pinned_and_recorded_as_not_yet_servable() {
    // Bonding before a segment freezes is legal by design, and pinning ahead
    // is what stops a prune from landing between the freeze and the next
    // re-pin. Such a member is accepted — but recorded, because a read for
    // it is an honest miss until the freeze boundary crosses it, and that is
    // not the same thing as a fault.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");

    let h = holdings(&[0, 1]);
    let set = ServeSet::from_connected_record(&record(&h), 10_000);
    let pinned = PinnedServeSet::acquire(&StorePinner(Arc::clone(&store)), set)
        .await
        .expect("frozen + not-yet-frozen is a healthy set");

    assert_eq!(pinned.not_yet_frozen(), &[1]);
    assert_eq!(pinned.serve_set().shard_ids(), &[0, 1]);

    // And the pin is real: a prune with no further pinning call leaves both
    // members covered.
    store.prune_frozen(&[]).expect("prune");
    assert!(
        store
            .open_frozen_segment_body(shekyl_curve_tree::SegmentId(0))
            .expect("read")
            .is_some(),
        "the pin taken at acquire() is what survives the prune"
    );
}

#[tokio::test]
async fn a_failed_pin_mints_no_witness() {
    // The pinner failing leaves the serve-set's state unknown, so there is
    // nothing to hand `start`. Pinning is idempotent, so the caller's move
    // is to retry — which is why this is a distinct arm from the pruned
    // case, whose remedy is a rebuild.
    let h = holdings(&[0]);
    let set = ServeSet::from_connected_record(&record(&h), 5);
    let err = PinnedServeSet::acquire(&DeadPinner, set)
        .await
        .expect_err("a dead pinner cannot establish the pins");
    assert!(matches!(err, PinError::Pinner { .. }));
}

#[tokio::test]
async fn a_pinner_that_under_reports_mints_no_witness() {
    // The gap this closes: `acquire` trusted the outcome list to describe the
    // members it asked about. A short list carried no `AlreadyPruned`, so the
    // witness minted — for a set whose unreported members were never pinned,
    // and an unpinned member is precisely what `prune_frozen` may remove out
    // from under a read. A witness that is not checked is an assumption
    // wearing a type.
    let h = holdings(&[0, 1, 2]);
    let set = ServeSet::from_connected_record(&record(&h), 5);
    let err = PinnedServeSet::acquire(&ShortPinner, set)
        .await
        .expect_err("a pinner that skipped a member cannot witness its pin");
    match err {
        PinError::PinnerCoverageMismatch {
            requested,
            returned,
        } => {
            assert_eq!(requested, vec![0, 1, 2]);
            assert_eq!(returned, vec![0, 1]);
        }
        other => panic!("expected a coverage mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pinner_that_answers_out_of_order_mints_no_witness() {
    // The trait promises outcomes in the caller's order and nothing verified
    // it, so the promise was decoration. Enforcing the documented contract is
    // cheaper than discovering later which callers had quietly come to depend
    // on it.
    let h = holdings(&[0, 1, 2]);
    let set = ServeSet::from_connected_record(&record(&h), 5);
    let err = PinnedServeSet::acquire(&ReorderingPinner, set)
        .await
        .expect_err("outcomes out of the caller's order break the trait contract");
    assert!(matches!(err, PinError::PinnerCoverageMismatch { .. }));
}

#[tokio::test]
async fn a_pinner_that_substitutes_members_mints_no_witness() {
    // The negative control on the check itself: this reply has the RIGHT
    // COUNT and the wrong members, so a length comparison would accept it.
    // Comparing the sequence is what makes the check about identity rather
    // than arithmetic.
    let h = holdings(&[0, 1, 2]);
    let set = ServeSet::from_connected_record(&record(&h), 5);
    let err = PinnedServeSet::acquire(&SubstitutingPinner, set)
        .await
        .expect_err("a pinner answering about other members witnesses nothing");
    assert!(matches!(err, PinError::PinnerCoverageMismatch { .. }));
}

// ---------------------------------------------------------------------------
// The composition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_serving_endpoint_outlives_tor_incarnations() {
    // The load-bearing invariant. `TorService` republishes the onion on every
    // incarnation from one `OnionServiceSpec` holding one loopback target, so
    // a listener that rebound per incarnation would leave the published
    // address pointing at a dead port — the persona looks healthy, publishes,
    // and answers nothing.
    //
    // The supervisor here cannot launch (its binary fails the hash gate), so
    // it churns through failed incarnations for the length of the test. The
    // serving endpoint must be untouched by that.
    //
    // What enforces the invariant is the *absence* of a rebind path, not this
    // test — `serve_addr` reads a field nothing mutates. What this test
    // genuinely establishes is the observable half: the listener is still
    // answering, with the same bytes, after the supervisor has failed
    // repeatedly. It is the guard against someone adding the rebind later.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");

    let h = holdings(&[0]);
    let set = ServeSet::from_connected_record(&record(&h), 10_000);
    let pinned = PinnedServeSet::acquire(&StorePinner(Arc::clone(&store)), set)
        .await
        .expect("pin");

    let dir = tempfile::tempdir().expect("tempdir");
    let id = identity();
    let expected_service_id = id.service_id().clone();
    let host = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: id,
            virtual_port: 80,
            max_streams: 8,
        },
        ServingReader::new(Arc::clone(&store)),
        pinned,
    )
    .await
    .expect("host starts without a working tor — the endpoint does not need one");

    // Derived, so it is known before tor is.
    assert_eq!(host.service_id(), &expected_service_id);

    let addr = host.serve_addr();
    assert!(addr.ip().is_loopback(), "the serve target is loopback");

    let first = fetch(addr, "/x-provisional/v0/shard/0").await;
    assert_eq!(
        body_of(&first).len(),
        leaves_per_segment() * 128,
        "a whole shard, not a 404 that happens to be non-empty"
    );

    // Let the supervisor fail several incarnations.
    let mut posture = host.posture();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut failures = 0u32;
    while failures < 3 {
        tokio::select! {
            changed = posture.changed() => {
                changed.expect("supervisor alive");
                if matches!(
                    &*posture.borrow_and_update(),
                    TorPosture::Degraded { .. } | TorPosture::Restarting { .. }
                ) {
                    failures += 1;
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                panic!("supervisor never reported a failed incarnation");
            }
        }
    }

    assert_eq!(
        host.serve_addr(),
        addr,
        "the loopback target must not move under incarnation churn"
    );
    let second = fetch(addr, "/x-provisional/v0/shard/0").await;
    assert_eq!(second, first, "and it must still be serving the same bytes");
    let (served, _refused, failures, _accept_errors) = host.counters();
    assert_eq!(served, 2);
    assert_eq!(failures, 0);

    host.shutdown().await;
}

#[tokio::test]
async fn shutdown_stops_the_listener() {
    // Teardown order is tor-then-listener (so no descriptor outlives the
    // port it points at); what is observable without a live onion is that
    // the listener is gone once shutdown resolves.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let h = holdings(&[]);
    let set = ServeSet::from_connected_record(&record(&h), 0);
    let pinned = PinnedServeSet::acquire(&StorePinner(Arc::clone(&store)), set)
        .await
        .expect("an empty serve-set pins vacuously");

    let dir = tempfile::tempdir().expect("tempdir");
    let host = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: identity(),
            virtual_port: 80,
            max_streams: 8,
        },
        ServingReader::new(store),
        pinned,
    )
    .await
    .expect("start");

    let addr = host.serve_addr();
    assert!(
        TcpStream::connect(addr).await.is_ok(),
        "serving before stop"
    );

    host.shutdown().await;

    assert!(
        TcpStream::connect(addr).await.is_err(),
        "the listener is gone once shutdown resolves"
    );
}

#[test]
fn host_errors_name_what_the_operator_must_do() {
    // Rule 82: a start failure the operator sees must say what failed, not
    // just that something did.
    let bind = HostError::Bind {
        detail: "address in use".into(),
    };
    assert!(bind.to_string().contains("address in use"));
    assert!(HostError::NonLoopbackTarget
        .to_string()
        .contains("non-loopback"));
}
