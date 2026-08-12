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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use shekyl_curve_tree::{
    leaves_per_segment, BlockHeight, Gindex, LeafEntry, LeafStore, OutputIdentity, SegmentPin,
    ServingReader, TargetKind,
};
use shekyl_p_host::{
    HostError, PersonaServing, PersonaServingHost, PinError, PinReport, PinnedServeSet,
    ServeSetPinner, Staleness, StalenessBound,
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

/// A pinner over a real store — the production shape, minus the actor hop
/// and the claim-source fetch (both SH-2b's, and neither observable on this
/// axis). It *reports* its serve-set, exactly as the engine implementor will
/// report the one it derives from the connected bond record; the host never
/// supplies it.
///
/// The set is behind a lock so a test can move it, which is what an
/// on-chain `HoldingsUpdate` looks like from here.
struct StorePinner {
    store: Arc<LeafStore>,
    reported: Mutex<(Vec<u64>, u64)>,
    fail: Mutex<bool>,
}

impl StorePinner {
    fn new(store: Arc<LeafStore>, shard_ids: &[u64], as_of_height: u64) -> Self {
        Self {
            store,
            reported: Mutex::new((shard_ids.to_vec(), as_of_height)),
            fail: Mutex::new(false),
        }
    }

    /// The pinner starts failing — the transport dropped, the actor died.
    fn fail_next(&self) {
        *self.fail.lock().expect("lock") = true;
    }

    /// Holdings move on-chain: the record now says something else.
    fn holdings_became(&self, shard_ids: &[u64], as_of_height: u64) {
        *self.reported.lock().expect("lock") = (shard_ids.to_vec(), as_of_height);
    }
}

impl ServeSetPinner for StorePinner {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        if *self.fail.lock().expect("lock") {
            return Err("pinner is down".into());
        }
        let (shard_ids, as_of_height) = self.reported.lock().expect("lock").clone();
        let outcomes = self
            .store
            .pin_serve_set(&shard_ids)
            .map_err(|e| format!("{e:?}"))?;
        // Both halves off the one store — the production implementor takes
        // them from the one `CurveTreeClient` it owns, for the same reason.
        Ok(PinReport {
            shard_ids,
            as_of_height,
            outcomes,
            reader: ServingReader::new(Arc::clone(&self.store)),
        })
    }
}

/// A pinner that always fails, for the "the witness is not minted" arm.
struct DeadPinner;

impl ServeSetPinner for DeadPinner {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        Err("curve-tree actor unavailable".into())
    }
}

/// Reports outcomes that do not describe the set it reported. `SHORT` drops a
/// member, `REORDER` permutes, `SUBSTITUTE` keeps the right COUNT and the
/// wrong members — the last is the negative control that keeps the check
/// about identity rather than arithmetic.
struct IncoherentPinner {
    shard_ids: Vec<u64>,
    mode: Incoherence,
}

#[derive(Clone, Copy)]
enum Incoherence {
    Short,
    Reorder,
    Substitute,
}

impl ServeSetPinner for IncoherentPinner {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let mut outcomes: Vec<(u64, SegmentPin)> = self
            .shard_ids
            .iter()
            .map(|&id| (id, SegmentPin::PinnedServable))
            .collect();
        match self.mode {
            Incoherence::Short => {
                outcomes.pop();
            }
            Incoherence::Reorder => outcomes.reverse(),
            Incoherence::Substitute => {
                for o in &mut outcomes {
                    o.0 += 1_000_000;
                }
            }
        }
        Ok(PinReport {
            shard_ids: self.shard_ids.clone(),
            as_of_height: 1,
            outcomes,
            reader: ServingReader::new(Arc::new(LeafStore::open_ephemeral().expect("open store"))),
        })
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

    let err = PinnedServeSet::acquire(&StorePinner::new(Arc::clone(&store), &[0, 1], 10_000))
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

    let pinned = PinnedServeSet::acquire(&StorePinner::new(Arc::clone(&store), &[0, 1], 10_000))
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
    let err = PinnedServeSet::acquire(&DeadPinner)
        .await
        .expect_err("a dead pinner cannot establish the pins");
    assert!(matches!(err, PinError::Pinner { .. }));
}

#[tokio::test]
async fn a_report_whose_outcomes_do_not_cover_its_own_set_mints_no_witness() {
    // The witness is evidence that the pins cover the obligation. A report
    // stating a set and then describing a different one is not that, and the
    // three shapes are covered together: a dropped member, a permutation, and
    // a substitution with the right COUNT and the wrong members — the last is
    // why the check compares identity rather than arithmetic.
    for mode in [
        Incoherence::Short,
        Incoherence::Reorder,
        Incoherence::Substitute,
    ] {
        let err = PinnedServeSet::acquire(&IncoherentPinner {
            shard_ids: vec![7, 8, 9],
            mode,
        })
        .await
        .expect_err("an incoherent report must not mint a witness");
        let PinError::PinnerCoverageMismatch {
            reported_set,
            covered,
        } = &err
        else {
            panic!("expected a coverage mismatch, got {err:?}");
        };
        assert_eq!(reported_set, &[7, 8, 9]);
        assert_ne!(covered, reported_set);
        assert!(err.to_string().contains("implementor defect"));
    }
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

    let pinner = StorePinner::new(Arc::clone(&store), &[0], 10_000);

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
        &pinner,
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
    let pinner = StorePinner::new(Arc::clone(&store), &[], 0);

    let dir = tempfile::tempdir().expect("tempdir");
    let host = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: identity(),
            virtual_port: 80,
            max_streams: 8,
        },
        &pinner,
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

// ---------------------------------------------------------------------------
// Keeping the serve-set current, and noticing when it stops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_refresh_pins_shards_gained_since_the_host_started() {
    // The steady-state hazard, and it needs no reorg and no adversary: §9.6
    // item 3 has an archiver posting `HoldingsUpdate` continuously to keep
    // covering newly frozen segments, so an honest persona doing exactly what
    // the design says gains shards its running host never pinned. A prune in
    // that window discards bytes no re-pin can restore.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");

    let pinner = StorePinner::new(Arc::clone(&store), &[0], 1);

    let dir = tempfile::tempdir().expect("tempdir");
    let host = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: identity(),
            virtual_port: 80,
            max_streams: 8,
        },
        &pinner,
    )
    .await
    .expect("start");

    // Holdings grow to cover segment 1, which then freezes.
    pinner.holdings_became(&[0, 1], 20_000);
    host.refresh().await.expect("refresh");
    let mut second = segment_entries();
    for (i, e) in second.iter_mut().enumerate() {
        e.gindex = Gindex(leaves_per_segment() as u64 + i as u64);
    }
    store
        .append_block_deltas(&second, &[], &[], BlockHeight(20_000))
        .expect("freeze segment 1");

    // The prune that would have cost the shard. The refresh's pin is what
    // survives it — taken before the freeze, which is the whole point.
    store.prune_frozen(&[]).expect("prune");
    let body = fetch(host.serve_addr(), "/x-provisional/v0/shard/1").await;
    assert_eq!(
        body_of(&body).len(),
        leaves_per_segment() * 128,
        "the gained shard must be servable — an unrefreshed host loses it here"
    );

    host.shutdown().await;
}

#[tokio::test]
async fn staleness_reads_two_clocks_with_independent_drivers() {
    // The tripwire for a refresh that has STOPPED. `as_of_height` advances
    // only on refresh (persona-side P-scan sweep); the store's sync tip
    // advances on the principal's block scan. Ingest without refresh is
    // exactly the divergence a halted sweep produces.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], 0);
    let pinned = PinnedServeSet::acquire(&pinner).await.expect("pin");

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        pinned.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 },
        "a store that has ingested nothing cannot be stale against anything"
    );

    // Ingest advances the tip; nothing refreshes the serve-set.
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("ingest");
    let stale = pinned.staleness(bound).expect("read staleness");
    assert!(stale.is_stale(), "10_000 blocks of ingest, no refresh");
    assert_eq!(stale.lag(), 10_000);
    // Rule 82: the message names the check the operator should make.
    assert!(stale.to_string().contains("P-scan sweep is still running"));

    // And a refresh clears it — the same two clocks, re-aligned.
    pinner.holdings_became(&[], 10_000);
    let refreshed = pinned.refreshed(&pinner).await.expect("refresh");
    assert_eq!(
        refreshed.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );
}

#[tokio::test]
async fn a_failed_refresh_leaves_the_previous_pins_in_place() {
    // Acquire before release: a refresh that cannot pin must not drop the
    // witness it has. Stale pins retain bytes; missing pins lose them, and
    // only one of those is recoverable.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    let pinner = StorePinner::new(Arc::clone(&store), &[0], 1);

    let dir = tempfile::tempdir().expect("tempdir");
    let host = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: identity(),
            virtual_port: 80,
            max_streams: 8,
        },
        &pinner,
    )
    .await
    .expect("start");

    // The host holds the pinner it started with, so "a refresh that fails"
    // is now the pinner failing rather than a different pinner being handed
    // in — which is the point: there is no second pinner to hand in.
    pinner.fail_next();
    let err = host
        .refresh()
        .await
        .expect_err("a failing pinner cannot refresh");
    assert!(matches!(err, PinError::Pinner { .. }));
    assert_eq!(
        host.pinned_serve_set().serve_set().as_of_height(),
        1,
        "the previous witness survives a failed refresh"
    );

    // And the pins it holds are still real.
    store.prune_frozen(&[]).expect("prune");
    assert_eq!(
        body_of(&fetch(host.serve_addr(), "/x-provisional/v0/shard/0").await).len(),
        leaves_per_segment() * 128
    );

    host.shutdown().await;
}
