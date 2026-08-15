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
    ServingReader, TargetKind, TreePosition,
};
use shekyl_p_host::{
    HostError, PersonaServing, PersonaServingHost, PinError, PinReport, PinnedServeSet,
    ReportedSet, ServeSetPinner, Staleness, StalenessBound,
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
/// and the claim-source fetch (both on `EngineServeSetPinner` in this PR,
/// neither observable on this axis). It *reports* its serve-set, exactly
/// as the engine implementor reports the one it derives from the
/// connected bond record; the host never supplies it.
///
/// The set is behind a lock so a test can move it, which is what an
/// on-chain `HoldingsUpdate` looks like from here.
struct StorePinner {
    store: Arc<LeafStore>,
    reported: Mutex<(Vec<u64>, BlockHeight)>,
    fail: Mutex<bool>,
}

impl StorePinner {
    fn new(store: Arc<LeafStore>, shard_ids: &[u64], as_of_height: BlockHeight) -> Self {
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

    /// …and stops failing: the transport came back.
    fn recovered(&self) {
        *self.fail.lock().expect("lock") = false;
    }

    /// Holdings move on-chain: the record now says something else.
    fn holdings_became(&self, shard_ids: &[u64], as_of_height: BlockHeight) {
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
            set: ReportedSet::ShardList {
                shard_ids,
                outcomes,
            },
            as_of_height,
            reader: ServingReader::new(Arc::clone(&self.store)),
        })
    }
}

/// A pinner that is slow on its **second** call and immediate afterwards,
/// reporting a distinguishable set and stamp per call.
///
/// Call 1 is the host's startup acquire. Calls 2 and 3 are the two concurrent
/// refreshes, and making the earlier of them the slow one is what orders the
/// race: without a gate spanning the whole attempt, call 3 installs its newer
/// witness first and call 2 then overwrites it with the older one derived from
/// a staler read.
struct SlowSecondCallPinner {
    store: Arc<LeafStore>,
    calls: Mutex<u64>,
}

impl ServeSetPinner for SlowSecondCallPinner {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let generation = {
            let mut calls = self.calls.lock().expect("lock");
            *calls += 1;
            *calls
        };
        if generation == 2 {
            // Long enough that the other refresh completes inside it when the
            // two are not serialized, and irrelevant when they are.
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // The set grows on the third call, so the *newest* report is the one
        // covering both shards. A final witness of `[0]` means an older report
        // won.
        let shard_ids: Vec<u64> = if generation >= 3 { vec![0, 1] } else { vec![0] };
        let outcomes = self
            .store
            .pin_serve_set(&shard_ids)
            .map_err(|e| format!("{e:?}"))?;
        Ok(PinReport {
            set: ReportedSet::ShardList {
                shard_ids,
                outcomes,
            },
            as_of_height: BlockHeight(generation * 1_000),
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
            set: ReportedSet::ShardList {
                shard_ids: self.shard_ids.clone(),
                outcomes,
            },
            as_of_height: BlockHeight(1),
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
    //
    // TWO members are pruned, deliberately: with one, "lists every pruned
    // member" and "lists the first pruned member" are the same assertion,
    // and the contract this test is named for would go unverified.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let mut both = segment_entries();
    let mut second = segment_entries();
    for (i, e) in second.iter_mut().enumerate() {
        e.gindex = Gindex(leaves_per_segment() as u64 + i as u64);
    }
    both.extend(second);
    store
        .append_block_deltas(&both, &[], &[], BlockHeight(10_000))
        .expect("append and freeze segments 0 and 1");
    store.prune_frozen(&[]).expect("prune without pinning");

    let err = PinnedServeSet::acquire(&StorePinner::new(
        Arc::clone(&store),
        &[0, 1, 2],
        BlockHeight(10_000),
    ))
    .await
    .expect_err("a pruned member must refuse the set");

    assert_eq!(
        err,
        PinError::MembersAlreadyPruned {
            shard_ids: vec![0, 1]
        },
        "every pruned member, not just the first — the remedy is a rebuild \
         and the operator wants its extent in one message"
    );
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

    let pinned = PinnedServeSet::acquire(&StorePinner::new(
        Arc::clone(&store),
        &[0, 1],
        BlockHeight(10_000),
    ))
    .await
    .expect("frozen + not-yet-frozen is a healthy set");

    assert_eq!(pinned.not_yet_frozen_at_last_pin(), &[1]);
    assert_eq!(pinned.serve_set().shard_ids(), Some(&[0u64, 1][..]));

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
    // The pinner failing leaves the serve-set's state unknown, so `start`
    // cannot acquire a witness. Pinning is idempotent, so the caller's
    // move is to retry — which is why this is a distinct arm from the
    // pruned case, whose remedy is a rebuild.
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

    let pinner = StorePinner::new(Arc::clone(&store), &[0], BlockHeight(10_000));

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
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(0));

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
    let pin = HostError::Pin(PinError::Pinner {
        detail: "curve-tree actor unavailable".into(),
    });
    assert!(pin.to_string().contains("did not start"));
    assert!(pin.to_string().contains("curve-tree actor unavailable"));
}

// ---------------------------------------------------------------------------
// Keeping the serve-set current, and noticing when it stops
// ---------------------------------------------------------------------------

#[tokio::test]
async fn overlapping_refreshes_cannot_install_an_older_witness_last() {
    // `refresh` is a read-modify-write on serving state: read the witness,
    // pin, install. The witness `Mutex` makes each write atomic and says
    // nothing about the sequence, so two overlapping attempts can finish out
    // of order and leave the *older* report installed — a host serving a
    // stale serve-set while its own witness claims to be current, which is
    // §9.6 item 4's silent slash arriving through the refresh built to close
    // it.
    //
    // This is a live axis rather than a hypothetical: `refresh` is `pub`, has
    // no production caller yet, and its own doc tells the SH-2b wiring to call
    // it on every tick.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");

    let pinner = SlowSecondCallPinner {
        store: Arc::clone(&store),
        calls: Mutex::new(0),
    };

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

    // Both attempts must succeed — serializing them must not turn the loser
    // into an error the caller has to interpret.
    let (first, second) = tokio::join!(host.refresh(), host.refresh());
    first.expect("first refresh");
    second.expect("second refresh");

    let witness = host.pinned_serve_set();
    assert_eq!(
        witness.serve_set().shard_ids(),
        Some(&[0u64, 1][..]),
        "the newest report must be the installed one; `[0]` is the older \
         attempt finishing last and overwriting it"
    );
    assert_eq!(
        witness.serve_set().as_of_height(),
        BlockHeight(3_000),
        "the stamp must come from the last attempt to run, not the last to finish"
    );

    host.shutdown().await;
}

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

    let pinner = StorePinner::new(Arc::clone(&store), &[0], BlockHeight(1));

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
    pinner.holdings_became(&[0, 1], BlockHeight(20_000));
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
async fn staleness_reads_one_clock_twice_with_independent_drivers() {
    // The tripwire for a refresh that has STOPPED. Both operands are the
    // store's own sync tip: the value stamped at the last refresh (the
    // persona-side P-scan sweep) and the value now (advanced by the
    // principal's block scan). Ingest without refresh is exactly the
    // divergence a halted sweep produces.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(0));
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
    assert_eq!(stale.lag(), Some(10_000));
    // Rule 82: the message names the check the operator should make.
    assert!(stale.to_string().contains("refresh is still succeeding"));

    // And a refresh clears it — the same two clocks, re-aligned.
    pinner.holdings_became(&[], BlockHeight(10_000));
    let refreshed = pinned.refreshed(&pinner).await.expect("refresh");
    assert_eq!(
        refreshed.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );
}

#[tokio::test]
async fn staleness_measures_local_ingest_not_the_distance_to_the_daemon() {
    // THE NEGATIVE CONTROL FOR THE CLOCK THE LAG IS READ FROM. The record's
    // `as_of_height` is the DAEMON's tip over RPC; the store's sync tip is
    // LOCAL. A wallet that has been offline restarts far below its daemon,
    // and differencing the two would report a healthy zero for the whole
    // catch-up — precisely the window in which holdings move and a shard
    // gained on chain goes unpinned.
    //
    // So the fixture is that shape deliberately: a record stamped at daemon
    // height 500_000 over a store that has ingested nothing. Reading
    // `tip - as_of_height` here saturates to `Current { lag: 0 }` no matter
    // how much this wallet ingests. Reading one clock twice does not.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(500_000));
    let pinned = PinnedServeSet::acquire(&pinner).await.expect("pin");

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        pinned.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 },
        "nothing ingested since the pin, however far below the daemon this wallet sits"
    );

    // The wallet catches up. The serve-set is not re-derived.
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("ingest");

    assert_eq!(
        pinned.staleness(bound).expect("read staleness"),
        Staleness::Stale {
            lag: 10_000,
            bound: 100
        },
        "10_000 blocks of local ingest is 10_000 blocks of staleness — the daemon's \
         height at the time of the pin is not part of this subtraction"
    );
}

#[tokio::test]
async fn a_store_rollback_beneath_the_pins_is_its_own_reading() {
    // The sync tip is NOT monotonic: `truncate_from_tree_position` resets it
    // to zero and `rollback_to_fork` moves it back to the fork. Both also
    // delete pinned-segment rows above the truncation point — so a tip below
    // the stamped baseline means the witness is naming pins the store may
    // have just dropped.
    //
    // A saturating subtraction would report that as `Current { lag: 0 }`: an
    // affirmative all-clear on the one store event that can unpin a member.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    let pinner = StorePinner::new(Arc::clone(&store), &[0], BlockHeight(10_000));
    let pinned = PinnedServeSet::acquire(&pinner).await.expect("pin");

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        pinned.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );

    // A reorg deep enough to invalidate the sync tip.
    store
        .truncate_from_tree_position(TreePosition(0))
        .expect("rollback");

    // The truncation deleted this member's pin row, so the reading is the
    // measured condition rather than the inferred one: `PinsDropped` outranks
    // `RolledBack` because it reports an exposure that exists now, and a tip
    // that happens to be low is only evidence that one might.
    let reading = pinned.staleness(bound).expect("read staleness");
    assert_eq!(
        reading,
        Staleness::PinsDropped {
            dropped: 1,
            claimed: 1
        },
        "the rollback dropped the pin, and that is what must be reported"
    );
    assert!(reading.is_stale(), "the pins it named are gone");
    assert_eq!(
        reading.lag(),
        None,
        "the store un-ingested; there is no lag to report and 0 would be a lie"
    );
    assert_eq!(
        pinned.dropped_pins().expect("list dropped pins"),
        vec![0],
        "the ids stay available for a log line even though the status is a ratio"
    );
    // Rule 82: the message must say the bytes are prunable now, not that a
    // reorg happened and will sort itself out.
    assert!(reading.to_string().contains("no longer pinned"));
}

#[tokio::test]
async fn re_ingest_past_the_baseline_does_not_clear_a_dropped_pin() {
    // The tip is not monotonic, and it is not evidence about pins. A rollback
    // deletes pinned-segment rows; block ingest afterwards climbs the tip back
    // past the stamped baseline and restores **no** pin rows. Any reading
    // derived from the tip therefore self-clears — `checked_sub` goes positive
    // again and reports `Current` — while the members stay prunable.
    //
    // That is the silent-slash shape this whole slice exists to close, arriving
    // through the tripwire itself: a host whose refresh trigger is the failed
    // component would return to an affirmative healthy reading while serving
    // shards nothing retains.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    let pinner = StorePinner::new(Arc::clone(&store), &[0], BlockHeight(10_000));
    let pinned = PinnedServeSet::acquire(&pinner).await.expect("pin");

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        pinned.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );

    // Reorg: the pin row for segment 0 goes with it.
    store
        .truncate_from_tree_position(TreePosition(0))
        .expect("rollback");

    // The chain re-converges and the principal ingests straight back past the
    // height the witness was stamped at. Nothing here re-pins.
    let mut replayed = segment_entries();
    for (i, e) in replayed.iter_mut().enumerate() {
        e.gindex = Gindex(i as u64);
    }
    store
        // Just past the baseline and well inside the bound, so a tip-derived
        // reading lands on `Current` rather than merely on the wrong arm.
        // That is the finding's actual hazard: not a bad number, an
        // affirmative all-clear.
        .append_block_deltas(&replayed, &[], &[], BlockHeight(10_050))
        .expect("re-ingest past the baseline");
    assert!(
        store.sync_tip_height().expect("tip") > BlockHeight(10_000),
        "the premise of this test is that the tip climbed back ABOVE the baseline"
    );

    let reading = pinned.staleness(bound).expect("read staleness");
    assert_eq!(
        reading,
        Staleness::PinsDropped {
            dropped: 1,
            claimed: 1
        },
        "a tip-derived reading reports Current with lag 50 here; the pin is still gone"
    );
    assert!(
        reading.is_stale(),
        "returning to healthy on re-ingest is the defect this test exists for"
    );

    // And it clears only by actually re-pinning — the structural latch.
    let refreshed = pinned.refreshed(&pinner).await.expect("re-pin");
    assert_eq!(
        refreshed.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 },
        "a successful re-pin is the one thing that restores a healthy reading"
    );
}

#[tokio::test]
async fn one_terminally_pruned_member_does_not_wedge_every_later_refresh() {
    // `AlreadyPruned` is terminal by the store's own contract — chain
    // replay, not retry. Refusing the whole report on refresh, as `acquire`
    // does, would make EVERY later refresh fail for the life of the host:
    // the witness freezes, and every shard connected afterwards goes
    // unpinned and prunable. That is §9.6 item 4's slash re-entering through
    // the error path of the refresh built to close it.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(0));
    let pinned = PinnedServeSet::acquire(&pinner).await.expect("pin");

    // Segment 0 freezes and is pruned before this persona ever bonded it.
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    store.prune_frozen(&[]).expect("prune unpinned");

    // Holdings now name the unrecoverable shard 0 AND a fresh shard 1.
    pinner.holdings_became(&[0, 1], BlockHeight(20_000));
    let refreshed = pinned
        .refreshed(&pinner)
        .await
        .expect("a pruned member must not refuse the refresh");

    assert_eq!(
        refreshed.already_pruned(),
        &[0],
        "the unrecoverable member stays visible rather than being swallowed"
    );
    assert_eq!(refreshed.serve_set().shard_ids(), Some(&[0u64, 1][..]));

    // The point of not refusing: shard 1 got pinned. Freeze it, prune, and
    // it must still be there — under a whole-set refusal it would not be.
    let mut second = segment_entries();
    for (i, e) in second.iter_mut().enumerate() {
        e.gindex = Gindex(leaves_per_segment() as u64 + i as u64);
    }
    store
        .append_block_deltas(&second, &[], &[], BlockHeight(20_000))
        .expect("freeze segment 1");
    store.prune_frozen(&[]).expect("prune");
    assert!(
        store
            .open_frozen_segment_body(shekyl_curve_tree::SegmentId(1))
            .expect("read")
            .is_some(),
        "the refresh's pin on the gained shard is what survives the prune"
    );

    // And the host is not wedged: refresh still works afterwards.
    refreshed
        .refreshed(&pinner)
        .await
        .expect("refresh stays available for every future tick");
}

#[tokio::test]
async fn a_pruned_member_still_refuses_the_start() {
    // The asymmetry is deliberate and this is its other half: nothing is
    // serving yet, so refusing costs nothing and the rebuild wants to be
    // paid before the persona advertises itself.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    store.prune_frozen(&[]).expect("prune unpinned");

    let err = PinnedServeSet::acquire(&StorePinner::new(
        Arc::clone(&store),
        &[0],
        BlockHeight(10_000),
    ))
    .await
    .expect_err("acquire still refuses what refresh records");
    assert_eq!(err, PinError::MembersAlreadyPruned { shard_ids: vec![0] });
}

#[tokio::test]
async fn a_failing_refresh_is_visible_when_both_store_clocks_are_frozen() {
    // THE COMMON-MODE ARM. Every store-derived signal shares a failure mode
    // with the thing it watches: a curve-tree actor that fail-stops and
    // cannot be resumed stops block ingest AND fails every pin, so the
    // stamped baseline and the live tip freeze together and the lag stays
    // constant. A tripwire built only on those clocks reads `Current`
    // forever on a comprehensively broken wallet.
    //
    // The fixture is that exact shape: the pinner is down and the store
    // ingests nothing, so the lag arms have nothing to say. The count of
    // ATTEMPTS is the one local fact the fault cannot suppress.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(0));
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

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        host.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );

    // Everything stops at once. No ingest, no successful pin.
    pinner.fail_next();
    host.refresh().await.expect_err("the pinner is down");
    assert_eq!(
        host.staleness(bound).expect("read staleness"),
        Staleness::RefreshFailing { consecutive: 1 },
        "the store clocks are frozen and agree; only the attempt count moved"
    );

    host.refresh().await.expect_err("still down");
    host.refresh().await.expect_err("still down");
    let reading = host.staleness(bound).expect("read staleness");
    assert_eq!(
        reading,
        Staleness::RefreshFailing { consecutive: 3 },
        "the count is what separates a transient blip from a stoppage"
    );
    assert!(reading.is_stale());
    assert_eq!(reading.lag(), None, "no store reading was taken");
    // Rule 82: the message names what to check.
    assert!(reading.to_string().contains("curve-tree actor"));

    // Recovery clears it — the reading is about the LAST attempt, not a
    // latch an operator has to reset.
    pinner.recovered();
    host.refresh().await.expect("the transport came back");
    assert_eq!(
        host.staleness(bound).expect("read staleness"),
        Staleness::Current { lag: 0 }
    );

    host.shutdown().await;
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
    let pinner = StorePinner::new(Arc::clone(&store), &[0], BlockHeight(1));

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
        BlockHeight(1),
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

#[tokio::test]
async fn start_refuses_a_pinner_that_cannot_pin() {
    // start acquires internally, so a dead pinner is a host that never
    // begins — not a host serving an empty or unknown set.
    let dir = tempfile::tempdir().expect("tempdir");
    let err = PersonaServingHost::start(
        churning_tor(&dir),
        PersonaServing {
            identity: identity(),
            virtual_port: 80,
            max_streams: 8,
        },
        DeadPinner,
    )
    .await
    .expect_err("a dead pinner cannot start a host");
    assert!(matches!(err, HostError::Pin(PinError::Pinner { .. })));
}

#[tokio::test]
async fn a_refresh_that_pins_a_different_store_keeps_the_previous_witness() {
    // The host serves the store it acquired. A refresh whose pins land
    // elsewhere would mint a witness for a store nobody is reading. The
    // previous pins stay; the mismatch is an implementor defect.
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("freeze segment 0");
    let pinned =
        PinnedServeSet::acquire(&StorePinner::new(Arc::clone(&store), &[0], BlockHeight(1)))
            .await
            .expect("pin");

    struct OtherStorePinner;
    impl ServeSetPinner for OtherStorePinner {
        async fn pin_serve_set(&self) -> Result<PinReport, String> {
            let other = Arc::new(LeafStore::open_ephemeral().expect("other store"));
            Ok(PinReport {
                set: ReportedSet::ShardList {
                    shard_ids: vec![0],
                    outcomes: vec![(0, SegmentPin::PinnedServable)],
                },
                as_of_height: BlockHeight(2),
                reader: ServingReader::new(other),
            })
        }
    }

    let err = pinned
        .refreshed(&OtherStorePinner)
        .await
        .expect_err("pins in a different store cannot replace this witness");
    assert!(matches!(err, PinError::PinnerStoreMismatch));
    assert_eq!(pinned.serve_set().as_of_height(), BlockHeight(1));
}

#[tokio::test]
async fn host_staleness_uses_the_live_witness() {
    // PersonaServingHost::staleness is the operator-facing read. It must
    // go through the same poison-tolerant lock as every other witness
    // access — this bites against a host-side expect that would turn
    // one panic into a persona that stops answering; it does NOT cover
    // the lag arithmetic (that is
    // `staleness_reads_one_clock_twice_with_independent_drivers`).
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    let pinner = StorePinner::new(Arc::clone(&store), &[], BlockHeight(0));
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

    let bound = StalenessBound::blocks(100);
    assert_eq!(
        host.staleness(bound).expect("read host staleness"),
        Staleness::Current { lag: 0 }
    );

    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("ingest");
    let stale = host.staleness(bound).expect("read host staleness");
    assert!(
        stale.is_stale(),
        "ingest without refresh is stale on the host"
    );

    host.shutdown().await;
}

// ---------------------------------------------------------------------------
// The CompleteTree prefix arm (COMPLETETREE_ACTIVATION.md D-1/D-5, slice 2)
// ---------------------------------------------------------------------------

/// A pinner reporting the CompleteTree prefix over a real store — the
/// slice-3 production shape minus the actor hop and the claim-source fetch:
/// it reads the store's own burial-gated freeze cursor and reports it, so
/// the growth KAT below exercises the real "shards freeze → the obligation
/// grows" path rather than a number a test invented.
struct PrefixPinner {
    store: Arc<LeafStore>,
}

impl ServeSetPinner for PrefixPinner {
    async fn pin_serve_set(&self) -> Result<PinReport, String> {
        let frozen_count = self.store.next_freeze_seg().map_err(|e| format!("{e:?}"))?;
        Ok(PinReport {
            set: ReportedSet::CompleteTreePrefix { frozen_count },
            as_of_height: BlockHeight(10_000),
            reader: ServingReader::new(Arc::clone(&self.store)),
        })
    }
}

/// The prefix arm's precondition, both directions: a report over an
/// undeclared store refuses with the typed error naming the remedy, and the
/// same report acquires once the posture is declared. The membership
/// boundary is asserted on the resulting witness (`k-1` in, `k` out), plus
/// the accessors that keep the two-empties hazard closed: `shard_ids()` is
/// `None` for a whole-corpus obligation, never an empty list.
#[tokio::test]
async fn prefix_acquire_requires_the_declared_posture_and_bounds_membership() {
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");
    let pinner = PrefixPinner {
        store: Arc::clone(&store),
    };

    let err = PinnedServeSet::acquire(&pinner)
        .await
        .expect_err("a corpus claim over an undeclared store must refuse");
    assert!(matches!(err, PinError::PostureNotDeclared), "got {err:?}");
    assert!(
        err.to_string().contains("set_prune_disabled"),
        "the refusal must name the remedy: {err}"
    );

    store.set_prune_disabled().expect("declare the posture");
    let pinned = PinnedServeSet::acquire(&pinner)
        .await
        .expect("the declared posture is the prefix arm's pin");

    let set = pinned.serve_set();
    assert_eq!(set.complete_tree_frozen_count(), Some(1));
    assert!(set.contains(0), "k-1 is in the obligation");
    assert!(!set.contains(1), "k is not — the boundary is exclusive");
    assert!(!set.is_empty());
    assert_eq!(
        set.shard_ids(),
        None,
        "a whole-corpus obligation has no list; rendering it as [] would \
         rebuild the two-empties conflation"
    );
    assert!(pinned.not_yet_frozen_at_last_pin().is_empty());
    assert!(pinned.already_pruned().is_empty());
    assert!(matches!(
        pinned.staleness(StalenessBound::blocks(64)).expect("read"),
        Staleness::Current { .. }
    ));
}

/// D-5's growth policy, driven through the real store: a segment that
/// freezes between refreshes enters the obligation at the next refresh,
/// with no list maintained anywhere — the pinner re-reads the cursor and
/// the membership boundary moves.
#[tokio::test]
async fn prefix_refresh_admits_a_segment_that_froze_since_the_last_one() {
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store
        .append_block_deltas(&segment_entries(), &[], &[], BlockHeight(10_000))
        .expect("append and freeze segment 0");
    store.set_prune_disabled().expect("declare the posture");
    let pinner = PrefixPinner {
        store: Arc::clone(&store),
    };

    let pinned = PinnedServeSet::acquire(&pinner).await.expect("acquire");
    assert!(!pinned.serve_set().contains(1), "segment 1 has not frozen");

    // Segment 1 fills and freezes — the chain kept growing.
    let mut second = segment_entries();
    for (i, e) in second.iter_mut().enumerate() {
        e.gindex = Gindex(leaves_per_segment() as u64 + i as u64);
    }
    store
        .append_block_deltas(&second, &[], &[], BlockHeight(20_000))
        .expect("append and freeze segment 1");

    let refreshed = pinned.refreshed(&pinner).await.expect("refresh");
    assert_eq!(refreshed.serve_set().complete_tree_frozen_count(), Some(2));
    assert!(
        refreshed.serve_set().contains(1),
        "the newly frozen segment joined the obligation on the refresh \
         after its freeze — the growth policy is the re-read"
    );
    assert!(
        !refreshed.serve_set().contains(2),
        "and the boundary moved to exactly the new cursor"
    );
}

/// The prefix over a store that has frozen nothing is honestly empty — a
/// Foundation wallet at genesis owes nothing servable yet — and still
/// acquires, because an empty obligation is a state, not a fault.
#[tokio::test]
async fn prefix_over_an_unfrozen_store_is_empty_and_still_acquires() {
    let store = Arc::new(LeafStore::open_ephemeral().expect("open store"));
    store.set_prune_disabled().expect("declare the posture");
    let pinner = PrefixPinner {
        store: Arc::clone(&store),
    };

    let pinned = PinnedServeSet::acquire(&pinner)
        .await
        .expect("an empty corpus is not an error");
    assert!(pinned.serve_set().is_empty());
    assert_eq!(pinned.serve_set().complete_tree_frozen_count(), Some(0));
    assert!(!pinned.serve_set().contains(0));
    assert!(
        pinned.dropped_pins().expect("read").is_empty(),
        "no per-member pins exist to drop on the prefix arm"
    );
}
