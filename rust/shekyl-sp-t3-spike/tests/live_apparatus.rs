// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live apparatus validation — the §7 `#[ignore]`d end-to-end gate.
//!
//! **This is not the measurement.** It proves the apparatus works: two personas
//! publish, both are reachable over real rendezvous circuits, both serve their
//! bytes intact, the derived `.onion` is the one tor published, and the services
//! are withdrawn on shutdown. The measurement itself is the `pd-f2-measure`
//! binary, which is deliberately not a test (§7: tests must not depend on network
//! conditions, and a distribution is the wrong shape for a green/red verdict).
//!
//! The payload here is small on purpose. A 3.33 MB fetch would make this a slow
//! *latency* test whose result depends on the network — exactly what §7 forbids —
//! whereas what needs asserting is that the wiring is correct. The shard-sized
//! payload belongs to the measurement run.
//!
//! Run with:
//! ```text
//! SHEKYL_SPIKE_TOR=/path/to/pinned/tor \
//!   cargo test -p shekyl-sp-t3-spike --test live_apparatus -- --ignored --nocapture
//! ```

use std::sync::Arc;

use shekyl_sp_t3_spike::harness::{cold_client_id, warm_client_id, Apparatus};

/// The pinned tor binary. **Hard-fails** rather than skipping, so a
/// misconfigured integration lane is loud instead of silently passing by not
/// running (the same posture as `shekyl-tor`'s `test_support::tor_binary`).
fn tor_binary() -> std::path::PathBuf {
    std::env::var_os("SHEKYL_SPIKE_TOR")
        .map(std::path::PathBuf::from)
        .expect("SHEKYL_SPIKE_TOR must point at the pinned Tor Expert Bundle binary")
}

#[tokio::test]
#[ignore = "requires the pinned Tor binary via SHEKYL_SPIKE_TOR (bootstraps, publishes onions, network)"]
async fn two_personas_publish_and_serve_over_real_rendezvous() {
    // A payload with structure, so a truncated or substituted response fails the
    // byte comparison rather than passing a length check.
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();
    let len = payload.len();

    let dir = tempfile::tempdir().expect("tempdir");
    let app = Apparatus::bring_up(
        tor_binary(),
        dir.path().join("tor-data"),
        2,
        Arc::from(payload.clone().into_boxed_slice()),
    )
    .await
    .expect("apparatus comes up");

    // The D2 encoding claim — tor publishes the v3 address the derivation
    // predicts — is enforced inside `bring_up` itself: it derives each persona's
    // service id and fail-stops if tor's published id differs (`harness.rs`, the
    // `published != service_id` guard). Reaching this point means every persona's
    // published `.onion` already matched its derived one; re-deriving here against
    // the same pure function would only restate that, so it is not repeated.
    //
    // What is still worth asserting is that the two personas do not share an
    // address — distinct slots must publish distinct onions.
    assert_ne!(
        app.personas[0].service_id(),
        app.personas[1].service_id(),
        "distinct slots must publish distinct onions"
    );

    app.await_reachable(len)
        .await
        .expect("at least one persona becomes reachable");

    // Both personas serve, over distinct client circuits, and the bytes arrive
    // intact. Distinct client ids so the two fetches ride separate circuits —
    // the client-side isolation SP-T2 proved, exercised here on the serving axis.
    for (index, id_seq) in [(0usize, 900_001u64), (1usize, 900_002u64)] {
        let obs = app.timed_fetch(&cold_client_id(id_seq), index, len).await;
        assert!(
            obs.is_success(),
            "persona {index} must serve its shard over the rendezvous: {obs:?}"
        );
    }

    // A warm fetch (reused client id) must also succeed — this is the arm the
    // measurement calls optimistic, and a failure here would mean the warm arm
    // measures nothing.
    let warm = app.timed_fetch(&warm_client_id(), 0, len).await;
    assert!(
        warm.is_success(),
        "warm-circuit fetch must succeed: {warm:?}"
    );

    // Apparatus cross-check: the endpoints served exactly the requests the client
    // leg believes it made (2 persona fetches + 1 warm + at least 1 reachability
    // probe). A "success" that the endpoint never saw would mean the bytes came
    // from somewhere else entirely.
    assert!(
        app.served_total() >= 4,
        "the endpoints must have served every counted fetch, got {}",
        app.served_total()
    );

    // Teardown withdraws the onions (`on_stop` issues DEL_ONION before killing
    // the child) and reaps tor.
    app.shutdown().await;
}
