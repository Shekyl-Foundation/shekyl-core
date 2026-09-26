// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Live apparatus validation — the §7 `#[ignore]`d end-to-end gate.
//!
//! **This is not the measurement.** It proves the apparatus works: two personas
//! publish (each behind its own tor), both are reachable from the client tor
//! over real rendezvous circuits, both serve bodies whose countersignature
//! verifies under the persona's key and whose length matches the serving
//! contract (frame + leaves), the derived `.onion` is the one tor published,
//! `NEWNYM`
//! is accepted by the client tor, and the services are withdrawn on shutdown.
//! The measurement itself is the `pd-f2-measure`
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

use shekyl_sp_t3_spike::harness::Apparatus;

/// The pinned tor binary. **Hard-fails** rather than skipping, so a
/// misconfigured integration lane is loud instead of silently passing by not
/// running (the same posture as `shekyl-tor-control-client`'s `test_support::tor_binary`).
fn tor_binary() -> std::path::PathBuf {
    std::env::var_os("SHEKYL_SPIKE_TOR")
        .map(std::path::PathBuf::from)
        .expect("SHEKYL_SPIKE_TOR must point at the pinned Tor Expert Bundle binary")
}

#[tokio::test]
#[ignore = "requires the pinned Tor binary via SHEKYL_SPIKE_TOR (bootstraps, publishes onions, network)"]
async fn two_personas_publish_and_serve_over_real_rendezvous() {
    // A payload whose length is a whole number of leaves: the served frame
    // requires that, and the apparatus derives expected body length (frame +
    // leaves) itself. The live gate asserts that derived length plus a valid
    // countersignature — `fetch_via` plugs `ContentVerify` open so a short
    // body stays `Truncated` (stream) rather than a content refusal the
    // measurement would void as apparatus error. Same-length substitution is
    // not this gate's subject (the endpoint is ours).
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();

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

    app.await_reachable()
        .await
        .expect("every persona becomes reachable and none is refused");

    // Both personas serve, cold: countersignature valid under the persona's
    // key, derived body length matches. A `NEWNYM`
    // before each is the cold arm's mechanism, so its acceptance by the client
    // tor is asserted here too — a rig whose "cold" signal was silently
    // refused would time warm circuits and call them cold.
    for index in [0usize, 1usize] {
        app.rotate_client_circuits()
            .await
            .expect("client tor accepts SIGNAL NEWNYM");
        let obs = app.timed_fetch(index).await;
        // The serve-side counters are in the message so a `Circuit` here
        // can be told apart from `P` shedding the connection at its cap.
        assert!(
            obs.is_success(),
            "persona {index} must serve its shard over the rendezvous: {obs:?} \
             (served so far: {}, shed at the serve-side cap: {})",
            app.served_total(),
            app.refused_total()
        );
    }

    // A warm fetch (no signal, same persona) must also succeed — this is the
    // arm the measurement calls optimistic, and a failure here would mean the
    // warm arm measures nothing. Persona 1 is the one fetched *last*, with no
    // `NEWNYM` since: its rendezvous circuit is the one the client tor still
    // holds. Persona 0's was dirtied by the signal before persona 1's fetch,
    // so refetching it here would build a fresh circuit and validate nothing
    // about reuse.
    let warm = app.timed_fetch(1).await;
    assert!(
        warm.is_success(),
        "warm-circuit fetch must succeed: {warm:?}"
    );

    // Apparatus cross-check: the endpoints served every request the client
    // leg believes it made (2 cold fetches + 1 warm + at least one cold
    // readiness probe per persona). A "success" that the endpoint never saw
    // would mean the bytes came from somewhere else entirely.
    assert!(
        app.served_total() >= 5,
        "the endpoints must have served every counted fetch, got {}",
        app.served_total()
    );

    // Teardown withdraws the onions (`on_stop` issues DEL_ONION before killing
    // the child) and reaps tor.
    app.shutdown().await;
}
