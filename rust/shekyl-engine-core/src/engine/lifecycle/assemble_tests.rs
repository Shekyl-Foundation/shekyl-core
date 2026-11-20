// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! S6 at the wallet open (conformance build only): what
//! [`observe_stake_self_cert`] does with the stake engine's random-number
//! check, after the open has spawned both actors. A `#[path]` child of
//! `assemble.rs`, so the function under test stays private to it.

use super::*;

use tempfile::TempDir;

use crate::engine::curve_tree_actor::{CurveTreeHandle, CurveTreeHandleError};
use crate::engine::stake_engine::test_fixtures::{spawn_over, spawn_with_self_cert, TestSelfCert};
use crate::engine::stake_engine::StakeEngineError;
use shekyl_curve_tree::CurveTreeClient;

fn curve_tree_over(dir: &TempDir) -> CurveTreeHandle {
    let client = CurveTreeClient::open(dir.path().join("curve_tree.redb"))
        .expect("open fresh curve-tree client");
    CurveTreeHandle::spawn(client)
}

/// A source that fails the check refuses the open with the unit
/// `OpenError::StakeRngSelfCertFailed`, and both actors the open spawned
/// are stopped before the refusal returns, so the `?` at the call site
/// drops no live actor and the wallet's files are closed.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_random_source_check_refuses_the_open_and_stops_its_actors() {
    let dir = TempDir::new().expect("tempdir");
    let curve_tree = curve_tree_over(&dir);
    let stake = spawn_with_self_cert(&[0], TestSelfCert::Degenerate);

    let refused = observe_stake_self_cert(&stake, &curve_tree);

    assert!(
        matches!(refused, Err(OpenError::StakeRngSelfCertFailed)),
        "a degenerate source must refuse the open, got {refused:?}"
    );
    assert!(matches!(
        curve_tree.ingested_tip_height().await,
        Err(CurveTreeHandleError::Unavailable)
    ));
    assert!(matches!(
        stake.active_persona().await,
        Err(StakeEngineError::StakeActorUnavailable)
    ));
}

/// A check that passes lets the open go on with both actors serving.
/// The check is skipped here rather than graded over `OsRng`, so the
/// grade's one-in-a-million false alarm cannot fail this test; the real
/// grade's pass path is the stake suite's
/// `session_self_cert_passes_over_os_rng_at_spawn`.
#[tokio::test(flavor = "multi_thread")]
async fn a_passed_check_leaves_both_actors_serving() {
    let dir = TempDir::new().expect("tempdir");
    let curve_tree = curve_tree_over(&dir);
    let stake = spawn_over(&[0], &[], None);

    let observed = observe_stake_self_cert(&stake, &curve_tree);

    assert!(
        observed.is_ok(),
        "a passed check must not refuse the open, got {observed:?}"
    );
    assert!(curve_tree.ingested_tip_height().await.is_ok());
    assert!(stake.active_persona().await.is_ok());

    stake.shutdown().await;
    curve_tree.shutdown().await;
}
