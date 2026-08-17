// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `Engine::start_serving_if_staker` — the construction site.

use shekyl_p_host::PersonaServing;

use super::task::{
    spawn_serving_task, ServingConfig, CLAIM_SOURCE_TIMEOUT, SERVING_MAX_STREAMS,
    SERVING_VIRTUAL_PORT,
};
use super::tor_config::{tor_service_config, TorConfigError};
use super::ServingHandle;

/// Why a staker's serving host could not be started.
#[derive(Debug, thiserror::Error)]
pub enum ServingStartError {
    /// No stake engine is resident.
    #[error("this wallet is not staking")]
    NoStakeEngine,
    /// `staking_enabled` with no resident actor — the mid-session bond-watch
    /// recovery state. Names the reopen remedy rather than reporting a generic
    /// "not a staker" over a wallet that just recovered its staking history
    /// (rule 82), mirroring `PScanStartError::RecoveredPendingReopen`.
    #[error("this wallet recovered staking history this session; reopen it to start serving")]
    RecoveredPendingReopen,
    /// The wallet's Tor configuration could not be established.
    ///
    /// The source may name a local path; callers that cross a wire (JSON-RPC)
    /// must not stringify this variant for the client.
    #[error("the wallet's Tor configuration is unusable")]
    TorConfig(#[source] TorConfigError),
    /// The persona's serving identity could not be read from the stake engine.
    ///
    /// Source is boxed so this public error does not name the crate-private
    /// `StakeEngineError` (same shape as `PScanStartError::LoadFailed`).
    #[error("the persona's serving identity is unavailable")]
    Identity(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The daemon this wallet talks to is not on loopback, so there is no
    /// persona-isolated transport to derive the serve-set over.
    ///
    /// Serving currently requires an **own node** — which is the documented
    /// privacy default (SP-T2: "run-your-own-node is the privacy default"), and
    /// the ② remote posture that would lift this is the unbuilt 2c
    /// config-source slice. Refused loudly with the remedy named rather than
    /// silently serving a set derived over the principal's shared connection.
    ///
    /// The source may name the refused URL; do not stringify it onto a client
    /// surface.
    #[error(
        "serving derives its shard set over a persona-isolated transport, which \
         currently requires your own node on loopback"
    )]
    DaemonNotLoopback(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// A serving host is already running for this wallet — the single-flight
    /// slot is held. Two hosts would publish the same onion and fight over
    /// one Tor data directory.
    #[error("a serving host is already running for this wallet")]
    AlreadyRunning,
}

// Same Engine-trait privacy posture as `start_pscan_with`: the engine traits are
// `pub(crate)` and the entry point is re-exported for the embedder, exactly as
// `PScanHandle`'s is.
#[allow(private_bounds)]
impl<S, D, L, E, R, P> crate::engine::Engine<S, D, L, E, R, P, shekyl_engine_file::WalletFile>
where
    S: crate::engine::EngineSignerKind + Send + Sync + 'static,
    D: crate::engine::traits::DaemonEngine,
    L: crate::engine::traits::LedgerEngine,
    E: crate::engine::traits::EconomicsEngine,
    R: crate::engine::traits::RefreshEngine,
    P: crate::engine::traits::PendingTxEngine,
    Self: Send + Sync,
{
    /// Start the persona serving host **iff this wallet is a staker with an
    /// active persona** — the lifecycle auto-start, sibling to
    /// [`start_pscan_if_staker`](Self::start_pscan_if_staker).
    ///
    /// Returns `Ok(None)` for a non-staker, and for a staker with no *active*
    /// persona: there is nothing to serve until one is activated, and
    /// first-stake mid-session already collapses onto reopen under Model D, so
    /// the serving start follows the same rule rather than inventing a
    /// mid-session activation hook.
    ///
    /// The returned [`ServingHandle`] is **embedder-held** for the wallet's open
    /// lifetime, exactly as `PScanHandle` is, and shutting it down is what
    /// unpublishes the onion in the right order.
    ///
    /// # Posture-blind by design
    ///
    /// This site does not read the persona's holdings kind, and must not
    /// start to. Both archival postures start a host here; which obligation
    /// that host carries — an explicit shard list or the whole frozen
    /// prefix — is derived one layer down by `EngineServeSetPinner`, from
    /// the **connected bond record** (`COMPLETETREE_ACTIVATION.md` D-1).
    /// The SH-2b question this call once carried ("should a host start at
    /// all for a `CompleteTree` persona?") is closed by that split: yes,
    /// and the kind-aware decision lives with the code that reads the
    /// record rather than with the code that spawns the task.
    ///
    /// A Foundation wallet whose store has frozen nothing yet starts on an
    /// **empty prefix** (`frozen_count = 0`) and grows at refresh as
    /// segments freeze (D-5). That is a valid serving state, not a reason
    /// to withhold the host: the obligation is empty precisely because the
    /// corpus is, and a host that refused to start would have to be started
    /// by something later noticing — the polling nobody writes.
    ///
    /// # The daemon endpoint is the caller's
    ///
    /// The serve-set is derived over a persona-isolated transport, and the
    /// wallet's daemon address lives with the embedder rather than on the
    /// `Engine` — the same shape `submit_emission_claim` already uses for the
    /// claim path. The caller passes the address it already holds; this method
    /// builds the ① local-posture transport from it and refuses anything that
    /// is not loopback.
    ///
    /// # No filesystem I/O under the engine lock
    ///
    /// The read borrow clones spawn inputs (stake handle, curve-tree handle,
    /// wallet path, device prefs). Directory creation and the loopback
    /// transport constructor run after the lock is released — the same
    /// discipline [`start_pscan`](Self::start_pscan) documents.
    ///
    /// # Errors
    ///
    /// [`ServingStartError`] — see its variants. Every arm except
    /// [`AlreadyRunning`](ServingStartError::AlreadyRunning) is fail-closed at
    /// open: a staker that cannot serve accrues misses toward a slash, and the
    /// operator cannot see it happening.
    pub async fn start_serving_if_staker(
        self_arc: std::sync::Arc<tokio::sync::RwLock<Self>>,
        daemon_address: &str,
    ) -> Result<Option<ServingHandle>, ServingStartError> {
        // Brief read borrow: clone the spawn inputs. Filesystem work stays
        // outside this lock — `tor_service_config` creates and chmods a
        // directory, and holding the engine `RwLock` across that would stall
        // every other reader on disk.
        let (stake, curve_tree, base_path, device) = {
            let g = self_arc.read().await;
            let stake = match g.stake_handle() {
                Some(stake) => stake,
                None if g.ledger.staking_enabled() => {
                    return Err(ServingStartError::RecoveredPendingReopen)
                }
                None => return Ok(None),
            };
            (
                stake,
                g.curve_tree.clone(),
                g.persistence().base_path().to_path_buf(),
                g.prefs().device.clone(),
            )
        };

        let tor = tor_service_config(&base_path, &device).map_err(ServingStartError::TorConfig)?;

        let Some(active) = stake
            .active_persona()
            .await
            .map_err(|e| ServingStartError::Identity(Box::new(e)))?
        else {
            // A staker with no active persona has nothing to serve yet.
            return Ok(None);
        };

        // Claim only once we know we will start a host. An idle staker must
        // not occupy the slot; a second start after activation must.
        let slot_guard = {
            let g = self_arc.read().await;
            g.open_slots
                .serving
                .try_claim()
                .ok_or(ServingStartError::AlreadyRunning)?
        };

        let identity = stake
            .persona_onion_identity(active.p_slot)
            .await
            .map_err(|e| ServingStartError::Identity(Box::new(e)))?;
        let p_id = shekyl_archival_retention::id::p_canonical_id_from_hybrid_pubkey(
            &active
                .bond_id
                .to_canonical_bytes()
                .map_err(|e| ServingStartError::Identity(Box::new(e)))?,
        );

        // ① local posture. `LocalNodeRpc` refuses a non-loopback URL by
        // construction, so the refusal below is the type's, not a check here.
        let claim_rpc =
            crate::engine::prpc::LocalNodeRpc::new(daemon_address.to_owned(), CLAIM_SOURCE_TIMEOUT)
                .await
                .map_err(|e| ServingStartError::DaemonNotLoopback(Box::new(e)))?;

        let pinner = crate::engine::stake_engine::serve_set_source::EngineServeSetPinner::new(
            curve_tree,
            claim_rpc,
            p_id.to_bytes(),
        );

        Ok(Some(spawn_serving_task(
            tor,
            PersonaServing {
                identity,
                virtual_port: SERVING_VIRTUAL_PORT,
                max_streams: SERVING_MAX_STREAMS,
            },
            pinner,
            std::sync::Arc::new(shekyl_operator_alarm::OperatorAlarms::new()),
            ServingConfig::production(
                crate::engine::pscan::start::DEFAULT_PSCAN_CADENCE,
                // Single-sourced from the same place the submit driver's
                // watchdog horizon comes from, rather than taken as an
                // embedder argument: the block target is a consensus
                // parameter, not a wallet setting.
                shekyl_economics::EconomicParams::default().daa_target_seconds,
            ),
            // The wallet's own directory — the volume the curve-tree
            // store grows on. Tor's data dir is deliberately not used:
            // it can be a different mount, and the disk that matters
            // is the one the corpus lands on.
            base_path.clone(),
            slot_guard,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_rpc_transport::HttpRpc;
    use shekyl_types::PSlot;
    use tempfile::TempDir;
    use tokio::sync::RwLock;

    use crate::engine::signer::SoloSigner;
    use crate::engine::{Credentials, DaemonClient, Engine, EngineCreateParams, OpenedEngine};

    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct HttpRpc (no actual connection attempted)");
        DaemonClient::new(rpc)
    }

    fn fixed_seed() -> [u8; MASTER_SEED_BYTES] {
        let mut s = [0u8; MASTER_SEED_BYTES];
        for (i, b) in s.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap_or(0).wrapping_mul(7);
        }
        s
    }

    fn creds() -> Credentials<'static> {
        Credentials::password_only(b"correct horse battery staple")
    }

    fn non_staker_engine() -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
        (tmp, engine)
    }

    fn staker_engine(slot: u32) -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let network = params.network;
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
        engine
            .persist_bond_record(PSlot::from_raw(slot))
            .expect("persist bond record");
        engine.close(&creds).expect("close");
        let opened = Engine::<SoloSigner>::open_full(
            &base,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen staker");
        let engine = match opened {
            OpenedEngine::Loaded(w) => w,
            OpenedEngine::Restored { wallet, .. } => wallet,
        };
        assert!(engine.stake_handle().is_some());
        (tmp, engine)
    }

    async fn activate(engine: &Engine<SoloSigner>, slot: u32) {
        let stake = engine.stake_handle().expect("staker");
        let handle = stake
            .mint_handle(PSlot::from_raw(slot))
            .await
            .expect("mint");
        stake.activate_persona(handle).await.expect("activate");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_serving_if_staker_is_none_for_a_non_staker() {
        let (_tmp, engine) = non_staker_engine();
        let arc = Arc::new(RwLock::new(engine));
        let started =
            Engine::<SoloSigner>::start_serving_if_staker(arc.clone(), "http://127.0.0.1:1")
                .await
                .expect("non-staker auto-start must not error");
        assert!(started.is_none(), "a non-staker gets no serving host");
        assert!(
            !arc.read().await.open_slots.serving.is_claimed(),
            "the quiet path must not claim the serving slot"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_staker_gets_no_host_and_does_not_claim_the_slot() {
        let (_tmp, engine) = staker_engine(3);
        let arc = Arc::new(RwLock::new(engine));
        let started =
            Engine::<SoloSigner>::start_serving_if_staker(arc.clone(), "http://127.0.0.1:1")
                .await
                .expect("idle staker is Ok(None), not an error");
        assert!(
            started.is_none(),
            "nothing to serve until a persona is active"
        );
        assert!(
            !arc.read().await.open_slots.serving.is_claimed(),
            "an idle staker must not occupy the slot an activation will need"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_remote_daemon_is_refused_rather_than_served_over_the_principal() {
        let (_tmp, engine) = staker_engine(3);
        activate(&engine, 3).await;
        let arc = Arc::new(RwLock::new(engine));
        let Err(err) =
            Engine::<SoloSigner>::start_serving_if_staker(arc.clone(), "http://example.com:18081")
                .await
        else {
            panic!("non-loopback must fail closed");
        };
        assert!(
            matches!(err, ServingStartError::DaemonNotLoopback(_)),
            "got {err:?}"
        );
        assert!(
            !arc.read().await.open_slots.serving.is_claimed(),
            "a refused start must release the slot"
        );
        // The public Display must not carry the refused URL — that string
        // crosses JSON-RPC via the wallet-rpc From impl.
        let shown = err.to_string();
        assert!(
            !shown.contains("example.com"),
            "the refused host must not leak onto a client surface: {shown}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_start_is_already_running_while_the_first_host_is_held() {
        let (_tmp, engine) = staker_engine(3);
        activate(&engine, 3).await;
        let arc = Arc::new(RwLock::new(engine));
        let first =
            Engine::<SoloSigner>::start_serving_if_staker(arc.clone(), "http://127.0.0.1:1")
                .await
                .expect("first start")
                .expect("active persona starts a host");
        assert!(arc.read().await.open_slots.serving.is_claimed());

        match Engine::<SoloSigner>::start_serving_if_staker(arc.clone(), "http://127.0.0.1:1").await
        {
            Err(ServingStartError::AlreadyRunning) => {}
            Ok(_) => panic!("expected AlreadyRunning, got a second handle"),
            Err(other) => panic!("expected AlreadyRunning, got {other:?}"),
        }

        first.shutdown().await;
        assert!(
            !arc.read().await.open_slots.serving.is_claimed(),
            "shutdown releases the serving slot"
        );
    }
}
