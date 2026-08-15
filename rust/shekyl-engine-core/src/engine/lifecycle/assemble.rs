// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Engine field assembly shared by create and open.
//!
//! This is the remaining lifecycle carve named by the decomposition
//! ratchet: one place establishes cache invariants and runs the SP-R0
//! staking reconcile before persona derive.

use tracing::warn;

use shekyl_address::Network;
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::account::{DerivationNetwork, SeedFormat, MASTER_SEED_BYTES};
use shekyl_crypto_pq::archival_p::derive_archival_p_keys;
use shekyl_engine_file::WalletFile;
use shekyl_engine_prefs::WalletPrefs;
use shekyl_engine_state::{LedgerIndexes, StakingBlock, WalletLedger};

use crate::engine::error::{IoError, KeyError, OpenError};
use crate::engine::stake_engine::{PSlot, StakeEngineHandle, ARCHIVAL_PERSONA_LOOKAHEAD};
use crate::engine::{Capability, DaemonClient, Engine, SoloSigner};

use super::support::{network_to_derivation, rederivation_failure_detail};
use super::FirstStakeIntent;

impl Engine<SoloSigner> {
    /// Internal field-by-field assembly used by [`Self::create`] and
    /// [`Self::open_full`]. Pulled out so the cache invariants
    /// (network, capability) are established in exactly one place, and the
    /// SP-R0 staking reconcile runs before the persona derive on every open path.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assemble(
        mut file: WalletFile,
        keys: AllKeysBlob,
        master_seed: &[u8; MASTER_SEED_BYTES],
        seed_format: SeedFormat,
        mut ledger: WalletLedger,
        indexes: LedgerIndexes,
        prefs: WalletPrefs,
        daemon: DaemonClient,
        network: Network,
        capability: Capability,
        first_stake_intent: Option<FirstStakeIntent>,
    ) -> Result<Self, OpenError> {
        let state_wrap_key = crate::engine::sealing_keys::state_wrap_key_from_wallet_file(&file);

        // SP-R0 open-time staking reconciliation (arms #2 retired GC, #3
        // phantom GC, #4 SA-5 monotone raise) — before the persona derive.
        // The raise's interesting slots sit *outside* the bonded hint (a
        // rolled-back record is missing them), so this runs whenever a
        // pscan seal exists, not only when the hint is non-empty. Drops
        // stay no-ops on an empty hint. Mutations are in-memory (persisted
        // by the normal save discipline; a lost pass re-runs at the next
        // open — idempotent).
        //
        // A seal read/decode failure DEGRADES to skipping the reconcile
        // rather than failing the open: the seals are auxiliary. Skipping
        // the drops is conservative for funds (keep, don't drop). Skipping
        // the raise cannot heal a rolled-back cursor from chain evidence;
        // spawn still applies the hint-fed `monotone_current_slot_from_record`.
        // The staker's scan path still fails loud on the same corrupt seal
        // at `start_pscan`.
        let derivation_network = network_to_derivation(network);
        // Cache-first, identity-only on miss: persona ids are pure functions
        // of the seed and never invalidate, so a slot already in the sealed
        // `persona_id_cache` costs zero keygens here (the reconcile re-reads
        // ids for bonded + lookahead slots on EVERY open — re-deriving them
        // was pure waste), and a miss derives only the identity hybrid
        // (`derive_archival_p_identity_pk` — byte-identical to the full
        // bundle's `hybrid_bond_id`, pinned in `shekyl-crypto-pq`), skipping
        // the ML-KEM / receive / bond-spend work no id consumer needs.
        // Cache-consistency note: a sighted slot was matched against the
        // CACHED id at scan time, so evaluating arm #3 with the same cached
        // id is the self-consistent read; the cache rides the AEAD-sealed
        // ledger, which is what guards its integrity.
        let cached_probe_ids = ledger.staking.persona_id_cache.clone();
        let id_of_slot = move |slot: u32| -> Result<shekyl_types::PCanonicalId, OpenError> {
            if let Some(id) = cached_probe_ids.get(&slot) {
                return Ok(*id);
            }
            let identity_pk = shekyl_crypto_pq::archival_p::derive_archival_p_identity_pk(
                master_seed,
                derivation_network,
                seed_format,
                slot,
            )
            .map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;
            let bytes = identity_pk.to_canonical_bytes().map_err(|_| {
                OpenError::Key(KeyError::Primitive {
                    detail: "persona canonical id encode failed",
                })
            })?;
            Ok(shekyl_archival_retention::p_canonical_id_from_hybrid_pubkey(&bytes))
        };
        // The bond watch's retired refusal set: probe ids for durably-retired
        // slots are excluded from the watch (their cursor burn is arm #2's,
        // from the same seal). Empty when the seal is ABSENT (fresh restore —
        // nothing was ever retired, so the empty set is a true statement and
        // the watch runs: that IS the flagship reconstruction path).
        //
        // An UNREADABLE seal is a different case: the retirement evidence
        // exists but cannot be consulted, so the refusal set is unknown, not
        // empty — and adoption on positive sightings would re-adopt durably
        // retired slots on every rescan with no arm #2 run to drop them
        // (the reconcile is skipped on the same unreadable seal, so this
        // does NOT converge; a persistent decode failure churns forever).
        // The watch therefore DISABLES until the evidence is readable:
        // `bond_watch_enabled` gates the producer's watch map below. The
        // wallet still opens (funds access must not hang on the staking
        // seal); the staker's scan path fails loud on the same seal at
        // `start_pscan`, which is where the corruption gets surfaced and
        // resolved — and the next open with a readable (or absent) seal
        // re-arms the watch.
        let mut probe_retired: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        let mut bond_watch_enabled = true;
        match load_open_staking_evidence(&file, &state_wrap_key) {
            Ok(Some(OpenStakingEvidence {
                evidence,
                pending_slots,
                retired_slots,
            })) => {
                crate::engine::stake_persist::reconcile_staking_at_open(
                    &mut ledger.staking,
                    &evidence,
                    &pending_slots,
                    &retired_slots,
                    ARCHIVAL_PERSONA_LOOKAHEAD,
                    &id_of_slot,
                )?;
                probe_retired = retired_slots;
            }
            // No sealed scan state yet — nothing to reconcile against.
            Ok(None) => {}
            Err(detail) => {
                bond_watch_enabled = false;
                tracing::warn!(
                    %detail,
                    "SP-R0: open-time staking reconcile skipped — sealed scan \
                     evidence unreadable; bonded hint kept as-is, the \
                     chain-fed cursor raise does not run, and the bond watch \
                     is disabled for this session (the retired refusal set is \
                     unknown, so sighting adoption would be unsound). The \
                     wallet opens; a staker's scan will fail loud on the same \
                     seal"
                );
            }
        }

        // Bond-watch probe cache (SA-R-6 from-seed reconstruction): derive
        // the public persona ids for the probe window while the seed is
        // transiently in scope. Runs AFTER the reconcile so the window sits
        // above the (possibly raised) cursor, and UNCONDITIONALLY — a
        // never-staked wallet derives its `0..=W` window once (derive-once:
        // ids never invalidate), which is what makes the rescan-time pointer
        // reconstruction hold for every wallet, not only known stakers.
        crate::engine::bond_watch::extend_probe_cache(
            &mut ledger.staking,
            &probe_retired,
            crate::engine::stake_engine::ARCHIVAL_PERSONA_PROBE_WINDOW,
            &id_of_slot,
        )?;

        let prefs_hmac_key = shekyl_engine_prefs::PrefsHmacKey::derive(
            &file.opened_keys().file_kek,
            file.expected_classical_address(),
        );
        file.zeroize_transient_file_kek();
        // Construct the producer's view-and-spend material once, from
        // the freshly-derived `AllKeysBlob`, and move it into the
        // `LocalRefresh` aggregate per
        // [`docs/design/STAGE_1_PR_4_REFRESH_ENGINE.md`] §5.4.7 R4
        // (a-instance-scoped) + §7.X C5. `ViewMaterial` does not
        // implement `Clone`; the orchestrator never holds a second
        // copy after the move. The construction site is unique to
        // `assemble` so future open paths inherit the wiring
        // automatically.
        let view_material = crate::engine::view_material::ViewMaterial::try_from_keys(&keys)
            .map_err(|e| match e {
                crate::engine::error::RefreshError::Io(io) => OpenError::Io(io),
                // `try_from_keys` constructs only `RefreshError::Io(IoError::Scanner)`,
                // but the exhaustive match keeps the mapping
                // robust if `try_from_keys`'s error surface ever
                // widens (and surfaces a defensive translation
                // rather than a panic).
                other => OpenError::Io(IoError::Scanner {
                    detail: format!("ViewMaterial construction failed: {other:?}"),
                }),
            })?;
        let scan_start_floor = crate::engine::scan_floor::effective_scan_floor(
            ledger.sync_state.restore_from_height,
            file.effective_skip_to_height(),
            file.effective_refresh_from_block_height(),
        );
        // §6 step 3(a): derive the merge-path view-secret projection from the
        // owned blob *while it is still borrowable* — before `KeyActor::spawn`
        // consumes it below. This is the (6-i) construction-time projection;
        // the full blob then lives only in the actor.
        let merge_view_secret =
            crate::engine::key_actor::HandleDerivationViewSecret::from_keys(&keys);
        let refresh = std::sync::Arc::new(if bond_watch_enabled {
            crate::engine::local_refresh::LocalRefresh::with_bond_watch(
                view_material,
                scan_start_floor,
                // The watch map: the probe-id cache inverted, since-retired
                // slots filtered (see `bond_watch::watch_map`).
                crate::engine::bond_watch::watch_map(&ledger.staking, &probe_retired),
            )
        } else {
            // Retirement evidence unreadable (see the reconcile above): the
            // refusal set is unknown, so the watch runs EMPTY this session —
            // no sightings are produced and nothing can be (re-)adopted.
            // The probe-id cache above still extended (ids are pure,
            // derive-once, and never wrong); only adoption is gated.
            crate::engine::local_refresh::LocalRefresh::new(view_material, scan_start_floor)
        });

        // §6 step 3(b): spawn the `KeyActor`, which takes the `AllKeysBlob` by
        // value. After this point no `&AllKeysBlob` is reachable from the
        // orchestrator — every public read resolves from the handle's
        // construction-time projections, and every secret-touching op routes
        // through the actor's message protocol (§4.1–4.2). The spawn requires an
        // ambient runtime (`KeyEngineHandle::spawn` asserts `Handle::try_current`;
        // §4.2 require-ambient disposition — no engine-owned nested runtime).
        // `merge_view_secret` was derived above (step 3(a)) before this
        // consuming spawn.
        let key = crate::engine::key_actor::KeyEngineHandle::spawn(keys);

        // CT-5a commit 2: open the FCMP++ curve-tree store *beside the wallet
        // files* (`docs/design/CT5_ENGINE_WIRING.md` §3.1) and spawn the actor
        // over it. The store is the `.curvetree` sibling of the `.wallet` /
        // `.wallet.keys` pair; `open_and_spawn` resumes from its contents with
        // no genesis replay (R1-Q2). It requires the same ambient runtime the
        // `KeyEngineHandle::spawn` above already asserts, so it is grouped here
        // with the other actor spawn. A store-open failure is a wallet-file
        // boundary failure (the store is a wallet companion file), so it maps to
        // `IoError::WalletFile` with a curve-tree-store detail prefix rather than
        // a new error variant (which would force a downstream RPC-tier match).
        let curve_tree = {
            let store_path =
                shekyl_engine_file::paths::curve_tree_store_path_from(file.base_path());
            crate::engine::curve_tree_actor::CurveTreeHandle::open_and_spawn(&store_path).map_err(
                |e| {
                    OpenError::Io(IoError::WalletFile {
                        detail: format!("curve-tree store open failed: {e:?}"),
                    })
                },
            )?
        };

        // ARCHIVAL_BOND_CONSTRUCTION.md §10.2 (Model D): for a staker, derive the
        // derive-forward set from the still-borrowed `master_seed` and spawn the
        // StakeEngine over it. Read `&ledger.staking` *before* `ledger` is moved
        // into the `LocalLedger` aggregate below. Non-stakers (the common case)
        // get `None` — no derivation, no resident personas, no actor.
        let stake = Self::spawn_stake_engine_if_staker(
            master_seed,
            network_to_derivation(network),
            seed_format,
            &ledger.staking,
            first_stake_intent,
        )?;

        let ledger = std::sync::Arc::new(crate::engine::local_ledger::LocalLedger::new(
            ledger, indexes,
        ));
        let fee_snapshot_source =
            crate::engine::fee_snapshot::DaemonFeeSnapshotSource::new(daemon.clone());
        let submitter = std::sync::Arc::new(
            crate::engine::transaction_submitter::DaemonTransactionSubmitter::new(
                std::sync::Arc::new(daemon.clone()),
            ),
        );
        let pending = crate::engine::LocalPendingTx::new(
            // §6 step 4: the signer no longer holds `Arc<AllKeysBlob>`; it
            // carries a `KeyEngineHandle` clone and the future signing path
            // routes through the actor's `SignTransaction` message.
            std::sync::Arc::new(crate::engine::LocalSigner::new(key.clone())),
            crate::engine::WalletGreedyOutputSelector,
            crate::engine::DaemonFeeEstimator,
            fee_snapshot_source,
            submitter,
            std::sync::Arc::clone(&ledger),
            // CT-5 §3.2.1 D1/D3 (commit 4b): share the curve-tree actor handle so
            // the spend path gates selection on `min(synced_height, tree_cursor)`.
            Some(curve_tree.clone()),
            std::sync::Arc::new(crate::engine::TracingDiagnosticSink),
            crate::engine::pending::ReservationTTLConfig::default(),
            network,
        );

        // The economics slot is assembled but not consumed by any production
        // path at V3.0 (PR 7 R6). The base-subsidy consensus cutover
        // (7-cutover / C2c, #93) routed `get_block_reward` to the Rust
        // primitive `shekyl_base_block_reward` directly, not through this
        // trait, so this engine field stays unconsumed. (The claim-era
        // pool_weighted_total chain-read seam was retired with the
        // confidential-staking sweep.)
        let economics = crate::engine::local_economics::LocalEconomics::new();

        // §5.3 submit lifecycle driver: the escape horizon is derived from
        // the consensus block target (`daa_target_seconds`, generated from
        // `config/consensus_constants.json` into `shekyl_economics`), the
        // same source the kernel's `WatchdogConfig::from_block_target`
        // documents. Owned by the Engine so its overlays persist across
        // ticks; the wallet surface and daemon are lent per tick.
        let submit_driver =
            tokio::sync::Mutex::new(crate::engine::submit_lifecycle::SubmitLifecycleDriver::new(
                shekyl_economics::EconomicParams::default().daa_target_seconds,
            ));

        Ok(Self {
            persistence: file,
            state_wrap_key,
            prefs_hmac_key,
            key,
            curve_tree,
            merge_view_secret,
            ledger,
            pending,
            submit_driver,
            prefs,
            daemon,
            network,
            capability,
            refresh_slot: crate::engine::refresh::RefreshSlot::new(),
            open_slots: crate::engine::refresh_slot::OpenTaskSlots::new(),
            pending_write_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            refresh,
            economics,
            stake,
            _signer: std::marker::PhantomData,
        })
    }

    /// Derive the Model-D derive-forward set and spawn the archival
    /// [`StakeEngine`](crate::engine::stake_engine::StakeEngine) for a staker, or return
    /// `None` for a non-staker (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2).
    ///
    /// The derive-forward set is
    /// [`StakingBlock::derive_forward_slots`] — `{bonded} ∪ {cursor ..= cursor+k}`,
    /// where `cursor` is the **scan-reconciled monotone** persona cursor
    /// ([`StakingBlock::monotone_current_slot_from_record`]) — never at or below
    /// an observed bonded slot, so a stale/rolled-back `p_slot` can never re-derive
    /// a moved-past persona as "current". The bonded slots are unioned in because
    /// under Model D the seed is dropped after this function returns, so a persona
    /// absent from the held set is unreachable for the wallet's life — and a
    /// retired-but-bonded persona's `bond_spend` key is needed to unbond it.
    ///
    /// The bundles are derived here from the transiently-borrowed `master_seed`;
    /// the seed is **not** moved in (it stays owned by the caller and drops at the
    /// caller's function end), and it never reaches the spawned actor. The actor
    /// starts **idle** (`active = None`): nothing is on the wire until 2c-2b's
    /// request path mints a [`PersonaHandle`](crate::engine::stake_engine::PersonaHandle)
    /// and activates it.
    ///
    /// # Cost
    ///
    /// One PQ keygen per slot in the set, run synchronously here. The whole
    /// `create` / `open_full` call is the blocking unit async callers wrap in
    /// `spawn_blocking` (module docs), so this is off the open hot path at that
    /// granularity; intra-call parallelism across the (small, `k`-bounded) set is
    /// a perf follow-up, not a correctness concern. Only stakers pay it.
    ///
    /// # Errors
    ///
    /// [`OpenError::Key`] if any archival derivation fails (same closed-error
    /// contract as `rederive_account`).
    fn spawn_stake_engine_if_staker(
        master_seed: &[u8; MASTER_SEED_BYTES],
        derivation_network: DerivationNetwork,
        seed_format: SeedFormat,
        staking: &StakingBlock,
        first_stake_intent: Option<FirstStakeIntent>,
    ) -> Result<Option<StakeEngineHandle>, OpenError> {
        // SA-R1-a (ARCHIVAL_STAKE_ACTIVATION_PLAN.md §5.6/§5.7, RATIFIED):
        // first-stake needs a spawned StakeEngine to assemble against BEFORE
        // `persist_bond_record` flips `staking_enabled`, so the gate admits a
        // transient first-stake intent. Pin (firewall gate): the intent is
        // NEVER persisted — it is set only by the credentialed `stake` RPC's
        // open-with-intent parameter and is `None` in every other open. An
        // aborted first-stake (spawn without persist) leaves only transient
        // derivation, dropped when the actor dies at close; the durable
        // staker state is exactly what `persist_bond_record` writes.
        if !staking.staking_enabled && first_stake_intent.is_none() {
            return Ok(None);
        }

        // The settlement-epoch schedule is consensus, and the wallet's epoch
        // arithmetic (P-scan accrual join epochs, claim-window recomputes)
        // runs on the genesis schedule unless this process explicitly armed
        // the regtest override — which no production wallet ever does. A
        // leaked SHEKYL_SETTLEMENT_EPOCH_BLOCKS (shared systemd template,
        // container base layer) is therefore ignored, and this is the loud,
        // once-per-open surface that names the ignored lever so the operator
        // can clean the environment instead of guessing.
        if shekyl_archival_retention::settlement_epoch_override_ignored() {
            warn!(
                "SHEKYL_SETTLEMENT_EPOCH_BLOCKS is set but this wallet is not an armed \
                 regtest context; the override is IGNORED and the genesis settlement-epoch \
                 schedule is in effect — unset the variable (it is a fakechain-only lever)"
            );
        }

        let mut slots = staking.derive_forward_slots(ARCHIVAL_PERSONA_LOOKAHEAD);
        // SA-R1-a: the intent slot rides the derive set (`{S} ∪ lookahead`,
        // plan §5.0 step 3) — normally already inside the lookahead window
        // (the monotone cursor IS the next slot), but unioned explicitly so
        // the bootstrap spawn is the real spawn even for a non-default slot.
        if let Some(intent) = first_stake_intent {
            slots.insert(intent.slot().to_raw());
        }

        let mut bundles = std::collections::BTreeMap::new();
        for &slot in &slots {
            let keys = derive_archival_p_keys(master_seed, derivation_network, seed_format, slot)
                .map_err(|e| {
                OpenError::Key(KeyError::Primitive {
                    detail: rederivation_failure_detail(&e),
                })
            })?;
            bundles.insert(PSlot::from_raw(slot), keys);
        }

        let mut bonded: std::collections::BTreeSet<PSlot> = staking
            .bonded_slots
            .iter()
            .copied()
            .map(PSlot::from_raw)
            .collect();
        // SA-R1-a: the intent slot is tagged bonded-ELECT (actor-local, never
        // persisted): the bonded tag is what makes a persona scannable
        // (`bonded_scan_inputs`) and activation-wipe-proof, and first-stake
        // needs both — the `stake_in` funding output must be discoverable by
        // the P-scan before the sweep can validate it, and an activation must
        // not wipe the elect's keys mid-bootstrap. If the first-stake aborts,
        // the tag dies with the actor (transient); durable bondedness remains
        // solely `persist_bond_record`'s write.
        if let Some(intent) = first_stake_intent {
            bonded.insert(intent.slot());
        }

        // Idle at open: the request path (2c-2b) mints a handle and activates.
        let handle = StakeEngineHandle::spawn(bundles, bonded, None);

        // S6 (conformance build only) — eager observation of the actor's
        // `on_start` RNG self-cert. Block wallet-open until the grade completes;
        // a non-conformant CSPRNG surfaces as `OpenError`, failing open loudly
        // rather than staking on an RNG that cannot produce unlinkable timing.
        //
        // This deliberately uses `block_in_place` directly rather than
        // `drive_persistence`: the awaited work (the actor's `on_start`) runs on
        // the *ambient* runtime, not inside the future, so `drive_persistence`'s
        // current-thread fallback (a fresh runtime on a scope thread) would
        // deadlock — the actor would never be polled while we wait. `block_in_place`
        // on a multi-thread runtime releases this worker so the actor keeps
        // running; on a current-thread runtime it *panics* loudly (the
        // panic-not-deadlock signal). Production wallet-open runs on the
        // `rt-multi-thread` ambient runtime; conformance tests must use
        // `#[tokio::test(flavor = "multi_thread")]`.
        #[cfg(feature = "conformance")]
        {
            let rt = tokio::runtime::Handle::current();
            let cert = tokio::task::block_in_place(|| rt.block_on(handle.wait_for_self_cert()));
            if let Err(failure) = cert {
                return Err(OpenError::StakeRngSelfCertFailed(failure));
            }
        }

        Ok(Some(handle))
    }
}

/// Sealed evidence the open-time SP-R0 reconcile consumes: arm #3's
/// reconcile set, the W3 pending bridge, and arm #2's done-side retired
/// slots. `Ok(None)` if no pscan seal exists yet; `Err(detail)` on ANY
/// read/decode failure — including a pending seal that cannot be read
/// while the pscan seal can, because a GC run without the pending bridge
/// could wrongfully drop a W3 slot. The caller degrades an `Err` to
/// skipping the reconcile (keep the hint, skip the chain-fed raise),
/// never to an open failure.
struct OpenStakingEvidence {
    evidence: crate::engine::pscan::reconcile::PReconcileSet,
    pending_slots: std::collections::BTreeSet<u32>,
    retired_slots: std::collections::BTreeSet<u32>,
}

fn load_open_staking_evidence(
    file: &WalletFile,
    state_wrap_key: &crate::engine::sealing_keys::StateWrapKey,
) -> Result<Option<OpenStakingEvidence>, String> {
    let Some(bytes) = file
        .open_pscan_state(state_wrap_key.as_bytes())
        .map_err(|e| format!("pscan seal read failed: {e}"))?
    else {
        return Ok(None);
    };
    let state = shekyl_engine_state::pscan_state::PScanState::from_postcard_bytes(&bytes)
        .map_err(|e| format!("pscan seal decode failed: {e}"))?;
    let evidence = crate::engine::pscan::accrual::PScanAccrual::from_state(&state).reconcile_set();
    // SP-R0 arm #2: the done-side ledger's retired slots ride along so the
    // caller can apply the records-driven hint clean before the phantom sweep.
    let retired_slots: std::collections::BTreeSet<u32> = state
        .retired_records()
        .iter()
        .map(|r| r.p_slot.to_raw())
        .collect();
    let pending_slots: std::collections::BTreeSet<u32> = match file
        .open_pending_posts(state_wrap_key.as_bytes())
        .map_err(|e| format!("pending seal read failed: {e}"))?
    {
        Some(bytes) => {
            shekyl_engine_state::pending_post_block::PendingPostBlock::from_postcard_bytes(&bytes)
                .map_err(|e| format!("pending seal decode failed: {e}"))?
                .posts()
                .iter()
                .map(|p| p.p_slot.to_raw())
                .collect()
        }
        None => std::collections::BTreeSet::new(),
    };
    Ok(Some(OpenStakingEvidence {
        evidence,
        pending_slots,
        retired_slots,
    }))
}
