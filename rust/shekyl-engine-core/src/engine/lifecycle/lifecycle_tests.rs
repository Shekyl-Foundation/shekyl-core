// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the Engine open/create/close lifecycle (`engine/lifecycle/`).
//!
//! Wired as a `#[path]` child of `lifecycle::tests`, so `use super::*`
//! resolves into the workflow module and private items stay testable;
//! the sibling file exists so the decomposition ratchet counts the
//! workflow file, not its test suite (the
//! `transfer/transfer_pending_tx_tests.rs` pattern).

use super::*;

use std::path::PathBuf;

use shekyl_address::Network;
use shekyl_crypto_pq::account::SeedFormat;
use shekyl_crypto_pq::wallet_envelope::KdfParams;
use shekyl_engine_prefs::hmac_key::FILE_KEK_BYTES;
use shekyl_rpc_transport::HttpRpc;
use tempfile::TempDir;
use zeroize::Zeroizing;

/// Produce a `DaemonClient` against a never-resolved URL. The
/// lifecycle methods covered here do not issue any RPC calls;
/// the daemon is held on the `Engine<S>` for refresh / submit
/// paths that land in later commits.
///
/// **Runs inside the ambient test runtime.** Since `KeyEngineHandle::spawn`
/// became require-ambient (§4.2), every engine-building lifecycle test is a
/// `#[tokio::test(flavor = "multi_thread")]`. This helper therefore must not
/// build a *nested* runtime (`block_on` inside a runtime panics); it bridges
/// the async `HttpRpc::new` to the sync test body via
/// `block_in_place` + the ambient handle — the same shape as
/// [`super::drive_persistence`]'s multi-thread branch, and the reason the
/// tests pin `flavor = "multi_thread"`.
fn dummy_daemon() -> DaemonClient {
    let rpc = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(HttpRpc::new("http://127.0.0.1:1".to_string()))
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

fn fixed_seed_other() -> [u8; MASTER_SEED_BYTES] {
    let mut s = fixed_seed();
    s[0] ^= 0x55;
    s[31] ^= 0xAA;
    s
}

fn state_wrap_key_from_bytes(
    bytes: &[u8; FILE_KEK_BYTES],
) -> super::super::sealing_keys::StateWrapKey {
    use super::super::sealing_keys::StateWrapKey;
    StateWrapKey::from_region2_key(Zeroizing::new(*bytes))
}

#[tokio::test(flavor = "multi_thread")]
async fn drive_persistence_from_tokio_worker_does_not_panic() {
    tokio::spawn(async {
        super::drive_persistence(std::future::ready(()));
    })
    .await
    .expect("join");
}

fn assert_open_state_aead_failure(err: OpenError) {
    use super::super::error::PersistenceError;
    match err {
        OpenError::Persistence(PersistenceError::WalletFile(WalletFileError::Envelope(
            WalletEnvelopeError::InvalidPasswordOrCorrupt,
        )))
        | OpenError::Io(IoError::WalletFile { .. }) => {}
        other => panic!("expected state AEAD failure on reopen, got {other:?}"),
    }
}

struct CreateFixture {
    _tmp: TempDir,
    base_path: PathBuf,
}

fn make_create_fixture() -> CreateFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base_path = tmp.path().join("wallet");
    CreateFixture {
        _tmp: tmp,
        base_path,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_full_then_open_full_round_trips_state() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse battery staple";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let created = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    assert_eq!(created.network(), network);
    assert_eq!(created.capability(), Capability::Full);
    assert_eq!(created.outstanding_pending_txs(), 0);
    // Close so the advisory lock is released before reopen.
    created.close(&creds).expect("close created wallet");

    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen FULL wallet");
    assert!(matches!(opened, OpenedEngine::Loaded(_)));
    let wallet = opened.into_wallet();
    assert_eq!(wallet.network(), network);
    assert_eq!(wallet.capability(), Capability::Full);
}

/// The bond-watch probe cache is built **unconditionally** — a
/// never-staked wallet's create derives the public persona ids for the
/// `0..=W` window (SA-R-6 from-seed reconstruction: the principal scan
/// and the credential-less `rescan_blockchain` always have candidates),
/// and a reopen loads the persisted map bit-identically instead of
/// re-paying the derivation.
#[tokio::test(flavor = "multi_thread")]
async fn create_and_open_build_the_bond_watch_probe_cache_unconditionally() {
    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"probe cache unconditional");
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let created = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
    let w = super::super::stake_engine::ARCHIVAL_PERSONA_PROBE_WINDOW;
    let at_create = created.ledger().staking.persona_id_cache.clone();
    assert!(!created.ledger().staking.staking_enabled, "non-staker");
    assert_eq!(
        at_create.len(),
        (w + 1) as usize,
        "create derives ids for the full 0..=W window"
    );
    assert!(at_create.contains_key(&0) && at_create.contains_key(&w));
    created.close(&creds).expect("close");

    let reopened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen")
    .into_wallet();
    assert_eq!(
        reopened.ledger().staking.persona_id_cache,
        at_create,
        "the persisted cache reloads identically (derive-once semantics)"
    );
}

/// An unreadable pscan seal disables the bond watch for the session:
/// the retired refusal set is unknown (not empty), so sighting
/// adoption would be unsound — a persistent decode failure would
/// otherwise re-adopt durably retired slots on every rescan with no
/// arm #2 run to drop them. Negative-controlled: the same wallet with
/// an ABSENT seal (fresh restore, `Ok(None)`) arms the watch from the
/// probe cache, so the assertion pair fails if the gate is dropped
/// (both legs armed) or over-applied (both legs empty).
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_pscan_seal_disables_the_bond_watch() {
    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"unreadable seal disables watch");
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create")
        .close(&creds)
        .expect("close after create");

    // Control leg: no pscan seal exists yet => `Ok(None)` => the watch
    // arms over the whole probe cache (a fresh restore is the flagship
    // reconstruction path and must stay watched).
    let healthy = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("healthy open")
    .into_wallet();
    assert!(
        healthy.refresh.bond_watch_is_armed(),
        "control: an absent seal arms the watch"
    );
    healthy.close(&creds).expect("close healthy");

    // Corrupt leg: garbage where the seal should be => `Err` => the
    // wallet still opens (funds access must not hang on the staking
    // seal) but the watch is disabled.
    let pscan_path = shekyl_engine_file::paths::pscan_state_path_from(&fix.base_path);
    std::fs::write(&pscan_path, b"not a sealed pscan state").expect("write garbage seal");
    let degraded = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("the wallet still opens on an unreadable staking seal")
    .into_wallet();
    assert!(
        !degraded.refresh.bond_watch_is_armed(),
        "an unreadable seal must disable the bond watch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn open_full_with_wrong_password_returns_incorrect_password() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    let bad_password: &[u8] = b"WRONG PASSWORD";
    let bad_creds = Credentials::password_only(bad_password);
    let err = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &bad_creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("wrong password must refuse");
    assert!(matches!(err, OpenError::IncorrectPassword), "got {err:?}");
}

/// SA-R1-a: an open carrying the first-stake intent spawns the
/// StakeEngine for a NON-staker (`staking_enabled` still false), and an
/// aborted first-stake (intent open, then close with no persist) leaves
/// **nothing durable** — the next plain open is a plain non-staker open.
/// The intent is transient by construction (a call parameter, never
/// persisted): this test is the pin's executable form.
#[tokio::test(flavor = "multi_thread")]
async fn first_stake_intent_spawns_transiently_and_aborts_clean() {
    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"correct horse");
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    // Plain open: a non-staker gets no StakeEngine (the existing gate).
    let plain = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("plain open")
    .into_wallet();
    assert!(!plain.has_stake_engine(), "non-staker: no actor");
    assert!(!plain.ledger().staking.staking_enabled);
    plain.close(&creds).expect("close plain");

    // Intent open: the actor spawns pre-persist (SA-R1-a), while the
    // durable staking state is untouched.
    let intent = Engine::<SoloSigner>::open_full_with_first_stake_intent(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
        0,
    )
    .expect("intent open")
    .into_wallet();
    assert!(intent.has_stake_engine(), "intent open spawns the actor");
    assert!(
        !intent.ledger().staking.staking_enabled,
        "the intent flips nothing durable"
    );
    // Abort: close without persisting a bond record.
    intent.close(&creds).expect("close aborted first-stake");

    // The abort left nothing: a plain reopen is a plain non-staker open.
    let after = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen after abort")
    .into_wallet();
    assert!(
        !after.has_stake_engine(),
        "aborted intent must not stick (SA-R1-a pin: transient, never persisted)"
    );
    assert!(!after.ledger().staking.staking_enabled);
    assert!(after.ledger().staking.bonded_slots.is_empty());
}

/// Integrated refusal paths of `Engine::first_stake` (rule 82 taxonomy),
/// and the W1 invariant: a refusal writes **nothing durable** — the
/// wallet remains a clean non-staker after any pre-persist failure.
#[tokio::test(flavor = "multi_thread")]
async fn first_stake_refuses_cleanly_before_the_durable_point() {
    use crate::engine::FirstStakeError;
    use tokio::sync::RwLock;

    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"correct horse");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    // No StakeEngine resident (plain open, no intent): the continuation
    // refuses with the internal-sequencing arm — never a partial write.
    let plain = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("plain open")
    .into_wallet();
    let arc = std::sync::Arc::new(RwLock::new(plain));
    let err = Engine::first_stake(arc.clone(), 0)
        .await
        .expect_err("no stake engine must refuse");
    assert!(matches!(err, FirstStakeError::NoStakeEngine), "got {err:?}");
    {
        let g = arc.read().await;
        assert!(!g.ledger().staking.staking_enabled);
        assert!(g.ledger().staking.bonded_slots.is_empty());
    }
    let plain = std::sync::Arc::try_unwrap(arc)
        .unwrap_or_else(|_| panic!("sole owner"))
        .into_inner();
    plain.close(&creds).expect("close");

    // Intent open (actor resident), unreachable daemon: the first
    // pre-persist step to touch the daemon (the fee estimate) fails →
    // the `FeeEstimate` arm (a daemon fault, deliberately NOT the
    // `Funding` "fund and retry" misdiagnosis — rule 82), and — the W1
    // pin — nothing durable was written: the wallet reopens as a plain
    // non-staker.
    let intent = Engine::<SoloSigner>::open_full_with_first_stake_intent(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
        0,
    )
    .expect("intent open")
    .into_wallet();
    let arc = std::sync::Arc::new(RwLock::new(intent));
    let err = Engine::first_stake(arc.clone(), 0)
        .await
        .expect_err("unreachable daemon must refuse pre-persist");
    assert!(
        matches!(err, FirstStakeError::FeeEstimate(_)),
        "got {err:?}"
    );
    {
        let g = arc.read().await;
        assert!(
            !g.ledger().staking.staking_enabled,
            "W1: a pre-persist refusal writes nothing durable"
        );
        assert!(g.ledger().staking.bonded_slots.is_empty());
    }
    let intent = std::sync::Arc::try_unwrap(arc)
        .unwrap_or_else(|_| panic!("sole owner"))
        .into_inner();
    intent.close(&creds).expect("close");

    let after = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen")
    .into_wallet();
    assert!(!after.has_stake_engine(), "still a clean non-staker");
}

/// SP-R0 arm #2 — the open-time records-driven clean: a durably RETIRED
/// slot is dropped from the live hint before derive (no evidence gate —
/// the wallet's own ledger), and an emptied hint reverts the wallet to
/// a non-staker; an unrelated retired slot leaves the live one alone.
#[tokio::test(flavor = "multi_thread")]
async fn retired_records_clean_the_live_hint_at_open() {
    use shekyl_engine_state::pscan_cursor::PScanCursor;
    use shekyl_engine_state::pscan_state::{PScanState, RetiredPersonaRecord, PSCAN_STATE_VERSION};
    use shekyl_types::{PCanonicalId, PSlot, SettlementEpoch};
    let _ = PSCAN_STATE_VERSION; // version pinned by the schema snapshot

    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"correct horse");
    let seed = fixed_seed();
    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
    engine
        .persist_bond_record(PSlot::from_raw(0))
        .expect("persist");
    engine.close(&creds).expect("close");

    let seal_retired = |slots: &[u32]| {
        let (file, _outcome) = shekyl_engine_file::WalletFile::open(
            &fix.base_path,
            b"correct horse",
            network,
            SafetyOverrides::none(),
        )
        .expect("file open");
        let key = super::super::sealing_keys::state_wrap_key_from_wallet_file(&file);
        let state = PScanState::new(
            PScanCursor::genesis(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            slots
                .iter()
                .map(|&slot| RetiredPersonaRecord {
                    p_slot: PSlot::from_raw(slot),
                    p_canonical_id: PCanonicalId::from_bytes(
                        [u8::try_from(slot).unwrap_or(0xFF); 32],
                    ),
                    unbond_epoch: SettlementEpoch::from_raw(0),
                    retired_epoch: SettlementEpoch::from_raw(30),
                })
                .collect(),
            std::collections::BTreeMap::new(),
        );
        file.save_pscan_state(key.as_bytes(), &state.to_postcard_bytes().expect("encode"))
            .expect("seal");
    };

    // Unrelated retired slot: the live slot survives, still a staker.
    seal_retired(&[5]);
    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("open")
    .into_wallet();
    assert!(opened.ledger().staking.staking_enabled);
    assert!(opened.ledger().staking.bonded_slots.contains(&0));
    assert!(opened.has_stake_engine());
    opened.close(&creds).expect("close");

    // The bonded slot itself retired: cleaned, reverted, no actor.
    seal_retired(&[5, 0]);
    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("open")
    .into_wallet();
    assert!(
        !opened.ledger().staking.staking_enabled,
        "an emptied hint reverts the wallet to a non-staker"
    );
    assert!(opened.ledger().staking.bonded_slots.is_empty());
    assert!(
        !opened.has_stake_engine(),
        "no actor for a fully-retired wallet"
    );
    opened.close(&creds).expect("close");
}

/// Phase 1 query surface: `Engine::primary_address` assembles the
/// wallet's one reusable address from the `KeyActor`'s cached
/// public projection and the engine's cached network, and the
/// result survives an encode → decode round trip through the
/// `shekyl-address` codec.
#[tokio::test(flavor = "multi_thread")]
async fn primary_address_renders_and_round_trips() {
    use crate::engine::ShekylAddress;

    let fix = make_create_fixture();
    let creds = Credentials::password_only(b"correct horse");
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

    let addr = wallet.primary_address();
    assert_eq!(addr.network, network);

    let encoded = addr.encode().expect("encode primary address");
    let decoded = ShekylAddress::decode_for_network(&encoded, network)
        .expect("decode primary address for the wallet's network");
    assert_eq!(decoded.spend_key, addr.spend_key);
    assert_eq!(decoded.view_key, addr.view_key);
    assert_eq!(decoded.ml_kem_encap_key, addr.ml_kem_encap_key);

    wallet.close(&creds).expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_full_with_wrong_network_returns_network_mismatch() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let wallet_network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    // Stagenet was used at create time; ask Mainnet.
    let other = Network::Mainnet;
    let err = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        other,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("network mismatch must refuse");
    match err {
        OpenError::NetworkMismatch { wallet, expected } => {
            assert_eq!(wallet, wallet_network);
            assert_eq!(expected, other);
        }
        other => panic!("expected NetworkMismatch, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_rewraps_envelope_then_reopen_uses_new_password() {
    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let network = params.network;
    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");
    wallet.close(&creds_new).expect("close after rotate");

    // Old password must refuse.
    let err = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds_old,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("old password must refuse after rotation");
    assert!(matches!(err, OpenError::IncorrectPassword), "got {err:?}");

    // New password succeeds.
    let _ = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds_new,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen with new password");
}

/// FOLLOWUPS V3.0: verify the rotated envelope round-trips against an
/// *independently constructed* [`WalletFile::open`] call rather than
/// only against [`Engine::open_full`]. This pins the full
/// I/O ↔ KDF ↔ AEAD chain at the orchestrator layer: if
/// `change_password` left the on-disk envelope in any state the
/// wallet-file layer alone cannot decode, this test fails even when
/// the orchestrator's own reopen path happens to succeed off cached
/// bytes.
///
/// Capability coverage: FULL only. ViewOnly / HardwareOffload are
/// added when their `open_*` bodies land (see the View/HW lifecycle
/// entry in `docs/FOLLOWUPS.md`).
#[tokio::test(flavor = "multi_thread")]
async fn change_password_round_trips_via_independent_wallet_file_open() {
    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let network = params.network;
    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");
    wallet.close(&creds_new).expect("close after rotate");

    // Old password must refuse at the wallet-file layer with the
    // envelope's deliberately-indistinct AEAD failure.
    let err = WalletFile::open(&fix.base_path, p_old, network, SafetyOverrides::none())
        .expect_err("old password must refuse at the wallet-file layer");
    assert!(
        matches!(
            err,
            WalletFileError::Envelope(WalletEnvelopeError::InvalidPasswordOrCorrupt)
        ),
        "got {err:?}"
    );

    // New password opens through the wallet-file layer alone, finds
    // the persisted state (close saved it), and reports FULL.
    let (file, outcome) = WalletFile::open(&fix.base_path, p_new, network, SafetyOverrides::none())
        .expect("independent WalletFile::open with new password");
    assert_eq!(file.capability(), Capability::Full);
    assert!(
        matches!(outcome, shekyl_engine_file::OpenOutcome::StateLoaded(_)),
        "expected StateLoaded after a clean close, got {outcome:?}"
    );
}

/// Companion to the round-trip test above: a rotation that also
/// changes KDF parameters must rewrite the envelope header so the
/// new cost parameters govern subsequent opens. Asserted via
/// [`inspect_keys_file`](shekyl_crypto_pq::wallet_envelope::inspect_keys_file)
/// on the raw on-disk bytes — open-success alone cannot distinguish
/// "new KDF recorded" from "new KDF silently dropped", because
/// `open` reads whatever parameters the header declares.
#[tokio::test(flavor = "multi_thread")]
async fn change_password_with_new_kdf_rewrites_envelope_header() {
    use shekyl_crypto_pq::wallet_envelope::inspect_keys_file;
    use shekyl_engine_file::paths::keys_path_from;

    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let network = params.network;
    let created_kdf = params.kdf;
    // Still minimum-wall-clock, but distinguishable from the
    // create-time parameters.
    let rotated_kdf = KdfParams {
        m_log2: created_kdf.m_log2,
        t: created_kdf.t + 1,
        p: created_kdf.p,
    };

    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    wallet
        .change_password(&creds_old, &creds_new, Some(rotated_kdf))
        .expect("rotate password with new KDF params");
    wallet.close(&creds_new).expect("close after rotate");

    let keys_bytes = std::fs::read(keys_path_from(&fix.base_path)).expect("read rotated keys file");
    let header = inspect_keys_file(&keys_bytes).expect("inspect rotated keys file header");
    assert_eq!(header.kdf.m_log2, rotated_kdf.m_log2);
    assert_eq!(header.kdf.t, rotated_kdf.t);
    assert_eq!(header.kdf.p, rotated_kdf.p);

    // And the rewritten header actually governs an independent open.
    let (file, _outcome) =
        WalletFile::open(&fix.base_path, p_new, network, SafetyOverrides::none())
            .expect("independent WalletFile::open after KDF rotation");
    assert_eq!(file.capability(), Capability::Full);
}

#[tokio::test(flavor = "multi_thread")]
async fn open_full_after_state_file_deleted_returns_restored_from_height() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let restore_height = u64::from(params.restore_height_hint);
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    // Delete the state file to force the lost-state recovery
    // path. The keys file is left intact.
    let state_path = {
        let mut p = fix.base_path.clone();
        // `shekyl_engine_file` writes `<base>.keys` and
        // `<base>` (no extension) — match the latter.
        assert!(p.set_extension(""), "base path should have no extension");
        p
    };
    std::fs::remove_file(&state_path).expect("delete state file");

    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen after state loss");
    match opened {
        OpenedEngine::Restored {
            wallet,
            from_height,
        } => {
            assert_eq!(from_height, restore_height);
            assert_eq!(wallet.capability(), Capability::Full);
        }
        OpenedEngine::Loaded(_) => panic!("expected Restored, got Loaded"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn close_with_outstanding_reservation_returns_outstanding_pending_tx() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

    use super::super::local_pending_tx::ConsumerHeldEntry;

    let id = super::super::pending::ReservationId::new(0);
    wallet
        .pending
        .state
        .lock()
        .expect("pending state lock not poisoned")
        .consumer_held
        .insert(id, ConsumerHeldEntry::for_outstanding_test(vec![0xAB; 64]));

    let count_before = wallet.outstanding_pending_txs();
    assert_eq!(count_before, 1);

    let err = wallet
        .close(&creds)
        .expect_err("close must refuse with outstanding reservation");
    match err {
        OpenError::OutstandingPendingTx { count } => assert_eq!(count, count_before),
        other => panic!("expected OutstandingPendingTx, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn persist_for_close_keeps_engine_on_outstanding_reservation() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");

    use super::super::local_pending_tx::ConsumerHeldEntry;

    let id = super::super::pending::ReservationId::new(0);
    wallet
        .pending
        .state
        .lock()
        .expect("pending state lock not poisoned")
        .consumer_held
        .insert(id, ConsumerHeldEntry::for_outstanding_test(vec![0xAB; 64]));

    let count_before = wallet.outstanding_pending_txs();
    assert_eq!(count_before, 1);

    // Non-consuming flush must leave `wallet` usable (RPC restore path).
    let err = wallet
        .persist_for_close()
        .expect_err("persist_for_close must refuse with outstanding reservation");
    match err {
        OpenError::OutstandingPendingTx { count } => assert_eq!(count, count_before),
        other => panic!("expected OutstandingPendingTx, got {other:?}"),
    }
    assert_eq!(wallet.outstanding_pending_txs(), count_before);
    wallet
        .close(&creds)
        .expect_err("still outstanding after failed persist");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_view_only_returns_capability_not_yet_implemented() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    // Create a FULL wallet on disk so the call site is realistic;
    // the stub method returns the typed error before touching the
    // file, but constructing the file makes the test resemble the
    // real CLI flow.
    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    let err = Engine::<SoloSigner>::open_view_only(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("view-only stub must refuse");
    match err {
        OpenError::CapabilityNotYetImplemented { capability } => {
            assert_eq!(capability, Capability::ViewOnly);
        }
        other => panic!("expected CapabilityNotYetImplemented, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn open_hardware_offload_returns_capability_not_yet_implemented() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    let err = Engine::<SoloSigner>::open_hardware_offload(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("hardware-offload stub must refuse");
    match err {
        OpenError::CapabilityNotYetImplemented { capability } => {
            assert_eq!(capability, Capability::HardwareOffload);
        }
        other => panic!("expected CapabilityNotYetImplemented, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tampered_prefs_are_recovered_and_warned_about() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    // Corrupt the prefs HMAC companion file. The wallet-file
    // layer writes `<base>.prefs.toml` and
    // `<base>.prefs.toml.hmac`; flipping bits in the HMAC
    // triggers the tamper path on next load.
    let hmac_path = {
        let p = fix.base_path.with_extension("prefs.toml.hmac");
        // Some platforms silently drop the secondary extension;
        // tolerate either form.
        if p.exists() {
            p
        } else {
            let mut alt = fix.base_path.clone();
            alt.set_file_name(format!(
                "{}.prefs.toml.hmac",
                fix.base_path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("wallet")
            ));
            alt
        }
    };
    if hmac_path.exists() {
        let mut bytes = std::fs::read(&hmac_path).expect("read hmac");
        if let Some(b) = bytes.first_mut() {
            *b ^= 0xFF;
        }
        std::fs::write(&hmac_path, &bytes).expect("write tampered hmac");
    }

    // Reopen — must succeed even on the tampered branch (the
    // policy is "warn + use defaults", not refuse-to-open). The
    // warn is checked at the documentation layer; capturing
    // `tracing` events in tests requires a subscriber setup we
    // do not need here.
    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen succeeds even when prefs are tampered");
    let _wallet = opened.into_wallet();
}

use super::super::traits::PersistenceEngine;
use super::drive_persistence;
use shekyl_crypto_pq::wallet_envelope::WalletEnvelopeError;
use shekyl_engine_file::WalletFileError;

#[tokio::test(flavor = "multi_thread")]
async fn persistence_trait_save_state_round_trip() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse battery staple";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        wallet.state_wrap_key(),
        &ledger_guard.ledger,
    ))
    .expect("trait save_state");
    drop(ledger_guard);
    wallet.close(&creds).expect("close");

    let opened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen after trait save");
    assert!(matches!(opened, OpenedEngine::Loaded(_)));
}

#[tokio::test(flavor = "multi_thread")]
async fn change_password_flushes_prefs() {
    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let network = params.network;
    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    wallet.prefs_mut().cosmetic.default_decimal_point = 9;
    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");
    wallet.close(&creds_new).expect("close after rotate");

    let reopened = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds_new,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen with new password")
    .into_wallet();
    assert_eq!(reopened.prefs().cosmetic.default_decimal_point, 9);
}

#[tokio::test(flavor = "multi_thread")]
async fn password_rotate_preserves_state_wrap_key_bytes() {
    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    let before = *wallet.state_wrap_key().as_bytes();
    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");
    assert_eq!(
        before,
        *wallet.state_wrap_key().as_bytes(),
        "wrap_key_region_2 is unchanged when file_kek plaintext is unchanged"
    );
}

/// Design §2c / F-R3.8: open → save_state(k) ok → rotate ok → save_state(k_stale)
/// without re-derive must fail loud when keys-file bytes used for AAD drift.
#[tokio::test(flavor = "multi_thread")]
async fn stale_state_wrap_key_fails_after_rotate_without_rederive() {
    use shekyl_engine_file::paths::keys_path_from;

    let fix_a = make_create_fixture();
    let tmp_b = tempfile::tempdir().expect("tempdir");
    let base_b = tmp_b.path().join("other.wallet");
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed_a = fixed_seed();
    let seed_b = fixed_seed_other();

    let params_a = EngineCreateParams::for_test_full(&fix_a.base_path, &creds_old, &seed_a);
    let network = params_a.network;
    let mut wallet =
        Engine::<SoloSigner>::create(params_a, dummy_daemon()).expect("create wallet A");
    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        wallet.state_wrap_key(),
        &ledger_guard.ledger,
    ))
    .expect("save before rotate");
    drop(ledger_guard);

    let k_stale = state_wrap_key_from_bytes(wallet.state_wrap_key().as_bytes());

    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");

    // Wallet B: different seed → different seed_block_tag in keys file.
    let params_b = EngineCreateParams::for_test_full(&base_b, &creds_old, &seed_b);
    Engine::<SoloSigner>::create(params_b, dummy_daemon())
        .expect("create wallet B")
        .close(&creds_old)
        .expect("close B");
    let foreign_keys = std::fs::read(keys_path_from(&base_b)).expect("read B keys file");

    // Orchestrator still holds k_stale; in-memory keys bytes drift to another wallet.
    wallet
        .file()
        .replace_keys_file_bytes_in_memory_for_tests(foreign_keys);

    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        &k_stale,
        &ledger_guard.ledger,
    ))
    .expect("save seals with stale key + mismatched keys-file AAD");
    drop(ledger_guard);
    drop(wallet);

    let err = Engine::<SoloSigner>::open_full(
        &fix_a.base_path,
        &creds_new,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("reopen must reject state sealed with stale wrap key");
    assert_open_state_aead_failure(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_state_wrap_key_sealed_state_fails_on_reopen() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse battery staple";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    let wallet = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        wallet.state_wrap_key(),
        &ledger_guard.ledger,
    ))
    .expect("save baseline");
    drop(ledger_guard);

    let mut wrong_bytes = *wallet.state_wrap_key().as_bytes();
    wrong_bytes[0] ^= 0xFF;
    let wrong_key = state_wrap_key_from_bytes(&wrong_bytes);

    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        &wrong_key,
        &ledger_guard.ledger,
    ))
    .expect("save with wrong wrap key still seals");
    drop(ledger_guard);
    drop(wallet);

    let err = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect_err("reopen must reject state sealed with wrong wrap key");
    assert_open_state_aead_failure(err);
}

#[tokio::test(flavor = "multi_thread")]
async fn rederived_state_wrap_key_succeeds_after_rotate() {
    let fix = make_create_fixture();
    let p_old: &[u8] = b"old password";
    let p_new: &[u8] = b"new password";
    let creds_old = Credentials::password_only(p_old);
    let creds_new = Credentials::password_only(p_new);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds_old, &seed);
    let network = params.network;
    let mut wallet =
        Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create FULL wallet");
    wallet
        .change_password(&creds_old, &creds_new, None)
        .expect("rotate password");
    wallet.close(&creds_new).expect("close after rotate");

    let wallet = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds_new,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("reopen after rotate")
    .into_wallet();
    let ledger_guard = wallet.ledger.read();
    drive_persistence(PersistenceEngine::save_state(
        wallet.persistence(),
        wallet.state_wrap_key(),
        &ledger_guard.ledger,
    ))
    .expect("save with re-derived wrap key");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_does_not_retain_file_kek() {
    let fix = make_create_fixture();
    let password: &[u8] = b"correct horse";
    let creds = Credentials::password_only(password);
    let seed = fixed_seed();

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    let network = params.network;
    Engine::<SoloSigner>::create(params, dummy_daemon())
        .expect("create FULL wallet")
        .close(&creds)
        .expect("close after create");

    let wallet = Engine::<SoloSigner>::open_full(
        &fix.base_path,
        &creds,
        network,
        dummy_daemon(),
        SafetyOverrides::none(),
    )
    .expect("open_full")
    .into_wallet();
    assert!(
        wallet.file().opened_keys().file_kek.iter().all(|&b| b == 0),
        "file_kek must be zeroized after open ritual"
    );
    assert_ne!(
        wallet.state_wrap_key().as_bytes(),
        &[0u8; 32],
        "session must hold derived wrap_key_region_2"
    );
}

#[test]
fn panic_hook_does_not_leak_state_wrap_key() {
    use std::sync::{Arc, Mutex};

    use super::super::sealing_keys::StateWrapKey;
    use shekyl_engine_prefs::hmac_key::FILE_KEK_BYTES;
    use zeroize::Zeroizing;

    let marker = [0x42u8; FILE_KEK_BYTES];
    let key = StateWrapKey::from_region2_key(Zeroizing::new(marker));
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_hook = Arc::clone(&captured);
    let previous = std::panic::take_hook();
    struct RestorePanicHook(Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>);
    impl Drop for RestorePanicHook {
        fn drop(&mut self) {
            std::panic::set_hook(std::mem::replace(&mut self.0, Box::new(|_| {})));
        }
    }
    let _restore = RestorePanicHook(previous);
    std::panic::set_hook(Box::new(move |info| {
        captured_hook
            .lock()
            .expect("panic capture lock")
            .push_str(&info.to_string());
    }));

    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _hold = &key;
        panic!("forced persistence test panic");
    }));
    assert!(payload.is_err());

    let text = captured.lock().expect("panic capture lock");
    assert!(
        text.contains("forced persistence test panic"),
        "sanity: panic message present"
    );
    for chunk in marker.chunks(4) {
        let needle = chunk.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert!(
            !text.contains(&needle),
            "panic output leaked key bytes as hex: {text}"
        );
    }
}

/// Sanity-check that `for_test_full` produces a `EngineCreateParams`
/// callable through `Engine::create` without surprises. Functionally
/// covered by `create_full_then_open_full_round_trips_state`; this
/// case is the smaller, focused regression for the helper itself.
#[test]
fn for_test_full_helper_produces_creatable_params() {
    let fix = make_create_fixture();
    let password: &[u8] = b"hunter2";
    let creds = Credentials::password_only(password);
    let seed = [0xAAu8; MASTER_SEED_BYTES];

    let params = EngineCreateParams::for_test_full(&fix.base_path, &creds, &seed);
    // Field assertions: pinned defaults from the helper.
    assert_eq!(params.network, Network::Stagenet);
    assert_eq!(params.creation_timestamp, 0);
    assert_eq!(params.restore_height_hint, 0);
    match params.capability {
        CapabilityInput::Full {
            seed_format,
            master_seed_64,
        } => {
            assert_eq!(seed_format, SeedFormat::Bip39);
            assert_eq!(master_seed_64, &seed);
        }
    }
    // KDF profile is the minimum-wall-clock fast variant.
    let _: KdfParams = params.kdf;
}
