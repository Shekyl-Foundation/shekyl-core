// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Unit tests for the stake-engine actor (`engine/stake_engine.rs`).
//!
//! Wired as a `#[path]` child of `stake_engine::tests`, so `use super::*`
//! resolves into the actor module and private items stay testable; the
//! sibling file exists so the decomposition ratchet counts the actor file,
//! not its test suite (the `proofs_tests.rs` / transfer suite pattern).

//! Lifecycle contract tests for [`StakeEngine`] / [`StakeEngineHandle`]
//! (`ARCHIVAL_BOND_CONSTRUCTION.md` §10.2) under **Model D**: the actor holds
//! pre-derived bundles, never the seed. Tests derive the derive-forward set
//! with the `derive_archival_p_keys` oracle (via the shared `test_fixtures`)
//! and hand it in, then exercise the actor through real messages — no mocks.
//! The same oracle is rerun to confirm the actor projects the genesis-frozen
//! identity bytes.

use super::test_fixtures::{constructed_record, derive_bundle, spawn_over};
use super::*;

use shekyl_archival_retention::{ShardSet, MAX_CLAIM_AGE_W};

/// The genesis-frozen `hybrid_bond_id` canonical bytes for a slot, computed
/// directly via the derivation oracle.
fn oracle_bond_id(p_slot: u32) -> Vec<u8> {
    derive_bundle(p_slot)
        .hybrid_bond_id()
        .to_canonical_bytes()
        .expect("derived bond id is canonical")
}

fn bond_id_bytes(identity: &PersonaIdentity) -> Vec<u8> {
    identity
        .bond_id
        .to_canonical_bytes()
        .expect("persona bond id is canonical")
}

/// Mint a handle for `slot` and activate it, returning the public identity.
/// The common caller flow: a handle authorizes exactly one activation.
async fn mint_and_activate(
    handle: &StakeEngineHandle,
    slot: u32,
) -> Result<PersonaIdentity, StakeEngineError> {
    let h = handle.mint_handle(PSlot::from_raw(slot)).await?;
    handle.activate_persona(h).await
}

/// GF-2 boundary (the firewall-critical half of `Engine::stake_in`): the
/// address the actor projects for the active persona — public-only, built
/// in-actor, no re-derivation — is one `P`'s own dual-scan recovers.
/// Construct an output to the *projected* address, then recover it with `P`'s
/// secret bundle (the `derive_bundle` oracle — test-side only; production
/// never re-derives). A wrong projection (wrong keys / wrong persona) fails
/// recovery.
#[tokio::test]
async fn active_persona_receive_address_is_recovered_by_p_dual_scan() {
    use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
    use shekyl_crypto_pq::output::{construct_output, scan_output_recover};

    let slot = 3u32;
    // Address network is the sender's; it does not affect the derived keys
    // (which the `DerivationNetwork` fixes), only the address encoding.
    let network = Network::Mainnet;

    let stake = spawn_over(&[slot], &[], Some(slot));
    let address = stake
        .active_persona_receive_address(network)
        .await
        .expect("accessor")
        .expect("an active persona projects an address")
        .encode()
        .expect("encode P's projected address");

    // The address `stake_in` would target, decoded back to key material.
    let decoded = ShekylAddress::decode_for_network(&address, network).expect("decode");
    let x25519_pk = ed25519_pk_to_x25519_pk(&decoded.view_key).expect("montgomery");

    let amount = 50_000u64;
    let output_index = 7u64;
    let constructed = construct_output(
        &[0x5Au8; 32],
        &x25519_pk,
        &decoded.ml_kem_encap_key,
        &decoded.spend_key,
        amount,
        output_index,
    )
    .expect("construct an output to P's projected address");

    // P's dual-scan (secret bundle via the test oracle) recovers it.
    let keys = derive_bundle(slot);
    let recovered = scan_output_recover(
        keys.view_sk.as_canonical_bytes(),
        keys.ml_kem_dk.as_canonical_bytes(),
        &constructed.kem_ciphertext_x25519,
        &constructed.kem_ciphertext_ml_kem,
        &constructed.output_key,
        &constructed.commitment,
        &constructed.enc_amount,
        constructed.amount_tag,
        &constructed.enc_label,
        constructed.label_tag,
        constructed.view_tag_prefilter,
        output_index,
    )
    .expect("P recovers the output addressed via the actor's projection");

    assert_eq!(
        recovered.amount, amount,
        "recovered amount matches the funded amount"
    );
    assert_eq!(
        &recovered.recovered_spend_key,
        keys.spend_pk.as_canonical_bytes(),
        "the output is owned by P (projected address == P's receive key)"
    );

    // Idle actor projects no address (the `NoActivePersona` path).
    let idle = spawn_over(&[slot], &[], None);
    assert!(
        idle.active_persona_receive_address(network)
            .await
            .expect("accessor")
            .is_none(),
        "an idle actor projects no receive address"
    );
}

/// WI-2 D-A1/D-A3 — the P-side spend-bundle re-derivation is
/// byte-identical to the scanner-side derivation chain for the same
/// output (the M3b byte-identical-derivation property, P edition,
/// `ARCHIVAL_BOND_WI2_ASSEMBLY.md` §4).
///
/// The persisted `PFundingOutputRecord` carries only public identity
/// (`ciphertext`, `index_in_transaction`); assemble-time spending is
/// sound only if [`derive_p_source_secrets_bundle`] recomputes exactly
/// the secrets the scan derived (and dropped) at discovery time. The
/// oracle here is `scan_output_recover` — the same chain the persona
/// `GuaranteedScanner` drives — hand-composed into a bundle, plus the
/// SAL open `x·G + y·T == O` as the real-correctness guard.
#[test]
fn p_source_secrets_bundle_byte_identical_against_scan_chain() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use shekyl_crypto_pq::output::{construct_output, scan_output_recover};

    let keys = derive_bundle(0);
    let tx_key_secret = [0x5Au8; 32];

    for output_index in [0u64, 1, 7, 255, 1_000_000] {
        let constructed = construct_output(
            &tx_key_secret,
            &keys.x25519_pk,
            &keys.ml_kem_ek,
            keys.spend_pk.as_canonical_bytes(),
            50_000u64.wrapping_add(output_index),
            output_index,
        )
        .expect("construct_output succeeds for a P-paid synthetic output");
        let ciphertext = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };

        // Oracle: the scanner-side chain, hand-composed (x = ho + b,
        // no claim offset — P outputs are paid to the base spend key).
        let recovered = scan_output_recover(
            keys.view_sk.as_canonical_bytes(),
            keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount,
            constructed.amount_tag,
            &constructed.enc_label,
            constructed.label_tag,
            constructed.view_tag_prefilter,
            output_index,
        )
        .expect("scan_output_recover claims the P-paid output");
        let ho: Scalar =
            Option::from(Scalar::from_canonical_bytes(recovered.ho)).expect("ho canonical");
        let b: Scalar = Scalar::from_bytes_mod_order(*keys.spend_sk.as_canonical_bytes());
        let oracle_x = (ho + b).to_bytes();

        // Assemble-time chain under test.
        let bundle = derive_p_source_secrets_bundle(&keys, &ciphertext, output_index)
            .expect("derive_p_source_secrets_bundle succeeds against own ciphertext");

        assert_eq!(
            *bundle.spend_key_x, oracle_x,
            "spend_key_x byte-identity violated (output_index={output_index})"
        );
        assert_eq!(*bundle.spend_key_y, recovered.y);
        assert_eq!(*bundle.commitment_mask, recovered.z);
        assert_eq!(bundle.combined_ss.as_slice(), &recovered.combined_ss[..]);
        assert_eq!(bundle.output_index, output_index);

        // Real-correctness guard: the derived witness opens the output
        // key under the SAL relation the daemon enforces.
        let x: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_x)).expect("x canonical");
        let y: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_y)).expect("y canonical");
        let o = CompressedEdwardsY(constructed.output_key)
            .decompress()
            .expect("O decompresses");
        assert_eq!(
            (&x * ED25519_BASEPOINT_TABLE) + (*shekyl_curve_generators::T * y),
            o,
            "SAL relation x·G + y·T == O violated (output_index={output_index})"
        );
    }
}

/// A corrupted funding-record ciphertext fails closed at re-derivation
/// (the D-A5 "spend-bundle derivation failure" row): a low-order X25519
/// component is rejected by `recover_combined_ss`, never silently spent.
#[test]
fn p_source_secrets_bundle_rejects_tampered_ciphertext() {
    let keys = derive_bundle(0);
    let tampered = HybridCiphertext {
        x25519: [0u8; 32], // low-order Montgomery point u=0
        ml_kem: vec![0u8; shekyl_crypto_pq::kem::ML_KEM_768_CT_LEN],
    };
    let err = derive_p_source_secrets_bundle(&keys, &tampered, 0)
        .expect_err("a low-order X25519 component must be rejected");
    assert!(matches!(
        err,
        KeyEngineError::SourceCiphertextDecapsulationFailed(_)
    ));
}

// §10.1 — an actor spawned with no initial active slot is idle.
#[tokio::test]
async fn idle_actor_has_no_active_persona() {
    let handle = spawn_over(&[0, 1], &[], None);
    let active = handle
        .active_persona()
        .await
        .expect("active query succeeds");
    assert!(active.is_none(), "no initial active slot ⇒ idle");
}

// §10.1 — activating a held persona projects its public identity, which
// matches the genesis-frozen derivation oracle.
#[tokio::test]
async fn activate_returns_genesis_frozen_identity() {
    let handle = spawn_over(&[0], &[], None);
    let oracle0 = oracle_bond_id(0);

    let identity = mint_and_activate(&handle, 0)
        .await
        .expect("activation of a held persona");
    assert_eq!(identity.p_slot, PSlot::from_raw(0));
    assert_eq!(
        bond_id_bytes(&identity),
        oracle0,
        "actor projects the genesis-frozen bond identity"
    );

    let active = handle
        .active_persona()
        .await
        .expect("active query succeeds")
        .expect("a persona is active after activation");
    assert_eq!(active.p_slot, PSlot::from_raw(0));
    assert_eq!(bond_id_bytes(&active), oracle0);
}

// §10.1 robustness #3 — identity is deterministic across a respawn: a fresh
// actor over a fresh derivation of the same slot projects byte-identical
// identity. The runtime consumer of the `ARCHIVAL_P_DERIVE_V1` freeze.
#[tokio::test]
async fn identity_is_deterministic_across_respawn() {
    let first = {
        let handle = spawn_over(&[0], &[], None);
        bond_id_bytes(&mint_and_activate(&handle, 0).await.expect("activate 0"))
        // handle (and its actor) drop here
    };
    let second = {
        let handle = spawn_over(&[0], &[], None);
        bond_id_bytes(&mint_and_activate(&handle, 0).await.expect("activate 0"))
    };
    assert_eq!(
        first, second,
        "re-deriving the same slot from the same seed must be byte-identical"
    );
}

// Minting a handle for a slot outside the held derive-forward set is the
// real domain error `LookaheadExhausted` (reopen to extend the lookahead) —
// not a panic, not a can't-happen.
#[tokio::test]
async fn mint_unheld_slot_is_lookahead_exhausted() {
    let handle = spawn_over(&[0, 1], &[], None);
    let err = handle
        .mint_handle(PSlot::from_raw(7))
        .await
        .expect_err("slot 7 is not held");
    assert!(
        matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot::from_raw(7)),
        "expected LookaheadExhausted{{7}}, got {err:?}"
    );
}

// §10.1 robustness #2 — activation replaces the active persona in a single
// transition: after activating to slot 1, slot 1 is the *only* active persona.
#[tokio::test]
async fn activation_replaces_active_persona() {
    let handle = spawn_over(&[0, 1], &[0, 1], None);

    let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
    let id1 = mint_and_activate(&handle, 1)
        .await
        .expect("activate slot 1");
    assert_ne!(
        bond_id_bytes(&id0),
        bond_id_bytes(&id1),
        "distinct slots project distinct personas"
    );
    assert_eq!(id1.p_slot, PSlot::from_raw(1));

    let active = handle
        .active_persona()
        .await
        .expect("active query")
        .expect("a persona is active");
    assert_eq!(active.p_slot, PSlot::from_raw(1));
    assert_eq!(bond_id_bytes(&active), bond_id_bytes(&id1));
}

// Typed contract #4 — activation wipes the retired *ephemeral* persona: after
// moving away from an unbonded slot, that slot is no longer held, so a
// subsequent mint is `LookaheadExhausted`.
#[tokio::test]
async fn activation_wipes_ephemeral_retired() {
    let handle = spawn_over(&[0, 1], &[], None); // both ephemeral

    mint_and_activate(&handle, 0).await.expect("activate 0");
    mint_and_activate(&handle, 1)
        .await
        .expect("activate slot 1 (wipes ephemeral 0)");

    let err = handle
        .mint_handle(PSlot::from_raw(0))
        .await
        .expect_err("retired ephemeral slot 0 was wiped");
    assert!(
        matches!(err, StakeEngineError::LookaheadExhausted { requested } if requested == PSlot::from_raw(0)),
        "expected LookaheadExhausted{{0}} after ephemeral wipe, got {err:?}"
    );

    let active = handle
        .active_persona()
        .await
        .expect("active query")
        .expect("slot 1 active");
    assert_eq!(active.p_slot, PSlot::from_raw(1));
}

// Typed contract #4 — activation keeps a retired *bonded* persona resident:
// unbonding it later stays reachable, so it can be re-activated after a
// activation that passed over it.
#[tokio::test]
async fn activation_keeps_bonded_retired() {
    let handle = spawn_over(&[0, 1], &[0], None); // slot 0 bonded, slot 1 ephemeral

    let id0 = mint_and_activate(&handle, 0).await.expect("activate 0");
    mint_and_activate(&handle, 1)
        .await
        .expect("activate slot 1 (bonded 0 stays)");

    // Slot 0 is still held — re-mintable and re-activatable.
    let id0_again = mint_and_activate(&handle, 0)
        .await
        .expect("bonded slot 0 survived the activation");
    assert_eq!(
        bond_id_bytes(&id0_again),
        bond_id_bytes(&id0),
        "re-activated bonded persona is the same identity"
    );
}

// Typed contract #2 — a handle minted before an activation is stale afterward:
// the activation advanced the actor's generation, so the retained handle is
// rejected rather than acting against a possibly-wiped persona.
#[tokio::test]
async fn stale_handle_after_activation_is_rejected() {
    // Both bonded so the activation cannot wipe — isolating the generation
    // guard from the membership guard.
    let handle = spawn_over(&[0, 1], &[0, 1], None);

    // Mint a handle for slot 0 up front, then rotate via a *different*
    // handle, leaving the slot-0 handle straddling the activation.
    let stale = handle
        .mint_handle(PSlot::from_raw(0))
        .await
        .expect("mint slot 0");
    mint_and_activate(&handle, 1)
        .await
        .expect("activate slot 1 (advances generation)");

    let err = handle
        .activate_persona(stale)
        .await
        .expect_err("a handle retained across an activation is stale");
    assert!(
        matches!(err, StakeEngineError::StaleHandle),
        "expected StaleHandle, got {err:?}"
    );
}

// Activating the already-active slot is idempotent (same identity, no error,
// no generation advance — the handle's generation still matches).
#[tokio::test]
async fn activate_same_slot_is_idempotent() {
    let handle = spawn_over(&[2], &[], Some(2));
    let a = mint_and_activate(&handle, 2).await.expect("activate 2");
    let b = mint_and_activate(&handle, 2).await.expect("re-activate 2");
    assert_eq!(bond_id_bytes(&a), bond_id_bytes(&b));
}

// Require-ambient spawn contract: without an ambient Tokio runtime, `spawn`
// panics with the contract message. Plain `#[test]` precisely *because* it
// must run with no ambient runtime.
#[test]
#[should_panic(expected = "requires an ambient Tokio runtime")]
fn spawn_without_ambient_runtime_panics() {
    let _handle = StakeEngineHandle::spawn(BTreeMap::new(), BTreeSet::new(), None);
}

// Mailbox `Send` contract (structural): message + reply types are `Send` as
// kameo requires.
#[test]
fn message_and_reply_types_are_send() {
    fn assert_send<T: Send>() {}
    assert_send::<MintPersonaHandle>();
    assert_send::<ActivatePersona>();
    assert_send::<ActivePersona>();
    assert_send::<PersonaHandle>();
    assert_send::<PersonaIdentity>();
    assert_send::<StakeEngineError>();
}

/// Test-only message whose handler panics, to exercise the fail-stop path.
struct InjectPanic;

impl Message<InjectPanic> for StakeEngine {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: InjectPanic,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        panic!("test-injected panic: exercise fail-stop");
    }
}

// Panic → fail-stop → terminal, non-retryable `StakeActorUnavailable`.
// Injects a panic; asserts the actor dies and that *repeated* calls all
// collapse to the terminal error (a retry never recovers).
#[tokio::test]
async fn panic_fail_stops_and_calls_are_terminally_unavailable() {
    let handle = spawn_over(&[0], &[], None);

    // Sanity: a live mint+activate works before the panic.
    assert!(mint_and_activate(&handle, 0).await.is_ok());

    // Inject the panic; on_panic → Break (fail-stop). The panicking ask
    // resolves to a transport error as the actor dies.
    let panic_ask = handle.actor.ask(InjectPanic).await;
    assert!(
        panic_ask.is_err(),
        "a panicking handler resolves to an error"
    );
    handle.actor.wait_for_shutdown().await;
    assert!(!handle.actor.is_alive(), "panic fail-stops the actor");

    // Terminal + non-retryable across the message surface.
    for attempt in 0..3 {
        let err = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect_err("post-death mint fails");
        assert!(
            matches!(err, StakeEngineError::StakeActorUnavailable),
            "attempt {attempt}: expected StakeActorUnavailable, got {err:?}"
        );
    }
    let err = handle
        .active_persona()
        .await
        .expect_err("post-death query fails");
    assert!(matches!(err, StakeEngineError::StakeActorUnavailable));
}

// -----------------------------------------------------------------------
// Bond-PR 2c-2b S7 — request-path composition KAT + own-surface negatives
// -----------------------------------------------------------------------
//
// S7(a): `verify_credit_funding` reject on wrong funding.
// S7(b): degeneracy guard fires on degenerate draw (double-jitter-trap RNG).
//
// The `draw_entry_gap_guarded` helper is extracted and tested directly so the
// degeneracy logic is exercised with injectable RNGs without going through the
// actor (which uses `OsRngGapAdapter` in production).
//
// S7(c) unrepresentability ("sign without ticket", "unheld-handle sign") is
// NOT covered by trybuild: that path was retired (plan §4.1 R0-D1) because the
// capability tokens are `pub(crate)` with module-private fields, so an external
// trybuild crate cannot name them without re-exposing firewall internals. It is
// instead enforced unconditionally by the type system (module-private fields +
// by-value consumption), with the `!Clone` half pinned by the always-on
// `AmbiguousIfImpl` `const _` guard above (near `PersonaHandle`).

/// S7(b) — degeneracy guard fires on a stuck-RNG (double-jitter-trap pattern).
///
/// A `ConstRng` that always returns the same `u64` produces identical spread
/// values on every call to `draw_entry_gap`, so `draw_entry_gap_guarded`
/// must fire the degeneracy guard for any window > 0.
#[test]
fn degeneracy_guard_fires_on_stuck_rng() {
    struct ConstRng(u64);
    impl GapRng for ConstRng {
        fn next_u64(&mut self) -> u64 {
            self.0
        }
    }

    // Any constant value produces the same spread twice → guard fires.
    // Use the canonical operational window (single-sourced) so the test
    // tracks the wallet's real draw window rather than a stray literal.
    for seed in [0u64, 1, 42, u64::MAX / 2] {
        let mut rng = ConstRng(seed);
        let result = draw_entry_gap_guarded(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW, &mut rng);
        assert!(
            result.is_err(),
            "stuck-RNG seed {seed}: expected degeneracy guard to fire, got ok"
        );
    }
}

/// S7(b) — degeneracy guard passes a correct RNG.
///
/// A deterministic counter RNG produces distinct consecutive spreads (except
/// in pathological cases the guard's false-positive rate handles via retry),
/// so the guard should pass for the common case.
#[test]
fn degeneracy_guard_passes_correct_rng() {
    struct CounterRng(u64);
    impl GapRng for CounterRng {
        fn next_u64(&mut self) -> u64 {
            let v = self.0;
            self.0 = self.0.wrapping_add(1_000_000_007); // large coprime step
            v
        }
    }

    let mut rng = CounterRng(0xDEAD_BEEF_0000_0000);
    let result = draw_entry_gap_guarded(shekyl_standoff::DEFAULT_ENTRY_GAP_WINDOW, &mut rng);
    assert!(
        result.is_ok(),
        "counter RNG should not trigger the degeneracy guard: {result:?}"
    );
}

/// S7(a) — `verify_credit_funding` rejects incorrect funding totals.
///
/// Tests the builder-level funding invariant directly (the actor path would
/// call `verify_credit_funding` after the `sign_bond` handler produces the
/// `JoinMarketVin`). Exercises both underflow and overflow cases.
#[test]
fn verify_credit_funding_rejects_wrong_total() {
    use shekyl_archival_bond_builder::{verify_credit_funding, BondBuildError};
    use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};
    use shekyl_units::AtomicUnits;

    let bundle = derive_bundle(0);
    let holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    };
    let tx_prefix_hash = [0u8; 32];
    let vin = build_join_market_vin(&bundle, holdings, &tx_prefix_hash)
        .expect("build_join_market_vin succeeds for valid inputs");

    let fee = AtomicUnits::from_raw(100);
    let outputs = AtomicUnits::from_raw(500);
    let bond_credit = AtomicUnits::from_raw(vin.vin().bond_credit);
    let correct_total = outputs
        .checked_add(fee)
        .and_then(|s| s.checked_add(bond_credit))
        .expect("test amounts fit in u64");

    assert!(
        verify_credit_funding(correct_total, outputs, fee, &vin).is_ok(),
        "correct total must pass"
    );

    let short = AtomicUnits::from_raw(correct_total.to_raw() - 1);
    let err =
        verify_credit_funding(short, outputs, fee, &vin).expect_err("underflow funding must fail");
    assert!(
        matches!(err, BondBuildError::CreditImbalance { .. }),
        "wrong error: {err:?}"
    );

    let over = AtomicUnits::from_raw(correct_total.to_raw() + 1);
    let err =
        verify_credit_funding(over, outputs, fee, &vin).expect_err("overflow funding must fail");
    assert!(
        matches!(err, BondBuildError::CreditImbalance { .. }),
        "wrong error: {err:?}"
    );
}

/// S7 slot-mismatch negative — a ticket for slot A with a handle for slot B
/// produces [`StakeEngineError::SlotMismatch`], not a signing attempt.
#[tokio::test]
async fn sign_bond_slot_mismatch_is_rejected() {
    use crate::engine::stake_persist::PersistedBondTicket;
    use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};

    let handle = spawn_over(&[0, 1], &[], None);
    mint_and_activate(&handle, 0)
        .await
        .expect("activate slot 0");
    let h0 = handle
        .mint_handle(PSlot::from_raw(0))
        .await
        .expect("mint handle for slot 0");

    // Forge a ticket for slot 1 (bypassing Engine::persist_bond_record
    // via the test-only constructor on PersistedBondTicket).
    let ticket_for_slot_1 = PersistedBondTicket::__test_only_forge(PSlot::from_raw(1));

    let holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    };
    let err = handle
        .sign_bond(h0, ticket_for_slot_1, holdings, [0u8; 32])
        .await
        .expect_err("slot mismatch must fail");

    assert!(
        matches!(
            err,
            StakeEngineError::SlotMismatch {
                handle_slot,
                ticket_slot,
            } if handle_slot == PSlot::from_raw(0) && ticket_slot == PSlot::from_raw(1)
        ),
        "expected SlotMismatch(0, 1), got {err:?}"
    );
}

/// GF-7 hooks-spec §6.2 (emission-complete for the 2c-2b surface) — a
/// successful `sign_bond` emits exactly the draw-consumption and schedule
/// events to the **injected** observer, and the emitted payloads are
/// internally consistent: the scheduled offset equals the drawn spread
/// (causal — the post fires `spread` blocks after the private intent), and
/// it matches the offset riding the reply. Also pins the §3 payload
/// discipline the sim depends on: opaque slot ordinal and the sweepable
/// window parameter on the draw event.
#[cfg(feature = "gf7-hooks")]
#[tokio::test]
async fn sign_bond_emits_gf7_draw_and_schedule_events() {
    use std::sync::{Arc, Mutex};

    use crate::engine::stake_persist::PersistedBondTicket;
    use shekyl_archival_retention::{HoldingsDescriptor, HoldingsKind};

    struct Recorder(Arc<Mutex<Vec<TimelineEvent>>>);
    impl BroadcastTimelineObserver for Recorder {
        fn record(&mut self, event: TimelineEvent) {
            self.0.lock().expect("recorder lock").push(event);
        }
    }

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let bundles: BTreeMap<PSlot, ArchivalPKeys> = [(PSlot::from_raw(0), derive_bundle(0))]
        .into_iter()
        .collect();
    let handle = StakeEngineHandle {
        actor: StakeEngine::spawn(StakeEngineArgs {
            bundles,
            bonded: BTreeSet::new(),
            active: None,
            #[cfg(feature = "conformance")]
            self_cert: TestSelfCert::Skip,
            observer: Box::new(Recorder(Arc::clone(&recorded))),
        }),
    };

    let h0 = handle
        .mint_handle(PSlot::from_raw(0))
        .await
        .expect("mint handle for slot 0");
    let ticket = PersistedBondTicket::__test_only_forge(PSlot::from_raw(0));
    let holdings = HoldingsDescriptor {
        kind: HoldingsKind::ShardSetCompact,
        shard_ids: ShardSet::new(vec![7, 42]).unwrap(),
    };
    let post = handle
        .sign_bond(h0, ticket, holdings, [0u8; 32])
        .await
        .expect("sign_bond succeeds for a held, matching slot");

    let events = recorded.lock().expect("recorder lock");
    assert_eq!(
        events.len(),
        2,
        "exactly the two 2c-2b emission points fire: {events:?}"
    );

    let spread = match events[0] {
        TimelineEvent::EntryGapDrawConsumed {
            persona,
            window_blocks,
            spread_blocks,
        } => {
            assert_eq!(persona, 0, "opaque wallet-local slot ordinal");
            assert_eq!(
                window_blocks,
                DEFAULT_ENTRY_GAP.as_blocks(),
                "sweepable window parameter rides the event"
            );
            spread_blocks
        }
        ref other => panic!("first event must be the draw consumption, got {other:?}"),
    };

    match events[1] {
        TimelineEvent::BondPostScheduled {
            persona,
            bond_post_offset_blocks,
        } => {
            assert_eq!(persona, 0, "same persona ordinal as the draw event");
            // Causal by construction: the post fires `spread` blocks after
            // the private intent; there is no second event and no coin.
            assert_eq!(
                bond_post_offset_blocks, spread,
                "scheduled offset must be the drawn spread"
            );
            assert_eq!(
                bond_post_offset_blocks, post.bond_post_offset_blocks,
                "schedule event must match the offset riding the reply"
            );
        }
        ref other => panic!("second event must be the schedule, got {other:?}"),
    }
}

// ---- SP-3/SP-5: the offloaded dual-extractor scan-step ----

use shekyl_crypto_pq::kem::HybridKemPublicKey;
use shekyl_scanner::bench_fixtures::scannable_block_for_recipient;
use shekyl_types::{BlockHeight, SettlementEpoch};
use shekyl_units::AtomicUnits;
use shekyl_wire::transaction::{BondPost, BondPostKind, Input};
use shekyl_wire::Holdings;

/// The cleartext canonical id an on-chain bond-post carries for `slot`.
fn canonical_id(slot: u32) -> PCanonicalId {
    p_canonical_id_from_hybrid_pubkey(&oracle_bond_id(slot))
}

/// A block with one output addressed to persona `slot`.
fn block_funding(slot: u32) -> ScannableBlock {
    let p = derive_bundle(slot);
    let kem = HybridKemPublicKey {
        x25519: p.x25519_pk,
        ml_kem: p.ml_kem_ek.to_vec(),
    };
    scannable_block_for_recipient(1, &kem, p.spend_pk.as_canonical_bytes())
}

/// Append a JoinMarket bond-post for persona `slot` to a block's first tx.
fn with_bond_post(mut block: ScannableBlock, slot: u32) -> ScannableBlock {
    let post = BondPost {
        hybrid_public_key: oracle_bond_id(slot),
        p_canonical_id: canonical_id(slot).to_bytes(),
        kind: BondPostKind::JoinMarket {
            bond_spend_pk: Vec::new(),
        },
        holdings: Holdings::CompleteTree,
        bonded_total_atomic: 1_000,
        bond_credit: 1_000,
        bond_debit: 0,
    };
    block.transactions[0]
        .prefix
        .inputs
        .push(Input::BondPost(Box::new(post)));
    block
}

fn one_block_range(h: u64) -> BlockRange {
    BlockRange::new(BlockHeight::from_raw(h), BlockHeight::from_raw(h + 1)).expect("range")
}

// SP-3/SP-5 — a bonded persona's funding *and* its bond-post both come back
// (public) through the actor's offloaded scan-step; `view_sk` never crosses.
#[tokio::test]
async fn scan_step_extracts_funding_and_bond_post_for_a_bonded_persona() {
    let handle = spawn_over(&[0], &[0], None); // persona 0 held AND bonded
    let block = with_bond_post(block_funding(0), 0);

    let res = handle
        .scan_step(one_block_range(20_001), vec![block], Vec::new().into())
        .await
        .expect("scan-step succeeds");

    assert_eq!(
        res.funding.len(),
        1,
        "the bonded persona's output is summed"
    );
    assert_eq!(res.funding[0].epoch, SettlementEpoch::from_raw(2)); // 20_001 / 10_000
    assert!(res.funding[0].amount > AtomicUnits::ZERO);
    assert_eq!(res.bond_post_matches.len(), 1, "its bond-post matched");
    assert_eq!(res.bond_post_matches[0].p_canonical_id, canonical_id(0));
}

// A persona that is HELD but not BONDED is not scanned, and a foreign bond-post
// does not match — the bonded tag gates the scan set (DQ8; SP-6 reconciles).
#[tokio::test]
async fn scan_step_skips_non_bonded_personas_and_foreign_posts() {
    // Persona 0 bonded; the block is addressed to persona 1 (held, not bonded)
    // and carries persona 1's bond-post.
    let handle = spawn_over(&[0, 1], &[0], None);
    let block = with_bond_post(block_funding(1), 1);

    let res = handle
        .scan_step(one_block_range(20_001), vec![block], Vec::new().into())
        .await
        .expect("scan-step succeeds");

    assert!(
        res.funding.is_empty(),
        "persona 1's output is not ours to recover"
    );
    assert!(
        res.bond_post_matches.is_empty(),
        "persona 1's canonical id is not in the bonded union"
    );
}

// Bounded + offloaded (DQ6): the handler returns and frees the mailbox, so the
// actor answers the next message rather than freezing on the scan.
#[tokio::test]
async fn actor_is_responsive_after_a_scan_step() {
    let handle = spawn_over(&[0], &[0], None);
    let _ = handle
        .scan_step(
            one_block_range(1),
            vec![block_funding(0)],
            Vec::new().into(),
        )
        .await
        .expect("scan-step succeeds");
    let active = handle.active_persona().await.expect("still responsive");
    assert!(active.is_none(), "actor processed the follow-up message");
}

// ---- DQ8: witness-gated retirement of a terminal bonded persona ----

/// A witness exists iff the persona's last creditable epoch `e_last = U` has
/// fallen *below* the claim window floor `settled − W`. The boundary edge —
/// `settled = U + W`, where `U` is still the oldest claimable epoch — must
/// **not** retire (it's the off-by-one that would wipe a still-claimable
/// persona). Eligibility begins at `settled = U + W + 1`.
#[test]
fn retirement_witness_fires_one_epoch_after_the_claim_window_closes() {
    let id = canonical_id(0);
    let unbond = SettlementEpoch::from_raw(10);
    // settled = U + W: U is exactly the oldest claimable epoch → still claimable
    // → must NOT retire.
    assert!(
        RetirementWitness::from_confirmed_unbond(
            id,
            unbond,
            SettlementEpoch::from_raw(10 + MAX_CLAIM_AGE_W),
        )
        .is_none(),
        "U is still claimable at settled = U + W; retiring here is stuck funds"
    );
    // settled = U + W + 1: U has dropped below the window floor → retire.
    assert!(
        RetirementWitness::from_confirmed_unbond(
            id,
            unbond,
            SettlementEpoch::from_raw(10 + MAX_CLAIM_AGE_W + 1),
        )
        .is_some(),
        "retire once U falls out of the claim window"
    );
}

/// The witness retires (wipes) a terminal bonded persona, and the retire is
/// idempotent: re-handing it after the persona is gone is a `NotHeld` no-op.
#[tokio::test]
async fn retire_wipes_a_terminal_persona_and_is_idempotent() {
    let handle = spawn_over(&[0], &[0], None); // persona 0 bonded, not active
    let witness = RetirementWitness::from_confirmed_unbond(
        canonical_id(0),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
    )
    .expect("eligible");

    assert_eq!(
        handle
            .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
            .await
            .expect("retire"),
        RetireOutcome::Retired {
            slot: PSlot::from_raw(0)
        }
    );

    // Gone now → a fresh witness for the same persona is a no-op.
    let again = RetirementWitness::from_confirmed_unbond(
        canonical_id(0),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
    )
    .expect("eligible");
    assert_eq!(
        handle
            .retire_bonded_persona(again, std::sync::Arc::new(FundedSlots::default()))
            .await
            .expect("retire"),
        RetireOutcome::NotHeld,
        "retiring an already-gone persona is an idempotent no-op"
    );
}

/// The funded-gate: a terminal persona whose slot still holds unspent
/// funding is left in place ([`RetireOutcome::SkippedFunded`]) — wiping it
/// would strand the funds. Once drained (the slot leaves the funded set) the
/// same witness retires it.
#[tokio::test]
async fn retire_defers_a_funded_persona_then_wipes_once_drained() {
    let handle = spawn_over(&[0], &[0], None); // persona 0 bonded, not active
    let witness = || {
        RetirementWitness::from_confirmed_unbond(
            canonical_id(0),
            SettlementEpoch::from_raw(0),
            SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
        )
        .expect("eligible")
    };

    // Slot 0 still holds unspent funding → the wipe is refused.
    let funded = FundedSlots::from_slots([PSlot::from_raw(0)]);
    assert_eq!(
        handle
            .retire_bonded_persona(witness(), std::sync::Arc::new(funded))
            .await
            .expect("retire"),
        RetireOutcome::SkippedFunded {
            slot: PSlot::from_raw(0)
        },
        "a funded slot is never wiped (stuck-funds guard)"
    );

    // Drained now (empty funded set) → the same witness retires it.
    assert_eq!(
        handle
            .retire_bonded_persona(witness(), std::sync::Arc::new(FundedSlots::default()))
            .await
            .expect("retire"),
        RetireOutcome::Retired {
            slot: PSlot::from_raw(0)
        },
        "once drained the deferred retire fires"
    );
}

/// The active persona is never wiped mid-use — retire skips it (the next
/// activation moves `active` away, then the retire re-fires).
#[tokio::test]
async fn retire_skips_the_active_persona() {
    let handle = spawn_over(&[0], &[0], Some(0)); // persona 0 bonded AND active
    let witness = RetirementWitness::from_confirmed_unbond(
        canonical_id(0),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
    )
    .expect("eligible");
    assert_eq!(
        handle
            .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
            .await
            .expect("retire"),
        RetireOutcome::SkippedActive {
            slot: PSlot::from_raw(0)
        }
    );
}

/// A witness for a persona we do not hold (never bonded, or another wallet's)
/// is a `NotHeld` no-op — the actor matches only its own bonded union.
#[tokio::test]
async fn retire_an_unheld_persona_is_notheld() {
    let handle = spawn_over(&[0], &[0], None); // we hold persona 0
                                               // A witness for persona 1 (not held).
    let witness = RetirementWitness::from_confirmed_unbond(
        canonical_id(1),
        SettlementEpoch::from_raw(0),
        SettlementEpoch::from_raw(MAX_CLAIM_AGE_W + 1),
    )
    .expect("eligible");
    assert_eq!(
        handle
            .retire_bonded_persona(witness, std::sync::Arc::new(FundedSlots::default()))
            .await
            .expect("retire"),
        RetireOutcome::NotHeld
    );
}

/// S6 — session RNG self-cert wiring (conformance build only).
#[cfg(feature = "conformance")]
mod s6_self_cert {
    use super::*;

    /// The **decision**: a stuck RNG (constant output) grades non-conformant,
    /// so the extracted self-cert returns the typed start error. Proves
    /// fail-stop *decides* correctly without spawning; the full
    /// spawn→`OpenError` path with a degenerate source is the Round-2 test.
    #[test]
    fn run_session_self_cert_rejects_stuck_rng() {
        struct ConstRng(u64);
        impl GapRng for ConstRng {
            fn next_u64(&mut self) -> u64 {
                self.0
            }
        }
        let mut rng = ConstRng(0x42);
        let result = run_session_self_cert(&mut rng);
        assert!(
            matches!(result, Err(StakeEngineStartError::RngSelfCertFailed(_))),
            "a stuck RNG must fail the session self-cert, got {result:?}"
        );
    }

    /// Build a handle with an explicit self-cert mode (the bulk-test
    /// `spawn_over` uses `Skip`; the S6 tests need `RealOsRng`/`Degenerate`).
    fn spawn_with_self_cert(held: &[u32], mode: TestSelfCert) -> StakeEngineHandle {
        let bundles: BTreeMap<PSlot, ArchivalPKeys> = held
            .iter()
            .map(|&s| (PSlot::from_raw(s), derive_bundle(s)))
            .collect();
        let args = StakeEngineArgs {
            bundles,
            bonded: BTreeSet::new(),
            active: None,
            self_cert: mode,
            #[cfg(feature = "gf7-hooks")]
            observer: Box::new(shekyl_standoff::gf7::NoOpObserver),
        };
        StakeEngineHandle {
            actor: StakeEngine::spawn(args),
        }
    }

    /// The **wiring**: the production `OsRng` adapter grades conformant, so a
    /// freshly spawned StakeEngine starts cleanly and the eager observation
    /// path (`wait_for_self_cert`) returns `Ok`. Multi-thread so the actor
    /// task keeps running while the test awaits its startup. (A single real
    /// grade per run keeps the α=1e-6 false-positive negligible — the flake
    /// risk only became real when every spawn graded; see `StakeEngineArgs`.)
    #[tokio::test(flavor = "multi_thread")]
    async fn session_self_cert_passes_over_os_rng_at_spawn() {
        let handle = spawn_with_self_cert(&[0], TestSelfCert::RealOsRng);
        let cert = handle.wait_for_self_cert().await;
        assert!(
            cert.is_ok(),
            "the production OsRng adapter must pass the session self-cert, got {cert:?}"
        );
        // The actor is alive and serving after a passing self-cert.
        assert!(handle.active_persona().await.is_ok());
    }

    /// The full **fail-stop path** (R0-D# / Round 2): a degenerate self-cert
    /// source makes `on_start` return `Err`, kameo turns that into a startup
    /// failure (the actor never enters its message loop), the eager
    /// observation (`wait_for_self_cert`) surfaces it as `Err`, and the actor
    /// is dead — any later op collapses to the terminal `StakeActorUnavailable`.
    /// (At the wallet-open path this same `Err` becomes
    /// `OpenError::StakeRngSelfCertFailed`.)
    #[tokio::test(flavor = "multi_thread")]
    async fn degenerate_self_cert_fail_stops_spawn() {
        // Force a degenerate source so `on_start` returns Err and the actor
        // fail-stops (the spawn helper builds args directly with the mode).
        let handle = spawn_with_self_cert(&[0], TestSelfCert::Degenerate);

        let cert = handle.wait_for_self_cert().await;
        assert!(
            cert.is_err(),
            "a degenerate self-cert source must fail-stop the spawn, got {cert:?}"
        );
        // The actor fail-stopped: subsequent ops are terminally unavailable.
        assert!(matches!(
            handle.active_persona().await,
            Err(StakeEngineError::StakeActorUnavailable)
        ));
    }
}

/// PR-3 commit 4 — [`AssembleEmissionClaim`]'s end-to-end **daemon-side
/// differential**: parse the produced bytes, re-derive every consensus
/// operand (`archival_emission_index`, the erase-rule signable hash, the
/// ordered reward-commit set, the id-equality key) from the wire alone,
/// and drive the landed verifiers over the PARSED vin — nothing below
/// reuses the builder's in-memory intermediates, so builder/daemon drift
/// on any of those rules fails here rather than at a real daemon.
///
/// The old handler-side refusal KATs (stale anchor, backing-in-fee-set,
/// mandatory fee funding) moved to `backing_set.rs` with the checks
/// themselves: `ClaimOperands` is mintable only through the sweep seal,
/// so those states have no expressible form at this message boundary.
mod emission_claim_assembly {
    use super::*;

    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_types::BlockHeight;
    use shekyl_wire::{Ct, Transaction};

    use crate::engine::backing_set::{BackingSet, MembershipPath};
    use crate::engine::bond_assembly::SpentRecordsDurablyPruned;
    use crate::engine::emission_claim::test_fixtures::{snapshot, source_with};
    use crate::engine::emission_source::EmissionClaimSource;
    use crate::engine::synthetic_tree::consistent_synthetic_path;

    /// The known-claimable source shape shared with the `emission_claim`
    /// step-7 differential (settled = 10, epochs 4 and 5 claimable) — one
    /// fixture family across both differential halves, per the
    /// `test_fixtures` module doc.
    fn claimable_source() -> EmissionClaimSource {
        source_with(10, vec![], vec![snapshot(4), snapshot(5)])
    }

    /// The end-to-end daemon-side differential. Assembly runs over a
    /// depth-consistent synthetic tree with two REAL P-paid outputs
    /// (backing + fee spend); every check below then re-derives the
    /// daemon's operands from the produced BYTES:
    ///
    /// 1. **Index pin** — `classify_archival_tx` finds the emission vin
    ///    after the ToKey key images, so `archival_emission_index ==
    ///    count(key images)`.
    /// 2. **Erase rule** (`blockchain.cpp:3866`) — remove the vin
    ///    WHOLESALE from the *parsed* prefix and hash what remains via
    ///    `shekyl_wire`'s independent prefix-hash implementation; the
    ///    landed verifiers accept the vin's membership proof and both
    ///    auths against THAT hash, or the builder's from-parts signable
    ///    hash diverged from the daemon's.
    /// 3. **Id-equality** (`blockchain.cpp:3783`) — the vin's `p_pubkey`
    ///    derives the claimant id, and the emission `pqc_auths` slot
    ///    carries the same key.
    /// 4. **Reward-commit rule** — non-zero WIRE amounts in vout order,
    ///    commitments from the tx's outPk (never the builder's copy),
    ///    exactly one loud vout carrying `total_reward`.
    /// 5. **Claims leg** — `self_check_claims` (the landed economics
    ///    verifier) over the parsed vin and the paired source.
    #[tokio::test(flavor = "multi_thread")]
    async fn assembled_claim_survives_the_daemon_side_differential() {
        let handle = spawn_over(&[0], &[], None);
        let h = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("slot 0 held");
        let keys = derive_bundle(0);
        let source = claimable_source();
        let tip = source.chain_height.to_raw() - 1;

        // Two real P-paid outputs in ONE leaf chunk — the backing
        // (rung-2 lineage) and the fee spend (rung 3) — under one
        // depth-consistent single-path tree shared by both proofs.
        let (backing_record, backing_leaf) =
            constructed_record(&keys, 11, 5, 750_000, 0, MintLineageOutput::BondPostChange);
        let (fee_record, fee_leaf) =
            constructed_record(&keys, 22, 6, 90_000, 1, MintLineageOutput::ExternalTransfer);
        let backing_gindex = backing_record.gindex;
        let leaf_chunk = vec![backing_leaf, fee_leaf];
        // Depth 2 — the wire encoder's spendable minimum (`fcmp_layers >=
        // 2`); the synthetic single-path tree is depth-consistent at any
        // depth.
        let depth = 2u8;
        let (c1_layers, c2_layers, tree_root) = consistent_synthetic_path(&leaf_chunk, depth);
        let tree_ctx = TreeContext {
            reference_block: [7u8; 32],
            tree_root,
            tree_depth: depth,
        };

        // Mint the sealed operands through the ONLY route there is:
        // designate the backing at the source's tip, sweep the fee
        // inputs against it (the Q11 exclusion and the item-6 same-tip
        // check fire in the mint, exercised by the `backing_set.rs`
        // KATs), then zip the assembled paths in. Both leaves share the
        // single synthetic path, so every witness record gets the same
        // path data — exactly the old hand-built shape, now sealed.
        let fee = 10_000u64;
        let records = [backing_record.clone(), fee_record];
        let swept = BackingSet::from_spendable(
            &[backing_record],
            PSlot::from_raw(0),
            BlockHeight::from_raw(tip),
            BlockHeight::from_raw(0),
        )
        .designate_backing()
        .expect("the rung-2 record designates")
        .fee_sweep(
            source.clone(),
            &SpentRecordsDurablyPruned::for_test(),
            &records,
            PSlot::from_raw(0),
            &Default::default(),
            AtomicUnits::from_raw(fee),
        )
        .expect("the fee sweep mints the sealed witness");
        let paths: Vec<MembershipPath> = swept
            .path_records()
            .map(|_| MembershipPath {
                leaf_chunk: leaf_chunk.clone(),
                c1_layers: c1_layers.clone(),
                c2_layers: c2_layers.clone(),
            })
            .collect();
        let operands = swept
            .with_paths(paths)
            .expect("one path per witness record");

        let reply = handle
            .assemble_emission_claim(AssembleEmissionClaim {
                handle: h,
                operands,
                tree_ctx,
            })
            .await
            .expect("emission-claim assembly completes end-to-end");

        assert!(reply.total_reward > 0, "fixture epochs carry a real reward");
        assert_eq!(reply.claimed_epochs, vec![4, 5]);
        assert!(reply.size_deferred.is_empty());
        // Q11 surface: only the fee spend is reserved — the backing is
        // consumed as backing, never as a fee input.
        assert_eq!(reply.fee_gindexes, vec![GlobalOutputIndex::from_raw(22)]);
        assert!(!reply.fee_gindexes.contains(&backing_gindex));

        // ── Everything below recomputes from the wire BYTES. ──────────
        let mut cursor: &[u8] = reply.bound_tx.bytes();
        let mut tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
        assert!(cursor.is_empty(), "no trailing bytes after the tx");

        // (1) Index pin.
        let to_key_count = tx
            .prefix
            .inputs
            .iter()
            .filter(|i| matches!(i, Input::ToKey { .. }))
            .count();
        assert_eq!(to_key_count, 1, "one fee spend");
        let emission_index = tx
            .prefix
            .inputs
            .iter()
            .position(|i| matches!(i, Input::ArchivalRewardEmission { .. }))
            .expect("emission vin present");
        assert_eq!(
            emission_index, to_key_count,
            "emission vin sits after the key images — the daemon's erase index"
        );
        assert_eq!(tx.prefix.inputs.len(), to_key_count + 1);

        // Exact-parse the vin blob (the daemon's canonical-encoding
        // demand; `read` consumes the 0x04 tag the blob carries).
        let Input::ArchivalRewardEmission { canonical_bytes } = &tx.prefix.inputs[emission_index]
        else {
            unreachable!("position() matched this variant");
        };
        let vin = ArchivalRewardEmissionVin::read(&mut canonical_bytes.as_slice())
            .expect("vin blob parses");

        // (3) Id-equality: vin p_pubkey derives the claimant id...
        let expected_id = p_canonical_id_from_hybrid_pubkey(
            &keys
                .hybrid_sign_pk
                .to_canonical_bytes()
                .expect("identity encodes"),
        );
        assert_eq!(
            p_canonical_id_from_hybrid_pubkey(&vin.p_pubkey),
            expected_id
        );
        // ...and the emission pqc_auths slot carries the SAME key (the
        // daemon derives the slot's id and demands equality — the
        // resolved symmetry item, NOT the bond's slot-key rule assumed).
        let Ct::Fcmp {
            base,
            pqc_auths,
            fee: wire_fee,
            ..
        } = &tx.ct
        else {
            panic!("emission claim is an Fcmp ct");
        };
        assert_eq!(*wire_fee, fee);
        assert_eq!(pqc_auths.len(), tx.prefix.inputs.len());
        assert_eq!(
            pqc_auths[emission_index].hybrid_public_key, vin.p_pubkey,
            "emission slot key == vin p_pubkey (id-equality's operand)"
        );

        // (4) The daemon's reward-commit rule.
        let reward_commits: Vec<RewardCommit> = tx
            .prefix
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| o.amount != 0)
            .map(|(i, o)| RewardCommit {
                commitment: base.commitments[i],
                amount_plain: o.amount,
                one_time_key: o.key,
            })
            .collect();
        assert_eq!(reward_commits.len(), 1, "exactly one loud vout");
        assert_eq!(reward_commits[0].amount_plain, reply.total_reward);
        let vout_reward_sum: u64 = reward_commits.iter().map(|c| c.amount_plain).sum();

        // (2) The erase rule: remove the emission vin WHOLESALE from the
        // parsed prefix; hash what remains through the wire crate's own
        // prefix-hash path (independent of the builder's from-parts
        // hasher).
        let full_prefix_hash = tx.prefix_hash();
        tx.prefix.inputs.remove(emission_index);
        let signable = tx.prefix_hash();

        // Premise arm: the erase is load-bearing — the vin-less hash
        // differs from the full prefix hash, and the auths REFUSE the
        // wrong (un-erased) operand. Without this, the accepts below
        // could go vacuously green if the two hashes ever coincided.
        assert_ne!(signable, full_prefix_hash, "the erase must change the hash");
        emission_vin_verify_auth(&vin, &reward_commits, &full_prefix_hash)
            .expect_err("auths must refuse a signable hash that was not erase-derived");

        // The three landed-verifier legs over the PARSED vin and the
        // recomputed operands: membership proof + leaf gate, both role
        // auths, and the economics recompute. A builder/daemon drift in
        // the signable hash, index derivation, commit set, or either
        // auth key refuses here.
        emission_vin_verify_backing(&vin, &tree_root, depth, signable)
            .expect("backing leg verifies against the erase-rule hash");
        emission_vin_verify_auth(&vin, &reward_commits, &signable)
            .expect("both auth legs verify against the erase-rule hash");
        self_check_claims(&source, &vin, vout_reward_sum)
            .expect("claims leg verifies against the paired source");
    }
}

/// F-D2 DS-PR-1 — the drain's **composite wire-shape arm** (T-DS-6 ∧
/// T-DS-7), checked from the produced BYTES: a `P`→principal drain
/// serializes as a modal 2-out confidential transfer. Every property below
/// that a bond/claim carries and a transfer does not — an archival prefix
/// input, a loud (plaintext-amount) vout, an identity auth slot — is
/// asserted ABSENT, and every property a modal transfer has — exactly two
/// confidential outputs, spend-only `pqc_auths` — asserted present.
///
/// The full byte-diff against a live principal-keyed transfer and the
/// scan-claim confirmation of the change output (T-DS-3) land with the
/// DS-PR-2 regtest e2e (mirroring the emission daemon-side differential's
/// own e2e placement); these in-crate arms fix the structural shape the
/// e2e then confirms empirically.
mod drain_assembly_shape {
    use super::*;

    use shekyl_engine_state::pscan_state::MintLineageOutput;
    use shekyl_wire::{Ct, Transaction};

    use crate::engine::drain_assembly::{AssembleDrain, DrainAssemblyError, DrainDestination};
    use crate::engine::synthetic_tree::consistent_synthetic_path;

    /// Two REAL P-paid funding inputs (`600_000 + 400_000`) in one
    /// depth-consistent synthetic leaf chunk, plus a valid principal
    /// destination (a distinct persona's public triple — the drain does not
    /// care whose principal it is, only that the keys are well-formed).
    fn drain_fixture() -> (Vec<FundingInputContext>, TreeContext, DrainDestination, u64) {
        let keys = derive_bundle(0);
        let (rec0, leaf0) = constructed_record(
            &keys,
            11,
            5,
            600_000,
            0,
            MintLineageOutput::ExternalTransfer,
        );
        let (rec1, leaf1) = constructed_record(
            &keys,
            22,
            6,
            400_000,
            1,
            MintLineageOutput::ExternalTransfer,
        );
        let leaf_chunk = vec![leaf0, leaf1];
        let depth = 2u8;
        let (c1_layers, c2_layers, tree_root) = consistent_synthetic_path(&leaf_chunk, depth);
        let tree_ctx = TreeContext {
            reference_block: [7u8; 32],
            tree_root,
            tree_depth: depth,
        };
        let funding = vec![
            FundingInputContext {
                record: rec0,
                leaf_chunk: leaf_chunk.clone(),
                c1_layers: c1_layers.clone(),
                c2_layers: c2_layers.clone(),
            },
            FundingInputContext {
                record: rec1,
                leaf_chunk,
                c1_layers,
                c2_layers,
            },
        ];
        // Principal = a different persona's public keys (valid points/encap
        // key), so the payment vout is genuinely NOT a P-space output.
        let principal = derive_bundle(9);
        let dest = DrainDestination {
            spend_pk: *principal.spend_pk.as_canonical_bytes(),
            x25519_pk: principal.x25519_pk,
            ml_kem_ek: principal.ml_kem_ek.to_vec(),
        };
        (funding, tree_ctx, dest, 1_000_000)
    }

    /// A partial drain (`payment < available - fee`, change > 0) is a modal
    /// 2-out confidential transfer on the wire.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_is_transfer_shaped() {
        let handle = spawn_over(&[0], &[], None);
        let h = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("slot 0 held");
        let (funding, tree_ctx, dest, _available) = drain_fixture();

        let fee = 10_000u64;
        let reply = handle
            .assemble_drain(AssembleDrain {
                handle: h,
                funding,
                tree_ctx,
                dest,
                payment_amount: 600_000, // change = 1_000_000 - 600_000 - 10_000 > 0
                fee,
            })
            .await
            .expect("drain assembly completes end-to-end");

        assert_eq!(
            reply.funding_gindexes.len(),
            2,
            "both funding inputs reserved"
        );

        // ── Everything below recomputes from the wire BYTES. ──────────
        let mut cursor: &[u8] = reply.bound_tx.bytes();
        let tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
        assert!(cursor.is_empty(), "no trailing bytes after the tx");

        // Transfer-shaped prefix inputs: every input is a plain ToKey
        // key-image spend — NO `ArchivalRewardEmission`, NO `BondPost`.
        assert_eq!(tx.prefix.inputs.len(), 2, "two funding spends");
        assert!(
            tx.prefix
                .inputs
                .iter()
                .all(|i| matches!(i, Input::ToKey { .. })),
            "a drain carries only key-image spends — no archival prefix input"
        );

        // Modal 2-out (T-DS-6): exactly two outputs, both CONFIDENTIAL
        // (wire amount 0) — no loud reward vout, unlike an emission claim.
        assert_eq!(tx.prefix.outputs.len(), 2, "principal payment + P change");
        assert!(
            tx.prefix.outputs.iter().all(|o| o.amount == 0),
            "both vouts are confidential (no plaintext amount on the wire)"
        );

        let Ct::Fcmp {
            pqc_auths,
            fee: wire_fee,
            ..
        } = &tx.ct
        else {
            panic!("a drain is an Fcmp ct");
        };
        assert_eq!(*wire_fee, fee, "wire fee matches the assembled fee");

        // Spend-only `pqc_auths`: one slot per input, NO identity auth slot
        // (the byte-shape difference between a drain and a bond is exactly
        // the absence of the P-identity auth the bond appends).
        assert_eq!(
            pqc_auths.len(),
            tx.prefix.inputs.len(),
            "one auth per spend — no extra identity slot"
        );
        let p_identity = derive_bundle(0)
            .hybrid_sign_pk
            .to_canonical_bytes()
            .expect("identity encodes");
        assert!(
            pqc_auths.iter().all(|a| a.hybrid_public_key != p_identity),
            "no auth slot carries P's identity key — a drain does not sign as a persona"
        );
    }

    /// A drain-**all** (`payment == available - fee`, change == 0) STILL
    /// emits two nonzero outputs: with no residual `P` value to return, the
    /// principal payment is SPLIT into two nonzero principal outputs (a sweep
    /// to self), so the vout count is the modal `2` (T-DS-6) and the daemon
    /// prunable-tx floor holds — a 1-out drain (the distinguishable shape) is
    /// never produced.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_all_still_emits_two_outputs() {
        let handle = spawn_over(&[0], &[], None);
        let h = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("slot 0 held");
        let (funding, tree_ctx, dest, available) = drain_fixture();

        let fee = 10_000u64;
        let reply = handle
            .assemble_drain(AssembleDrain {
                handle: h,
                funding,
                tree_ctx,
                dest,
                payment_amount: available - fee, // change == 0
                fee,
            })
            .await
            .expect("drain-all assembly completes end-to-end");

        let mut cursor: &[u8] = reply.bound_tx.bytes();
        let tx = Transaction::read(&mut cursor).expect("assembled bytes parse whole");
        assert!(cursor.is_empty());
        assert_eq!(
            tx.prefix.outputs.len(),
            2,
            "drain-all splits the payment into two principal outputs — modal 2-out, never 1-out"
        );
        assert!(
            tx.prefix.outputs.iter().all(|o| o.amount == 0),
            "both vouts confidential (no plaintext amount on the wire)"
        );
    }

    /// A drain-all whose net payment (`available - fee`) is a single atomic
    /// unit cannot form two nonzero outputs, so it is refused **loudly** with
    /// [`DrainAssemblyError::PaymentUnsplittable`] rather than shaped into
    /// the distinguishable 1-out (T-DS-6). Pathological — the fee dwarfs one
    /// atomic unit — but the refusal is structural, not best-effort.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_all_net_below_two_is_refused() {
        let handle = spawn_over(&[0], &[], None);
        let h = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("slot 0 held");
        let (funding, tree_ctx, dest, available) = drain_fixture();

        // fee = available - 1 ⇒ net payment == 1, change == 0 ⇒ unsplittable.
        let fee = available - 1;
        let err = handle
            .assemble_drain(AssembleDrain {
                handle: h,
                funding,
                tree_ctx,
                dest,
                payment_amount: 1,
                fee,
            })
            .await
            .expect_err("a 1-atomic net drain-all cannot be a modal 2-out");
        assert!(
            matches!(
                err,
                StakeEngineError::DrainAssembly(DrainAssemblyError::PaymentUnsplittable { net: 1 })
            ),
            "expected DrainAssembly(PaymentUnsplittable {{ net: 1 }}), got {err:?}"
        );
    }

    /// A drain that pays **zero** to the principal is not a drain: it is
    /// refused up front with [`DrainAssemblyError::PaymentZero`] before any
    /// output construction, rather than surfacing later as the shared
    /// prover's opaque `ZeroOutputAmount` on a zero-value vout 0 — a
    /// caller-input error, diagnosed at its source.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_zero_payment_is_refused() {
        let handle = spawn_over(&[0], &[], None);
        let h = handle
            .mint_handle(PSlot::from_raw(0))
            .await
            .expect("slot 0 held");
        let (funding, tree_ctx, dest, available) = drain_fixture();

        // Ample funding, small fee ⇒ change > 0; the zero payment (not the
        // funding) is what is rejected, before any output is built.
        let fee = 10_000u64;
        assert!(available > fee, "fixture funds exceed the fee (change > 0)");
        let err = handle
            .assemble_drain(AssembleDrain {
                handle: h,
                funding,
                tree_ctx,
                dest,
                payment_amount: 0,
                fee,
            })
            .await
            .expect_err("a zero-payment drain pays nothing to principal");
        assert!(
            matches!(
                err,
                StakeEngineError::DrainAssembly(DrainAssemblyError::PaymentZero)
            ),
            "expected DrainAssembly(PaymentZero), got {err:?}"
        );
    }

    /// The composite wire-shape arm (T-DS-6 ∧ T-DS-7): the two drain regimes
    /// an observer could try to tell apart — a **partial** drain (change > 0)
    /// and a **drain-all** (change == 0, principal payment split) — must be
    /// byte-identical modulo the hidden/committed leaves. Transfer-parity
    /// itself is by construction (both regimes and an ordinary `sign_tx`
    /// transfer share the single [`assemble_transfer_wire`] constructor), so
    /// this diff guards the one remaining degree of freedom: that
    /// split-on-drain-all reshaped the amounts WITHOUT perturbing the wire
    /// skeleton. A whole-tx normalized byte-diff, not a sub-surface check.
    #[tokio::test(flavor = "multi_thread")]
    async fn drain_partial_and_drain_all_are_wire_identical() {
        let fee = 10_000u64;

        let partial = {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, available) = drain_fixture();
            let reply = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: 600_000, // change = available - 600_000 - fee > 0
                    fee,
                })
                .await
                .expect("partial drain assembles");
            assert!(
                available - 600_000 - fee > 0,
                "fixture keeps change positive"
            );
            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let tx = Transaction::read(&mut cursor).expect("partial parses whole");
            assert!(cursor.is_empty());
            tx
        };

        let drain_all = {
            let handle = spawn_over(&[0], &[], None);
            let h = handle
                .mint_handle(PSlot::from_raw(0))
                .await
                .expect("slot 0 held");
            let (funding, tree_ctx, dest, available) = drain_fixture();
            let reply = handle
                .assemble_drain(AssembleDrain {
                    handle: h,
                    funding,
                    tree_ctx,
                    dest,
                    payment_amount: available - fee, // change == 0 ⇒ split
                    fee,
                })
                .await
                .expect("drain-all assembles");
            let mut cursor: &[u8] = reply.bound_tx.bytes();
            let tx = Transaction::read(&mut cursor).expect("drain-all parses whole");
            assert!(cursor.is_empty());
            tx
        };

        // Sanity: the raw bytes DIFFER (hidden values are genuinely distinct)
        // — otherwise the normalized equality below would be vacuous.
        assert_ne!(
            crate::engine::test_support::whole_tx_wire_bytes(&partial),
            crate::engine::test_support::whole_tx_wire_bytes(&drain_all),
            "raw drain bytes must differ (distinct hidden amounts)"
        );

        let mut partial_norm = partial;
        let mut drain_all_norm = drain_all;
        crate::engine::test_support::normalize_fcmp_wire_shape(&mut partial_norm);
        crate::engine::test_support::normalize_fcmp_wire_shape(&mut drain_all_norm);

        assert_eq!(
            crate::engine::test_support::whole_tx_wire_bytes(&partial_norm),
            crate::engine::test_support::whole_tx_wire_bytes(&drain_all_norm),
            "partial drain and drain-all are wire-identical modulo hidden \
                 leaves — the split-on-drain-all path did not perturb the skeleton"
        );
    }
}
