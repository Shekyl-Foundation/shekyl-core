// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The principal → active-`P` funding leg (`stake_in`), `PRINCIPAL_STAKE_LIFECYCLE.md`
//! §2 / PR-P2 — the first unblocked cut of the principal orchestrator surface.
//!
//! `stake_in` is an **ordinary FCMP++ transfer** principal → `P`'s public
//! receive address, byte-indistinguishable from any other transfer (DQ1, the
//! frozen Q11 genesis wire: no `C_stake`, band, range proof, or minimum). It
//! **composes** the built [`build_pending_tx_async`](super::Engine::build_pending_tx_async)
//! path and touches **no `P` secret** — `P` is only a public recipient, its
//! receive address projected public-only out of `StakeEngine` (rule 36).
//!
//! The leg's worth is the **GF-2 boundary** it proves: an output addressed the
//! way `stake_in` addresses `P` is recovered by `P`'s own dual-scan (the
//! `#[cfg(test)]` end-test below). The cover-amount structuring
//! (`bond_floor + cover`, drawn via `shekyl-standoff`) is the funding flow's
//! concern, not this transfer's mechanics (§5.2).

use shekyl_address::AddressError;
use shekyl_units::AtomicUnits;

use super::fee_estimator::FeePriority;
use super::pending::{PendingTx, TxRecipient, TxRequest};
use super::stake_engine::StakeEngineError;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::{EngineSignerKind, SendError};

/// Why [`Engine::stake_in`](super::Engine::stake_in) could not build the funding
/// transfer.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // inert until the principal-stake RPC surface consumes it (PR-P3+)
pub(crate) enum StakeInError {
    /// This wallet is not an archival staker (no `StakeEngine`) — there is no
    /// persona to fund.
    #[error("wallet is not staking; no persona to fund")]
    NotStaking,
    /// No persona is currently active — mint + activate one before funding it.
    #[error("no active persona to fund")]
    NoActivePersona,
    /// The stake engine could not project the active persona's receive address.
    #[error("stake engine: {0}")]
    StakeEngine(#[source] StakeEngineError),
    /// Encoding `P`'s receive address failed.
    #[error("encoding P's receive address: {0}")]
    Address(#[source] AddressError),
    /// The underlying transfer build failed (funding, fee, reservation, …).
    #[error(transparent)]
    Send(#[from] SendError),
}

// `dead_code`: `stake_in` is the built PR-P2 method; its production caller is the
// principal-stake RPC surface (PR-P3+). The end-test is the current exerciser.
#[allow(dead_code, private_bounds)] // private_bounds: same posture as build_pending_tx_async
impl<S, D, L, E, R, P, F> super::Engine<S, D, L, E, R, P, F>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    L: LedgerEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
    F: PersistenceEngine,
{
    /// Fund the wallet's currently-active archival persona `P` (PR-P2).
    ///
    /// An **ordinary FCMP++ transfer** principal → `P`'s public receive address
    /// (DQ1). Exactly one recipient, so the transfer yields **one** `P`-output
    /// (plus the principal's own change) — the later bond-post sweep then
    /// consumes a single input, keeping the P-public bond post's input-count
    /// from signalling funding-tranche count (GF-4b). `P` is a public recipient;
    /// no `P` secret is touched (rule 36 — the address is projected public-only
    /// from `StakeEngine`).
    ///
    /// The `amount` is transferred **verbatim** — no floor / minimum / band
    /// check (DQ1; `ARCHIVAL_BOND_FLOOR_ATOMIC` is a *bond-post* precondition, not
    /// a `stake_in` gate). Its `bond_floor + cover` structuring (and the
    /// `shekyl-standoff` cover draw) belongs to the funding flow, not this leg
    /// (`PRINCIPAL_STAKE_LIFECYCLE.md` §5.2).
    ///
    /// **Carried-over open concern (GF-7, not resolved here):** `build_pending_tx`
    /// appends the principal's own change output (subaddress 0), co-present with
    /// the `P`-output in this tx. Whether that co-presence is a principal↔`P`
    /// linkage vector is an open GF-7 question on a *distinct* firewall surface
    /// from this leg's GF-2 boundary (rule 19) — tracked, to be resolved with the
    /// bond-funding-separation (GF-7) work, not in this PR.
    ///
    /// # Errors
    ///
    /// [`StakeInError`]: not staking, no active persona, address encode, or the
    /// underlying transfer build ([`SendError`] — insufficient funds, etc.).
    pub(crate) async fn stake_in(
        &mut self,
        amount: AtomicUnits,
    ) -> Result<PendingTx, StakeInError> {
        let request = self.stake_in_request(amount).await?;
        self.build_pending_tx_async(&request)
            .await
            .map_err(StakeInError::Send)
    }

    /// Resolve the active persona into the single-recipient [`TxRequest`]
    /// [`stake_in`](Self::stake_in) builds — the leg's **novel** logic (the
    /// recipient is `P`'s address; everything downstream is the shared transfer
    /// path). Split out so the GF-2 boundary test can exercise the address
    /// resolution without an on-chain build (which is daemon-gated).
    async fn stake_in_request(&self, amount: AtomicUnits) -> Result<TxRequest, StakeInError> {
        let stake = self.stake_handle().ok_or(StakeInError::NotStaking)?;
        // The actor projects P's address (public-only `ShekylAddress`, built
        // in-actor from the live bundle — never re-derived, no P secret crosses;
        // rule 36). The principal's own network is the address's network.
        let address = stake
            .active_persona_receive_address(self.network)
            .await
            .map_err(StakeInError::StakeEngine)?
            .ok_or(StakeInError::NoActivePersona)?
            .encode()
            .map_err(StakeInError::Address)?;
        Ok(TxRequest {
            recipients: vec![TxRecipient {
                address,
                amount_atomic_units: amount,
            }],
            // Funding a persona is a routine wallet-local transfer; standard fee.
            priority: FeePriority::Standard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StakeInError;
    use crate::engine::{
        Credentials, DaemonClient, Engine, EngineCreateParams, OpenedEngine, SoloSigner,
    };
    use shekyl_crypto_pq::account::MASTER_SEED_BYTES;
    use shekyl_engine_file::SafetyOverrides;
    use shekyl_rpc_transport::SimpleRequestRpc;
    use shekyl_types::PSlot;
    use shekyl_units::AtomicUnits;
    use tempfile::TempDir;

    /// A `DaemonClient` that never connects: `stake_in`'s tested paths (address
    /// resolution + the `NotStaking` refusal) touch no network. (Same shape as
    /// the lifecycle/pscan suites' helper; replicated because those are
    /// test-private.)
    fn dummy_daemon() -> DaemonClient {
        let rpc = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(SimpleRequestRpc::new("http://127.0.0.1:1".to_string()))
        })
        .expect("construct SimpleRequestRpc (no actual connection attempted)");
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

    /// A fresh **non-staker** full engine (no bond record → `stake_handle()` is
    /// `None`).
    fn non_staker_engine() -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let engine =
            Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create non-staker");
        (tmp, engine)
    }

    /// A **staker** engine (persists a bond record for `slot` → `staking_enabled`,
    /// then reopens so the StakeEngine spawns). Idle — the caller activates a
    /// persona if it needs one.
    fn staker_engine(slot: u32) -> (TempDir, Engine<SoloSigner>) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let base = tmp.path().join("wallet");
        let (creds, seed) = (creds(), fixed_seed());
        let params = EngineCreateParams::for_test_full(&base, &creds, &seed);
        let network = params.network;
        let engine = Engine::<SoloSigner>::create(params, dummy_daemon()).expect("create");
        engine
            .persist_bond_record(PSlot::from_raw(slot))
            .expect("persist bond record → staking_enabled");
        engine.close(&creds).expect("close created wallet");
        let opened = Engine::<SoloSigner>::open_full(
            &base,
            &creds,
            network,
            dummy_daemon(),
            SafetyOverrides::none(),
        )
        .expect("reopen staker wallet");
        let engine = match opened {
            OpenedEngine::Loaded(w) => w,
            OpenedEngine::Restored { wallet, .. } => wallet,
        };
        assert!(
            engine.stake_handle().is_some(),
            "a staker reopen spawns the StakeEngine"
        );
        (tmp, engine)
    }

    /// Mint + activate persona `slot` on a staker engine.
    async fn activate(engine: &Engine<SoloSigner>, slot: u32) {
        let stake = engine.stake_handle().expect("staker has a StakeEngine");
        let handle = stake
            .mint_handle(PSlot::from_raw(slot))
            .await
            .expect("mint persona handle");
        stake
            .activate_persona(handle)
            .await
            .expect("activate persona");
    }

    /// A non-staker cannot fund a persona it does not have — refused up front,
    /// before any network / build. Exercises `stake_in` → `stake_in_request`.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_on_a_non_staker_is_not_staking() {
        let (_tmp, mut engine) = non_staker_engine();
        let err = engine
            .stake_in(AtomicUnits::from_raw(50_000))
            .await
            .expect_err("a non-staker cannot stake_in");
        assert!(matches!(err, StakeInError::NotStaking), "got {err:?}");
    }

    /// A staker with no active persona has nothing to fund.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_on_an_idle_staker_has_no_active_persona() {
        let (_tmp, engine) = staker_engine(3);
        let err = engine
            .stake_in_request(AtomicUnits::from_raw(50_000))
            .await
            .expect_err("an idle staker has no active persona");
        assert!(matches!(err, StakeInError::NoActivePersona), "got {err:?}");
    }

    /// Happy path: with a persona active, `stake_in` builds a **single-recipient**
    /// request (GF-4b single-output funding) to exactly the address the actor
    /// projects for that persona — the recipient side of the leg, funding aside.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_request_is_a_single_output_to_the_active_persona() {
        let (_tmp, engine) = staker_engine(3);
        activate(&engine, 3).await;
        let amount = AtomicUnits::from_raw(50_000);

        let request = engine
            .stake_in_request(amount)
            .await
            .expect("stake_in_request resolves the active persona");

        assert_eq!(request.recipients.len(), 1, "single-output funding (GF-4b)");
        assert_eq!(
            request.recipients[0].amount_atomic_units, amount,
            "amount verbatim"
        );

        let projected = engine
            .stake_handle()
            .expect("staker")
            .active_persona_receive_address(engine.network())
            .await
            .expect("accessor")
            .expect("active persona")
            .encode()
            .expect("encode");
        assert_eq!(
            request.recipients[0].address, projected,
            "the recipient is the active persona's projected address"
        );
    }
}
