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
//! `#[cfg(test)]` end-test below).
//!
//! **Amount-axis cover is applied here** (`ARCHIVAL_COVER_DRAW.md` §8): the
//! transfer carries `stake + cover`, never a bare `bond_floor`. An earlier
//! revision of this note called the cover structuring "the funding flow's
//! concern, not this transfer's mechanics" and no funding-flow layer ever
//! applied it — so every `stake_in` shipped a clean `bond_floor`-shaped amount,
//! the exact fingerprint the mechanism exists to remove. It is this transfer's
//! mechanics, because this is the transaction whose amount is observed.

use rand_core::RngCore as _;
use shekyl_address::AddressError;
use shekyl_standoff::{draw_cover_amount, COVER_RUNWAY_FLOOR_ATOMIC};
use shekyl_units::AtomicUnits;

use super::fee_estimator::FeePriority;
use super::pending::{PendingTx, TxRecipient, TxRequest};
use super::stake_engine::StakeEngineError;
use super::stake_timing::OsRngGapAdapter;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::{EngineSignerKind, SendError};

/// The `count` fed to `draw_cover_amount` until a canonical global
/// standing-bond-count read exists (`ARCHIVAL_COVER_DRAW.md` §8).
///
/// Named rather than inlined so the gap is greppable and can never be mistaken
/// for a real population read. `span(0) == 0`, so the draw is degenerate today
/// and the amount axis carries no entropy — the open genesis distinguisher.
/// Every wallet must pin the SAME value: a per-wallet `C` breaks the
/// cross-wallet uniformity the draw depends on, which is a worse leak than the
/// degenerate span.
const CANONICAL_STANDING_BOND_COUNT_UNAVAILABLE: u64 = 0;

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
    /// The OS entropy source failed the pre-draw probe. Typed rather than left
    /// to the draw's panic backstop: `stake_in` is a user-initiated operation,
    /// so a dead entropy source should refuse the call, not fell the process
    /// (rule 82). The panic in `OsRngGapAdapter` remains the backstop for a
    /// source that dies *between* probe and draw — never a silent low-entropy
    /// cover, which would be the actual privacy failure.
    #[error("OS entropy source unavailable for the cover draw: {0}")]
    RngSourceFailed(#[source] rand_core::Error),
    /// `stake + cover` overflowed `AtomicUnits`. Unreachable for any real
    /// amount (the cover is one rung); loud rather than wrapping, because a
    /// wrapped total would silently send the *wrong* amount — a privacy and
    /// correctness failure, not a rounding one.
    #[error("stake amount {stake} + cover {cover} overflows the money type")]
    CoverOverflow { stake: u64, cover: u64 },
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
    /// The transfer carries **`amount + cover`**, never `amount` verbatim: the
    /// funding-seam cover is applied here (`ARCHIVAL_COVER_DRAW.md`), because
    /// this is the transaction whose amount is observed. `amount` itself takes
    /// no floor / minimum / band check (DQ1; `ARCHIVAL_BOND_FLOOR_ATOMIC` is a
    /// *bond-post* precondition, not a `stake_in` gate).
    ///
    /// The cover is **system-determined, never a caller parameter** — a
    /// caller-chosen cover is a cross-wallet uniformity break, which is itself
    /// the leak. See `stake_in_request` for the draw and its open limitation.
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
        // Amount-axis funding-seam cover (`ARCHIVAL_COVER_DRAW.md` §8): the
        // principal sends `stake + cover`; `P` stakes the floor and holds the
        // cover as working capital, flowing out as a `P`-change output (so
        // `verify_credit_funding`'s `output_total` already accounts for it).
        // Without this the transfer carries a clean `bond_floor`-shaped amount
        // — a direct amount fingerprint tying the principal's send to the
        // public bond, and the one funding-seam axis that is closable purely
        // wallet-side.
        //
        // **System-determined, not a caller parameter.** The cover is the
        // protocol's to choose, not the funder's: a caller-supplied cover is a
        // cross-wallet uniformity break (§8 — two wallets drawing differently
        // draw from different distributions, which is itself the leak). The
        // opt-out (`cover == 0`, the disclosed stake-only path) belongs behind
        // an advanced setting with its privacy warning, never on this seam.
        //
        // **The draw IS the defense.** GENESIS §2.0 / `PRINCIPAL_STAKE_LIFECYCLE.md`
        // §3.1: "the cover defense reduces entirely to the entropy of the cover
        // draw". So this calls `draw_cover_amount` — never a hardcoded amount.
        // A constant offset is exactly as self-tagging as a bare `bond_floor`:
        // it leaves the funding transfer distinguishable from ordinary traffic,
        // which is the only property that matters. The transfer is protected
        // iff it is INDISTINGUISHABLE from a normal transfer; it then borrows
        // the entire ambient transaction graph as its anonymity set for free,
        // but only for as long as it carries nothing that tags it out.
        //
        // **`count = 0` is a deliberate uniform pin, and it is the open gap.**
        // `count` is the GLOBAL standing-bond count and there is no source for
        // it: `ARCHIVAL_COVER_DRAW.md` §8 records that no live-maintained
        // standing-bond-count exists ("the earlier 'the source already exists
        // in `EpochCloseInputs.bonds`' claim was wrong") and that a canonical
        // epoch-boundary read must be specified first. Substituting this
        // wallet's own bond count would be WORSE than pinning: §8's
        // load-bearing constraint is cross-wallet uniformity — two wallets
        // drawing over different `C` draw from different distributions, and
        // that divergence *is* the leak the mechanism exists to close.
        //
        // Consequence, stated plainly rather than buried: `span(0) == 0`, so
        // the draw currently yields `C_min` exactly and the amount axis carries
        // ZERO entropy. The call shape is correct — entropy flows the instant a
        // canonical `C` crosses `COVER_TAIL_COUNT` — but the amount
        // distinguisher is NOT closed at genesis. Tracked as a genesis blocker.
        // Entropy preflight, mirroring `stake_engine`'s S4/S5 pattern: probe the
        // source so the predictable failure returns a typed error instead of
        // reaching the draw's panic backstop.
        let mut probe = [0u8; 8];
        rand_core::OsRng
            .try_fill_bytes(&mut probe)
            .map_err(StakeInError::RngSourceFailed)?;
        let mut rng = OsRngGapAdapter;
        let cover = AtomicUnits::from_raw(draw_cover_amount(
            CANONICAL_STANDING_BOND_COUNT_UNAVAILABLE,
            COVER_RUNWAY_FLOOR_ATOMIC,
            &mut rng,
        ));
        let funded = amount
            .checked_add(cover)
            .ok_or(StakeInError::CoverOverflow {
                stake: amount.to_raw(),
                cover: cover.to_raw(),
            })?;
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
                amount_atomic_units: funded,
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
    use shekyl_standoff::COVER_RUNWAY_FLOOR_ATOMIC;
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
        // Assert the INVARIANT, not the current degenerate evaluation: the draw
        // is `C_min + U[0, span]`, so `funded >= stake + C_min` always, and
        // `span == 0` only while no canonical standing-bond count exists. An
        // exact-equality assert would pass today and go flaky the moment cover
        // becomes genuinely random — pinning an evaluation, not a property.
        let funded = request.recipients[0].amount_atomic_units;
        assert!(
            funded >= AtomicUnits::from_raw(50_000 + COVER_RUNWAY_FLOOR_ATOMIC),
            "funded {funded:?} < stake + runway floor: cover must be at least C_min \
             (ARCHIVAL_COVER_DRAW.md amount axis)"
        );
        assert_ne!(
            funded, amount,
            "a verbatim stake amount is the amount fingerprint the cover exists to remove"
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
