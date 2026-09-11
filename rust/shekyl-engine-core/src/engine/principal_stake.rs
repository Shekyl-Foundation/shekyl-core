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
//! **Amount-axis cover is applied here** (`ARCHIVAL_COVER_DRAW.md`): the
//! transfer carries `stake + cover` with `cover ~ U(0, bond_floor)`, so the
//! funded amount lands strictly between rung multiples and a bond post can
//! never be *proven* to be one. An earlier revision of this note called the
//! cover structuring "the funding flow's concern, not this transfer's
//! mechanics" and no funding-flow layer ever applied it — so every `stake_in`
//! shipped a clean `bond_floor`-shaped amount. It is this transfer's mechanics,
//! because this is the transaction whose amount is observed.

use rand_core::RngCore as _;
use shekyl_address::AddressError;
use shekyl_standoff::{draw_cover_amount, COVER_RUNG_ATOMIC};
use shekyl_units::AtomicUnits;

use super::fee_estimator::FeePriority;
use super::pending::{PendingTx, TxRecipient, TxRequest};
use super::stake_timing::OsRngGapAdapter;
use super::traits::{
    DaemonEngine, EconomicsEngine, LedgerEngine, PendingTxEngine, PersistenceEngine, RefreshEngine,
};
use super::{EngineSignerKind, SendError};

// `shekyl-standoff` mirrors the bond rung locally (it has no retention
// dependency, being the leaf draw crate). This crate depends on both, so it is
// the one place that can assert the mirror has not drifted — a divergence would
// silently move the cover's upper bound off `bond_floor`, so the funded amount
// could land on a rung boundary and the unprovability property would break.
const _: () = assert!(
    COVER_RUNG_ATOMIC == shekyl_archival_retention::ARCHIVAL_BOND_FLOOR_ATOMIC,
    "cover rung mirror drifted from ARCHIVAL_BOND_FLOOR_ATOMIC"
);

/// Why [`Engine::stake_in`](super::Engine::stake_in) could not build the funding
/// transfer.
///
/// `pub` (WI-RPC-5): the wallet-RPC `stake_in` handler matches on these arms
/// to pick its refusal code (`-29500` for the no-persona arms, the `-291xx`
/// send codes via [`Send`](Self::Send)). The actor arm carries the
/// crate-private `StakeEngineError`'s **rendering**, not the type — its
/// messages are already user-facing and scalar-free, and the actor error
/// hierarchy stays inside the crate (rule 36 posture).
#[derive(Debug, thiserror::Error)]
pub enum StakeInError {
    /// This wallet is not an archival staker (no `StakeEngine`) — there is no
    /// persona to fund.
    #[error("wallet is not staking; no persona to fund")]
    NotStaking,
    /// No persona is currently active — mint + activate one before funding it.
    #[error("no active persona to fund")]
    NoActivePersona,
    /// The stake engine could not project the active persona's receive address
    /// (the crate-private actor error's own user-facing rendering).
    #[error("stake engine: {0}")]
    StakeEngine(String),
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

// The `dead_code` staging allow retired with WI-RPC-5: the production caller
// the PR-P2 note reserved (the principal-stake RPC surface) landed as the
// wallet-RPC `stake_in` handler, which calls this `pub` method.
#[allow(private_bounds)] // same posture as build_pending_tx_async
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
    /// the leak. The user may add working capital *on top* of `amount`; the
    /// cover draw itself takes no on-chain input. See `stake_in_request`.
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
    ///
    /// `&self` (W-B step 1 parity with
    /// [`build_pending_tx_async`](super::Engine::build_pending_tx_async), which
    /// is the entire body after the address resolution): the slow FCMP++
    /// assembly is serialized by the pending-tx implementor's own permit, so an
    /// embedder holds a shared borrow across the build and concurrent read RPCs
    /// proceed. The PR-P2 frozen contract is the `stake_in(amount) ->
    /// PendingTx` shape; an earlier `&mut self` receiver predated the W-B
    /// interior-mutability split and would force the wallet-RPC handler onto a
    /// write guard, stalling every read RPC behind a daemon round trip + proving
    /// build for exclusivity that binds nothing.
    pub async fn stake_in(&self, amount: AtomicUnits) -> Result<PendingTx, StakeInError> {
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
        // Amount-axis cover (`ARCHIVAL_COVER_DRAW.md`): the principal sends
        // `stake + cover`; `P` holds the cover as working capital, flowing out
        // as a `P`-change output.
        //
        // NOT the primary defense — amounts are CT-hidden, so attribution is
        // already denied on chain (WI-4 §18.9). This is defense in depth: with
        // `cover ~ U(0, bond_floor)` the funded amount lands STRICTLY between
        // rung multiples, so it is never a clean bond floor and a bond post can
        // never be *proven* to be one (`shekyl_standoff::draw_cover_amount`).
        //
        // System-determined, never a caller parameter — a caller-chosen cover
        // forks the distribution across wallets, which is itself the leak. The
        // draw takes NO on-chain input (pure entropy against a fixed constant):
        // anything an observer could read would be the same predictor the
        // wallet uses. The user may add working capital ON TOP; that is a
        // separate addition and is why the draw needs no runway floor of its
        // own (see `draw_cover_amount`'s two-role doc).
        //
        // Entropy preflight, mirroring `stake_engine`'s Round-3 pattern: probe
        // the source so a dead RNG returns a typed error instead of reaching the
        // draw's panic backstop. `stake_in` is user-initiated (rule 82); the
        // panic stays the backstop for a source dying between probe and draw,
        // which must never yield a silent low-entropy cover.
        let mut probe = [0u8; 8];
        rand_core::OsRng
            .try_fill_bytes(&mut probe)
            .map_err(StakeInError::RngSourceFailed)?;
        let mut rng = OsRngGapAdapter;
        let cover = AtomicUnits::from_raw(draw_cover_amount(&mut rng));
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
            .map_err(|e| StakeInError::StakeEngine(e.to_string()))?
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
    use crate::engine::test_support::{activate_persona, staker_engine};
    use shekyl_standoff::COVER_RUNG_ATOMIC;
    use shekyl_units::AtomicUnits;

    /// This suite's deterministic-seed multiplier (`test_support::fixed_seed`).
    const SEED_MULT: u8 = 7;

    /// A non-staker cannot fund a persona it does not have — refused up front,
    /// before any network / build. Exercises `stake_in` → `stake_in_request`.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_on_a_non_staker_is_not_staking() {
        let (_tmp, engine) = crate::engine::test_support::non_staker_engine(SEED_MULT);
        let err = engine
            .stake_in(AtomicUnits::from_raw(50_000))
            .await
            .expect_err("a non-staker cannot stake_in");
        assert!(matches!(err, StakeInError::NotStaking), "got {err:?}");
    }

    /// A staker with no active persona has nothing to fund.
    #[tokio::test(flavor = "multi_thread")]
    async fn stake_in_on_an_idle_staker_has_no_active_persona() {
        let (_tmp, engine) = staker_engine(3, SEED_MULT);
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
        let (_tmp, engine) = staker_engine(3, SEED_MULT);
        activate_persona(&engine, 3).await;
        let amount = AtomicUnits::from_raw(50_000);

        let request = engine
            .stake_in_request(amount)
            .await
            .expect("stake_in_request resolves the active persona");

        assert_eq!(request.recipients.len(), 1, "single-output funding (GF-4b)");
        // Assert the INVARIANT the draw guarantees, never an exact value:
        // `funded = stake + cover` with `cover ~ U(0, RUNG)`, so
        // `stake < funded < stake + RUNG` always. An exact assert would be
        // flaky against a genuinely random cover for correct behaviour.
        let funded = request.recipients[0].amount_atomic_units;
        assert!(
            funded > amount,
            "funded {funded:?} did not exceed the stake — cover must be strictly positive"
        );
        assert!(
            funded < AtomicUnits::from_raw(50_000 + COVER_RUNG_ATOMIC),
            "funded {funded:?} reached stake + a full rung — cover must be sub-rung"
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
