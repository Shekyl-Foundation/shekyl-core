// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The one-glance balance every wallet surface renders (the contract's
//! `get_balance`; WI-RPC-5), computed once, here, from the two authoritative
//! reads it composes: the ledger's [`BalanceSummary`] and the sealed staking
//! view's [`StakedBalance`].
//!
//! Before this module the projection — which leg is "liquid", how the two
//! bonded legs sum, what an unreadable staking seal does to the staking
//! fields — lived in `shekyl-wallet-rpc` alone, and every other consumer of
//! the engine (the desktop wallet embeds it directly) either restated it or
//! shipped a different balance under the same name. A projection restated
//! is a projection that drifts; this is its single home, for the RPC to
//! serialize and for the GUI to consume.
//!
//! # Two arms, never a fabricated zero
//!
//! - **Degrade.** The sealed `.wallet.pscan` / `.wallet.pending` files could
//!   not be *read* ([`StakingReadError::File`] / [`StakingReadError::Codec`]):
//!   the liquid fields stay authoritative and [`BalanceView::staking`] is
//!   `None`. Absence is structurally distinct from `0` — a staker must never
//!   be shown "nothing staked" over a bad seal.
//! - **Loud.** A seal that *loaded* but whose money totals overflow the
//!   money type is corrupt state and answers a [`BalanceViewError`]:
//!   [`BalanceViewError::SealedTotals`] when the staking read's own sums
//!   overflow, [`BalanceViewError::BondedLegs`] when those two legs each fit
//!   and their sum does not. Checked, not saturating — a clamped `u64::MAX`
//!   would render as a plausible (absurd) balance — and an error, not a
//!   panic, because hosts build with `panic = "abort"`. The two arms keep
//!   the client messages that predate this module.
//!
//! # Lock choreography
//!
//! The ledger lock is not re-entrant. The staking read owns the one safe
//! order (`staking_read_with_ledger`: the caller's read under one guard,
//! the guard dropped, then the seals). This module only classifies that
//! result and projects it, so the session-adoption flag has one definition.

use shekyl_engine_state::WalletLedger;
use shekyl_scanner::{BalanceSummary, WalletLedgerExt as _};
use shekyl_units::AtomicUnits;

use super::local_ledger::LocalLedger;
use super::signer::EngineSignerKind;
use super::staking_read::{StakedBalance, StakingReadError, StakingReadView};
use super::traits::{DaemonEngine, EconomicsEngine, PendingTxEngine, RefreshEngine};
use super::Engine;

/// The staking half of the one-glance balance, projected from the sealed
/// staking view. Present only when that view could be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakedTotals {
    /// Bond principal under confirmed live bonds PLUS principal committed by
    /// in-flight sealed posts — the sum of the two bonded legs that
    /// [`StakedBalance`] keeps separate. This scalar exists for the
    /// one-glance surface; the legs stay distinct on the staking read.
    pub staked: AtomicUnits,
    /// Emission-reward money received and still unspent in staking-side
    /// outputs ([`StakedBalance::rewards_received_unspent`] verbatim). NOT a
    /// claim-era "accrued but unclaimed" entitlement — no such user-visible
    /// quantity exists in the archival design.
    pub claimable_rewards: AtomicUnits,
}

/// The contract's `get_balance`, as engine facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceView {
    /// Spendable now. Maps from `unlocked` until staking splits liquid from
    /// locked principal; carried as its own field so that split is a change
    /// here, not in every consumer.
    pub liquid: AtomicUnits,
    /// Unlocked and not frozen ([`BalanceSummary::unlocked`]).
    pub unlocked: AtomicUnits,
    /// Committed to a network-exposed spend awaiting confirmation
    /// ([`BalanceSummary::awaiting_confirmation`]): counted in the total,
    /// never spendable.
    pub pending: AtomicUnits,
    /// Received-but-unspendable outputs ([`BalanceSummary::unspendable`]):
    /// on chain, retained, never spendable by this wallet; counted nowhere
    /// else.
    pub unspendable: AtomicUnits,
    /// The staking totals, or `None` when the sealed staking state could
    /// not be read (the degrade arm). A non-staker's totals are present and
    /// genuinely zero.
    pub staking: Option<StakedTotals>,
}

/// A balance snapshot plus whatever the caller read under the same ledger
/// guard, so composite reads (the RPC's `get_wallet_info`) stay coherent
/// with the balance without a second guard.
#[derive(Debug)]
pub struct BalanceSnapshot<T> {
    pub view: BalanceView,
    /// The caller's read, taken under the same guard as the balance.
    pub extra: T,
    /// The full staking view the balance was projected from, when readable.
    pub staking: Option<StakingReadView>,
}

/// The loud arm: corrupt money totals. Every unreadable-seal case degrades
/// instead (see the module docs).
///
/// The two variants are the two client messages wallet RPC already served.
/// [`Self::BondedLegs`] is the glance sum; [`Self::SealedTotals`] is the
/// staking read's own aggregation. The [`Display`] text is that client
/// message, so the RPC mapping does not rephrase it.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum BalanceViewError {
    /// The two bonded legs each fit in the money type and their sum does not.
    /// The supply cap keeps any legitimate sum far below `u64::MAX`, so this
    /// is corrupt state, not a large wallet.
    #[error("bonded principal legs exceed the money type (corrupt staking view)")]
    BondedLegs,
    /// [`StakingReadError::Overflow`]: the sealed totals overflowed while the
    /// staking read aggregated them.
    #[error("staking totals overflowed the money type (corrupt staking state)")]
    SealedTotals,
}

/// Project the one-glance balance from its two inputs. Pure; the
/// arithmetic lives here so it is tested once and consumed everywhere.
///
/// `staking: None` is the degrade arm and projects [`BalanceView::staking`]
/// absent. A non-staker passes `Some(&StakedBalance::ZERO)` — a true zero.
///
/// # Errors
///
/// [`BalanceViewError::BondedLegs`] when the two bonded legs sum past `u64`.
pub(crate) fn project_balance(
    summary: &BalanceSummary,
    staking: Option<&StakedBalance>,
) -> Result<BalanceView, BalanceViewError> {
    let staking = staking
        .map(|s| {
            s.bonded_principal_confirmed
                .checked_add(s.bonded_principal_pending)
                .map(|staked| StakedTotals {
                    staked,
                    claimable_rewards: s.rewards_received_unspent,
                })
                .ok_or(BalanceViewError::BondedLegs)
        })
        .transpose()?;
    Ok(BalanceView {
        liquid: summary.unlocked,
        unlocked: summary.unlocked,
        pending: summary.awaiting_confirmation,
        unspendable: summary.unspendable,
        staking,
    })
}

/// Classify a staking read for the balance surface: unreadable degrades to
/// absence, corrupt totals are loud.
fn degrade_or_loud(
    result: Result<StakingReadView, StakingReadError>,
) -> Result<Option<StakingReadView>, BalanceViewError> {
    match result {
        Ok(view) => Ok(Some(view)),
        Err(e @ (StakingReadError::File(_) | StakingReadError::Codec(_))) => {
            tracing::warn!(error = %e, "staking read failed; balance degrades its staking fields");
            Ok(None)
        }
        Err(e @ StakingReadError::Overflow) => {
            tracing::warn!(error = %e, "staking read corrupt; balance fails loud");
            Err(BalanceViewError::SealedTotals)
        }
    }
}

// `F = WalletFile` / `L = LocalLedger`: the same specialization as the staking
// read this composes. Free function, not an inherent `Engine::` method: the
// product door is `StakeFacade::balance_view` / `balance_snapshot_with`
// (`ENGINE_COMPOSITION_DECOMPOSITION.md`, the 2026-09-02 inherent-API freeze).
#[allow(private_bounds)]
pub(super) fn balance_snapshot_with<S, D, E, R, P, T>(
    engine: &Engine<S, D, LocalLedger, E, R, P, shekyl_engine_file::WalletFile>,
    under_guard: impl FnOnce(&WalletLedger) -> T,
) -> Result<BalanceSnapshot<T>, BalanceViewError>
where
    S: EngineSignerKind,
    D: DaemonEngine,
    E: EconomicsEngine,
    R: RefreshEngine,
    P: PendingTxEngine,
{
    let ((summary, extra), read) =
        engine.staking_read_with_ledger(|wallet| (wallet.balance(), under_guard(wallet)));
    let staking = degrade_or_loud(read)?;
    let view = project_balance(&summary, staking.as_ref().map(|v| &v.balance)).inspect_err(
        |e| tracing::warn!(error = %e, "balance projection refused a corrupt staking total"),
    )?;
    Ok(BalanceSnapshot {
        view,
        extra,
        staking,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(unlocked: u64, pending: u64, unspendable: u64) -> BalanceSummary {
        BalanceSummary {
            total: AtomicUnits::from_raw(unlocked + pending + unspendable),
            unlocked: AtomicUnits::from_raw(unlocked),
            locked_by_timelock: AtomicUnits::ZERO,
            frozen: AtomicUnits::ZERO,
            unspendable: AtomicUnits::from_raw(unspendable),
            awaiting_confirmation: AtomicUnits::from_raw(pending),
        }
    }

    #[test]
    fn liquid_maps_from_unlocked_and_the_other_legs_are_verbatim() {
        let v = project_balance(&summary(40, 5, 7), Some(&StakedBalance::ZERO)).unwrap();
        assert_eq!(v.liquid, AtomicUnits::from_raw(40));
        assert_eq!(v.unlocked, AtomicUnits::from_raw(40));
        assert_eq!(v.pending, AtomicUnits::from_raw(5));
        assert_eq!(v.unspendable, AtomicUnits::from_raw(7));
        // A non-staker's zeros are true zeros, present, not the degrade arm.
        assert_eq!(
            v.staking,
            Some(StakedTotals {
                staked: AtomicUnits::ZERO,
                claimable_rewards: AtomicUnits::ZERO
            })
        );
    }

    #[test]
    fn staked_sums_the_two_bonded_legs_and_rewards_pass_through() {
        let staking = StakedBalance {
            bonded_principal_confirmed: AtomicUnits::from_raw(70_000),
            bonded_principal_pending: AtomicUnits::from_raw(30_000),
            rewards_received_unspent: AtomicUnits::from_raw(1_234),
        };
        let v = project_balance(&summary(40, 0, 0), Some(&staking)).unwrap();
        let totals = v.staking.unwrap();
        assert_eq!(totals.staked, AtomicUnits::from_raw(100_000));
        assert_eq!(totals.claimable_rewards, AtomicUnits::from_raw(1_234));
        assert_eq!(
            v.unlocked,
            AtomicUnits::from_raw(40),
            "principal legs untouched"
        );
    }

    #[test]
    fn an_unreadable_staking_seal_is_absence_not_zero() {
        let v = project_balance(&summary(40, 0, 0), None).unwrap();
        assert_eq!(v.staking, None);
        assert_eq!(
            v.liquid,
            AtomicUnits::from_raw(40),
            "liquid stays authoritative"
        );
    }

    #[test]
    fn bonded_legs_past_the_money_type_are_loud_not_saturated() {
        let staking = StakedBalance {
            bonded_principal_confirmed: AtomicUnits::from_raw(u64::MAX),
            bonded_principal_pending: AtomicUnits::from_raw(1),
            rewards_received_unspent: AtomicUnits::ZERO,
        };
        assert_eq!(
            project_balance(&summary(0, 0, 0), Some(&staking)).unwrap_err(),
            BalanceViewError::BondedLegs
        );
    }

    #[test]
    fn unreadable_seal_degrades_and_overflow_is_loud() {
        let view = StakingReadView {
            staking_enabled: false,
            balance: StakedBalance::ZERO,
            outputs: vec![],
            pscan_synced_height: None,
            recovery_pending_reopen: false,
        };
        assert!(degrade_or_loud(Ok(view)).unwrap().is_some());
        let unreadable = StakingReadError::File(shekyl_engine_file::WalletFileError::Io(
            std::io::Error::other("disk gone"),
        ));
        assert!(degrade_or_loud(Err(unreadable)).unwrap().is_none());
        let undecodable = StakingReadError::Codec(
            shekyl_engine_state::WalletLedgerError::UnsupportedFormatVersion { file: 1, binary: 2 },
        );
        assert!(degrade_or_loud(Err(undecodable)).unwrap().is_none());
        let sealed = degrade_or_loud(Err(StakingReadError::Overflow)).unwrap_err();
        assert_eq!(sealed, BalanceViewError::SealedTotals);
        assert_eq!(
            sealed.to_string(),
            "staking totals overflowed the money type (corrupt staking state)"
        );
        assert_eq!(
            BalanceViewError::BondedLegs.to_string(),
            "bonded principal legs exceed the money type (corrupt staking view)"
        );
    }
}
