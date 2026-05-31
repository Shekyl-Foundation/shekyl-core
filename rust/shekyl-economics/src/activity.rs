//! Chain-derived activity observables for the adaptive fee burn.
//!
//! [`ActivityMetric`] carries the **raw integer observables** the burn
//! formula consumes (transaction volume, circulating supply, total
//! staked) plus the height they were sampled at. Per
//! `docs/design/STAGE_1_PR_7_ECONOMICS_ENGINE.md` §5.3 R1, ratios
//! (`stake_ratio`, `supply_ratio`, `volume_ratio`) are **not** carried
//! here — they are formed inside [`crate::burn::calc_burn_pct`] from a
//! single ratio helper ([`crate::params::calc_stake_ratio`]) so the
//! `EconomicsEngine::burn_amount` path and the consensus FFI path
//! cannot diverge (Bug-2 class).
//!
//! # Coherence is a constructor-caller obligation
//!
//! [`ActivityMetric::new`] validates **internal-consistency**
//! invariants only (a field set that is impossible for any single
//! chain state). It cannot validate that the four fields were sampled
//! from **one** chain view at `as_of_height` — that **coherence**
//! contract (§6.3 G4) is the producer's responsibility: assemble the
//! bundle from one LMDB read transaction or one atomic daemon endpoint,
//! never from three sequential RPCs. A coherent-but-stale bundle is
//! accepted; the consumer applies its own staleness policy against
//! `as_of_height` (the failure mode at V3.0 is wrong advisory display,
//! not a failed send or theft — consensus recomputes burn at accept).

use serde::Serialize;

use crate::params::MONEY_SUPPLY;

/// Structural-invariant failure from [`ActivityMetric::new`].
///
/// These are field combinations impossible for **any** single chain
/// state. They are distinct from coherence violations (four fields from
/// different chain views), which `new` cannot detect — see the module
/// docs. The discriminator is surfaced to the orchestrator error layer
/// (`EconomicsError::ActivityInvariantViolation`) so a caller can tell
/// which invariant a producer broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActivityInvariantViolation {
    /// `circulating_supply` exceeds the hard coin-supply ceiling
    /// ([`MONEY_SUPPLY`]) — no chain state can have emitted more than
    /// the total supply.
    #[error("circulating_supply {circulating_supply} exceeds MONEY_SUPPLY {money_supply}")]
    CirculatingExceedsSupply {
        /// The offending `circulating_supply`.
        circulating_supply: u64,
        /// The configured supply ceiling.
        money_supply: u64,
    },

    /// `total_staked` exceeds `circulating_supply` — more coin cannot be
    /// staked than exists in circulation.
    #[error("total_staked {total_staked} exceeds circulating_supply {circulating_supply}")]
    StakedExceedsCirculating {
        /// The offending `total_staked`.
        total_staked: u128,
        /// The circulating supply it was compared against.
        circulating_supply: u64,
    },

    /// `as_of_height == 0` (genesis) with non-zero supply or stake. At
    /// genesis no block has emitted coin and no stake can have accrued;
    /// a non-zero observable at height 0 is structurally impossible.
    #[error(
        "genesis (as_of_height=0) must have zero supply/stake: circulating_supply={circulating_supply}, total_staked={total_staked}"
    )]
    GenesisStateNonZero {
        /// The circulating supply reported at genesis.
        circulating_supply: u64,
        /// The total staked reported at genesis.
        total_staked: u128,
    },
}

/// Raw chain-derived observables for the adaptive fee burn at a height.
///
/// Construct via [`ActivityMetric::new`]; there is **no** field-literal
/// or `#[cfg(test)]` backdoor constructor (§6.3 G4). Tests use the same
/// `new` over `RecordedChainFixture` rows — "real path, real fixture."
///
/// `Serialize` is derived (debug-log / fixture-emit parity with
/// production); `Deserialize` is deliberately **not** derived so that
/// every in-memory `ActivityMetric` has passed `new`'s invariant check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActivityMetric {
    /// Rolling `SHEKYL_TX_VOLUME_WINDOW` (720-block) mean transaction
    /// count, daemon-reported (`get_tx_volume_avg(as_of_height)`).
    pub tx_volume: u64,
    /// Prev-block `already_generated` at `as_of_height` — the
    /// consensus burn-site quantity (`validate_miner_transaction`),
    /// **not** `already_generated − total_burned`.
    pub circulating_supply: u64,
    /// Principal-pool total staked amount from the chain mirror
    /// (`u128` per Bug 7), **not** a wallet-local registry.
    pub total_staked: u128,
    /// Height all four fields were sampled for (`0` = genesis). The
    /// coherence anchor: consumers compare against the chain tip to
    /// decide whether the estimate is stale.
    pub as_of_height: u64,
}

impl ActivityMetric {
    /// Construct after validating the structural invariants in
    /// [`ActivityInvariantViolation`].
    ///
    /// Coherence (all four fields from one chain view at `as_of_height`)
    /// is **not** checked here — it is the producer's obligation (module
    /// docs / §6.3 G4). A coherent-but-stale bundle is a valid
    /// `ActivityMetric`.
    pub fn new(
        tx_volume: u64,
        circulating_supply: u64,
        total_staked: u128,
        as_of_height: u64,
    ) -> Result<Self, ActivityInvariantViolation> {
        if circulating_supply > MONEY_SUPPLY {
            return Err(ActivityInvariantViolation::CirculatingExceedsSupply {
                circulating_supply,
                money_supply: MONEY_SUPPLY,
            });
        }
        if total_staked > u128::from(circulating_supply) {
            return Err(ActivityInvariantViolation::StakedExceedsCirculating {
                total_staked,
                circulating_supply,
            });
        }
        if as_of_height == 0 && (circulating_supply != 0 || total_staked != 0) {
            return Err(ActivityInvariantViolation::GenesisStateNonZero {
                circulating_supply,
                total_staked,
            });
        }
        Ok(Self {
            tx_volume,
            circulating_supply,
            total_staked,
            as_of_height,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_steady_state() {
        let m = ActivityMetric::new(48, 987_654_321, 12_345_678, 1234).unwrap();
        assert_eq!(m.tx_volume, 48);
        assert_eq!(m.as_of_height, 1234);
    }

    #[test]
    fn new_accepts_genesis_zero_state() {
        let m = ActivityMetric::new(0, 0, 0, 0).unwrap();
        assert_eq!(m.circulating_supply, 0);
    }

    #[test]
    fn new_rejects_circulating_over_supply() {
        let err = ActivityMetric::new(0, MONEY_SUPPLY + 1, 0, 10).unwrap_err();
        assert!(matches!(
            err,
            ActivityInvariantViolation::CirculatingExceedsSupply { .. }
        ));
    }

    #[test]
    fn new_rejects_staked_over_circulating() {
        let err = ActivityMetric::new(0, 1_000, 1_001, 10).unwrap_err();
        assert!(matches!(
            err,
            ActivityInvariantViolation::StakedExceedsCirculating { .. }
        ));
    }

    #[test]
    fn new_rejects_nonzero_genesis() {
        let err = ActivityMetric::new(0, 1, 0, 0).unwrap_err();
        assert!(matches!(
            err,
            ActivityInvariantViolation::GenesisStateNonZero { .. }
        ));
    }
}
