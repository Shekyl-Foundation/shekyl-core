//! The transaction-volume operand, carried as the exact ratio it is.
//!
//! Every demand-responsive term in the economics — the release multiplier
//! `M_r`, the burn rate `b`, and through them the fee correction `C` —
//! reads one chain observable: the mean transaction count per block over
//! the trailing `TX_VOLUME_WINDOW` (720) blocks, divided by the configured
//! baseline. Until FL-R24 the daemon evaluated that mean as an integer
//! (`tx_count_sum / blocks`, truncating) and passed the truncated `u64`
//! across the FFI. The truncation was a **quantizer on a consensus
//! operand**: one tick of it moves `M_r` by `1/V` and the reward and fee
//! floor with it, and the round-19 instrument showed the integer arm holds
//! FL-C7's loop in a persistent limit cycle (worst 312 bp) where the exact
//! arm converges everywhere (`FEE_LADDER_DERIVATION.md` §11.7, FL-E1).
//!
//! [`TxVolume`] is the fix at the type: the window crosses every boundary
//! as `(tx_count_sum, blocks)`, and the division happens once, inside the
//! ratio the consumer actually needs, with the baseline already in the
//! denominator — `sum · SCALE / (baseline · blocks)`. Nothing is rounded
//! before that division. `calc_release_multiplier` and `calc_burn_pct` are
//! scale-invariant in `(volume, baseline)`, so the *shape* of every result
//! is unchanged; what changes is that the operand no longer snaps to whole
//! transactions per block.
//!
//! One type, two constructors. [`TxVolume::window`] is the chain form and
//! the only one the daemon uses. [`TxVolume::per_block`] expresses a
//! whole-number mean (`blocks = 1`) for instruments and KATs whose
//! scenarios are written as "V transactions per block"; it is exact for
//! what it says and is not a compatibility path — an integer mean over one
//! block and the same integer mean over 720 blocks are the same ratio.

use serde::Serialize;

use crate::params::SCALE;

/// The trailing-window transaction volume as an exact ratio,
/// `tx_count_sum : blocks`.
///
/// `blocks` is the number of blocks the window actually covers — `720`
/// once the chain is that deep, `height` before it, `0` at genesis. A
/// window over zero blocks has no mean; every ratio on it is `0`, which is
/// the value the daemon returned for genesis before this type existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TxVolume {
    tx_count_sum: u64,
    blocks: u64,
}

impl TxVolume {
    /// The genesis operand: no blocks behind the tip, no transactions.
    pub const ZERO: Self = Self {
        tx_count_sum: 0,
        blocks: 0,
    };

    /// The chain form: `tx_count_sum` transactions counted over `blocks`
    /// blocks. This is what `Blockchain::get_tx_volume_window` marshals.
    #[must_use]
    pub const fn window(tx_count_sum: u64, blocks: u64) -> Self {
        Self {
            tx_count_sum,
            blocks,
        }
    }

    /// A whole-number mean of `mean` transactions per block: the same
    /// ratio as `window(mean · n, n)` for any `n ≥ 1`.
    #[must_use]
    pub const fn per_block(mean: u64) -> Self {
        Self::window(mean, 1)
    }

    /// Transactions counted over the window.
    #[must_use]
    pub const fn tx_count_sum(self) -> u64 {
        self.tx_count_sum
    }

    /// Blocks the window covers.
    #[must_use]
    pub const fn blocks(self) -> u64 {
        self.blocks
    }

    /// `volume / baseline` in `SCALE` fixed point, computed as
    /// `tx_count_sum · SCALE / (baseline · blocks)` — one division, after
    /// every multiplication, so nothing is truncated before the ratio.
    ///
    /// Saturating at `u64::MAX`, not wrapping: this is reached through
    /// `extern "C"` where the operands are bare `u64`s, and a wrapped ratio
    /// past the rail would read as a *small* one, which `clamp` then
    /// honours as `release_min` — the opposite end of the range from the
    /// truth. `0` when the baseline is unconfigured or the window is empty.
    #[must_use]
    pub fn ratio_scaled(self, baseline: u64) -> u64 {
        if baseline == 0 || self.blocks == 0 {
            return 0;
        }
        u64::try_from(
            u128::from(self.tx_count_sum) * u128::from(SCALE)
                / (u128::from(baseline) * u128::from(self.blocks)),
        )
        .unwrap_or(u64::MAX)
    }

    /// `volume / baseline` in `SCALE²` fixed point — the operand of the
    /// burn rate's integer square root, whose result is then in `SCALE`
    /// units. Same single division, same saturation, same zero cases as
    /// [`ratio_scaled`](Self::ratio_scaled).
    #[must_use]
    pub fn ratio_scaled_squared(self, baseline: u64) -> u64 {
        if baseline == 0 || self.blocks == 0 {
            return 0;
        }
        u64::try_from(
            u128::from(self.tx_count_sum) * u128::from(SCALE) * u128::from(SCALE)
                / (u128::from(baseline) * u128::from(self.blocks)),
        )
        .unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::TX_VOLUME_WINDOW;

    #[test]
    fn per_block_and_window_are_the_same_ratio() {
        for mean in [0u64, 1, 39, 40, 50, 500] {
            let a = TxVolume::per_block(mean);
            let b = TxVolume::window(mean * TX_VOLUME_WINDOW, TX_VOLUME_WINDOW);
            assert_eq!(a.ratio_scaled(40), b.ratio_scaled(40), "mean {mean}");
            assert_eq!(
                a.ratio_scaled_squared(40),
                b.ratio_scaled_squared(40),
                "mean {mean}"
            );
        }
    }

    /// FL-R24's whole point, at the type: a fractional mean is a different
    /// operand from its floor. `39.5` tx/block against a baseline of `40`
    /// is `0.9875`, and the truncated form would have read it as `39/40`.
    #[test]
    fn fractional_mean_is_not_its_floor() {
        let half = TxVolume::window(
            39 * TX_VOLUME_WINDOW + TX_VOLUME_WINDOW / 2,
            TX_VOLUME_WINDOW,
        );
        assert_eq!(half.ratio_scaled(40), 987_500);
        assert_eq!(TxVolume::per_block(39).ratio_scaled(40), 975_000);
        assert_eq!(TxVolume::per_block(40).ratio_scaled(40), SCALE);
    }

    #[test]
    fn empty_window_and_zero_baseline_are_zero() {
        assert_eq!(TxVolume::ZERO.ratio_scaled(40), 0);
        assert_eq!(TxVolume::ZERO.ratio_scaled_squared(40), 0);
        assert_eq!(TxVolume::window(7, 0).ratio_scaled(40), 0);
        assert_eq!(TxVolume::per_block(100).ratio_scaled(0), 0);
        assert_eq!(TxVolume::per_block(100).ratio_scaled_squared(0), 0);
    }

    #[test]
    fn ratio_saturates_rather_than_wrapping() {
        let v = TxVolume::window(u64::MAX, 1);
        assert_eq!(v.ratio_scaled(1), u64::MAX);
        assert_eq!(v.ratio_scaled_squared(1), u64::MAX);
    }

    /// The pre-720 window: `blocks = height`, so the mean is over the
    /// blocks that exist, not over an imagined 720.
    #[test]
    fn short_window_divides_by_its_own_length() {
        let v = TxVolume::window(10, 100);
        assert_eq!(v.ratio_scaled(1), SCALE / 10);
    }
}
