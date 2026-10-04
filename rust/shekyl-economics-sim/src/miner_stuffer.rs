// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The cheapest archival byte: what each stuffer pays to add one shard to
//! the corpus, at a block the honest fold built
//! (`docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.10, ESR-7).
//!
//! The chain does not care which adversary stuffs; the burden model consumes
//! the minimum over [`AttackKind`]. Each kind says which chain prices it.
//! The minimum on a chain is that filter, so a kind that is priced cannot
//! be left out of the minimum.
//!
//! - **Relay stuffer.** He reaches blocks through the pool, which offers
//!   bodies by fee per byte. At the relay floor (the Economy rung) the
//!   producer's fill rule ([`Fill`]) admits him only where the honest bodies
//!   leave room. Otherwise he has to outrank them, at one atomic unit per
//!   byte above the honest rate. He pays the campaign at whichever rate gets
//!   him in ([`stuffer_cost_per_shard_atomic`]).
//! - **Miner.** He lists his own bodies in the block the honest fold built.
//!   Today the relay floor does not apply to them; once it is enforced, every
//!   one of them pays it. His cost is the cheapest integer packing: how many
//!   honest bodies to drop and how many of his own to add, with the final
//!   weight inside the block bound. Cost and the blocks a shard takes come
//!   from that one packing. The cost is the fall in his payout — the miner
//!   leg of the emission and his fee income. The staker's loss is an
//!   externality, not his outlay. A self-archiver also recovers part of the
//!   staker pool, taken only from his own fees.
//!
//! Where the reward is still the full emission, only the fullest packing of
//! that region is priced: another free transaction cannot raise the cost per
//! byte. That reduction is the flat reward, so it holds on every fee
//! schedule the comparison arms run. Past that weight the penalty is
//! quadratic, so every count is priced. A hashrate share and a time budget
//! then set how many shards a miner can stuff at the chosen price, not the
//! price.
//!
//! A column is an approach. Miner approaches differ by [`MinerTerms`] — the
//! relay floor, or not, and the pool share recovered — and one packing
//! search prices all of them. The production arm and the flat control both
//! call [`envelope_at`], so a terms change is compared on each arm. A new
//! approach is a new [`AttackKind`], its place in [`AttackKind::ALL`], and
//! the arms of [`AttackKind::priced_on`], [`AttackKind::column`], and
//! [`AttackKind::terms`]. It is not a second cost formula. A comparison that
//! needs a further constraint on what a packing may do adds that constraint
//! to [`MinerTerms`], where every column already reads it.

use std::cmp::Ordering;
use std::collections::HashSet;

use shekyl_block_template::Fill;
use shekyl_economics::{
    compute_burn_split_at, penalty_free_weight, split_block_emission, ClosedShardCount,
    EconomicParams,
};
use shekyl_tx_weight::predict_weight;
use shekyl_types::SHARD_LENGTH;

use crate::calibration::{
    all_shapes, stuffer_cost_per_shard_atomic, stuffer_shape, tree_depth_for_leaves, PerByteRate,
    Shape,
};
use crate::engine::SimParams;
use crate::fee_model::FeePoint;
use crate::stage2::LastBlock;

/// How the cheapest packing changed the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// No honest body dropped, and the reward unchanged.
    FreeRoom,
    /// No honest body dropped, and the reward lower.
    Penalty,
    /// Honest bodies dropped, and the reward not lower.
    Displacement,
    /// Honest bodies dropped, and the reward lower.
    Mixed,
}

/// Which chain an attacker is priced on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PricedOn {
    /// The chain as it stands: the relay floor does not apply to a block's
    /// own bodies.
    Today,
    /// The chain once that floor does apply.
    AfterFix,
    /// Both.
    Both,
}

impl PricedOn {
    fn on_today(self) -> bool {
        matches!(self, Self::Today | Self::Both)
    }

    fn on_after_fix(self) -> bool {
        matches!(self, Self::AfterFix | Self::Both)
    }
}

/// The holders a shard's staker-pool share divides among, for the one-of-many
/// self-archiving bound (`ARCHIVAL_TEST_EQUALS_JOB_SEQUENCING.md`, "~100
/// co-holders").
pub(crate) const CO_HOLDERS: u64 = 100;

/// A fraction of the staker pool, recovered from the attacker's own fees.
/// The denominator is at least one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PoolShare {
    num: u64,
    den: u64,
}

impl PoolShare {
    /// Recovers nothing.
    const NONE: Self = Self { num: 0, den: 1 };
    /// One holder among [`CO_HOLDERS`].
    const ONE_OF_MANY: Self = Self {
        num: 1,
        den: CO_HOLDERS,
    };
    /// The whole holder set.
    const WHOLE: Self = Self { num: 1, den: 1 };

    /// `pool × own_fees / total_fees × num / den`, floored at each division,
    /// and never more than the pool those fees funded.
    fn of(self, pool: u64, own_fees: u64, total_fees: u64) -> u64 {
        if total_fees == 0 || self.num == 0 || own_fees == 0 {
            return 0;
        }
        debug_assert!(self.den >= 1);
        let share = u128::from(pool) * u128::from(own_fees) / u128::from(total_fees)
            * u128::from(self.num)
            / u128::from(self.den);
        u64::try_from(share).unwrap_or(pool).min(pool)
    }
}

/// What a miner approach is allowed to do. The packing search is one
/// function of these terms: a column does not bring its own formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MinerTerms {
    /// When true, his bodies pay the relay floor. On today's chain they do not.
    pay_floor: bool,
    /// The pool share he recovers from his own fees.
    recovery: PoolShare,
}

/// How one column of the comparison is priced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approach {
    /// Through the pool, at the rate the fill rule lists.
    Relay,
    /// Own bodies, under [`MinerTerms`].
    Miner(MinerTerms),
}

/// One attacker. A new variant is a compile error in [`Self::priced_on`],
/// [`Self::column`], and [`Self::terms`]. [`Self::ALL`] is the list the
/// envelope prices, and the minima are filters of that list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttackKind {
    Relay,
    MinerUnenforced,
    MinerEnforced,
    SelfOneOfMany,
    SelfWholeSet,
}

impl AttackKind {
    /// Column order of the envelope. The same order [`Self::column`] names.
    const ALL: [Self; 5] = [
        Self::Relay,
        Self::MinerUnenforced,
        Self::MinerEnforced,
        Self::SelfOneOfMany,
        Self::SelfWholeSet,
    ];

    fn priced_on(self) -> PricedOn {
        match self {
            Self::Relay => PricedOn::Both,
            Self::MinerUnenforced => PricedOn::Today,
            Self::MinerEnforced | Self::SelfOneOfMany | Self::SelfWholeSet => PricedOn::AfterFix,
        }
    }

    fn column(self) -> usize {
        match self {
            Self::Relay => 0,
            Self::MinerUnenforced => 1,
            Self::MinerEnforced => 2,
            Self::SelfOneOfMany => 3,
            Self::SelfWholeSet => 4,
        }
    }

    /// The approach this column compares. Miner columns are terms for the
    /// one packing search; the relay column is the pool path.
    fn terms(self) -> Approach {
        match self {
            Self::Relay => Approach::Relay,
            Self::MinerUnenforced => Approach::Miner(MinerTerms {
                pay_floor: false,
                recovery: PoolShare::NONE,
            }),
            Self::MinerEnforced => Approach::Miner(MinerTerms {
                pay_floor: true,
                recovery: PoolShare::NONE,
            }),
            Self::SelfOneOfMany => Approach::Miner(MinerTerms {
                pay_floor: true,
                recovery: PoolShare::ONE_OF_MANY,
            }),
            Self::SelfWholeSet => Approach::Miner(MinerTerms {
                pay_floor: true,
                recovery: PoolShare::WHOLE,
            }),
        }
    }
}

/// A miner's cheapest shard at one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MinerShard {
    /// Atomic units per shard.
    pub(crate) cost_atomic: u128,
    /// Blocks the miner must mine to land one shard at that price.
    pub(crate) blocks: u64,
    pub(crate) placement: Placement,
}

/// What one attacker pays for one shard.
#[derive(Debug, Clone, Copy)]
enum AttackCost {
    Relay {
        rate: PerByteRate,
        at_floor: bool,
        atomic: u128,
    },
    Miner(MinerShard),
}

impl AttackCost {
    fn atomic(self) -> u128 {
        match self {
            Self::Relay { atomic, .. } => atomic,
            Self::Miner(shard) => shard.cost_atomic,
        }
    }

    fn miner(self) -> MinerShard {
        match self {
            Self::Miner(shard) => shard,
            Self::Relay { .. } => panic!("the relay stuffer has no packing"),
        }
    }
}

/// One priced attacker: the kind, the chain it belongs to, and what it pays.
#[derive(Debug, Clone, Copy)]
struct Attack {
    kind: AttackKind,
    priced_on: PricedOn,
    cost: AttackCost,
}

/// What each attacker pays for one shard at one block. The list is
/// [`AttackKind::ALL`]; the two minima are filters of it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Envelope {
    attacks: [Attack; AttackKind::ALL.len()],
}

impl Envelope {
    fn attack(&self, kind: AttackKind) -> &Attack {
        self.attacks
            .iter()
            .find(|attack| attack.kind == kind)
            .expect("every attacker is priced")
    }

    fn miner(&self, kind: AttackKind) -> MinerShard {
        self.attack(kind).cost.miner()
    }

    /// The cheapest shard among the attackers `priced` selects.
    fn cheapest(&self, priced: impl Fn(PricedOn) -> bool) -> u128 {
        self.attacks
            .iter()
            .filter(|attack| priced(attack.priced_on))
            .map(|attack| attack.cost.atomic())
            .min()
            .expect("a chain names its attackers")
    }

    /// The cheapest shard on the chain as it stands.
    pub(crate) fn today_atomic(&self) -> u128 {
        self.cheapest(PricedOn::on_today)
    }

    /// The cheapest shard once the floor applies to a block's own bodies.
    pub(crate) fn after_fix_atomic(&self) -> u128 {
        self.cheapest(PricedOn::on_after_fix)
    }
}

/// The block the honest fold built, and the operands an attacker prices it
/// at.
struct Block<'a> {
    at: FeePoint<'a>,
    economic: &'a EconomicParams,
    depth: u8,
    median: u64,
    honest: Fill<'a>,
    /// Weight the honest bodies leave under the emission's full weight.
    room: u64,
    burn_pct: u64,
    closed_shards: ClosedShardCount,
    honest_weight: u64,
    honest_fee: u64,
}

impl<'a> Block<'a> {
    fn new(last: &LastBlock, economic: &'a EconomicParams) -> Self {
        let at = FeePoint {
            already_generated: last.already_generated,
            volume: last.volume,
            long_term_median: last.medians.long_term_effective_median.to_raw(),
            sigma_scaled: last.sigma_scaled,
            burn_pct_scaled: last.burn_pct_scaled,
            chain_leaves: last.chain_leaves,
            params: economic,
        };
        let median = last.medians.effective_median.to_raw();
        let honest = Fill::listed(
            median,
            last.already_generated,
            last.volume,
            economic,
            last.bodies_weight,
            last.fees,
        )
        .expect("the fold listed this block");
        let room = penalty_free_weight(median, economic)
            .min(honest.bodies_weight_bound())
            .saturating_sub(honest.bodies_weight());
        Self {
            at,
            economic,
            depth: tree_depth_for_leaves(last.chain_leaves),
            median,
            honest,
            room,
            burn_pct: last.burn_pct_scaled,
            closed_shards: ClosedShardCount::new(last.closed_shards),
            honest_weight: last.honest_tx.weight,
            honest_fee: last.honest_tx.fee_atomic,
        }
    }

    /// The miner's payout for one block: his emission leg, his fee income,
    /// less the fees he paid to list his own bodies, plus `recovery` of the
    /// staker pool those fees funded. The pool share is taken from his own
    /// fees only, on the block's one burn split.
    fn net(&self, reward: u64, total_fees: u64, own_fees: u64, recovery: PoolShare) -> i128 {
        let (miner_emission, _) = split_block_emission(reward, self.at.sigma_scaled);
        let split =
            compute_burn_split_at(total_fees, self.burn_pct, self.closed_shards, self.economic);
        let recovered = recovery.of(split.staker_pool_amount, own_fees, total_fees);
        i128::from(miner_emission) + i128::from(split.miner_fee_income) + i128::from(recovered)
            - i128::from(own_fees)
    }

    /// The relay stuffer: the rate that gets his bodies listed, and his
    /// campaign's cost for one shard at it.
    fn relay(&self, floor: PerByteRate) -> (PerByteRate, bool, u128) {
        let shape = stuffer_shape(self.depth, floor);
        let mut after_honest = self.honest;
        let at_floor = after_honest.admit(
            shape.tx_weight(self.depth, floor),
            shape.tx_fee_atomic(self.depth, floor),
        );
        let rate = if at_floor {
            floor
        } else {
            // Outrank the honest bodies: one atomic unit per byte above their
            // rate, which the pool offers first and the fill rule lists under
            // the median in their place.
            PerByteRate::from_atomic(self.honest_fee / self.honest_weight.max(1) + 1)
        };
        (
            rate,
            at_floor,
            stuffer_cost_per_shard_atomic(self.at.chain_leaves, rate),
        )
    }

    /// One attacker at this block. The cost is the approach's: every miner
    /// column goes through the same search under its own terms.
    fn price(&self, kind: AttackKind, floor: PerByteRate) -> Attack {
        let cost = match kind.terms() {
            Approach::Relay => {
                let (rate, at_floor, atomic) = self.relay(floor);
                AttackCost::Relay {
                    rate,
                    at_floor,
                    atomic,
                }
            }
            Approach::Miner(terms) => AttackCost::Miner(
                self.cheapest_packing(terms.pay_floor.then_some(floor), terms.recovery)
                    .shard(),
            ),
        };
        Attack {
            kind,
            priced_on: kind.priced_on(),
            cost,
        }
    }

    /// The cheapest integer packing of this block under one miner's terms.
    /// `floor` is what his bodies pay when the approach charges the relay
    /// floor. `recovery` is the pool share those fees return to him.
    fn cheapest_packing(&self, floor: Option<PerByteRate>, recovery: PoolShare) -> PricedPacking {
        let honest = self.honest_bodies();
        let mut best: Option<PricedPacking> = None;
        // The search key is the body, not the shape that produced it. The
        // shape walk stays in builder order, so a tie keeps the earlier shape.
        let mut seen = HashSet::new();
        for shape in all_shapes() {
            let Some(body) = StuffingBody::from_shape(shape, self.depth, floor) else {
                continue;
            };
            if !seen.insert(body) {
                continue;
            }
            self.consider(&mut best, honest, body, recovery);
        }
        best.expect("the shape space has a body the bound can hold")
    }

    fn consider(
        &self,
        best: &mut Option<PricedPacking>,
        honest: HonestBodies,
        body: StuffingBody,
        recovery: PoolShare,
    ) {
        let bound = self.honest.bodies_weight_bound();
        let free_ceiling = penalty_free_weight(self.median, self.economic).min(bound);
        for dropped in 0..=honest.count {
            let Some(kept_weight) = honest.kept_weight(dropped) else {
                continue;
            };
            let Some(room) = bound.checked_sub(kept_weight) else {
                continue;
            };
            let max_stuffed = room / body.weight;
            if max_stuffed == 0 {
                continue;
            }
            // Below the penalty-free weight the reward does not move, on any
            // fee schedule. Cost per archival byte then falls as more bodies
            // are listed, so only the fullest packing of that region is a
            // candidate. Past it, every count is priced.
            let free_stuffed = free_ceiling.saturating_sub(kept_weight) / body.weight;
            let free_full = free_stuffed.min(max_stuffed);
            if free_full >= 1 {
                self.offer(best, honest, dropped, free_full, body, recovery);
            }
            if max_stuffed > free_stuffed {
                for stuffed in free_stuffed.saturating_add(1)..=max_stuffed {
                    self.offer(best, honest, dropped, stuffed, body, recovery);
                }
            }
        }
    }

    fn offer(
        &self,
        best: &mut Option<PricedPacking>,
        honest: HonestBodies,
        dropped: u64,
        stuffed: u64,
        body: StuffingBody,
        recovery: PoolShare,
    ) {
        let Some(packing) = self.packing_at(honest, dropped, stuffed, body, recovery) else {
            return;
        };
        if best.as_ref().is_none_or(|held| packing.beats(held)) {
            *best = Some(packing);
        }
    }

    fn packing_at(
        &self,
        honest: HonestBodies,
        dropped: u64,
        stuffed: u64,
        body: StuffingBody,
        recovery: PoolShare,
    ) -> Option<PricedPacking> {
        if stuffed == 0 || dropped > honest.count {
            return None;
        }
        let kept_weight = honest.kept_weight(dropped)?;
        let kept_fees = honest.kept_fees(dropped)?;
        let added_weight = stuffed.checked_mul(body.weight)?;
        let own_fees = stuffed.checked_mul(body.fee)?;
        let total_weight = kept_weight.checked_add(added_weight)?;
        if total_weight > self.honest.bodies_weight_bound() {
            return None;
        }
        let total_fees = kept_fees.checked_add(own_fees)?;
        let reward_before = self.honest.reward();
        let reward_after = self.honest.reward_at(total_weight).ok()?;
        let net_before = self.net(reward_before, self.honest.fees(), 0, recovery);
        let net_after = self.net(reward_after, total_fees, own_fees, recovery);
        let block_cost = u128::try_from((net_before - net_after).max(0)).unwrap_or(u128::MAX);
        Some(PricedPacking {
            block_cost,
            block_bytes: u128::from(stuffed) * u128::from(body.archival),
            dropped,
            stuffed,
            weight: body.weight,
            reward_before,
            reward_after,
            archival: body.archival,
        })
    }

    /// The honest bodies as identical transactions, plus a remainder the
    /// fill did not count as one of them.
    fn honest_bodies(&self) -> HonestBodies {
        let weight = self.honest_weight;
        let count = if weight == 0 {
            0
        } else {
            self.honest.bodies_weight() / weight
        };
        let counted_weight = count.saturating_mul(weight);
        let counted_fees = count
            .saturating_mul(self.honest_fee)
            .min(self.honest.fees());
        HonestBodies {
            count,
            weight,
            fee: self.honest_fee,
            remainder_weight: self.honest.bodies_weight() - counted_weight,
            remainder_fees: self.honest.fees() - counted_fees,
        }
    }
}

/// One stuffing transaction the search can list. Shapes that land on the
/// same weight, fee, and archival length are the same packing, so the search
/// prices the body once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StuffingBody {
    weight: u64,
    fee: u64,
    archival: u64,
}

impl StuffingBody {
    /// The body `shape` lists at `depth` when `floor` is the rate the
    /// approach charges. Nothing, when the shape has no weight.
    fn from_shape(shape: Shape, depth: u8, floor: Option<PerByteRate>) -> Option<Self> {
        let fee = floor.map_or(0, |rate| shape.tx_fee_atomic(depth, rate));
        let weight = u64::try_from(predict_weight(shape.n_in, shape.n_out, depth, fee)).ok()?;
        if weight == 0 {
            return None;
        }
        Some(Self {
            weight,
            fee,
            archival: shape.archival_bytes(depth).max(1),
        })
    }
}

/// The honest bodies a packing may drop, as a count of one transaction.
#[derive(Clone, Copy)]
struct HonestBodies {
    count: u64,
    weight: u64,
    fee: u64,
    remainder_weight: u64,
    remainder_fees: u64,
}

impl HonestBodies {
    fn kept_weight(self, dropped: u64) -> Option<u64> {
        let kept = self.count.checked_sub(dropped)?;
        kept.checked_mul(self.weight)?
            .checked_add(self.remainder_weight)
    }

    fn kept_fees(self, dropped: u64) -> Option<u64> {
        let kept = self.count.checked_sub(dropped)?;
        kept.checked_mul(self.fee)?.checked_add(self.remainder_fees)
    }
}

/// One integer packing, before it is turned into a shard price.
struct PricedPacking {
    /// The fall in the miner's payout, saturated at zero.
    block_cost: u128,
    /// Archival bytes the packing adds to the block.
    block_bytes: u128,
    dropped: u64,
    stuffed: u64,
    /// The stuffing body's weight. The shard price is in archival bytes;
    /// the throughput test reads the weight the search chose.
    #[cfg_attr(not(test), allow(dead_code))]
    weight: u64,
    reward_before: u64,
    reward_after: u64,
    archival: u64,
}

impl PricedPacking {
    fn placement(&self) -> Placement {
        match (self.dropped > 0, self.reward_after < self.reward_before) {
            (false, false) => Placement::FreeRoom,
            (false, true) => Placement::Penalty,
            (true, false) => Placement::Displacement,
            (true, true) => Placement::Mixed,
        }
    }

    /// Shard cost and block count from this packing. The last partial block
    /// is a fraction of one packing, not a whole one.
    fn shard(&self) -> MinerShard {
        let txs = u128::from(SHARD_LENGTH.to_raw()).div_ceil(u128::from(self.archival.max(1)));
        let stuffed = u128::from(self.stuffed.max(1));
        MinerShard {
            cost_atomic: (txs * self.block_cost).div_ceil(stuffed),
            blocks: u64::try_from(txs.div_ceil(stuffed)).unwrap_or(u64::MAX),
            placement: self.placement(),
        }
    }

    /// Cheaper per archival byte, and on a tie the packing that puts more
    /// bytes in the block. A zero-cost packing therefore fills the free
    /// room instead of listing one body.
    fn beats(&self, other: &Self) -> bool {
        match cost_per_byte_ord(
            self.block_cost,
            self.block_bytes,
            other.block_cost,
            other.block_bytes,
        ) {
            Ordering::Less => true,
            Ordering::Equal => self.block_bytes > other.block_bytes,
            Ordering::Greater => false,
        }
    }
}

/// `cost / bytes` as an ordering. The remainder cross-product is exact:
/// both byte counts are one block's archival length.
fn cost_per_byte_ord(cost_a: u128, bytes_a: u128, cost_b: u128, bytes_b: u128) -> Ordering {
    let (quot_a, rem_a) = (cost_a / bytes_a, cost_a % bytes_a);
    let (quot_b, rem_b) = (cost_b / bytes_b, cost_b % bytes_b);
    match quot_a.cmp(&quot_b) {
        Ordering::Equal => (rem_a * bytes_b).cmp(&(rem_b * bytes_a)),
        ord => ord,
    }
}

/// Where the report samples the envelope: three eras of the baseline, and a
/// chain whose demand sits below the zone, where free room exists (§5.10).
const ROWS: [(&str, u64, &str); 4] = [
    ("baseline_steady_state", 5, "constrained"),
    ("baseline_steady_state", 20, "carried"),
    ("baseline_steady_state", 45, "tail"),
    ("high_history_low_activity", 50, "below zone"),
];

/// Hashrate shares and time budgets (blocks) the shard counts are read at.
const SHARES_PCT: [u64; 2] = [10, 33];

/// Print the envelope (§5.10). SKL per shard; the last two columns are the
/// minimum on the chain as it stands and once the floor is enforced on a
/// block's own bodies.
pub(crate) fn print_envelope(
    out: &mut impl core::fmt::Write,
    params: &SimParams,
    folded: &[crate::stage2::FoldedScenario],
) -> core::fmt::Result {
    let budgets = [
        ("epoch", shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS),
        ("year", params.blocks_per_year),
        ("decade", 10 * params.blocks_per_year),
    ];
    writeln!(
        out,
        "\nESR-7 — THE CHEAPEST ARCHIVAL BYTE: SKL to add one shard at a block the honest fold built.\n\
         relay = through the pool at the rate that gets listed (floor, or one atomic/B above the\n\
         honest rate); miner U = own bodies at no fee (today: the relay floor does not apply to them),\n\
         the cheapest integer packing of the block; miner E = the same paying the floor\n\
         (C2-R2 Q9's fix, a declared divergence); self = E recovering the staker pool's part as one of\n\
         {CO_HOLDERS} holders, and as the whole holder set. 'today' / 'fixed' = the minimum over the\n\
         attackers on each chain."
    )?;
    writeln!(
        out,
        "{:<12} {:>3} {:<11} {:>7} {:>6} {:>11} {:>12} {:>13} {:>11} {:>11} {:>11} {:>11} {:>11}",
        "scenario",
        "y",
        "era",
        "M (KB)",
        "room",
        "relay",
        "miner U",
        "(placement)",
        "miner E",
        "self 1/100",
        "self all",
        "today",
        "fixed"
    )?;
    let skl = |atomic: u128| atomic as f64 / crate::burden::COIN as f64;
    let mut shard_rows = Vec::new();
    for (name, year, era) in ROWS {
        let scenario = folded
            .iter()
            .find(|s| s.name == name)
            .expect("the scenario exists");
        let Some(agg) = scenario.aggs.iter().find(|a| a.year == year) else {
            continue;
        };
        let last = agg.last_block;
        let e = envelope_at(&last, params);
        let economic = params.economic();
        let block = Block::new(&last, &economic);
        let unenforced = e.miner(AttackKind::MinerUnenforced);
        let (relay_rate, relay_at_floor, relay_atomic) = match e.attack(AttackKind::Relay).cost {
            AttackCost::Relay {
                rate,
                at_floor,
                atomic,
            } => (rate, at_floor, atomic),
            AttackCost::Miner(_) => unreachable!("relay is priced as a rate"),
        };
        writeln!(
            out,
            "{:<12} {:>3} {:<11} {:>7.0} {:>6.0} {:>11.4} {:>12.4} {:>13} {:>11.4} {:>11.4} {:>11.4} {:>11.4} {:>11.4}",
            crate::stage2::trunc(name, 12),
            year,
            era,
            block.median as f64 / 1.0e3,
            block.room as f64 / 1.0e3,
            skl(relay_atomic),
            skl(unenforced.cost_atomic),
            format!("{:?}", unenforced.placement),
            skl(e.miner(AttackKind::MinerEnforced).cost_atomic),
            skl(e.miner(AttackKind::SelfOneOfMany).cost_atomic),
            skl(e.miner(AttackKind::SelfWholeSet).cost_atomic),
            skl(e.today_atomic()),
            skl(e.after_fix_atomic()),
        )?;
        shard_rows.push((name, year, unenforced.blocks, relay_at_floor, relay_rate));
    }
    writeln!(
        out,
        "  -> Shards a miner stuffs at the U price within a budget: share x budget / blocks per shard.\n\
         Hashrate and time set a rate, not a price; a larger campaign raises the overshoot and the price."
    )?;
    for (name, year, blocks, at_floor, rate) in shard_rows {
        let cells: Vec<String> = SHARES_PCT
            .iter()
            .flat_map(|&pct| {
                budgets.iter().map(move |&(label, n)| {
                    format!("{pct}%/{label} {}", n * pct / 100 / blocks.max(1))
                })
            })
            .collect();
        writeln!(
            out,
            "       {:<12} y{year:<3} {blocks:>5} blocks/shard; relay at {} atomic/B{}: {}",
            crate::stage2::trunc(name, 12),
            rate.atomic(),
            if at_floor {
                " (the floor)"
            } else {
                " (outranking honest)"
            },
            cells.join(", ")
        )?;
    }
    Ok(())
}

/// Every attacker at the block a fold ended a year on.
pub(crate) fn envelope_at(last: &LastBlock, params: &SimParams) -> Envelope {
    let economic = params.economic();
    let block = Block::new(last, &economic);
    let floor = params.fee.admission_rate(&block.at);
    // Column order is the approach list. A match arm that numbers a column
    // differently from [`AttackKind::ALL`] fails this before the report prints.
    debug_assert!(AttackKind::ALL
        .iter()
        .enumerate()
        .all(|(column, kind)| kind.column() == column));
    Envelope {
        attacks: AttackKind::ALL.map(|kind| block.price(kind, floor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_block_template::Fill;
    use shekyl_chain_rules::medians_from;
    use shekyl_economics::{
        compute_burn_split_at, paid_block_reward, split_block_emission, TxVolume,
    };

    use crate::fee_model::OrdinaryTx;

    /// A block whose honest demand is `offered` identical transactions, listed
    /// by the fill rule. The stuffer reads the listing, it does not re-offer.
    fn block_at(offered: u64, params: &SimParams) -> LastBlock {
        let economic = params.economic();
        let zone = economic.full_reward_zone;
        let volume = TxVolume::per_block(params.tx_volume_baseline);
        let at = FeePoint {
            already_generated: economic.emission_curve_asymptote / 3,
            volume,
            long_term_median: zone,
            sigma_scaled: 100_000,
            burn_pct_scaled: 200_000,
            chain_leaves: 50_000_000,
            params: &economic,
        };
        let honest_tx: OrdinaryTx = params.fee.ordinary_tx(&at);
        let medians = medians_from(zone, zone);
        let mut fill = Fill::empty(
            medians.effective_median.to_raw(),
            at.already_generated,
            volume,
            &economic,
        )
        .expect("priced");
        fill.admit_up_to(honest_tx.weight, honest_tx.fee_atomic, offered);
        LastBlock {
            already_generated: at.already_generated,
            volume,
            sigma_scaled: at.sigma_scaled,
            burn_pct_scaled: at.burn_pct_scaled,
            chain_leaves: at.chain_leaves,
            closed_shards: 1_000,
            medians,
            honest_tx,
            bodies_weight: fill.bodies_weight(),
            fees: fill.fees(),
        }
    }

    /// Where honest demand leaves room under the median, the relay stuffer
    /// gets in at the floor and the unenforced miner stuffs for nothing;
    /// where it fills the block, the relay stuffer must outrank the honest
    /// bodies and the miner pays.
    #[test]
    fn free_room_is_free_and_a_full_block_is_not() {
        let params = SimParams::default();
        let roomy = envelope_at(&block_at(5, &params), &params);
        let roomy_relay = relay_of(&roomy);
        let roomy_miner = roomy.miner(AttackKind::MinerUnenforced);
        assert!(roomy_relay.1, "admitted at the floor beside 5 bodies");
        assert_eq!(roomy_miner.cost_atomic, 0);
        assert_eq!(roomy_miner.placement, Placement::FreeRoom);
        let economic = params.economic();
        let block = Block::new(&block_at(5, &params), &economic);
        let chosen = block.cheapest_packing(None, PoolShare::NONE);
        let free = penalty_free_weight(block.median, block.economic)
            .min(block.honest.bodies_weight_bound())
            .saturating_sub(
                block
                    .honest_bodies()
                    .kept_weight(0)
                    .expect("nothing dropped"),
            );
        assert_eq!(
            chosen.stuffed,
            free / chosen.weight,
            "a zero-cost packing fills the free room"
        );
        assert_eq!(chosen.dropped, 0);

        let full = envelope_at(&block_at(1_000, &params), &params);
        assert!(!relay_of(&full).1, "a full block refuses the floor rate");
        let full_miner = full.miner(AttackKind::MinerUnenforced);
        assert!(full_miner.cost_atomic > 0);
        assert_ne!(full_miner.placement, Placement::FreeRoom);
    }

    fn relay_of(envelope: &Envelope) -> (PerByteRate, bool, u128) {
        match envelope.attack(AttackKind::Relay).cost {
            AttackCost::Relay {
                rate,
                at_floor,
                atomic,
            } => (rate, at_floor, atomic),
            AttackCost::Miner(_) => unreachable!("relay is priced as a rate"),
        }
    }

    /// Recovering more of the staker pool can only lower the miner's cost.
    /// Each minimum is the cheapest attacker that chain prices, and every
    /// such attacker is at least that cheap.
    #[test]
    fn the_minimum_is_every_attacker_that_chain_prices() {
        let params = SimParams::default();
        for (i, kind) in AttackKind::ALL.iter().enumerate() {
            assert_eq!(kind.column(), i, "the column is the list position");
        }
        for offered in [5, 22, 1_000] {
            let e = envelope_at(&block_at(offered, &params), &params);
            let mut seen = [false; AttackKind::ALL.len()];
            for attack in &e.attacks {
                assert!(!seen[attack.kind.column()], "one column per attacker");
                seen[attack.kind.column()] = true;
                assert_eq!(attack.priced_on, attack.kind.priced_on());
                match (attack.kind.terms(), attack.cost) {
                    (Approach::Relay, AttackCost::Relay { .. })
                    | (Approach::Miner(_), AttackCost::Miner(_)) => {}
                    (Approach::Relay, AttackCost::Miner(_))
                    | (Approach::Miner(_), AttackCost::Relay { .. }) => {
                        panic!("the cost is the approach");
                    }
                }
            }
            assert!(seen.iter().copied().all(|priced| priced));
            assert_min_covers(&e, e.today_atomic(), PricedOn::on_today);
            assert_min_covers(&e, e.after_fix_atomic(), PricedOn::on_after_fix);
            let enforced = e.miner(AttackKind::MinerEnforced).cost_atomic;
            let one = e.miner(AttackKind::SelfOneOfMany).cost_atomic;
            let whole = e.miner(AttackKind::SelfWholeSet).cost_atomic;
            assert!(one <= enforced, "offered {offered}");
            assert!(whole <= one, "offered {offered}");
        }
    }

    fn assert_min_covers(envelope: &Envelope, min: u128, priced: impl Fn(PricedOn) -> bool) {
        let mut found = false;
        for attack in &envelope.attacks {
            if priced(attack.priced_on) {
                assert!(attack.cost.atomic() >= min);
                found |= attack.cost.atomic() == min;
            }
        }
        assert!(found, "the minimum is one of the attackers on that chain");
    }

    /// Adding one zero-fee body past a full block costs the miner his
    /// emission leg of the penalty, not the gross reward. The staker's leg
    /// is not his outlay.
    #[test]
    fn the_penalty_leg_is_the_miners_emission_share() {
        let params = SimParams::default();
        let last = block_at(1_000, &params);
        let economic = params.economic();
        let block = Block::new(&last, &economic);
        let weight = 20_000;
        let packing = block
            .packing_at(
                block.honest_bodies(),
                0,
                1,
                StuffingBody {
                    weight,
                    fee: 0,
                    archival: 1,
                },
                PoolShare::NONE,
            )
            .expect("one more transaction fits under the limit");
        let owed = |w| {
            paid_block_reward(
                block.median,
                w,
                last.already_generated,
                last.volume,
                &economic,
            )
            .expect("priced")
        };
        let before = split_block_emission(owed(block.honest.bodies_weight()), last.sigma_scaled).0;
        let after = split_block_emission(
            owed(block.honest.bodies_weight() + weight),
            last.sigma_scaled,
        )
        .0;
        assert!(before > after, "the penalty lowers the reward");
        assert_eq!(packing.block_cost, u128::from(before - after));
        assert_eq!(packing.placement(), Placement::Penalty);
    }

    /// A packing's cost is the before/after change in the miner's payout,
    /// from the emission split and the block's burn split. The payout is
    /// written out here, so the assertion is not the search calling itself.
    #[test]
    fn a_packing_costs_the_change_in_the_miners_payout() {
        let params = SimParams::default();
        let last = block_at(1_000, &params);
        let economic = params.economic();
        let block = Block::new(&last, &economic);
        let dropped = 3;
        let stuffed = 2;
        let weight = 20_000;
        let fee = 4_000_000;
        let share = PoolShare::ONE_OF_MANY;
        let packing = block
            .packing_at(
                block.honest_bodies(),
                dropped,
                stuffed,
                StuffingBody {
                    weight,
                    fee,
                    archival: 1,
                },
                share,
            )
            .expect("the packing fits");
        let honest = block.honest_bodies();
        let kept = honest.count - dropped;
        let fees_before = block.honest.fees();
        let fees_after = kept * honest.fee + honest.remainder_fees + stuffed * fee;
        let weight_after = kept * honest.weight + honest.remainder_weight + stuffed * weight;
        let reward_before = block.honest.reward();
        let reward_after = block
            .honest
            .reward_at(weight_after)
            .expect("within the bound");
        // The same arithmetic as the pool share and the block payout, written
        // out so a drift in either of them fails here.
        let payout = |reward: u64, fees: u64, own: u64| -> i128 {
            let miner_emission = split_block_emission(reward, last.sigma_scaled).0;
            let split =
                compute_burn_split_at(fees, last.burn_pct_scaled, block.closed_shards, &economic);
            let recovered = if fees == 0 || own == 0 {
                0
            } else {
                u128::from(split.staker_pool_amount) * u128::from(own) / u128::from(fees)
                    * u128::from(share.num)
                    / u128::from(share.den)
            };
            let recovered = i128::try_from(recovered).unwrap_or(i128::MAX);
            i128::from(miner_emission) + i128::from(split.miner_fee_income) + recovered
                - i128::from(own)
        };
        let expected = (payout(reward_before, fees_before, 0)
            - payout(reward_after, fees_after, stuffed * fee))
        .max(0);
        assert_eq!(
            packing.block_cost,
            u128::try_from(expected).unwrap_or(u128::MAX)
        );
        assert_eq!(packing.dropped, dropped);
        assert_eq!(packing.stuffed, stuffed);
    }
}
