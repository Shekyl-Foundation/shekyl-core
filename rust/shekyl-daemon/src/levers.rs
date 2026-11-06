// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The schedule levers the daemon judges in their rows' terms
//! (`DAEMON_CONFIG_CUTOVER.md` §4.2, §6): the seed-epoch rows and the
//! settlement rows. The configuration check asks each and latches nothing
//! (`INPUT_GRAMMAR.md` IG-Q59); a start asks the same check and then arms
//! what has an owner.
//!
//! The seed-epoch rows (`dev-pow-seed-epoch-blocks`,
//! `dev-pow-seed-epoch-lag`) are judged and not armed: the Rust validator
//! pins the epoch constants (`shekyl-chain-rules`, CEN-D3) and reads no
//! lever, and the C++ seed-height export that read the recorded pair went
//! with the remnant (`P2P_3_REMNANT_CUTOVER_BRIEF.md` §3). The rows keep
//! their refusals so the grammar's contract holds until they are ruled.

use shekyl_difficulty::{SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG};

/// Why the daemon's seed-epoch rows were refused. Each arm names the row
/// it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedEpochRefusal {
    /// `dev-pow-seed-epoch-blocks` is not a power of two in range.
    Blocks(String),
    /// `dev-pow-seed-epoch-lag` is not a power of two at most the lag.
    Lag(String),
}

impl SeedEpochRefusal {
    /// The option the refusal is about.
    #[must_use]
    pub const fn row(&self) -> Option<&'static str> {
        match self {
            Self::Blocks(_) => Some("dev-pow-seed-epoch-blocks"),
            Self::Lag(_) => Some("dev-pow-seed-epoch-lag"),
        }
    }

    /// The rule the diagnostic prints.
    #[must_use]
    pub fn rule(&self) -> &str {
        match self {
            Self::Blocks(rule) | Self::Lag(rule) => rule,
        }
    }
}

impl std::fmt::Display for SeedEpochRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule())
    }
}

impl std::error::Error for SeedEpochRefusal {}

/// The schedule the daemon's seed-epoch rows name, or the row's refusal.
/// Pure. `None` is the mainnet value.
///
/// # Errors
/// [`SeedEpochRefusal::Blocks`] when the length is not a power of two in
/// `2..=SEEDHASH_EPOCH_BLOCKS`, [`SeedEpochRefusal::Lag`] when the lag is
/// not a power of two at most `SEEDHASH_EPOCH_LAG`.
pub fn check_seed_epoch(
    blocks: Option<u64>,
    lag: Option<u64>,
) -> Result<(u64, u64), SeedEpochRefusal> {
    let blocks = match blocks {
        Some(b) if (2..=SEEDHASH_EPOCH_BLOCKS).contains(&b) && b.is_power_of_two() => b,
        Some(_) => {
            return Err(SeedEpochRefusal::Blocks(format!(
                "a power of two from 2 to {SEEDHASH_EPOCH_BLOCKS}"
            )))
        }
        None => SEEDHASH_EPOCH_BLOCKS,
    };
    let lag = match lag {
        Some(l) if l <= SEEDHASH_EPOCH_LAG && l.is_power_of_two() => l,
        Some(_) => {
            return Err(SeedEpochRefusal::Lag(format!(
                "a power of two at most {SEEDHASH_EPOCH_LAG}"
            )))
        }
        None => SEEDHASH_EPOCH_LAG,
    };
    Ok((blocks, lag))
}

/// Why the daemon's settlement rows were refused. Each arm names the row
/// it is about, except a latch that already happened: that refusal is the
/// machine's, and pinning either row would blame the wrong one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementScheduleRefusal {
    /// `dev-settlement-epoch-blocks` is outside the cap's floor.
    Epoch(String),
    /// `dev-archival-reorg-depth` is outside `1..=ARCHIVAL_REORG_DEPTH_BLOCKS`.
    Reorg(String),
    /// The schedule had already latched. No row owns that fact.
    Latched(String),
}

impl SettlementScheduleRefusal {
    /// The option the refusal is about, when one option owns it.
    #[must_use]
    pub const fn row(&self) -> Option<&'static str> {
        match self {
            Self::Epoch(_) => Some("dev-settlement-epoch-blocks"),
            Self::Reorg(_) => Some("dev-archival-reorg-depth"),
            Self::Latched(_) => None,
        }
    }

    /// The rule the diagnostic prints, in the row's terms.
    #[must_use]
    pub fn rule(&self) -> &str {
        match self {
            Self::Epoch(rule) | Self::Reorg(rule) | Self::Latched(rule) => rule,
        }
    }
}

impl std::fmt::Display for SettlementScheduleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule())
    }
}

impl std::error::Error for SettlementScheduleRefusal {}

/// Arms the settlement schedule from the daemon's `dev-` rows: a start
/// calls this before the node, whose first epoch arithmetic latches the
/// schedule, exists. `None` is the genesis pin. The daemon refuses to
/// start on `Err`, naming the row the arm carries.
///
/// # Errors
/// [`SettlementScheduleRefusal`]: a value outside its range, or a schedule
/// already latched.
pub fn arm_settlement_schedule(
    blocks: Option<u64>,
    reorg_cap: Option<u64>,
) -> Result<u64, SettlementScheduleRefusal> {
    shekyl_archival_retention::arm_settlement_epoch_override(blocks, reorg_cap)
        .map_err(|e| in_the_rows_terms(&e))
}

/// The settlement epoch length the daemon's `dev-` rows name, or the
/// row's refusal, with nothing latched: the configuration check's half.
/// [`arm_settlement_schedule`] judges by the same check before it latches.
///
/// # Errors
/// [`SettlementScheduleRefusal::Epoch`] and
/// [`SettlementScheduleRefusal::Reorg`]; never `Latched`.
pub fn check_settlement_schedule(
    blocks: Option<u64>,
    reorg_cap: Option<u64>,
) -> Result<u64, SettlementScheduleRefusal> {
    shekyl_archival_retention::check_settlement_epoch_override(blocks, reorg_cap)
        .map(|(target, _)| target)
        .map_err(|e| in_the_rows_terms(&e))
}

/// The rule in the row's terms. The error's own text names the
/// environment variables the wallet engine still reads; this mapping
/// does not.
fn in_the_rows_terms(
    e: &shekyl_archival_retention::SettlementEpochOverrideError,
) -> SettlementScheduleRefusal {
    use shekyl_archival_retention::SettlementEpochOverrideError as E;
    use shekyl_archival_retention::ARCHIVAL_REORG_DEPTH_BLOCKS;
    let epoch_max = shekyl_archival_retention::archival_params().settlement_epoch_blocks;
    match e {
        E::Invalid {
            floor, reorg_cap, ..
        } => SettlementScheduleRefusal::Epoch(format!(
            "an integer from {floor} to {epoch_max}, strictly above the archival reorg depth of {reorg_cap}"
        )),
        E::InvalidReorgCap { .. } => SettlementScheduleRefusal::Reorg(format!(
            "an integer from 1 to {ARCHIVAL_REORG_DEPTH_BLOCKS}"
        )),
        E::ArmedTooLate { latched } => SettlementScheduleRefusal::Latched(format!(
            "the settlement schedule had already latched at {latched} blocks before the daemon recorded the row"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed-epoch rows are judged in their own terms: a length that is
    /// not a power of two in range names its row, a lag above the pin
    /// names its, and unset is the mainnet pair.
    #[test]
    fn the_seed_epoch_rows_are_refused_in_their_terms_and_unset_is_the_pin() {
        let e = check_seed_epoch(Some(3), None).unwrap_err();
        assert!(matches!(e, SeedEpochRefusal::Blocks(_)));
        assert_eq!(e.row(), Some("dev-pow-seed-epoch-blocks"));
        assert_eq!(
            e.rule(),
            format!("a power of two from 2 to {SEEDHASH_EPOCH_BLOCKS}")
        );
        let e = check_seed_epoch(None, Some(SEEDHASH_EPOCH_LAG * 2)).unwrap_err();
        assert!(matches!(e, SeedEpochRefusal::Lag(_)));
        assert_eq!(e.row(), Some("dev-pow-seed-epoch-lag"));
        assert_eq!(
            check_seed_epoch(None, None),
            Ok((SEEDHASH_EPOCH_BLOCKS, SEEDHASH_EPOCH_LAG))
        );
        assert_eq!(check_seed_epoch(Some(16), Some(4)), Ok((16, 4)));
    }

    /// The daemon's refusal names the row's rule, not an environment
    /// variable. The latch is process-wide, so this test arms nothing
    /// that could succeed; the refusals come before the latch.
    #[test]
    fn a_settlement_lever_off_its_range_is_refused_in_the_rows_terms() {
        let e = arm_settlement_schedule(Some(40), None).unwrap_err();
        assert!(matches!(e, SettlementScheduleRefusal::Epoch(_)));
        assert_eq!(e.row(), Some("dev-settlement-epoch-blocks"));
        assert!(
            e.rule().starts_with("an integer from 721 to 10000"),
            "{}",
            e.rule()
        );
        assert!(!e.rule().contains("SHEKYL_"), "{}", e.rule());
        let e = arm_settlement_schedule(None, Some(0)).unwrap_err();
        assert!(matches!(e, SettlementScheduleRefusal::Reorg(_)));
        assert_eq!(e.row(), Some("dev-archival-reorg-depth"));
        assert!(
            e.rule().starts_with("an integer from 1 to "),
            "{}",
            e.rule()
        );
    }

    /// The configuration check's half: the same refusals in the same
    /// terms, and a valid pair is a value, never a latch, however many
    /// times it is asked and whatever this process latched.
    #[test]
    fn the_check_refuses_as_the_arm_does_and_latches_nothing() {
        let a = arm_settlement_schedule(Some(40), None).unwrap_err();
        let c = check_settlement_schedule(Some(40), None).unwrap_err();
        assert_eq!(a, c);
        let a = arm_settlement_schedule(None, Some(0)).unwrap_err();
        let c = check_settlement_schedule(None, Some(0)).unwrap_err();
        assert_eq!(a, c);
        assert_eq!(check_settlement_schedule(Some(800), Some(10)), Ok(800));
        assert_eq!(check_settlement_schedule(Some(900), Some(10)), Ok(900));
        assert_eq!(
            check_settlement_schedule(None, None),
            Ok(shekyl_archival_retention::SETTLEMENT_EPOCH_BLOCKS)
        );
    }
}
