// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A run's parameters: the production baseline and the named overrides
//! that depart from it (ESR-16 completion, ruling 6, 2026-10-29;
//! `docs/design/ECONOMICS_SIM_PRODUCTION_REBASE.md` §5.26).
//!
//! The baseline is the three structs production reads, from their own
//! accessors: [`shekyl_economics::economic_params`],
//! [`shekyl_economics::relay_policy`] and
//! [`shekyl_archival_retention::archival_params`]. The sim holds no copy of
//! a production field. A run departs from it only by an [`Override`]: a
//! path `set.field` and a value. Each struct's overrides are written onto
//! its serialized baseline and the result deserialized, and each struct
//! deserializes only through its own validator, so an override naming a
//! field the struct does not have, or a value its validator refuses, fails
//! here, before any fold starts.
//!
//! The sim's own inputs, which production has no value for (the demand
//! schedules, the fee arm, the horizon), are not overrides; they stay in
//! the scenario and in [`crate::engine::SimParams::fee`].

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;
use shekyl_archival_retention::ArchivalParams;
use shekyl_economics::{EconomicParams, RelayPolicy};

/// One departure from the baseline: `set.field = value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Override {
    /// `economic`, `relay` or `archival`: which production struct.
    pub set: ParamSet,
    /// The field's name in that struct, as it serializes.
    pub field: String,
    /// The value. Every production parameter is an unsigned integer; a
    /// `u32` field refuses a value past `u32::MAX` at the door.
    pub value: u64,
}

/// Which production struct an [`Override`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ParamSet {
    /// [`EconomicParams`], chain identity (the params digest).
    Economic,
    /// [`RelayPolicy`], what a node relays and quotes.
    Relay,
    /// [`ArchivalParams`], the archival consensus set.
    Archival,
}

impl ParamSet {
    const ALL: [Self; 3] = [Self::Economic, Self::Relay, Self::Archival];

    /// The path prefix an override names this set by.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Economic => "economic",
            Self::Relay => "relay",
            Self::Archival => "archival",
        }
    }
}

impl Override {
    /// Parse `set.field=value`, the form `--set` takes.
    ///
    /// # Errors
    ///
    /// [`OverrideError::Malformed`] when the text is not that form, the set
    /// is not one of [`ParamSet`]'s, or the value is not an unsigned
    /// integer. Whether the field exists is the door's question
    /// ([`Baseline::with`]), not the parser's.
    pub fn parse(text: &str) -> Result<Self, OverrideError> {
        let malformed = || OverrideError::Malformed(text.to_string());
        let (path, value) = text.split_once('=').ok_or_else(malformed)?;
        let (set, field) = path.split_once('.').ok_or_else(malformed)?;
        let set = ParamSet::ALL
            .into_iter()
            .find(|s| s.name() == set)
            .ok_or_else(malformed)?;
        if field.is_empty() {
            return Err(malformed());
        }
        let value = value.parse::<u64>().map_err(|_| malformed())?;
        Ok(Self {
            set,
            field: field.to_string(),
            value,
        })
    }

    /// The override's path, `set.field`.
    #[must_use]
    pub fn path(&self) -> String {
        format!("{}.{}", self.set.name(), self.field)
    }
}

impl fmt::Display for Override {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.path(), self.value)
    }
}

/// Why a run's overrides were refused. Every arm fails before the fold.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OverrideError {
    /// Not `set.field=value` with a known set and an unsigned value.
    #[error("override {0:?} is not set.field=value (set: economic, relay or archival)")]
    Malformed(String),
    /// The struct has no such field.
    #[error("override {path}: {set} has no field {field:?}", set = .set.name())]
    UnknownField {
        /// The set named.
        set: ParamSet,
        /// The field named.
        field: String,
        /// `set.field`.
        path: String,
    },
    /// The same path twice: which value the run used would be an accident
    /// of order.
    #[error("override {0} is given twice")]
    Duplicate(String),
    /// The mode's report reads no such field: a cell on it would print the
    /// baseline, which reads as "no effect".
    #[error("override {path}: field has no reader in {mode}")]
    NoReader {
        /// `set.field`.
        path: String,
        /// The mode and arm, as the operator names them.
        mode: &'static str,
    },
    /// The field is read, but moves nothing in this run without another
    /// setting (the escalation knee on a flat escalation).
    #[error("override {path}: moves nothing in {mode} while {why}")]
    Inert {
        /// `set.field`.
        path: String,
        /// The mode and arm.
        mode: &'static str,
        /// The run's state that makes it inert.
        why: &'static str,
    },
    /// The struct's validator refused the overridden set (or the value does
    /// not fit the field's width).
    #[error("{set} overrides refused by its validator: {reason}", set = .set.name())]
    Refused {
        /// The set whose validator refused.
        set: ParamSet,
        /// The validator's own message.
        reason: String,
    },
}

/// The three production structs a run folds under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Baseline {
    /// [`EconomicParams`].
    pub economic: EconomicParams,
    /// [`RelayPolicy`].
    pub relay: RelayPolicy,
    /// [`ArchivalParams`].
    pub archival: ArchivalParams,
}

impl Baseline {
    /// What production reads: each struct from its own accessor.
    #[must_use]
    pub fn shipped() -> Self {
        Self {
            economic: shekyl_economics::economic_params().clone(),
            relay: *shekyl_economics::relay_policy(),
            archival: *shekyl_archival_retention::archival_params(),
        }
    }

    /// This baseline with `overrides` written on, each struct through its
    /// own validator.
    ///
    /// # Errors
    ///
    /// [`OverrideError`]: a duplicate path, a field the struct does not
    /// have, or a set its validator refuses.
    pub fn with(&self, overrides: &[Override]) -> Result<Self, OverrideError> {
        let mut seen = std::collections::BTreeSet::new();
        for o in overrides {
            if !seen.insert(o.path()) {
                return Err(OverrideError::Duplicate(o.path()));
            }
        }
        Ok(Self {
            economic: apply(&self.economic, ParamSet::Economic, overrides)?,
            relay: apply(&self.relay, ParamSet::Relay, overrides)?,
            archival: apply(&self.archival, ParamSet::Archival, overrides)?,
        })
    }
}

/// Write `set`'s overrides onto `base` and deserialize the result. The
/// serialized baseline is the field list: a name not among its keys is
/// refused here, explicitly, rather than left to the wire form's
/// `deny_unknown_fields` (which `EconomicParams`' wire does not carry).
fn apply<T: Serialize + DeserializeOwned>(
    base: &T,
    set: ParamSet,
    overrides: &[Override],
) -> Result<T, OverrideError> {
    let mut fields = match serde_json::to_value(base) {
        Ok(serde_json::Value::Object(fields)) => fields,
        _ => unreachable!("a production parameter struct serializes to a JSON object"),
    };
    let mut any = false;
    for o in overrides.iter().filter(|o| o.set == set) {
        let slot = fields
            .get_mut(&o.field)
            .ok_or_else(|| OverrideError::UnknownField {
                set,
                field: o.field.clone(),
                path: o.path(),
            })?;
        *slot = o.value.into();
        any = true;
    }
    // An untouched set is the baseline itself; the round trip would only
    // re-check what its accessor already holds.
    if !any {
        return serde_json::from_value(serde_json::Value::Object(fields))
            .map_err(|e| unreachable!("the baseline {} set deserializes: {e}", set.name()));
    }
    serde_json::from_value(serde_json::Value::Object(fields)).map_err(|e| OverrideError::Refused {
        set,
        reason: e.to_string(),
    })
}

/// One field a mode's report reads, and a value in its validator's band at
/// which the report moves. The per-mode lists below are the reach a cell
/// has: an override outside its mode's list is refused
/// ([`check_reach`]), and `every_declared_reader_moves_its_report` runs
/// each entry and fails when the report does not move, so a field listed
/// as read that no figure depends on fails by name. A mode that gains a
/// reader lists the field in the same commit.
#[derive(Clone, Copy, Debug)]
pub struct Reader {
    /// `set.field`.
    pub path: &'static str,
    /// A value the field's validator accepts that moves the report.
    // Read by `every_declared_reader_moves_its_report`: the binary has no
    // library target, so a field only a test reads is dead in the bin (the
    // `cartel.rs` precedent).
    #[cfg_attr(not(test), allow(dead_code))]
    pub moves_at: u64,
    /// When the field moves the report only under another setting: what
    /// must hold of the run, why, and the override that makes it hold.
    pub only_if: Option<Condition>,
}

/// A run state a field needs before its value moves any figure.
#[derive(Clone, Copy, Debug)]
pub struct Condition {
    /// The state that leaves the field inert, as the refusal names it.
    pub inert_while: &'static str,
    /// Whether the run is in that state.
    pub inert: fn(&Baseline) -> bool,
    /// An override that leaves it (the test's companion).
    #[cfg_attr(not(test), allow(dead_code))]
    pub companion: (&'static str, u64),
}

const fn read(path: &'static str, moves_at: u64) -> Reader {
    Reader {
        path,
        moves_at,
        only_if: None,
    }
}

/// The escalation knee moves the fold's pool share only off a flat
/// escalation: at the shipped asymptote, equal to the pool share, the ramp
/// has no span and every knee prices the same.
const KNEE: Reader = Reader {
    path: "economic.escalation_knee_n",
    moves_at: 1_000_000,
    only_if: Some(Condition {
        inert_while: "the escalation is flat (escalation_asymptote_share equals staker_pool_share)",
        inert: |run| run.economic.escalation_asymptote_share == run.economic.staker_pool_share,
        companion: ("economic.escalation_asymptote_share", 500_000),
    }),
};

/// The fields `--stage2` reads on both arms: the fold's economics and the
/// archival arms' parameters. Measured, not assumed
/// (`every_declared_reader_moves_its_report`): the reward age weight is
/// read but inert, because the sim scores every shard at age 0, where `g`
/// is its base; the release cooldown and the bond-duration pair reach no
/// `--stage2` figure. None of the three is listed, so a cell on one is
/// refused.
macro_rules! stage2_common {
    () => {
        [
            read("economic.release_min", 850_000),
            read("economic.release_max", 1_250_000),
            read("economic.tx_volume_baseline", 60),
            read("economic.burn_base_rate", 450_000),
            read("economic.burn_cap", 850_000),
            read("economic.staker_pool_share", 200_000),
            read(
                "economic.emission_curve_asymptote",
                4_200_000_000_000_000_000,
            ),
            read("economic.emission_speed_factor_per_block", 21),
            read("economic.final_subsidy_per_minute", 250_000_000),
            read("economic.daa_target_seconds", 180),
            read("economic.escalation_asymptote_share", 500_000),
            KNEE,
            read("economic.full_reward_zone", 350_000),
            read("economic.staker_emission_share", 120_000),
            read("economic.staker_emission_decay", 850_000),
            read("economic.block_weight_surge_factor", 6),
            read("economic.block_weight_limit_multiple", 3_000_000),
            read("archival.bond_floor_atomic", 800_000_000),
            read("archival.settlement_epoch_blocks", 8_000),
            read("archival.max_claim_age_w", 30),
            read("archival.failure_window_m", 10),
            read("archival.failure_window_n", 12),
        ]
    };
}

/// `--stage2` on the production fee arm: the common set, the long-term
/// clamp, and the relay fields the production ladder prices the fee with
/// (`w_ref`, the Standard ratio, the lattice). The lookback, the slack, the
/// claim hold and the Priority factor are not read: every ordinary
/// transaction pays Standard and no fold admits against a window.
pub const STAGE2_PRODUCTION_READS: &[Reader] = &{
    let common = stage2_common!();
    let more = [
        read("economic.long_term_weight_clamp", 2_000_000),
        read("relay.fee_decimal_places", 8),
        read("relay.ref_tx_weight", 4_000),
        read("relay.standard_over_economy", 5),
    ];
    let mut all = [read("", 0); 26];
    let mut i = 0;
    while i < common.len() {
        all[i] = common[i];
        i += 1;
    }
    let mut j = 0;
    while j < more.len() {
        all[i + j] = more[j];
        j += 1;
    }
    all
};

/// `--stage2 --control-flat-fee`: the flat fee prices no ladder, so no
/// relay field reaches it, and the long-term clamp moves no figure the
/// control arm prints.
pub const STAGE2_CONTROL_READS: &[Reader] = &stage2_common!();

/// The reach of the mode a run is printed in: its name and its readers.
#[must_use]
pub fn stage2_reach(control: bool) -> (&'static str, &'static [Reader]) {
    if control {
        ("--stage2 --control-flat-fee", STAGE2_CONTROL_READS)
    } else {
        ("--stage2", STAGE2_PRODUCTION_READS)
    }
}

/// Refuse an override the mode's report does not read, or one its run
/// leaves inert, before any fold.
///
/// # Errors
///
/// [`OverrideError::NoReader`] or [`OverrideError::Inert`].
pub fn check_reach(
    overrides: &[Override],
    run: &Baseline,
    mode: &'static str,
    reads: &[Reader],
) -> Result<(), OverrideError> {
    for o in overrides {
        let path = o.path();
        let Some(reader) = reads.iter().find(|r| r.path == path) else {
            return Err(OverrideError::NoReader { path, mode });
        };
        if let Some(condition) = reader.only_if {
            if (condition.inert)(run) {
                return Err(OverrideError::Inert {
                    path,
                    mode,
                    why: condition.inert_while,
                });
            }
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The header every report starts with: the three digests of the
/// production baseline the run starts from, and the run's overrides, one
/// per line, or `(none)`. The digests name the baseline, not the run: the
/// consensus digest is over the shipped files, which no override edits,
/// so the overrides are what distinguish a run from its baseline.
///
/// # Errors
///
/// The sink's.
pub fn write_header(out: &mut impl fmt::Write, overrides: &[Override]) -> fmt::Result {
    let shipped = Baseline::shipped();
    writeln!(
        out,
        "baseline params digest:    {}",
        hex(&shekyl_economics::params_digest(&shipped.economic))
    )?;
    writeln!(
        out,
        "baseline consensus digest: {}",
        shekyl_rpc_types::CONSENSUS_CONSTANTS_DIGEST
    )?;
    writeln!(
        out,
        "baseline relay digest:     {}",
        hex(&shekyl_economics::relay_policy_digest(&shipped.relay))
    )?;
    if overrides.is_empty() {
        writeln!(out, "overrides: (none)")?;
    } else {
        writeln!(out, "overrides:")?;
        for o in overrides {
            writeln!(out, "  {o}")?;
        }
    }
    writeln!(out)
}

/// A sweep cell's report beside its baseline's, line by line. A line the
/// cell shares with the baseline is printed as it is. A line that differs
/// is printed as the cell's, then the baseline's beside it, then each
/// number that moved as `baseline → cell (Δ)`. A cell whose overrides
/// change nothing prints its report unchanged, byte for byte.
#[must_use]
pub fn beside_baseline(cell: &str, baseline: &str) -> String {
    let mut out = String::new();
    let cell_lines: Vec<&str> = cell.lines().collect();
    let base_lines: Vec<&str> = baseline.lines().collect();
    for i in 0..cell_lines.len().max(base_lines.len()) {
        match (cell_lines.get(i), base_lines.get(i)) {
            (Some(c), Some(b)) if c == b => {
                out.push_str(c);
                out.push('\n');
            }
            (c, b) => {
                let c = c.copied().unwrap_or("");
                let b = b.copied().unwrap_or("");
                out.push_str(c);
                out.push('\n');
                out.push_str("    baseline: ");
                out.push_str(b);
                out.push('\n');
                let moved = number_moves(b, c);
                if !moved.is_empty() {
                    out.push_str("    moved: ");
                    out.push_str(&moved.join(", "));
                    out.push('\n');
                }
            }
        }
    }
    // `lines()` drops a final newline; keep the cell's.
    if !cell.ends_with('\n') {
        out.pop();
    }
    out
}

/// The numbers in a line, in order, as written.
fn numbers(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let starts = bytes[i].is_ascii_digit()
            || (bytes[i] == b'-'
                && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()));
        if starts {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_digit()
                    || (bytes[i] == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)))
            {
                i += 1;
            }
            found.push(&line[start..i]);
        } else {
            i += 1;
        }
    }
    found
}

/// `baseline → cell (Δ)` for each number that differs, when both lines
/// carry the same count of numbers; otherwise nothing, and the two lines
/// printed above say it.
fn number_moves(baseline: &str, cell: &str) -> Vec<String> {
    let b = numbers(baseline);
    let c = numbers(cell);
    if b.len() != c.len() {
        return Vec::new();
    }
    b.iter()
        .zip(&c)
        .filter(|(x, y)| x != y)
        .map(|(x, y)| match (x.parse::<f64>(), y.parse::<f64>()) {
            (Ok(xv), Ok(yv)) => {
                let places = y.split_once('.').map_or(0, |(_, frac)| frac.len());
                format!("{x} → {y} ({:+.places$})", yv - xv)
            }
            _ => format!("{x} → {y}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> Override {
        Override::parse(text).expect("well-formed")
    }

    #[test]
    fn the_shipped_baseline_is_the_accessors() {
        let shipped = Baseline::shipped();
        assert_eq!(&shipped.economic, shekyl_economics::economic_params());
        assert_eq!(&shipped.relay, shekyl_economics::relay_policy());
        assert_eq!(
            &shipped.archival,
            shekyl_archival_retention::archival_params()
        );
        assert_eq!(shipped.with(&[]), Ok(shipped.clone()));
    }

    /// A default-valued override is the baseline: the door writes the value
    /// it already holds and the validator passes it.
    #[test]
    fn a_default_valued_override_is_the_baseline() {
        let shipped = Baseline::shipped();
        let same = shipped
            .with(&[
                set(&format!(
                    "economic.release_min={}",
                    shipped.economic.release_min
                )),
                set(&format!(
                    "relay.fee_decimal_places={}",
                    shipped.relay.fee_decimal_places
                )),
                set(&format!(
                    "archival.failure_window_m={}",
                    shipped.archival.failure_window_m
                )),
            ])
            .expect("the shipped values pass");
        assert_eq!(same, shipped);
    }

    #[test]
    fn an_override_moves_its_field_and_nothing_else() {
        let shipped = Baseline::shipped();
        let run = shipped
            .with(&[
                set("economic.daa_target_seconds=3600"),
                set("relay.fee_decimal_places=8"),
            ])
            .expect("in band");
        assert_eq!(run.economic.daa_target_seconds, 3_600);
        assert_eq!(run.economic.blocks_per_year(), 8_760);
        assert_eq!(run.relay.fee_decimal_places, 8);
        assert_eq!(
            EconomicParams {
                daa_target_seconds: shipped.economic.daa_target_seconds,
                ..run.economic.clone()
            },
            shipped.economic
        );
        assert_eq!(
            RelayPolicy {
                fee_decimal_places: shipped.relay.fee_decimal_places,
                ..run.relay
            },
            shipped.relay
        );
        assert_eq!(run.archival, shipped.archival);
    }

    /// E16-14's door: a missing field, a refused value, a value past its
    /// field's width, and a duplicate path each fail, naming what failed.
    #[test]
    fn the_door_refuses_before_the_fold() {
        let shipped = Baseline::shipped();
        assert_eq!(
            shipped.with(&[set("economic.blocks_per_year=8760")]),
            Err(OverrideError::UnknownField {
                set: ParamSet::Economic,
                field: "blocks_per_year".into(),
                path: "economic.blocks_per_year".into(),
            })
        );
        assert!(matches!(
            shipped.with(&[set("relay.lookback_blocks=5")]),
            Err(OverrideError::UnknownField {
                set: ParamSet::Relay,
                ..
            })
        ));
        assert!(matches!(
            shipped.with(&[set("archival.failure_window_m=0")]),
            Err(OverrideError::Refused { set: ParamSet::Archival, reason })
                if reason == "failure window m is zero"
        ));
        assert!(matches!(
            shipped.with(&[set("relay.standard_over_economy=0")]),
            Err(OverrideError::Refused {
                set: ParamSet::Relay,
                ..
            })
        ));
        assert!(matches!(
            shipped.with(&[set("economic.daa_target_seconds=0")]),
            Err(OverrideError::Refused {
                set: ParamSet::Economic,
                ..
            })
        ));
        assert!(matches!(
            shipped.with(&[set("archival.failure_window_n=4294967296")]),
            Err(OverrideError::Refused {
                set: ParamSet::Archival,
                ..
            })
        ));
        assert_eq!(
            shipped.with(&[set("relay.lookback=4"), set("relay.lookback=6")]),
            Err(OverrideError::Duplicate("relay.lookback".into()))
        );
    }

    #[test]
    fn the_parser_takes_set_field_value_only() {
        assert_eq!(
            Override::parse("economic.burn_cap=1"),
            Ok(Override {
                set: ParamSet::Economic,
                field: "burn_cap".into(),
                value: 1,
            })
        );
        for bad in [
            "economic.burn_cap",
            "burn_cap=1",
            "fees.burn_cap=1",
            "economic.=1",
            "economic.burn_cap=-1",
            "economic.burn_cap=0.5",
        ] {
            assert_eq!(
                Override::parse(bad),
                Err(OverrideError::Malformed(bad.into())),
                "{bad}"
            );
        }
        assert_eq!(set("relay.lookback=6").to_string(), "relay.lookback=6");
    }

    /// The header's three digests pinned as literals: a test that rendered
    /// the constants and compared them to themselves would hold nothing. A
    /// moved digest moves this test, which is the point.
    #[test]
    fn a_baseline_runs_header_is_the_three_digests_and_no_overrides() {
        let mut header = String::new();
        write_header(&mut header, &[]).expect("String sink");
        assert_eq!(
            header,
            "baseline params digest:    5a63a1d174bf5ef7fda7bb966e3e5e1f2ec00c90c6f7374d37cf146c9238bed2\n\
             baseline consensus digest: 2227f8a01a4a47c9f42e46d3a7c01fc900d4927c03ec71bbbfc74d6be69829bd\n\
             baseline relay digest:     5f19950d8d031d0efa1f8e09f06d92c3b9a357175a9685ab7bd7fd49b45cc6b2\n\
             overrides: (none)\n\
             \n"
        );
        let mut header = String::new();
        write_header(
            &mut header,
            &[
                set("relay.fee_decimal_places=8"),
                set("economic.burn_cap=1"),
            ],
        )
        .expect("String sink");
        assert!(
            header.ends_with("overrides:\n  relay.fee_decimal_places=8\n  economic.burn_cap=1\n\n")
        );
    }

    #[test]
    fn the_reach_refuses_an_unread_or_inert_field() {
        let shipped = Baseline::shipped();
        let (mode, reads) = stage2_reach(true);
        assert_eq!(
            check_reach(&[set("relay.ref_tx_weight=4000")], &shipped, mode, reads),
            Err(OverrideError::NoReader {
                path: "relay.ref_tx_weight".into(),
                mode: "--stage2 --control-flat-fee",
            })
        );
        let (mode, reads) = stage2_reach(false);
        assert_eq!(
            check_reach(&[set("relay.ref_tx_weight=4000")], &shipped, mode, reads),
            Ok(())
        );
        assert!(matches!(
            check_reach(
                &[set("economic.escalation_knee_n=1000000")],
                &shipped,
                mode,
                reads
            ),
            Err(OverrideError::Inert { .. })
        ));
        let off_flat = shipped
            .with(&[set("economic.escalation_asymptote_share=500000")])
            .expect("in band");
        assert_eq!(
            check_reach(
                &[
                    set("economic.escalation_asymptote_share=500000"),
                    set("economic.escalation_knee_n=1000000"),
                ],
                &off_flat,
                mode,
                reads
            ),
            Ok(())
        );
        // Every declared value passes its validator.
        for (mode, reads) in [stage2_reach(false), stage2_reach(true)] {
            for r in reads {
                let mut cell =
                    vec![Override::parse(&format!("{}={}", r.path, r.moves_at))
                        .expect("well-formed")];
                if let Some(c) = r.only_if {
                    cell.push(
                        Override::parse(&format!("{}={}", c.companion.0, c.companion.1))
                            .expect("well-formed"),
                    );
                }
                assert!(
                    shipped.with(&cell).is_ok(),
                    "{mode}: {} = {}",
                    r.path,
                    r.moves_at
                );
            }
        }
    }

    /// E16-7 per mode (the review of 2026-10-30): each field a mode
    /// declares as read moves that mode's report at its declared value, on
    /// the arm it is declared for. A field whose effect needs another
    /// setting is compared against a cell with that setting alone. The
    /// cells run in parallel; each is a full `--stage2` narration.
    #[test]
    #[ignore = "one full --stage2 narration per declared field on both arms; run with --release --ignored; nightly economics-sim-ignored"]
    fn every_declared_reader_moves_its_report() {
        use crate::engine::SimParams;
        let narrate = |overrides: Vec<Override>, control: bool| -> String {
            let mut run = SimParams::with_overrides(overrides).expect("a declared value passes");
            if control {
                run.fee = SimParams::section_12_14_control().fee;
            }
            let mut out = String::new();
            crate::stage2::run_stage2(&mut out, &run).expect("String sink");
            out
        };
        let parse = |path: &str, value: u64| {
            Override::parse(&format!("{path}={value}")).expect("well-formed")
        };
        // Every narration the test needs, once: each arm's reference (the
        // baseline, or a field's companion alone) and each field's cell.
        let mut narrations: Vec<(Vec<Override>, bool)> = Vec::new();
        let mut index = |overrides: Vec<Override>, control: bool| -> usize {
            if let Some(i) = narrations
                .iter()
                .position(|(o, c)| *o == overrides && *c == control)
            {
                return i;
            }
            narrations.push((overrides, control));
            narrations.len() - 1
        };
        let mut pairs: Vec<(String, usize, usize)> = Vec::new();
        for (control, (mode, reads)) in [(false, stage2_reach(false)), (true, stage2_reach(true))] {
            for r in reads {
                let base: Vec<Override> = r
                    .only_if
                    .map(|c| vec![parse(c.companion.0, c.companion.1)])
                    .unwrap_or_default();
                let mut cell = base.clone();
                cell.push(parse(r.path, r.moves_at));
                let (b, c) = (index(base, control), index(cell, control));
                pairs.push((format!("{mode}: {}={}", r.path, r.moves_at), b, c));
            }
        }
        let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        // A cell whose fold panics is a failure named with the rest, not the
        // end of the run.
        let mut text: Vec<Option<String>> = Vec::with_capacity(narrations.len());
        for chunk in narrations.chunks(threads) {
            let done: Vec<Option<String>> = std::thread::scope(|scope| {
                let handles: Vec<_> = chunk
                    .iter()
                    .map(|(overrides, control)| {
                        scope.spawn(move || narrate(overrides.clone(), *control))
                    })
                    .collect();
                handles.into_iter().map(|h| h.join().ok()).collect()
            });
            text.extend(done);
        }
        let unmoved: Vec<String> = pairs
            .iter()
            .filter_map(|(name, b, c)| match (&text[*b], &text[*c]) {
                (Some(base), Some(cell)) if base == cell => Some(name.clone()),
                (Some(_), Some(_)) => None,
                _ => Some(format!("{name} (the fold panicked)")),
            })
            .collect();
        assert!(
            unmoved.is_empty(),
            "declared but the report did not move:\n  {}",
            unmoved.join("\n  ")
        );
    }

    #[test]
    fn a_cell_prints_each_moved_figure_beside_its_baseline() {
        let baseline = "title\nburn 12.50% at 1000 blocks\nsame 7\n";
        let cell = "title\nburn 13.75% at 1000 blocks\nsame 7\n";
        assert_eq!(
            beside_baseline(cell, baseline),
            "title\n\
             burn 13.75% at 1000 blocks\n\
             \x20   baseline: burn 12.50% at 1000 blocks\n\
             \x20   moved: 12.50 → 13.75 (+1.25)\n\
             same 7\n"
        );
        assert_eq!(beside_baseline(baseline, baseline), baseline);
        // A line whose shape changed prints both lines and no number pairs.
        assert_eq!(
            beside_baseline("a 1 2\n", "a 1\n"),
            "a 1 2\n    baseline: a 1\n"
        );
        assert_eq!(numbers("x-1 at -2.5, v3 9."), vec!["1", "-2.5", "3", "9"]);
    }
}
