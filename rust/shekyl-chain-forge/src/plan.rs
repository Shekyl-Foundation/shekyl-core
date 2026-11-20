// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A forge plan: the chain's name, its seed, its network and schedule, and
//! its steps in order (`CHAIN_FORGE.md` §11.2).
//!
//! Each step is a call the executor has a production path for. A lane that
//! needs a new kind of block adds a step kind here and to the executor, not
//! a harness of its own. A step may name an event; the manifest indexes the
//! event at the block that completed the step, and a consumer asks for the
//! chain up to that name, never for a height.
//!
//! Values the plan does not write are derived, and stay derived: `"settled"`
//! is the settled schedule's epoch length, computed when the chain is
//! forged, and the manifest records the number it produced.

use serde::{Deserialize, Serialize};

use crate::seed::{PlanSeed, SeedFault};

/// A plan as written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The chain's name.
    pub chain: String,
    /// The seed, 64 hex digits.
    pub seed: String,
    /// The network. Only `regtest` is accepted (`CHAIN_FORGE.md` §6).
    pub network: String,
    /// The fixed difficulty. Only 1 is accepted until the LWMA chain
    /// (`CF-6`) adds live difficulty.
    pub fixed_difficulty: u64,
    /// The settlement schedule.
    pub schedule: Schedule,
    /// Seconds between consecutive blocks' timestamps, from regtest's
    /// genesis. A fixed-difficulty chain's rules read heights, not times, so
    /// the spacing moves no verdict; it is written because it moves every
    /// block's bytes. A short spacing keeps a chain's timestamps behind any
    /// real clock: a trace is replayed under the node's own clock, which
    /// refuses a block stamped past it (CEN-C1), so a chain stamped ahead of
    /// the wall clock would replay or not depending on when it was forged.
    pub block_seconds: u64,
    /// The steps, in order.
    #[serde(rename = "step")]
    pub steps: Vec<Step>,
}

/// The settlement schedule a plan asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Blocks per settlement epoch.
    pub settlement_epoch_blocks: EpochBlocks,
    /// The reorg cap, strictly inside the epoch.
    pub reorg_cap_blocks: u64,
}

/// A settlement epoch's length: derived, or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EpochBlocks {
    /// The settled schedule's derived length (`settled_epoch_blocks()`): the
    /// shortest epoch in which every drawable pair is guaranteed its counted
    /// draws.
    Settled,
    /// A length the plan writes.
    #[serde(untagged)]
    Blocks(u64),
}

/// One step: an optional event name and what to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The event this step completes, indexed in the manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// What the step does.
    #[serde(flatten)]
    pub action: Action,
}

/// What a step does. Every randomness source of `CHAIN_FORGE.md` §5.2 that
/// the step reaches draws from the plan's seed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    /// Mine `blocks` blocks that list nothing.
    Mine {
        /// How many.
        blocks: u64,
    },
    /// The miner spends `inputs` of its matured coinbases, oldest unspent
    /// first, in one transaction to itself (S1, S2 when `inputs` > 1, S3,
    /// S5, S6), and the next block lists it.
    Spend {
        /// Inputs, 1 to the wire's limit.
        inputs: u32,
    },
    /// Real spends of the miner's coinbases, built across threads, until
    /// `count` shards are closed (S9, and S1–S6 in every spend).
    FillShards {
        /// Shards closed when the step ends.
        count: u64,
    },
    /// Persona `persona` is funded by a coinbase spend that carries its
    /// compact join of `shards`, at the first height the join is
    /// admissible (S5 for its bond slot).
    Join {
        /// The persona's slot in the plan.
        persona: u32,
        /// The closed shards it holds.
        shards: Vec<u64>,
    },
    /// Mine through the end of the first epoch persona `persona` is drawn
    /// in (the epoch after its join's), each block's draws committed (S7),
    /// each drawing block's bundle filed with every draw passing, receipts
    /// signed by the holder (S8), and admitted by the next block.
    Serve {
        /// The persona's slot in the plan.
        persona: u32,
    },
    /// Persona `persona` claims its reward for the epoch it served, in the
    /// first block after that epoch's slash pass (S4, and S1–S6 on its fee
    /// side). The chain's only bond, shard and served pair are the
    /// persona's: the claim's terms are the close's arithmetic over them.
    Claim {
        /// The persona's slot in the plan.
        persona: u32,
    },
    /// Persona `persona` serves its shard on the production serve loop
    /// over loopback, the bundle producer's own task reads it and files
    /// the bundles, and the chain mines through the slash pass of the first
    /// epoch the persona is drawn in: a producer plan (`CHAIN_FORGE.md`
    /// §4, the producer audit). Every input the audit classes as drawn
    /// comes from the plan's seed; a run in which any read stalled is
    /// refused.
    Produce {
        /// The persona's slot in the plan.
        persona: u32,
        /// The spread each read's start delay is drawn below, in
        /// milliseconds. An input to the chain's bytes: the producer draws
        /// its start delays from the stream its read plans come from, and
        /// how much of the stream a draw below the spread takes depends on
        /// the spread, so another spread moves a later read plan.
        start_spread_ms: u64,
    },
    /// A competing branch of `depth + 1` blocks from `depth` below the tip,
    /// the first listing a spend the branch it competes with did not: a
    /// shallow reorg, written as `offer` records the replay's fork choice
    /// switches to (`CHAIN_FORGE.md` §7.1).
    Reorg {
        /// Blocks popped; at most the schedule's reorg cap.
        depth: u64,
    },
}

/// Why a plan was refused.
#[derive(Debug, thiserror::Error)]
pub enum PlanFault {
    /// Not a plan's TOML.
    #[error("plan: {0}")]
    Toml(#[from] toml::de::Error),
    /// The seed did not parse.
    #[error("plan: {0}")]
    Seed(#[from] SeedFault),
    /// A network other than regtest.
    #[error("plan: a forged chain is regtest's, not {0:?}'s")]
    Network(String),
    /// A block spacing of zero.
    #[error("plan: block_seconds is at least 1")]
    BlockSeconds,
    /// A difficulty this increment does not forge.
    #[error("plan: fixed difficulty {0}; only 1 is forged until the LWMA chain")]
    Difficulty(u64),
    /// Two steps name one event.
    #[error("plan: the event {0:?} is named twice")]
    DuplicateEvent(String),
    /// A `fill-shards` step that names an event: a fill names its own, one
    /// `shard-<k>-closed` per shard it closes.
    #[error("plan: a fill-shards step names its events itself (shard-<k>-closed), so it takes no `event`")]
    FillNamesItsEvents,
    /// A step that names an event of the fill's form.
    #[error("plan: the event {0:?} has the form a fill names its closes with (shard-<k>-closed)")]
    FillEventName(String),
    /// A plan with nothing to do.
    #[error("plan: no steps")]
    Empty,
}

impl Plan {
    /// Parse and check a plan's text.
    ///
    /// # Errors
    ///
    /// [`PlanFault`].
    pub fn parse(text: &str) -> Result<Self, PlanFault> {
        let plan: Self = toml::from_str(text)?;
        plan.seed()?;
        if plan.network != "regtest" {
            return Err(PlanFault::Network(plan.network));
        }
        if plan.fixed_difficulty != 1 {
            return Err(PlanFault::Difficulty(plan.fixed_difficulty));
        }
        if plan.block_seconds == 0 {
            return Err(PlanFault::BlockSeconds);
        }
        if plan.steps.is_empty() {
            return Err(PlanFault::Empty);
        }
        for step in &plan.steps {
            match (&step.action, &step.event) {
                (Action::FillShards { .. }, Some(_)) => return Err(PlanFault::FillNamesItsEvents),
                (_, Some(name)) if is_close_event(name) => {
                    return Err(PlanFault::FillEventName(name.clone()))
                }
                _ => {}
            }
        }
        let mut events = std::collections::BTreeSet::new();
        for name in plan.steps.iter().filter_map(|step| step.event.as_ref()) {
            if !events.insert(name) {
                return Err(PlanFault::DuplicateEvent(name.clone()));
            }
        }
        Ok(plan)
    }

    /// The plan's seed.
    ///
    /// # Errors
    ///
    /// [`SeedFault`] when it is not 64 hex digits.
    pub fn seed(&self) -> Result<PlanSeed, SeedFault> {
        PlanSeed::from_hex(&self.seed)
    }
}

/// The event a fill records when shard `shard` closes: the block whose fold
/// first counted it closed (`CHAIN_FORGE.md` §11.2). A reader takes a
/// shard's close height from the manifest's event of this name.
#[must_use]
pub fn close_event(shard: u64) -> String {
    format!("shard-{shard}-closed")
}

/// Whether `name` has a fill's close-event form, `shard-<k>-closed`.
#[must_use]
pub fn is_close_event(name: &str) -> bool {
    name.strip_prefix("shard-")
        .and_then(|rest| rest.strip_suffix("-closed"))
        .is_some_and(|k| !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAN: &str = r#"
chain = "small"
seed = "0000000000000000000000000000000000000000000000000000000000000001"
network = "regtest"
fixed_difficulty = 1
block_seconds = 1
schedule = { settlement_epoch_blocks = "settled", reorg_cap_blocks = 10 }

[[step]]
do = "mine"
blocks = 3

[[step]]
event = "first-two-in-spend"
do = "spend"
inputs = 2

[[step]]
do = "fill-shards"
count = 1

[[step]]
event = "first-join"
do = "join"
persona = 0
shards = [0]

[[step]]
do = "serve"
persona = 0

[[step]]
event = "first-claim"
do = "claim"
persona = 0

[[step]]
event = "reorg-shallow"
do = "reorg"
depth = 2

[[step]]
do = "produce"
persona = 0
start_spread_ms = 50
"#;

    #[test]
    fn a_plan_parses_every_step_kind() {
        let plan = Plan::parse(PLAN).expect("parses");
        assert_eq!(plan.schedule.settlement_epoch_blocks, EpochBlocks::Settled);
        assert_eq!(plan.steps.len(), 8);
        assert_eq!(
            plan.steps[7].action,
            Action::Produce {
                persona: 0,
                start_spread_ms: 50
            }
        );
        assert_eq!(plan.steps[1].action, Action::Spend { inputs: 2 });
        assert_eq!(plan.steps[1].event.as_deref(), Some("first-two-in-spend"));
        assert_eq!(plan.steps[6].action, Action::Reorg { depth: 2 });
        let written = PLAN.replace("\"settled\"", "20");
        let plan = Plan::parse(&written).expect("a written length parses");
        assert_eq!(
            plan.schedule.settlement_epoch_blocks,
            EpochBlocks::Blocks(20)
        );
    }

    #[test]
    fn a_plan_off_regtest_or_with_a_bad_seed_is_refused() {
        assert!(matches!(
            Plan::parse(&PLAN.replace("\"regtest\"", "\"mainnet\"")),
            Err(PlanFault::Network(_))
        ));
        assert!(matches!(
            Plan::parse(&PLAN.replace("fixed_difficulty = 1", "fixed_difficulty = 2")),
            Err(PlanFault::Difficulty(2))
        ));
        assert!(matches!(
            Plan::parse(&PLAN.replace("0001\"", "01\"")),
            Err(PlanFault::Seed(_))
        ));
        assert!(matches!(
            Plan::parse(&PLAN.replace("first-claim", "first-join")),
            Err(PlanFault::DuplicateEvent(_))
        ));
        assert!(Plan::parse(&PLAN.replace("blocks = 3", "blocks = 3\nextra = 1")).is_err());
        assert!(Plan::parse(&PLAN.replace("do = \"mine\"", "do = \"smelt\"")).is_err());
        assert!(matches!(
            Plan::parse(&PLAN.replace("block_seconds = 1", "block_seconds = 0")),
            Err(PlanFault::BlockSeconds)
        ));
    }

    #[test]
    fn a_fill_names_its_closes_and_no_step_takes_that_form() {
        assert!(matches!(
            Plan::parse(&PLAN.replace(
                "do = \"fill-shards\"",
                "event = \"filled\"\ndo = \"fill-shards\""
            )),
            Err(PlanFault::FillNamesItsEvents)
        ));
        assert!(matches!(
            Plan::parse(&PLAN.replace("first-join", "shard-3-closed")),
            Err(PlanFault::FillEventName(name)) if name == "shard-3-closed"
        ));
        assert_eq!(close_event(2), "shard-2-closed");
        assert!(is_close_event("shard-12-closed"));
        for not in [
            "shard--closed",
            "shard-x-closed",
            "shard-1-open",
            "shard-1-closed-2",
        ] {
            assert!(!is_close_event(not), "{not}");
        }
    }
}
