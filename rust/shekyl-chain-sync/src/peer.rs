// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One peer's sync conversation.
//!
//! The coordinator ([`crate::model::Sync`]) decides whom to ask, how much
//! to ask for, and when this node is synced. This module is the other
//! machine: the phase of a single peer. A mode carries only the data that
//! mode uses, so a past-cap window cannot hold a proof and a slot's
//! withheld headers cannot exist on a run that joins `T`.
//!
//! The conversation is not one exclusive phase. A header run, that run's
//! follow-up request, a body span, and an unsolicited announce are
//! independent tracks, and a peer may hold more than one at once. What is
//! exclusive is the run's mode.
//!
//! The connector finishes the handshake and then emits `SessionOpened`.
//! There is no handshaking mode here. `Synced` is the coordinator's
//! derived state, not a peer's. A session that fails a universal rule is
//! removed; a missed deadline is not that failure.

use std::collections::BTreeSet;
use std::time::Duration;

use shekyl_chain_rules::{seed_height, FormAttempt, HeaderJudged, RuleSet, Target};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{BlockBody, PowBlob};

use crate::claim::PeerClaim;
use crate::model::CachePlan;

/// What this peer has said about bodies, apart from any one run.
#[derive(Default)]
pub(crate) struct Inventory {
    /// The peer reported the block missing.
    pub unavailable: BTreeSet<BlockHash>,
    /// Held by the peer, past the body budget.
    pub deferred: BTreeSet<BlockHash>,
    /// Served as a skeleton while this node keeps the full bytes.
    pub skeleton: BTreeSet<BlockHash>,
}

/// Gates that outlive a mode. Each clears on its own event.
#[derive(Clone, Copy)]
pub(crate) struct Gates {
    /// Not drawn for headers until the claim changes.
    pub header_quiet: bool,
    /// Missed a body deadline. A source again when `H*` changes.
    pub body_excluded: bool,
    /// Already followed one past-cap run. Clears when the claim changes.
    pub past_cap_followed: bool,
    /// The one evidence draw has been spent.
    pub evidence_spent: bool,
}

impl Gates {
    pub(crate) const fn open() -> Self {
        Self {
            header_quiet: false,
            body_excluded: false,
            past_cap_followed: false,
            evidence_spent: false,
        }
    }
}

/// A header request, and the heights it named.
pub(crate) struct HeaderRequest<K> {
    pub session: K,
    pub id: u64,
    pub points: Vec<(BlockHeight, BlockHash)>,
}

/// The body span this peer is serving.
pub(crate) struct BodySpan {
    pub id: u64,
    pub hashes: Vec<BlockHash>,
}

/// One CS-Q4(c) wait. `fork` is the shallowest parent height among the
/// runs that disputed `work(L)` when the first body past that fork was
/// about to be committed. `sessions` is that moment's set and does not
/// gain members later.
pub(crate) struct Dispute<K> {
    pub(crate) fork: BlockHeight,
    pub(crate) sessions: BTreeSet<K>,
}

/// An announce proving beside the header run. It does not replace the run.
pub(crate) struct Announced {
    pub job: u64,
    pub pow: PowBlob,
    pub seed: BlockHash,
    pub target: Target,
    pub rule: RuleSet,
    pub attempt: FormAttempt,
    pub body: BlockBody,
    /// The connecting height from the cheap check.
    pub height: BlockHeight,
}

/// A header this node has cheap-checked and not yet finished proving.
pub(crate) struct Checked {
    pub pow: PowBlob,
    pub hash: BlockHash,
    pub height: BlockHeight,
    pub work: shekyl_difficulty::CumulativeDifficulty,
    pub seed: BlockHash,
    pub target: Target,
    pub rule: RuleSet,
    pub header: shekyl_wire::BlockHeader,
}

/// The chain buffer every run mode shares. Proof and withheld headers
/// live on the mode, not here.
pub(crate) struct Chain {
    /// The header the run extends. Evidence re-requests from here when
    /// the cheap-check window no longer starts at the fork.
    pub parent: BlockHash,
    pub parent_height: BlockHeight,
    pub checked: Vec<Checked>,
    pub proven: usize,
    pub attempt: FormAttempt,
}

/// The run's mode. The variants that hash carry the proof job. The
/// variants that withhold headers carry those headers.
pub(crate) enum Mode {
    /// In cap. A proved header joins `T`.
    Reachable {
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// The long-run slot. Headers stay off `T` until they beat `H*`.
    Slot {
        /// Proved headers not yet admitted to `T`.
        held: Vec<HeaderJudged>,
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// Verifying a prefix to compare with the slot holder.
    Challenging {
        /// Proved headers not yet admitted to `T`.
        held: Vec<HeaderJudged>,
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
    /// Past the reorg cap. The chain keeps its window and is not hashed.
    PastCap,
    /// Past the cap, heavier than the local chain, waiting for the one draw.
    EvidenceCandidate,
    /// The evidence check. A proved header joins `T`.
    Evidence {
        /// The proof in flight, when one is.
        proof: Option<u64>,
    },
}

/// Headers received and not yet part of `T`.
pub(crate) struct Run {
    pub chain: Chain,
    mode: Mode,
}

impl Run {
    pub(crate) fn open(
        parent: BlockHash,
        parent_height: BlockHeight,
        checked: Vec<Checked>,
        past_cap: bool,
    ) -> Self {
        Self {
            chain: Chain {
                parent,
                parent_height,
                checked,
                proven: 0,
                attempt: FormAttempt::FIRST,
            },
            mode: if past_cap {
                Mode::PastCap
            } else {
                Mode::Reachable { proof: None }
            },
        }
    }

    pub(crate) fn past_cap(&self) -> bool {
        matches!(
            self.mode,
            Mode::PastCap | Mode::EvidenceCandidate | Mode::Evidence { .. }
        )
    }

    /// A reachable run with headers not yet proven. Its proof moves `H*`
    /// when it lands.
    pub(crate) fn proving_toward_star(&self) -> bool {
        matches!(self.mode, Mode::Reachable { .. }) && self.chain.proven < self.chain.checked.len()
    }

    pub(crate) fn is_slot(&self) -> bool {
        matches!(self.mode, Mode::Slot { .. })
    }

    pub(crate) fn is_challenging(&self) -> bool {
        matches!(self.mode, Mode::Challenging { .. })
    }

    pub(crate) fn is_candidate(&self) -> bool {
        matches!(self.mode, Mode::EvidenceCandidate)
    }

    pub(crate) fn is_evidence(&self) -> bool {
        matches!(self.mode, Mode::Evidence { .. })
    }

    /// The cheap-check window no longer starts at the header after the
    /// fork. An evidence check cannot hash that suffix.
    pub(crate) fn omits_fork(&self) -> bool {
        self.chain.checked.first().is_some_and(|first| {
            first.height.to_raw() > self.chain.parent_height.to_raw().saturating_add(1)
        })
    }

    /// A proved header joins `T`. Slot and challenge headers join only
    /// once they beat `H*`. A past-cap window does not join.
    pub(crate) fn joins_tree(&self, beats_star: bool) -> bool {
        match self.mode {
            Mode::Reachable { .. } | Mode::Evidence { .. } => true,
            Mode::Slot { .. } | Mode::Challenging { .. } => beats_star,
            Mode::PastCap | Mode::EvidenceCandidate => false,
        }
    }

    pub(crate) fn proof(&self) -> Option<u64> {
        match self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => proof,
            Mode::PastCap | Mode::EvidenceCandidate => None,
        }
    }

    /// Arm a proof. A window that is not hashed cannot carry one.
    pub(crate) fn arm_proof(&mut self, id: u64) -> bool {
        let slot = match &mut self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => proof,
            Mode::PastCap | Mode::EvidenceCandidate => return false,
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(id);
        true
    }

    pub(crate) fn clear_proof(&mut self) {
        if let Some(slot) = self.proof_slot() {
            *slot = None;
        }
    }

    fn proof_slot(&mut self) -> Option<&mut Option<u64>> {
        match &mut self.mode {
            Mode::Reachable { proof }
            | Mode::Slot { proof, .. }
            | Mode::Challenging { proof, .. }
            | Mode::Evidence { proof } => Some(proof),
            Mode::PastCap | Mode::EvidenceCandidate => None,
        }
    }

    pub(crate) fn push_held(&mut self, header: HeaderJudged) {
        if let Some(held) = self.held_slot() {
            held.push(header);
        }
    }

    pub(crate) fn take_held(&mut self) -> Vec<HeaderJudged> {
        self.held_slot().map(std::mem::take).unwrap_or_default()
    }

    fn held_slot(&mut self) -> Option<&mut Vec<HeaderJudged>> {
        match &mut self.mode {
            Mode::Slot { held, .. } | Mode::Challenging { held, .. } => Some(held),
            _ => None,
        }
    }

    /// Past-cap is fork geometry and it sticks. A run that was hashing
    /// drops its proof: the window is not hashed until the evidence draw.
    pub(crate) fn adopt_geometry(&mut self, past_cap: bool) {
        if !past_cap || self.past_cap() {
            return;
        }
        self.mode = Mode::PastCap;
    }

    pub(crate) fn enter_slot(&mut self) {
        let proof = self.proof();
        let held = self.take_held();
        self.mode = Mode::Slot { held, proof };
    }

    pub(crate) fn enter_challenge(&mut self) {
        let proof = self.proof();
        let held = self.take_held();
        self.mode = Mode::Challenging { held, proof };
    }

    /// The slot moved to a challenger. Keep the proof; drop withheld headers.
    pub(crate) fn release_slot(&mut self) {
        let proof = self.proof();
        self.mode = Mode::Reachable { proof };
    }

    /// Heavier than the local chain, and still only a window.
    pub(crate) fn nominate(&mut self) {
        if matches!(self.mode, Mode::PastCap) {
            self.mode = Mode::EvidenceCandidate;
        }
    }

    pub(crate) fn begin_evidence(&mut self) {
        self.mode = Mode::Evidence { proof: None };
    }
}

/// `None` is an unearned seed. It is not hashed and not charged to the peer.
pub(crate) fn cache_for(run: &Run, index: usize) -> Option<CachePlan> {
    let checked = &run.chain.checked[index];
    // The evidence check's first seed is unearned: it is a block on our
    // chain, below the fork. Every header that still names it uses the
    // evidence cache. A later seed is earned on the branch.
    if run.is_evidence()
        && run
            .chain
            .checked
            .first()
            .is_some_and(|first| first.seed == checked.seed)
    {
        return Some(CachePlan::Evidence(checked.seed));
    }
    let on_main = match seed_height(checked.height) {
        None => true,
        Some(seed_at) => seed_at.to_raw() <= run.chain.parent_height.to_raw(),
    };
    if on_main {
        return Some(CachePlan::Main(checked.seed));
    }
    let seed_at = seed_height(checked.height)?;
    let seed_index = run
        .chain
        .checked
        .iter()
        .position(|c| c.height == seed_at || c.hash == checked.seed)?;
    if seed_index < run.chain.proven && index <= run.chain.proven {
        Some(CachePlan::Branch(checked.seed))
    } else {
        None
    }
}

/// One open peer.
pub(crate) struct Peer<K> {
    pub transit: Duration,
    pub claim: Option<PeerClaim>,
    /// The highest block this peer has named.
    pub frontier: Option<(BlockHeight, BlockHash)>,
    pub gates: Gates,
    pub inventory: Inventory,
    /// The header run. Absent when this peer is not extending a fork.
    pub run: Option<Run>,
    /// This peer's own header follow-up: the run's next locator, or a
    /// relocate. The coordinator's one frontier request is not stored here.
    pub follow_up: Option<HeaderRequest<K>>,
    /// The body span this peer is serving.
    pub span: Option<BodySpan>,
    /// Announces proving beside the run.
    pub announced: Vec<Announced>,
}

impl<K> Peer<K> {
    pub(crate) fn open(transit: Duration, claim: Option<PeerClaim>) -> Self {
        Self {
            transit,
            claim,
            frontier: None,
            gates: Gates::open(),
            inventory: Inventory::default(),
            run: None,
            follow_up: None,
            span: None,
            announced: Vec::new(),
        }
    }
}
