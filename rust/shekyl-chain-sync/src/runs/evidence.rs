// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The long-run slot, a challenge of that slot, and the one evidence
//! check. Each is a mode of one peer. The coordinator draws the check.
//! The transition lives here.

use shekyl_chain_rules::{seed_height, RuleSet};
use shekyl_difficulty::{CumulativeDifficulty, MTP_WINDOW_USIZE, N_USIZE};
use shekyl_draw_rng::RelayRng;
use shekyl_types::{BlockCount, BlockHeight};

use super::fork_depth;
use crate::model::{draw_one, Command, HashClass, Sync};

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    pub(crate) fn alarm_from_tree(&mut self, out: &mut Vec<Command<K>>) {
        if self.alarm_sent {
            return;
        }
        let Some(local) = self.local else {
            return;
        };
        let cap = self.cap();
        let Some(height) = local.height else {
            return;
        };
        for hash in self.tree.tip_hashes() {
            let Some(placed) = self.tree.placement(hash) else {
                continue;
            };
            let depth = fork_depth(Some(height), placed.fork);
            let work = self
                .tree
                .record(hash)
                .map(|r| r.cumulative_difficulty)
                .unwrap_or(CumulativeDifficulty::ZERO);
            if work > local.work && depth > cap {
                out.push(Command::RaiseAlarm {
                    fork_at: placed.fork,
                    tip: hash,
                    work,
                });
                self.alarm_sent = true;
                self.tree.mark_invalid(hash);
                return;
            }
        }
    }

    pub(super) fn evidence_alarm(&mut self, session: K, out: &mut Vec<Command<K>>) {
        let Some(run) = self.peers.get(&session).and_then(|s| s.run.as_ref()) else {
            return;
        };
        if !run.is_evidence() {
            return;
        }
        let Some(work) = run
            .chain
            .checked
            .get(run.chain.proven.saturating_sub(1))
            .map(|c| c.work)
        else {
            return;
        };
        let local = self
            .local
            .map(|l| l.work)
            .unwrap_or(CumulativeDifficulty::ZERO);
        if work > local && !self.alarm_sent {
            out.push(Command::RaiseAlarm {
                fork_at: run.chain.parent_height,
                tip: run.chain.checked[run.chain.proven - 1].hash,
                work,
            });
            self.alarm_sent = true;
            self.drop_run(session);
        }
    }

    pub(super) fn note_evidence(&mut self, session: K) {
        let Some(state) = self.peers.get_mut(&session) else {
            return;
        };
        if self.alarm || state.gates.evidence_spent {
            return;
        }
        let local = self
            .local
            .map(|l| l.work)
            .unwrap_or(CumulativeDifficulty::ZERO);
        let heavier = state
            .run
            .as_ref()
            .and_then(|run| run.chain.checked.last())
            .is_some_and(|c| c.work > local);
        if heavier {
            if let Some(run) = state.run.as_mut() {
                run.nominate();
            }
        }
    }

    /// One evidence check, drawn uniformly from the waiting candidates.
    /// Nothing is drawn while the latch is set, or while a check runs.
    pub(crate) fn start_evidence(&mut self, rng: &mut impl RelayRng, out: &mut Vec<Command<K>>) {
        if self.alarm || self.evidence_holder().is_some() {
            return;
        }
        let candidates: Vec<K> = self
            .peers
            .iter()
            .filter(|(_, state)| {
                !state.gates.evidence_spent
                    && state
                        .run
                        .as_ref()
                        .is_some_and(crate::peer::Run::is_candidate)
            })
            .map(|(session, _)| *session)
            .collect();
        let Some(session) = draw_one(rng, &candidates) else {
            return;
        };
        if let Some(state) = self.peers.get_mut(&session) {
            state.gates.evidence_spent = true;
            if let Some(run) = state.run.as_mut() {
                run.begin_evidence();
            }
        }
        self.plan_proof(session, HashClass::Evidence, out);
    }

    pub(super) fn past_bound(&self, session: K, cap: BlockCount) -> bool {
        let Some(run) = self.peers.get(&session).and_then(|s| s.run.as_ref()) else {
            return false;
        };
        let depth = fork_depth(
            self.local.and_then(|local| local.height),
            run.chain.parent_height,
        );
        let bound = depth.to_raw().saturating_add(cap.to_raw());
        // Trimmed runs no longer hold every header. The bound is on the
        // height the run has reached, which the window still names.
        let reached = run
            .chain
            .checked
            .last()
            .map(|c| {
                c.height
                    .to_raw()
                    .saturating_sub(run.chain.parent_height.to_raw())
            })
            .unwrap_or(0);
        reached > bound
    }

    /// A past-cap run keeps the window the branch view reads: the LWMA
    /// window, the median, and the seed headers those heights name.
    pub(super) fn trim_window(&mut self, session: K) {
        let Some(run) = self.peers.get_mut(&session).and_then(|s| s.run.as_mut()) else {
            return;
        };
        if !run.past_cap() {
            return;
        }
        let tail = N_USIZE.max(MTP_WINDOW_USIZE).saturating_add(1);
        if run.chain.checked.len() <= tail {
            return;
        }
        let mut from = run.chain.checked.len() - tail;
        let seeds: Vec<BlockHeight> = run.chain.checked[from..]
            .iter()
            .filter_map(|c| seed_height(c.height))
            .collect();
        for seed in seeds {
            if let Some(idx) = run.chain.checked.iter().position(|c| c.height == seed) {
                from = from.min(idx);
            }
        }
        if from == 0 {
            return;
        }
        run.chain.checked.drain(..from);
        run.chain.proven = run.chain.proven.saturating_sub(from);
    }

    pub(super) fn settle_challenge(&mut self, session: K) {
        let ready = self
            .peers
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .is_some_and(|run| {
                run.is_challenging()
                    && run.chain.proven > 0
                    && run.chain.proven >= run.chain.checked.len()
            });
        if !ready {
            return;
        }
        let frontier = self
            .peers
            .get(&session)
            .and_then(|s| s.run.as_ref())
            .and_then(|run| run.chain.checked.get(run.chain.proven - 1))
            .map(|c| (c.height, c.work));
        let Some((height, work)) = frontier else {
            return;
        };
        let holder = self.slot_holder().filter(|holder| *holder != session);
        let holder_work = holder.and_then(|holder| {
            self.peers
                .get(&holder)
                .and_then(|s| s.run.as_ref())
                .and_then(|run| {
                    run.chain
                        .checked
                        .iter()
                        .enumerate()
                        .find(|(index, c)| c.height == height && *index < run.chain.proven)
                        .map(|(_, c)| c.work)
                })
        });
        let take = holder_work.is_none_or(|held| work > held);
        if !take {
            if let Some(state) = self.peers.get_mut(&session) {
                state.gates.header_quiet = true;
                state.run = None;
            }
            return;
        }
        if let Some(holder) = holder {
            let cap_headers = usize::try_from(self.cap().to_raw()).unwrap_or(1);
            if let Some(state) = self.peers.get_mut(&holder) {
                if let Some(run) = state.run.as_mut() {
                    run.release_slot();
                    run.chain.checked.truncate(cap_headers);
                    run.chain.proven = run.chain.proven.min(run.chain.checked.len());
                }
            }
        }
        if let Some(run) = self.peers.get_mut(&session).and_then(|s| s.run.as_mut()) {
            run.enter_slot();
        }
    }

    pub(super) fn consider_slot(&mut self, session: K, out: &mut Vec<Command<K>>) {
        // The first run to fill its budget takes the slot by verifying
        // its prefix. A later run verifies its own prefix first; the
        // comparison is that verified work, at its frontier height.
        let vacant = self.slot_holder().is_none();
        if let Some(run) = self.peers.get_mut(&session).and_then(|s| s.run.as_mut()) {
            if vacant {
                run.enter_slot();
            } else {
                run.enter_challenge();
            }
        }
        self.plan_proof(session, HashClass::HeaderPow, out);
    }
}
