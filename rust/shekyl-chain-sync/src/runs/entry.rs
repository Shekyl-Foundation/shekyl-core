// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An offered arrival's outcome, and an unsolicited announce proving
//! beside a header run. The announce is its own job. It does not replace
//! the run.

use std::time::Instant;

use shekyl_chain_rules::{
    target_claim, Fault, FormAttempt, FormedHeader, HeaderView, OpenHeader, RuleSet,
};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_wire::{Block, BlockBody, PowBlob, TxBody};

use super::{retry_of, Judged, WallClock};
use crate::model::{
    BoundArrival, CachePlan, CloseCause, Command, HashClass, Job, Outcome, ProveItem, Proved, Sync,
};
use crate::peer::Announced;

impl<K, R> Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(BlockHeight) -> RuleSet,
{
    pub(crate) fn on_entry<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        tag: u64,
        outcome: Outcome,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        // The tag is the arrival. An unknown tag names nothing we offered,
        // so it closes no session.
        let Some(pos) = self
            .outstanding
            .iter()
            .position(|arrival| arrival.tag == tag)
        else {
            return Ok(());
        };
        let arrival = self.outstanding.remove(pos);
        let session = arrival.session;
        let hash = arrival.header.hash();
        match outcome {
            Outcome::Connected { relay } => {
                self.accepted.insert(hash);
                if relay {
                    out.push(Command::Relay { hash });
                }
            }
            Outcome::Refused { verdict } => {
                self.tree.mark_invalid(hash);
                self.prune_served();
                self.reselect(main)?;
                self.close(session, CloseCause::BlockRefused(verdict), out);
            }
            Outcome::PromotionRefused { verdict, block } => {
                // The switch refused an ancestor. Invalidate that hash.
                // Close the session that supplied it, when it is still known.
                self.tree.mark_invalid(block);
                let supplier = self.served.remove(&block);
                self.prune_served();
                self.reselect(main)?;
                if let Some(supplier) = supplier {
                    if self.peers.contains_key(&supplier) {
                        self.close(supplier, CloseCause::BlockRefused(verdict), out);
                    }
                }
            }
            Outcome::Oversize { invalidate } => {
                if invalidate {
                    self.tree.mark_invalid(hash);
                    self.prune_served();
                    self.reselect(main)?;
                }
                self.close(session, CloseCause::Oversize, out);
            }
            Outcome::Unlinked { at } => {
                if let Some(state) = self.peers.get_mut(&session) {
                    state.gates.header_quiet = false;
                }
                self.locate(session, at, now, out);
            }
            Outcome::BeyondCap => {
                if let Some(state) = self.peers.get_mut(&session) {
                    state.gates.header_quiet = false;
                }
            }
            Outcome::MissingBodies { indices } => {
                out.push(Command::RequestMissingTxs {
                    session,
                    block: hash,
                    indices,
                });
            }
            Outcome::NoRoom => {
                // The allowance that authorized the offer was already spent.
                // Freeze it until the entry reports a new one.
                self.seats = Some(0);
                self.held.push(arrival);
            }
            // The entry already holds this body, so the walk treats it as present.
            Outcome::Noted => {
                self.accepted.insert(hash);
            }
            // The entry handed the arrival back. The seat the offer spent
            // is free, and the next plan asks for the body again.
            Outcome::Again | Outcome::Throttled => {
                self.seats = self.seats.map(|seats| seats.saturating_add(1));
            }
        }
        Ok(())
    }

    pub(crate) fn on_room(&mut self, seats: u32, out: &mut Vec<Command<K>>) {
        self.seats = Some(seats);
        self.flush_offers(out);
    }

    pub(crate) fn on_announce<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        session: K,
        body: &BlockBody,
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        if !self.peers.contains_key(&session) {
            return Ok(());
        }
        // One unproved announce per session. A second is not stored and
        // does not close: the peer has not failed a universal rule.
        if self
            .peers
            .get(&session)
            .is_some_and(|peer| !peer.announced.is_empty())
        {
            return Ok(());
        }
        let Ok(parsed) = Block::from_bytes(&body.block) else {
            return Ok(());
        };
        let Ok(pow) = PowBlob::read(&parsed.pow_blob()) else {
            return Ok(());
        };
        let parent = pow.header.previous;
        if !self.tree.contains(parent) && self.local.is_none_or(|local| local.hash != parent) {
            return Ok(());
        }
        let parent_height = self
            .tree
            .placement(parent)
            .map(|placed| placed.height)
            .or_else(|| self.local.and_then(|local| local.height))
            .unwrap_or(BlockHeight::ZERO);
        let view = self.view_for(main, parent, parent_height, &[]);
        let connecting = view
            .tip()?
            .map(|tip| tip.height + BlockCount::ONE)
            .unwrap_or(BlockHeight::ZERO);
        let seed = Self::seed_of(&view, connecting)?;
        let rule = (self.rules)(connecting);
        let target = match target_claim(&view, connecting, &rule) {
            Ok(Ok(target)) => target,
            Ok(Err(refused)) => {
                self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                return Ok(());
            }
            Err(Fault::View(fault)) => return Err(fault),
            Err(Fault::Stale(_) | Fault::Corrupt(_)) => return Ok(()),
        };
        let open = OpenHeader::from_pow(&pow, seed, target, FormAttempt::FIRST);
        let prospect = match shekyl_chain_rules::judge_header_cheap(
            &open,
            &view,
            &rule,
            &self.trust,
            &WallClock(self.wall),
        ) {
            Ok(Ok(prospect)) => prospect,
            Ok(Err(refused)) => {
                self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                return Ok(());
            }
            Err(fault) => match fault {
                shekyl_chain_rules::ProspectFault::Chain(Fault::View(fault)) => return Err(fault),
                _ => return Ok(()),
            },
        };
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let item = ProveItem {
            pow: pow.write(),
            seed,
            target,
            attempt: FormAttempt::FIRST,
            rule_set: rule,
        };
        if let Some(peer) = self.peers.get_mut(&session) {
            peer.announced.push(Announced {
                job: id,
                pow,
                seed,
                target,
                rule,
                attempt: FormAttempt::FIRST,
                body: body.clone(),
                height: prospect.connecting,
            });
        }
        out.push(Command::Prove {
            job: Job::from_raw(id),
            class: HashClass::Unsolicited,
            cache: CachePlan::Main(seed),
            items: vec![item],
        });
        Ok(())
    }

    pub(super) fn announce_for(&self, job: u64) -> Option<K> {
        self.peers.iter().find_map(|(key, peer)| {
            peer.announced
                .iter()
                .any(|item| item.job == job)
                .then_some(*key)
        })
    }

    fn take_announce(&mut self, session: K, job: u64) -> Option<Announced> {
        let peer = self.peers.get_mut(&session)?;
        let index = peer.announced.iter().position(|item| item.job == job)?;
        Some(peer.announced.remove(index))
    }

    pub(super) fn on_announced_proved<'id, H: HeaderView<'id>>(
        &mut self,
        main: &H,
        job: Job,
        results: &[Proved],
        out: &mut Vec<Command<K>>,
    ) -> Result<(), H::Fault> {
        let Some(session) = self.announce_for(job.raw()) else {
            return Ok(());
        };
        let Some(mut announced) = self.take_announce(session, job.raw()) else {
            return Ok(());
        };
        let Some(result) = results.first() else {
            return Ok(());
        };
        match result {
            Proved::Refused(refused) => {
                self.close(session, CloseCause::HeaderRefused(refused.rule), out);
                Ok(())
            }
            Proved::Formed(formed) => {
                let parent = formed.previous();
                match self.judge_standalone(main, parent, formed) {
                    Judged::View(fault) => {
                        if let Some(peer) = self.peers.get_mut(&session) {
                            peer.announced.push(announced);
                        }
                        Err(fault)
                    }
                    Judged::Refused(row) => {
                        self.close(session, CloseCause::HeaderRefused(row), out);
                        Ok(())
                    }
                    Judged::Gone => Ok(()),
                    Judged::Stale(stale) => {
                        if let Some(next) = retry_of(&stale) {
                            announced.attempt = next;
                            let id = self.next_id;
                            self.next_id = self.next_id.saturating_add(1);
                            announced.job = id;
                            let item = ProveItem {
                                pow: announced.pow.write(),
                                seed: announced.seed,
                                target: announced.target,
                                attempt: next,
                                rule_set: announced.rule,
                            };
                            let seed = announced.seed;
                            if let Some(peer) = self.peers.get_mut(&session) {
                                peer.announced.push(announced);
                            }
                            out.push(Command::Prove {
                                job: Job::from_raw(id),
                                class: HashClass::Unsolicited,
                                cache: CachePlan::Main(seed),
                                items: vec![item],
                            });
                        }
                        Ok(())
                    }
                    Judged::Ok(header) => {
                        let header = *header;
                        let hash = header.hash();
                        let height = announced.height;
                        let body = announced.body;
                        self.tree.insert(header);
                        self.reselect(main)?;
                        if let Some(peer) = self.peers.get_mut(&session) {
                            let higher = peer
                                .frontier
                                .is_none_or(|(have, _)| height.to_raw() >= have.to_raw());
                            if higher {
                                peer.frontier = Some((height, hash));
                            }
                        }
                        self.finish_announced(session, hash, &body, out);
                        Ok(())
                    }
                }
            }
        }
    }

    /// Bind an announced body to the header now in `T`. A short body asks
    /// for the missing transactions. A body that does not match closes the
    /// session and leaves the header.
    fn finish_announced(
        &mut self,
        session: K,
        hash: BlockHash,
        body: &BlockBody,
        out: &mut Vec<Command<K>>,
    ) {
        let Some(judged) = self.judged_in_tree(hash) else {
            return;
        };
        let listed = Block::from_bytes(&body.block)
            .map(|block| block.transaction_hashes.len())
            .unwrap_or(0);
        if body.txs.len() < listed {
            let start = u64::try_from(body.txs.len()).unwrap_or(0);
            let end = u64::try_from(listed).unwrap_or(start);
            out.push(Command::RequestMissingTxs {
                session,
                block: hash,
                indices: (start..end).collect(),
            });
            return;
        }
        if let Err(refused) = shekyl_chain_rules::bind_body(&judged, body) {
            self.close(session, CloseCause::Bind(refused.rule), out);
            return;
        }
        if body.txs.iter().any(|tx| matches!(tx, TxBody::Skeleton(_))) {
            if let Some(peer) = self.peers.get_mut(&session) {
                peer.inventory.skeleton.insert(hash);
            }
            return;
        }
        let tag = self.next_tag;
        self.next_tag = self.next_tag.saturating_add(1);
        self.held.push(BoundArrival {
            tag,
            session,
            header: judged,
            body: body.clone(),
        });
        self.flush_offers(out);
    }

    pub(crate) fn prune_served(&mut self) {
        let live = |hash: &BlockHash| self.tree.contains(*hash) && !self.tree.remembers(*hash);
        self.served.retain(|hash, _| live(hash));
        self.accepted.retain(live);
    }

    fn judge_standalone<'id, H: HeaderView<'id>>(
        &self,
        main: &H,
        parent: BlockHash,
        formed: &FormedHeader,
    ) -> Judged<H::Fault> {
        let parent_height = self
            .tree
            .placement(parent)
            .map(|placed| placed.height)
            .or_else(|| {
                self.local
                    .filter(|local| local.hash == parent)
                    .and_then(|local| local.height)
            })
            .unwrap_or(BlockHeight::ZERO);
        let view = self.view_for(main, parent, parent_height, &[]);
        match shekyl_chain_rules::judge_header(formed, &view, &formed.rule_set(), &self.trust) {
            Ok(Ok(judged)) => Judged::Ok(Box::new(judged)),
            Ok(Err(refused)) => Judged::Refused(refused.rule),
            Err(Fault::View(fault)) => Judged::View(fault),
            Err(Fault::Stale(stale)) => Judged::Stale(Box::new(stale)),
            Err(Fault::Corrupt(_)) => Judged::Gone,
        }
    }
}
