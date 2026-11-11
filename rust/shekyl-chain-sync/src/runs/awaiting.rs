// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Blocks waiting for their bundle bodies (the switch's C3;
//! `ARCHIVAL_SERVE_CREDIT_SPEC.md` §7.5, `SCS-P27`).
//!
//! A block's section names bundles, and a body travels beside it only when
//! the sender holds it: 2008 carries references alone, and a 2014 server
//! sends the bodies it holds. A bound body whose section names a body it
//! did not carry is not offered. It waits here while the owner answers what
//! this node's body store holds and asks the sender for the rest (2016,
//! [`Command::RequestBundleBodies`]). When every reference has its body the
//! arrival is held and offered like any other.
//!
//! **No verdict while waiting.** A block waiting on its bodies is never
//! marked invalid and never stalls the tip. The wait is bounded:
//!
//! - in count, per session ([`AWAITING_PER_SESSION`]) and in total
//!   ([`AWAITING_TOTAL`]); a block past either bound does not wait: it is
//!   dropped, not refused, and asked for again like any body this node
//!   does not hold;
//! - in age ([`AWAITING_AGE`]); an expired wait is dropped, not refused.
//!   The age is read when the next event arrives, so a wait ends at the
//!   first event at or after it.
//!
//! Each waiting entry pins one bound block body, so the memory the set can
//! hold is [`AWAITING_TOTAL`] block bodies.
//!
//! **A bound holds back the new block; it never evicts a wait.** Every
//! wait has an ask out, and the owner closes a session that has
//! [`AWAITING_PER_SESSION`] asks unanswered when it is asked again. A wait
//! dropped while its ask is still out would let this model ask that
//! session once more than the owner allows, so one 2014 answer carrying
//! five such blocks would close an honest server. Held back instead, a
//! session's asks never outnumber its waits, and a wait is dropped with its
//! ask unanswered only at [`AWAITING_AGE`]: the owner closes a session only
//! for an ask it left that long. A span's lowest blocks, which connect
//! first, keep their waits. A waiting block is not put in another body
//! span while its bundle bodies are asked for, and a copy that carries
//! them, announced while it waits, is held at once; the wait stays until
//! its ask is answered, and its answer then offers nothing twice.
//!
//! **Only a proven header waits.** A wait holds a [`BoundArrival`], whose
//! header is a `HeaderJudged`: the validator's token for a header whose
//! proof of work it verified, taken from `T`, which holds nothing else.
//! Both ways in bind a body to a header already in `T` — a 2014 answer for
//! a hash this node asked for, and an announce after its proof came back —
//! so no session can make a block wait with bytes it merely sent. What a
//! session can do without work of its own is send a proven block's body
//! without its bundle bodies, and then not answer.
//!
//! **Every sender is asked.** A wait is the block's, not its first
//! sender's. Each session that sends the block without the bodies is asked
//! for them, up to its own bound, and any of them completes it. A
//! withholder that announces a tip block first therefore delays it by
//! nothing: the honest announcers behind it are asked as they arrive. A
//! sender that closes, or answers with nothing, leaves the wait to the
//! others; the wait ends when none is left.
//!
//! **Withholding.** A relayer serves the bodies of the blocks it relays
//! (`SCS-P27`). A session that announced a block and answers the 2016 for
//! its bodies with nothing is closed
//! ([`CloseCause::BundleBodiesWithheld`]). So is one that announced a
//! block, was asked, and has sent no body [`AWAITING_AGE`] later (Rick,
//! 2026-11-10): silence would otherwise keep a proven block out of the
//! body planner for the whole wait at no cost. A session asked only
//! because it served the block in a 2014 is not closed either way: it
//! served what it held. A miner that
//! withholds its own bundle's body therefore never has its block offered
//! here, so its branch is never adopted, and the bounds keep the waiting
//! from growing.
//!
//! **Below `D_max`.** A block deep enough that every node has discarded its
//! bodies is not this path's: §8 rules what a skeleton sync accepts (kept
//! bytes against the header root). Sync has no skeleton offer yet
//! (`OfferedBody::from_full` refuses a skeleton transaction), so such a
//! block waits here and expires; the bootstrap lane builds that offer.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use shekyl_chain_rules::CarriedBodies;
use shekyl_types::BlockHash;

use crate::protocol::{BoundArrival, CloseCause, Command, OfferedBody};

/// Blocks one session may have waiting for bundle bodies at once.
///
/// `Assumption` (written down, not measured): a session relays one block at
/// a time near the tip, and a short run of them during sync; four covers a
/// tip and a brief reorg without one session holding the set.
pub const AWAITING_PER_SESSION: usize = 4;

/// Blocks waiting for bundle bodies at once, over every session.
///
/// `Assumption` (written down, not measured): each entry pins one block
/// body, at most the block weight limit, so this bounds the set at sixteen
/// block bodies.
pub const AWAITING_TOTAL: usize = 16;

/// How long a block waits for its bundle bodies before it is dropped.
///
/// `Assumption` (written down, not measured): one round trip to the
/// sender and a store read, with room for a slow link. A block dropped here
/// is not refused; it is asked for again like any body this node does not
/// hold.
pub const AWAITING_AGE: Duration = Duration::from_secs(30);

/// One block waiting for its bundle bodies.
pub(crate) struct Waiting<K> {
    /// The bound arrival, with the bodies it has so far. Its session is
    /// one of [`Self::asked`].
    pub(crate) arrival: BoundArrival<K>,
    /// When it started waiting.
    pub(crate) since: Instant,
    /// The sessions asked for its bodies.
    pub(crate) asked: BTreeMap<K, Ask>,
}

/// One session's ask for a waiting block's bodies.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ask {
    /// Whether this node had asked the session for the block (a 2014
    /// answer) or it announced the block.
    pub(crate) sender: Sender,
    /// When it was asked.
    pub(crate) at: Instant,
    /// It has sent a body since. An empty answer is not one: that sender
    /// leaves the wait.
    pub(crate) answered: bool,
}

/// How a session came to send a waiting block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sender {
    /// It answered this node's 2014: it served what it held.
    Asked,
    /// It announced the block: a relayer serves the bodies of the blocks
    /// it relays (`SCS-P27`).
    Announced,
}

impl Sender {
    const fn of<K>(arrival: &BoundArrival<K>) -> Self {
        if arrival.solicited {
            Self::Asked
        } else {
            Self::Announced
        }
    }
}

/// The waiting blocks, by hash.
pub(crate) type Awaiting<K> = BTreeMap<BlockHash, Waiting<K>>;

/// The references of `body`'s section that no carried body answers, in
/// section order and undecoded. A body answers a reference when it hashes
/// to its prunable hash and is the reference's length (§7.5). Each carried
/// body is hashed once ([`CarriedBodies`]), not once per reference. A
/// reference that does not parse has no body to wait for: `bind_body`
/// refused the block before it got here.
pub(crate) fn unanswered(body: &OfferedBody) -> Vec<Vec<u8>> {
    let carried = CarriedBodies::index(body.bundle_bodies.iter().map(Vec::as_slice));
    let mut missing = Vec::new();
    for (position, bytes) in body.bundle_references.iter().enumerate() {
        let Ok(reference) = shekyl_chain_rules::open_reference(position, bytes) else {
            continue;
        };
        let answered = carried
            .named_by(&reference)
            .is_some_and(|named| reference.accept_body(named).is_ok());
        if !answered {
            missing.push(bytes.clone());
        }
    }
    missing
}

impl<K, R> crate::model::Sync<K, R>
where
    K: Copy + Ord + std::hash::Hash + std::fmt::Debug,
    R: Fn(shekyl_types::BlockHeight) -> shekyl_chain_rules::RuleSet,
{
    /// Hold `arrival` for the entry, or, when its section names bodies it
    /// did not carry, make it wait for them and ask the owner (module docs).
    /// A session is asked for a block once; a second session that sends a
    /// waiting block without its bodies is asked too. A block past either
    /// bound is dropped without an ask; no wait is evicted for it.
    pub(crate) fn hold_or_await(
        &mut self,
        arrival: BoundArrival<K>,
        now: Instant,
        out: &mut Vec<Command<K>>,
    ) {
        let missing = unanswered(&arrival.body);
        if missing.is_empty() {
            self.held.insert(arrival);
            return;
        }
        // As the transaction path asks 2009 only while requesting: a node
        // that is not asking peers has nothing that would complete a wait.
        if !self.requests() {
            return;
        }
        let block = arrival.header.hash();
        let session = arrival.session;
        let of_session = self
            .awaiting
            .values()
            .filter(|waiting| waiting.asked.contains_key(&session))
            .count();
        let ask = Ask {
            sender: Sender::of(&arrival),
            at: now,
            answered: false,
        };
        if let Some(waiting) = self.awaiting.get_mut(&block) {
            // The wait may hold bodies this copy did not carry: ask for
            // what the wait still lacks.
            if waiting.asked.contains_key(&session) || of_session >= AWAITING_PER_SESSION {
                return;
            }
            waiting.asked.insert(session, ask);
            out.push(Command::RequestBundleBodies {
                session,
                block,
                references: unanswered(&waiting.arrival.body),
            });
            return;
        }
        if of_session >= AWAITING_PER_SESSION || self.awaiting.len() >= AWAITING_TOTAL {
            return;
        }
        out.push(Command::RequestBundleBodies {
            session,
            block,
            references: missing,
        });
        self.awaiting.insert(
            block,
            Waiting {
                arrival,
                since: now,
                asked: BTreeMap::from([(session, ask)]),
            },
        );
    }

    /// Bodies for a waiting block (module docs). They complete it, and it is
    /// held and offered; or they are part of what it waits for, and it keeps
    /// waiting; or the session answered with nothing, and it is closed when
    /// it announced the block. The wait is then the other senders', and is
    /// dropped when there is none.
    pub(crate) fn on_bundle_bodies(
        &mut self,
        session: K,
        block: BlockHash,
        bodies: Vec<Vec<u8>>,
        out: &mut Vec<Command<K>>,
    ) {
        let Some(mut waiting) = self.awaiting.remove(&block) else {
            return;
        };
        let Some(ask) = waiting.asked.get_mut(&session) else {
            self.awaiting.insert(block, waiting);
            return;
        };
        let answered_nothing = bodies.is_empty();
        ask.answered |= !answered_nothing;
        waiting.arrival.body.bundle_bodies.extend(bodies);
        if unanswered(&waiting.arrival.body).is_empty() {
            // A whole copy announced while this waited is already on its
            // way to the entry, or through it.
            if !self.accepted.contains(&block) && !self.outstanding.contains(block) {
                self.held.insert(waiting.arrival);
            }
            self.flush_offers(out);
            return;
        }
        if answered_nothing {
            let ask = waiting.asked.remove(&session);
            if ask.is_some_and(|ask| ask.sender == Sender::Announced)
                && self.peers.contains_key(&session)
            {
                self.close(session, CloseCause::BundleBodiesWithheld, out);
            }
            if !waiting.pass_to_another_sender(session) {
                return;
            }
        }
        self.awaiting.insert(block, waiting);
    }

    /// Drop every block that has waited [`AWAITING_AGE`] or longer. Not a
    /// refusal: the block is asked for again like any body this node does
    /// not hold.
    ///
    /// An announcer that was asked [`AWAITING_AGE`] ago and has sent no
    /// body is closed, as one that answered with nothing is: silence
    /// withholds as well as an empty answer does (module docs). A session
    /// asked because it served the block in a 2014 is not closed, and
    /// neither is an announcer asked more recently than that, whose answer
    /// may still be on its way when the wait it joined runs out.
    pub(crate) fn expire_waiting(&mut self, now: Instant, out: &mut Vec<Command<K>>) {
        let aged = |since: Instant| now.saturating_duration_since(since) >= AWAITING_AGE;
        let mut silent = std::collections::BTreeSet::new();
        self.awaiting.retain(|_, waiting| {
            if !aged(waiting.since) {
                return true;
            }
            silent.extend(
                waiting
                    .asked
                    .iter()
                    .filter(|(_, ask)| {
                        ask.sender == Sender::Announced && !ask.answered && aged(ask.at)
                    })
                    .map(|(session, _)| *session),
            );
            false
        });
        for session in silent {
            if self.peers.contains_key(&session) {
                self.close(session, CloseCause::BundleBodiesWithheld, out);
            }
        }
    }

    /// The session is gone: a block it sent waits on for its other
    /// senders, and is dropped when it has none.
    pub(crate) fn drop_waiting_from(&mut self, session: K) {
        self.awaiting.retain(|_, waiting| {
            waiting.asked.remove(&session);
            waiting.pass_to_another_sender(session)
        });
    }
}

impl<K: Copy + Ord> Waiting<K> {
    /// `gone` is no longer asked. When the arrival was its, the arrival
    /// becomes another sender's, so nothing held or offered names a
    /// session that left. `false` when no sender is left.
    fn pass_to_another_sender(&mut self, gone: K) -> bool {
        let Some((&next, ask)) = self.asked.iter().next() else {
            return false;
        };
        if self.arrival.session == gone {
            self.arrival.session = next;
            self.arrival.solicited = ask.sender == Sender::Asked;
        }
        true
    }
}

#[cfg(test)]
#[path = "awaiting_tests.rs"]
mod tests;
