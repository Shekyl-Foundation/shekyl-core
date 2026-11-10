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
//!   ([`AWAITING_TOTAL`]); a new wait past either bound drops the oldest;
//! - in age ([`AWAITING_AGE`]); an expired wait is dropped, not refused.
//!
//! Each waiting entry pins one bound block body, so the memory the set can
//! hold is [`AWAITING_TOTAL`] block bodies.
//!
//! **Withholding.** A relayer serves the bodies of the blocks it relays
//! (`SCS-P27`). A session that announced a block and answers the 2016 for
//! its bodies with nothing is closed
//! ([`CloseCause::BundleBodiesWithheld`]). A session asked only because it
//! served the block in a 2014 is not: it served what it held. A miner that
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
    /// The bound arrival, with the bodies it has so far.
    pub(crate) arrival: BoundArrival<K>,
    /// When it started waiting.
    pub(crate) since: Instant,
}

/// The waiting blocks, by hash.
pub(crate) type Awaiting<K> = BTreeMap<BlockHash, Waiting<K>>;

/// The references of `body`'s section that no carried body answers, in
/// section order and undecoded. A body answers a reference when it is the
/// reference's length and hashes to its prunable hash (§7.5). A reference
/// that does not parse has no body to wait for: `bind_body` refused the
/// block before it got here.
pub(crate) fn unanswered(body: &OfferedBody) -> Vec<Vec<u8>> {
    let mut missing = Vec::new();
    for (position, bytes) in body.bundle_references.iter().enumerate() {
        let Ok(reference) = shekyl_chain_rules::open_reference(position, bytes) else {
            continue;
        };
        let answered = body
            .bundle_bodies
            .iter()
            .any(|carried| reference.accept_body(carried).is_ok());
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
    /// A block already waiting is not asked for twice.
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
        let block = arrival.header.hash();
        if self.awaiting.contains_key(&block) {
            return;
        }
        let session = arrival.session;
        while self
            .awaiting
            .values()
            .filter(|waiting| waiting.arrival.session == session)
            .count()
            >= AWAITING_PER_SESSION
        {
            self.drop_oldest_waiting(Some(session));
        }
        while self.awaiting.len() >= AWAITING_TOTAL {
            self.drop_oldest_waiting(None);
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
            },
        );
    }

    /// Bodies for a waiting block (module docs). They complete it, and it is
    /// held and offered; or they are part of what it waits for, and it keeps
    /// waiting; or the session answered with nothing, and the block is
    /// dropped — and the session closed when it announced the block.
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
        if waiting.arrival.session != session {
            self.awaiting.insert(block, waiting);
            return;
        }
        let answered_nothing = bodies.is_empty();
        waiting.arrival.body.bundle_bodies.extend(bodies);
        if unanswered(&waiting.arrival.body).is_empty() {
            self.held.insert(waiting.arrival);
            self.flush_offers(out);
            return;
        }
        if answered_nothing {
            if !waiting.arrival.solicited && self.peers.contains_key(&session) {
                self.close(session, CloseCause::BundleBodiesWithheld, out);
            }
            return;
        }
        self.awaiting.insert(block, waiting);
    }

    /// Drop every block that has waited [`AWAITING_AGE`] or longer. Not a
    /// refusal: the block is asked for again like any body this node does
    /// not hold.
    pub(crate) fn expire_waiting(&mut self, now: Instant) {
        self.awaiting
            .retain(|_, waiting| now.saturating_duration_since(waiting.since) < AWAITING_AGE);
    }

    /// Drop the blocks `session` sent that are waiting: the session is gone.
    pub(crate) fn drop_waiting_from(&mut self, session: K) {
        self.awaiting
            .retain(|_, waiting| waiting.arrival.session != session);
    }

    /// Drop the oldest waiting block, of `session` when it is named.
    fn drop_oldest_waiting(&mut self, session: Option<K>) {
        let oldest = self
            .awaiting
            .iter()
            .filter(|(_, waiting)| session.is_none_or(|s| waiting.arrival.session == s))
            // Two waits that began at one instant are ordered by arrival:
            // the tag rises with each bound body.
            .min_by_key(|(_, waiting)| (waiting.since, waiting.arrival.tag))
            .map(|(block, _)| *block);
        if let Some(block) = oldest {
            self.awaiting.remove(&block);
        }
    }
}

#[cfg(test)]
#[path = "awaiting_tests.rs"]
mod tests;
