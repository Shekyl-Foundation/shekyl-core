// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One accepted span: parse, place, form under a hasher permit, connect.
//!
//! An alternative is gated before any of that work builds a cache. A run
//! that extends the tip pins its seeds — at most two, older then newer —
//! under one permit before any block hashes, and the hash looks the cache
//! up. A miss is not a derive.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};

use kameo::error::SendError;
use shekyl_chain_rules::{
    form, Candidate, CenRow, Fault, FormAttempt, HeaderView, InvalidBlock, StatelessPass,
    StructurallyValid, Substrate, Tip,
};
use shekyl_chain_store::store::{AltCannot, SnapshotView, StoreCannot, StoreError};
use shekyl_hash_budget::{Class, Permit};
use shekyl_mempool::{stateless, Pool, PoolFault};
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, Transaction};
use tokio::sync::oneshot;

use super::{Accepted, ArrivalTag, CannotFollow, Origin, Reply, ReplySlot, ServiceFault, Shared};
use crate::cache_window::AltSpend;
use crate::connector::{Apply, ObserveTarget, OfferAlt, Offered, Reorganize, RunFault, Switched};
use crate::plan_form::{form_plan, PlanStop};
use crate::router::{claim_alt, claim_run, ClaimStop, ClaimedAlt, Claims};

/// What a span task carries for an arrival once its bytes parsed.
struct Parsed {
    slot: ReplySlot,
    tag: ArrivalTag,
    /// The hasher class its `form` waits in.
    class: Class,
    block: Block,
    /// The carried bodies, by the hash they claim to list.
    bodies: Vec<Transaction>,
}

impl Parsed {
    fn hash(&self) -> BlockHash {
        self.block.hash()
    }
}

/// Bodies a block carried, for the pool's door.
enum Carried {
    /// The alternative block whose stored bodies are offered.
    Alt(BlockHash),
    /// Bodies in hand.
    Bodies(Vec<Transaction>),
}

/// Why preparing those bodies stopped before the pool lock.
enum PrepFault {
    /// The chain store could not be read.
    Store(StoreError),
    /// The chain view faulted while step 1 ran.
    Chain(Fault<StoreError>),
}

/// What one step of a span leaves for the rest of it.
enum Next {
    /// Go on with the queue.
    Continue,
    /// Place these again, at the front of the queue, in order.
    Again(Vec<Parsed>),
    /// `by` was refused: these and every arrival still queued reply
    /// `Cancelled { by }`.
    Cancel {
        /// The refused arrival.
        by: ArrivalTag,
        /// The rest of the step's arrivals.
        rest: Vec<Parsed>,
    },
    /// The service is stopping or failed: what is left answers `Stopped`.
    Halt,
}

/// The hasher class an arrival's `form` waits in: a block this node asked
/// for or made is the chain's; an announcement is unsolicited.
const fn class_of(origin: Origin) -> Class {
    match origin {
        Origin::Peer {
            solicited: false, ..
        } => Class::Unsolicited,
        Origin::Peer {
            solicited: true, ..
        }
        | Origin::Local => Class::Chain,
    }
}

/// Parse one accepted arrival. A blob the wire cannot parse is a verdict
/// against the block (CEN-A6); a carried body that does not parse is a body
/// the block's list cannot pair (CEN-G2).
fn parse(accepted: Accepted) -> Result<Parsed, (ReplySlot, ArrivalTag, InvalidBlock)> {
    let Accepted {
        slot,
        tag,
        origin,
        block,
        bodies,
    } = accepted;
    let refused = |rule| InvalidBlock::new(rule, shekyl_chain_rules::Locus::Block);
    let Ok(block) = Block::from_bytes(&block) else {
        return Err((slot, tag, refused(shekyl_chain_rules::CenRow::A6)));
    };
    let mut parsed = Vec::with_capacity(bodies.len());
    for body in &bodies {
        let Ok(tx) = Transaction::from_bytes(body) else {
            return Err((slot, tag, refused(shekyl_chain_rules::CenRow::G2)));
        };
        parsed.push(tx);
    }
    Ok(Parsed {
        slot,
        tag,
        class: class_of(origin),
        block,
        bodies: parsed,
    })
}

/// The candidate for `parsed`: its listed bodies in listed order, then any
/// carried body the list does not name. A listed body the arrival did not
/// carry is resolved from the bodies `pool` shows, and only those: a stem
/// transaction the pool holds counts as missing.
fn assemble(parsed: &Parsed, pool: Option<&Pool>) -> Result<Candidate, Vec<usize>> {
    let mut carried: Vec<Option<&Transaction>> = parsed.bodies.iter().map(Some).collect();
    let mut listed = Vec::with_capacity(parsed.block.transaction_hashes.len());
    let mut missing = Vec::new();
    for (index, txid) in parsed.block.transaction_hashes.iter().enumerate() {
        let found = carried
            .iter_mut()
            .find(|slot| slot.is_some_and(|tx| tx.txid_parts().hash == *txid))
            .and_then(Option::take);
        match found.or_else(|| pool.and_then(|pool| pool.shown_body(txid))) {
            Some(tx) => listed.push(tx.clone()),
            None => missing.push(index),
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    listed.extend(carried.into_iter().flatten().cloned());
    Ok(Candidate::new(parsed.block.clone(), listed))
}

/// Work one accepted span.
pub(super) async fn run_span<S>(shared: Arc<Shared<S>>, span: Vec<Accepted>)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    // No hash until the two cache slots hold this tip's seeds. A stop
    // while that is outstanding answers every arrival `Stopped`.
    if shared.seed_pair().await.is_none() {
        return;
    }
    let mut queue: VecDeque<Parsed> = VecDeque::with_capacity(span.len());
    let mut refused_by = None;
    for accepted in span {
        match parse(accepted) {
            Ok(parsed) => queue.push_back(parsed),
            Err((slot, tag, refused)) => {
                slot.send(Reply::Refused(refused));
                refused_by.get_or_insert(tag);
            }
        }
    }
    if let Some(by) = refused_by {
        for parsed in queue {
            parsed.slot.send(Reply::Cancelled { by });
        }
        return;
    }
    while let Some(front) = queue.pop_front() {
        if shared.stopping() {
            return;
        }
        let candidate = match assemble(&front, shared.shown_pool().as_deref()) {
            Ok(candidate) => candidate,
            Err(indices) => {
                front.slot.send(Reply::MissingBodies { indices });
                continue;
            }
        };
        let placed = match crate::router::place(&shared.store, &front.block) {
            Ok(placed) => placed,
            Err(e) => return shared.fail(e.into()),
        };
        let next = match placed {
            crate::router::Placed::AlreadyHeld => {
                front.slot.send(Reply::AlreadyHeld);
                Next::Continue
            }
            crate::router::Placed::Unlinked { at } => {
                front.slot.send(Reply::Unlinked { at });
                Next::Continue
            }
            crate::router::Placed::Alt => offer_alt(&shared, front, candidate).await,
            crate::router::Placed::Extend { height } => {
                let mut run = vec![(front, candidate)];
                while let Some(next) = queue.front() {
                    if next.block.header.previous != run[run.len() - 1].0.hash() {
                        break;
                    }
                    let Ok(next_candidate) = assemble(next, shared.shown_pool().as_deref()) else {
                        break;
                    };
                    let next = queue.pop_front().expect("peeked");
                    run.push((next, next_candidate));
                }
                extend_run(&shared, height, run).await
            }
        };
        match next {
            Next::Continue => {}
            Next::Again(again) => {
                for parsed in again.into_iter().rev() {
                    queue.push_front(parsed);
                }
            }
            Next::Cancel { by, rest } => {
                for parsed in rest.into_iter().chain(queue.drain(..)) {
                    parsed.slot.send(Reply::Cancelled { by });
                }
                return;
            }
            Next::Halt => return,
        }
    }
}

/// Pin `seeds` in order under one permit of `class`, then record the last
/// as the canonical slot. The permit covers the derive. A hash does not.
/// `false` when the service stopped before the pin.
async fn pin_seeds<S>(shared: &Arc<Shared<S>>, seeds: &[BlockHash], class: Class) -> bool
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    if seeds.is_empty() {
        return true;
    }
    let budget = shared.budget.clone();
    let substrate = Arc::clone(shared.substrate());
    let pin_lock = Arc::clone(&shared.pin_lock);
    let stop = Arc::clone(&shared.stop_flag);
    let pinned = seeds.to_vec();
    let did = tokio::task::spawn_blocking(move || {
        let Some(_permit) = budget.acquire_unless(class, &stop) else {
            return false;
        };
        let _gate = pin_lock.lock().unwrap_or_else(PoisonError::into_inner);
        for seed in &pinned {
            substrate.pin_seed(seed);
        }
        true
    })
    .await
    .expect("a pin does not panic");
    if did {
        shared.note_pins(seeds);
    }
    did
}

/// Seeds in the order a forward run names them: the first is the older.
fn distinct_seeds(claims: &[Claims]) -> Vec<BlockHash> {
    let mut seeds = Vec::new();
    for claim in claims {
        if !seeds.contains(&claim.seed) {
            seeds.push(claim.seed);
        }
    }
    seeds
}

/// A block's `form`, or nothing when the run was abandoned before it began.
type Formed<F> = Result<Result<StructurallyValid, InvalidBlock>, F>;

/// `form` one block on a blocking thread, holding `permit` for the life of
/// the `form`. `abandon` is checked first, and set by a refusal before the
/// permit is given back, so no block launched behind a refused one starts
/// a hash.
fn spawn_form<S>(
    shared: &Arc<Shared<S>>,
    permit: Permit,
    candidate: Candidate,
    claims: Claims,
    abandon: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Option<Formed<S::Fault>>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let substrate = Arc::clone(shared.substrate());
    tokio::task::spawn_blocking(move || {
        if abandon.load(Ordering::Acquire) {
            return None;
        }
        let verdict = form(
            candidate,
            &claims.rule_set,
            &*substrate,
            claims.seed,
            claims.target,
            &claims.references,
            FormAttempt::FIRST,
        );
        if matches!(verdict, Ok(Err(_))) {
            abandon.store(true, Ordering::Release);
        }
        drop(permit);
        Some(verdict)
    })
}

/// Take a permit for `class`, or `None` once the service is stopping.
/// The budget blocks, so the wait is a blocking task's. The seed is not
/// pinned here.
async fn acquire<S>(shared: &Arc<Shared<S>>, class: Class) -> Option<Permit>
where
    S: Substrate + Send + Sync + 'static,
{
    let budget = shared.budget.clone();
    let stop = Arc::clone(&shared.stop_flag);
    tokio::task::spawn_blocking(move || budget.acquire_unless(class, &stop))
        .await
        .expect("a permit wait does not panic")
}

/// A run extending the tip from `first`. The run's seeds are pinned before
/// any block hashes, so one block's pin cannot evict the cache the previous
/// block is still hashing under.
async fn extend_run<S>(
    shared: &Arc<Shared<S>>,
    first: BlockHeight,
    run: Vec<(Parsed, Candidate)>,
) -> Next
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let mut arrivals = VecDeque::with_capacity(run.len());
    let mut candidates = Vec::with_capacity(run.len());
    for (parsed, candidate) in run {
        arrivals.push_back(parsed);
        candidates.push(candidate);
    }
    let class = arrivals
        .front()
        .map(|parsed| parsed.class)
        .unwrap_or(Class::Chain);
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    let for_claims = candidates.clone();
    let (claims, stop) =
        tokio::task::spawn_blocking(move || claim_run(&store, rules, first, &for_claims))
            .await
            .expect("the claim reader does not panic");
    // The snapshot no longer has this run on the tip. Nothing was derived
    // that a hash could use, and the arrivals are placed again.
    if matches!(stop, Some(ClaimStop::Moved)) {
        return Next::Again(arrivals.into_iter().collect());
    }
    if !pin_seeds(shared, &distinct_seeds(&claims), class).await {
        return Next::Halt;
    }
    let abandon = Arc::new(AtomicBool::new(false));
    let mut receivers = Vec::with_capacity(claims.len());
    let mut jobs = Vec::with_capacity(claims.len());
    for (index, (claim, candidate)) in claims.into_iter().zip(candidates).enumerate() {
        let (sender, receiver) = oneshot::channel();
        receivers.push((claim.height, receiver));
        let class = arrivals[index].class;
        jobs.push((candidate, claim, class, sender));
    }
    let launcher = {
        let shared = Arc::clone(shared);
        let abandon = Arc::clone(&abandon);
        tokio::spawn(async move {
            let mut forming = Vec::new();
            for (candidate, claims, class, sender) in jobs {
                if shared.stopping() || abandon.load(Ordering::Acquire) {
                    break;
                }
                let Some(held) = acquire(&shared, class).await else {
                    break;
                };
                let form = spawn_form(&shared, held, candidate, claims, Arc::clone(&abandon));
                forming.push(tokio::spawn(async move {
                    if let Ok(Some(formed)) = form.await {
                        let _unread = sender.send(formed);
                    }
                }));
            }
            for form in forming {
                let _joined = form.await;
            }
        })
    };
    let next = connect_run(shared, &mut arrivals, receivers, stop, &abandon).await;
    abandon.store(true, Ordering::Release);
    let _joined = launcher.await;
    next
}

/// The arrivals of a run, as the replies leave them.
fn rest(arrivals: &mut VecDeque<Parsed>) -> Vec<Parsed> {
    arrivals.drain(..).collect()
}

/// Connect a run's formed blocks in order as each `form` ends.
async fn connect_run<S>(
    shared: &Arc<Shared<S>>,
    arrivals: &mut VecDeque<Parsed>,
    receivers: Vec<(BlockHeight, oneshot::Receiver<Formed<S::Fault>>)>,
    stop: Option<ClaimStop>,
    abandon: &AtomicBool,
) -> Next
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    for (height, receiver) in receivers {
        let arrival = arrivals.pop_front().expect("one arrival per claim");
        let Ok(formed) = receiver.await else {
            return Next::Halt;
        };
        if shared.stopping() {
            abandon.store(true, Ordering::Release);
            return Next::Halt;
        }
        let formed = match formed {
            Ok(Ok(formed)) => formed,
            Ok(Err(refused)) => {
                arrival.slot.send(Reply::Refused(refused));
                return Next::Cancel {
                    by: arrival.tag,
                    rest: rest(arrivals),
                };
            }
            Err(fault) if shared.substrate().cache_absent(&fault) => {
                // The slots moved under the hash. Place again: the run pins
                // the window it needs, and a miss does not derive.
                abandon.store(true, Ordering::Release);
                let mut again = vec![arrival];
                again.extend(rest(arrivals));
                return Next::Again(again);
            }
            Err(fault) => {
                abandon.store(true, Ordering::Release);
                shared.fail(ServiceFault::Substrate(fault));
                return Next::Halt;
            }
        };
        match shared
            .connector
            .ask(Apply(vec![(height, Ok(formed))]))
            .await
        {
            Ok(applied) => match applied.refused {
                // This path only applies a block whose parent was the tip.
                // CEN-A2 then says that parent is no longer the tip, at the
                // same height: a replacement, not a block this peer proved
                // invalid. A height change is `HeightClaim`, below.
                Some((_, refused)) if refused.rule == CenRow::A2 => {
                    abandon.store(true, Ordering::Release);
                    let mut again = vec![arrival];
                    again.extend(rest(arrivals));
                    return Next::Again(again);
                }
                Some((_, refused)) => {
                    abandon.store(true, Ordering::Release);
                    arrival.slot.send(Reply::Refused(refused));
                    return Next::Cancel {
                        by: arrival.tag,
                        rest: rest(arrivals),
                    };
                }
                None => {
                    let (height, hash) = applied.connected[0];
                    arrival.slot.send(Reply::Connected { height, hash });
                }
            },
            Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
                abandon.store(true, Ordering::Release);
                let mut again = vec![arrival];
                again.extend(rest(arrivals));
                return Next::Again(again);
            }
            Err(err) => {
                abandon.store(true, Ordering::Release);
                shared.fail(unreachable_or(err));
                return Next::Halt;
            }
        }
    }
    match stop {
        None => Next::Continue,
        Some(ClaimStop::Refused { refused, .. }) => {
            let arrival = arrivals.pop_front().expect("the refused block is next");
            arrival.slot.send(Reply::Refused(refused));
            Next::Cancel {
                by: arrival.tag,
                rest: rest(arrivals),
            }
        }
        Some(ClaimStop::Corrupt { height, .. }) => {
            match shared.connector.ask(ObserveTarget { height }).await {
                Ok(()) => Next::Again(rest(arrivals)),
                Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
                    Next::Again(rest(arrivals))
                }
                Err(err) => {
                    shared.fail(unreachable_or(err));
                    Next::Halt
                }
            }
        }
        Some(ClaimStop::Store(e)) => {
            shared.fail(e.into());
            Next::Halt
        }
        Some(ClaimStop::Moved) => Next::Again(rest(arrivals)),
    }
}

/// An alternative arrival. The fork and the seed are judged before a permit
/// is taken and before any cache is built. An alternative never pins: the
/// two slots already hold every seed inside the cap.
async fn offer_alt<S>(shared: &Arc<Shared<S>>, arrival: Parsed, candidate: Candidate) -> Next
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let Some(window) = shared.seed_pair().await else {
        return Next::Halt;
    };
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    let trust = rules.trust();
    let for_claims = candidate.clone();
    let claimed =
        tokio::task::spawn_blocking(move || claim_alt(&store, rules, &for_claims, &window, &trust))
            .await
            .expect("the claim reader does not panic");
    let claims = match claimed {
        Ok(ClaimedAlt::Ready(claims)) => claims,
        Ok(ClaimedAlt::Spend(spend)) => return answer_spend(arrival, spend),
        Err(ClaimStop::Refused { refused, .. }) => return refuse(arrival, refused),
        Err(ClaimStop::Store(StoreError::Cannot(StoreCannot::Alt(AltCannot::Unlinked {
            ..
        })))) => {
            return Next::Again(vec![arrival]);
        }
        Err(ClaimStop::Store(e)) => {
            shared.fail(e.into());
            return Next::Halt;
        }
        Err(ClaimStop::Corrupt { height, corrupt }) => {
            shared.fail(ServiceFault::Corrupt { height, corrupt });
            return Next::Halt;
        }
        Err(ClaimStop::Moved) => return Next::Again(vec![arrival]),
    };
    let Some(now) = shared.seed_now() else {
        return Next::Halt;
    };
    if !now.holds(&claims.seed) {
        let height = claims.height;
        arrival.slot.send(Reply::OutsideWindow { height });
        return Next::Continue;
    }
    let height = claims.height;
    let Some(held) = acquire(shared, arrival.class).await else {
        return Next::Halt;
    };
    let forming = spawn_form(
        shared,
        held,
        candidate,
        claims,
        Arc::new(AtomicBool::new(false)),
    );
    let formed = match forming.await.expect("a form worker does not panic") {
        Some(Ok(Ok(formed))) => formed,
        Some(Ok(Err(verdict))) => return refuse(arrival, verdict),
        Some(Err(fault)) if shared.substrate().cache_absent(&fault) => {
            arrival.slot.send(Reply::OutsideWindow { height });
            return Next::Continue;
        }
        Some(Err(fault)) => {
            shared.fail(ServiceFault::Substrate(fault));
            return Next::Halt;
        }
        None => unreachable!("a lone arrival's form is never abandoned"),
    };
    let offered = match shared.connector.ask(OfferAlt(formed)).await {
        Ok(offered) => offered,
        Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
            return Next::Again(vec![arrival])
        }
        Err(err) => {
            shared.fail(unreachable_or(err));
            return Next::Halt;
        }
    };
    // Stored, and its proof of work passed: its bodies go to the pool now
    // (CEN-K9), not before.
    if matches!(
        offered,
        Offered::Held { .. } | Offered::BeyondCap(_) | Offered::SwitchDue(_)
    ) {
        offer_carried(shared, Carried::Alt(arrival.hash())).await;
    }
    let reply = match settled(offered) {
        Ok(reply) => reply,
        Err(Carry::Refuse(verdict)) => return refuse(arrival, verdict),
        Err(Carry::Switch(plan)) => match carry_out(shared, *plan).await {
            Some(reply) => reply,
            None => return Next::Halt,
        },
    };
    arrival.slot.send(reply);
    Next::Continue
}

/// What [`settled`] hands back for the caller to carry on.
enum Carry {
    /// The cheap tier's verdict: refuse the arrival.
    Refuse(InvalidBlock),
    /// A switch is due.
    Switch(Box<crate::connector::SwitchPlan>),
}

/// The reply for the store's outcome, when it needs no further step.
///
/// A stored alternative past the cap proves a heavier chain this node
/// cannot follow: [`CannotFollow::BeyondCap`], never the door's
/// [`Reply::BeyondCap`] hint (DX-Q2 item 8).
fn settled(offered: Offered) -> Result<Reply, Carry> {
    match offered {
        Offered::Refused(verdict) => Err(Carry::Refuse(verdict)),
        Offered::Unlinked { at } => Ok(Reply::Unlinked { at }),
        Offered::AlreadyHeld => Ok(Reply::AlreadyHeld),
        Offered::Held { height } => Ok(Reply::Held { height }),
        Offered::BeyondCap(beyond) => Ok(Reply::CannotFollow(CannotFollow::BeyondCap(beyond))),
        Offered::SwitchDue(plan) => Err(Carry::Switch(Box::new(plan))),
    }
}

/// The reply for a switch's outcome. `Err` hands back the landed switch,
/// whose returned bodies the caller offers first.
///
/// Past the cap and below the floor are proven outcomes:
/// [`Reply::CannotFollow`] (DX-Q2 item 8).
fn switch_reply(switched: Switched) -> Result<Reply, crate::connector::SwitchDone> {
    match switched {
        Switched::Done(done) => Err(done),
        Switched::Refused {
            at, hash, refused, ..
        } => Ok(Reply::PromotionRefused { at, hash, refused }),
        Switched::BeyondCap(beyond) => Ok(Reply::CannotFollow(CannotFollow::BeyondCap(beyond))),
        Switched::BelowFloor { tip, floor } => Ok(Reply::CannotFollow(CannotFollow::BelowFloor {
            tip: BlockHeight::from_raw(tip),
            floor: BlockHeight::from_raw(floor),
        })),
    }
}

/// The early gate's answer. Nothing was stored and nothing was hashed.
fn answer_spend(arrival: Parsed, spend: AltSpend) -> Next {
    match spend {
        AltSpend::Hash => unreachable!("a hash is the ready arm"),
        AltSpend::Refused(verdict) => refuse(arrival, verdict),
        AltSpend::BeyondCap(beyond) => {
            arrival.slot.send(Reply::BeyondCap(beyond));
            Next::Continue
        }
        AltSpend::OutsideWindow { height } => {
            arrival.slot.send(Reply::OutsideWindow { height });
            Next::Continue
        }
    }
}

/// A verdict against the block cancels nothing behind it: an alternative is
/// one arrival.
fn refuse(arrival: Parsed, refused: InvalidBlock) -> Next {
    let by = arrival.tag;
    arrival.slot.send(Reply::Refused(refused));
    Next::Cancel {
        by,
        rest: Vec::new(),
    }
}

/// Carry out a switch an arrival made due. A missing cache reinstalls the
/// window once — the chain's seeds, under a permit — and does not halt the
/// service when the seed is still absent.
async fn carry_out<S>(shared: &Arc<Shared<S>>, plan: crate::connector::SwitchPlan) -> Option<Reply>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let mut formed = form_switch(shared, &plan).await;
    if let Err(PlanStop::Substrate(fault)) = &formed {
        if shared.substrate().cache_absent(fault) {
            if let Err(e) = super::install_window(shared).await {
                shared.fail(e.into());
                return None;
            }
            formed = form_switch(shared, &plan).await;
        }
    }
    let switched = match formed {
        Ok(formed) => shared
            .connector
            .ask(Reorganize {
                tip: plan.tip,
                alt_tip: plan.alt_tip,
                demoted: formed.demoted,
                promoted: formed.promoted,
            })
            .await
            .map_err(Asked::from),
        Err(PlanStop::Refused(refusal)) if refusal.demoted => {
            shared.fail(ServiceFault::DemotionRefused {
                hash: refusal.hash,
                refused: refusal.refused,
            });
            return None;
        }
        Err(PlanStop::Refused(refusal)) => shared
            .connector
            .ask(crate::connector::RefusePromotion {
                tip: plan.tip,
                alt_tip: plan.alt_tip,
                hash: refusal.hash,
                refused: refusal.refused,
            })
            .await
            .map_err(Asked::from),
        Err(PlanStop::Substrate(fault)) if shared.substrate().cache_absent(&fault) => {
            return Some(Reply::Held {
                height: plan
                    .promoted
                    .last()
                    .map_or(plan.root.height, |block| block.at.height),
            });
        }
        Err(PlanStop::Substrate(fault)) => {
            shared.fail(ServiceFault::Substrate(fault));
            return None;
        }
    };
    match switched.map(switch_reply) {
        Ok(Ok(reply)) => Some(reply),
        Ok(Err(done)) => {
            offer_carried(shared, Carried::Bodies(done.returned)).await;
            Some(Reply::Switched {
                demoted: done.demoted,
                promoted: done.promoted,
            })
        }
        Err(Asked::Fault(RunFault::StalePlan { .. })) => Some(Reply::Held {
            height: plan
                .promoted
                .last()
                .map_or(plan.root.height, |block| block.at.height),
        }),
        Err(err) => {
            shared.fail(err.into_fault());
            None
        }
    }
}

/// Form `plan` off the runtime. Each block takes a chain permit for the
/// hash; the plan does not pin.
async fn form_switch<S>(
    shared: &Arc<Shared<S>>,
    plan: &crate::connector::SwitchPlan,
) -> Result<crate::plan_form::FormedPlan, PlanStop<S::Fault>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let substrate = Arc::clone(shared.substrate());
    let rules = shared.rules;
    let budget = shared.budget.clone();
    let plan = plan.clone();
    tokio::task::spawn_blocking(move || {
        let threads = budget.permits();
        let gate = move || budget.acquire(Class::Chain);
        form_plan(&plan, rules, &*substrate, threads, &gate)
    })
    .await
    .expect("the plan's forming does not panic")
}

/// Offer carried bodies to the pool. Step 1 runs before the pool lock.
/// A tip that moved parks the bodies for the follower. A pool-file fault
/// retires the pool and leaves block ingest running. A chain fault stops
/// the service.
async fn offer_carried<S>(shared: &Arc<Shared<S>>, carried: Carried)
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    if !shared.pool_is_live() {
        return;
    }
    let prepared = match prepare_carried(shared, carried).await {
        Ok(None) => return,
        Ok(Some(prepared)) => prepared,
        Err(PrepFault::Store(e)) => return shared.fail(e.into()),
        Err(PrepFault::Chain(fault)) => {
            return shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
        }
    };
    let bodies: Vec<Transaction> = prepared.iter().map(|(tx, _)| tx.clone()).collect();
    let done = super::with_pool(shared, move |pool, _, view, rule_set, policy, now| {
        pool.offer_prepared(prepared, now, view, rule_set, policy)
    })
    .await;
    let offers = match done {
        None => return,
        Some(Err(e)) => return shared.fail(e.into()),
        Some(Ok(offers)) => offers,
    };
    let division = super::window::divide_pool_faults(offers.faults, &bodies);
    if let Some(fault) = division.chain {
        return shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
    }
    if let Some(store) = division.file {
        return shared.pool_dead(&store);
    }
    if !division.parked.is_empty() {
        shared.hand_pending(division.parked);
    }
}

/// One carried body's step 1, computed before the pool lock.
type PreparedStep1 = Vec<(Transaction, Result<StatelessPass, InvalidBlock>)>;

/// Step 1 for `carried`, against the chain, with the pool unlocked. `None`
/// when an alternative's bodies are no longer stored.
async fn prepare_carried<S>(
    shared: &Arc<Shared<S>>,
    carried: Carried,
) -> Result<Option<PreparedStep1>, PrepFault>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    tokio::task::spawn_blocking(move || prepare_blocking(&store, rules, carried))
        .await
        .expect("preparing carried bodies does not panic")
}

fn prepare_blocking(
    store: &shekyl_chain_store::store::ChainStore,
    rules: crate::schedule::ChainRules,
    carried: Carried,
) -> Result<Option<PreparedStep1>, PrepFault> {
    let snap = store.begin_read().map_err(PrepFault::Store)?;
    let bodies = match carried {
        Carried::Alt(block) => match snap.alt_block_bodies(&block).map_err(PrepFault::Store)? {
            Some(stored) => stored.into_transactions(),
            None => return Ok(None),
        },
        Carried::Bodies(bodies) => bodies,
    };
    let view = SnapshotView::new(&snap);
    let tip = HeaderView::tip(&view)
        .map_err(Fault::View)
        .map_err(PrepFault::Chain)?;
    let rule_set = rules.in_force(Tip::connecting_height(tip.as_ref()));
    let mut prepared = Vec::with_capacity(bodies.len());
    for tx in bodies {
        match stateless(&tx, &view, &rule_set, None) {
            Ok(step1) => prepared.push((tx, step1)),
            Err(fault) => return Err(PrepFault::Chain(fault)),
        }
    }
    Ok(Some(prepared))
}

/// A connector reply's error without the message type: the handler's
/// fault, or the mailbox.
enum Asked {
    Fault(RunFault),
    Mailbox,
}

impl<M> From<SendError<M, RunFault>> for Asked {
    fn from(err: SendError<M, RunFault>) -> Self {
        match err {
            SendError::HandlerError(fault) => Self::Fault(fault),
            SendError::ActorNotRunning(_)
            | SendError::ActorStopped
            | SendError::MailboxFull(_)
            | SendError::Timeout(_) => Self::Mailbox,
        }
    }
}

impl Asked {
    /// The service's fault for a reply that is not a stale placement.
    fn into_fault<F>(self) -> ServiceFault<F> {
        match self {
            Self::Fault(fault) => ServiceFault::Connector(fault),
            Self::Mailbox => ServiceFault::Mailbox,
        }
    }
}

/// A connector reply's error, as the service's fault.
fn unreachable_or<M, F>(err: SendError<M, RunFault>) -> ServiceFault<F> {
    Asked::from(err).into_fault()
}

/// Whether a connector fault is a stale placement: the arrival is placed
/// again, never refused.
const fn is_stale(fault: &RunFault) -> bool {
    matches!(
        fault,
        RunFault::HeightClaim { .. }
            | RunFault::StaleSeed { .. }
            | RunFault::StaleTarget { .. }
            | RunFault::StaleReference { .. }
            | RunFault::NotAlternative { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::PopBeyondReorgCap;
    use shekyl_types::BlockCount;

    fn beyond() -> PopBeyondReorgCap {
        PopBeyondReorgCap {
            depth: BlockCount::from_raw(721),
            cap: BlockCount::from_raw(720),
        }
    }

    /// A stored alternative past the cap is the proven outcome, not the
    /// door's hint (DX-Q2 item 8).
    #[test]
    fn a_stored_fork_past_the_cap_is_cannot_follow() {
        let Ok(reply) = settled(Offered::BeyondCap(beyond())) else {
            panic!("settled answers a stored fork past the cap");
        };
        assert_eq!(
            reply,
            Reply::CannotFollow(CannotFollow::BeyondCap(beyond()))
        );
    }

    /// Both of a switch's refusals to follow are the proven outcome.
    #[test]
    fn a_switch_past_the_cap_or_below_the_floor_is_cannot_follow() {
        let Ok(past) = switch_reply(Switched::BeyondCap(beyond())) else {
            panic!("a switch past the cap is answered");
        };
        assert_eq!(past, Reply::CannotFollow(CannotFollow::BeyondCap(beyond())));
        let Ok(floor) = switch_reply(Switched::BelowFloor { tip: 9, floor: 4 }) else {
            panic!("a switch below the floor is answered");
        };
        assert_eq!(
            floor,
            Reply::CannotFollow(CannotFollow::BelowFloor {
                tip: BlockHeight::from_raw(9),
                floor: BlockHeight::from_raw(4),
            })
        );
    }
}
