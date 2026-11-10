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
use shekyl_archival_retention::BundleBody;
use shekyl_chain_rules::{
    form, form_judged, Candidate, CenRow, Fault, FormAttempt, FormClaims, HeaderJudged, HeaderView,
    InvalidBlock, StatelessPass, StructurallyValid, Substrate, Tip,
};
use shekyl_chain_store::store::{AltCannot, ChainStore, SnapshotView, StoreCannot, StoreError};
use shekyl_hash_budget::{Class, Permit};
use shekyl_mempool::{stateless, Admission, Duplicate, Pool, PoolFault};
use shekyl_types::archival::BundleReferences;
use shekyl_types::{BlockHash, BlockHeight};
use shekyl_wire::{Block, Transaction};
use tokio::sync::oneshot;

use super::{Accepted, ArrivalTag, CannotFollow, Proof, Reply, ReplySlot, ServiceFault, Shared};
use crate::cache_window::AltSpend;
use crate::connector::{
    Apply, ObserveTarget, OfferAlt, Offered, Reorganize, RunFault, Settlement, Switched,
};
use crate::plan_form::{form_plan, PlanStop};
use crate::router::{claim_alt, claim_run, ClaimStop, ClaimedAlt, Claims};
use crate::substrate::Branch;

/// What a span task carries for an arrival once its bytes parsed.
struct Parsed {
    slot: ReplySlot,
    tag: ArrivalTag,
    block: Block,
    /// The carried bodies, by the hash they claim to list.
    bodies: Vec<Transaction>,
    /// How this arrival is formed. A judged proof is not hashed here.
    proof: Proof,
    /// The bundle references carried beside the block.
    references: Option<BundleReferences>,
    /// The bundle bodies carried beside the block, unverified.
    bundle_bodies: Vec<Vec<u8>>,
}

impl Parsed {
    fn hash(&self) -> BlockHash {
        self.block.hash()
    }
}

/// Bodies a block carried, for the pool's door.
pub(super) enum Carried {
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

/// Parse one accepted arrival. A blob the wire cannot parse is a verdict
/// against the block (CEN-A6); a carried body that does not parse is a body
/// the block's list cannot pair (CEN-G2).
fn parse(accepted: Accepted) -> Result<Parsed, (ReplySlot, ArrivalTag, InvalidBlock)> {
    let Accepted {
        slot,
        tag,
        block,
        bodies,
        proof,
        references,
        bundle_bodies,
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
    // References that are not a section — an empty one, or more than a
    // section holds — are CEN-J29's: no root counts them. What each
    // reference says is the validator's to open.
    let Ok(references) = BundleReferences::from_sidecar(references) else {
        return Err((slot, tag, refused(shekyl_chain_rules::CenRow::J29)));
    };
    Ok(Parsed {
        slot,
        tag,
        block,
        bodies: parsed,
        proof,
        references,
        bundle_bodies,
    })
}

/// Why an arrival did not assemble into a candidate.
enum Assembly {
    /// Listed transactions neither carried nor shown by the pool, by index.
    MissingTxs(Vec<usize>),
    /// A carried bundle body hashes to its reference and does not parse:
    /// the block committed to it, so the block is refused (CEN-J32).
    Refused(InvalidBlock),
    /// The body store could not be read.
    Store(StoreError),
}

/// The candidate for `parsed`: its listed bodies in listed order, then any
/// carried body the list does not name. A listed body the arrival did not
/// carry is resolved from the bodies `pool` shows, and only those: a stem
/// transaction the pool holds counts as missing. The bundle bodies are
/// [`bundle_bodies`]'.
fn assemble(
    parsed: &Parsed,
    pool: Option<&Pool>,
    store: &ChainStore,
) -> Result<Candidate, Assembly> {
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
        return Err(Assembly::MissingTxs(missing));
    }
    listed.extend(carried.into_iter().flatten().cloned());
    let bodies = bundle_bodies(parsed.references.as_ref(), &parsed.bundle_bodies, store)?;
    Ok(Candidate::new(parsed.block.clone(), listed)
        .with_bundle_references(parsed.references.clone())
        .with_bundle_bodies(bodies))
}

/// The body of each of `section`'s references, in section order:
/// one the arrival carried, accepted on hash equality (§7.5) by the
/// validator's [`shekyl_chain_rules::open_body`], or else the one the body
/// store holds under the reference's prunable hash.
///
/// A reference with neither stops the list there. The candidate then lacks
/// that body, which `validate` faults as `Stale::BundleBody`, never a
/// verdict: the sync owner asks 2016 for a body this node does not hold
/// before it offers the block, so a gap here is a driver defect. A
/// reference that does not parse stops the list too; `validate` refuses it
/// (CEN-J29) before it reads a body.
fn bundle_bodies(
    section: Option<&BundleReferences>,
    carried: &[Vec<u8>],
    store: &ChainStore,
) -> Result<Vec<BundleBody>, Assembly> {
    let Some(section) = section else {
        return Ok(Vec::new());
    };
    let mut snapshot = None;
    let mut bodies = Vec::with_capacity(section.as_slice().len());
    for (position, bytes) in section.as_slice().iter().enumerate() {
        let Ok(reference) = shekyl_chain_rules::open_reference(position, bytes) else {
            return Ok(bodies);
        };
        let mut found = None;
        for bytes in carried {
            match shekyl_chain_rules::open_body::<core::convert::Infallible>(&reference, bytes) {
                Ok(body) => {
                    found = Some(body);
                    break;
                }
                Err(shekyl_chain_rules::BundleRefused::Invalid(invalid)) => {
                    return Err(Assembly::Refused(InvalidBlock::new(
                        invalid.row(),
                        shekyl_chain_rules::Locus::Bundle { position },
                    )));
                }
                Err(_) => {}
            }
        }
        if found.is_none() {
            if snapshot.is_none() {
                snapshot = Some(store.begin_read().map_err(Assembly::Store)?);
            }
            let snap = snapshot.as_ref().expect("opened above");
            found = snap
                .bundle_body(reference.prunable_hash())
                .map_err(Assembly::Store)?;
        }
        match found {
            Some(body) => bodies.push(body),
            None => return Ok(bodies),
        }
    }
    Ok(bodies)
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
        let candidate = match assemble(&front, shared.shown_pool().as_deref(), &shared.store) {
            Ok(candidate) => candidate,
            Err(Assembly::MissingTxs(indices)) => {
                let hash = front.hash();
                front.slot.send(Reply::MissingBodies { hash, indices });
                continue;
            }
            Err(Assembly::Refused(refused)) => {
                front.slot.send(Reply::Refused(refused));
                continue;
            }
            Err(Assembly::Store(e)) => return shared.fail(e.into()),
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
                    let Ok(next_candidate) =
                        assemble(next, shared.shown_pool().as_deref(), &shared.store)
                    else {
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
            &FormClaims {
                rule_set: &claims.rule_set,
                seed: claims.seed,
                target: claims.target,
                references: &claims.references,
                network: claims.network,
            },
            &*substrate,
            FormAttempt::FIRST,
        );
        if matches!(verdict, Ok(Err(_))) {
            abandon.store(true, Ordering::Release);
        }
        drop(permit);
        Some(verdict)
    })
}

/// `form_judged` one bound block on a blocking thread. It does not hash, so
/// it takes no hasher permit: the proof inside `judged` is the one chain
/// sync's executor paid for (CS2-Q1). Its time goes to `metrics`, when the
/// service has a sink.
fn spawn_form_judged<F>(
    candidate: Candidate,
    judged: Box<HeaderJudged>,
    claims: Claims,
    abandon: Arc<AtomicBool>,
    metrics: Option<Arc<crate::metrics::Metrics>>,
) -> tokio::task::JoinHandle<Option<Formed<F>>>
where
    F: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        if abandon.load(Ordering::Acquire) {
            return None;
        }
        let started = std::time::Instant::now();
        let verdict = form_judged(candidate, &judged, &claims.references, &claims.network);
        if let Some(metrics) = &metrics {
            metrics.block_formed(started.elapsed());
        }
        if verdict.is_err() {
            abandon.store(true, Ordering::Release);
        }
        Some(Ok(verdict))
    })
}

/// What one form returned.
enum FormedOne<F> {
    /// The header formed.
    Ready(Box<StructurallyValid>),
    /// The header was refused.
    Refused(InvalidBlock),
    /// The cache the hash looked up was not pinned.
    Absent(F),
    /// The substrate faulted.
    Fault(F),
    /// The form was abandoned, or it never started.
    Stopped,
}

/// Sort one form's answer. `absent` says which substrate fault is a cache
/// miss. A form that did not run is [`FormedOne::Stopped`].
fn formed_one<F>(formed: Option<Formed<F>>, absent: impl Fn(&F) -> bool) -> FormedOne<F> {
    match formed {
        Some(Ok(Ok(formed))) => FormedOne::Ready(Box::new(formed)),
        Some(Ok(Err(verdict))) => FormedOne::Refused(verdict),
        Some(Err(fault)) if absent(&fault) => FormedOne::Absent(fault),
        Some(Err(fault)) => FormedOne::Fault(fault),
        None => FormedOne::Stopped,
    }
}

/// Start the arrival's form. A judged proof does not take a permit. A
/// hashed one takes one permit of its class, and returns `None` when the
/// service stopped before that permit.
async fn begin_form<S>(
    shared: &Arc<Shared<S>>,
    proof: Proof,
    candidate: Candidate,
    claims: Claims,
    abandon: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<Option<Formed<S::Fault>>>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    match proof {
        Proof::Judged(judged) => Some(spawn_form_judged(
            candidate,
            judged,
            claims,
            abandon,
            shared.metrics.clone(),
        )),
        Proof::Hash { class } => {
            let held = acquire(shared, class).await?;
            Some(spawn_form(shared, held, candidate, claims, abandon))
        }
    }
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
        .iter()
        .find_map(|parsed| parsed.proof.hash_class())
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
    // A bound arrival does not hash, so only the seeds the rest of the run
    // hashes under are pinned.
    let hashed: Vec<Claims> = claims
        .iter()
        .zip(arrivals.iter())
        .filter(|(_, parsed)| parsed.proof.hash_class().is_some())
        .map(|(claim, _)| claim.clone())
        .collect();
    if !pin_seeds(shared, &distinct_seeds(&hashed), class).await {
        return Next::Halt;
    }
    let abandon = Arc::new(AtomicBool::new(false));
    let mut receivers = Vec::with_capacity(claims.len());
    let mut jobs = Vec::with_capacity(claims.len());
    for (index, (claim, candidate)) in claims.into_iter().zip(candidates).enumerate() {
        let (sender, receiver) = oneshot::channel();
        receivers.push((claim.height, receiver));
        let proof = arrivals[index].proof.clone();
        jobs.push((candidate, claim, proof, sender));
    }
    let launcher = {
        let shared = Arc::clone(shared);
        let abandon = Arc::clone(&abandon);
        tokio::spawn(async move {
            let mut forming = Vec::new();
            for (candidate, claims, proof, sender) in jobs {
                if shared.stopping() || abandon.load(Ordering::Acquire) {
                    break;
                }
                let Some(form) =
                    begin_form(&shared, proof, candidate, claims, Arc::clone(&abandon)).await
                else {
                    break;
                };
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

/// One formed block of a run: the height it claims, the arrival the
/// reply goes to, and the verdict the connector connects.
struct FormedBlock {
    height: BlockHeight,
    arrival: Parsed,
    valid: StructurallyValid,
}

/// What stopped the forms before every arrival of the run was in.
/// The blocks formed before it still land, in the run's one write;
/// this is answered after that write.
enum FormStop {
    /// `form` refused this arrival.
    Refused {
        arrival: Parsed,
        refused: InvalidBlock,
    },
    /// The slots moved under this arrival's hash.
    Again(Parsed),
}

/// Connect a run's formed blocks in one write once every form of the
/// run has ended, or the first refusal or fault has: one transaction,
/// one commit, one `TipChanged` when anything connected.
///
/// The prefix is answered `Connected` before the stop is answered. A
/// crash rolls the open run back. Durability of that one commit is the
/// store's.
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
    let mut formed: Vec<FormedBlock> = Vec::with_capacity(receivers.len());
    let mut form_stop = None;
    for (height, receiver) in receivers {
        let arrival = arrivals.pop_front().expect("one arrival per claim");
        let Ok(form) = receiver.await else {
            return Next::Halt;
        };
        if shared.stopping() {
            abandon.store(true, Ordering::Release);
            return Next::Halt;
        }
        match form {
            Ok(Ok(valid)) => formed.push(FormedBlock {
                height,
                arrival,
                valid,
            }),
            // No form starts after a refusal or a moved slot: the launcher
            // reads `abandon` before each one, so it is set here, not after
            // the write that lands the prefix.
            Ok(Err(refused)) => {
                abandon.store(true, Ordering::Release);
                form_stop = Some(FormStop::Refused { arrival, refused });
                break;
            }
            Err(fault) if shared.substrate().cache_absent(&fault) => {
                abandon.store(true, Ordering::Release);
                form_stop = Some(FormStop::Again(arrival));
                break;
            }
            // A substrate fault fails the service now, before any write:
            // the prefix formed so far does not land on a service that is
            // ending, and the fault is never behind a write's own outcome.
            Err(fault) => {
                abandon.store(true, Ordering::Release);
                shared.fail(ServiceFault::Substrate(fault));
                return Next::Halt;
            }
        }
    }
    if !formed.is_empty() {
        let mut block_arrivals = Vec::with_capacity(formed.len());
        let mut run = Vec::with_capacity(formed.len());
        for block in formed {
            block_arrivals.push(block.arrival);
            run.push((block.height, Ok(block.valid)));
        }
        let submitted = run.len();
        let started = std::time::Instant::now();
        let applied = shared.connector.ask(Apply(run)).await;
        if let Some(metrics) = &shared.metrics {
            metrics.applied(submitted, started.elapsed());
        }
        match applied {
            Ok(mut applied) => {
                let settlement = applied.take_settlement(submitted);
                if let Some(next) = settle(
                    &applied.connected,
                    settlement,
                    &mut block_arrivals,
                    form_stop,
                    arrivals,
                    abandon,
                ) {
                    return next;
                }
            }
            Err(SendError::HandlerError(fault)) if is_stale(&fault) => {
                abandon.store(true, Ordering::Release);
                return Next::Again(carry(block_arrivals, form_stop, arrivals));
            }
            Err(err) => {
                abandon.store(true, Ordering::Release);
                shared.fail(unreachable_or(err));
                return Next::Halt;
            }
        }
    } else if let Some(stop) = form_stop {
        abandon.store(true, Ordering::Release);
        return stop_next(stop, arrivals);
    }
    match stop {
        None => Next::Continue,
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

/// Answer `Connected` for the prefix and leave the unlanded tail in `arrivals`.
fn answer_connected(
    arrivals: &mut Vec<Parsed>,
    connected: &[(BlockHeight, BlockHash)],
    landed: usize,
) {
    let tail = arrivals.split_off(landed);
    for ((height, hash), arrival) in connected.iter().zip(arrivals.drain(..)) {
        arrival.slot.send(Reply::Connected {
            height: *height,
            hash: *hash,
        });
    }
    *arrivals = tail;
}

/// The arrivals a `Next` carries past the write: those formed but not
/// landed, the one that ended the wait, then the rest of the run.
fn carry(
    mut pending: Vec<Parsed>,
    stop: Option<FormStop>,
    queued: &mut VecDeque<Parsed>,
) -> Vec<Parsed> {
    if let Some(stop) = stop {
        let arrival = match stop {
            FormStop::Refused { arrival, .. } | FormStop::Again(arrival) => arrival,
        };
        pending.push(arrival);
    }
    pending.extend(queued.drain(..));
    pending
}

/// Answer a form stop. The caller has already set `abandon`.
fn stop_next(stop: FormStop, queued: &mut VecDeque<Parsed>) -> Next {
    match stop {
        FormStop::Refused { arrival, refused } => {
            arrival.slot.send(Reply::Refused(refused));
            Next::Cancel {
                by: arrival.tag,
                rest: queued.drain(..).collect(),
            }
        }
        FormStop::Again(arrival) => {
            let mut again = vec![arrival];
            again.extend(queued.drain(..));
            Next::Again(again)
        }
    }
}

/// Turn one apply's settlement into the next step. `None` is a run that
/// landed with no form stop: the claim stop, if any, is still to answer.
fn settle(
    connected: &[(BlockHeight, BlockHash)],
    settlement: Settlement,
    arrivals: &mut Vec<Parsed>,
    form_stop: Option<FormStop>,
    queued: &mut VecDeque<Parsed>,
    abandon: &AtomicBool,
) -> Option<Next> {
    match settlement {
        Settlement::Landed { landed } => {
            answer_connected(arrivals, connected, landed);
            match form_stop {
                None => None,
                Some(stop) => {
                    abandon.store(true, Ordering::Release);
                    Some(stop_next(stop, queued))
                }
            }
        }
        // CEN-A2 says the parent is no longer the tip, at the same height:
        // a replacement, not a block this peer proved invalid.
        Settlement::Refused { landed, refused } if refused.rule == CenRow::A2 => {
            answer_connected(arrivals, connected, landed);
            abandon.store(true, Ordering::Release);
            Some(Next::Again(carry(
                std::mem::take(arrivals),
                form_stop,
                queued,
            )))
        }
        Settlement::Refused { landed, refused } => {
            answer_connected(arrivals, connected, landed);
            abandon.store(true, Ordering::Release);
            if arrivals.is_empty() {
                return Some(Next::Halt);
            }
            let arrival = arrivals.remove(0);
            arrival.slot.send(Reply::Refused(refused));
            Some(Next::Cancel {
                by: arrival.tag,
                rest: carry(std::mem::take(arrivals), form_stop, queued),
            })
        }
        Settlement::Short { landed } => {
            answer_connected(arrivals, connected, landed);
            abandon.store(true, Ordering::Release);
            Some(Next::Again(carry(
                std::mem::take(arrivals),
                form_stop,
                queued,
            )))
        }
        Settlement::Broken => {
            abandon.store(true, Ordering::Release);
            Some(Next::Halt)
        }
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
    // The first window is installed before any hash: a hash before it
    // would miss.
    if shared.seed_pair().await.is_none() {
        return Next::Halt;
    }
    let store = Arc::clone(&shared.store);
    let rules = shared.rules;
    let for_claims = candidate.clone();
    let claimed = tokio::task::spawn_blocking(move || claim_alt(&store, rules, &for_claims))
        .await
        .expect("the claim reader does not panic");
    let (claims, prepare) = match claimed {
        Ok(ClaimedAlt::Ready { claims, prepare }) => (claims, prepare),
        Ok(ClaimedAlt::Spend(spend)) => return answer_spend(shared, arrival, spend),
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
    let height = claims.height;
    let proof = arrival.proof.clone();
    let formed = match proof {
        Proof::Hash { class } if prepare => {
            // The branch's own seed block (B2): prepared, never pinned, and
            // the form hashes with the cache the preparation returned. A miss
            // after that is a fault.
            let formed = form_on_branch(shared, class, candidate, claims).await;
            match formed_one(formed, |fault| shared.substrate().cache_absent(fault)) {
                FormedOne::Ready(formed) => *formed,
                FormedOne::Refused(verdict) => return refuse(arrival, verdict),
                FormedOne::Absent(_) => {
                    shared.fail(ServiceFault::PreparedSeedAbsent { height });
                    return Next::Halt;
                }
                FormedOne::Fault(fault) => {
                    shared.fail(ServiceFault::Substrate(fault));
                    return Next::Halt;
                }
                FormedOne::Stopped => return Next::Halt,
            }
        }
        proof => {
            let judged = matches!(proof, Proof::Judged(_));
            let Some(forming) = begin_form(
                shared,
                proof,
                candidate,
                claims,
                Arc::new(AtomicBool::new(false)),
            )
            .await
            else {
                return Next::Halt;
            };
            match formed_one(
                forming.await.expect("a form worker does not panic"),
                |fault| !judged && shared.substrate().cache_absent(fault),
            ) {
                FormedOne::Ready(formed) => *formed,
                FormedOne::Refused(verdict) => return refuse(arrival, verdict),
                FormedOne::Absent(_) => {
                    // A below-fork seed is one of the pair the claim judged on
                    // its snapshot; the slots lag that pair until the window is
                    // installed for it. Install it, under a chain permit, and
                    // place the arrival again.
                    if let Err(stop) = super::install_window(shared).await {
                        super::record_window_stop(shared, stop);
                        return Next::Halt;
                    }
                    return Next::Again(vec![arrival]);
                }
                // A judged form does not hash. A fault there, or a form that
                // was abandoned, stops this arrival and names no verdict.
                FormedOne::Fault(_) if judged => return Next::Halt,
                FormedOne::Fault(fault) => {
                    shared.fail(ServiceFault::Substrate(fault));
                    return Next::Halt;
                }
                FormedOne::Stopped => return Next::Halt,
            }
        }
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
        Offered::Held { .. } | Offered::BeyondCap { .. } | Offered::SwitchDue(_)
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
        Offered::BeyondCap { beyond, .. } => {
            Ok(Reply::CannotFollow(CannotFollow::BeyondCap(beyond)))
        }
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
        Switched::BeyondCap { beyond, .. } => {
            Ok(Reply::CannotFollow(CannotFollow::BeyondCap(beyond)))
        }
        Switched::BelowFloor { tip, floor, .. } => {
            Ok(Reply::CannotFollow(CannotFollow::BelowFloor {
                tip: BlockHeight::from_raw(tip),
                floor: BlockHeight::from_raw(floor),
            }))
        }
    }
}

/// The early gate's answer. Nothing was stored and nothing was hashed. A
/// below-fork seed the window does not hold is this node's defect: the
/// service stops on it, and the arrival is answered `Stopped`.
fn answer_spend<S>(shared: &Arc<Shared<S>>, arrival: Parsed, spend: AltSpend) -> Next
where
    S: Substrate,
    S::Fault: core::fmt::Debug,
{
    match spend {
        AltSpend::Hash | AltSpend::Prepare => unreachable!("a hash is the ready arm"),
        AltSpend::BeyondCap(beyond) => {
            arrival.slot.send(Reply::BeyondCap(beyond));
            Next::Continue
        }
        AltSpend::SeedNotInWindow { height } => {
            shared.fail(ServiceFault::SeedNotInWindow { height });
            Next::Halt
        }
    }
}

/// Form one alternative under its branch's own seed (B2). The branch gate
/// first, then a permit of the arrival's class, then the preparation under
/// the pin lock: the lock order every pin takes. The form hashes with the
/// cache the preparation returned. `None` when the service stopped.
async fn form_on_branch<S>(
    shared: &Arc<Shared<S>>,
    class: Class,
    candidate: Candidate,
    claims: Claims,
) -> Option<Formed<S::Fault>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let _one_branch = shared.branch_form().await;
    let permit = acquire(shared, class).await?;
    let worker = Arc::clone(shared);
    let formed = tokio::task::spawn_blocking(move || {
        let seed = claims.seed;
        let held = {
            let _pin = worker
                .pin_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            worker.substrate().prepare_seed(&seed)
        };
        worker.note_prepared(seed);
        let held = [(seed, held)];
        let branch = Branch::new(&**worker.substrate(), &held);
        let verdict = form(
            candidate,
            &FormClaims {
                rule_set: &claims.rule_set,
                seed,
                target: claims.target,
                references: &claims.references,
                network: claims.network,
            },
            &branch,
            FormAttempt::FIRST,
        );
        drop(permit);
        verdict
    })
    .await
    .expect("a branch form does not panic");
    Some(formed)
}

/// The seeds a switch's promoted run names on its own branch: above the
/// fork point (B2 item 4). Distinct, ascending.
fn branch_seeds(plan: &crate::connector::SwitchPlan) -> Vec<BlockHash> {
    let mut seeds: Vec<BlockHash> = Vec::new();
    for promoted in &plan.promoted {
        let on_branch = shekyl_chain_rules::seed_height(promoted.at.height)
            .is_some_and(|at| at > plan.root.height);
        if on_branch && !seeds.contains(&promoted.at.seed) {
            seeds.push(promoted.at.seed);
        }
    }
    seeds
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

/// Carry out a switch an arrival made due. Promoted blocks that name
/// their branch's own seed are formed under a preparation of it (B2 item
/// 4), behind the branch gate. A below-fork seed the slots lag reinstalls
/// the window once, under a permit. A cache still absent after that is a
/// fault: every seed the switch names was prepared or installed.
async fn carry_out<S>(shared: &Arc<Shared<S>>, plan: crate::connector::SwitchPlan) -> Option<Reply>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
{
    let seeds = branch_seeds(&plan);
    let _one_branch = if seeds.is_empty() {
        None
    } else {
        Some(shared.branch_form().await)
    };
    let held = prepare_all(shared, &seeds).await?;
    let mut formed = form_switch(shared, &plan, Arc::clone(&held)).await;
    if let Err(PlanStop::Substrate(fault)) = &formed {
        if shared.substrate().cache_absent(fault) {
            if let Err(stop) = super::install_window(shared).await {
                super::record_window_stop(shared, stop);
                return None;
            }
            formed = form_switch(shared, &plan, held).await;
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
            shared.fail(ServiceFault::PreparedSeedAbsent {
                height: plan
                    .promoted
                    .last()
                    .map_or(plan.root.height, |block| block.at.height),
            });
            return None;
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

/// Prepare each of a switch's branch seeds under a chain permit and the
/// pin lock, one at a time. `None` when the service stopped.
async fn prepare_all<S>(
    shared: &Arc<Shared<S>>,
    seeds: &[BlockHash],
) -> Option<Arc<Vec<(BlockHash, S::Held)>>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
    S::Held: 'static,
{
    let mut held = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        let permit = acquire(shared, Class::Chain).await?;
        let worker = Arc::clone(shared);
        let cache = tokio::task::spawn_blocking(move || {
            let cache = {
                let _pin = worker
                    .pin_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                worker.substrate().prepare_seed(&seed)
            };
            worker.note_prepared(seed);
            drop(permit);
            cache
        })
        .await
        .expect("a preparation does not panic");
        held.push((seed, cache));
    }
    Some(Arc::new(held))
}

/// Form `plan` off the runtime, hashing each prepared branch seed under
/// its held cache. Each block takes a chain permit for the hash; the plan
/// does not pin.
async fn form_switch<S>(
    shared: &Arc<Shared<S>>,
    plan: &crate::connector::SwitchPlan,
    held: Arc<Vec<(BlockHash, S::Held)>>,
) -> Result<crate::plan_form::FormedPlan, PlanStop<S::Fault>>
where
    S: Substrate + Send + Sync + 'static,
    S::Fault: core::fmt::Debug + Send + 'static,
    S::Held: 'static,
{
    let substrate = Arc::clone(shared.substrate());
    let rules = shared.rules;
    let budget = shared.budget.clone();
    let plan = plan.clone();
    tokio::task::spawn_blocking(move || {
        let threads = budget.permits();
        let gate = move || budget.acquire(Class::Chain);
        let branch = Branch::new(&*substrate, held.as_slice());
        form_plan(&plan, rules, &branch, threads, &gate)
    })
    .await
    .expect("the plan's forming does not panic")
}

/// Offer carried bodies to the pool. Step 1 runs before the pool lock.
/// A tip that moved parks the bodies for the follower. A pool-file fault
/// retires the pool and leaves block ingest running. A chain fault stops
/// the service.
pub(super) async fn offer_carried<S>(shared: &Arc<Shared<S>>, carried: Carried)
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
    // A returned body the pool now shows is a shown-set change the relay's
    // hook never sees (it came from a block, not a submit), and its
    // admission judged at the tip the pop left, which the pool's work order
    // keeps behind the heavier tip it last judged at: the attendant's
    // reconcile re-judges at this tip and the next build lists it. Without
    // the wake the posted job stayed the one built before the return, and a
    // `generateblocks` after a pop waited on it for ever.
    let shown_changed = offers.admissions.iter().any(|(_, admission)| {
        matches!(
            admission,
            Admission::Admitted { .. } | Admission::Duplicate(Duplicate::InPool)
        )
    });
    let division = super::window::divide_pool_faults(offers.faults, &bodies);
    if let Some(fault) = division.chain {
        return shared.fail(ServiceFault::Pool(PoolFault::Chain(fault)));
    }
    if let Some(store) = division.file {
        return shared.pool_dead(&store);
    }
    if !division.parked.is_empty() {
        shared.hand_pending(division.parked);
    } else if shown_changed {
        shared.shown_changed();
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
        match stateless(&tx, &view, &rule_set, &rules.trust().network_id(), None) {
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

    fn evidence() -> shekyl_chain_store::codec::FollowingDegraded {
        shekyl_chain_store::codec::FollowingDegraded {
            fork_at: shekyl_types::BlockHeight::from_raw(1),
            tip: shekyl_types::BlockHash::from_bytes([2u8; 32]),
            work: shekyl_difficulty::CumulativeDifficulty::from_raw(3),
        }
    }

    /// A stored alternative past the cap is the proven outcome, not the
    /// door's hint (DX-Q2 item 8).
    #[test]
    fn a_stored_fork_past_the_cap_is_cannot_follow() {
        let Ok(reply) = settled(Offered::BeyondCap {
            beyond: beyond(),
            evidence: evidence(),
        }) else {
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
        let Ok(past) = switch_reply(Switched::BeyondCap {
            beyond: beyond(),
            evidence: evidence(),
        }) else {
            panic!("a switch past the cap is answered");
        };
        assert_eq!(past, Reply::CannotFollow(CannotFollow::BeyondCap(beyond())));
        let Ok(floor) = switch_reply(Switched::BelowFloor {
            tip: 9,
            floor: 4,
            evidence: evidence(),
        }) else {
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

    /// Assembly finds each reference's body (the switch's C3): one the
    /// arrival carried, by hash; else the one the body store holds; and a
    /// carried body that hashes to its reference and does not parse is the
    /// block's own defect, refused at that reference (CEN-J32). A reference
    /// with neither stops the list for `validate` to fault.
    ///
    /// Red edits: drop the store lookup — the queued body is not found;
    /// map a malformed carried body to "not this reference's" — no
    /// refusal.
    #[test]
    fn bundle_bodies_come_carried_or_from_the_store_and_a_malformed_one_is_refused() {
        use shekyl_archival_retention::{bundle_prunable_hash, BundleKept, BundleRef, PassBitmap};
        use shekyl_chain_rules::harness::bundle::BundleWorld;
        use shekyl_chain_rules::RuleSet;

        let rules = RuleSet::GENESIS;
        let carried_world = BundleWorld::with(
            shekyl_types::BlockHeight::from_raw(5),
            BundleWorld::SEED,
            0,
            &rules,
        );
        let (carried_ref, carried_body) = carried_world.bundle(&[]);
        let stored_world = BundleWorld::with(
            shekyl_types::BlockHeight::from_raw(6),
            BundleWorld::SEED,
            0,
            &rules,
        );
        let (stored_ref, stored_body) = stored_world.bundle(&[]);
        let absent_world = BundleWorld::with(
            shekyl_types::BlockHeight::from_raw(7),
            BundleWorld::SEED,
            0,
            &rules,
        );
        let (absent_ref, _) = absent_world.bundle(&[]);

        let path = crate::test_support::tmp("span-bundle-bodies");
        let store = crate::test_support::open_store(&path);
        let queued: Result<(), StoreError> = store.write(|batch| {
            batch.queue_bundle(
                &stored_ref,
                &stored_body,
                shekyl_types::BlockHeight::from_raw(6),
                shekyl_types::BlockHash::from_bytes([0x11; 32]),
                64,
            )
        });
        queued.expect("the store holds the second body");

        let section = |refs: &[&BundleRef]| {
            BundleReferences::new(refs.iter().map(|r| r.encode()).collect()).expect("a section")
        };
        let both = section(&[&carried_ref, &stored_ref]);
        let found = bundle_bodies(Some(&both), &[carried_body.as_bytes().to_vec()], &store)
            .ok()
            .expect("both bodies resolve");
        assert_eq!(found, vec![carried_body.clone(), stored_body.clone()]);

        let gap = section(&[&carried_ref, &absent_ref, &stored_ref]);
        let found = bundle_bodies(Some(&gap), &[carried_body.as_bytes().to_vec()], &store)
            .ok()
            .expect("the list stops at the gap");
        assert_eq!(
            found,
            vec![carried_body],
            "a body nobody holds stops the list"
        );

        let garbage = vec![0xEE; 64];
        let none = PassBitmap::new(0, &[]).expect("an empty bitmap");
        let malformed_ref = BundleRef::new(
            BundleKept {
                h: shekyl_types::BlockHeight::from_raw(8),
                seed: [0x5E; 32],
                passes: none.clone(),
                support: none,
            },
            bundle_prunable_hash(&garbage),
        );
        let malformed = section(&[&malformed_ref]);
        match bundle_bodies(Some(&malformed), &[garbage], &store) {
            Err(Assembly::Refused(refused)) => {
                assert_eq!(refused.rule, shekyl_chain_rules::CenRow::J32);
                assert_eq!(
                    refused.locus,
                    shekyl_chain_rules::Locus::Bundle { position: 0 }
                );
            }
            Ok(_) => panic!("a malformed committed body was accepted"),
            Err(_) => panic!("a malformed committed body was not refused"),
        }
        drop(store);
    }
}
