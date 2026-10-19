// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ingest service over scenario chains (`DRS_X_STORE_FLIP.md` PR2-Q1,
//! PR2-Q5): blocks a scenario driver mined elsewhere arrive at a service
//! over a fresh store, the way a peer's blocks do.
//!
//! The service's substrate is [`Gated`]: the free longhash, a clock ahead
//! of every scenario timestamp, and a gate a test closes on one block's
//! hash to hold its `form` while another arrival's write moves the tip
//! under it.

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use shekyl_chain_rules::Substrate;
use shekyl_chain_store::store::ChainStore;
use shekyl_types::{BlockHash, BlockHeight, PowHash, Timestamp};

use super::{Arrival, ArrivalTag, Door, Origin, Refusal, Reply, Service, ServiceConfig, SessionId};
use crate::connector::Rewind;
use crate::scenario::{Mined, Scenario, CLOCK_START, RULES};
use crate::test_support::{cleanup, open_store, tmp};
use shekyl_hash_budget::Budget;

/// The free longhash under a clock ahead of the scenarios', with a gate.
pub(crate) struct Gated {
    held: Mutex<HashSet<BlockHash>>,
    opened: Condvar,
    hashes: AtomicUsize,
    /// Longhashes that met a closed gate and waited.
    waited: AtomicUsize,
    /// Seeds pinned: every cache this substrate was asked to build.
    pins: AtomicUsize,
}

impl Gated {
    pub(crate) fn new() -> Self {
        Self {
            held: Mutex::new(HashSet::new()),
            opened: Condvar::new(),
            hashes: AtomicUsize::new(0),
            waited: AtomicUsize::new(0),
            pins: AtomicUsize::new(0),
        }
    }

    /// Hold `block`'s longhash until [`Self::open`].
    pub(crate) fn hold(&self, block: BlockHash) {
        self.held.lock().expect("gate").insert(block);
    }

    /// Let `block`'s longhash run.
    pub(crate) fn open(&self, block: BlockHash) {
        self.held.lock().expect("gate").remove(&block);
        self.opened.notify_all();
    }

    /// Longhashes computed so far.
    pub(crate) fn hashes(&self) -> usize {
        self.hashes.load(Ordering::Acquire)
    }

    /// Seeds pinned so far.
    pub(crate) fn pins(&self) -> usize {
        self.pins.load(Ordering::Acquire)
    }

    /// Wait until a longhash has met a closed gate: the held block is in
    /// `form`, so its placement was made.
    pub(crate) async fn until_held(&self) {
        while self.waited.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    }
}

impl Substrate for Gated {
    type Fault = std::convert::Infallible;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(Timestamp::from_raw(CLOCK_START.to_raw() + 1_000_000))
    }

    fn longhash(&self, pow_blob: &[u8], _seed: &BlockHash) -> Result<PowHash, Self::Fault> {
        let identity = shekyl_wire::identity_of_pow_blob(pow_blob);
        let mut held = self.held.lock().expect("gate");
        if held.contains(&identity) {
            self.waited.fetch_add(1, Ordering::AcqRel);
        }
        while held.contains(&identity) {
            held = self.opened.wait(held).expect("gate");
        }
        drop(held);
        self.hashes.fetch_add(1, Ordering::AcqRel);
        Ok(PowHash::from_bytes([0; 32]))
    }

    fn pin_seed(&self, _seed: &BlockHash) {
        self.pins.fetch_add(1, Ordering::AcqRel);
    }
}

/// `mined` as a peer's arrival on `session`.
pub(crate) fn arrival(tag: u64, session: u64, mined: &Mined) -> Arrival {
    Arrival {
        tag: ArrivalTag(tag),
        origin: Origin::Peer {
            session: SessionId(session),
            solicited: true,
        },
        block: mined.template.block.serialize(),
        bodies: mined
            .template
            .transactions
            .iter()
            .map(shekyl_wire::Transaction::serialize)
            .collect(),
    }
}

/// A service over a fresh store named `name`, and the store's path.
pub(crate) fn service(
    name: &str,
    substrate: Arc<Gated>,
    config: ServiceConfig,
) -> (Service<Gated>, std::path::PathBuf) {
    service_on(name, substrate, config, Budget::of_host())
}

/// [`service`] taking its permits from `budget`.
pub(crate) fn service_on(
    name: &str,
    substrate: Arc<Gated>,
    config: ServiceConfig,
    budget: Budget,
) -> (Service<Gated>, std::path::PathBuf) {
    let path = tmp(name);
    let store: ChainStore = open_store(&path);
    (
        Service::start(
            Arc::new(store),
            RULES,
            substrate,
            config,
            budget,
            super::Follow::default(),
        ),
        path,
    )
}

/// [`service`] under `rules`, over a store opened under the rule set in
/// force at genesis.
pub(crate) fn service_under(
    name: &str,
    substrate: Arc<Gated>,
    config: ServiceConfig,
    rules: crate::schedule::ChainRules,
) -> (Service<Gated>, std::path::PathBuf) {
    let path = tmp(name);
    let store = crate::test_support::open_store_under(
        &path,
        &rules.in_force(BlockHeight::ZERO),
        shekyl_chain_store::apply_policy::ApplyPolicy::Full,
    );
    (
        Service::start(
            Arc::new(store),
            rules,
            substrate,
            config,
            Budget::of_host(),
            super::Follow::default(),
        ),
        path,
    )
}

/// Offer `blocks` as one span from `session` and wait for every reply.
pub(crate) async fn offer_all(door: &Door, session: u64, blocks: &[Mined]) -> Vec<Reply> {
    // A caller asks for room before it sends: spans no larger than the
    // room the door reports, each answered before the next.
    let mut replies = Vec::new();
    let mut index = 0u64;
    for chunk in blocks.chunks(door.room().max(1)) {
        let span = chunk
            .iter()
            .map(|m| {
                index += 1;
                arrival(session * 1_000 + index - 1, session, m)
            })
            .collect();
        let tickets = door.offer_span(span).expect("room");
        for ticket in tickets {
            replies.push(ticket.reply().await.reply);
        }
    }
    replies
}

/// What the store holds for `hash`: on the main chain, as an alt row.
fn homes(service: &Service<Gated>, hash: BlockHash) -> (bool, bool) {
    let store = Arc::clone(&service.shared.store);
    let snap = store.begin_read().expect("read");
    (
        snap.height_of(&hash).expect("height").is_some(),
        snap.has_alt_block(&hash).expect("alt"),
    )
}

/// A prefix mined by one driver connects through the door, each block
/// answered `Connected` at its height.
#[tokio::test(flavor = "multi_thread")]
async fn a_span_from_the_tip_connects_in_order() {
    let mut y = Scenario::open("service-span-y");
    let blocks = y.mine(6).await;
    let gate = Arc::new(Gated::new());
    let (service, path) = service("service-span", Arc::clone(&gate), ServiceConfig::default());
    let replies = offer_all(&service.door(), 1, &blocks).await;
    for (mined, reply) in blocks.iter().zip(&replies) {
        assert_eq!(
            *reply,
            Reply::Connected {
                height: mined.height,
                hash: mined.hash
            }
        );
    }
    service.stop().await.expect("stops");
    y.close().await;
    cleanup(&path);
}

/// Two arrivals at one height from two sessions: one connects and the
/// other is held as an alternative. Neither is connected twice.
#[tokio::test(flavor = "multi_thread")]
async fn two_arrivals_at_one_height_one_connects_and_one_is_held() {
    let mut y = Scenario::open("service-two-y");
    let mut z = Scenario::open("service-two-z");
    let prefix = y.mine(4).await;
    z.mine(4).await;
    y.idle();
    let a = y.mine(1).await;
    let b = z.mine(1).await;
    assert_ne!(a[0].hash, b[0].hash, "two blocks at one height");
    let (service, path) = service(
        "service-two",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
    );
    let door = service.door();
    offer_all(&door, 1, &prefix).await;
    let first = door.offer(arrival(10, 2, &a[0])).expect("room");
    let second = door.offer(arrival(20, 3, &b[0])).expect("room");
    let replies = [first.reply().await.reply, second.reply().await.reply];
    let connected = replies
        .iter()
        .filter(|r| matches!(r, Reply::Connected { .. }))
        .count();
    let held = replies
        .iter()
        .filter(|r| matches!(r, Reply::Held { .. }))
        .count();
    assert_eq!((connected, held), (1, 1), "{replies:?}");
    for hash in [a[0].hash, b[0].hash] {
        let (main, alt) = homes(&service, hash);
        assert!(main ^ alt, "{hash:?} has exactly one home");
    }
    service.stop().await.expect("stops");
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}

/// One block id from two sessions, placed once as an alternative and once
/// as an extension: after both settle it is in exactly one of the main
/// chain and the alt table. The tip moves between the two placements by an
/// operator rewind, which leaves the alternative row standing on the tip.
#[tokio::test(flavor = "multi_thread")]
async fn one_block_placed_alt_then_extend_has_one_home() {
    let mut y = Scenario::open("service-home-y");
    let mut z = Scenario::open("service-home-z");
    let prefix = y.mine(4).await;
    z.mine(4).await;
    y.idle();
    let tip = y.mine(1).await;
    let x = z.mine(1).await;
    let (service, path) = service(
        "service-home",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
    );
    let door = service.door();
    offer_all(&door, 1, &prefix).await;
    offer_all(&door, 1, &tip).await;
    // Session 2: x's parent is not the tip, so it is offered as an
    // alternative and held.
    let held = door
        .offer(arrival(20, 2, &x[0]))
        .expect("room")
        .reply()
        .await;
    assert!(matches!(held.reply, Reply::Held { .. }), "{held:?}");
    assert_eq!(homes(&service, x[0].hash), (false, true));
    // The operator pops the tip: x's parent is the tip now.
    service
        .connector()
        .ask(Rewind {
            to: BlockHeight::from_raw(3),
        })
        .await
        .expect("rewind");
    // Session 3: the same block, placed as an extension.
    let connected = door
        .offer(arrival(30, 3, &x[0]))
        .expect("room")
        .reply()
        .await;
    assert_eq!(
        connected.reply,
        Reply::Connected {
            height: x[0].height,
            hash: x[0].hash
        }
    );
    assert_eq!(
        homes(&service, x[0].hash),
        (true, false),
        "the connect took x out of the alt table"
    );
    service.stop().await.expect("stops");
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}

/// An extension whose parent stops being the tip before it connects is
/// placed again, and ends as the work says: a block at the height another
/// session filled is held; on a branch with more work after it, the switch
/// follows.
#[tokio::test(flavor = "multi_thread")]
async fn an_extension_whose_parent_moves_is_placed_again() {
    let mut y = Scenario::open("service-moves-y");
    let mut z = Scenario::open("service-moves-z");
    let prefix = y.mine(4).await;
    z.mine(4).await;
    y.idle();
    let mine = y.mine(2).await;
    let theirs = z.mine(1).await;
    let gate = Arc::new(Gated::new());
    let (service, path) = service("service-moves", Arc::clone(&gate), ServiceConfig::default());
    let door = service.door();
    offer_all(&door, 1, &prefix).await;
    // `mine[0]` is placed as an extension and held in `form` ...
    gate.hold(mine[0].hash);
    let held = door.offer(arrival(10, 2, &mine[0])).expect("room");
    gate.until_held().await;
    // ... while another session's block at the same height connects.
    let other = door
        .offer(arrival(20, 3, &theirs[0]))
        .expect("room")
        .reply()
        .await;
    assert!(matches!(other.reply, Reply::Connected { .. }), "{other:?}");
    gate.open(mine[0].hash);
    let replaced = held.reply().await;
    assert!(
        matches!(replaced.reply, Reply::Held { height } if height == mine[0].height),
        "placed again as an alternative: {replaced:?}"
    );
    // Its successor carries the branch past the incumbent: the switch.
    let switched = door
        .offer(arrival(11, 2, &mine[1]))
        .expect("room")
        .reply()
        .await;
    match switched.reply {
        Reply::Switched { promoted, .. } => {
            assert_eq!(
                promoted,
                vec![
                    (mine[0].height, mine[0].hash),
                    (mine[1].height, mine[1].hash)
                ]
            );
        }
        other => panic!("the heavier branch switches: {other:?}"),
    }
    service.stop().await.expect("stops");
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}

/// Room is asked before sending: a span larger than the room is refused
/// before acceptance and nothing of it is kept, the room comes back as
/// arrivals are answered, and a stop answers every accepted arrival not yet
/// connected `Stopped`.
#[tokio::test(flavor = "multi_thread")]
async fn no_room_is_refused_before_acceptance_and_a_stop_answers_stopped() {
    let mut y = Scenario::open("service-room-y");
    let blocks = y.mine(4).await;
    let gate = Arc::new(Gated::new());
    let config = ServiceConfig {
        // Three seats: one stays reserved, so a sync caller sees two.
        room: NonZeroUsize::new(3).expect("three"),
    };
    let (service, path) = service_on(
        "service-room",
        Arc::clone(&gate),
        config,
        Budget::new(NonZeroUsize::MIN),
    );
    let door = service.door();
    assert_eq!(door.room(), 2);
    let span: Vec<_> = blocks[..3]
        .iter()
        .map(|m| arrival(m.height.to_raw(), 1, m))
        .collect();
    assert_eq!(door.offer_span(span).err(), Some(Refusal::NoRoom));
    assert_eq!(door.room(), 2, "nothing of a refused span is kept");
    let replies = offer_all(&door, 1, &blocks[..2]).await;
    assert!(replies.iter().all(|r| matches!(r, Reply::Connected { .. })));
    assert_eq!(door.room(), 2, "each reply gives its room back");

    // An arrival held in `form`, and the next block behind it in its span.
    gate.hold(blocks[2].hash);
    let tickets = door
        .offer_span(vec![arrival(30, 1, &blocks[2]), arrival(31, 1, &blocks[3])])
        .expect("room");
    gate.until_held().await;
    let stop = tokio::spawn(service.stop());
    // The held `form` finishes and its block may connect; the stop answers
    // the rest.
    while !stop.is_finished() && door.room() != 0 {
        tokio::task::yield_now().await;
    }
    gate.open(blocks[2].hash);
    stop.await.expect("joins").expect("stops");
    for ticket in tickets {
        let tagged = ticket.reply().await;
        if tagged.tag == ArrivalTag(31) {
            assert_eq!(
                tagged.reply,
                Reply::Stopped,
                "not connected before the stop"
            );
        } else {
            assert!(
                matches!(tagged.reply, Reply::Stopped | Reply::Connected { .. }),
                "{tagged:?}"
            );
        }
    }
    assert_eq!(door.room(), 0, "a stopped door has no room");
    y.close().await;
    cleanup(&path);
}

/// CEN-A1, held by the router: an arrival this node holds — on the main
/// chain, or as an alternative block off the tip — is `AlreadyHeld`, and
/// nothing is formed or written for it.
#[tokio::test]
async fn an_arrival_this_node_holds_is_already_held() {
    let mut y = Scenario::open("service-a1-y");
    let mut z = Scenario::open("service-a1-z");
    let prefix = y.mine(3).await;
    z.mine(3).await;
    y.idle();
    let tip = y.mine(1).await;
    let side = z.mine(1).await;
    let gate = Arc::new(Gated::new());
    let (service, path) = service("service-a1", Arc::clone(&gate), ServiceConfig::default());
    let door = service.door();
    offer_all(&door, 1, &prefix).await;
    offer_all(&door, 1, &tip).await;
    let held = door
        .offer(arrival(20, 2, &side[0]))
        .expect("room")
        .reply()
        .await;
    assert!(matches!(held.reply, Reply::Held { .. }), "{held:?}");
    let hashed = gate.hashes();
    for (tag, mined) in [(30, &prefix[1]), (31, &tip[0]), (32, &side[0])] {
        let again = door
            .offer(arrival(tag, 3, mined))
            .expect("room")
            .reply()
            .await;
        assert_eq!(again.reply, Reply::AlreadyHeld, "{:?}", mined.height);
    }
    assert_eq!(gate.hashes(), hashed, "nothing held is formed again");
    service.stop().await.expect("stops");
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}

/// CEN-A4, held by the router: an arrival whose parent neither table holds
/// is `Unlinked` at that parent and is not stored. There is no orphan
/// store.
#[tokio::test]
async fn an_arrival_whose_parent_is_unheld_is_unlinked_and_not_stored() {
    let mut y = Scenario::open("service-a4-y");
    let blocks = y.mine(4).await;
    let gate = Arc::new(Gated::new());
    let (service, path) = service("service-a4", Arc::clone(&gate), ServiceConfig::default());
    let door = service.door();
    offer_all(&door, 1, &blocks[..2]).await;
    let orphan = door
        .offer(arrival(30, 2, &blocks[3]))
        .expect("room")
        .reply()
        .await;
    assert_eq!(orphan.reply, Reply::Unlinked { at: blocks[2].hash });
    assert_eq!(homes(&service, blocks[3].hash), (false, false));
    service.stop().await.expect("stops");
    y.close().await;
    cleanup(&path);
}

/// A service whose session buckets refill by a clock the test advances.
fn service_with_clock(
    name: &str,
    substrate: Arc<Gated>,
    config: ServiceConfig,
) -> (
    Service<Gated>,
    std::path::PathBuf,
    Arc<std::sync::atomic::AtomicU64>,
) {
    let path = tmp(name);
    let store: ChainStore = open_store(&path);
    let millis = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let read = Arc::clone(&millis);
    let clock: super::Clock =
        Arc::new(move || std::time::Duration::from_millis(read.load(Ordering::Acquire)));
    (
        Service::start_with_clock(
            Arc::new(store),
            RULES,
            substrate,
            config,
            Budget::of_host(),
            super::Follow::default(),
            clock,
        ),
        path,
        millis,
    )
}

/// An arrival of `len` junk bytes on `session`.
fn junk(tag: u64, session: u64, solicited: bool, len: usize) -> Arrival {
    Arrival {
        tag: ArrivalTag(tag),
        origin: Origin::Peer {
            session: SessionId(session),
            solicited,
        },
        block: vec![0xA5; len],
        bodies: Vec::new(),
    }
}

/// Two unsolicited arrivals per target interval pass a session's bucket
/// and the third is `Throttled` before it is parsed: its bytes are junk,
/// and no reply is owed for it. The bucket refills a token per half
/// interval. A span this node asked for takes no tokens, and another
/// session has its own bucket.
#[tokio::test]
async fn the_third_unsolicited_arrival_in_an_interval_is_throttled_before_parse() {
    let (service, path, millis) = service_with_clock(
        "service-bucket",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
    );
    let door = service.door();
    let first = door.offer(junk(1, 5, false, 64)).expect("a token");
    let second = door.offer(junk(2, 5, false, 64)).expect("a token");
    assert_eq!(
        door.offer(junk(3, 5, false, 64)).err(),
        Some(Refusal::Throttled)
    );
    // The two accepted ones were parsed, and are junk.
    for ticket in [first, second] {
        assert!(matches!(ticket.reply().await.reply, Reply::Refused(_)));
    }
    let solicited: Vec<_> = (10..15).map(|tag| junk(tag, 5, true, 64)).collect();
    let tickets = door
        .offer_span(solicited)
        .expect("solicited takes no tokens");
    for ticket in tickets {
        let _ = ticket.reply().await;
    }
    assert!(
        door.offer(junk(20, 6, false, 64)).is_ok(),
        "another session"
    );
    let half = shekyl_difficulty::T_SECONDS * 1_000 / 2;
    millis.store(half - 1, Ordering::Release);
    assert_eq!(
        door.offer(junk(4, 5, false, 64)).err(),
        Some(Refusal::Throttled)
    );
    millis.store(half, Ordering::Release);
    assert!(
        door.offer(junk(5, 5, false, 64)).is_ok(),
        "one token earned"
    );
    service.stop().await.expect("stops");
    cleanup(&path);
}

/// An arrival one byte over the bound is refused before parse; one at the
/// bound is accepted, and its junk is then refused by the parser.
#[tokio::test]
async fn an_arrival_one_byte_over_the_bound_is_oversize_before_parse() {
    let (service, path) = service(
        "service-oversize",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
    );
    let door = service.door();
    let (_, bound) = crate::admission::ArrivalBound::at(&service.shared.store).expect("bound");
    let at = usize::try_from(bound.0).expect("fits");
    assert_eq!(
        door.offer(junk(1, 1, true, at + 1)).err(),
        Some(Refusal::Oversize)
    );
    let accepted = door.offer(junk(2, 1, true, at)).expect("at the bound");
    assert!(matches!(accepted.reply().await.reply, Reply::Refused(_)));
    service.stop().await.expect("stops");
    cleanup(&path);
}

/// A span with a refused block in the middle: the blocks before it
/// connect, it is `Refused`, every block after it is `Cancelled` by it, and
/// no hash starts after the refusal — the substrate's calls are the
/// connected blocks' alone. The refused block carries a non-zero
/// `minor_version` (CEN-B2), a header row `form` judges before the
/// longhash, and the block after it names it as its parent, so it is in
/// the same run and launched behind it.
#[tokio::test]
async fn a_refused_block_cancels_the_rest_of_its_span_and_no_hash_starts_after_it() {
    let mut y = Scenario::open("service-cancel-y");
    let blocks = y.mine(6).await;
    let gate = Arc::new(Gated::new());
    let (service, path) = service_on(
        "service-cancel",
        Arc::clone(&gate),
        ServiceConfig::default(),
        Budget::new(NonZeroUsize::MIN),
    );
    let door = service.door();
    offer_all(&door, 1, &blocks[..2]).await;
    let hashed = gate.hashes();
    let mut bad = blocks[4].template.block.clone();
    bad.header.minor_version = 1;
    let mut after = blocks[5].template.block.clone();
    after.header.previous = bad.hash();
    let span = vec![
        arrival(20, 2, &blocks[2]),
        arrival(21, 2, &blocks[3]),
        Arrival {
            block: bad.serialize(),
            ..arrival(22, 2, &blocks[4])
        },
        Arrival {
            block: after.serialize(),
            ..arrival(23, 2, &blocks[5])
        },
    ];
    let mut replies = Vec::new();
    for ticket in door.offer_span(span).expect("room") {
        replies.push(ticket.reply().await.reply);
    }
    assert!(matches!(replies[0], Reply::Connected { .. }), "{replies:?}");
    assert!(matches!(replies[1], Reply::Connected { .. }), "{replies:?}");
    assert!(
        matches!(replies[2], Reply::Refused(refused) if refused.rule == shekyl_chain_rules::CenRow::B2),
        "{replies:?}"
    );
    assert_eq!(replies[3], Reply::Cancelled { by: ArrivalTag(22) });
    assert_eq!(gate.hashes(), hashed + 2, "no hash after the refusal");
    service.stop().await.expect("stops");
    y.close().await;
    cleanup(&path);
}

/// An arrival's `form` waits in its origin's class (PR2-Q3): a block this
/// node asked for in the chain's, an announcement in the unsolicited one.
#[tokio::test(flavor = "multi_thread")]
async fn an_arrival_forms_in_the_class_its_origin_names() {
    use shekyl_hash_budget::Class;
    let mut y = Scenario::open("service-class-y");
    let blocks = y.mine(3).await;
    let budget = Budget::new(NonZeroUsize::MIN);
    let (service, path) = service_on(
        "service-class",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
        budget.clone(),
    );
    let door = service.door();
    for (index, (solicited, class)) in [(true, Class::Chain), (false, Class::Unsolicited)]
        .into_iter()
        .enumerate()
    {
        let held = {
            let budget = budget.clone();
            tokio::task::spawn_blocking(move || budget.acquire(Class::HeaderPow))
                .await
                .expect("joins")
        };
        let mut offered = arrival(u64::try_from(index).expect("small"), 1, &blocks[index]);
        offered.origin = Origin::Peer {
            session: SessionId(1),
            solicited,
        };
        let ticket = door.offer(offered).expect("room and a token");
        let started = std::time::Instant::now();
        // The attendant may already be waiting in the chain class to pin
        // the window. The form is the increase after the offer.
        let waiting_before = budget.waiting(class);
        while budget.waiting(class) <= waiting_before {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the form never waited in {class:?}"
            );
            tokio::task::yield_now().await;
        }
        drop(held);
        let reply = ticket.reply().await;
        assert!(matches!(reply.reply, Reply::Connected { .. }), "{reply:?}");
    }
    service.stop().await.expect("stops");
    y.close().await;
    cleanup(&path);
}

/// `TipChanged` (DX-Q2 item 5) is published once after each committed
/// connect, pop and switch, and never before the commit: a watcher that
/// reads the store on every publication finds the published tip already
/// recorded there. A connect the validator refuses publishes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn tip_changed_is_published_once_per_commit_and_never_before_it() {
    use crate::connector::TipChanged;
    let mut y = Scenario::open("service-tip-y");
    let mut z = Scenario::open("service-tip-z");
    let prefix = y.mine(4).await;
    z.mine(4).await;
    y.idle();
    let ours = y.mine(2).await;
    let theirs = z.mine(2).await;
    let (service, path) = service(
        "service-tip",
        Arc::new(Gated::new()),
        ServiceConfig::default(),
    );
    let door = service.door();
    let mut tips = service.watch_tip().await.expect("watch");
    assert_eq!(
        *tips.borrow_and_update(),
        TipChanged { seq: 0, tip: None },
        "once at start"
    );

    // The watcher: every publication's tip is already the store's record.
    let store = Arc::clone(&service.shared.store);
    let mut watched = service.watch_tip().await.expect("watch");
    let watcher = tokio::spawn(async move {
        let mut seen = 0;
        while watched.changed().await.is_ok() {
            let published = *watched.borrow_and_update();
            let Some(tip) = published.tip else { continue };
            let snap = store.begin_read().expect("read");
            assert_eq!(
                snap.height_of(&tip.top_id).expect("height"),
                tip.count.tip(),
                "publication {} is ahead of the store",
                published.seq
            );
            seen += 1;
        }
        seen
    });

    let mut expect_seq = 0;
    let mut next = |tips: &mut tokio::sync::watch::Receiver<TipChanged>, top: BlockHash| {
        expect_seq += 1;
        assert!(tips.has_changed().expect("open"), "a publication");
        let now = *tips.borrow_and_update();
        assert_eq!(now.seq, expect_seq, "once per commit");
        assert_eq!(now.tip.map(|t| t.top_id), Some(top));
    };
    for mined in &prefix {
        assert!(matches!(
            door.offer(arrival(mined.height.to_raw(), 1, mined))
                .expect("room")
                .reply()
                .await
                .reply,
            Reply::Connected { .. }
        ));
        next(&mut tips, mined.hash);
    }
    door.offer(arrival(10, 1, &ours[0]))
        .expect("room")
        .reply()
        .await;
    next(&mut tips, ours[0].hash);
    // A block `validate` refuses publishes nothing: a timestamp below the
    // median of the blocks before it (CEN-C2), judged in the connect's
    // write, so the `Apply` runs and commits no block.
    let mut bad = ours[1].template.block.clone();
    bad.header.timestamp = 0;
    let refused = door
        .offer(Arrival {
            block: bad.serialize(),
            ..arrival(11, 1, &ours[1])
        })
        .expect("room")
        .reply()
        .await;
    assert!(
        matches!(refused.reply, Reply::Refused(r) if r.rule == shekyl_chain_rules::CenRow::C2),
        "{refused:?}"
    );
    assert!(!tips.has_changed().expect("open"), "nothing committed");
    // An alternative block held publishes nothing; the one that makes the
    // heavier branch the chain is a switch, published once.
    let held = door
        .offer(arrival(12, 2, &theirs[0]))
        .expect("room")
        .reply()
        .await;
    assert!(matches!(held.reply, Reply::Held { .. }), "{held:?}");
    assert!(
        !tips.has_changed().expect("open"),
        "holding an alternative commits no tip"
    );
    let switched = door
        .offer(arrival(13, 2, &theirs[1]))
        .expect("room")
        .reply()
        .await;
    assert!(
        matches!(switched.reply, Reply::Switched { .. }),
        "{switched:?}"
    );
    next(&mut tips, theirs[1].hash);
    // A pop.
    service
        .connector()
        .ask(Rewind {
            to: theirs[0].height,
        })
        .await
        .expect("rewind");
    next(&mut tips, theirs[0].hash);
    service.stop().await.expect("stops");
    assert_eq!(
        watcher.await.expect("joins"),
        expect_seq,
        "the watcher saw every one"
    );
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}

/// The tip follower posts the miner's job for the block after the tip
/// while the node is synced, and withdraws it while the node is behind
/// (DX-Q2 item 5); each new tip posts a new job.
#[tokio::test(flavor = "multi_thread")]
async fn the_follower_posts_while_synced_and_withdraws_while_behind() {
    use crate::follower::{MinerFeed, TemplateSource};
    use shekyl_miner::JobBoard;
    /// A source that posts the block a driver mined at the job's height.
    struct Mined(Vec<crate::scenario::Mined>);
    impl TemplateSource for Mined {
        fn template(
            &self,
            facts: &crate::connector::ChainFacts,
        ) -> Option<(shekyl_wire::Block, Vec<shekyl_wire::Transaction>)> {
            let at = usize::try_from(facts.connecting.to_raw()).ok()?;
            let mined = self.0.get(at)?;
            Some((
                mined.template.block.clone(),
                mined.template.transactions.clone(),
            ))
        }
    }
    let mut y = Scenario::open("service-follow-y");
    let blocks = y.mine(3).await;
    let path = tmp("service-follow");
    let board = Arc::new(JobBoard::new());
    let (synced_tx, synced) = tokio::sync::watch::channel(false);
    let (_sink, found) = shekyl_miner::found_blocks();
    let service = Service::start(
        Arc::new(open_store(&path)),
        RULES,
        Arc::new(Gated::new()),
        ServiceConfig::default(),
        Budget::of_host(),
        super::Follow {
            miner: Some(MinerFeed {
                board: Arc::clone(&board),
                source: Arc::new(Mined(blocks.clone())),
                synced,
                found,
            }),
            pool: None,
        },
    );
    let mut followed = service.followed();
    let until_followed = |followed: &mut tokio::sync::watch::Receiver<u64>, seq: u64| {
        let mut followed = followed.clone();
        async move {
            followed.wait_for(|at| *at >= seq).await.expect("following");
        }
    };
    until_followed(&mut followed, 0).await;
    assert!(board.posted().is_none(), "behind: nothing to mine");
    synced_tx.send_replace(true);
    let started = std::time::Instant::now();
    while board.posted().is_none() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "no job posted"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        board.posted().expect("posted").1.height,
        BlockHeight::from_raw(0)
    );
    offer_all(&service.door(), 1, &blocks[..1]).await;
    until_followed(&mut followed, 1).await;
    assert_eq!(
        board.posted().expect("posted").1.height,
        BlockHeight::from_raw(1),
        "the next tip's job"
    );
    synced_tx.send_replace(false);
    let started = std::time::Instant::now();
    while board.posted().is_some() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "not withdrawn"
        );
        tokio::task::yield_now().await;
    }
    service.stop().await.expect("stops");
    y.close().await;
    cleanup(&path);
}

/// The door's answer to a fork past the cap is the hint, `BeyondCap`, and
/// it costs nothing: no hash, no pin, nothing stored. A stored heavier
/// chain past the cap is `CannotFollow`, a different variant
/// (`span::settled`); only that one sets `following_degraded` at the flip
/// (DX-Q2 item 8).
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_past_the_cap_is_answered_at_the_door_without_a_hash_or_a_pin() {
    use crate::scenario_shard::{levered_rules, REORG_CAP_BLOCKS};
    let rules = levered_rules();
    let mut y = Scenario::open_under("service-cap-y", crate::scenario::FreeHash, rules);
    let mut z = Scenario::open_under("service-cap-z", crate::scenario::FreeHash, rules);
    // A shared prefix of two blocks: the fork's root is block 1.
    let prefix = y.mine(2).await;
    z.mine(2).await;
    y.idle();
    // The main chain's tip sits one block past the cap above the root, so
    // the fork at height 2 would pop cap + 1 blocks.
    let main = y.mine(REORG_CAP_BLOCKS + 1).await;
    let fork = z.mine(1).await;
    let substrate = Arc::new(Gated::new());
    let (service, path) = service_under(
        "service-cap",
        Arc::clone(&substrate),
        ServiceConfig::default(),
        rules,
    );
    let door = service.door();
    offer_all(&door, 1, &prefix).await;
    offer_all(&door, 1, &main).await;
    let (hashes, pins) = (substrate.hashes(), substrate.pins());
    let reply = door
        .offer(arrival(90, 2, &fork[0]))
        .expect("room")
        .reply()
        .await
        .reply;
    assert!(
        matches!(reply, Reply::BeyondCap(beyond)
            if beyond.depth.to_raw() == REORG_CAP_BLOCKS + 1
                && beyond.cap.to_raw() == REORG_CAP_BLOCKS),
        "{reply:?}"
    );
    assert_eq!(substrate.hashes(), hashes, "no hash for the door's answer");
    assert_eq!(substrate.pins(), pins, "no cache built for it");
    assert_eq!(
        homes(&service, fork[0].hash),
        (false, false),
        "nothing stored"
    );
    service.stop().await.expect("stops");
    for s in [y, z] {
        s.close().await;
    }
    cleanup(&path);
}
