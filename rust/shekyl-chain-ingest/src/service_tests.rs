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

/// The free longhash under a clock ahead of the scenarios', with a gate.
pub(crate) struct Gated {
    held: Mutex<HashSet<BlockHash>>,
    opened: Condvar,
    hashes: AtomicUsize,
    /// Longhashes that met a closed gate and waited.
    waited: AtomicUsize,
}

impl Gated {
    pub(crate) fn new() -> Self {
        Self {
            held: Mutex::new(HashSet::new()),
            opened: Condvar::new(),
            hashes: AtomicUsize::new(0),
            waited: AtomicUsize::new(0),
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
    let path = tmp(name);
    let store: ChainStore = open_store(&path);
    (
        Service::start(Arc::new(store), RULES, substrate, config),
        path,
    )
}

/// Offer `blocks` as one span from `session` and wait for every reply.
pub(crate) async fn offer_all(door: &Door, session: u64, blocks: &[Mined]) -> Vec<Reply> {
    let span = blocks
        .iter()
        .enumerate()
        .map(|(i, m)| arrival(session * 1_000 + i as u64, session, m))
        .collect();
    let tickets = door.offer_span(span).expect("room");
    let mut replies = Vec::new();
    for ticket in tickets {
        replies.push(ticket.reply().await.reply);
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
        room: NonZeroUsize::new(2).expect("two"),
        hashers: NonZeroUsize::MIN,
    };
    let (service, path) = service("service-room", Arc::clone(&gate), config);
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
