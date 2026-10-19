// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ingest entry over a live service: what crosses the boundary, not
//! what the service decides (the ingest crate's own tests judge that).

use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use shekyl_chain_ingest::service::{Follow, Service, ServiceConfig};
use shekyl_chain_ingest::ChainRules;
use shekyl_chain_rules::{CenRow, FakechainSchedule, Substrate};
use shekyl_chain_store::codec::SettlementEpochBlocks;
use shekyl_chain_store::store::ChainStore;
use shekyl_hash_budget::Budget;
use shekyl_types::{BlockHash, PowHash, Timestamp};

use super::*;

/// The process has one installed door and one bound post: one test at a
/// time.
static LANE: Mutex<()> = Mutex::new(());

/// What the post received: connection, tag, kind, rule, indices.
type Posted = (u64, u64, u32, u16, Vec<u64>);
static POSTED: Mutex<Vec<Posted>> = Mutex::new(Vec::new());

unsafe extern "C" fn collect(
    _ctx: *mut c_void,
    reply: *const ShekylIngestReply,
    indices: *const u64,
    indices_len: usize,
) {
    let reply = unsafe { *reply };
    let indices = unsafe { slice_from_typed_ptr(indices, indices_len) }
        .expect("indices")
        .to_vec();
    POSTED.lock().expect("posted").push((
        reply.connection,
        reply.tag,
        reply.kind,
        reply.rule,
        indices,
    ));
}

/// The free longhash at a fixed clock.
struct Free;

impl Substrate for Free {
    type Fault = std::convert::Infallible;

    fn local_clock(&self) -> Result<Timestamp, Self::Fault> {
        Ok(Timestamp::from_raw(1_800_000_000))
    }

    fn longhash(&self, _: &[u8], _: &BlockHash) -> Result<PowHash, Self::Fault> {
        Ok(PowHash::from_bytes([0; 32]))
    }
}

const RULES: ChainRules = ChainRules::Regtest {
    fixed_difficulty: Some(std::num::NonZeroU128::MIN),
    schedule: FakechainSchedule::PRODUCTION,
};

fn blob(bytes: &[u8]) -> ShekylIngestBlob {
    ShekylIngestBlob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

/// Room is reported before sending; an unbound entry refuses; a span the
/// door accepts is answered once per arrival, tagged with the arrival and
/// its connection, through the bound post — here, junk the wire refuses
/// (CEN-A6). Unbinding drains those replies before it returns. A span past
/// the room is `NO_ROOM` before acceptance, a null buffer is `INVALID`
/// before a seat is taken, a block past the arrival bound is `OVERSIZE`,
/// and a body list the block cannot name is `INVALID`. Three seats: one
/// stays reserved, so a sync caller sees two.
#[test]
fn a_span_is_answered_per_arrival_through_the_bound_post() {
    let _lane = LANE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    POSTED.lock().expect("posted").clear();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let dir = tempfile::tempdir().expect("dir");
    let epoch = SettlementEpochBlocks::new(10_000).expect("an epoch");
    let store = ChainStore::create(dir.path().join("chain"), epoch).expect("create");
    let service = runtime.block_on(async {
        Service::start(
            Arc::new(store),
            RULES,
            Arc::new(Free),
            ServiceConfig {
                room: std::num::NonZeroUsize::new(3).expect("three"),
            },
            Budget::of_host(),
            Follow::default(),
        )
    });
    let junk = [vec![0xA5u8; 40], vec![0x5Au8; 40]];
    let arrivals: Vec<ShekylIngestArrival> = junk
        .iter()
        .enumerate()
        .map(|(i, bytes)| ShekylIngestArrival {
            tag: 100 + i as u64,
            block: blob(bytes),
            bodies: std::ptr::null(),
            bodies_len: 0,
        })
        .collect();

    // Nothing installed or bound: no room, and an offer is refused.
    uninstall();
    unsafe { shekyl_ingest_bind(std::ptr::null_mut(), None) };
    assert_eq!(shekyl_ingest_room(), 0);
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, arrivals.as_ptr(), arrivals.len()) },
        SHEKYL_INGEST_UNBOUND
    );

    install(service.door(), runtime.handle().clone());
    let mut ctx = 0u8;
    unsafe { shekyl_ingest_bind(std::ptr::from_mut(&mut ctx).cast(), Some(collect)) };
    assert_eq!(shekyl_ingest_room(), 2);
    let three: Vec<ShekylIngestArrival> = arrivals.iter().chain(&arrivals[..1]).copied().collect();
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, three.as_ptr(), three.len()) },
        SHEKYL_INGEST_NO_ROOM,
        "past the room, before acceptance"
    );
    let four: Vec<ShekylIngestArrival> = arrivals.iter().cycle().take(4).copied().collect();
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, four.as_ptr(), four.len()) },
        SHEKYL_INGEST_NO_ROOM,
        "a span longer than the window is never seated"
    );
    assert_eq!(shekyl_ingest_room(), 2);
    let mut missing = arrivals[0];
    missing.block.ptr = std::ptr::null();
    missing.block.len = 4;
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, std::ptr::from_ref(&missing), 1) },
        SHEKYL_INGEST_INVALID,
        "a missing buffer is refused before a seat is taken"
    );
    assert_eq!(shekyl_ingest_room(), 2, "the invalid span took no seat");
    let max_bytes = service
        .door()
        .max_arrival_bytes()
        .expect("the arrival bound");
    let over = usize::try_from(max_bytes)
        .expect("the bound fits")
        .saturating_add(1);
    assert!(u64::try_from(over).expect("over fits") > max_bytes);
    let stub = [0u8; 1];
    let mut huge = arrivals[0];
    huge.block = ShekylIngestBlob {
        ptr: stub.as_ptr(),
        len: over,
    };
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, std::ptr::from_ref(&huge), 1) },
        SHEKYL_INGEST_OVERSIZE,
        "a block past the arrival bound is refused before a seat is taken"
    );
    assert_eq!(shekyl_ingest_room(), 2, "the oversize span took no seat");
    let empty = ShekylIngestBlob {
        ptr: std::ptr::null(),
        len: 0,
    };
    let listed = [empty, empty];
    let mut unnamed = arrivals[0];
    unnamed.bodies = listed.as_ptr();
    unnamed.bodies_len = listed.len();
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, std::ptr::from_ref(&unnamed), 1) },
        SHEKYL_INGEST_INVALID,
        "more bodies than the block can name is refused before a seat is taken"
    );
    assert_eq!(shekyl_ingest_room(), 2, "the unnamed span took no seat");
    let one = [ShekylIngestBlob {
        ptr: stub.as_ptr(),
        len: over,
    }];
    let mut heavy = arrivals[0];
    heavy.bodies = one.as_ptr();
    heavy.bodies_len = one.len();
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, std::ptr::from_ref(&heavy), 1) },
        SHEKYL_INGEST_OVERSIZE,
        "carried bytes past the bound are refused before they are copied"
    );
    assert_eq!(shekyl_ingest_room(), 2, "the heavy span took no seat");
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, arrivals.as_ptr(), arrivals.len()) },
        SHEKYL_INGEST_ACCEPTED
    );
    // Unbind drains the replies already accepted, then an offer is unbound.
    unsafe { shekyl_ingest_bind(std::ptr::null_mut(), None) };
    let mut posted = POSTED.lock().expect("posted").clone();
    posted.sort_by_key(|p| p.1);
    let a6 = u16::from(CenRow::A6.index());
    assert_eq!(
        posted,
        vec![
            (7, 100, SHEKYL_INGEST_REFUSED, a6, Vec::new()),
            (7, 101, SHEKYL_INGEST_REFUSED, a6, Vec::new()),
        ]
    );
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, arrivals.as_ptr(), arrivals.len()) },
        SHEKYL_INGEST_UNBOUND,
        "an unbind stops acceptance"
    );
    shekyl_ingest_session_closed(7);
    uninstall();
    runtime.block_on(async { service.stop().await.expect("stops") });
}

/// The reply kinds and the admission codes are the header's constexprs.
/// A mismatch would let C++ close a session on a harmless `Cancelled`.
#[test]
fn reply_codes_are_the_headers() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/shekyl/shekyl_ffi.h");
    let header = std::fs::read_to_string(&path).expect("the ingest entry's header");
    let mut header_codes = std::collections::BTreeMap::new();
    for line in header.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("constexpr ") else {
            continue;
        };
        let Some(eq) = rest.find('=') else {
            continue;
        };
        let Some(name) = rest[..eq].split_whitespace().last() else {
            continue;
        };
        if !name.starts_with("SHEKYL_INGEST_") {
            continue;
        }
        let value = rest[eq + 1..].trim().trim_end_matches(';').trim();
        let value: i64 = value.parse().unwrap_or_else(|_| panic!("code {name}"));
        header_codes.insert(name.to_string(), value);
    }
    let rust_codes = [
        (
            "SHEKYL_INGEST_CONNECTED",
            i64::from(SHEKYL_INGEST_CONNECTED),
        ),
        ("SHEKYL_INGEST_REFUSED", i64::from(SHEKYL_INGEST_REFUSED)),
        ("SHEKYL_INGEST_UNLINKED", i64::from(SHEKYL_INGEST_UNLINKED)),
        (
            "SHEKYL_INGEST_ALREADY_HELD",
            i64::from(SHEKYL_INGEST_ALREADY_HELD),
        ),
        ("SHEKYL_INGEST_HELD", i64::from(SHEKYL_INGEST_HELD)),
        (
            "SHEKYL_INGEST_BEYOND_CAP",
            i64::from(SHEKYL_INGEST_BEYOND_CAP),
        ),
        ("SHEKYL_INGEST_SWITCHED", i64::from(SHEKYL_INGEST_SWITCHED)),
        (
            "SHEKYL_INGEST_PROMOTION_REFUSED",
            i64::from(SHEKYL_INGEST_PROMOTION_REFUSED),
        ),
        (
            "SHEKYL_INGEST_CANNOT_FOLLOW_BELOW_FLOOR",
            i64::from(SHEKYL_INGEST_CANNOT_FOLLOW_BELOW_FLOOR),
        ),
        (
            "SHEKYL_INGEST_MISSING_BODIES",
            i64::from(SHEKYL_INGEST_MISSING_BODIES),
        ),
        (
            "SHEKYL_INGEST_CANCELLED",
            i64::from(SHEKYL_INGEST_CANCELLED),
        ),
        ("SHEKYL_INGEST_STOPPED", i64::from(SHEKYL_INGEST_STOPPED)),
        (
            "SHEKYL_INGEST_OUTSIDE_WINDOW",
            i64::from(SHEKYL_INGEST_OUTSIDE_WINDOW),
        ),
        (
            "SHEKYL_INGEST_CANNOT_FOLLOW_BEYOND_CAP",
            i64::from(SHEKYL_INGEST_CANNOT_FOLLOW_BEYOND_CAP),
        ),
        ("SHEKYL_INGEST_ACCEPTED", i64::from(SHEKYL_INGEST_ACCEPTED)),
        ("SHEKYL_INGEST_NO_ROOM", i64::from(SHEKYL_INGEST_NO_ROOM)),
        (
            "SHEKYL_INGEST_THROTTLED",
            i64::from(SHEKYL_INGEST_THROTTLED),
        ),
        ("SHEKYL_INGEST_OVERSIZE", i64::from(SHEKYL_INGEST_OVERSIZE)),
        ("SHEKYL_INGEST_UNBOUND", i64::from(SHEKYL_INGEST_UNBOUND)),
        ("SHEKYL_INGEST_INVALID", i64::from(SHEKYL_INGEST_INVALID)),
        (
            "SHEKYL_INGEST_REENTRANT",
            i64::from(SHEKYL_INGEST_REENTRANT),
        ),
    ];
    assert_eq!(header_codes.len(), rust_codes.len(), "{header_codes:?}");
    for (name, value) in rust_codes {
        assert_eq!(
            header_codes.get(name).copied(),
            Some(value),
            "{name} drifted from the header"
        );
    }
}

/// Which reply shape `reply` is. Exhaustive, so a new `Reply` or
/// `CannotFollow` variant does not compile until it has an index here,
/// and [`every_reply_encodes_to_its_own_header_kind`] fails until it has a
/// sample.
fn shape(reply: &Reply) -> usize {
    match reply {
        Reply::Connected { .. } => 0,
        Reply::Refused(_) => 1,
        Reply::Unlinked { .. } => 2,
        Reply::AlreadyHeld => 3,
        Reply::Held { .. } => 4,
        Reply::BeyondCap(_) => 5,
        Reply::OutsideWindow { .. } => 6,
        Reply::Switched { .. } => 7,
        Reply::PromotionRefused { .. } => 8,
        Reply::CannotFollow(CannotFollow::BeyondCap(_)) => 9,
        Reply::CannotFollow(CannotFollow::BelowFloor { .. }) => 10,
        Reply::MissingBodies { .. } => 11,
        Reply::Cancelled { .. } => 12,
        Reply::Stopped => 13,
    }
}

/// One reply of each shape.
fn one_of_each() -> Vec<Reply> {
    use shekyl_chain_ingest::connector::PopBeyondReorgCap;
    use shekyl_chain_rules::{InvalidBlock, Locus};
    use shekyl_types::{BlockCount, BlockHeight};
    let height = BlockHeight::from_raw(7);
    let hash = BlockHash::from_bytes([3; 32]);
    let verdict = InvalidBlock::new(CenRow::B2, Locus::Block);
    let beyond = PopBeyondReorgCap {
        depth: BlockCount::from_raw(11),
        cap: BlockCount::from_raw(10),
    };
    vec![
        Reply::Connected { height, hash },
        Reply::Refused(verdict),
        Reply::Unlinked { at: hash },
        Reply::AlreadyHeld,
        Reply::Held { height },
        Reply::BeyondCap(beyond),
        Reply::OutsideWindow { height },
        Reply::Switched {
            demoted: vec![(height, hash)],
            promoted: vec![(height, hash)],
        },
        Reply::PromotionRefused {
            at: height,
            hash,
            refused: verdict,
        },
        Reply::CannotFollow(CannotFollow::BeyondCap(beyond)),
        Reply::CannotFollow(CannotFollow::BelowFloor {
            tip: height,
            floor: BlockHeight::from_raw(2),
        }),
        Reply::MissingBodies { indices: vec![0] },
        Reply::Cancelled { by: ArrivalTag(4) },
        Reply::Stopped,
    ]
}

/// Every reply shape encodes to a kind of its own, and the kinds are the
/// header's reply constants, all of them and nothing else. The door's
/// past-cap hint and the stored, proven past-cap outcome are different
/// kinds (DX-Q2 item 8).
#[test]
fn every_reply_encodes_to_its_own_header_kind() {
    let samples = one_of_each();
    let shapes: std::collections::BTreeSet<usize> = samples.iter().map(shape).collect();
    assert_eq!(
        shapes,
        (0..samples.len()).collect(),
        "one sample per shape, every shape sampled"
    );
    let kinds: std::collections::BTreeSet<u32> = samples
        .into_iter()
        .map(|reply| {
            encode(
                1,
                Tagged {
                    tag: ArrivalTag(1),
                    reply,
                },
            )
            .0
            .kind
        })
        .collect();
    assert_eq!(kinds.len(), shapes.len(), "two shapes share a kind");
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src/shekyl/shekyl_ffi.h");
    let header = std::fs::read_to_string(&path).expect("the ingest entry's header");
    let header_kinds: std::collections::BTreeSet<u32> = header
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("constexpr std::uint32_t SHEKYL_INGEST_")
        })
        .map(|rest| {
            let value = rest.split('=').nth(1).expect("a value");
            value.trim().trim_end_matches(';').parse().expect("a kind")
        })
        .collect();
    assert_eq!(kinds, header_kinds, "the encoded kinds are the header's");
    assert_ne!(
        SHEKYL_INGEST_BEYOND_CAP,
        SHEKYL_INGEST_CANNOT_FOLLOW_BEYOND_CAP
    );
}

/// An accepted arrival the service never reached is answered at its stop,
/// and that `STOPPED` is posted through the bound post before an unbind
/// returns. An unbind on the replies' own runtime cannot wait for them, so
/// it is refused and changes nothing. The runtime is a current-thread one
/// left undriven between the offer and the stop, so the span is still
/// queued when the stop lands.
#[test]
fn an_accepted_arrival_is_answered_stopped_through_the_post_at_a_stop() {
    let _lane = LANE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    POSTED.lock().expect("posted").clear();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let dir = tempfile::tempdir().expect("dir");
    let epoch = SettlementEpochBlocks::new(10_000).expect("an epoch");
    let store = ChainStore::create(dir.path().join("chain"), epoch).expect("create");
    let service = runtime.block_on(async {
        Service::start(
            Arc::new(store),
            RULES,
            Arc::new(Free),
            ServiceConfig::default(),
            Budget::of_host(),
            Follow::default(),
        )
    });
    install(service.door(), runtime.handle().clone());
    let mut ctx = 0u8;
    assert_eq!(
        unsafe { shekyl_ingest_bind(std::ptr::from_mut(&mut ctx).cast(), Some(collect)) },
        0
    );
    let junk = vec![0xA5u8; 40];
    let one = [ShekylIngestArrival {
        tag: 300,
        block: blob(&junk),
        bodies: std::ptr::null(),
        bodies_len: 0,
    }];
    // Accepted while the runtime is not driven: the span waits in the
    // service's queue.
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(9, 1, one.as_ptr(), one.len()) },
        SHEKYL_INGEST_ACCEPTED
    );
    // An unbind on the runtime that posts the replies is refused.
    let reentrant =
        runtime.block_on(async { unsafe { shekyl_ingest_bind(std::ptr::null_mut(), None) } });
    assert_eq!(reentrant, SHEKYL_INGEST_REENTRANT);
    runtime.block_on(async { service.stop().await.expect("stops") });
    // Unbind from another thread while this one drives the runtime: the
    // drain posts the reply before the unbind returns.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let unbinder = std::thread::spawn(move || {
        let code = unsafe { shekyl_ingest_bind(std::ptr::null_mut(), None) };
        let _sent = done_tx.send(code);
    });
    let code = runtime.block_on(async {
        loop {
            if let Ok(code) = done_rx.try_recv() {
                break code;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    });
    unbinder.join().expect("joins");
    assert_eq!(code, 0);
    assert_eq!(
        *POSTED.lock().expect("posted"),
        vec![(9, 300, SHEKYL_INGEST_STOPPED, 0, Vec::new())],
        "the accepted arrival is answered STOPPED through the post"
    );
    uninstall();
}
