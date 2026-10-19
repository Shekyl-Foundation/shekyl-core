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
/// (CEN-A6); and a span past the room is `NO_ROOM` before acceptance.
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
                room: std::num::NonZeroUsize::new(2).expect("two"),
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
    assert_eq!(
        unsafe { shekyl_ingest_offer_span(7, 1, arrivals.as_ptr(), arrivals.len()) },
        SHEKYL_INGEST_ACCEPTED
    );
    let started = std::time::Instant::now();
    while POSTED.lock().expect("posted").len() < 2 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "no replies"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
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
    shekyl_ingest_session_closed(7);
    uninstall();
    unsafe { shekyl_ingest_bind(std::ptr::null_mut(), None) };
    runtime.block_on(async { service.stop().await.expect("stops") });
}
