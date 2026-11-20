// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A held body that does not read back as it was opened is reported to the
//! store it came from, once, as the shard it was opened as
//! (`HeldShardSource::report_fault`; `WALLET_SIDE_STORE.md` §6.7.1): the
//! store failing mid-body, a body longer than it was opened at, and one
//! shorter. A body that reads back reports nothing, and neither does a
//! requester that stops reading, which is not a fault of the store.
//!
//! The source is a real body store with one step tampered between it and
//! the loop, because the faults are the store's to produce and the store
//! does not produce them on demand.

use std::sync::{Arc, Mutex};

use shekyl_p_store::{BodyStore, HeldShard, StoreKey};
use shekyl_types::{BlockHeight, ShardId};
use tokio::io::AsyncWrite;

use super::invariant::Requester;
use super::{
    filler, good_get_shard_0, render_ok, resolve, write_response, Resolved, OWN_HEIGHT,
    RECEIPT_ENVELOPE_LEN, WRITE_CHUNK_BYTES,
};
use crate::countersign::{PassSigner, TestReceiptKeySigner};
use crate::provider::{HeldShardSource, ProviderError, ShardProvider, StoreShardProvider};
use crate::serve_counters::ServeCounterReader;

/// Three storage chunks, the last a short one.
const BODY_BYTES: usize = 2 * WRITE_CHUNK_BYTES + 7;

/// What the source does to the store's reads on their way to the loop.
#[derive(Debug, Clone, Copy)]
enum Tamper {
    /// Nothing: the store's chunks as they are.
    None,
    /// The read of this chunk fails.
    FailsAt(u32),
    /// The last chunk carries one byte past the opened length.
    Longer,
    /// The last chunk is one byte short of it.
    Shorter,
}

/// The store, read through [`Tamper`], keeping every report it is given.
struct Recording {
    store: BodyStore,
    tamper: Tamper,
    reported: Mutex<Vec<ShardId>>,
}

impl Recording {
    fn reported(&self) -> Vec<ShardId> {
        self.reported.lock().expect("reports").clone()
    }
}

impl HeldShardSource for Recording {
    fn open_shard(&self, shard_id: ShardId) -> Result<Option<HeldShard>, ProviderError> {
        HeldShardSource::open_shard(&self.store, shard_id)
    }

    fn read_chunk(&self, held: &HeldShard, index: u32) -> Result<Vec<u8>, ProviderError> {
        let mut chunk = HeldShardSource::read_chunk(&self.store, held, index)?;
        let last = index + 1 == held.chunk_count();
        match self.tamper {
            Tamper::FailsAt(at) if at == index => return Err(ProviderError::other("tampered")),
            Tamper::Longer if last => chunk.push(0),
            Tamper::Shorter if last => {
                chunk.pop();
            }
            _ => {}
        }
        Ok(chunk)
    }

    fn report_fault(&self, held: &HeldShard) {
        self.reported.lock().expect("reports").push(held.shard_id());
    }
}

/// Serve shard 0 out of a store read through `tamper`, into `sink`.
async fn serve<W: AsyncWrite + Unpin>(
    tamper: Tamper,
    sink: &mut W,
) -> (Arc<Recording>, ServeCounterReader, std::io::Result<()>) {
    let store = BodyStore::open_ephemeral(StoreKey::from_bytes([0x6b; 32])).expect("open");
    store
        .put_shard(ShardId::from_raw(0), &filler(BODY_BYTES, 0x44))
        .expect("put");
    let source = Arc::new(Recording {
        store,
        tamper,
        reported: Mutex::new(Vec::new()),
    });
    let provider: Arc<dyn ShardProvider> = Arc::new(StoreShardProvider::new(
        Arc::clone(&source) as Arc<dyn HeldShardSource>
    ));
    let signer: Arc<dyn PassSigner> = Arc::new(TestReceiptKeySigner::ephemeral(
        BlockHeight::from_raw(OWN_HEIGHT),
    ));
    let counters = ServeCounterReader::zeroed();
    let writer = counters.writer();
    let resolved = resolve(
        good_get_shard_0().as_bytes(),
        provider,
        Arc::clone(&signer),
        &writer,
    )
    .await;
    assert!(
        matches!(resolved, Resolved::Held(_)),
        "a valid request for a held shard"
    );
    let outcome = write_response(sink, resolved, signer, &writer).await;
    (source, counters, outcome)
}

#[tokio::test]
async fn each_fault_of_a_held_body_reports_its_shard_once() {
    for tamper in [Tamper::FailsAt(1), Tamper::Longer, Tamper::Shorter] {
        let mut out = Vec::new();
        let (source, counters, outcome) = serve(tamper, &mut out).await;
        assert!(outcome.is_err(), "{tamper:?}: the response ends short");
        assert_eq!(
            source.reported(),
            [ShardId::from_raw(0)],
            "{tamper:?}: the opened shard is reported, once"
        );
        assert_eq!(counters.lookup_failure_count(), 1, "{tamper:?}");
        assert_eq!(counters.served_count(), 0, "{tamper:?}");
    }
}

#[tokio::test]
async fn a_body_that_reads_back_reports_nothing() {
    let mut out = Vec::new();
    let (source, counters, outcome) = serve(Tamper::None, &mut out).await;
    outcome.expect("a whole body and its signature");
    assert_eq!(counters.served_count(), 1);
    assert_eq!(source.reported(), []);
}

#[tokio::test]
async fn a_requester_that_stops_reading_reports_nothing() {
    // The requester takes the head and one chunk of the body, then refuses.
    // The store is whole; the response ends for the requester's reason.
    let head = render_ok(u64::try_from(BODY_BYTES + RECEIPT_ENVELOPE_LEN).expect("fits")).len();
    let mut requester = Requester {
        taken: 0,
        cap: head + WRITE_CHUNK_BYTES,
    };
    let (source, counters, outcome) = serve(Tamper::None, &mut requester).await;
    assert!(outcome.is_err(), "the refused write ends the response");
    assert_eq!(
        source.reported(),
        [],
        "a requester leaving is not the store's fault"
    );
    assert_eq!(counters.lookup_failure_count(), 0);
}
