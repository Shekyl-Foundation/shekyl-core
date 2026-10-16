// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Shard lookup behind the serving loop: the [`ShardProvider`] seam and its
//! production [`BodyStoreReader`] implementation.
//!
//! The seam exists so the loop's wire behaviour is testable without a
//! store, and so the store read (synchronous redb) is confined behind one
//! trait the endpoint calls via `spawn_blocking`. It is **not** an
//! abstraction over storage backends — the store is `shekyl-p-store`,
//! and the trait's second implementor is the test fixture.
//!
//! # Read-only, structurally
//!
//! [`StoreShardProvider`] is built from a [`BodyStoreReader`], not from
//! the writer: fill and erase live on `BodyStore` under `StakeEngine`,
//! and the serving loop runs beside it. What is left in this module
//! cannot write to the store at all, which is the property that keeps
//! "the serving side is a reader" from being a convention.
//!
//! This module stays free of Tor and key material.

use std::sync::Arc;

use shekyl_p_store::{BodyStoreReader, ShardFrameBody, StoreError};
use shekyl_types::ShardId;

/// A shard lookup failed for an infrastructure reason (store I/O)
/// or a serve-set construction bug. Counted locally by the endpoint
/// when it is a lookup failure. On the wire it is the bare 503 the endpoint
/// gives for every fault of its own — never the 404, which means "not
/// held", and never a response that says which fault.
///
/// Variants are for operator-side / harness diagnostics only; the wire path
/// collapses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// redb / store failure other than a named pruned-segment case.
    Store {
        /// Local diagnostic (`Debug` of the store error); never on the wire.
        detail: String,
    },
    /// Non-store failure (tests, future callers).
    Other {
        /// Local diagnostic; never on the wire.
        detail: String,
    },
}

impl ProviderError {
    /// A non-store lookup failure with a local diagnostic description.
    pub fn other(detail: impl Into<String>) -> Self {
        Self::Other {
            detail: detail.into(),
        }
    }

    /// Map a body-store error. Every arm is infrastructure: a missing
    /// shard is `Ok(None)` at open, not an error.
    fn from_store(err: &StoreError) -> Self {
        Self::Store {
            detail: format!("{err:?}"),
        }
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store { detail } | Self::Other { detail } => {
                write!(f, "shard lookup failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// The body of one served shard, read in bounded chunks.
///
/// **Chunked, not materialised.** The serving loop holds one body per
/// in-flight connection for as long as that connection takes, so a
/// whole-shard buffer would silently convert the endpoint's concurrency cap
/// into a resident-memory bound of `MAX_INFLIGHT × W` — a bill the rule-76
/// provisioning floor cannot pay, and one the cap does not claim to be
/// charging. Peak cost here is one chunk.
///
/// **Opaque to the loop.** The bytes are whatever the provider holds for
/// the shard — the `shekyl_wire::shard_frame` body over the shard's
/// archival good (`SF-D8` amendment 2026-10-08) — and the loop neither
/// parses nor frames them: it declares their length, streams them, and
/// signs for them. A body that is the wrong content is the requester's to
/// refuse against its skeleton rows; nothing a serving loop could prepend
/// would make it right.
///
/// [`Self::len`] is fixed when the body is opened, from the store's meta
/// row, and exact before the first chunk is read. That is what lets the
/// response head — including `content-length` — go out before any chunk
/// byte is read. A chunk that later fails authentication can only close
/// the stream (`WSS` §6.6.5).
#[derive(Debug)]
pub struct ShardBody {
    source: Source,
    /// Total payload length, fixed at open.
    len: u64,
}

/// Where a body's bytes come from. Private: the production and fixture
/// sources differ in cost, not in contract, and the wire path must not be
/// able to tell them apart.
#[derive(Debug)]
enum Source {
    /// `shard_frame` streamed from `P`'s body store (production).
    Held(Box<ShardFrameBody>),
    /// Opaque in-memory payload (tests, measurement harnesses).
    Flat { bytes: Arc<[u8]>, read: usize },
    /// An in-memory payload that counts the chunks it yields into a counter
    /// the test holds. How a test sees that a requester who stopped taking
    /// bytes stopped the serve loop reading them. A read at the end of the
    /// body yields nothing and is not counted: the count is of shard bytes
    /// handed over, in chunks, which is the work the invariant is about.
    #[cfg(test)]
    Counted {
        bytes: Arc<[u8]>,
        read: usize,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    },
}

/// The next chunk of at most `max_bytes` out of `bytes` from `*read`,
/// advancing the cursor; `None` at the end.
fn slice_chunk(bytes: &[u8], read: &mut usize, max_bytes: usize) -> Option<Vec<u8>> {
    if *read >= bytes.len() {
        return None;
    }
    let stop = bytes.len().min(*read + max_bytes.max(1));
    let chunk = bytes[*read..stop].to_vec();
    *read = stop;
    Some(chunk)
}

/// A body length as the wire declares it.
fn wire_len(len: usize) -> u64 {
    u64::try_from(len).expect("a body length on this host fits u64")
}

impl ShardBody {
    /// An in-memory body — fixtures and measurement harnesses, which hold
    /// the shard's bytes rather than read them from a store.
    #[must_use]
    pub fn flat(bytes: Arc<[u8]>) -> Self {
        let len = wire_len(bytes.len());
        Self {
            source: Source::Flat { bytes, read: 0 },
            len,
        }
    }

    /// [`Self::flat`], counting every chunk it yields into `reads`.
    #[cfg(test)]
    pub(crate) fn counted(bytes: Arc<[u8]>, reads: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        let len = wire_len(bytes.len());
        Self {
            source: Source::Counted {
                bytes,
                read: 0,
                reads,
            },
            len,
        }
    }

    /// A store-backed `shard_frame` body.
    #[must_use]
    pub fn held(body: ShardFrameBody) -> Self {
        let len = body.len();
        Self {
            source: Source::Held(Box::new(body)),
            len,
        }
    }

    /// The body's total length — what `content-length` declares ahead of
    /// the envelope.
    ///
    /// **Fixed once, when the body is opened**, and stored rather than
    /// derived on demand. That is not a cache: the length describes the
    /// response that was *chosen*, and servability is settled before any
    /// byte is written, so it is fixed at exactly the moment the response
    /// is. Deriving it from the remaining length would make it shrink as
    /// chunks were read — a figure that answers a different question after
    /// the first chunk.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the body has no bytes at all. A provider that opens one is
    /// serving an empty shard, which no range produces (`SHT-Q2`: every
    /// shard is non-empty); the loop still streams it correctly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes not yet read. Shrinks as chunks are taken; [`Self::len`] does
    /// not.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        match &self.source {
            Source::Held(body) => body.remaining_bytes(),
            Source::Flat { bytes, read } => bytes.len() - read,
            #[cfg(test)]
            Source::Counted { bytes, read, .. } => bytes.len() - read,
        }
    }

    /// Next body chunk of at most `max_bytes`, or `None` at the end.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] if the store fails part-way through a body. The
    /// response head is already on the wire by then, so the loop can only
    /// close; the counter is the signal.
    pub fn next_chunk(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, ProviderError> {
        match &mut self.source {
            Source::Held(body) => body
                .next_chunk(max_bytes)
                .map_err(|e| ProviderError::from_store(&e)),
            Source::Flat { bytes, read } => Ok(slice_chunk(bytes, read, max_bytes)),
            #[cfg(test)]
            Source::Counted { bytes, read, reads } => {
                let chunk = slice_chunk(bytes, read, max_bytes);
                if chunk.is_some() {
                    reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(chunk)
            }
        }
    }
}

/// Serve-side shard lookup.
///
/// `Ok(None)` is the *unservable* case — unknown id, or a segment that has
/// not frozen yet (no committed `R_k`, so nothing content-verifiable to
/// serve). `Err` is infrastructure failure. The endpoint renders the first
/// as the bare 404 and the second as the bare 503.
pub trait ShardProvider: Send + Sync + 'static {
    /// Open the body for `shard_id` — the `shekyl_wire::shard_frame` body
    /// over the shard's archival good, exactly what the requester checks
    /// against its skeleton rows (`SF-D8` amendment 2026-10-08).
    ///
    /// Servability is settled by this call, before any byte of response is
    /// written; the returned [`ShardBody`] then only streams. That
    /// ordering is what lets the endpoint answer a fault with a status — a
    /// body that discovered missing bytes half-way through could only stop,
    /// and a requester would read that as a stall and retry it.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on store failure. A shard that is not held is
    /// `Ok(None)`, not an error.
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError>;
}

/// The production provider: shard reads out of `P`'s body store, through
/// a read-only [`BodyStoreReader`], serving a held `shard_frame`.
///
/// Fill and erase live on [`shekyl_p_store::BodyStore`] under
/// `StakeEngine`. This type cannot write.
pub struct StoreShardProvider {
    reader: BodyStoreReader,
}

impl StoreShardProvider {
    /// Wrap a read-only body-store handle.
    #[must_use]
    pub fn new(reader: BodyStoreReader) -> Self {
        Self { reader }
    }
}

impl ShardProvider for StoreShardProvider {
    fn shard_bytes(&self, shard_id: u64) -> Result<Option<ShardBody>, ProviderError> {
        match self.reader.open_shard(ShardId::from_raw(shard_id)) {
            Ok(Some(body)) => Ok(Some(ShardBody::held(body))),
            Ok(None) => Ok(None),
            Err(e) => Err(ProviderError::from_store(&e)),
        }
    }
}
