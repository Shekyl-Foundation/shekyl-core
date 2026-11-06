// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A held shard as the store hands it out: plain data, nothing that reaches
//! the store.

use shekyl_types::ShardId;

use crate::store::ShardMeta;

/// A shard the store holds, opened for serving.
///
/// Plain data: the shard's id, its length, and how many storage chunks it is
/// read in. Nothing here reaches the store or its key. The store's owner
/// mints one with [`BodyStore::open_shard`](crate::BodyStore::open_shard) and
/// answers each [`BodyStore::read_chunk`](crate::BodyStore::read_chunk) for
/// it with an owned plaintext copy, so a serving loop holds bytes, never a
/// handle on the file (`WALLET_SIDE_STORE.md` `WSS-Q13`; `CURVE_TREE_CLIENT.md`
/// §11.1).
///
/// [`Self::len`] is fixed at open so `content-length` can go out before any
/// byte is read. A refill between the open and a chunk read mints a fresh
/// salt, so that chunk fails authentication
/// ([`StoreError::Corrupt`](crate::StoreError::Corrupt)) rather than mixing
/// two bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldShard {
    pub(crate) shard_id: ShardId,
    pub(crate) meta: ShardMeta,
}

impl HeldShard {
    /// The shard this body is.
    #[must_use]
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Total payload length, fixed at open.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.meta.body_len
    }

    /// Whether the opened body has no bytes. No closed shard produces one
    /// (`SHT-Q2`); a serving loop still streams it correctly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.meta.body_len == 0
    }

    /// How many storage chunks the body is read in, indexed from 0.
    #[must_use]
    pub fn chunk_count(&self) -> u32 {
        self.meta.chunk_count
    }
}
