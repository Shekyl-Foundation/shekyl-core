// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Chunked reader over one held shard's `shard_frame` bytes.

use std::sync::Arc;

use shekyl_types::ShardId;

use crate::error::StoreError;
use crate::store::{open_chunk, Inner, ShardMeta};

/// The body of one served shard, read in bounded chunks.
///
/// Peak cost is one decrypted storage chunk. [`Self::len`] is fixed at
/// open so `content-length` can go out before any byte is read.
pub struct ShardFrameBody {
    inner: Arc<Inner>,
    slot: [u8; 32],
    shard_id: ShardId,
    salt: [u8; 16],
    body_len: u64,
    chunk_count: u32,
    /// Next storage chunk to decrypt.
    next_index: u32,
    /// Unread tail of the last decrypted chunk.
    leftover: Vec<u8>,
    leftover_off: usize,
    /// Bytes already handed to the caller.
    yielded: u64,
}

impl ShardFrameBody {
    pub(crate) fn new(
        inner: Arc<Inner>,
        slot: [u8; 32],
        shard_id: ShardId,
        meta: ShardMeta,
    ) -> Self {
        Self {
            inner,
            slot,
            shard_id,
            salt: meta.salt,
            body_len: meta.body_len,
            chunk_count: meta.chunk_count,
            next_index: 0,
            leftover: Vec::new(),
            leftover_off: 0,
            yielded: 0,
        }
    }

    /// Total payload length, fixed at open.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.body_len
    }

    /// Whether the opened body has no bytes. No closed shard produces
    /// one (`SHT-Q2`); the loop still streams it correctly.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.body_len == 0
    }

    /// Bytes not yet read. Shrinks; [`Self::len`] does not.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        usize::try_from(self.body_len.saturating_sub(self.yielded)).expect("fits usize")
    }

    /// Next body chunk of at most `max_bytes`, or `None` at the end.
    ///
    /// # Errors
    ///
    /// [`StoreError::Corrupt`] or [`StoreError::Backend`] if a sealed
    /// chunk cannot be opened. The response head may already be out.
    pub fn next_chunk(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, StoreError> {
        if self.yielded >= self.body_len {
            return Ok(None);
        }
        let want = max_bytes.max(1);
        if self.leftover_off >= self.leftover.len() {
            if self.next_index >= self.chunk_count {
                return Ok(None);
            }
            self.leftover = open_chunk(
                &self.inner,
                &self.slot,
                self.shard_id,
                &self.salt,
                u64::from(self.next_index),
            )?;
            self.leftover_off = 0;
            self.next_index = self.next_index.saturating_add(1);
        }
        let avail = self.leftover.len().saturating_sub(self.leftover_off);
        let take = avail.min(want);
        let chunk = self.leftover[self.leftover_off..self.leftover_off + take].to_vec();
        self.leftover_off += take;
        self.yielded = self
            .yielded
            .saturating_add(u64::try_from(take).expect("fits"));
        // Drop the decrypted chunk once it is spent so peak memory stays
        // one chunk, not one chunk plus its leftover copy.
        if self.leftover_off >= self.leftover.len() {
            self.leftover = Vec::new();
            self.leftover_off = 0;
        }
        Ok(Some(chunk))
    }
}
