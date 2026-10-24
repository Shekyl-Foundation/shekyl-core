// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Bodies on their way to the entry: held for room, then offered. Each is
//! found by its header's hash, and an offered one by its tag too, so no
//! lookup walks the set.

use std::collections::BTreeMap;

use shekyl_types::BlockHash;

use crate::model::BoundArrival;

/// Bodies bound to their headers, waiting for the entry's room, by header
/// hash. One per header: a second body for a header already held is not
/// kept.
pub(crate) struct Held<K>(BTreeMap<BlockHash, BoundArrival<K>>);

impl<K: Copy + Eq> Held<K> {
    pub(crate) const fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) fn insert(&mut self, arrival: BoundArrival<K>) {
        self.0.entry(arrival.header.hash()).or_insert(arrival);
    }

    pub(crate) fn contains(&self, hash: BlockHash) -> bool {
        self.0.contains_key(&hash)
    }

    pub(crate) fn take(&mut self, hash: BlockHash) -> Option<BoundArrival<K>> {
        self.0.remove(&hash)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The session closed: its bodies are not offered.
    pub(crate) fn drop_session(&mut self, session: K) {
        self.0.retain(|_, arrival| arrival.session != session);
    }
}

/// Arrivals offered to the entry and not yet answered, by tag and by
/// header hash.
pub(crate) struct Offered<K> {
    by_tag: BTreeMap<u64, BoundArrival<K>>,
    tag_of: BTreeMap<BlockHash, u64>,
}

impl<K: Copy + Eq> Offered<K> {
    pub(crate) const fn new() -> Self {
        Self {
            by_tag: BTreeMap::new(),
            tag_of: BTreeMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, arrival: BoundArrival<K>) {
        self.tag_of.insert(arrival.header.hash(), arrival.tag);
        self.by_tag.insert(arrival.tag, arrival);
    }

    pub(crate) fn contains(&self, hash: BlockHash) -> bool {
        self.tag_of.contains_key(&hash)
    }

    /// The entry answered `tag`: the arrival it names, if it is ours.
    pub(crate) fn answered(&mut self, tag: u64) -> Option<BoundArrival<K>> {
        let arrival = self.by_tag.remove(&tag)?;
        self.tag_of.remove(&arrival.header.hash());
        Some(arrival)
    }

    /// The session closed: its offers are forgotten.
    pub(crate) fn drop_session(&mut self, session: K) {
        let tag_of = &mut self.tag_of;
        self.by_tag.retain(|_, arrival| {
            let keep = arrival.session != session;
            if !keep {
                tag_of.remove(&arrival.header.hash());
            }
            keep
        });
    }
}
