// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `P`'s serving body store (`WALLET_SIDE_STORE.md` `WSS-Q1`(a)).
//!
//! One redb file, owned by one actor (the wallet's body-store actor),
//! holding whole-shard [`shekyl_wire::shard_frame`] bodies. The store never
//! talks to the daemon (`WSS-17`). It answers only "is this shard present,
//! and what are its bytes", one storage chunk at a time, with servability
//! settled at open (`WSS-Q7`). Its handle is not shared: the owner hands out
//! [`HeldShard`]s and owned chunk copies, and the key never leaves it
//! (`WSS-Q13`).
//!
//! At rest each storage chunk is sealed under one store key with
//! `nonce = salt ‖ chunk_index`. A refill mints a fresh salt, so a
//! reused slot cannot reproduce a nonce (`WSS` §6.6.5). Table keys are
//! cSHAKE256 of the store key and the shard id, so a stolen file does
//! not name the shards it holds (`WSS-18`). Open also checks a cell
//! sealed under that key, so a file written by another key is refused
//! before any shard row is trusted.
//!
//! This crate holds no Tor, no key-derivation from a wallet password,
//! and no serve-set: the caller supplies the key and decides when to
//! erase (`WSS-Q8` / the pin-release gate).

#![forbid(unsafe_code)]

mod body;
mod error;
mod store;

pub use body::HeldShard;
pub use error::StoreError;
pub use store::{derive_store_key, BodyStore, StoreKey};

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_types::ShardId;

    fn key() -> StoreKey {
        StoreKey::from_bytes([0x5a; 32])
    }

    fn shard(n: u64) -> ShardId {
        ShardId::from_raw(n)
    }

    /// Every chunk of a held shard, in order, as a serving loop reads it.
    fn read_body(store: &BodyStore, id: ShardId) -> Vec<u8> {
        let held = store.open_shard(id).expect("open").expect("held");
        let mut got = Vec::new();
        for index in 0..held.chunk_count() {
            got.extend_from_slice(&store.read_chunk(&held, index).expect("chunk"));
        }
        assert_eq!(
            got.len() as u64,
            held.len(),
            "the body is the length it opened at"
        );
        got
    }

    #[test]
    fn put_then_stream_recovers_the_frame() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        let frame = b"\x01\x01not-a-real-frame-but-opaque".to_vec();
        store.put_shard(shard(3), &frame).expect("put");
        assert_eq!(read_body(&store, shard(3)), frame);
        assert!(store.holds(shard(3)).expect("holds"));
        assert!(!store.holds(shard(4)).expect("absent"));
    }

    #[test]
    fn a_multi_chunk_body_reads_back_chunk_by_chunk() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        let frame: Vec<u8> = (0..(3 * store::CHUNK_BYTES + 5))
            .map(|i| u8::try_from(i % 251).expect("fits"))
            .collect();
        store.put_shard(shard(5), &frame).expect("put");
        let held = store.open_shard(shard(5)).expect("open").expect("held");
        assert_eq!(held.chunk_count(), 4);
        assert_eq!(read_body(&store, shard(5)), frame);
        assert!(matches!(
            store.read_chunk(&held, held.chunk_count()),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_chunk_read_across_a_refill_fails_authentication() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        store.put_shard(shard(6), b"first").expect("put");
        let held = store.open_shard(shard(6)).expect("open").expect("held");
        store.put_shard(shard(6), b"other").expect("refill");
        assert!(matches!(
            store.read_chunk(&held, 0),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_missing_shard_is_an_ordinary_miss() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        assert!(store.open_shard(shard(1)).expect("open").is_none());
    }

    #[test]
    fn refill_mints_a_fresh_salt_and_replaces_the_bytes() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        store.put_shard(shard(0), b"first").expect("put");
        store.put_shard(shard(0), b"second-longer").expect("refill");
        assert_eq!(read_body(&store, shard(0)), b"second-longer");
    }

    #[test]
    fn erase_makes_the_shard_a_miss() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        store.put_shard(shard(9), b"gone").expect("put");
        store.erase_shard(shard(9)).expect("erase");
        assert!(store.open_shard(shard(9)).expect("open").is_none());
    }

    #[test]
    fn a_wrong_key_cannot_name_or_open_a_shard() {
        let store = BodyStore::open_ephemeral(key()).expect("open");
        store.put_shard(shard(2), b"secret-link").expect("put");
        let other = BodyStore::open_ephemeral(StoreKey::from_bytes([0x11; 32])).expect("other");
        // Different key ⇒ different slot hash, so the row is not found.
        assert!(other.open_shard(shard(2)).expect("open").is_none());
    }

    #[test]
    fn a_swapped_key_is_refused_before_any_shard_row_is_trusted() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("p.store");
        let frame = b"sealed-under-a";
        {
            let store = BodyStore::open(&path, key()).expect("create");
            store.put_shard(shard(4), frame).expect("put");
        }
        let wrong = BodyStore::open(&path, StoreKey::from_bytes([0x11; 32]));
        assert!(matches!(wrong, Err(StoreError::KeyRejected)));
        let store = BodyStore::open(&path, key()).expect("reopen");
        assert_eq!(read_body(&store, shard(4)), frame);
    }

    #[test]
    fn persist_round_trip_on_a_path() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("p.store");
        {
            let store = BodyStore::open(&path, key()).expect("create");
            store.put_shard(shard(7), b"on-disk").expect("put");
        }
        let store = BodyStore::open(&path, key()).expect("reopen");
        assert_eq!(read_body(&store, shard(7)), b"on-disk");
    }

    #[test]
    fn derive_store_key_is_domain_separated() {
        let kek = [0x42u8; 32];
        let a = derive_store_key(&kek);
        let b = derive_store_key(&kek);
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), &kek);
    }
}
