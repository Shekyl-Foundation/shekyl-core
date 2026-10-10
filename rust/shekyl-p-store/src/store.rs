// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The redb file and the two handles on it: a writer and a read-only
//! clone the serving loop is allowed to hold.

use std::path::Path;
use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use shekyl_chacha::{seal, KEY_SIZE, NONCE_SIZE};
use shekyl_crypto_hash::cshake256_32;
use shekyl_types::ShardId;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::body::ShardFrameBody;
use crate::error::{StoreError, SCHEMA_VERSION};

const SHARDS: TableDefinition<&[u8; 32], [u8; META_LEN]> = TableDefinition::new("p_shards");
const CHUNKS: TableDefinition<&[u8; CHUNK_KEY_LEN], &[u8]> = TableDefinition::new("p_chunks");
const META: TableDefinition<&str, u8> = TableDefinition::new("p_meta");
/// The verifier cell. Not the schema table: that cell is a `u8`, and the
/// ciphertext does not belong there.
const KEY_CHECK: TableDefinition<&str, &[u8]> = TableDefinition::new("p_key_check");

const META_LEN: usize = 16 + 8 + 4;
const CHUNK_KEY_LEN: usize = 32 + 8;
/// One storage chunk. Peak resident cost of a serve is this plus the
/// AEAD tag, not the shard (`WSS-Q7` property 3).
pub(crate) const CHUNK_BYTES: usize = 64 * 1024;
const SALT_LEN: usize = 16;

const SCHEMA_CELL: &str = "schema";
const KEY_CHECK_CELL: &str = "verifier";

/// One cell, written once at init. Chunk nonces are a random salt
/// concatenated with a chunk index, so this domain-constant nonce cannot
/// collide with one. Password change re-wraps `file_kek` and does not
/// rotate the store key, so the cell stays valid. Do not re-seal it
/// under this nonce with different plaintext.
const KEY_CHECK_NONCE: [u8; NONCE_SIZE] = *b"p-store-key-check-nonce!";
/// Plaintext of the verifier. A domain constant, never a shard id.
const KEY_CHECK_PLAINTEXT: &[u8] = b"shekyl/p-store-key-ok-v1";
/// Associated data of the verifier. A label used only as AEAD AAD, not a
/// cSHAKE customization, so it is not a mechanism-1 domain.
const KEY_CHECK_AAD: &[u8] = b"shekyl/p-store-key-check-v1";

/// cSHAKE256 customization for [`derive_store_key`] (rule 30: one label,
/// one function, versioned).
pub const STORE_AEAD_CUSTOMIZATION: &[u8] = b"shekyl/p-store-aead-v1";

/// cSHAKE256 customization for the per-shard table slot.
pub const STORE_SLOT_CUSTOMIZATION: &[u8] = b"shekyl/p-store-slot-v1";

/// The single store key. Derived from the wallet's existing hierarchy
/// ([`derive_store_key`]); never a per-shard key (`WSS-Q12` rejected
/// per-shard wrapping).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct StoreKey([u8; KEY_SIZE]);

impl StoreKey {
    /// Wrap an already-derived 32-byte key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// Domain-separated cSHAKE256 of the wallet `file_kek`. Open verifies a
/// cell sealed under that key, so a swapped companion file fails AEAD
/// before any shard row is trusted.
#[must_use]
pub fn derive_store_key(file_kek: &[u8; KEY_SIZE]) -> StoreKey {
    StoreKey(cshake256_32(STORE_AEAD_CUSTOMIZATION, file_kek))
}

pub(crate) struct Inner {
    db: Database,
    key: StoreKey,
}

/// The writer: fill, refill, erase. The serving loop never holds this.
pub struct BodyStore {
    inner: Arc<Inner>,
}

/// Read-only handle the provider is allowed to hold. Cannot write, so
/// "the serving side is a reader" is a type, not a convention.
#[derive(Clone)]
pub struct BodyStoreReader {
    inner: Arc<Inner>,
}

impl BodyStore {
    /// Open or create the store at `path` under `key`.
    ///
    /// An existing file is checked before any write: the schema byte,
    /// then a cell sealed under `key`. A missing cell or a failed open
    /// is [`StoreError::KeyRejected`]. Pre-genesis, delete the file and
    /// reopen; there is no migration.
    ///
    /// # Errors
    ///
    /// [`StoreError::Schema`] if an existing file's version cell is not
    /// [`SCHEMA_VERSION`]; [`StoreError::KeyRejected`] if that file was
    /// not sealed under `key`; [`StoreError::Backend`] on I/O.
    pub fn open(path: impl AsRef<Path>, key: StoreKey) -> Result<Self, StoreError> {
        let existed = path.as_ref().exists();
        let db = Database::create(path)?;
        let store = Self {
            inner: Arc::new(Inner { db, key }),
        };
        if existed {
            store.check_schema()?;
            store.check_key()?;
        } else {
            store.init_tables()?;
        }
        Ok(store)
    }

    /// In-memory store for tests and fixtures.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] if redb cannot build the in-memory backend.
    pub fn open_ephemeral(key: StoreKey) -> Result<Self, StoreError> {
        let db = Database::builder().create_with_backend(InMemoryBackend::new())?;
        let store = Self {
            inner: Arc::new(Inner { db, key }),
        };
        store.init_tables()?;
        Ok(store)
    }

    /// A read-only clone. The provider takes this, never [`Self`].
    #[must_use]
    pub fn reader(&self) -> BodyStoreReader {
        BodyStoreReader {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Write (or replace) the shard's `shard_frame` bytes. Mints a
    /// fresh salt, so a refill cannot reuse a nonce.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on I/O.
    pub fn put_shard(&self, shard_id: ShardId, frame: &[u8]) -> Result<(), StoreError> {
        let slot = slot_key(self.inner.key.as_bytes(), shard_id);
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let chunks = frame.chunks(CHUNK_BYTES).collect::<Vec<_>>();
        let chunk_count = u32::try_from(chunks.len()).expect("a shard's chunk count fits u32");
        let body_len = u64::try_from(frame.len()).expect("a body length fits u64");

        let txn = self.inner.db.begin_write()?;
        {
            let mut shards = txn.open_table(SHARDS)?;
            let mut bodies = txn.open_table(CHUNKS)?;
            if let Some(old) = shards.get(&slot)? {
                drop_chunks(&mut bodies, &slot, decode_meta(old.value()).chunk_count)?;
            }
            for (i, chunk) in chunks.iter().enumerate() {
                let index = u64::try_from(i).expect("chunk index fits u64");
                let sealed = seal_chunk(self.inner.key.as_bytes(), &salt, shard_id, index, chunk);
                let ck = chunk_key(&slot, index);
                bodies.insert(&ck, sealed.as_slice())?;
            }
            shards.insert(&slot, encode_meta(&salt, body_len, chunk_count))?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Drop the shard. The only path that erases (`WSS` §6.2.6).
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on I/O.
    pub fn erase_shard(&self, shard_id: ShardId) -> Result<(), StoreError> {
        let slot = slot_key(self.inner.key.as_bytes(), shard_id);
        let txn = self.inner.db.begin_write()?;
        {
            let mut shards = txn.open_table(SHARDS)?;
            let mut bodies = txn.open_table(CHUNKS)?;
            if let Some(old) = shards.get(&slot)? {
                drop_chunks(&mut bodies, &slot, decode_meta(old.value()).chunk_count)?;
            }
            shards.remove(&slot)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn check_schema(&self) -> Result<(), StoreError> {
        let txn = self.inner.db.begin_read()?;
        let found = match txn.open_table(META) {
            Ok(meta) => meta.get(SCHEMA_CELL)?.map(|v| v.value()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };
        match found {
            Some(SCHEMA_VERSION) => Ok(()),
            Some(other) => Err(StoreError::Schema { found: other }),
            None => Err(StoreError::Schema { found: 0 }),
        }
    }

    /// The verifier is sealed under the store key. A plaintext tag would
    /// be forgeable by rewriting the cell; AEAD is not.
    fn check_key(&self) -> Result<(), StoreError> {
        let txn = self.inner.db.begin_read()?;
        let sealed = match txn.open_table(KEY_CHECK) {
            Ok(table) => table.get(KEY_CHECK_CELL)?.map(|row| row.value().to_vec()),
            Err(redb::TableError::TableDoesNotExist(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let Some(sealed) = sealed else {
            return Err(StoreError::KeyRejected);
        };
        match shekyl_chacha::open(
            self.inner.key.as_bytes(),
            &KEY_CHECK_NONCE,
            KEY_CHECK_AAD,
            &sealed,
        ) {
            Ok(plain) if plain.as_slice() == KEY_CHECK_PLAINTEXT => Ok(()),
            _ => Err(StoreError::KeyRejected),
        }
    }

    /// Create the tables and the verifier. Called only for a new file:
    /// a reopen must not rewrite the cell under the same nonce.
    fn init_tables(&self) -> Result<(), StoreError> {
        let txn = self.inner.db.begin_write()?;
        let _ = txn.open_table(SHARDS)?;
        let _ = txn.open_table(CHUNKS)?;
        {
            let mut meta = txn.open_table(META)?;
            meta.insert(SCHEMA_CELL, SCHEMA_VERSION)?;
        }
        {
            let mut check = txn.open_table(KEY_CHECK)?;
            let sealed = seal(
                self.inner.key.as_bytes(),
                &KEY_CHECK_NONCE,
                KEY_CHECK_AAD,
                KEY_CHECK_PLAINTEXT,
            );
            check.insert(KEY_CHECK_CELL, sealed.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod key_check_tests {
    use super::*;

    #[test]
    fn a_schema_file_without_the_verifier_cell_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("bare.store");
        {
            let db = Database::create(&path).expect("create");
            let txn = db.begin_write().expect("write");
            {
                let mut meta = txn.open_table(META).expect("meta");
                meta.insert(SCHEMA_CELL, SCHEMA_VERSION).expect("schema");
            }
            txn.commit().expect("commit");
        }
        let opened = BodyStore::open(&path, StoreKey::from_bytes([0x5a; 32]));
        assert!(matches!(opened, Err(StoreError::KeyRejected)));
    }
}

impl BodyStoreReader {
    /// Open the body if the shard is held. Servability is settled here.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on I/O; [`StoreError::Corrupt`] if the
    /// meta row is the wrong width.
    pub fn open_shard(&self, shard_id: ShardId) -> Result<Option<ShardFrameBody>, StoreError> {
        let slot = slot_key(self.inner.key.as_bytes(), shard_id);
        let txn = self.inner.db.begin_read()?;
        let shards = match txn.open_table(SHARDS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(row) = shards.get(&slot)? else {
            return Ok(None);
        };
        let meta = decode_meta(row.value());
        Ok(Some(ShardFrameBody::new(
            Arc::clone(&self.inner),
            slot,
            shard_id,
            meta,
        )))
    }

    /// Whether the slot is occupied. Used by reconcile, not by the
    /// provider (the provider stays blind to the serve set).
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on I/O.
    pub fn holds(&self, shard_id: ShardId) -> Result<bool, StoreError> {
        Ok(self.open_shard(shard_id)?.is_some())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ShardMeta {
    pub salt: [u8; SALT_LEN],
    pub body_len: u64,
    pub chunk_count: u32,
}

fn encode_meta(salt: &[u8; SALT_LEN], body_len: u64, chunk_count: u32) -> [u8; META_LEN] {
    let mut out = [0u8; META_LEN];
    out[..SALT_LEN].copy_from_slice(salt);
    out[SALT_LEN..SALT_LEN + 8].copy_from_slice(&body_len.to_le_bytes());
    out[SALT_LEN + 8..].copy_from_slice(&chunk_count.to_le_bytes());
    out
}

fn decode_meta(bytes: [u8; META_LEN]) -> ShardMeta {
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[..SALT_LEN]);
    let body_len = u64::from_le_bytes(bytes[SALT_LEN..SALT_LEN + 8].try_into().expect("8"));
    let chunk_count = u32::from_le_bytes(bytes[SALT_LEN + 8..].try_into().expect("4"));
    ShardMeta {
        salt,
        body_len,
        chunk_count,
    }
}

fn slot_key(store_key: &[u8; KEY_SIZE], shard_id: ShardId) -> [u8; 32] {
    let mut input = [0u8; KEY_SIZE + 8];
    input[..KEY_SIZE].copy_from_slice(store_key);
    input[KEY_SIZE..].copy_from_slice(&shard_id.to_raw().to_le_bytes());
    cshake256_32(STORE_SLOT_CUSTOMIZATION, &input)
}

fn chunk_key(slot: &[u8; 32], index: u64) -> [u8; CHUNK_KEY_LEN] {
    let mut key = [0u8; CHUNK_KEY_LEN];
    key[..32].copy_from_slice(slot);
    key[32..].copy_from_slice(&index.to_le_bytes());
    key
}

fn drop_chunks(
    table: &mut redb::Table<&[u8; CHUNK_KEY_LEN], &[u8]>,
    slot: &[u8; 32],
    chunk_count: u32,
) -> Result<(), StoreError> {
    for i in 0..chunk_count {
        let ck = chunk_key(slot, u64::from(i));
        table.remove(&ck)?;
    }
    Ok(())
}

pub(crate) fn seal_chunk(
    key: &[u8; KEY_SIZE],
    salt: &[u8; SALT_LEN],
    shard_id: ShardId,
    index: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    seal(key, &nonce(salt, index), &aad(shard_id, index), plaintext)
}

pub(crate) fn nonce(salt: &[u8; SALT_LEN], index: u64) -> [u8; NONCE_SIZE] {
    let mut n = [0u8; NONCE_SIZE];
    n[..SALT_LEN].copy_from_slice(salt);
    n[SALT_LEN..].copy_from_slice(&index.to_le_bytes());
    n
}

pub(crate) fn aad(shard_id: ShardId, index: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&shard_id.to_raw().to_le_bytes());
    out[8..].copy_from_slice(&index.to_le_bytes());
    out
}

pub(crate) fn open_chunk(
    inner: &Inner,
    slot: &[u8; 32],
    shard_id: ShardId,
    salt: &[u8; SALT_LEN],
    index: u64,
) -> Result<Vec<u8>, StoreError> {
    let txn = inner.db.begin_read()?;
    let table = txn.open_table(CHUNKS)?;
    let ck = chunk_key(slot, index);
    let Some(row) = table.get(&ck)? else {
        return Err(StoreError::Corrupt {
            detail: "sealed chunk missing after open".to_owned(),
        });
    };
    shekyl_chacha::open(
        inner.key.as_bytes(),
        &nonce(salt, index),
        &aad(shard_id, index),
        row.value(),
    )
    .map_err(|_| StoreError::Corrupt {
        detail: "sealed chunk failed authentication".to_owned(),
    })
}
