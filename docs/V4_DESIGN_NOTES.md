# V4 Design Notes

This document captures design decisions, deferred work, and architectural direction for Shekyl V4. Items here are **not part of V3** — they are future work that was explicitly deferred with documented reasoning so it doesn't have to be rediscovered.

---

## LMDB Storage Layer: `heed` Migration

### Status: Deferred from V3

### What

Replace the current C++ `BlockchainLMDB` class (which accesses LMDB via raw `mdb_*` C API calls) with Rust's `heed` crate, eliminating the C FFI round-trip for all blockchain database operations.

### Why it was deferred

An incremental migration (table-by-table, with both C++ and Rust writing to the same LMDB environment during a transition period) introduces unacceptable risk surface for a system that is not broken:

1. **Two-writer coordination.** LMDB allows exactly one write transaction at a time per environment. Having both C++ (`m_write_batch_txn`) and Rust (`heed::RwTxn`) compete for write access requires explicit coordination (mutexes, or passing a raw `MDB_txn*` pointer across FFI). Any failure in this coordination deadlocks the node.

2. **Schema drift.** During the migration window, the schema must be consistent across two codebases: C++ struct layouts (`mdb_block_info_4`, `outkey`, `outtx`, etc.) and Rust `heed` typed databases. A mismatch causes silent data corruption on reads.

3. **Map resize race.** LMDB's `mdb_env_set_mapsize` invalidates all existing transactions and pointers. If one runtime resizes while the other holds a read transaction, the reader crashes or reads garbage. Both sides must coordinate resizes, which requires careful cross-language signaling.

4. **Inconsistent read snapshots.** LMDB's MVCC gives each reader a snapshot at the time of `mdb_txn_begin`. If Rust reads via one snapshot while C++ writes under a different one, the Rust reader may see stale state. This is not a bug in LMDB, but it creates subtle logic bugs when two codebases assume they're seeing consistent state.

5. **The current FFI JSON round-trip is a performance tax, not a correctness risk.** The wallet RPC routes through JSON serialization/deserialization, which is slow but functionally correct. Fixing this is an optimization, not a safety requirement.

### Recommended approach for V4

When the migration is undertaken, it should follow these principles:

1. **Single `Env` handle owned by Rust (`heed`).** Rust opens the LMDB environment and owns the `heed::Env`. The raw `MDB_env*` pointer is passed to C++ via FFI for any remaining C++ code that needs read access during the transition.

2. **No split write ownership.** There must never be a period where both C++ and Rust independently write to different tables in the same environment. The migration cutover should be atomic: one commit switches from C++ `BlockchainLMDB` to Rust `HeedBlockchainDB`.

3. **Read-only cross-process access first.** If an intermediate step is needed, start with Rust opening the environment read-only (for wallet scanning, RPC queries) while C++ retains write ownership. This is safe because LMDB allows unlimited concurrent readers.

4. **Full `BlockchainLMDB` port as a unit cutover.** Rather than migrating table-by-table, port the entire `BlockchainLMDB` class to Rust as one unit. The class has ~28 sub-databases (documented in [`LMDB_SCHEMA.md`](LMDB_SCHEMA.md)) and well-defined transaction boundaries (documented in [`LMDB_WRITE_ATOMICITY_AUDIT.md`](LMDB_WRITE_ATOMICITY_AUDIT.md)).

5. **`heed` 1.x (not `heed3`).** The vendored LMDB is based on OpenLDAP's `mdb.master` branch (version 0.9.70). The `heed` 1.x crate wraps this same branch. The `heed3` crate wraps `mdb.master3`, which has API-breaking changes and is not compatible with existing database files. See [`VENDORED_DEPENDENCIES.md`](VENDORED_DEPENDENCIES.md) for details.

### Prerequisites

Before starting the migration:

- [x] `docs/LMDB_SCHEMA.md` must be complete and verified (done as of V3)
- [x] All write atomicity gaps must be resolved (done as of V3; see audit document)
- [ ] The Rust wallet and scanner must be proven stable in production use on V3
- [ ] A comprehensive database round-trip test must exist: write via C++, read via Rust (and vice versa) for every sub-database, to verify struct layout compatibility

### Effort estimate

Large. The `BlockchainLMDB` class is ~5000 lines of C++ with 28 sub-databases, complex cursor management, batch transaction lifecycle, and migration code paths. The Rust port would need to replicate all of this, plus maintain backward compatibility with existing database files.

### References

- [`docs/LMDB_SCHEMA.md`](LMDB_SCHEMA.md) — complete schema reference for all 28 sub-databases
- [`docs/LMDB_WRITE_ATOMICITY_AUDIT.md`](LMDB_WRITE_ATOMICITY_AUDIT.md) — audit of all write transaction boundaries
- [`docs/VENDORED_DEPENDENCIES.md`](VENDORED_DEPENDENCIES.md) — LMDB version pinning and branch tracking
- `src/blockchain_db/lmdb/db_lmdb.cpp` — current C++ implementation
- `src/blockchain_db/lmdb/db_lmdb.h` — DBI handle declarations and struct definitions
