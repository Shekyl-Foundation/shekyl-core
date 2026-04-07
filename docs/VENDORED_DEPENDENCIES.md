# Vendored C/C++ Dependencies

This document tracks vendored C/C++ dependencies in the `external/` tree. For Rust crate vendoring, see [SHEKYL_OXIDE_VENDORING.md](SHEKYL_OXIDE_VENDORING.md).

---

## LMDB (Lightning Memory-Mapped Database)

### Location

`external/db_drivers/liblmdb/`

### Version

| Field | Value |
|---|---|
| `MDB_VERSION_MAJOR` | 0 |
| `MDB_VERSION_MINOR` | 9 |
| `MDB_VERSION_PATCH` | 70 |
| `MDB_VERSION_DATE` | "December 19, 2015" |
| Version string | `0.9.70` |

The version `0.9.70` is a **Monero-project custom version number** inherited by Shekyl. The upstream OpenLDAP project uses a different release numbering scheme (0.9.x releases tracked on the `mdb.RE/0.9` branch). The Monero/Shekyl vendored copy is based on OpenLDAP's **`mdb.master`** development branch, with additional patches cherry-picked and applied.

### Upstream tracking

The vendored copy includes patches from the OpenLDAP ITS (Issue Tracking System) tracker beyond what's in any official LMDB release:

- ITS#9385: fix using `MDB_NOSUBDIR` with nonexistent file
- ITS#9496: fix `mdb_env_open` bug from #8704
- ITS#9500: fix regression from ITS#8662
- ITS#9007: don't free loose writemap pages
- ITS#9068: fix backslash escaping
- ITS#8704: raw partition support (preliminary)

### Last modified in Shekyl repo

| File | Commit | Date |
|---|---|---|
| `mdb.c` | `e5621cc08` | 2022-06-03 |
| `lmdb.h` | `e5621cc08` | 2022-06-03 |

### Branch distinction: `mdb.master` vs `mdb.master3`

OpenLDAP maintains two active development branches:

- **`mdb.master`**: The branch our vendored copy tracks. LMDB API version 0.9.x. Uses the `MDB_` prefix. This is what the Rust `heed` (v1.x) crate wraps.
- **`mdb.master3`**: A newer development line with `MDB3_` prefix, multi-value support, and API-breaking changes. This is what `heed3` (v3.x) wraps.

For any future LMDB migration to Rust's `heed`, the branch distinction matters:
- `heed` 1.x → `mdb.master` (compatible with our current DB files)
- `heed3` 3.x → `mdb.master3` (requires DB migration, not backward compatible)

### Known CVEs

| CVE | Affects us? | Description |
|---|---|---|
| CVE-2026-22185 | **No** (affects `mdb_load` utility, ≤ 0.9.14) | Heap buffer underflow in `readline()` of `mdb_load` when processing malformed input with embedded NUL bytes. Our vendored version (0.9.70) includes the ITS#10421 fix. The `mdb_load` utility is not used at runtime — it's a standalone import tool. |

No other CVEs have been filed against LMDB core (`mdb.c`, `lmdb.h`) as of April 2026.

### Update procedure

1. Identify the desired OpenLDAP `mdb.master` commit with the fix.
2. Cherry-pick or manually apply the patch to `external/db_drivers/liblmdb/`.
3. Verify the `MDB_VERSION_*` macros are updated if the patch changes them.
4. Run full test suite: unit tests, blockchain sync test, and LMDB-specific stress tests.
5. Update this document with the new commit and ITS references.
6. Commit with the upstream ITS reference in the message (e.g., `ITS#XXXX description`).

### Compilation

LMDB is compiled via `external/db_drivers/liblmdb/CMakeLists.txt`. It is statically linked into all Shekyl executables that use `BlockchainLMDB`. No external LMDB shared library is used.
