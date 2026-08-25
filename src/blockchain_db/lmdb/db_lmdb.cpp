// Copyright (c) 2014-2022, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "db_lmdb.h"
#include "shekyl/consensus_constants_generated.h"
#include "shekyl/shekyl_ffi.h"

#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/format.hpp>
#include <boost/circular_buffer.hpp>
#include <memory>  // std::unique_ptr
#include <cstring>  // memcpy
#include <map>
#include <unordered_map>
#include <array>

// `disable_ntfs_compression` below calls `DeviceIoControl` with
// `FSCTL_SET_COMPRESSION`. Pull in the Windows API surface locally on
// every Windows toolchain we build on:
//
//   * MSVC: `<winioctl.h>` depends on `<windows.h>` for its foundation
//     types (`ULONG`, `BOOLEAN`, `_Field_size_(...)`, ...). Before
//     Chore #2 those came in transitively through easylogging++; with
//     that gone we have to establish the base ourselves or the SDK
//     header explodes with "unknown override specifier" on
//     `_Field_size_`-style SAL annotations.
//
//   * MinGW-w64: `<windows.h>` skips `<winioctl.h>` under
//     `WIN32_LEAN_AND_MEAN` (the project-wide flag set in the root
//     `CMakeLists.txt`), so we include it explicitly after.
//
// One stubborn case remains: on MSYS2 CI the `<winioctl.h>`
// `#ifndef _FILESYSTEMFSCTL_` guard is already closed by the time we
// reach it (some upstream header in the boost/lmdb chain defines the
// sentinel), so `FSCTL_SET_COMPRESSION` silently goes missing. Its
// value has been stable since NT 4.0, so we re-supply the definition
// from the primitives that are declared unconditionally at the top of
// `<winioctl.h>` (`CTL_CODE`, `FILE_DEVICE_FILE_SYSTEM`,
// `METHOD_BUFFERED`, `FILE_READ_DATA`, `FILE_WRITE_DATA`). This is a
// local rescue, not a compatibility shim — if the upstream guard ever
// clears up, our `#ifndef` simply no-ops.
#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#ifndef FSCTL_SET_COMPRESSION
#define FSCTL_SET_COMPRESSION \
  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 16, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#endif
#endif

#include "string_tools.h"
#include "common/util.h"
#include "common/pruning.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "profile_tools.h"
#include "fcmp/ct_ops.h"

#undef SHEKYL_DEFAULT_LOG_CATEGORY
#define SHEKYL_DEFAULT_LOG_CATEGORY "blockchain.db.lmdb"


#if defined(__x86_64)
#define MISALIGNED_OK	1
#endif

using epee::string_tools::pod_to_hex;
using namespace crypto;

// Increase when the DB structure changes.
// V7: curve-tree tables restructured — composite keys replace DUPSORT,
// bidirectional output↔leaf mapping tables and block-pending journal added.
// V8: persisted pop-symmetric frozen-shard counter added to `properties`
// (`archival_frozen_shard_count`, ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4);
// a pre-V8 DB has segment rows the counter does not account for.
// Nodes with pre-V8 data dirs must delete and resync.
// V9: block header gains `attestation_root` (ARCHIVAL_CREDIT_WIRE.md §3), so
// the persisted block blob in `blocks` grows 32 bytes; a pre-V9 blob has no
// attestation_root and the V9 parser cannot read it. Delete and resync. The
// block's boost serializer (cryptonote_boost_serialization.h, the alt-block /
// txpool caches and blocks.dat exports) enforces the same boundary via
// BOOST_CLASS_VERSION(cryptonote::block, 1): a pre-V9 archive is refused
// loudly, not misparsed.
//   Within V9 (no bump): the additive `archival_attestation_witness` table and
//   its reorg-survival `archival_alt_attestation_witness` counterpart
//   (ARCHIVAL_CREDIT_WIRE.md §3.2/§4, transport B2) are opened with MDB_CREATE.
//   A new empty table is backward-compatible on an existing env — it does not
//   change the block blob and needs no resync — so they ride the V9 boundary
//   rather than asserting a false incompatibility with a bump.
#define VERSION 9

namespace
{

#pragma pack(push, 1)
// This MUST be identical to output_data_t, without the extra rct data at the end
struct pre_rct_output_data_t
{
  crypto::public_key pubkey;       //!< the output's public key (for spend verification)
  uint64_t           unlock_time;  //!< the output's unlock time (or height)
  uint64_t           height;       //!< the height of the block which created the output
};
#pragma pack(pop)

template <typename T>
inline void throw0(const T &e)
{
  LOG_PRINT_L0(e.what());
  throw e;
}

template <typename T>
inline void throw1(const T &e)
{
  LOG_PRINT_L1(e.what());
  throw e;
}

#define MDB_val_set(var, val)   MDB_val var = {sizeof(val), (void *)&val}

#define MDB_val_sized(var, val) MDB_val var = {val.size(), (void *)val.data()}

#define MDB_val_str(var, val) MDB_val var = {strlen(val) + 1, (void *)val}

template<typename T>
struct MDB_val_copy: public MDB_val
{
  MDB_val_copy(const T &t) :
    t_copy(t)
  {
    mv_size = sizeof (T);
    mv_data = &t_copy;
  }
private:
  T t_copy;
};

template<>
struct MDB_val_copy<cryptonote::blobdata>: public MDB_val
{
  MDB_val_copy(const cryptonote::blobdata &bd) :
    data(new char[bd.size()])
  {
    memcpy(data.get(), bd.data(), bd.size());
    mv_size = bd.size();
    mv_data = data.get();
  }
private:
  std::unique_ptr<char[]> data;
};

template<>
struct MDB_val_copy<const char*>: public MDB_val
{
  MDB_val_copy(const char *s):
    size(strlen(s)+1), // include the NUL, makes it easier for compares
    data(new char[size])
  {
    mv_size = size;
    mv_data = data.get();
    memcpy(mv_data, s, size);
  }
private:
  size_t size;
  std::unique_ptr<char[]> data;
};

}

namespace cryptonote
{

int BlockchainLMDB::compare_uint64(const MDB_val *a, const MDB_val *b)
{
  uint64_t va, vb;
  memcpy(&va, a->mv_data, sizeof(va));
  memcpy(&vb, b->mv_data, sizeof(vb));
  return (va < vb) ? -1 : va > vb;
}

int BlockchainLMDB::compare_hash32(const MDB_val *a, const MDB_val *b)
{
  uint32_t *va = (uint32_t*) a->mv_data;
  uint32_t *vb = (uint32_t*) b->mv_data;
  for (int n = 7; n >= 0; n--)
  {
    if (va[n] == vb[n])
      continue;
    return va[n] < vb[n] ? -1 : 1;
  }

  return 0;
}

int BlockchainLMDB::compare_string(const MDB_val *a, const MDB_val *b)
{
  const char *va = (const char*) a->mv_data;
  const char *vb = (const char*) b->mv_data;
  const size_t sz = std::min(a->mv_size, b->mv_size);
  int ret = strncmp(va, vb, sz);
  if (ret)
    return ret;
  if (a->mv_size < b->mv_size)
    return -1;
  if (a->mv_size > b->mv_size)
    return 1;
  return 0;
}

}

namespace
{

/* DB schema:
 *
 * Table            Key          Data
 * -----            ---          ----
 * blocks           block ID     block blob
 * block_heights    block hash   block height
 * block_info       block ID     {block metadata}
 *
 * txs_pruned       txn ID       pruned txn blob
 * txs_pqc_auths    txn ID       pqc_auths slice (v3+ non-coinbase), optional
 * txs_prunable     txn ID       prunable txn blob
 * txs_prunable_hash txn ID      prunable txn hash
 * txs_prunable_tip txn ID       height
 * tx_indices       txn hash     {txn ID, metadata}
 * tx_outputs       txn ID       [txn amount output indices]
 *
 * output_txs       output ID    {txn hash, local index}
 * output_amounts   amount       [{amount output index, metadata}...]
 *
 * spent_keys       input hash   -
 *
 * txpool_meta      txn hash     txn metadata
 * txpool_blob      txn hash     txn blob
 *
 * alt_blocks       block hash   {block data, block blob}
 *
 * Note: where the data items are of uniform size, DUPFIXED tables have
 * been used to save space. In most of these cases, a dummy "zerokval"
 * key is used when accessing the table; the Key listed above will be
 * attached as a prefix on the Data to serve as the DUPSORT key.
 * (DUPFIXED saves 8 bytes per record.)
 *
 * The output_amounts table doesn't use a dummy key, but uses DUPSORT.
 */
// ─── The LMDB table list ───────────────────────────────────────────────────
//
// One list, two products: the name constants below and `kLmdbTableCount`, which
// is what `mdb_env_set_maxdbs` is given. Adding a table means adding a line
// here — a table cannot be opened without a name, and a name cannot be added
// without the count following it.
//
// This replaced a hand-maintained `48` sitting three hundred lines from the
// opens it was counting, at the moment the 49th table arrived (`SO-D4`,
// `ARCHIVAL_SETTLEMENT_WRITER.md`). That overflow fails at **runtime only**: it
// compiles, links, and passes every test that never opens a fresh environment,
// then throws `MDB_DBS_FULL` on a real node. A ceiling that cannot notice its
// own subject is not a ceiling (rule 47).
#define SHEKYL_LMDB_TABLES(X) \
  X(LMDB_BLOCKS,                            "blocks") \
  X(LMDB_BLOCK_HEIGHTS,                     "block_heights") \
  X(LMDB_BLOCK_INFO,                        "block_info") \
  \
  X(LMDB_TXS,                               "txs") \
  X(LMDB_TXS_PRUNED,                        "txs_pruned") \
  X(LMDB_TXS_PQC_AUTHS,                     "txs_pqc_auths") \
  X(LMDB_TXS_PRUNABLE,                      "txs_prunable") \
  X(LMDB_TXS_PRUNABLE_HASH,                 "txs_prunable_hash") \
  X(LMDB_TXS_PRUNABLE_TIP,                  "txs_prunable_tip") \
  X(LMDB_TX_INDICES,                        "tx_indices") \
  X(LMDB_TX_OUTPUTS,                        "tx_outputs") \
  \
  X(LMDB_OUTPUT_TXS,                        "output_txs") \
  X(LMDB_OUTPUT_AMOUNTS,                    "output_amounts") \
  X(LMDB_SPENT_KEYS,                        "spent_keys") \
  \
  X(LMDB_TXPOOL_META,                       "txpool_meta") \
  X(LMDB_TXPOOL_BLOB,                       "txpool_blob") \
  \
  X(LMDB_ALT_BLOCKS,                        "alt_blocks") \
  \
  X(LMDB_HF_STARTING_HEIGHTS,               "hf_starting_heights") \
  X(LMDB_HF_VERSIONS,                       "hf_versions") \
  \
  X(LMDB_PROPERTIES,                        "properties") \
  \
  X(LMDB_BLOCK_BURN,                        "block_burn") \
  X(LMDB_ARCHIVAL_SERVE_CREDIT,             "archival_serve_credit") \
  X(LMDB_ARCHIVAL_SETTLEMENT,               "archival_settlement") \
  X(LMDB_ARCHIVAL_ATTESTATION_WITNESS,      "archival_attestation_witness") \
  X(LMDB_ARCHIVAL_ALT_ATTESTATION_WITNESS,  "archival_alt_attestation_witness") \
  X(LMDB_ARCHIVAL_BOND,                     "archival_bond") \
  X(LMDB_ARCHIVAL_SHARD_SEGMENT,            "archival_shard_segment") \
  X(LMDB_ARCHIVAL_SLASH_APPLIED,            "archival_slash_applied") \
  X(LMDB_ARCHIVAL_SLASH_LOG,                "archival_slash_log") \
  X(LMDB_ARCHIVAL_EMISSION_CLAIM_LOG,       "archival_emission_claim_log") \
  X(LMDB_ARCHIVAL_BOND_UNBOND_LOG,          "archival_bond_unbond_log") \
  X(LMDB_ARCHIVAL_BOND_HOLDINGS_UPDATE_LOG, "archival_bond_holdings_update_log") \
  X(LMDB_ARCHIVAL_BOND_REBOND_LOG,          "archival_bond_rebond_log") \
  X(LMDB_ARCHIVAL_R_MARKET,                 "archival_r_market") \
  X(LMDB_ARCHIVAL_SIGMA_WORK,               "archival_sigma_work") \
  X(LMDB_ARCHIVAL_EPOCH_CLOSE_LOG,          "archival_epoch_close_log") \
  X(LMDB_ARCHIVAL_BUDGET_ACCRUAL,           "archival_budget_accrual") \
  X(LMDB_ARCHIVAL_BUDGET,                   "archival_budget") \
  \
  X(LMDB_PENDING_TREE_LEAVES,               "pending_tree_leaves") \
  X(LMDB_PENDING_TREE_DRAIN,                "pending_tree_drain") \
  X(LMDB_BLOCK_PENDING_ADDITIONS,           "block_pending_additions") \
  X(LMDB_OUTPUT_TO_LEAF,                    "output_to_leaf") \
  X(LMDB_LEAF_TO_OUTPUT,                    "leaf_to_output") \
  \
  X(LMDB_CURVE_TREE_LEAVES,                 "curve_tree_leaves") \
  X(LMDB_CURVE_TREE_LAYERS,                 "curve_tree_layers") \
  X(LMDB_CURVE_TREE_META,                   "curve_tree_meta") \
  X(LMDB_CURVE_TREE_CHECKPOINTS,            "curve_tree_checkpoints") \
  X(LMDB_CURVE_TREE_ROOTS,                  "curve_tree_roots") \
  \
  X(LMDB_OUTPUT_METADATA,                   "output_metadata") \
  /* end of list */

#define SHEKYL_LMDB_TABLE_DECL(sym, name) const char* const sym = name;
SHEKYL_LMDB_TABLES(SHEKYL_LMDB_TABLE_DECL)
#undef SHEKYL_LMDB_TABLE_DECL

#define SHEKYL_LMDB_TABLE_COUNT(sym, name) +1
// Number of named LMDB tables — derived from the list, never counted by hand.
constexpr unsigned kLmdbTableCount = 0 SHEKYL_LMDB_TABLES(SHEKYL_LMDB_TABLE_COUNT);
#undef SHEKYL_LMDB_TABLE_COUNT

const char zerokey[8] = {0};
const MDB_val zerokval = { sizeof(zerokey), (void *)zerokey };

const std::string lmdb_error(const std::string& error_string, int mdb_res)
{
  const std::string full_string = error_string + mdb_strerror(mdb_res);
  return full_string;
}

inline void lmdb_db_open(MDB_txn* txn, const char* name, int flags, MDB_dbi& dbi, const std::string& error_string)
{
  if (auto res = mdb_dbi_open(txn, name, flags, &dbi))
    throw0(cryptonote::DB_OPEN_FAILURE((lmdb_error(error_string + " : ", res) + std::string(" - you may want to start with --db-salvage")).c_str()));
}

//! Named tables that chain-reset deliberately leaves alone (mempool lifecycle).
bool is_chain_reset_keep_table(const std::string& name)
{
  return name == LMDB_TXPOOL_META || name == LMDB_TXPOOL_BLOB;
}

//! Keys of the unnamed main DB are the environment's named-table names.
std::vector<std::string> named_table_names(MDB_txn* txn)
{
  MDB_dbi main_dbi;
  if (auto result = mdb_dbi_open(txn, NULL, 0, &main_dbi))
    throw0(cryptonote::DB_ERROR(lmdb_error("Failed to open the unnamed main db: ", result).c_str()));

  MDB_cursor *cur = nullptr;
  if (auto result = mdb_cursor_open(txn, main_dbi, &cur))
    throw0(cryptonote::DB_ERROR(lmdb_error("Failed to open a cursor over table names: ", result).c_str()));

  std::vector<std::string> names;
  MDB_val k, v;
  int result;
  while ((result = mdb_cursor_get(cur, &k, &v, MDB_NEXT)) == 0)
    names.emplace_back(static_cast<const char*>(k.mv_data), k.mv_size);
  mdb_cursor_close(cur);
  if (result != MDB_NOTFOUND)
    throw0(cryptonote::DB_ERROR(lmdb_error("Failed to enumerate table names: ", result).c_str()));
  return names;
}

}  // anonymous namespace

#define CURSOR(name) \
	if (!m_cur_ ## name) { \
	  int result = mdb_cursor_open(*m_write_txn, m_ ## name, &m_cur_ ## name); \
	  if (result) \
        throw0(DB_ERROR(lmdb_error("Failed to open cursor: ", result).c_str())); \
	}

#define RCURSOR(name) \
	if (!m_cur_ ## name) { \
	  int result = mdb_cursor_open(m_txn, m_ ## name, (MDB_cursor **)&m_cur_ ## name); \
	  if (result) \
        throw0(DB_ERROR(lmdb_error("Failed to open cursor: ", result).c_str())); \
	  if (m_cursors != &m_wcursors) \
	    m_tinfo->m_ti_rflags.m_rf_ ## name = true; \
	} else if (m_cursors != &m_wcursors && !m_tinfo->m_ti_rflags.m_rf_ ## name) { \
	  int result = mdb_cursor_renew(m_txn, m_cur_ ## name); \
      if (result) \
        throw0(DB_ERROR(lmdb_error("Failed to renew cursor: ", result).c_str())); \
	  m_tinfo->m_ti_rflags.m_rf_ ## name = true; \
	}

namespace cryptonote
{

typedef struct mdb_block_info_1
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight; // a size_t really but we need 32-bit compat
  uint64_t bi_diff;
  crypto::hash bi_hash;
} mdb_block_info_1;

typedef struct mdb_block_info_2
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight; // a size_t really but we need 32-bit compat
  uint64_t bi_diff;
  crypto::hash bi_hash;
  uint64_t bi_cum_rct;
} mdb_block_info_2;

typedef struct mdb_block_info_3
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight; // a size_t really but we need 32-bit compat
  uint64_t bi_diff;
  crypto::hash bi_hash;
  uint64_t bi_cum_rct;
  uint64_t bi_long_term_block_weight;
} mdb_block_info_3;

typedef struct mdb_block_info_4
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight; // a size_t really but we need 32-bit compat
  uint64_t bi_diff_lo;
  uint64_t bi_diff_hi;
  crypto::hash bi_hash;
  uint64_t bi_cum_rct;
  uint64_t bi_long_term_block_weight;
} mdb_block_info_4;

typedef mdb_block_info_4 mdb_block_info;

typedef struct blk_height {
    crypto::hash bh_hash;
    uint64_t bh_height;
} blk_height;

typedef struct pre_rct_outkey {
    uint64_t amount_index;
    uint64_t output_id;
    pre_rct_output_data_t data;
} pre_rct_outkey;

typedef struct outkey {
    uint64_t amount_index;
    uint64_t output_id;
    output_data_t data;
} outkey;

typedef struct outtx {
    uint64_t output_id;
    crypto::hash tx_hash;
    uint64_t local_index;
} outtx;

std::atomic<uint64_t> mdb_txn_safe::num_active_txns{0};
std::atomic_flag mdb_txn_safe::creation_gate = ATOMIC_FLAG_INIT;

mdb_threadinfo::~mdb_threadinfo()
{
  MDB_cursor **cur = &m_ti_rcursors.m_txc_blocks;
  unsigned i;
  for (i=0; i<sizeof(mdb_txn_cursors)/sizeof(MDB_cursor *); i++)
    if (cur[i])
      mdb_cursor_close(cur[i]);
  if (m_ti_rtxn)
    mdb_txn_abort(m_ti_rtxn);
}

mdb_txn_safe::mdb_txn_safe(const bool check) : m_txn(NULL), m_tinfo(NULL), m_check(check)
{
  if (check)
  {
    while (creation_gate.test_and_set());
    num_active_txns++;
    creation_gate.clear();
  }
}

mdb_txn_safe::~mdb_txn_safe()
{
  if (!m_check)
    return;
  LOG_PRINT_L3("mdb_txn_safe: destructor");
  if (m_tinfo != nullptr)
  {
    mdb_txn_reset(m_tinfo->m_ti_rtxn);
    memset(&m_tinfo->m_ti_rflags, 0, sizeof(m_tinfo->m_ti_rflags));
  } else if (m_txn != nullptr)
  {
    if (m_batch_txn) // this is a batch txn and should have been handled before this point for safety
    {
      LOG_PRINT_L0("WARNING: mdb_txn_safe: m_txn is a batch txn and it's not NULL in destructor - calling mdb_txn_abort()");
    }
    else
    {
      // Example of when this occurs: a lookup fails, so a read-only txn is
      // aborted through this destructor. However, successful read-only txns
      // ideally should have been committed when done and not end up here.
      //
      // NOTE: not sure if this is ever reached for a non-batch write
      // transaction, but it's probably not ideal if it did.
      LOG_PRINT_L3("mdb_txn_safe: m_txn not NULL in destructor - calling mdb_txn_abort()");
    }
    mdb_txn_abort(m_txn);
  }
  num_active_txns--;
}

void mdb_txn_safe::uncheck()
{
  num_active_txns--;
  m_check = false;
}

void mdb_txn_safe::commit(std::string message)
{
  if (message.size() == 0)
  {
    message = "Failed to commit a transaction to the db";
  }

  if (auto result = mdb_txn_commit(m_txn))
  {
    m_txn = nullptr;
    throw0(DB_ERROR(lmdb_error(message + ": ", result).c_str()));
  }
  m_txn = nullptr;
}

void mdb_txn_safe::abort()
{
  LOG_PRINT_L3("mdb_txn_safe: abort()");
  if(m_txn != nullptr)
  {
    mdb_txn_abort(m_txn);
    m_txn = nullptr;
  }
  else
  {
    LOG_PRINT_L0("WARNING: mdb_txn_safe: abort() called, but m_txn is NULL");
  }
}

uint64_t mdb_txn_safe::num_active_tx() const
{
  return num_active_txns;
}

void mdb_txn_safe::prevent_new_txns()
{
  while (creation_gate.test_and_set());
}

void mdb_txn_safe::wait_no_active_txns()
{
  while (num_active_txns > 0);
}

void mdb_txn_safe::allow_new_txns()
{
  creation_gate.clear();
}

void mdb_txn_safe::increment_txns(int i)
{
	num_active_txns += i;
}

#define TXN_PREFIX(flags); \
  mdb_txn_safe auto_txn; \
  mdb_txn_safe* txn_ptr = &auto_txn; \
  if (m_batch_active) \
    txn_ptr = m_write_txn; \
  else \
  { \
    if (auto mdb_res = lmdb_txn_begin(m_env, NULL, flags, auto_txn)) \
      throw0(DB_ERROR(lmdb_error(std::string("Failed to create a transaction for the db in ")+__FUNCTION__+": ", mdb_res).c_str())); \
  } \

#define TXN_PREFIX_RDONLY() \
  MDB_txn *m_txn; \
  mdb_txn_cursors *m_cursors; \
  mdb_txn_safe auto_txn; \
  bool my_rtxn = block_rtxn_start(&m_txn, &m_cursors); \
  if (my_rtxn) auto_txn.m_tinfo = m_tinfo.get(); \
  else auto_txn.uncheck()
#define TXN_POSTFIX_RDONLY()

#define TXN_POSTFIX_SUCCESS() \
  do { \
    if (! m_batch_active) \
      auto_txn.commit(); \
  } while(0)

void lmdb_resized(MDB_env *env, int isactive)
{
  mdb_txn_safe::prevent_new_txns();

  MGINFO("LMDB map resize detected.");

  MDB_envinfo mei;

  mdb_env_info(env, &mei);
  uint64_t old = mei.me_mapsize;

  if (isactive)
    mdb_txn_safe::increment_txns(-1);
  mdb_txn_safe::wait_no_active_txns();
  if (isactive)
    mdb_txn_safe::increment_txns(1);

  int result = mdb_env_set_mapsize(env, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set new mapsize: ", result).c_str()));

  mdb_env_info(env, &mei);
  uint64_t new_mapsize = mei.me_mapsize;

  MGINFO("LMDB Mapsize increased." << "  Old: " << old / (1024 * 1024) << "MiB" << ", New: " << new_mapsize / (1024 * 1024) << "MiB");

  mdb_txn_safe::allow_new_txns();
}

inline int lmdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn)
{
  int res = mdb_txn_begin(env, parent, flags, txn);
  if (res == MDB_MAP_RESIZED) {
    lmdb_resized(env, 1);
    res = mdb_txn_begin(env, parent, flags, txn);
  }
  return res;
}

inline int lmdb_txn_renew(MDB_txn *txn)
{
  int res = mdb_txn_renew(txn);
  if (res == MDB_MAP_RESIZED) {
    lmdb_resized(mdb_txn_env(txn), 0);
    res = mdb_txn_renew(txn);
  }
  return res;
}

inline void BlockchainLMDB::check_open() const
{
  if (!m_open)
    throw0(DB_ERROR("DB operation attempted on a not-open DB instance"));
}

void BlockchainLMDB::do_resize(uint64_t increase_size)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  CRITICAL_REGION_LOCAL(m_synchronization_lock);
  const uint64_t add_size = 1LL << 30;

  // check disk capacity
  try
  {
    boost::filesystem::path path(m_folder);
    boost::filesystem::space_info si = boost::filesystem::space(path);
    if(si.available < add_size)
    {
      MERROR("!! WARNING: Insufficient free space to extend database !!: " <<
          (si.available >> 20L) << " MB available, " << (add_size >> 20L) << " MB needed");
      return;
    }
  }
  catch(...)
  {
    // print something but proceed.
    MWARNING("Unable to query free disk space.");
  }

  MDB_envinfo mei;

  mdb_env_info(m_env, &mei);

  MDB_stat mst;

  mdb_env_stat(m_env, &mst);

  // add 1Gb per resize, instead of doing a percentage increase
  uint64_t new_mapsize = (uint64_t) mei.me_mapsize + add_size;

  // If given, use increase_size instead of above way of resizing.
  // This is currently used for increasing by an estimated size at start of new
  // batch txn.
  if (increase_size > 0)
    new_mapsize = mei.me_mapsize + increase_size;

  new_mapsize += (new_mapsize % mst.ms_psize);

  mdb_txn_safe::prevent_new_txns();

  if (m_write_txn != nullptr)
  {
    if (m_batch_active)
    {
      throw0(DB_ERROR("lmdb resizing not yet supported when batch transactions enabled!"));
    }
    else
    {
      throw0(DB_ERROR("attempting resize with write transaction in progress, this should not happen!"));
    }
  }

  mdb_txn_safe::wait_no_active_txns();

  int result = mdb_env_set_mapsize(m_env, new_mapsize);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set new mapsize: ", result).c_str()));

  MGINFO("LMDB Mapsize increased." << "  Old: " << mei.me_mapsize / (1024 * 1024) << "MiB" << ", New: " << new_mapsize / (1024 * 1024) << "MiB");

  mdb_txn_safe::allow_new_txns();
}

// threshold_size is used for batch transactions
bool BlockchainLMDB::need_resize(uint64_t threshold_size) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
#if defined(ENABLE_AUTO_RESIZE)
  MDB_envinfo mei;

  mdb_env_info(m_env, &mei);

  MDB_stat mst;

  mdb_env_stat(m_env, &mst);

  // size_used doesn't include data yet to be committed, which can be
  // significant size during batch transactions. For that, we estimate the size
  // needed at the beginning of the batch transaction and pass in the
  // additional size needed.
  uint64_t size_used = mst.ms_psize * mei.me_last_pgno;

  MDEBUG("DB map size:     " << mei.me_mapsize);
  MDEBUG("Space used:      " << size_used);
  MDEBUG("Space remaining: " << mei.me_mapsize - size_used);
  MDEBUG("Size threshold:  " << threshold_size);
  float resize_percent = RESIZE_PERCENT;
  MDEBUG(boost::format("Percent used: %.04f  Percent threshold: %.04f") % (100.*size_used/mei.me_mapsize) % (100.*resize_percent));

  if (threshold_size > 0)
  {
    if (mei.me_mapsize - size_used < threshold_size)
    {
      MINFO("Threshold met (size-based)");
      return true;
    }
    else
      return false;
  }

  if ((double)size_used / mei.me_mapsize  > resize_percent)
  {
    MINFO("Threshold met (percent-based)");
    return true;
  }
  return false;
#else
  return false;
#endif
}

void BlockchainLMDB::check_and_resize_for_batch(uint64_t batch_num_blocks, uint64_t batch_bytes)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  MTRACE("[" << __func__ << "] " << "checking DB size");
  const uint64_t min_increase_size = 512 * (1 << 20);
  uint64_t threshold_size = 0;
  uint64_t increase_size = 0;
  if (batch_num_blocks > 0)
  {
    threshold_size = get_estimated_batch_size(batch_num_blocks, batch_bytes);
    MDEBUG("calculated batch size: " << threshold_size);

    // The increased DB size could be a multiple of threshold_size, a fixed
    // size increase (> threshold_size), or other variations.
    //
    // Currently we use the greater of threshold size and a minimum size. The
    // minimum size increase is used to avoid frequent resizes when the batch
    // size is set to a very small numbers of blocks.
    increase_size = (threshold_size > min_increase_size) ? threshold_size : min_increase_size;
    MDEBUG("increase size: " << increase_size);
  }

  // if threshold_size is 0 (i.e. number of blocks for batch not passed in), it
  // will fall back to the percent-based threshold check instead of the
  // size-based check
  if (need_resize(threshold_size))
  {
    MGINFO("[batch] DB resize needed");
    do_resize(increase_size);
  }
}

uint64_t BlockchainLMDB::get_estimated_batch_size(uint64_t batch_num_blocks, uint64_t batch_bytes) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  uint64_t threshold_size = 0;

  // batch size estimate * batch safety factor = final size estimate
  // Takes into account "reasonable" block size increases in batch.
  float batch_safety_factor = 1.7f;
  float batch_fudge_factor = batch_safety_factor * batch_num_blocks;
  // estimate of stored block expanded from raw block, including denormalization and db overhead.
  // Note that this probably doesn't grow linearly with block size.
  float db_expand_factor = 4.5f;
  uint64_t num_prev_blocks = 500;
  // For resizing purposes, allow for at least 4k average block size.
  uint64_t min_block_size = 4 * 1024;

  uint64_t block_stop = 0;
  uint64_t m_height = height();
  if (m_height > 1)
    block_stop = m_height - 1;
  uint64_t block_start = 0;
  if (block_stop >= num_prev_blocks)
    block_start = block_stop - num_prev_blocks + 1;
  uint32_t num_blocks_used = 0;
  uint64_t total_block_size = 0;
  MDEBUG("[" << __func__ << "] " << "m_height: " << m_height << "  block_start: " << block_start << "  block_stop: " << block_stop);
  size_t avg_block_size = 0;
  if (batch_bytes)
  {
    avg_block_size = batch_bytes / batch_num_blocks;
    goto estim;
  }
  if (m_height == 0)
  {
    MDEBUG("No existing blocks to check for average block size");
  }
  else if (m_cum_count >= num_prev_blocks)
  {
    avg_block_size = m_cum_size / m_cum_count;
    MDEBUG("average block size across recent " << m_cum_count << " blocks: " << avg_block_size);
    m_cum_size = 0;
    m_cum_count = 0;
  }
  else
  {
    {
      TXN_PREFIX_RDONLY();
      for (uint64_t block_num = block_start; block_num <= block_stop; ++block_num)
      {
        // we have access to block weight, which will be greater or equal to block size,
        // so use this as a proxy. If it's too much off, we might have to check actual size,
        // which involves reading more data, so is not really wanted
        size_t block_weight = get_block_weight(block_num);
        total_block_size += block_weight;
        // Track number of blocks being totalled here instead of assuming, in case
        // some blocks were to be skipped for being outliers.
        ++num_blocks_used;
      }
    }
    avg_block_size = total_block_size / (num_blocks_used ? num_blocks_used : 1);
    MDEBUG("average block size across recent " << num_blocks_used << " blocks: " << avg_block_size);
  }
estim:
  if (avg_block_size < min_block_size)
    avg_block_size = min_block_size;
  MDEBUG("estimated average block size for batch: " << avg_block_size);

  // bigger safety margin on smaller block sizes
  if (batch_fudge_factor < 5000.0)
    batch_fudge_factor = 5000.0;
  threshold_size = avg_block_size * db_expand_factor * batch_fudge_factor;
  return threshold_size;
}

void BlockchainLMDB::add_block(const block& blk, size_t block_weight, uint64_t long_term_block_weight, const difficulty_type& cumulative_difficulty, const uint64_t& coins_generated,
    uint64_t num_rct_outs, const crypto::hash& blk_hash)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  uint64_t m_height = height();

  CURSOR(block_heights)
  blk_height bh = {blk_hash, m_height};
  MDB_val_set(val_h, bh);
  if (mdb_cursor_get(m_cur_block_heights, (MDB_val *)&zerokval, &val_h, MDB_GET_BOTH) == 0)
    throw1(BLOCK_EXISTS("Attempting to add block that's already in the db"));

  if (m_height > 0)
  {
    MDB_val_set(parent_key, blk.prev_id);
    int result = mdb_cursor_get(m_cur_block_heights, (MDB_val *)&zerokval, &parent_key, MDB_GET_BOTH);
    if (result)
    {
      LOG_PRINT_L3("m_height: " << m_height);
      LOG_PRINT_L3("parent_key: " << blk.prev_id);
      throw0(DB_ERROR(lmdb_error("Failed to get top block hash to check for new block's parent: ", result).c_str()));
    }
    blk_height *prev = (blk_height *)parent_key.mv_data;
    if (prev->bh_height != m_height - 1)
      throw0(BLOCK_PARENT_DNE("Top block is not new block's parent"));
  }

  int result = 0;

  MDB_val_set(key, m_height);

  CURSOR(blocks)
  CURSOR(block_info)

  // this call to mdb_cursor_put will change height()
  cryptonote::blobdata block_blob(block_to_blob(blk));
  MDB_val_sized(blob, block_blob);
  result = mdb_cursor_put(m_cur_blocks, &key, &blob, MDB_APPEND);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add block blob to db transaction: ", result).c_str()));

  mdb_block_info bi;
  bi.bi_height = m_height;
  bi.bi_timestamp = blk.timestamp;
  bi.bi_coins = coins_generated;
  bi.bi_weight = block_weight;
  bi.bi_diff_hi = ((cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  bi.bi_diff_lo = (cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
  bi.bi_hash = blk_hash;
  bi.bi_cum_rct = num_rct_outs;
  if (blk.major_version >= 4)
  {
    uint64_t last_height = m_height-1;
    MDB_val_set(h, last_height);
    if ((result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &h, MDB_GET_BOTH)))
        throw1(BLOCK_DNE(lmdb_error("Failed to get block info: ", result).c_str()));
    const mdb_block_info *bi_prev = (const mdb_block_info*)h.mv_data;
    bi.bi_cum_rct += bi_prev->bi_cum_rct;
  }
  bi.bi_long_term_block_weight = long_term_block_weight;

  MDB_val_set(val, bi);
  result = mdb_cursor_put(m_cur_block_info, (MDB_val *)&zerokval, &val, MDB_APPENDDUP);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add block info to db transaction: ", result).c_str()));

  result = mdb_cursor_put(m_cur_block_heights, (MDB_val *)&zerokval, &val_h, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add block height by hash to db transaction: ", result).c_str()));

  // we use weight as a proxy for size, since we don't have size but weight is >= size
  // and often actually equal
  m_cum_size += block_weight;
  m_cum_count++;
}

void BlockchainLMDB::remove_block()
{
  int result;

  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  uint64_t m_height = height();

  if (m_height == 0)
    throw0(BLOCK_DNE ("Attempting to remove block from an empty blockchain"));

  mdb_txn_cursors *m_cursors = &m_wcursors;
  CURSOR(block_info)
  CURSOR(block_heights)
  CURSOR(blocks)
  MDB_val_copy<uint64_t> k(m_height - 1);
  MDB_val h = k;
  if ((result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &h, MDB_GET_BOTH)))
      throw1(BLOCK_DNE(lmdb_error("Attempting to remove block that's not in the db: ", result).c_str()));

  // must use h now; deleting from m_block_info will invalidate it
  mdb_block_info *bi = (mdb_block_info *)h.mv_data;
  blk_height bh = {bi->bi_hash, 0};
  h.mv_data = (void *)&bh;
  h.mv_size = sizeof(bh);
  if ((result = mdb_cursor_get(m_cur_block_heights, (MDB_val *)&zerokval, &h, MDB_GET_BOTH)))
      throw1(DB_ERROR(lmdb_error("Failed to locate block height by hash for removal: ", result).c_str()));
  if ((result = mdb_cursor_del(m_cur_block_heights, 0)))
      throw1(DB_ERROR(lmdb_error("Failed to add removal of block height by hash to db transaction: ", result).c_str()));

  if ((result = mdb_cursor_del(m_cur_blocks, 0)))
      throw1(DB_ERROR(lmdb_error("Failed to add removal of block to db transaction: ", result).c_str()));

  if ((result = mdb_cursor_del(m_cur_block_info, 0)))
      throw1(DB_ERROR(lmdb_error("Failed to add removal of block info to db transaction: ", result).c_str()));
}

uint64_t BlockchainLMDB::add_transaction_data(const crypto::hash& blk_hash, const std::pair<transaction, blobdata_ref>& txp, const crypto::hash& tx_hash, const crypto::hash& tx_prunable_hash)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  uint64_t m_height = height();

  int result;
  uint64_t tx_id = get_tx_count();

  CURSOR(txs_pruned)
  CURSOR(txs_pqc_auths)
  CURSOR(txs_prunable)
  CURSOR(txs_prunable_hash)
  CURSOR(txs_prunable_tip)
  CURSOR(tx_indices)

  MDB_val_set(val_tx_id, tx_id);
  MDB_val_set(val_h, tx_hash);
  result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &val_h, MDB_GET_BOTH);
  if (result == 0) {
    txindex *tip = (txindex *)val_h.mv_data;
    throw1(TX_EXISTS(std::string("Attempting to add transaction that's already in the db (tx id ").append(boost::lexical_cast<std::string>(tip->data.tx_id)).append(")").c_str()));
  } else if (result != MDB_NOTFOUND) {
    throw1(DB_ERROR(lmdb_error(std::string("Error checking if tx index exists for tx hash ") + epee::string_tools::pod_to_hex(tx_hash) + ": ", result).c_str()));
  }

  const cryptonote::transaction &tx = txp.first;
  txindex ti;
  ti.key = tx_hash;
  ti.data.tx_id = tx_id;
  ti.data.unlock_time = tx.unlock_time;
  ti.data.block_id = m_height;  // we don't need blk_hash since we know m_height

  val_h.mv_size = sizeof(ti);
  val_h.mv_data = (void *)&ti;

  result = mdb_cursor_put(m_cur_tx_indices, (MDB_val *)&zerokval, &val_h, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add tx data to db transaction: ", result).c_str()));

  const cryptonote::blobdata_ref &blob = txp.second;

  unsigned int unprunable_size = tx.unprunable_size;
  unsigned int pqc_off = tx.pqc_auths_offset.load();
  if (unprunable_size == 0)
  {
    std::stringstream ss;
    binary_archive<true> ba(ss);
    bool r = const_cast<cryptonote::transaction&>(tx).serialize_base(ba);
    if (!r)
      throw0(DB_ERROR("Failed to serialize pruned tx"));
    unprunable_size = static_cast<unsigned int>(ss.str().size());
    pqc_off = tx.pqc_auths_offset.load();
  }

  const bool split_pqc = tx.version >= 3 && !tx.vin.empty()
      && !std::holds_alternative<cryptonote::txin_gen>(tx.vin[0]);
  if (split_pqc && pqc_off == 0 && unprunable_size != 0)
  {
    std::stringstream ss;
    binary_archive<true> ba(ss);
    if (const_cast<cryptonote::transaction&>(tx).serialize_base(ba))
      pqc_off = tx.pqc_auths_offset.load();
  }

  if (unprunable_size > blob.size())
    throw0(DB_ERROR("pruned tx size is larger than tx size"));

  size_t pruned1_sz = unprunable_size;
  size_t pruned2_sz = 0;
  const char *const blob_data = blob.data();
  if (split_pqc && pqc_off < unprunable_size)
  {
    pruned1_sz = pqc_off;
    pruned2_sz = static_cast<size_t>(unprunable_size) - pqc_off;
  }

  MDB_val pruned_blob = {pruned1_sz, (void*)blob_data};
  result = mdb_cursor_put(m_cur_txs_pruned, &val_tx_id, &pruned_blob, MDB_APPEND);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add pruned tx blob to db transaction: ", result).c_str()));

  if (pruned2_sz > 0)
  {
    MDB_val pqc_blob = {pruned2_sz, (void*)(blob_data + pqc_off)};
    result = mdb_cursor_put(m_cur_txs_pqc_auths, &val_tx_id, &pqc_blob, MDB_APPEND);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to add pqc_auths tx blob to db transaction: ", result).c_str()));
  }

  MDB_val prunable_blob = {blob.size() - unprunable_size, (void*)(blob.data() + unprunable_size)};
  result = mdb_cursor_put(m_cur_txs_prunable, &val_tx_id, &prunable_blob, MDB_APPEND);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add prunable tx blob to db transaction: ", result).c_str()));

  if (get_blockchain_pruning_seed())
  {
    MDB_val_set(val_height, m_height);
    result = mdb_cursor_put(m_cur_txs_prunable_tip, &val_tx_id, &val_height, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to add prunable tx id to db transaction: ", result).c_str()));
  }

  if (tx.version > 1)
  {
    MDB_val_set(val_prunable_hash, tx_prunable_hash);
    result = mdb_cursor_put(m_cur_txs_prunable_hash, &val_tx_id, &val_prunable_hash, MDB_APPEND);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to add prunable tx prunable hash to db transaction: ", result).c_str()));
  }

  return tx_id;
}

// TODO: compare pros and cons of looking up the tx hash's tx index once and
// passing it in to functions like this
void BlockchainLMDB::remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx)
{
  int result;

  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  mdb_txn_cursors *m_cursors = &m_wcursors;
  CURSOR(tx_indices)
  CURSOR(txs_pruned)
  CURSOR(txs_pqc_auths)
  CURSOR(txs_prunable)
  CURSOR(txs_prunable_hash)
  CURSOR(txs_prunable_tip)
  CURSOR(tx_outputs)

  MDB_val_set(val_h, tx_hash);

  if (mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &val_h, MDB_GET_BOTH))
      throw1(TX_DNE("Attempting to remove transaction that isn't in the db"));
  txindex *tip = (txindex *)val_h.mv_data;
  MDB_val_set(val_tx_id, tip->data.tx_id);

  if ((result = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, NULL, MDB_SET)))
      throw1(DB_ERROR(lmdb_error("Failed to locate pruned tx for removal: ", result).c_str()));
  result = mdb_cursor_del(m_cur_txs_pruned, 0);
  if (result)
      throw1(DB_ERROR(lmdb_error("Failed to add removal of pruned tx to db transaction: ", result).c_str()));

  result = mdb_cursor_get(m_cur_txs_pqc_auths, &val_tx_id, NULL, MDB_SET);
  if (result == 0)
  {
      result = mdb_cursor_del(m_cur_txs_pqc_auths, 0);
      if (result)
          throw1(DB_ERROR(lmdb_error("Failed to add removal of pqc_auths tx to db transaction: ", result).c_str()));
  }
  else if (result != MDB_NOTFOUND)
      throw1(DB_ERROR(lmdb_error("Failed to locate pqc_auths tx for removal: ", result).c_str()));

  result = mdb_cursor_get(m_cur_txs_prunable, &val_tx_id, NULL, MDB_SET);
  if (result == 0)
  {
      result = mdb_cursor_del(m_cur_txs_prunable, 0);
      if (result)
          throw1(DB_ERROR(lmdb_error("Failed to add removal of prunable tx to db transaction: ", result).c_str()));
  }
  else if (result != MDB_NOTFOUND)
      throw1(DB_ERROR(lmdb_error("Failed to locate prunable tx for removal: ", result).c_str()));

  result = mdb_cursor_get(m_cur_txs_prunable_tip, &val_tx_id, NULL, MDB_SET);
  if (result && result != MDB_NOTFOUND)
      throw1(DB_ERROR(lmdb_error("Failed to locate tx id for removal: ", result).c_str()));
  if (result == 0)
  {
    result = mdb_cursor_del(m_cur_txs_prunable_tip, 0);
    if (result)
        throw1(DB_ERROR(lmdb_error("Error adding removal of tx id to db transaction", result).c_str()));
  }

  if (tx.version > 1)
  {
    if ((result = mdb_cursor_get(m_cur_txs_prunable_hash, &val_tx_id, NULL, MDB_SET)))
        throw1(DB_ERROR(lmdb_error("Failed to locate prunable hash tx for removal: ", result).c_str()));
    result = mdb_cursor_del(m_cur_txs_prunable_hash, 0);
    if (result)
        throw1(DB_ERROR(lmdb_error("Failed to add removal of prunable hash tx to db transaction: ", result).c_str()));
  }

  remove_tx_outputs(tip->data.tx_id, tx);

  result = mdb_cursor_get(m_cur_tx_outputs, &val_tx_id, NULL, MDB_SET);
  if (result == MDB_NOTFOUND)
    LOG_PRINT_L1("tx has no outputs to remove: " << tx_hash);
  else if (result)
    throw1(DB_ERROR(lmdb_error("Failed to locate tx outputs for removal: ", result).c_str()));
  if (!result)
  {
    result = mdb_cursor_del(m_cur_tx_outputs, 0);
    if (result)
      throw1(DB_ERROR(lmdb_error("Failed to add removal of tx outputs to db transaction: ", result).c_str()));
  }

  // Don't delete the tx_indices entry until the end, after we're done with val_tx_id
  if (mdb_cursor_del(m_cur_tx_indices, 0))
      throw1(DB_ERROR("Failed to add removal of tx index to db transaction"));
}

uint64_t BlockchainLMDB::add_output(const crypto::hash& tx_hash,
    const tx_out& tx_output,
    const uint64_t& local_index,
    const uint64_t unlock_time,
    const ct::key *commitment)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  uint64_t m_height = height();
  uint64_t m_num_outputs = num_outputs();

  int result = 0;

  CURSOR(output_txs)
  CURSOR(output_amounts)

  crypto::public_key output_public_key;
  if (!get_output_public_key(tx_output, output_public_key))
    throw0(DB_ERROR("Could not get an output public key from a tx output."));
  if (tx_output.amount == 0 && !commitment)
    throw0(DB_ERROR("RCT output without commitment"));

  outtx ot = {m_num_outputs, tx_hash, local_index};
  MDB_val_set(vot, ot);

  result = mdb_cursor_put(m_cur_output_txs, (MDB_val *)&zerokval, &vot, MDB_APPENDDUP);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add output tx hash to db transaction: ", result).c_str()));

  outkey ok;
  MDB_val data;
  MDB_val_copy<uint64_t> val_amount(tx_output.amount);
  result = mdb_cursor_get(m_cur_output_amounts, &val_amount, &data, MDB_SET);
  if (!result)
    {
      mdb_size_t num_elems = 0;
      result = mdb_cursor_count(m_cur_output_amounts, &num_elems);
      if (result)
        throw0(DB_ERROR(std::string("Failed to get number of outputs for amount: ").append(mdb_strerror(result)).c_str()));
      ok.amount_index = num_elems;
    }
  else if (result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to get output amount in db transaction: ", result).c_str()));
  else
    ok.amount_index = 0;
  ok.output_id = m_num_outputs;
  ok.data.pubkey = output_public_key;
  ok.data.unlock_time = unlock_time;
  ok.data.height = m_height;
  if (tx_output.amount == 0)
  {
    ok.data.commitment = *commitment;
    data.mv_size = sizeof(ok);
  }
  else
  {
    data.mv_size = sizeof(pre_rct_outkey);
  }
  data.mv_data = &ok;

  if ((result = mdb_cursor_put(m_cur_output_amounts, &val_amount, &data, MDB_APPENDDUP)))
      throw0(DB_ERROR(lmdb_error("Failed to add output pubkey to db transaction: ", result).c_str()));

  return ok.amount_index;
}

void BlockchainLMDB::add_tx_amount_output_indices(const uint64_t tx_id,
    const std::vector<uint64_t>& amount_output_indices)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  CURSOR(tx_outputs)

  int result = 0;

  size_t num_outputs = amount_output_indices.size();

  MDB_val_set(k_tx_id, tx_id);
  MDB_val v;
  v.mv_data = num_outputs ? (void *)amount_output_indices.data() : (void*)"";
  v.mv_size = sizeof(uint64_t) * num_outputs;
  // LOG_PRINT_L1("tx_outputs[tx_hash] size: " << v.mv_size);

  result = mdb_cursor_put(m_cur_tx_outputs, &k_tx_id, &v, MDB_APPEND);
  if (result)
    throw0(DB_ERROR(std::string("Failed to add <tx hash, amount output index array> to db transaction: ").append(mdb_strerror(result)).c_str()));
}

void BlockchainLMDB::remove_tx_outputs(const uint64_t tx_id, const transaction& tx)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  std::vector<std::vector<uint64_t>> amount_output_indices_set = get_tx_amount_output_indices(tx_id, 1);
  const std::vector<uint64_t> &amount_output_indices = amount_output_indices_set.front();

  if (amount_output_indices.empty())
  {
    if (tx.vout.empty())
      LOG_PRINT_L2("tx has no outputs, so no output indices");
    else
      throw0(DB_ERROR("tx has outputs, but no output indices found"));
  }

  // Coinbase and archival-emission vouts store as amount-0 RCT records with
  // their outPk commitment regardless of the plaintext amount in the tx (see
  // BlockchainDB::add_transaction), so their removal keys on amount 0 too.
  bool is_pseudo_rct = tx.version >= 2 && tx.vin.size() == 1 && std::holds_alternative<txin_gen>(tx.vin[0]);
  const bool is_emission_tx = tx_has_archival_emission_vin(tx.vin);
  for (size_t i = tx.vout.size(); i-- > 0;)
  {
    uint64_t amount = (is_pseudo_rct || is_emission_tx) ? 0 : tx.vout[i].amount;
    remove_output(amount, amount_output_indices[i]);
  }
}

void BlockchainLMDB::remove_output(const uint64_t amount, const uint64_t& out_index)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  CURSOR(output_amounts);
  CURSOR(output_txs);

  MDB_val_set(k, amount);
  MDB_val_set(v, out_index);

  auto result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_GET_BOTH);
  if (result == MDB_NOTFOUND)
    throw1(OUTPUT_DNE("Attempting to get an output index by amount and amount index, but amount not found"));
  else if (result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to get an output", result).c_str()));

  const pre_rct_outkey *ok = (const pre_rct_outkey *)v.mv_data;
  MDB_val_set(otxk, ok->output_id);
  result = mdb_cursor_get(m_cur_output_txs, (MDB_val *)&zerokval, &otxk, MDB_GET_BOTH);
  if (result == MDB_NOTFOUND)
  {
    throw0(DB_ERROR("Unexpected: global output index not found in m_output_txs"));
  }
  else if (result)
  {
    throw1(DB_ERROR(lmdb_error("Error adding removal of output tx to db transaction", result).c_str()));
  }
  result = mdb_cursor_del(m_cur_output_txs, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error(std::string("Error deleting output index ").append(boost::lexical_cast<std::string>(out_index).append(": ")).c_str(), result).c_str()));

  // now delete the amount
  result = mdb_cursor_del(m_cur_output_amounts, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error(std::string("Error deleting amount for output index ").append(boost::lexical_cast<std::string>(out_index).append(": ")).c_str(), result).c_str()));
}

void BlockchainLMDB::prune_outputs(uint64_t amount)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;
  CURSOR(output_amounts);
  CURSOR(output_txs);

  MINFO("Pruning outputs for amount " << amount);

  MDB_val v;
  MDB_val_set(k, amount);
  int result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_SET);
  if (result == MDB_NOTFOUND)
    return;
  if (result)
    throw0(DB_ERROR(lmdb_error("Error looking up outputs: ", result).c_str()));

  // gather output ids
  mdb_size_t num_elems;
  mdb_cursor_count(m_cur_output_amounts, &num_elems);
  MINFO(num_elems << " outputs found");
  std::vector<uint64_t> output_ids;
  output_ids.reserve(num_elems);
  while (1)
  {
    const pre_rct_outkey *okp = (const pre_rct_outkey *)v.mv_data;
    output_ids.push_back(okp->output_id);
    MDEBUG("output id " << okp->output_id);
    result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_NEXT_DUP);
    if (result == MDB_NOTFOUND)
      break;
    if (result)
      throw0(DB_ERROR(lmdb_error("Error counting outputs: ", result).c_str()));
  }
  if (output_ids.size() != num_elems)
    throw0(DB_ERROR("Unexpected number of outputs"));

  result = mdb_cursor_del(m_cur_output_amounts, MDB_NODUPDATA);
  if (result)
    throw0(DB_ERROR(lmdb_error("Error deleting outputs: ", result).c_str()));

  for (uint64_t output_id: output_ids)
  {
    MDB_val_set(v, output_id);
    result = mdb_cursor_get(m_cur_output_txs, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
    if (result)
      throw0(DB_ERROR(lmdb_error("Error looking up output: ", result).c_str()));
    result = mdb_cursor_del(m_cur_output_txs, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Error deleting output: ", result).c_str()));
  }
}

void BlockchainLMDB::add_spent_key(const crypto::key_image& k_image)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(spent_keys)

  MDB_val k = {sizeof(k_image), (void *)&k_image};
  if (auto result = mdb_cursor_put(m_cur_spent_keys, (MDB_val *)&zerokval, &k, MDB_NODUPDATA)) {
    if (result == MDB_KEYEXIST)
      throw1(KEY_IMAGE_EXISTS("Attempting to add spent key image that's already in the db"));
    else
      throw1(DB_ERROR(lmdb_error("Error adding spent key image to db transaction: ", result).c_str()));
  }
}

void BlockchainLMDB::remove_spent_key(const crypto::key_image& k_image)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(spent_keys)

  MDB_val k = {sizeof(k_image), (void *)&k_image};
  auto result = mdb_cursor_get(m_cur_spent_keys, (MDB_val *)&zerokval, &k, MDB_GET_BOTH);
  if (result != 0 && result != MDB_NOTFOUND)
      throw1(DB_ERROR(lmdb_error("Error finding spent key to remove", result).c_str()));
  if (!result)
  {
    result = mdb_cursor_del(m_cur_spent_keys, 0);
    if (result)
        throw1(DB_ERROR(lmdb_error("Error adding removal of key image to db transaction", result).c_str()));
  }
}

BlockchainLMDB::~BlockchainLMDB()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  // batch transaction shouldn't be active at this point. If it is, consider it aborted.
  if (m_batch_active)
  {
    try { BlockchainLMDB::batch_abort(); }
    catch (...) { /* ignore */ }
  }
  if (m_open)
    BlockchainLMDB::close();
}

BlockchainLMDB::BlockchainLMDB(bool batch_transactions): BlockchainDB()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // initialize folder to something "safe" just in case
  // someone accidentally misuses this class...
  m_folder = "thishsouldnotexistbecauseitisgibberish";

  m_batch_transactions = batch_transactions;
  m_write_txn = nullptr;
  m_write_batch_txn = nullptr;
  m_batch_active = false;
  m_cum_size = 0;
  m_cum_count = 0;

  // reset may also need changing when initialize things here

  m_hardfork = nullptr;
}

#ifdef WIN32
static bool disable_ntfs_compression(const boost::filesystem::path& filepath)
{
  DWORD file_attributes = ::GetFileAttributesW(filepath.c_str());
  if (file_attributes == INVALID_FILE_ATTRIBUTES)
  {
    MERROR("Failed to get " << filepath.string() << " file attributes. Error: " << ::GetLastError());
    return false;
  }
  
  if (!(file_attributes & FILE_ATTRIBUTE_COMPRESSED))
    return true; // not compressed

  LOG_PRINT_L1("Disabling NTFS compression for " << filepath.string());
  HANDLE file_handle = ::CreateFileW(
    filepath.c_str(),
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    nullptr,
    OPEN_EXISTING,
    boost::filesystem::is_directory(filepath) ? FILE_FLAG_BACKUP_SEMANTICS : 0, // Needed to open handles to directories
    nullptr
  );

  if (file_handle == INVALID_HANDLE_VALUE)
  {
    MERROR("Failed to open handle: " << filepath.string() << ". Error: " << ::GetLastError());
    return false;
  }

  USHORT compression_state = COMPRESSION_FORMAT_NONE;
  DWORD bytes_returned;
  BOOL ok = ::DeviceIoControl(
    file_handle,
    FSCTL_SET_COMPRESSION,
    &compression_state,
    sizeof(compression_state),
    nullptr,
    0,
    &bytes_returned,
    nullptr
  );

  ::CloseHandle(file_handle);
  return ok;
}
#endif

void BlockchainLMDB::open(const std::string& filename, const int db_flags)
{
  int result;
  int mdb_flags = MDB_NORDAHEAD;

  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  if (m_open)
    throw0(DB_OPEN_FAILURE("Attempted to open db, but it's already open"));

  boost::filesystem::path direc(filename);
  if (!boost::filesystem::exists(direc) &&
      !boost::filesystem::create_directories(direc)) {
      throw0(DB_OPEN_FAILURE(std::string("Failed to create directory ").append(filename).c_str()));
  }

  // check for existing LMDB files in base directory
  boost::filesystem::path old_files = direc.parent_path();
  if (boost::filesystem::exists(old_files / CRYPTONOTE_BLOCKCHAINDATA_FILENAME)
      || boost::filesystem::exists(old_files / CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME))
  {
    LOG_PRINT_L0("Found existing LMDB files in " << old_files.string());
    LOG_PRINT_L0("Move " << CRYPTONOTE_BLOCKCHAINDATA_FILENAME << " and/or " << CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME << " to " << filename << ", or delete them, and then restart");
    throw DB_ERROR("Database could not be opened");
  }

#ifdef WIN32
  // ensure NTFS compression is disabled on the directory and database file to avoid corruption of the blockchain 
  if (!disable_ntfs_compression(filename))
    LOG_PRINT_L0("Failed to disable NTFS compression on folder: " << filename << ". Error: " << ::GetLastError());
  boost::filesystem::path datafile(filename);
  datafile /= CRYPTONOTE_BLOCKCHAINDATA_FILENAME;
  if (!boost::filesystem::exists(datafile))
    boost::filesystem::ofstream(datafile).close(); // create the file to see if NTFS compression is enabled beforehand
  if (!disable_ntfs_compression(datafile))
    throw DB_ERROR("Database file is NTFS compressed and compression could not be disabled");
#endif

  std::optional<bool> is_hdd_result = tools::is_hdd(filename.c_str());
  if (is_hdd_result)
  {
    if (is_hdd_result.value())
        MCLOG_RED(el::Level::Warning, "global", "The blockchain is on a rotating drive: this will be very slow, use an SSD if possible");
  }

  m_folder = filename;

#ifdef __OpenBSD__
  if ((mdb_flags & MDB_WRITEMAP) == 0) {
    MCLOG_RED(el::Level::Info, "global", "Running on OpenBSD: forcing WRITEMAP");
    mdb_flags |= MDB_WRITEMAP;
  }
#endif
  // set up lmdb environment
  if ((result = mdb_env_create(&m_env)))
    throw0(DB_ERROR(lmdb_error("Failed to create lmdb environment: ", result).c_str()));
  // Derived from SHEKYL_LMDB_TABLES, never counted by hand: the list that names
  // the tables is the list that sizes the ceiling, so the two cannot drift. See
  // that list for why a hand-maintained number was the wrong shape here — the
  // overflow is a runtime-only failure.
  //
  // The prose this replaced enumerated which tables the number covered
  // ("gate-2/gate-4 archival subdbs ... 48 includes the credit-wire
  // attestation-witness side table plus its alt counterpart"). Every such
  // sentence is a second copy of the list, and it was already one table behind
  // when the settlement table arrived. Deleted rather than extended: the list
  // is three hundred lines up and is now the only place that answers "which
  // tables".
  if ((result = mdb_env_set_maxdbs(m_env, kLmdbTableCount)))
    throw0(DB_ERROR(lmdb_error("Failed to set max number of dbs: ", result).c_str()));

  int threads = tools::get_max_concurrency();
  if (threads > 110 &&	/* maxreaders default is 126, leave some slots for other read processes */
    (result = mdb_env_set_maxreaders(m_env, threads+16)))
    throw0(DB_ERROR(lmdb_error("Failed to set max number of readers: ", result).c_str()));

  size_t mapsize = DEFAULT_MAPSIZE;

  if (db_flags & DBF_FAST)
    mdb_flags |= MDB_NOSYNC;
  if (db_flags & DBF_FASTEST)
    mdb_flags |= MDB_NOSYNC | MDB_WRITEMAP | MDB_MAPASYNC;
  if (db_flags & DBF_RDONLY)
    mdb_flags = MDB_RDONLY;
  if (db_flags & DBF_SALVAGE)
    mdb_flags |= MDB_PREVSNAPSHOT;

  if (auto result = mdb_env_open(m_env, filename.c_str(), mdb_flags, 0644))
    throw0(DB_ERROR(lmdb_error("Failed to open lmdb environment: ", result).c_str()));

  MDB_envinfo mei;
  mdb_env_info(m_env, &mei);
  uint64_t cur_mapsize = (uint64_t)mei.me_mapsize;

  if (cur_mapsize < mapsize)
  {
    if (auto result = mdb_env_set_mapsize(m_env, mapsize))
      throw0(DB_ERROR(lmdb_error("Failed to set max memory map size: ", result).c_str()));
    mdb_env_info(m_env, &mei);
    cur_mapsize = (uint64_t)mei.me_mapsize;
    LOG_PRINT_L1("LMDB memory map size: " << cur_mapsize);
  }

  if (need_resize())
  {
    LOG_PRINT_L0("LMDB memory map needs to be resized, doing that now.");
    do_resize();
  }

  int txn_flags = 0;
  if (mdb_flags & MDB_RDONLY)
    txn_flags |= MDB_RDONLY;

  // get a read/write MDB_txn, depending on mdb_flags
  mdb_txn_safe txn;
  if (auto mdb_res = mdb_txn_begin(m_env, NULL, txn_flags, txn))
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", mdb_res).c_str()));

  // open necessary databases, and set properties as needed
  // uses macros to avoid having to change things too many places
  // also change blockchain_prune.cpp to match
  lmdb_db_open(txn, LMDB_BLOCKS, MDB_INTEGERKEY | MDB_CREATE, m_blocks, "Failed to open db handle for m_blocks");

  lmdb_db_open(txn, LMDB_BLOCK_INFO, MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED, m_block_info, "Failed to open db handle for m_block_info");
  lmdb_db_open(txn, LMDB_BLOCK_HEIGHTS, MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED, m_block_heights, "Failed to open db handle for m_block_heights");

  lmdb_db_open(txn, LMDB_TXS, MDB_INTEGERKEY | MDB_CREATE, m_txs, "Failed to open db handle for m_txs");
  lmdb_db_open(txn, LMDB_TXS_PRUNED, MDB_INTEGERKEY | MDB_CREATE, m_txs_pruned, "Failed to open db handle for m_txs_pruned");
  lmdb_db_open(txn, LMDB_TXS_PQC_AUTHS, MDB_INTEGERKEY | MDB_CREATE, m_txs_pqc_auths, "Failed to open db handle for m_txs_pqc_auths");
  lmdb_db_open(txn, LMDB_TXS_PRUNABLE, MDB_INTEGERKEY | MDB_CREATE, m_txs_prunable, "Failed to open db handle for m_txs_prunable");
  lmdb_db_open(txn, LMDB_TXS_PRUNABLE_HASH, MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, m_txs_prunable_hash, "Failed to open db handle for m_txs_prunable_hash");
  if (!(mdb_flags & MDB_RDONLY))
    lmdb_db_open(txn, LMDB_TXS_PRUNABLE_TIP, MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, m_txs_prunable_tip, "Failed to open db handle for m_txs_prunable_tip");
  lmdb_db_open(txn, LMDB_TX_INDICES, MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED, m_tx_indices, "Failed to open db handle for m_tx_indices");
  lmdb_db_open(txn, LMDB_TX_OUTPUTS, MDB_INTEGERKEY | MDB_CREATE, m_tx_outputs, "Failed to open db handle for m_tx_outputs");

  lmdb_db_open(txn, LMDB_OUTPUT_TXS, MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED, m_output_txs, "Failed to open db handle for m_output_txs");
  lmdb_db_open(txn, LMDB_OUTPUT_AMOUNTS, MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, m_output_amounts, "Failed to open db handle for m_output_amounts");

  lmdb_db_open(txn, LMDB_SPENT_KEYS, MDB_INTEGERKEY | MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED, m_spent_keys, "Failed to open db handle for m_spent_keys");

  lmdb_db_open(txn, LMDB_TXPOOL_META, MDB_CREATE, m_txpool_meta, "Failed to open db handle for m_txpool_meta");
  lmdb_db_open(txn, LMDB_TXPOOL_BLOB, MDB_CREATE, m_txpool_blob, "Failed to open db handle for m_txpool_blob");

  lmdb_db_open(txn, LMDB_ALT_BLOCKS, MDB_CREATE, m_alt_blocks, "Failed to open db handle for m_alt_blocks");

  // this subdb is dropped on sight, so it may not be present when we open the DB.
  // Since we use MDB_CREATE, we'll get an exception if we open read-only and it does not exist.
  // So we don't open for read-only, and also not drop below. It is not used elsewhere.
  if (!(mdb_flags & MDB_RDONLY))
    lmdb_db_open(txn, LMDB_HF_STARTING_HEIGHTS, MDB_CREATE, m_hf_starting_heights, "Failed to open db handle for m_hf_starting_heights");

  lmdb_db_open(txn, LMDB_HF_VERSIONS, MDB_INTEGERKEY | MDB_CREATE, m_hf_versions, "Failed to open db handle for m_hf_versions");

  lmdb_db_open(txn, LMDB_PROPERTIES, MDB_CREATE, m_properties, "Failed to open db handle for m_properties");

  lmdb_db_open(txn, LMDB_BLOCK_BURN, MDB_INTEGERKEY | MDB_CREATE, m_block_burn, "Failed to open db handle for m_block_burn");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SERVE_CREDIT, MDB_CREATE, m_archival_serve_credit,
    "Failed to open db handle for m_archival_serve_credit");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SETTLEMENT, MDB_CREATE, m_archival_settlement,
    "Failed to open db handle for m_archival_settlement");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BOND, MDB_CREATE, m_archival_bond,
    "Failed to open db handle for m_archival_bond");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SHARD_SEGMENT, MDB_CREATE, m_archival_shard_segment,
    "Failed to open db handle for m_archival_shard_segment");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SLASH_APPLIED, MDB_CREATE, m_archival_slash_applied,
    "Failed to open db handle for m_archival_slash_applied");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SLASH_LOG, MDB_CREATE, m_archival_slash_log,
    "Failed to open db handle for m_archival_slash_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_EMISSION_CLAIM_LOG, MDB_CREATE, m_archival_emission_claim_log,
    "Failed to open db handle for m_archival_emission_claim_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BOND_UNBOND_LOG, MDB_CREATE, m_archival_bond_unbond_log,
    "Failed to open db handle for m_archival_bond_unbond_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BOND_HOLDINGS_UPDATE_LOG, MDB_CREATE,
    m_archival_bond_holdings_update_log,
    "Failed to open db handle for m_archival_bond_holdings_update_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BOND_REBOND_LOG, MDB_CREATE, m_archival_bond_rebond_log,
    "Failed to open db handle for m_archival_bond_rebond_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_R_MARKET, MDB_CREATE, m_archival_r_market,
    "Failed to open db handle for m_archival_r_market");
  lmdb_db_open(txn, LMDB_ARCHIVAL_SIGMA_WORK, MDB_CREATE, m_archival_sigma_work,
    "Failed to open db handle for m_archival_sigma_work");
  lmdb_db_open(txn, LMDB_ARCHIVAL_EPOCH_CLOSE_LOG, MDB_CREATE, m_archival_epoch_close_log,
    "Failed to open db handle for m_archival_epoch_close_log");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BUDGET_ACCRUAL, MDB_CREATE, m_archival_budget_accrual,
    "Failed to open db handle for m_archival_budget_accrual");
  lmdb_db_open(txn, LMDB_ARCHIVAL_BUDGET, MDB_CREATE, m_archival_budget,
    "Failed to open db handle for m_archival_budget");
  // MDB_INTEGERKEY is correct here: a single native-endian uint64 height key
  // (mirrors m_curve_tree_roots), NOT a composite BE key like the archival
  // tables above — so its cursor iterates in numeric order and the height prune
  // below can break on the first retained row.
  lmdb_db_open(txn, LMDB_ARCHIVAL_ATTESTATION_WITNESS, MDB_INTEGERKEY | MDB_CREATE, m_archival_attestation_witness,
    "Failed to open db handle for m_archival_attestation_witness");
  // Reorg-survival counterpart, keyed by BLOCK HASH (32B, compare_hash32 set below),
  // NOT height — alt blocks are not height-canonical. Plain MDB_CREATE (no INTEGERKEY).
  lmdb_db_open(txn, LMDB_ARCHIVAL_ALT_ATTESTATION_WITNESS, MDB_CREATE, m_archival_alt_attestation_witness,
    "Failed to open db handle for m_archival_alt_attestation_witness");

  // INVARIANT: Shekyl curve-tree state uses composite keys. No DUPSORT.
  // If you're reaching for MDB_DUPSORT, stop and use a composite key instead.
  // The prior DUPSORT-on-content design was the root cause of a consensus bug
  // where leaf ordering depended on byte-sorted content instead of output index.
  //
  // Do NOT add MDB_INTEGERKEY to these — composite keys are multi-field
  // big-endian byte arrays, not native-endian integers. MDB_INTEGERKEY would
  // silently break sort order on little-endian machines.
  lmdb_db_open(txn, LMDB_PENDING_TREE_LEAVES, MDB_CREATE, m_pending_tree_leaves, "Failed to open db handle for m_pending_tree_leaves");
  lmdb_db_open(txn, LMDB_PENDING_TREE_DRAIN, MDB_CREATE, m_pending_tree_drain, "Failed to open db handle for m_pending_tree_drain");
  lmdb_db_open(txn, LMDB_BLOCK_PENDING_ADDITIONS, MDB_CREATE, m_block_pending_additions, "Failed to open db handle for m_block_pending_additions");

  // MDB_INTEGERKEY is correct here — single native-endian uint64 keys.
  lmdb_db_open(txn, LMDB_OUTPUT_TO_LEAF, MDB_INTEGERKEY | MDB_CREATE, m_output_to_leaf, "Failed to open db handle for m_output_to_leaf");
  lmdb_db_open(txn, LMDB_LEAF_TO_OUTPUT, MDB_INTEGERKEY | MDB_CREATE, m_leaf_to_output, "Failed to open db handle for m_leaf_to_output");

  lmdb_db_open(txn, LMDB_CURVE_TREE_LEAVES, MDB_INTEGERKEY | MDB_CREATE, m_curve_tree_leaves, "Failed to open db handle for m_curve_tree_leaves");
  lmdb_db_open(txn, LMDB_CURVE_TREE_LAYERS, MDB_INTEGERKEY | MDB_CREATE, m_curve_tree_layers, "Failed to open db handle for m_curve_tree_layers");
  lmdb_db_open(txn, LMDB_CURVE_TREE_META,   MDB_CREATE, m_curve_tree_meta, "Failed to open db handle for m_curve_tree_meta");
  lmdb_db_open(txn, LMDB_CURVE_TREE_CHECKPOINTS, MDB_INTEGERKEY | MDB_CREATE, m_curve_tree_checkpoints, "Failed to open db handle for m_curve_tree_checkpoints");
  lmdb_db_open(txn, LMDB_CURVE_TREE_ROOTS, MDB_INTEGERKEY | MDB_CREATE, m_curve_tree_roots, "Failed to open db handle for m_curve_tree_roots");

  lmdb_db_open(txn, LMDB_OUTPUT_METADATA, MDB_INTEGERKEY | MDB_CREATE, m_output_metadata, "Failed to open db handle for m_output_metadata");

  mdb_set_dupsort(txn, m_spent_keys, compare_hash32);
  mdb_set_dupsort(txn, m_block_heights, compare_hash32);
  mdb_set_dupsort(txn, m_tx_indices, compare_hash32);
  mdb_set_dupsort(txn, m_output_amounts, compare_uint64);
  mdb_set_dupsort(txn, m_output_txs, compare_uint64);
  mdb_set_dupsort(txn, m_block_info, compare_uint64);
  if (!(mdb_flags & MDB_RDONLY))
    mdb_set_dupsort(txn, m_txs_prunable_tip, compare_uint64);
  mdb_set_compare(txn, m_txs_prunable, compare_uint64);
  mdb_set_compare(txn, m_txs_pqc_auths, compare_uint64);
  mdb_set_dupsort(txn, m_txs_prunable_hash, compare_uint64);

  mdb_set_compare(txn, m_txpool_meta, compare_hash32);
  mdb_set_compare(txn, m_txpool_blob, compare_hash32);
  mdb_set_compare(txn, m_alt_blocks, compare_hash32);
  mdb_set_compare(txn, m_archival_alt_attestation_witness, compare_hash32);
  mdb_set_compare(txn, m_properties, compare_string);

  if (!(mdb_flags & MDB_RDONLY))
  {
    result = mdb_drop(txn, m_hf_starting_heights, 1);
    if (result && result != MDB_NOTFOUND)
      throw0(DB_ERROR(lmdb_error("Failed to drop m_hf_starting_heights: ", result).c_str()));
  }

  // get and keep current height
  MDB_stat db_stats;
  if ((result = mdb_stat(txn, m_blocks, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_blocks: ", result).c_str()));
  LOG_PRINT_L2("Setting m_height to: " << db_stats.ms_entries);
  uint64_t m_height = db_stats.ms_entries;

  bool compatible = true;

  MDB_val_str(k, "version");
  MDB_val v;
  auto get_result = mdb_get(txn, m_properties, &k, &v);
  if(get_result == MDB_SUCCESS)
  {
    const uint32_t db_version = *(const uint32_t*)v.mv_data;
    if (db_version > VERSION)
    {
      MWARNING("Existing lmdb database was made by a later version (" << db_version << "). We don't know how it will change yet.");
      compatible = false;
    }
#if VERSION > 0
    else if (db_version < VERSION)
    {
      if (mdb_flags & MDB_RDONLY)
      {
        txn.abort();
        mdb_env_close(m_env);
        m_open = false;
        MFATAL("Existing lmdb database needs to be converted, which cannot be done on a read-only database.");
        MFATAL("Please run shekyld once to convert the database.");
        return;
      }
      // Note that there was a schema change within version 0 as well.
      // See commit e5d2680094ee15889934fe28901e4e133cda56f2 2015/07/10
      // We don't handle the old format previous to that commit.
      txn.commit();
      m_open = true;
      migrate(db_version);
      return;
    }
#endif
  }
  else
  {
    // if not found, and the DB is non-empty, this is probably
    // an "old" version 0, which we don't handle. If the DB is
    // empty it's fine.
    if (VERSION > 0 && m_height > 0)
      compatible = false;
  }

  if (!compatible)
  {
    txn.abort();
    mdb_env_close(m_env);
    m_open = false;
    MFATAL("Existing lmdb database is incompatible with this version.");
    MFATAL("Please delete the existing database and resync.");
    return;
  }

  if (!(mdb_flags & MDB_RDONLY))
  {
    // only write version on an empty DB
    if (m_height == 0)
    {
      MDB_val_str(k, "version");
      MDB_val_copy<uint32_t> v(VERSION);
      auto put_result = mdb_put(txn, m_properties, &k, &v, 0);
      if (put_result != MDB_SUCCESS)
      {
        txn.abort();
        mdb_env_close(m_env);
        m_open = false;
        MERROR("Failed to write version to database.");
        return;
      }
    }
  }

  // commit the transaction
  txn.commit();

  m_open = true;
  // from here, init should be finished
}

void BlockchainLMDB::close()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (m_batch_active)
  {
    LOG_PRINT_L3("close() first calling batch_abort() due to active batch transaction");
    BlockchainLMDB::batch_abort();
  }
  BlockchainLMDB::sync();
  m_tinfo.reset();

  // mdb_env_close requires all txns/cursors to be closed first and must be
  // called from a single thread.  This is guaranteed by the daemon shutdown
  // sequence: Blockchain::deinit() → batch_abort/sync → close().
  mdb_env_close(m_env);
  m_open = false;
}

void BlockchainLMDB::sync()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (BlockchainLMDB::is_read_only())
    return;

  // Does nothing unless LMDB environment was opened with MDB_NOSYNC or in part
  // MDB_NOMETASYNC. Force flush to be synchronous.
  if (auto result = mdb_env_sync(m_env, true))
  {
    throw0(DB_ERROR(lmdb_error("Failed to sync database: ", result).c_str()));
  }
}

void BlockchainLMDB::safesyncmode(const bool onoff)
{
  MINFO("switching safe mode " << (onoff ? "on" : "off"));
  mdb_env_set_flags(m_env, MDB_NOSYNC|MDB_MAPASYNC, !onoff);
}

void BlockchainLMDB::reset()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  mdb_txn_safe txn;
  if (auto result = lmdb_txn_begin(m_env, NULL, 0, txn))
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));

  // Fresh-database state: enumerate every named table (main-DB keys ARE
  // table names) and empty it, then re-seed the version row — the only
  // thing open() writes on an empty DB. Readers treat empty tables as
  // "no state" (e.g. curve-tree leaf_count: MDB_NOTFOUND → 0). A
  // hand-written drop list goes stale when tables are added; the
  // 2026-08-07 audit found 25 Shekyl tables surviving reset, and
  // re-used heights/hashes made stale rows consensus-wrong and silent.
  // Tables that must SURVIVE go through table_survives_chain_reset —
  // the sole remaining hand-maintained residual (txpool only: mempool
  // lifecycle is tx_memory_pool's; reset has never touched it).
  for (const std::string &name : named_table_names(txn))
  {
    if (is_chain_reset_keep_table(name))
      continue;
    // open() already opened each name; LMDB returns the existing DBI
    // slot, so member handles stay valid across the wipe.
    MDB_dbi dbi;
    if (auto result = mdb_dbi_open(txn, name.c_str(), 0, &dbi))
      throw0(DB_ERROR(lmdb_error("Failed to open table " + name + " for reset: ", result).c_str()));
    if (auto result = mdb_drop(txn, dbi, 0))
      throw0(DB_ERROR(lmdb_error("Failed to drop table " + name + ": ", result).c_str()));
  }

  // Re-seed exactly what open() writes on an empty database: the version.
  MDB_val_str(k, "version");
  MDB_val_copy<uint32_t> v(VERSION);
  if (auto result = mdb_put(txn, m_properties, &k, &v, 0))
    throw0(DB_ERROR(lmdb_error("Failed to write version to database: ", result).c_str()));

  txn.commit();
  m_cum_size = 0;
  m_cum_count = 0;
}

bool BlockchainLMDB::table_survives_chain_reset(const std::string& name)
{
  return is_chain_reset_keep_table(name);
}

std::map<std::string, uint64_t> BlockchainLMDB::get_table_entry_counts() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  mdb_txn_safe txn;
  if (auto result = lmdb_txn_begin(m_env, NULL, MDB_RDONLY, txn))
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));

  std::map<std::string, uint64_t> counts;
  for (const std::string &name : named_table_names(txn))
  {
    MDB_dbi dbi;
    if (auto open_result = mdb_dbi_open(txn, name.c_str(), 0, &dbi))
      throw0(DB_ERROR(lmdb_error("Failed to open table " + name + ": ", open_result).c_str()));
    MDB_stat stat;
    if (auto stat_result = mdb_stat(txn, dbi, &stat))
      throw0(DB_ERROR(lmdb_error("Failed to stat table " + name + ": ", stat_result).c_str()));
    // mdb_stat.ms_entries: total data items (lmdb.h). For MDB_DUPSORT
    // tables each key/value pair is one item — md_entries is incremented
    // per successful data insert (see mdb_cursor_put), not unique keys.
    counts[name] = stat.ms_entries;
  }

  txn.commit();
  return counts;
}

std::vector<std::string> BlockchainLMDB::get_filenames() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  std::vector<std::string> filenames;

  boost::filesystem::path datafile(m_folder);
  datafile /= CRYPTONOTE_BLOCKCHAINDATA_FILENAME;
  boost::filesystem::path lockfile(m_folder);
  lockfile /= CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME;

  filenames.push_back(datafile.string());
  filenames.push_back(lockfile.string());

  return filenames;
}

bool BlockchainLMDB::remove_data_file(const std::string& folder) const
{
  const std::string filename = folder + "/data.mdb";
  try
  {
    boost::filesystem::remove(filename);
  }
  catch (const std::exception &e)
  {
    MERROR("Failed to remove " << filename << ": " << e.what());
    return false;
  }
  return true;
}

std::string BlockchainLMDB::get_db_name() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  return std::string("lmdb");
}

// TODO: this?
bool BlockchainLMDB::lock()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  return false;
}

// TODO: this?
void BlockchainLMDB::unlock()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
}


// The below two macros are for DB access within block add/remove, whether
// regular batch txn is in use or not. m_write_txn is used as a batch txn, even
// if it's only within block add/remove.
//
// DB access functions that may be called both within block add/remove and
// without should use these. If the function will be called ONLY within block
// add/remove, m_write_txn alone may be used instead of these macros.

#define TXN_BLOCK_PREFIX(flags); \
  mdb_txn_safe auto_txn; \
  mdb_txn_safe* txn_ptr = &auto_txn; \
  if (m_batch_active || m_write_txn) \
    txn_ptr = m_write_txn; \
  else \
  { \
    if (auto mdb_res = lmdb_txn_begin(m_env, NULL, flags, auto_txn)) \
      throw0(DB_ERROR(lmdb_error(std::string("Failed to create a transaction for the db in ")+__FUNCTION__+": ", mdb_res).c_str())); \
  } \

#define TXN_BLOCK_POSTFIX_SUCCESS() \
  do { \
    if (! m_batch_active && ! m_write_txn) \
      auto_txn.commit(); \
  } while(0)

void BlockchainLMDB::add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata_ref &blob, const txpool_tx_meta_t &meta)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(txpool_meta)
  CURSOR(txpool_blob)

  MDB_val k = {sizeof(txid), (void *)&txid};
  MDB_val v = {sizeof(meta), (void *)&meta};
  if (auto result = mdb_cursor_put(m_cur_txpool_meta, &k, &v, MDB_NODUPDATA)) {
    if (result == MDB_KEYEXIST)
      throw1(DB_ERROR("Attempting to add txpool tx metadata that's already in the db"));
    else
      throw1(DB_ERROR(lmdb_error("Error adding txpool tx metadata to db transaction: ", result).c_str()));
  }
  MDB_val_sized(blob_val, blob);
  if (auto result = mdb_cursor_put(m_cur_txpool_blob, &k, &blob_val, MDB_NODUPDATA)) {
    if (result == MDB_KEYEXIST)
      throw1(DB_ERROR("Attempting to add txpool tx blob that's already in the db"));
    else
      throw1(DB_ERROR(lmdb_error("Error adding txpool tx blob to db transaction: ", result).c_str()));
  }
}

void BlockchainLMDB::update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t &meta)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(txpool_meta)
  CURSOR(txpool_blob)

  MDB_val k = {sizeof(txid), (void *)&txid};
  MDB_val v;
  auto result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, MDB_SET);
  if (result != 0)
    throw1(DB_ERROR(lmdb_error("Error finding txpool tx meta to update: ", result).c_str()));
  result = mdb_cursor_del(m_cur_txpool_meta, 0);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error adding removal of txpool tx metadata to db transaction: ", result).c_str()));
  v = MDB_val({sizeof(meta), (void *)&meta});
  if ((result = mdb_cursor_put(m_cur_txpool_meta, &k, &v, MDB_NODUPDATA)) != 0) {
    if (result == MDB_KEYEXIST)
      throw1(DB_ERROR("Attempting to add txpool tx metadata that's already in the db"));
    else
      throw1(DB_ERROR(lmdb_error("Error adding txpool tx metadata to db transaction: ", result).c_str()));
  }
}

uint64_t BlockchainLMDB::get_txpool_tx_count(relay_category category) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  int result;
  uint64_t num_entries = 0;

  TXN_PREFIX_RDONLY();

  if (category == relay_category::all)
  {
    // No filtering, we can get the number of tx the "fast" way
    MDB_stat db_stats;
    if ((result = mdb_stat(m_txn, m_txpool_meta, &db_stats)))
      throw0(DB_ERROR(lmdb_error("Failed to query m_txpool_meta: ", result).c_str()));
    num_entries = db_stats.ms_entries;
  }
  else
  {
    // Filter unrelayed tx out of the result, so we need to loop over transactions and check their meta data
    RCURSOR(txpool_meta);
    RCURSOR(txpool_blob);

    MDB_val k;
    MDB_val v;
    MDB_cursor_op op = MDB_FIRST;
    while (1)
    {
      result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, op);
      op = MDB_NEXT;
      if (result == MDB_NOTFOUND)
        break;
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate txpool tx metadata: ", result).c_str()));
      const txpool_tx_meta_t &meta = *(const txpool_tx_meta_t*)v.mv_data;
      if (meta.matches(category))
        ++num_entries;
    }
  }
  TXN_POSTFIX_RDONLY();

  return num_entries;
}

bool BlockchainLMDB::txpool_has_tx(const crypto::hash& txid, relay_category tx_category) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(txpool_meta)

  MDB_val k = {sizeof(txid), (void *)&txid};
  MDB_val v;
  auto result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, MDB_SET);
  if (result != 0 && result != MDB_NOTFOUND)
    throw1(DB_ERROR(lmdb_error("Error finding txpool tx meta: ", result).c_str()));
  if (result == MDB_NOTFOUND)
    return false;

  bool found = true;
  if (tx_category != relay_category::all)
  {
    const txpool_tx_meta_t &meta = *(const txpool_tx_meta_t*)v.mv_data;
    found = meta.matches(tx_category);
  }
  TXN_POSTFIX_RDONLY();
  return found;
}

void BlockchainLMDB::remove_txpool_tx(const crypto::hash& txid)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(txpool_meta)
  CURSOR(txpool_blob)

  MDB_val k = {sizeof(txid), (void *)&txid};
  auto result = mdb_cursor_get(m_cur_txpool_meta, &k, NULL, MDB_SET);
  if (result != 0 && result != MDB_NOTFOUND)
    throw1(DB_ERROR(lmdb_error("Error finding txpool tx meta to remove: ", result).c_str()));
  if (!result)
  {
    result = mdb_cursor_del(m_cur_txpool_meta, 0);
    if (result)
      throw1(DB_ERROR(lmdb_error("Error adding removal of txpool tx metadata to db transaction: ", result).c_str()));
  }
  result = mdb_cursor_get(m_cur_txpool_blob, &k, NULL, MDB_SET);
  if (result != 0 && result != MDB_NOTFOUND)
    throw1(DB_ERROR(lmdb_error("Error finding txpool tx blob to remove: ", result).c_str()));
  if (!result)
  {
    result = mdb_cursor_del(m_cur_txpool_blob, 0);
    if (result)
      throw1(DB_ERROR(lmdb_error("Error adding removal of txpool tx blob to db transaction: ", result).c_str()));
  }
}

bool BlockchainLMDB::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(txpool_meta)

  MDB_val k = {sizeof(txid), (void *)&txid};
  MDB_val v;
  auto result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, MDB_SET);
  if (result == MDB_NOTFOUND)
      return false;
  if (result != 0)
      throw1(DB_ERROR(lmdb_error("Error finding txpool tx meta: ", result).c_str()));

  meta = *(const txpool_tx_meta_t*)v.mv_data;
  TXN_POSTFIX_RDONLY();
  return true;
}

bool BlockchainLMDB::get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(txpool_blob)

  MDB_val k = {sizeof(txid), (void *)&txid};
  MDB_val v;

  // if filtering, make sure those requirements are met before copying blob
  if (tx_category != relay_category::all)
  {
    RCURSOR(txpool_meta)
    auto result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, MDB_SET);
    if (result == MDB_NOTFOUND)
      return false;
    if (result != 0)
      throw1(DB_ERROR(lmdb_error("Error finding txpool tx meta: ", result).c_str()));

    const txpool_tx_meta_t& meta = *(const txpool_tx_meta_t*)v.mv_data;
    if (!meta.matches(tx_category))
      return false;
  }

  auto result = mdb_cursor_get(m_cur_txpool_blob, &k, &v, MDB_SET);
  if (result == MDB_NOTFOUND)
    return false;
  if (result != 0)
      throw1(DB_ERROR(lmdb_error("Error finding txpool tx blob: ", result).c_str()));

  bd.assign(reinterpret_cast<const char*>(v.mv_data), v.mv_size);
  TXN_POSTFIX_RDONLY();
  return true;
}

cryptonote::blobdata BlockchainLMDB::get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const
{
  cryptonote::blobdata bd;
  if (!get_txpool_tx_blob(txid, bd, tx_category))
    throw1(DB_ERROR("Tx not found in txpool: "));
  return bd;
}

uint32_t BlockchainLMDB::get_blockchain_pruning_seed() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(properties)
  MDB_val_str(k, "pruning_seed");
  MDB_val v;
  int result = mdb_cursor_get(m_cur_properties, &k, &v, MDB_SET);
  if (result == MDB_NOTFOUND)
    return 0;
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to retrieve pruning seed: ", result).c_str()));
  if (v.mv_size != sizeof(uint32_t))
    throw0(DB_ERROR("Failed to retrieve or create pruning seed: unexpected value size"));
  uint32_t pruning_seed;
  memcpy(&pruning_seed, v.mv_data, sizeof(pruning_seed));
  TXN_POSTFIX_RDONLY();
  return pruning_seed;
}

static bool is_v1_tx(MDB_cursor *c_txs_pruned, MDB_val *tx_id)
{
  MDB_val v;
  int ret = mdb_cursor_get(c_txs_pruned, tx_id, &v, MDB_SET);
  if (ret)
    throw0(DB_ERROR(lmdb_error("Failed to find transaction pruned data: ", ret).c_str()));
  if (v.mv_size == 0)
    throw0(DB_ERROR("Invalid transaction pruned data"));
  return cryptonote::is_v1_tx(cryptonote::blobdata_ref{(const char*)v.mv_data, v.mv_size});
}

enum { prune_mode_prune, prune_mode_update, prune_mode_check };

bool BlockchainLMDB::prune_worker(int mode, uint32_t pruning_seed)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  const uint32_t log_stripes = tools::get_pruning_log_stripes(pruning_seed);
  if (log_stripes && log_stripes != CRYPTONOTE_PRUNING_LOG_STRIPES)
    throw0(DB_ERROR("Pruning seed not in range"));
  pruning_seed = tools::get_pruning_stripe(pruning_seed);
  if (pruning_seed > (1ul << CRYPTONOTE_PRUNING_LOG_STRIPES))
    throw0(DB_ERROR("Pruning seed not in range"));
  check_open();

  TIME_MEASURE_START(t);

  size_t n_total_records = 0, n_prunable_records = 0, n_pruned_records = 0, commit_counter = 0;
  uint64_t n_bytes = 0;

  mdb_txn_safe txn;
  auto result = mdb_txn_begin(m_env, NULL, 0, txn);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));

  MDB_stat db_stats;
  if ((result = mdb_stat(txn, m_txs_prunable, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_txs_prunable: ", result).c_str()));
  const size_t pages0 = db_stats.ms_branch_pages + db_stats.ms_leaf_pages + db_stats.ms_overflow_pages;

  MDB_val_str(k, "pruning_seed");
  MDB_val v;
  result = mdb_get(txn, m_properties, &k, &v);
  bool prune_tip_table = false;
  if (result == MDB_NOTFOUND)
  {
    // not pruned yet
    if (mode != prune_mode_prune)
    {
      txn.abort();
      TIME_MEASURE_FINISH(t);
      MDEBUG("Pruning not enabled, nothing to do");
      return true;
    }
    if (pruning_seed == 0)
      pruning_seed = tools::get_random_stripe();
    pruning_seed = tools::make_pruning_seed(pruning_seed, CRYPTONOTE_PRUNING_LOG_STRIPES);
    v.mv_data = &pruning_seed;
    v.mv_size = sizeof(pruning_seed);
    result = mdb_put(txn, m_properties, &k, &v, 0);
    if (result)
      throw0(DB_ERROR("Failed to save pruning seed"));
    prune_tip_table = false;
  }
  else if (result == 0)
  {
    // pruned already
    if (v.mv_size != sizeof(uint32_t))
      throw0(DB_ERROR("Failed to retrieve or create pruning seed: unexpected value size"));
    const uint32_t data = *(const uint32_t*)v.mv_data;
    if (pruning_seed == 0)
      pruning_seed = tools::get_pruning_stripe(data);
    if (tools::get_pruning_stripe(data) != pruning_seed)
      throw0(DB_ERROR("Blockchain already pruned with different seed"));
    if (tools::get_pruning_log_stripes(data) != CRYPTONOTE_PRUNING_LOG_STRIPES)
      throw0(DB_ERROR("Blockchain already pruned with different base"));
    pruning_seed = tools::make_pruning_seed(pruning_seed, CRYPTONOTE_PRUNING_LOG_STRIPES);
    prune_tip_table = (mode == prune_mode_update);
  }
  else
  {
    throw0(DB_ERROR(lmdb_error("Failed to retrieve or create pruning seed: ", result).c_str()));
  }

  if (mode == prune_mode_check)
    MINFO("Checking blockchain pruning...");
  else
    MINFO("Pruning blockchain...");

  MDB_cursor *c_txs_pruned, *c_txs_prunable, *c_txs_prunable_tip;
  result = mdb_cursor_open(txn, m_txs_pruned, &c_txs_pruned);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_pruned: ", result).c_str()));
  result = mdb_cursor_open(txn, m_txs_prunable, &c_txs_prunable);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable: ", result).c_str()));
  result = mdb_cursor_open(txn, m_txs_prunable_tip, &c_txs_prunable_tip);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable_tip: ", result).c_str()));
  const uint64_t blockchain_height = height();

  if (prune_tip_table)
  {
    MDB_cursor_op op = MDB_FIRST;
    while (1)
    {
      int ret = mdb_cursor_get(c_txs_prunable_tip, &k, &v, op);
      op = MDB_NEXT;
      if (ret == MDB_NOTFOUND)
        break;
      if (ret)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate transactions: ", ret).c_str()));

      uint64_t block_height;
      memcpy(&block_height, v.mv_data, sizeof(block_height));
      if (block_height + CRYPTONOTE_PRUNING_TIP_BLOCKS < blockchain_height)
      {
        ++n_total_records;
        if (!tools::has_unpruned_block(block_height, blockchain_height, pruning_seed) && !is_v1_tx(c_txs_pruned, &k))
        {
          ++n_prunable_records;
          result = mdb_cursor_get(c_txs_prunable, &k, &v, MDB_SET);
          if (result == MDB_NOTFOUND)
            MDEBUG("Already pruned at height " << block_height << "/" << blockchain_height);
          else if (result)
            throw0(DB_ERROR(lmdb_error("Failed to find transaction prunable data: ", result).c_str()));
          else
          {
            MDEBUG("Pruning at height " << block_height << "/" << blockchain_height);
            ++n_pruned_records;
            ++commit_counter;
            n_bytes += k.mv_size + v.mv_size;
            result = mdb_cursor_del(c_txs_prunable, 0);
            if (result)
              throw0(DB_ERROR(lmdb_error("Failed to delete transaction prunable data: ", result).c_str()));
          }
        }
        result = mdb_cursor_del(c_txs_prunable_tip, 0);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to delete transaction tip data: ", result).c_str()));

        if (mode != prune_mode_check && commit_counter >= 4096)
        {
          MDEBUG("Committing txn at checkpoint...");
          txn.commit();
          result = mdb_txn_begin(m_env, NULL, 0, txn);
          if (result)
            throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));
          result = mdb_cursor_open(txn, m_txs_pruned, &c_txs_pruned);
          if (result)
            throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_pruned: ", result).c_str()));
          result = mdb_cursor_open(txn, m_txs_prunable, &c_txs_prunable);
          if (result)
            throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable: ", result).c_str()));
          result = mdb_cursor_open(txn, m_txs_prunable_tip, &c_txs_prunable_tip);
          if (result)
            throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable_tip: ", result).c_str()));
          commit_counter = 0;
        }
      }
    }
  }
  else
  {
    MDB_cursor *c_tx_indices;
    result = mdb_cursor_open(txn, m_tx_indices, &c_tx_indices);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to open a cursor for tx_indices: ", result).c_str()));
    MDB_cursor_op op = MDB_FIRST;
    while (1)
    {
      int ret = mdb_cursor_get(c_tx_indices, &k, &v, op);
      op = MDB_NEXT;
      if (ret == MDB_NOTFOUND)
        break;
      if (ret)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate transactions: ", ret).c_str()));

      ++n_total_records;
      //const txindex *ti = (const txindex *)v.mv_data;
      txindex ti;
      memcpy(&ti, v.mv_data, sizeof(ti));
      const uint64_t block_height = ti.data.block_id;
      if (block_height + CRYPTONOTE_PRUNING_TIP_BLOCKS >= blockchain_height)
      {
        MDB_val_set(kp, ti.data.tx_id);
        MDB_val_set(vp, block_height);
        if (mode == prune_mode_check)
        {
          result = mdb_cursor_get(c_txs_prunable_tip, &kp, &vp, MDB_SET);
          if (result && result != MDB_NOTFOUND)
            throw0(DB_ERROR(lmdb_error("Error looking for transaction prunable data: ", result).c_str()));
          if (result == MDB_NOTFOUND)
            MERROR("Transaction not found in prunable tip table for height " << block_height << "/" << blockchain_height <<
                ", seed " << epee::string_tools::to_string_hex(pruning_seed));
        }
        else
        {
          result = mdb_cursor_put(c_txs_prunable_tip, &kp, &vp, 0);
          if (result && result != MDB_NOTFOUND)
            throw0(DB_ERROR(lmdb_error("Error looking for transaction prunable data: ", result).c_str()));
        }
      }
      MDB_val_set(kp, ti.data.tx_id);
      if (!tools::has_unpruned_block(block_height, blockchain_height, pruning_seed) && !is_v1_tx(c_txs_pruned, &kp))
      {
        result = mdb_cursor_get(c_txs_prunable, &kp, &v, MDB_SET);
        if (result && result != MDB_NOTFOUND)
          throw0(DB_ERROR(lmdb_error("Error looking for transaction prunable data: ", result).c_str()));
        if (mode == prune_mode_check)
        {
          if (result != MDB_NOTFOUND)
            MERROR("Prunable data found for pruned height " << block_height << "/" << blockchain_height <<
                ", seed " << epee::string_tools::to_string_hex(pruning_seed));
        }
        else
        {
          ++n_prunable_records;
          if (result == MDB_NOTFOUND)
            MDEBUG("Already pruned at height " << block_height << "/" << blockchain_height);
          else
          {
            MDEBUG("Pruning at height " << block_height << "/" << blockchain_height);
            ++n_pruned_records;
            n_bytes += kp.mv_size + v.mv_size;
            result = mdb_cursor_del(c_txs_prunable, 0);
            if (result)
              throw0(DB_ERROR(lmdb_error("Failed to delete transaction prunable data: ", result).c_str()));
            ++commit_counter;
          }
        }
      }
      else
      {
        if (mode == prune_mode_check)
        {
          MDB_val_set(kp, ti.data.tx_id);
          result = mdb_cursor_get(c_txs_prunable, &kp, &v, MDB_SET);
          if (result && result != MDB_NOTFOUND)
            throw0(DB_ERROR(lmdb_error("Error looking for transaction prunable data: ", result).c_str()));
          if (result == MDB_NOTFOUND)
            MERROR("Prunable data not found for unpruned height " << block_height << "/" << blockchain_height <<
                ", seed " << epee::string_tools::to_string_hex(pruning_seed));
        }
      }

      if (mode != prune_mode_check && commit_counter >= 4096)
      {
        MDEBUG("Committing txn at checkpoint...");
        txn.commit();
        result = mdb_txn_begin(m_env, NULL, 0, txn);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));
        result = mdb_cursor_open(txn, m_txs_pruned, &c_txs_pruned);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_pruned: ", result).c_str()));
        result = mdb_cursor_open(txn, m_txs_prunable, &c_txs_prunable);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable: ", result).c_str()));
        result = mdb_cursor_open(txn, m_txs_prunable_tip, &c_txs_prunable_tip);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to open a cursor for txs_prunable_tip: ", result).c_str()));
        result = mdb_cursor_open(txn, m_tx_indices, &c_tx_indices);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to open a cursor for tx_indices: ", result).c_str()));
        MDB_val val;
        val.mv_size = sizeof(ti);
        val.mv_data = (void *)&ti;
        result = mdb_cursor_get(c_tx_indices, (MDB_val*)&zerokval, &val, MDB_GET_BOTH);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to restore cursor for tx_indices: ", result).c_str()));
        commit_counter = 0;
      }
    }
    mdb_cursor_close(c_tx_indices);
  }

  if ((result = mdb_stat(txn, m_txs_prunable, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_txs_prunable: ", result).c_str()));
  const size_t pages1 = db_stats.ms_branch_pages + db_stats.ms_leaf_pages + db_stats.ms_overflow_pages;
  const size_t db_bytes = (pages0 - pages1) * db_stats.ms_psize;

  mdb_cursor_close(c_txs_prunable_tip);
  mdb_cursor_close(c_txs_prunable);
  mdb_cursor_close(c_txs_pruned);

  txn.commit();

  TIME_MEASURE_FINISH(t);

  MINFO((mode == prune_mode_check ? "Checked" : "Pruned") << " blockchain in " <<
      t << " ms: " << (n_bytes/1024.0f/1024.0f) << " MB (" << db_bytes/1024.0f/1024.0f << " MB) pruned in " <<
      n_pruned_records << " records (" << pages0 - pages1 << "/" << pages0 << " " << db_stats.ms_psize << " byte pages), " <<
      n_prunable_records << "/" << n_total_records << " pruned records");
  return true;
}

bool BlockchainLMDB::prune_blockchain(uint32_t pruning_seed)
{
  return prune_worker(prune_mode_prune, pruning_seed);
}

bool BlockchainLMDB::update_pruning()
{
  return prune_worker(prune_mode_update, 0);
}

bool BlockchainLMDB::check_pruning()
{
  return prune_worker(prune_mode_check, 0);
}

bool BlockchainLMDB::for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f, bool include_blob, relay_category category) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(txpool_meta);
  RCURSOR(txpool_blob);

  MDB_val k;
  MDB_val v;
  bool ret = true;

  MDB_cursor_op op = MDB_FIRST;
  while (1)
  {
    int result = mdb_cursor_get(m_cur_txpool_meta, &k, &v, op);
    op = MDB_NEXT;
    if (result == MDB_NOTFOUND)
      break;
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to enumerate txpool tx metadata: ", result).c_str()));
    const crypto::hash txid = *(const crypto::hash*)k.mv_data;
    const txpool_tx_meta_t &meta = *(const txpool_tx_meta_t*)v.mv_data;
    if (!meta.matches(category))
      continue;
    cryptonote::blobdata_ref bd;
    if (include_blob)
    {
      MDB_val b;
      result = mdb_cursor_get(m_cur_txpool_blob, &k, &b, MDB_SET);
      if (result == MDB_NOTFOUND)
        throw0(DB_ERROR("Failed to find txpool tx blob to match metadata"));
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate txpool tx blob: ", result).c_str()));
      bd = {reinterpret_cast<const char*>(b.mv_data), b.mv_size};
    }

    if (!f(txid, meta, &bd)) {
      ret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return ret;
}

bool BlockchainLMDB::for_all_alt_blocks(std::function<bool(const crypto::hash&, const alt_block_data_t&, const cryptonote::blobdata_ref*)> f, bool include_blob) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(alt_blocks);

  MDB_val k;
  MDB_val v;
  bool ret = true;

  MDB_cursor_op op = MDB_FIRST;
  while (1)
  {
    int result = mdb_cursor_get(m_cur_alt_blocks, &k, &v, op);
    op = MDB_NEXT;
    if (result == MDB_NOTFOUND)
      break;
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to enumerate alt blocks: ", result).c_str()));
    const crypto::hash &blkid = *(const crypto::hash*)k.mv_data;
    if (v.mv_size < sizeof(alt_block_data_t))
      throw0(DB_ERROR("alt_blocks record is too small"));
    alt_block_data_t data;
    memcpy(&data, v.mv_data, sizeof(data));
    cryptonote::blobdata_ref bd;
    if (include_blob)
    {
      bd = {reinterpret_cast<const char*>(v.mv_data) + sizeof(alt_block_data_t), v.mv_size - sizeof(alt_block_data_t)};
    }

    if (!f(blkid, data, &bd)) {
      ret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return ret;
}

bool BlockchainLMDB::block_exists(const crypto::hash& h, uint64_t *height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_heights);

  bool ret = false;
  MDB_val_set(key, h);
  auto get_result = mdb_cursor_get(m_cur_block_heights, (MDB_val *)&zerokval, &key, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    LOG_PRINT_L3("Block with hash " << epee::string_tools::pod_to_hex(h) << " not found in db");
  }
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch block index from hash", get_result).c_str()));
  else
  {
    if (height)
    {
      const blk_height *bhp = (const blk_height *)key.mv_data;
      *height = bhp->bh_height;
    }
    ret = true;
  }

  TXN_POSTFIX_RDONLY();
  return ret;
}

cryptonote::blobdata BlockchainLMDB::get_block_blob(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  return get_block_blob_from_height(get_block_height(h));
}

uint64_t BlockchainLMDB::get_block_height(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_heights);

  MDB_val_set(key, h);
  auto get_result = mdb_cursor_get(m_cur_block_heights, (MDB_val *)&zerokval, &key, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
    throw1(BLOCK_DNE("Attempted to retrieve non-existent block height"));
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a block height from the db"));

  blk_height *bhp = (blk_height *)key.mv_data;
  uint64_t ret = bhp->bh_height;
  TXN_POSTFIX_RDONLY();
  return ret;
}

block_header BlockchainLMDB::get_block_header(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // block_header object is automatically cast from block object
  return get_block(h);
}

cryptonote::blobdata BlockchainLMDB::get_block_blob_from_height(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(blocks);

  MDB_val_copy<uint64_t> key(height);
  MDB_val result;
  auto get_result = mdb_cursor_get(m_cur_blocks, &key, &result, MDB_SET);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get block from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- block not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a block from the db"));

  blobdata bd;
  bd.assign(reinterpret_cast<char*>(result.mv_data), result.mv_size);

  TXN_POSTFIX_RDONLY();

  return bd;
}

uint64_t BlockchainLMDB::get_block_timestamp(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get timestamp from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- timestamp not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a timestamp from the db"));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  uint64_t ret = bi->bi_timestamp;
  TXN_POSTFIX_RDONLY();
  return ret;
}

std::vector<uint64_t> BlockchainLMDB::get_block_cumulative_rct_outputs(const std::vector<uint64_t> &heights) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  std::vector<uint64_t> res;
  int result;

  if (heights.empty())
    return {};
  res.reserve(heights.size());

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_stat db_stats;
  if ((result = mdb_stat(m_txn, m_blocks, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_blocks: ", result).c_str()));
  for (size_t i = 0; i < heights.size(); ++i)
    if (heights[i] >= db_stats.ms_entries)
      throw0(BLOCK_DNE(std::string("Attempt to get rct distribution from height " + std::to_string(heights[i]) + " failed -- block size not in db").c_str()));

  MDB_val v;

  uint64_t prev_height = heights[0];
  uint64_t range_begin = 0, range_end = 0;
  for (uint64_t height: heights)
  {
    if (height >= range_begin && height < range_end)
    {
      // nohting to do
    }
    else
    {
      if (height == prev_height + 1)
      {
        MDB_val k2;
        result = mdb_cursor_get(m_cur_block_info, &k2, &v, MDB_NEXT_MULTIPLE);
        range_begin = ((const mdb_block_info*)v.mv_data)->bi_height;
        range_end = range_begin + v.mv_size / sizeof(mdb_block_info); // whole records please
        if (height < range_begin || height >= range_end)
          throw0(DB_ERROR(("Height " + std::to_string(height) + " not included in multuple record range: " + std::to_string(range_begin) + "-" + std::to_string(range_end)).c_str()));
      }
      else
      {
        v.mv_size = sizeof(uint64_t);
        v.mv_data = (void*)&height;
        result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
        range_begin = height;
        range_end = range_begin + 1;
      }
      if (result)
        throw0(DB_ERROR(lmdb_error("Error attempting to retrieve rct distribution from the db: ", result).c_str()));
    }
    const mdb_block_info *bi = ((const mdb_block_info *)v.mv_data) + (height - range_begin);
    res.push_back(bi->bi_cum_rct);
    prev_height = height;
  }

  TXN_POSTFIX_RDONLY();
  return res;
}

uint64_t BlockchainLMDB::get_top_block_timestamp() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  uint64_t m_height = height();

  // if no blocks, return 0
  if (m_height == 0)
  {
    return 0;
  }

  return get_block_timestamp(m_height - 1);
}

size_t BlockchainLMDB::get_block_weight(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get block size from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- block size not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a block size from the db"));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  size_t ret = bi->bi_weight;
  TXN_POSTFIX_RDONLY();
  return ret;
}

std::vector<uint64_t> BlockchainLMDB::get_block_info_64bit_fields(uint64_t start_height, size_t count, off_t offset) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  const uint64_t h = height();
  if (start_height >= h)
    throw0(DB_ERROR(("Height " + std::to_string(start_height) + " not in blockchain").c_str()));

  std::vector<uint64_t> ret;
  ret.reserve(count);

  MDB_val v;
  uint64_t range_begin = 0, range_end = 0;
  for (uint64_t height = start_height; height < h && count--; ++height)
  {
    if (height >= range_begin && height < range_end)
    {
      // nothing to do
    }
    else
    {
      int result = 0;
      if (range_end > 0)
      {
        MDB_val k2;
        result = mdb_cursor_get(m_cur_block_info, &k2, &v, MDB_NEXT_MULTIPLE);
        range_begin = ((const mdb_block_info*)v.mv_data)->bi_height;
        range_end = range_begin + v.mv_size / sizeof(mdb_block_info); // whole records please
        if (height < range_begin || height >= range_end)
          throw0(DB_ERROR(("Height " + std::to_string(height) + " not included in multiple record range: " + std::to_string(range_begin) + "-" + std::to_string(range_end)).c_str()));
      }
      else
      {
        v.mv_size = sizeof(uint64_t);
        v.mv_data = (void*)&height;
        result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
        range_begin = height;
        range_end = range_begin + 1;
      }
      if (result)
        throw0(DB_ERROR(lmdb_error("Error attempting to retrieve block_info from the db: ", result).c_str()));
    }
    const mdb_block_info *bi = ((const mdb_block_info *)v.mv_data) + (height - range_begin);
    ret.push_back(*(const uint64_t*)(((const char*)bi) + offset));
  }

  TXN_POSTFIX_RDONLY();
  return ret;
}

std::vector<uint64_t> BlockchainLMDB::get_block_weights(uint64_t start_height, size_t count) const
{
  return get_block_info_64bit_fields(start_height, count, offsetof(mdb_block_info, bi_weight));
}

std::vector<uint64_t> BlockchainLMDB::get_long_term_block_weights(uint64_t start_height, size_t count) const
{
  return get_block_info_64bit_fields(start_height, count, offsetof(mdb_block_info, bi_long_term_block_weight));
}

difficulty_type BlockchainLMDB::get_block_cumulative_difficulty(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__ << "  height: " << height);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get cumulative difficulty from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- difficulty not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a cumulative difficulty from the db"));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  difficulty_type ret = bi->bi_diff_hi;
  ret <<= 64;
  ret |= bi->bi_diff_lo;
  TXN_POSTFIX_RDONLY();
  return ret;
}

difficulty_type BlockchainLMDB::get_block_difficulty(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  difficulty_type diff1 = 0;
  difficulty_type diff2 = 0;

  diff1 = get_block_cumulative_difficulty(height);
  if (height != 0)
  {
    diff2 = get_block_cumulative_difficulty(height - 1);
  }

  return diff1 - diff2;
}

void BlockchainLMDB::correct_block_cumulative_difficulties(const uint64_t& start_height, const std::vector<difficulty_type>& new_cumulative_difficulties)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  int result = 0;
  block_wtxn_start();
  CURSOR(block_info)

  const uint64_t bc_height = height();
  if (start_height + new_cumulative_difficulties.size() != bc_height)
  {
    block_wtxn_abort();
    throw0(DB_ERROR("Incorrect new_cumulative_difficulties size"));
  }

  for (uint64_t height = start_height; height < bc_height; ++height)
  {
    MDB_val_set(key, height);
    result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &key, MDB_GET_BOTH);
    if (result)
      throw1(BLOCK_DNE(lmdb_error("Failed to get block info: ", result).c_str()));

    mdb_block_info bi = *(mdb_block_info*)key.mv_data;
    const difficulty_type d = new_cumulative_difficulties[height - start_height];
    bi.bi_diff_hi = ((d >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    bi.bi_diff_lo = (d & 0xffffffffffffffff).convert_to<uint64_t>();

    MDB_val_set(key2, height);
    MDB_val_set(val, bi);
    result = mdb_cursor_put(m_cur_block_info, &key2, &val, MDB_CURRENT);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to overwrite block info to db transaction: ", result).c_str()));
  }
  block_wtxn_stop();
}

uint64_t BlockchainLMDB::get_block_already_generated_coins(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get generated coins from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- block size not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a total generated coins from the db"));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  uint64_t ret = bi->bi_coins;
  TXN_POSTFIX_RDONLY();
  return ret;
}

uint64_t BlockchainLMDB::get_block_long_term_weight(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get block long term weight from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- block info not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve a long term block weight from the db"));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  uint64_t ret = bi->bi_long_term_block_weight;
  TXN_POSTFIX_RDONLY();
  return ret;
}

crypto::hash BlockchainLMDB::get_block_hash_from_height(const uint64_t& height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(block_info);

  MDB_val_set(result, height);
  auto get_result = mdb_cursor_get(m_cur_block_info, (MDB_val *)&zerokval, &result, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw0(BLOCK_DNE(std::string("Attempt to get hash from height ").append(boost::lexical_cast<std::string>(height)).append(" failed -- hash not in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("Error attempting to retrieve a block hash from the db: ", get_result).c_str()));

  mdb_block_info *bi = (mdb_block_info *)result.mv_data;
  crypto::hash ret = bi->bi_hash;
  TXN_POSTFIX_RDONLY();
  return ret;
}

std::vector<block> BlockchainLMDB::get_blocks_range(const uint64_t& h1, const uint64_t& h2) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  std::vector<block> v;

  for (uint64_t height = h1; height <= h2; ++height)
  {
    v.push_back(get_block_from_height(height));
  }

  return v;
}

std::vector<crypto::hash> BlockchainLMDB::get_hashes_range(const uint64_t& h1, const uint64_t& h2) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  std::vector<crypto::hash> v;

  for (uint64_t height = h1; height <= h2; ++height)
  {
    v.push_back(get_block_hash_from_height(height));
  }

  return v;
}

crypto::hash BlockchainLMDB::top_block_hash(uint64_t *block_height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  uint64_t m_height = height();
  if (block_height)
    *block_height = m_height - 1;
  if (m_height != 0)
  {
    return get_block_hash_from_height(m_height - 1);
  }

  return null_hash;
}

block BlockchainLMDB::get_top_block() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  uint64_t m_height = height();

  if (m_height != 0)
  {
    return get_block_from_height(m_height - 1);
  }

  block b;
  return b;
}

uint64_t BlockchainLMDB::height() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  TXN_PREFIX_RDONLY();
  int result;

  // get current height
  MDB_stat db_stats;
  if ((result = mdb_stat(m_txn, m_blocks, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_blocks: ", result).c_str()));
  return db_stats.ms_entries;
}

uint64_t BlockchainLMDB::num_outputs() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  TXN_PREFIX_RDONLY();
  int result;

  RCURSOR(output_txs)

  uint64_t num = 0;
  MDB_val k, v;
  result = mdb_cursor_get(m_cur_output_txs, &k, &v, MDB_LAST);
  if (result == MDB_NOTFOUND)
    num = 0;
  else if (result == 0)
    num = 1 + ((const outtx*)v.mv_data)->output_id;
  else
    throw0(DB_ERROR(lmdb_error("Failed to query m_output_txs: ", result).c_str()));

  return num;
}

bool BlockchainLMDB::tx_exists(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);

  MDB_val_set(key, h);
  bool tx_found = false;

  TIME_MEASURE_START(time1);
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &key, MDB_GET_BOTH);
  if (get_result == 0)
    tx_found = true;
  else if (get_result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error(std::string("DB error attempting to fetch transaction index from hash ") + epee::string_tools::pod_to_hex(h) + ": ", get_result).c_str()));

  TIME_MEASURE_FINISH(time1);
  time_tx_exists += time1;

  TXN_POSTFIX_RDONLY();

  if (! tx_found)
  {
    LOG_PRINT_L3("transaction with hash " << epee::string_tools::pod_to_hex(h) << " not found in db");
    return false;
  }

  return true;
}

bool BlockchainLMDB::tx_exists(const crypto::hash& h, uint64_t& tx_id) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);

  MDB_val_set(v, h);

  TIME_MEASURE_START(time1);
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  TIME_MEASURE_FINISH(time1);
  time_tx_exists += time1;
  if (!get_result) {
    txindex *tip = (txindex *)v.mv_data;
    tx_id = tip->data.tx_id;
  }

  TXN_POSTFIX_RDONLY();

  bool ret = false;
  if (get_result == MDB_NOTFOUND)
  {
    LOG_PRINT_L3("transaction with hash " << epee::string_tools::pod_to_hex(h) << " not found in db");
  }
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch transaction from hash", get_result).c_str()));
  else
    ret = true;

  return ret;
}

uint64_t BlockchainLMDB::get_tx_unlock_time(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);

  MDB_val_set(v, h);
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
    throw1(TX_DNE(lmdb_error(std::string("tx data with hash ") + epee::string_tools::pod_to_hex(h) + " not found in db: ", get_result).c_str()));
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx data from hash: ", get_result).c_str()));

  txindex *tip = (txindex *)v.mv_data;
  uint64_t ret = tip->data.unlock_time;
  TXN_POSTFIX_RDONLY();
  return ret;
}

bool BlockchainLMDB::get_tx_blob(const crypto::hash& h, cryptonote::blobdata &bd) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);
  RCURSOR(txs_pruned);
  RCURSOR(txs_pqc_auths);
  RCURSOR(txs_prunable);

  MDB_val_set(v, h);
  MDB_val result0, result1;
  MDB_val result_pqc = {0, nullptr};
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == 0)
  {
    txindex *tip = (txindex *)v.mv_data;
    MDB_val_set(val_tx_id, tip->data.tx_id);
    get_result = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, &result0, MDB_SET);
    if (get_result == 0)
    {
      (void)mdb_cursor_get(m_cur_txs_pqc_auths, &val_tx_id, &result_pqc, MDB_SET);
      get_result = mdb_cursor_get(m_cur_txs_prunable, &val_tx_id, &result1, MDB_SET);
    }
  }
  if (get_result == MDB_NOTFOUND)
    return false;
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx from hash", get_result).c_str()));

  bd.assign(reinterpret_cast<char*>(result0.mv_data), result0.mv_size);
  if (result_pqc.mv_size)
    bd.append(reinterpret_cast<char*>(result_pqc.mv_data), result_pqc.mv_size);
  bd.append(reinterpret_cast<char*>(result1.mv_data), result1.mv_size);

  TXN_POSTFIX_RDONLY();

  return true;
}

bool BlockchainLMDB::get_pruned_tx_blob(const crypto::hash& h, cryptonote::blobdata &bd) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);
  RCURSOR(txs_pruned);
  RCURSOR(txs_pqc_auths);

  MDB_val_set(v, h);
  MDB_val result;
  MDB_val result_pqc = {0, nullptr};
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == 0)
  {
    txindex *tip = (txindex *)v.mv_data;
    MDB_val_set(val_tx_id, tip->data.tx_id);
    get_result = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, &result, MDB_SET);
    if (get_result == 0)
      (void)mdb_cursor_get(m_cur_txs_pqc_auths, &val_tx_id, &result_pqc, MDB_SET);
  }
  if (get_result == MDB_NOTFOUND)
    return false;
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx from hash", get_result).c_str()));

  bd.assign(reinterpret_cast<char*>(result.mv_data), result.mv_size);
  if (result_pqc.mv_size)
    bd.append(reinterpret_cast<char*>(result_pqc.mv_data), result_pqc.mv_size);

  TXN_POSTFIX_RDONLY();

  return true;
}

bool BlockchainLMDB::get_pruned_tx_blobs_from(const crypto::hash& h, size_t count, std::vector<cryptonote::blobdata> &bd) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!count)
    return true;

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);
  RCURSOR(txs_pruned);
  RCURSOR(txs_pqc_auths);

  bd.reserve(bd.size() + count);

  MDB_val_set(v, h);
  MDB_val result;
  MDB_val result_pqc = {0, nullptr};
  int res = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (res == MDB_NOTFOUND)
    return false;
  if (res)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx from hash", res).c_str()));

  const txindex *tip = (const txindex *)v.mv_data;
  const uint64_t id = tip->data.tx_id;
  MDB_val_set(val_tx_id, id);
  MDB_cursor_op op = MDB_SET;
  while (count--)
  {
    res = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, &result, op);
    op = MDB_NEXT;
    if (res == MDB_NOTFOUND)
      return false;
    if (res)
      throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx blob", res).c_str()));
    cryptonote::blobdata chunk(reinterpret_cast<char*>(result.mv_data), result.mv_size);
    result_pqc = {0, nullptr};
    (void)mdb_cursor_get(m_cur_txs_pqc_auths, &val_tx_id, &result_pqc, MDB_SET);
    if (result_pqc.mv_size)
      chunk.append(reinterpret_cast<char*>(result_pqc.mv_data), result_pqc.mv_size);
    bd.emplace_back(std::move(chunk));
  }

  TXN_POSTFIX_RDONLY();

  return true;
}

bool BlockchainLMDB::get_blocks_from(uint64_t start_height, size_t min_block_count, size_t max_block_count, size_t max_tx_count, size_t max_size, std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata>>>>& blocks, bool pruned, bool skip_coinbase, bool get_miner_tx_hash) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(blocks);
  RCURSOR(tx_indices);
  RCURSOR(txs_pruned);
  RCURSOR(txs_pqc_auths);
  if (!pruned)
  {
    RCURSOR(txs_prunable);
  }

  blocks.reserve(std::min<size_t>(max_block_count, 10000)); // guard against very large max count if only checking bytes
  const uint64_t blockchain_height = height();
  uint64_t size = 0;
  size_t num_txes = 0;
  MDB_val_copy<uint64_t> key(start_height);
  MDB_val v, val_tx_id;
  uint64_t tx_id = ~0;
  for (uint64_t h = start_height; h < blockchain_height && blocks.size() < max_block_count && (size < max_size || blocks.size() < min_block_count); ++h)
  {
    MDB_cursor_op op = h == start_height ? MDB_SET : MDB_NEXT;
    int result = mdb_cursor_get(m_cur_blocks, &key, &v, op);
    if (result == MDB_NOTFOUND)
      throw0(BLOCK_DNE(std::string("Attempt to get block from height ").append(boost::lexical_cast<std::string>(h)).append(" failed -- block not in db").c_str()));
    else if (result)
      throw0(DB_ERROR(lmdb_error("Error attempting to retrieve a block from the db", result).c_str()));

    blocks.resize(blocks.size() + 1);
    auto &current_block = blocks.back();

    current_block.first.first.assign(reinterpret_cast<char*>(v.mv_data), v.mv_size);
    size += v.mv_size;

    cryptonote::block b;
    if (!parse_and_validate_block_from_blob(current_block.first.first, b))
      throw0(DB_ERROR("Invalid block"));
    current_block.first.second = get_miner_tx_hash ? cryptonote::get_transaction_hash(b.miner_tx) : crypto::null_hash;

    // get the tx_id for the first tx (the first block's coinbase tx)
    if (h == start_height)
    {
      crypto::hash hash = cryptonote::get_transaction_hash(b.miner_tx);
      MDB_val_set(v, hash);
      result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
      if (result)
        throw0(DB_ERROR(lmdb_error("Error attempting to retrieve block coinbase transaction from the db: ", result).c_str()));

      const txindex *tip = (const txindex *)v.mv_data;
      tx_id = tip->data.tx_id;
      val_tx_id.mv_data = &tx_id;
      val_tx_id.mv_size = sizeof(tx_id);
    }

    if (skip_coinbase)
    {
      result = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, &v, op);
      if (result)
        throw0(DB_ERROR(lmdb_error("Error attempting to retrieve transaction data from the db: ", result).c_str()));
      if (!pruned)
      {
        result = mdb_cursor_get(m_cur_txs_prunable, &val_tx_id, &v, op);
        if (result)
          throw0(DB_ERROR(lmdb_error("Error attempting to retrieve transaction data from the db: ", result).c_str()));
      }
    }

    op = MDB_NEXT;

    current_block.second.reserve(b.tx_hashes.size());
    num_txes += b.tx_hashes.size() + (skip_coinbase ? 0 : 1);
    for (const auto &tx_hash: b.tx_hashes)
    {
      // get pruned data
      cryptonote::blobdata tx_blob;
      result = mdb_cursor_get(m_cur_txs_pruned, &val_tx_id, &v, op);
      if (result)
        throw0(DB_ERROR(lmdb_error("Error attempting to retrieve transaction data from the db: ", result).c_str()));
      tx_blob.assign((const char*)v.mv_data, v.mv_size);
      {
        MDB_val vpqc = {0, nullptr};
        (void)mdb_cursor_get(m_cur_txs_pqc_auths, &val_tx_id, &vpqc, MDB_SET);
        if (vpqc.mv_size)
          tx_blob.append(reinterpret_cast<const char*>(vpqc.mv_data), vpqc.mv_size);
      }

      if (!pruned)
      {
        result = mdb_cursor_get(m_cur_txs_prunable, &val_tx_id, &v, op);
        if (result)
          throw0(DB_ERROR(lmdb_error("Error attempting to retrieve transaction data from the db: ", result).c_str()));
        tx_blob.append(reinterpret_cast<const char*>(v.mv_data), v.mv_size);
      }
      current_block.second.push_back(std::make_pair(tx_hash, std::move(tx_blob)));
      size += current_block.second.back().second.size();
    }

    if (blocks.size() >= min_block_count && num_txes >= max_tx_count)
      break;
  }

  TXN_POSTFIX_RDONLY();

  return true;
}

bool BlockchainLMDB::get_prunable_tx_blob(const crypto::hash& h, cryptonote::blobdata &bd) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);
  RCURSOR(txs_prunable);

  MDB_val_set(v, h);
  MDB_val result;
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == 0)
  {
    const txindex *tip = (const txindex *)v.mv_data;
    MDB_val_set(val_tx_id, tip->data.tx_id);
    get_result = mdb_cursor_get(m_cur_txs_prunable, &val_tx_id, &result, MDB_SET);
  }
  if (get_result == MDB_NOTFOUND)
    return false;
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx from hash", get_result).c_str()));

  bd.assign(reinterpret_cast<char*>(result.mv_data), result.mv_size);

  TXN_POSTFIX_RDONLY();

  return true;
}

bool BlockchainLMDB::get_prunable_tx_hash(const crypto::hash& tx_hash, crypto::hash &prunable_hash) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);
  RCURSOR(txs_prunable_hash);

  MDB_val_set(v, tx_hash);
  MDB_val result;
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == 0)
  {
    txindex *tip = (txindex *)v.mv_data;
    MDB_val_set(val_tx_id, tip->data.tx_id);
    get_result = mdb_cursor_get(m_cur_txs_prunable_hash, &val_tx_id, &result, MDB_SET);
  }
  if (get_result == MDB_NOTFOUND)
    return false;
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx prunable hash from tx hash", get_result).c_str()));

  prunable_hash = *(const crypto::hash*)result.mv_data;

  TXN_POSTFIX_RDONLY();

  return true;
}

uint64_t BlockchainLMDB::get_tx_count() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  int result;

  MDB_stat db_stats;
  if ((result = mdb_stat(m_txn, m_txs_pruned, &db_stats)))
    throw0(DB_ERROR(lmdb_error("Failed to query m_txs_pruned: ", result).c_str()));

  TXN_POSTFIX_RDONLY();

  return db_stats.ms_entries;
}

std::vector<transaction> BlockchainLMDB::get_tx_list(const std::vector<crypto::hash>& hlist) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  std::vector<transaction> v;

  for (auto& h : hlist)
  {
    v.push_back(get_tx(h));
  }

  return v;
}

uint64_t BlockchainLMDB::get_tx_id(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);

  MDB_val_set(v, h);
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw1(TX_DNE(std::string("tx_data_t with hash ").append(epee::string_tools::pod_to_hex(h)).append(" not found in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx id from hash", get_result).c_str()));

  txindex *tip = (txindex *)v.mv_data;
  uint64_t ret = tip->data.tx_id;
  TXN_POSTFIX_RDONLY();
  return ret;
}

uint64_t BlockchainLMDB::get_tx_block_height(const crypto::hash& h) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_indices);

  MDB_val_set(v, h);
  auto get_result = mdb_cursor_get(m_cur_tx_indices, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
  {
    throw1(TX_DNE(std::string("tx_data_t with hash ").append(epee::string_tools::pod_to_hex(h)).append(" not found in db").c_str()));
  }
  else if (get_result)
    throw0(DB_ERROR(lmdb_error("DB error attempting to fetch tx height from hash", get_result).c_str()));

  txindex *tip = (txindex *)v.mv_data;
  uint64_t ret = tip->data.block_id;
  TXN_POSTFIX_RDONLY();
  return ret;
}

uint64_t BlockchainLMDB::get_num_outputs(const uint64_t& amount) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  MDB_val_copy<uint64_t> k(amount);
  MDB_val v;
  mdb_size_t num_elems = 0;
  auto result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_SET);
  if (result == MDB_SUCCESS)
  {
    mdb_cursor_count(m_cur_output_amounts, &num_elems);
  }
  else if (result != MDB_NOTFOUND)
    throw0(DB_ERROR("DB error attempting to get number of outputs of an amount"));

  TXN_POSTFIX_RDONLY();

  return num_elems;
}

output_data_t BlockchainLMDB::get_output_key(const uint64_t& amount, const uint64_t& index, bool include_commitmemt) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  MDB_val_set(k, amount);
  MDB_val_set(v, index);
  auto get_result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
    throw1(OUTPUT_DNE(std::string("Attempting to get output pubkey by index, but key does not exist: amount " +
        std::to_string(amount) + ", index " + std::to_string(index)).c_str()));
  else if (get_result)
    throw0(DB_ERROR("Error attempting to retrieve an output pubkey from the db"));

  // Shekyl: all outputs are RCT (amount == 0 table). No pre-RCT outputs exist.
  if (amount != 0)
    throw0(DB_ERROR("Non-zero amount in output lookup — Shekyl has no pre-RCT outputs"));
  output_data_t ret;
  const outkey *okp = (const outkey *)v.mv_data;
  ret = okp->data;
  TXN_POSTFIX_RDONLY();
  return ret;
}

tx_out_index BlockchainLMDB::get_output_tx_and_index_from_global(const uint64_t& output_id) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_txs);

  MDB_val_set(v, output_id);

  auto get_result = mdb_cursor_get(m_cur_output_txs, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
  if (get_result == MDB_NOTFOUND)
    throw1(OUTPUT_DNE("output with given index not in db"));
  else if (get_result)
    throw0(DB_ERROR("DB error attempting to fetch output tx hash"));

  outtx *ot = (outtx *)v.mv_data;
  tx_out_index ret = tx_out_index(ot->tx_hash, ot->local_index);

  TXN_POSTFIX_RDONLY();
  return ret;
}

tx_out_index BlockchainLMDB::get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  std::vector < uint64_t > offsets;
  std::vector<tx_out_index> indices;
  offsets.push_back(index);
  get_output_tx_and_index(amount, offsets, indices);
  if (!indices.size())
    throw1(OUTPUT_DNE("Attempting to get an output index by amount and amount index, but amount not found"));

  return indices[0];
}

std::vector<std::vector<uint64_t>> BlockchainLMDB::get_tx_amount_output_indices(uint64_t tx_id, size_t n_txes) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(tx_outputs);

  MDB_val_set(k_tx_id, tx_id);
  MDB_val v;
  std::vector<std::vector<uint64_t>> amount_output_indices_set;
  amount_output_indices_set.reserve(n_txes);

  MDB_cursor_op op = MDB_SET;
  while (n_txes-- > 0)
  {
    int result = mdb_cursor_get(m_cur_tx_outputs, &k_tx_id, &v, op);
    if (result == MDB_NOTFOUND)
      LOG_PRINT_L0("WARNING: Unexpected: tx has no amount indices stored in "
          "tx_outputs, but it should have an empty entry even if it's a tx without "
          "outputs");
    else if (result)
      throw0(DB_ERROR(lmdb_error("DB error attempting to get data for tx_outputs[tx_index]", result).c_str()));

    op = MDB_NEXT;

    const uint64_t* indices = (const uint64_t*)v.mv_data;
    size_t num_outputs = v.mv_size / sizeof(uint64_t);

    amount_output_indices_set.resize(amount_output_indices_set.size() + 1);
    std::vector<uint64_t> &amount_output_indices = amount_output_indices_set.back();
    amount_output_indices.reserve(num_outputs);
    for (size_t i = 0; i < num_outputs; ++i)
    {
      amount_output_indices.push_back(indices[i]);
    }
  }

  TXN_POSTFIX_RDONLY();
  return amount_output_indices_set;
}

bool BlockchainLMDB::has_key_image(const crypto::key_image& img) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  bool ret;

  TXN_PREFIX_RDONLY();
  RCURSOR(spent_keys);

  MDB_val k = {sizeof(img), (void *)&img};
  ret = (mdb_cursor_get(m_cur_spent_keys, (MDB_val *)&zerokval, &k, MDB_GET_BOTH) == 0);

  TXN_POSTFIX_RDONLY();
  return ret;
}

std::vector<bool> BlockchainLMDB::has_key_images(const epee::span<const crypto::key_image> img) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  std::vector<bool> ret(img.size(), true);

  TXN_PREFIX_RDONLY();
  RCURSOR(spent_keys);

  for (std::size_t i = 0; i < img.size(); ++i)
  {
    crypto::key_image ki = img[i];
    MDB_val k = {sizeof(ki), reinterpret_cast<void*>(&ki)};
    ret[i] = (mdb_cursor_get(m_cur_spent_keys, const_cast<MDB_val *>(&zerokval), &k, MDB_GET_BOTH) == 0);
  }

  TXN_POSTFIX_RDONLY();
  return ret;
}

bool BlockchainLMDB::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(spent_keys);

  MDB_val k, v;
  bool fret = true;

  k = zerokval;
  MDB_cursor_op op = MDB_FIRST;
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_spent_keys, &k, &v, op);
    op = MDB_NEXT;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret < 0)
      throw0(DB_ERROR("Failed to enumerate key images"));
    const crypto::key_image k_image = *(const crypto::key_image*)v.mv_data;
    if (!f(k_image)) {
      fret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return fret;
}

bool BlockchainLMDB::for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)> f) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(blocks);

  MDB_val k;
  MDB_val v;
  bool fret = true;

  MDB_cursor_op op;
  if (h1)
  {
    k = MDB_val{sizeof(h1), (void*)&h1};
    op = MDB_SET;
  } else
  {
    op = MDB_FIRST;
  }
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_blocks, &k, &v, op);
    op = MDB_NEXT;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR("Failed to enumerate blocks"));
    uint64_t height = *(const uint64_t*)k.mv_data;
    blobdata_ref bd{reinterpret_cast<char*>(v.mv_data), v.mv_size};
    block b;
    if (!parse_and_validate_block_from_blob(bd, b))
      throw0(DB_ERROR("Failed to parse block from blob retrieved from the db"));
    crypto::hash hash;
    if (!get_block_hash(b, hash))
        throw0(DB_ERROR("Failed to get block hash from blob retrieved from the db"));
    if (!f(height, hash, b)) {
      fret = false;
      break;
    }
    if (height >= h2)
      break;
  }

  TXN_POSTFIX_RDONLY();

  return fret;
}

bool BlockchainLMDB::for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f, bool pruned) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(txs_pruned);
  RCURSOR(txs_pqc_auths);
  RCURSOR(txs_prunable);
  RCURSOR(tx_indices);

  MDB_val k;
  MDB_val v;
  bool fret = true;

  MDB_cursor_op op = MDB_FIRST;
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_tx_indices, &k, &v, op);
    op = MDB_NEXT;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR(lmdb_error("Failed to enumerate transactions: ", ret).c_str()));

    txindex *ti = (txindex *)v.mv_data;
    const crypto::hash hash = ti->key;
    k.mv_data = (void *)&ti->data.tx_id;
    k.mv_size = sizeof(ti->data.tx_id);

    ret = mdb_cursor_get(m_cur_txs_pruned, &k, &v, MDB_SET);
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR(lmdb_error("Failed to enumerate transactions: ", ret).c_str()));
    transaction tx;
    if (pruned)
    {
      cryptonote::blobdata bd;
      bd.assign(reinterpret_cast<char*>(v.mv_data), v.mv_size);
      MDB_val vpqc = {0, nullptr};
      (void)mdb_cursor_get(m_cur_txs_pqc_auths, &k, &vpqc, MDB_SET);
      if (vpqc.mv_size)
        bd.append(reinterpret_cast<char*>(vpqc.mv_data), vpqc.mv_size);
      if (!parse_and_validate_tx_base_from_blob(bd, tx))
        throw0(DB_ERROR("Failed to parse tx from blob retrieved from the db"));
    }
    else
    {
      blobdata bd;
      bd.assign(reinterpret_cast<char*>(v.mv_data), v.mv_size);
      MDB_val vpqc = {0, nullptr};
      (void)mdb_cursor_get(m_cur_txs_pqc_auths, &k, &vpqc, MDB_SET);
      if (vpqc.mv_size)
        bd.append(reinterpret_cast<char*>(vpqc.mv_data), vpqc.mv_size);
      ret = mdb_cursor_get(m_cur_txs_prunable, &k, &v, MDB_SET);
      if (ret)
        throw0(DB_ERROR(lmdb_error("Failed to get prunable tx data the db: ", ret).c_str()));
      bd.append(reinterpret_cast<char*>(v.mv_data), v.mv_size);
      if (!parse_and_validate_tx_from_blob(bd, tx))
        throw0(DB_ERROR("Failed to parse tx from blob retrieved from the db"));
    }
    if (!f(hash, tx)) {
      fret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return fret;
}

bool BlockchainLMDB::for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  MDB_val k;
  MDB_val v;
  bool fret = true;

  MDB_cursor_op op = MDB_FIRST;
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_output_amounts, &k, &v, op);
    op = MDB_NEXT;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR("Failed to enumerate outputs"));
    uint64_t amount = *(const uint64_t*)k.mv_data;
    outkey *ok = (outkey *)v.mv_data;
    tx_out_index toi = get_output_tx_and_index_from_global(ok->output_id);
    if (!f(amount, toi.first, ok->data.height, toi.second)) {
      fret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return fret;
}

bool BlockchainLMDB::for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  MDB_val_set(k, amount);
  MDB_val v;
  bool fret = true;

  MDB_cursor_op op = MDB_SET;
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_output_amounts, &k, &v, op);
    op = MDB_NEXT_DUP;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR("Failed to enumerate outputs"));
    uint64_t out_amount = *(const uint64_t*)k.mv_data;
    if (amount != out_amount)
    {
      MERROR("Amount is not the expected amount");
      fret = false;
      break;
    }
    const outkey *ok = (const outkey *)v.mv_data;
    if (!f(ok->data.height)) {
      fret = false;
      break;
    }
  }

  TXN_POSTFIX_RDONLY();

  return fret;
}

// batch_num_blocks: (optional) Used to check if resize needed before batch transaction starts.
bool BlockchainLMDB::batch_start(uint64_t batch_num_blocks, uint64_t batch_bytes)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (! m_batch_transactions)
    throw0(DB_ERROR("batch transactions not enabled"));
  if (m_batch_active)
    return false;
  if (m_write_batch_txn != nullptr)
    return false;
  if (m_write_txn)
    throw0(DB_ERROR("batch transaction attempted, but m_write_txn already in use"));
  check_open();

  m_writer = boost::this_thread::get_id();
  check_and_resize_for_batch(batch_num_blocks, batch_bytes);

  m_write_batch_txn = new mdb_txn_safe();

  // NOTE: need to make sure it's destroyed properly when done
  if (auto mdb_res = lmdb_txn_begin(m_env, NULL, 0, *m_write_batch_txn))
  {
    delete m_write_batch_txn;
    m_write_batch_txn = nullptr;
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", mdb_res).c_str()));
  }
  // indicates this transaction is for batch transactions, but not whether it's
  // active
  m_write_batch_txn->m_batch_txn = true;
  m_write_txn = m_write_batch_txn;

  m_batch_active = true;
  memset(&m_wcursors, 0, sizeof(m_wcursors));
  if (m_tinfo.get())
  {
    if (m_tinfo->m_ti_rflags.m_rf_txn)
      mdb_txn_reset(m_tinfo->m_ti_rtxn);
    memset(&m_tinfo->m_ti_rflags, 0, sizeof(m_tinfo->m_ti_rflags));
  }

  LOG_PRINT_L3("batch transaction: begin");
  return true;
}

void BlockchainLMDB::batch_commit()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (! m_batch_transactions)
    throw0(DB_ERROR("batch transactions not enabled"));
  if (! m_batch_active)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_write_batch_txn == nullptr)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_writer != boost::this_thread::get_id())
    throw1(DB_ERROR("batch transaction owned by other thread"));

  check_open();

  LOG_PRINT_L3("batch transaction: committing...");
  TIME_MEASURE_START(time1);
  m_write_txn->commit();
  TIME_MEASURE_FINISH(time1);
  time_commit1 += time1;
  LOG_PRINT_L3("batch transaction: committed");

  m_write_txn = nullptr;
  delete m_write_batch_txn;
  m_write_batch_txn = nullptr;
  memset(&m_wcursors, 0, sizeof(m_wcursors));
}

void BlockchainLMDB::cleanup_batch()
{
  // for destruction of batch transaction
  m_write_txn = nullptr;
  delete m_write_batch_txn;
  m_write_batch_txn = nullptr;
  m_batch_active = false;
  memset(&m_wcursors, 0, sizeof(m_wcursors));
}

void BlockchainLMDB::batch_stop()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (! m_batch_transactions)
    throw0(DB_ERROR("batch transactions not enabled"));
  if (! m_batch_active)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_write_batch_txn == nullptr)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_writer != boost::this_thread::get_id())
    throw1(DB_ERROR("batch transaction owned by other thread"));
  check_open();
  LOG_PRINT_L3("batch transaction: committing...");
  TIME_MEASURE_START(time1);
  try
  {
    m_write_txn->commit();
    TIME_MEASURE_FINISH(time1);
    time_commit1 += time1;
    cleanup_batch();
  }
  catch (const std::exception &e)
  {
    cleanup_batch();
    throw;
  }
  LOG_PRINT_L3("batch transaction: end");
}

void BlockchainLMDB::batch_abort()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (! m_batch_transactions)
    throw0(DB_ERROR("batch transactions not enabled"));
  if (! m_batch_active)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_write_batch_txn == nullptr)
    throw1(DB_ERROR("batch transaction not in progress"));
  if (m_writer != boost::this_thread::get_id())
    throw1(DB_ERROR("batch transaction owned by other thread"));
  check_open();
  // for destruction of batch transaction
  m_write_txn = nullptr;
  // explicitly call in case mdb_env_close() (BlockchainLMDB::close()) called before BlockchainLMDB destructor called.
  m_write_batch_txn->abort();
  delete m_write_batch_txn;
  m_write_batch_txn = nullptr;
  m_batch_active = false;
  memset(&m_wcursors, 0, sizeof(m_wcursors));
  LOG_PRINT_L3("batch transaction: aborted");
}

void BlockchainLMDB::set_batch_transactions(bool batch_transactions)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if ((batch_transactions) && (m_batch_transactions))
  {
    MINFO("batch transaction mode already enabled, but asked to enable batch mode");
  }
  m_batch_transactions = batch_transactions;
  MINFO("batch transactions " << (m_batch_transactions ? "enabled" : "disabled"));
}

// return true if we started the txn, false if already started
bool BlockchainLMDB::block_rtxn_start(MDB_txn **mtxn, mdb_txn_cursors **mcur) const
{
  bool ret = false;
  mdb_threadinfo *tinfo;
  if (m_write_txn && m_writer == boost::this_thread::get_id()) {
    *mtxn = m_write_txn->m_txn;
    *mcur = (mdb_txn_cursors *)&m_wcursors;
    return ret;
  }
  /* Check for existing info and force reset if env doesn't match -
   * only happens if env was opened/closed multiple times in same process
   */
  if (!(tinfo = m_tinfo.get()) || mdb_txn_env(tinfo->m_ti_rtxn) != m_env)
  {
    tinfo = new mdb_threadinfo;
    m_tinfo.reset(tinfo);
    memset(&tinfo->m_ti_rcursors, 0, sizeof(tinfo->m_ti_rcursors));
    memset(&tinfo->m_ti_rflags, 0, sizeof(tinfo->m_ti_rflags));
    if (auto mdb_res = lmdb_txn_begin(m_env, NULL, MDB_RDONLY, &tinfo->m_ti_rtxn))
      throw0(DB_ERROR_TXN_START(lmdb_error("Failed to create a read transaction for the db: ", mdb_res).c_str()));
    ret = true;
  } else if (!tinfo->m_ti_rflags.m_rf_txn)
  {
    if (auto mdb_res = lmdb_txn_renew(tinfo->m_ti_rtxn))
      throw0(DB_ERROR_TXN_START(lmdb_error("Failed to renew a read transaction for the db: ", mdb_res).c_str()));
    ret = true;
  }
  if (ret)
    tinfo->m_ti_rflags.m_rf_txn = true;
  *mtxn = tinfo->m_ti_rtxn;
  *mcur = &tinfo->m_ti_rcursors;

  if (ret)
    LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  return ret;
}

void BlockchainLMDB::block_rtxn_stop() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  mdb_txn_reset(m_tinfo->m_ti_rtxn);
  memset(&m_tinfo->m_ti_rflags, 0, sizeof(m_tinfo->m_ti_rflags));
  /* cancel out the increment from rtxn_start */
  mdb_txn_safe::increment_txns(-1);
}

bool BlockchainLMDB::block_rtxn_start() const
{
  MDB_txn *mtxn;
  mdb_txn_cursors *mcur;
  /* auto_txn is only used for the create gate */
  mdb_txn_safe auto_txn;
  bool ret = block_rtxn_start(&mtxn, &mcur);
  if (ret)
    auto_txn.increment_txns(1); /* remember there is an active readtxn */
  return ret;
}

void BlockchainLMDB::block_wtxn_start()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // Distinguish the exceptions here from exceptions that would be thrown while
  // using the txn and committing it.
  //
  // If an exception is thrown in this setup, we don't want the caller to catch
  // it and proceed as if there were an existing write txn, such as trying to
  // call block_txn_abort(). It also indicates a serious issue which will
  // probably be thrown up another layer.
  if (! m_batch_active && m_write_txn)
    throw0(DB_ERROR_TXN_START((std::string("Attempted to start new write txn when write txn already exists in ")+__FUNCTION__).c_str()));
  if (! m_batch_active)
  {
    m_writer = boost::this_thread::get_id();
    m_write_txn = new mdb_txn_safe();
    if (auto mdb_res = lmdb_txn_begin(m_env, NULL, 0, *m_write_txn))
    {
      delete m_write_txn;
      m_write_txn = nullptr;
      throw0(DB_ERROR_TXN_START(lmdb_error("Failed to create a transaction for the db: ", mdb_res).c_str()));
    }
    memset(&m_wcursors, 0, sizeof(m_wcursors));
    if (m_tinfo.get())
    {
      if (m_tinfo->m_ti_rflags.m_rf_txn)
        mdb_txn_reset(m_tinfo->m_ti_rtxn);
      memset(&m_tinfo->m_ti_rflags, 0, sizeof(m_tinfo->m_ti_rflags));
    }
  } else if (m_writer != boost::this_thread::get_id())
    throw0(DB_ERROR_TXN_START((std::string("Attempted to start new write txn when batch txn already exists in ")+__FUNCTION__).c_str()));
}

void BlockchainLMDB::block_wtxn_stop()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (!m_write_txn)
    throw0(DB_ERROR_TXN_START((std::string("Attempted to stop write txn when no such txn exists in ")+__FUNCTION__).c_str()));
  if (m_writer != boost::this_thread::get_id())
    throw0(DB_ERROR_TXN_START((std::string("Attempted to stop write txn from the wrong thread in ")+__FUNCTION__).c_str()));
  {
    if (! m_batch_active)
	{
      TIME_MEASURE_START(time1);
      m_write_txn->commit();
      TIME_MEASURE_FINISH(time1);
      time_commit1 += time1;

      delete m_write_txn;
      m_write_txn = nullptr;
      memset(&m_wcursors, 0, sizeof(m_wcursors));
	}
  }
}

void BlockchainLMDB::block_wtxn_abort()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  if (!m_write_txn)
    throw0(DB_ERROR_TXN_START((std::string("Attempted to abort write txn when no such txn exists in ")+__FUNCTION__).c_str()));
  if (m_writer != boost::this_thread::get_id())
    throw0(DB_ERROR_TXN_START((std::string("Attempted to abort write txn from the wrong thread in ")+__FUNCTION__).c_str()));

  if (! m_batch_active)
  {
    delete m_write_txn;
    m_write_txn = nullptr;
    memset(&m_wcursors, 0, sizeof(m_wcursors));
  }
}

void BlockchainLMDB::block_rtxn_abort() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  mdb_txn_reset(m_tinfo->m_ti_rtxn);
  memset(&m_tinfo->m_ti_rflags, 0, sizeof(m_tinfo->m_ti_rflags));
}

uint64_t BlockchainLMDB::add_block(const std::pair<block, blobdata>& blk, size_t block_weight, uint64_t long_term_block_weight, const difficulty_type& cumulative_difficulty, const uint64_t& coins_generated,
    uint64_t archival_budget_accrual, const blobdata& attestation_witness, const std::vector<std::pair<transaction, blobdata>>& txs)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  uint64_t m_height = height();

  if (m_height % 1024 == 0)
  {
    // for batch mode, DB resize check is done at start of batch transaction
    if (! m_batch_active && need_resize())
    {
      LOG_PRINT_L0("LMDB memory map needs to be resized, doing that now.");
      do_resize();
    }
  }

  try
  {
    BlockchainDB::add_block(blk, block_weight, long_term_block_weight, cumulative_difficulty, coins_generated, archival_budget_accrual, attestation_witness, txs);
  }
  catch (const DB_ERROR_TXN_START& e)
  {
    throw;
  }

  return ++m_height;
}

void BlockchainLMDB::pop_block(block& blk, std::vector<transaction>& txs)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  block_wtxn_start();

  try
  {
    BlockchainDB::pop_block(blk, txs);
    block_wtxn_stop();
  }
  catch (...)
  {
    block_wtxn_abort();
    throw;
  }
}

void BlockchainLMDB::get_output_tx_and_index_from_global(const std::vector<uint64_t> &global_indices,
    std::vector<tx_out_index> &tx_out_indices) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  tx_out_indices.clear();
  tx_out_indices.reserve(global_indices.size());

  TXN_PREFIX_RDONLY();
  RCURSOR(output_txs);

  for (const uint64_t &output_id : global_indices)
  {
    MDB_val_set(v, output_id);

    auto get_result = mdb_cursor_get(m_cur_output_txs, (MDB_val *)&zerokval, &v, MDB_GET_BOTH);
    if (get_result == MDB_NOTFOUND)
      throw1(OUTPUT_DNE("output with given index not in db"));
    else if (get_result)
      throw0(DB_ERROR("DB error attempting to fetch output tx hash"));

    const outtx *ot = (const outtx *)v.mv_data;
    tx_out_indices.push_back(tx_out_index(ot->tx_hash, ot->local_index));
  }

  TXN_POSTFIX_RDONLY();
}

void BlockchainLMDB::get_output_key(const epee::span<const uint64_t> &amounts, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, bool allow_partial) const
{
  if (amounts.size() != 1 && amounts.size() != offsets.size())
    throw0(DB_ERROR("Invalid sizes of amounts and offsets"));

  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  TIME_MEASURE_START(db3);
  check_open();
  outputs.clear();
  outputs.reserve(offsets.size());

  TXN_PREFIX_RDONLY();

  RCURSOR(output_amounts);

  for (size_t i = 0; i < offsets.size(); ++i)
  {
    const uint64_t amount = amounts.size() == 1 ? amounts[0] : amounts[i];
    MDB_val_set(k, amount);
    MDB_val_set(v, offsets[i]);

    auto get_result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_GET_BOTH);
    if (get_result == MDB_NOTFOUND)
    {
      if (allow_partial)
      {
        MDEBUG("Partial result: " << outputs.size() << "/" << offsets.size());
        break;
      }
      throw1(OUTPUT_DNE((std::string("Attempting to get output pubkey by global index (amount ") + boost::lexical_cast<std::string>(amount) + ", index " + boost::lexical_cast<std::string>(offsets[i]) + ", count " + boost::lexical_cast<std::string>(get_num_outputs(amount)) + "), but key does not exist (current height " + boost::lexical_cast<std::string>(height()) + ")").c_str()));
    }
    else if (get_result)
      throw0(DB_ERROR(lmdb_error("Error attempting to retrieve an output pubkey from the db", get_result).c_str()));

    if (amount != 0)
      throw0(DB_ERROR("Non-zero amount in batch output lookup — Shekyl has no pre-RCT outputs"));
    const outkey *okp = (const outkey *)v.mv_data;
    outputs.push_back(okp->data);
  }

  TXN_POSTFIX_RDONLY();

  TIME_MEASURE_FINISH(db3);
  LOG_PRINT_L3("db3: " << db3);
}

void BlockchainLMDB::get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  indices.clear();

  std::vector <uint64_t> tx_indices;
  tx_indices.reserve(offsets.size());
  TXN_PREFIX_RDONLY();

  RCURSOR(output_amounts);

  MDB_val_set(k, amount);
  for (const uint64_t &index : offsets)
  {
    MDB_val_set(v, index);

    auto get_result = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_GET_BOTH);
    if (get_result == MDB_NOTFOUND)
      throw1(OUTPUT_DNE("Attempting to get output by index, but key does not exist"));
    else if (get_result)
      throw0(DB_ERROR(lmdb_error("Error attempting to retrieve an output from the db", get_result).c_str()));

    const outkey *okp = (const outkey *)v.mv_data;
    tx_indices.push_back(okp->output_id);
  }

  TIME_MEASURE_START(db3);
  if(tx_indices.size() > 0)
  {
    get_output_tx_and_index_from_global(tx_indices, indices);
  }
  TIME_MEASURE_FINISH(db3);
  LOG_PRINT_L3("db3: " << db3);
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> BlockchainLMDB::get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
  MDB_val k;
  MDB_val v;

  if (amounts.empty())
  {
    MDB_cursor_op op = MDB_FIRST;
    while (1)
    {
      int ret = mdb_cursor_get(m_cur_output_amounts, &k, &v, op);
      op = MDB_NEXT_NODUP;
      if (ret == MDB_NOTFOUND)
        break;
      if (ret)
        throw0(DB_ERROR(lmdb_error("Failed to enumerate outputs: ", ret).c_str()));
      mdb_size_t num_elems = 0;
      mdb_cursor_count(m_cur_output_amounts, &num_elems);
      uint64_t amount = *(const uint64_t*)k.mv_data;
      if (num_elems >= min_count)
        histogram[amount] = std::make_tuple(num_elems, 0, 0);
    }
  }
  else
  {
    for (const auto &amount: amounts)
    {
      MDB_val_copy<uint64_t> k(amount);
      int ret = mdb_cursor_get(m_cur_output_amounts, &k, &v, MDB_SET);
      if (ret == MDB_NOTFOUND)
      {
        if (0 >= min_count)
          histogram[amount] = std::make_tuple(0, 0, 0);
      }
      else if (ret == MDB_SUCCESS)
      {
        mdb_size_t num_elems = 0;
        mdb_cursor_count(m_cur_output_amounts, &num_elems);
        if (num_elems >= min_count)
          histogram[amount] = std::make_tuple(num_elems, 0, 0);
      }
      else
      {
        throw0(DB_ERROR(lmdb_error("Failed to enumerate outputs: ", ret).c_str()));
      }
    }
  }

  if (unlocked || recent_cutoff > 0) {
    const uint64_t blockchain_height = height();
    for (std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>::iterator i = histogram.begin(); i != histogram.end(); ++i) {
      uint64_t amount = i->first;
      uint64_t num_elems = std::get<0>(i->second);
      while (num_elems > 0) {
        const tx_out_index toi = get_output_tx_and_index(amount, num_elems - 1);
        const uint64_t height = get_tx_block_height(toi.first);
        if (height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE <= blockchain_height)
          break;
        --num_elems;
      }
      // modifying second does not invalidate the iterator
      std::get<1>(i->second) = num_elems;

      if (recent_cutoff > 0)
      {
        uint64_t recent = 0;
        while (num_elems > 0) {
          const tx_out_index toi = get_output_tx_and_index(amount, num_elems - 1);
          const uint64_t height = get_tx_block_height(toi.first);
          const uint64_t ts = get_block_timestamp(height);
          if (ts < recent_cutoff)
            break;
          --num_elems;
          ++recent;
        }
        // modifying second does not invalidate the iterator
        std::get<2>(i->second) = recent;
      }
    }
  }

  TXN_POSTFIX_RDONLY();

  return histogram;
}

bool BlockchainLMDB::get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, std::vector<uint64_t> &distribution, uint64_t &base) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(output_amounts);

  distribution.clear();
  const uint64_t db_height = height();
  if (from_height >= db_height)
    return false;
  distribution.resize(db_height - from_height, 0);

  MDB_val_set(k, amount);
  MDB_val v;
  MDB_cursor_op op = MDB_SET;
  base = 0;
  while (1)
  {
    int ret = mdb_cursor_get(m_cur_output_amounts, &k, &v, op);
    op = MDB_NEXT_DUP;
    if (ret == MDB_NOTFOUND)
      break;
    if (ret)
      throw0(DB_ERROR("Failed to enumerate outputs"));
    const outkey *ok = (const outkey *)v.mv_data;
    const uint64_t height = ok->data.height;
    if (height >= from_height)
      distribution[height - from_height]++;
    else
      base++;
    if (to_height > 0 && height > to_height)
      break;
  }

  distribution[0] += base;
  for (size_t n = 1; n < distribution.size(); ++n)
    distribution[n] += distribution[n - 1];
  base = 0;

  TXN_POSTFIX_RDONLY();

  return true;
}

void BlockchainLMDB::check_hard_fork_info()
{
}

void BlockchainLMDB::drop_hard_fork_info()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX(0);

  auto result = mdb_drop(*txn_ptr, m_hf_starting_heights, 1);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error dropping hard fork starting heights db: ", result).c_str()));
  result = mdb_drop(*txn_ptr, m_hf_versions, 1);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error dropping hard fork versions db: ", result).c_str()));

  TXN_POSTFIX_SUCCESS();
}

void BlockchainLMDB::set_hard_fork_version(uint64_t height, uint8_t version)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_BLOCK_PREFIX(0);

  MDB_val_copy<uint64_t> val_key(height);
  MDB_val_copy<uint8_t> val_value(version);
  int result;
  result = mdb_put(*txn_ptr, m_hf_versions, &val_key, &val_value, MDB_APPEND);
  if (result == MDB_KEYEXIST)
    result = mdb_put(*txn_ptr, m_hf_versions, &val_key, &val_value, 0);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error adding hard fork version to db transaction: ", result).c_str()));

  TXN_BLOCK_POSTFIX_SUCCESS();
}

uint8_t BlockchainLMDB::get_hard_fork_version(uint64_t height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(hf_versions);

  MDB_val_copy<uint64_t> val_key(height);
  MDB_val val_ret;
  auto result = mdb_cursor_get(m_cur_hf_versions, &val_key, &val_ret, MDB_SET);
  if (result == MDB_NOTFOUND || result)
    throw0(DB_ERROR(lmdb_error("Error attempting to retrieve a hard fork version at height " + boost::lexical_cast<std::string>(height) + " from the db: ", result).c_str()));

  uint8_t ret = *(const uint8_t*)val_ret.mv_data;
  TXN_POSTFIX_RDONLY();
  return ret;
}

void BlockchainLMDB::add_alt_block(const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref &blob)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(alt_blocks)

  MDB_val k = {sizeof(blkid), (void *)&blkid};
  const size_t val_size = sizeof(alt_block_data_t) + blob.size();
  std::unique_ptr<char[]> val(new char[val_size]);
  memcpy(val.get(), &data, sizeof(alt_block_data_t));
  memcpy(val.get() + sizeof(alt_block_data_t), blob.data(), blob.size());
  MDB_val v = {val_size, (void *)val.get()};
  if (auto result = mdb_cursor_put(m_cur_alt_blocks, &k, &v, MDB_NODUPDATA)) {
    if (result == MDB_KEYEXIST)
      throw1(DB_ERROR("Attempting to add alternate block that's already in the db"));
    else
      throw1(DB_ERROR(lmdb_error("Error adding alternate block to db transaction: ", result).c_str()));
  }
}

bool BlockchainLMDB::get_alt_block(const crypto::hash &blkid, alt_block_data_t *data, cryptonote::blobdata *blob)
{
  LOG_PRINT_L3("BlockchainLMDB:: " << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(alt_blocks);

  MDB_val_set(k, blkid);
  MDB_val v;
  int result = mdb_cursor_get(m_cur_alt_blocks, &k, &v, MDB_SET);
  if (result == MDB_NOTFOUND)
    return false;

  if (result)
    throw0(DB_ERROR(lmdb_error("Error attempting to retrieve alternate block " + epee::string_tools::pod_to_hex(blkid) + " from the db: ", result).c_str()));
  if (v.mv_size < sizeof(alt_block_data_t))
    throw0(DB_ERROR("Record size is less than expected"));

  if (data)
    memcpy(data, v.mv_data, sizeof(alt_block_data_t));
  if (blob)
    blob->assign(((const char*)(v.mv_data)) + sizeof(alt_block_data_t), v.mv_size - sizeof(alt_block_data_t));

  TXN_POSTFIX_RDONLY();
  return true;
}

void BlockchainLMDB::remove_alt_block(const crypto::hash &blkid)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  mdb_txn_cursors *m_cursors = &m_wcursors;

  CURSOR(alt_blocks)

  MDB_val k = {sizeof(blkid), (void *)&blkid};
  MDB_val v;
  int result = mdb_cursor_get(m_cur_alt_blocks, &k, &v, MDB_SET);
  if (result)
    throw0(DB_ERROR(lmdb_error("Error locating alternate block " + epee::string_tools::pod_to_hex(blkid) + " in the db: ", result).c_str()));
  result = mdb_cursor_del(m_cur_alt_blocks, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Error deleting alternate block " + epee::string_tools::pod_to_hex(blkid) + " from the db: ", result).c_str()));
  // The alt block's attestation witness (if any) never outlives it (credit-wire CW-2).
  remove_archival_alt_attestation_witness(blkid);
}

uint64_t BlockchainLMDB::get_alt_block_count()
{
  LOG_PRINT_L3("BlockchainLMDB:: " << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  RCURSOR(alt_blocks);

  MDB_stat db_stats;
  int result = mdb_stat(m_txn, m_alt_blocks, &db_stats);
  uint64_t count = 0;
  if (result != MDB_NOTFOUND)
  {
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to query m_alt_blocks: ", result).c_str()));
    count = db_stats.ms_entries;
  }
  TXN_POSTFIX_RDONLY();
  return count;
}

void BlockchainLMDB::drop_alt_blocks()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX(0);

  auto result = mdb_drop(*txn_ptr, m_alt_blocks, 0);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error dropping alternative blocks: ", result).c_str()));
  // Drop the alt-chain attestation witnesses alongside their alt blocks (credit-wire CW-2).
  result = mdb_drop(*txn_ptr, m_archival_alt_attestation_witness, 0);
  if (result)
    throw1(DB_ERROR(lmdb_error("Error dropping alt attestation witnesses: ", result).c_str()));

  TXN_POSTFIX_SUCCESS();
}

bool BlockchainLMDB::is_read_only() const
{
  unsigned int flags;
  auto result = mdb_env_get_flags(m_env, &flags);
  if (result)
    throw0(DB_ERROR(lmdb_error("Error getting database environment info: ", result).c_str()));

  if (flags & MDB_RDONLY)
    return true;

  return false;
}

uint64_t BlockchainLMDB::get_database_size() const
{
  boost::filesystem::path datafile(m_folder);
  datafile /= CRYPTONOTE_BLOCKCHAINDATA_FILENAME;
  boost::system::error_code ec{};
  const boost::uintmax_t size = boost::filesystem::file_size(datafile, ec);
  return (ec ? 0 : static_cast<uint64_t>(size));
}

void BlockchainLMDB::fixup()
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // Always call parent as well
  BlockchainDB::fixup();
}

void BlockchainLMDB::add_block_burn(uint64_t height, uint64_t amount)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(height), (void *)&height};
  MDB_val v = {sizeof(amount), (void *)&amount};
  int result = mdb_put(*m_write_txn, m_block_burn, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add block burn: ", result).c_str()));
}

uint64_t BlockchainLMDB::get_block_burn(uint64_t height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(height), (void *)&height};
  MDB_val v;
  auto get_result = mdb_get(m_txn, m_block_burn, &k, &v);
  if (get_result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return 0;
  }
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get block burn: ", get_result).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR(("Bad block burn record at height " + std::to_string(height)
      + ": expected " + std::to_string(sizeof(uint64_t)) + " bytes, got "
      + std::to_string(v.mv_size)).c_str()));
  uint64_t amount;
  memcpy(&amount, v.mv_data, sizeof(amount));
  TXN_POSTFIX_RDONLY();
  return amount;
}

void BlockchainLMDB::remove_block_burn(uint64_t height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(height), (void *)&height};
  int result = mdb_del(*m_write_txn, m_block_burn, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove block burn: ", result).c_str()));
}

// ─── Archival budget accrual (ARCHIVAL_BUDGET_SCHEDULE.md §3.1) ─────────────
//
// The burn-record idiom over the archival table family's byte conventions:
// BE(height) key → BE(amount) value (big-endian so the close's bounded
// range-sum and the prune walk iterate in numeric height order — the family
// comment at the table opens applies; MDB_INTEGERKEY would be wrong here).

void BlockchainLMDB::add_archival_budget_accrual(uint64_t height, uint64_t amount)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBudgetAccrualKey key(height);
  uint8_t val_be[8];
  shekyl::db::store_be64(val_be, amount);
  MDB_val k = key.as_mdb_val();
  MDB_val v = { sizeof(val_be), val_be };
  int result = mdb_put(*m_write_txn, m_archival_budget_accrual, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add archival budget accrual: ", result).c_str()));
}

uint64_t BlockchainLMDB::get_archival_budget_accrual(uint64_t height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBudgetAccrualKey key(height);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_budget_accrual, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return 0;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival budget accrual: ", get_result).c_str()));
  if (v.mv_size != 8)
    throw0(DB_ERROR(("Bad archival budget accrual record at height " + std::to_string(height)
      + ": expected 8 bytes, got " + std::to_string(v.mv_size)).c_str()));
  return shekyl::db::load_be64(static_cast<const uint8_t*>(v.mv_data));
}

void BlockchainLMDB::remove_archival_budget_accrual(uint64_t height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBudgetAccrualKey key(height);
  MDB_val k = key.as_mdb_val();
  int result = mdb_del(*m_write_txn, m_archival_budget_accrual, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove archival budget accrual: ", result).c_str()));
}





void BlockchainLMDB::set_total_bonded_atomic(uint64_t balance)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  const std::string key = "total_bonded_atomic";
  MDB_val k = {key.size(), (void *)key.data()};
  MDB_val v = {sizeof(balance), (void *)&balance};
  int result = mdb_put(*m_write_txn, m_properties, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set total bonded atomic: ", result).c_str()));
}

uint64_t BlockchainLMDB::get_total_bonded_atomic() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  const std::string key = "total_bonded_atomic";
  MDB_val k = {key.size(), (void *)key.data()};
  MDB_val v;
  auto get_result = mdb_get(m_txn, m_properties, &k, &v);
  if (get_result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return 0;
  }
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to read total bonded atomic: ", get_result).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR("Bad total bonded atomic size in DB"));
  uint64_t balance;
  memcpy(&balance, v.mv_data, sizeof(balance));
  TXN_POSTFIX_RDONLY();
  return balance;
}


void BlockchainLMDB::set_settlement_epoch_blocks_pin(uint64_t blocks)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // Init-time write (Blockchain::init, before any block-add txn exists), so
  // this manages its own short transaction — the same shape as
  // prune_worker's pruning_seed write.
  mdb_txn_safe txn;
  if (auto result = mdb_txn_begin(m_env, NULL, 0, txn))
    throw0(DB_ERROR(lmdb_error("Failed to create a transaction for the db: ", result).c_str()));

  MDB_val_str(k, "settlement_epoch_blocks");
  MDB_val v = {sizeof(blocks), (void *)&blocks};
  if (auto result = mdb_put(txn, m_properties, &k, &v, 0))
    throw0(DB_ERROR(lmdb_error("Failed to set settlement epoch blocks pin: ", result).c_str()));
  txn.commit();
}

uint64_t BlockchainLMDB::get_settlement_epoch_blocks_pin() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val_str(k, "settlement_epoch_blocks");
  MDB_val v;
  auto get_result = mdb_get(m_txn, m_properties, &k, &v);
  if (get_result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return 0;
  }
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to read settlement epoch blocks pin: ", get_result).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR("Bad settlement epoch blocks pin size in DB"));
  uint64_t blocks;
  memcpy(&blocks, v.mv_data, sizeof(blocks));
  TXN_POSTFIX_RDONLY();
  return blocks;
}

void BlockchainLMDB::set_total_burned(uint64_t amount)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  const std::string key = "total_burned";
  MDB_val k = {key.size(), (void *)key.data()};
  MDB_val v = {sizeof(amount), (void *)&amount};
  int result = mdb_put(*m_write_txn, m_properties, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set total burned: ", result).c_str()));
}

uint64_t BlockchainLMDB::get_total_burned() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  const std::string key = "total_burned";
  MDB_val k = {key.size(), (void *)key.data()};
  MDB_val v;
  auto get_result = mdb_get(m_txn, m_properties, &k, &v);
  if (get_result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return 0;
  }
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get total burned: ", get_result).c_str()));
  uint64_t amount;
  memcpy(&amount, v.mv_data, sizeof(amount));
  TXN_POSTFIX_RDONLY();
  return amount;
}




int BlockchainLMDB::archival_db_get(MDB_dbi dbi, MDB_val* k, MDB_val* v) const
{
  // No bare `if (m_write_txn)` fast path: `block_rtxn_start` (inside
  // TXN_PREFIX_RDONLY) already returns the write txn on the writer thread,
  // and an LMDB write txn must never be touched from any other thread — a
  // non-writer caller (e.g. the claim-source RPC worker) gets a read
  // snapshot instead of racing the writer's uncommitted txn.
  TXN_PREFIX_RDONLY();
  const int rc = mdb_get(m_txn, dbi, k, v);
  TXN_POSTFIX_RDONLY();
  return rc;
}

bool BlockchainLMDB::has_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_serve_credit, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return false;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival serve-credit bit: ", get_result).c_str()));
  return true;
}

void BlockchainLMDB::set_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  static const uint8_t flag = 1;
  MDB_val v = {sizeof(flag), const_cast<uint8_t*>(&flag)};
  const int result = mdb_put(*m_write_txn, m_archival_serve_credit, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set archival serve-credit bit: ", result).c_str()));
}

void BlockchainLMDB::remove_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  const int result = mdb_del(*m_write_txn, m_archival_serve_credit, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove archival serve-credit bit: ", result).c_str()));
}

bool BlockchainLMDB::load_archival_bond_value(const crypto::hash& p_id,
  shekyl::db::ArchivalBondValue& out) const
{
  shekyl::db::ArchivalBondKey key(reinterpret_cast<const uint8_t*>(p_id.data));
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_bond, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return false;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival bond record: ", get_result).c_str()));
  if (!shekyl::db::ArchivalBondValue::decode(v.mv_data, v.mv_size, out))
    throw0(DB_ERROR("Failed to decode archival bond record"));
  return true;
}

bool BlockchainLMDB::get_archival_bond_hybrid_pubkey(const crypto::hash& p_id,
  std::vector<uint8_t>& out_pubkey) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    return false;
  out_pubkey = bond.hybrid_pubkey;
  return !out_pubkey.empty();
}

bool BlockchainLMDB::get_archival_bond_value(const crypto::hash& p_id,
  shekyl::db::ArchivalBondValue& out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  return load_archival_bond_value(p_id, out);
}

bool BlockchainLMDB::archival_slash_removed_holding_after(const crypto::hash& p_id,
  uint64_t shard_id, uint64_t at_height) const
{
  // Range-scan the slash log strictly above at_height. A v2 log row proves
  // what the slash destroyed: a compact erase of exactly `shard_id`, or a
  // complete-tree demotion (pre-image held every shard). Either shape at a
  // height > at_height proves the bond still held `shard_id` at at_height.
  //
  // No height strictly above the maximum exists, so the answer at
  // at_height == max is false by construction — and the early return keeps
  // the scan start key `at_height + 1` from wrapping to 0 (which would
  // range-scan the whole log and report a false positive).
  if (at_height == std::numeric_limits<uint64_t>::max())
    return false;

  // Invariant across the whole scan (at_height is fixed) — compute the epoch
  // once rather than per log row.
  const uint64_t at_epoch = shekyl_archival_settlement_epoch_at_height(at_height);

  const auto scan = [&](MDB_txn* txn) -> bool {
    MDB_cursor* cur = nullptr;
    const int open_rc = mdb_cursor_open(txn, m_archival_slash_log, &cur);
    if (open_rc)
      throw0(DB_ERROR(lmdb_error("Failed to open archival_slash_log cursor: ", open_rc).c_str()));

    bool removed = false;
    shekyl::db::ArchivalSlashLogKey start_key(at_height + 1, 0);
    MDB_val k = start_key.as_mdb_val();
    MDB_val v;
    int rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while (rc == 0)
    {
      shekyl::db::ArchivalSlashRevertValue entry{};
      if (!shekyl::db::ArchivalSlashRevertValue::decode(v.mv_data, v.mv_size, entry))
      {
        mdb_cursor_close(cur);
        throw std::runtime_error("FATAL: archival slash log decode failed during holdings scan");
      }
      // A compact row reconstructs one shard's tenure, which began at its
      // journaled v6 add-epoch — a slashed-away shard was held at at_height
      // only for heights in epochs strictly after that add (the same
      // per-shard E_add + 1 bound the tip-held arm applies; P2B-7 Pin 5). A
      // complete-tree demotion row clears every holding and reconstructs
      // held-back-to-join (a foundation record cannot HoldingsUpdate).
      if (!entry.is_epoch_marker()
        && std::memcmp(entry.p_id, p_id.data, 32) == 0
        && (entry.holdings_pre_kind
              == shekyl::db::ArchivalSlashRevertValue::kPreKindCompleteTree
            || (entry.shard_id == shard_id
                && at_epoch > entry.slashed_shard_add_epoch)))
      {
        removed = true;
        break;
      }
      rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }
    if (rc && rc != MDB_NOTFOUND)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("archival_slash_log cursor error during holdings scan: ", rc).c_str()));
    }
    mdb_cursor_close(cur);
    return removed;
  };

  // Thread-aware txn selection via block_rtxn_start — see archival_db_get.
  TXN_PREFIX_RDONLY();
  const bool removed = scan(m_txn);
  TXN_POSTFIX_RDONLY();
  return removed;
}

bool BlockchainLMDB::archival_bond_holds_shard(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t at_height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    return false;

  return archival_bond_holds_shard_of(p_id, bond, shard_id, at_height);
}

bool BlockchainLMDB::archival_bond_holds_shard_of(const crypto::hash& p_id,
  const shekyl::db::ArchivalBondValue& bond, uint64_t shard_id, uint64_t at_height) const
{
  // Split out of archival_bond_holds_shard so a caller that already holds the
  // decoded record does not pay a re-load + re-decode per query. The failure-
  // window look-back asks this up to n times for one (P, s) candidate; the
  // slash scan has the record in hand from its own cursor walk.

  // As-of-height semantics (WS-1, REWARD_EMISSION_E3_GATING_ROUND.md §5;
  // extended for mutable holdings by the HoldingsUpdate connect slice —
  // P2B-7 Pin 4/5): both consumers — serve-credit acceptance and slash
  // eligibility — ask "did P hold s at the challenge fire height?", so this
  // answers at at_height, not at tip. Under HoldingsUpdate, holdings grow
  // (add) as well as shrink (drop/slash), so "held at tip" no longer reaches
  // back to join; it reaches back to the shard's (latest) ADD:
  //
  //   held at tip, CompleteTree ⇒ held back to join (a foundation record
  //                               cannot HoldingsUpdate; the callers' record
  //                               epoch gating puts every fire height after
  //                               join);
  //   held at tip, compact      ⇒ held for every height in epochs STRICTLY
  //                               AFTER the shard's v6 add-epoch. The add
  //                               connected at an unknown height WITHIN its
  //                               add epoch, so holding is epoch-guaranteed
  //                               only from the next epoch on — which is
  //                               exactly Pin 5's per-shard E_add + 1 rule
  //                               (counted/claimable/challengeable from
  //                               E_add + 1; the partial add epoch is
  //                               forfeited in BOTH directions: no serve
  //                               credit can be earned in it, and no
  //                               challenge fired in it can slash). For
  //                               at_height at/before the add epoch, fall
  //                               through to the slash reconstruction — a
  //                               PREVIOUS tenure of s that a slash removed
  //                               still answers held for its own heights;
  //   not held at tip           ⇒ held at at_height iff a logged slash
  //                               strictly above at_height removed it (a
  //                               slash *at* at_height means already-removed:
  //                               holdings at h are the post-connect state of
  //                               block h). A voluntarily DROPPED shard keeps
  //                               no interval (grace-tail, P2B-7 Pin 2 —
  //                               ratified: no drop sub-state, no
  //                               bond_event_log row), so it answers not-held
  //                               for every height: the drop epoch's own
  //                               pending acceptances are forfeited, the
  //                               symmetric twin of the forfeited add epoch.
  if (bond.holds_shard(shard_id))
  {
    if (bond.is_complete_tree())
      return true;
    const auto it = std::find(bond.held_shard_ids.begin(), bond.held_shard_ids.end(), shard_id);
    const size_t idx = static_cast<size_t>(it - bond.held_shard_ids.begin());
    if (idx >= bond.shard_add_epochs.size())
      throw std::runtime_error(
        "FATAL: shard_add_epochs desynced from held_shard_ids in holds_shard");
    if (shekyl_archival_settlement_epoch_at_height(at_height) > bond.shard_add_epochs[idx])
      return true;
    return archival_slash_removed_holding_after(p_id, shard_id, at_height);
  }

  return archival_slash_removed_holding_after(p_id, shard_id, at_height);
}

namespace {

// ─── Height-keyed archival journal helpers ─────────────────────────────────
//
// Three archival journals (slash log, emission-claim log, unbond log) share
// the same BE(height)‖BE(seq) row layout and the same three sub-operations:
// probe the next free seq for a height, read every row at a height, delete
// every row at a height. `KeyT` is the row-key type (constructed from
// (height, seq)); the write-txn and dbi are passed in so these stay storage
// adapters with no consensus logic. The slash log's epoch-marker special seq
// keeps its own bespoke loop; the emission-claim and unbond logs are the two
// clean consumers.

// Next unused seq at `height` (linear probe from 0 — one journal holds only
// the few rows a single block appended).
template <typename KeyT>
uint32_t archival_journal_next_seq(MDB_txn* wtxn, MDB_dbi dbi, uint64_t height,
  const char* ctx)
{
  uint32_t seq = 0;
  for (;; ++seq)
  {
    KeyT key(height, seq);
    MDB_val k = key.as_mdb_val();
    MDB_val v;
    const int rc = mdb_get(wtxn, dbi, &k, &v);
    if (rc == MDB_NOTFOUND)
      return seq;
    if (rc)
      throw0(DB_ERROR(lmdb_error(std::string("Failed to probe ") + ctx + ": ", rc).c_str()));
  }
}

// Append one already-encoded row at `height`/`seq`.
template <typename KeyT>
void archival_journal_put(MDB_txn* wtxn, MDB_dbi dbi, uint64_t height, uint32_t seq,
  const std::vector<uint8_t>& encoded, const char* ctx)
{
  KeyT key(height, seq);
  MDB_val k = key.as_mdb_val();
  MDB_val v = {encoded.size(), const_cast<uint8_t*>(encoded.data())};
  const int rc = mdb_put(wtxn, dbi, &k, &v, 0);
  if (rc)
    throw0(DB_ERROR(lmdb_error(std::string("Failed to append ") + ctx + ": ", rc).c_str()));
}

// Decode every row at `height` (seq 0.. until the first gap) into `ValT`s.
template <typename KeyT, typename ValT>
std::vector<ValT> archival_journal_read(MDB_txn* wtxn, MDB_dbi dbi, uint64_t height,
  const char* ctx)
{
  std::vector<ValT> rows;
  for (uint32_t seq = 0; ; ++seq)
  {
    KeyT key(height, seq);
    MDB_val k = key.as_mdb_val();
    MDB_val v;
    const int rc = mdb_get(wtxn, dbi, &k, &v);
    if (rc == MDB_NOTFOUND)
      break;
    if (rc)
      throw0(DB_ERROR(lmdb_error(std::string("Failed to read ") + ctx + " on pop: ", rc).c_str()));
    ValT entry{};
    if (!ValT::decode(v.mv_data, v.mv_size, entry))
      throw std::runtime_error(std::string("FATAL: ") + ctx + " decode failed on pop");
    rows.push_back(std::move(entry));
  }
  return rows;
}

// Delete rows [0, count) at `height`.
template <typename KeyT>
void archival_journal_delete(MDB_txn* wtxn, MDB_dbi dbi, uint64_t height, uint32_t count,
  const char* ctx)
{
  for (uint32_t seq = 0; seq < count; ++seq)
  {
    KeyT key(height, seq);
    MDB_val k = key.as_mdb_val();
    const int rc = mdb_del(wtxn, dbi, &k, nullptr);
    if (rc)
      throw0(DB_ERROR(lmdb_error(std::string("Failed to delete ") + ctx + " on pop: ", rc).c_str()));
  }
}

// Flatten BadInterval records into the [start, end_exclusive, ...] pair
// layout expected by the Rust FFI. Storage adapter only; the interval
// semantics live in shekyl-archival-retention.
std::vector<uint64_t> archival_bad_intervals_flat(const shekyl::db::ArchivalBondValue& bond)
{
  std::vector<uint64_t> flat;
  flat.reserve(bond.bad_intervals.size() * 2);
  for (const auto& iv : bond.bad_intervals)
  {
    flat.push_back(iv.start_epoch);
    flat.push_back(iv.end_exclusive);
  }
  return flat;
}

bool archival_bond_good_through_ffi(const shekyl::db::ArchivalBondValue& bond,
  uint64_t settlement_epoch)
{
  const std::vector<uint64_t> intervals = archival_bad_intervals_flat(bond);
  return shekyl_archival_good_through(bond.join_settlement_epoch, settlement_epoch,
    intervals.empty() ? nullptr : intervals.data(), intervals.size() / 2) != 0;
}

} // namespace

bool BlockchainLMDB::archival_bond_good_through(const crypto::hash& p_id,
  uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    return false;
  return archival_bond_good_through_ffi(bond, settlement_epoch);
}

uint64_t BlockchainLMDB::archival_bond_join_epoch(const crypto::hash& p_id) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    return std::numeric_limits<uint64_t>::max();
  return bond.join_settlement_epoch;
}

bool BlockchainLMDB::get_archival_shard_segment_at_height(uint64_t shard_id, uint64_t at_height,
  crypto::hash& out_rk, uint64_t& out_leaf_count) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalShardKey key(shard_id);
  MDB_val k = key.as_mdb_val();
  TXN_PREFIX_RDONLY();
  MDB_val v;
  const int get_result = mdb_get(m_txn, m_archival_shard_segment, &k, &v);
  TXN_POSTFIX_RDONLY();
  if (get_result != 0)
    return false;

  shekyl::db::ArchivalShardSegmentValue segment{};
  if (!shekyl::db::ArchivalShardSegmentValue::decode(v.mv_data, v.mv_size, segment))
    return false;
  if (at_height < segment.freeze_height)
    return false;

  std::memcpy(out_rk.data, segment.segment_subroot_rk.data(), 32);
  out_leaf_count = segment.segment_leaf_count;
  return out_leaf_count > 0;
}

void BlockchainLMDB::put_archival_bond_record(const crypto::hash& p_id,
  const std::vector<uint8_t>& hybrid_pubkey,
  const std::vector<uint8_t>& bond_spend_pk, uint64_t join_settlement_epoch,
  uint64_t bonded_total_atomic, uint8_t holdings_kind,
  const std::vector<uint64_t>& held_shard_ids,
  const std::vector<std::pair<uint64_t, uint64_t>>& bad_intervals)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);

  shekyl::db::ArchivalBondValue bond{};
  bond.hybrid_pubkey = hybrid_pubkey;
  // GF-1: the committed debit authorizer (gate-4 §4.1) — written once here,
  // at join time; immutable for the record's life (re-keying is a full
  // Unbond + re-JoinMarket). Every later bond_debit's pqc auth verifies
  // against this copy, never the identity key.
  bond.bond_spend_pk = bond_spend_pk;
  bond.join_settlement_epoch = join_settlement_epoch;
  bond.bonded_total_atomic = bonded_total_atomic;
  bond.holdings_kind = holdings_kind;
  bond.held_shard_ids = held_shard_ids;
  // v6: every join-time shard was acquired at E_join, so its per-shard
  // add-epoch is the record's join epoch (index-parallel to held_shard_ids).
  // HoldingsUpdate-add later appends E_add for a new shard; the drop path and
  // per-shard E_add+1 counting read this array.
  bond.shard_add_epochs.assign(held_shard_ids.size(), join_settlement_epoch);
  // Join-time invariant: a fresh compact bond must hold at least one shard
  // (JoinMarket rejects empty holdings). This is a precondition of *this*
  // writer, not of the record shape — post-slash records can be legitimately
  // compact-and-empty and write through put_archival_bond_value below.
  if (holdings_kind == shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact
    && held_shard_ids.empty())
  {
    throw std::runtime_error("FATAL: ShardSetCompact bond record requires shard ids");
  }
  bond.bad_intervals.reserve(bad_intervals.size());
  for (const auto& iv : bad_intervals)
  {
    shekyl::db::ArchivalBondValue::BadInterval entry{};
    entry.start_epoch = iv.first;
    entry.end_exclusive = iv.second;
    bond.bad_intervals.push_back(entry);
  }
  // claimed_settlement_epochs / first_paying_emission_height stay default
  // (empty / 0): the sole caller is JoinMarket connect, which starts a fresh P
  // with no prior emission claims. Load-modify-store callers must instead use
  // put_archival_bond_value so those v4 fields survive (F-S1).
  put_archival_bond_value(p_id, bond);
}

void BlockchainLMDB::put_archival_bond_value(const crypto::hash& p_id,
  const shekyl::db::ArchivalBondValue& bond)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (bond.holdings_kind == shekyl::db::ArchivalBondValue::kHoldingsCompleteTree
    && !bond.held_shard_ids.empty())
  {
    throw std::runtime_error("FATAL: CompleteTree bond record must not carry shard ids");
  }
  // Deliberately NO "compact requires shard ids" guard here: a compact record
  // with empty holdings is the legitimate post-slash shape (complete-tree
  // demotion clears every holding; a compact bond slashed on its last shard
  // ends empty), and both slash paths write through this function. The
  // non-empty requirement is a JoinMarket precondition and lives in
  // put_archival_bond_record, the join-time writer.

  const std::vector<uint8_t> encoded = bond.encode();
  shekyl::db::ArchivalBondKey key(reinterpret_cast<const uint8_t*>(p_id.data));
  MDB_val k = key.as_mdb_val();
  MDB_val v = { encoded.size(), const_cast<uint8_t*>(encoded.data()) };
  const int result = mdb_put(*m_write_txn, m_archival_bond, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to put archival bond record: ", result).c_str()));
}

void BlockchainLMDB::remove_archival_bond_record(const crypto::hash& p_id)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBondKey key(reinterpret_cast<const uint8_t*>(p_id.data));
  MDB_val k = key.as_mdb_val();
  const int result = mdb_del(*m_write_txn, m_archival_bond, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove archival bond record: ", result).c_str()));
}

uint64_t BlockchainLMDB::get_archival_last_slash_epoch() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  const std::string key = "archival_last_slash_epoch";
  MDB_val k = {key.size(), (void*)key.data()};
  MDB_val v;
  const int get_result = mdb_get(m_txn, m_properties, &k, &v);
  TXN_POSTFIX_RDONLY();
  if (get_result == MDB_NOTFOUND)
    return std::numeric_limits<uint64_t>::max();
  if (get_result || v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR(lmdb_error("Failed to get archival_last_slash_epoch: ", get_result).c_str()));
  uint64_t epoch = 0;
  std::memcpy(&epoch, v.mv_data, sizeof(epoch));
  return epoch;
}

void BlockchainLMDB::set_archival_last_slash_epoch(uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  const std::string key = "archival_last_slash_epoch";
  MDB_val k = {key.size(), (void*)key.data()};
  MDB_val v = {sizeof(settlement_epoch), (void*)&settlement_epoch};
  const int result = mdb_put(*m_write_txn, m_properties, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set archival_last_slash_epoch: ", result).c_str()));
}

bool BlockchainLMDB::has_archival_slash_applied(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_slash_applied, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return false;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival slash-applied bit: ", get_result).c_str()));
  return true;
}

void BlockchainLMDB::set_archival_slash_applied(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  static const uint8_t flag = 1;
  MDB_val v = {sizeof(flag), const_cast<uint8_t*>(&flag)};
  const int result = mdb_put(*m_write_txn, m_archival_slash_applied, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to set archival slash-applied bit: ", result).c_str()));
}

void BlockchainLMDB::remove_archival_slash_applied(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  const int result = mdb_del(*m_write_txn, m_archival_slash_applied, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove archival slash-applied bit: ", result).c_str()));
}

void BlockchainLMDB::append_archival_slash_log(uint64_t block_height, uint32_t seq,
  const shekyl::db::ArchivalSlashRevertValue& entry)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  const std::vector<uint8_t> encoded = entry.encode();
  shekyl::db::ArchivalSlashLogKey key(block_height, seq);
  MDB_val k = key.as_mdb_val();
  MDB_val v = {encoded.size(), const_cast<uint8_t*>(encoded.data())};
  const int result = mdb_put(*m_write_txn, m_archival_slash_log, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to append archival slash log: ", result).c_str()));
}

bool BlockchainLMDB::archival_baseline_observed_at_epoch(uint64_t block_height,
  const crypto::hash& p_id, const shekyl::db::ArchivalBondValue& bond, uint64_t shard_id,
  uint64_t settlement_epoch, ArchivalSealHashCache* seal_cache) const
{
  // Was a baseline challenge actually POSED to (p_id, shard_id) at this epoch,
  // and has its outcome resolved? This is the observability predicate the
  // sliding-window failure confirmation counts over
  // (docs/completed/ARCHIVAL_FAILURE_CONFIRMATION_PIN.md §1): an epoch in which
  // the pair was bonded but untested is NOT an observation, so it can never be
  // counted as a miss. It answers only "was it posed", never "was it answered"
  // — the serve_credit_bit is the caller's separate read.
  //
  // The failure-window look-back walks epochs downward and stops at the first
  // epoch this returns false for, which is what scopes the window to the pair's
  // current continuous challengeable run. Three consensus boundaries fall out
  // of that, none special-cased: before E_join + 1 and inside a bad interval
  // good_through is false (so a slash -> Rebond reinstatement starts the window
  // clean); at or before the shard's E_add the as-of-H_fire holdings read is
  // false (the partial add epoch is forfeited in both directions, P2B-7 Pin 5).

  // good_through covers both the join-epoch gate and bad-interval exclusion
  // (ARCHIVAL_INCENTIVES §3.4); computed in Rust.
  //
  // Deliberately no tip-holdings pre-filter here (WS-1): eligibility is
  // "held at the challenge fire height and didn't respond", answered by the
  // as-of-height read at the bottom. A tip read ahead of it let a P drop the
  // shard after the fire and escape the slash.
  if (!archival_bond_good_through_ffi(bond, settlement_epoch))
    return false;

  const uint64_t h_open = shekyl_archival_epoch_open_height(settlement_epoch);
  const uint64_t h_close = shekyl_archival_epoch_close_height(settlement_epoch);
  const uint64_t h_slash_deadline = shekyl_archival_epoch_slash_deadline_height(settlement_epoch);
  if (block_height <= h_slash_deadline)
    return false;

  const uint64_t h_seal = shekyl_archival_challenge_seal_height(h_open);
  if (h_seal > block_height)
    return false;

  // The seal-block hash depends on the epoch (via h_seal), not the shard, so
  // across the caller's shard loop the same handful of heights are read over
  // and over. Memoize per height when a cache is supplied; the value is
  // immutable for a committed height within the scan's write txn, so this is
  // behaviour-identical to fetching every time.
  crypto::hash seal_hash{};
  bool have_seal = false;
  if (seal_cache)
  {
    const auto it = seal_cache->find(h_seal);
    if (it != seal_cache->end())
    {
      seal_hash = it->second;
      have_seal = true;
    }
  }
  if (!have_seal)
  {
    try
    {
      seal_hash = get_block_hash_from_height(h_seal);
    }
    catch (const std::exception&)
    {
      return false;
    }
    if (seal_cache)
      (*seal_cache)[h_seal] = seal_hash;
  }

  // Derived identically to the serve-credit consumer (blockchain.cpp) from the
  // same deterministic inputs (WS-1 h_fire symmetry). No range check: H_fire is
  // in (0, H_close] for every well-formed epoch — see challenge_fire_height's
  // reopen criterion (a Round-2 re-pin that admits H_close <= H_seal restores it
  // at both consumers). The h_seal-vs-block_height guard above already precludes
  // the degenerate epochs that could put H_fire out of range.
  const uint64_t h_fire = shekyl_archival_challenge_fire_height(
    h_open, h_close, reinterpret_cast<const uint8_t*>(seal_hash.data),
    reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);

  return archival_bond_holds_shard_of(p_id, bond, shard_id, h_fire);
}

bool BlockchainLMDB::archival_failure_window_slashable(uint64_t block_height,
  const crypto::hash& p_id, const shekyl::db::ArchivalBondValue& bond, uint64_t shard_id,
  uint64_t settlement_epoch, ArchivalSealHashCache* seal_cache) const
{
  // Gather the trailing window and hand it to Rust. This function reads LMDB
  // and decides NOTHING (20-rust-vs-cpp-policy): m, n, the stop budget, and the
  // m-of-n verdict all come from shekyl-archival-retention::failure_window.
  //
  // Nothing is persisted. The window is recomputed from the serve_credit_bit
  // ledger and the bond record on every evaluation, which is what makes it
  // reorg-safe for free: pop_block already reverts both (gate-2 §8, gate-4 §5),
  // so a rewound bit is a rewound observation with no second copy to resync.
  //
  // m/n/serve_budget are compile-time constants (generated from
  // config/consensus_constants.json into shekyl-archival-retention); the FFI
  // returns generated constants, never runtime state, so they cannot change
  // between calls. Fetch once per process behind a function-local static — this
  // is still the one authority (no header-constant drift pair) but pays the
  // marshal exactly once, not on every slash-candidate. m is unused C++-side
  // (the m-of-n verdict is Rust's); n bounds the look-back, serve_budget stops
  // it early.
  struct WindowParams { uint32_t m, n, serve_budget; };
  static const WindowParams window = [] {
    WindowParams p{};
    if (shekyl_archival_failure_window_params(&p.m, &p.n, &p.serve_budget)
      != SHEKYL_ARCHIVAL_FAILURE_WINDOW_ABSORB)
      throw std::runtime_error("FATAL: archival failure-window params marshal failed");
    return p;
  }();
  const uint32_t window_n = window.n;
  const uint32_t serve_budget = window.serve_budget;

  std::vector<uint64_t> epochs;
  std::vector<uint8_t> served;
  epochs.reserve(window_n);
  served.reserve(window_n);

  // Head of the window is the decision epoch, which the caller has already
  // established is an observed miss.
  epochs.push_back(settlement_epoch);
  served.push_back(0);

  uint32_t passes_seen = 0;
  uint64_t epoch = settlement_epoch;
  while (epochs.size() < window_n && epoch > 0)
  {
    --epoch;
    if (!archival_baseline_observed_at_epoch(block_height, p_id, bond, shard_id, epoch, seal_cache))
      break; // boundary of the pair's current continuous challengeable run
    const bool passed = has_archival_serve_credit_bit(p_id, shard_id, epoch);
    epochs.push_back(epoch);
    served.push_back(passed ? 1 : 0);
    // Rust-computed stop budget (n - m): once more than this many observations
    // in the window have PASSED, fewer than m misses remain possible however
    // far back the history goes, so reading further is wasted LMDB traffic.
    // Truncating here cannot change the verdict — the short window is still
    // handed to Rust, which necessarily answers ABSORB for it — so the decision
    // stays on the Rust side of the boundary rather than being short-circuited
    // by this loop.
    if (passed && ++passes_seen > serve_budget)
      break;
  }

  const uint8_t verdict = shekyl_archival_failure_window_slashable(
    epochs.data(), served.data(), epochs.size());
  if (verdict == SHEKYL_ARCHIVAL_FAILURE_WINDOW_ERR_MARSHAL)
    throw std::runtime_error(
      "FATAL: archival failure-window rejected the gathered observation sequence");
  return verdict == SHEKYL_ARCHIVAL_FAILURE_WINDOW_SLASH;
}

bool BlockchainLMDB::archival_challenge_failed_at_height(uint64_t block_height,
  const crypto::hash& p_id, const shekyl::db::ArchivalBondValue& bond, uint64_t shard_id,
  uint64_t settlement_epoch, ArchivalSealHashCache* seal_cache) const
{
  // Cheap single-key reads first: an epoch with an affirmative pass, or one an
  // earlier scan already slashed, is not a candidate at all. (All the
  // predicates here are pure reads, so their order is free; the beacon
  // reconstruction below is the expensive one and runs last.)
  if (has_archival_serve_credit_bit(p_id, shard_id, settlement_epoch))
    return false;
  if (has_archival_slash_applied(p_id, shard_id, settlement_epoch))
    return false;

  // A miss only counts if a baseline was posed and resolved at this epoch.
  if (!archival_baseline_observed_at_epoch(block_height, p_id, bond, shard_id, settlement_epoch, seal_cache))
    return false;

  // Sliding-window m-of-n failure confirmation (the pin's "not-durably-absent"
  // property): one missed baseline is NOT a slashable failure. Everything
  // downstream of this — apply_archival_slash_one and the interval it appends
  // via shekyl_archival_slash_open_interval_to_append — is unchanged; only
  // WHETHER the slash fires is decided here.
  return archival_failure_window_slashable(block_height, p_id, bond, shard_id, settlement_epoch, seal_cache);
}

void BlockchainLMDB::apply_archival_slash_one(uint64_t block_height, uint32_t& seq,
  const crypto::hash& p_id, uint64_t shard_id, uint64_t settlement_epoch,
  uint64_t slashed_amount)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // Exposed for direct invocation (slash scheduler + unit tests), so the
  // open-DB / active-write-txn preconditions the scheduler enforces must be
  // enforced here too: every mutating helper below (put_archival_bond_value,
  // set_total_*, append_archival_slash_log) dereferences *m_write_txn. Fail
  // loudly on misuse rather than dereferencing a null txn (UB).
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival slash apply requires active write txn");

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    throw std::runtime_error("FATAL: archival slash without bond record");

  // Captured pre-mutation: the slash log's revert row records what the slash
  // destroyed (WS-1). Complete-tree demotion clears every holding, so the
  // pre-image kind — not the post-image shape — is what pop-revert and
  // as-of-height reconstruction need.
  const uint8_t holdings_pre_kind = bond.holdings_kind;
  // v6/v3: the erased shard's add-epoch, captured before the erase so the pop
  // revert restores its shard_add_epochs entry exactly. Stays 0 for a
  // complete-tree demotion (which clears the whole array, restored by kind).
  uint64_t slashed_shard_add_epoch = 0;

  auto& shards = bond.held_shard_ids;
  if (bond.is_complete_tree())
  {
    bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsShardSetCompact;
    shards.clear();
    bond.shard_add_epochs.clear(); // v6 coupling: drop the add-epochs with the shards
  }
  else
  {
    const auto it = std::find(shards.begin(), shards.end(), shard_id);
    // Unreachable from the scheduler: process_archival_slash_for_epoch only
    // challenges shards the record currently holds, so the shard is always
    // present here. In particular an Exited record (Unbond connect) holds
    // nothing and is never a slash candidate — slashability ends at the
    // connect; the refund is never clawed back (ratified 2026-07-12). The
    // HoldingsUpdate-drop revisit is DISCHARGED (this slice): a voluntarily
    // dropped shard leaves held_shard_ids at the drop connect, so the
    // scheduler never challenges it and this arm stays unreachable — by the
    // same grace-tail ratification (P2B-7 Pin 2/3, 2026-07-15): the drop's
    // verify preconditions (per-shard cooldown + slashes settled through the
    // shard's last-served anchor) guarantee every epoch through the anchor
    // resolved on still-bonded collateral, and the unserved tail past it is
    // exit-forgiven at the connect, capped at one cooldown. (The parenthetical
    // that used to sit here — "'stop serving, hold, never drop' keeps being
    // slashed, so the persona is pushed to actually drop" — was a
    // single-strike argument and is corrected with the sliding-window m-of-n;
    // see the process_archival_slash_for_epoch note below.) Fail loudly rather
    // than silently no-op (the connect-fold posture).
    if (it == shards.end())
      throw std::runtime_error("FATAL: archival slash apply for a shard the record does not hold");
    // v6 coupling is STRICT: the two per-shard arrays are index-parallel, so
    // the found index is always in range. A size mismatch is record
    // corruption, not a tolerable desync — fail loudly here (the connect-fold
    // posture) rather than skipping the add-epoch erase and surfacing it later
    // as an opaque encode-time throw with the arrays already mismatched.
    const size_t idx = static_cast<size_t>(it - shards.begin());
    if (idx >= bond.shard_add_epochs.size())
      throw std::runtime_error(
        "FATAL: shard_add_epochs desynced from held_shard_ids on slash apply");
    slashed_shard_add_epoch = bond.shard_add_epochs[idx];
    bond.shard_add_epochs.erase(bond.shard_add_epochs.begin() + idx);
    shards.erase(it);
  }

  // Same-epoch coalescing (P2B-9 Pin 5) — the decision AND the interval shape
  // live Rust-side (bond_connect::slash_open_interval_to_append, where the
  // full rationale is documented): append [E, MAX) only when no open interval
  // exists, so an offline N-shard record slashed N times in one block appends
  // exactly one interval instead of overrunning the codec cap and throwing at
  // encode inside this block-connect hook. The pop revert is
  // coalescing-compatible (its remove_if strips every matching open interval
  // on the first same-epoch row and no-ops after). Computed on the pre-append
  // log — neither branch above touches bad_intervals.
  //
  // The flat marshal fills a fixed stack buffer: the interval log is
  // codec-capped at kMaxBadIntervals (genesis-frozen), so the worst case is
  // 4 KiB of stack and the per-shard slash sweep — the hot loop this hook
  // runs in once per failed shard — performs no heap allocation here. A log
  // above the cap cannot exist on disk (encode/decode both reject it); if one
  // is ever observed the record is corrupt, and that must be loud.
  if (bond.bad_intervals.size() > shekyl::db::ArchivalBondValue::kMaxBadIntervals)
    throw std::runtime_error(
      "FATAL: bond record interval log exceeds the codec cap at slash apply");
  std::array<uint64_t, 2 * shekyl::db::ArchivalBondValue::kMaxBadIntervals> intervals_flat;
  const size_t iv_pairs = bond.bad_intervals.size();
  for (size_t i = 0; i < iv_pairs; ++i)
  {
    intervals_flat[2 * i] = bond.bad_intervals[i].start_epoch;
    intervals_flat[2 * i + 1] = bond.bad_intervals[i].end_exclusive;
  }
  uint64_t iv_start = 0;
  uint64_t iv_end = 0;
  const uint8_t iv_rc = shekyl_archival_slash_open_interval_to_append(
    iv_pairs == 0 ? nullptr : intervals_flat.data(), iv_pairs,
    settlement_epoch, &iv_start, &iv_end);
  if (iv_rc == SHEKYL_ARCHIVAL_SLASH_INTERVAL_APPEND)
  {
    shekyl::db::ArchivalBondValue::BadInterval iv{};
    iv.start_epoch = iv_start;
    iv.end_exclusive = iv_end;
    bond.bad_intervals.push_back(iv);
  }
  else if (iv_rc != SHEKYL_ARCHIVAL_SLASH_INTERVAL_COALESCE)
  {
    throw std::runtime_error("FATAL: archival slash interval decision failed (code "
      + std::to_string(static_cast<unsigned>(iv_rc)) + ")");
  }

  if (bond.bonded_total_atomic < slashed_amount)
    throw std::runtime_error("FATAL: per-P bonded_total_atomic underflow on slash");
  bond.bonded_total_atomic -= slashed_amount;

  // Write the mutated record whole so the v4 claimed-epoch set and
  // first_paying_emission_height survive the slash (F-S1 / F-E5).
  put_archival_bond_value(p_id, bond);

  const uint64_t bonded_total = get_total_bonded_atomic();
  if (slashed_amount > bonded_total)
    throw std::runtime_error("FATAL: total_bonded_atomic underflow on slash");
  set_total_bonded_atomic(bonded_total - slashed_amount);

  const uint64_t burned_total = get_total_burned();
  if (burned_total > std::numeric_limits<uint64_t>::max() - slashed_amount)
    throw std::runtime_error("FATAL: total_burned overflow on slash");
  set_total_burned(burned_total + slashed_amount);

  set_archival_slash_applied(p_id, shard_id, settlement_epoch);

  shekyl::db::ArchivalSlashRevertValue log_entry{};
  std::memcpy(log_entry.p_id, p_id.data, 32);
  log_entry.shard_id = shard_id;
  log_entry.settlement_epoch = settlement_epoch;
  log_entry.slashed_amount = slashed_amount;
  log_entry.holdings_pre_kind = holdings_pre_kind;
  log_entry.slashed_shard_add_epoch = slashed_shard_add_epoch;
  append_archival_slash_log(block_height, seq++, log_entry);
}

void BlockchainLMDB::process_archival_slash_for_epoch(uint64_t block_height,
  uint64_t settlement_epoch, uint32_t& seq)
{
  const uint64_t h_slash_deadline = shekyl_archival_epoch_slash_deadline_height(settlement_epoch);
  if (block_height <= h_slash_deadline)
    return;

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival slash scheduler requires active write txn");

  const uint64_t floor = SHEKYL_ARCHIVAL_BOND_FLOOR_ATOMIC;

  // One seal-hash memo for the whole epoch scan (see ArchivalSealHashCache):
  // every record's failure-window look-back reads the same per-epoch seal-block
  // hashes, so sharing one cache across all records folds what would be
  // N_records x N_shards x n re-reads of the same handful of heights down to one
  // read each. Scoped to this call — a fresh scan (including after a pop_block
  // rewind) rebuilds it — so no stale hash can outlive the write txn it was read
  // under.
  ArchivalSealHashCache seal_cache;

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_bond, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_bond cursor for slash: ", rc).c_str()));

  MDB_val k, v;
  rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);

  while (rc == 0)
  {
    if (k.mv_size != 32)
      throw std::runtime_error("FATAL: archival_bond key size mismatch during slash scan");

    crypto::hash p_id{};
    std::memcpy(p_id.data, k.mv_data, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!shekyl::db::ArchivalBondValue::decode(v.mv_data, v.mv_size, bond))
      throw std::runtime_error("FATAL: archival_bond decode failed during slash scan");

    // Only currently held shards are challenged. An Exited record (Unbond
    // connect: compact-and-empty) therefore never reaches a challenge — by
    // design, not accident: slashability ends at the Unbond connect, and the
    // release verify guarantees every epoch through the record's last-served
    // anchor settled BEFORE the exit (ratified 2026-07-12; the exit-forgiven
    // tail is release_cooldown.rs's module contract). Slash-emptied records
    // are excluded the same way, with earlier epochs already settled by the
    // scheduler's ascending epoch order. A voluntarily DROPPED shard
    // (HoldingsUpdate grace-tail, ratified P2B-7 Pin 2/3) is excluded by the
    // same per-shard contract: the drop verify required its cooldown elapsed
    // AND slashes settled through its last-served anchor, so every epoch a
    // serve was credited for has resolved on bonded collateral; the unserved
    // tail between the anchor and the drop connect is exit-forgiven, capped
    // at one cooldown — a bounded, deliberately-accepted forgiveness.
    //
    // CORRECTED with the sliding-window m-of-n (2026-07-25). The clause that
    // used to close this paragraph — "not an escape (the alternative, 'stop
    // serving and just hold', keeps being slashed every epoch)" — was true
    // only while consensus single-struck. It no longer is: holding without
    // serving is now slash-free for up to m-1 observed misses. That is the
    // window working as designed at end-of-life, not a new escape. The release
    // cooldown anchors on the last SERVED epoch and clears only
    // RELEASE_COOLDOWN_EPOCHS (2) past it — far below m (11) — so a departing
    // record rides the SAME m-1 forgiveness envelope a still-bonded record
    // already gets anywhere in its life, earns nothing while dark, and cannot
    // exceed the window's tolerance without first crossing m-of-n and being
    // slashed. An exit-time "clear the window before release" gate would punish
    // the honest crash-then-leave record identically to the adversarial squeeze
    // — the two are on-chain indistinguishable, and both sit inside a tolerance
    // the window already grants — so it is deliberately NOT added. What
    // genuinely remains for the Round-2 stressnet is the SIZING of m/n for
    // crisis-time correlated failure (ARCHIVAL_FAILURE_CONFIRMATION_PIN.md
    // §3.2); the exit tail is subsumed by that sizing, not a separate decision
    // (FOLLOWUPS.md V3.1).
    //
    // Scan cost, for whoever profiles this next: the complete-tree arm below
    // walks the whole shard registry and breaks only on a shard that SLASHES,
    // so while a non-serving foundation record is inside its m-1 absorb window
    // it walks every shard AND runs a full look-back per shard, where
    // single-strike broke on the first failure. That is N_shards x n LMDB
    // reads. The one expensive read in each observation — the per-epoch
    // challenge seal-block hash, a function of the epoch and not the shard — is
    // memoized across the whole scan by seal_cache (below), so it is fetched
    // once per epoch, not once per (shard, epoch). What remains is bounded and
    // rare rather than hot: a shard that served short-circuits before any of
    // this, and the scheduler settles each epoch exactly once (the watermark
    // advances), so the cost is once per epoch, not once per block.
    if (bond.is_complete_tree())
    {
      MDB_cursor* seg_cur = nullptr;
      int seg_rc = mdb_cursor_open(*m_write_txn, m_archival_shard_segment, &seg_cur);
      if (seg_rc)
        throw0(DB_ERROR(lmdb_error("Failed to open archival_shard_segment cursor for slash: ", seg_rc).c_str()));

      MDB_val sk, sv;
      seg_rc = mdb_cursor_get(seg_cur, &sk, &sv, MDB_FIRST);
      while (seg_rc == 0)
      {
        if (sk.mv_size != 8)
          throw std::runtime_error("FATAL: archival_shard_segment key size mismatch during slash scan");
        const uint64_t shard_id = shekyl::db::load_be64(static_cast<const uint8_t*>(sk.mv_data));
        if (archival_challenge_failed_at_height(block_height, p_id, bond, shard_id, settlement_epoch, &seal_cache))
        {
          apply_archival_slash_one(block_height, seq, p_id, shard_id, settlement_epoch, floor);
          break;
        }
        seg_rc = mdb_cursor_get(seg_cur, &sk, &sv, MDB_NEXT);
      }
      if (seg_rc != MDB_NOTFOUND)
        throw0(DB_ERROR(lmdb_error("archival_shard_segment cursor error during slash scan: ", seg_rc).c_str()));
      mdb_cursor_close(seg_cur);
    }
    else
    {
      for (const uint64_t shard_id : bond.held_shard_ids)
      {
        if (archival_challenge_failed_at_height(block_height, p_id, bond, shard_id, settlement_epoch, &seal_cache))
          apply_archival_slash_one(block_height, seq, p_id, shard_id, settlement_epoch, floor);
      }
    }

    rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }

  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_bond cursor error during slash scan: ", rc).c_str()));

  mdb_cursor_close(cur);

  // The epoch marker is NOT written here. It records the FIRST epoch folded at
  // this height and is written once, by the scheduler
  // (process_archival_slash_at_height) -- see the note there for why per-epoch
  // writes could not express a multi-epoch fold.
}

void BlockchainLMDB::process_archival_slash_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  uint64_t last_epoch = get_archival_last_slash_epoch();
  uint64_t next_epoch = (last_epoch == std::numeric_limits<uint64_t>::max()) ? 0 : last_epoch + 1;
  uint32_t seq = 0;
  bool marker_written = false;

  while (true)
  {
    const uint64_t h_slash_deadline = shekyl_archival_epoch_slash_deadline_height(next_epoch);
    if (block_height <= h_slash_deadline)
      break;

    // The epoch marker records the FIRST epoch this height folded, written
    // ONCE per height.
    //
    // It used to be written per epoch by process_archival_slash_for_epoch, at
    // the fixed key (block_height, kArchivalSlashLogEpochMarkerSeq) -- so a
    // height that folded several epochs overwrote it and kept only the LAST.
    // The revert then read that value as "what this height folded" and was
    // wrong twice: it rewound `last_slash_epoch` to `last - 1`, so the
    // reconnect restarted at `last` and NEVER re-applied the epochs before it
    // whose slashes the same pop had just undone; and (once the settlement
    // writer is live) it deleted one epoch's settlement rows out of several.
    //
    // A single marker cannot express a span, and the span is what the revert
    // needs. Recording the FIRST epoch makes it expressible: the last is
    // recoverable at revert time from `archival_last_slash_epoch`, because
    // pops are tip-first, so any higher block's folds are already undone and
    // that value is exactly this height's last.
    //
    // One fold per height is the norm -- deadlines are SETTLEMENT_EPOCH_BLOCKS
    // apart and this runs on every connect -- which is why the old shape
    // survived. Nothing enforces it, so it was an invariant held by
    // circumstance, and the settlement revert was about to lean on it.
    if (!marker_written)
    {
      shekyl::db::ArchivalSlashRevertValue marker{};
      marker.settlement_epoch = next_epoch;
      append_archival_slash_log(block_height, shekyl::db::kArchivalSlashLogEpochMarkerSeq, marker);
      marker_written = true;
    }

    process_archival_slash_for_epoch(block_height, next_epoch, seq);
    set_archival_last_slash_epoch(next_epoch);

    if (next_epoch == std::numeric_limits<uint64_t>::max())
      break;
    ++next_epoch;
  }
}

void BlockchainLMDB::revert_archival_slashes_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival slash revert requires active write txn");

  uint64_t epoch_marker = std::numeric_limits<uint64_t>::max();

  shekyl::db::ArchivalSlashLogKey marker_key(block_height,
    shekyl::db::kArchivalSlashLogEpochMarkerSeq);
  MDB_val marker_k = marker_key.as_mdb_val();
  MDB_val marker_v;
  const int marker_get = mdb_get(*m_write_txn, m_archival_slash_log, &marker_k, &marker_v);
  if (marker_get == 0)
  {
    shekyl::db::ArchivalSlashRevertValue marker_entry{};
    if (!shekyl::db::ArchivalSlashRevertValue::decode(marker_v.mv_data, marker_v.mv_size,
          marker_entry))
      throw std::runtime_error("FATAL: archival slash epoch marker decode failed on pop");
    epoch_marker = marker_entry.settlement_epoch;
    mdb_del(*m_write_txn, m_archival_slash_log, &marker_k, nullptr);
  }
  else if (marker_get != MDB_NOTFOUND)
  {
    throw0(DB_ERROR(lmdb_error("Failed to read archival slash epoch marker on pop: ",
      marker_get).c_str()));
  }

  for (uint32_t seq = 0; ; ++seq)
  {
    shekyl::db::ArchivalSlashLogKey key(block_height, seq);
    MDB_val k = key.as_mdb_val();
    MDB_val v;
    const int get_result = mdb_get(*m_write_txn, m_archival_slash_log, &k, &v);
    if (get_result == MDB_NOTFOUND)
      break;
    if (get_result)
      throw0(DB_ERROR(lmdb_error("Failed to read archival slash log on pop: ", get_result).c_str()));

    shekyl::db::ArchivalSlashRevertValue entry{};
    if (!shekyl::db::ArchivalSlashRevertValue::decode(v.mv_data, v.mv_size, entry))
      throw std::runtime_error("FATAL: archival slash log decode failed on pop");

    if (entry.is_epoch_marker())
      continue;

    crypto::hash p_id{};
    std::memcpy(p_id.data, entry.p_id, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!load_archival_bond_value(p_id, bond))
      throw std::runtime_error("FATAL: archival slash revert without bond record");

    // The v2 log row records the pre-slash holdings kind, so the revert
    // restores the recorded pre-image directly — no amount/emptiness
    // heuristic (which mis-restored a slashed single-shard compact bond to
    // complete-tree whenever the amounts coincided).
    if (entry.holdings_pre_kind
      == shekyl::db::ArchivalSlashRevertValue::kPreKindCompleteTree)
    {
      bond.holdings_kind = shekyl::db::ArchivalBondValue::kHoldingsCompleteTree;
      bond.held_shard_ids.clear();
      bond.shard_add_epochs.clear(); // v6 coupling: complete-tree holds no shard list
      bond.bad_intervals.erase(
        std::remove_if(bond.bad_intervals.begin(), bond.bad_intervals.end(),
          [&](const shekyl::db::ArchivalBondValue::BadInterval& iv) {
            return iv.start_epoch <= entry.settlement_epoch
              && (iv.end_exclusive == std::numeric_limits<uint64_t>::max()
                || entry.settlement_epoch < iv.end_exclusive);
          }),
        bond.bad_intervals.end());
    }
    else if (!bond.holds_shard(entry.shard_id))
    {
      bond.held_shard_ids.push_back(entry.shard_id);
      // v6 coupling: restore the reverted shard's add-epoch (v3 log field),
      // keeping the parallel arrays coupled after the re-add.
      bond.shard_add_epochs.push_back(entry.slashed_shard_add_epoch);
      bond.bad_intervals.erase(
        std::remove_if(bond.bad_intervals.begin(), bond.bad_intervals.end(),
          [&](const shekyl::db::ArchivalBondValue::BadInterval& iv) {
            return iv.start_epoch == entry.settlement_epoch
              && iv.end_exclusive == std::numeric_limits<uint64_t>::max();
          }),
        bond.bad_intervals.end());
    }

    if (bond.bonded_total_atomic > std::numeric_limits<uint64_t>::max() - entry.slashed_amount)
      throw std::runtime_error("FATAL: per-P bonded_total_atomic overflow on slash revert");
    bond.bonded_total_atomic += entry.slashed_amount;

    // Reorg/pop_block path: write the mutated record whole so the v4
    // claimed-epoch set and first_paying_emission_height survive the revert,
    // preserving the "dedup state reverts with pop_block" invariant
    // (F-S1 / F-E5; FOLLOWUPS.md:1652).
    put_archival_bond_value(p_id, bond);

    const uint64_t bonded_total = get_total_bonded_atomic();
    if (bonded_total > std::numeric_limits<uint64_t>::max() - entry.slashed_amount)
      throw std::runtime_error("FATAL: total_bonded_atomic overflow on slash revert");
    set_total_bonded_atomic(bonded_total + entry.slashed_amount);

    const uint64_t burned_total = get_total_burned();
    if (entry.slashed_amount > burned_total)
      throw std::runtime_error("FATAL: total_burned underflow on slash revert");
    set_total_burned(burned_total - entry.slashed_amount);

    remove_archival_slash_applied(p_id, entry.shard_id, entry.settlement_epoch);
    mdb_del(*m_write_txn, m_archival_slash_log, &k, nullptr);
  }

  if (epoch_marker != std::numeric_limits<uint64_t>::max())
  {
    // `epoch_marker` is the FIRST epoch this height folded; `last` is its
    // LAST. Pops are tip-first, so any higher block's folds are already
    // reverted and `archival_last_slash_epoch` is exactly this height's last.
    const uint64_t last = get_archival_last_slash_epoch();
    if (last != std::numeric_limits<uint64_t>::max() && last < epoch_marker)
    {
      // The chain state says fewer epochs are folded than this height's own
      // journal says it folded. Loud, because silently skipping the rewind
      // would leave the reverted slashes unrepeatable and diverge the branch.
      throw std::runtime_error("FATAL: archival slash epoch marker precedes the last folded epoch");
    }
    if (last != std::numeric_limits<uint64_t>::max())
    {
      // SO-D6: settlement rows are a memoised derivation over final chain
      // state, not received evidence, so the revert DELETES them and lets the
      // re-connect recompute — the same shape revert_archival_epoch_close_at_
      // height uses for r_market/sigma_work/budget. The attestation-witness
      // table journals instead because its evidence is *received* and cannot be
      // reproduced on a losing branch; a settlement row can, by definition.
      //
      // Scoped to the SPAN this height folded, `[epoch_marker, last]`, and to
      // the same span the slash rewind below undoes — so the two cannot hold a
      // second opinion about what this height did. That was the intent when
      // this was scoped to a single epoch; the marker simply could not express
      // a multi-epoch fold, so "the epoch" and "what this height folded" were
      // the same value only when the fold was one epoch wide.
      for (uint64_t e = epoch_marker; e <= last; ++e)
      {
        delete_archival_settlement_for_epoch(e);
        if (e == std::numeric_limits<uint64_t>::max())
          break;  // saturating guard: `e <= last` cannot terminate at u64 max
      }

      if (epoch_marker == 0)
        set_archival_last_slash_epoch(std::numeric_limits<uint64_t>::max());
      else
        set_archival_last_slash_epoch(epoch_marker - 1);
    }
  }
}

void BlockchainLMDB::apply_archival_emission_claim(uint64_t block_height,
  const crypto::hash& p_id, const std::vector<uint64_t>& settlement_epochs)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // Exposed for direct invocation (C-1 connect dispatch + unit tests), so the
  // open-DB / active-write-txn preconditions are enforced here (every
  // mutating helper below dereferences *m_write_txn).
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival emission claim requires active write txn");
  if (settlement_epochs.empty())
    throw std::runtime_error("FATAL: archival emission claim with no settlement epochs");

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    throw std::runtime_error("FATAL: archival emission claim without bond record");

  // Journal the full pre-image BEFORE mutating (WS-2 §6.3): the connect
  // mutation is insert + window prune, and the prune's floor keys on the tip
  // settled epoch — non-monotonic under reorg. Recording only the inserted
  // epochs cannot restore what the prune evicted; a floor-lowering pop then
  // leaves an already-claimed epoch absent from the restored set and its
  // reward mints twice. The full pre-image restores byte-identically.
  shekyl::db::ArchivalEmissionClaimRevertValue log_entry{};
  std::memcpy(log_entry.p_id, p_id.data, 32);
  log_entry.pre_claimed_epochs = bond.claimed_settlement_epochs;
  log_entry.pre_first_paying_emission_height = bond.first_paying_emission_height;

  // The claim-window operand is the tip epoch index — the same `C` the
  // verify-side claim-age bound uses, so verify and connect cannot disagree
  // about expiry (E3 gating round §3 item 3 pin (b)).
  const uint64_t current_settled_epoch =
    shekyl_archival_settlement_epoch_at_height(block_height);

  constexpr size_t cap = shekyl::db::ArchivalBondValue::kMaxClaimedEpochs;
  uint64_t set_buf[cap] = {};
  size_t set_len = bond.claimed_settlement_epochs.size();
  // Unreachable through the codec (decode enforces the cap), kept as a
  // buffer-bounds guard for direct callers.
  if (set_len > cap)
    throw std::runtime_error("FATAL: archival emission claim set exceeds cap");
  std::copy(bond.claimed_settlement_epochs.begin(), bond.claimed_settlement_epochs.end(),
    set_buf);

  for (const uint64_t epoch : settlement_epochs)
  {
    const uint8_t rc = shekyl_archival_claimed_epochs_check_and_set(
      set_buf, &set_len, cap, epoch, current_settled_epoch);
    if (rc == SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_INSERTED)
      continue;
    // Never a soft skip (§6.2): a dedup hit here means verify's
    // contains-check and the block-level (P,E) pass were both bypassed, and
    // an unclaimable epoch means verify's finalization/age bounds were —
    // either way the block must not connect with a paid-but-unmarked epoch.
    if (rc == SHEKYL_ARCHIVAL_CLAIMED_EPOCHS_ALREADY_CLAIMED)
      throw std::runtime_error("FATAL: archival emission claim dedup breach at connect");
    throw std::runtime_error("FATAL: archival emission claim unclaimable epoch at connect");
  }
  bond.claimed_settlement_epochs.assign(set_buf, set_buf + set_len);
  // Set-once: 0 is the unset sentinel (unreachable as a real value — no
  // emission can pay before the first epoch closes at height SEB).
  if (bond.first_paying_emission_height == 0)
    bond.first_paying_emission_height = block_height;
  put_archival_bond_value(p_id, bond);

  // Append the journal row at the next free seq for this height. More than
  // one emission per block is legal (distinct P); more than one per (P,
  // block) is foreclosed by the block-level pass, but the probe + the
  // reverse-order restore in the revert keep this correct regardless.
  const uint32_t seq = archival_journal_next_seq<shekyl::db::ArchivalEmissionClaimLogKey>(
    *m_write_txn, m_archival_emission_claim_log, block_height,
    "archival emission claim log");
  archival_journal_put<shekyl::db::ArchivalEmissionClaimLogKey>(
    *m_write_txn, m_archival_emission_claim_log, block_height, seq, log_entry.encode(),
    "archival emission claim log");
}

void BlockchainLMDB::revert_archival_emission_claims_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival emission claim revert requires active write txn");

  const std::vector<shekyl::db::ArchivalEmissionClaimRevertValue> rows =
    archival_journal_read<shekyl::db::ArchivalEmissionClaimLogKey,
      shekyl::db::ArchivalEmissionClaimRevertValue>(
      *m_write_txn, m_archival_emission_claim_log, block_height,
      "archival emission claim log");

  // Restore in reverse connect order so the earliest pre-image lands last —
  // correct even if multiple rows exist for the same P at this height.
  for (auto it = rows.rbegin(); it != rows.rend(); ++it)
  {
    crypto::hash p_id{};
    std::memcpy(p_id.data, it->p_id, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!load_archival_bond_value(p_id, bond))
      throw std::runtime_error("FATAL: archival emission claim revert without bond record");

    bond.claimed_settlement_epochs = it->pre_claimed_epochs;
    bond.first_paying_emission_height = it->pre_first_paying_emission_height;
    // Write the record whole so holdings / bad intervals / bonded totals
    // (untouched by the claim) survive the restore (F-S1 / F-E5 shape).
    put_archival_bond_value(p_id, bond);
  }

  archival_journal_delete<shekyl::db::ArchivalEmissionClaimLogKey>(
    *m_write_txn, m_archival_emission_claim_log, block_height,
    static_cast<uint32_t>(rows.size()), "archival emission claim log");
}

void BlockchainLMDB::apply_archival_unbond(uint64_t block_height,
  const crypto::hash& p_id, uint64_t vin_bond_debit)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  // Exposed for direct invocation (bond-post connect dispatch + unit tests),
  // so the open-DB / active-write-txn preconditions are enforced here (every
  // mutating helper below dereferences *m_write_txn).
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival unbond requires active write txn");

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    throw std::runtime_error("FATAL: archival unbond without bond record");

  // Journal the record's full pre-image BEFORE mutating (gate-4 §3.5 connect
  // step 1, the emission WS-2 §6.3 shape): the vin carries the POST-connect
  // state, so the released holdings and the interval log are not
  // reconstructible at pop without this row. Only the three fields the
  // connect mutates are journaled — disjoint from the emission-claim
  // journal's fields, so the two reverts compose in any order.
  shekyl::db::ArchivalBondUnbondRevertValue log_entry{};
  std::memcpy(log_entry.p_id, p_id.data, 32);
  log_entry.pre_bonded_total = bond.bonded_total_atomic;
  log_entry.pre_holdings_kind = bond.holdings_kind;
  log_entry.pre_shard_ids = bond.held_shard_ids;
  log_entry.pre_shard_add_epochs = bond.shard_add_epochs; // v6 coupling
  log_entry.pre_bad_intervals.reserve(bond.bad_intervals.size());
  for (const auto& iv : bond.bad_intervals)
    log_entry.pre_bad_intervals.emplace_back(iv.start_epoch, iv.end_exclusive);

  // The Rust fold dictates the entire write set (gate-4 §4.3; rule 20 — no
  // consensus arithmetic here). Counter-threading obligation (§3.5): the
  // LIVE total is read here, per post, immediately before the fold — never a
  // caller-hoisted per-block value, which would clobber across multiple
  // bond posts in one block.
  const uint64_t total_bonded = get_total_bonded_atomic();
  const uint64_t unbond_epoch = shekyl_archival_settlement_epoch_at_height(block_height);
  uint64_t post_bonded_total = 0;
  uint8_t post_holdings_kind = 0;
  uint64_t post_held_shard_count = 0;
  uint64_t close_start = 0;
  uint64_t close_end = 0;
  uint64_t new_total_bonded = 0;
  const uint8_t fold_rc = shekyl_archival_unbond_connect(
    bond.bonded_total_atomic, bond.holdings_kind, bond.held_shard_ids.size(),
    bond.bad_intervals.size(), vin_bond_debit, total_bonded, unbond_epoch,
    &post_bonded_total, &post_holdings_kind, &post_held_shard_count,
    &close_start, &close_end, &new_total_bonded);
  // Never a soft skip: a fold error here means verify (plus the block-level
  // per-P pass) was bypassed or the record/counter state is corrupt — the
  // block must not connect with a half-applied release.
  if (fold_rc != SHEKYL_ARCHIVAL_UNBOND_APPLY_OK)
    throw std::runtime_error("FATAL: archival unbond connect fold failed (code "
      + std::to_string(static_cast<unsigned>(fold_rc)) + ")");
  if (post_held_shard_count != 0)
    throw std::runtime_error("FATAL: archival unbond fold returned non-empty holdings");

  // Write exactly what the fold dictates.
  bond.bonded_total_atomic = post_bonded_total;
  bond.holdings_kind = post_holdings_kind;
  bond.held_shard_ids.clear();
  bond.shard_add_epochs.clear(); // v6 coupling: Exited record holds no shards
  shekyl::db::ArchivalBondValue::BadInterval close{};
  close.start_epoch = close_start;
  close.end_exclusive = close_end;
  bond.bad_intervals.push_back(close);
  // Whole-record write so the v4 claimed set / first_paying_emission_height
  // (untouched by the release) survive (F-S1).
  put_archival_bond_value(p_id, bond);
  set_total_bonded_atomic(new_total_bonded);

  // Append the journal row at the next free seq for this height (the per-P
  // pass forecloses same-P multiplicity but distinct-P unbonds per block are
  // legal, so the seq space is shared per height).
  const uint32_t seq = archival_journal_next_seq<shekyl::db::ArchivalBondUnbondLogKey>(
    *m_write_txn, m_archival_bond_unbond_log, block_height, "archival bond unbond log");
  archival_journal_put<shekyl::db::ArchivalBondUnbondLogKey>(
    *m_write_txn, m_archival_bond_unbond_log, block_height, seq, log_entry.encode(),
    "archival bond unbond log");
}

void BlockchainLMDB::revert_archival_unbonds_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival unbond revert requires active write txn");

  const std::vector<shekyl::db::ArchivalBondUnbondRevertValue> rows =
    archival_journal_read<shekyl::db::ArchivalBondUnbondLogKey,
      shekyl::db::ArchivalBondUnbondRevertValue>(
      *m_write_txn, m_archival_bond_unbond_log, block_height, "archival bond unbond log");

  const uint64_t unbond_epoch = shekyl_archival_settlement_epoch_at_height(block_height);

  // Restore in reverse connect order (§5). Trailing-entry invariant (ratified
  // 2026-07-12, gate-4 §3.5): slashability ends at the Unbond connect — the
  // slash scheduler only examines currently held shards and an Exited record
  // holds none — so nothing ever appends after the clean close and the
  // trailing entry here is always this connect's close. pop_block still runs
  // revert_archival_slashes_at_height first as a defensive ordering belt; any
  // future change that let an interval land after a clean close would surface
  // in the fold below as MISSING_CLEAN_CLOSE, loud.
  for (auto it = rows.rbegin(); it != rows.rend(); ++it)
  {
    crypto::hash p_id{};
    std::memcpy(p_id.data, it->p_id, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!load_archival_bond_value(p_id, bond))
      throw std::runtime_error("FATAL: archival unbond revert without bond record");

    // Rust pop fold: validates the tip record is the connect's product
    // (Exited state + trailing clean close) and re-credits the counter
    // (checked add). Per-row live counter read — same threading as connect.
    const uint8_t has_trailing = bond.bad_intervals.empty() ? 0 : 1;
    const uint64_t trailing_start = has_trailing ? bond.bad_intervals.back().start_epoch : 0;
    const uint64_t trailing_end = has_trailing ? bond.bad_intervals.back().end_exclusive : 0;
    const uint64_t total_bonded = get_total_bonded_atomic();
    uint64_t new_total_bonded = 0;
    const uint8_t fold_rc = shekyl_archival_unbond_pop(
      bond.bonded_total_atomic, bond.held_shard_ids.size(),
      has_trailing, trailing_start, trailing_end, unbond_epoch,
      it->pre_bonded_total, total_bonded, &new_total_bonded);
    if (fold_rc != SHEKYL_ARCHIVAL_UNBOND_APPLY_OK)
      throw std::runtime_error("FATAL: archival unbond pop fold failed (code "
        + std::to_string(static_cast<unsigned>(fold_rc)) + ")");

    // Restore exactly the three mutated fields from the pre-image; the v4
    // claimed set / first_paying_emission_height (owned by the emission
    // journal) survive untouched (F-S1).
    bond.bonded_total_atomic = it->pre_bonded_total;
    bond.holdings_kind = it->pre_holdings_kind;
    bond.held_shard_ids = it->pre_shard_ids;
    bond.shard_add_epochs = it->pre_shard_add_epochs; // v6 coupling
    bond.bad_intervals.clear();
    bond.bad_intervals.reserve(it->pre_bad_intervals.size());
    for (const auto& iv : it->pre_bad_intervals)
    {
      shekyl::db::ArchivalBondValue::BadInterval entry{};
      entry.start_epoch = iv.first;
      entry.end_exclusive = iv.second;
      bond.bad_intervals.push_back(entry);
    }
    put_archival_bond_value(p_id, bond);
    set_total_bonded_atomic(new_total_bonded);
  }

  archival_journal_delete<shekyl::db::ArchivalBondUnbondLogKey>(
    *m_write_txn, m_archival_bond_unbond_log, block_height,
    static_cast<uint32_t>(rows.size()), "archival bond unbond log");
}

namespace {
// Rebuild the index-parallel add-epoch array for a POST holdings set from the
// pre-connect (shard_id -> add_epoch) association. The association is indexed
// once (O(n)) so a large post set does not force a quadratic per-shard scan at
// the 4096 holdings cap. The mapping is exact — a POST shard with no pre-image
// entry (and no override) is a fold/record desync, so it aborts loud rather
// than inventing an epoch.
std::vector<uint64_t> rebuild_shard_add_epochs(
  const std::vector<uint64_t>& post_shard_ids,
  const std::vector<uint64_t>& prev_shard_ids,
  const std::vector<uint64_t>& prev_add_epochs,
  const std::vector<uint64_t>& override_shard_ids, uint64_t override_add_epoch)
{
  std::unordered_map<uint64_t, uint64_t> prev_add_epoch_of;
  prev_add_epoch_of.reserve(prev_shard_ids.size());
  for (size_t i = 0; i < prev_shard_ids.size(); ++i)
    prev_add_epoch_of.emplace(prev_shard_ids[i], prev_add_epochs[i]);
  // The common no-override path (HoldingsUpdate-drop, standing-only Rebond)
  // skips populating the lookup set — an empty set answers every query false
  // without paying its buckets.
  std::unordered_set<uint64_t> overrides;
  if (!override_shard_ids.empty())
    overrides.insert(override_shard_ids.begin(), override_shard_ids.end());

  std::vector<uint64_t> out;
  out.reserve(post_shard_ids.size());
  for (const uint64_t s : post_shard_ids)
  {
    if (!overrides.empty() && overrides.count(s))
    {
      out.push_back(override_add_epoch);
      continue;
    }
    const auto it = prev_add_epoch_of.find(s);
    if (it == prev_add_epoch_of.end())
      throw std::runtime_error(
        "FATAL: bond-post carried shard missing from pre-image add-epochs");
    out.push_back(it->second);
  }
  return out;
}
} // namespace

// Shared bond-record connect-writer scaffold (gate-4 §4.4 / §3.4): txn guard,
// record load, v6 desync check, pre-image capture, live-counter read, the
// kind-specific Rust fold via `fold`, the optional in-place interval close,
// then the coupled-array rebuild + record/counter writes + the kind's journal
// append. HoldingsUpdate add/drop and Rebond differ ONLY in the fold and the
// journal row they supply; single-sourcing the scaffold means a
// journal/ordering/invariant change cannot land on one bond-post kind and
// silently miss another (the kinds must stay reorg-twinned with their pops).
void BlockchainLMDB::apply_archival_bond_record_update(uint64_t block_height,
  const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids,
  const char* arm, const bond_record_fold_t& fold, const bond_record_journal_t& journal)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error(std::string("FATAL: archival ") + arm
      + " requires active write txn");

  shekyl::db::ArchivalBondValue bond{};
  if (!load_archival_bond_value(p_id, bond))
    throw std::runtime_error(std::string("FATAL: archival ") + arm + " without bond record");
  if (bond.held_shard_ids.size() != bond.shard_add_epochs.size())
    throw std::runtime_error("FATAL: bond record shard id / add-epoch length desync");

  // Capture the pre-image of the mutated fields before mutating (the emission
  // WS-2 §6.3 shape); the journal row itself is put AFTER the record/counter
  // writes below — the same atomic txn, so the ordering is a readability
  // contract, not a durability one. The vin carries the POST holdings, so the
  // pre-state shard set and add-epochs are not reconstructible at pop without
  // this capture.
  BondRecordPreImage pre{};
  pre.pre_bonded_total = bond.bonded_total_atomic;
  pre.pre_shard_ids = bond.held_shard_ids;
  pre.pre_shard_add_epochs = bond.shard_add_epochs;

  // Counter-threading (§3.5): read the LIVE total per post, immediately before
  // the fold — never a caller-hoisted per-block value.
  const uint64_t total_bonded = get_total_bonded_atomic();
  BondRecordFoldOuts outs{};
  const uint8_t fold_rc = fold(bond, total_bonded, outs);
  if (fold_rc != 0)
    throw std::runtime_error(std::string("FATAL: archival ") + arm
      + " connect fold failed (code " + std::to_string(static_cast<unsigned>(fold_rc)) + ")");

  // Optional in-place interval close (Rebond Pin 3): the fold names the one
  // open interval; its pre-close start_epoch rides the pre-image so the pop
  // re-opens exactly that entry.
  if (outs.has_interval_close)
  {
    if (outs.closed_interval_index >= bond.bad_intervals.size())
      throw std::runtime_error(std::string("FATAL: archival ") + arm
        + " fold returned an out-of-range interval index");
    pre.closed_interval_start =
      bond.bad_intervals[outs.closed_interval_index].start_epoch;
    bond.bad_intervals[outs.closed_interval_index].end_exclusive =
      outs.interval_end_exclusive;
  }

  // Write exactly what the fold dictates: held_shard_ids = post, and the
  // index-parallel add-epochs rebuilt (carried shards keep theirs; the fold's
  // override shards take its override epoch).
  bond.shard_add_epochs = rebuild_shard_add_epochs(post_shard_ids,
    pre.pre_shard_ids, pre.pre_shard_add_epochs, outs.override_shard_ids,
    outs.override_add_epoch);
  bond.bonded_total_atomic = outs.new_bonded_total;
  bond.held_shard_ids = post_shard_ids;
  put_archival_bond_value(p_id, bond);
  set_total_bonded_atomic(outs.new_total_bonded);

  journal(pre, outs);
}

void BlockchainLMDB::put_archival_holdings_update_journal(uint64_t block_height,
  const crypto::hash& p_id, const BondRecordPreImage& pre)
{
  shekyl::db::ArchivalBondHoldingsUpdateRevertValue log_entry{};
  std::memcpy(log_entry.p_id, p_id.data, 32);
  log_entry.pre_bonded_total = pre.pre_bonded_total;
  log_entry.pre_shard_ids = pre.pre_shard_ids;
  log_entry.pre_shard_add_epochs = pre.pre_shard_add_epochs;
  const uint32_t seq = archival_journal_next_seq<shekyl::db::ArchivalBondHoldingsUpdateLogKey>(
    *m_write_txn, m_archival_bond_holdings_update_log, block_height,
    "archival bond holdings-update log");
  archival_journal_put<shekyl::db::ArchivalBondHoldingsUpdateLogKey>(
    *m_write_txn, m_archival_bond_holdings_update_log, block_height, seq, log_entry.encode(),
    "archival bond holdings-update log");
}

void BlockchainLMDB::apply_archival_holdings_update_add(uint64_t block_height,
  const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids)
{
  const uint64_t add_epoch = shekyl_archival_settlement_epoch_at_height(block_height);
  apply_archival_bond_record_update(block_height, p_id, post_shard_ids,
    "holdings-update-add",
    [&](const shekyl::db::ArchivalBondValue& bond, uint64_t total_bonded,
      BondRecordFoldOuts& outs) -> uint8_t {
      uint64_t added_shard_id = 0;
      uint64_t add_epoch_out = 0;
      const uint8_t rc = shekyl_archival_holdings_update_add_connect(
        bond.bonded_total_atomic,
        bond.held_shard_ids.empty() ? nullptr : bond.held_shard_ids.data(),
        bond.held_shard_ids.size(),
        post_shard_ids.empty() ? nullptr : post_shard_ids.data(),
        post_shard_ids.size(),
        total_bonded, add_epoch,
        &added_shard_id, &add_epoch_out, &outs.new_bonded_total, &outs.new_total_bonded);
      // The added shard takes E_add as its coupled add-epoch. Record stays
      // Bonded (ShardSetCompact) — no interval, no clean close (grace-tail).
      outs.override_shard_ids = {added_shard_id};
      outs.override_add_epoch = add_epoch_out;
      return rc;
    },
    [&](const BondRecordPreImage& pre, const BondRecordFoldOuts&) {
      put_archival_holdings_update_journal(block_height, p_id, pre);
    });
}

void BlockchainLMDB::apply_archival_holdings_update_drop(uint64_t block_height,
  const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids)
{
  apply_archival_bond_record_update(block_height, p_id, post_shard_ids,
    "holdings-update-drop",
    [&](const shekyl::db::ArchivalBondValue& bond, uint64_t total_bonded,
      BondRecordFoldOuts& outs) -> uint8_t {
      uint64_t dropped_shard_id = 0;
      uint64_t refund_atomic = 0;
      const uint8_t rc = shekyl_archival_holdings_update_drop_connect(
        bond.bonded_total_atomic,
        bond.held_shard_ids.empty() ? nullptr : bond.held_shard_ids.data(),
        bond.held_shard_ids.size(),
        post_shard_ids.empty() ? nullptr : post_shard_ids.data(),
        post_shard_ids.size(),
        total_bonded,
        &dropped_shard_id, &outs.new_bonded_total, &outs.new_total_bonded, &refund_atomic);
      // refund_atomic (== FLOOR) is the released collateral the vin's
      // bond_debit returns to circulation, CT-balanced on the wire — not a
      // ledger write here. Every POST shard is carried (the dropped one is
      // gone) — no override.
      (void)refund_atomic;
      return rc;
    },
    [&](const BondRecordPreImage& pre, const BondRecordFoldOuts&) {
      put_archival_holdings_update_journal(block_height, p_id, pre);
    });
}

void BlockchainLMDB::revert_archival_holdings_updates_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival holdings-update revert requires active write txn");

  const std::vector<shekyl::db::ArchivalBondHoldingsUpdateRevertValue> rows =
    archival_journal_read<shekyl::db::ArchivalBondHoldingsUpdateLogKey,
      shekyl::db::ArchivalBondHoldingsUpdateRevertValue>(
      *m_write_txn, m_archival_bond_holdings_update_log, block_height,
      "archival bond holdings-update log");

  // Restore in reverse connect order (§5). The record stays Bonded throughout,
  // so there is no Exited/clean-close check — the pop fold only guards that the
  // tip and pre-image balances differ by exactly one FLOOR.
  for (auto it = rows.rbegin(); it != rows.rend(); ++it)
  {
    crypto::hash p_id{};
    std::memcpy(p_id.data, it->p_id, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!load_archival_bond_value(p_id, bond))
      throw std::runtime_error("FATAL: archival holdings-update revert without bond record");

    const uint64_t total_bonded = get_total_bonded_atomic();
    uint64_t new_total_bonded = 0;
    const uint8_t fold_rc = shekyl_archival_holdings_update_pop(
      bond.bonded_total_atomic, it->pre_bonded_total, total_bonded, &new_total_bonded);
    if (fold_rc != SHEKYL_ARCHIVAL_HU_APPLY_OK)
      throw std::runtime_error("FATAL: archival holdings-update pop fold failed (code "
        + std::to_string(static_cast<unsigned>(fold_rc)) + ")");

    // Restore exactly the mutated fields from the pre-image; holdings_kind
    // (stays ShardSetCompact) and bad_intervals (untouched by the connect) were
    // never journaled and need no restore.
    bond.bonded_total_atomic = it->pre_bonded_total;
    bond.held_shard_ids = it->pre_shard_ids;
    bond.shard_add_epochs = it->pre_shard_add_epochs;
    put_archival_bond_value(p_id, bond);
    set_total_bonded_atomic(new_total_bonded);
  }

  archival_journal_delete<shekyl::db::ArchivalBondHoldingsUpdateLogKey>(
    *m_write_txn, m_archival_bond_holdings_update_log, block_height,
    static_cast<uint32_t>(rows.size()), "archival bond holdings-update log");
}

void BlockchainLMDB::apply_archival_rebond(uint64_t block_height,
  const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids)
{
  const uint64_t rebond_epoch = shekyl_archival_settlement_epoch_at_height(block_height);
  apply_archival_bond_record_update(block_height, p_id, post_shard_ids, "rebond",
    [&](const shekyl::db::ArchivalBondValue& bond, uint64_t total_bonded,
      BondRecordFoldOuts& outs) -> uint8_t {
      // Marshal the interval log as flattened (start, end_exclusive) pairs —
      // the fold owns the open-interval selection and the E_rebond + 1 close.
      const std::vector<uint64_t> intervals_flat = archival_bad_intervals_flat(bond);
      std::vector<uint64_t> added(post_shard_ids.size(), 0);
      size_t added_len = 0;
      uint64_t add_epoch = 0;
      uint64_t closed_idx = 0;
      uint64_t interval_end = 0;
      const uint8_t rc = shekyl_archival_rebond_connect(
        bond.bonded_total_atomic,
        bond.held_shard_ids.empty() ? nullptr : bond.held_shard_ids.data(),
        bond.held_shard_ids.size(),
        intervals_flat.empty() ? nullptr : intervals_flat.data(),
        bond.bad_intervals.size(),
        post_shard_ids.empty() ? nullptr : post_shard_ids.data(),
        post_shard_ids.size(),
        total_bonded, rebond_epoch,
        added.empty() ? nullptr : added.data(), added.size(), &added_len,
        &add_epoch, &closed_idx, &interval_end,
        &outs.new_bonded_total, &outs.new_total_bonded);
      if (rc != SHEKYL_ARCHIVAL_REBOND_APPLY_OK)
        return rc;
      added.resize(added_len);
      // Added shards (post ∖ current) take E_rebond as their coupled
      // add-epoch (Pin 7); the open interval closes IN PLACE at E_rebond + 1
      // (Pin 3 — the record stays Bonded, standing resumes at E_rebond + 1).
      outs.override_shard_ids = std::move(added);
      outs.override_add_epoch = add_epoch;
      outs.has_interval_close = true;
      outs.closed_interval_index = closed_idx;
      outs.interval_end_exclusive = interval_end;
      return rc;
    },
    [&](const BondRecordPreImage& pre, const BondRecordFoldOuts& outs) {
      // The closed interval's identity rides the journal row so the pop
      // re-opens exactly that entry; pre_bonded_total == 0 is legal (terminal
      // reinstatement).
      shekyl::db::ArchivalBondRebondRevertValue log_entry{};
      std::memcpy(log_entry.p_id, p_id.data, 32);
      log_entry.pre_bonded_total = pre.pre_bonded_total;
      log_entry.closed_interval_index =
        static_cast<uint32_t>(outs.closed_interval_index);
      log_entry.closed_interval_start = pre.closed_interval_start;
      log_entry.pre_shard_ids = pre.pre_shard_ids;
      log_entry.pre_shard_add_epochs = pre.pre_shard_add_epochs;
      const uint32_t seq = archival_journal_next_seq<shekyl::db::ArchivalBondRebondLogKey>(
        *m_write_txn, m_archival_bond_rebond_log, block_height, "archival bond rebond log");
      archival_journal_put<shekyl::db::ArchivalBondRebondLogKey>(
        *m_write_txn, m_archival_bond_rebond_log, block_height, seq, log_entry.encode(),
        "archival bond rebond log");
    });
}

void BlockchainLMDB::revert_archival_rebonds_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival rebond revert requires active write txn");

  const std::vector<shekyl::db::ArchivalBondRebondRevertValue> rows =
    archival_journal_read<shekyl::db::ArchivalBondRebondLogKey,
      shekyl::db::ArchivalBondRebondRevertValue>(
      *m_write_txn, m_archival_bond_rebond_log, block_height, "archival bond rebond log");

  const uint64_t rebond_epoch = shekyl_archival_settlement_epoch_at_height(block_height);

  // Restore in reverse connect order (§5). The record stays Bonded throughout;
  // the pop fold guards the counter delta (a non-negative whole number of
  // FLOORs — zero for standing-only) and the identity belts below pin the
  // re-opened interval to the connect's product.
  for (auto it = rows.rbegin(); it != rows.rend(); ++it)
  {
    crypto::hash p_id{};
    std::memcpy(p_id.data, it->p_id, 32);

    shekyl::db::ArchivalBondValue bond{};
    if (!load_archival_bond_value(p_id, bond))
      throw std::runtime_error("FATAL: archival rebond revert without bond record");

    const uint64_t total_bonded = get_total_bonded_atomic();
    uint64_t new_total_bonded = 0;
    const uint8_t fold_rc = shekyl_archival_rebond_pop(
      bond.bonded_total_atomic, it->pre_bonded_total, total_bonded, &new_total_bonded);
    if (fold_rc != SHEKYL_ARCHIVAL_REBOND_APPLY_OK)
      throw std::runtime_error("FATAL: archival rebond pop fold failed (code "
        + std::to_string(static_cast<unsigned>(fold_rc)) + ")");

    // Re-open the journaled interval: the entry must exist, carry the
    // journaled start, and be the connect's close (end == E_rebond + 1) —
    // anything else means the journal does not describe this record's tip
    // state (desync), which must be loud, not papered over.
    const size_t idx = it->closed_interval_index;
    if (idx >= bond.bad_intervals.size()
      || bond.bad_intervals[idx].start_epoch != it->closed_interval_start
      || bond.bad_intervals[idx].end_exclusive != rebond_epoch + 1)
      throw std::runtime_error(
        "FATAL: archival rebond revert interval desync (journal does not match tip)");
    bond.bad_intervals[idx].end_exclusive = std::numeric_limits<uint64_t>::max();

    // Restore exactly the mutated fields from the pre-image; holdings_kind
    // (stays ShardSetCompact) and the other intervals were never touched.
    bond.bonded_total_atomic = it->pre_bonded_total;
    bond.held_shard_ids = it->pre_shard_ids;
    bond.shard_add_epochs = it->pre_shard_add_epochs;
    put_archival_bond_value(p_id, bond);
    set_total_bonded_atomic(new_total_bonded);
  }

  archival_journal_delete<shekyl::db::ArchivalBondRebondLogKey>(
    *m_write_txn, m_archival_bond_rebond_log, block_height,
    static_cast<uint32_t>(rows.size()), "archival bond rebond log");
}

bool BlockchainLMDB::archival_shard_freeze_height(uint64_t shard_id, uint64_t& out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalShardKey key(shard_id);
  MDB_val k = key.as_mdb_val();
  TXN_PREFIX_RDONLY();
  MDB_val v;
  const int rc = mdb_get(m_txn, m_archival_shard_segment, &k, &v);
  TXN_POSTFIX_RDONLY();
  if (rc == MDB_NOTFOUND)
    return false;
  if (rc)
    throw0(DB_ERROR(lmdb_error(
      "Failed to get archival_shard_segment for freeze height: ", rc).c_str()));

  shekyl::db::ArchivalShardSegmentValue segment{};
  if (!shekyl::db::ArchivalShardSegmentValue::decode(v.mv_data, v.mv_size, segment))
    return false;
  out = segment.freeze_height;
  return true;
}

std::vector<uint64_t> BlockchainLMDB::archival_bond_last_served_epochs(
  const crypto::hash& p_id, const std::vector<uint64_t>& shard_ids) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // One reverse-cursor seek per held shard over the BE composite key
  // `P_id ‖ BE64(shard) ‖ BE64(epoch)` (P2B-8 Q1: the byte-sort IS
  // (P, shard, epoch) ascending, so shard s's last-served epoch is the
  // predecessor of the probe `P ‖ BE64(s) ‖ BE64(u64::MAX)`). Never-served
  // shards are omitted from the result — the Rust fold treats them as
  // carrying no cooldown anchor.
  std::vector<uint64_t> out;
  out.reserve(shard_ids.size());

  TXN_PREFIX_RDONLY();
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(m_txn, m_archival_serve_credit, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_serve_credit cursor for last-served: ",
      rc).c_str()));

  for (const uint64_t shard_id : shard_ids)
  {
    shekyl::db::ArchivalServeCreditKey probe(
      reinterpret_cast<const uint8_t*>(p_id.data), shard_id,
      std::numeric_limits<uint64_t>::max());
    MDB_val probe_val = probe.as_mdb_val();
    MDB_val k = probe_val;
    MDB_val v;
    rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    if (rc == 0)
    {
      // SET_RANGE positions at the first key >= probe. An exact hit IS the
      // shard's max (epoch == u64::MAX, unreachable in practice but handled
      // exactly); otherwise the predecessor holds it, if it shares the
      // (P, shard) prefix.
      if (k.mv_size == probe_val.mv_size
          && std::memcmp(k.mv_data, probe_val.mv_data, k.mv_size) == 0)
      {
        out.push_back(std::numeric_limits<uint64_t>::max());
        continue;
      }
      rc = mdb_cursor_get(cur, &k, &v, MDB_PREV);
    }
    else if (rc == MDB_NOTFOUND)
    {
      // Probe is past every key — the table's last entry is the predecessor.
      rc = mdb_cursor_get(cur, &k, &v, MDB_LAST);
    }
    if (rc == MDB_NOTFOUND)
      continue; // empty table or no predecessor: shard never served
    if (rc)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("Failed archival_serve_credit reverse seek: ", rc).c_str()));
    }
    if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
    {
      mdb_cursor_close(cur);
      throw std::runtime_error("FATAL: archival_serve_credit key size mismatch at last-served");
    }
    const auto* kb = static_cast<const uint8_t*>(k.mv_data);
    if (std::memcmp(kb, p_id.data, 32) != 0
        || shekyl::db::load_be64(kb + 32) != shard_id)
      continue; // predecessor belongs to another (P, shard): never served
    out.push_back(shekyl::db::load_be64(kb + 40));
  }

  mdb_cursor_close(cur);
  TXN_POSTFIX_RDONLY();
  return out;
}

std::vector<uint64_t> BlockchainLMDB::archival_bond_all_last_served_epochs(
  const crypto::hash& p_id) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // The all-shards form of the last-served marshal, for CompleteTree records
  // (they store no shard list — the record "holds" every shard). Hop scan
  // over the same BE composite key `P_id ‖ BE64(shard) ‖ BE64(epoch)`: seek
  // to each served shard's first row, jump straight to that shard's max
  // epoch via the `epoch = u64::MAX` probe, record it, then hop to the next
  // shard's prefix — two seeks per *served* shard, never a row-by-row walk
  // of a shard's whole epoch history.
  std::vector<uint64_t> out;

  TXN_PREFIX_RDONLY();
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(m_txn, m_archival_serve_credit, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_serve_credit cursor for all-last-served: ",
      rc).c_str()));

  uint64_t next_shard = 0;
  bool shard_probe_wrapped = false;
  while (!shard_probe_wrapped)
  {
    // First row at or past (P, next_shard, 0): the next served shard, if any.
    shekyl::db::ArchivalServeCreditKey lo_probe(
      reinterpret_cast<const uint8_t*>(p_id.data), next_shard, 0);
    MDB_val lo = lo_probe.as_mdb_val();
    MDB_val k = lo;
    MDB_val v;
    rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    if (rc == MDB_NOTFOUND)
      break;
    if (rc)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("Failed archival_serve_credit forward seek: ", rc).c_str()));
    }
    if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
    {
      mdb_cursor_close(cur);
      throw std::runtime_error("FATAL: archival_serve_credit key size mismatch at all-last-served");
    }
    const auto* kb = static_cast<const uint8_t*>(k.mv_data);
    if (std::memcmp(kb, p_id.data, 32) != 0)
      break; // past P's prefix: no more served shards
    const uint64_t shard_id = shekyl::db::load_be64(kb + 32);

    // This shard's max epoch: predecessor of (P, shard, u64::MAX) — the same
    // reverse-seek the per-shard form uses; an exact hit IS the max.
    shekyl::db::ArchivalServeCreditKey hi_probe(
      reinterpret_cast<const uint8_t*>(p_id.data), shard_id,
      std::numeric_limits<uint64_t>::max());
    MDB_val hi = hi_probe.as_mdb_val();
    k = hi;
    rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    if (rc == 0
        && k.mv_size == hi.mv_size
        && std::memcmp(k.mv_data, hi.mv_data, k.mv_size) == 0)
    {
      out.push_back(std::numeric_limits<uint64_t>::max());
    }
    else
    {
      if (rc == 0)
        rc = mdb_cursor_get(cur, &k, &v, MDB_PREV);
      else if (rc == MDB_NOTFOUND)
        rc = mdb_cursor_get(cur, &k, &v, MDB_LAST);
      if (rc)
      {
        mdb_cursor_close(cur);
        throw0(DB_ERROR(lmdb_error("Failed archival_serve_credit reverse seek: ", rc).c_str()));
      }
      if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
      {
        mdb_cursor_close(cur);
        throw std::runtime_error("FATAL: archival_serve_credit key size mismatch at all-last-served");
      }
      kb = static_cast<const uint8_t*>(k.mv_data);
      // The forward seek above proved at least one (P, shard, E) row exists,
      // so the predecessor of (P, shard, MAX) is within this shard's prefix.
      if (std::memcmp(kb, p_id.data, 32) != 0
          || shekyl::db::load_be64(kb + 32) != shard_id)
      {
        mdb_cursor_close(cur);
        throw std::runtime_error("FATAL: archival_serve_credit reverse seek left the shard prefix");
      }
      out.push_back(shekyl::db::load_be64(kb + 40));
    }

    if (shard_id == std::numeric_limits<uint64_t>::max())
      shard_probe_wrapped = true;
    else
      next_shard = shard_id + 1;
  }

  mdb_cursor_close(cur);
  TXN_POSTFIX_RDONLY();
  return out;
}

void BlockchainLMDB::delete_archival_r_market_for_epoch(uint64_t settlement_epoch)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_r_market, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_r_market cursor for delete: ", rc).c_str()));

  // After mdb_cursor_del the cursor carries C_DEL: the next MDB_NEXT yields
  // the item that moved into the deleted slot, so one op-rotating loop
  // visits every row exactly once (same pattern in all archival delete loops).
  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalRMarketKeySize)
      throw std::runtime_error("FATAL: archival_r_market key size mismatch on delete");
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data) + 8);
    if (epoch == settlement_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_r_market row: ", rc).c_str()));
    }
  }
  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_r_market cursor error on delete: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_r_market_before_epoch(uint64_t prune_below_epoch)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_r_market, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_r_market cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalRMarketKeySize)
      throw std::runtime_error("FATAL: archival_r_market key size mismatch on prune");
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data) + 8);
    if (epoch < prune_below_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_r_market row on prune: ", rc).c_str()));
    }
  }
  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_r_market cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_sigma_work_for_epoch(uint64_t settlement_epoch)
{
  shekyl::db::ArchivalSigmaWorkKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  const int result = mdb_del(*m_write_txn, m_archival_sigma_work, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to delete archival_sigma_work row: ", result).c_str()));
}

void BlockchainLMDB::delete_archival_sigma_work_before_epoch(uint64_t prune_below_epoch)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_sigma_work, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_sigma_work cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalSigmaWorkKeySize)
      throw std::runtime_error("FATAL: archival_sigma_work key size mismatch on prune");
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data));
    if (epoch < prune_below_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_sigma_work row on prune: ", rc).c_str()));
    }
  }
  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_sigma_work cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_serve_credit_before_epoch(uint64_t prune_below_epoch)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_serve_credit, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_serve_credit cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
      throw std::runtime_error("FATAL: archival_serve_credit key size mismatch on prune");
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data) + 40);
    if (epoch < prune_below_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_serve_credit row on prune: ", rc).c_str()));
    }
  }
  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_serve_credit cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::set_archival_settlement(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch, uint32_t passes, uint32_t issued)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival settlement write requires active write txn");

  // Rust owns the value: it folds (passes, issued) and emits the three bytes.
  // C++ never composes an outcome byte, so a settlement whose outcome
  // contradicts its counts is not a thing this side can express (SO-D2).
  std::array<uint8_t, 3> row{};
  static_assert(sizeof(row) == 3, "settlement row is outcome||passes||issued");
  if (shekyl_archival_settlement_row_len() != row.size())
    throw std::runtime_error("FATAL: settlement row length disagrees with the Rust definition");

  const uint8_t rc = shekyl_archival_settlement_row(passes, issued, row.data());
  if (rc != 0)
    throw std::runtime_error("FATAL: settlement fold refused (P, shard, E) counts; code "
      + std::to_string(static_cast<unsigned>(rc)));

  shekyl::db::ArchivalServeCreditKey key(
    reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v{ row.size(), row.data() };
  const int result = mdb_put(*m_write_txn, m_archival_settlement, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to write archival_settlement row: ", result).c_str()));
}

bool BlockchainLMDB::get_archival_settlement(const crypto::hash& p_id, uint64_t shard_id,
  uint64_t settlement_epoch, std::array<uint8_t, 3>& out_row) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalServeCreditKey key(
    reinterpret_cast<const uint8_t*>(p_id.data), shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  // Same read helper the serve-credit bit uses -- this table has no dedicated
  // cursor member, and adding one would be plumbing for a reader that does a
  // single point lookup.
  const int result = archival_db_get(m_archival_settlement, &k, &v);
  if (result == MDB_NOTFOUND)
    return false;
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to read archival_settlement row: ", result).c_str()));
  if (v.mv_size != out_row.size())
    throw std::runtime_error("FATAL: archival_settlement value size mismatch");

  std::memcpy(out_row.data(), v.mv_data, out_row.size());
  return true;
}

void BlockchainLMDB::delete_archival_settlement_for_epoch(uint64_t settlement_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival settlement revert requires active write txn");

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_settlement, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_settlement cursor for revert: ", rc).c_str()));

  // Every exit closes the cursor first, including the throwing ones.
  //
  // **This is the file's MINORITY shape, and saying so is the point.** The
  // twin directly above -- `delete_archival_serve_credit_before_epoch` -- is
  // byte-for-byte this function with a different table and does NOT close on
  // its throw paths, and it is one of roughly eighteen such functions here.
  // This one was written by copying that idiom, so a reader who assumes the
  // difference is meaningful should know it is a correction, not a
  // distinction between the two tables.
  //
  // Why correct it rather than match the neighbours: `mdb_cursor_close`
  // requires a write cursor's transaction to still be LIVE (lmdb.h), so the
  // close must happen HERE, while the throw is still unwinding this frame and
  // before any caller aborts the txn -- there is no correct place to do it
  // later. Severity is bounded either way, and that is worth stating too so
  // nobody reads this as a leak fix: the txn frees its cursors when it ends
  // ("It and its cursors must not be used again", lmdb.h on commit/abort), and
  // every throw here is already on a fatal path. What is fixed is a handle
  // held open across an unwind, for three lines.
  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
    {
      mdb_cursor_close(cur);
      throw std::runtime_error("FATAL: archival_settlement key size mismatch on revert");
    }
    // Epoch is the last 8 bytes: P_id[32] || BE(shard) || BE(E).
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data) + 40);
    if (epoch == settlement_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
      {
        mdb_cursor_close(cur);
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_settlement row on revert: ", rc).c_str()));
      }
    }
  }
  if (rc != MDB_NOTFOUND)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("archival_settlement cursor error on revert: ", rc).c_str()));
  }
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_budget_for_epoch(uint64_t settlement_epoch)
{
  shekyl::db::ArchivalBudgetKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  const int result = mdb_del(*m_write_txn, m_archival_budget, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to delete archival_budget row: ", result).c_str()));
}

void BlockchainLMDB::delete_archival_budget_before_epoch(uint64_t prune_below_epoch)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_budget, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_budget cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalBudgetKeySize)
      throw std::runtime_error("FATAL: archival_budget key size mismatch on prune");
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data));
    if (epoch >= prune_below_epoch)
      break;  // BE keys iterate in numeric order; everything past here is retained.
    rc = mdb_cursor_del(cur, 0);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to delete archival_budget row on prune: ", rc).c_str()));
  }
  if (rc && rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_budget cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_budget_accrual_before_height(uint64_t prune_below_height)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_budget_accrual, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_budget_accrual cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalBudgetAccrualKeySize)
      throw std::runtime_error("FATAL: archival_budget_accrual key size mismatch on prune");
    const uint64_t height = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data));
    if (height >= prune_below_height)
      break;  // BE keys iterate in numeric order; everything past here is retained.
    rc = mdb_cursor_del(cur, 0);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to delete archival_budget_accrual row on prune: ", rc).c_str()));
  }
  if (rc && rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_budget_accrual cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

void BlockchainLMDB::delete_archival_attestation_witness_before_height(uint64_t prune_below_height)
{
  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_attestation_witness, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_attestation_witness cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != sizeof(uint64_t))
      throw std::runtime_error("FATAL: archival_attestation_witness key size mismatch on prune");
    // Native-endian uint64 key (MDB_INTEGERKEY) — read directly, not load_be64.
    uint64_t height;
    memcpy(&height, k.mv_data, sizeof(height));
    if (height >= prune_below_height)
      break;  // MDB_INTEGERKEY iterates in numeric order; everything past here is retained.
    rc = mdb_cursor_del(cur, 0);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to delete archival_attestation_witness row on prune: ", rc).c_str()));
  }
  if (rc && rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_attestation_witness cursor error on prune: ", rc).c_str()));
  mdb_cursor_close(cur);
}

// Retention prune for the settlement table, mirroring
// delete_archival_serve_credit_before_epoch: same tail-epoch scan, same
// reason (SO-D2's key puts the epoch LAST so a pair's epochs range-scan in
// order, which costs a full-table walk here).
//
// Without this the table was the ONE epoch-scoped archival table the shared
// prune did not visit, so its rows would have accumulated for the life of the
// chain the moment the writer went live. It is latent today only because
// set_archival_settlement has no production caller yet -- which is exactly
// the kind of "not reachable, so not wrong" that stops being true silently.
void BlockchainLMDB::delete_archival_settlement_before_epoch(uint64_t prune_below_epoch)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival settlement prune requires active write txn");

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_settlement, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_settlement cursor for prune: ", rc).c_str()));

  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalServeCreditKeySize)
    {
      mdb_cursor_close(cur);
      throw std::runtime_error("FATAL: archival_settlement key size mismatch on prune");
    }
    // Epoch is the last 8 bytes: P_id[32] || BE(shard) || BE(E).
    const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data) + 40);
    if (epoch < prune_below_epoch)
    {
      rc = mdb_cursor_del(cur, 0);
      if (rc)
      {
        mdb_cursor_close(cur);
        throw0(DB_ERROR(lmdb_error("Failed to delete archival_settlement row on prune: ", rc).c_str()));
      }
    }
  }
  if (rc != MDB_NOTFOUND)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("archival_settlement cursor error on prune: ", rc).c_str()));
  }
  mdb_cursor_close(cur);
}

void BlockchainLMDB::prune_archival_epochs_before(uint64_t prune_below_epoch)
{
  if (prune_below_epoch == 0)
    return;

  delete_archival_serve_credit_before_epoch(prune_below_epoch);
  // SO-D1's verdict rows retire on the same horizon as the evidence they fold.
  delete_archival_settlement_before_epoch(prune_below_epoch);
  delete_archival_r_market_before_epoch(prune_below_epoch);
  delete_archival_sigma_work_before_epoch(prune_below_epoch);
  delete_archival_budget_before_epoch(prune_below_epoch);
  // Accrual rows below the pruned epochs' first height: only needed for a
  // re-close within the reorg window, which the retention window dominates
  // (ARCHIVAL_BUDGET_SCHEDULE.md §3.2).
  delete_archival_budget_accrual_before_height(
    shekyl_archival_epoch_open_height(prune_below_epoch));
  // Credit-wire attestation witnesses (ARCHIVAL_CREDIT_WIRE.md §3.2/§4): the
  // admission-only r + signatures are dead once a block is beyond the reorg
  // window that could re-drive its connect. Pruned at the same epoch-open height
  // boundary as the accrual rows — the retention window dominates the reorg
  // window, so this drops them no earlier than they can be needed. (Settlement
  // reads the kept tx_extra headers, never this witness — the §4 seam.)
  //
  // The floor goes through archival_attestation_witness_key: the accrual table is
  // keyed at the block INDEX, this one at index + 1, so handing both the same
  // 0-based epoch-open height would leave the retired epoch's last block holding
  // its witness for a whole extra epoch. This is the one site that starts from a
  // 0-based index, so it is the one the helper exists for.
  delete_archival_attestation_witness_before_height(
    archival_attestation_witness_key(shekyl_archival_epoch_open_height(prune_below_epoch)));
}

uint64_t BlockchainLMDB::get_archival_frozen_shard_count_on_write_txn() const
{
  // Persisted pop-symmetric frozen-shard counter
  // (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4): +1 in the CREATE-only row
  // writer, −1 per row the pop revert deletes, so it moves in lockstep with
  // the segment table by construction. Read on the write txn so the close
  // sees same-txn freezes (the M1 §1.1 same-snapshot pin).
  const std::string key = "archival_frozen_shard_count";
  MDB_val k = {key.size(), const_cast<char*>(key.data())};
  MDB_val v;
  const int rc = mdb_get(*m_write_txn, m_properties, &k, &v);
  if (rc == MDB_NOTFOUND)
    return 0;
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to read archival frozen-shard counter: ", rc).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw std::runtime_error("FATAL: archival frozen-shard counter size mismatch");
  uint64_t count = 0;
  memcpy(&count, v.mv_data, sizeof(count));
  return count;
}

void BlockchainLMDB::set_archival_frozen_shard_count_on_write_txn(uint64_t count)
{
  const std::string key = "archival_frozen_shard_count";
  MDB_val k = {key.size(), const_cast<char*>(key.data())};
  MDB_val v = {sizeof(count), &count};
  const int rc = mdb_put(*m_write_txn, m_properties, &k, &v, 0);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to set archival frozen-shard counter: ", rc).c_str()));
}

uint64_t BlockchainLMDB::count_frozen_shard_rows_by_walk_for_test() const
{
  // Differential oracle for the O(1) counter (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md
  // §4.4): the pre-counter full-table walk, retained as the test-side truth
  // the counter is differential-tested against across freeze/pop/re-apply
  // cycles. Counts every decodable row (per-row decode failure is the same
  // loud abort as the old count pass); the close-boundary height check lives
  // in the production reader's frontier probe, not here — every production
  // row satisfies it by construction. Test-support only; no production
  // caller (tripwire-pinned).
  if (!m_write_txn)
    throw std::runtime_error("FATAL: frozen-shard walk requires active write txn");

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_shard_segment, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_shard_segment cursor for frozen-shard walk: ", rc).c_str()));
  // RAII close so the loud-abort throws below cannot strand the cursor.
  const std::unique_ptr<MDB_cursor, decltype(&mdb_cursor_close)> cur_guard(cur, &mdb_cursor_close);

  uint64_t count = 0;
  MDB_val k, v;
  MDB_cursor_op op = MDB_FIRST;
  while ((rc = mdb_cursor_get(cur, &k, &v, op)) == 0)
  {
    op = MDB_NEXT;
    if (k.mv_size != shekyl::db::kArchivalShardKeySize)
      throw std::runtime_error("FATAL: archival_shard_segment key size mismatch at frozen-shard walk");
    shekyl::db::ArchivalShardSegmentValue segment{};
    if (!shekyl::db::ArchivalShardSegmentValue::decode(v.mv_data, v.mv_size, segment))
      throw std::runtime_error("FATAL: archival_shard_segment decode failed at frozen-shard walk");
    ++count;
  }
  if (rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_shard_segment cursor error at frozen-shard walk: ", rc).c_str()));
  return count;
}

uint64_t BlockchainLMDB::count_frozen_shards_at_close(uint64_t h_close) const
{
  // The single counting read over m_archival_shard_segment
  // (ARCHIVAL_REWARD_GATE_M1.md §1.1 count-pass discipline), now O(1): the
  // persisted pop-symmetric counter (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md
  // §4.4) replaces the full-table walk the pre-counter implementation
  // repeated at every close. Runs on the close's write txn so the count and
  // the close see the same snapshot. Two O(1) frontier checks on the
  // MDB_LAST row keep the §1.1 pins armed: the row must decode (the M3-2
  // loud abort, exercised at the frontier), and its freeze_height must
  // satisfy the close boundary — equality counts, and under the production
  // writer (rows freeze at or below the writing block's height, O-2
  // monotone) a frontier row above h_close is tree/registry disagreement:
  // corruption, aborted as loudly as a decode failure, never leniently
  // filtered (the fixture-branch "future rows don't count yet" disposition
  // is superseded — M1 §11.11).
  if (!m_write_txn)
    throw std::runtime_error("FATAL: frozen-shard count requires active write txn");

  const uint64_t count = get_archival_frozen_shard_count_on_write_txn();

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_shard_segment, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_shard_segment cursor for frozen-shard frontier check: ", rc).c_str()));
  const std::unique_ptr<MDB_cursor, decltype(&mdb_cursor_close)> cur_guard(cur, &mdb_cursor_close);

  MDB_val k, v;
  rc = mdb_cursor_get(cur, &k, &v, MDB_LAST);
  if (rc == MDB_NOTFOUND)
  {
    // Counter/table divergence in either direction is a loud abort: a
    // silently-wrong operand is a consensus fork in the gating direction.
    if (count != 0)
      throw std::runtime_error("FATAL: frozen-shard counter nonzero over an empty segment table");
    return 0;
  }
  if (rc)
    throw0(DB_ERROR(lmdb_error("archival_shard_segment cursor error at frozen-shard frontier check: ", rc).c_str()));
  if (count == 0)
    throw std::runtime_error("FATAL: frozen-shard counter zero with segment rows present");
  if (k.mv_size != shekyl::db::kArchivalShardKeySize)
    throw std::runtime_error("FATAL: archival_shard_segment key size mismatch at frozen-shard frontier check");
  shekyl::db::ArchivalShardSegmentValue segment{};
  if (!shekyl::db::ArchivalShardSegmentValue::decode(v.mv_data, v.mv_size, segment))
    throw std::runtime_error("FATAL: archival_shard_segment decode failed at frozen-shard frontier check");
  if (!(segment.freeze_height <= h_close))
    throw std::runtime_error("FATAL: frontier segment row frozen above the close height");
  return count;
}

bool BlockchainLMDB::has_archival_sigma_work_row(uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalSigmaWorkKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int result = archival_db_get(m_archival_sigma_work, &k, &v);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to probe archival_sigma_work row: ", result).c_str()));
  return result == 0;
}

uint64_t BlockchainLMDB::get_archival_budget(uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBudgetKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_budget, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return 0;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival_budget: ", get_result).c_str()));
  if (v.mv_size != 8)
    throw0(DB_ERROR(("Bad archival_budget record at epoch " + std::to_string(settlement_epoch)
      + ": expected 8 bytes, got " + std::to_string(v.mv_size)).c_str()));
  return shekyl::db::load_be64(static_cast<const uint8_t*>(v.mv_data));
}

bool BlockchainLMDB::has_archival_budget_row(uint64_t settlement_epoch) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalBudgetKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int result = archival_db_get(m_archival_budget, &k, &v);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to probe archival_budget row: ", result).c_str()));
  return result == 0;
}

namespace
{
  // Defined in the curve-tree anonymous-namespace block below; declared here
  // so the freeze hooks (and the layer-chunk corruption helper) can address
  // the layer rows the same-txn grow wrote.
  uint64_t ct_layer_chunk_key(uint8_t layer, uint64_t chunk);
}

void BlockchainLMDB::put_archival_shard_segment_raw_for_corruption_test(uint64_t shard_id,
  const std::vector<uint8_t>& blob)
{
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: raw segment write requires active write txn");
  shekyl::db::ArchivalShardKey key(shard_id);
  MDB_val k = key.as_mdb_val();
  MDB_val v = { blob.size(), const_cast<uint8_t*>(blob.data()) };
  const int result = mdb_put(*m_write_txn, m_archival_shard_segment, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to put raw archival shard segment: ", result).c_str()));
}

bool BlockchainLMDB::get_archival_shard_segment_raw_for_test(uint64_t shard_id,
  std::vector<uint8_t>& out_blob) const
{
  check_open();
  shekyl::db::ArchivalShardKey key(shard_id);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int result = archival_db_get(m_archival_shard_segment, &k, &v);
  if (result == MDB_NOTFOUND)
    return false;
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to get raw archival shard segment: ", result).c_str()));
  out_blob.assign(static_cast<const uint8_t*>(v.mv_data),
    static_cast<const uint8_t*>(v.mv_data) + v.mv_size);
  return true;
}

void BlockchainLMDB::remove_curve_tree_layer_chunk_for_corruption_test(uint8_t layer, uint64_t chunk)
{
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: layer-chunk corruption delete requires active write txn");
  uint64_t layer_key = ct_layer_chunk_key(layer, chunk);
  MDB_val k = {sizeof(layer_key), (void *)&layer_key};
  const int result = mdb_del(*m_write_txn, m_curve_tree_layers, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to delete curve tree layer chunk for corruption test: ", result).c_str()));
}

uint64_t BlockchainLMDB::read_curve_tree_leaf_count_on_write_txn() const
{
  // Single canonical same-txn "leaf_count" reader (the freeze hooks' only
  // meta access): read on the block's write txn so post-grow / post-trim
  // mutations are visible. Absent row is a legitimately-empty tree (0 leaves).
  const std::string lc_key = "leaf_count";
  MDB_val k = {lc_key.size(), const_cast<char*>(lc_key.data())};
  MDB_val v;
  const int rc = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
  if (rc == MDB_NOTFOUND)
    return 0;
  // A present-but-malformed row is corruption, not an LMDB error — abort with
  // an accurate message (lmdb_error(rc=0) would say "Success").
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to get curve tree leaf count on write txn: ", rc).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR("FATAL: malformed curve tree leaf_count row on write txn (wrong size)"));
  uint64_t leaf_count = 0;
  memcpy(&leaf_count, v.mv_data, sizeof(uint64_t));
  return leaf_count;
}

uint64_t BlockchainLMDB::frozen_segment_count_on_write_txn() const
{
  // Post-grow / post-trim leaf count, read on the block's write txn so the
  // hook sees the same-txn tree mutation. The boundary division lives ONLY
  // in the Rust entry point (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §5.1
  // division-one-site discipline).
  return shekyl_archival_frozen_segment_count(read_curve_tree_leaf_count_on_write_txn());
}

void BlockchainLMDB::process_archival_segment_freezes_at_height(uint64_t block_height)
{
  // Segment-freeze connect hook (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.1):
  // for every level-2 subtree the same-txn grow completed, write a registry
  // row with freeze_height = block_height and R_k read from the layer-2
  // chunk the grow just wrote (which IS the frozen sub-root — MMR finality).
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: segment freeze requires active write txn");

  const uint64_t complete = frozen_segment_count_on_write_txn();

  // Resume point: one-row reverse peek over the table this writer owns
  // (empty table => 0). This is the writer deriving its own frontier from
  // its own rows — not a second count pass (tripwire-exempt by name).
  uint64_t next = 0;
  {
    MDB_cursor* cur = nullptr;
    int rc = mdb_cursor_open(*m_write_txn, m_archival_shard_segment, &cur);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to open archival_shard_segment cursor for freeze resume peek: ", rc).c_str()));
    const std::unique_ptr<MDB_cursor, decltype(&mdb_cursor_close)> cur_guard(cur, &mdb_cursor_close);
    MDB_val k, v;
    rc = mdb_cursor_get(cur, &k, &v, MDB_LAST);
    if (rc == 0)
    {
      if (k.mv_size != shekyl::db::kArchivalShardKeySize)
        throw std::runtime_error("FATAL: archival_shard_segment key size mismatch at freeze resume peek");
      next = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data)) + 1;
    }
    else if (rc != MDB_NOTFOUND)
      throw0(DB_ERROR(lmdb_error("archival_shard_segment cursor error at freeze resume peek: ", rc).c_str()));
  }

  for (uint64_t shard_id = next; shard_id < complete; ++shard_id)
  {
    // A missing layer-2 chunk for a completed segment means the tree and
    // the freeze rule disagree — corruption, not a skippable row (same
    // loud-abort class as the M1 count pass's decode failure).
    const uint64_t layer_key = ct_layer_chunk_key(2, shard_id);
    MDB_val lk = {sizeof(layer_key), (void *)&layer_key};
    MDB_val lv;
    const int rc = mdb_get(*m_write_txn, m_curve_tree_layers, &lk, &lv);
    if (rc)
      throw0(DB_ERROR(lmdb_error(
        "FATAL: missing layer-2 chunk for completed segment at freeze: ", rc).c_str()));
    if (lv.mv_size != 32)
      throw0(DB_ERROR("FATAL: malformed layer-2 chunk for completed segment at freeze (wrong size)"));
    crypto::hash rk{};
    memcpy(rk.data, lv.mv_data, 32);
    put_archival_shard_segment(shard_id, block_height, rk, SHEKYL_ARCHIVAL_SEGMENT_LEAF_COUNT);
  }
}

void BlockchainLMDB::revert_archival_segment_freezes()
{
  // Segment-freeze pop hook (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.2):
  // delete every row with shard_id >= frozen_segment_count(post-trim leaf
  // count). Derived from the same Rust entry point as the connect hook, so
  // re-applied blocks recreate rows bit-identically (O-3 pop-symmetry). No
  // journal: the drain journal already restores the leaf count exactly.
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!m_write_txn)
    throw std::runtime_error("FATAL: segment freeze revert requires active write txn");

  const uint64_t complete = frozen_segment_count_on_write_txn();

  MDB_cursor* cur = nullptr;
  int rc = mdb_cursor_open(*m_write_txn, m_archival_shard_segment, &cur);
  if (rc)
    throw0(DB_ERROR(lmdb_error("Failed to open archival_shard_segment cursor for freeze revert: ", rc).c_str()));
  const std::unique_ptr<MDB_cursor, decltype(&mdb_cursor_close)> cur_guard(cur, &mdb_cursor_close);
  MDB_val k, v;
  uint64_t deleted = 0;
  while ((rc = mdb_cursor_get(cur, &k, &v, MDB_LAST)) == 0)
  {
    if (k.mv_size != shekyl::db::kArchivalShardKeySize)
      throw std::runtime_error("FATAL: archival_shard_segment key size mismatch at freeze revert");
    const uint64_t shard_id = shekyl::db::load_be64(static_cast<const uint8_t*>(k.mv_data));
    if (shard_id < complete)
      break;
    rc = mdb_cursor_del(cur, 0);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to delete archival_shard_segment row at freeze revert: ", rc).c_str()));
    ++deleted;
  }
  if (rc != 0 && rc != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("archival_shard_segment cursor error at freeze revert: ", rc).c_str()));

  // Persisted pop-symmetric counter, pop side
  // (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4): decrement by the rows this
  // walk actually deleted — the symmetric writer the counter could not have
  // before this pipeline existed.
  if (deleted > 0)
  {
    const uint64_t frozen_count = get_archival_frozen_shard_count_on_write_txn();
    if (frozen_count < deleted)
      throw std::runtime_error("FATAL: archival frozen-shard counter underflow on freeze revert");
    set_archival_frozen_shard_count_on_write_txn(frozen_count - deleted);
  }
}

void BlockchainLMDB::gather_archival_epoch_rows(uint64_t settlement_epoch,
  const crypto::hash* p_id, ArchivalEmissionEpochSnapshot& out) const
{
  gather_archival_epoch_rows_window(settlement_epoch, settlement_epoch + 1, p_id, &out);
}

void BlockchainLMDB::gather_archival_epoch_rows_window(uint64_t epoch_lo, uint64_t epoch_hi,
  const crypto::hash* p_id, ArchivalEmissionEpochSnapshot* outs) const
{
  if (epoch_hi <= epoch_lo)
    return;
  const size_t window = static_cast<size_t>(epoch_hi - epoch_lo);
  for (size_t w = 0; w < window; ++w)
  {
    outs[w].bonds.clear();
    outs[w].shards.clear();
    outs[w].credit_pairs.clear();
    outs[w].claimant_bond_idx = SIZE_MAX;
  }

  // One pass over the serve-credit rows collects, for every settlement epoch
  // in [epoch_lo, epoch_hi), the (bond, shard) pairs plus the distinct bond
  // and shard-segment records they reference. Storage reads only; all
  // consensus semantics (market membership, scarcity, curve, r/sigma
  // aggregation) run in Rust. Shared by the epoch close, the emission
  // snapshot, and the claim-source window (WS-1 §5.5 single sourcing, C++
  // side): every consumer of the as-of-E gather funnels through this one
  // row-selection routine, so none can diverge on row selection. The epoch
  // is the key SUFFIX (p_id | shard | epoch, BE), so a range seek by epoch
  // is impossible — the full-table pass is inherent to the key layout; the
  // window form exists so the claim-source RPC pays it once per request,
  // not once per window epoch. Deterministic re-gather: serve-credit keys
  // are BE-ordered, cursor order is key order, and indices are assigned
  // first-encounter per epoch, so the same table contents always produce
  // the same arrays — a width-1 window is row-for-row the pre-window gather.
  const auto scan = [&](MDB_txn* txn) {
    // Per-epoch first-encounter indices. SIZE_MAX marks a P with no
    // decodable bond record so its rows are skipped without re-reading the
    // bond table.
    std::vector<std::unordered_map<crypto::hash, size_t>> bond_index(window);
    std::vector<std::map<uint64_t, size_t>> shard_index(window);
    // Bond and shard-segment records are keyed by P / shard alone (not by
    // epoch), so within one read view a single decode serves every epoch in
    // the window.
    std::unordered_map<crypto::hash, std::pair<bool, ArchivalEmissionEpochSnapshot::BondRow>> bond_cache;
    std::map<uint64_t, ArchivalEmissionEpochSnapshot::ShardRow> shard_cache;

    MDB_cursor* credit_cur = nullptr;
    int rc = mdb_cursor_open(txn, m_archival_serve_credit, &credit_cur);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to open archival_serve_credit cursor for epoch gather: ", rc).c_str()));

    MDB_val ck, cv;
    rc = mdb_cursor_get(credit_cur, &ck, &cv, MDB_FIRST);
    while (rc == 0)
    {
      if (ck.mv_size != shekyl::db::kArchivalServeCreditKeySize)
      {
        mdb_cursor_close(credit_cur);
        throw std::runtime_error("FATAL: archival_serve_credit key size mismatch at epoch gather");
      }

      const uint64_t epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(ck.mv_data) + 40);
      if (epoch >= epoch_lo && epoch < epoch_hi)
      {
        const size_t w = static_cast<size_t>(epoch - epoch_lo);
        ArchivalEmissionEpochSnapshot& out = outs[w];
        crypto::hash row_p_id{};
        std::memcpy(row_p_id.data, ck.mv_data, 32);
        const uint64_t shard_id = shekyl::db::load_be64(static_cast<const uint8_t*>(ck.mv_data) + 32);

        auto bond_it = bond_index[w].find(row_p_id);
        if (bond_it == bond_index[w].end())
        {
          auto cached = bond_cache.find(row_p_id);
          if (cached == bond_cache.end())
          {
            std::pair<bool, ArchivalEmissionEpochSnapshot::BondRow> entry{false, {}};
            shekyl::db::ArchivalBondValue bond{};
            if (load_archival_bond_value(row_p_id, bond))
            {
              entry.first = true;
              // WS-1: no holdings descriptor crosses into the work channel.
              // The held-and-served set is the serve-credit rows themselves —
              // each credit was acceptance-gated on holding at the challenge
              // fire height, so the pairs are the as-of-E witness; re-filtering
              // them against tip holdings was the M2-1 drop-after-serve
              // under-count.
              entry.second.join_settlement_epoch = bond.join_settlement_epoch;
              entry.second.is_foundation_complete_tree = bond.is_complete_tree();
              entry.second.bad_intervals_flat = archival_bad_intervals_flat(bond);
            }
            cached = bond_cache.emplace(row_p_id, std::move(entry)).first;
          }
          size_t idx = std::numeric_limits<size_t>::max();
          if (cached->second.first)
          {
            idx = out.bonds.size();
            out.bonds.push_back(cached->second.second);
            if (p_id && row_p_id == *p_id)
              out.claimant_bond_idx = idx;
          }
          bond_it = bond_index[w].emplace(row_p_id, idx).first;
        }
        if (bond_it->second != std::numeric_limits<size_t>::max())
        {
          auto shard_it = shard_index[w].find(shard_id);
          if (shard_it == shard_index[w].end())
          {
            auto scached = shard_cache.find(shard_id);
            if (scached == shard_cache.end())
            {
              ArchivalEmissionEpochSnapshot::ShardRow shard;
              shard.shard_id = shard_id;

              shekyl::db::ArchivalShardKey skey(shard_id);
              MDB_val sk = skey.as_mdb_val();
              MDB_val sv;
              const int seg_rc = mdb_get(txn, m_archival_shard_segment, &sk, &sv);
              if (seg_rc && seg_rc != MDB_NOTFOUND)
              {
                mdb_cursor_close(credit_cur);
                throw0(DB_ERROR(lmdb_error("Failed to get archival_shard_segment at epoch gather: ", seg_rc).c_str()));
              }
              if (seg_rc == 0)
              {
                shekyl::db::ArchivalShardSegmentValue segment{};
                if (!shekyl::db::ArchivalShardSegmentValue::decode(sv.mv_data, sv.mv_size, segment))
                {
                  mdb_cursor_close(credit_cur);
                  throw std::runtime_error("FATAL: archival_shard_segment decode failed at epoch gather");
                }
                shard.freeze_height = segment.freeze_height;
                shard.has_segment = true;
              }
              scached = shard_cache.emplace(shard_id, shard).first;
            }

            shard_it = shard_index[w].emplace(shard_id, out.shards.size()).first;
            out.shards.push_back(scached->second);
          }
          out.credit_pairs.push_back({ bond_it->second, shard_it->second });
        }
      }
      rc = mdb_cursor_get(credit_cur, &ck, &cv, MDB_NEXT);
    }
    if (rc != MDB_NOTFOUND)
    {
      mdb_cursor_close(credit_cur);
      throw0(DB_ERROR(lmdb_error("archival_serve_credit cursor error at epoch gather: ", rc).c_str()));
    }
    mdb_cursor_close(credit_cur);
  };

  // Thread-aware txn selection via block_rtxn_start — see archival_db_get.
  TXN_PREFIX_RDONLY();
  scan(m_txn);
  TXN_POSTFIX_RDONLY();
}

void BlockchainLMDB::gather_archival_emission_epoch_snapshot(const crypto::hash& p_id,
  uint64_t settlement_epoch, ArchivalEmissionEpochSnapshot& out) const
{
  // Width-1 window: the windowed gather is the single implementation, so
  // the per-epoch and windowed forms cannot diverge (WS-1 §5.5).
  //
  // `settlement_epoch` is attacker-reachable via the emission vin's
  // `settlement_epochs` (the wire codec bounds the count and ordering, not the
  // value — emission_wire.rs), so it can be UINT64_MAX. There the half-open
  // window [E, E+1) wraps to the empty [UINT64_MAX, 0) and the gather returns
  // nothing; emit the reset "no close row" snapshot (settlement_epoch set,
  // has_budget_row false) the verify shim already rejects, rather than
  // front()-ing an empty vector. Same impossible-epoch semantics as the
  // base-class stub; the claimable-window bound stays the single Rust
  // decision (never a second C++-side epoch check here).
  std::vector<ArchivalEmissionEpochSnapshot> snaps;
  gather_archival_emission_window_snapshots(p_id, settlement_epoch, settlement_epoch + 1, snaps);
  if (snaps.empty())
  {
    out = ArchivalEmissionEpochSnapshot{};
    out.settlement_epoch = settlement_epoch;
    return;
  }
  out = std::move(snaps.front());
}

void BlockchainLMDB::gather_archival_emission_window_snapshots(const crypto::hash& p_id,
  uint64_t epoch_lo, uint64_t epoch_hi, std::vector<ArchivalEmissionEpochSnapshot>& out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  out.clear();
  if (epoch_hi <= epoch_lo)
    return;
  out.resize(static_cast<size_t>(epoch_hi - epoch_lo));
  for (uint64_t settlement_epoch = epoch_lo; settlement_epoch < epoch_hi; ++settlement_epoch)
  {
    ArchivalEmissionEpochSnapshot& snap = out[static_cast<size_t>(settlement_epoch - epoch_lo)];
    snap.settlement_epoch = settlement_epoch;
    // The close-processing boundary the close's gather froze at — the
    // shard-age operand the compute received. Single-sourced from the same
    // Rust formula the close scheduler uses; 0 (impossible epoch) cannot occur
    // for a claimable E, which the caller has already height-gated.
    snap.close_block_height = shekyl_archival_epoch_close_processing_height(settlement_epoch);
    // The persisted finalized Σwork(E) — the stored denominator, never a
    // recompute: the close's outcome reaches verify only through this value.
    snap.sigma_work_milli = get_archival_sigma_work_milli(settlement_epoch);
    // The frozen budget(E) close row (ARCHIVAL_BUDGET_SCHEDULE.md §3.3):
    // budget and denominator were frozen in the same close event, so the
    // gather reads them from the same table family — no new live operand.
    // Absent row (never closed / pruned) is a gather failure the verify shim
    // rejects on; present-and-zero is a closed zero-budget epoch, rejected
    // downstream by wire positivity, not here.
    snap.has_budget_row = has_archival_budget_row(settlement_epoch);
    snap.budget_atomic = snap.has_budget_row ? get_archival_budget(settlement_epoch) : 0;
  }
  // All window epochs' rows in ONE serve-credit table pass — the
  // unauthenticated claim-source RPC's per-request work bound.
  gather_archival_epoch_rows_window(epoch_lo, epoch_hi, &p_id, out.data());
}

void BlockchainLMDB::process_archival_epoch_close_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  uint64_t settlement_epoch = 0;
  if (!shekyl_archival_epoch_close_due(block_height, &settlement_epoch))
    return;

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival epoch close requires active write txn");

  // Gather phase: the shared as-of-E row gather (also the emission
  // snapshot's source — WS-1 §5.5 single sourcing).
  ArchivalEmissionEpochSnapshot rows;
  gather_archival_epoch_rows(settlement_epoch, nullptr, rows);

  // Compute phase: single coarse FFI call into shekyl-archival-retention.
  // Struct→FFI marshaling via the snapshot's shared helpers (single source
  // with the emission-verify path — WS-1 §5.5).
  const std::vector<shekyl_archival_epoch_close_bond> bond_ffi = rows.to_ffi_bonds();
  const std::vector<shekyl_archival_epoch_close_shard> shards = rows.to_ffi_shards();
  const std::vector<shekyl_archival_credit_pair> pairs = rows.to_ffi_credit_pairs();

  std::vector<uint64_t> r_market(shards.size(), 0);
  uint64_t sigma_work_milli = 0;
  const uint8_t compute_rc = shekyl_archival_epoch_close_compute(
    settlement_epoch, block_height,
    bond_ffi.empty() ? nullptr : bond_ffi.data(), bond_ffi.size(),
    shards.empty() ? nullptr : shards.data(), shards.size(),
    pairs.empty() ? nullptr : pairs.data(), pairs.size(),
    r_market.empty() ? nullptr : r_market.data(), &sigma_work_milli);
  if (compute_rc != SHEKYL_ARCHIVAL_EPOCH_CLOSE_OK)
    throw std::runtime_error("FATAL: archival epoch close compute failed (rc="
      + std::to_string(static_cast<unsigned>(compute_rc)) + ")");

  // Store phase: persist the Rust-computed results.
  for (size_t i = 0; i < shards.size(); ++i)
  {
    if (r_market[i] == 0)
      continue;
    uint8_t val_be[8];
    shekyl::db::store_be64(val_be, r_market[i]);
    shekyl::db::ArchivalRMarketKey rkey(rows.shards[i].shard_id, settlement_epoch);
    MDB_val rk = rkey.as_mdb_val();
    MDB_val rv = { sizeof(val_be), val_be };
    const int put_rc = mdb_put(*m_write_txn, m_archival_r_market, &rk, &rv, 0);
    if (put_rc)
      throw0(DB_ERROR(lmdb_error("Failed to put archival_r_market: ", put_rc).c_str()));
  }

  uint8_t sigma_be[8];
  shekyl::db::store_be64(sigma_be, sigma_work_milli);
  shekyl::db::ArchivalSigmaWorkKey sigma_key(settlement_epoch);
  MDB_val sk = sigma_key.as_mdb_val();
  MDB_val sv = { sizeof(sigma_be), sigma_be };
  const int sigma_put = mdb_put(*m_write_txn, m_archival_sigma_work, &sk, &sv, 0);
  if (sigma_put)
    throw0(DB_ERROR(lmdb_error("Failed to put archival_sigma_work: ", sigma_put).c_str()));

  // Frozen budget(E) close row (ARCHIVAL_BUDGET_SCHEDULE.md §3.2): the
  // bounded range-sum of the redirected per-height accrual rows over
  // [E·SEB, (E+1)·SEB), written in the same txn as the sigma row so budget
  // and denominator freeze in the same close event (the M1 same-snapshot
  // pin). `block_height` is the close-processing height (E+1)·SEB — the
  // exclusive upper bound. Written unconditionally: a present-and-zero row
  // is a closed zero-budget epoch (§5, structurally non-claimable),
  // distinguishable from never-closed (gather failure at verify).
  uint64_t budget_atomic = 0;
  {
    const uint64_t start_height = shekyl_archival_epoch_open_height(settlement_epoch);
    MDB_cursor* cur = nullptr;
    int rc = mdb_cursor_open(*m_write_txn, m_archival_budget_accrual, &cur);
    if (rc)
      throw0(DB_ERROR(lmdb_error("Failed to open archival_budget_accrual cursor for close: ", rc).c_str()));
    shekyl::db::ArchivalBudgetAccrualKey start_key(start_height);
    MDB_val ak = start_key.as_mdb_val();
    MDB_val av;
    rc = mdb_cursor_get(cur, &ak, &av, MDB_SET_RANGE);
    while (rc == 0)
    {
      if (ak.mv_size != shekyl::db::kArchivalBudgetAccrualKeySize)
        throw std::runtime_error("FATAL: archival_budget_accrual key size mismatch on close");
      const uint64_t h = shekyl::db::load_be64(static_cast<const uint8_t*>(ak.mv_data));
      if (h >= block_height)
        break;
      if (av.mv_size != 8)
        throw std::runtime_error("FATAL: archival_budget_accrual value size mismatch on close");
      const uint64_t amount = shekyl::db::load_be64(static_cast<const uint8_t*>(av.mv_data));
      if (amount > std::numeric_limits<uint64_t>::max() - budget_atomic)
        // Impossible for well-formed rows (Σ inflow is supply-bounded); a
        // wrap here is row corruption and must abort, not mint.
        throw std::runtime_error("FATAL: archival budget accrual sum overflow on close");
      budget_atomic += amount;
      rc = mdb_cursor_get(cur, &ak, &av, MDB_NEXT);
    }
    if (rc && rc != MDB_NOTFOUND)
      throw0(DB_ERROR(lmdb_error("archival_budget_accrual cursor error on close: ", rc).c_str()));
    mdb_cursor_close(cur);
  }
  uint8_t budget_be[8];
  shekyl::db::store_be64(budget_be, budget_atomic);
  shekyl::db::ArchivalBudgetKey budget_key(settlement_epoch);
  MDB_val bk = budget_key.as_mdb_val();
  MDB_val bv = { sizeof(budget_be), budget_be };
  const int budget_put = mdb_put(*m_write_txn, m_archival_budget, &bk, &bv, 0);
  if (budget_put)
    throw0(DB_ERROR(lmdb_error("Failed to put archival_budget: ", budget_put).c_str()));

  uint8_t epoch_be[8];
  shekyl::db::store_be64(epoch_be, settlement_epoch);
  shekyl::db::ArchivalEpochCloseLogKey log_key(block_height);
  MDB_val log_k = log_key.as_mdb_val();
  MDB_val log_v = { sizeof(epoch_be), epoch_be };
  const int log_put = mdb_put(*m_write_txn, m_archival_epoch_close_log, &log_k, &log_v, 0);
  if (log_put)
    throw0(DB_ERROR(lmdb_error("Failed to put archival_epoch_close_log: ", log_put).c_str()));

  uint64_t prune_below = 0;
  if (shekyl_archival_prune_below_epoch(block_height, &prune_below))
    prune_archival_epochs_before(prune_below);
}

void BlockchainLMDB::revert_archival_epoch_close_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (!m_write_txn)
    throw std::runtime_error("FATAL: archival epoch close revert requires active write txn");

  shekyl::db::ArchivalEpochCloseLogKey log_key(block_height);
  MDB_val log_k = log_key.as_mdb_val();
  MDB_val log_v;
  const int log_get = mdb_get(*m_write_txn, m_archival_epoch_close_log, &log_k, &log_v);
  if (log_get == MDB_NOTFOUND)
    return;
  if (log_get)
    throw0(DB_ERROR(lmdb_error("Failed to read archival_epoch_close_log on pop: ", log_get).c_str()));
  if (log_v.mv_size != 8)
    throw std::runtime_error("FATAL: archival_epoch_close_log value size mismatch on pop");

  const uint64_t settlement_epoch = shekyl::db::load_be64(static_cast<const uint8_t*>(log_v.mv_data));
  delete_archival_r_market_for_epoch(settlement_epoch);
  delete_archival_sigma_work_for_epoch(settlement_epoch);
  // The frozen budget row reverts with the close family; the per-height
  // accrual rows do NOT (each reverts with its own block's pop, in
  // BlockchainDB::pop_block) — a pop-and-re-close re-sums the retained
  // accrual rows plus the re-connecting block's freshly written row and
  // reproduces the budget byte-identically (ARCHIVAL_BUDGET_SCHEDULE.md
  // §3.2, KAT B3 and the epoch-boundary round-trip KAT).
  delete_archival_budget_for_epoch(settlement_epoch);
  const int log_del = mdb_del(*m_write_txn, m_archival_epoch_close_log, &log_k, nullptr);
  if (log_del && log_del != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to delete archival_epoch_close_log on pop: ", log_del).c_str()));
}

uint64_t BlockchainLMDB::get_archival_r_market(uint64_t shard_id,
  uint64_t settlement_epoch) const
{
  shekyl::db::ArchivalRMarketKey key(shard_id, settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_r_market, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return 0;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival_r_market: ", get_result).c_str()));
  if (v.mv_size != 8)
    throw std::runtime_error("FATAL: archival_r_market value size mismatch");
  return shekyl::db::load_be64(static_cast<const uint8_t*>(v.mv_data));
}

uint64_t BlockchainLMDB::get_archival_sigma_work_milli(uint64_t settlement_epoch) const
{
  shekyl::db::ArchivalSigmaWorkKey key(settlement_epoch);
  MDB_val k = key.as_mdb_val();
  MDB_val v;
  const int get_result = archival_db_get(m_archival_sigma_work, &k, &v);
  if (get_result == MDB_NOTFOUND)
    return 0;
  if (get_result)
    throw0(DB_ERROR(lmdb_error("Failed to get archival_sigma_work: ", get_result).c_str()));
  if (v.mv_size != 8)
    throw std::runtime_error("FATAL: archival_sigma_work value size mismatch");
  return shekyl::db::load_be64(static_cast<const uint8_t*>(v.mv_data));
}

void BlockchainLMDB::put_archival_shard_segment(uint64_t shard_id, uint64_t freeze_height,
  const crypto::hash& segment_subroot_rk, uint64_t segment_leaf_count)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  shekyl::db::ArchivalShardSegmentValue segment{};
  segment.freeze_height = freeze_height;
  segment.segment_leaf_count = segment_leaf_count;
  std::memcpy(segment.segment_subroot_rk.data(), segment_subroot_rk.data, 32);

  const std::vector<uint8_t> encoded = segment.encode();
  shekyl::db::ArchivalShardKey key(shard_id);
  MDB_val k = key.as_mdb_val();
  MDB_val v = { encoded.size(), const_cast<uint8_t*>(encoded.data()) };
  // MDB_NOOVERWRITE makes the CREATE-only registry contract structural
  // (LMDB_SCHEMA.md: single row per shard; the overwrite-the-frozen-row
  // adversary O-2 refuses), and is what keeps the +1 below in lockstep with
  // the table: every successful put is exactly one new row.
  const int result = mdb_put(*m_write_txn, m_archival_shard_segment, &k, &v, MDB_NOOVERWRITE);
  if (result == MDB_KEYEXIST)
    throw std::runtime_error("FATAL: archival shard segment row overwrite refused (rows are CREATE-only, O-2)");
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to put archival shard segment: ", result).c_str()));

  // Persisted pop-symmetric counter, freeze side
  // (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4.4): increment where the row is
  // created, so counter and table cannot drift apart.
  const uint64_t frozen_count = get_archival_frozen_shard_count_on_write_txn();
  if (frozen_count == std::numeric_limits<uint64_t>::max())
    throw std::runtime_error("FATAL: archival frozen-shard counter overflow");
  set_archival_frozen_shard_count_on_write_txn(frozen_count + 1);
}

// ─── Deferred Staked Leaf Insertion ─────────────────────────────────────────

using shekyl::db::MaturityHeight;
using shekyl::db::OutputIndex;
using shekyl::db::BlockHeight;
using shekyl::db::TreePosition;
using shekyl::db::PendingLeafKey;
using shekyl::db::DrainKey;
using shekyl::db::DrainValue;
using shekyl::db::BlockPendingKey;
using shekyl::db::BlockPendingValue;
using shekyl::db::U64Key;
using shekyl::db::kLeafSize;

void BlockchainLMDB::add_pending_tree_leaf(MaturityHeight maturity, OutputIndex output, const uint8_t* leaf_data)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  PendingLeafKey key(maturity, output);
  MDB_val k = key.as_mdb_val();
  MDB_val v = {kLeafSize, const_cast<uint8_t*>(leaf_data)};

  int result = mdb_put(*m_write_txn, m_pending_tree_leaves, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add pending tree leaf: ", result).c_str()));
}

void BlockchainLMDB::remove_pending_tree_leaf(MaturityHeight maturity, OutputIndex output)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  PendingLeafKey key(maturity, output);
  MDB_val k = key.as_mdb_val();

  int result = mdb_del(*m_write_txn, m_pending_tree_leaves, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove pending tree leaf: ", result).c_str()));
}

uint64_t BlockchainLMDB::drain_pending_tree_leaves(BlockHeight current_height, std::vector<uint8_t>& out_leaves)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  uint64_t count = 0;
  const uint64_t tree_leaf_base = get_curve_tree_leaf_count();

  MDB_cursor *cur;
  int result = mdb_cursor_open(*m_write_txn, m_pending_tree_leaves, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for pending_tree_leaves: ", result).c_str()));

  MDB_val k, v;
  result = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
  while (result == 0)
  {
    auto decoded = PendingLeafKey::from_mdb_val(k);
    if (decoded.maturity().value > current_height.value)
      break;

    if (v.mv_size != kLeafSize)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR("Unexpected pending tree leaf value size"));
    }

    const uint8_t* leaf_ptr = reinterpret_cast<const uint8_t*>(v.mv_data);
    out_leaves.insert(out_leaves.end(), leaf_ptr, leaf_ptr + kLeafSize);

    TreePosition tree_pos{tree_leaf_base + count};
    add_pending_tree_drain_entry(current_height, decoded.output(), decoded.maturity(), leaf_ptr);
    add_output_leaf_mapping(decoded.output(), tree_pos);
    ++count;

    result = mdb_cursor_del(cur, 0);
    if (result)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("Failed to delete drained pending tree leaf: ", result).c_str()));
    }

    result = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }
  if (result != MDB_NOTFOUND && result != 0)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("Error iterating pending_tree_leaves: ", result).c_str()));
  }

  mdb_cursor_close(cur);
  return count;
}

void BlockchainLMDB::add_pending_tree_drain_entry(BlockHeight block_height, OutputIndex output,
                                                    MaturityHeight maturity, const uint8_t* leaf_data)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  DrainKey dk(block_height, output);
  DrainValue dv(maturity, leaf_data);
  MDB_val k = dk.as_mdb_val();
  MDB_val v = dv.as_mdb_val();

  int result = mdb_put(*m_write_txn, m_pending_tree_drain, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add pending tree drain entry: ", result).c_str()));
}

std::vector<BlockchainDB::drain_entry_t> BlockchainLMDB::get_pending_tree_drain_entries(BlockHeight block_height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  std::vector<drain_entry_t> entries;
  TXN_PREFIX_RDONLY();

  MDB_cursor *cur;
  int result = mdb_cursor_open(m_txn, m_pending_tree_drain, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for pending_tree_drain: ", result).c_str()));

  DrainKey seek = DrainKey::prefix(block_height);
  MDB_val k = seek.as_mdb_val();
  MDB_val v;
  result = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
  while (result == 0)
  {
    auto decoded_key = DrainKey::from_mdb_val(k);
    if (decoded_key.block_height() != block_height)
      break;

    auto decoded_val = DrainValue::from_mdb_val(v);
    drain_entry_t entry;
    entry.maturity = decoded_val.maturity();
    entry.output = decoded_key.output();
    std::memcpy(entry.leaf.data(), decoded_val.leaf(), kLeafSize);
    entries.push_back(entry);

    result = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }
  if (result != MDB_NOTFOUND && result != 0)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("Error reading pending_tree_drain: ", result).c_str()));
  }

  mdb_cursor_close(cur);
  TXN_POSTFIX_RDONLY();
  return entries;
}

void BlockchainLMDB::remove_pending_tree_drain_entries(BlockHeight block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_cursor *cur;
  int result = mdb_cursor_open(*m_write_txn, m_pending_tree_drain, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for pending_tree_drain: ", result).c_str()));

  DrainKey seek = DrainKey::prefix(block_height);
  MDB_val k = seek.as_mdb_val();
  MDB_val v;
  result = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
  while (result == 0)
  {
    auto decoded = DrainKey::from_mdb_val(k);
    if (decoded.block_height() != block_height)
      break;

    result = mdb_cursor_del(cur, 0);
    if (result)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("Failed to delete pending tree drain entry: ", result).c_str()));
    }

    result = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }
  if (result != MDB_NOTFOUND && result != 0)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("Error iterating pending_tree_drain for removal: ", result).c_str()));
  }

  mdb_cursor_close(cur);
}

// ─── Block Pending Additions Journal ────────────────────────────────────────

void BlockchainLMDB::add_block_pending_addition(BlockHeight height, OutputIndex output, MaturityHeight maturity)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  BlockPendingKey bpk(height, output);
  BlockPendingValue bpv(maturity);
  MDB_val k = bpk.as_mdb_val();
  MDB_val v = bpv.as_mdb_val();

  int result = mdb_put(*m_write_txn, m_block_pending_additions, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add block pending addition: ", result).c_str()));
}

std::vector<std::pair<MaturityHeight, OutputIndex>> BlockchainLMDB::get_block_pending_additions(BlockHeight height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  std::vector<std::pair<MaturityHeight, OutputIndex>> entries;
  TXN_PREFIX_RDONLY();

  MDB_cursor *cur;
  int result = mdb_cursor_open(m_txn, m_block_pending_additions, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for block_pending_additions: ", result).c_str()));

  BlockPendingKey seek = BlockPendingKey::prefix(height);
  MDB_val k = seek.as_mdb_val();
  MDB_val v;
  result = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
  while (result == 0)
  {
    auto decoded = BlockPendingKey::from_mdb_val(k);
    if (decoded.block_height() != height)
      break;

    auto val = BlockPendingValue::from_mdb_val(v);
    entries.emplace_back(val.maturity(), decoded.output());

    result = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }
  if (result != MDB_NOTFOUND && result != 0)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("Error reading block_pending_additions: ", result).c_str()));
  }

  mdb_cursor_close(cur);
  TXN_POSTFIX_RDONLY();
  return entries;
}

void BlockchainLMDB::remove_block_pending_additions(BlockHeight height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_cursor *cur;
  int result = mdb_cursor_open(*m_write_txn, m_block_pending_additions, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for block_pending_additions: ", result).c_str()));

  BlockPendingKey seek = BlockPendingKey::prefix(height);
  MDB_val k = seek.as_mdb_val();
  MDB_val v;
  result = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
  while (result == 0)
  {
    auto decoded = BlockPendingKey::from_mdb_val(k);
    if (decoded.block_height() != height)
      break;

    result = mdb_cursor_del(cur, 0);
    if (result)
    {
      mdb_cursor_close(cur);
      throw0(DB_ERROR(lmdb_error("Failed to delete block pending addition: ", result).c_str()));
    }

    result = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
  }
  if (result != MDB_NOTFOUND && result != 0)
  {
    mdb_cursor_close(cur);
    throw0(DB_ERROR(lmdb_error("Error iterating block_pending_additions for removal: ", result).c_str()));
  }

  mdb_cursor_close(cur);
}

// ─── Output ↔ Leaf Mapping ──────────────────────────────────────────────────

void BlockchainLMDB::add_output_leaf_mapping(OutputIndex output, TreePosition tree_pos)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  U64Key ok(output.value);
  U64Key tv(tree_pos.value);
  MDB_val k = ok.as_mdb_val();
  MDB_val v = tv.as_mdb_val();
  int result = mdb_put(*m_write_txn, m_output_to_leaf, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add output->leaf mapping: ", result).c_str()));

  U64Key tk(tree_pos.value);
  U64Key ov(output.value);
  MDB_val k2 = tk.as_mdb_val();
  MDB_val v2 = ov.as_mdb_val();
  result = mdb_put(*m_write_txn, m_leaf_to_output, &k2, &v2, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to add leaf->output mapping: ", result).c_str()));
}

void BlockchainLMDB::remove_output_leaf_mapping(OutputIndex output, TreePosition tree_pos)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // Verify stored value matches before deleting
  U64Key ok(output.value);
  MDB_val k = ok.as_mdb_val();
  MDB_val v;
  int result = mdb_get(*m_write_txn, m_output_to_leaf, &k, &v);
  if (result == MDB_NOTFOUND)
    return;
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to look up output->leaf for removal: ", result).c_str()));
  if (v.mv_size != sizeof(uint64_t) || *(const uint64_t*)v.mv_data != tree_pos.value)
    throw0(DB_ERROR("output->leaf mapping mismatch during removal"));

  result = mdb_del(*m_write_txn, m_output_to_leaf, &k, nullptr);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to delete output->leaf mapping: ", result).c_str()));

  U64Key tk(tree_pos.value);
  MDB_val k2 = tk.as_mdb_val();
  result = mdb_del(*m_write_txn, m_leaf_to_output, &k2, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to delete leaf->output mapping: ", result).c_str()));
}

bool BlockchainLMDB::get_output_leaf_index(OutputIndex output, TreePosition& pos_out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  U64Key ok(output.value);
  MDB_val k = ok.as_mdb_val();
  MDB_val v;
  int result = mdb_get(m_txn, m_output_to_leaf, &k, &v);
  if (result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return false;
  }
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to get output->leaf mapping: ", result).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR("Unexpected output->leaf value size"));
  pos_out = TreePosition{*(const uint64_t*)v.mv_data};
  TXN_POSTFIX_RDONLY();
  return true;
}

bool BlockchainLMDB::get_leaf_output_index(TreePosition tree_pos, OutputIndex& out_out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  U64Key tk(tree_pos.value);
  MDB_val k = tk.as_mdb_val();
  MDB_val v;
  int result = mdb_get(m_txn, m_leaf_to_output, &k, &v);
  if (result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return false;
  }
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to get leaf->output mapping: ", result).c_str()));
  if (v.mv_size != sizeof(uint64_t))
    throw0(DB_ERROR("Unexpected leaf->output value size"));
  out_out = OutputIndex{*(const uint64_t*)v.mv_data};
  TXN_POSTFIX_RDONLY();
  return true;
}

// ─── FCMP++ Curve Tree ──────────────────────────────────────────────────────

namespace {
  static constexpr uint32_t CT_SCALARS_PER_LEAF = 4;
  static constexpr uint32_t CT_SELENE_CHUNK_WIDTH = 38;  // LAYER_ONE_LEN
  static constexpr uint32_t CT_HELIOS_CHUNK_WIDTH = 18;  // LAYER_TWO_LEN
  static constexpr size_t CT_LEAF_SIZE = shekyl::db::kLeafSize;  // 4 Selene scalars × 32B

  // LMDB key for m_curve_tree_layers (MDB_INTEGERKEY, native uint64_t order).
  // High 8 bits: layer index (0 = leaf/Selene, 1 = Helios, 2 = Selene, ...;
  //   max 255 layers).
  // Low 56 bits: chunk index within the layer (~7.2e16 chunks per layer).
  // This layout ensures keys within the same layer are contiguous and
  // monotonically increasing, and all keys for layer N sort before layer N+1,
  // which enables efficient MDB_SET_RANGE cursor scans in pruning.
  uint64_t ct_layer_chunk_key(uint8_t layer, uint64_t chunk) {
    return (static_cast<uint64_t>(layer) << 56) | chunk;
  }

  uint32_t ct_chunk_width(uint8_t layer) {
    if (layer == 0)
      return CT_SELENE_CHUNK_WIDTH;
    return (layer % 2 == 0) ? CT_SELENE_CHUNK_WIDTH : CT_HELIOS_CHUNK_WIDTH;
  }

  uint32_t ct_leaf_scalars_per_chunk() {
    return CT_SCALARS_PER_LEAF * CT_SELENE_CHUNK_WIDTH;
  }
}

void BlockchainLMDB::grow_curve_tree(const std::vector<uint8_t>& leaf_data, uint64_t num_new_outputs)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (num_new_outputs == 0 || leaf_data.size() != num_new_outputs * CT_LEAF_SIZE)
    throw0(DB_ERROR("Invalid leaf_data size for grow_curve_tree"));

  // Read current leaf count from meta
  uint64_t old_leaf_count = 0;
  {
    const std::string meta_key = "leaf_count";
    MDB_val k = {meta_key.size(), (void *)meta_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size == sizeof(uint64_t))
      memcpy(&old_leaf_count, v.mv_data, sizeof(uint64_t));
    else if (result != MDB_NOTFOUND)
      throw0(DB_ERROR(lmdb_error("Failed to get curve tree leaf count: ", result).c_str()));
  }

  uint64_t new_leaf_count = old_leaf_count + num_new_outputs;

  // Store each leaf
  for (uint64_t i = 0; i < num_new_outputs; ++i)
  {
    uint64_t global_idx = old_leaf_count + i;
    MDB_val k = {sizeof(global_idx), (void *)&global_idx};
    MDB_val v = {CT_LEAF_SIZE, (void *)(leaf_data.data() + i * CT_LEAF_SIZE)};
    int result = mdb_put(*m_write_txn, m_curve_tree_leaves, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree leaf: ", result).c_str()));
  }

  // Propagate hash updates through the tree layers.
  // Layer 0 (leaf layer, Selene): each chunk holds CT_SELENE_CHUNK_WIDTH outputs,
  // each contributing CT_SCALARS_PER_LEAF scalars.
  // Higher layers: each chunk holds ct_chunk_width(layer) children.

  // Determine which leaf-layer chunks are affected
  uint64_t first_affected_leaf_chunk = old_leaf_count / CT_SELENE_CHUNK_WIDTH;
  uint64_t last_affected_leaf_chunk  = (new_leaf_count > 0) ? (new_leaf_count - 1) / CT_SELENE_CHUNK_WIDTH : 0;

  // The leaf (Selene) layer is maintained incrementally below: its hash_grow
  // accumulates scalars at a real offset and telescopes to the narrow leaf-chunk
  // hash. Every layer ABOVE the leaf is then recomposed narrow by the Rust FFI
  // (shekyl_curve_tree_grow_upper_layers == build_layers), replacing the former
  // in-place incremental deepening that dropped a pre-existing sibling at the
  // first layer-2 Selene root — the depth-3 consensus divergence.

  // Process leaf-layer chunks
  for (uint64_t chunk = first_affected_leaf_chunk; chunk <= last_affected_leaf_chunk; ++chunk)
  {
    uint64_t chunk_start_output = chunk * CT_SELENE_CHUNK_WIDTH;

    // Determine which outputs in this chunk are new
    uint64_t first_new_in_chunk = (old_leaf_count > chunk_start_output) ? (old_leaf_count - chunk_start_output) : 0;
    uint64_t chunk_end_output = std::min((chunk + 1) * static_cast<uint64_t>(CT_SELENE_CHUNK_WIDTH), new_leaf_count);
    uint64_t num_new_in_chunk = chunk_end_output - chunk_start_output - first_new_in_chunk;
    if (num_new_in_chunk == 0) continue;

    // Load the existing chunk hash (or use hash_init for a new chunk)
    std::array<uint8_t, 32> existing_hash;
    uint64_t layer_key = ct_layer_chunk_key(0, chunk);
    {
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      MDB_val v;
      int result = mdb_get(*m_write_txn, m_curve_tree_layers, &k, &v);
      if (result == 0 && v.mv_size == 32) {
        memcpy(existing_hash.data(), v.mv_data, 32);
      } else if (result == MDB_NOTFOUND) {
        shekyl_curve_tree_selene_hash_init(existing_hash.data());
      } else {
        throw0(DB_ERROR(lmdb_error("Failed to get curve tree layer hash: ", result).c_str()));
      }
    }

    // Collect new scalars (4 per output)
    uint64_t scalar_offset = first_new_in_chunk * CT_SCALARS_PER_LEAF;
    std::vector<uint8_t> new_scalars;
    for (uint64_t out_idx = chunk_start_output + first_new_in_chunk; out_idx < chunk_end_output; ++out_idx)
    {
      // Read leaf from DB (we just stored it above)
      MDB_val k = {sizeof(out_idx), (void *)&out_idx};
      MDB_val v;
      int result = mdb_get(*m_write_txn, m_curve_tree_leaves, &k, &v);
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to read curve tree leaf: ", result).c_str()));
      new_scalars.insert(new_scalars.end(), (const uint8_t*)v.mv_data, (const uint8_t*)v.mv_data + CT_LEAF_SIZE);
    }

    // The scalar at position scalar_offset was never written to the Pedersen
    // commitment (it's a new leaf position being appended), so its implicit
    // prior value is zero.  This is correct even for partial-chunk extension:
    // scalars 0..scalar_offset-1 are already baked into existing_hash, and
    // everything from scalar_offset onward is fresh.
    std::array<uint8_t, 32> existing_child_at_offset = {};

    // Hash grow with all new scalars at once
    std::array<uint8_t, 32> new_hash;
    uint64_t num_scalars = num_new_in_chunk * CT_SCALARS_PER_LEAF;
    bool ok = shekyl_curve_tree_hash_grow_selene(
      existing_hash.data(),
      scalar_offset,
      existing_child_at_offset.data(),
      new_scalars.data(),
      num_scalars,
      new_hash.data()
    );
    if (!ok)
      throw0(DB_ERROR("Rust FFI: shekyl_curve_tree_hash_grow_selene failed"));

    // Store updated chunk hash
    {
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      MDB_val v = {32, new_hash.data()};
      int result = mdb_put(*m_write_txn, m_curve_tree_layers, &k, &v, 0);
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to store curve tree leaf chunk hash: ", result).c_str()));
    }
  }

  // Recompose every layer ABOVE the leaf, narrow, via the Rust FFI — the correct
  // producer-side grow (== build_layers). This retires the former in-place
  // incremental deepening, which built a newly-created parent chunk from only the
  // deepening child and dropped the pre-existing sibling at the first layer-2
  // Selene root (the depth-3 consensus divergence; see
  // shekyl-fcmp/tests/curve_tree_freeze.rs and FOLLOWUPS). The leaf layer above is
  // already correct; here we read it back in full and let the FFI produce every
  // upper layer + the root.
  const uint64_t num_leaf_chunks =
    (new_leaf_count + CT_SELENE_CHUNK_WIDTH - 1) / CT_SELENE_CHUNK_WIDTH;

  std::vector<uint8_t> leaf_chunks(static_cast<size_t>(num_leaf_chunks) * 32);
  for (uint64_t c = 0; c < num_leaf_chunks; ++c)
  {
    uint64_t layer_key = ct_layer_chunk_key(0, c);
    MDB_val k = {sizeof(layer_key), (void *)&layer_key};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_layers, &k, &v);
    if (result != 0)
      throw0(DB_ERROR(lmdb_error("Failed to read curve tree leaf chunk for upper-layer recompose: ", result).c_str()));
    if (v.mv_size != 32)
      throw0(DB_ERROR("Curve tree leaf chunk has unexpected size (expected 32 bytes)"));
    memcpy(leaf_chunks.data() + static_cast<size_t>(c) * 32, v.mv_data, 32);
  }

  // The total upper-layer chunk count is at most num_leaf_chunks: each layer shrinks
  // by the chunk-width ladder, and the one boundary case — a single leaf chunk, still
  // promoted to its own Helios root — makes the count EQUAL num_leaf_chunks rather
  // than exceed it. Size with a +1 defensive margin; tree depth is a small handful,
  // so 16 layer-size slots are ample.
  std::vector<uint8_t> upper_chunks(static_cast<size_t>(num_leaf_chunks + 1) * 32);
  std::array<uint64_t, 16> layer_sizes = {};
  uint64_t num_upper_layers = 0;
  std::array<uint8_t, 32> root = {};
  if (!shekyl_curve_tree_grow_upper_layers(
        leaf_chunks.data(), num_leaf_chunks,
        upper_chunks.data(), num_leaf_chunks + 1,
        layer_sizes.data(), layer_sizes.size(),
        &num_upper_layers, root.data()))
    throw0(DB_ERROR("Rust FFI: shekyl_curve_tree_grow_upper_layers failed"));

  // Persist the recomposed upper-layer chunk hashes (layers 1..num_upper_layers).
  uint64_t written = 0;
  for (uint64_t li = 0; li < num_upper_layers; ++li)
  {
    const uint8_t out_layer = static_cast<uint8_t>(li + 1);
    for (uint64_t c = 0; c < layer_sizes[li]; ++c)
    {
      uint64_t layer_key = ct_layer_chunk_key(out_layer, c);
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      MDB_val v = {32, upper_chunks.data() + static_cast<size_t>(written) * 32};
      int result = mdb_put(*m_write_txn, m_curve_tree_layers, &k, &v, 0);
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to store curve tree upper layer hash: ", result).c_str()));
      ++written;
    }
  }

  // Update meta: root, leaf_count, depth.
  {
    const std::string root_key = "root";
    MDB_val k = {root_key.size(), (void *)root_key.data()};
    MDB_val v = {32, root.data()};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree root: ", result).c_str()));
  }

  {
    const std::string lc_key = "leaf_count";
    MDB_val k = {lc_key.size(), (void *)lc_key.data()};
    MDB_val v = {sizeof(new_leaf_count), (void *)&new_leaf_count};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree leaf count: ", result).c_str()));
  }

  {
    // depth = number of layers above the leaf (consensus: fcmp_layers = depth + 1).
    if (num_upper_layers > 0xff)
      throw0(DB_ERROR("Curve tree depth exceeds uint8_t range (FFI returned an impossible layer count)"));
    const std::string depth_key = "depth";
    const uint8_t depth = static_cast<uint8_t>(num_upper_layers);
    MDB_val k = {depth_key.size(), (void *)depth_key.data()};
    MDB_val v = {sizeof(depth), (void *)&depth};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree depth: ", result).c_str()));
  }
}

void BlockchainLMDB::trim_curve_tree(uint64_t num_outputs_to_remove)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (num_outputs_to_remove == 0) return;

  // Read current leaf count from within the write transaction
  uint64_t old_leaf_count = 0;
  {
    const std::string meta_key = "leaf_count";
    MDB_val k = {meta_key.size(), (void *)meta_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size == sizeof(uint64_t))
      memcpy(&old_leaf_count, v.mv_data, sizeof(uint64_t));
    else if (result != MDB_NOTFOUND)
      throw0(DB_ERROR(lmdb_error("Failed to get curve tree leaf count in trim: ", result).c_str()));
  }

  if (num_outputs_to_remove > old_leaf_count)
    throw0(DB_ERROR("Cannot trim more leaves than exist in curve tree"));

  uint64_t new_leaf_count = old_leaf_count - num_outputs_to_remove;

  // Read current depth
  uint8_t old_depth = 0;
  {
    const std::string depth_key = "depth";
    MDB_val k = {depth_key.size(), (void *)depth_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size >= 1)
      old_depth = *static_cast<const uint8_t*>(v.mv_data);
  }

  if (new_leaf_count == 0)
  {
    // Trim to empty: delete all leaves, clear all layers, reset meta
    for (uint64_t i = 0; i < old_leaf_count; ++i)
    {
      MDB_val k = {sizeof(i), (void *)&i};
      mdb_del(*m_write_txn, m_curve_tree_leaves, &k, nullptr);
    }
    {
      MDB_cursor *cur;
      int result = mdb_cursor_open(*m_write_txn, m_curve_tree_layers, &cur);
      if (result == 0) {
        MDB_val k, v;
        while (mdb_cursor_get(cur, &k, &v, MDB_NEXT) == 0)
          mdb_cursor_del(cur, 0);
        mdb_cursor_close(cur);
      }
    }
    std::array<uint8_t, 32> init_root = {};
    shekyl_curve_tree_selene_hash_init(init_root.data());
    {
      const std::string root_key = "root";
      MDB_val k = {root_key.size(), (void *)root_key.data()};
      MDB_val v = {32, init_root.data()};
      mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    }
    {
      uint64_t zero = 0;
      const std::string lc_key = "leaf_count";
      MDB_val k = {lc_key.size(), (void *)lc_key.data()};
      MDB_val v = {sizeof(zero), (void *)&zero};
      mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    }
    {
      uint8_t depth = 0;
      const std::string depth_key = "depth";
      MDB_val k = {depth_key.size(), (void *)depth_key.data()};
      MDB_val v = {sizeof(depth), (void *)&depth};
      mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    }
    return;
  }

  // --- Incremental trim: O(removed * log(N)) ---
  // Determine which leaf-layer chunks are affected
  uint64_t first_affected_chunk = new_leaf_count / CT_SELENE_CHUNK_WIDTH;
  uint64_t last_affected_chunk = (old_leaf_count - 1) / CT_SELENE_CHUNK_WIDTH;

  // Process affected leaf-layer chunks using hash_trim
  for (uint64_t chunk = first_affected_chunk; chunk <= last_affected_chunk; ++chunk)
  {
    uint64_t chunk_start = chunk * CT_SELENE_CHUNK_WIDTH;
    uint64_t remaining_in_chunk = (new_leaf_count > chunk_start)
      ? (new_leaf_count - chunk_start) : 0;
    uint64_t old_chunk_end = std::min((chunk + 1) * static_cast<uint64_t>(CT_SELENE_CHUNK_WIDTH), old_leaf_count);

    // Load existing chunk hash
    std::array<uint8_t, 32> old_hash;
    uint64_t layer_key = ct_layer_chunk_key(0, chunk);
    {
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      MDB_val v;
      int result = mdb_get(*m_write_txn, m_curve_tree_layers, &k, &v);
      if (result == 0 && v.mv_size == 32)
        memcpy(old_hash.data(), v.mv_data, 32);
      else
        throw0(DB_ERROR(lmdb_error("Failed to read leaf chunk hash for trim: ", result).c_str()));
    }

    if (remaining_in_chunk == 0)
    {
      // Entire chunk removed — delete it from the leaf layer.
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      mdb_del(*m_write_txn, m_curve_tree_layers, &k, nullptr);
    }
    else
    {
      // Partial trim: use hash_trim to remove trailing scalars
      uint64_t trim_offset = remaining_in_chunk * CT_SCALARS_PER_LEAF;
      uint64_t num_removed_leaves = old_chunk_end - chunk_start - remaining_in_chunk;
      uint64_t num_removed_scalars = num_removed_leaves * CT_SCALARS_PER_LEAF;

      // Read the scalar values being removed
      std::vector<uint8_t> removed_scalars;
      removed_scalars.reserve(num_removed_scalars * 32);
      for (uint64_t out_idx = chunk_start + remaining_in_chunk; out_idx < old_chunk_end; ++out_idx)
      {
        MDB_val k = {sizeof(out_idx), (void *)&out_idx};
        MDB_val v;
        int result = mdb_get(*m_write_txn, m_curve_tree_leaves, &k, &v);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to read leaf for trim: ", result).c_str()));
        removed_scalars.insert(removed_scalars.end(),
          (const uint8_t*)v.mv_data, (const uint8_t*)v.mv_data + CT_LEAF_SIZE);
      }

      std::array<uint8_t, 32> grow_back = {};
      std::array<uint8_t, 32> new_hash;
      bool ok = shekyl_curve_tree_hash_trim_selene(
        old_hash.data(), trim_offset,
        removed_scalars.data(), num_removed_scalars,
        grow_back.data(), new_hash.data());
      if (!ok)
        throw0(DB_ERROR("Rust FFI: shekyl_curve_tree_hash_trim_selene failed in trim"));

      // Store the updated chunk hash
      {
        MDB_val k = {sizeof(layer_key), (void *)&layer_key};
        MDB_val v = {32, new_hash.data()};
        int result = mdb_put(*m_write_txn, m_curve_tree_layers, &k, &v, 0);
        if (result)
          throw0(DB_ERROR(lmdb_error("Failed to store trimmed leaf chunk hash: ", result).c_str()));
      }
    }
  }

  // Delete removed leaf entries
  for (uint64_t i = new_leaf_count; i < old_leaf_count; ++i)
  {
    MDB_val k = {sizeof(i), (void *)&i};
    mdb_del(*m_write_txn, m_curve_tree_leaves, &k, nullptr);
  }

  // Recompose the upper layers from the (now-trimmed) leaf layer, mirroring
  // grow_curve_tree. The previous in-place incremental upper-layer propagation had
  // the same defect as grow: reshaping by old->new differences dropped the
  // pre-existing sibling at a layer boundary, so the header root diverged from the
  // wallet's narrow build_layers. Recomposing every upper layer narrow (== the Rust
  // shekyl_curve_tree_grow_upper_layers FFI) is the consensus-correct construction.

  // Read the leaf-chunk layer (layer 0, [0, num_leaf_chunks)).
  uint64_t num_leaf_chunks = (new_leaf_count + CT_SELENE_CHUNK_WIDTH - 1) / CT_SELENE_CHUNK_WIDTH;
  std::vector<uint8_t> leaf_chunks(static_cast<size_t>(num_leaf_chunks) * 32);
  for (uint64_t c = 0; c < num_leaf_chunks; ++c)
  {
    uint64_t layer_key = ct_layer_chunk_key(0, c);
    MDB_val k = {sizeof(layer_key), (void *)&layer_key};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_layers, &k, &v);
    if (result != 0)
      throw0(DB_ERROR(lmdb_error("Failed to read leaf chunk for trim upper-layer recompose: ", result).c_str()));
    if (v.mv_size != 32)
      throw0(DB_ERROR("Curve tree leaf chunk has unexpected size in trim (expected 32 bytes)"));
    memcpy(leaf_chunks.data() + static_cast<size_t>(c) * 32, v.mv_data, 32);
  }

  // Trim shrinks the tree, so the old structure can have more or deeper upper-layer
  // chunks than the new one. Delete every existing upper-layer chunk (layer >= 1)
  // before rewriting; layer 0 (the leaf chunks read above) is kept. Without this a
  // shrinking tree would leave stale chunks beyond the new structure.
  //
  // Two passes — collect the upper-layer keys, then delete by key — rather than
  // deleting through the cursor mid-scan. The read pass starts at MDB_FIRST (a fresh
  // cursor is unpositioned), advances with MDB_NEXT, and treats any terminating code
  // other than MDB_NOTFOUND as fatal, so the cleanup can't silently stop early and
  // leave stale chunks.
  {
    std::vector<uint64_t> stale_upper_keys;
    {
      MDB_cursor *cur;
      int result = mdb_cursor_open(*m_write_txn, m_curve_tree_layers, &cur);
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to open cursor to clear upper layers in trim: ", result).c_str()));
      MDB_val k, v;
      int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
      for (; rc == 0; rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
      {
        if (k.mv_size != sizeof(uint64_t))
          continue;
        uint64_t key_val;
        memcpy(&key_val, k.mv_data, sizeof(uint64_t));
        if ((key_val >> 56) >= 1)
          stale_upper_keys.push_back(key_val);
      }
      mdb_cursor_close(cur);
      if (rc != MDB_NOTFOUND)
        throw0(DB_ERROR(lmdb_error("Failed to scan curve tree layers in trim: ", rc).c_str()));
    }
    for (uint64_t stale_key : stale_upper_keys)
    {
      MDB_val k = {sizeof(stale_key), (void *)&stale_key};
      int result = mdb_del(*m_write_txn, m_curve_tree_layers, &k, nullptr);
      if (result && result != MDB_NOTFOUND)
        throw0(DB_ERROR(lmdb_error("Failed to delete stale curve tree upper chunk in trim: ", result).c_str()));
    }
  }

  // The total upper-layer chunk count is at most num_leaf_chunks (equal only for a
  // single leaf chunk, promoted to its own Helios root); +1 is a defensive margin.
  std::vector<uint8_t> upper_chunks(static_cast<size_t>(num_leaf_chunks + 1) * 32);
  std::array<uint64_t, 16> layer_sizes = {};
  uint64_t num_upper_layers = 0;
  std::array<uint8_t, 32> root = {};
  if (!shekyl_curve_tree_grow_upper_layers(
        leaf_chunks.data(), num_leaf_chunks,
        upper_chunks.data(), num_leaf_chunks + 1,
        layer_sizes.data(), layer_sizes.size(),
        &num_upper_layers, root.data()))
    throw0(DB_ERROR("Rust FFI: shekyl_curve_tree_grow_upper_layers failed in trim"));

  // Persist the recomposed upper-layer chunk hashes (layers 1..num_upper_layers).
  uint64_t written = 0;
  for (uint64_t li = 0; li < num_upper_layers; ++li)
  {
    const uint8_t out_layer = static_cast<uint8_t>(li + 1);
    for (uint64_t c = 0; c < layer_sizes[li]; ++c)
    {
      uint64_t layer_key = ct_layer_chunk_key(out_layer, c);
      MDB_val k = {sizeof(layer_key), (void *)&layer_key};
      MDB_val v = {32, upper_chunks.data() + static_cast<size_t>(written) * 32};
      int result = mdb_put(*m_write_txn, m_curve_tree_layers, &k, &v, 0);
      if (result)
        throw0(DB_ERROR(lmdb_error("Failed to store curve tree upper layer hash in trim: ", result).c_str()));
      ++written;
    }
  }

  // Update meta: root, leaf_count, depth (mirrors grow_curve_tree).
  {
    const std::string root_key = "root";
    MDB_val k = {root_key.size(), (void *)root_key.data()};
    MDB_val v = {32, root.data()};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree root after trim: ", result).c_str()));
  }
  {
    const std::string lc_key = "leaf_count";
    MDB_val k = {lc_key.size(), (void *)lc_key.data()};
    MDB_val v = {sizeof(new_leaf_count), (void *)&new_leaf_count};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store leaf count after trim: ", result).c_str()));
  }
  {
    // depth = number of layers above the leaf (consensus: fcmp_layers = depth + 1).
    if (num_upper_layers > 0xff)
      throw0(DB_ERROR("Curve tree depth exceeds uint8_t range in trim (FFI returned an impossible layer count)"));
    const std::string depth_key = "depth";
    const uint8_t depth = static_cast<uint8_t>(num_upper_layers);
    MDB_val k = {depth_key.size(), (void *)depth_key.data()};
    MDB_val v = {sizeof(depth), (void *)&depth};
    int result = mdb_put(*m_write_txn, m_curve_tree_meta, &k, &v, 0);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to store curve tree depth after trim: ", result).c_str()));
  }

  LOG_PRINT_L2("Incremental curve tree trim: removed " << num_outputs_to_remove
    << " outputs (" << old_leaf_count << " → " << new_leaf_count << ")");
}

std::array<uint8_t, 32> BlockchainLMDB::get_curve_tree_root() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // Returns the Selene hash_init value if the tree is empty (no leaves stored).
  // Callers should compare against hash_init or check get_curve_tree_leaf_count()
  // to distinguish an empty tree from a root that happens to be the identity.
  TXN_PREFIX_RDONLY();
  const std::string root_key = "root";
  MDB_val k = {root_key.size(), (void *)root_key.data()};
  MDB_val v;
  std::array<uint8_t, 32> root = {};
  int result = mdb_get(m_txn, m_curve_tree_meta, &k, &v);
  if (result == 0 && v.mv_size == 32)
    memcpy(root.data(), v.mv_data, 32);
  else if (result == MDB_NOTFOUND)
    shekyl_curve_tree_selene_hash_init(root.data());
  else
    throw0(DB_ERROR(lmdb_error("Failed to get curve tree root: ", result).c_str()));
  TXN_POSTFIX_RDONLY();
  return root;
}

uint8_t BlockchainLMDB::get_curve_tree_depth() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  const std::string depth_key = "depth";
  MDB_val k = {depth_key.size(), (void *)depth_key.data()};
  MDB_val v;
  uint8_t depth = 0;
  int result = mdb_get(m_txn, m_curve_tree_meta, &k, &v);
  if (result == 0 && v.mv_size >= 1)
    depth = *static_cast<const uint8_t*>(v.mv_data);
  TXN_POSTFIX_RDONLY();
  return depth;
}

uint64_t BlockchainLMDB::get_curve_tree_leaf_count() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  const std::string lc_key = "leaf_count";
  MDB_val k = {lc_key.size(), (void *)lc_key.data()};
  MDB_val v;
  uint64_t count = 0;
  int result = mdb_get(m_txn, m_curve_tree_meta, &k, &v);
  if (result == 0 && v.mv_size == sizeof(uint64_t))
    memcpy(&count, v.mv_data, sizeof(uint64_t));
  TXN_POSTFIX_RDONLY();
  return count;
}

bool BlockchainLMDB::get_curve_tree_layer_hash(uint8_t layer, uint64_t chunk, uint8_t* hash_out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!hash_out) return false;

  TXN_PREFIX_RDONLY();
  uint64_t key = ct_layer_chunk_key(layer, chunk);
  MDB_val k = {sizeof(key), (void *)&key};
  MDB_val v;
  int result = mdb_get(m_txn, m_curve_tree_layers, &k, &v);
  bool found = (result == 0 && v.mv_size == 32);
  if (found)
    memcpy(hash_out, v.mv_data, 32);
  TXN_POSTFIX_RDONLY();
  return found;
}

bool BlockchainLMDB::get_curve_tree_leaf_by_tree_position(uint64_t tree_position, uint8_t* leaf_out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!leaf_out) return false;

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(tree_position), (void *)&tree_position};
  MDB_val v;
  int result = mdb_get(m_txn, m_curve_tree_leaves, &k, &v);
  bool found = (result == 0 && v.mv_size == CT_LEAF_SIZE);
  if (found)
    memcpy(leaf_out, v.mv_data, CT_LEAF_SIZE);
  TXN_POSTFIX_RDONLY();
  return found;
}

bool BlockchainLMDB::get_curve_tree_leaf_chunk(uint64_t first_tree_position, uint64_t count, uint8_t* out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!out) return false;
  if (count == 0) return true;

  TXN_PREFIX_RDONLY();
  MDB_cursor* cur = nullptr;
  int result = mdb_cursor_open(m_txn, m_curve_tree_leaves, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open curve tree leaf cursor: ", result).c_str()));
  const std::unique_ptr<MDB_cursor, decltype(&mdb_cursor_close)> cur_guard(cur, &mdb_cursor_close);

  // One root-to-leaf traversal to position at first_tree_position, then a
  // sequential page walk for the rest — the keys are contiguous and
  // integer-ordered (m_curve_tree_leaves is MDB_INTEGERKEY). Every leaf in the
  // run must be present and full; a gap or short row is registry/tree
  // disagreement, reported as a whole-chunk miss (false).
  uint64_t pos = first_tree_position;
  MDB_val k = {sizeof(pos), (void *)&pos};
  MDB_val v;
  MDB_cursor_op op = MDB_SET;
  for (uint64_t i = 0; i < count; ++i)
  {
    result = mdb_cursor_get(cur, &k, &v, op);
    if (result == MDB_NOTFOUND)
    {
      TXN_POSTFIX_RDONLY();
      return false;
    }
    if (result)
      throw0(DB_ERROR(lmdb_error("Curve tree leaf cursor error at chunk read: ", result).c_str()));
    // MDB_NEXT can walk past the run's end into an unrelated key; pin each row
    // to its expected contiguous position.
    if (k.mv_size != sizeof(uint64_t) ||
        *static_cast<const uint64_t*>(k.mv_data) != first_tree_position + i ||
        v.mv_size != CT_LEAF_SIZE)
    {
      TXN_POSTFIX_RDONLY();
      return false;
    }
    memcpy(out + i * CT_LEAF_SIZE, v.mv_data, CT_LEAF_SIZE);
    op = MDB_NEXT;
  }
  TXN_POSTFIX_RDONLY();
  return true;
}

bool BlockchainLMDB::get_curve_tree_leaf_by_output_index(uint64_t output_index, uint8_t* leaf_out) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();
  if (!leaf_out) return false;

  TreePosition pos{0};
  if (!get_output_leaf_index(OutputIndex{output_index}, pos))
    return false;
  return get_curve_tree_leaf_by_tree_position(pos.value, leaf_out);
}

void BlockchainLMDB::store_curve_tree_root_at_height(uint64_t block_height, const std::array<uint8_t, 32>& root)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v = {root.size(), (void *)root.data()};
  int result = mdb_put(*m_write_txn, m_curve_tree_roots, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to store curve tree root at height: ", result).c_str()));
}

std::array<uint8_t, 32> BlockchainLMDB::get_curve_tree_root_at_height(uint64_t block_height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v;
  int result = mdb_get(m_txn, m_curve_tree_roots, &k, &v);
  std::array<uint8_t, 32> root{};
  if (result == 0 && v.mv_size == 32)
    memcpy(root.data(), v.mv_data, 32);
  else if (result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Error looking up curve tree root at height: ", result).c_str()));
  TXN_POSTFIX_RDONLY();
  return root;
}

void BlockchainLMDB::remove_curve_tree_root_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(block_height), (void *)&block_height};
  int result = mdb_del(*m_write_txn, m_curve_tree_roots, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove curve tree root at height: ", result).c_str()));
}

// Credit-wire attestation witness (ARCHIVAL_CREDIT_WIRE.md §3.2/§4): prunable
// admission bytes (r + pass signatures), height-keyed (native uint64,
// MDB_INTEGERKEY), opaque at this layer. Mirrors the curve-tree root primitives
// above — same key shape, same write-txn discipline.
void BlockchainLMDB::store_archival_attestation_witness_at_height(uint64_t block_height, const blobdata& witness)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v = {witness.size(), (void *)witness.data()};
  int result = mdb_put(*m_write_txn, m_archival_attestation_witness, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to store attestation witness at height: ", result).c_str()));
}

blobdata BlockchainLMDB::get_archival_attestation_witness_at_height(uint64_t block_height) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v;
  int result = mdb_get(m_txn, m_archival_attestation_witness, &k, &v);
  blobdata witness;
  if (result == 0)
    witness.assign(static_cast<const char *>(v.mv_data), v.mv_size);
  else if (result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Error looking up attestation witness at height: ", result).c_str()));
  TXN_POSTFIX_RDONLY();
  return witness;
}

void BlockchainLMDB::remove_archival_attestation_witness_at_height(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(block_height), (void *)&block_height};
  int result = mdb_del(*m_write_txn, m_archival_attestation_witness, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove attestation witness at height: ", result).c_str()));
}

// Reorg-survival alt-chain attestation witness (ARCHIVAL_CREDIT_WIRE.md §3): the
// same opaque bytes as the height-keyed primitives above, but keyed by BLOCK HASH
// (compare_hash32, set at open) so an alt block carries its witness across a reorg.
// Lifetime is tied to the alt block via remove_alt_block / drop_alt_blocks.
void BlockchainLMDB::store_archival_alt_attestation_witness(const crypto::hash& blkid, const blobdata& witness)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(blkid), (void *)&blkid};
  MDB_val v = {witness.size(), (void *)witness.data()};
  int result = mdb_put(*m_write_txn, m_archival_alt_attestation_witness, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to store alt attestation witness: ", result).c_str()));
}

blobdata BlockchainLMDB::get_archival_alt_attestation_witness(const crypto::hash& blkid) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(blkid), (void *)&blkid};
  MDB_val v;
  int result = mdb_get(m_txn, m_archival_alt_attestation_witness, &k, &v);
  blobdata witness;
  if (result == 0)
    witness.assign(static_cast<const char *>(v.mv_data), v.mv_size);
  else if (result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Error looking up alt attestation witness: ", result).c_str()));
  TXN_POSTFIX_RDONLY();
  return witness;
}

void BlockchainLMDB::remove_archival_alt_attestation_witness(const crypto::hash& blkid)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(blkid), (void *)&blkid};
  int result = mdb_del(*m_write_txn, m_archival_alt_attestation_witness, &k, nullptr);
  if (result && result != MDB_NOTFOUND)
    throw0(DB_ERROR(lmdb_error("Failed to remove alt attestation witness: ", result).c_str()));
}

void BlockchainLMDB::save_curve_tree_checkpoint(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  std::array<uint8_t, 32> root = {};
  uint8_t depth = 0;
  uint64_t leaf_count = 0;
  bool root_ok = false, depth_ok = false, lc_ok = false;

  {
    const std::string root_key = "root";
    MDB_val k = {root_key.size(), (void *)root_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size == 32) {
      memcpy(root.data(), v.mv_data, 32);
      root_ok = true;
    }
  }
  {
    const std::string depth_key = "depth";
    MDB_val k = {depth_key.size(), (void *)depth_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size >= 1) {
      depth = *static_cast<const uint8_t*>(v.mv_data);
      depth_ok = true;
    }
  }
  {
    const std::string lc_key = "leaf_count";
    MDB_val k = {lc_key.size(), (void *)lc_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size == sizeof(uint64_t)) {
      memcpy(&leaf_count, v.mv_data, sizeof(uint64_t));
      lc_ok = true;
    }
  }

  if (!root_ok || !depth_ok || !lc_ok || leaf_count == 0)
  {
    LOG_PRINT_L1("Skipping curve tree checkpoint at height " << block_height
      << ": incomplete meta (root_ok=" << root_ok << " depth_ok=" << depth_ok
      << " lc_ok=" << lc_ok << " leaf_count=" << leaf_count << ")");
    return;
  }

  // Checkpoint format: root[32] || depth[1] || leaf_count[8] = 41 bytes
  std::vector<uint8_t> checkpoint_data(32 + 1 + sizeof(uint64_t));
  memcpy(checkpoint_data.data(), root.data(), 32);
  checkpoint_data[32] = depth;
  memcpy(checkpoint_data.data() + 33, &leaf_count, sizeof(uint64_t));

  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v = {checkpoint_data.size(), (void *)checkpoint_data.data()};
  int result = mdb_put(*m_write_txn, m_curve_tree_checkpoints, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to save curve tree checkpoint: ", result).c_str()));

  LOG_PRINT_L2("Saved curve tree checkpoint at height " << block_height
    << " (leaf_count=" << leaf_count << ", depth=" << (int)depth << ")");
}

bool BlockchainLMDB::get_curve_tree_checkpoint(uint64_t block_height, std::vector<uint8_t>& checkpoint_data) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_val k = {sizeof(block_height), (void *)&block_height};
  MDB_val v;
  int result = mdb_get(m_txn, m_curve_tree_checkpoints, &k, &v);
  if (result == MDB_NOTFOUND)
  {
    TXN_POSTFIX_RDONLY();
    return false;
  }
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to get curve tree checkpoint: ", result).c_str()));
  checkpoint_data.assign(static_cast<const uint8_t*>(v.mv_data),
                         static_cast<const uint8_t*>(v.mv_data) + v.mv_size);
  TXN_POSTFIX_RDONLY();
  return true;
}

uint64_t BlockchainLMDB::get_latest_curve_tree_checkpoint_height() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();
  MDB_cursor *cur;
  int result = mdb_cursor_open(m_txn, m_curve_tree_checkpoints, &cur);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to open cursor for curve tree checkpoints: ", result).c_str()));

  uint64_t latest_height = 0;
  MDB_val k, v;
  result = mdb_cursor_get(cur, &k, &v, MDB_LAST);
  if (result == 0 && k.mv_size == sizeof(uint64_t))
    memcpy(&latest_height, k.mv_data, sizeof(uint64_t));

  mdb_cursor_close(cur);
  TXN_POSTFIX_RDONLY();
  return latest_height;
}

void BlockchainLMDB::prune_curve_tree_intermediate_layers(uint64_t checkpoint_height)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  // Find the previous checkpoint to determine which leaf range was already
  // covered.  We only prune layer entries for chunks that are fully below
  // the previous checkpoint (those hashes are redundant -- they can be
  // recomputed from leaves if ever needed again).
  uint64_t prev_checkpoint_height = 0;
  uint64_t prev_leaf_count = 0;
  {
    MDB_cursor *cur;
    int result = mdb_cursor_open(*m_write_txn, m_curve_tree_checkpoints, &cur);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to open cursor for checkpoint scan: ", result).c_str()));

    MDB_val k = {sizeof(checkpoint_height), (void *)&checkpoint_height};
    MDB_val v;
    result = mdb_cursor_get(cur, &k, &v, MDB_SET);
    if (result == 0)
    {
      result = mdb_cursor_get(cur, &k, &v, MDB_PREV);
      if (result == 0 && k.mv_size == sizeof(uint64_t))
      {
        memcpy(&prev_checkpoint_height, k.mv_data, sizeof(uint64_t));
        // Checkpoint format: root[32] || depth[1] || leaf_count[8]
        if (v.mv_size >= 41)
          memcpy(&prev_leaf_count, static_cast<const uint8_t*>(v.mv_data) + 33, sizeof(uint64_t));
      }
    }
    mdb_cursor_close(cur);
  }

  if (prev_checkpoint_height == 0 || prev_leaf_count == 0)
    return;

  uint8_t depth = 0;
  {
    const std::string depth_key = "depth";
    MDB_val k = {depth_key.size(), (void *)depth_key.data()};
    MDB_val v;
    int result = mdb_get(*m_write_txn, m_curve_tree_meta, &k, &v);
    if (result == 0 && v.mv_size >= 1)
      depth = *static_cast<const uint8_t*>(v.mv_data);
  }

  if (depth < 3)
    return;

  // Prune intermediate layers (1 through depth-2).  For each layer, only
  // delete chunk entries whose index is strictly below the chunk boundary
  // implied by prev_leaf_count.  These chunks are fully "sealed" by the
  // previous checkpoint and can be recomputed from leaves.
  uint64_t pruned_count = 0;
  uint64_t child_boundary = prev_leaf_count / CT_SELENE_CHUNK_WIDTH;

  for (uint8_t layer = 1; layer <= depth - 2; ++layer)
  {
    uint32_t parent_width = ct_chunk_width(layer);
    uint64_t parent_boundary = child_boundary / parent_width;
    if (parent_boundary == 0)
      break;

    uint64_t layer_prefix = static_cast<uint64_t>(layer) << 56;
    uint64_t start_key = layer_prefix;
    uint64_t prune_up_to = layer_prefix | (parent_boundary - 1);

    MDB_cursor *cur;
    int result = mdb_cursor_open(*m_write_txn, m_curve_tree_layers, &cur);
    if (result)
      throw0(DB_ERROR(lmdb_error("Failed to open layers cursor for pruning: ", result).c_str()));

    MDB_val k = {sizeof(start_key), (void *)&start_key};
    MDB_val v;
    result = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while (result == 0)
    {
      uint64_t current_key;
      memcpy(&current_key, k.mv_data, sizeof(uint64_t));
      if (current_key > prune_up_to)
        break;
      result = mdb_cursor_del(cur, 0);
      if (result)
        break;
      ++pruned_count;
      // LMDB contract: after mdb_cursor_del, the cursor is positioned on the
      // *next* item (or invalidated if there is none).  MDB_GET_CURRENT
      // retrieves that next item without advancing further.  MDB_NEXT would
      // skip one entry because the cursor already advanced.
      result = mdb_cursor_get(cur, &k, &v, MDB_GET_CURRENT);
      if (result == MDB_NOTFOUND)
        break;
    }
    mdb_cursor_close(cur);

    child_boundary = parent_boundary;
  }

  // Garbage-collect checkpoints older than the previous one -- only the two
  // most recent checkpoints are needed (current + previous for pruning range).
  if (prev_checkpoint_height > 0)
  {
    MDB_cursor *cur;
    int result = mdb_cursor_open(*m_write_txn, m_curve_tree_checkpoints, &cur);
    if (result == 0)
    {
      MDB_val k, v;
      result = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
      while (result == 0)
      {
        uint64_t h = 0;
        memcpy(&h, k.mv_data, sizeof(uint64_t));
        if (h >= prev_checkpoint_height)
          break;
        result = mdb_cursor_del(cur, 0);
        if (result) break;
        // Same LMDB post-delete contract: cursor already on next item.
        result = mdb_cursor_get(cur, &k, &v, MDB_GET_CURRENT);
        if (result == MDB_NOTFOUND) break;
      }
      mdb_cursor_close(cur);
    }
  }

  LOG_PRINT_L2("Pruned " << pruned_count << " intermediate layer entries below prev checkpoint " << prev_checkpoint_height);
}

// ─── Output Metadata Pruning ──────────────────────────────────────────────────

void BlockchainLMDB::store_output_metadata(uint64_t global_output_index, const output_pruning_metadata_t& meta)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  MDB_val k = {sizeof(global_output_index), (void *)&global_output_index};
  MDB_val v = {sizeof(output_pruning_metadata_t), (void *)&meta};

  int result = mdb_put(*m_write_txn, m_output_metadata, &k, &v, 0);
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to store output metadata: ", result).c_str()));
}

bool BlockchainLMDB::get_output_metadata(uint64_t global_output_index, output_pruning_metadata_t& meta) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  TXN_PREFIX_RDONLY();

  MDB_val k = {sizeof(global_output_index), (void *)&global_output_index};
  MDB_val v;

  int result = mdb_get(m_txn, m_output_metadata, &k, &v);
  if (result == MDB_NOTFOUND)
    return false;
  if (result)
    throw0(DB_ERROR(lmdb_error("Failed to get output metadata: ", result).c_str()));
  if (v.mv_size != sizeof(output_pruning_metadata_t))
    throw0(DB_ERROR("Unexpected output metadata size"));

  memcpy(&meta, v.mv_data, sizeof(output_pruning_metadata_t));
  TXN_POSTFIX_RDONLY();
  return true;
}

bool BlockchainLMDB::is_output_pruned(uint64_t global_output_index) const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  output_pruning_metadata_t meta;
  if (!get_output_metadata(global_output_index, meta))
    return false;
  return meta.pruned != 0;
}

uint64_t BlockchainLMDB::read_tx_prune_next_block_height() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  uint64_t next = 0;
  TXN_PREFIX_RDONLY();
  MDB_val v;
  MDB_val_str(k_new, "tx_prune_next_block");
  int r = mdb_get(m_txn, m_properties, &k_new, &v);
  if (r == 0 && v.mv_size == sizeof(uint64_t))
    memcpy(&next, v.mv_data, sizeof(uint64_t));
  else
  {
    MDB_val_str(k_old, "last_pruned_tx_data_height");
    r = mdb_get(m_txn, m_properties, &k_old, &v);
    if (r == 0 && v.mv_size == sizeof(uint64_t))
    {
      uint64_t legacy_last_inclusive = 0;
      memcpy(&legacy_last_inclusive, v.mv_data, sizeof(uint64_t));
      next = legacy_last_inclusive + 1;
    }
  }
  TXN_POSTFIX_RDONLY();
  return next;
}

void BlockchainLMDB::write_tx_prune_next_block_height(MDB_txn* wtxn, uint64_t next_block)
{
  MDB_val_str(wk, "tx_prune_next_block");
  MDB_val wv = {sizeof(next_block), (void *)&next_block};
  if (int err = mdb_put(wtxn, m_properties, &wk, &wv, 0))
    throw0(DB_ERROR(lmdb_error("tx_prune_next_block watermark: ", err).c_str()));
  MDB_val_str(wk_old, "last_pruned_tx_data_height");
  (void)mdb_del(wtxn, m_properties, &wk_old, NULL);
}

uint64_t BlockchainLMDB::get_last_pruned_tx_data_height() const
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  const uint64_t next = read_tx_prune_next_block_height();
  return next > 0 ? next - 1 : 0;
}

bool BlockchainLMDB::tx_has_verification_data(const crypto::hash& tx_hash) const
{
  cryptonote::blobdata bd;
  return get_prunable_tx_blob(tx_hash, bd);
}

bool BlockchainLMDB::prune_tx_data(uint64_t depth)
{
  LOG_PRINT_L3("BlockchainLMDB::" << __func__);
  check_open();

  if (depth == 0)
    depth = CRYPTONOTE_TX_PRUNE_DEPTH;

  const uint64_t blockchain_height = height();
  if (blockchain_height <= depth)
    return true;

  const uint64_t prune_below_height = blockchain_height - depth;

  const uint64_t next_block = read_tx_prune_next_block_height();
  if (next_block >= prune_below_height)
  {
    LOG_PRINT_L2("prune_tx_data: already pruned through block " << (next_block > 0 ? next_block - 1 : 0)
                 << ", next block " << next_block << ", target exclusive " << prune_below_height
                 << " -- nothing to do");
    return true;
  }

  uint64_t h = next_block;
  LOG_PRINT_L1("prune_tx_data: pruning transactions in blocks " << h
               << " .. " << prune_below_height
               << " (reorg depth " << depth << ")");

  mdb_txn_safe *const saved_write = m_write_txn;
  struct write_txn_restorer {
    mdb_txn_safe **slot;
    mdb_txn_safe *old;
    ~write_txn_restorer() { *slot = old; }
  } restorer{&m_write_txn, saved_write};

  while (h < prune_below_height)
  {
    mdb_txn_safe wtxn(false);
    if (int err = mdb_txn_begin(m_env, NULL, 0, wtxn))
      throw0(DB_ERROR(lmdb_error("prune_tx_data: failed to begin write txn: ", err).c_str()));
    m_write_txn = &wtxn;

    MDB_stat st{};
    if (int err = mdb_stat(wtxn, m_blocks, &st))
    {
      m_write_txn = saved_write;
      throw0(DB_ERROR(lmdb_error("prune_tx_data: mdb_stat m_blocks: ", err).c_str()));
    }
    const uint64_t chain_h = st.ms_entries;
    if (chain_h <= depth)
    {
      wtxn.commit();
      m_write_txn = saved_write;
      return true;
    }
    const uint64_t safe_below = chain_h - depth;
    const uint64_t batch_end = std::min<uint64_t>({h + 256, prune_below_height, safe_below});
    if (h >= batch_end)
    {
      wtxn.commit();
      m_write_txn = saved_write;
      return true;
    }

    auto prune_tx_outputs = [&](uint64_t tx_id, const cryptonote::transaction& tx, uint64_t block_height) {
      (void)block_height;
      std::vector<std::vector<uint64_t>> aoi = get_tx_amount_output_indices(tx_id, 1);
      if (aoi.empty())
        return;
      const std::vector<uint64_t>& outs = aoi[0];
      const size_t n = std::min(outs.size(), tx.vout.size());
      for (size_t i = 0; i < n; ++i)
      {
        // Match BlockchainDB::add_transaction: RCT coinbase outputs are indexed under amount 0.
        uint64_t amount = tx.vout[i].amount;
        if (!tx.vin.empty() && std::holds_alternative<cryptonote::txin_gen>(tx.vin[0]) && tx.version >= 2)
          amount = 0;
        const uint64_t gidx = outs[i];
        output_data_t od = get_output_key(amount, gidx, true);
        output_pruning_metadata_t meta{};
        meta.pubkey = od.pubkey;
        meta.commitment = od.commitment;
        meta.unlock_time = od.unlock_time;
        meta.height = od.height;
        meta.pruned = 1;
        store_output_metadata(gidx, meta);
      }
      MDB_val ktx{};
      ktx.mv_data = &tx_id;
      ktx.mv_size = sizeof(tx_id);
      (void)mdb_del(wtxn, m_txs_prunable, &ktx, NULL);
      (void)mdb_del(wtxn, m_txs_prunable_hash, &ktx, NULL);
      (void)mdb_del(wtxn, m_txs_pqc_auths, &ktx, NULL);
    };

    for (; h < batch_end; ++h)
    {
      cryptonote::block blk = get_block_from_height(h);

      const crypto::hash miner_h = cryptonote::get_transaction_hash(blk.miner_tx);
      try
      {
        const uint64_t miner_id = get_tx_id(miner_h);
        cryptonote::transaction mtx;
        if (!get_pruned_tx(miner_h, mtx))
          throw0(DB_ERROR("prune_tx_data: failed to load miner tx"));
        prune_tx_outputs(miner_id, mtx, h);
      }
      catch (const TX_DNE&)
      {
        throw0(DB_ERROR(("prune_tx_data: miner tx missing at height " + std::to_string(h) +
                         "; refusing to advance prune watermark on partial batch").c_str()));
      }

      for (const crypto::hash& txh : blk.tx_hashes)
      {
        try
        {
          const uint64_t tid = get_tx_id(txh);
          cryptonote::transaction tx;
          if (!get_pruned_tx(txh, tx))
            throw0(DB_ERROR("prune_tx_data: failed to load tx"));
          prune_tx_outputs(tid, tx, h);
        }
        catch (const TX_DNE&)
        {
          throw0(DB_ERROR(("prune_tx_data: tx " + epee::string_tools::pod_to_hex(txh) +
                           " not found at height " + std::to_string(h) +
                           "; refusing to advance prune watermark on partial batch").c_str()));
        }
      }
    }

    {
      write_tx_prune_next_block_height(wtxn, h);
    }

    wtxn.commit();
    m_write_txn = saved_write;
  }

  m_write_txn = saved_write;
  return true;
}

void BlockchainLMDB::migrate(const uint32_t oldversion)
{
  // Pre-genesis posture (15-deletion-and-debt.mdc, 60-no-monero-legacy.mdc):
  // no in-Shekyl migration code; `rm -rf` and resync is the migration path.
  // V9 added the block-header `attestation_root` (ARCHIVAL_CREDIT_WIRE.md §3):
  // a pre-V9 block blob has no attestation_root bytes, so the V9 parser cannot
  // read it. V8 added the persisted frozen-shard counter (properties
  // `archival_frozen_shard_count`); a pre-V8 DB carries segment rows the counter
  // does not account for. Neither has an in-place path; refuse loudly. (The
  // Monero-era migrate_0_1..migrate_5_6 ladder was unreachable from this guard
  // and has been deleted.)
  if (oldversion < VERSION)
  {
    // Message tracks VERSION so the next bump cannot leave a stale "pre-VN".
    throw0(DB_ERROR(("Database schema is pre-V" + std::to_string(VERSION)
      + "; no pre-genesis migration path exists. Delete the data directory and resync.").c_str()));
  }
}

}  // namespace cryptonote
