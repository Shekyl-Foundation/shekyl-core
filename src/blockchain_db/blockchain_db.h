// Copyright (c) 2014-2022, The Monero Project
//
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
#ifndef BLOCKCHAIN_DB_H
#define BLOCKCHAIN_DB_H

#pragma once

#include <array>
#include <cstring>
#include <string>
#include <exception>
#include <boost/program_options.hpp>
#include "common/command_line.h"
#include "crypto/hash.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_protocol/enums.h"
#include "net/enums.h"
#include "blockchain_db/shekyl_types.h"
#include "shekyl/shekyl_ffi.h" // epoch-close FFI row structs for ArchivalEmissionEpochSnapshot::to_ffi_*

/** \file
 * Cryptonote Blockchain Database Interface
 *
 * The DB interface is a store for the canonical block chain.
 * It serves as a persistent storage for the blockchain.
 *
 * For the sake of efficiency, a concrete implementation may also
 * store some blockchain data outside of the blocks, such as spent
 * transfer key images, unspent transaction outputs, etc.
 *
 * Examples are as follows:
 *
 * Transactions are duplicated so that we don't have to fetch a whole block
 * in order to fetch a transaction from that block.
 *
 * Spent key images are duplicated outside of the blocks so it is quick
 * to verify an output hasn't already been spent
 *
 * Unspent transaction outputs are duplicated to quickly gather random
 * outputs to use for mixins
 *
 * Indices and Identifiers:
 * The word "index" is used ambiguously throughout this code. It is
 * particularly confusing when talking about the output or transaction
 * tables since their indexing can refer to themselves or each other.
 * I have attempted to clarify these usages here:
 *
 * Blocks, transactions, and outputs are all identified by a hash.
 * For storage efficiency, a 64-bit integer ID is used instead of the hash
 * inside the DB. Tables exist to map between hash and ID. A block ID is
 * also referred to as its "height". Transactions and outputs generally are
 * not referred to by ID outside of this module, but the tx ID is returned
 * by tx_exists() and used by get_tx_amount_output_indices(). Like their
 * corresponding hashes, IDs are globally unique.
 *
 * The remaining uses of the word "index" refer to local offsets, and are
 * not globally unique. An "amount output index" N refers to the Nth output
 * of a specific amount. An "output local index" N refers to the Nth output
 * of a specific tx.
 *
 * Exceptions:
 *   DB_ERROR -- generic
 *   DB_OPEN_FAILURE
 *   DB_CREATE_FAILURE
 *   DB_SYNC_FAILURE
 *   BLOCK_DNE
 *   BLOCK_PARENT_DNE
 *   BLOCK_EXISTS
 *   BLOCK_INVALID -- considering making this multiple errors
 *   TX_DNE
 *   TX_EXISTS
 *   OUTPUT_DNE
 *   OUTPUT_EXISTS
 *   KEY_IMAGE_EXISTS
 */

namespace cryptonote
{

/** a pair of <transaction hash, output index>, typedef for convenience */
typedef std::pair<crypto::hash, uint64_t> tx_out_index;

extern const command_line::arg_descriptor<std::string> arg_db_sync_mode;
extern const command_line::arg_descriptor<bool, false> arg_db_salvage;

enum class relay_category : uint8_t
{
  broadcasted = 0,//!< Public txes received via block/fluff
  /*! Every tx not marked `relay_method::none`.

      Deliberately NOT collapsed into `all`, even though nothing supplies
      `none` at admission any more: the pool's writers are
      `handle_incoming_tx` (p2p `stem`/`fluff`, import `block`),
      `Blockchain`'s reorg re-adds (`block`), and the engine submit
      (`local`). `none` means "received via RPC with `do_not_relay` set" and
      Shekyl has no such RPC.

      It is not a zero-decode guard, and it is worth saying so because that is
      the plausible-sounding reason to keep it: a zeroed record decodes to
      `fluff`, NOT `none` (`get_relay_method` falls through state 0 to the
      `fluff` return). Reaching `none` needs `do_not_relay = 1`, which only a
      build that had a `do_not_relay` writer could have persisted.

      What it actually is: the DB-layer half of a two-layer filter. Its one production
      reader is `get_relayable_transactions`, which passes it to
      `for_all_txpool_txes` and *also* tests `!meta.do_not_relay` in the loop
      body. So this category is not the sole guard against relaying a
      do-not-relay entry, and no test should be credited for that. It stays
      because it costs nothing and it is the only filter at the DB read;
      removing it is a change to the relay loop's iteration, which is a
      different surface from this classifier. */
  relayable,
  all             //!< Everything in the db
};

/* `legacy` was deleted here. It was `broadcasted` + `relay_method::none` --
   the most public class unioned with the most private one -- and its own
   doc gave the reason as "rpc relay requests or historical reasons". The
   history was Monero's pre-Dandelion++ RPC; Shekyl is v3-from-genesis with
   no such client (rule 60), so the union had no member any caller wanted.
   Nine of its ten call sites were asking "is this publicly known", which is
   `broadcasted`, and one of those -- `fill_block_template` -- would have
   admitted a do-not-relay transaction into a block template had `none` ever
   been reachable. The tenth, `core::pool_has_tx`, was asking a different
   question and now says so: it asks `all`, because its caller wants "do I
   already hold these bytes". See the note at its definition.
   `matches_category`'s table is pinned exhaustively by
   `tests/unit_tests/relay_category.cpp`.

   Removing a middle member renumbered `all`, and that is deliberately NOT
   compensated with an explicit value or a reserved gap. These values have no
   counterparty: `relay_category` is never cast, never serialized, and never
   crosses the FFI -- unlike `relay_method`, whose bytes ARE a contract and are
   pinned by `static_assert` in `cryptonote_protocol/enums.h`. Pinning a value
   with no reader would tell the next maintainer a wire contract exists, which
   is the shape of debt this deletion removes. Reopen if `relay_category` ever
   gains a persisted or FFI representation: the pin then goes beside that
   representation, as `relay_method`'s does. */

bool matches_category(relay_method method, relay_category category) noexcept;

/**
 * @brief LMDB height key for a block's attestation witness.
 *
 * Mirrors `store_curve_tree_root_at_height`: keyed at the post-add chain height
 * (`block_index + 1`), not the block's 0-based index. Every read/write site that
 * starts from a 0-based block index MUST go through this helper so the +1
 * cannot drift between add / serve / reorg paths.
 */
inline uint64_t archival_attestation_witness_key(uint64_t block_index) noexcept
{
  return block_index + 1;
}

#pragma pack(push, 1)

/**
 * @brief a struct containing output metadata
 */
struct output_data_t
{
  crypto::public_key pubkey;       //!< the output's public key (for spend verification)
  uint64_t           unlock_time;  //!< the output's unlock time (or height)
  uint64_t           height;       //!< the height of the block which created the output
  ct::key           commitment;   //!< the output's amount commitment (for spend verification)
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tx_data_t
{
  uint64_t tx_id;
  uint64_t unlock_time;
  uint64_t block_id;
};
#pragma pack(pop)

struct alt_block_data_t
{
  uint64_t height;
  uint64_t cumulative_weight;
  uint64_t cumulative_difficulty_low;
  uint64_t cumulative_difficulty_high;
  uint64_t already_generated_coins;
};

#pragma pack(push, 1)
/**
 * @brief per-output metadata retained after transaction pruning.
 *
 * When a block is confirmed beyond CRYPTONOTE_TX_PRUNE_DEPTH (see prune_tx_data),
 * verification blobs can be discarded. This struct preserves the
 * data wallets need for scanning: public key, commitment, unlock time,
 * and the block height that confirmed the output.
 */
struct output_pruning_metadata_t
{
  crypto::public_key pubkey;       //!< output one-time public key
  ct::key           commitment;   //!< Pedersen commitment (amount commitment)
  uint64_t           unlock_time;  //!< unlock time or height
  uint64_t           height;       //!< block height containing this output
  uint8_t            pruned;       //!< 1 if the parent tx's prunable data was removed
  uint8_t            padding[7];   //!< alignment to 8-byte boundary
};
#pragma pack(pop)

/**
 * @brief a struct containing txpool per transaction metadata
 */
struct txpool_tx_meta_t
{
  crypto::hash max_used_block_id;
  crypto::hash last_failed_id;
  uint64_t weight;
  uint64_t fee;
  uint64_t max_used_block_height;
  uint64_t last_failed_height;
  uint64_t receive_time;
  uint64_t last_relayed_time; //!< If Dandelion++ stem, randomized embargo time. Otherwise, last relayed timestamp.
  // 112 bytes
  uint8_t kept_by_block;
  uint8_t relayed;
  uint8_t do_not_relay;
  uint8_t double_spend_seen: 1;
  uint8_t pruned: 1;
  uint8_t is_local: 1;
  uint8_t dandelionpp_stem : 1;
  /*! This transaction has been seen arriving from somewhere OTHER than the
      peer it was stemmed to — F-10's predicate, resolved.

      Named for the fact rather than for what the pool does with it. The fact
      is "observed circulating"; disarming the origin's re-broadcast is one
      consumer's response to it (`get_relayable_transactions`' `local` arm),
      and a second consumer wanting the same fact should not have to read a
      field named after the first one's reaction.

      Set by `tx_memory_pool::on_stem_propagated`, from the Rust stem watch's
      verdict. NOT a timer and not a count: the watch refuses to resolve an
      arrival charged to the successor the observation was given to, so an
      echo from the peer that was handed the stem sets nothing (F-10, §49).

      ZERO IS "NOT OBSERVED", which is why this bit and not a new one. It held
      `is_forwarding` until Q12-U2 deleted `relay_method::forward`, then sat
      reserved — never read, written only as an explicit zero. So every record
      ever persisted carries zero here by construction, the layout does not
      move (`fcmp_verified` and `origin_zone` keep their positions), and the
      conservative reading is the one old records already give.

      Still zeroed by `set_relay_method`, and that stays CORRECT rather than
      being worked around: `upgrade_relay_method` only calls it when the
      method strictly increases, so a pinned `local` origin — the only class
      that uses the re-broadcast arm — keeps the bit for its whole life, while
      an entry that genuinely leaves `local` for `fluff`/`block` has left that
      arm and should not carry a disarm for it. */
  uint8_t observed_circulating: 1;
  uint8_t fcmp_verified: 1;  // set when fcmp_verification_hash is valid
  //! Zone this transaction ARRIVED over. See set_origin_zone/get_origin_zone.
  //
  // Q12-U1. Exactly two bits, because `invalid`/`public_`/`i2p`/`tor` is four
  // values -- the right width, not merely spare room. The record stays a fixed
  // 192 bytes, so nothing about the format grows and there is no version to
  // bump (rule 42 governs `rust/shekyl-engine-{state,file}/**`; this is
  // daemon-side C++ LMDB, re-verified at pre-flight rather than inherited).
  //
  // LIVE PRODUCTION INPUT since 2026-08-25, and the rule-15 deletion clause
  // below is therefore SPENT. `tx_pool.cpp`'s `local_relay_base` reads this
  // field on every relay pass to pick the parameter class for an origin's
  // re-broadcast interval (DAEMON_RELAY_PRIVACY.md §92.5c item 3): a value
  // change here changes when a transaction is re-emitted. Deleting the field
  // now silently reverts every origin to the clearnet wait.
  //
  // It reached that state having been telemetry with three scoped consumers,
  // none delivered: U1 pool-loop routing — deleted with
  // `relay_method::forward` (Q12-D3); U2 re-relay origin bucketing — retracted
  // (`2cd0fb72`, not a leak fix); U3 zone-labelled `/get_stem_tallies` —
  // collection zone, not this field. Fourth consumer, named 2026-08-13: the
  // Q12-D6a isolation arm (`Q12_D6A_PEER_DISCOVERY_RUN.md` §6) — distinguish
  // originated-on-anon from relayed-on-anon.
  //
  // The reading it acquired is narrow and worth stating so it is not widened
  // by accident: the retry timer asks only "anonymity class or clearnet
  // class?", and every entry that reaches it carries `invalid`, which resolves
  // to the anonymity class. It is not a routing decision and does not select a
  // peer.
  //
  // NO MIGRATION, and the reason is load-bearing: `zone::invalid == 0`, and a
  // record written before this field existed has these bits zero, so it
  // decodes to "origin unknown" -- already the correct sentinel.
  //
  // That is stronger than "the spare bits happen to be zero". The predecessor
  // `bf_padding` (now `observed_circulating`) was never READ anywhere at the
  // time, and its only writes were three
  // explicit `= 0` assignments in tx_pool.cpp, now replaced by the setter. So
  // every record ever persisted carries zero here by construction, and the
  // fallback is a fact about the data rather than a hope about it.
  uint8_t origin_zone: 2;

  // FCMP++ verification cache: hash(proof || tree_root || key_images).
  // When fcmp_verified == 1, the proof was previously verified against
  // the parameters encoded in this hash.  Re-verification can be skipped
  // if the recomputed hash matches.
  crypto::hash fcmp_verification_hash;

  uint8_t padding[44]; // till 192 bytes

  void set_relay_method(relay_method method) noexcept;
  relay_method get_relay_method() const noexcept;

  //! Record the zone this transaction ARRIVED over.
  //
  // Deliberately separate from `set_relay_method`. The relay method is a
  // routing DECISION and the origin zone is a FACT about where the bytes came
  // from; folding the fact into the decision is what made the zone
  // unrecoverable in the first place -- `relay_method::forward` meant "arrived
  // somewhere other than clearnet" and threw away which somewhere.
  //
  // The setter itself is last-write. First-arrival is `add_tx`'s rule: it
  // calls this only on a fresh insert, so a stem→fluff upgrade does not
  // revise the provenance.
  void set_origin_zone(epee::net_utils::zone zone) noexcept;

  //! The zone this transaction arrived over, or `zone::invalid` if unknown.
  //
  // `invalid` is returned for every record written before this field existed,
  // and for locally originated transactions, which did not arrive over
  // anything. Callers must treat it as "origin unknown" rather than as a
  // fourth transport. Nothing production-routes on this value. Named
  // consumer: Q12-D6a isolation arm (`Q12_D6A_PEER_DISCOVERY_RUN.md` §6).
  // The HF re-validation read is preservation, not that consumer.
  epee::net_utils::zone get_origin_zone() const noexcept;

  //! \return True if `get_relay_method()` now returns `method`.
  bool upgrade_relay_method(relay_method method) noexcept;

  //! See `relay_category` description
  bool matches(const relay_category category) const noexcept
  {
    return matches_category(get_relay_method(), category);
  }
};


#define DBF_SAFE       1
#define DBF_FAST       2
#define DBF_FASTEST    4
#define DBF_RDONLY     8
#define DBF_SALVAGE 0x10

/***********************************
 * Exception Definitions
 ***********************************/

/**
 * @brief A base class for BlockchainDB exceptions
 */
class DB_EXCEPTION : public std::exception
{
  private:
    std::string m;

  protected:
    DB_EXCEPTION(const char *s) : m(s) { }

  public:
    virtual ~DB_EXCEPTION() { }

    const char* what() const throw()
    {
      return m.c_str();
    }
};

/**
 * @brief A generic BlockchainDB exception
 */
class DB_ERROR : public DB_EXCEPTION
{
  public:
    DB_ERROR() : DB_EXCEPTION("Generic DB Error") { }
    DB_ERROR(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when there is an error starting a DB transaction
 */
class DB_ERROR_TXN_START : public DB_EXCEPTION
{
  public:
    DB_ERROR_TXN_START() : DB_EXCEPTION("DB Error in starting txn") { }
    DB_ERROR_TXN_START(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when opening the BlockchainDB fails
 */
class DB_OPEN_FAILURE : public DB_EXCEPTION
{
  public:
    DB_OPEN_FAILURE() : DB_EXCEPTION("Failed to open the db") { }
    DB_OPEN_FAILURE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when creating the BlockchainDB fails
 */
class DB_CREATE_FAILURE : public DB_EXCEPTION
{
  public:
    DB_CREATE_FAILURE() : DB_EXCEPTION("Failed to create the db") { }
    DB_CREATE_FAILURE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when synchronizing the BlockchainDB to disk fails
 */
class DB_SYNC_FAILURE : public DB_EXCEPTION
{
  public:
    DB_SYNC_FAILURE() : DB_EXCEPTION("Failed to sync the db") { }
    DB_SYNC_FAILURE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a requested block does not exist
 */
class BLOCK_DNE : public DB_EXCEPTION
{
  public:
    BLOCK_DNE() : DB_EXCEPTION("The block requested does not exist") { }
    BLOCK_DNE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a block's parent does not exist (and it needed to)
 */
class BLOCK_PARENT_DNE : public DB_EXCEPTION
{
  public:
    BLOCK_PARENT_DNE() : DB_EXCEPTION("The parent of the block does not exist") { }
    BLOCK_PARENT_DNE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a block exists, but shouldn't, namely when adding a block
 */
class BLOCK_EXISTS : public DB_EXCEPTION
{
  public:
    BLOCK_EXISTS() : DB_EXCEPTION("The block to be added already exists!") { }
    BLOCK_EXISTS(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when something is wrong with the block to be added
 */
class BLOCK_INVALID : public DB_EXCEPTION
{
  public:
    BLOCK_INVALID() : DB_EXCEPTION("The block to be added did not pass validation!") { }
    BLOCK_INVALID(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a requested transaction does not exist
 */
class TX_DNE : public DB_EXCEPTION
{
  public:
    TX_DNE() : DB_EXCEPTION("The transaction requested does not exist") { }
    TX_DNE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a transaction exists, but shouldn't, namely when adding a block
 */
class TX_EXISTS : public DB_EXCEPTION
{
  public:
    TX_EXISTS() : DB_EXCEPTION("The transaction to be added already exists!") { }
    TX_EXISTS(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a requested output does not exist
 */
class OUTPUT_DNE : public DB_EXCEPTION
{
  public:
    OUTPUT_DNE() : DB_EXCEPTION("The output requested does not exist!") { }
    OUTPUT_DNE(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when an output exists, but shouldn't, namely when adding a block
 */
class OUTPUT_EXISTS : public DB_EXCEPTION
{
  public:
    OUTPUT_EXISTS() : DB_EXCEPTION("The output to be added already exists!") { }
    OUTPUT_EXISTS(const char* s) : DB_EXCEPTION(s) { }
};

/**
 * @brief thrown when a spent key image exists, but shouldn't, namely when adding a block
 */
class KEY_IMAGE_EXISTS : public DB_EXCEPTION
{
  public:
    KEY_IMAGE_EXISTS() : DB_EXCEPTION("The spent key image to be added already exists!") { }
    KEY_IMAGE_EXISTS(const char* s) : DB_EXCEPTION(s) { }
};

/***********************************
 * End of Exception Definitions
 ***********************************/


/// The as-of-E consensus snapshot for one claimed settlement epoch, gathered
/// by `gather_archival_emission_epoch_snapshot` (M-2/Q7,
/// REWARD_EMISSION_E3_GATING_ROUND.md §3 item 2). Plain-value rows mirroring
/// the epoch-close gather shape; the consumer marshals them into the
/// `shekyl_archival_emission_epoch_snapshot` FFI struct (pointers into these
/// vectors) for `shekyl_emission_vin_verify` /
/// `shekyl_archival_emission_epoch_work`.
///
/// Deliberately carries no holdings descriptor (WS-1 §5): the held-and-served
/// set is the serve-credit rows themselves; tip holdings never enter the work
/// channel.
struct ArchivalEmissionEpochSnapshot
{
  uint64_t settlement_epoch = 0;
  /// The close-processing height (E+1)·SEB the close ran at (the shard-age
  /// operand). NOT H_close(E): that is `shekyl_archival_epoch_close_height(E)`
  /// = the epoch's last block / credit deadline = (E+1)·SEB − 1, one block
  /// lower. Source this from `shekyl_archival_epoch_close_processing_height`,
  /// never the lookalike `shekyl_archival_epoch_close_height`.
  uint64_t close_block_height = 0;
  /// Persisted finalized Σwork(E) milli (0 when the epoch closed empty or
  /// was M1-gated) — the stored denominator, never a recompute.
  uint64_t sigma_work_milli = 0;
  /// Frozen `budget(E)` (ARCHIVAL_BUDGET_SCHEDULE.md §3.3): the stored
  /// close-row value — budget and denominator freeze in the same close
  /// event; verify never re-sums the accrual rows. Meaningful only when
  /// `has_budget_row`.
  uint64_t budget_atomic = 0;
  /// Whether the frozen `archival_budget` row exists. Absent (never closed
  /// or pruned) is a gather failure → the verify shim rejects; a
  /// present-and-zero row is a closed zero-budget epoch, rejected
  /// downstream by wire positivity, not by the gather.
  bool has_budget_row = false;
  struct BondRow
  {
    uint64_t join_settlement_epoch = 0;
    bool is_foundation_complete_tree = false;
    /// Flattened (start_epoch, end_exclusive) pairs.
    std::vector<uint64_t> bad_intervals_flat;
  };
  struct ShardRow
  {
    uint64_t shard_id = 0;
    uint64_t freeze_height = 0;
    bool has_segment = false;
  };
  struct CreditPair
  {
    size_t bond_idx = 0;
    size_t shard_idx = 0;
  };
  std::vector<BondRow> bonds;
  std::vector<ShardRow> shards;
  std::vector<CreditPair> credit_pairs;
  /// Claimant P's index into `bonds`; SIZE_MAX when P has no serve-credit
  /// row in E (its work is then zero by construction).
  size_t claimant_bond_idx = SIZE_MAX;

  // Marshal the plain-value rows into the epoch-close FFI arrays. Single
  // source for the struct→FFI field mapping so the close path
  // (`process_archival_epoch_close_at_height`), the emission-verify shim, and
  // the KATs cannot drift on it (WS-1 §5.5 single sourcing — the row *gather*
  // is single-sourced in `gather_archival_epoch_rows`, this is the marshaling
  // half). The returned vectors' `bad_intervals_ptr`s alias this snapshot's
  // `BondRow::bad_intervals_flat`, so the snapshot must outlive them.
  std::vector<shekyl_archival_epoch_close_bond> to_ffi_bonds() const;
  std::vector<shekyl_archival_epoch_close_shard> to_ffi_shards() const;
  std::vector<shekyl_archival_credit_pair> to_ffi_credit_pairs() const;
};

/**
 * @brief The BlockchainDB backing store interface declaration/contract
 *
 * This class provides a uniform interface for using BlockchainDB to store
 * a blockchain.  Any implementation of this class will also implement all
 * functions exposed here, so one can use this class without knowing what
 * implementation is being used.  Refer to each pure virtual function's
 * documentation here when implementing a BlockchainDB subclass.
 *
 * A subclass which encounters an issue should report that issue by throwing
 * a DB_EXCEPTION which adequately conveys the issue.
 */
class BlockchainDB
{
private:
  /*********************************************************************
   * private virtual members
   *********************************************************************/

  /**
   * @brief add the block and metadata to the db
   *
   * The subclass implementing this will add the specified block and
   * block metadata to its backing store.  This does not include its
   * transactions, those are added in a separate step.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param blk the block to be added
   * @param block_weight the weight of the block (transactions and all)
   * @param long_term_block_weight the long term block weight of the block (transactions and all)
   * @param cumulative_difficulty the accumulated difficulty after this block
   * @param coins_generated the number of coins generated total after this block
   * @param blk_hash the hash of the block
   */
  virtual void add_block( const block& blk
                , size_t block_weight
                , uint64_t long_term_block_weight
                , const difficulty_type& cumulative_difficulty
                , const uint64_t& coins_generated
                , uint64_t num_rct_outs
                , const crypto::hash& blk_hash
                ) = 0;

  /**
   * @brief remove data about the top block
   *
   * The subclass implementing this will remove the block data from the top
   * block in the chain.  The data to be removed is that which was added in
   * BlockchainDB::add_block(const block& blk, size_t block_weight, uint64_t long_term_block_weight, const difficulty_type& cumulative_difficulty, const uint64_t& coins_generated, const crypto::hash& blk_hash)
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void remove_block() = 0;

  /**
   * @brief store the transaction and its metadata
   *
   * The subclass implementing this will add the specified transaction data
   * to its backing store.  This includes only the transaction blob itself
   * and the other data passed here, not the separate outputs of the
   * transaction.
   *
   * It returns a tx ID, which is a mapping from the tx_hash. The tx ID
   * is used in #add_tx_amount_output_indices().
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param blk_hash the hash of the block containing the transaction
   * @param tx the transaction to be added
   * @param tx_hash the hash of the transaction
   * @param tx_prunable_hash the hash of the prunable part of the transaction
   * @return the transaction ID
   */
  virtual uint64_t add_transaction_data(const crypto::hash& blk_hash, const std::pair<transaction, blobdata_ref>& tx, const crypto::hash& tx_hash, const crypto::hash& tx_prunable_hash) = 0;

  /**
   * @brief remove data about a transaction
   *
   * The subclass implementing this will remove the transaction data 
   * for the passed transaction.  The data to be removed was added in
   * add_transaction_data().  Additionally, current subclasses have behavior
   * which requires the transaction itself as a parameter here.  Future
   * implementations should note that this parameter is subject to be removed
   * at a later time.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param tx_hash the hash of the transaction to be removed
   * @param tx the transaction
   */
  virtual void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx) = 0;

  /**
   * @brief store an output
   *
   * The subclass implementing this will add the output data passed to its
   * backing store in a suitable manner.  In addition, the subclass is responsible
   * for keeping track of the global output count in some manner, so that
   * outputs may be indexed by the order in which they were created.  In the
   * future, this tracking (of the number, at least) should be moved to
   * this class, as it is necessary and the same among all BlockchainDB.
   *
   * It returns an amount output index, which is the index of the output
   * for its specified amount.
   *
   * This data should be stored in such a manner that the only thing needed to
   * reverse the process is the tx_out.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param tx_hash hash of the transaction the output was created by
   * @param tx_output the output
   * @param local_index index of the output in its transaction
   * @param unlock_time unlock time/height of the output
   * @param commitment the rct commitment to the output amount
   * @return amount output index
   */
  virtual uint64_t add_output(const crypto::hash& tx_hash, const tx_out& tx_output, const uint64_t& local_index, const uint64_t unlock_time, const ct::key *commitment) = 0;

  /**
   * @brief store amount output indices for a tx's outputs
   *
   * The subclass implementing this will add the amount output indices to its
   * backing store in a suitable manner. The tx_id will be the same one that
   * was returned from #add_output().
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param tx_id ID of the transaction containing these outputs
   * @param amount_output_indices the amount output indices of the transaction
   */
  virtual void add_tx_amount_output_indices(const uint64_t tx_id, const std::vector<uint64_t>& amount_output_indices) = 0;

  /**
   * @brief store a spent key
   *
   * The subclass implementing this will store the spent key image.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param k_image the spent key image to store
   */
  virtual void add_spent_key(const crypto::key_image& k_image) = 0;

  /**
   * @brief remove a spent key
   *
   * The subclass implementing this will remove the key image.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param k_image the spent key image to remove
   */
  virtual void remove_spent_key(const crypto::key_image& k_image) = 0;


  /*********************************************************************
   * private concrete members
   *********************************************************************/
  /**
   * @brief private version of pop_block, for undoing if an add_block fails
   *
   * This function simply calls pop_block(block& blk, std::vector<transaction>& txs)
   * with dummy parameters, as the returns-by-reference can be discarded.
   */
  void pop_block();

  // helper function to remove transaction from blockchain
  /**
   * @brief helper function to remove transaction from the blockchain
   *
   * This function encapsulates aspects of removing a transaction.
   *
   * @param tx_hash the hash of the transaction to be removed
   */
  // `block_height` is the height of the block being popped — supplied by
  // `pop_block`, never recomputed here. The vin does not carry the block
  // (PC-D2 makes it implicit), so this function CANNOT rebuild the widened
  // serve-credit key on its own, and reading ambient chain state would be the
  // invariant-held-by-circumstance shape §3.4.2 refuses.
  void remove_transaction(const crypto::hash& tx_hash, uint64_t block_height);

  uint64_t num_calls = 0;  //!< a performance metric
  uint64_t time_blk_hash = 0;  //!< a performance metric
  uint64_t time_add_block1 = 0;  //!< a performance metric
  uint64_t time_add_transaction = 0;  //!< a performance metric


protected:

  /**
   * @brief helper function for add_transactions, to add each individual transaction
   *
   * This function is called by add_transactions() for each transaction to be
   * added.
   *
   * @param blk_hash hash of the block which has the transaction
   * @param tx the transaction to add
   * @param tx_hash_ptr the hash of the transaction, if already calculated
   * @param tx_prunable_hash_ptr the hash of the prunable part of the transaction, if already calculated
   */
  // `block_height` is the height of the block this tx is being added in
  // (PC-D4): the serve-credit ledger key carries it, so the add path must be
  // TOLD the height rather than infer it. `remove_transaction` takes the same
  // value from `pop_block`, which is what makes the pop delete the key the add
  // wrote (ARCHIVAL_PER_CHALLENGE_RECORD.md §3.4.2).
  void add_transaction(const crypto::hash& blk_hash, const std::pair<transaction, blobdata_ref>& tx, uint64_t block_height, const crypto::hash* tx_hash_ptr = NULL, const crypto::hash* tx_prunable_hash_ptr = NULL);

  mutable uint64_t time_tx_exists = 0;  //!< a performance metric
  uint64_t time_commit1 = 0;  //!< a performance metric
  bool m_auto_remove_logs = true;  //!< whether or not to automatically remove old logs

  HardFork* m_hardfork;

public:

  /**
   * @brief An empty constructor.
   */
  BlockchainDB(): m_hardfork(NULL), m_open(false) { }

  /**
   * @brief An empty destructor.
   */
  virtual ~BlockchainDB() { };

  /**
   * @brief init command line options
   */
  static void init_options(boost::program_options::options_description& desc);

  /**
   * @brief reset profiling stats
   */
  void reset_stats();

  /**
   * @brief show profiling stats
   *
   * This function prints current performance/profiling data to whichever
   * log file(s) are set up (possibly including stdout or stderr)
   */
  void show_stats();

  /**
   * @brief open a db, or create it if necessary.
   *
   * This function opens an existing database or creates it if it
   * does not exist.
   *
   * The subclass implementing this will handle all file opening/creation,
   * and is responsible for maintaining its state.
   *
   * The parameter <filename> may not refer to a file name, necessarily, but
   * could be an IP:PORT for a database which needs it, and so on.  Calling it
   * <filename> is convenient and should be descriptive enough, however.
   *
   * For now, db_flags are
   * specific to the subclass being instantiated.  This is subject to change,
   * and the db_flags parameter may be deprecated.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param filename a string referring to the BlockchainDB to open
   * @param db_flags flags relevant to how to open/use the BlockchainDB
   */
  virtual void open(const std::string& filename, const int db_flags = 0) = 0;

  /**
   * @brief Gets the current open/ready state of the BlockchainDB
   *
   * @return true if open/ready, otherwise false
   */
  bool is_open() const;

  /**
   * @brief close the BlockchainDB
   *
   * At minimum, this call ensures that further use of the BlockchainDB
   * instance will not have effect.  In any case where it is necessary
   * to do so, a subclass implementing this will sync with disk.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void close() = 0;

  /**
   * @brief sync the BlockchainDB with disk
   *
   * This function should write any changes to whatever permanent backing
   * store the subclass uses.  Example: a BlockchainDB instance which
   * keeps the whole blockchain in RAM won't need to regularly access a
   * disk, but should write out its state when this is called.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void sync() = 0;

  /**
   * @brief toggle safe syncs for the DB
   *
   * Used to switch DBF_SAFE on or off after starting up with DBF_FAST.
   */
  virtual void safesyncmode(const bool onoff) = 0;

  /**
   * @brief Remove everything from the BlockchainDB
   *
   * This function should completely remove all data from a BlockchainDB.
   *
   * Use with caution!
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void reset() = 0;

  /**
   * @brief get all files used by the BlockchainDB (if any)
   *
   * This function is largely for ease of automation, namely for unit tests.
   *
   * The subclass implementation should return all filenames it uses.
   *
   * @return a list of filenames
   */
  virtual std::vector<std::string> get_filenames() const = 0;

  /**
   * @brief remove file(s) storing the database
   *
   * This function is for resetting the database (for core tests, functional tests, etc).
   * The function reset() is not usable because it needs to open the database file first
   * which can fail if the existing database file is in an incompatible format.
   * As such, this function needs to be called before calling open().
   *
   * @param folder    The path of the folder containing the database file(s) which must not end with slash '/'.
   *
   * @return          true if the operation is succesfull
   */
  virtual bool remove_data_file(const std::string& folder) const = 0;

  // return the name of the folder the db's file(s) should reside in
  /**
   * @brief gets the name of the folder the BlockchainDB's file(s) should be in
   *
   * The subclass implementation should return the name of the folder in which
   * it stores files, or an empty string if there is none.
   *
   * @return the name of the folder with the BlockchainDB's files, if any.
   */
  virtual std::string get_db_name() const = 0;


  // Unused stubs — all synchronization is done at the Blockchain level via
  // m_blockchain_lock.  Retained for interface compatibility; no callers exist.
  virtual bool lock() = 0;

  /**
   * @brief This function releases the BlockchainDB lock
   *
   * The subclass, should it have implemented lock(), will release any lock
   * held by the calling thread.  In the case of recursive locking, it should
   * release one instance of a lock.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void unlock() = 0;

  /**
   * @brief tells the BlockchainDB to start a new "batch" of blocks
   *
   * If the subclass implements a batching method of caching blocks in RAM to
   * be added to a backing store in groups, it should start a batch which will
   * end either when <batch_num_blocks> has been added or batch_stop() has
   * been called.  In either case, it should end the batch and write to its
   * backing store.
   *
   * If a batch is already in-progress, this function must return false.
   * If a batch was started by this call, it must return true.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param batch_num_blocks number of blocks to batch together
   *
   * @return true if we started the batch, false if already started
   */
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) = 0;

  /**
   * @brief ends a batch transaction
   *
   * If the subclass implements batching, this function should store the
   * batch it is currently on and mark it finished.
   *
   * If no batch is in-progress, this function should throw a DB_ERROR.
   * This exception may change in the future if it is deemed necessary to
   * have a more granular exception type for this scenario.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void batch_stop() = 0;

  /**
   * @brief aborts a batch transaction
   *
   * If the subclass implements batching, this function should abort the
   * batch it is currently on.
   *
   * If no batch is in-progress, this function should throw a DB_ERROR.
   * This exception may change in the future if it is deemed necessary to
   * have a more granular exception type for this scenario.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   */
  virtual void batch_abort() = 0;

  /**
   * @brief sets whether or not to batch transactions
   *
   * If the subclass implements batching, this function tells it to begin
   * batching automatically.
   *
   * If the subclass implements batching and has a batch in-progress, a
   * parameter of false should disable batching and call batch_stop() to
   * store the current batch.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param bool batch whether or not to use batch transactions.
   */
  virtual void set_batch_transactions(bool) = 0;

  virtual void block_wtxn_start() = 0;
  virtual void block_wtxn_stop() = 0;
  virtual void block_wtxn_abort() = 0;
  virtual bool block_rtxn_start() const = 0;
  virtual void block_rtxn_stop() const = 0;
  virtual void block_rtxn_abort() const = 0;

  virtual void set_hard_fork(HardFork* hf);

  // adds a block with the given metadata to the top of the blockchain, returns the new height
  /**
   * @brief handles the addition of a new block to BlockchainDB
   *
   * This function organizes block addition and calls various functions as
   * necessary.
   *
   * NOTE: subclass implementations of this (or the functions it calls) need
   * to handle undoing any partially-added blocks in the event of a failure.
   *
   * If any of this cannot be done, the subclass should throw the corresponding
   * subclass of DB_EXCEPTION
   *
   * @param blk the block to be added
   * @param block_weight the size of the block (transactions and all)
   * @param long_term_block_weight the long term weight of the block (transactions and all)
   * @param cumulative_difficulty the accumulated difficulty after this block
   * @param coins_generated the number of coins generated total after this block
   * @param archival_budget_accrual the block's staker inflow
   *   (ARCHIVAL_BUDGET_SCHEDULE.md §3.1); 0 when the inflow is zero (genesis,
   *   or fully decayed). Computed by the caller BEFORE add_block so the
   *   hardfork operand is the connecting block's own validated version, and
   *   written here (keyed at the block's index) before the epoch-close hook
   *   fires, so the close of an epoch sees its final block's row
   *   (F-B1a/F-B1b).
   * @param attestation_witness the block's prunable credit-wire admission
   *   witness (`r` + per-pass HybridSignatures; ARCHIVAL_CREDIT_WIRE.md
   *   §3.2/§4, transport B2). Opaque bytes here, decoded/verified in Rust behind
   *   the FFI. Stored in the height-keyed m_archival_attestation_witness side
   *   table in this same write txn (keyed to mirror the curve-tree root) and
   *   pruned after horizon. Empty until the cutover packs pass records (interim
   *   blocks carry the empty attestation set); an empty witness writes no row —
   *   absent key reads as "no witness", the skip-when-empty convention the
   *   accrual row above uses.
   * @param txs the transactions in the block
   *
   * @return the height of the chain post-addition
   */
  virtual uint64_t add_block( const std::pair<block, blobdata>& blk
                            , size_t block_weight
                            , uint64_t long_term_block_weight
                            , const difficulty_type& cumulative_difficulty
                            , const uint64_t& coins_generated
                            , uint64_t archival_budget_accrual
                            , const blobdata& attestation_witness
                            , const std::vector<std::pair<transaction, blobdata>>& txs
                            );

  /**
   * @brief checks if a block exists
   *
   * @param h the hash of the requested block
   * @param height if non NULL, returns the block's height if found
   *
   * @return true of the block exists, otherwise false
   */
  virtual bool block_exists(const crypto::hash& h, uint64_t *height = NULL) const = 0;

  /**
   * @brief fetches the block with the given hash
   *
   * The subclass should return the requested block.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param h the hash to look for
   *
   * @return the block requested
   */
  virtual cryptonote::blobdata get_block_blob(const crypto::hash& h) const = 0;

  /**
   * @brief fetches the block with the given hash
   *
   * Returns the requested block.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param h the hash to look for
   *
   * @return the block requested
   */
  virtual block get_block(const crypto::hash& h) const;

  /**
   * @brief gets the height of the block with a given hash
   *
   * The subclass should return the requested height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param h the hash to look for
   *
   * @return the height
   */
  virtual uint64_t get_block_height(const crypto::hash& h) const = 0;

  /**
   * @brief fetch a block header
   *
   * The subclass should return the block header from the block with
   * the given hash.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param h the hash to look for
   *
   * @return the block header
   */
  virtual block_header get_block_header(const crypto::hash& h) const = 0;

  /**
   * @brief fetch a block blob by height
   *
   * The subclass should return the block at the given height.
   *
   * If the block does not exist, that is to say if the blockchain is not
   * that high, then the subclass should throw BLOCK_DNE
   *
   * @param height the height to look for
   *
   * @return the block blob
   */
  virtual cryptonote::blobdata get_block_blob_from_height(const uint64_t& height) const = 0;

  /**
   * @brief fetch a block by height
   *
   * If the block does not exist, that is to say if the blockchain is not
   * that high, then the subclass should throw BLOCK_DNE
   *
   * @param height the height to look for
   *
   * @return the block
   */
  virtual block get_block_from_height(const uint64_t& height) const;

  /**
   * @brief fetch a block's timestamp
   *
   * The subclass should return the timestamp of the block with the
   * given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the timestamp
   */
  virtual uint64_t get_block_timestamp(const uint64_t& height) const = 0;

  /**
   * @brief fetch a block's cumulative number of rct outputs
   *
   * The subclass should return the numer of rct outputs in the blockchain
   * up to the block with the given height (inclusive).
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the cumulative number of rct outputs
   */
  virtual std::vector<uint64_t> get_block_cumulative_rct_outputs(const std::vector<uint64_t> &heights) const = 0;

  /**
   * @brief fetch the top block's timestamp
   *
   * The subclass should return the timestamp of the most recent block.
   *
   * @return the top block's timestamp
   */
  virtual uint64_t get_top_block_timestamp() const = 0;

  /**
   * @brief fetch a block's weight
   *
   * The subclass should return the weight of the block with the
   * given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the weight
   */
  virtual size_t get_block_weight(const uint64_t& height) const = 0;

  /**
   * @brief fetch the last N blocks' weights
   *
   * If there are fewer than N blocks, the returned array will be smaller than N
   *
   * @param count the number of blocks requested
   *
   * @return the weights
   */
  virtual std::vector<uint64_t> get_block_weights(uint64_t start_height, size_t count) const = 0;

  /**
   * @brief fetch a block's cumulative difficulty
   *
   * The subclass should return the cumulative difficulty of the block with the
   * given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the cumulative difficulty
   */
  virtual difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const = 0;

  /**
   * @brief fetch a block's difficulty
   *
   * The subclass should return the difficulty of the block with the
   * given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the difficulty
   */
  virtual difficulty_type get_block_difficulty(const uint64_t& height) const = 0;

  /**
   * @brief correct blocks cumulative difficulties that were incorrectly calculated due to the 'difficulty drift' bug
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param start_height the height where the drift starts
   * @param new_cumulative_difficulties new cumulative difficulties to be stored
   */
  virtual void correct_block_cumulative_difficulties(const uint64_t& start_height, const std::vector<difficulty_type>& new_cumulative_difficulties) = 0;

  /**
   * @brief fetch a block's already generated coins
   *
   * The subclass should return the total coins generated as of the block
   * with the given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the already generated coins
   */
  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const = 0;

  /**
   * @brief fetch a block's long term weight
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the long term weight
   */
  virtual uint64_t get_block_long_term_weight(const uint64_t& height) const = 0;

  /**
   * @brief fetch the last N blocks' long term weights
   *
   * If there are fewer than N blocks, the returned array will be smaller than N
   *
   * @param count the number of blocks requested
   *
   * @return the weights
   */
  virtual std::vector<uint64_t> get_long_term_block_weights(uint64_t start_height, size_t count) const = 0;

  /**
   * @brief fetch a block's hash
   *
   * The subclass should return hash of the block with the
   * given height.
   *
   * If the block does not exist, the subclass should throw BLOCK_DNE
   *
   * @param height the height requested
   *
   * @return the hash
   */
  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const = 0;

  /**
   * @brief fetch a list of blocks
   *
   * The subclass should return a vector of blocks with heights starting at
   * h1 and ending at h2, inclusively.
   *
   * If the height range requested goes past the end of the blockchain,
   * the subclass should throw BLOCK_DNE.  (current implementations simply
   * don't catch this exception as thrown by methods called within)
   *
   * @param h1 the start height
   * @param h2 the end height
   *
   * @return a vector of blocks
   */
  virtual std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const = 0;

  /**
   * @brief fetch a list of block hashes
   *
   * The subclass should return a vector of block hashes from blocks with
   * heights starting at h1 and ending at h2, inclusively.
   *
   * If the height range requested goes past the end of the blockchain,
   * the subclass should throw BLOCK_DNE.  (current implementations simply
   * don't catch this exception as thrown by methods called within)
   *
   * @param h1 the start height
   * @param h2 the end height
   *
   * @return a vector of block hashes
   */
  virtual std::vector<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const = 0;

  /**
   * @brief fetch the top block's hash
   *
   * The subclass should return the hash of the most recent block
   *
   * @param block_height if non NULL, returns the height of that block (ie, the blockchain height minus 1)
   *
   * @return the top block's hash
   */
  virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const = 0;

  /**
   * @brief fetch the top block
   *
   * The subclass should return most recent block
   *
   * @return the top block
   */
  virtual block get_top_block() const = 0;

  /**
   * @brief fetch the current blockchain height
   *
   * The subclass should return the current blockchain height
   *
   * @return the current blockchain height
   */
  virtual uint64_t height() const = 0;


  /**
   * <!--
   * TODO: Rewrite (if necessary) such that all calls to remove_* are
   *       done in concrete members of this base class.
   * -->
   *
   * @brief pops the top block off the blockchain
   *
   * The subclass should remove the most recent block from the blockchain,
   * along with all transactions, outputs, and other metadata created as
   * a result of its addition to the blockchain.  Most of this is handled
   * by the concrete members of the base class provided the subclass correctly
   * implements remove_* functions.
   *
   * The subclass should return by reference the popped block and
   * its associated transactions
   *
   * @param blk return-by-reference the block which was popped
   * @param txs return-by-reference the transactions from the popped block
   */
  virtual void pop_block(block& blk, std::vector<transaction>& txs);


  /**
   * @brief check if a transaction with a given hash exists
   *
   * The subclass should check if a transaction is stored which has the
   * given hash and return true if so, false otherwise.
   *
   * @param h the hash to check against
   * @param tx_id (optional) returns the tx_id for the tx hash
   *
   * @return true if the transaction exists, otherwise false
   */
  virtual bool tx_exists(const crypto::hash& h) const = 0;
  virtual bool tx_exists(const crypto::hash& h, uint64_t& tx_id) const = 0;

  // return unlock time of tx with hash <h>
  /**
   * @brief fetch a transaction's unlock time/height
   *
   * The subclass should return the stored unlock time for the transaction
   * with the given hash.
   *
   * If no such transaction exists, the subclass should throw TX_DNE.
   *
   * @param h the hash of the requested transaction
   *
   * @return the unlock time/height
   */
  virtual uint64_t get_tx_unlock_time(const crypto::hash& h) const = 0;

  // return tx with hash <h>
  // throw if no such tx exists
  /**
   * @brief fetches the transaction with the given hash
   *
   * If the transaction does not exist, the subclass should throw TX_DNE.
   *
   * @param h the hash to look for
   *
   * @return the transaction with the given hash
   */
  virtual transaction get_tx(const crypto::hash& h) const;

  /**
   * @brief fetches the transaction base with the given hash
   *
   * If the transaction does not exist, the subclass should throw TX_DNE.
   *
   * @param h the hash to look for
   *
   * @return the transaction with the given hash
   */
  virtual transaction get_pruned_tx(const crypto::hash& h) const;

  /**
   * @brief fetches the transaction with the given hash
   *
   * If the transaction does not exist, the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transaction was found
   */
  virtual bool get_tx(const crypto::hash& h, transaction &tx) const;

  /**
   * @brief fetches the transaction base with the given hash
   *
   * If the transaction does not exist, the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transaction was found
   */
  virtual bool get_pruned_tx(const crypto::hash& h, transaction &tx) const;

  /**
   * @brief fetches the transaction blob with the given hash
   *
   * The subclass should return the transaction stored which has the given
   * hash.
   *
   * If the transaction does not exist, the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transaction was found
   */
  virtual bool get_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const = 0;

  /**
   * @brief fetches the pruned transaction blob with the given hash
   *
   * The subclass should return the pruned transaction stored which has the given
   * hash.
   *
   * If the transaction does not exist, the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transaction was found
   */
  virtual bool get_pruned_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const = 0;

  /**
   * @brief fetches a number of pruned transaction blob from the given hash, in canonical blockchain order
   *
   * The subclass should return the pruned transactions stored from the one with the given
   * hash.
   *
   * If the first transaction does not exist, the subclass should return false.
   * If the first transaction exists, but there are fewer transactions starting with it
   * than requested, the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transactions were found
   */
  virtual bool get_pruned_tx_blobs_from(const crypto::hash& h, size_t count, std::vector<cryptonote::blobdata> &bd) const = 0;

  /**
   * @brief fetches a variable number of blocks and transactions from the given height, in canonical blockchain order
   *
   * The subclass should return the blocks and transactions stored from the one with the given
   * height. The number of blocks returned is variable, based on the max_size passed.
   *
   * @param start_height the height of the first block
   * @param min_block_count the minimum number of blocks to return, if they exist
   * @param max_block_count the maximum number of blocks to return
   * @param max_tx_count the maximum number of txes to return
   * @param max_size the maximum size of block/transaction data to return (will be exceeded by one blocks's worth at most, if min_count is met)
   * @param blocks the returned block/transaction data
   * @param pruned whether to return full or pruned tx data
   * @param skip_coinbase whether to return or skip coinbase transactions (they're in blocks regardless)
   * @param get_miner_tx_hash whether to calculate and return the miner (coinbase) tx hash
   *
   * The call will return at least min_block_count if possible, even if this contravenes max_tx_count
   *
   * @return true iff the blocks and transactions were found
   */
  virtual bool get_blocks_from(uint64_t start_height, size_t min_block_count, size_t max_block_count, size_t max_tx_count, size_t max_size, std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata>>>>& blocks, bool pruned, bool skip_coinbase, bool get_miner_tx_hash) const = 0;

  /**
   * @brief fetches the prunable transaction blob with the given hash
   *
   * The subclass should return the prunable transaction stored which has the given
   * hash.
   *
   * If the transaction does not exist, or if we do not have that prunable data,
   * the subclass should return false.
   *
   * @param h the hash to look for
   *
   * @return true iff the transaction was found and we have its prunable data
   */
  virtual bool get_prunable_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const = 0;

  /**
   * @brief fetches the prunable transaction hash
   *
   * The subclass should return the hash of the prunable transaction data.
   *
   * If the transaction hash does not exist, the subclass should return false.
   *
   * @param h the tx hash to look for
   *
   * @return true iff the transaction was found
   */
  virtual bool get_prunable_tx_hash(const crypto::hash& tx_hash, crypto::hash &prunable_hash) const = 0;

  /**
   * @brief fetches the total number of transactions ever
   *
   * The subclass should return a count of all the transactions from
   * all blocks.
   *
   * @return the number of transactions in the blockchain
   */
  virtual uint64_t get_tx_count() const = 0;

  /**
   * @brief fetches a list of transactions based on their hashes
   *
   * The subclass should attempt to fetch each transaction referred to by
   * the hashes passed.
   *
   * Currently, if any of the transactions is not in BlockchainDB, the call
   * to get_tx in the implementation will throw TX_DNE.
   *
   * <!-- TODO: decide if this behavior is correct for missing transactions -->
   *
   * @param hlist a list of hashes
   *
   * @return the list of transactions
   */
  virtual std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const = 0;

  // returns height of block that contains transaction with hash <h>
  /**
   * @brief fetches the height of a transaction's block
   *
   * The subclass should attempt to return the height of the block containing
   * the transaction with the given hash.
   *
   * If the transaction cannot be found, the subclass should throw TX_DNE.
   *
   * @param h the hash of the transaction
   *
   * @return the height of the transaction's block
   */
  virtual uint64_t get_tx_block_height(const crypto::hash& h) const = 0;

  // returns the total number of outputs of amount <amount>
  /**
   * @brief fetches the number of outputs of a given amount
   *
   * The subclass should return a count of outputs of the given amount,
   * or zero if there are none.
   *
   * <!-- TODO: should outputs spent with a low mixin (especially 0) be
   * excluded from the count? -->
   *
   * @param amount the output amount being looked up
   *
   * @return the number of outputs of the given amount
   */
  virtual uint64_t get_num_outputs(const uint64_t& amount) const = 0;

  /**
   * @brief return index of the first element (should be hidden, but isn't)
   *
   * @return the index
   */
  virtual uint64_t get_indexing_base() const { return 0; }

  /**
   * @brief get some of an output's data
   *
   * The subclass should return the public key, unlock time, and block height
   * for the output with the given amount and index, collected in a struct.
   *
   * If the output cannot be found, the subclass should throw OUTPUT_DNE.
   *
   * If any of these parts cannot be found, but some are, the subclass
   * should throw DB_ERROR with a message stating as much.
   *
   * @param amount the output amount
   * @param index the output's index (indexed by amount)
   *
   * @return the requested output data
   */
  virtual output_data_t get_output_key(const uint64_t& amount, const uint64_t& index, bool include_commitmemt = true) const = 0;

  /**
   * @brief gets an output's tx hash and index
   *
   * The subclass should return the hash of the transaction which created the
   * output with the global index given, as well as its index in that transaction.
   *
   * @param index an output's global index
   *
   * @return the tx hash and output index
   */
  virtual tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const = 0;

  /**
   * @brief gets an output's tx hash and index
   *
   * The subclass should return the hash of the transaction which created the
   * output with the amount and index given, as well as its index in that
   * transaction.
   *
   * @param amount an output amount
   * @param index an output's amount-specific index
   *
   * @return the tx hash and output index
   */
  virtual tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const = 0;

  /**
   * @brief gets some outputs' tx hashes and indices
   *
   * This function is a mirror of
   * get_output_tx_and_index(const uint64_t& amount, const uint64_t& index),
   * but for a list of outputs rather than just one.
   *
   * @param amount an output amount
   * @param offsets a list of amount-specific output indices
   * @param indices return-by-reference a list of tx hashes and output indices (as pairs)
   */
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices) const = 0;

  /**
   * @brief gets outputs' data
   *
   * This function is a mirror of
   * get_output_data(const uint64_t& amount, const uint64_t& index)
   * but for a list of outputs rather than just one.
   *
   * @param amounts an output amount, or as many as offsets
   * @param offsets a list of amount-specific output indices
   * @param outputs return-by-reference a list of outputs' metadata
   */
  virtual void get_output_key(const epee::span<const uint64_t> &amounts, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, bool allow_partial = false) const = 0;
  
  /*
   * FIXME: Need to check with git blame and ask what this does to
   * document it
   */
  virtual bool can_thread_bulk_indices() const = 0;

  /**
   * @brief gets output indices (amount-specific) for a transaction's outputs
   *
   * The subclass should fetch the amount-specific output indices for each
   * output in the transaction with the given ID.
   *
   * If the transaction does not exist, the subclass should throw TX_DNE.
   *
   * If an output cannot be found, the subclass should throw OUTPUT_DNE.
   *
   * @param tx_id a transaction ID
   * @param n_txes how many txes to get data for, starting with tx_id
   *
   * @return a list of amount-specific output indices
   */
  virtual std::vector<std::vector<uint64_t>> get_tx_amount_output_indices(const uint64_t tx_id, size_t n_txes = 1) const = 0;

  /**
   * @brief check if a key image is stored as spent
   *
   * @param img the key image to check for
   *
   * @return true if the image is present, otherwise false
   */
  virtual bool has_key_image(const crypto::key_image& img) const = 0;

  /**
   * @brief check if key images are stored as spent
   *
   * @param img the key images to check for
   *
   * @return true at element `i` if the `img[i]` is present, otherwise false
   */
  virtual std::vector<bool> has_key_images(const epee::span<const crypto::key_image> img) const;

  /**
   * @brief add a txpool transaction
   *
   * @param details the details of the transaction to add
   */
  virtual void add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata_ref &blob, const txpool_tx_meta_t& details) = 0;

  /**
   * @brief update a txpool transaction's metadata
   *
   * @param txid the txid of the transaction to update
   * @param details the details of the transaction to update
   */
  virtual void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t& details) = 0;

  /**
   * @brief get the number of transactions in the txpool
   */
  virtual uint64_t get_txpool_tx_count(relay_category tx_category = relay_category::broadcasted) const = 0;

  /**
   * @brief check whether a txid is in the txpool and meets tx_category requirements
   */
  virtual bool txpool_has_tx(const crypto::hash &txid, relay_category tx_category) const = 0;

  /**
   * @brief remove a txpool transaction
   *
   * @param txid the transaction id of the transation to remove
   */
  virtual void remove_txpool_tx(const crypto::hash& txid) = 0;

  /**
   * @brief get a txpool transaction's metadata
   *
   * @param txid the transaction id of the transation to lookup
   * @param meta the metadata to return
   *
   * @return true if the tx meta was found, false otherwise
   */
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const = 0;

  /**
   * @brief get a txpool transaction's blob
   *
   * @param txid the transaction id of the transation to lookup
   * @param bd the blob to return
   * @param tx_category for filtering out hidden/private txes
   *
   * @return True iff `txid` is in the pool and meets `tx_category` requirements
   */
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd, relay_category tx_category) const = 0;

  /**
   * @brief get a txpool transaction's blob
   *
   * @param txid the transaction id of the transation to lookup
   *
   * @return the blob for that transaction
   */
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const = 0;

  /**
   * @brief Check if `tx_hash` relay status is in `category`.
   *
   * @param tx_hash hash of the transaction to lookup
   * @param category relay status category to test against
   *
   * @return True if `tx_hash` latest relay status is in `category`.
   */
  bool txpool_tx_matches_category(const crypto::hash& tx_hash, relay_category category);

  /**
   * @brief prune output data for the given amount
   *
   * @param amount the amount for which to prune data
   */
  virtual void prune_outputs(uint64_t amount) = 0;

  /**
   * @brief get the blockchain pruning seed
   * @return the blockchain pruning seed
   */
  virtual uint32_t get_blockchain_pruning_seed() const = 0;

  /**
   * @brief prunes the blockchain
   * @param pruning_seed the seed to use, 0 for default (highly recommended)
   * @return success iff true
   */
  virtual bool prune_blockchain(uint32_t pruning_seed = 0) = 0;

  /**
   * @brief prunes recent blockchain changes as needed, iff pruning is enabled
   * @return success iff true
   */
  virtual bool update_pruning() = 0;

  /**
   * @brief checks pruning was done correctly, iff enabled
   * @return success iff true
   */
  virtual bool check_pruning() = 0;

  // ─── Output Metadata Pruning ──────────────────────────────────────────────

  /**
   * @brief store per-output metadata for post-pruning wallet scanning.
   *
   * Called before discarding a transaction's prunable data. The metadata
   * preserves what wallets need (pubkey, commitment, height, unlock_time).
   *
   * @param global_output_index  the output's global index
   * @param meta                 the metadata to persist
   */
  virtual void store_output_metadata(uint64_t global_output_index,
                                     const output_pruning_metadata_t& meta) = 0;

  /**
   * @brief retrieve stored output metadata.
   *
   * @param global_output_index  the output's global index
   * @param meta                 return-by-reference metadata
   * @return true if metadata exists for this output
   */
  virtual bool get_output_metadata(uint64_t global_output_index,
                                   output_pruning_metadata_t& meta) const = 0;

  /**
   * @brief check whether an output's parent transaction has been pruned.
   *
   * @param global_output_index  the output's global index
   * @return true if prunable data has been removed for this output's tx
   */
  virtual bool is_output_pruned(uint64_t global_output_index) const = 0;

  /**
   * @brief prune confirmed transaction data beyond the reorg safety depth.
   *
   * For each transaction in blocks older than (tip - depth), stores output
   * metadata in the output_metadata table and removes prunable verification
   * data (and the optional `txs_pqc_auths` slice).
   *
   * @param depth  confirmation depth; use 0 for CRYPTONOTE_TX_PRUNE_DEPTH
   * @return true on success
   */
  virtual bool prune_tx_data(uint64_t depth = 0) = 0;

  /**
   * @brief last block height for which post-confirmation tx verification data was pruned (0 if none).
   */
  virtual uint64_t get_last_pruned_tx_data_height() const = 0;

  /**
   * @brief true if the tx still has prunable verification data in the db (Bulletproofs+/FCMP++/pseudoOuts).
   */
  virtual bool tx_has_verification_data(const crypto::hash& tx_hash) const = 0;

  /**
   * @brief add a new alternative block
   *
   * @param: blkid the block hash
   * @param: data: the metadata for the block
   * @param: blob: the block's blob
   */
  virtual void add_alt_block(const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref &blob) = 0;

  /**
   * @brief get an alternative block by hash
   *
   * @param: blkid the block hash
   * @param: data: the metadata for the block
   * @param: blob: the block's blob
   *
   * @return true if the block was found in the alternative blocks list, false otherwise
   */
  virtual bool get_alt_block(const crypto::hash &blkid, alt_block_data_t *data, cryptonote::blobdata *blob) = 0;

  /**
   * @brief remove an alternative block
   *
   * @param: blkid the block hash
   */
  virtual void remove_alt_block(const crypto::hash &blkid) = 0;

  /**
   * @brief get the number of alternative blocks stored
   */
  virtual uint64_t get_alt_block_count() = 0;

  /**
   * @brief drop all alternative blocks
   */
  virtual void drop_alt_blocks() = 0;

  /**
   * @brief runs a function over all txpool transactions
   *
   * The subclass should run the passed function for each txpool tx it has
   * stored, passing the tx id and metadata as its parameters.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * @param std::function fn the function to run
   *
   * @return false if the function returns false for any transaction, otherwise true
   */
  virtual bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)>, bool include_blob = false, relay_category category = relay_category::broadcasted) const = 0;

  /**
   * @brief runs a function over all key images stored
   *
   * The subclass should run the passed function for each key image it has
   * stored, passing the key image as its parameter.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * @param std::function fn the function to run
   *
   * @return false if the function returns false for any key image, otherwise true
   */
  virtual bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const = 0;

  /**
   * @brief runs a function over a range of blocks
   *
   * The subclass should run the passed function for each block in the
   * specified range, passing (block_height, block_hash, block) as its parameters.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * The subclass should throw DB_ERROR if any of the expected values are
   * not found.  Current implementations simply return false.
   *
   * @param h1 the start height
   * @param h2 the end height
   * @param std::function fn the function to run
   *
   * @return false if the function returns false for any block, otherwise true
   */
  virtual bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>) const = 0;

  /**
   * @brief runs a function over all transactions stored
   *
   * The subclass should run the passed function for each transaction it has
   * stored, passing (transaction_hash, transaction) as its parameters.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * The subclass should throw DB_ERROR if any of the expected values are
   * not found.  Current implementations simply return false.
   *
   * @param std::function fn the function to run
   * @param bool pruned whether to only get pruned tx data, or the whole
   *
   * @return false if the function returns false for any transaction, otherwise true
   */
  virtual bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>, bool pruned) const = 0;

  /**
   * @brief runs a function over all outputs stored
   *
   * The subclass should run the passed function for each output it has
   * stored, passing (amount, transaction_hash, tx_local_output_index)
   * as its parameters.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * The subclass should throw DB_ERROR if any of the expected values are
   * not found.  Current implementations simply return false.
   *
   * @param std::function f the function to run
   *
   * @return false if the function returns false for any output, otherwise true
   */
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const = 0;
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const = 0;

  /**
   * @brief runs a function over all alternative blocks stored
   *
   * The subclass should run the passed function for each alt block it has
   * stored, passing (blkid, data, blob) as its parameters.
   *
   * If any call to the function returns false, the subclass should return
   * false.  Otherwise, the subclass returns true.
   *
   * The subclass should throw DB_ERROR if any of the expected values are
   * not found.  Current implementations simply return false.
   *
   * @param std::function f the function to run
   *
   * @return false if the function returns false for any output, otherwise true
   */
  virtual bool for_all_alt_blocks(std::function<bool(const crypto::hash &blkid, const alt_block_data_t &data, const cryptonote::blobdata_ref *blob)> f, bool include_blob = false) const = 0;


  //
  // Hard fork related storage
  //

  /**
   * @brief sets which hardfork version a height is on
   *
   * @param height the height
   * @param version the version
   */
  virtual void set_hard_fork_version(uint64_t height, uint8_t version) = 0;

  /**
   * @brief checks which hardfork version a height is on
   *
   * @param height the height
   *
   * @return the version
   */
  virtual uint8_t get_hard_fork_version(uint64_t height) const = 0;

  /**
   * @brief verify hard fork info in database
   */
  virtual void check_hard_fork_info() = 0;

  /**
   * @brief delete hard fork info from database
   */
  virtual void drop_hard_fork_info() = 0;

  /**
   * @brief return a histogram of outputs on the blockchain
   *
   * @param amounts optional set of amounts to lookup
   * @param unlocked whether to restrict count to unlocked outputs
   * @param recent_cutoff timestamp to determine whether an output is recent
   * @param min_count return only amounts with at least that many instances
   *
   * @return a set of amount/instances
   */
  virtual std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const = 0;

  virtual bool get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, std::vector<uint64_t> &distribution, uint64_t &base) const = 0;

  /**
   * @brief is BlockchainDB in read-only mode?
   *
   * @return true if in read-only mode, otherwise false
   */
  virtual bool is_read_only() const = 0;

  /**
   * @brief get disk space requirements
   *
   * @return the size required
   */
  virtual uint64_t get_database_size() const = 0;

  // TODO: this should perhaps be (or call) a series of functions which
  // progressively update through version updates
  /**
   * @brief fix up anything that may be wrong due to past bugs
   */
  virtual void fixup();

  /**
   * @brief set whether or not to automatically remove logs
   *
   * This function is only relevant for one implementation (BlockchainBDB), but
   * is here to keep BlockchainDB users implementation-agnostic.
   *
   * @param auto_remove whether or not to auto-remove logs
   */
  void set_auto_remove_logs(bool auto_remove) { m_auto_remove_logs = auto_remove; }

  // Per-height destroyed-amount record (the adaptive fee burn's destroyed
  // share), so pop_block can roll `total_burned` back without recomputing
  // the block's burn.
  virtual void add_block_burn(uint64_t height, uint64_t amount) = 0;
  virtual uint64_t get_block_burn(uint64_t height) const = 0;
  virtual void remove_block_burn(uint64_t height) = 0;

  // Per-height staker-inflow accrual row (`archival_budget_accrual`,
  // ARCHIVAL_BUDGET_SCHEDULE.md §3.1). The amount is computed for every
  // non-genesis block since the pre-activation burn leg's deletion
  // (emission is a genesis fact; §2.2), but the row is persisted only
  // when the amount is nonzero — the burn-record idiom: absent height
  // reads as 0, pop removes the height row. The rows are summed once per
  // epoch into the frozen `archival_budget` close row and pruned with
  // the epoch family.
  virtual void add_archival_budget_accrual(uint64_t height, uint64_t amount) = 0;
  virtual uint64_t get_archival_budget_accrual(uint64_t height) const = 0;
  virtual void remove_archival_budget_accrual(uint64_t height) = 0;

  virtual void set_total_bonded_atomic(uint64_t balance) = 0;
  virtual uint64_t get_total_bonded_atomic() const = 0;

  virtual void set_total_burned(uint64_t amount) = 0;
  virtual uint64_t get_total_burned() const = 0;

  // Fakechain settlement-epoch schedule pin (Blockchain::init): the schedule
  // the datadir's epoch-derived rows (bond join epochs, serve-credit bits)
  // were written under. 0 = not pinned yet. The setter manages its own write
  // transaction — it runs at init, outside any block-add txn.
  virtual void set_settlement_epoch_blocks_pin(uint64_t blocks) = 0;
  virtual uint64_t get_settlement_epoch_blocks_pin() const = 0;


  // ─── Archival serve-credit ledger (gate-2 §3.1) ───────────────────────────

  // PC-D4: the ledger is per-CHALLENGE, keyed `(P, shard, E, block_height)`.
  // A pair-epoch now holds up to CHALLENGES_PER_PAIR_PER_EPOCH rows, one per
  // block that challenged it, and consensus counts passes by ENUMERATING them
  // — no field anywhere carries a tally (PC-D1/PC-D5).
  //
  // `block_height` is the height of the block the record rides in. It must be
  // passed by the caller on BOTH the add and the pop path, from the same
  // source, and never read from ambient chain state: a pop that recomputed the
  // height from `height()` would delete a key it never wrote
  // (ARCHIVAL_PER_CHALLENGE_RECORD.md §3.4.2).
  /// Exact per-challenge read: a row for this pair at THIS block.
  ///
  /// Admission stays pair-epoch-wide (`pass_count > 0`) while the live issuer
  /// is the one-challenge-per-pair-epoch beacon (`challenge_fire_height` /
  /// `challenge_leaf_index`). The assignment cutover (`assign_epoch` — Rust
  /// only, no FFI; ARCHIVAL_CHALLENGE_MECHANISM.md §9.5.1) makes this the
  /// uniqueness question. Named blocker, named caller: do not delete under
  /// rule 15. Tests that pass their own height are not coverage of a
  /// production caller that does not exist yet.
  virtual bool has_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch, uint64_t block_height) const = 0;
  virtual void set_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch, uint64_t block_height) = 0;
  virtual void remove_archival_serve_credit_bit(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch, uint64_t block_height) = 0;

  /// Rows recorded for `(P, shard, E)` — the PC-D5 enumeration over the
  /// pair-epoch prefix. Admission and the failure window collapse this to
  /// `> 0` while the beacon still issues one challenge; the settlement writer
  /// (SO-D7) and the assignment cutover's count bound consume the number.
  virtual uint32_t archival_serve_credit_pass_count(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t settlement_epoch) const = 0;

  // Gate-4 / shard-registry substrate (default: false until implemented).
  virtual bool get_archival_bond_hybrid_pubkey(const crypto::hash& p_id,
    std::vector<uint8_t>& out_pubkey) const;
  // Full-bond reader: returns the complete decoded record (including the v4
  // claimed-epoch set and first_paying_emission_height) so load-modify-store
  // callers and tests can observe every field, not just the scalar projections.
  virtual bool get_archival_bond_value(const crypto::hash& p_id,
    shekyl::db::ArchivalBondValue& out) const;
  virtual bool archival_bond_holds_shard(const crypto::hash& p_id, uint64_t shard_id,
    uint64_t at_height) const;
  virtual bool archival_bond_good_through(const crypto::hash& p_id,
    uint64_t settlement_epoch) const;
  virtual uint64_t archival_bond_join_epoch(const crypto::hash& p_id) const;
  virtual bool get_archival_shard_segment_at_height(uint64_t shard_id, uint64_t at_height,
    crypto::hash& out_rk, uint64_t& out_leaf_count) const;

  // Gate-4 bond-post / registry writers (substrate seeding until bond vin lands).
  // `bond_spend_pk` is the GF-1 debit authorizer the JoinMarket connect
  // commits (gate-4 §4.1) — deliberately no default: every caller states the
  // key, so the production connect can never silently commit a record whose
  // debits are unauthorized-forever. Test seeders pass {} when the record's
  // debit path is not under test.
  virtual void put_archival_bond_record(const crypto::hash& p_id,
    const std::vector<uint8_t>& hybrid_pubkey,
    const std::vector<uint8_t>& bond_spend_pk, uint64_t join_settlement_epoch,
    uint64_t bonded_total_atomic, uint8_t holdings_kind,
    const std::vector<uint64_t>& held_shard_ids,
    const std::vector<std::pair<uint64_t, uint64_t>>& bad_intervals = {});
  // Full-bond writer: serializes the entire record. Load-modify-store callers
  // (slash apply/revert) must write through this rather than
  // put_archival_bond_record, whose scalar-arg signature cannot carry the v4
  // claimed-epoch set / first_paying_emission_height and would silently wipe
  // them (REWARD_EMISSION_VIN_PLAN.md §1.5 F-S1 / F-E5).
  virtual void put_archival_bond_value(const crypto::hash& p_id,
    const shekyl::db::ArchivalBondValue& bond);
  virtual void remove_archival_bond_record(const crypto::hash& p_id);
  virtual void put_archival_shard_segment(uint64_t shard_id, uint64_t freeze_height,
    const crypto::hash& segment_subroot_rk, uint64_t segment_leaf_count);

  // ─── Segment-freeze pipeline (ARCHIVAL_SEGMENT_FREEZE_PIPELINE.md §4) ─────
  //
  // The production writer/deleter for the shard-segment registry. Freezing
  // is a first-crossing rule over the consensus curve-tree leaf count
  // (frozen = floor(leaf_count / SEGMENT_LEAF_COUNT), computed ONLY by the
  // Rust entry point shekyl_archival_frozen_segment_count). Both hooks run
  // inside the block's write txn: the connect hook immediately after
  // grow_curve_tree, the pop hook after trim_curve_tree — partial commit on
  // either path is a consensus split (M1 §1.3 obligations O-1..O-3).

  /// Connect hook (§4.1): write a registry row for every level-2 subtree the
  /// same-txn grow completed, with `freeze_height = block_height` and `R_k`
  /// read from the layer-2 chunk the grow just wrote. No-op when no segment
  /// boundary was crossed.
  virtual void process_archival_segment_freezes_at_height(uint64_t block_height);
  /// Pop hook (§4.2): delete every registry row with
  /// `shard_id >= frozen_segment_count(post-trim leaf count)`. The delete
  /// rule is derived from the same function as the write rule, so re-applied
  /// blocks recreate rows bit-identically (O-3 pop-symmetry).
  virtual void revert_archival_segment_freezes();

  /// Gate-2 §6 / gate-4 §4.2: slash scheduler at `H_slash_deadline` (LMDB impl).
  virtual void process_archival_slash_at_height(uint64_t block_height);
  /// Revert slash journal rows recorded when `block_height` connected.
  virtual void revert_archival_slashes_at_height(uint64_t block_height);
  /// Emission-claim dedup writer (WS-2 §6.2, the connect-path single writer):
  /// records every epoch in `settlement_epochs` in `P`'s claimed set via the
  /// windowed `claimed_epochs_check_and_set` FFI, sets
  /// `first_paying_emission_height` if unset, and journals the pre-image for
  /// pop-revert. A dedup hit or an unclaimable epoch is a hard error, never a
  /// soft skip — verify's contains-check and the block-level `(P,E)` pass
  /// (C-1) foreclose both, so reaching either means a dedup layer was
  /// bypassed. Caller: the emission vin connect dispatch (C-1).
  virtual void apply_archival_emission_claim(uint64_t block_height, const crypto::hash& p_id,
    const std::vector<uint64_t>& settlement_epochs);
  /// Restore the pre-image journal rows recorded when `block_height`
  /// connected (§6.3: the naive remove-inverse leaves prune-evicted
  /// already-claimed epochs out of the restored set — the double-mint).
  virtual void revert_archival_emission_claims_at_height(uint64_t block_height);
  /// Unbond connect writer (gate-4 §4.3 "On confirm"; the Rust fold
  /// `shekyl_archival_unbond_connect` dictates the entire write set — record
  /// to the Exited shape, clean interval-close appended, counter debited):
  /// journals the record's full pre-image first (the emission WS-2 §6.3
  /// shape — the vin carries the POST-state, so holdings are otherwise
  /// unreconstructible at pop). Reads the LIVE `total_bonded_atomic`
  /// internally (per-post get→fold→set threading — a hoisted per-block read
  /// would clobber across multiple bond posts; §3.5 counter-threading
  /// obligation). Any fold error is a hard abort, never a soft skip.
  /// Caller: the bond-post vin connect dispatch (add_transaction).
  virtual void apply_archival_unbond(uint64_t block_height, const crypto::hash& p_id,
    uint64_t vin_bond_debit);
  /// Restore the Unbond pre-image journal rows recorded when `block_height`
  /// connected, re-crediting `total_bonded_atomic` via the Rust pop fold
  /// (which validates the tip record is the connect's product — Exited state
  /// + trailing clean close). Trailing-entry invariant (ratified 2026-07-12,
  /// §3.5): slashability ends at the Unbond connect — the slash scheduler
  /// only challenges currently held shards and an Exited record holds none —
  /// so nothing appends after the clean close and the trailing entry is
  /// always the connect's close. pop_block still runs the slash revert first
  /// as a defensive ordering belt; a violation surfaces in the fold as
  /// MISSING_CLEAN_CLOSE, loud.
  virtual void revert_archival_unbonds_at_height(uint64_t block_height);
  /// HoldingsUpdate-add connect writer (gate-4 §4.4; the Rust fold
  /// `shekyl_archival_holdings_update_add_connect` dictates the counter
  /// movement): sets `held_shard_ids = post` and rebuilds the index-parallel
  /// `shard_add_epochs` (carried shards keep their add-epoch; the one added
  /// shard takes `E_add = settlement_epoch(block_height)`). The record stays
  /// `Bonded` (ShardSetCompact) — no interval, no clean close (grace-tail
  /// posture). Journals the full pre-image of the mutated fields first, and
  /// reads the LIVE `total_bonded_atomic` internally (per-post threading, as
  /// Unbond). Any fold error is a hard abort. Caller: the bond-post vin
  /// connect dispatch (add_transaction).
  virtual void apply_archival_holdings_update_add(uint64_t block_height,
    const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids);
  /// HoldingsUpdate-drop connect writer (gate-4 §4.4 grace-tail): sets
  /// `held_shard_ids = post` and rebuilds `shard_add_epochs` (the dropped
  /// shard's add-epoch vanishes with it); the released FLOOR returns via the
  /// `bond_debit` CT-balance source term (no ledger write). Same journal +
  /// per-post counter threading as the add. Caller: add_transaction.
  virtual void apply_archival_holdings_update_drop(uint64_t block_height,
    const crypto::hash& p_id, const std::vector<uint64_t>& post_shard_ids);
  /// Restore the HoldingsUpdate pre-image journal rows recorded when
  /// `block_height` connected, reverting `total_bonded_atomic` via the Rust
  /// pop fold (which guards that the tip and pre-image balances differ by
  /// exactly one FLOOR — a single-shard change). The record stays Bonded
  /// throughout, so there is no Exited/clean-close check (the add/drop pop
  /// twin, gate-4 §5).
  virtual void revert_archival_holdings_updates_at_height(uint64_t block_height);
  /// Rebond connect writer (gate-4 §3.4; P2B-9 reinstatement; the Rust fold
  /// `shekyl_archival_rebond_connect` dictates the write set): sets
  /// `held_shard_ids = post` (a verified superset of current) and rebuilds the
  /// index-parallel `shard_add_epochs` (carried shards keep theirs; added
  /// shards take `E_rebond` — Pin 7), closes the open bad interval IN PLACE
  /// (`end_exclusive = E_rebond + 1` — Pin 3; the record stays `Bonded`,
  /// standing resumes at `E_rebond + 1`), and credits the counters by
  /// `|added|·FLOOR` (zero for standing-only). Journals the pre-image of the
  /// mutated fields (including the closed interval's index + start) first, and
  /// reads the LIVE `total_bonded_atomic` internally (per-post threading). Any
  /// fold error is a hard abort. Caller: the bond-post vin connect dispatch.
  virtual void apply_archival_rebond(uint64_t block_height, const crypto::hash& p_id,
    const std::vector<uint64_t>& post_shard_ids);
  /// Restore the Rebond pre-image journal rows recorded when `block_height`
  /// connected: re-open the journaled interval to `end_exclusive = MAX`
  /// (identity-belted against the journal's index + start and the connect's
  /// `E_rebond + 1` close), restore holdings/add-epochs/balance, and revert
  /// `total_bonded_atomic` via the Rust pop fold (non-negative whole-FLOOR
  /// delta guard — zero included).
  virtual void revert_archival_rebonds_at_height(uint64_t block_height);
  /// HoldingsUpdate-drop verify marshaling: the dropped shard's segment
  /// freeze height (feeds the retention-horizon age-at-add). Returns false
  /// when the shard has no frozen segment — a REACHABLE state, not
  /// corruption: the add verify deliberately does not require a frozen
  /// segment (bond_post.rs), so the caller fails closed by marshaling
  /// freeze_height 0 (the genesis-band "oldest" sentinel → the longest
  /// horizon); the Rust age computation pins a segment that froze at/after
  /// H_close(add_epoch) to the same longest-horizon extreme.
  virtual bool archival_shard_freeze_height(uint64_t shard_id, uint64_t& out) const;
  /// Unbond verify marshaling (P2B-8 Q1/Q2): each held shard's last-served
  /// settlement epoch — one reverse-cursor seek per shard over the BE
  /// composite serve-credit key `P_id ‖ BE64(shard) ‖ BE64(epoch) ‖
  /// BE64(block_height)` (PC-D4; the seek's ceiling probe takes MAX in the
  /// appended component too) — with
  /// never-served shards omitted (they carry no bit; the Rust fold treats an
  /// empty result as never-served ⇒ cooldown vacuously elapsed). The fold to
  /// the whole-record anchor and the cooldown verdict stay Rust-side
  /// (`whole_record_last_served` via the verify FFI).
  virtual std::vector<uint64_t> archival_bond_last_served_epochs(
    const crypto::hash& p_id, const std::vector<uint64_t>& shard_ids) const;
  /// The all-shards form of the last-served marshal, for records that store
  /// no shard list (CompleteTree holds every shard): a `P`-prefix hop scan
  /// over the serve-credit table yielding each *served* shard's last-served
  /// epoch — one reverse seek per served shard, never a full-table walk.
  /// Without this, a CompleteTree persona's cooldown anchor would fold from
  /// an empty list and the release gate would be vacuously open.
  virtual std::vector<uint64_t> archival_bond_all_last_served_epochs(
    const crypto::hash& p_id) const;
  /// The slash scheduler's monotone settled watermark
  /// (`archival_last_slash_epoch`): every settlement epoch `<=` the returned
  /// value has been scanned at its slash deadline. u64 max = no epoch settled
  /// yet (the storage sentinel). Marshaled into the Unbond release verify
  /// (SLASH_SETTLEMENT_PENDING gate).
  virtual uint64_t get_archival_last_slash_epoch() const;
  /// Finalize `R_market` / `Σwork` at settlement-epoch close (`ARCHIVAL_CONSENSUS_STATE.md` §3.3–§3.5).
  virtual void process_archival_epoch_close_at_height(uint64_t block_height);
  /// Revert epoch-close materialization when `block_height` is popped.
  virtual void revert_archival_epoch_close_at_height(uint64_t block_height);
  virtual uint64_t get_archival_r_market(uint64_t shard_id, uint64_t settlement_epoch) const;
  virtual uint64_t get_archival_sigma_work_milli(uint64_t settlement_epoch) const;
  /// Frozen `budget(E)` close row (ARCHIVAL_BUDGET_SCHEDULE.md §3.2): the
  /// bounded accrual-row sum the close materialized in the same txn as the
  /// sigma row. NOTFOUND is laundered to 0 like the sigma getter; the
  /// verify-side gather distinguishes absent-row (never closed / pruned →
  /// reject) via the stored-shape probe on the LMDB class.
  virtual uint64_t get_archival_budget(uint64_t settlement_epoch) const;
  /// Re-derive the as-of-E consensus snapshot for a claimed settlement epoch
  /// (M-2/Q7, REWARD_EMISSION_E3_GATING_ROUND.md §3 item 2): the same
  /// serve-credit/bond/shard row gather the close ran at H_close(E) — via the
  /// one shared gather routine — plus the **persisted** Σwork(E) and
  /// budget(E) close rows. Sound because every gathered row is immutable for
  /// a claimable E: credit acceptance rejects responses past H_close, pruning
  /// deletes only below the claim window's floor, and reorg pops revert close
  /// and credits symmetrically. Caller gates claimability (epoch closed,
  /// claim window) before calling; the C-1 emission dispatch in
  /// `Blockchain::check_tx_inputs` is the production consumer, the snapshot
  /// identity KATs the test consumer. Default resets `out` (has_budget_row
  /// false → the dispatch rejects).
  virtual void gather_archival_emission_epoch_snapshot(const crypto::hash& p_id,
    uint64_t settlement_epoch, ArchivalEmissionEpochSnapshot& out) const;
  /// Windowed form of the snapshot gather (EMISSION_CLAIM_BUILDER.md §7):
  /// one snapshot per epoch in `[epoch_lo, epoch_hi)`, per-epoch identical
  /// to `gather_archival_emission_epoch_snapshot`. The LMDB override
  /// collects every epoch's rows in a single serve-credit table pass so the
  /// unauthenticated claim-source RPC costs one scan per request, not one
  /// per window epoch; the default delegates to the per-epoch gather.
  virtual void gather_archival_emission_window_snapshots(const crypto::hash& p_id,
    uint64_t epoch_lo, uint64_t epoch_hi,
    std::vector<ArchivalEmissionEpochSnapshot>& out) const;

  // ─── Deferred Staked Leaf Insertion ─────────────────────────────────────────

  /**
   * @brief store a pre-computed curve tree leaf for deferred insertion.
   *
   * All outputs are deferred: they enter the pending table at creation and
   * drain into the curve tree when their maturity height is reached.
   *
   * @param maturity   the height at which this leaf becomes eligible
   * @param output     the global output index of this output
   * @param leaf_data  128 bytes of pre-computed leaf data
   */
  virtual void add_pending_tree_leaf(shekyl::db::MaturityHeight maturity,
                                     shekyl::db::OutputIndex output,
                                     const uint8_t* leaf_data) = 0;

  /**
   * @brief remove a specific pending tree leaf by composite key.
   *
   * Used by pop_block (via the block-pending journal) to remove outputs
   * that were added to pending at the popped block height.
   *
   * @param maturity   the maturity key of the leaf to remove
   * @param output     the output index (second half of composite key)
   */
  virtual void remove_pending_tree_leaf(shekyl::db::MaturityHeight maturity,
                                        shekyl::db::OutputIndex output) = 0;

  /**
   * @brief drain all pending leaves whose maturity_height <= current_height.
   *
   * Removes matching entries from the pending table, appends their 128-byte
   * leaf data to @p out_leaves, and journals each drained leaf via
   * add_pending_tree_drain_entry. Also writes output-to-leaf and
   * leaf-to-output mappings as tree positions are assigned.
   *
   * @param current_height  the height of the block being added (also the journal key)
   * @param out_leaves      output buffer; 128 bytes appended per drained leaf
   * @return number of leaves drained
   */
  virtual uint64_t drain_pending_tree_leaves(shekyl::db::BlockHeight current_height,
                                              std::vector<uint8_t>& out_leaves) = 0;

  struct drain_entry_t {
    shekyl::db::MaturityHeight maturity;
    shekyl::db::OutputIndex    output;
    std::array<uint8_t, 128>   leaf;

    drain_entry_t()
      : maturity(shekyl::db::MaturityHeight{0})
      , output(shekyl::db::OutputIndex{0})
      , leaf{}
    {}

    drain_entry_t(shekyl::db::MaturityHeight m, shekyl::db::OutputIndex o, const uint8_t* data)
      : maturity(m), output(o), leaf{}
    {
      if (data) std::memcpy(leaf.data(), data, 128);
    }
  };

  /**
   * @brief journal a drained leaf for pop_block reversibility.
   *
   * Each drained leaf is recorded with its original maturity_height and
   * output_index so that pop_block can re-insert it into the pending table.
   *
   * @param block_height  the block at which the drain occurred
   * @param output        the output index (part of the composite drain key)
   * @param maturity      the leaf's original pending table maturity
   * @param leaf_data     128 bytes of leaf data
   */
  virtual void add_pending_tree_drain_entry(shekyl::db::BlockHeight block_height,
                                            shekyl::db::OutputIndex output,
                                            shekyl::db::MaturityHeight maturity,
                                            const uint8_t* leaf_data) = 0;

  /**
   * @brief read all drain journal entries for a given block height.
   *
   * @param block_height  the block to query
   * @return vector of drain_entry_t (maturity, output, leaf) in drain order
   */
  virtual std::vector<drain_entry_t> get_pending_tree_drain_entries(shekyl::db::BlockHeight block_height) const = 0;

  /**
   * @brief remove all drain journal entries for a given block height.
   */
  virtual void remove_pending_tree_drain_entries(shekyl::db::BlockHeight block_height) = 0;

  // ─── Block Pending Additions Journal ───────────────────────────────────────

  /**
   * @brief record that a pending tree leaf was added by this block.
   *
   * pop_block reads this journal to delete exact entries from
   * m_pending_tree_leaves without reconstruction.
   */
  virtual void add_block_pending_addition(shekyl::db::BlockHeight height,
                                          shekyl::db::OutputIndex output,
                                          shekyl::db::MaturityHeight maturity) = 0;

  /**
   * @brief read all pending additions journaled for a given block.
   *
   * @return vector of (maturity, output) pairs
   */
  virtual std::vector<std::pair<shekyl::db::MaturityHeight, shekyl::db::OutputIndex>>
      get_block_pending_additions(shekyl::db::BlockHeight height) const = 0;

  /**
   * @brief remove all block-pending-addition journal entries for a block.
   */
  virtual void remove_block_pending_additions(shekyl::db::BlockHeight height) = 0;

  // ─── Output ↔ Leaf Mapping ─────────────────────────────────────────────────

  /**
   * @brief record the bidirectional mapping between output index and tree position.
   *
   * Written during drain when a tree position is assigned.
   */
  virtual void add_output_leaf_mapping(shekyl::db::OutputIndex output,
                                       shekyl::db::TreePosition tree_pos) = 0;

  /**
   * @brief remove the bidirectional output↔leaf mapping.
   *
   * Asserts stored value matches @p tree_pos before deleting.
   */
  virtual void remove_output_leaf_mapping(shekyl::db::OutputIndex output,
                                          shekyl::db::TreePosition tree_pos) = 0;

  /**
   * @brief look up the tree position for a given global output index.
   *
   * @param output  the output to query
   * @param pos_out filled on success
   * @return true if mapping exists
   */
  virtual bool get_output_leaf_index(shekyl::db::OutputIndex output,
                                     shekyl::db::TreePosition& pos_out) const = 0;

  /**
   * @brief look up the global output index for a given tree position.
   *
   * @param tree_pos the tree position to query
   * @param out_out  filled on success
   * @return true if mapping exists
   */
  virtual bool get_leaf_output_index(shekyl::db::TreePosition tree_pos,
                                     shekyl::db::OutputIndex& out_out) const = 0;

  // ─── FCMP++ Curve Tree ─────────────────────────────────────────────────────

  /**
   * @brief grow the curve tree by appending new leaf data for outputs added in a block.
   *
   * Each leaf is 128 bytes: {O.x[32], I.x[32], C.x[32], H(pqc_pk)[32]}.
   * The implementation stores the leaves, recomputes affected chunk hashes
   * via Rust FFI (Helios/Selene Pedersen commitments), and updates all
   * internal layers up to the root.
   *
   * @param leaf_data  serialized 4-scalar leaves, 128 bytes per output
   * @param num_new_outputs  number of outputs (leaf_data.size() / 128)
   */
  virtual void grow_curve_tree(const std::vector<uint8_t>& leaf_data, uint64_t num_new_outputs) = 0;

  /**
   * @brief trim the curve tree, removing outputs during a block pop/reorg.
   *
   * @param num_outputs_to_remove  number of most-recent outputs to remove
   */
  virtual void trim_curve_tree(uint64_t num_outputs_to_remove) = 0;

  /**
   * @brief return the current curve tree root (32-byte serialized point).
   */
  virtual std::array<uint8_t, 32> get_curve_tree_root() const = 0;

  /**
   * @brief return the current tree depth (number of layers).
   */
  virtual uint8_t get_curve_tree_depth() const = 0;

  /**
   * @brief return the total number of leaves (outputs) in the curve tree.
   */
  virtual uint64_t get_curve_tree_leaf_count() const = 0;

  /**
   * @brief get the hash for a specific layer/chunk in the tree.
   *
   * @param layer  layer index (0 = leaf layer)
   * @param chunk  chunk index within the layer
   * @param hash_out  32-byte output buffer
   * @return true if the entry exists
   */
  virtual bool get_curve_tree_layer_hash(uint8_t layer, uint64_t chunk, uint8_t* hash_out) const = 0;

  /**
   * @brief get the leaf data for a specific tree position.
   *
   * WARNING: The parameter is a tree_position, NOT a global_output_index.
   * Use get_curve_tree_leaf_by_output_index() if you have an output index.
   *
   * @param tree_position  the leaf's position in the curve tree (0-indexed)
   * @param leaf_out       128-byte output buffer
   * @return true if the leaf exists
   */
  virtual bool get_curve_tree_leaf_by_tree_position(uint64_t tree_position, uint8_t* leaf_out) const = 0;

  /**
   * @brief get the leaf data for a specific global output index.
   *
   * Performs a double lookup: output_index → tree_position via m_output_to_leaf,
   * then tree_position → leaf via m_curve_tree_leaves.
   * Callers who want a consistent pair must do both inside a single read txn.
   *
   * @param output_index  the global output index
   * @param leaf_out      128-byte output buffer
   * @return true if the output has a tree leaf (i.e., it has been drained)
   */
  virtual bool get_curve_tree_leaf_by_output_index(uint64_t output_index, uint8_t* leaf_out) const = 0;

  /**
   * @brief get a contiguous run of leaves by tree position in one read.
   *
   * Reads `count` leaves starting at `first_tree_position` into `out`
   * (count × 128 bytes, densely packed). Returns false — leaving `out`
   * unspecified — if any leaf in the run is missing or malformed; callers
   * must not read `out` on false.
   *
   * The base implementation loops over get_curve_tree_leaf_by_tree_position();
   * LMDB overrides it with a single cursor scan (one B-tree traversal instead
   * of one per leaf) for the serve-credit verification hot path.
   *
   * @param first_tree_position  tree position of the first leaf in the run
   * @param count                number of contiguous leaves to read
   * @param out                  output buffer of count × 128 bytes
   * @return true iff every leaf in the run was present and full
   */
  virtual bool get_curve_tree_leaf_chunk(uint64_t first_tree_position, uint64_t count, uint8_t* out) const;

  // ─── FCMP++ Per-Height Curve Tree Root ──────────────────────────────────

  /**
   * @brief store the current curve tree root keyed by block height.
   *
   * Called after every block addition so that historical tree roots can be
   * looked up by height during FCMP++ proof construction and verification
   * (where the reference block's tree root is needed, not the current tip).
   */
  virtual void store_curve_tree_root_at_height(uint64_t block_height, const std::array<uint8_t, 32>& root) = 0;

  /**
   * @brief retrieve the curve tree root that was current at a given height.
   *
   * @param block_height  the height to look up
   * @return 32-byte root hash (all-zero if no entry exists)
   */
  virtual std::array<uint8_t, 32> get_curve_tree_root_at_height(uint64_t block_height) const = 0;

  /**
   * @brief remove the stored curve tree root for a given height.
   *
   * Called during pop_block to keep the table consistent with chain state.
   */
  virtual void remove_curve_tree_root_at_height(uint64_t block_height) = 0;

  // ─── Credit-wire attestation witness (prunable, admission-only) ───────────
  // The per-block `r` + pass-signature witness (ARCHIVAL_CREDIT_WIRE.md §3.2/§4,
  // credit-wire CW-2): two tables, each with ONE owner.
  //   * height-keyed — owned by the MAIN CHAIN. Written by add_block, deleted by
  //     pop_block, reaped by the retention prune.
  //   * hash-keyed — owned by the ALT-BLOCK TABLE. Written beside add_alt_block,
  //     deleted beside remove_alt_block / drop_alt_blocks / reset. A row exists
  //     there iff its alt block does, so no path can orphan one.
  // Neither owner writes the other's table; a block moving between main and alt
  // carries its witness explicitly through block_connect_supplement.
  // Mined commitment lives in the block header's attestation_root (not the blob).
  // Opaque bytes at this layer; decode/verify live in Rust.

  /**
   * @brief store a block's attestation witness keyed by block height.
   *
   * Called from add_block in the same write txn as the block add (keyed to
   * mirror store_curve_tree_root_at_height). Not called for an empty witness.
   */
  virtual void store_archival_attestation_witness_at_height(uint64_t block_height, const blobdata& witness) = 0;

  /**
   * @brief retrieve the attestation witness stored at a given height.
   *
   * @return the witness blob, or empty if no row exists (a block with an empty
   *   attestation set, or a pruned/never-written height).
   */
  virtual blobdata get_archival_attestation_witness_at_height(uint64_t block_height) const = 0;

  /**
   * @brief remove the stored attestation witness for a given height.
   *
   * Tolerant of a missing key. Called by pop_block (the block leaves main) and
   * by the retention prune.
   */
  virtual void remove_archival_attestation_witness_at_height(uint64_t block_height) = 0;

  // ─── Alt-chain attestation witness (hash-keyed) ───────────────────────────
  // Hash-keyed counterpart to the height-keyed main table, holding the witness of
  // every block currently in the alt-block table — whether it arrived as an alt
  // block or was demoted there by a reorg. Its rows are owned by the alt block:
  // written beside add_alt_block, removed by remove_alt_block / drop_alt_blocks /
  // reset(). Nothing else writes or deletes here, so a row cannot outlive (or
  // survive without) its alt block.

  /**
   * @brief store an alt block's attestation witness keyed by block hash.
   *
   * Called from handle_alternative_block alongside add_alt_block, in the same
   * write txn. Not called for an empty witness (stores no row).
   */
  virtual void store_archival_alt_attestation_witness(const crypto::hash& blkid, const blobdata& witness) = 0;

  /**
   * @brief retrieve the attestation witness stashed for an alt block.
   *
   * @return the witness blob, or empty if no row exists (an alt block with an
   *   empty attestation set, or one added before this table existed).
   */
  virtual blobdata get_archival_alt_attestation_witness(const crypto::hash& blkid) const = 0;

  /**
   * @brief remove the stashed attestation witness for an alt block.
   *
   * Tolerant of a missing key. Invoked implicitly by remove_alt_block /
   * drop_alt_blocks so the witness never outlives its alt block.
   */
  virtual void remove_archival_alt_attestation_witness(const crypto::hash& blkid) = 0;

  // ─── FCMP++ Curve Tree Checkpoints & Pruning ─────────────────────────────

  /**
   * @brief save a curve tree checkpoint at the given block height.
   *
   * Serializes current tree metadata (root, depth, leaf_count) and stores it
   * keyed by block_height for fast-sync resumption.
   */
  virtual void save_curve_tree_checkpoint(uint64_t block_height) = 0;

  /**
   * @brief retrieve checkpoint data for a specific block height.
   *
   * @param block_height  the height to look up
   * @param checkpoint_data  output buffer for the serialized checkpoint
   * @return true if a checkpoint exists at the given height
   */
  virtual bool get_curve_tree_checkpoint(uint64_t block_height, std::vector<uint8_t>& checkpoint_data) const = 0;

  /**
   * @brief return the height of the most recent curve tree checkpoint.
   *
   * @return the checkpoint height, or 0 if no checkpoints exist
   */
  virtual uint64_t get_latest_curve_tree_checkpoint_height() const = 0;

  /**
   * @brief remove intermediate layer hashes between checkpoints.
   *
   * Given a checkpoint height, removes internal hash layers that can be
   * recomputed from leaves between the previous checkpoint and this one.
   * Leaves and the latest live layer state are preserved.
   *
   * @param checkpoint_height  the checkpoint up to which to prune
   */
  virtual void prune_curve_tree_intermediate_layers(uint64_t checkpoint_height) = 0;

  bool m_open;  //!< Whether or not the BlockchainDB is open/ready for use
  mutable epee::critical_section m_synchronization_lock;  //!< A lock, currently for when BlockchainLMDB needs to resize the backing db file

};  // class BlockchainDB

class db_txn_guard
{
public:
  db_txn_guard(BlockchainDB *db, bool readonly): db(db), readonly(readonly), active(false)
  {
    if (readonly)
    {
      active = db->block_rtxn_start();
    }
    else
    {
      db->block_wtxn_start();
      active = true;
    }
  }
  virtual ~db_txn_guard()
  {
    stop();
  }
  void stop()
  {
    if (active)
    {
      if (readonly)
        db->block_rtxn_stop();
      else
        db->block_wtxn_stop();
      active = false;
    }
  }
  void abort()
  {
    if (readonly)
      db->block_rtxn_abort();
    else
      db->block_wtxn_abort();
    active = false;
  }

private:
  BlockchainDB *db;
  bool readonly;
  bool active;
};

class db_rtxn_guard: public db_txn_guard { public: db_rtxn_guard(BlockchainDB *db): db_txn_guard(db, true) {} };
class db_wtxn_guard: public db_txn_guard { public: db_wtxn_guard(BlockchainDB *db): db_txn_guard(db, false) {} };

BlockchainDB *new_db();

}  // namespace cryptonote

#endif  // BLOCKCHAIN_DB_H
