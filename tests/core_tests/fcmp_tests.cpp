// Copyright (c) 2026, The Shekyl Project
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

#include "fcmp_tests.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#ifndef CHECK_TEST_CONDITION_MSG
#define CHECK_TEST_CONDITION_MSG(expr, msg) CHECK_TEST_CONDITION(expr)
#endif

using namespace cryptonote;

// ═══════════════════════════════════════════════════════════════════════
// gen_fcmp_tx_valid
// Constructs a full FCMP++ transaction (proof + PQC auth) during replay
// and submits it to the pool. Verifies acceptance.
// ═══════════════════════════════════════════════════════════════════════

gen_fcmp_tx_valid::gen_fcmp_tx_valid()
{
  REGISTER_CALLBACK_METHOD(gen_fcmp_tx_valid, check_fcmp_tx_accepted);
}

bool gen_fcmp_tx_valid::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  MAKE_ACCOUNT(events, miner_account);
  MAKE_ACCOUNT(events, alice);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);

  REWIND_BLOCKS_N(events, blk_mature, blk_0, miner_account, 70);

  DO_CALLBACK(events, "check_fcmp_tx_accepted");

  return true;
}

bool gen_fcmp_tx_valid::check_fcmp_tx_accepted(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_fcmp_tx_valid::check_fcmp_tx_accepted");

  const account_base& miner_account = std::get<account_base>(events[0]);
  const account_base& alice = std::get<account_base>(events[1]);

  // Find the head block
  block blk_head = get_head_block(events);

  uint64_t chain_height = c.get_current_blockchain_height();
  LOG_PRINT_L0("Chain height: " << chain_height
    << ", curve tree leaves: " << c.get_blockchain_storage().get_db().get_curve_tree_leaf_count()
    << ", tree depth: " << (int)c.get_blockchain_storage().get_db().get_curve_tree_depth());

  CHECK_TEST_CONDITION(chain_height > CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + FCMP_REFERENCE_BLOCK_MIN_AGE);
  CHECK_TEST_CONDITION(c.get_blockchain_storage().get_db().get_curve_tree_leaf_count() > 0);

  transaction tx;
  uint64_t amount = TESTS_DEFAULT_FEE * 10;
  bool r = construct_fcmp_tx(c, miner_account, alice.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx failed");

  // Submit to pool
  tx_verification_context tvc{};
  bool kept_by_block = false;
  cryptonote::blobdata tx_blob;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx, tx_blob), "Failed to serialize tx");
  r = c.handle_incoming_tx(tx_blob, tvc, cryptonote::relay_method::local, kept_by_block);
  CHECK_TEST_CONDITION_MSG(!tvc.m_verifivation_failed, "FCMP++ transaction was rejected by the pool");
  CHECK_TEST_CONDITION_MSG(r, "handle_incoming_tx returned false");

  LOG_PRINT_L0("FCMP++ transaction " << get_transaction_hash(tx) << " accepted into pool");

  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// gen_fcmp_tx_double_spend
// Constructs two FCMP++ transactions spending the same output.
// The second must be rejected as a double spend.
// ═══════════════════════════════════════════════════════════════════════

gen_fcmp_tx_double_spend::gen_fcmp_tx_double_spend()
{
  REGISTER_CALLBACK_METHOD(gen_fcmp_tx_double_spend, check_double_spend_rejected);
}

bool gen_fcmp_tx_double_spend::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  MAKE_ACCOUNT(events, miner_account);
  MAKE_ACCOUNT(events, alice);
  MAKE_ACCOUNT(events, bob);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  REWIND_BLOCKS_N(events, blk_mature, blk_0, miner_account, 70);

  DO_CALLBACK(events, "check_double_spend_rejected");
  return true;
}

bool gen_fcmp_tx_double_spend::check_double_spend_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_fcmp_tx_double_spend::check_double_spend_rejected");

  const account_base& miner_account = std::get<account_base>(events[0]);
  const account_base& alice = std::get<account_base>(events[1]);
  const account_base& bob = std::get<account_base>(events[2]);
  block blk_head = get_head_block(events);

  uint64_t amount = TESTS_DEFAULT_FEE * 5;

  // First tx should succeed
  transaction tx1;
  bool r = construct_fcmp_tx(c, miner_account, alice.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx1);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx (tx1) failed");

  tx_verification_context tvc1{};
  cryptonote::blobdata blob1;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx1, blob1), "Failed to serialize tx1");
  r = c.handle_incoming_tx(blob1, tvc1, cryptonote::relay_method::local, false);
  CHECK_TEST_CONDITION_MSG(!tvc1.m_verifivation_failed, "tx1 was rejected");

  // Second tx spending the same output should be rejected
  transaction tx2;
  r = construct_fcmp_tx(c, miner_account, bob.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx2);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx (tx2) failed");

  tx_verification_context tvc2{};
  cryptonote::blobdata blob2;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx2, blob2), "Failed to serialize tx2");
  r = c.handle_incoming_tx(blob2, tvc2, cryptonote::relay_method::local, false);
  CHECK_TEST_CONDITION_MSG(tvc2.m_double_spend, "tx2 should have been flagged as double spend");

  LOG_PRINT_L0("Double-spend FCMP++ transaction correctly rejected");
  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// gen_fcmp_tx_reference_block_too_old
// ═══════════════════════════════════════════════════════════════════════

gen_fcmp_tx_reference_block_too_old::gen_fcmp_tx_reference_block_too_old()
{
  REGISTER_CALLBACK_METHOD(gen_fcmp_tx_reference_block_too_old, check_stale_reference_rejected);
}

bool gen_fcmp_tx_reference_block_too_old::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  MAKE_ACCOUNT(events, miner_account);
  MAKE_ACCOUNT(events, alice);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  REWIND_BLOCKS_N(events, blk_mature, blk_0, miner_account, FCMP_REFERENCE_BLOCK_MAX_AGE + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + 10);

  DO_CALLBACK(events, "check_stale_reference_rejected");
  return true;
}

bool gen_fcmp_tx_reference_block_too_old::check_stale_reference_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_fcmp_tx_reference_block_too_old::check_stale_reference_rejected");

  const account_base& miner_account = std::get<account_base>(events[0]);
  const account_base& alice = std::get<account_base>(events[1]);
  block blk_head = get_head_block(events);

  // Build a valid FCMP++ tx first
  transaction tx;
  uint64_t amount = TESTS_DEFAULT_FEE * 5;
  bool r = construct_fcmp_tx(c, miner_account, alice.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx failed");

  // Tamper: set referenceBlock to a very old block (height 0)
  const auto& bs = c.get_blockchain_storage();
  tx.rct_signatures.referenceBlock = bs.get_block_id_by_height(0);
  tx.invalidate_hashes();

  tx_verification_context tvc{};
  cryptonote::blobdata tx_blob;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx, tx_blob), "Failed to serialize tx");
  r = c.handle_incoming_tx(tx_blob, tvc, cryptonote::relay_method::local, false);
  CHECK_TEST_CONDITION_MSG(tvc.m_verifivation_failed, "Too-old referenceBlock should be rejected");

  LOG_PRINT_L0("Stale referenceBlock correctly rejected");
  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// gen_fcmp_tx_reference_block_too_recent
// ═══════════════════════════════════════════════════════════════════════

gen_fcmp_tx_reference_block_too_recent::gen_fcmp_tx_reference_block_too_recent()
{
  REGISTER_CALLBACK_METHOD(gen_fcmp_tx_reference_block_too_recent, check_recent_reference_rejected);
}

bool gen_fcmp_tx_reference_block_too_recent::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  MAKE_ACCOUNT(events, miner_account);
  MAKE_ACCOUNT(events, alice);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  REWIND_BLOCKS_N(events, blk_mature, blk_0, miner_account, 70);

  DO_CALLBACK(events, "check_recent_reference_rejected");
  return true;
}

bool gen_fcmp_tx_reference_block_too_recent::check_recent_reference_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_fcmp_tx_reference_block_too_recent::check_recent_reference_rejected");

  const account_base& miner_account = std::get<account_base>(events[0]);
  const account_base& alice = std::get<account_base>(events[1]);
  block blk_head = get_head_block(events);

  transaction tx;
  uint64_t amount = TESTS_DEFAULT_FEE * 5;
  bool r = construct_fcmp_tx(c, miner_account, alice.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx failed");

  // Tamper: set referenceBlock to the tip (too recent -- within MIN_AGE)
  const auto& bs = c.get_blockchain_storage();
  uint64_t chain_height = c.get_current_blockchain_height();
  tx.rct_signatures.referenceBlock = bs.get_block_id_by_height(chain_height - 1);
  tx.invalidate_hashes();

  tx_verification_context tvc{};
  cryptonote::blobdata tx_blob;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx, tx_blob), "Failed to serialize tx");
  r = c.handle_incoming_tx(tx_blob, tvc, cryptonote::relay_method::local, false);
  CHECK_TEST_CONDITION_MSG(tvc.m_verifivation_failed, "Too-recent referenceBlock should be rejected");

  LOG_PRINT_L0("Too-recent referenceBlock correctly rejected");
  return true;
}

// ═══════════════════════════════════════════════════════════════════════
// gen_fcmp_tx_timestamp_unlock_rejected
// Constructs a transaction with unlock_time set to a timestamp value
// (>= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL). Must be rejected.
// ═══════════════════════════════════════════════════════════════════════

gen_fcmp_tx_timestamp_unlock_rejected::gen_fcmp_tx_timestamp_unlock_rejected()
{
  REGISTER_CALLBACK_METHOD(gen_fcmp_tx_timestamp_unlock_rejected, check_timestamp_unlock_rejected);
}

bool gen_fcmp_tx_timestamp_unlock_rejected::generate(std::vector<test_event_entry>& events) const
{
  uint64_t ts_start = 1338224400;

  MAKE_ACCOUNT(events, miner_account);
  MAKE_ACCOUNT(events, alice);
  MAKE_GENESIS_BLOCK(events, blk_0, miner_account, ts_start);
  REWIND_BLOCKS_N(events, blk_mature, blk_0, miner_account, 70);

  DO_CALLBACK(events, "check_timestamp_unlock_rejected");
  return true;
}

bool gen_fcmp_tx_timestamp_unlock_rejected::check_timestamp_unlock_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_fcmp_tx_timestamp_unlock_rejected::check_timestamp_unlock_rejected");

  const account_base& miner_account = std::get<account_base>(events[0]);
  const account_base& alice = std::get<account_base>(events[1]);
  block blk_head = get_head_block(events);

  transaction tx;
  uint64_t amount = TESTS_DEFAULT_FEE * 5;
  bool r = construct_fcmp_tx(c, miner_account, alice.get_keys().m_account_address,
    amount, TESTS_DEFAULT_FEE, events, blk_head, tx);
  CHECK_TEST_CONDITION_MSG(r, "construct_fcmp_tx failed");

  // Tamper: set unlock_time to a timestamp (which is >= CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL)
  tx.unlock_time = CRYPTONOTE_MAX_BLOCK_NUMBER;
  tx.invalidate_hashes();

  tx_verification_context tvc{};
  cryptonote::blobdata tx_blob;
  CHECK_TEST_CONDITION_MSG(t_serializable_object_to_blob(tx, tx_blob), "Failed to serialize tx");
  r = c.handle_incoming_tx(tx_blob, tvc, cryptonote::relay_method::local, false);
  CHECK_TEST_CONDITION_MSG(tvc.m_verifivation_failed, "Timestamp-based unlock_time should be rejected");

  LOG_PRINT_L0("Timestamp unlock_time correctly rejected");
  return true;
}
