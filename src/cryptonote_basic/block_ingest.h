// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#pragma once

#include "cryptonote_basic/verification_context.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
  /// PWD-B7 block-ingest write path. Folds `incoming` into `bvc.m_outcome`
  /// through the Rust type. First writer wins. Non-reject arms only —
  /// rejections go through reject_block_* so the drop slot is paired.
  inline void record_block_ingest(block_verification_context &bvc, uint8_t incoming)
  {
    shekyl_block_ingest_record(&bvc.m_outcome, incoming);
  }

  inline bool block_added(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_is_added(bvc.m_outcome);
  }

  inline bool block_already_exists(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_already_exists(bvc.m_outcome);
  }

  inline bool block_orphaned(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_is_orphaned(bvc.m_outcome);
  }

  inline bool block_missing_txs(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_missing_txs(bvc.m_outcome);
  }

  inline bool block_rejected(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_is_rejected(bvc.m_outcome);
  }

  inline bool block_bad_pow(const block_verification_context &bvc)
  {
    return shekyl_block_ingest_is_bad_pow(bvc.m_outcome);
  }

  /// Classify a form rejection and return false. Pairing lives in Rust.
  inline bool reject_block_form(block_verification_context &bvc)
  {
    shekyl_block_ingest_reject_form(&bvc.m_outcome, &bvc.m_drop_verdict);
    return false;
  }

  inline bool reject_block_bad_pow(block_verification_context &bvc)
  {
    shekyl_block_ingest_reject_bad_pow(&bvc.m_outcome, &bvc.m_drop_verdict);
    return false;
  }

  inline bool reject_block_state(block_verification_context &bvc)
  {
    shekyl_block_ingest_reject_state(&bvc.m_outcome, &bvc.m_drop_verdict);
    return false;
  }

  inline bool reject_block_internal(block_verification_context &bvc)
  {
    shekyl_block_ingest_reject_internal(&bvc.m_outcome, &bvc.m_drop_verdict);
    return false;
  }

  /// Fold a tx-path drop verdict onto the block context. The tx path already
  /// classified; we do not re-interpret the code here.
  inline bool reject_block_from_tvc(block_verification_context &bvc,
    const tx_verification_context &tvc)
  {
    shekyl_block_ingest_reject_with_drop(&bvc.m_outcome, &bvc.m_drop_verdict, tvc.m_drop_verdict);
    return false;
  }

  /// Announce-path instruction. C++ asks the predicates; it does not
  /// switch on the byte.
  inline uint8_t block_announce_action(const block_verification_context &bvc, bool handle_ok)
  {
    return shekyl_block_announce_action(bvc.m_outcome, bvc.m_drop_verdict, handle_ok);
  }

  inline bool block_announce_re_request_txs(uint8_t action)
  {
    return shekyl_block_announce_re_request_txs(action);
  }

  inline bool block_announce_drop(uint8_t action)
  {
    return shekyl_block_announce_drop(action);
  }

  inline bool block_announce_heavier_score(uint8_t action)
  {
    return shekyl_block_announce_heavier_score(action);
  }

  inline bool block_announce_our_failure(uint8_t action)
  {
    return shekyl_block_announce_our_failure(action);
  }

  inline bool block_announce_relay(uint8_t action)
  {
    return shekyl_block_announce_relay(action);
  }

  inline bool block_announce_request_history(uint8_t action)
  {
    return shekyl_block_announce_request_history(action);
  }

  /// GET_OBJECTS sync-path instruction.
  inline uint8_t block_sync_action(const block_verification_context &bvc)
  {
    return shekyl_block_sync_action(bvc.m_outcome, bvc.m_drop_verdict);
  }

  inline bool block_sync_drop(uint8_t action)
  {
    return shekyl_block_sync_drop(action);
  }

  inline bool block_sync_heavier_score(uint8_t action)
  {
    return shekyl_block_sync_heavier_score(action);
  }

  inline bool block_sync_orphan_resync(uint8_t action)
  {
    return shekyl_block_sync_orphan_resync(action);
  }
}
