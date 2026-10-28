// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One span of block arrivals, into the Rust ingest door
//! (`DRS_X_STORE_FLIP.md` DX-Q2 item 2). The bytes stay alive for the
//! call; the door copies them before it returns.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "cryptonote_protocol_defs.h"
#include "shekyl/shekyl_ffi.h"

namespace cryptonote
{
  /// Offer `blocks` from `connection`. `solicited` is a span this node
  /// asked for. The result is `shekyl_ingest_offer_span`'s: accepted, or
  /// a refusal before acceptance. A door with no room answers
  /// `SHEKYL_INGEST_NO_ROOM` without being asked to take the span.
  inline int offer_block_span(std::uint64_t connection, bool solicited,
      const std::vector<block_complete_entry>& blocks)
  {
    if (blocks.empty() || shekyl_ingest_room() == 0)
      return SHEKYL_INGEST_NO_ROOM;
    std::vector<std::vector<shekyl_ingest_blob>> bodies;
    std::vector<shekyl_ingest_arrival> arrivals;
    bodies.reserve(blocks.size());
    arrivals.reserve(blocks.size());
    for (const block_complete_entry& block : blocks)
    {
      std::vector<shekyl_ingest_blob>& txs = bodies.emplace_back();
      txs.reserve(block.txs.size());
      for (const tx_blob_entry& tx : block.txs)
      {
        txs.push_back(shekyl_ingest_blob{
            reinterpret_cast<const std::uint8_t*>(tx.blob.data()), tx.blob.size()});
      }
      arrivals.push_back(shekyl_ingest_arrival{
          static_cast<std::uint64_t>(arrivals.size()),
          shekyl_ingest_blob{
              reinterpret_cast<const std::uint8_t*>(block.block.data()), block.block.size()},
          txs.empty() ? nullptr : txs.data(),
          txs.size()});
    }
    return shekyl_ingest_offer_span(connection, solicited ? 1 : 0, arrivals.data(), arrivals.size());
  }
}
