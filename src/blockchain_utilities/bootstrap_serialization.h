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

#pragma once

#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_config.h"
#include "serialization/difficulty_type.h"


namespace cryptonote
{
  namespace bootstrap
  {

    // Minor version at which a chunk started carrying the credit-wire attestation
    // witness. A file below this is refused on import: the field is trailing, so
    // parsing an older chunk with the current block_package would fail mid-record
    // anyway, and a bootstrap silently missing every witness is worse than a loud
    // "re-export this file".
    constexpr uint8_t BOOTSTRAP_MINOR_VERSION_WITNESS = 1;

    struct file_info
    {
      uint8_t  major_version;
      uint8_t  minor_version;
      uint32_t header_size;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(major_version);
        FIELD(minor_version);
        VARINT_FIELD(header_size);
      END_SERIALIZE()
    };

    struct blocks_info
    {
      // block heights of file's first and last blocks, zero-based indexes
      uint64_t block_first;
      uint64_t block_last;

      // file position, for directly reading last block
      uint64_t block_last_pos;

      BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(block_first);
        VARINT_FIELD(block_last);
        VARINT_FIELD(block_last_pos);
      END_SERIALIZE()
    };

    struct block_package_1
    {
      cryptonote::block block;
      std::vector<transaction> txs;
      size_t block_weight;
      uint64_t cumulative_difficulty;
      uint64_t coins_generated;

      BEGIN_SERIALIZE()
        FIELD(block)
        FIELD(txs)
        VARINT_FIELD(block_weight)
        VARINT_FIELD(cumulative_difficulty)
        VARINT_FIELD(coins_generated)
      END_SERIALIZE()
    };

    // Bootstrap chunk as written by minor version >= BOOTSTRAP_MINOR_VERSION_WITNESS.
    // Earlier minors are refused at the import entry point rather than parsed with a
    // trailing field missing.
    struct block_package
    {
      cryptonote::block block;
      std::vector<transaction> txs;
      size_t block_weight;
      difficulty_type cumulative_difficulty;
      uint64_t coins_generated;
      // Credit-wire attestation witness (ARCHIVAL_CREDIT_WIRE.md §3, credit-wire
      // CW-2). Opaque bytes, exactly as the p2p block_complete_entry carries them.
      // Without it in the export format a bootstrapped node holds no witness for any
      // imported block — it can serve none to its IBD peers and, after the cutover,
      // cannot re-drive their admission.
      blobdata attestation_witness;

      BEGIN_SERIALIZE()
        FIELD(block)
        FIELD(txs)
        VARINT_FIELD(block_weight)
        FIELD(cumulative_difficulty)
        VARINT_FIELD(coins_generated)
        FIELD(attestation_witness)
        // Bound the opaque blob at this codec, the same way block_complete_entry's KV
        // map does for the p2p path — a bootstrap file is an untrusted input too, and
        // a cap enforced by the importer instead would miss any other reader.
        if (!config::archival_attestation_witness_within_transport_cap(attestation_witness.size()))
          return false;
      END_SERIALIZE()
    };

  }

}
