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

#pragma once
#include "chaingen.h"

struct gen_fcmp_tx_valid : public test_chain_unit_base
{
  gen_fcmp_tx_valid();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_fcmp_tx_accepted(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_fcmp_tx_double_spend : public test_chain_unit_base
{
  gen_fcmp_tx_double_spend();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_double_spend_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_fcmp_tx_reference_block_too_old : public test_chain_unit_base
{
  gen_fcmp_tx_reference_block_too_old();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_stale_reference_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_fcmp_tx_reference_block_too_recent : public test_chain_unit_base
{
  gen_fcmp_tx_reference_block_too_recent();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_recent_reference_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};

struct gen_fcmp_tx_timestamp_unlock_rejected : public test_chain_unit_base
{
  gen_fcmp_tx_timestamp_unlock_rejected();
  bool generate(std::vector<test_event_entry>& events) const;
  bool check_timestamp_unlock_rejected(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry>& events);
};
