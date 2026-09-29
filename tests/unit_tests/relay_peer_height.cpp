// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#include "gtest/gtest.h"

#include "cryptonote_basic/connection_context.h"

// The control's falsifier. Local chain length 85 is coinbase height 84.
// The recorded field is that chain length. A later shorter block does not
// pull it back down.
TEST(relay_peer, an_accepted_block_raises_recorded_height_and_never_lowers_it)
{
  cryptonote::cryptonote_connection_context context;
  context.m_remote_blockchain_height = 46;

  cryptonote::raise_remote_height(context, cryptonote::chain_length_of_accepted_block(84));
  EXPECT_GE(context.m_remote_blockchain_height, 85u);
  EXPECT_EQ(context.m_remote_height_source,
      cryptonote::cryptonote_connection_context::remote_height_source::accepted_block);

  cryptonote::raise_remote_height(context, cryptonote::chain_length_of_accepted_block(40));
  EXPECT_EQ(context.m_remote_blockchain_height, 85u);
}
