// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

// The bytes of a transaction the serializer accepted. Production reports a
// refusal through `tx_to_blob`'s return value. A test that built the
// transaction has no use for the fragment a refusal leaves behind, so here
// a refusal ends the test.

#pragma once

#include <stdexcept>

#include "cryptonote_basic/cryptonote_format_utils.h"

namespace shekyl_test_fixtures
{

inline cryptonote::blobdata tx_blob(const cryptonote::transaction& tx)
{
  cryptonote::blobdata blob;
  if (!cryptonote::tx_to_blob(tx, blob))
    throw std::runtime_error("test fixture: the transaction did not serialize");
  return blob;
}

}  // namespace shekyl_test_fixtures
