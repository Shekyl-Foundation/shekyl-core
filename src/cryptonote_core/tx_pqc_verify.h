// Copyright (c) 2024, The Monero Project
//
// All rights reserved.
//
// PQC verification for TransactionV3 hybrid signatures.

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include <boost/optional.hpp>

namespace cryptonote
{

/// Build the signed payload for v3 PQC verification.
/// Payload = serialize(prefix) || serialize(rct_signing_body) || serialize(pqc_auth_header).
/// Returns false if tx is not v3 or missing pqc_auth.
bool get_transaction_signed_payload(const transaction& tx, std::string& payload_out);

/// Verify the PQC hybrid signature on a v3 transaction.
/// Returns true if tx is not v3 (skip) or if verification succeeds.
/// Returns false if v3 tx has invalid or missing pqc_auth, or verification fails.
bool verify_transaction_pqc_auth(const transaction& tx);

/// Verify with scheme downgrade protection.
/// When expected_scheme_id is provided, the spend's scheme_id must match.
/// Pass the expected scheme from the creating transaction's tx_extra PQC
/// ownership tag to prevent scheme downgrade attacks.
bool verify_transaction_pqc_auth(const transaction& tx,
                                  const boost::optional<uint8_t>& expected_scheme_id);

} // namespace cryptonote
