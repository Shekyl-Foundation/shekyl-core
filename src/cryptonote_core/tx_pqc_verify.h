// Copyright (c) 2024, The Monero Project
//
// All rights reserved.
//
// PQC verification for TransactionV3 hybrid signatures.

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"

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

} // namespace cryptonote
