// Copyright (c) 2025-2026, The Shekyl Foundation
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

/// Build the signed payload for v3 PQC verification for input \p input_index.
/// Payload = serialize(prefix) || serialize(rct_signing_body) || H(rct_prunable)
///         || serialize(pqc_auth_header_i) || H(pqc_pk_0) || ... || H(pqc_pk_{N-1})
/// H(rct_prunable) is cn_fast_hash of the serialized prunable data (fcmp_pp_proof,
/// pseudoOuts, curve_trees_tree_depth, Bulletproofs+), binding the PQC signature
/// to the FCMP++ proof and preventing prunable data substitution.
/// The concatenation of all inputs' PQC public-key hashes binds each signature
/// to the complete set of authorized keys, preventing key-substitution attacks.
/// Returns false if tx is not v3, index out of range, or missing pqc_auths entry.
bool get_transaction_signed_payload(const transaction& tx, size_t input_index, std::string& payload_out);

/// Verify the PQC hybrid signature on a v3 transaction.
/// Returns true if tx is not v3 (skip) or if verification succeeds.
/// Returns false if v3 tx has invalid or missing pqc_auths, or verification fails.
/// Each input is validated per-input (scheme_id ∈ {1,2}, key-blob length bounds,
/// and the hybrid/multisig signature). MSW-6 (PQC_MULTISIG.md §16.3) withdrew the
/// former tx-wide scheme_id agreement; the call site in blockchain.cpp carries the
/// rationale (the foreclosed cross-model linkage is a wallet concern per TM-1, not
/// a consensus rule).
bool verify_transaction_pqc_auth(const transaction& tx);

} // namespace cryptonote
