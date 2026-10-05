// Copyright (c) 2025-2026, The Shekyl Foundation
// Copyright (c) 2024, The Monero Project
//
// All rights reserved.
//
// PQC verification for TransactionV3 hybrid signatures.

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{

/// Verify the PQC hybrid signature on a v3 transaction.
///
/// The per-input signing preimage — what each hybrid signature is over
/// (FCMP_SPEND_SIGNING_PREIMAGE.md §1.1) — is derived by shekyl-wire through
/// shekyl_tx_pqc_signing_payload_hashes (CEN-I17; E6 slice 6 commit 7). This
/// file hands the transaction's bytes over and verifies each input's
/// signature against the hash it receives; it assembles nothing.
/// Returns true if tx is not v3 (skip) or if verification succeeds.
/// Returns false if v3 tx has invalid or missing pqc_auths, or verification fails.
/// Each input is validated per-input (scheme_id ∈ {1,2}, key-blob length bounds,
/// and the hybrid/multisig signature). MSW-6 (PQC_MULTISIG.md §16.3) withdrew the
/// former tx-wide scheme_id agreement; the call site in blockchain.cpp carries the
/// rationale (the foreclosed cross-model linkage has no externality and mirrors
/// the opt-in scheme_id=2 self-marking cost, so it is a wallet coin-selection
/// invariant — a blocking E′/MS-5 ship gate — not a consensus rule; not TM-1).
bool verify_transaction_pqc_auth(const transaction& tx);

} // namespace cryptonote
