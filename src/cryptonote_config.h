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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include "shekyl/economics_params_generated.h"
#include "shekyl/consensus_constants_generated.h"

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL            CRYPTONOTE_MAX_BLOCK_NUMBER
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     3
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10

// SHEKYL_EMISSION_CURVE_ASYMPTOTE/COIN/emission constants are generated from config/economics_params.json.

// The short-term block-weight median's window (CEN-G6b), generated from
// config/consensus_constants.json (`block_weight_short_term_window_blocks`)
// so that C++ and Rust read one value; the legacy name is kept for its
// call sites (rule 93: rename when touched). One reader: the median
// (update_next_cumulative_weight_limit). Rust owner:
// shekyl-economics::params::BLOCK_WEIGHT_SHORT_TERM_WINDOW.
#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 SHEKYL_BLOCK_WEIGHT_SHORT_TERM_WINDOW_BLOCKS
// The penalty-free zone is generated from config/consensus_constants.json
// (`block_weight_full_reward_zone_bytes`) so that C++ and Rust read one
// value; the legacy name is kept for its call sites (rule 93: rename when
// touched). Rust owner: shekyl-economics::EconomicParams::full_reward_zone.
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    SHEKYL_BLOCK_WEIGHT_FULL_REWARD_ZONE_BYTES //size of block (bytes) after which reward for block calculated using block size - second change, from v5
// The long-term block-weight median's window (CEN-G6), generated from
// config/consensus_constants.json (`block_weight_long_term_window_blocks`);
// the legacy name is kept for its call sites (rule 93). Rust owner:
// shekyl-economics::params::BLOCK_WEIGHT_LONG_TERM_WINDOW.
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   SHEKYL_BLOCK_WEIGHT_LONG_TERM_WINDOW_BLOCKS // size in blocks of the long term block weight median window
// Display precision and atomic-unit constant are generated from config/economics_params.json.
// w_ref is shekyl_economics::RELAY_FLOOR_REFERENCE_TX_WEIGHT. The floor and
// the ladder read it inside the FFI; it is not a C++ macro.

// Four-component economics constants are generated from config/economics_params.json.


// Difficulty constants: LWMA-1 sources N (window size), T (target block
// time), and the derived FTL/MTP from `config/consensus_constants.json`
// via `shekyl/consensus_constants_generated.h` (`SHEKYL_DAA_WINDOW_N`,
// `SHEKYL_DAA_TARGET_SECONDS`, `SHEKYL_DAA_FTL_SECONDS`,
// `SHEKYL_DAA_MTP_WINDOW`). The inherited CryptoNote `DIFFICULTY_*`
// `#define`s (V1/V2 targets, WINDOW/LAG/CUT/BLOCKS_COUNT, the
// V1 BLOCKS_ESTIMATE_TIMESPAN alias) were deleted in Phase 4 of the
// LWMA-1 migration; see `docs/completed/DAA_LWMA1.md` §9.2 and the
// `docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md` §3 disposition.

// The relay's constants are Rust's, and none of them is a macro here: the
// Dandelion++ stem count, epoch and fluff terms, the embargo, the covert
// cadence and its channel count all live in shekyl-relay-privacy's `params`
// (`DandelionParams`, `params::inherited`, `params::carrier`), where each
// value and its derivation are pinned by tests. No C++ reads any of them.
// Derivation and ownership: docs/design/DAEMON_RELAY_PRIVACY.md sec 10.5,
// 12.7, 16, 17.

/* CRYPTONOTE_FORWARD_DELAY_BASE / _AVERAGE were here, and Q12-U2 deleted them
   with the mechanism they timed.

   They delayed forwarding from Tor to ipv4/6 "such that 2+ incoming
   connections could have sent the tx" — a delay on the tor->clearnet bridge.
   Q12-D3 removes the bridge from the admission path: an arrival stems on the
   zone it arrived over rather than crossing to clearnet on a timer, so there
   is no longer a boundary here for a delay to blur. The latency the anonymity
   path does cost is carried by the per-zone `hop` (§89.2,
   ANON_ZONE_TRANSIT_ASSUMPTION_MS), which is where a per-zone cost belongs.

   This is the disposition Q12-U4 was reserved for, and it is the deletion
   branch rather than a derivation: the pending Q-12 item was "derive AVERAGE
   from the stated anonymity-set objective, fix the family from measurement",
   and a constant whose mechanism no longer exists is not derived, it is
   removed. BASE goes with it — it had no consumer and was kept only as the
   record of the pair, which is exactly the reason that expires when the pair
   does.

   The Q-11 Unit 0 warning that governed them (DO NOT re-couple to NOISE_*)
   dies with them and is not inherited by anything: the covert cadence defends
   the wire observer and keeps its own constants, in Rust (`params::carrier`). */


// P2P_DEFAULT_CONNECTIONS_COUNT is gone: the outbound connection count is
// Rust-owned (`shekyl_relay_privacy::params::P2P_DEFAULT_OUT_PEERS`, the
// dialer's target) and no C++ reads it; the sync heuristics that compared
// against it hand their counts to `shekyl_sync_*` (`shekyl/shekyl_ffi.h`,
// DAEMON_CONFIG_CUTOVER.md §4.2). Every relay-privacy measurement simulates
// the deployed out-degree, so a value C++ could move on its own left those
// instruments free to describe a network the daemon no longer runs -- F-7's
// failure mode one layer down. See DAEMON_RELAY_PRIVACY.md §70.


// The protocol version is `shekyl_version::PROTOCOL_VERSION`, a Rust
// constant (DAEMON_CONFIG_CUTOVER.md DC-Q20); no C++ reads it.

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

// FCMP++ consensus parameters
//
// Output maturity is enforced by universal deferred tree insertion: outputs
// only enter the curve tree after their type-specific maturity period
// (coinbase: MINED_MONEY_UNLOCK_WINDOW; every other output:
// DEFAULT_TX_SPENDABLE_AGE -- the claim-era "staked" arm was retired with
// the confidential-staking cutover and never existed in code, CEN-L12).
// MIN_AGE is a reorg safety margin ensuring the referenced tree state is
// stable.
//
// `FCMP_REFERENCE_BLOCK_{MIN,MAX}_AGE` come from the JSON authority at
// `config/consensus_constants.json` (generated into
// `shekyl/consensus_constants_generated.h` by
// `cmake/generate_consensus_constants.py`). The Rust multisig wallet
// at `rust/shekyl-engine-core/src/multisig/v31/intent.rs` consumes the
// same JSON via `rust/shekyl-engine-core/build.rs` so the two sides
// cannot drift. Bug 3 of the 2026-05-05 FFI constant-drift audit
// motivated the JSON authority; see
// `docs/audit_trail/2026-05-ffi-constant-drift-audit.md`.
#define FCMP_REFERENCE_BLOCK_MAX_AGE            SHEKYL_FCMP_REFERENCE_BLOCK_MAX_AGE
#define FCMP_REFERENCE_BLOCK_MIN_AGE            SHEKYL_FCMP_REFERENCE_BLOCK_MIN_AGE
#define FCMP_MAX_INPUTS_PER_TX                  8    // bounds proof generation time and tx size
static_assert(FCMP_REFERENCE_BLOCK_MAX_AGE > FCMP_REFERENCE_BLOCK_MIN_AGE,
  "FCMP_REFERENCE_BLOCK_MAX_AGE must be > MIN_AGE to give wallets a valid reference block window");
// Sentinel against silent loss-of-meaning if the JSON authority is bumped
// without thinking. Decision 14 (commit `6561278d9`, 2026-04-04) locked
// MIN_AGE = 5 once universal deferred curve-tree insertion made the
// value a reorg-safety margin only. Loosening below 5 needs a fresh
// consensus review; tightening above ~10 starts rejecting legitimate
// proposers' reference blocks. If you genuinely need to change either,
// edit `config/consensus_constants.json`, update the Decision 14
// rationale in the changelog, and only then bump these sentinel
// values. The Rust side has matching const-evaluated `assert!` sentinels
// (`const _: () = assert!(...)` blocks; the `static_assertions` crate's
// `const_assert!` macro is intentionally not used so no extra dependency
// is pulled in for a single sentinel call site) in
// `rust/shekyl-engine-core/src/multisig/v31/intent.rs`.
static_assert(FCMP_REFERENCE_BLOCK_MIN_AGE == 5,
  "FCMP_REFERENCE_BLOCK_MIN_AGE diverged from Decision 14 baseline (5); review consensus implications before updating the sentinel");
static_assert(FCMP_REFERENCE_BLOCK_MAX_AGE == 100,
  "FCMP_REFERENCE_BLOCK_MAX_AGE diverged from baseline (100); review consensus implications before updating the sentinel");

#define BULLETPROOF_MAX_OUTPUTS                 16
#define BULLETPROOF_PLUS_MAX_OUTPUTS            16



// New constants are intended to go here
namespace config
{
  // Hash domain separators (only values with a live caller)
  const char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
  const char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";
  // PQC Multisig (scheme_id = 2)
  // MSW-G (settled 2026-07-15: 2f+1 at f=2; withdrew the same-day MAX=8).
  // Correctness cap only (verify_multisig / MultisigKeyContainer reject
  // n_total > MAX); NOT the source of the DoS ceilings below. The C++ twin of
  // shekyl-crypto-pq's MAX_MULTISIG_PARTICIPANTS — the cross-language KAT
  // (`fcmp.cpp::msw1_pqc_constants_match_rust`) pins C++ == Rust, the only
  // check that catches the two sides drifting from each other (F-1).
  const uint32_t MAX_MULTISIG_PARTICIPANTS{5};
  // Per-participant serialized lengths (twins of SINGLE_KEY/SIG_CANONICAL_LEN
  // + SPEND_AUTH_PUBKEY_LEN). Ed25519(32) + ML-DSA-65(1952) + 12 header = 1996;
  // classical spend-auth pubkey = 32; Ed25519(64) + ML-DSA-65(3309) + 12 = 3385.
  constexpr size_t PQC_HYBRID_SINGLE_KEY_LEN = 1996;
  constexpr size_t PQC_SPEND_AUTH_PUBKEY_LEN = 32;
  constexpr size_t PQC_HYBRID_SINGLE_SIG_LEN = 3385;
  // DoS ceilings for the serialized multisig key / signature containers.
  // Round, generous, DECOUPLED from MAX — correctness is the exact-length
  // container parse, not this bound. The static_asserts make a ceiling below
  // the largest legal container a COMPILE error (MSW-1 / F-1: the old
  // `2 + N*LEN` fossil omitted the 3-byte header and the 32-byte-per-participant
  // spend-auth keys, and silently rejected a legal 5-of-5).
  constexpr size_t PQC_MAX_PUBLIC_KEY_BLOB = 16384;
  constexpr size_t PQC_MAX_SIGNATURE_BLOB = 32768;
  static_assert(PQC_MAX_PUBLIC_KEY_BLOB >=
      3 + MAX_MULTISIG_PARTICIPANTS * (PQC_HYBRID_SINGLE_KEY_LEN + PQC_SPEND_AUTH_PUBKEY_LEN),
      "PQC_MAX_PUBLIC_KEY_BLOB below the largest legal MultisigKeyContainer — see MSW-1/F-1");
  static_assert(PQC_MAX_SIGNATURE_BLOB >=
      1 + MAX_MULTISIG_PARTICIPANTS * (PQC_HYBRID_SINGLE_SIG_LEN + 1),
      "PQC_MAX_SIGNATURE_BLOB below the largest legal MultisigSigContainer — see MSW-1/F-1");

  // Archival serve-credit transport ceilings (gate-2 §5.1 / RF-D1). The
  // interior is shekyl-archival-retention::wire; these size the opaque blobs.
  // RF-D1 / rule 40: the serve-credit vin is an OPAQUE blob (`canonical_bytes`,
  // tag byte included) whose only parser is shekyl-archival-retention::wire.
  // This is a transport ceiling, twin of shekyl-wire's
  // `ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES` (pinned there by const-assert to the
  // same literal; a drift fails one side).
  //   kept: tag(1) + p_id(32) + shard varint(<=10) + epoch varint(<=10) + Ed25519(64)
  constexpr size_t ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES = 1 + 32 + 10 + 10 + 64;
  static_assert(ARCHIVAL_SERVE_CREDIT_VIN_MAX_BYTES == 117, "twin of shekyl-wire's ceiling");
  // The PRUNED-record ceiling deliberately does NOT live here. It is enforced
  // in ct::CtSigPrunable (ct_types.h), which cannot include this header
  // without a layering regression, so that is its one C++ home
  // (`ct::CtSigPrunable::SERVE_CREDIT_PRUNED_MAX_BYTES`, pinned to the same
  // literal as shekyl-wire's). A copy here would have been a third site that
  // only declared -- a duplicate across a boundary that is inconvenient, not
  // impossible, to cross, which is not the kind rule 17 licenses.
  // The DETERMINISTIC size of one pruned pass record for a frozen segment at
  // SEGMENT_LAYER_J = 2 (depth 3: one Selene branch layer of 38 scalars, one
  // Helios of 18 -- CR-D2's 1,792 B) plus the ML-DSA leg, plus the per-record
  // length prefix C++ transports it under. `get_pruned_transaction_weight`
  // needs this so a pruned node reconstructs a serve-credit tx's weight exactly,
  // the way it reconstructs pseudoOuts for a spend.
  //   encode_path = [1][38] 38x32 + [1][18] 18x32 = 2 + 1216 + 2 + 576 = 1796
  //   record      = 1796 + 3309 = 5105;  varint(5105) = 2 bytes  => 5107
  constexpr size_t ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES = 2 + (2 + 38 * 32) + (2 + 18 * 32) + 3309;
  static_assert(ARCHIVAL_SERVE_CREDIT_PRUNED_RECORD_BYTES == 5107, "CR-D2 arithmetic + framing");
  constexpr size_t ARCHIVAL_MAX_HOLDINGS_SHARDS = 4096;
  // Archival reward-emission vin transport cap (C-1; REWARD_EMISSION_VIN_PLAN.md
  // PR-E2 shim). The C++ side carries the Rust canonical encoding as an opaque
  // blob; the real structural bounds live in emission_wire.rs. This cap only
  // bounds the deserializer's allocation: the wire maximum is dominated by
  // work_claim (15 epochs x 4096 shard entries x <=14B ~ 860 KiB) + backing
  // proof (64 KiB) + hybrid keys/sigs (~9 KiB) < 1 MiB.
  constexpr size_t ARCHIVAL_EMISSION_VIN_MAX_BYTES = 1024 * 1024;

}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    REGTEST,
    UNDEFINED = 255
  };
}
