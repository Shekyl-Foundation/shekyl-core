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
#include <boost/uuid/uuid.hpp>
#include "shekyl/economics_params_generated.h"
#include "shekyl/consensus_constants_generated.h"

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_BLOCK_HEIGHT_SENTINEL            CRYPTONOTE_MAX_BLOCK_NUMBER
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     3
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10
/** Depth (in blocks) below the chain tip before tx verification data may be pruned (~7d at 120s/block). */
#define CRYPTONOTE_TX_PRUNE_DEPTH                       5000

// MONEY_SUPPLY/COIN/emission constants are generated from config/economics_params.json.

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
// Display precision and atomic-unit constant are generated from config/economics_params.json.

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000) // pow(10, 7)
#define FEE_PER_KB                                      ((uint64_t)2000000) // 2 * pow(10, 6)
#define FEE_PER_BYTE                                    ((uint64_t)300)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000000) // 2 * pow(10, 6)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000) // 10 * pow(10, 9)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)2000000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT         ((uint64_t)3000)

// Four-component economics constants are generated from config/economics_params.json.

#define ORPHANED_BLOCKS_MAX_COUNT                       100


// Difficulty constants: LWMA-1 sources N (window size), T (target block
// time), and the derived FTL/MTP from `config/consensus_constants.json`
// via `shekyl/consensus_constants_generated.h` (`SHEKYL_DAA_WINDOW_N`,
// `SHEKYL_DAA_TARGET_SECONDS`, `SHEKYL_DAA_FTL_SECONDS`,
// `SHEKYL_DAA_MTP_WINDOW`). The inherited CryptoNote `DIFFICULTY_*`
// `#define`s (V1/V2 targets, WINDOW/LAG/CUT/BLOCKS_COUNT, the
// V1 BLOCKS_ESTIMATE_TIMESPAN alias) were deleted in Phase 4 of the
// LWMA-1 migration; see `docs/completed/DAA_LWMA1.md` §9.2 and the
// `docs/completed/DAA_LWMA1_PHASE4_PREFLIGHT.md` §3 disposition.

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   SHEKYL_DAA_TARGET_SECONDS * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT              25000  //max blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week


// 2 is the out-degree of the (approximately) 4-regular expander stem graph, and is
// load-bearing for privacy, not a tuning knob: 1 makes every stem a single-node
// black-hole point-of-failure; >=3 fans the stem toward a tree and leaks to the
// first-spy estimator. Do NOT raise this to harden the slot-occupancy attack
// (ProxyMark / W3) — that trades a demonstrated active attack for a real passive
// leak; the occupancy defence lives in peer selection (g_max), not the count.
// Derivation and guard: docs/design/DAEMON_RELAY_PRIVACY.md sec 12.7.
#define CRYPTONOTE_DANDELIONPP_STEMS              2 // number of outgoing stem connections per epoch
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
// The fluff probability (20 %) and the fluff-flush delay are Rust-owned and
// must not become macros here again: both live in shekyl-relay-privacy's
// DandelionParams / FluffScheduler, constructed inside shekyl_relay_zone_new
// (only STEMS and the epoch pair above cross the FFI). The inherited
// FLUFF_PROBABILITY / FLUSH_AVERAGE macros were deleted as dead — no C++
// read either — and the flush comment was wrong besides: production fluff
// delay is memoryless geometric, not Poisson.
// Derivation and ownership: docs/design/DAEMON_RELAY_PRIVACY.md sec 10.5, 16.
// The stem embargo is NOT a constant here any more, and must not become one
// again. The inherited `CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE = 39` did not
// follow from the derivation printed beside it (the formula it cited gives
// 16.61 s; 39 s reproduces only if you read log10 for ln), and it was drawn
// from a Poisson under a derivation assuming exponential survival, so the
// backstop it exists to provide never fired. Both the value (now 190 s) and the
// distribution come from shekyl-relay-privacy's `EmbargoTimer` via
// src/shekyl/shekyl_ffi.h, where the number and its
// derivation live in the same place and are pinned by tests.
// Derivation and guard: docs/design/DAEMON_RELAY_PRIVACY.md sec 17.

// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

/* CRYPTONOTE_FORWARD_DELAY_BASE / _AVERAGE were here, and Q12-U2 deleted them
   with the mechanism they timed.

   They delayed forwarding from i2p/tor to ipv4/6 "such that 2+ incoming
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
   the wire observer and keeps its own constants below, untouched. */

#define CRYPTONOTE_MAX_FRAGMENTS                        20 // ~20 * NOISE_BYTES max payload size for covert/noise send

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT     1000
#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT        20000
#define DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP       3
#define DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP      25
#define DEFAULT_RPC_MAX_CONNECTIONS                     100
#define DEFAULT_RPC_SOFT_LIMIT_SIZE                     25 * 1024 * 1024 // 25 MiB
#define MAX_RPC_CONTENT_LENGTH                          1048576 // 1 MB

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

// P2P_DEFAULT_CONNECTIONS_COUNT is gone: the default outbound connection count
// is Rust-owned and reached through `shekyl_p2p_default_out_peers()`
// (`shekyl/shekyl_ffi.h`). Every relay-privacy measurement simulates the
// deployed out-degree, so a value C++ could move on its own left those
// instruments free to describe a network the daemon no longer runs -- F-7's
// failure mode one layer down. See DAEMON_RELAY_PRIVACY.md §70.
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_MAX_PEERS_IN_HANDSHAKE                      250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       8192       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     32768       // kB/s

/*! How long a failed address is not retried, on the PUBLIC zone.

  An hour is right here and is unchanged: on a clearnet address a failed dial
  usually means a down host, and not retrying a down host for an hour is cheap
  and polite. */
#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour

/*! The same, for an ANONYMITY zone, on the FIRST failure. Doubles per
    consecutive failure up to `P2P_FAILED_ADDR_FORGET_SECONDS`, and is cleared
    entirely by a successful handshake.

    \note THIS IS NOT A LATENCY. It is not derived from how long a descriptor
      fetch takes, and lengthening it does not give a slow fetch more time —
      `P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT` governs that, and measurement showed
      fetches to be BIMODAL: under ~30 s or never, with 30 s and 75 s timeouts
      producing an identical failure rate.

    What this value must outlast is a TOR-PROTOCOL event: the window during
    which a hidden service is undialable because its introduction points have
    just changed. That window is why the constant exists at this size:

      - roughly 1 anonymity node in 5 fails to publish its descriptor on first
        start, while reporting healthy;
      - the remedy is to restart tor, which republishes with NEW introduction
        points;
      - dials landing in that window fail at 55% against 13% for a settled
        service;
      - and under a one-hour suppression every node that dialled during it is
        blind to that peer for an hour, so the node looks broken and the
        operator restarts again. The repair sustains the failure.

    PROVISIONED AT THE p90 OF MEASURED POST-RESTART RECOVERY, NOT THE MEDIAN.
    Twenty services restarted with the same keys recovered at a median of 96 s
    but with a tail to 262 s -- more than twice the median -- and the asymmetry
    is one-sided: a window that is too SHORT retries into the same dead
    interval, fails, escalates the counter, and pushes the next attempt further
    out, so under-estimating COMPOUNDS rather than degrades. Over-estimating
    costs only a slightly slower first retry. Same shape as F's provisioning,
    and the same direction.

    p90 is also the largest quantile the retry budget admits: at 240 s three
    attempts across twelve candidates cost 3300 s, while provisioning at the
    observed maximum would cost 3720 s and exceed the very hour this constant
    exists to avoid spending.

    \note An hour on an anonymity zone is not merely impolite, it is
      DISCONNECTING. With a per-dial failure rate around 0.15-0.23 and F-8b's
      floor of 12, a node reaches the floor only if at most `A-1-12` of its
      candidates burn: at `A = 15` that succeeds about a third of the time. So
      below roughly `A = 19` the floor is unreachable BY SUPPRESSION — the peers
      exist and answer, and the node has blacklisted them — and a node below the
      floor does not stem on the anonymity zone at all.

    See docs/design/Q12_D6A_PEER_DISCOVERY_RUN.md sections 11.5-11.12. */
#define P2P_ANON_FAILED_ADDR_FORGET_SECONDS             240         //4 min = p90 of measured recovery
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAG_ZSTD_COMPRESSION               0x02
#define P2P_SUPPORT_FLAGS                               (P2P_SUPPORT_FLAG_FLUFFY_BLOCKS | P2P_SUPPORT_FLAG_ZSTD_COMPRESSION)

#define RPC_IP_FAILS_BEFORE_BLOCK                       3

// Shekyl protocol version. Single integer, independent of software version.
// See docs/VERSIONING.md for the full scheme.
//   3 = FCMP++ curve tree, hybrid PQC (Ed25519+ML-DSA-65, X25519+ML-KEM-768)
//   4 = lattice-only threshold sigs (future, pending NIST standardization)
#define SHEKYL_PROTOCOL_VERSION                 3

#define CRYPTONOTE_NAME                         "shekyl"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define RPC_PAYMENTS_DATA_FILENAME              "rpcpayments.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

// Rebooted chain: all features active from genesis (HF 1).
// Only constants still referenced in production code are kept.
#define HF_VERSION_DYNAMIC_FEE                  1
#define HF_VERSION_CRYPTONIGHT_VARIANT_1        1
#define HF_VERSION_PER_BYTE_FEE                 1
#define HF_VERSION_SMALLER_BP                   1
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       1
#define HF_VERSION_EXACT_COINBASE               1
#define HF_VERSION_BULLETPROOF_PLUS             1
#define HF_VERSION_VIEW_TAGS                    1
#define HF_VERSION_2021_SCALING                 1
#define HF_VERSION_SHEKYL_NG                    1  // Three-component economics: release rate, burn, staking
#define HF_VERSION_FCMP_PLUS_PLUS_PQC           1  // FCMP++ full-chain membership proofs + per-output PQC keys

// FCMP++ consensus parameters
//
// Output maturity is enforced by universal deferred tree insertion: outputs
// only enter the curve tree after their type-specific maturity period
// (coinbase: MINED_MONEY_UNLOCK_WINDOW, regular: DEFAULT_TX_SPENDABLE_AGE,
// staked: max(effective_lock_until, DEFAULT_TX_SPENDABLE_AGE)).  MIN_AGE is a reorg
// safety margin ensuring the referenced tree state is stable.
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
constexpr uint64_t FCMP_CURVE_TREE_CHECKPOINT_INTERVAL = 10000;
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

#define PER_KB_FEE_QUANTIZATION_DECIMALS        6 // Keep fee quantization at 1e-6 SKL while display precision is 1e-9 SKL.
#define CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES 2

#define HASH_OF_HASHES_STEP                     512

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16
#define BULLETPROOF_PLUS_MAX_OUTPUTS            16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500 // the smaller, the more space saved

#define RPC_CREDITS_PER_HASH_SCALE ((float)(1<<24))

#define DNS_BLOCKLIST_LIFETIME (86400 * 8)

// Legacy Monero-era cap was 1060 bytes. FCMP++ adds per-output tx_extra (tags 0x06/0x07):
// hybrid KEM ciphertext (~1120 B) + PQC leaf hash (32 B) each, plus pubkey/nonce/padding.
// Worst case BULLETPROOF_PLUS_MAX_OUTPUTS (16) needs on the order of 20 KiB; 24 KiB leaves headroom.
#define MAX_TX_EXTRA_SIZE                       24576

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_SKL_PER_KB = 500; // placeholder
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000000); // 2 * pow(10, 6) = 0.002 SKL
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000); // pow(10, 5) = 0.0001 SKL

  uint16_t const P2P_DEFAULT_PORT = 11021;
  uint16_t const RPC_DEFAULT_PORT = 11029;
  boost::uuids::uuid const NETWORK_ID = { {
      0x55, 0x6C, 0xA9, 0x70, 0x8F, 0xF9, 0x1F, 0x7A, 0x40, 0x69, 0xDA, 0xF3, 0xFC, 0x55, 0xBB, 0xBD
    } }; // mainnet network id (rotated v3.1.0-alpha.6, fresh-genesis)
  std::string const GENESIS_TX = "033c01000005808095e789c60400e3ef622d8e76ec7efefdc7e2ea312e00aca8768ae2524563fc5bbd45d771551b95808095e789c60400c70960e3379184b3fee3a9791634097c5cffb955ebd6b5863cee2b165aadef3128808095e789c6040072383c8ddb95c23201607c657d0e6a43c5920e98e857e7113c654712ea8f59b374808095e789c60400da1f56bfa2daed6849c24bbce9d0b730981d4a7c6ca86f1e2806b4ddca49f79b3e808095e789c60400c7dfb5dd8a7df132bd3f44af33eed70e15720830a77438014e500f4771d679f97ba72d011a8cb3e68c291b49a449499741facdd19f9195174f1f37c5a5d76485c3473c9706e02b3e7c32ef1d5b88bdaa64fef5763991bbade3b2b1f14131a32e0afda337cfa15c2747da2e17cb99d8990acacf175fc520ac77cb61194a0df12f71c6f4860ad8eda5bac76c0120f8c2c53f446d011e8c3db045b1e17cb491ee95feaa68c25ba2183c530958da35f12517bcb7bc2de035d07b41c7ed510c4d8d6c8b524adad463ffe27411fcadde8043abf77fe045a5e99da15f31b0ae07c32a89df5b053a94e6625e3b6809deaa276c40ee0efc88edd68b6c6d79632b2f61bf2e7b9d1178e6ac07060375fc66b820f4ac12f2e3b7ab109f8686f8f649a27f518fb5ac77e567f1f92cabac11d9bc0184efc465913982e8f80d0c9034e6579677ca1c1d81f80687de913c78570e2315a1940009ae381fe7e50e829377505c7da56f1bdd783084ae61779b66be144ac1d566cd7b1c09f7386cabd7d17248adc82385d31f0bbff90df6efd3cdd818f4c09eb23713333cfe015d7fa358d1cdc76ed0f0ab6dcc7b3833248bd5e0d9f0b05ed93d0a0a6d8c8108e05e3daa17f96c7a8c7303def291344f84de812c52e6c4f4bec6f2d5549436d20ab8170200396c0c352d880d3e625858723aac69c3c30f25d61725fa19b4ed54cc8e61b2af1c2ac8db093cb2a363fe0cf21b70a9cddac8f261a360b687508b93eacd4f845967dd10ad309630cbe94cdc59cbeb8a324f99a9e30206c6cba897837098d73d262f67d999f7a605ebcf25ce55324d9c926d62fc2f00553aaa78cd39879ecb44522d47c8895eb8b1de008c549a477ec63358553d83999d24c62b3c6aae7631e6f9c5df0b653e9481859c0421f338921abc0086fc12838de606762d21fbe7afb08ba3570a2c5918fb346715ffa8785e744984f8e1e8eda3fb51083e20611802c2b31591d2980098e901b3d5387a69e09513858556111677d01a4bd1be0a1be407704e6c797c3d87cc65d3cb95af31176088cf60ed5c6985ce1aa4d4e40e7d798241a0263c2d01b2989e7b0d37cee47a283cd51b990b40dc5fa14326bdb106bb55e7e940abb13b8e95eba4ff7c06a909b5ed5caeec5de99a42cfaa7d4356c965ee1dd0281bd076e0f5ff11cac8e52b24c43c62e75d6218440027bd3b2a11196499a54b944582dca90dd9af64d05b8808a55c2cd7c40dd746dfa7d75e034b23c651b3361293f121f0976adabd117adeda0075662da9bbe8584a97d870e0bbb22a188b57459028925b65df2adf99e2e139d237805e8e1b08161cd5abdbadd4921fdb8a09c40e0255ee64dc9d4c24506a6892961b0a87c24521f6e54a360d2c851166b7e51f1adde29e16940171b29fc528f3f2175b72c39d7ce9be463ded6d816092db7c1c18dd7129e3fa7731ec7787aebbeac7868622c28af7f8159b91bc6536e026d80b067f6f5f59dcfe4459158c4e5ff7bd348f84ab610c992b7eb1365c65a123b26383e31839e7fb9aec00e0d54058567f60e39e55fda4d329735a4e7572c0a58cd7221aac9033d075c1edc6df61afa9d15d27cf1c052605ad5890a40a80d951426f400e2783cfd44459ea67377b43987b520189d4151aa03c3856147f9d2da4a9e6a979eb9e6eb225dbf3a6796437af2b75d72d504ef56d190db56a9a356ab108eb2c666e3fd05edf14e8639b639180bb52063e6f17e0898cf9e779bda2bef665c9c3e42651944ba21f0bc349d6e77697318a19bf42f80fcd9b6e4e9b343675b4f83bff4c315ccad100597c7566380797040a5b9b6938cdc8bd10270c3a5ef37bc2063b6e88c8e2a8c6499ff2d11c6027d0ba2a856327966b9d15a650122c1cdaa6bc2cb1bbd426362b62dfd3f6686484e0d7da6dabc0c3112f97d869f0c1b786c69330c9f444e85ff393f6e641bbf53f8408419ab38d28cf3e3e73ca7d4952879efbf9020f6f363259123ffacff975efec70a568bdf61aa5096109e1d43d6db00ebe53937fb4d99c9792f5d213db901a44d3d3491ef42b1c223817f1dc52f61ae645d4e474b407d84d2a93a338147622662fef14aabc9b705ff3fc3bdbe7f138cec24ad480561ea18e1683de7efc325e5dd4bbe92aa6c7fa0795a3dad2d2b46cff2df0899a27c47251f51fba3ab21bb972b314b80699c258d486b04feb91923760da18d99a6d8f62046bce4b3d7cf0d2bfcbb7f556d453762af1a3f9c11a6524bcbb22b5203f9504b430c2d0ff5b01fcdda8bd40c1c543805910b6d9e020304cd691cfc0b7cb8ab4af9ae740ab3fe57c6bf5dc94fc994c58bd3e13c75b4ac93b1f020f3ba650168de625690b96ea7753b8d2efa17bb57fd6d56fc51e4901b5e43896402b7a4e907b8c5175a4e8ffea8056b817545905edd31b7575fcc1c63390642cf0dde1912f02455d8ab0816655d759d6a0663a64e21c1d6392b0d4444aca11355258bb814d702caae226da1bd1ebf0678cca901a795e50191e9be7a34e209f0160b922c0684a6f5e6589ebfa22a3f5713059aa924980f7312c9ba7d1a79014076b74f7e4381106d7178752e469d771346d5978500a90d1c303cd394942b5c6f3817680b73c80a4cdc548e6a414324a05f9ca00da0723bbd0ab0dcdd3d57a6fb10c7005b84a3e4ebf303857ef45e62ad1719c42ce234e629b7d93def37c8a8c2a357e9039d3138fe7ee710e4e9fddb8a756b583e674bbb1824e97c5660974b93fd306452ad06aab6aff4ea8b396eca116193d87f7afd81b2125c295b817c3e99ea89b1d5c2440010f984a0e1f7460de9937e0cedf2eebbacab11778d8fd379793e39e96b222f31adb79b738e5da2b7b9e039cf5f65d51d39822aadb880ef797d0f9c8339b5df673799abe49da141cf50b8779cf004d0ef19235a61d2ae5c559267c52d08c3bcd8d75a8074814ff66263695feb33b8af837f19eb7f9aaef361e29d1134a9355aa41e88296986d676401e983b79a37a4c710ff414b437f8ba0a4bfb85f6ec36ff7f5667eecd28b9fa2c00c0ef66f3bba058a760c330456c0e4652368e19f87684e7d83fd0e0af3cbf55e9710dd1c8aa6abdbf62662138da712c90a70c27357b175635b39be956d447feadab2aba74eb797a36c2d1f1cf48d9656fd7592e6e9d3c000f4da43926153196871664db98c0ea4b70d26a112fa43ddb1d4817051f442df097759eddc2252f0bb66a7bb2708e49d977cdb60fc2651478e9fb9b45a3157500836aeed8d1581876f44b46133730c27040496484b82795b64300842b4b4e8bcc1043ba6dc0a947ae180951358c0924526f4f9e8726ec666387efafefe5bbb1c29a866b92cc13a9cff16a266424b51b15d9661c83e9c0fdaa5f095957c5140150d7b0ae7dc5e48615ec51c58d951e0491e1b9ad3cb2e8f753c142d81a98c6606d4bf055b9213ad05fe67f1ea06ca6f6a04976f24870406407356bfc62172b4e394c527ddb4f1688f9bea6e7ea9c4b1023eafeb425ac4af119d1a57268c193acefbbfe486dae9441a0eed68a6da110353a2784c9703c2f78f20bf9a200accedf1ba0492459133fbe38db1223372e5a1d2bf05b428e822d625f218d10f877635317ca6512e73ac4bb5c7bdc1841b18e7017a7e949a36f463cb1de6d4f0b5e70f71301414b6a8f62f70c17f4100a9732f425c7abe21a9743ddf4ee63aa75e40223ddc155a9a2fc65638587b48a55eb5e94004501f7afd44f505c269305f8b32c36a6442a4d029df7154701a20f1932e59015dcc7f75c3ff1a305a8e5c58a6f89dc5d90b2bd7a19b8f32748462d79ed85a75236e786a2fd18018b6f00f8dccdbc21a580685f36c1f0be920d83bc02ea7dffe2c61d3eba084a23379a7caebad8e8370ac5746998486e1a6de1c40ed5f13c682252270a25799490b124ae0c82d816f5efa7c1acfeeb8e39513a964df938f7678c0c46813ef9137b4a341e233bf892d7e3760e463a1a7abe5d43a78ae6da76e1e7d06b2a878f7f9c66bdb54007bcd3c03980077266b810ebf598b21f2af8d00d31e1298c2478a6d8a0d47c71cc55c932fb3f42c601510d397afebbd4453e575058758a855fd51d597150916a0180e588799147dadd78469bfb30bb217d9f7a4e620217fae615d79172237ba2624ee4b51424ae55c5fe548ff6e030df5b61e1b17a412a9f7e46066bb015bbe4ddfdc472a748a8a976a536ee27066e8518b977c6e200e3d809e7b916bfda53135ef76bdef7ab86672d94690521fe25761bc0591e007358b0794bc628913893c1489c3905d62f7d2f0af39822c44c57772634e54029b4b3af40b0a3aab72b6ef3c966deca1794ea1c8487b7ca32c42198868063ad7e927cc879f427f1bb98a6e3152994a678da963369453fba33b32350b1eb890e8fe2085c59fbfdf41311df5222971195190233f389a7a9b0f9b8b96c323b8d4ff35fa127b7053d5db8254b6dd6588387922a104fbb98b5af841e7d9e1e93370d3ec482cbb11b63fdb777071dbc9a920f6e58d75e057ad6f0b0c5822bdf7342ffe0d8f838849d99b163a9fccf660a55e36c86fc81baa5b307a3523bdef6ed0cdbdd0da6b5931da19200e56e5a719ee9326da3a8e9d769254928b8ca7293f7776d485d4c3b3b9eaf829f2dcc821865a2ded0327b260d4f666269571708cad180a1b91efe5db174f2a7d993bf94c889ddc7fead98456325069333962fd52fea70c39aaa2b8dad23039270b11bb0d74d56f9de7d8016aeb76c9e8ce01cd9861a4bcc5b0c71a999b886aa97bd54c73ad77de88d46f92303b74ec6f9e3e824de85ce5f53f8ed9006ad7cfcf5fc20d519bfaf6ced307d2ab3ff934a16305264633f0a74a53cdb8347e07a0a0f763ad036776bbc2afe61096c31d66fd1d815262341d52984c3a57f5f1e1afa4c48b98d1d177b007b6efbf7857c57f3c8f35a282a847ee695b50fb5c20a53e5fd0aa5338f0cb53cfdd2d8461ea248438d7a5ab6da6871ecce919682f2248eb4034fdfef8e711d718f8c4dd3d1235b37026dae799907983b942a49bb05cbb1e6c5b163758c4951d39514e83a6bf144598576156f13670740634076db9d6939282dfcf7b2c35bd973483f9753d3e791d86ac68c017f8c7b92a24b03c36a9178f2f2a0ab48db7be563d8acc2c21cbc08248cce95fab7943bf84c58c2fbe2215eac4e84e4b6e29f3141d15d4aabb566da9fbd9f91405990996e62ce26f5638afd8b39ba9005ee7677812b745e708ad977f71af0069eefff9bfa8f06affbc374d9b2d7af48f41c25fe1200392defa189a806e97c164a56a94a13b197475e031b1e29b1a41f6d4a535ab653916885a3abe8b40945d0aef440e9be9e94496c21820cf341e4b1c01f4e59f7b6b2f306c3765f5bc59b1c69e011222d72fd49a33ab78b71bd6c29af2eaf1cad2cb770b9008a2a806d5e34f3dfdc11a6010f0bc9b027aeb86b466d7c6b9ebaf6c029d96a06e578ac1dac603731bc0def1d9763454765a9439237cb3351328a633b2c8cd750fc22636f23906f5d8c0e8dce41e7119ad3ba14d61c00ece60c6eda001a30de52881fe504c593787deae0bde524046a7508c813ee2fda902fc448ab4e73170340720b524e46761ac1291d7f2a8bcbb09a120af2937d3522a61e514e94c3cf4e0599979ad0f3c7e2b09e0f3ed3330347d60e1fcce386453add10167507abb69caf89c8783e5cd3fb76eb6317a7d910c6733d6a4464286863a3357437a3e3c9afedb3fe9ad004a3960f4a8e164ad0f0e10a9ea1669a0f174842a38f99c722a97be19838722287e40c0bee905e0faa4e7645c930985096dc2020a705821ab7ed4bf6d0142e1887b54dc2fc221332ff0239aa7a4bfbf48d2d175c6d53d0be5d3f71edc45bb6c7b20edb7c2c454e545ba9b11f4c03a21691e184855c42f88fbbef93db6a2c6532d8165c21642ada7bdb81b01a01dbf522b7d5aea02b5ce23ffe2abd8c2d958c830f588b67eb27f97c45ba690c158b114ccd9ebcabebf55f1a5958123b3377bdaa3a249212fcd15807c43fead9316e5365e83a7b710ffb63dc1a6c31fbfdbabaf274563fdd3670ca9a604bab798498954cbbfb8b8555b32ef8ef1958643b2a78fbec4a1f1d6621809d199d2977cd6b3873a7c065260ce3ddc1e6172cc0edb1aa1f721fac52de5760d64ccbbcc04bdaf35729a690fb860f9e435ea0018cfed6c019942a65e99c626bc903c36a4a928a3b40a7c9cea450d82a4abdec2b0938891a73174cfd6f3eda7b73ed033ef8c337e3c96b8adabefbfb8d361c427af7a4a8d5d7147dde1679495603442f276168fbe9c2e0d53ae78d12332c44b3cdb900a0bccb8e8b3de3da5b5e5819852ba2264325bb0865c772fd4fc07b6a927641e36f401918cbf8dde3a3b3425bde200947d9f5dbfabe18af107aaeec480c2ab22bdd617e537d6bfd5ca5d722a9dbbe7b16db678da03752669963e557f752b6b3bc9b519928536bd4f00577549450bfaebbb466661530e45decd4adb4d26da7110acad3346f54316cc84634a8869a205cd6fcffcc51214b8b206ae5aa49b150ed5e6e2579e852625ce4100ff12f1d33152e2f09a593e4145068c22526813ec747d7c624327882390c0ba068a846142437e1f9ab6828b77a6c6c0cd42b8ee201c680416b4047212d754d77084269300807101a5c796ecc603068e25b1ba4cd5681e1dc39f1d8455993e34371cf53d47e098159081f950e1cd19b50fe677ea5db79a565a11ccecc7c89eb8325f855d8fba38ddb0aa0b6c0e4c4b587e153a7fb9d02021276a361e074b174c8b7ed541f35a5851bb8e67c559df021294f6fc5ae9a7e4f8c59419ba5405c63007541628dfe72992b6f01b462014e6c80b892dfc74e9337406e17ff315d42c63663eca7e33ef03ad1c029f3c075a507ff97bfb5a34291f01f646c0a09c4befb2b20f47a45aa8f0dcd7562a4ef196d74121c656520908cf70612ca7c1f1af9468757c900149615e3493a2a363c89caf7a2812f204f0e972220d62a9ab04a50f4a32aad875cdac8f20ea7e8dd590d7b09986ec0bfc3db2f8446b37fb0de5c10d1b3824af9eefa9996e16fdbbae0046db845e78e2317bb442c223687459464fc9357547fcc28f7c8210520a5a20dcf065669ccb3555b607fff4fe9390c5e4241d354476fff5a8ae655613cc619ad0ded26082fb3c58fa29d2a2481da348d78fc224833f125f33fb53b3aec6802bbf59211078358f6663fcd849295545320551c098f908e1d046bd58bfd2b40449b7b5b03fea2d81ec353a2f43518410bb95e7dbfcd3eccf4796409bd4e9c67c3492237e256f4f2782e75b30e0c8f292f40275d16c10cda297e0c65553c054e407d8b7bfe117d7be4a8988f4c6eaed650cddbab32e4b829a475d1c7cdbb6ef832da023d0b3940f627d5ceeb47513ef0954bab43e4bbdb929edbf1209af72da0b30f207f8c4a86b616ffbf4a56cc548bf9d3321efd7333381fab459967bbcae71031900a54023733470d3c67a780707cb99662dbd3c3cae3d9295ab919d655465681197b7c1751736254d2727cc3abb797221714ee49b794fc9dd928c813657bd9e64a724acd98b313c4552898ba4c639538fb69dcfb206a5204955c0adbfd296738f004c37f93e2128dd37931234c7b1961579da1a67f432ce0cd7cf014d2e9501635d12ec40c850216b617f33409d1aafc48c652ba47a4fe3295b8b83bc48e840f7a144cc8fb94827f2b00c84b4bb77f340c4b2e5c9365f4d199b835cade84a65e61ae41ba4f6715236343ba563b5a89ee17119f631cd5804e83fc9dcdc9230a69fbd642c97b8baf2d91d23398c122a86affec094ec0047600512640d636f96ef22a1cfc268e26a31f8f650a623b9cace826e3c02737f91e4adbbaafdffa52245164fcc5fc929aa62567277cc36a65bca8c254cdaf67b33b0440359219aeabe44516eb13522165d8a34a4be277b5420625810cf8b48319314195c8122f961cc8bff76dc141f06dc484607a001e9f44edfb424bbb33ad730b74f5704f5bff11b5e552bdd64a373f636e27d9171639e9b397f69e5ebff9011cc227108304eff3f152f432cda204cdc0da64d1268db6f51101742dba18fe4aca9b8a3814686cf793632fe5cb31d984a3f8073a2345815fd49dc49f2de9dcddf284398d7df4f9749997a39cfa513cb4ed07008692d1f743147791e02c7d4e01952a9f74032baf0ee890b604c86402de2eeb1367601001ae9aa7ede3133a4a96cf40aab53ce44f41f2ffdbf3f80eb66f867887b1217e3492de1899324339ff76c42d0e37b6fe65fc673929233eccd0539f19a25489ba675cc423923f86fabe24438981c7be9aaf662722ecbc8b428fa411cb93aefe0474465a21456bf331faaa45e7738fdc11d0b434e0384abaf9a190033b93b301ca7a63a8f58c6049bc50d730adf853989d02d117a8164afb13c469a3ed8fa8c6f28963e9c99576762ed7c382f2af512b4571a734519858a2c0e2ec60b9cdc28594f48dd8f20e7711f0fcd3b169ed718cc518e22816762aa9e78b9c33ff9ba1d1a31bb617029f855624cdad620fba11f015ecc66669fa4c6233d972b";
  uint32_t const GENESIS_NONCE = 10000;

  // Hash domain separators
  const char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
  const char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
  const char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";
  const char HASH_KEY_RINGDB[] = "ringdsb";
  const char HASH_KEY_SUBADDRESS[] = "SubAddr";
  const unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  const unsigned char HASH_KEY_WALLET = 0x8c;
  const unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  const unsigned char HASH_KEY_BACKGROUND_CACHE = 0x8e;
  const unsigned char HASH_KEY_BACKGROUND_KEYS_FILE = 0x8f;
  const unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x58;
  const unsigned char HASH_KEY_MEMORY = 'k';
  const char HASH_KEY_MESSAGE_SIGNING[] = "ShekylMessageSignature";
  const unsigned char HASH_KEY_MM_SLOT = 'm';
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

  // Archival serve-credit vin (gate-2 §5.1); bounds match shekyl-archival-retention::wire.
  constexpr size_t ARCHIVAL_LEAF_BYTES = 128;
  constexpr size_t ARCHIVAL_MAX_PATH_LAYERS_PER_KIND = 64;
  constexpr size_t ARCHIVAL_MAX_BRANCH_SCALARS = 256;
  constexpr size_t ARCHIVAL_MAX_HOLDINGS_SHARDS = 4096;
  // Archival credit-wire attestation (ARCHIVAL_CREDIT_WIRE.md §3): the coinbase
  // tx_extra carries per-record kept headers (p_id·s·E·kind), each
  // ATTESTATION_HEADER_BYTES; this length matches
  // shekyl-archival-retention::attestation_wire (ATTESTATION_HEADER_LEN = 49).
  // MAX_ATTESTATION_RECORDS is the genesis-frozen consensus cap on the attestation
  // carrier — the coinbase has no other tx_extra size check on the connect/validate
  // path — bounding per-block admission cost (one hybrid-signature verify per pass
  // record) and the coinbase extra size (256 × 49 B ≈ 12.5 KiB).
  constexpr size_t ARCHIVAL_ATTESTATION_HEADER_BYTES = 49;
  constexpr size_t ARCHIVAL_MAX_ATTESTATION_RECORDS = 256;
  // Archival attestation-witness transport cap (ARCHIVAL_CREDIT_WIRE.md §3,
  // credit-wire CW-2). The block_complete_entry carries the Rust canonical witness
  // encoding (r ‖ count ‖ count × HybridSignature) as an opaque blob, stored only
  // in a prunable side table; the real structural bounds live in
  // shekyl-archival-retention::attestation_wire (BlockAttestationWitness). This is
  // an allocation guard, not a structural check: it bounds every deserializer that
  // buffers the blob so a peer cannot force an unbounded RAM/disk write before the
  // Rust decoder runs. Exact record-count/length validation is the Rust decoder's
  // job (Phase 2 admission), never this guard.
  //
  // Written as the maximum itself — r(32) + count(8) + MAX records × one hybrid
  // signature — rather than a round number above it. A hand-picked slack figure is
  // free padding an attacker may send on every block for no consensus reason, and
  // it silently stops tracking the real bound the moment either operand moves. The
  // FFI gate asserts this equals Rust's own maximum
  // (shekyl_archival_attestation_witness_max_bytes), so a divergence is loud.
  constexpr size_t ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES =
    32 + 8 + ARCHIVAL_MAX_ATTESTATION_RECORDS * PQC_HYBRID_SINGLE_SIG_LEN;
  // Transport-cap predicate shared by every codec that deserializes an opaque
  // attestation-witness blob (the p2p block_complete_entry KV map, the bootstrap
  // block_package). Enforced AT the codec, not at its callers: a call-site check
  // only covers the ingress paths someone remembered, and the next one added
  // silently gets no bound at all.
  constexpr bool archival_attestation_witness_within_transport_cap(size_t n) noexcept
  {
    return n <= ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES;
  }
  // Archival reward-emission vin transport cap (C-1; REWARD_EMISSION_VIN_PLAN.md
  // PR-E2 shim). The C++ side carries the Rust canonical encoding as an opaque
  // blob; the real structural bounds live in emission_wire.rs. This cap only
  // bounds the deserializer's allocation: the wire maximum is dominated by
  // work_claim (15 epochs x 4096 shard entries x <=14B ~ 860 KiB) + backing
  // proof (64 KiB) + hybrid keys/sigs (~9 KiB) < 1 MiB.
  constexpr size_t ARCHIVAL_EMISSION_VIN_MAX_BYTES = 1024 * 1024;

  namespace testnet
  {
    uint16_t const P2P_DEFAULT_PORT = 12021;
    uint16_t const RPC_DEFAULT_PORT = 12029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x78, 0xCE, 0x05, 0x5B, 0xBB, 0xDA, 0x79, 0x56, 0xB9, 0xC8, 0xA1, 0xA2, 0xEC, 0x1F, 0x76, 0x72
      } }; // testnet network id (rotated v3.1.0-alpha.6, fresh-genesis)
      std::string const GENESIS_TX = "033c01000005808095e789c6040017b61a81cff4015c41fe55d623e5976254f1a779ae1a9e6758b50cb015513a4037808095e789c60400948d864d2245df95241b7507ca2a86fae33d13d304731188210f29924fbb232d54808095e789c604003f325dbde4fa4adebd7dcbd89719bb6c5829f0e77fcae845c9094ef1f964fd1706808095e789c60400e103aa55c94b5a3cfa34d6f5213f06440ac3ad93716bdf452d410ed217c3bb4ae6808095e789c60400573ee311b895834a7a5d6b3b97e40482a28d69b29e7d2783990ec6805cd5b29d7fa72d012ef8ecf56da4030d5f1a6e2dc2eccb479ed1c87f7a9dc7e87d6b61df99b3214906e02bbdeab077fb2ca738acacf42e3b8c30d1f29082272f9b398bf0acb679d054c3159db5021c073c95a3adf922179dc63e215a4edef1fc1d8c5ab4ef1bdb039e6140ec03658cb282ab00eccd5b79709871e519b2a5702bee9edd540e71eefd2f3aa519c24c84a4c94b05b5d88133e8ae975243f72330f57900d982fe081d4bf403240f1c90efee3c3aaaeaee7664e28506b08f0e30f06895b580d71c940620599ebfb41cce5b5f0e433151a4dbf19c69b7a839db459f8dc2f8a81560c8dadfe6311301ca96fb9fb9f6fef2f8aeeac11fc85a39f570a8441f3c7d38f3b40f55de37c967af5a9292238ade316c0b5fb5c24c36c549b8e7c820de8116f07cabe0b83460261801fe162182fb3b537061d935cf6b560829e3029671db01f6266e2332ad3252c6b4a10c1d6f32f063c1d83b51c6bd214fab3dd2b642c30e1712da463d127cee522a00aad38e0eded2504160c31536da51a8adfc1d0774e2400de1f82751e48319d8d8d81682efa6339ec6c3a03ed50ac1d6c010de55950fcf6275f504e7dd97bb40d9630519848b1b2cac46df8aa168fabc873e7080f23afeaf1172dd06c086de9eda75f20fb12d7ec15748b1c1c2290c08040298610c265ec45e647bd140cfecb04793ce4432ad92c9ef226cad83a5218fe659b4a33d30c809f97839894b5ba8aac7695e4f3f3250326bb4c93d93120efc34807e5b3b980874b536891d17f71881a75ff3bc2d8336d05b9197213347730164dac047e7d523ca01aa085831343986df645cd0e6051e3e7c24b21b47d8fa3dd3e9401ca7f45a257a70c5ee797e2d00914d874e8cd530c2fc5832a8680f8af952dafc81f642d1b76e8d027c3b54190b9fb2442e93e68184f655246e8a2fdf9bbda0ddf50a4ebce6305acbb1aa8c5db53f88ace3455a019a13505653574761cc8e35b0a6d52de2697d738f68c177c1c7658433eff9528b9405650ceed33d1d36f55a98f42d6c3e06b76db20e5ad0c7684879267533f9bf543de2a2e9471d15b3057f2269b09692f5ccaac1e398b3518272dce12127aa27d6e5f96d2cc7c1a8bc2b30691d6db57172e6624327e53325931f454ccada4f0cf8ac98dcb6225d46bd8e8b3f316aacae7848036797f4b46c8e672c5baccfc5c49956583c7616939635e178262ed269d8c18c290820689bc095b7ed2177712a3341b8205e06836bbe8fbb4cafd6c790105853713e60beaa8cb24797e805a001b159f678d54cc71a9baa3fa0a6a32dc6a263cdb36758d6aacb1564a45ba9fefe6f0e81e1d611ecf2fa0531b15f377c5c109841e64dcca454d8caee38e6d4575df86acf5d5283d334f8ae20e2dcc82753935d98165983efe0d40b156fbb89fb8dbae292a1a8c2d61fe6d817ff4b1f856da88e030f41e68852db303313ff877bb609d1ee071d1a02cf052757c95866c1eb93d6883dd2bf0136ad51d947918d803eb786f1eb8711476cef9cd330c1442ce0611198c6f2b6b9243e3273ff571cc723632b1786d06f7c3fb35a1eb71cfdf684a2d459bd8aaad2b0d128dbd24a4de282e6fc3d2c876d5ec836dabd051908787b662e418608a75e7dbd28d16eb32383eb04f517e869994446ef7ce550f456ae88d0e3785cec16191122a3694083d3502d8953760922e08f0a2a4b204faf25fad98d0f74aa98a694c65c2e9c7bade9e0307703453c49431fb5277748c10abe1eb58c0e27283c26ff7fff74ae06ed78a82a2e897834687c50dda8c110eb44eba773b5af609b7ed42463e1f9e28ecb1a8ec5c5ef4be749b24bab0ef7b6892ad78fdf12766fcb0dc1f99ef458a0c97b3f1bf40289fd013f90bdf0b60c9b9163f6c70b5bb7095eb43a73835be0e4b531c60a092ebdeaa57a0a65c34ff29935571d47e05c3d002098e1022650902744e1ebf81d66a45c0f3d8d0a3e8afabed8d11678395d1d1f26775bc6adc1c280805878189f1e44503934e5cff107d5d42ef38466f6754674da5543118d3df7ceb143b70780db7520cf5c46a66a88a9841468215f8a9b6a096fb8508e727e59e0a024ff5ef8d9271f1a56109c142b73d9de93b8ab360b7716449351e11fdd070fdf0d6f9502da88ee59232d38e5aeefc00ffc5120b1ae93bcc098ef0b465fbb33014fdd9cd015b9db292ef1b7a687c35f0d9fc2033c96c1eece37059a5f93d6ebd294b68f8c1bf550a88e2eef58251b90c09595b46d56dc7472b24db6cf47c7bd7ee2ada3d863fac02474ad501e028aaaf26b73ca5e87cd78051cb216f5609bfddbcdb3fa5bc52d7532136b020553317fc5448dd85fc7ab4917fb0789e9bc0ffbe8ef71d454e9cfd2180d9369b920bb9e51b8d5a0524a33442d83aea8bfc334a2635e3d165fb3381e60c560632413e7d7e9dbb517cd56afcf28cc0d67185cc6c71fab3a3443dcddfea1d05273563cda396e9247a002d9e3983af3a16eb8fd5b27c657b7fb8923c6c1754b3a88c2596c7c6c6e0829bfc049e1a93623cd427dd22e8f86094bbfb97b1b3c8abfa85bdb01f226c73911c1a66129a63da5191f0dc9789907dc778373caf86a1de9fed4d9b9376493a37c16c38e3457344582d43850c8855a4f4854dd5394ff93e49a522b32c9d26c30b27d70c5bd54b785bd4dd8e5ed37d9a39beedaf6f9f3bc21356b0ef895703750d0b8f641c9544f0a71a13bcfe1b18698eddb71f8dfdc8fb0ae85946c82cf083a9f73983f038c085d511e894204935e13922cff108eeebd317cc886b6b4b9e0425c3f57437dbe3a2b6eaa9d4d9a1f06829cd7089cb360adde413909f5efddd1824e77131c4d41d21f01df588bf39624ead404682ce2b959837337f34333d47bd0a7b02903e622a044d7921237a342fd2b2de6bf0f22803b6d6fc7b6f062c9277436e5db7f4bae46cb09912a7a4b9abe648ba6c513acfc5da27cd65718bc054a356827d418c38e8bbd1e81edb8bd0f26751668664cf2a0916eb6ec06e7cf84a4eb5eea4b725231ca8ba396913f77c14e16fbf1921df06080f8ea110d862b10599b13990c67454740588f0a5eb7abd191a54266594e1cc26ce4b5fe8d37108123cad1815ac69003b50d85bdffac612ea4b24b5c2e06fabe6e1476408eccbf7bc942fed7d4f4725e39ffb63931a348b32fafc61d8976bd8deefc572a841192d3c6a79dde71637afb4a77f67d185b346de37b60150f3fefda40a7160bf0629ceae1ad3035895bae5450bc4b029bf1e32bda4196d4bf3510870e6c31cf4272f7eb42a8137ae500bbb2a8ae7b778819c44c18fe5059270803ab4ed53f8eb2b897683c397d07851c97e815611e73d3bcc620f825f5c68b6bac3f577fd1868043184c8c8733bda91de2f05ba4a5cebb074eafa11a83862d94a0bdd5f28f48e5dca69584f6ca416f2a2296bdfd54957b4d701346479107b325c79424021add9d98c38009f22cd82d07c7666f3b28a98542713ace86247f42c83a99fa811f57a0052a8f817135a37db8444f9e807fb43f73d011848b90013b75036669abb66d8d7c99fb5720d37a57629ab321832cfe9191d6c325dae14bd3bd7d2966e50e61bae0485fd7c00fa16d1159e4d7a1173731c434da5e5e2b1f387ed0422680e080e1cc143299830bc0b167b736b9a692dd17d0efed84a100b2117468ade188398b849b3df562c310a5de2f0a203a379f2ab430d782bdc17befd0d8ff2c613e5b5e26ea00d140e986194c946849ff08c0ab795d6e339dd721628873f83c48a36445dbcec13c6bbf3ca780622c2aac75f898de82dd050d52e637464d5acd934325a55a6057e7e63db3fd6c5f970edb396f7e57ce52f8f472846d6cf7e29036d0171f66462b3f1db317155b6fb03354095f1bbce9fe59873a8e9a574b3c91446cb7299589f3f5fb49d926e3c49ccf07e53a39bbe90ed38a7115b041ae2cdfc338cb42e0336aecbcf8867b8334c51adbb8f0f9c01b6db6fcd2959e63a23f8fc9d690d5c53021e390c55b78232497d4295ada5f904f39c92be0fb91e2d1a06db0019b4ce0015d3933948d81ccda1ba4fb6027d4198d12cbef9bc43864216410d0164402f7e6179d1ca60cd6379381c0834ee2d89591c402a5ed4817c9f5b0352b9339f1d83f3e905181ed47796115ab202fd36daac1bce3e34227e32181f520b35a1fbb4e33fd84224a314ac65c323115a52fead3d2c6404b77dbfe60c061aaaa43744dd61c41f4970b021095f7ea8b6dc8713046e7e3a3895711f86c424c207cdc4245b9817db2171ca1bdc422da6c551ad65e76871b07eff288f1bdab4753581794de4b19835d50d7211206aa512cc6bedd91296dfeb43702dcbc196c3c49a99387369d66cec278d0561238ae62d3a53f61fb983bef78bca9f7a59576bc80b21021496ae273f1daca183accd0d68612dfa7165a48f53f0da5e1d9bfa858a2659b643fc2d7b91b5231d578a0b536bf766803ca46b0117076d33967515c9beabab2df056b3a9894b4f27e4a09350ccd62a4015c9127e3d92d6680311e4afda16fbe62c7014413537f0818dda54072a8c93124aaea2f5eef7c3c0cf11f95c26982f33d09f918849d5386e5f3ed60e6f13b13cbebe7f8747317ba4c864e82a2f1ade6e0eec777f8886758e9559c1288696077591b2adc71549b37c878ed3ab6d94f34a1bbaef807a3d31b2fcce90828754ad5b106eb3d3b2d7558f37c1a0749e4f8a613b237e2641fb3d04e22c173188f765decebaff635409b45d72c5a5dc91786181d324980f8ade2be0d259708af630b0059edc2a8d4d02d5830df6262bd9ddbe8ff00f5662cabfcd2ea30771253b9559208a3fe723ae3aa369d13e9e370cf85438b8f663352fcd6dcef93e882adb15a6b7762d15254e4598dff4eebd956706409ebc6ee444617c90dec29fad4a088ed1e76a879819d49ea785327304d41e1afaa2cdcf5f9016c6d0de1d5716f274d13b76225ee01783eb893ce50ef457d986b0ce4ca5fab288acfd0c5cd64b4092b76003c2c76e3e5357536e56f54968301e2437f38f1e0faec95b6c4661b7573ae43664c4056037da1a2c8a12706eba23486b252cf8185e811b45c2696715c6cd1bfd1223c04a108ae32d0047689ada7180ef7e99da44b3ca3159a25e9e34c55f9234ea848f78d8cf2193a37220b3c3e0c95f505267b943d2e2d1cc8b31ddb5e4e007f941942e277410c20c83051fd23734dd6bf1c04253ab5d244c99d287786105668ce196a83984cd3f1da14b2021809ed7b93b27dc1f1b76ba1fedea27514379ce92fb4591f9374b3dd28c9d4f94686da2d42f0b457f01786de15044783e60ac28ed49ff7a64bbf32f23211748c551466ee87775477dfac906c4ecf31d9d3ca5c1936b653673a93552e67359be77dc0c082002be26b7758da6e802eb6c4f92202726872296537913e766bc1e98e91cca0897cccf9e1a1e1f1710a0b5398e34238f55938a01e23d19660b154182190c64d102955c0ea6cc9d745d6b625925d8e70f477ab06dae246a0c878e14b8e28bdfb361e07f56c94c38c86a27c71b1d85fb6f36cfe2a645dd5bd3f2371db78ce4aac32d9d222822e1c136eecc10effbaf56728b401efc22ff1c52c00b64a63677ae49339405afddef90511978e459f9ba046e4de7993cfba2dd584ce500d964d13f11a922177a1a4e35505b49194b2b15a0c5586728299ef5bfc25df9c0e5a72a23313bb51b8bd0ae0977adae4f9cc7fdc731e14d6c971b9d54c25453dce53caea39b477314d206631dc5401e7ee7ddc31ecda345b0066a1a5a06d203e9c85a208ce0ef95690a4ed3b31be1d058c832e429eeb225d894e5a495be95376231279a61c8653ee3aa663c3563505fb326f73cae6d2b2d225e2ce5dfc1fc9f2387208dd953121aa8e93deff33e89c5d364372b766a29a54c225c7baaeec5081d739d3e35b9cd9ba07efc14acf4a40071cca5e0c7a76b428ce5148476c37924f62ea9878948395460c062b5cf3f42b8e85cd5c412a2d05d813ca01f92854c4f0abdbf8544795b067f8deb3f87b75ca1c6763d0ed22c3987e135ca269b19d589f2a2a1c98b59a91f52004f4af51f250ff5e1384bac3774e5de0fc6271fbe1ff2b5c46c0b9ffbc806e40686c60736c2a29a61753379c5150eb336c3cb4f1d1c25336ad9dfa794f3b581c680db249c0728721b346af7d7f4f1c931884d2727b42cff1c104d1a8f1d2b1f4fe7dea47fcba5d60d71478da424b4da95f508c5973c24a537c729027c4af81df49c54d668040e126b4e0e598d813abe96ff1fbab33b5092a297d80c25b4329f376d5a1f5bec5da555d53b6699430495e069c4498782faff1c0fc0fda500c19f651b439cd6f8c354a7a5086ad5ad5fddef1fa2a3248ae31d16993e12f0523247c643cbb307b38bae7454b747e2952674bc5edd4e25ebb741ee24bb4ae216ceacaea5c6be3b82a557571e018cd5a25a4233c6306981947245e5e9eaf0f9b0124459ca57fb70c7a65e3c034218c03ca995b21e43a0b3234b3709c3b6ad797c916491067f771fd3309a1e1f281ddec6364a1302322abc59cce507b81554848ba78473cfb39fcc2221c8c7d50612b7ab0a2882791af1e97321645ab80f00b6e821090db087b98f45a6f9dd25c87e58087103679dc1271712f6b5ed6f719bd8e1e5cb3784cd94e55764e7a00d58e837e02a8046d77287b1cfdd94c76ab86c28db48ae292009f3250b4c1e14e00c1b6acc157b6e1d0c930395753134d0b52f05ede8ee12f514e4a7cf51dc112940db09508bb301bdc01a6412075e4acd7bb372c7633a91c97ea08eb244f077a761763c25617f58887df29f52493c18e9af3e662049bb6be4729f14fa0958abb5ddb0ff0df13ff5d79999b4834faaee308907e7665ae9b218e003ac4b8fa75ebae6d56b4272f493098c118594a48526562383bc2f061bf88d3c6a6ae74ce1e2549291da941f30c34172a636c96bf5a5f75a9974dae43f4cd54d105831e7a5610a45dc9cea53035462f5328beb555a968f72f53be4c5cc83473b263388001a7051ef10d04cfc54f6a448cf3970450fda803aa51eaa2f393035cc2715e92f41082ed47e94ce424dc79b12adbd4a612cb482172386e39c9c590fd47f861d865c8aa33fda327bced003907492e0f5d555321ec38dcb54bd4058f740df8af4b4904e573c8f81e1b65ed7c1ab54023c99b5a20aa5bcf52d486c4aece13079229e642b79cbade34ab5f1cb7b5ced51363df55ffab409a2e8cff8b4be03d5b9c4a79174e8f6d2be8201d9314d8a8ac6484cda7fb9f9da8e78ac9eda6552a98ab66b2839aef155fbe0f6a10f85fd272d14995cf971354742d21197c72dafcaa843d81cf49c407f5ee614c0c11ac1edc04d3232806ff8e75cafe1da5cea67464f85dbd03dfaa56f824c3aeb245e0a690739485f474acd9e750de8caa4d3b7caca219e3a643054b0189e3ffda06845140c486053e0c8d54bbe9ad1be0072d6be63c830fafb600c2fb5acf7e26c392b0f5784502261fbc94c5b6809df8302658c1624aaad65e0506623ca043a03fceb3d210b4b97d188aef683e7116f45778d74eb0e5d1746d76b65538eae7864156909349730e3cc062cef8e827d9a899f799718f0684058ecc5741c6f2fa1209f86753588f9242b70cbbedecd949dd08d13d1cf38fe0c5990ce811843074e475c9b6d8d37be6e93c01c0b50c5fa6cd769113ad163db584c576eea3c8378d74a678615153df9e2df9ffa00da1fa527dcdb2120fe04c759642905ce4cc520dbe36123133079228e7c9f98e4915236d0a7c7d4feca84611df7090011014b97756b75e6aa6c307c101de50b8ba80bcd531d2e5c0825dc76e498b25cc73fa941a30d27fc8d99aed5f89fc40c27724f433f36c1a58ca963265db7b26ea56dde3f98e35f03f8f5cc85f9ac1c77d52291230a61f7045a1e8e651a02ff48cbf0e2607a001f1a762c28b737c56338e4ff628f205b402422be22d2562c21fb6a102ee64e0242675c8b0cbc4c95aaf1c56710a7e6a52e5db79a0d1b4624f8bcc5b1dbc3df030664a451b88d3398ae6c1415dc9b2af2b79ee32b521ec53929275b4804797a073075436079d668fe7d11662cf9975c5106bd0a28dc8a7732810e3cd405c430a59dd83b6626748208ac13fdf5d9881348365ebb5b0b8eb4a680bdaaf5d3ee6141700b4216a369bebc2589a6b46d8d4bbfdc61ede6ae8302f06e42ea356a09939f991b65747f28e28ab16c34ec741abd88958133866ceab5c30a93a393b87a2fc806c85868b9815c075e27d8f9b5700e1ad79b0a66a57d7d3b203b39e438f9afb0a70fb9e9210f249c4964546b8ee6f3e98dbfe8715f777136fe990b9d8b780a7fdb62d40fa31b0e5729de8c880efc40622879b92240fa2406e5de4479f91c43c1746d2db73c33fc7f77f400ebd9bc6537086c3fd9c14374116cf488f1104ab4f60d9c7a14976fda744b7ca000ea3ddf308170c20f67bf056343cdbeb3db8dba610d5e0fc286c49ee5c6c437599f7d3aa2a94bf97734d92e3541f4f8c";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x2D, 0x21, 0x97, 0x54, 0xA1, 0xBD, 0x79, 0xBA, 0x05, 0x40, 0xFD, 0xFB, 0x8D, 0xC8, 0xA4, 0xAE
      } }; // stagenet network id (rotated v3.1.0-alpha.6, fresh-genesis)
    std::string const GENESIS_TX = "033c01000005808095e789c604004c7855f2b5c11f7deb3fd9d348350cafd374d9c0289a86fc4138f46b4440fa708e808095e789c60400a18e066bef2f266b5157d1e79108e13bed568ac778610da820a6f40476431db381808095e789c6040043b278518a8df24dcdbf17efc051162a633ba117d762b0ddaa735527588e86ef5e808095e789c60400374253aa6bd07caa03ca7898df8c837cb467b2f936654c331a72e54d134f239d93808095e789c60400e5d181663ceaae560670ad43d661517753e07b638849f00521fa4f52c9c30d6846a72d01ad22f026b767674b64ec072e593b751cc2492d6366777d911e2ef61a6bc5430206e02b80352da1f1dac7a43af5b9181767cd3a4968238e71ca3bfdca0cfb22222f023d32e0c04f2f93b11509611089a6fbb8769d7a4230fa25cfa78704a89dc05cbab22adad3ec14f20b82a56ad24643a40599c370ceff83d9549cd51f3973cf4930b9734f93e54647019398a5d84a7622fc79ab846174170f41596337a54386d6614a7ffa5b46157ebdefd18a00aec14e338c7be8aebc3436b78524926fcd84058b3d0735ab71182f55c58f4b2dffa93fa7564fc9f4e8cf9fd46fbe93b95bcb03e4aa2ad39e99db8b77e421da8deb248cee55e30ee629634f0883da680f3d597ac430d43509562f216928badff55ac80c5645704bdc41af462addbf5cf456a7b24a495658a78085a1099f094caee1fb2abe9413e3d84dc17d211f4f3993a9e143f2f847ea560f0cd541443c12e685c0fe732c9d5b7049f2fc21900e2248860f1a5454aefbc743096ed13d8c6f786ec724292f87a533686e93af4e61744bcfa30bfc9f47ba622c95385c21b7db6f4662d797e7efc55c95393556bd319f93eeedef90c3d31946e7f84e830ea7e6d5065e54bee6669b89773e2fc7308e1567ea652154ad416349806629baa25acbd7d6ac80add2924fbf80536bcb2de652f6c6d21adf797d6e6ee8b961b9db2a1a02d5006dd74510586eded67a8ff0ea74305fdaf60d68bc9f3ae173daab2640310932e6501b760f1231dc7fe8345ed533aa6875214f77e8af4c0bc57779632c8af9fa630860bcf40643a0505cc9ed63d944a0698d4f101c170bb72fcf406ffa2ab4abbd7a71a853cfa353584d01131ae072c7cfb6f9b1011f40ee7446932be407a0975c77ca7c7ac67f6ef40ab9f6eb460016fa8ddfdd647c9240d7763341509bb526b5b7ec26d4930ce9d0d592ecffed9f0774ecc8c6b340ce673f2967348d25b435f6e9a39c3005c924d3b3b1ee792a2e4dd52dd2a26cbac3e3d80bf5489e1336f3b79e7de45ab0695d5d7724e7f81e780f686e162460ba0c3e10ac0ba133ebdbb12111ccc92a9d4e627243d2bcc9ce255e896e0b38f5e6318458bd443615d3e15c9bb70240e99a6e3c3a9a0426941e3d25e37048fe629d9e133c59158fa824b6d9c30c11d71aa974c346110e8120b925f500cf944e9dcb48c302168d07f63cc4580343636a56925b0fe2a9f3dc7a6675a8325a88870faa91db678fbb50d3f6409ea4ef69e3bbcec84ed644c7d117327c36ead7aec77bed58e2b36b60a31073a286ddc09462c04d36e5443e89f7e6dc205df7abf06bbb6e8ec1f57741a57d8f5d15cd5bc230f6899a020627c109b65bce9b77fa99d7927ddd9a9895a794e33213d9ffc924a0a7ffd04506e735bf3afb44a061bcc1083a1d45a710cd7299f52d4c33a0924d5757126523c1fd90a77bae459ac49533935a874376a5cebbc026c2a5d1cf74d7f38577253b289db33488864ff0e210f8e0f95cdba4782f3b1f026c1bfbff744341f28b0cbd56f2d0fa9107229977eb0a23bafd581d089c91b95148152ddf6318fea674b389a4fdd9b48cefb11243bea1f34f4e527eec3376d89940e3595b437249d6b6054f74a6e5e5483db2d1651e83a71c3e7293dfc1198d032726a87af6a3f4b8f54e6edbaf3897deaa6e8cacb8966c2f0a61a5f8dd9aaca73cb73a8c104a88f11080c87f18f337044ac127086f7d7054a5f7cb50db57b4897c77cdef9c51556650b61bbd4adba69020b059dc8f355a1d7abdd7dabf104edbfbdf28a6ee556800a522c05fc56116b2c6ce83856409d1d19d4c3fea8b55f31a420fe2a9ad7a5403da1f649578a90280ba8c8a59f4eeaccdc90cba010692f3372e5edce100a2eb7ce768d5994237c9bfdb55a10e3e28b55770f924579953809fa6964b24ebd542fe40e85e9280553af20f4260908b09995903bc8392e6641c0f54f8411e1ca783b88f6c90cc3afc2f5eb0b7e221fc2c99e6daf0e94a50615a4b0e4db9ed715be8e44155467c209a19db24f21318b575f48f948b2674f184738baea0d124832f1909326340f8d6c53d7aed20a7dc335467a0972c72a22bef406fd80b693503fb4751ce07f49e38f1b9601c2d79ad8647e6c44f5be7370b780f29134ce1b3a712b75931c986b9483f6f2279875df25db0dde1cd47468915305a8f4089c085774db76029cd2b0475e8afe74e6e54996e22dab3f6dfdc4539277ebb152201bd0ff59d7c4efadd39e4414605235d4e119a2f034143706cdc5b6765f6c5e51f77d30d9157ac29c04836e21eb6b0598e18cecf58738414e5656b299119a0f405b3104656d75c5a2e1bb73186f17a790b15c50628818feb1694ab08e099b8a6b21c1786037400f625ebd682fab08329b742b434de42d36f8fc537d820ad0e9a0da252e00dd8ca852bf8b2d025ed95ccd9d4bd7dfd3521677974069c0cff6934863663857d32a893e78b751e5cab4ce468e9305dabc782879d2bbb07eb1fe0d91ec9796e91fa12d27c6fd8b6bcb0801b0b5154df69e7ae79a02d3d879ca46684ac6e7cd28e1b246a37fe100667d5fad98e0e56454361caf6e804d5b6a83c5b1f97b15b3097eb9a36d5483a45bd4eb0fe2e66caab4687dc26d8b59e5d281dfd53dce6c91c852f847528702552ac799a3afdeb5e458932ff7a92a75a96eebd87b41053fee0a8b7d438f63a1b6c74ac815d7d29bd356bcc8265151a0cdf065b03b664e1dd694ae37e5a8e6aee1722c78f778c5216247ad9a2a4ce97e3ef7b5a1e4cec4d988496364dbdbbede759297cd85157baf79f35c92137bb5061b1c6330941f5969c9b89af4a27c00e0f1b1764631753fbfcde0bfce47ad081c81d6cec74a041fe3f0dde5e0dbe0e3dccb3146d01a35c8e33533a3cc5f73759a626d48423a9316f3245b382007fed530ae20219b230c653c44697c95db1ed7eb44e8f61c7b85f6e4109cdac0166e0e4604f028fae28680cda1db31a68916547dd53a04f07c40ff59966f7cce6bc6d1528c089b59311fa90813e4d7de7cfd40534ad3d597c70091873778bb4c69fab9dc8edd64ee94a66f4ae4a46960b8d038b03737287b82c766cb361995726a5d148b98343709ebd2e16ae7fcc5baedcb103ca8f9474c44ea85015719f8864bec741d769709bde4774c526479204b6ebc73faf326be0af7960eb4f254b3c53d14c69b0bd803d963f59f9543daa24c9566884ee33d18498ba59305b1fcbbb7f0c170bbecc22f4b7a1a748a50276e2f7fea797193524f98cd0502b0fcc3116779ca031306335d688bacd7fa49556d3c0087ae82ab59a9bc59f0d246eeb4dbe8b782aca79db31fefedbc40d888b08f4eeff446ce34bcfb591bfb3803071bcc75ebbfd2fcb16ba64fa66262d340e47a04ed8e23da2eeecb7c53175cdde1750dc93ed27e082680181ce75d9fea664ada43d8a62fc18efe518645ddce2e09a73491ea8720912ecfa90513c16ff4b7737d4e8c8f77d00967433c4eac259856463d389fc944a23072376c27a149ab3f4a5020bbfa839b722696ecf6ba93f2da43ad7a7748a12e0daaff9b029c5c027aa4a88b55770f192cdaae1011077ca4eb77fa1947d7ffc800dab6d29d5188046682cefcd90117caf9b527d53d2b4a31aa9afe83efe558c86ba3f977bec851b6f22ca5f454b8a262778df793c14cd4185b9b6fad95f456483e21eba375ee86b51255a4b878bd5db9cef07691f9c44493a89133c6ad747bab9b8c9140eada054bfd9f3b406f429e05b11603cbd3e59f077e343db24e341cee665a54403cc121e9bc0e73c628453457a8e2ba2be4560fc2cb048bc266db4d0b406e9c75f21104bf8aa04b3a6b034522ff4770920522f96e9d8538d23f138de8b8155c7cae900624b6bd347d8ff1b09a1cd5812ce26d17ac3436d4dc6a079092205a37a6eb4b93c6a60cf37c314a4b17b63778885ac2ddc7c31906d2815cc958a1853f64e35a006e4812248f0d5f3e2d7f8f17ff1a5ce483d724ca5639a6f7959c56cb3c06919db48b871c18c95f5138063cacf55e237099893bac3183348237a2dba510a0274066f206b0d11f3420e00b2818bf0f0c084f47c1ac99ef284e60d182e633b10d3b198a917f8c5cad1d8d95e98d1f5fdeb53ef9de4c1d6d2ec71090f6b3c6a9ce2b90c21b63d2a094535b752d8e2d1baa96a93ce8538135cd5ee6e2b0f8c71b6a34f36d1dba090e068901d1647bc19efe8b67c2294c021a6092e57a05c1d5792d357872de1474058c8f2fabe530f64809050ff60482168a561979fa6e04249d1060866ee80ce97ec89a2b14f9ffb54c29cb802f4a51c8b8b24e92d09f70e828c537cedc4250bc070f5057815b9aa458795038d4b261153c3c4ea849b11e0f789d62b6c9f52a72597b0e22171c9969abc09b66a9ee228b473959bc83203651a0388c33205930da8307d8af0c1ae06dc2d62581f3c3d0979d6bd5333913149c2c77befc846cc7b4a85e24895d9304df5884c8cd0266efc80d3837d302204adee5f3bca1d7caeae26de08c6a76977f2a4f028bcc2f17d037b051dbb6e5476e4666495e8fa331174b185147babcddaf75a3895bbdfbb9c1864d3e990fc0d2d64d1c424d003a15a85ca9181d8ae0664daf2427b6ac5fbaeb41d130e19f8329ed4e8061a4e491b4ba4572471f2a1f581d7371c4a45d9d50c710d127a500601c4251491492e78e367f1e437d77e6f88252234a12406a991ae59cef9848d64fcbcc941e8b5426fe9e83ead8e137f1e89af235e54184d7fd1cb58f034140f0ae9ded8b900cfc9526e6171ef504780b782dd868d3ddb66415e69a0df1e9a9b3bae74d9c134c46e6fdf2a9c0d6614af2e5e469977eba3aba7ca5d56fefd73ce73b898f17cb2186da86dbe9da7702a1fa9d461cc6bdc76c28debd867777db69ceeeeac0fef913538af3b3772857fd36a22c758ae121dd51dfd6a84b613376a2d078649b5b94565d37e86fc96b07bd1c0fc99d34de15f94543592e3bdaf012f49ede359ef622e6f723d169e91020239b8affdb49cd1241c7b33006aeea1ed7aee98fa1f0eb7ac7a374441eae15bce0dddd3ba471ba34d793cd5a5c58a27fa248a644506b19e7584943436d371941e5ce68c665cd74b322b40bb5340116e56efc609994f8288e2d8e4a18992ee32f724ac337989843adfa0db7b84e879012d64f647cb5651aa0089779fad08b53e0b40fa4b1d4e911dfe71f7958abaf92294f84306259dbbc89eaddc9f9b5011224b83a7813065e0255ff5389fe3b1314c9614a83d729cc312da923f0cd3b790957323a127fbb589d1e5c88df74870e4d3c4fd8cf3b5951320212aef299cdbc833ae434d778b9d1c7a5df40fa7b1e1cfba967d85a165dac8d395f01656ee1777147f85b9205d3479b96e3ca03546a8ffab145f05540624e989c74a5d848b10adfda2183540ec8d04ea46f8aa580f43ab3d8f157281130936d2bc7c1ff8d40eeaa25cd672b0b7c3f4c065c0b061998c7df430b1779ea5e45f27f64666ae4b0d66ee512b97a3b295e2d4c18424886c5d0860c69ad054ba43f11280c872c3d524de49f3613ea4989abb179b5b0a4059dcf1e6067d1696e98bf6b9f4b61bd06b374dfa7f4c735d50b6031e46af94540f3a2761c61004e546690109577e1b1691648459feafbcb7122bbb14568e9980cc19699181e661ae19bbed76be65500623b571606dc07d3ded9614cc9dee7e544862ee2f63122bbaa34c94e65e6f6bb52fe9ac3f06cf4496f8e6a520e7abd5fecab7a2fdfd44d3a90890e556c731d9edede56595dd8ff80c95123c0642ad5226d04d77e9b89280c1f50eebc3576b11a5cb2f3c405e2dad815f4faaa4e5d62b501928b6946ca6be2286031613c8a6e4f5c0130bc40f7e99270503ff27a7ae2e6ca98db3ba7903a2b8c5557938f4893e3871db7a8d95256f792eeee8f03a6286d136a65a48ad25aedc3f426dab1efcfba545fb59274d01f4f5430cce2082f61f15f352721cc2bfbbade2417ce648ad96926c2db976ea669a587ce1bc50c7f357d073268c269ec5c2feab229aa269c19fb2872228168e94a61b3b50d7bd13a8064306b3eec5afb326edaad17b51fa911420d04f90f36eed46e4844515de86b5c6c4ed7e4ffdf240e117e1dc37aa3977a04f3643de8ab033588db0ed2d90b3b2c89865e0ddd3ead8131c39734d16bec30335c19af5101e822fcc6986071bf1fa25deff6114d4e70aa2a0516fc44991208e294af4b9d294fb9a9a4d79b839181d2ae89db9bce9e6806f82f9f28f12c287a7f1939b25f500395af9f2ed2e59925bf05c1d6683d3d99dd234188be9862c2e62c69fbcb4b0dd5ccd95876cb4af7196b7927408895e557a2734260433693e8296e98daf37c56c2a282e8c13ccdac3b2e20b3e0982c02ecece0482444c8729794818ce5aee6eaf7e1713aead3207e5b4b2b735dfb5061b69ec69c8317079cde7a0daa669fd7eaa24b1dd33f658074fd57b619bb34b0331437fd44f4f28aecf91d951f45a39ff54db9e172faa59292c530a4155c73393b732b613fae1ef00d778603867fb7f745dc17347cca8d1fa57053a65650b9c0bf7eefc9b8c69892eab8cbff643e66392e6909355cbc37c7e53f3d6ca27caaa8f3e59313554ddef5a4796faac70ca47d80a0ba7dde1b153839957099cddc80fb9f161285ff0b47ecd834e0888905e081417505d2ee5141420c39a4f829d19a36b789b77420245c8aa76d1c0f379d69247ba7f28b517073a3878059a02a5495ce5e18dd4eebf0326fabf217818e6a8fba1cba9e642b2567c39398478673e277c480f9729c8162aa9a36eb3bfe3a9c8b5380f2fccaca97ab4cd3e8f2fdd0a931334a248f3901f2b431ade83818cd86516ed114ed7cff62052471800b731e99134dd24b61c96a7583894673cab15909b34bd72f4ed8fec70149e3c2d66592d850e836682031b18d623c3e4ee0984ecc67c95f0910d42e4d69005bb8ac4c56c0143c66fdfa7909587c70099da1c7cab7f02493e3ca1218b60f8040d848aa3d1ccfc473a46797f4d03cea519caf762c1ae8180efea745ac2f7f4fe0957fb110547f3adfae90b59410f5a312879c676fad5f3adde3b9930e704218da6997777499fb3a8462cbd607f884b9360f819cc2e00cebafc8806747a38c4461874ebdd9814c7742713d8d221b4f4d90fbedbce70d58b4630ff64974fff74763f9ed4147e4cac27e46616651e976d9272df789af1b37a2b8d52af971f398433dc70a3ac4e9e9a38102175c6e877fcaa09ddd9314b14c19e4c9277401f1156f408fe540f98375fdd2c858a05afd90f8925f2bab61cdf5c79a3e0c3579c24667ec236ce4effa5f6b29543f2ffd433c13c145f9490aa8282662e3e39ddc6cbb37e3274cc42bfc3171553d2fdc17d58d01f1b24fa704ffc296d0368b990c9fa7e3565567eaa6dbd9a0ca54cc3a929aac78f163eb39f0a1d8df81d002b90de718cfdafd88266253981479a164461eaa6d87f641fe2e2aa4a8bb352084190857ebcf835936b3b8a6275b5447170c12f8ab10108b6d7129adf1a78baa8061895958e957c93b8ca428d3792e6e351d79f1d87856e78f2ff5383f875c024eeb6327bab27adbff581ad8d03614b41d9cb9e5f89aca1918f715ec3b8e5b463c073b22369ace14c69836602ee64b733f45b7ff906657d722cdd27af05f6bdf4bd299f68336a4dc48faf1108b35640945181dbfa3b1963aa5cff1ef04eff31980edd426b77cd3013bee447126f514a7e1a20290c3b8301cee725deb253f6422e0327db3d83cda55465f0500d6ed2a9382b4ccd6d5da86cd2ebd41c224fd187d29b7d7a9a6efa65d56a712947b15a50eb34e25e7022fd91dbc6f5cfcfa1b2689d103b6b519902d5606073c9797390141023c7756bb369ab5df8507513bccd2e47ffabcaa6a0f99826dfbd3e2c94bacf86c9b1addb5e113bb7b1d2b5dd07a0016e6b1a9a17755a1bdf754748f1af19ae667e9ed2d523a182a6390b2082ce602b4956ab925619a127872db8c7fc3f85b3d2517a57df2d7bb6fc1d518d9cef813345b9ca33f5ea711dc6763548093d1b69d04b5ba14fd19deecef8862cde29577da953ff4208467f655e623de036219ba1db1a2e4c1b1fd81b6cd2dd80dd510e6db18a9a609339e5770842e388766dc0274107f093dd22e15d79260186e42b2a4c002fca671162589849c2c637739886c34c3620e6fdf06b525dfbcceecc5bdb796f61c919f7d694fe5c3281ab19cd31da8e2c11c6c02509505d457c5e3c6d809d5138cc071a0725e3e9a521101e9ca5f82cc076907c3fccb132fdf247b7086e9cbaa01910b11be31410e398a76db1839b70f9986e4f84dc965adde101631ead4ad667599106f995a2f1a8aaef073e97237acbec025b0e6bd64ea0615ed4159e4f57a0d660364f27ee14e6eae183b9917a3d1b8890ebfd8e154ff11e39865865a9a9356f41a7ceca3639f8d080adc30142cd17ff0c9f9d8465e023897a98d16e074760e407c1eeba590a7420fc220ba6f48956b29caac12d3b3fd648";
    uint32_t const GENESIS_NONCE = 10002;
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
  struct config_t
  {
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = {
      ::config::P2P_DEFAULT_PORT,
      ::config::RPC_DEFAULT_PORT,
      ::config::NETWORK_ID,
      ::config::GENESIS_TX,
      ::config::GENESIS_NONCE
    };
    static const config_t testnet = {
      ::config::testnet::P2P_DEFAULT_PORT,
      ::config::testnet::RPC_DEFAULT_PORT,
      ::config::testnet::NETWORK_ID,
      ::config::testnet::GENESIS_TX,
      ::config::testnet::GENESIS_NONCE
    };
    static const config_t stagenet = {
      ::config::stagenet::P2P_DEFAULT_PORT,
      ::config::stagenet::RPC_DEFAULT_PORT,
      ::config::stagenet::NETWORK_ID,
      ::config::stagenet::GENESIS_TX,
      ::config::stagenet::GENESIS_NONCE
    };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
