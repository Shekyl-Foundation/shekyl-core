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

// Noise cadence and fragment window. The epoch pair
// (CRYPTONOTE_NOISE_MIN_EPOCH / _EPOCH_RANGE) went with noise_zone_params:
// C++ no longer selects a noise epoch; the Dandelion++ epoch crosses as
// min_epoch_secs. MIN_DELAY / DELAY_RANGE are the source the Rust
// inherited mirrors transcribe.
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
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
  std::string const GENESIS_TX = "033c01000005808095e789c60400c55b1d9666ab0d8caa759e9860625d99423f6a22556494d295f4c1ba4bf1032928808095e789c60400baebaa50913866a9d501cd6e7d040f8db0bb83a1ee7b23fb8e2894bc7fe643eb8b808095e789c60400cd497a2edd6a8afdf5ede44686aa6354f5255b9212fc3c6f62c379ec22c4eedbe8808095e789c604001e01f50ac9100c19247e58ef269e9dea828f7dc82c286b8322282a2f20712411de808095e789c6040031d582d80d3ee3e2f42c4c5fd8965971e22a512ba9d6be362d75ecfdc55c95774ba72d016df89a70da4b0f5036d6ca5f64a29f02f87aee90944a8a7c111dac0354f54d3f06e02bed29bbf99b1de5f2087b44989cbc6c7dbd75d84440427e83b322ccea23b273110d76226d8b038fb693f6e464c83256f86a50239c5096a9a121437267d88cade6b56cffc9c7114f87f091d13897902d92ec067e009f8e89f05d2efa50eab4914439f696be3345c64b1b90433c78f5474d602dc160e9c3d2488b1d49a4b0b1a9489b2ae1a7767b8d493bd17aea77dd05b15023ed0e735c334473d3cff71f79ed6b251d4b661a08fca217255ad116d8815b239415855d8b967a979c7b16c33b73c7ae304f652757b4f8c1d890ab9f3c6684f0e7fea2db44d1eceb034f8daba592f01111bbde3f3fa13e76c5bb95f026234dcdc096b09ec81d31fd3e7c9718bdc6a9d8f966e292847b3ff0f9a1e7c22e5e1cbf2056dc3b84adfa1873f68a361627c9442b5fb8fa793b1fb33494fe4c2e27c62aa6801b3714be08854269328bac96e3c5798aabe0c1fcdd25a3af1532a2b96888a75f801d9983c461694e2cab1e1fd094d7f1428ed45d9d7cc3624594e978480dd4cbd804bd68d5019475ecebdec9da2eee7f21efb98f3d086b7a094e748c8207e16ac1c7fb1b88c1a3cb72dbaa7cb1d74b43a3df4f84d51821d9ed69ebdcd1d014d991789c65356d3ffef28b4f24d775491ec9b00f441db30e84acdd87f1841c6511a20f24bbd0c603491595b4507cd9ccccf002559976f90bdec96d017f109e57e06c084de0a7840d9aba4abeee30899c1f2686f94716adf569f1872fa10a22b001aa6c2f7524f77a6747852457b0bc3f02fbd3e9316cc21e230e3aeb9d59a32ebc50c7ca7608590aec389408d262242f48de61e5950981c94ec0009f072a56131201b4e4da8b78db02dcd4acf9d34fb1635a569cb1f54d1ef2471e62be99569441d1bad53beaa7e67235550da1b5ad660719c5f95ff4be581d2b4353889c4c86b49e0ec018a68c2db75ac1cd2d960594eb2e6454946474465166f0c73ac7bdf5075d69498d9782ba4e86e0e6ccd9ff09887608bbe970e957a7cd501639fa6afb5b14e2f173d51ce815ea1be12a7a2e4f2ea57daea80452d906b6d00a78e66975f37a699a80dd975313b7e5024250927ea9c0342c1022211de23cd6fcea395070165c8d64c55cc88c0bc4e8856458117799b216cd3d5e0e98a91b8465ff839c6b22909a35b232895b2158b20e88184c03e9584af0a84324c9d512d880798b0638278c3669c2205740d7b2f41ff88500dc7f3e2b66bcd1ddf9fcd9ec12a4632fcc9f5d30e994dcc4ebc4e87574d4c93491dda83c1db801e1376b6b98271469911c3b42881ee51c4a1c6cf8c92699f553bcd9885181f40b3cb5ab18a8f04e4b5d816da44610255e6371dafba04f09251d2818a23b52409c585134c491ee5de8a000306bb1f35d4a01ad32e896f4bd0dd398c537a00820ffe7bba91bc81a6b9d26441cb22e44c74868f8440816d1f62f5e6da41e0cfae6d3cba8b00e3cbd506622b1b8e2562f8829668bccac3439926e0b6dffc410b3616aec8b25891321fa403702be6e7806046b0da6be44a92e1575c7dcc7b8d96d27de44966596fd58d81bd87fef7386d37ec485953dc0ab02449a8604e50d7c379c4f8446a4d6bbdcbee375f90e7d8a274aecc6d36dc8a0f0f459ea50b725cf475a70f7ca48e8005ec943876abbda0d245390f14c9aa87d4319b858cb55cba168c32963522fe5172ed64f2edc36803e5a7b8b50c2143070031cd3dbca1254111f32c68a136ab2c3262d1e6f545abdb0db9226db57e97f9836087ab25d522d49d91ccb362e060a13e2a22671aa705cb2efb9eabfb698cc35663a7e6e0af5e1e5446605b9446f1223a373adad44f50fd1c771599e387fb99572e9bb61628474e23caecb3690cd9591f76864fde8d2a517339a77520b426fedf09e0820b42b7f93402a1c9464fa8d3a28c4bdfbc5c8c1c7e05629e5c39e2b2c4f5add367c72f75e80ff3c196c47183662167dd80a1680a12819e0782d45857ee534c82391fcc53d58f5a05c5ff5102cb5c86309e60421c43a20830308cb5bfe2c16f38eab86393e922935d430f61b12525be69a9f5b40eb5dfa6faca5f0724bd08c5f72246247efa8d8ecff510e8549aafd99687b2f9e99340f1b5163fd1c1a5b3d341f536f9d760322747c24901f478eb6c137807e0af8c4c340ac251ab309ff1d1c45c6d5ab129c4a04fce43e3327d8cff6babde37021de27640d6f61b9450b531acc8df78eb1cb84b5b75e8d15987a29d292f9a190727c4e78a6a5d342f1be3715f9bdc0fb6602aa46be5f572886fe3bcfce37c65497f8963b1f0ce16cd42a313a15a270fed391b5c2214ee2467c545ef12dbe2df5d28cddeb622e6d66f4fe7c2624beff49af089f0adec2774b8eceb7453f35073b94cbd07b001458f18ef5b3d01313f9a657a65460b5c2f77d57d37df7c57f4d8fc50db75fdcac0d5135766471bb612679dabfff97a7b3eea9beac244aeed18bb4a43b68418faad0224c643a96f039f5581b64c012804ef5cbad032be95aa248eb831c3a88d715d1296c795a6eca77b5ab55acf16f5152d923f68c09df2a89a89a258fdae8348e00372be7e7aecf5179c49817eab668a6cf80368bbbf15d279c4b30cb508571674f6980c2c84c1255ab5cfdc0b622aa59dd119d08a6cb0c2ee7ba142700279b0079cc245dd1dd2b1885e13c79fccf1140d0568a33978406d2cff27d6fa3068bcb274f108a6084459e6eb32cb1a8a3ead15942f3ef69ebc5840f6ab0623727a7e3f6f860c8a7c91324e4cada0016f9b744b39f2f22206ae81885ee4c994ab933123ba29919fd74a46f3943db3b1d3ff974a8b01b933b19f00af88b6987a878b3b64adf514f1b13ea2d5dae6758708685f0d0ca0b48487f67069613d1fe97e7de438f62218180e5addbb70f1d9a3953cd80a52670b5c22b8099f156571bf92ee7bfc98e60db7557e45b7fcd1730c29c30afe756357be14d6302fa82a780c5e0f8b6ed74a60c474d1cda3e994443df457fb9462279d3c95272bcd6c557c51f46e2ce273ebdbe41e4b4175dce34c8efcf82f268d65e6af2c253869947de98ca3cc4b4a6c41d5df9087f016ebcfd4f01298461b955a4b2d3ae697f9564110e627f13b6bb61e167e5b23183faaf899c6309c08328a447b9129ef12764987993ce70d68e0fcb831a39303c3d343291701f8c729cf05b1ac2bd149c65a148c430765a306e63b22229023151ff7b1aa4f95025440dff0fd40ec2ce194ddaf065aeee84d3a0e6f73d30df4eecb1217dc3be1f2ea3327b82fbae0a812ff1bb9a782e95504480afb40e9b19831f137b873ccc3055c42cca575ff900030daad8e4c2fe3f7ce6bc221ba9a80ea0e33dad8f586a67fc94cc2a72edb3fa8f98c21a8a14902356ab9b0d2d0e24b70b3f57ca5db6cb1e7a061e8b695f972d69c53614fb61f17e24591e370042981f424dcc07d9bfaa3123fb799d870cc26b86735687bb6bbd488d900522651a19a7f794941760bb58b5f662bdca775cd92e316e8153c017d7b9f03b7aaa292b4e046dc14778fba68ff6836b70dc268482d88b49e96fbcea3d25124416865e67293ab75277bcc0d33f64f45505eefb73324cd40e5c43937e396d05ef0d6aef743e96104ae0dd46f3e2d3758e6d37376234b6d3506ff1671f3a67539b7e16704fd26e503d94db38f5580d72d2a620e60d30459c37b2977aaf2ea45d6fef3b95d1de7039c2de12f1b05879815f39371694643555f7d69f06cd553ee0f86061a9634ebc4c0ce9590bfeb7c333630253615d0e20d793b7671e8c5af8b76be8223972f517224850c6c30b73906cdfd5273f871adde02991c9c5d50655d1fd711792f36af811144716e684961ab64b81da42a533cc65dd28ded3ae7c2500ab044f75c92496557d43937afdb4889c0280e185d5cc7f91c286ae47259bc7bb52c740127e84320f8330b126546e557ac55aca0bf6557c0371ccc0eb0346461a06cacffa067a80f60e172d74f142c58345695895cfbfb02d6aa0aa79cc169c596be8be1b13550be18b5c09d8d914cf95fb5fb4f90b0c59d6971221869ad0c04e52fcfbb5145b72aeb54ae6e7c79a6c170f0e5c2e025f9c61e88d38608b6f87532b99afe564bd02a1f531528a3f653a589d33e65bcd2dc448659376c428e8e1bc190391899a57607aa9c9beac79117ffd67d47bbbf0f3ed512b5cfcdc283f3cf830924b51896868eb2c67f5e88368c99c2343020739a3df9841b433a6bb94c81b3e8fc6d365799abb4284328d392727a604a5e9cf3f452f0fe3704465902e8a06c1602fe77963e982ef3a98e1869b3854ff91720c71eff759c7a9a559cc226b3213cd50a9577ba47b9d9174f23e54af3b143d4b09534f53c05cd260d1fd90a5e9d972508f197e143f94d87725b8316985706b5ed22d8e8a454a9c89198c73978964cdce9f1c1d329e701cf63eb837229608bce43f7a1f7b19d7ae3a86c380ee101143e606bd13fba3d7a569970157cb5528b79d5cca2f9b8546fd01d490145424af27cc22085080c64b261443c2c7c732cf683251b5eb6681f10fbfcd2ab5f11df46b186b0ee055a987c3b2bba8d0912ca0d2b7f23aaaa6a26dffc2793d7ed44266ed0b32a1b2d0fdfce3b285aba383f46ba03fa6bec9a7a028ac4323988084906509fe40149f891214a2bbf79150cbf08d8527f4c5bd096ff2e12ab3cc3416a4337578eb36f0a822d258e12d69cb266bf4c31c2b82c730db48190dd62f293a1ccfedf56f764d1e2e3cd1b04fad2d755251f73de500dea36caac32b8eac47500b4f6e525074687720fd5d8051e3dc04bc6459d4e233645b82393181581edcce5ea4b6171468adf52436421d010da80347df87511c0490d8d38cb96fb5f60e47e0d964d271852952be76e575ff14f617f03f60fa671807edd41965876a68cacc78f490c9224864c88ffef1286d83aec702d48235917becacdbcc2dc8ef3da3fc521d0eaa92e1b995bb8c6844ceddf162fc40c723faa8e7b4351f434fffe2f0f91f1847f716801af9335ac74c7dd29d289b8b0c7816e9d06a769618138cb3a9a3b36987b38e8ac455fc00d3613c1a9c30d48a01bdc71848cb5dd0ee071fdb4aaba47b05e4abf995b6dbbb7b95f0447b38fc45a4d5e7d67a4257f842c6262f6810eebc18c7039b93ede797337498c01a3a5c8130820d757b8fab5e0cc38468eb975e7cf9b1232f044d4c7b410aecd8c6a2a3b32477d06a3f3c755c103401ecc3a30082ae459a7653377e07b1aae94dbf071030c761bc4746a9599986a19f6566c4e241d90cabdcfaad3a27a8a98322fcd7c0c67d5f6a5b68b34af94c25779c9ea094f21407fc23bf72e93dd06d554cd697d9ef235685a7ffe7b001ed6ea7ec8bbee9d26744803c9bd94ace188cc93076ba43a22a8c1489da7e140247221be8ad3298c109f4ce1959df0ac250804c110f59cfef2bae5cce784e29a0a3e951b2fd76a9bcf6b5ba590ef45955a83a63978672b57cef61e916e7d125c370f5fee192686bb78f561b7c3e8998f8522aa6ade6da65a439ce3b91f1a0d83b37c10a78df45326451f41bab825851c26ea059c885bbf76289254c537db092d36ab9bc1836fa2ce82cf7b0376e34d704cbc2433367e6723042f899e99fa6fb5c175e4a1b3cc96f4a105878a1bbea81242831d9c01a9e144bde924e79b2d224ef374854b512836a9e67c9388e8251e32641118bfeaa67b21e6ee51f86561a7e52c726ef595e2889a4aa91c828582e06a03d462a0fe992ad733c22fb174122a1bdd1cc7772e8c0ff20642a76140a4413ad4ee536e74546548086d7c4f0e7353ea4495239180e373cec8141878e6928274c33d33b26ce5a9f9e1c3dfd45bb22e69b8fce7e871e59d28f2285787dab92c60d5ec9c53197dd7335a357e8433d891c8265b6921159ba0c3f45450131b7634e70620fd8cd15e59bb39fc90af29bf8e9b541fa3f9d9b482f11ea0bf48563cb3da2a5204a680fdb496ee7845cab3e54c2add6dd0f145c523e933a9723eac94f1aff27572b41fdb9acbb349ffd351fb5ffb832a17df938520154af52c52cdaba4269415b42d9fc2f7aafe396c350fed9955deb3a95e0ea843e7c314c0a3c36e39c491c1a47f2c9465f7fb0b573e1503b6d6629949d5b209e5c0b1cfb6ddae5faa8babc4e5ec876213ff4e47b10becc5a3d372cd1e50ed1688e0232a7673099166b5fdd97cf93d846f6025f0ebcf59a0f003f07ef7656f33a03a5a83ddd94f1cce1c424f739d80d829124340fca7575df79e11444587fde35486140c417a0abc1d4a3779ad571472458511e45ae1ce1c4e71c88aed2ca7657d86150d19514d98846e3a56d11418e2862653b2d66aebd8177cf8dc090de72b5130b7f7494bcc1ae32b5b3425ba194f181d8fc7ae876c3f662c0ce3361d3f9b4e8c205c2dfedae0d6e57f9d6ae01d2734198dd2258f3807e0a634c340a957912ad2d766ac1e2c58c056bf3e7c062b69527133fdd248d0f1f5a6e0009bd790b0f39bbb35a2d1d2b2c0e10ecf904b7b0bc2444d3576c60331be41a11292553bc2e5010169334e4c5f6fa2b2d87f6e96fcc9591578fcbd37ec3eeee841bc78d9a8a05abc2629c1db7fe83b485f8d934a58cf13857d1a14afba01c3d421823b86c124003f7f041c0cde8f7bfa60dc95a809ed1d1dc53367feddcbb0e6473b6f4ef93e2e2fa063f3a5f0ec332311417017cbacbc4a11491a6c1970b9e5d3e208b57801e1e9438989c53442f24803573c5c9a7366a2806430942c3a3a58b52aebcbf3270fb5e5d7f1d03495f56afe3c5b23027532da79aac18d22d5fe866a0684f62e98d35f2c96fb8cc74cc41297791b30ed0b9771c01e6bb3d6f96616b4969ee7b718928bb1a944dd385124374fea07f2ce508108fe880d49fe33894fb51a159c26cd1c359eb9fca3b8eeceaaa5b31316a9c4624f7650c49fcf7f85f2258865760758bd099891ab05add808f70e0ddcf6efda1f75c7a335e38648ceb26041ca9c0ac95abdb1c6c37f7f473d05ccebc5ef86df331bb7407415f5d87ed35c14285ff5fe54bb6ea4f70630d5f90e2f2f2b064891af3c6f24b2e52669eed225023f1928d38eed81e66c3fac7e9163f5b37cfaf84e912a0a9c8dc991a468576fc3f04c6a53ff9e7faa8473f4c7b9636e04572e831acec433e4b4704685162eaf7f31c3807c9a1aaca60ab80a707f39fc33fd677fc718f7c2d7cc98ee0a0de329c91e25b2259938df1f0d67c25666dea7bc7291757339527e1b8c6f2070a03021d626bac9c074f50c9bbbb1eb49fb8ee9c30e3b8d8a898beec31b9d298eeefc0c40f3aed0a6f6303cfc7bbf099abb3ecc807e92c836874af2ca42f26f3352a47cea4c19ba7abb055ed2525992407f1725420291c26d053c6c704f85b20edaefd80fcc26714c4b61fb9b996b2454114a3ac63723a0f3c205c509903b1dbf000302b2e50cce6b1a9f3a8cae8256e0c4789be1f6fb22555179779dc0158dc32abe791b913a62fb186e37c0efcbf7050b84edd5c1296b01b4c61b1a7723bb4abac31f6ecb3a27d774b6fa7c5456d34fe0ca48f65bc8c446eeb6e4eafab238fd6e66f4267c8e420b6da76c2ba24ba12f2d59d1c52ce11fc273610530e78353264b5342692a7008c4c13b2b57419a668a32f967e9877ca6c1d54aeaf85d0429a50d8a73d02845bf4037dedfa53e5e906a27853570ee6475f9be2d7a60d65f1c3c7cfd011087aaa3b1a7e35b1437cb2aa89e16ea4edc243cb101d82a0fcbf31abf4251154772a1232a3f669212a95b0a8c4ef54d8806efb13b264cedad4e85fa4d3c84b9494a01de023a0fe6755b1057ef4277c596adc9dfc9fbbfa724e728c5d190e04b3df6f57d081afdaee22e6f7f7854d265bc433870eccbf82febc6a7b0521c35eb8bad33eeb0de052606a16bb96ce07a001f938208e2d25192bb45f0b22520184cea9918135fc6d4ef6cc2bbd16f49f0d64ba84b0669b984bbcd851daa43e32c71658c0a667cd77a7b0bb5751381b2b6e5910d6644ede316edf265321d3af15859e1f1f8791525c5c656c465eae67d04f55edd8d8a11089bcb413e57d732df0fe5202cfb3c2306d5fd3de803b247a671c1fbc36b5897ccc26e761e79941f2ebd8e742c5286e2bed2afec4a952b60bd9860b007e4ec5f0728371271610b234878b22f1ba9fc0c6e6cbc0c132835eb72db6163847b5b51bc852ade8f8c1ce2ef50462c51aa1407736de39766f576b5b16610ecee12e7a432aac6741d004e3025c7750aab0e2b089bc486f10d4727d862ba388a78eb46cf5df381ee64f2e99ffa3190f4359eab1e344ae5c5afab98cf86ef692e5bbe5b22f4f1c8e21f2bf181cf96d110c8255677d09e82349f9758771caee1d47314dbe47e49dbf74e3a4635ac5cc40c0376b0bbfc3581b22746c3a8d9eef08864c49045ac4fca8eae131f1ea8b47972a879166b2755522675c35a53d529a4a70d35127892a1748c6d2cfd10916d55b17694c2b259802f490b145";
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

  // Archival serve-credit transport ceilings (gate-2 §5.1 / RF-D1). The
  // interior is shekyl-archival-retention::wire; these size the opaque blobs.
  constexpr size_t ARCHIVAL_MAX_PATH_LAYERS_PER_KIND = 64;
  constexpr size_t ARCHIVAL_MAX_BRANCH_SCALARS = 256;

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
  // encoding (count ‖ count × HybridSignature) as an opaque blob, stored only
  // in a prunable side table; the real structural bounds live in
  // shekyl-archival-retention::attestation_wire (BlockAttestationWitness). This is
  // an allocation guard, not a structural check: it bounds every deserializer that
  // buffers the blob so a peer cannot force an unbounded RAM/disk write before the
  // Rust decoder runs. Exact record-count/length validation is the Rust decoder's
  // job (Phase 2 admission), never this guard.
  //
  // Written as the maximum itself — count(8) + MAX records × one hybrid
  // signature — rather than a round number above it. (The leading r(32) is gone:
  // RF-D3 deleted the producer's revealed randomness from the witness, so the
  // blob is framing plus signatures.) A hand-picked slack figure is
  // free padding an attacker may send on every block for no consensus reason, and
  // it silently stops tracking the real bound the moment either operand moves. The
  // FFI gate asserts this equals Rust's own maximum
  // (shekyl_archival_attestation_witness_max_bytes), so a divergence is loud.
  constexpr size_t ARCHIVAL_ATTESTATION_WITNESS_MAX_BYTES =
    8 + ARCHIVAL_MAX_ATTESTATION_RECORDS * PQC_HYBRID_SINGLE_SIG_LEN;
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
      std::string const GENESIS_TX = "033c01000005808095e789c60400c86b09f3664378bd771e3de0cecbba516713ff6dd6a51e6d4767d17a8dad4e414c808095e789c60400861c155c9e6cc5e48bafd3720d49634794829bb38820bf8c818d059e0d8ab3bdf3808095e789c604009a482838df04284d31eebd1cbbf40ab33b0e742bfed3a36ce8cb05288df8122e3f808095e789c6040098fd64f8227383aaa458c3fcc3dade9e79cefa380e34bb6bd6694bfe733d44ba7f808095e789c6040043e404b194f6bc812e43b912d35b44d55ae7199988c2093b4c7e045e832bfb909fa72d0134f77c699adeb3c8e22ecc30dfcddb1b23d9f58f5df430914b0de804ae90895806e02b4dc8be076b3cbc7ced817edb0004450889e5f5b53cafedd5a5df81f4854534770443e7cf116689880d72003509c1acdb9c434cfa589dddf1087a3d7eaa7f7b41152009428488c878a723a5becb0a28f6aea33278e1503a7dd9e742eeac7950a5e2853ac0733883bce5a010b8136a3842807bcf57f3e99f2105ef385ee14f0cdb1b13234f6b36cff08bc7f9a0317317accee406d17255a06a16c3b34ec632008c3faeb1e1cbab4477ff5c5ee606f4580ad7dfac49606a5f59976665043999355e9f722314217a12f9996bea2c0ec2ec9165cc61af979a416c414f74ca21ce13c0f3462fc4bc33141392d7b8e9a1578e712652f14f926636c908216028ec8cc96fdd1c7dfcb422b8a1ab3e47095d680420801ff889b38b92f6e5fd9efdfe842c9e8471b57205b6c7c4aad19b1a63c2045095b92c7834a590e684e2bec4bdf4afa2a13a68a66794e5febe00e429638711e04478249dc1a3eb5da8a81a708b1d5a64806d8c95e27e0a9d278cfb88440b8f98178cb2402f2b0613b1208d8e9e679750641c8e7dc89adbd07eb09c2d93947a7e51df99b1c4d8c730e0e175ece6bb890f5fe57a09c255a1fc847b020debc19cb65b0ee66bfcf6401ae6f4d630f6ee61901aa5cbdeea2147be71d15ddc94d32ab8d19fb83f7fab4238c86effae581d2ffb36872c997ed2816c2cfe29ee6b8ff973ef6c2dde6ee316d64aa430221cd3073ca59c7b14840a980631c99636896a60ceafcba0d1b27aaf9d17dabd2ba4735441c87181c98ff49b1e7f636b0231c08b6d3b29e217cdd240c01b42a2eed948b10f48eeb69548ea56a0ca46f30d02d4c1d54777925f4708e92006ebdcb265ba090e6c4dcc0668a47cafe56b67f711985b2b76c179f00fbd002395df0c22f223f66b7c33b476f3d635c39c943dfe42b2182303f2016f8b0c8f95048ff01acec35ec94d4d88ea1fc5fdb0048e22690626386eb78d669227bbc7bed689b56ce81074e52bbf0baa5a06a605ca9ecadb8ee8d9d30555c7caa8ae3a6be982b36dc71055271dfa15559f664ee3b480f5170615dde6de3df267834e6f97e180830da0e33c7bab7939610563f46d22ee8a8898fb149327261e3915bde5ca0871809917cf36ad0692fec54a2d94ae160043870a0d827ca70faca156c8e35e1319de74aaa72d4c19cec6b1a2c631fa73c263fc748c9e7059acf1d26e7a11b51d063799ed92de7379366abe741f3a59fd9e6084f890a877bd4d98c4b1db406ddc4cbcb3daee810d035702aa4f4af425b62183ac254e6c6ceb7666d36db1563a82be2e09b43fa68efe4916f0058e78515a72ef0531600e2d0f0b2a1ecb08c8ef3c82215f0b1909afc47e0b7931820811ccabe3d2b4147192fb73fc2f4125215426fe7418135bfa7f9f08945698c334c5497f7b1d6a743b9c1a56f254bf0bb4ee60fc630e52e8da07408e31b3ffa7e71486b84bb1c394f9c04272452034656f4f83b1c86e10fac58cfac544979cb7e231e273362e5e85aab72190a0a907482fe93f1c948cf1446f3638b347c969b9939e4829ff3f1ff18ba2e3a8064d1a9a41b0cc8c345dce284e681fbb97dfb91b3e055246db8fb9ebc03e29373dbafed44cf05ee12c52be1ec112969eb07a1f71e5dd627d52254d2cd734d2a9dbd686f3451a91a6b6c8bd41be0f2d5d9dd1d0100b4709681c4cac6914d2572be6a7b9e52241d8453779042412633af23ec9ca7fac74be3514c61b40fa56ec7bbeaa44d5c55342aca53cb4bfec8432162a3ce03f68403dd3a48389c792313e68644171e9eea539381a8875f27235ec92943521d97d7785ed3e9c09c5c6e4e4da0c71c4a6d635d157732ec5600145b41a6eb315229cabe1a35d60a1fc0cf073d7bffd4de7bd67cbfc5cfbf00fb6d55d7157ab07534edbc6629bc73aace717f1ac66b2bfdfe4313a25a90cbe060822f71ef24646f678bc26072f5fd7e24fd2ed6c7888e98c701395efb816dcae563796fe807b834235a74c19353b5dbdbdcc48020e6090553d23a95dacc67505d53c8ee0c1dae490191c1e341d0cdcc463bdbe3f1c58bc72e8b1ef644937eed6d845dfd73831696ad1e0e3ce70f642d422a1c28e3e08bffe9a597b2816590768a3ee0370f27b8d2c08fb85daf297cdba8e99353c973af11b3af11253692f7e1df923e72a23c65d6665b76307477daf3f3b435436b8200202b1137e8810790e861cd0ce7af0e0cf91f22dc5d77233dcf59d56f4a20977a712ae1596bbbb3268c7a2c6c21b4f19b29d658ca2ca1aa32af105a599cf73aa0494cfdfa3abd0214eadd24cd1eb42d2a8cf92d391603467ff7119d3b73bea0f9b51d2dedbaf143ecb3565833917786ba46f6f5dd4861cf6431119955a9b473791684b9818481c27fac542e0d6c051f64a78dec0f04dfb8720be14f8000fec0712f34570d2ad224963c3978b552211784c8d4dce23a2db94fa901c7ef39810d96a74d003822b1f5b558474a791ad87b53217e77c3bee74648e81f306137bb4ec6f4214d1ca0fef0a7d3012597d18f5fcc167e7c6e26e82a5a5e27112be07548400bde61437a133908b398c0e665241f3db9ce6b02d4fc14d353f28ff9cd82bd80c748bae3fe0554a9264ee9ff66afebd8714fe93323c2deb6d65731621a8892997fb82e23d330ec9644ebbf017d8d641a356934d9dec7b065db97ab9e9c1833cda532afe307e2cb0f17e13809672ddddf6d5d7c4c59eec8a59e6a9ae601ab3f463d3ca61a691ea74fed4ad046dd0466698a438190efee673f8c39f9da05e3a4a4a1f38b0f400747c4e56cc29252f6168866ce464477ecc863c390926432bb3f400f459037efcaf6039841eadb330911b05e82bde282ab81c906f7cda89673c3866ed206842142275d23521620127289f63cf1719ae47e7f42ef5875ac728d9bae6c2b3158881fef7723a305fb2c9f5a81beb35031bca1b881a39c2d1fe308ef6899dfce2d74991018fa29dcfcb9a1322209b81a116e751c78a34df218cda0d18e3931d55ece4413d9bb893c02baaddfed4358b8aa8814877c52ef6cabbedc1263a6deb1a6f5129e8a27413b8bc4529f2ffbf01dcf4079463b9fbf9bef5242489892b27b965732ff2f7b320adbd8fa61b4ba0baf1121d8df8e8ea4c6eafe89c9d59a6ff98500b07f386d009cc9323258ffa0e2d6316b801a50823e3deff6a3c7ee5246cd574be5d4342f2242130854432cf253aba06499f267d46ea94e74e9da0238c4da8574014cf2a54c49f3593af523e94914c40b603ade17b0128cb2f8c47c246de5817d20758b54f3d7d39ed0f393a382500828046dcf7dc88390020fd2b1b17565c93f03ab7db4317a75381c5a6ea80c0db9ac051a7788347b2b55c5f1140f4b9da1ea1bec42fc6081684669e45cb0cab864b737d8b38043caf2f309acbf8812756bf538c8358e89683d57e5d732104e8e29cb2dd73395134deb0b8c532cfcd5b61193f65d33de3e21f2ac14e68b619ef560dfcec3fc481e4d61b0f1739717056888e32a0fceb9188fd465a18af3d7c29686493008f7d8a700a2e0318973d94e13389195bca534e274d36334e00d6f6440f7417b0293ee6ab9c5ac171eb1e7ee2866342bd0381700f47ced9492b0a9b566c22c8e7709fba95871875876e739337c946842069c291b8aeabbb7ed8db3c88c9f24bcc757928a9c7c24f883ad70834b940c366b238f8109d69a35a87560739de334719397149f01c90861ab2a482b892248b809d0f0aa15a3169723c6fd64e62c9b551f28c6da914a89f9c06937a78cfa7c678f8756dc8761099a552a5e6c7a40ba1405da6946cc8c913121d100a4f44c2a950082ee3a2ecceea07f1ddf34dffe64516717a382e3f1ec384293136ae43eb31e2e2b380824c13e200d77b0d43a97e38c00fca4f3d0dd4926761179d5cad3b4bcff5c09b5bfcfa31f309a305e337ed1e0bdec7193958035c4a0512d7c12a43d21fad77a8c8a4773c73b0c5371bec6952c49ccb3f656af18523a681a2c91d034cdba2be9685169382b3d7f05d893b691581fdd1b2d1d8f7ac2c6ceccc981ed4743ed0a47fb6c36e50cdf76bba8dfc8a68e79d8fce1a5e0adeb0e427929f37bf64159b0228bce812847594ecb1bfe78bdec8949934b19eaf0ae5d922ba5fcd02b2d5a70643c9314030d05732ab9b5fe7de80691a3e2663b71e911dd2b2a45fcf2b15618bb20a4cdfb3229b62e980d8ddf0fb235b5f61c4a844b27b77016fef95bc4389dbcd5be0a7bcb105698b43c34fe4a34301132e8aaa3b0f860e29e0552c563a538a7d7a567e7557787843323d905ec4a0bccb628440d26722ebd9c203c7de2d46a756fd8ab147d9117da3506ec5c7278f7a9d4a189e3eedabd11c442570a015c05b9dbc5c98df26b8997629a4f82d891d8a8da36fc581aca6613bcf2f64826842783beb7c8646a047e1d02a4bcba70973c811dd98908e41131314dc5953fe68bc6ef5ccc8605c2248a3872db6bbef766c0f07b3d718e284a862671701b722298af77ef6418e55e1795f79568306a9a1ebe44986a4e73be0c8ba0ea381e31257555aefa419c81877c901f4e0777b536e500b7d2c6479cc7bec27cbf81a9f30b2761764430c62a9e36467dd2f68c28eb8fe40c923a1aeab3b88c53e19da0f41cc165fd73279c67b9a2c051160ab6eb2e8781453b4713599988dd333b4c26764b030d2821bea416db1a21487d201c9236075db88142abdcdd13cb71a5735ee0198d879dd89432b3cf71afed79a94dd221148dc30fd2f38712cea747224400152bbf729e9631016895f4e2ba070172548ed0b072a1a4d124ea03c1adfd2785ec79840778bfd166e7bd20b26a2f7af755ad92c7ebccd338062fba840a95ba14483db028dfa5bca919391884a3bd4e5ac1dad0ea4cf167aea734140811d7a54837d6f98cd1cb3cc92a9de2416275a7ad1a827b4af370b0a2fbaf6e31be223a025df9acdf745018f549be77421265fb4c6974114190bc4d8ac18740e771f045e4dd34432311ea6511064347a6b19492a25727c2589d904c2fb0cfcf8f1a4c1c36663ba4a23d46c327ea847a6f36a84ed3c4cfd6c4932f69d278b04cb84ca7a88bbaa4e5801f223014498085fe43f113edcfc2122086c277bd12683ed88d9913a965bb84aecbb422c8ce1e6c6c83aa2313ddbbfa5c2bdde2a40a4fb7e2ef5afb09a44e634c4ebc884fa88c77812762a10794000182888485999c27e2eefcd3bbea91b3de375ae248079d35e9cf1ca7626c24734a22249d9d86f5ce0bb4549b1eeb7945a40bd02676ab24add060ba415961d1c22f5b5ca50a81f0fc235d9142a5525c888942a7ffe4f06cf3e04a79186b631ef4a6d2c72df60814ea7a8380c9426c16398e7cac19e0a3b6bef4a9d35be003a628a71c8fdc73f0a6dfb24700c5c4619daac80cac53ac041a6fdfdee9a6c113ee0fba969dfade601261afeaa1c5e34b33e22477ea0d21794e5336633f349a019212a18faa5c00c36be995d4356d5eed5bc113830456e0da04bae149a2009eb08faec5dcb81e9f3a5d520b4e5b09d35fd86ebd7d9424a1d6624c0f9711100fa66b5188cd21addd4cc1b91372ba42f931513e5c7642b50741841e1d36f9cbccfc9ddd657a41fed90007961bba56240d3bba4b76229c8bd9850b2da746e7c9f1fd98ee69382d846e1a1e9046a0370a1d558eceb09140625b78ccb89fc60682f874fb13ac3a28b6be08cd311ba5165000d61761be99d11cd4afcb15ae1407aefeb033dabe65789d168e0a8150455d0e575a9009f90e619fe7429a6cdf11e0476191e4ff7a0643955fc2f2abc47d632e056a01c2b81c65a3a00ada79caf42ef444892247c5f234f049576db411c024fc4b500f009eacd7181815e9048da426539eb1ca36c2d809153ae19ca5cd6887ebd8d87dc450458a8cc4e9fdb019939f2befa7fedae37e6afc29a02fadb0fa39932415c6c2681daa373d2edf7b7f6aef59bdaff232a32dbab32491f1456e801d9a00715ae3518157983e9e4528e2ec8b3352ec282f29b4c66367c015b5e001bdf40d4a076f22e7a938547942673ed2380063c057b9bd54c3948de214b89597989713716911a34e80cae442e7b73ab091398624bd7d8fb4bdcc0c87d9cb2395bbd5461f9791764b3653671797ea40b4324e07df277dae6ad36a637339f1965058153ca9983eb20c6b3764f1ad1c6e217088324520d645b1aabdc38f36567145bc9a85ddcd1c7d409e4e34c39d29ff6e247ab43c6d9ba8c2cd070218f0ecf2b960d2043d683d7d3988ee627a229b63b0949748bc32297e979092f19b15be0ffbee3c68a5c25b280456b492c796d63cd866817f142cae74c1995375c0d968c9a2cdf3fef218ed17fa34bdd1030641591227630d58d80f96821077b5e80a744abf8dcfaa3c5d6d575a379643a37873383d76e990ba71ffe78ccc472387adda28439644cd75bc5f8a88b063842fe42efe48626ca8290898008b366f7be3f301452f18d889697d53a6aaf1b2a1ebdf6152c57b2dad70ad67a6e93caf2a2881d1a94a3543d841ff23c1cb42c56cd44fff59682dfbadd96142d0fa81287e3d308288b5b07ff6770b4b4a40e07598b408e21bd90f77bf5ab17cf4e4d90bb935e800c1c0b0f05727e7961ae9bb1d2067d0996b7ce7a50b5ee80127ebd72d7a4124c6d9d65573c3343d64fc4fc10967529d1186edf62584c4846d73b2f217134cc6a8d2a4bc67a52a20793e22218ca75bf6ff168a6c8365e0ef048e94a43a1c4537c38cbf4c34a1a5e8033542cb5503e30fe3ca1d612490ac08f5351a1cadec52430f26c19281b887dbf1919133e1051753952964c2ea13466c41d89d440ed322ed3da20bce64305c045b2f8ba0c6f34072b4c2e0be27f8194b7e505ba1dc8c0c68ce2cd3d3fad055aca8f25f743ece81a2147ff6c0fa47df38934ee02a7884691790874856c11be700b67b6fb1f5ac2d0b9167644565f0af4cd5f3bb1267427c238a3e1b93c84b95ef03f68f6016e85f98037a82e3624774208012931f3b8817c0da136c30ceaee34fcc271be9137a0611c3182172a90c835e34425659d4773b030310f36523ba4ff0dd16999350c514c4cd009af4e24eac62245b7e20f32c383a085f783036eafcad8cca4a2897edcf4ab4a698b0495d3c0d25fa95f6555f9495b8720d9fd011131196a868dde73d238bf434c934081729218bfeba77d11ae45bc14d87bf188fbf75ed5a8dd9dca3b7255c72b9a52f3e1aa84e9e1ef71dabc5e4ec43b5d867551e81aa375054b0eb70bdfe7035919d4ce7eafeee345c4bf30939278f1ad59892957501ad7a3dc3172f583b28f54d38c6e754f0e245c055fcb835a05ef8f680214905476445e56f69ee64be4fe170a672e4364662d000faeda710e8664600530cd551e6595e1d91a329ffd7c0bc625a7f0612235801ce6369e9a8c53d95803d4308851d6a344caccb6345ca773c7c1b04a5e4d7a82fa0541231baa6b6202e2965325806160814ec685d755758f968f3c4a898a54ceb127641bd63883493ef7240152137a2676d6bd759488de93626899ebea3ff257dfd0a1f1e348c911b350b82561f0133916cbaee39d01599656ebf3f34656c451ed2c2652be4dfad7a8b1cb8b6f7b37284d409885c2e804c20e2b22bb7cdeefe3049e01b8e9ebde31cd8b219dc76d55941e95748fc85cd5e97817789b5b46b661a8ec38770ec093a7facc0709bfe940f70bec4c0e489cf236b49283768e17b8d64e0d1c96b6dd3d7c7aaa290d95247a5257cbf72238534da6ec1f7eed433e83c7edf1e06969e5f3d8237decdc6ad95b29c4e75e77513c3fddd58c2cae4df07ef8f37b8411e09088abe8bb2db0257fac5ff78bb7b5cc5d950fb85a975eebd7c7fdf53ed4ca91053b46b69db7c3e6e3e5f291d4d4a707a001bde76ea99327c3d2d80eb4469f0cb9a05c357fe15c47edc8f8b4fdee8ccaed03e96f951f31c131a25190623cc528d5ed8527aa691c5f126ec0bef887d7ce1257f0d4cae9b5fd000d6ac35d8263072fcd2da8842832debf979efac5e6efd4d07bf8d704fe1cf17de67b5bbf88c1b820bcd74d4a1a85d5bb7af2788cc7f6d0c8307795d54133661dd0f19f60556e40290c856b48fc5826b108ac31a31396828a0600ae0d1232a2efae941bc7daad012ef7cf6496c52c86d30e577b359e57c6c1f9b46b62b89281419122e1c98155c4b29b8cc46ec9f20ec79545ace443190909a23c449cac3199f9a96cb1dbeede57d62dccc127d176d5e0558966449b59f1bcd58c4d8585425c8277b2d2e3f8c119ad7ddf502ebd7c1e91bf617cad1b997b2c720c59effc44c452fca75a69d89d5aad67093c5558e1da221fd1fc75fc33a63bf0f7a936549c67c43636c1f90c7e32c132372868201e4e277c54905ee294dba1f9443f8f74cd59c63fcc881583714b4c0f09d89f07f1c1a509d88102f6f144db7e43372a3dab0c2f0a01766ee0d87f47d3fbd25f61281bb829cf4b71";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x2D, 0x21, 0x97, 0x54, 0xA1, 0xBD, 0x79, 0xBA, 0x05, 0x40, 0xFD, 0xFB, 0x8D, 0xC8, 0xA4, 0xAE
      } }; // stagenet network id (rotated v3.1.0-alpha.6, fresh-genesis)
    std::string const GENESIS_TX = "033c01000005808095e789c60400aa76cdeddfa3f4f93f333d37a0f63acf2e62563ade27486f14fb67b5d79e487b6d808095e789c60400664755d58181a5b43e65326042c302b78c286dbd31864fa78eeaa2306f81281b39808095e789c604002ab0c7fe2794e3067b512e95678229dc177f90db3c16cef28dbb0b17395d56c0be808095e789c604006c8f7f91be5e10c12a2589da1bc18497b5944f96237bda892c34dbb19fde37ecc1808095e789c6040005a594ae065fb9b8ce59815d640bfb404ea04f9bb79d4ce044a5096f3ceafccb9ca72d012b6b5e5e8daa06da41c4f25a1c49c5af79664489cb6fd419e49cdf880f825fc206e02b1ace537420df626b89fc5e1f583b2aeac6694f351c5077f69dce819a5764871541d6347fbf5f8dc5bd78a81c7475febc18a8f4360d5909d4e94b396d6bd34a8712d7fea35aa9a8b22d0eeefc2e8acc4818bc6cd555d1c37992ccc59831daa039ef087b9646e6acf19386b525a9aa5d19fcd500bff60083e926ee7b3721ec6c95b50a5d6901ad845c75ffbea02dc263b9f1e55e0767d222bb0e6f7495aaeabb68f8a1a4c15c59fb40b951532631940571edf0aa7747423fa1b191c764367ab2fcb757f6ac304fb24725bcf6ab2b1f3f34efc59096c879b0f54b3daea045d3e945713965f003c587c8dfdf80b72472fc0b1ba2cc3337b5e2e64eb619d00882994d49ba571b486303a3d986bdbea42ad454df269dd2516d12a0f8da68d8fc6958ddb11385056e42f1e44b2e840371ee3e415015d5d36fd0c3a4be34a5eb3d124b771e1a52495bb77da88134c46776348ea98ee95f1752c3be11391e7137772762bd9d5122eae7a6d605e4a12cb8054175f6221aa2319d88e596061dae44422698bd0a22acee7351e34f9c28cb98089b26d21375b91a865b8b6ca7bc1c771156dad3cd111bb077c1298e0268db01496254aabb11011ef6388d1b2ee5fb333156747555e883ac55650003ee376f1c94a3ecf3903d6e858018918bde1333f6897b3b8db8b09bac4d045904b644cae0c08673961ca8c1cb57623c518136c0061c9e147a730d0024a59b8ef525404529c65ee5fa8df8e24dcefd40ec89f05c04fa2374027c33faeb3af4a019a497f95de0b5b8ec53d276f21aed3ec02bea3715f64f0c5f961cd649ac2700adaaf0fc0495ed87b332297c75a03d9a46a368877d1b78b8b91a7025f9c32c1eae440e34023273472138aacfa3e817e1eedd606144dced30009bcfe04daf6a28e171a6711e4d6985ee795a788d8bbc7f2225f8a8d938f641576b2ef633681d7712c4d7615ef2f732ec3f38c77616a118d4747b9f33f28792984ae8aecb5c6c46ae9b9acefff06f2c3772ede252c41239d19e7b9d96c0a39b962962c0161fe63d1e69c790570a48b14c728274ab9a6ca2737927948abb769f4cb87e186e55530c8541fa481319d6cf3a0a3c6e1c12021ca2f0160402925e968af291337ca42b0d91d1e60daae6403efa7fd139f4ac9809f6f79bac69257b400e2a21fd20d9846735564f0b1b6d46c45a6c28cf6e91ff262af79ef5454780368c0303cdc34908368d8941cafbbaba6886a50757b70bb16e2267ba37a56b142e86532084bbf402416e3308fe5389c9724029ddc1fe78871eb0444e674383a9d0ba018458eac6229b85424cdaffe9bc03d9064eb7158db334d901a7547f28d89cd34bee11c9f855d675b7ac2585070efea8d5c0b497c2ad24004a0ecd6e79f2afa27959f705d6cdff4fd536b851e9253612bc06e7e06657b0663022de2d91d041f8a87193ca51de5cfbf476066c2526c042f1ad2fe7015c418ecdd366f0ad7dec3708b1f2888b155c6a56a92f4b375d67ac3f5b038a20dbbeb3e080fc4ef18f1a10c86a158140cf8007d9b220c4d077dd29d26375fa8bc9ebff772b069b10a394683494718b20a7aa3cd737c7fff94e4ba3a5d4d95642e9c843dcd65fa519c2d51da777448c18abbc0ff7d6fe8008bd842079d110b91254674d09d7a3a1cda02e03a39ca5f880a951c3b0754e246bde3659c87ffa640a48e488ea43bfe8a15bf8b9d80b78694724fb261c22f2184a277e2c287cc3a5411bd5c42f8ace0983735540d7fc7a900ffb1d9dacb9a20163948aa535fb78a48dd6719c60ba28028cc4e96f0db24388a73cb2f7da357696e29eea19a2018444b919a36645a24274792fa349317f2d13227441e3b4333c9af59d5d96b6a0bf4fa336d233c0431faa5ae8f65e7e7a5ef7a5a6b7f4c484e9c6d9bac258076cb424173286a0f2acc60fe1cb351b1e2f363fda6961e0a9967a025398d1cc1b8510328285014d8f72352bbd8b28d1c75e09cd5862b7e6cbfaa7e3028fd28fe760abf193ef8fff602224efa6291846e7e0860aa2a79e34c4f8bbd71ec8b104418fbc8647042347306fc385b48f6b47c88049747243ffacc39273a4c39aee67d8b0b43ea7a42cbf29f1af66c1d2f637d0319f3fcfcb94b545fc60d4a94cc621e68373745f8a70edab6b47a50edf703de100cac13d7b74ea9fe02c4a8ab1693f1126f25d375ceae0f1acade31e2b749c19b18c382e2c06613330a51e284f20d12ed1c2d4906051534e4c9e3c3b8ef8d503ac353eaf01f165ab413f1b7a247d20d288493698f7b8bf2453c60eb96d95498703c963b544a84888a8bbc161d6669aaf60e98b1cb66dfc49289112abdfedecd91b214071872f7f1b00f70b34ed2f1d0a96460acce9d0debd680f74c41ebc74ea4c93bc42eea772603a82eafe5bc8d03b181e872177ebf370e06282292819d980acbbf0d87e675b73d665579af783d3225444525a918fde0c715becf2a2d2baa9f458b272186df95a556373de9342f170a833682487522b30bdfbf9f8a686e4a240a21c6568dc645acb1055062d7b1b0cfa884e5066f742366168efa322ac8fb7f8ef0c9eaf94024091cdac60f81c55620a14e1d4381f68137148a570229e427d410453134dad5283600820c9321dec1cb0ead0e4687b650d26ae7b4a277b208132097b47f92e2ff7e43a7d48ad546b010bc327ff4c262e5ab98b41075e3d8ebf5dba3fb2b74596150626de6ab75182537fb896aac081ca0f7237ed15d12c3d7044cbe8c6519466516d36329f18743a11198883c7c82f2647aff612eb19f3e6273437247520719cf906a4472815f3048ad72b0f4df8fd2118267727347c47f7d5a950824c4921e5f19139beb608475726acfc6a7a66f198f029a0a9ab2d31bfcf1f75a73366156062bd42c849f5c813f63eca5030d6435b73431b8b15074681198631c457bffd5214e9307d734c71a91e7df75abcf5060421f94c1020a55e23a9fc700b010de1205001c4aa0c8997ebcac0156a72d44dbb3bd81cb85a145a6fd417f89a25d2f4bef22d58268eda084091cde87702dc7c1fb19165017aabf900adb7a759cdf2ce7181477707c270878024adcb607b947a8bf9e12f7d95476dc86de7ac70fb48acf5b96e70d217c7bb824d5c2e07d5ee5aa451f62a689f4e5d19de2edf8f75cc52ffc29c966c6218fe1841de68dd128c6887901abf3711ff7f4e934a414df80b5631d73bef0c9f2fdf417a16deac551bf751215aec2c575311b8279576d5683419c7ef6579bdeb8b9d7abb2d4daf989f766e4920c0d16cc411e2814af607bb62c021ff8b6754d914eecbc41e8dfd0bb71f60ea9bf633e8cabf923411fbba5c8cb84adad27671a6fdcb40a7077240dcecf3ea632315ee71de2ab14271edb27468aba516dd097d58e319e819df9546a3a8b1ac8d304a42d96203ff3c37724d21f90ec21de6239af7379a83dc3afb6247ef009764b14c3bbdf368ec02dac2ecb752a3905af12e6e65b10f3ae3d2a9f0efc559cc920deb41a1c452a9d9393a99d1b7d264848dd6c7da356433f228903db72973ec9e2fde4d3f2877c4143d8f7d0947525df88c4916ba452f804348d4d523870a6cf7c42f080b57dc55883df72bccc1529a0fc263f2427399feaa4f7b894dd63b43e7e4568f1cf5c010177d4b61dd4e1f89a2c6f59998c4d2eb1eb7ee4fc73c43b8d4748f3262f2805c4b1eac45b2d4b35034746552407cc949806dcfd32078482c3d26a7361b31e19c66b4481d0df113242c23ebd1e4977ae88704b8e8a5e20b96542a9b4d5ff4937abca8506f7f77e6088e0cee0b2e98743013cbbc7c789b4faa6c6ea9f083400f9b56f349922f763f428cd727d97a686cf5b18268814aca6431e216f7f9e9d96bc43fd4cb78b8a078e594f4f73e467a6d9c3b7f472e22f289814b7ca8da90c4b50c3923fff77518fb100e82d45701002da90f4d8d18ff6ba037206fc6fea7f5006e62690cda0c0e706df745ab5c34457111f98502f98d13fb247783b371b8c78927d1e8cc7ceadccce6221cc1605d7ece785daaf813365465af33b7028f436fbe27969c2349cba25f358cc33a034e289284d934cd0bcf933f583ee94956c4c971ba260fc53f60d53b529aed3f2964ff3bb6cf131446cb8219ed9003623cfce36b9a868328b2424e092ab4cf605d32800a4b0218acbc8bf8067f091092e29fa1b4ac81702cd999cdca936bf73efe7d3d2e3db70d0fe6332169b8bde89f8f8cf410925fad426779d8de71ab5b98c6e36cb85e82ca87d263df9f374133769974a2fa2f17c002376c273f95b45b9779afb902f3ee4202428c1f77c207183e9ca0ec3847da7ac9256dab9d14193c8aaca8bb51f276cf0d781423485729c57890a669f7c2a23effeab9e8b7ef15177b5af87015cae776ebbfdeebfddb86a36d06bc5ce29b559287f5df09ec49f70f35f8a4cba691753640ceae07db2dc541f53a7cab804717a1dc792d872be508d0afc1df73200411a7d82c6096fcd6098ef1a2f1ff6e6fd846fb8e13f0c69417061d8a41d8eb85e6311614bfc9e6858d9f598b9c40b08188aaf7bd3cb27c5e0d8d37dc360828db9166a463089b4136b18216cd5cba61fbd02eb9523f7bd00ba4869db3d4ac025ce1faa25e6c903fcf61015d2de2e83aa3e2631c6ff81e757c8ca3575165ce834ba8bbb4f542d99e1941b0dae3a476fb4b4ced9d8735c3e3f50fb9edff6494e3b303fecc8f88a879dfb37dcf22a470d489f246c7ba889db85b8d579116ad6138b1d3d8c4765d20b11c572857809821c90e09bfce3d6332fe6011dba97a6c67a906df9d3b10570f0cfd2c8ffa031a79ba377d7618f44faf62552dd0cc2d9651b9c296189b54aab2a898fd20d7cd47a80e75c0f4e3bb882c333e8edae230f856861e4a4103f5c01b5baedba830eb506e7a996358b078957feca1e8a18ec5f5d002811369e1d3ba059a4919139e4d9b9256757eb2d8a5a47beaf636d62e9547bfdff36b2648183ef7aafb5fcf487cf3769dbb7ed0b72da81c49223a787269e306ef3fc86182fb1a8c7d0d9ca36570901f020c3632f634c51f586d6004ab61c6b31c18b6484d7d3e3814d0b634c9382767baf1a0a65cce9cddb93b90decec4438693142e5422c4be7a1fdd8626b409365d9984ae3043fbdfe4a11133146d8b87d248225f2bd936caf5e9154f6f85494dafef1e523cea90b20f9100cfb96de1aaa45d135735004c9f55f35de839a482020ae5b6b98ae5681e8d1fbbe063e4a84bcb98cbcc71d4fc653985da0c30e16e7fd5e6f1214313e00c1626a84492e47392f5cbf910e2276e1bbab4949c04a39579a58a39974f996a82137f5c88e4dc0b766eb20a404dfb67509302b8700f7b87a4429fe524391e80906970bfede6b4d97b5ee5c2c9af0b7cdf20be6e0fedf73c28e75a5ecbae9a7d6bef0de1ac74931b872c5989d8b209e586435164e4b4242df53d0d000610e8b4f7669ad59e7c865c1c99f96c9895d65ff50d976f5bb4dd1301f48ee657c68526c2f1991cb0db20620bd41661749bccebc02208d9ff3e8e35b3740334542219e0524435454991e3c991dd343cd6a0c7b2e76f6759e94706505800f9cbb4b3f30815d94306975e286a1c65266cff6fc91d2065c708ab80da9e9d7ea55bfd52bd45290df4f90f6a939eaaacf45a45d16eac6aeca551d506aed7e3091834c92c63b5710f04537c0c7f8936b07ce51cac8615932ce7d6bc38231dfbf777bea7201fceda0e3a4524425da0904bde16fd93a4f371354eedbfdb58d157272b24a641203979093cf0664fa56ae71e8067797ca126eea2e531e2abe94f652c575c5736b78b50dd938df34385da93bc5d196807ab064f784a8800e5059c637eb9c0d6d4f509c76e5bb913db979bde5fe7e6c8f5e0f2f28e7c5dd1ac84a16747166564f73ee9881d6598bdccdde19e41f20c245f8623568e557c8daff6d6a60982b99074708ef56ec1349c2dfee3a5285aedd73e6b1c3c4416852ccfb956d7e4502c23dae700cfd65bcec0284a37b1c2dfb6595aa701b0da74ab59a1a360f8d7e05e4b67f23f2c5d23adf1e794b2c85848c8ef638e6a8ed1ecd2eb246bbdf7b97dbed5757f3b3e29c4a9e0a886fb5e1dbfaffdc2e7f673f3b4c0942bae1e2138ca3ca8c9297baac8bb96cd7de93f9cc2af971d1dac1b9f43d1c3c02180c04120824bfebc305b28541c99fadaa1ee86ad1af5ad82f1b8c0492d49670c8a506bc842b3889cfc78cab123f422c6f11bfee42573420f16a941d13e7f7b59f2adac6d4028c00c9a85e7cdbf6e97fb42ca1e032ad4f778cb52021335148ad8acef8aa852622e30a236f99e96df8a2c3f83a4e1a9ce6ebf3eabc42e4e68fb8004aae941ff167516b22fb13862a4151d76c6835f18ff62b092bd58d377720230fbf2abed71811dc525ccf26607985aa0f340b989859d23dc0c38da68087ade64b80d2839216ed0b400b948bb37e229a414674b454526800a0e711e298dd7102eb2684f1cdb3c3d9af5fdd9b8793e99cfab58b16dae0f707df963bf63cb344e8936f85aa53becd5efe2e9272aa83985d5adc46a76b422659fc12381f39a9014e8f51a3223be80b7b96faf495c17db64b43ab3da391543a28e022e9590296a988350d6e2e5bdbcf42ded1594b2c11be3e3584a25c5e5b8e8c9971f2376c3ef631585b0efd8392092dc483d3e5b0108d5ca39ea5157707adaa046326b9d8a0c01f67600bb81aa641f1b098d58d9a5a341a2eaee94196e565ea815d1fba1f9e43c266e7d482ae6413e8986b436ace46a643ad87a1c058cedba521ea3e808aacd8dfc3b47f0116d9b9e1111faf784b935ab571a263f7be24f0aa39290d56dedcbe0c7197c92b4759cbaf08668e89ef1e25b6b9f54849f1a32b438bc9ef66f228522db4a42247486b18114cfd9a54ae1a43236f5ac486a2a7fd6910e505a1f27f51a5998990d6cfc87aa1b9d30824e0c9bcf1bfb3aeb95b555c17e40c8eff1ac4ef47161190b3103a7fb38eb8d6b7e904bb2a329441d63cd75115de614f405a0d0fd7b6f403f956a91a54799b778b43a0162ecad6fb6dd0c41523a96da8adfaf615bce9e9f425e0a95649b2594444d77f5839a552bd9d65a439152b84a2a435941efd258cdda57c08ce8013fcc0633d6aa367e34daef507d85e37d9d9f692d989e0a616d1e8d2ac0f88b4e82f9b8aac7e8ef372bdefacbfac4fa98934b17f5f45376a9dd0cb74a1faf5561cfcf3b57f91aa878735b9dc10352a2015aacff603998778f605213791d79a5f0140d4bf4cd364712609e3a0939767ad99ccdc2af147bd3d05259a13c8de14429e25d7a7833155329607d98f10f3db6c0d096d20287e33b61bd04fcf8e20eeecb83ca64e5422e65f001827642320657f7db1a6dab909a904b55dcf76463d27f183ea73beaf5594ddff2ab911a21fbb4a0050ae64fe422abe443c0ccc22e0707c0e632076dcf60bfa1e328f209077589d90980ff7f4469004e0826c6ebc2a02ae501743d32a6901a6342d00f990b11a614c03e86756246275168b88721adde4a685648741559f323675bd892006fcc3f98e1a2f884cf0666f27e665800a243472b471daffaf545781164bfadb44aece7634f17dc3a3037fbdd7739c0fcb90ba0bf674e7e1decd97f3710007ef2fa9e8a2090cbcaf0672e2f2f04ed83765bd8c92cb28b63c2ed03d7c71788c92e3e2703b44132e941b08b69c9ca25be43bcfee2bd4363496f3d2bd522ca4ccad6d7a1216e156cc0e2a282841e2f3876903729c077c99293f5b6e690825373741f0dad1e3c6876e309b6a88ab75a326fc005daf9245a2c9b7fdcea0ea2f0c64ca13c144e5184c87a2a1d85780213639a002c2368d0f50c54fcd1254dbb4362def22d13242accb51313f491eebc3e3d13840e9507a00134a23d52e4e11314bb73fabbc823fab84eb18d3a5463d689154f1b057557ee6ef76c46aa7e599c577df246bc17e9a4cdcfd67a43a06a443739ac650cf98c6232a09ca6199b3e676989c40953a02a6b54921d71515d27188cedd4cae86522752e6b09e784133bfab7991d7f7e295e59b868eb8743001968d25dd5b0c513b07e45674d9cc29c2fc36bd8244ce5a13cf793035fe1ddc65a1a6f4e492d177597073b00b7c14b142bf8ac71bd6f4c31f1817f79e71da2a94534d7677bfc14f4797030ed71212740ab6b3ec9696b679b9bf0bafdbf1f5aa0eeb50d98c16bd3858043f78f171d0e93ef8dc0666a6f4a9f350d4269494f9cf146e0bc1c0e72b32f5f0ae7b7096f1bae959d42523f5060e9be62452a6440f8e1d8262bf58b8ae01347a4a81974bba4b5e6227b0e8c98fbfdb10717411e4c32f31b745bdc3f9ee0cf7a9271db27126521cdcb0f8dcad9d3adbe4263fcb810fb878a2931ec1c122c78fa9c9e4bbebf84001fa35746f53538954e8795e49c1747efed9e7a504127cec96d0394ad1d94774df721ea15ee2840198257fbf1b751f65de6b71db39b81";
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
