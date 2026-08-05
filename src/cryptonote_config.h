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
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 20 // out of 100
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5 // seconds average for poisson distributed fluff flush
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

// Both below are in seconds. The idea is to delay forwarding from i2p/tor
// to ipv4/6, such that 2+ incoming connections _could_ have sent the tx.
//
// DECOUPLED from CRYPTONOTE_NOISE_* (Q-11 Unit 0, 2026-07-31), value-neutrally:
// the inherited definitions derived these from the covert-cadence constants
// (BASE = NOISE_MIN_DELAY + NOISE_DELAY_RANGE; AVERAGE = BASE + BASE/2), which
// welded two mechanisms with two different adversaries to one numeral — the
// forward delay defends the peer/sybil observer at the tor->clearnet boundary,
// the covert cadence defends the wire observer — so re-deriving either would
// have silently rewritten the other. DO NOT re-couple these to NOISE_*.
//
// The values are inherited, not derived: the stated objective above is an
// anonymity-set claim ("2+ incoming connections could have sent it") that no
// derivation has ever been shown to satisfy, and the draw that consumes
// AVERAGE (tx_pool.cpp, crypto::random_poisson_seconds) carries the F-2/F-4
// family defect (Poisson, not memoryless). Both are Q-12
// (docs/design/DAEMON_RELAY_PRIVACY.md §22.2) — derive from the stated
// anonymity-set objective, fix the family from measurement. Do not change
// these numerals except through that derivation.
//
// BASE currently has NO CONSUMER: it was the derivation input for AVERAGE
// (22 ~= 15 * 3/2) until the decoupling above replaced both with literals.
// Kept rather than swept, because it is half of a registered open item and
// deleting it would delete the record of the pair -- zero consumers is not
// the same as safe to delete when a constant is a pending derivation's other
// half. If Q-12 concludes AVERAGE alone is the parameter, BASE goes then.
#define CRYPTONOTE_FORWARD_DELAY_BASE    15
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE 22

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

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
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
  std::string const GENESIS_TX = "033c01000005808095e789c6040007b6bb2a59d06411b50de7ba0d5a02dc002b685fda1751e0e8d9b7bbde799e9d11808095e789c6040088b6b87279841122c4295cce1aba30cd6dbf332b0f3297fd81c8e7bfd4b1376119808095e789c604003ec6a3dff3b37882b7bf60cb6bbca46ce540ca863d45bbb701aad18e1d517cae9f808095e789c6040044ca9f1efbc9c25850f3dcb051ca7a56533905663940f49807b21776b0bcbec94e808095e789c60400a4804b9879872f8da65480407c326b1df5b43d120123f78b32ec0eac9093c818e5a72d01e7469ec8ff2c02f03897ed4730e9c99550449418d014fbffad39e859c8332b7d06e02bb324fbeb7f7119586ca57c44f6cf0189c9dd2a1cc2da3cd7fcf66538e90a3f4cc8dc493a7cd8611c93d6b837f77458ecd4ee21e4ae81747664dcd7edbfbd13b280fcefc2a856e559d35e455c78052bbf77b02640dbb951dd3abbb7e5f498dc94206a07217a5b7bab6eb78a191a425899bdc223f2dbbd1b13d6fa93e23e005edc7d09524965d942329d616a21e82a43fef8a7833b47fd1b2ef164ecc7688abdc6924d354a0d42807013b51b398a1601c0c7b194a40f567c87a24a0e41bdfaf6a13659ef9c7a0b6ea5179b785b9ad70f4b2036e60fcbee494c30f9fb9beb51ec9dce95e10e0e851082b4093b2bb5fa69b1e38fdcfb007186ba545cd44e26e9ae4041f5586e844cd6b26b4dc5cc4bd0e7ed90eef4b6cfabc5ede42cf4403862e03eb98fb09c72aa93598f45dda87ebd171c19343105356268aa54a61e52d87ec0c498eaa91c144ef079b1c91c9079d8a8fdbc69c0d6bd18071725751575fd12935e6a286defc9eedb7b2158fe77396267c69765fb4d2c82e727148c1c73c310c4219380e71ccbfefd3714749c4de85848a1c1199bdc0440ba7dd3b9e58040ddae416ca8ed410f0add77c61f85a2dfc2134f0f01bfe1be62d79e0b77bfaeb4327d919472354435d20c8cc491cf06dfca97a1b661cb142e26a8b83ba4fe961dc5e0393e880bf17503a9766d782af41e13c89e97dd0555ff2795e4d8a136bbbe309fe99e7c57f5ff6a5b7167e5b9101217b694c749ecdce0532aa2140621d8e677423fec3c1a4352085f99ad92428238544825d2c381e1f9fbee2fe49a8cd8f69b9be8bee3bacea975d54f9aff37530214b302aa536cf0c2ed64a72bf39c2d68945f0c114d04762388404ffe6c78f35f5341e1d0ec1f0f989cae46ebf901a6bea5d1c1a6359e2f29a2eebc90687f2221488c9efcc5d553da30c4f8c50264c11ef8e30cc7fd99cf41dfa1b8766e319e35220475f8585dcf69a068fe1d9e3f7b38012dd933ebc81cd7140cb07436dd9c0888d116d0412a491b1a8016a700d5781d1e77c4395225cea6649f610af091b39e65bdab7c8524ffe93a938e537523c41386ef0decaca8b8bca011539f5bda262fbf7de483361e9b59daca92f88b5deca12621d7653d0858b6371ab92d73f7ab52d9012a84c6a1d8bc9bacbb3a331b1761d5115d984ac8d3bf51ac70e997b11df9558e5a62b5a8f3e9c772a7617b0a3692188e87e9d104932df97a6da23c9ddabed7ea29e2baf9956a35b6e52b5c310c23ef9c6babbe2a478b8802a02186d06a1b045e5312a3ebc7f8cb10135bc0a4dc5a66570680bddca1d531afb90bd0cc95f51510660632e7f6b1df8bde06c7487e3f7b23a361b1978cc36be4b9d553dbf269493cf04d3b8650139b979f0995b2ac4fdc84d6b1eb78d6949485e3fe59d7416de41a2e313732c5a0d8e03cb0e8d1773c2815ecf7244972b582426a0410f26b55efb5d66be093b4c6502f49dd77d83fa943b0473294c35cf2e4795adb0df501713061e2133b0d078db531a8f8d252b971bf4081d3cff5e6d9213e715c2a7445eabf82fe5d13bf2d848c3911a4c0e16f452b6df86fb9ab5edd5b6fcb4917e4e4def38306ffc8168073bb1aafc32bf4110ab97a38cdf0bcd241454be1931d08f0016707168cb3c654c2a9e825accedf603a3ed798a6cfc91e79f2194b1fb9505bda9442f22866fda00cbb5af05b7cae0e39ada7773a212644c4b7ea4b098e81885d44af4fcebc902c2eab79c8e707c4724921a447ce34c1e6df04bc20ec4d0626fcae871537d24e3fdb914a892f2c1a78f0fcd5ea364c430ec60765ac6559c9267e1d9a3d385defdba77aeebc9558be3dc761835624a7661056a94ec313c7df7c9e6e5659b3903bf435eae677bfb69ef2dcb7f36a2d524b40ce7df7cbd9abdfc1cbe033b092eec10152348330a2d242755cd1802ba4981d2c2cde856c44dce59aaa0547faf1a5e672b9eb10198fcdc001e5ce8ef51e40c0954e2feaa60c76b05ff37a67fd7d2b33d831d19322c551f0684700c8a49ef45d076436828cf14a326d6309d084655c48a2be0adab393ac0691c88f46dbbfcb621b0cbaf7a07b5f2160c1430f7ddc5b81c508a78e046838444be88280e574576440a090e5ad4fef38f1426d6f4c346b6ef9520c6f0e211552b4c4cf6f96783e4f625464e2d6437a9e0ca52af682eebe6abd2061d58bce8d411134709b9e4f92d68f3634a36f99eb8b59158d59499a0665e5a3a850cf2b08baa3895d48e77b85a38d16e3262164a3360041959b9cbaa51952f75120ef098b53b87819ff62ea3c1ddc341634ac25595ae214d26c8481680b067d6021bde37b7c775fd58429bb713f74c70d214055ae5389b2750d8a42f0aeb2fbbfe72145b27459340ed5ffb46a3b3ede6925e127dfc9caf81a647779361feab1a86f4332f8e496d9e3d8bba6cdd5c367969e31aa5862669c9c568fbb937fc20f1ad488b2f6a77703f8d9e7f5f83f2d287874829fd80f1b6dd258dbe0e19d9e4e9aa7adbe34c4a28b31d2e1401a139df879f69f4db8baf662c7adf6cfb23d8b9929407627810bc7727728d37c955568c8741a62e7bde1d070afe461bc0857692502ee1d07e6c0bb7d20c1ebdf8dec1376a8a4ad75a6dc3f91d87a25a81a7ccfd8ddef2722612a8436129432caa00c2fd33f5ce2d01529c45f4c33a6fa307c72e0241b48a045cb62b459b9df82efca06a40096f33b270c2c76f54b620e26e944583b634a11534a0f264535e9a964c036de4c486e2359eecba4fae7cfac032ac353158369414aa5326edb0360c33d932ab2d2543f4941b5d42cc7f9ef04d01052bd289964a2fbd3364d29174adddd97398e24020cc9e1df1cfc4d7b3991f1d14c6fd9b362361bb0a6bb2d4274bfee9ba05e7e46c69696c8500a7248f831584bf90bbede20cc76d8fbcd45b6244c301ad5d78e0c0245e404804ab8e5c6f6aaeade2b8d94056dc2c13205a37ba0be575cc7d755e0974db3e5e938216c6a043c6a42e8e378ba98b7b320f9507de32e5a06950100e7a45fd3d35a39e697fa6c05a846a2dffb605e0e6475597f3bdddf4f24466e6ea54f99f6689249f4ce997236749b25b8eac09b4471330a73d47e3aa1d31753395b96086e084b25590da38ed6ec11d00a3cc4a11dc5d95658781800731dd79846e49af7c01b2913089ab5881a0559504fba52fb85f0b3a625343663e5ef01119adc5f62b4665b6a977ddbf678559ab05ab534d101751246e5a50cf612ddb01029bee73e8bca10202f2de3ecf3cdd1f1697962fc522df5684414fe33a3a40f1f721bceebc9c487a1c0aa7f44af1db7a5695167bc520a90de3daf40e15246228458fb8daa948bb1c414f2c21fef5607be0704cc0ef402c5dde76587268be1cf13e628cefd30b1e7fc3eac18dd6081c9049ff6a4920c2f60ac8f701ea0b0cf665b5073216b5dd18ff2e04681c75cc8d89e3ba903594f4f83fd46ec940dd27743b56a05b6913a98d74075d100388170e62640a24c4de085a82fdbdd805136a91395556aa389787c3ef6db9303dc3688984315a3e0e41e14760923078b1fe6216a6f3bca2faa0e7ebf74803bc0605c73e96ce8e3f86920533c8e9060f6f64d8072295fda66fd348d9539adcea3b0e47d407b7706988eb4224c6bede85c203a3a138aba5455015d51558bb0ff175ca68357e853a9d4d1e4402c281c8dad1d1969ad4c4f8e85ede6626f6d121415dcbd6680a970712b66bea1394adf22a888f18006743f42108fa15796cff8b10fed63f6380a1be72b117179180ce8212119508c5331e71e86151243388e0606374e629233f4caea03ca7197f33afcc72d95283e4a524cffc7d96aa4ec4a11b1dfdb504f7ae6eff22351d28a15d15849a34995d47e6049e33498f6d45a8d53dd5541c583fa516cd320baea46bca00a528b967a1db47b7a7cf621342c349e47ec5b7601767b6f52628286237c4d3172f18b4639d1fd01bf79cd6a9d4ac7e1a5216a56e7b6781abdeacf58a8cc21301214dd817bef3b74ad2de319a1e9f87fe42f095623db44b5e73f19a401a6aed5c0cbe8274702bac8da60464d2bfbc58572b40bfdf4fb1ce85a84a6b77b683d988848975704576f3b39ae69319e7f03873fb614f5ab18019a30572356f74cd6862765c653618b4006dbe6656a0038e8b6d990e64559cfa394e3818075a26bb170a41c08cd13ce3fb3ffce49514813f8fa17b818ee318a1aad4516074505b045acabfdcc5a6b92ffe95525c71a6341d7542f132a9042e9f38fc4e3d4ef1512f2954347ea813f7ea166740e677f6b880c1543bb40d5857550b854a5ac0a24ad69bae112796f97d8912bb46639b9073646c7ba8afe3751a541dc5be4fbc1d05ec7728df958f92b7b2df8ad4483a17432dd240a800428fde8094473df0f4aaddd52bb402e28b8f0a3fffa122ec8805bc7488d1c9986a50b0594dd7d5fba0ec0d2d3f969ba2eb0df6f213bb2290fb3fe499a446e7da6243b42c8a0793022693157a4d8a9038f905d0eb02777e3fe40c7bce7459517bf2ecbbc795fdbb4a1db3b7b5b6b4ad0877fd2d0dd2253b679ba3dacb9fa89a235d87e6590c94f86251f6ec7fc28356dc91e6fc2ba6b4a74c8f9b652a9cb9be60ec5eaf0b8b6e233120c4e9502881f4cc1d743e8bbc3f035a939aaefa3606e23c3a26f75ad4cb454429996e04d93e1f4ff62fad2486ac9a1e04a9fa9b11c145805b2010da8aa314fccc86f1bc0ae975a9441577d5e257ffc91ae3359163c08cb469fd21cd8a23fab4c203b0984d491506ed5760ed1d6a578b36b22177b1376915cfbddec6381a0f90264325474309834d627b20558bdbdb37ddab5c4cab8980685e14e7aac380b2ff6cf2d6a24724af934fff0578658f7621fd0a82fadc7537d3852d2b695255471a822439450bca7699db57080231a29e621022c63439206f137e33cf43c75af0fea5e8f5f8b16ef7d62356db276eb47b8eeb88b852de7132ce66cadd15cf24e2284187fc0d66e6547f1510cb2b32bbcb7f71b6d198ff76b36ec2886183fdda5833225e4216103f3910b4def86bd8baa062211e6c608426e8ad05d06ea8424db96a9b3b20ca515040f76a0f071b81b75ac16cbc787df1b1a57d4bf58dc2e3c17b290f59cfbefd555a2ee730bd1c03acf5d285800d772f7ddba3b16ead6dedbe0097912f400e31b58aea0b0c07c9236b16564b0807fac272bb9cb044ce0923e8d0a52a8a2a250ba08e916342f846a1d942000d0e33dc85f11a5a17f475ab6ac520c653f0af5fc3e781283259cfb1c7d8df6c2734d1d335be6b3a300aa7f4402d15cf880146cff70e31958a20db0a0e10de48e6e9acfa24e050594e449109795a1e86cd91c39937e7743b4e586437db1582957ab657f4bc8c8c462f90b943285076ca6b27b43ac95844e80ff7846431c0a90133fffbf6087e59b3f79db207e97aa7bd08a2cabfcc08f5b3931e1a8b50dc1f49a0e6c98c80651c4246133f194b292f3deab4b380b51edcc539c324802f22d7702d8d98b0e888524b33870eac6e69483965e1026d20d64075d05e4fc4d243b419c7a6582b43964fcb014aa0a87788fea0b9d978e31ff747ff06e03743c3b85155870dbd4dab6e09ba80eb244cb105e261a401a28d2c4de4294276d4986a20371f34a7515485bb5ab26410d031443a2de6c3dd2dee6d7d7246009d90f7e7b9f8a149e52e9b19c276656a9348ae40b655cefb4b5992f438c4db81dc88068d4c3754c291ed631bce5c648a80f639555de3ce7b00a785d1360e97c36f554c4a623d291a73cfd0d8bde027a07506b72e9179bf3b5f581cf1f9f8d045ae213e648a1fb913467af858385858de14883d42b4eb6632b90565485bd7bd62a33d4140ee0370f6483d583da4320469694fe079293bafb6f482d3d67cbdb3f4396753824aa6b3892eb8cd4d414c19d9c141aae7e2f29827da9376d008e9abf3c7662c65c23f857741fc1729b8c8218b2c0dd4386f574f4acf10f6d1aa1cbea1fb2c8b927d9cdd106d96da57da2daa4891b451bff1a2d5f4ee112d43d0d94868211172cb8a8c5f4d46e5fa43ab8e3b52ebb05b84d53149f94e3888fc8a273cfe059cc16da9dc423793f03d86b6c16a0f2e17aa3db063e3890a41cd6c092ceb313d07499590f0f358f0e7ee4ed067c81040a48deee80afc1b262be249047191a856579a8d8d9f275590154cc113fa4561aa9d8ece6bd441229ee04a95bdbfd3b722b7c6414f43e00b0d0f0c9887631074716064ae77a9e778709e86742e2189afc77e8cf0b7864146984ccf1449e976ee39feebd9bdcd8e3b0ee3a0063d775faed3c2a87d110da8d495d0e37356bd0ddd5f2838f156dd058cf40514c9de3ed03c500362a350ff78d4eda953eeb792726cb26aa23d1f44835f08aa41b048d1e642764f0591f469900377a19b7188fb532c96066542213cc7cec8a18f4963f8c027e4708f21d7c020d028188196d3b49e049ef9ebee2aaf379f1c169bf5349b9be1c2d3d09d04eb8b36bd6c723d514d0e984d51f32d61c0fd736813bfc1023326f8dc23c0c5c9fa2d93eb2432fa8648dcf2b8cb97e7cb9beca6012c7d9742437fc7d57d369257de92c2482f56633b07ecf8892e8c1eb94e17c1a4fb06383875edd2d06134ec3edccdb7ac8c38c73ce9a0052627c56826f5662c48d3013af4231280d154a1077b45e785754dd19493fc9b1ef05cb1cf3c9ebafd2db3c28861571aa665677efee91387e1fb00c99fc689dd9988a12458b881a0abc2c7b5c9b21a4936a21ecb390582666e50561492c85badeef8955fcb529449041393e49ffd51876e1e161b1e7c439d74c56af4cca24e92817745075dfd70741f6da4f51165be1401c6ce58b0be4fa11ad21a74bfe4767530bb742783171efd8366cf1f6366182838420286defa700b2e26f1d1cba2487c30d09410acb12d01faf9f738cb9b3a664abd0be4f5ffb2007cf0cc0590e57a9748f86fbd16e631a30c18fd5ac3e56e77cbb9a83c910845de5a23766b49bffe7dfa245f592fe25342dc7b60a3162cbd529e38f5bad796200dfe94f1af1a7e7dde31f4414b2335e855ff46c6a8a56b41f32426f2a59c0c6b88900ef30698349284f493781e15942ca8a39cea8632406e85cdc938824142f9c8c685745d7a4f1e1e545da26f124d12f6f4b503b227043b62f18d0dfaaaf2a98e1634c776f33e3fa7920826d113c500fd7ed484344005a19307276780112a0461d356c27d0d66161d9fbff97380e6ff838c6f09f0398396b037042ac15a6299a30c936bd36c80cef37ac7c7a94b794b19012ebe12d735643b3519ac8143ffa798449bb740a30832eeff4f3b167b08ad0b0ff6fba114e9781ae42721791295ee6fbe83f3613b8dec93ccec98764758862bb6c8e66e0cdd71accecef92ed80717170c924cdfd0a3fa64096715ee35c26d9130ccd88257e7a475f05810302592bb4bc680cdd1a4c2afa87abed259ce8d76ad430caac346317f1d06f27eabb6ca12c2dd01fffef88ed01ae3c87692e37df4d40c6edb1a53ca89b2cb4ac916fb7688f9acc5565bf08585c9c00a7a5567dbf7c19fc36ead4857a5ad2871fbb46e17c176ffb6350453ced551dfb83f0194d1e907fd993ff6a4e75037bd712d30faa4fc9c0614dc97ebd5b06a7f71ccb1385cd691c05542ea0e096f8fdda696afc82969e4a115e12816d089fe1353ec8b5c7dcec3dd4a8192b2ded6ad7fffd592a594190c9480e500e65986457d168751d0de952e86d2bef69658b350aaf5d947ecd50cf59e981b0a1ad3edf53bbee824648eb2f6e3c07dcf5dbb898aab6537046c34c6a5efe9336cfde7d40de7e1595d365dd983d3e961b88cfc929c6a93aeae95a6e7d0738f2a29014b339c04915678b3e09edb258e36d50612d817e07a0012b19696bf07a18c5eb6db6950aa183c883d8e81d493e944cab775b3b310c076e148bcfd7b00dde137b9893cf416604830978de6399251f79de0e84e60a7dba232afda97f1be09afca7239f725c50c639253c7db8fcbfeb5f7e5b4813c061e755cc8bdfa1434dcbb8fe509f2f073df676d7190c42b07fe03703264261fcb4cb202a4bceaf02998efc0db27af152a91f073e259e581789010fe887a37228a7b11b00c243231edcf80196b4937caa0a1e1f3357faabf6d401ec7acf5cc1ea1fc9467de89780179913237811a5615ff2cafeb8ea70d5447d4cf6f5dcc845be3aedbbd550ba5c80a0ea1654a02cac21cc1d7876a439cb2336a2280a4868f5480002a1ba2ceacb1031bc550e3edfe5bd526201e7d5b578ffddb0b4f0dae86e12b5eccc992872abd7914513a4d0397bfb20d63e85cecfe0060d07dfdcc4f2d3097d281c12918f0c7df109375cb7339cb75914ccb22b79ac4207f091bf8a9e1a7d818a203c40a36d9b83ea158b845855feb7c494a1ea92f5431515ea147e064bd1680ce8fb92641c7c8c5926db18ef40bac33cd30265821d128decc5c2b3c5";
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
      std::string const GENESIS_TX = "033c01000005808095e789c60400c600f3e792463990852ed3b413e0f662af487acb726ecb611221288d9d1ddf1139808095e789c60400b8f7af8aa79d03eff2486a93f297b5961d373a9529d9eb4abfac450918e5b73419808095e789c60400375b1d5f3dd57e9c3dd479672d77898d4046d0a298ebe021c641f5e5e818755408808095e789c6040040aaf54b474d0faeac757c0ea3cf7645b91605c3a9c7ec1c24213460ccd8a94448808095e789c6040042932ff81e40bb6adbf184cda2e6d581a6eff361978960391ceea619805738213ea72d017feabb4a01ee56d1387ebf8707cf449dd20e2a0afeca1b7860bb2bb11a31d0a606e02becf592ad7446e066b40f54c541c7d73a675e5ee32ed6f42e9ba3b4d483dca011e68393b1ede9a0b9adb5834339fc78db0f7016fbcf60fc6308649b61c044be262de59ff7b11e3a8e434b778466ca7900596bb60e25df3c25ccebdd712c47598b7b4090d43c4e091b9099c904cec3051eeec4839ff1b2af545635c69e73df7001f5584dfdfe94954893c4f0f621439f9cf721e23ddbfd850c6d9b4e2afa47a2a9492d3737af020f4d975e20bc841bde27b5824dbf8be2ecc818782ef75abcd7cbc82b0966291c46e03bdb49441011045b35003f233de19e1d58f0a4ca21b592c7879e12dad840eca9274fa43600336366fe7e91c7252c46a813b9beb91ef9b188cc857966448cd1930a76f35c4c8e54b052c0c85d240feeb00ed445280ff71b65edef145591f570233e1e5927ea1dba89128ccbe77272b06f2cf7fc2d3d3ab0f0cef418be82b0b849300e6d772d0adfe2d95ba6b64c8ef6be9ed9deae95df43280821949987a325b8c9d22a13992c15727838cafd65f964dfee406eccb71303c9686d674a17bdb84910e75768a3ab18f2daf054bb082b649fa6c285fbcc65a911c3d509bb3b6cdb6d6a620d7d6ee4787d995e199625fe2eb61c2d3e310d1eca16bc431aa68ff99a533a3c27ca49d6041dd17061a1380397bdccf5c3e547065123ccb10e668423defa31717f61b50111520ffd33e5827b72af350d80e88165ae3b953a4a907b7909b1d7832f0162a7676d619cbe22427fbf7e341d5512637a840ebde501361562dcbc3d575a640a8d00a653db00dafaeebcc431bea51841209cd4b1fd5581c3d4d7615df012f7c986f021412f8ada1e9c248255ffce8c6580f36bb79110a8043e2a5b5ca63ecbe69e634c5b3ba515405dcf2cc046db51cf602f422f6c5365caf8d13e2cf71a8c753b71c122c67d7f1f1189a5d68bf56451e425e089e4ac67402e04ee36d6d15e15e477ff928285429da4acc6c0ef36640e1e719474df34a992e61c9cefc523b8b315f9f65318e722d71498c933190b02c1da066716b8e1d81bd938fbbc5dc9c7692f8553473d1419992b5114ba11fc9721c0825e0b6992fa456e7871a83671a5f4865ad2cd1239074f6d078044d0be3de01416a9c4deafcc8d6514a5824dc38b5fdd93510868c33574129d376f7c788bd35da90ae8c026142e8efcfaf1c99aaff1eb4bdf22ea854c4f0eca0761ef79fc81b825e94d8f6a30af037a7b54c150becbe59e330c634d7efa4d25da23b0a97ffe5bb533cb73aa89c7d5fb4791cb10f614bb019466bdae3a720c7753c3b47bbf99d2cd0f1ca142cf6ccc67f9d613d3fcf9bafd43ac53ac69c1c0d16c5a0d2381a81ab881bdfe7a66d203e553fb8c674d7622b6de8bb2ee5ad55503e84423d661649fea23859f9f9203a2a0e3cb0455dc3fe4825641d0ce02bdfaa6660270f300ad594dcadca4232c736a750ef8cc964f0fd01bf8317da625d788c537feef4c69579eef96e289438e2ff667d5e5bbc6302bea9da4550845b99c5c8e5c16fb95e20d77c58025e613b6fc6cd22f5c1096578fe97e5806114b6646259d0c4b3ec66e1942f1ea4592c5c3224da17bef3b3c0a31cbf1d94a1cadf202aee897bc2f98e6e914483bc3e0216251f4c9806e3dcefce6a90056101ea0ae6e9456eb0fb8d99312370f0422ef9d691878e3a432b7e2efaa807aba088077248ecf6ee74250bc76a4e236b5b4256adcad27de2d9b4dafe5bb84e6b9e56d943452d8de5b493637fdaadb43681dfde47d0d4bed27c1b1119406af03f2857431f66ba885315e942b58e49a3017ee5f129e191251fd86f30e493800bace5c93cf020893ce2f6fad4805623e6f1cf2cc7382433926caeb0e5d44eadd609752ed89c7ad90e98da013b217be5d51d626c537b24149fe98fc367502d852c16f0719e039aff5b02761e1092565f3c5d279a2456d9c7497188522872ad9d59a557c9a482cb8597d415d850ee5c7e4d08759956c5f7bee447eba17e734cb2dd389840fc0a71a6fd08347a04da1218acb6b99bce0542756c6a50c3b523373ae70867f2dd653138e94a1dde53542d4d15246965c9f531313ab1cafd8ec738924e18d4fe9130acbcf61eb791c79a9cef7b59b59cadf5e033c17accf74be310a5098a8b9bb78c65f1761efca425d50eaeb7934cd81cff2f5e4c94430bfd159edcbfb3f8120fcfb8a7891f70bb77be22cd21368fe832e6c5309025a35e654d64a32417121ceaa7872e483397d3791e07aa6b0da13a8e00f993f79a6e9cad8254a595ecddcf5d03d3de6a45a6d5e933a8ba1454d1fe88953973930933965382abb1cfab65d66814d624166e7a8520ea044d88e4c369a9f1a023f45af9d8ab522cfec7b0c70eb246358d972de3993198ba4fc24ccfa2016b5ea51510078784ecd74267f37686805ed875c9fa204d0001855548658884c4dee1a617d401b2788a2fb6994c1b19bb4bc854993af63f5931b2311a3a20028e052826481a13589da37c397b6cc4cf0464a7e4e64a0b24f12319747f4f044e6023dea8bebcb79b07b915b1c640f6bd227e285d9ccece30609c02151eedf0c7a87f9222a5f39e8d52842ad365c3615ff137bc12fd8c33d72644a4ed3a9b0c321967f3e3d60c7a65625541b60979aceebec9d319321c668b5e0c8ef8513ae739c4a05178548cddd45fc52191a530f37dcbb662424986caccc6fcea6d5c38364a7dc9d14102d6d930082f0a2dbb5449315f3dd2fb6b1d03d743f7f80423ef7bd89fc7dbae38ebe231fc6f63f5ad645a354ec5d45928ac4a56c3e752d1dded746edadf35832b0959368824951e544ee923941eedc72db6ddfb5c5a382a32e31e95fc126f4d91bc3090bfd4aa9ce84d74f1f9fce94ddb7766c0eed9c0e1ceb3c8b3ee4f7038fd54232d24da2f4fc61290544c8a04c4b99928e43f16087eed1305943e5cc35d165bf2e29d4d24958c5e6010514f3bc58007fa47e270cbb5afeba997ca2fa776da39ee1ab309cc9f3abea80a629ee20cd4d0e99ee4fc47dacc49f290ff6b3811309c8330e97da81dca056fd5f00df08b867b73f249284a16c1617aaf5626c0ab63c9857f6bf21413a91b9b90453802f07605e6d0dd7a3c256dccfab10e46170b176643cdaf4c4a8e2838510b7f58bac05a047206a78ce9704c1246ca0dbc29c4627446a51c02b0a752c4e018b94474e174551d1b439ecdb90e42db40cf8aa45c6e48268cef848445c726796550085f0f0f6a9cd95b8b1f027250e91d617cf66ff0bf91c727d94fa0e7e03c2248dd0854e397d01473fa2cc37c2383ff5d064a15a06f692d0cadb28098b5867b9535dfbdcec5c379ae95513635c397839cbcfbcf9b4564c0c554fd396df87868a462a20a63b03dc8c32f0c489f4e8cac5c644a37e7bcac3463a1f8511a98e53d4a3d4dccdd4da90951b2a363728e9d4f3cf7562d59503cfc09aa6fcaf7bd6bc473f7e74c4d0ac527435d1dddd7309fd7b54c94c47d49c24d94046914537750a4884364c5e9e2dc4b87cb2cb89d85e6c7c436d2e348961d9236185c80259dbec52a13e67a119c60debdf589e0b6d1a6162b8c4ad737d00143afd467d1c98fbff89277f3645ef9bfc1fdd94f4614f89fd7b6e83d617925dda1de4191a8fcfaabf613198d0602b9ae72077cb0827eaa7c60f5508816434eb4889ff9e58c633b170af76b7df101d216cd6a076d1fe2e348f4c21de2b61bd6379ff6335b4aacf37dcfeb94bda68a9bd790f8a280b2367de5b9d701d3f6f7a73b862ee9f76abc2d1270931897a66a47295c4faecd54b0910b7027939499d9424168f9ba8dd3774a7a085803fb07534e62724104136e322072c19e67d5a5fbe6b1beceba0af735315bffa0dcdc2c83ed8f809c996a687ee44e82edd281bc7c46d287ff3cf39d5a5fecd7c7b2cb010442b55edc17359c9a0005d498e680f0cc0c16df25e577b70c59f892fc9289c79fb77ca3b1ca1fb78ec83deb74e3eaa5e8cc738a28154b136eaec2451ae34b9775e8831a0db983700347431665050c019e9a09fe84cad6add05032f6cf196a31538ef5ff076e9ff05a5a6177e562c5fa9a2cd2f8a046d9e8c3587236953edd3dd0c63892a69f73e8da2010aed38293917819733ebcd0eb287f143788954bd59b275b42ccc29928ffa09ff99c97111d5423e331077ca534b69793535f61b8c6e93ffafa93b6c4ba95be5c03b89d3b566df8b413f758a70b4cd9309d6557d1108e0db950687ef59ea6ba97c8c3cf5b5ede35c37e299a257bb3d6e5f0e0ad2e990a62bd82b71c32a17bd8530b76560d1fd9bbf6b5bcc9fc347cf24343447a931c8a27fe2e39689e35a48a794ecda4aed2fa02683c9ab278430f0efff8b580a96269185d49255ab2e4042d8ba77c8ce623722092fac09b8aea5d7a68bc1bcd12de0f880682656fcedf58e390a91ccbd75ef4b401c0fcf629f9e1340bf97ccf638b5891693e05af90e5a745b02ea6ad6cabf0d9c0da5c34e0acdce4c5ee94b71b0143cb570aeb77b52e776be474d7e74cd5a46d8ab56780ace200abb21d3b7d716d00aeb58afe0b34620e7b87c39abaaae70ac7d6d5acf10f295ecbf6c7f1ec54c8b946db7887eafe95c66f2462bacdf35f18946f4af683ae08d19628c38701ad43cd0bd656d90096f888d13d420313edd27611781ee9e77de00985da7a8352f525c46c301da0a6a6efe0c6342fe50bc00a17fcf876aead15a3e2dc5fc39e7c22f2167d8cab75f76834936b2fe901c7217aaad0a23d3dc9c60d2d53f1abe4bc9bb86581ea90d9323aa1808ad69f09d2e7871251272c373f9753d5e9aecb951cf509e5a253094444ad1dc9c1ee344485479f5153321ea52b977f42b3d693f3e1bdbfed1bca8b4d510ddeb0d7f54bdfece6e2f76dbaa0b63a79bacfdc668b28e9d1fd55fbb2d673f811f64d1bb95b4d94a745b6aae905581b967185fc0a667f3c94a2240ecb377f797c1d2726083d8538378a2ff7d284d3d86d353f0a8474c5f86d5002d82b1df6cca3262e1b0203ef645785e7858b5f07053260727df34f23598a2ed26c35e8707b7a2e32810324011223959171a14a528d4ecf96edc7aeadc633d0ab86cb092b5ea8f71adb59b3ebb1ea96457cf3bfceb415d8df565d0d52cc69832ce25cddc32277317f9b39a6f118f8bb7d89d3fbcf44e04f474780a7ad1adc0b9748413c8b08aa229a75c5ca4fef8a7fe353971e4538435ffc37f8bb8cb38dea21c80766f2e2049e7555d50d30fe822dffb7f39adc6c371f26d485356f9688f5eaf98bdf46202be8672cb185e9712a6d13334f3ffc25ca107155b203f480a0a935041e32794e78355d10545afcb8be4911e6b83568614d868cb3684ada1e86fc44465366141d687539e88f477f66f13ba40a30e0886bb6d8a81d4f8f8b9bf516516111c1ebb90feb191ffc920e9ee36d6dcd92fdb709c7a9d766b0bba7959808192ed94635cc5258a5b0fa3eb85895b207e5e55453b0d60555c383930bc686e420c6744d8b80b39e3f2aafe643a83dfb0367680f5d608ab074ed0f384874b92ceb1109393d32b63998202cd4084806bd225b9a6febe3fafda96a8dcfccd56acc8c092b39974e240d04137526a52763c434d2b559319d8666fee20639617445dfdf9cea56ded50eb79df7c852c95de7fa25ca04620cae3a11273f2a9859f638ee9ca1cc34a4764ad02e2cc29c08d7eedb5ba660bbcbd19f6dbff0e531f74596de13b888fbf7e5a299224dd64380c1368d76afe94e33d00b6844129fc2fc12efb909d356feccc6d73f46960c14315814226a630ffdbbc5c1dc51f6f84ec52994b4521a9a75be33141102272a168752896465098f3c9b713eb7c7be4bcfa2ea94b9268262bb4351c2c6668edc34da7d40d718016fe31a78adb73060aff09e43d540f8728f66907de2fc3326cef24fedac7b32353e92fed0e90d3d590b59b3ef62774dc7efbde35eaa8cff43916e4159f588591e8ae0628c33d0446a42086ec6a0bf2549551712d85f583abba808b5b79d1961341cd4adfd8db0f3e1b6161533d1c925edae18092013984aa7ad14305d142f2ac852f17dfa6934a2d940b565ba9a8d44eeffc498f654b8be93fcb7084183c1ac6f6b510a8c94ad46784ae539d30c09578f1135c2603d5378142dfc3162cd018a5653f8575f5d8b003eefe2b6368d8a8e7c7af412163b7a58e18a64d5ee8bb4edb705c58788ede38daf83693eaf723c940c1376b8c85e8170d00b6f0d297232a60fd3d84fd8eb64bb946f1e6a544e220aef5c6ebaa6ea98bec4bf335ea56dab6638eac6f90d53924cc3f78f87b2dd5e76eace23f094d3e19ca16ffbe83d663cc69dcba193af08786792617c26a483cf373b86c6a6efc6510c7bd27f16ea0ebc7567eb40d2fb55a467250d616870ae6cef02a5352ce6f587b0506c36a7ef6d10ea0ab1690b8253aa74c152f263edbf2b01f4606788e9b27b86a464a8ff480dd89c779f2eb536de394421bf5295c6e6fc9505b6951e4b615ccc291c54ab2f2f38598e45c99eeeec8dec292f56cd1c0c9276488f19e35921697641e7caa29e0165bd32c5cf5f341d6978ed7a8614ab50dc4edd8a6115bae218bd2afe3d30a26b7045bf9c086b882f494f5d94b55980b21cfbdcf23c11c53268060dc3482f98083be0ae16592fa52857f44f3daec1fefd6a3a65160b34a3ae20c6138ecc23daad7758d7258d1291e8b84ae76f33387a3fda006011a4516e41df1f9a3b32adf22e07052e1612a070f16bc7077b52c20a03356eec31c660474049329ad1a927f8256796ef9087f1e80ed6e2886a3c84d351815603d516aee15f5a98a5235d6c84299ee1aa8b3b32fe8178c40524b5013e2a48c446966aad485ee443a3f76b0df3506acd317b6e48622c8b8276bd4ab10090e29217396a3667f7809c79fb870df53ce18de8e2d8da9c05a505d413ea015ee91f5dac7d0783fcfd5f88389a1ecd8693ef75e5ac7259627e30788e43ef47955d2cc517cc7eacb605f4d0974f075c1e40be99f4871f9a7504971bcea1a648a8af5ef51f03d3ead7ab43291399fd0484ddd0a04f4bd2137fca1a90d5e3723a61693443d3896c43d154e7093db7de73f3e4090480aa0787c3b6e7ab534bc15f4a5b75eacd403ea4c715107e7b132e44e6b277144f0f426dd4f69cb76b299a72caba7452c4b6e9293c9e8c8592fa3534e1a1502be0ba8dcd18bf6298cd033d369199b24228066cad858a1cbdc0b9c279b8d8472619a1e678aea2f8fd52c786805e77129793aa91010a8822c9dabfb94d3a5a0c5de8685e909ae494f1e6083918f7492c8f70ced74fb456e38e5f60bdfb26439b25c0a37803df9cb58355e2011f35069d788fc3eafeed7a98448b5acc78226c0433a42bc2b5692003a55270af3056a007b63a5cdc9324fd4dba6a3b18947dc77cedc44caab9a8a7685398b844a5d720955024f218588433eb7482d6fca223a092b7328ec5727bfca2a8a01c0e616b17d793b15492fa5fc241230a4110cc804e5e36f2a6acbff026f8da0d9e5f821e53deca170d6f8ef66c4a97e1f2e4a1c2dc396e4eba47e20a8b87eefe29f92b7aa2e6c642d6def7f6839c65dfe9cd11003da984a5945af80fb647ca2283bbe1d3d1862c93ef0407ae9789599cfcee8c4ee923af18cdbbea6eb6d3f3fbd354da5b6905d78164ac18c7417d072c87e3fda7e7ffae74df1c4d6078e14240e0ac118689d9fea8e17fbdf0f60e8d10922dbb00a229d5f18898693abf9c16b6f67fadde731432be03ec26558c598f99ab41e6525cfb046199fa22d6979ba97be78caf0e72ba597c818c2359b7b2afe835e44a6ce0b158d49af8cdbbd04d17da10472c3b22698e861dee7db171723036b73ce745dab9d126b9be5a1b84ca86a028877ab04b46ca17ac18b9b43f7cde6f35b07a001dc1ec0b487bbf31c1a9e3a6fdb83dfb7e95b1383614d479b70ef574c0a389e5658161d2c723a22679afa585ade6a67143ea31247b3c9e825dd588eece0bb6b696848d0140fc32f52417072103e5fb08b15c29679ed84862d825b61ce6638067f84294bea37d0b3afb144447fcd920ffdae4b39c286b680ff9a07e0e68e502e414a6df2476cb5986cf88f03f5c72c539b2bb64c41c4f402271d6d754429b5981d005749b004fc25e1b5ffbf6151ffa2b1f0234e1d7ad9ce69ab05e7089ac9f354958d6c154cc32b97d99c6586dd87ec703cd81a4c0125cf03be5c199d8b31f70d2fa33a90e9d66116b0c5187b6203956eee4d8899d220bd287125f71520878a464fdaaf1e35f2101d0bc5f2a145eda83deba8d19c7909eec2c6979bd71b7d022d45a10be7420348de57b46dfb00f79b471140b95a701a9d89a213bdbd5a248d28590d10170b6920940817600524cd8017e41a754ceb976fa37f863c4c112e29a9c22e7a861963cb1b0f347b85605f19f0e16fbd6ba39d8d76de512873c8fc8b451e39c935e69c59d3a0fa5dbf265bd906bda8e2ca66eb554a4a0014";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x2D, 0x21, 0x97, 0x54, 0xA1, 0xBD, 0x79, 0xBA, 0x05, 0x40, 0xFD, 0xFB, 0x8D, 0xC8, 0xA4, 0xAE
      } }; // stagenet network id (rotated v3.1.0-alpha.6, fresh-genesis)
    std::string const GENESIS_TX = "033c01000005808095e789c60400a235fcef428589da603471815a0edfcedbb03d7a3d49213b0f161639e4ce824f68808095e789c60400dd9e22d3bffef4ad5f0b857a8f4599f6b9623ff2fe3c1b1b5f0e0d7a6c81b029a2808095e789c60400fe7732d6d7416c3ed002ead0acdd3634dc826affb899c02d024b098bc3eb03f81b808095e789c60400032c563501954e32c006b4a6a19cafc97b910712198c818cf124163df49e810851808095e789c6040065940aeef3d51e29dd0e17129f7571477d86e1d1517747aa6ef6d276aabf6e94e2a72d0149b618dc3ef290b82b70a1ec99bef093d9fc0ae3984a79e2e716fff0b9f659c906e02b06068b96d482ff7a78ebaf8ce5ee7c0c52e93ca14fd79d5c6dd3064d3ec1ff3045fe394b2e4c780172d26e58eceac034960c1a70e26ab8072662ccf3c95dd1325044f82357d0d2c0d8a533a4ed99827b31bc7741225a949860c783cc5d65c04e6baea2962f6aa587a5aff8d9880ca51546ecf1ea473a37a456cfb25457ae0ef53838ee2debe480d2acdf01918b56c0b15bd915fc9d7e5bd92a2928157933298d6f3b60ad2d6e42dce9d05a082a8a747ad462e0336a3017be887a7ccd7ab299d59f3d0ecbb5fb69199c14356950959f53014f9c51f96d2d0916f8dec991da6365796a4ca75bbacdff3e5b98879d270d81417677f5743ce7e1d529566867e77263e5b9cbff76d7e5dbeb9abd05a22902ced44b798d1f34dddaed117268fbca41c5aa47fdf81598bb62a86f9b340f28340eabba0d0e2e765005355856380c094b005f7baeb8c79c9aeff32bf60f6d90cf1e0f1f6b6c03855eabeb767780a9bcc0c317465cadba5e286b3898f560948de366263b765819fdbf1f0b47d5844652b7a622e9ac4d494b82f56aa0976d26f43762b2efdd18358f92fb21221b784368934cbd7367a7574c8fbc30c05fad94b1f3c98a017a0d2550993fd948c9043114250fffc2553d45a99f7bc6d74c330a6575680663e2ea65c3da0ea1044aa02d9bcba1076a10adf26345323281cd20eb29330b232e1dc199723aa351ac9715d5fe4c3c5f723618e0f671e2a2fcaba374c1df7e600ce19f7c5cad13e3af8c241e449b6b3880fc4d6bc835881d53bbf770d80b8f1bf6ea7936cd8f59b047f4990371088b536e0a1860e09657f6327359a59d4a4848cfa4c315f023ecf01bdbb2f52aca293dd34099eaf3b7421594e995aa2e1d1720e88d4a890b862e023b4077596751fa664fb93864184651e376a5f69b63d9aaea3cb2e5f826a563fe2a1af184251d5e4f0a2183643b819090e74b79b99eec141a770eac224e724a28ef0b752ba023134b921e5d27e3f1353376e06ceccb3d89841bef0ab4d4175f4a4a233a5275779a94a4a6b378b776a2b86226db9cb684eec9d39990c0050999c56d5e4fbb1126caff205ea2b2325680949a9b7d206ec7c1ab3ff8f60956cd84a86f55b86d70f8a5965022e2cfae7da895cda9e759cbf3730d1f3bc0df1351afd7ec134dc73c52eaafc4a4040f34829613ca1c26154d66d7eda6dfdf42dce2457d7ee087fc18fb92496d7b2836d1d9b6268d931757cecf8beb4be8f31908dc5fdd76cf88e92b7e33850270a9cf3e95d7b80fdafbb8b12a17efc682a4186d4a859301d9eaa544d237f004c4b70050e1157175ef19cdf163e44a4f990480766edb70c878019cd3dee51f899cab10dbccec6df1c7488ef7b1295e6ed4c3a31f78f48443b06ed7aca0043924255561cfc50fa17f7043e9acf6d685d7eb042a3524372673e7e77e9d856f269082e013d9b06f419c724fffcf92656a3ff8d9a84d756402c960392248a111f879e6cf7bc5c5f1e7b85c7596d2b75b1d2dd03337afc7c3dedc1a7551f8842beef0d395bd8823b2d99c72ef54574e5de5170658e8ae7c64963e4e32150e0643f84f53d0af13b7679fbd0bd5e99f87f1c4fd96237a218fa60f1935d4a85b8655f3dd30c2e5e46570c1167344d76b5dbf83cfe905d48ca73a7ad3deb1b168de97726fbe54c297a217864944cb604b6fc85518b687579509fbb3698eaef6c3ff41e806e33a5ad49ff0467067ffc6d64ea5fa2a24abbb250845a2149cafaa95653c16670f9fd1477c7b41e8564ff8fe98fda1c651a3363ae81bac5dabb5e9fdae4e71222946ac783a4e3424a95961ea54643f463aabea494135dc14f00b9b1b5938c6cbd4f3b664aacbe7aeb76c2bbce438902ef6c9730262a7aadc7602e14f6b7eb12bdb68adf648b3e007637fd404fa6c93817756daacb76a7ed4fc71476381e7dc7567519e20b6ad7cd77e1d4c1294efa3f7ba8def01352da64c19a50a5263a2a1d3554ebb684c48420dad8fd4642d49e70d7acfa91d11dc0e24e4fb3c1b786a0cf190cea5925df95a31308e0170b13067ac4ddf3b293a9de366f8a3ba90530844fcb1ceb2015947a35055a01f6c3aaa543144640fc2e7e96c984d85219b33d7fa310744d16bd4bd132244995ca1c009214225053dc2483f13627d71f168defda1c60621bc6f7064a9209b6b64154326fc1c05dd5c8e6e5bcaee823f9a48bf960c3a3b34b32cdcce17b6f649c8c746598ddabf07db198b1cc55d6cf0403f151fb7f94d5bc115d38508ffb56068a99183361fda821fb39f53f7ad0e25e6dec8d280dfb4208523fa5ccf52ca41cb3c87d999f90c9a54dc3dc7195bc5d31207bee6058d32e17bdb3d9ff0316f6366d4934dd33392ab7637b59741c7dfb05e1f90225c14e6dc76bd634bbbb41e904c52a3bc5e67c6167f4a95cb177a1a94c77474b547e4418a395ffc90060c679564ae243b71e3a04112b31f9c11b1e27361577c99cfa92c966fef67284c6a04d652df9492e365fc669917db02731801e6592dad4c56c0a9631548096837370e7ea27964c9e5e091506a615bf8f86a55349b6f4f9d5a133c57e7b81116a2a0ac978d852c91ab55a745538de14e071c3d4a7305f57bd12a53ef2a9b5860fd7ecdf461e6de5c7ce30d0ef747a165bd84a345fddf2438987463b9a804025765a833b33190dbda4284677b5ea75bf23403832eb75818766217a0341cdc76028914e9de674221bcd1e1fa98a09252a7994a8d7925556eb1e0b3f6b31e4d9cb0ffa0c09767cb49ecabf9fb16cec0f9b095559f043c1378f91d8edf1102995226b1dce2bc9a6315cc9fc600a680da000983341af1cef60bbde45ff99511271247770a2d55463795f35d13ab63ae8009318e994b0e7eb3fb51258bf7986884c92af1fcdfa9737e084cde2856271f1af5ad8d1483d32428a723477f7e5c1c7d897cf2f5026a4a388e1f98b3032bc2d17b3a06d763c99bffc2c9a56ddc91f3ea02b42d32758e389caab25ab13de9019be32e1e54472eed47e2cfb4f29270cc26bd8c5938fed78a4d194d36bbf1cec174067da5b9aca924be8be387710baa297bab1ec4cc235d0464836bd1fb39b14a0bbe36f2856766b619b6b30a6a847e3b785be651097e1f2ecf6ec880dddbaebd5b22344d5d941603273f96d31ef1414f4d53f3d054ccdd8ff42e7fbb1b865bd17754a083353abe69002562b0edb1a02b55f9e85a9199fcd93e865c0fe8c8c5559f652cd5d1e744835357cfbbd327c1018367663ba19cfe7bc93f75528540f67824f581a22886ced3b68ed004883412bbb873416070f9d764482bba7b08bb24805c900b7a5868c7b96200bd5a7e1198736fb947861e9a88ffaab67bcbfa89f4a436a15c2e6608dcfd89658921e84e3930e2c6f321aeeeab7e94b6ff9a5181686ae717f6ea0cdc19e5a6a7379752a6ecc65f71461482e16212d0ecc0203819c9cd922f9c1545605ed660f835205f1dcf96fb632f19944f5d68976fb1b811401a7031c2c4a150cb1e99cf014ca23178ff6ed21b8559301380edd9d3b19ac199926e689ef90fb797bf958ed973e604f2d0e5507e07964944fe82394cbbd39bd9bdf795324e2331fc1e8c861bbe93bf4531aea501d02d80792fdcb059f0dfe09901e353f4d1259018529f080b97e5c6f3f1aebcdbcfe567055e4dbc0561b4c3604850beca73d85519a3c9d04962d95dfc12fea5bb93d7d68f27702497bcea73c175c475a7496fe7b23f93e845e36861b671dc5bf271751c2789727990e40ada88adf5ecbafb894f8447d57336748288a4f8062041d3ebdc3890cb62be6f9dddc85c930c6d955cb6233eb3b8067448e6f9207c88f095321356f794c71cdc78d271134e6da185eca9b8c8cd43a6677cfba2a80abfd4ca36c3b164b732623934c860f379f872bc19e10309da409df644d99181dfcb5f5f8e83298ed19194cf28e877435f5d12143fecbf4e2478ff35e47c4afe11169dd5620e063be6d905d686edbac399acafee6eaaebec51c7adce445b67677b2c5d59687975c1c771ffe5bcfd4a50749c3292507e3a889c0b12d8824c24b8ba2945dccdae0611af27f92804f2837dd7915e81ddbeec30d56cc76e1b4ba09e858f3ce0c7aac3d74c99158eabb1a05966781d4ab1fc5bae58aa2dbb20168f22a1bf9e5379cf624706923672572db27e3cffe37fa59ed7d2a14021a599abaaaaa900d5d4b32ae305fc513b036af13cdc507d689392b0347a7f702f2f0341c81e92450881f1e3a96d9a4dcd9c25a9adac21eec3490868c86331877dde493ffe88a6f1ef4a8a7012043b90c539966b5da0877612ba5fc11db5fb7e5c9a034860bcd7ac4a0d76c7a1fb8eee0b1ee404794412b091564ed3df3b6717ca96e7f961d54c4b447529bc1a730c312e52b3db73571f5f20e6be6a43ea225b5970cb9a5fc9151c72db182c9a125a7adf8634d4940c9c5872fc22cbb11975d30b4e775ed62dfc5f8f761190619e68d1e2cd6caad04e30e718d12057ea1432d831492c9c77029e3d23d30114519297c219b8f174e82a87e23b8e87e6cdfc801ad7b406688a84b6ee887b4c67664ae840891833fca94ab3fcee4942b0ef5b8d5a13f019ac7bec5529978a56a7c60a90207828fcdde4d92230fd4c9b273432d00667f3de497d0b60f0dbf8699675acfbad22f9068318175385ebd2cbbf583a46a2f7d30024d2c3982fdfa14631a48d3b053946217df0a663b4004455c581a0ea7790b95ec7a711f18605c27f7ffc50a82e34f75129fd435d4feb437047882bb07d21109fbc8b5644bd44a99207143effe7735dfd12f00d29d5f9f1f0262a34bd4af63318127f6232f4847cecebbb56b078423a3602c36b1eef7c752c1b7d646183626d72b710c500e61bce9293cd83627c6e5cf90c04bf0fa68b9e8a15b2780e210d88aeaa191c70ddd45613a2a02c733ea9210363f67556a282dd1fe67e36e0b51415ce3fb25b7dc2677998dcb5d8467781e77c41dd574614fc042234732dc51b50844a3a7e4bc97a13c7cd8e7497db99d026556ddc3e39559309515bc212f33b956c88a123bf9e389f4ab0e5e41832defbc8cf43896ccc0c424ad659986ad1fff9bbf9160082189ed3d9e6add98436809fcdcacc8b63760e8328f6863a868526c97ca77088d5279b3d2293be2276557efe7ed658545ae07395e1e0fcc226415cdeaf23cdc0f634ee89a1911c803efd94c4951801f82bb747fc6c9c6892624f2dd3597659ffcec6b6b8e41ee0bd4b0552fa2aa77becf9f8984f04d05442be52151caa8b970c7d9219e0a57a73b8ce10af4af6c9b40d5b1b9f002193d81d3ad956402877027b043b537196f67e25d83ce5790877ee45d9dfa4689a9d58c89e3a9d5922ba090d64251df19bef0e00ec79716be1f0475afddfac0498445984c2f27809ca5ca6be32666f3aa6628f34f845ee97c1575d58911ae78f35cd6f3a6e23cb75cbf1e09144accaad7342258f9facb3e81631ffc7ba815b6470dd3f71c089a078d946ff81826a8f09ff300fa61374cf5e3b774bd512d48b441701176acbf10b0759365e54984d3a8f298458fb95985ce43dfbc11ac4ec64d3eaa917ac8641f5de5cdea5bd34b205b3c3078577ba1f426c82252558f8f9603d68222143ca121bc51e3f0b7be923eb2c9122d8d9ded87cc0adb675235b8dfc9f7634a4e4f81a4c7c997c9d0711a55a123692ee063619e235733d79e9ad1f384d773606a89404996c970deb14ef34cba00ad6cd92e0c541e3fc366f5364046a4eaec1260a186b457b4bd707bd56cfbdaf9c05e7e6c8f5dd2b501c2f93c95da5caf137f723e27de051258ad55537373b60b5ce4a662e658a7197790f526e7e830e1438582555d7c0990ebf2ae4893f00832eaa33e9a3bb03f7b55bb358595cc34d734263783dff7876211094bfaf9b6d11a55a4b4c3ebfa2a46c34036926435f5d05e4e0cc7aab1573eb7e1b71a7e8a73c8ffb0eddea4580b6fb7d674594b34a6a5e71ac9319e97ce31d51f944991fc67f38a5c1fe424a2a330bf5c2826035da78fc33c1a99da5828a09c32d4d5fe5149d2c0301ee6ffbbe6209fa2100e28336f819a6d6ae7eef15bd1c1cde5c41665183f2781ba63d3cae6fe7f5a4827764becd35c11f7726e359ddffb11633a12ff8933827338a8d756436feedc24c0d66e8fe70b3370ac3d643e3ec70f6fb19756f7b9ca65ea17eb3597e11a10ade6dac23e8a59cd3cc956da6df0bf2815a40c305af97d54b7bb0750ede480f9cda27152e3db2ae4acd3612554ea8a5b98188f5a3d8e261a02b8d4c1db0fc14636aa10c3924c5a7e4b4b26a62ead546dc2aea2f364d4f3ae8f54dfad952709a2be4b3ec96b6f7735334b5464ab8220e342dd46a504479c1e4bf21a176973248cf66e48b39043d7a38d34fbab4d1c25cca0d11e918873d95c7f854ddeb1fb969c42b06cafc6523cdbb1ad99c5c4bc8fcec5768720d2edfbd96f8db3983b3dc1f9d83a0764a2bb1b309f9d2b9bba99e35025ed1ce9b6407c0c21787a95da12bc2d308226a01e34c06597d68b5fe23fbfd0964f561b5882163280bfad5085de34c3f9b4083e95b20f58bd381df59023ea3950e042424c764ccf0b5c419befa0342e0fb5c43a61cfa211e0c18efb35285071778b55bc5b6fc312b8d02e86b32569117ff97bbf203c18eb10576c881a5b9f254331770398ac1ca29229a6f065d2bba63d57005a702d4bb14e4a010fa54569973b05cac97719c1c57d3d10d8813ad15a3d55452c25edba78317c5b5d232943b4bcc9ede4311cd0cda010ebf6e7fd6d6c5e8564358e546ec81308df0b1a9f00c396f6a1de242870bcc8d6ad9d50e1777f085c5864d97ead558425795674d4266f00c3b263023a3cec3280766a6ae2b4145c11d91e035acc8e3b147e774442798c34a21699b1c3246e680d5953f03bccd94bbaf840f3ffaad1086087ac4886d2e92b146eddc658ea369992cb55bb01626aaf559f329ad16940e86a46c8b8043f9b7f9d859453efe21d06577970be6001f2ee1589faee170ae26691cc921bc0338545d7de14e48464d0cd127a3a4e5cd9766e68888cfa5416874c0fb18965eacba483ad701a2872222a13047ee3c0e69d0039cd0c293455c5d40f9d6c188e9d5654f304286faf4e2a18a0c78792988765ce136547bcb827acafaa20d91788f9a6a1880004ffc407f33cbf5e3f22ec9105a106d02950838e0fd2cbe224005f8dfb81ed0c851445c50a06ca3d8a7af84a741b5ff7447fd917684dcc82e36b50df298adaa693466a044f652d78b44cf1c80c6eb2edbff94cc70f5f171e9c968884fcbdd6e1cbae61120a4b9334a5261d4460a31352084c456c4de2321c3a419257eecfec226ec9779ee7e663345029b48fd5fb114473076129583e1ac40a17d0a1817951f4788cf13c6328a33cb3aee91c728a61fb2a4d6e16bbf7d3ece23fd689a1155f9d5a46c5df53453ae9b26cdac308d2f6daff23740215211673b27b16ee53a9a88382a0a72f4aead193fb61f51a083d3dbc508f22a87ab7b411a581d1ef149bae8111cab006b4e286a0cdaaa7b97407f26f161c2d7ae9b06f3b47aa350aa7b8b5424d4ec9ac2cb8230a0798a25aa66641f1d69b9d0dd75e74af58c51fc7d61dc7314017b3098f1c5e03036fc3677c14e3699f94d1b45031bc350972f30f9159e08fa7391c220dfcfd8c67ce6d6e7a58637635dbcb25e6e0ad5f982a0ca447bc465d998404b1be3964b1190fa33e73a81b6c5189b7e70f5184b8690ea586078b270079255b97620d67188f1e3d748216b76966b299307f86a0ee294d64332f3b01fb678eafdde29c16cfd9ef4bbc4284a04bccd60be4e5bdccf04df5c333c863b7ceb6868501ee47be0e4ba6f2cde7b04c00ebcd5644e7e6bdb8f5df3590607a001d7716e5030f1e29636c6908883989a94d42833c8cb151774bdd7973f31342a60802c4af1fa6ceebc0f70efd8a6e5153c0e1a87f9afad7ca9ca05ee7838044a0f74cf29b5d3d5ba0dda1d3400509692467bc13c584abf2be5660b210d6269e700fa10848adf6c0e4fe7699a73d7cdbc6efd72ab57b22853dc1a6f0a811a02630075e1e43d96089acee8a8cc57419ad525cf78d07097d63b77e409092e5c623b1900f017f885165c467fee850a6f07360859617a00163fc36967c7a275d860b26d28c2170e4e479744d0d16fd55a69b818f0838c094cfd938b09837ba33bba06887cfc07b7a0c57446504cab9e274d861c9facff6859560627034d04d59a247439500c0cb2fca73fcd9c0c072773198ec3bf1f82999c353d0eeceb9a4161f06cbb940d0a2385358c3a1dacc1b93aefba4ac054d814e7b790a816baa5e6f7e71c7f4f2f93c06749e79b5891488c09b947f61d9bd7b6e71079a5caaedabc872f1293d2497ac4054627f9bc9812b489e831c3450d83ae0d1ccaf9ee470d66b5e2b192eec7d289c92737fa495a520367a49c3cf48ff698fbbb083aa295ca";
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
