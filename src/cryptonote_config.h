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

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

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
// LWMA-1 migration; see `docs/design/DAA_LWMA1.md` §9.2 and the
// `docs/design/DAA_LWMA1_PHASE4_PREFLIGHT.md` §3 disposition.

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   SHEKYL_DAA_TARGET_SECONDS * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT              25000  //max blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week


#define CRYPTONOTE_DANDELIONPP_STEMS              2 // number of outgoing stem connections per epoch
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 20 // out of 100
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5 // seconds average for poisson distributed fluff flush
#define CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE   39 // seconds (see tx_pool.cpp for more info)

// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

// Both below are in seconds. The idea is to delay forwarding from i2p/tor
// to ipv4/6, such that 2+ incoming connections _could_ have sent the tx
#define CRYPTONOTE_FORWARD_DELAY_BASE (CRYPTONOTE_NOISE_MIN_DELAY + CRYPTONOTE_NOISE_DELAY_RANGE)
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE (CRYPTONOTE_FORWARD_DELAY_BASE + (CRYPTONOTE_FORWARD_DELAY_BASE / 2))

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

#define P2P_DEFAULT_CONNECTIONS_COUNT                   12
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
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

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
      0x6F, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0x6F, 0x6F, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0x6F
    } }; // Bender's nightmare
  std::string const GENESIS_TX = "033c01ff00018080e983b1de16038415337912b33627bb97b87bc18249c02b4efbb22b6b9c439f0556ae654c08eb7fa60901c67f3f1eeef178e8be72d109cb3cbcb65b2e81aa10483b9f43c82d49224198ac06e00854032e50e1f3ff94a95c3b7a10555eb7389344dc3be473f58b7c1c74b3366d209f4cb55f915921559ed75ce92cde8bf5e71cddd44bc108e5b965d503725a28c2c9080be84d579500adba8aaece5678893645ecaa3c7cae1122115099e4b9883eabeca5546556e9b817f30a79e5690e85b6438c995abecb77742524b2052c326de1364fffa35cefe19a21c42c7e93b47dae4b512ee8f98950d26197fd0086d40be7945ff69984f19b4bb37026d0f12eddaa8535e15fe45502f1fe33460c2776447588f451b7642262bdf4c1bc253f068b3edfe390ab8daf73863ffe1490394bd3779acffe6a82af734335ab5d39bf4fe47f7de78d20093a916c53d74a073a67709ee419523d32d3ed35ffc455841288ffc996b308afe964cb95f1dad390ed47d9262e49c9d99587764778c8e98f07979b746f2e6117314c5bbfef6c075286838f2c2426a91174adc71d67c3dc0f9a36f03ba379fffab715c13162d00d62a8e73d5fd31541c7d98ea07d1522bffa30a080b21e51441812b8332e48de789b1358d93f5807e50e362ea95afb81f3b3c4e41f8b94b1e0bc0815fc3d35732339df278c33dcf8d0e8d3a0fd544c067115e80696c0e0abe61055c749a394cce15af7d879d85ee2dad28581a3d16d81066b343fb6e5308579f9bb4a7d334e9a5071c82513d637b52f4fe5584874f4d57afd86dc96797e7367ca03dcb7f163eb5c8e48a3a4207a20d4356cc156d910322e101c1fb2681760058256fdc99fcbbde75bae900730a29baf95ca889a7ef86576cc807b7755aa8ef1dd2214d5f1885e5dabe3956d2226509a8a29e2d83f8530137d5f25c5ce0dda2bbf2c59a45bda2f97f54cc04f591b1d12a7ce04e576ca4a3ae324f29150abcfd277210d7ccf041844e17111869f64f206fc86934b47856333e52ec1a1fe7e77b45f3326821e93fdfdf08e5db63a6554aec5a5d89e0b91c9b6be9170c1ea91e683665fc5daddaeec02e2b4c8b151d25c9336dae53b33e80876b7778adc6da7b260d3186e6732d8d00c2c3af1f8274b48813dae49bcbc320b7d15f0555c730db21f4839b477e599f1e261eeb9fdb0adba811a2f8a76348405f2d8b3096d1885fdde66b114fde250a7072837cb1159b307a4a59eab68db56cf8119eb37d57ff4e0534cf10cb071455f5f89ad845fb4093293de940e18717fe9b02e6aa874ecc3656775d3d2345296c814a9bfe121eb57f1313816939971d13b08a02de03c30908ff5321075a90c7c80241b7a404d6c40c011db802b1b7e18f61101bddfa9e07bc2795c42294bcb442bb091d96040fead457d16bddae8045ddf68e2a93f7d49b7f11662b89e7a5ca3b231032900223c2e3404c6a3bae8232fe9e618a5160533f0617792ea09779cca00a00b8616cf671c35536df504a31448341561b3788d52196ca16129d8c0c0226c347ec000e3785c566e933c6389f541bda3690f51f2d5afbb7592b5320961c654df13bbe767b1ea23f1f621ab547d68bc524797f1464d1095037441658e13a3336d8665e134dac7e9a18ef6b3efde29e777010c49028b49f6ad4c21ab3a8095bcd81c5965cf07204da4b6632245d15e4fb21babc487b140f50ab476318f1bb92030c29d10e8772b00c8cd11891c0a6a96f1f33727617c5c73398bc549ad254db71e6a64955f99b9abaf056d5cb039c0c41df18375a9f1ae4b14dd";
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
  const uint32_t MAX_MULTISIG_PARTICIPANTS{7};
  // Max serialized PQC blob sizes for deserialization bounds checking.
  // Ed25519(32) + ML-DSA-65(1952) + 12 header = 1996 per participant.
  constexpr size_t PQC_HYBRID_SINGLE_KEY_LEN = 1996;
  constexpr size_t PQC_MAX_PUBLIC_KEY_BLOB = 2 + MAX_MULTISIG_PARTICIPANTS * PQC_HYBRID_SINGLE_KEY_LEN;
  // Ed25519(64) + ML-DSA-65(3309) + 12 header = 3385 per participant.
  constexpr size_t PQC_HYBRID_SINGLE_SIG_LEN = 3385;
  constexpr size_t PQC_MAX_SIGNATURE_BLOB = 2 + MAX_MULTISIG_PARTICIPANTS * PQC_HYBRID_SINGLE_SIG_LEN;

  // Archival serve-credit vin (gate-2 §5.1); bounds match shekyl-archival-retention::wire.
  constexpr size_t ARCHIVAL_LEAF_BYTES = 128;
  constexpr size_t ARCHIVAL_MAX_PATH_LAYERS_PER_KIND = 64;
  constexpr size_t ARCHIVAL_MAX_BRANCH_SCALARS = 256;
  constexpr size_t ARCHIVAL_MAX_HOLDINGS_SHARDS = 4096;

  namespace testnet
  {
    uint16_t const P2P_DEFAULT_PORT = 12021;
    uint16_t const RPC_DEFAULT_PORT = 12029;
    boost::uuids::uuid const NETWORK_ID = { {
        0xDE, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0xDE, 0xDE, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0xDE
      } }; // Bender's daydream
      std::string const GENESIS_TX = "033c01ff0005808095e789c6040378c52591151c8159001690dcfa368f7ede243348ad8d6d8752dc963e09c6ca2d5a808095e789c604038888a80b8804689c5b66b1b863aa9484bf9de8c901a314dbc2a2a9629188ff5db4808095e789c6040377f6a8c9728bf7e1275d28aab5327ccb5c943243aa0cb0b4788cdc35d05b480c62808095e789c604030c053efc76d296587d97dbee68c71f1158d96f2216d27b45352db816657e636fcd808095e789c6040300fb3a862b2b1d5a06a2b427a4d418534161348493f1b400f94f4630ae46222a57a72d01f70c4225ea26b8927054ee878182222297af6ae9086eec07a8dff448a33b59bc06e02b2940b5c83d414c5232bdfbb8d04060547ced996099e0d2895727eede7b13740955b9e973f11fa7a2545f0d38d0fca9eec696b3d2565f594f486a41cd4fab9f4cdbbf29aca3699d0d8636fafc8374e1d843cf92a9090421cc7fdc0d5af72739be1691fae98c73393eb20e679bbdfe425bd6a32e78428f576884353d3aa076d4544165317380c05ebb0022daebc17705f2e8f7295c32224efecc011323a1742ffde80cd2dbd866e3c0ed70acdfb0c1874561a968194c410df7a5ee2af5a93f6e6e747a53d4a1a2eb24a509f1671491180969aab529cd5e207cd9264c7b0c78944ce37b37751b539d20468bb4ce034a9347bf49d15a736f9e6eec2b80fcfa0345d8f11c641429c0163ea76909da2b016ded66e4791d374ffb41d9bdfff0182e4fe080da33e4ed5f097bc3fb6a75d10343e9bc2a5483f3f2c165e0d3f7987dbdea7630bb5218b370728ffec4dcc56acf694a1fd0f2b3d8c17dc1b0f99f7d8080768d29bbd82853d63ff4fdb26e7ad1a4bdbe798cb9bc3bb562b27c27d3a8b62b87c0af6547971d5c2fcac536f3828fb3a1723121280f6b0587e89f2cc85d116d0301edf70c8030ac9a172b767e9774ecdba21896f588ff57b2304cffde6b86eeaf43188baa3a0d5b29e634134288387db135a3941e493aee8f7839c99f4ee0ca7eaca5ea1d7e1bf4071d478b92c6ba401e12ade0815f67273b60f6ec4b6923ef392a47aa9734bafb9accbc0ee1b579b650d0bdd163409a281fdaf19fc7cdd42b48ecbfd69692a09c6b5fe83bddffe4c86d558d6e88cc9ffe4b9896604117145dfa02cf3482202eeb8ed5322cb50409564afcd42552630cd6ab2f6c7e5e14f332a81692e9fe2c6c40d408447241648c8f9a0755b934cefe2bba1927b00eead84f6d921b06e2e3bd881491a445e592b8e33e054d69f21bae8c1dff7e0fcca578eea89d1a6668338f4617d2398fc26be373848fde71f3ec6bbaa0f05f160877c4e7d73680dceb0d920b251fc50ee1465579f89993cd91a42d155eff2538061518098b1cb8c6f05989472df893cfdcd122781ad9fee87b0437d08dc852f0fb726a6b242138c5e99d4217bb730a0868aa6ceef6e4753d70a8d1f958861b5881d4edbb829e5fa6aa75ac088012f9ac7947e234ee69eb7e716887275e6d5c7a08d966d3906767d84edb953c050927e33eb9ab49c83ab70d19764c466d506a27cc556827aeea856920be9d77a92a7a576e5a3a70868119594daf3eebc737cebd2dcef2c7524a3b641de26060c50271c861c26a0b1f217e72e831dca75f43ef62abdeb2126712f34baf639bf3197643ce83d918ca6ad1ee302dd764a3a1e9bbf73aa69f63e4b7f93f7caeb7b8f6574e1f9602c719fe3154254eea21b8b7be99463d19ac9676288714eb1b9677348731525387735e810ea3abc847a8d9c83e8483faecab4b12bfbe70b9e4076cd8d3e1f2b4e27df74e442ffb5130ed13be766fa8bb28129464701409f22c3ea432b03b6c6164f7fe85a28f76647e528ca43a5a6c475cb950616b89120982d1d2ed49155b01e4ef26a46e28413254ab11a7c06e533ad5d2d9c47a09887eab3c17e4d933dbb6727cff6d3461eb4cffe7d605b13a6dc847aa6d406a4ce012bf3774a61c4417d297e47226eca584b1b540dbadae7fff0a86761121db9812baef227535ea99f34e6c3a2d81bbd2465f8efe0387335bff5e89fc6127a6caad0c69099267b5ec190727938f349d3a4706f790c36245141a7d24f5a6cebb900afb2f6814feeaa977463c33af2f6c2d44b3d207ee56e5c95390a3af6a1c4fa885dada8a5f5ae711f89ab5fa0bd0bf3186ebca57452ba398ad1cd5c1f1e2027290325acdc95410b2cdf6539bffb6db3f87fa402f2097ebd1eb5acaa1ce828799b41c2d8c3f02784cc72c732b7cd2bfcab7fd88085265b95c43ae1391d5485b9d50509d379797d0cc0da62f6291e6b0947db774c3b9bccda8d56e4c907a58185ffbb6030eb8eaf21b6156dd0baa3e6e9c17c7e07f4232bbacc2a5865ccc3832191a416dd879627d9f71ebc2e2e6a4e76058d663d30f9985a501b53f56b87359aa3b77b7695615919c862e9a301b242c03daffed87b21b41b84a3c75f317ceb442732ca34229208671382a6c117cb18719dfce584f005d80f58c15d5809177dfe2d9541331a982646b5c5585a07284f23e0d578f7b29618f81dbd98c46797178c118e1aa28c77aaf57ac582d3f9b20427e3408cf14b48bfb83ddb97a33e3e17bb540f8210e039a53ff74f0f03e2d9c923f9adddce0c47e6bc112f9a56ceed8330d1ba24cf3570d2ef4d6d0c0f8b3c89c3b6d421185d294d1ee515e786e42a92cffbb120bd33268dab775a86e919a7aa7d3b96a3380827298ca1a9d481baf74aff57174c5177841a16aaa93ff5959efe206d454db8eca5bc05b33d6abf33170275e3a67d820938eab73daccf04da1597b50cbf8d35462d97413b1f1e2bd4ac10d0abbeee4854e2ff90a8fbac07b93bfa9b4b21bb679f0e2f3a7878f6e0b786530b7b4603f91ff7db3c4da09055867762f0ae8ec8b226368fc84a2ad920db0d75c3ca8460c377494ef50b2188de6331ace9507f9ced951dc659e43e58481bc2a0e1cbde6191216bb80a12c334ebe8dff0b59c579a14edeeb54f0b53d64232d29a009899aeb0517e0505f4004de1b0b6b7344b7fb22e938d8a982fcf496174b0b217c69186eead1409a281526749dd6f441cd9bc110490d6184ef82ecc33d299536d8a81254ccab4378430dea9700d6905f84b2389f442fdc6ead7ca1e26749a37c0c640dca758f5ec86b098ce28a22a7b888a29ac29e109803ef0a4101d5faaffa484a1ef7ba520ceed457dc9488bbebd59515ae2aa85fba726e459e7e5a4a49f11b1507a9b91ada55515d27759670f346c2ad4c672f520c5ea75f92bb6fb6434d5e595dfda6d4718a944853093cbc5f77de3306500794cdc1b0605a87f88bdfc0988fac4cf0f73178bfdbf7795cecd0dac7d4586c018c9b6facdcd8f4c6f2eb5412bddbd71b71cd82d8e6513dba966622d70032ddaa68a9bcfa766c4b4ae35ddf058909b983d39a7a35ee8f01704790b9a442f205ea0374e9e1a2cfe7e14d93d3b437b5db963a8236e75e139d1ca7baad58f574888ca30f5281a640624a8b2b310bbd55ee40492e272ad746b267d60366af88e18b0a8fa60667f926dd5a5482728b269223a14590a87de1b436313682789684be27f1845fbaf999ccf038ad4ca8aa7461159e1b96eba874f58df7607c250a0998b2bc731a20e4b5e94d6662038185f8b5b12c94dac0c95c729b5061228127cfe35ea3a3883701b374731cd60dfc43f1ec1509a9a881e1c2b9aeb628cdabfe35dd2d589f3a8fd87372fca76b6dbccf7c059061fe455e2806e64ae48a3423a434ca4df5cff137ed764032096164263bd8b80e6d022af7121547c455cc49b6be091b3e9b31a992f4db808dd0a7b690669922bb0e66a80aa00f83a281c2e014bb335d70501e99ffe29ae35b4b0f8cb4ca453c6482f3d1a851c2ecd6a381d915d16cf237877df75f202c62681ec0a1216cc0a3aa923ebac5b6f2e80de03c9e9b4dddc1e2910e59688cab56ffc09157dd88322c9c09ddab57627bf5f47817c20332a1e3a5450f894ab198474f0bb7baf9c35d32c9f236aac54686e871b11677672ee9138ffbe165c9cc2077bfee58306b3320dfb25844172d06ba0a7123c25f7e75a46bc9a7e2c64ce4bb8de2aa3b858efab9ec8a9d3d9796c4a9a92941665e281a35d364f6e7bef82020bdf8ec840e5f4290e75152948fee98f6d727f5b4264e8664e89c33b3c3b0257d9cf961c34b79b42450d23bfe8d930387633136183c95ece0830a993e821a94e14574515ab4ac1f08895b3ff01654a8d36ba4f232b1ca9bbec9d0937051e7159a23cb8db0871cb82fcfd5a9f2fbd93646a18596df06aa6c41795bdb61d8060b5ca2b6746ca6c2d4c60ff3fc02c923fe562d641c7d45f8592a62b289984f17cb1d60a0cbea5eafb0c3dda261511504a92edd9a37b12017176128a035a5b43085b92c460d4c8a18a202cc31fab0ab3421abbff371bd555ec8434c991b30cc45dddec680af1ee5f52951f83efac1ec1c2e64fb0949856a849657a205dfaf065811b6c3c5f520d8f9e24949e7f6c7f0b30470377332476d224e3ed66a9bc9aab43fdb2f01767c7500a19b117a5d47b8e20f976438a83309dab4663695933d2366057de2d5c8c60ff66794d8192b70b12b12eabf7c8f2e42ab8f6106dd61c122688b7b7acd121d7b9fb39e6aa86d164e4e80acc6be9c76600d5455c1474e99a93a4f4bfb61354b32912ed344fefe0882556598697b14d2b248cb34c4db8d9134c656291be983a46fd3f3b13a27f1d3d7c7b40ddaf3dfab2e4e39e4252b74402e3a8c5b229be8ad1c3f7ca0135cb6f748528bcb0ce530b0edc47f936943a2df25f25cda8b7941e06dbd9f869a413a1a7f253abfa109a9fd5f1206c7a1007ed691445c1edc63dbba3f4caa469947a843150b0615cb79daf1f1b5d842ce1eb4687c39751553977a2e486917f4cd304e1baba0ae06b879e848e3bd5bb9a0b77894659a691239cc976eec6c4ab33e6c2721743a28ac899ef633d0af2e7a188ce3110e41fcf4a3f12a0f2b3893c90d78472a5ca57f2717ece69cb07155d6c1c29f3faa5cf01e4e275c39b935c878fca1c542a64ae401056a02836e399595613785d59992806b4a63bd0561c60836227854ce99ab159f8530c50a5d491d0d758eea6eb778edc044ad135a8f40f6be9a972d5bb79492bdf037eab2a1a6e78cb982e7ae5b5df0ebc630a0b61ac7e9be65495502940ec99b26e8399a62328d85c15d749584c8172d1eb71a99e7c1646bfc4ce0b3d9548b16dd857de16a471af866bfe5ec206058a1906aee424ba186e960e067df3842aa3ea536bea024e931f8eec8bcd9b9070a3c5183e7485607f7c265e9906c20492bd24c4bfc32370b8c179f3d88617ff72de344c89455878ba376d1a6fe55309e216e91e90a9f95e52ee0d273c92cb0cc9fb5bca7bfd5f14ba1e2a6ff5a314c5c6a010f662d08f6ba90bbde012e0269bc0cb870996b11c91137f82034aecf268927f7daf41120ba12dcedacc7a0815d1c970058664d2b2ee297746837a0aa1f30a2ca814172c4f8fd3bc0b6fc934969a03942ba0a3126d71e355b03286232f85a84011caf97f1eccfc87350df798a4b2802fd99256f9db2a902e6ad0260c7a05ad8778ac67c461e072b855327323a6d683ec42cf77e5bdecb414ddea794a1e5840592fec696c237223352ebd3e910102ae8e98bf6133ec220e0600580059aa64f3833894a5055cf1169f30ed609758bf12a3ade1d07ed0eaf5675b84cd9aadbf02ffb81fb2fef4bb8fffdbd368c4c3b99ad213985d88e6122dcc5c81b8bdec0b56bf323b097375d699f88340709ed30527ff664cf7bd0d13a8cd3cd8231977eb0ce53e23649560c4c87e9512c8504e2a007a7812eac8e4da168d25ec033b8f8a2834bc055442d89673e97585fba1c3056705787b38e6ae9cc152c05bbf23a45bc5fe812e1ff29f799dbef1a8957f41fe4ac348f50ad1eef62f2eddccb808ba92f5331cd530c4ca19a3cb05b556bb2dfb6c3e8882ccc3bf7a16443a986d8c030aee76e5d83b8d5da49702826b870940ed1262aae379770bff478fa9a595516fa1c781f1fcbe335d2fb953a3d094223fe6a26d7a03eb618700320c454760b92f5cd0680d00370edb94f57b65c04b1a50bce6a604406a171231c93c15771f2ddcaee1c8cecb351d23149dcdfe83de9de0b17cd3690890bca41dc686f0388022028b9cff4f287ceaa24425d95ed41e1251b551d13cf8849f22d6ed961e80d2bf13056060bab185e1a3f212e0600793f667cbe0d190cc17dfbfad46cb472a863c0fb0a0afa88f27ee17f50781e016ca3baa1ba7feff9431e00d79df175800aef940d5276bb5fd3d2d19c3c8e3451d46268f365add0a8a802a19b9277c935cdc541f41944b581c02c0d494f6c5096f5794f3b2c7abb5d8a0e941a1f9be7beaf274dd9b1f036d2d8da6e112b95895be1355ea273b89e5628cf451b5e3b0b95ddde3e23eb132198cb4c2439536ecde4a5afff971764ad614571ae8a35d5c47c36e21f584b49bf224bf75fbea4e9166679026e2c10d1db616722be4d7f7a088fac580145162b8d9253cca6f29c47497c784603c22a4330ae2688df44c3cb631e66eb0b0a8f062d8f042fb1e918dcf73168ae9d1f4629de6154a729364275a024d21c9013aac1073ebb73946722ed74ee4e084641041373324800892db5cfa79561117e80349d512cb4da2e41f2402ad007c7e91ba771456342ab8e826ffd54e0e5f1d16b454a4d92bdb3a7ea1e3c05158827c38016b5a8e2262105a504b9a4e02b6f9a89627f9ce907fdbd896048ac1d8c67e2971435ce9b5e5b8d312bb54f6ded45058f05c83ddfcc996566a43f6e3ed3de2e5ee237e7d02cd95ae5f490cfb5dde65d738523f11ce73b0f4924c56a5482df36374e5588c3debaf9bf5dc9e5d100ca66e8bf1134efa44d6990aff3304b4938d823e7f6c3d5aae807aa2572e339edb16b498a6df86b82a97e641197143f3e411e7f32ba11fffe32ba606133bd53547f7281a2b323f53fad950f8a4d4fd92a3a9a3ad490cbef7ac3a965fe7666f64aaab169ad5c0a9efd7d027ceb9c9509b48b41ce69084a324d7398198d28184e42e4844ede20eeba797eb1e0f81b9c53f88209993538356bb87413f129b852844ef9c42e99534f35d3797724312596593a3a8cbf6e9fb35959f8a75567e0cdcaaafdf0d46b8c497426853d195ef493d7864a231dd112f0f5a68c6325a5d3688435d7a4d43f65b01592c6d086efacced548bb6fd9b1136623107e3fe184ff4b52a75794263c07b3205c3b6ddb4b1b747b83944193372fa3c6013dc49b04da613de4e33d2e350f0462bf25aa1a60dce92a08669d4ff4ec19d148845f148b84f330349e5a1745f1b87c29741f99b1f2e6084491479db8204b7431674a575398720140d043fb01bc219c0049d8a1c9b3ed73b8317dd7d694a1c0bee65aa7a7d0bc1ff6ca30e28f9f2484b1959770c2ac4547953d18226ce8f10306c4aa9e9cf0a6bcb9174e90631e3501b948b2f51ee1bc78701c3094a9f48cceefb6a5108a8e6d70fab75a95342fe3d60bc29b1994a30d6e9cc639b3fd8e78fa9be97c6fd160c4588e1c40268743851e7d45437d7a9bf4566a3703d7c17e8cef80f2684d9a88bd25b38590fa04bfdfc992f3fa8f2c4a10f04ff94c63d4744fd825937a5b77b757ab549574566edde058c290153c05f9a44dab1eb32187277f31a8f0ee61b8c3ab8ac9c4d49feee6694343dbd5f791618e4bfc8f07aba71fa1c1b429dd9cd225ee9aaa990411e0a134e676c5fef98357d10d9562e8436e6c3f604c7e024f0031813b313696fd8a8f826222ec736b65781d039def4764d013ae762981d648219f0464601ea16b0cd76165e4c01d99b27d5833f7032dd89a652c6abe015a585876e8ba70a1dc70438eb08d1ab98a0d4885ebe8a7db3473037ee681953f0207430c19429e7de7033a0bf20cab8d3184b4a60309c3d8cb8271f5dbcfc8da2d9b3fbe7b7e47cfdf920e1ae1f457578d94c54c182d365f553806b9d98660fee128bddb3c235b806fd9e623a7760fa0fd727ba5b67bc87908416f94db760888f631ec96126079d74b860a14cd7527061d7440c7dacf2a2f3bc83989d8944cd98eb06adb38c3ae056a2fe47b227c5a330cdd614b12a842a2830c6c30b29cc328d8e39559d7129f9abfbd27313f9b815e2b6bcde521796ead7cff8ab79d172911cc87125954b6e388dcaaf1dadf705acff38f7572b898ce392390695860c3d76dd2fe1b07a0016ce18fb827fb2578edb631c170ee863d6242974f2f36f59408bd9097711e064341f6f394fbd87e9f55cbbe0d86292e09f22c5ecfaba5fd41cbfea37a612e591867718c3f3aae2c5a2a593a6383413a20d1758479af2cdc03e1744c20617bac3fca90cf5e77e559123aad5631a009c4d86d51e29f12605d6e82b0791811e12550ddc736e2e180768b84051a9989a3fd14fc7a698dc5bc8d5957c3866a01e9dc0b0059c167df825110725aa1ae5f5a49bf484c0f2e87d1d9c5810a5aef47a84835e641ca70cd475f56b63deff170dca1fa277f7981d72e60f546f6b6b60596c9cb27808df500e35cf382ca4146d1d99a597483bc6e0a52020c015ed945de5c16ae2826c977845bd7f4e0d5eefc99248606a84f093e196f8cdd70b7d2883892a560c7f5564a3a58dabdba5ae3fee6974274107f797e755d144b134b4ff72124e83196b0f5c0bc111c5bc8af5f5411780cae15ea4827559060341658ffd2e6d2d1fd563915e49746c2233b6975296d0e7d6c5b847c8670a972ecee3e19f9d168e4cdf48e09321311e7610945585bb8a161150f981e06e2736fea75c9bb";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12
      } }; // Bender's daydream
    std::string const GENESIS_TX = "033c01ff00018080e983b1de160352f562a672bcf8d7a75ab618fc321fe7d7c2fe8bad038dbf5d565015bf334d8a2ba60901e61a551ca4daa7411d9c91da75df8330b1f582cc4d55aeb7bee5367d890ec07906e0084b6abc62355d85a111358a61aaf1ffe7dda8732479685479aa58c1647c3c03345ac2db41ea26eb05fd0e9df5affd9db7aaf8428a15f75bbc2aecad63635c013d9630e5d556939480229b18dc1819db3788be8fb21ad302d402b237de3075e9e986961f1696d4c50e793ff133ef979d579099f0dd4785789c4c83c072c81130f3986d43e0f0edd16848771d8e9f3f50b755419323131e8aad41317814902af8a0eeaec14326f964a8dde1999beca0efc8038f0adb278b3e96fee2a65e7c9d8a1274e6e2bd2555c316412ad3cb643f8b43d5bc3d878d3b9fefaeace9135526edbe7f0e9beed35fe19f4228f9d0365946250057fc65bf1cbc077caa6ec713bfb2901b7f3486619a2682d75b558f5f4c92f8bda3e004a43be5990dc4dae5d6c037b7b4ab77eee874f1e99e5ae554474a1a16920c9bdc79e8913af1b462b7fb57fb08a62e0d2f8c478cdacbf513c39f1aafd4ea6726c04e01528c45fff4c94b327cec3df05ff1619e01b8702303e555d29da20f599c5a6961365d0acfdb0c98a2fdd47df5452c551c02797d7ae20eb60b2c9e5ae3ad35009ed2a7a85ede7249320b494e69755c774195e0e9be71f8d5a1c2468d3ed4cd6ca185a7b0d70aa897dc54f334395f7b3989a4ff293c9943ef8c40f3d2ac224004e5743cfab2c4dc69096edeb33fb69c08286bd3ebced7794d104e90bc13a2e56e5e037b8145ab3d138be38356a643ead2f926e11bd84d81885f8e56b889e0639b097150b79dcb83f03aaf5d4329532a921de902185c617fdd021f8056cde130a0c98ed3f6c72d1272807be2dd67bdd8c91be11fad1cff02d0d041c50deecc517527ffde3070a97274879b07e3eedc99fee5e08a94a0b2e8bb07ca2f3fd42e732c14a1cf4dc66b2a2302b48fd09b89432564b8b2d22d9944f67b4d08a56b79b177a1df39718501b59b5ad07ca378c2e7c1cdc4e938c04cb4f6ce633c7c646289aa12f720918ec415af6e0fde0e1fcf5dd8ed61a2479a0184cf08eab0eaccd52551cf6731ac56cbad22583b1aa4b4c2a4155c18f26c2c0bbb4b92f9fdd1ca9c31a5ead594d07e268665b508d787633c74040a5cc3766b23a29437e890b6eb097a890adcf7886cf005d153a48ca00bfd5cd60309942fa2624e452f1b1f56f32524ae702a811e1493c12ceb08b737f25ae4378e9b155b4aeddf9264a63b0ed3e6b2874689933a0efa4a8214a667eae1ec9efe714f0c441d84c12ce0e8903dc2be73b437fc847ba456b79459be4a10ca79b31bcb1a2665c580a5469c2314127a2400e3125c0c40a9a656633cd1f8af836b89066507a136912717cdb8bffd9b800976efaa65afc6ea0269b8504e177149e07187d70ba9aff833bdf224c4c463cde0b859997b1c124e69e3996b50d3d62245876c3f856ef4e19e2121dd29a7bf14c66103c87edd4a9f860de40053b7563caa80ec5b8489b80f113660c82e8d62749c104a23519b5ec1221d1c50322960128701f245386a66b214a3d92455e91eb95225ceef881eeca2d0b9f9434891f035afb10473a49d2cd53c5108e22cc45b9f9e298309c947f834d00d8f779ca2072003a74f0bc6f0559918a14e1c623ec78de285b7900fdf6f859adffe23dd9f491200bae1a00124be52b1ae1381acbe6e68c4821955ec70e6f1af140fc8f47818b86bf717115ba701e355395d162768348e8e0391";
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
