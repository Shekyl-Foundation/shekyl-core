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
  std::string const GENESIS_TX = "033c01ff00018080e983b1de1603de95796057e2d3f6c2e9ae08321031ce876fae7c09c2fde936718cb3a01c1056a1a6090156830589142979b0708f962fe4c018a48231e45f4549103160182b1e7e19919e06e0086fa5b697811aca3ea61bf910908f1607230f95863b11ee751e45fc6cc6de8969bfe7e3400aa86834d8c7bfe1d2ba0eaea5715b518025f3ba559c9a86a4545f30e9238fd78c4fe68dc1186f49fc0ed7a707ae1520763b3515927bcd5327ae9a185dbb959294c6901a59330e07da8020522ff03748296099a485dfb9bc5d97e7bfcb938ab65fcbe3cf084287033c7d65f9aec4da86cd4f628fa7232641bbca9960585bc94515e0dd64b36af3d576d4c02d7cd251f56c17f11c57dff60da2b7963e9934bcd65d6026934c599f9044c625ca5a07e64fba75b36eed1ccf76745780f33e9da6a848eab304fa538a1589588fac61876c7f877dde39056d4b9651110705d5efc9a7c6af4afe77f560069e04c930e9979158868b2fcf994d0447625b786e40a528d64bbb38cabbef6a854775157d8b831f57248c6afff2a14eb42f968d49f659deebc41c0de01d0da7856d3fd0dee7dedbdbffa746bd7ddec6f01375259f882920bb6efcef43ddb4f84ac9a40f6b0494e54b6cef8efb2c3c2abc59d4387c1a8d59aa3e34f0cd3f6f57cf37d1fc5a9752bd5a0e740bd82ed4160267f621f1136bfe0c27e604e4dcc84ebd20c18c3c853d8af48afdd6b5bbc9205929df8ee415b8752f78ca58b411f1efdc57c5282fdb2dab942d65ec150120d88a56f5f76aa0d9c1a796f607cb9177a1aaa672871e5fcc4e018c7ed25a4757bbe965c9bd2b8891d7bf013003f1df59864a093b2166abfc6a5e37eb698f117293a566afbb80496a875357c6c8baa1d309a3f41e6106f0f8e2840c0ca9991bc77f65951fbc50b7ff4732f2afe53ec91c2312c01bc845e7c2d9dd7a90231be5b4106adc10a2870c3b0996300420f54facaab233961dd13b4f96b6a703021719500ef5b97b4e56b1aebc33260c68b2a1f2aa31a288843d0a79255255c5952d742e265c0b1fce237f43fd11a273dd47dcf78b5a820bd1d1246430d26f1cf3288379a36dd7f7a01ef5aeb605bdeaf09b4541abbd2d4b0bb96220155c8ce631ed0587b5a15ed2fd8887cf4c2dacbbc46fa94049d4d35c33371526064fb94833cd66afa25ae6c119e2ae1e9e188a46131171a033d7c73bcbf4122880d93c0a609dfa3fccfa59767012f041ae0d559837651cb85c1b438d7f238881174350a533f7cf7fa08d3fc5ae2c60f8b665235f5eba14dbdbee473ee21e4bbce083e0242c31ff75e8172442d672d29090984764931cea51378bbd40c281675ce9ffaf20d7d67d92ae6334cd3724745397bb39d3463cbce882d2d462a62a8724c120a7d2e32061569d031c50b77075817bb668ee119576fa0de20ac04d8e30225b655fc29f78d98611904ca6b9412e932850a8cf453f82050e7cb4b4fb8e5ee40e06a76d2cc4a91b5e5e5d1f44bd52f2b008fddad673cf610db2dec1cd4f80ff04dde44c1e23dbc11c68049bd756dbfc4dc92ab8d387a38010ab0f1df083470e0e40a386e43dd3fbf4693a778162ace8a67266549570172622991fa2606e0b4f30867c7406314ab22efe92947c1c61c593bf2656d12b12d4c37515644441fc2c8dff517071ad2f5c17800fe8480b07201af663037de8117f1d4e9c45243d2663bdaa2a4be2dd2074ce19fecefb07202100a79711e47ef98289686610b5b9f199b1f04b4332a7089af73604933c17c8630e2954548698969efbb59afc9ba0ca6a9a298c";
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

  namespace testnet
  {
    uint16_t const P2P_DEFAULT_PORT = 12021;
    uint16_t const RPC_DEFAULT_PORT = 12029;
    boost::uuids::uuid const NETWORK_ID = { {
        0xDE, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0xDE, 0xDE, 0x04, 0x08, 0x0F, 0x10, 0x17, 0x2A, 0xDE
      } }; // Bender's daydream
      std::string const GENESIS_TX = "033c01ff0005808095e789c60403cf125aa1a29c11a8ea6a9e1bcd242cb397256dea5d3ee0bc08e439bbcc60fc3e03808095e789c604034a285c21bb4b7dec83f0f1b754acdc7f0768ec965ab6460aaa2f4f0bf0cd3a9ae4808095e789c60403d631b72f4deb0ea42602699cfd652be8880bc0609681becafe1b9ce212bb978289808095e789c60403973bde0743aafe75183708677eb969c249b1791ae6d1bc70e5298731f8e1a115c5808095e789c60403c225b57cc93c8c1e9a5c493dc2c59e8e2bebc2b6decc20e2020c7303a610b952d9a72d01de1f9a33b05b0079f3b9c6c563085acc96d4d4987a0e4d722736c73ffe25c87306e02b6f6b707c3cf8a9bbbb4f1dc592f0891aa35ddc9a04ec6bdaf49c11d0c87bcd72bd3c87f31f3f485a0b05dbc83e3744be2feae02ca838105badf0b704f462bb656cc9f91be7a2ce618cf527d923b744a3cf3551d45c67b4f3bd8f975a32c2cdaf18f8fdea3bc6001fa911a8ad907bfcc2ab59771669fa8629c47181ebca5fb84dc1f233874d033e27738dfb758e704fa68a6b7a8421b7a9efd54f274cdd89062f8e6203ead40c4d1dd8e6fa43744317ddb100df6a39ce82eb1ea3af536324e1534dab91d0c65c63e7c2b58603f745639607a8f672f99fd2f0f7196d31ae370e070e33f15f8d772182748b6d5748288e7e48eae959189dd5ece5a10b389eac52720de28c29e0aaa3c14271da612377afe11567988aeecf0f83593bc5f2283bb671716628c512d5e078587e50215d2897110efe3915345540f1d9b0d8d5a764b45493b1a4d76301756b9aa596d81d7612ae5605e294ac9a4511c5fbccf41f40e035f9044e8d5a16e2d9cc7ced57d9cfcb30fd6249a14ae1772216e206accf1725dd954f31b90d8560c82730a47bbad148b54431e29380e92d7c69daba7d0b7caa8ec39a1d4d980b94ec2933e02f363789e74d08ade786a077b28d4596d3012695a30fafd207981c93547427172608468857fae2f4504ab1f144a3a4a4861ce1ef0927d47d22b934839cf60a503bb27c284265a599437cf063f8dc8310ee60a683775232e9c81aa0d36c138fd24e1223fa9a2d7cb84e6f1c16e1f53d8536001625bc0a23fca6fdc129bd7a95d2edbfb3f434affd28cc38c0ac8ede1c0e4413a93a8ff62e78e1b7aec88a01eb1523f2dd3a8c40f9ea744c0c910a9a1d157cb0ec2bd32980efbc8070bcba6e262b6ee9dff80d4c3bf254cf746f7b674a5a41792a5473353e5e6f43f817f75dfe8874926adc2276266936e9184d237fd6269af26db5f68e1b35d8cab1414506fb52a1feeb164e3ca9a9b5a1e6554e2bb9cf81be20e998ae72a7b2df85289d361c4c8a33162e406bcd68750667f3a6d089bdf468e598aa50fd6ddcb8970195245e3b038323bd09a6e6011e8f402b95c820051b5de25bb9bac63bf19b54ccacc2d49019a87d283b9efee8176b171d7ddd1272cec9654f94727aeff831a6a63a0ba13bffd459b00a855bb37ccfb0f5b8d44bf899de76a5db1e26cce9a8324081cbc2de50dc6b2baa03b75b6ae1297518730cdff1f4dc0b178c5b2df27492d5784b83726ffa454047a0c5c03d97860559cfa805b07841542ca2a189bd540d8015019829a9e0f8e3baf9de3b8ae5dc812b69e315fe0bde3190e027d08922a2decd69a12e0002c73504b4091872c3ff727ea6af97aea45d3b54102ba9070b3c20cc0b3da6f8aec5d6a9818a08be467ef52b54767c499f264e3d33f47745390d4604c8c97a637b6126f86fe6976e8471ab71844ffd71bce3a623b2c848221bf4fd33baa7f8e14aa898d9e46ab7498e5712027495215dafba99682e386c877619a6fed3d5246456c8b8d95b31d9a8546f85162f8a99f763e5c05b4b2f276d86883ee3d829a283d9f7744c4a8d766afd9510143cc2c6b1d38ba0b36a4b391027d35ced6e0cf28eb114a4cc7cb6ceb8d881904fa7b509f89e89a26bb907ee82a71a1469d4878c124b8e4bce021965782c39b57d2ba21cebc0698eefd0db9d45d4ecb8342fc557ab168eb06b74177fefb10a962ab0b8f67805b8972be47ae9ad2823ed2bba6375c590ef047ef4acbd03786499578f1b90c83ac395c2cc6cb15741f516d9d9f215cdafdb425f836794f8dc5d2e1c8d0e23332b31fce2c54adef9dfddcab407a4b56d1b999e6375d56ec7702a89af1958300dedfa004ebbeb6106d2666d39e402afdfaed19c23dfbac935dfc9d4fdda14539500ffc20b5fc38bd058fab1b25f1326c021b94bb110bde9012979dd1829e4ba43ac8cf9bfc081bff761a8cde26fdbbb23362bb21572f2749ab563ca1ef048901ea6cb00486ff355c20eb98d64096f07d655b34afddf2f4012e7e4874b55cd4c053908eaef027d1a84fff96f5bbfcc7415483007b43a0cce8d98142e13a555d96026eb0348b105054045bdbe6581d6a2e2cfb9278835689e512516cc11663e2ff2097b2c43f9e4944bb453e5495c00b692519b494d22e6361c6688a21abcd8c876f989e2b205d7ca98b1c2e56a85de7c5c837fe0c58b781d10e2c13dabcb16c3d47451238949b0f8299717881854a2c363723c6dc7467012a31b5d80f799ca9fa30c21ea58ae71847b4610866510955bcbd1ef57bae2069b60d7765edcf14809b32f8a5e2f4714ebc08cc3fe55478700aa949dfb817fabdff7d9dd23f32585b8c9a441d8d183c3208f103eacde6a8e4e219e1166ac86bc4bfda5786abebed6ca5bfded36900008d03c8ddc805d7ec3ea9e23285847d5b7cb87f8568ffbbd28081477a9e3a27f62dc4d3caa09430ea56c4c9d2e8d1221d73d264a876eddae658e953408d744c601b4695e1ab126f2950446c9ec0b4b7866b8a19a45bb2457552f200dca2472dbc5e2c0593d67e2a95e2b955c15b459832bc53bf66cfa7e0135082e08888da4ff3731b17e14df83afca5de845ff36d6eee193f1e2ce0c7f9467fd8bb73a620bd7fb1f1c3985202eba55f9f273b66707a63854336c0a8948046f2db5fc9f6487bfe86b59b0cff374225658822d05fd4055c79200fc396e81702e8f0b71c7f9912f7eeb57055acda119364662baab77c659ca0d6cc537129053c0744d17b9bbc1268b2d5404daf25fef8ef771ea48ab46148d58415928e049870b0f3a6e8f604779019b6fac63844068e9c8397b31c1bd99fb9c2707b703e831c94354cb78961d72728760dcbb9ce89108ffa726de1854ee3b5f58468f428b535f51e6409c62c9db9c86076d2079acb6b9662600de3500314277da1363cfcecf23d466096be4e1914954fe8ca28e29e07cffb8fe08e30ee821d9b85058d5c415404c44438cae9acb7f09668a18c95cf02386ef5e7ada0626adc2b64583eeded3e3aea963293baa94f7b01e17c337d2d9c2d3f9d98da967aaf85b81111ccd798b41b00a2df5e4a0edf10ef95df731705f697eb096e84e0ac8bb51a74487865c061d2d7c86600ebed322eb6102a83a582075667adb08ad46b650af3fe2ab150fd6d69de294af0072530c945959aea886fbc862771d272b14c7835920019534b82122df3a31b5d332d82404b14e6a3bb8f47ccc45a974304913c3ad6d4ec917ed578cf718ee264f950323f0ff548326bf4ab7531250e8bdc735dca265164beb95d0d6961116e8412868965bf2c0ceb7f447ed6b086059561a1b16ee0fd0e30da5463a2cc3745e0427c3182d6d0fb2c40e4776edd5630e4666f6d1c58764af4590e90a1acd0389e2968aff48e0159e0523f9e19f30ead5debd3d9af3337a2cb4caea5cac4018a87e304c468798baf744150f78eb06b8d861b87d5be52becf54d3edc458dabb06ac691777362a276a79923815c7359766f95363a5b582f34fcf2afbbc5b3de531bfc7a99c58b53840b3238b24025684e0dd9fb1f227a373399d3809d11f76376a5ffe08976d2283846ebc8ee56749b9d2463f1743ed361d85ea69aaa7f1d060cdbf5f2d10e12e42e96560090fb71a97d2895dc696d6647d6793173e9889744ed520a738f5241ec5728851d8ce998ee5acce0b8c020da558152d0bbcf2e96102ab71daba4384e9cac2b88092197bc54f749b00eaf2ccfaa9f12f012ad09b58c10c6c2dab9c6fa816a019d91246ddaaf354891c64f8563f75b7e428c99c26f8e542917b93a8e0439b9397a88b1a4175f034b4b68f0c9cfc28f9d57a23dbb906b430dd7610abef0b3b87f01c9501c0a46d6ac13129d92d52435a511713b4b30f98c284409ea3a27d6cd8210e68751ec660a617b798ecad8ff92d7bedc47db53f6f223a93b755bf5e845aece250c80bc294713ab05e3c758e800e2a7e5e4f0883d4f38f47c3ca981327b4c0cfdde633faff216bdff717f7cb8c768b25dfbd342b4b861e863e6d3c894435b37aaf2f2dcd3a3f2f5af52a84a7f909979ab474097cd60d6273e297c00a2a4e0def0c07f6e2b48f0a1cc7db16c1cebaf11752e6013c750f5eab90315976797b2656d61dbf4c559cc5a891651ace0840787a237b4359f09d9e3180f5e51d53e06c0cda0f7bc3b44de12c5cfcc4b881e9ead57ebcf0280c3ec9b32bb9ffc6e75e27324a09bde7d1b145a8c3c6ea4812d8605a76f21ebf24c967d0ecb43f2dd81a6280819dc8f32d5f6bfb1073d2e033ba09a9b32aac5b8d6a51f35bbc099cc84336f509a98ca2e6fd9a6275b7c5bd47df1cd86b7f16a2b9414d7251b4387970a7f68206f4ea38c43ec23d59dee170362331641b1fc52cd8b7a6db6e040a9e8ae4aefa46bc264165981e0b1b2febc1aa952e00f0fe44721f50bb7ad302e4bbc704173de4f1db5b939071df89179023291cbd3ddd8d462a53008721a1f583a3610110bd8b49285088ecf58e30c96ac93af85b3b3c8bc8da5158b717d5e434264f3796f2bb8a3820887e90263009fea7a1aee76be2c8c4d58b228425552a4a03f984c7c4723f01135eb8d2b1fa583bac0a5a068d77a0ec904114ba3f0dd2d9e214a05687459c89ce7233919e4a7e93ef5c18bcc4ad4ee7f45452a6a8d47b6859845ceda915d6f70e57f7aed3fb0b0fb68d3242aee7f1c4d0aa41f8927aa4fed9545f2b0946d605218048b592af1b591422ef74f2920e3f5f3cefac149006c9d4eb91f5baa77c3d10fa8f36a0fa00a5730b481bc333b3d914babada5545c5072acbcf727edee3466c434b29cd0ab666a0b356250bb857cbf3fbe038b469291f513ec33c5daea029426d69c4e67dc010e6ffac7bbe696dfbd323d2a74f1561f77801b0acd281e90b86786a1ded652a402694bed52620b922d2bfec2ab4bb935af156d0d4419a571b142c9acf99fa21bf4457188748e22ad9aaf06b1e3ab2c1a35e33dd21da4f8fd656eedd3749d201c14bf42a8809d1c1d88db9edd82493c17f95bb35b9afdfa07116f90698aae8e9104760e03de6c47360b549dd8541f09c0432f1bbfa9ad879bb885a0dc6491069c36a6e29e3a08bd7a9b4caa81b6c9850becba04470d1b926967c1b378a32317e3371b5735a80bae6e69950513b1c7419e6ae57824570745df3280cb1593f5b4c9f6ad39c2a38f42ce135e9821ace9d2fc4c68105c6e9d47206b6fc0852940c2c688ab39e77f9357fc3e3e43890a57f8937d30cc8b779f3040d77c7f44b2f8690b761263fafd3a96f0aa2102bf847a44b8b413e89bc97df62e0f0e733d793c40c6bf1a752973d46d6f76adba1cbcc1c2555e8c1343e9ada49741ee1f4031ff9e1dad1b91ba456701b4b1150113fb70c60c8c39042c008f9bb9c0e6b8a2a27f279d8959504b936f4c87c35dda90703c9531840346a99ac03fd1e75102e9924bbdd06cd4787034c38f01c41edea49af1b3b5d97b3978477ef147f49e6da53f456c881269e65f3adbf020b1b9c22d007c637bccc14864ef5e7ebb4872db79f2d98aea5c634f711af5cd9e12e292ab33f7d083cb88d1125f73325b8894f784c9867a97388d35f2ab3f067e592804c899349f73a956d084a68b5774fcecafb6f91ff47f4425c3a18699bdb7528023f854ea4757ebe5cc63ba1f03a913dc57ce57898663a8347004ce6f9a9e16f71882c3342462b7b000fbef2f95986cfe58e7d80d1f7f8b3075a1f93cb62b0413dcb1270ae7f85d9179506890c1e0037db1edac30ca4dd74ba779942aec51ad6319e6e9c671c079100b162e59c5e6fa25a76e8fc1fcbde36b84892399fca9f84d22756c453cf270eb4c7ceeba8f3185130a7a3d66899d82a86516a63f21a04d87b4463bf3874840ef27bccd796cd4d0a6e658133b9c7c05d7f8971dd39eb227aa8b54f0160d291f7e327ef9a112dbbaa3a3f7e6d12164593de829e04b9d7f8b04e271051d4adcc5e9b685b352f3395712ab0f885b93399aa4e6c13bf8c62f615944c8876de502753713d1d5668e52f8a2542df1d6f7af3a99d9560117c6790a65b661b209268f840d884532ebd1adf6a26ab5248306a00074434af4af2b8a333e0085e0de08c9b4eecb37603d7d541aaa653bc473e8859b79483e4f9c0e70201a08a411a5d39a5937f8817f486be932267341a9de8545c15c3d5af757dd9474fae8308a536797144c5219d13d0506b612840ad70bd87af54c9fb6b1f4cede781cd0b5ce0938dd9b8c255f2df99eccc095e6ae85ca78cd29e821588330014096e8740f1d00449b8a8b795493e3ff6efbec1576c861bf3a09d18ae8afb6b97f3cb926601742c9f449488e87c11b6c9b657225955d9f5882fedf4c3bee3ad7ff325deba0234e0079845f29ddbaaaf91afa80b99f39e9f6e5014e56c2ddece218280a2a6d50d720853f170e73183095015d336275918081266c7b02a5b3bbc26e017de016e33e84350c0751157952da06d0d9c217615a98d7f188a684ece2f7cc812a4e90b4a14ccca77e601474c9bbe66b6317fdd6d6bb682b828bb004c252b8412ef79d0af2dfab04f69f9f9dece08b36c9a890d5a6baa61eea7b33bf349355f75182f9d621609aa88a83d0fd4d4700f72e9d73c602852fe1e4f070c15ccf0871d08a392cac08d8a9ece72d3ecbfae3e59b39849355f1c95d3b9212ca57ab66f7c26d58eaf0925d0ae42778b7125b2fe7db758534548b30e275fd592edbd7a7fa41bde4c9202353d374fc48660690bf5fbfb5ed3747ba9618f963ddc7f428d095c5cab97de9abf6bc52ba531a4aefb3e68688bbae2697850bbad58f00d0a0b9b2179a0cc1bcee05974110162abf80bdaa9bab348062e77c1c3ca2b3b4be4de9e5b51b032bc5f5c6b4341ed6e42dc40a4fac56c4c38b2cdbe96ae051aa50b6096310e0dcab0f40177f3bd1465f074a16ababc39a3a515ecc1b16960b0acdd8fd02ae5413822638d0ec5288b47b56f1261c2247c703dc062b29e9fde3555b003f169e2818ed14736715e54503b0aa479cb6fbf0087ecc835ade3e06eadbbc5b2700eae9950aef3f7ea767beb878856358d1b1c609d832403fc4a4548a7ff2c63c5336dcf02f32756f21af804b84c12fedf400cb5c7a9bd7812582280077e9f14d5c26fdbcfb08645f3b163bdd79235a961172757427d9fba9089a9ff657fccc281452545b40c0187c5aa206979b05a3791a94d5b4701aad045a7f87e131c5b6e91a23ae8a464b0f3a94a086078fcfb0a31d61d82f06a0ea1cf737ac9d9b1386d5d31af8d4b0d091fc7224e200c2d04431fb0fef219b0c1b70e0d673b65ca1e40712c5f79c9b3c3fbf4b45bacf05b590beeae722fe33e973b536a5bbf8309836cf187b076c5a127bf9768b1ba32a53cbdd3c2c443cacc77ad99e73b1081f665e22a28d0a402f31a0fcb99aedca607931d17502fd3ff35f21c7ddef4297c75db73e1d0a06f2f35811db4fd683ae5f01fe20bce6cf09bffbece35f1d006bee47f0ffd59474bd9f62ee18042e58df67df7c4865d9d86f47fdf2cd78a15ea2fdb0c0935eb9f9bc6b52fd02ebef062ea26b5e395dc1edf0a92a2f8483e64fbf9de3b1aa1ed1bd4dbf106f655af0afa65f29cc973d3e0c5e432509555a6952150427603eebfb12f23cf5dbd7dcc32fd533c11ba59b0bc6c5741d62b3d8d81c5e446e5721d4dea12a083ff545dea102c67c6f89deed71a6cefce158949040fee0f7ff12a85a169ceb8cd22e57014ae8ea92b53a2a75a1b2ccd4b53a8037c8a8edb1c22771f147b87225796c15ae592d58667c28dbff38dfed8d9146625b1f767ec2cbc261cd9486b01e379251a98bea3949cb74ab016808114689834150955ce7ae5fc5f0fb987b1ce5f26a40a9327cb6fb84af39ccc083d98ecdbb8d37e5fd4f48a7cdb3d190f213306807a00198f0fbafec3efca687e2177e81c0a9d7a9adfb2ee49124425448b041beec1c6c8ccf53a87cd1fdbda6825da07dc0bd8c9f91e4a775b169b9f7930c1aac57157f84b3056bf5ec27407d5aeeb5f0842360d782038bc077ee911603493e371ca76e75ec0239fa3ada4fcef0b31bfcbff580045b4d00fbe659d239566bfcecce367a0de255fac8aa5af5d6de5bb5927bffa78732a789d0c76584fac92f0c67e8a769006aaf4418c9e4eb479ddb360c501d854bbc6b9edbd8505a5b26dc17a3cab89bbe48387c1c980368e66d0461670dcfd7cf7edb5e9d81cb7a0bddd2f4f8344950b593dce8634508826f24d9f80c2b69381552f567a2994d723563a9b562c9a77de89e8f6931cb3cf23ba724a41b607d1856ef020dd7948898a82220d9b2ef665cb500fa481951efc548ffdedd675967cc769570dd87dc7cc1b6a8510d4cc809e13f0b7230fa51071868ebea756c4d5f9f4f6bf057274528f29239ac3b8b093a4e90b678870b637c416f66ae2f4aa9a77cac1a667081e24d29354558167f1e14963b311021bf498d5d1e59e315d626fa52976b3ff56dbe1366897fc3";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12
      } }; // Bender's daydream
    std::string const GENESIS_TX = "033c01ff00018080e983b1de1603e7d48ab86c2ed7e210e5ced994f88e243e9b32bd78dd29f3c3cf424acd1fc41354a6090163bfb38d0f4dbb3fe629eb4f72f93883253f991315cba53d15e1abcfbb0f91b806e008e9ebb42372527829010b8877a98a7af4c826468eefaf5ca257acd87ab9924a119d1c7d588c5178837716ce91fc35383ef9f8ee755a180c809b7b1c71ae9d0dc17f65749f2592dd5966f1b1a6ab962674f49f7b11450ee044597308bccd167e11b6cb6afb9272fcfce478b23965fde1dc6e0eb478342fe6072fbc1ee0d52e95632773d8af0ee6a106500d75b907b4503c5b80e659fcecdbfeb34f6dbe0ed4403bf438917105c93eeb3139b2eb07b8df4395eea6299daa09453e9d2ed46245c9ca24b1d436a1cfa0896c57a0d565bbfa21a482f977c4654db32f956b796f23bfcc57d0a9b177b2c0ee3204331b77996c2a8011e6859953034b7a33d31219ff8ffa47a50de07c7a18dcaf6bfb96d06a7fa1943176591224367a3f3d00a0f83b3b99b0072552f7c4273b1422f0a87b360a249baafb55b88245a14efd9c0037fcb45072c33ddddcf959631b691a6fe9f415407508d8f95246c843c8477039be31774252215c95a69db17edc0da3986c48daeb5640f1aa3c22e7d5b9e56c390d8fb009f858b43feb6363e3c8f45d0437f89c7270c1278762cad40e8e286ec3ecf5f22dd14e986d75ea3f1a3ba93edb70ebf69ed7adff6a4d3d61c8967683cdafe4b9daafcda24c74b2a9b2cc057d6468fefa22082d657ef0821b4a101eab86dc574456bb4bf23a0c465292a7b97a7cb5c2fd55da3f074f368892dd90f2b32573b16f7c52a5c11d237cab9f709a7609805b41f8d54cf5a14e2d179897dec91edaa578b560828e6741aa1dbd6c9ac47ddf2d9f521781e057c7ff39024521a60a844dba35f32686802e44d642e4c42d7f05718ee5783f798ef097d65535817bd4a72ea09acc71ec5e8e258add00af3f74196f8b518a593a1c7a5886e219b98d27b2518922c0ef00b2b16afcd8715e57d6d5ec8f2c3acb627d0a0cb44697286cffa1270139203a0b19a8bc89539205525362b737938a8394c6ab5992ca31d50e3711391e6e9ea8699fd49719e9052d554040785c6557cc1525f0c7c31c6cbca904ad7efcf51ea1aa4b1750db3c8a5609c60c67a3fff562c3823c1fb21c7645c267320c966c20727eeec2c607414454ee97525563868c69cde0fc9645eab2b7327d4d9187432361f3f4c1178dff6d1bdc1933d746dd06b6676c817fc3b46adcffccbdace81ba686f20a5e951bde24f05012bac82bac55809225e02ad14f1f030276e7425cd0cb166224710581313a58bd511c31fca1cbcd4397eff44b92e49bd1ff4be635bbc5427063c416244eb0e438fadd623899e0d9d78ab96780314e7af08991b670574734cfb1e2b64b95797cc0e986f75c52c1cd81f041d4546bc4cce344501a94f42c709da32de9c24d97bfeadc4f1aebc14dd1589e8d0ee157f1b217cc1b3d242634ffb5dcba247a2ac5ab88631cc26b71369201bcb931136f6466a3ccc34f73c9f379ea3312265cf5782e1297c424b0e2d2833fc06365ebe8a64790847d2c12156455b2205b7fa72879a83525fdb2e4a888ea8639a60e050d5447de2185e1d1fc9b8a27a5c72a9970a8a47ee819bd00eac8c7157aa6b48143ab98dae347e19be90720834ac8ac6aa0ffbae2eb894c69541f67b5ef473c33f878434154070ba9a48e490073e6fa403e826841fc39cde59c0a1f43c292d084d9a7423774abe5714a55f54b6c31068a080a485c90ed68534514fb162ef5";
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
