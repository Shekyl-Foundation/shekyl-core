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
      0x55, 0x6C, 0xA9, 0x70, 0x8F, 0xF9, 0x1F, 0x7A, 0x40, 0x69, 0xDA, 0xF3, 0xFC, 0x55, 0xBB, 0xBD
    } }; // mainnet network id (rotated v3.1.0-alpha.6, fresh-genesis)
  std::string const GENESIS_TX = "033c010000018080e983b1de1600b61971040994e2cf71d808ed0b3de62e2b987cd42a769c42e114d25d4a2953e6a8a60901a1b8c56cdfe5c58895fc9d0ad3158e796022a06364e7b6727f1fc4d7b6503f4406e008d02bf7fbe940ada00aac83b98d78a2993d659c7d5ab04e59bc37479a30300f51450016ce4f235d606b389a7ef049e84a6de51adb051a18152910232e9219a14f4e7fc596c5a6c54c139c3fceba8b06fe612df5e0f8b525d9f59e291c52888163262da11c2608940b9f932952179f0c8528ee8bf9c16dc28f237ed4efdfc5b7f21a5e951f6fdbcdd8d17a22c1418ba3293e020aff7f1ca4ad4039a79b4e17afa7893719a31e8c751c17dd14afa652a315e20d18d994929aaa2fa6dd2ae7bc31087ed558e2d26af4dd87cc47572b4239d415e4031424366cceed5de4b9cedf1a52454fd058a36ec2564c7a5b06a8ed87d9db6d2fde92f9ff637eda154efc0e2fd1dc16ed5d6f80c958aff2a6068f88ea8dbcad6b4c5b2ec04c98321ff303fe2cf2e10f45459cd26d84d8e818f8052712f9af580102ed9aa4ec6109bff347e4529c88802b8ce5019cc229dedc31eea060deb80c4a47325074e6a251c1ffa22bbf3d0a552fa45161546b9d57309acf5bc814edbce1f20482100fdeaac56408c0047b9bb5ebcb090ed9f5e5fa2df194261ddfc8facb9d13921afde445575ba83beea0081eaafdaf177306296dafe5f3d16fd86245cb262fcdb80f0e35e685c90f6ca5db99a6ddfcd8b04332bc71ca8c6f4d61b7239dcd12e0600d79241f3c5f5711b8ca105aa1d799fddbfa7827638fc6be63250063206987ba00a97d709b7a81d53d9a734c3a0874f34e8fd67f082b7e2de0b86ef7d7aa6be24d6c2ffe2c6f4d8f0535b7a1e97c306e4b6b63969ad52c88b7237ebee4d14d65e1e9a1ddcc8b0c928d002740b5853f340ea37c89b3cbb5eef982f99681dfd2eaef4309edac5eaae6cf0ad1dd4cb8f88bfb658f3d7f379ea2cefd2a27df840a2827d1c6f82d0073c01f8610c889e6b9d092af2d1abcae6650a0135ef2d1fb244b83bce0470d40ff76f834f7df8ed23f8d0efcb5a121f9f0b857a47b5fb0dbd231309ce3d6876a8ab9a7a6583f92622c9b8432c4beee9931daeea118ea6db44c43b2f90c69d216447bafe40370516ac1e997a48503b9b2f179730efaace1e9a3467f8a3bd00b3ea08f3cbb9361df57a058bed73a25b9eefd941b3f0f43d3aef00aeb8648703a5838e513f0226f1b743b42a3e6b458dbe06cea1985693b0ab68199d043fe9707ba77c8a671b852bb1a8bc86b1bb5084da843505f948bf1224c33302ee6123aa95c96537a848341c626295a229987990c544b1958ff69dd24ec4a1cdeeecee4bb84626411e3bdd0ac73ee7c68f4ca71dff663833e1bf8472997e7fe6bc6df78abfd90900f32f71f141b516c4ec188d29261da9c1fbaaaafab529e2cdd7e913da3a3fa67d623867805386e0bac27ae62e06338d964d33e6b42d02fff978ab70f64c32aaa2f90c7d1e2fd002483c8a5d6d1fb9222abfb3caf2532e2f5fac14e228c876ddd422e3adaf0ff63cf577a7475bd00a32531ae369f6a2d902fdf72183771d0c71434befb037d2bada7f9c9b8d213a6516fade3c5bf1244dff81d4ac12815aef4496f502d585af7a0fee81b7e885abf845e4afcc75fafbe2641453b60307b24e43d0e07200bf063cdc47dc6b2b2122fe1de4e7e07c423fe61cdcdfa35495a06e7e093ee6a00834dbc1be5b615564c7de20d1d9e56bfd0b05a10fcbe07b8aefd1ebb287b2574fa42ccadc0609786edf832e8b8e7f71e4012";
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
        0x78, 0xCE, 0x05, 0x5B, 0xBB, 0xDA, 0x79, 0x56, 0xB9, 0xC8, 0xA1, 0xA2, 0xEC, 0x1F, 0x76, 0x72
      } }; // testnet network id (rotated v3.1.0-alpha.6, fresh-genesis)
      std::string const GENESIS_TX = "033c01000005808095e789c604009528e8a58df0a813cff5a8268e4c96d661df618f5b7b43b1d1420aa567d790ac9a808095e789c6040051b5ca025a20b4b7086e88d15956ffebcdc8027914566262c01dc7aedab75f2851808095e789c60400a042a386b8b38c90ea994a4e776dd9760a09072ceeb9b3c85dc5baddde38078495808095e789c604001647d80be8f88d3b5e26cbb045bcb5f86cdbaaecbb2af73bc4fbdf1edc662737da808095e789c6040042dc291579fd7b3913f646db8c430f8f48e60450bae62bb1aec8b6f7cd54e37217a72d01d38b3ac5b6aff760d8fb7255c08972ef6dd5454b4bab8ecd315e30b4348ab07b06e02b00a4c9d147326c7127e1c51b18503b3bf17cc66aa3bee1910287a240f274ea731f67aad96c7d60fba9efb3d85a7b56f7d58e7361ed60c419685234f96a3fb3ca734e4701206e56bd294941e5cbbba50afb9b82aca8a71b28c55c6806372e6fb8a258938b2549b34f7762a27c1885d0fbfa520ec19ef1abf8ca3a7ee4f7e83ca0dec43f3b497022fb8c65ab67b3365714e9fd6268ad0338c04690d7c6ffdb7d1fa7ff01b7ed78facdce1d725c97413edcb16672a171c2735889b8c9c418c70212f644e59af8e13e3b0c5ce93ba217d713841dd5773bcfda230958e999d45cfaa5edca6fdd5dc31938c78fcc291cf23bc3c514139920b52ae592f863453ee96e172e74b41bfacb90a2f6ea0c395df9233857574384f92c8155e9203a75eef2bd06fc045b0ecff5f45355a1a6ec0dc08f7cbeab9a895634bf6275156e98471aba61fe3f3d5b2c4d23a570e5c13752e2dd677faea8e4a4ad78d5a5ce0a3038154049f148e8058271a5139e811531f9346ff96b9a27a302b284699041a94c2b1a7d6d4d6eff8d90944be2d275799be3dcae8ec74398b2d9571546040f0435e945b55b5763b3a09e4a04f68545804cff87172dd89c66e45aa57e40d0af7faae92515f95ed2b9e19b0b29f2798842eac9679580471b9e65d54547b9fa1dc81086794041da07cb6834d1bdc12bbe22f1349b5be55511725b79787bf26ecd931378d203bc4c331b1d6cd021651d52625501c1afc11836b6a1479453d72fbf6f199c337727046821bc322da8bc7b7d72de3b25b9f32c0de8cc3308f62388b7eccb783516dd82c7c4af451efa2f9ffde6d78e35b046e103c732418cbe5dee1e17df856f73a855866ea3995e6215e298a68bdbcece16c329c579c59eca13162af1330f8cdd5ba2b4b24a0d38bd87cf263f9b0f105756038e03aa90638893ecbe64fb2a046e866e1ddb16fbfbb7d897d483c32132205a2c60332faf03daebfed1e3e23e81777096b4d3720063473073566f0494646cd7c1df2a0612ca5677a309509169f98aaa4f951be2b547ec8fea86432f5fdd35fe6a3cf2389e7428362c2da4003a8fe3584a51d39d27528b48daed87984fd30e873b69b2a47007584840cec049e069da757d305a8f62c1e0cf3f01e6c4d6cae105a7e69b339cc20b9657ab8388e4f4d7498b8f74cd19c344f6f7a3de2330346d32ed8ab087609ce786accf5ae6f5fb9d560428710f18ce92af08db0a5b03f3019c9983524fababa2ca8ed45777008312fe136aee1a9b6c39407db0b40085e47a2bc7c9f777f168ffb1df36346074178309d7a8cdd2cdedf3ab1619b56c054fd6bf0cf9ecf230bf14d80d7656280434b6a54a53358ef5759a78ee2e281e08c96f151b2db1639dacdad5cfa98d23c91649f0bb685ba55d6c74aaceb52ac71129dbd671a1437bfe9fc8a1b5e276360ff3e49f536f65d8511ff354717f88c6c1caff044d97cc1cc8e544a8e05c72996c70ee1c1c545eedf4fbfd43dbce3a148fbd3c2811529df11a7ceb54596ab61bfbad7795c27d180a8cbc21b94cae57fc4bd5f2969a2394f13a039a9c306a2412aa390b9803de636cc505f4c84b3e8550488017e8dc067860518292aba63559365147d227b3f8ec59f3516588602434a62450ffa809a43c13779942762c4024876949f9f9d5275a16d7df124618869fcb00de0f388654a99d483d5a1e3c00fd2787ce0952eb4daf5b8846ea549ad198a507aa84940c3c7e2a2e76d9abf54c793b5278bb20aa9a585d5d9ae0b7466d0a75a54d6a0f077a089794b3595f972b30f94457c5ad0949c22fc80b0683264b6751a615621f2720a9619c818fd725b87367991eb64f1380db0c9461aed36427494aefb4a0f65d9529f5388e7f93af68aaa315bff7f5252884e0a622980e90b7dedcf8a11ccf989307aec9892639311f9701ba5bb85c95bbad2e5c400fbd1db0ef820f889c84f7a2f3e1c242607c0f60a7055e7ca71c031a17cad0431fe05fbca551ca423ebe527559eb2c4c3ebd3dc1a840dbfd8a6775bd9f6ccdc4dee4c1ce84beb2542fd3addd447e18401ebea38d0325e9ee0402582b7e9068bcf96a90e3fa815680dc80fef33a851d018aa09afd593b0db53a1aeeadae9bf8ffad9f1f5f2988aaf0db81249c204fd403824c2cb5b78573bd8e21582aebea47e40c0a7079b7726bcc602317af37b91288c99f1720c2e8f1237764dd9f56066ccc8a7a789f04b3ef1e06d87ce7ae20fa4d87d361a52e322d84a58320042339f6b479741b8c385c20d477be95c8d83b7ee87fcabb8a4d97d32009a24276bdc5628c4d59882c58d93e26308eab20c7a2b451008e0cea19035bbbc0b8002f54e2098094557db970bd533b75f36de025696cb99fa433e75ca1fefba14d87272292e92d2ca07b13d455b6c0d8eb88b71b4fc564aa8528378ee6e4951da2f1216f519947e57dc2c93b5bbef11951d6e53c3120a7460c21cc6b2c80ce755ad3262242c1d364c21279fac276ea7607eacffa39341dab43a7311571bab117bb471db974de48fa46ba96e9c5d6886d891d4e5268669722d75f7b88aaa40b75e2f378e6973e4b5790a1984f6271b2a44af8a9a5c360687ef090b8c4afc2d815fa50b6587f4f8ab99898f172a7c0c9806bd8fadf259c1e3abcd11850b8bf927abd22fd9f394b107c7e1783c177792a8cea32c255db94b4e9c99491b9c99af69f010117594c2cc60054e3ab63a483218142ca7c6b144bcc0ab68e9cd00fde9260d9e737089be4f381ebb9d937e778396cb343f76e08ca359bd78deae3a6f8a73dad4ce11e5f5fbbd033e789dcc3f9e6e993f7dcc605bb0f8625a5c75c6fb8f505246e4188baf6bad28451c4c1dfe49b3b94b540a5ae063bb3dd53244d4e52957c92fd05f9777ad066d71690fb41d346e4eaa43b3aad12a899f20ee67ecc3986a2dc189862fc8d011d02ddb0791575de87d46234d6e9c590277cbb474343b4650bafb02794897d3821921bade1e221c5167f9594ed2096b0671fb04fb7c70908859e0c0cc9ade131a61eb638c87f288198100034742bfeef166d2cb89db9d63ef6e7ed7860eebec40e5a6dbfd3d6fc5a01441c3e8d036e71f19e5d5cb68e313454283266d84cb82e939d76fe852445d27743b03f6b07ee893939d007417113fdff208d279eecb8ba7f3f03b4d371a0c2a0cf1eeeaf7add926f45290ab54a27c5800d814982ec5befca4977acb8a2b4f65c3364c713d4e38cfb106fd8d656903a6c42811de8d13e3d18714182bf6031d837954d29fd7488a100b50f5b3f3981bfdedd8566482ff0ac44cbbc0a36449cc9c5b4a1f8a73a25ba08830d178c843eb76a0b997d320db6ccbd4a7995b3f1cd446e4b47a57ceb1f31a2eda36243b30c3e4dd256d1196c2fa27f0539e18b91f27e6ed2d76e31fac0097596bb4cabfd44a3fcd288dfd68d1ecdd279b6982c65090c925e1d1cbe6202410f6e032f919c89acc4c7fcedd58a033907b6abcfbe9eec0f8d52ac9ae6801f582b5bd979de04e34eaa450dc8365ab4d8f5bbc3514477a777d6e6e10b3d4f636cd68866e2770f01fdb904eb0e86efcfc2b0a8d9697892356f3ed9828848d09327294e5c6df976c4a53391998ef4b25cbb0178e68f7872ec2786a6d385d1009016a9d5cf93e482337f5fb7097c790967e278a2acece81f505445937271a9985d30f84d4491616db30caa3183051ac5416a7863d995784de0aca415605d681156e0eeec5053860a3f1a94b0409f263b6fd2a26df40f310895c1cabbc0dc2b60c279b74fa6a2962c77734dcf76539623e9dba28a9817c8a44467203d56672e829e3ac55abb4e84315fb41008d53de7269e827762f52cd0080b1429eed811cb149fc012100a3f128e7c76e6be8006b4127042f2cd87928210ce552fe4146fdfa491d74aea7bc9e37e555fc61a869c5cab8250bf5e8bfb960bb059d5eca137f7931fe68cccf107009d238273f83553e0882045948b7e4ceea5d62c4bd604d10b959fc53c5cacef07ff84001b53fa765364a16c62ff090219f07bcde5fbcf8cfc6a2a0bb89d8030aabd9643809803cd3f77d3f5ceaa589a94114e9eaa24613aacf3745cd8a1498610dc95513193211ac2654fdbfcad2d8719c992d05c42792982e625d5c17ca05870482b1ede32f7088d120158a951c55435bd2490b17528847cbf120a27a375070523a679cea69c313caf3bee0838179624e2f3b75f98f317eedb16da1e7c8a015616653419e9cace2693c857678d28a648d6cfbc1a9eb19d10694a05135d40e35a977fbada22b3771ec7e289f038fa2d672efa92e6c453babba26e05c89d7104816413f04ebba95d213d6360429d9614fcde9acd10548b74a44ad7af31c734104612c111399f7e9d7eccc83d11bc31fc9fe1646d76becd3899b4d494528af7c44f04bb8911684ecd51feee61452a0467c0421fd94d3945329665248c1086c7b2f59e7fb27109381f634eacaa65b8e3c80c4dd020c546945d93136263088c34aefc2341f91cd3cd4854e0c9720cd89e83960008a11c8eb69616498e615ee4c60d3749a236e213ebb25d8b9993f64ba744d8f2aeb8a93f8007b802de289fee1e20f340ebd255d28de8e7c8a6ab1d2c9cb03319d7dd1dca31f64d83653819051dd71139583812ef470a1ef58fed9f2d069e60acfa2f805e43c393f41b9968b613b5bc418e5ade9aecd98aa01e2e49bdd0d8f0aa05e4d1256d44d1dc3cfcf5120386314c28f654cf07508c393ac0f6e6b590a34b2546702c2931c9a00d00733da69c3838b6d5a776e8c1d244f275f248a642173a2c1cf1eee284dc3148441058fce7d4feb43295e159c834f55e7b63e3de078b242594d941a30e39335694066bfdcd7f9c0574a31849a6f81d68b7f05a04b346fb3d0fe11dd1ddef132770acdc8f26b4528b02437c363e764707135c939d156cd9b006dc30ced2fefe50fce20cf9b70eec20ca21673c43ae5249e73a9d0af2ed96ba748b3ae0c94d0761e7f42960135988b26a689653f7b3d8732bf91ae1ef4c7fcabc8bf8ad10af50b10a0c66b4efc8272fbd03d7b1305199ddab551fe2ba1704efc0711dccddf2a7dfbcebbaf86936f70ec83062c633bf0cbf34b7b68c9bab66d7dc555b1d28e5c11a2634204d3886e9a34e21cb889fe9e527da6414018417c4be03b70e3af544abeae5fbb167e1c03728c856cee1a07ac0e62fe92c6422f4f2e162849f36053a0ec4d94e4c1305814418fc302978e8df8067488b1fe2b19d41ae870def3d77de0e62c838d098a0a0b84c0f24ec19e7e99d1d08d8ab72b3a9574f2fb9dc4eb357742a73b1326f8a02f6134e54be3d4fa90fd6584f678d00abeab33277c3f053858510239d479ae6da8c76b1596ce2b5c6e80ec02ca69e587b6cfa5ee1dfc41c6eeb52375b3ecb3c17563e9937953c2af69e17585fd6519c9adc57e1dd187611c59a94fd417bccf4b0573fafa85b1b258270c56da01484489f4c3558cc66431a1319b972936f96b6fd1fd594df2df931210dd5d43900501836399a8d652900daf9ac3055c5854de333718ee8b6e37206b958edbf81f1206653b1ba0c1197fcb1d46df5acd4aa027f39a2c98c8b84a3a226ab6acec5b4b8b6d176439440a3e5f33fec75ff8d897260a347d8dbeeefb69c76e6f96eb96fba90708d2cef67d129752387ed59b566313e6c8cb9cebcd5a1d6c26868354b40c31f7926294f85a609d835ff9796b4309ec3921041dadef9996a902735dc2c081d632984aa82f2d762aa3b83c65b1f4b66ec81e7673b4582cee07d3d04abe84650335da399bcc1d309b5f37ee2b2035ad82dbfa474f6df7aba0059acd72ed68c8630b0c2ed3de5a77e41369c315686ef537f77dae9292dfb443e479eabd4456a9f6f69e34c7154524fc177c5e1cab627fcc8e823ed1933930085a54b4a233282ece04023e8e0c6537a223fcc4b78f85f381406046f30fc42b277729f594badafc129e64a7dd4e0cc5c6bfafb69d985f46fab35f592da99dae63860d9b919e1ac6a299b424ea60769edfabc70999f2898c6071f72c040c2e645d645f8296c9a6ead2c499420c4dcba846473e13964ed1b7009350c83cb74cd5c132afddd226a413585703ca6097454fab51020f08b1e841f9b893a788b0c13997ce2d471bbca686d165fbda05052bbc728a6285630ff1035540c4903668c971b84be6360dab5eada90d6dac820a28a32e58719c3babcba2d6d26a771ce8ccce7ce21dddd69dbd988e5b013e29ea79c816f80d01ecb330765128a70975269606a766b644c1645a23367f3ab6c4de57a53f8384a88bc9055c934e48b0a1ade80fbfe4c996685de267cc846cefd02c5b8b0e3c92581722ae85b81dc95b48d5429d04b359f630648cf8faec68bdda1c0d4129ddbd3e50abd17d4f8526214f49f2ae083ae98c12dc5a291034123a1b83d967bbc81558ea5e5eec3ef7e1dd6efe3352dcf72d64301e73df668a28e2a917d2f8d735c3929ce58fc44b59feea1e6ae928fbcdbd1ec086e461f1f1cdf546cccc82ac838de670359420091e136facfe82f9fe742f2bed7bbcbcc16c69897bf0d598989df20b9fec5d73115677a8aff3d8d49470ebe856dfa002a8eb7cada0467776e82089303088ec9dcb49a9e42df8cbd285e7525043b608898ba769f59d4b563789871c6422c424c83486b758aa2cb9373cef1ad5c8922ef9d45cf326ce48d7c1cbd045f2524af659ba8e74e2bec71ae36a1156229c17ca7d78cb313447aef836445a13089adf905eb89d58f1f6b3a0ed7bed6362e0d4c45458bc2cbb5ddfd41b3dd2304aba17119cc402374ff097843b953acd98d2f9ae83ba666704da1121e5680f4bb441ed6a30aaf24ecf21d09cb770c6130bfa76bc991df11d11eb77690f01227ce8ca0e13890f9e2c61c64467b6b6e62e7f9d5252e0934389455f2664f508a5d199464906686bd632beb6b561febed1b66952986a235839e09bb76ac659a73b6b2b80c5a58057d39261dd813ce7ec237f9d4fab2a3e2f7dfa9660bdd9b69cc7cac7e4e8f00c0165a0f47b2fc5840d2af3226d371f5f28b46dfa243821725fd701f897f8a23d03bbb914e3137be4e26087a9b5e2bec640a3ad6e94c5927441d6e7c6377d5b976bdc2da5963528337e698d706a9adce756d328eee0ecb557b20db429e90d06d426f942ddc59d952f8cf57f7d180c1b8b3ffb2b8fb6c2052f3577728b1b5c8b3e942a810c92b5fe1329b3a1b51e550065a87e2a3b23f35e733ad30683c68b547f175919b9ccc50c84406099ca303ffa7433b013402bc4e491dd2742ae36f0db0e1123fcffd96d3b2b80e705399643ec27ba36dbbb98896c1056a2fb1ffe086486294c249135a04ddc396d3f7ef062e534a05b237a6330d892c5b8fe0f9a2b666d7a31e5d0534e9e4dab6ced1cf1ead63a6f8d93b14380c41584111eaaeee9ef3801a79e6d40937a845ec967edc2b063dbdbaf7c8c75934cc5892dd9bdd7c9ca82ee2d966148d89e4e439ba329d021346553d0cec248586c30e92d796c2d30284dfe87ff1966598b63f896e151230d49259e4746d8a2918ea857638d3c9125e72e5847b562dcbf17139195d11318e85b7cffd37d9d69d6a42da24d66a3ab8a2585fbb20a87031c5d6bbba2682ca1ad876f0c5c7ab7dadab65e23cab3eba7354d0e040ade1d1bd465046e868571e6a1392b5821f4f86115f88f9ee3332c944aeda5eba834a36b755f868b1f3023d6c8964080210a73f2d55d835b9d2518b6dbd8479b61a9705b32d78877f29ef33e3d04f95ab42b02cfc69d5e29d59e511bc1f12296b4ef986ab2fe3c7d6250e6c668bed2b31fa4dc9b59296b4c2077ab279bb1002e5c33bfdd6da7d70ce21b46e4de93eeec65423819a0f9d09f46c600e619145b23cd80bc1166d8607a00178e7237b54006ff1d6e9c0844aa8c4c852acfd3ddab6591210c839817da4793f946d554a0d4f84a56bda70dbb4ba0ce8bbf97e9a41db6b12f3b503cff152f70b1b1471a8a349dc3bbca2894dbffceb390d000e70d9b8b573b9d7f713d2234d4e955f5badbb2d591c978495522ccf49476e85eb12fda041b5e4e4a0e926b1c6711423c5b6b40e888e5fa8db5fac118ced5f78742994e78ff835d387daaec8570b001f070a81e1a7a61179f3ca2b7908bbe62fce4de356b1f05280282da1e1251ef9bb51c8c48801fb8b0713485334e4e2428289afd17ba1747f001be7eb1d90e59a9702b6aa0efe56f805ae3f841ebbbaa586d1d2b0eec65d7a7118b5f12e2c047b4ca05eaa02fd7860cc216c435973db0311179f145f97c6234b6da729f5d9f23fea606205d1ac98ffa3ebbe7f721c943ca30b329588d46016e2ee4fc3a5ff946cfd3b2f72de506beadc7c0ce6c125791b38b48537b2bf4950860da94567362ea4e0dac3b066d1417040061f4117b40eebb64559ba6d0bb2b45be9c124f9c1fd7d5109d1694caa648dd714e578763a16ea16262d995f2a87b0e174";
    uint32_t const GENESIS_NONCE = 10101;
  }

  namespace stagenet
  {
    uint16_t const P2P_DEFAULT_PORT = 13021;
    uint16_t const RPC_DEFAULT_PORT = 13029;
    boost::uuids::uuid const NETWORK_ID = { {
        0x2D, 0x21, 0x97, 0x54, 0xA1, 0xBD, 0x79, 0xBA, 0x05, 0x40, 0xFD, 0xFB, 0x8D, 0xC8, 0xA4, 0xAE
      } }; // stagenet network id (rotated v3.1.0-alpha.6, fresh-genesis)
    std::string const GENESIS_TX = "033c010000018080e983b1de16002f158ae8871c4e535daaac2bd2be1ced21daac45d32966149047872d377dd09552a6090159c7bcb67178ba75aa0987b99f6c3dc41140eef93dd7bc343084e7e5e883b79f06e008dc095a8d4483fb114de58977308017dbe97afc4f962f7e2bc02f6069c9d7260e03eca347120354e092f6376bef16ba903c8ae2fa1cd7f476305417eed6d4c1644e876bd7f2d1dc1f9c0c13ed4c2ffd995a183c0f861a0eafbe8f024b4c65da01e639abfd0e11837320fd312ceaa607be4de7347e65fd58e2c76ddacb0f5b1d4de41d3954cc585530efc3662ccb3cdeb6a37d40ab4f5a9a9d1f2cc71b6dfbb874cca9506cb2b6417c80b63b499d7c3ceb2a9b0f8b06cb603661489ba09e9c01255fb20b41237e29afacb51aa789ffdd9c2092ed030d5b52f1d560846ad1c628950d1140069259ab10ba5bf250584762c964e316e21647f61329591eab7de6c55f1e3eb06eb5f84491e1bcb91d45908225d6cb86359cb392acc7bf22dc0ab22f973547f7f3879b4783e3fb6b05b2b37dec1ed0e86d8298aceb383848d60753ac2bae2b8eb50ebd6af41bed32d7aaa2c2d9a167cad596f2318c7ed4465661c6daa528d7c8783b4113b5f1ac108f82f9a58f240d9ebb1485a3aa1d0a23363db21514d88618492facbd03cee8875e8e4261f7195827f7b54ebbecc128953f1d1200cccbc43fe4cb2b51f13272437b0bde84ba5cc7145b96ecf35b7c7856799ddc0edfdb7ae8a12864be35c3dada801672299892096a2db2b28a30b57ce43d1e8b6d70e5e76d31b58d2d83b433c0ca80babfac69cde4a6829b7214f231a2c330764b156249c64994e7c5b1bf14b4a17eb52bd30fe4ab6fb288fbea5db3103f3e8e677cf65957207e89c8938b72eaa10b6d936d19adf5047e9cb6ddb4cab1cb90012609b681a42ac6bc5afd1f3b9f3f65819d508d0523fa6d5e8d9fd4f25ca37bb5bff0887dd2d050496806ed96229592e4336a81237284661c39597d75399a3e6f1f7cde2225392c30aac0019a30ced4fd416b67bd8dac46974cc2082c196cf057e15e5eec83deb29d7e1948ae4e2d54c9e4c6a228abb60ea7f0316efa6b4d56421635293b22252d983de3ac23d415666504f5ea06a304a86dc3ef7814bd5f3988d296452d0fa9bfe43e0a2a012d61cf78cd99350c6fb204ca0d4b9556b7c20beac975a59e9b631e21bf03de5cfb2ecda653cb806c98d226ee5e4f59b421e2f4f59fba03f3e1ac72c4a4b591fb693be2153d42eacb8920a3251402935536252a3d70a67f811cdcc0e0e5f3297483d863911789650f66e2669691602ab76af3dac6e675cfe4a96c6b3d66e3280349e871c424dbea5971cefcef83902eff3ac2d745a66f0d0070e7c53513422bb719ae7bdd9aa7c762ffc0fb5ee40365bd5440fbc5daba95e5c7610ebe43e6679283b6544d5735cde3c9a21743e083030a0cdff1c808cf7eea2ed7fe8199895a31292bf00b5ac75770cec2fd7a9a6765bef9ff943fd680df8a0abd0e2f6f1209cc67c7d6f5f76925f1fc685495d49ac6e5a83dbe16569054e6af1248194ee6fea50379a674add0b2e44113921b9af90cfc50a0a2f0d8cefb378dddf4f24565afc7ae6d52a89ac3292c94dc48d75f56c4efdebd5fbcf9b4062a3569e40b8bf65459b954e089eb9b810e580faf3dd07ecb34efe045a1444e072072a15e0839a612127ed20bb58fdf5eb4ca0937daf9875099c55d171dc034580300eca4c802c979400be63892fde3009646fbaaf50eee05f6eebf8edb19b94b28652d0e32d6a51037dd42224e043410546e569c";
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
