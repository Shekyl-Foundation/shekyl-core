# Copyright (c) 2014-2022, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(unit_tests_sources
  account.cpp
  apply_permutation.cpp
  block_reward.cpp
  economics_c2a_prime.cpp
  bulletproofs_plus.cpp
  gap7_bp_bench.cpp
  command_line.cpp
  crypto.cpp
  daemon_rpc_client.cpp
  decompose_amount_into_digits.cpp
  device.cpp
  difficulty.cpp
  epee_levin_protocol_handler_async.cpp
  seam_endpoint.cpp
  epee_serialization.cpp
  epee_utils.cpp
  expect.cpp
  json_serialization.cpp
  get_xtype_from_string.cpp
  keccak.cpp
  levin.cpp
  logging.cpp
  main.cpp
  memwipe.cpp
  mining_parity.cpp
  mlocker.cpp
  mtp_boundary.cpp
  mul_div.cpp
  multiexp.cpp
  net.cpp
  node_server.cpp
  parse_amount.cpp
  peer_policy_drop_verdict.cpp
  random.cpp
  rpc_target_wire_contract.cpp
  rpc_facts_ffi_roundtrip.cpp
  rolling_median.cpp
  seed_epoch.cpp
  serialization.cpp
  sha256.cpp
  stall_detection_calibration.cpp
  stack_trace.cpp
  test_tx_utils.cpp
  threadpool.cpp
  util.cpp
  varint.cpp
  fcmp.cpp
  vercmp.cpp
  wallet_bip39_residency.cpp
  wipeable_string.cpp
  is_hdd.cpp
  aligned.cpp
  archival_credit_wire.cpp
  archival_serve_credit.cpp
  archival_bond_post.cpp
  archival_reward_emission.cpp
  archival_emission_ct_balance.cpp
  ct_balance_differential.cpp
  pruned_tx_hash_parity.cpp
  prunable_digest_parity.cpp
  tx_prunable_region_sole_occupant.cpp
  relay_category.cpp
  )

set(unit_tests_headers
  unit_tests_utils.h)

monero_add_minimal_executable(unit_tests
  ${unit_tests_sources}
  ${unit_tests_headers})
target_link_libraries(unit_tests
  PRIVATE
    fcmp
    cryptonote_protocol
    cryptonote_core
    rpc
    net
    serialization
    p2p
    # daemon_rpc_client.cpp exercises src/daemon/rpc_client.h, whose failure
    # path writes through scoped_message_writer -> rdln::suspend_readline
    # (same link the daemon carries; empty when built without readline).
    ${EPEE_READLINE}
    # The one Rust archive a C++ binary links (libshekyl_ffi.a; the
    # single-image contract, V3_WALLET_DECISION_LOG.md 2026-06-11). The
    # daemon's RPC server and its `shekyl_rpc_*` exports are not in it:
    # they reach shekyld as rlibs of the Rust binary (DC-Q19) and no C++
    # test calls them. daemon_rpc_client.cpp's transport,
    # `shekyl_daemon_ctl_*`, is shekyl-ffi's (`ctl_client`).
    ${SHEKYL_FFI_LINK_LIBS}
    # rpc repeats after the Rust archive: its members import
    # core_rpc_ffi_* / shekyl_submit_*, which live in rpc — left-to-right
    # static-archive resolution needs a post-archive occurrence.
    rpc
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${GTEST_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})
if(UNIX AND NOT APPLE)
  target_link_libraries(unit_tests PRIVATE pthread dl)
endif()
set_property(TARGET unit_tests
  PROPERTY
    FOLDER "tests")

if (NOT MSVC)
  set_property(TARGET unit_tests
    APPEND_STRING
    PROPERTY
      COMPILE_FLAGS " -Wno-undef -Wno-sign-compare")
endif ()

SET_PROPERTY(SOURCE main.cpp PROPERTY COMPILE_FLAGS -DDEFAULT_DATA_DIR="\\"${CMAKE_SOURCE_DIR}/tests/data\\"")
SET_PROPERTY(SOURCE archival_serve_credit_integration.cpp PROPERTY COMPILE_DEFINITIONS
  GATE2_KAT_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-archival-retention/tests/fixtures/gate2_serve_credit_kat_v1.json"
  SERVE_CREDIT_TX_PARITY_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-wire/tests/fixtures/serve_credit_tx_parity_v1.json")
# COMPILE_DEFINITIONS (not COMPILE_FLAGS) so CMake owns the per-generator
# quoting of the string-literal values. The quote characters below are part
# of each definition's value (CMake only treats quotes as delimiters at
# argument start), so the compiler receives -DNAME="/abs/path" and the
# macro expands to a valid C string literal — verified in build.ninja.
SET_PROPERTY(SOURCE archival_bond_record_v7_corpus.cpp PROPERTY COMPILE_DEFINITIONS
  ARCHIVAL_BOND_RECORD_V7_CORPUS_PATH="${CMAKE_SOURCE_DIR}/docs/test_vectors/ARCHIVAL_BOND_RECORD_V7.json")
SET_PROPERTY(SOURCE mtp_boundary.cpp PROPERTY COMPILE_DEFINITIONS
  MTP_BOUNDARY_VECTOR_PATH="${CMAKE_SOURCE_DIR}/docs/test_vectors/MTP_BOUNDARY_V1.json")
SET_PROPERTY(SOURCE pruned_tx_hash_parity.cpp PROPERTY COMPILE_DEFINITIONS
  PRUNED_TX_HASH_PARITY_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-wire/tests/fixtures/pruned_tx_hash_parity_v1.json"
  LIVE_ORACLE_SPEND_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-wire/tests/fixtures/live_oracle_spend_v1.json")
SET_PROPERTY(SOURCE prunable_digest_parity.cpp PROPERTY COMPILE_DEFINITIONS
  PRUNABLE_DIGEST_PARITY_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-wire/tests/fixtures/prunable_digest_parity_v1.json"
  PQC_SIGNING_PREIMAGE_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/rust/shekyl-wire/tests/fixtures/pqc_signing_preimage_v1.json")
SET_PROPERTY(SOURCE memwipe.cpp PROPERTY COMPILE_FLAGS -Ofast)

add_test(
  NAME    unit_tests
  COMMAND unit_tests --data-dir "${TEST_DATA_DIR}")

