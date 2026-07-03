# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Phase 3a Hole-1 gate: RandomX v2 C full-dataset vs Rust light-cache PoW
# parity (docs/design/RANDOMX_V2_PHASE3_PLAN.md §7). Built only when
# BUILD_RANDOMX_V2_MINER_LIB is ON, which provides the imported
# `shekyl_randomx_v2` target (external/randomx-v2 @ aaafe71, the
# full-dataset C library). This directory is added under that guard by
# tests/CMakeLists.txt.
#
# Cron-gate only: each ~2 080 MiB dataset takes minutes to allocate and
# initialize even with the multi-threaded fill, so the ctests here carry
# the `randomx_v2_full_parity` label (full sweep: 35 datasets) — with the
# daily subset additionally labeled `randomx_v2_full_parity_daily`
# (genesis + canonical + miner-KAT + the first 16 corpus seeds, mirroring
# the Phase 2g per-PR seed subset) — and are excluded from the per-PR
# fast gate (this directory is not configured without the miner-lib
# flag). The CI consumer is the `full-parity` job in
# .github/workflows/randomx-v2-differential.yml. Run locally with:
#
#   ctest -L randomx_v2_full_parity_daily   # daily-sized subset
#   ctest -L randomx_v2_full_parity         # full sweep
#
# The corpus invocations read the gen-parity-corpus v1 file (see
# rust/shekyl-randomx-differential/src/parity_corpus.rs). It is ~150 MiB
# and deterministic, so it is generated (not committed):
#
#   RANDOMX_V2_INSTALL_DIR=<build>/external/randomx-v2-install \
#     cargo run --release --locked -p shekyl-randomx-differential \
#       --bin gen-parity-corpus -- --out ${SHEKYL_PARITY_CORPUS_FILE}
#
# A missing file FAILS the corpus invocations (with the command above in
# the error) rather than skipping them — a skipped gate that reports
# green is the armed-gate-with-no-trigger failure mode this wiring
# exists to close.

monero_add_minimal_executable(randomx-v2-full-parity
  randomx_v2_full_parity.cpp
  full_dataset_init.h)

target_include_directories(randomx-v2-full-parity
  PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${MONERO_GENERATED_HEADERS_DIR}")

# - cryptonote_core: genesis derivation (generate_genesis_block /
#   get_block_hash / get_block_hashing_blob) and, transitively, the Rust FFI
#   image (${SHEKYL_FFI_LINK_LIBS}) that resolves shekyl_pow_randomx_v2_hash.
# - shekyl_randomx_v2: the full-dataset C reference; the imported target
#   propagates its include dir (randomx.h) via INTERFACE_INCLUDE_DIRECTORIES.
# - ${SHEKYL_FFI_LINK_LIBS} is also named explicitly to mirror the sibling
#   lwma1-cross-check harness and keep the FFI archive on the link line.
target_link_libraries(randomx-v2-full-parity
  PRIVATE
    cryptonote_core
    shekyl_randomx_v2
    ${SHEKYL_FFI_LINK_LIBS}
    ${EXTRA_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT})

# Separate-process, miner-shaped KAT tool (provenance closure for the
# frozen KAT; see randomx_v2_miner_kat.cpp). Deliberately links ONLY the
# C v2 library — no cryptonote_core, no Rust FFI — so its computation is
# independent of everything the parity harness links.
monero_add_minimal_executable(randomx-v2-miner-kat
  randomx_v2_miner_kat.cpp
  full_dataset_init.h)

target_link_libraries(randomx-v2-miner-kat
  PRIVATE
    shekyl_randomx_v2
    ${CMAKE_THREAD_LIBS_INIT})

set_property(TARGET randomx-v2-full-parity randomx-v2-miner-kat
  PROPERTY
    FOLDER "tests")

# One seed, one process, one ~2 080 MiB dataset (per-seed failure
# isolation; see the harness header). `genesis` covers the
# consensus-relevant seed (derived through the production path);
# `canonical` covers a second independent dataset and carries the frozen
# KAT anchor; `miner_kat` re-derives that anchor in the independent
# miner-shaped process; `corpus_seed_<i>` re-checks the Phase 2g
# canonical pins for nightly seed group <i> under C-full-dataset.
add_test(
  NAME    randomx_v2_full_parity_genesis
  COMMAND randomx-v2-full-parity genesis)
add_test(
  NAME    randomx_v2_full_parity_canonical
  COMMAND randomx-v2-full-parity canonical)

# Blob + expected hash mirror the harness's kKatBlobAscii /
# kFrozenKatHashHex (randomx_v2_full_parity.cpp). The duplication is
# deliberate and load-bearing: the tool must not share the harness's
# constants, so a drift between the two copies makes exactly one of the
# canonical / miner_kat tests fail — loudly flagging the drift — instead
# of both quietly agreeing on a changed value.
add_test(
  NAME    randomx_v2_full_parity_miner_kat
  COMMAND randomx-v2-miner-kat
          "Shekyl RandomX v2 full-dataset parity KAT (Phase 3a, pin aaafe71)"
          "34f8b0179159d837e463c17c8692c106d2d3536f7da325aeefeb3e22a136b651")

# Corpus sizing. _seed_count mirrors NIGHTLY_SEEDHASH_COUNT and
# _daily_seed_count mirrors PER_PR_SEEDHASH_COUNT
# (rust/shekyl-randomx-differential/src/corpus_random.rs). The harness
# re-checks the count against the corpus file header on every invocation
# (the <expected_seed_count> argument), so a corpus-sizing change that
# is not mirrored here fails every corpus test rather than silently
# leaving new seeds untested.
set(SHEKYL_PARITY_CORPUS_FILE "${CMAKE_CURRENT_BINARY_DIR}/parity_corpus.dat"
  CACHE FILEPATH
  "gen-parity-corpus v1 output consumed by the randomx_v2_full_parity corpus ctests")
set(_parity_corpus_seed_count 32)
set(_parity_daily_seed_count 16)

set(_parity_daily_tests
  randomx_v2_full_parity_genesis
  randomx_v2_full_parity_canonical
  randomx_v2_full_parity_miner_kat)
set(_parity_weekly_tests)
math(EXPR _parity_last_seed "${_parity_corpus_seed_count} - 1")
foreach(_seed RANGE 0 ${_parity_last_seed})
  add_test(
    NAME    randomx_v2_full_parity_corpus_seed_${_seed}
    COMMAND randomx-v2-full-parity corpus
            "${SHEKYL_PARITY_CORPUS_FILE}"
            ${_seed}
            ${_parity_corpus_seed_count})
  if(_seed LESS ${_parity_daily_seed_count})
    list(APPEND _parity_daily_tests randomx_v2_full_parity_corpus_seed_${_seed})
  else()
    list(APPEND _parity_weekly_tests randomx_v2_full_parity_corpus_seed_${_seed})
  endif()
endforeach()

# TIMEOUT: one dataset build (multi-threaded) + ≤32 hashes per test is
# minutes, not an hour; 3600 s is generous headroom over ctest's 1500 s
# default so a slow shared runner cannot flake the gate.
set_tests_properties(
  ${_parity_daily_tests}
  PROPERTIES
    LABELS "randomx_v2_full_parity;randomx_v2_full_parity_daily"
    TIMEOUT 3600)
# Guard: if _parity_daily_seed_count is ever raised to the full corpus
# count, the weekly list is empty and a bare set_tests_properties() would
# be a configure-time error.
if(_parity_weekly_tests)
  set_tests_properties(
    ${_parity_weekly_tests}
    PROPERTIES
      LABELS "randomx_v2_full_parity"
      TIMEOUT 3600)
endif()
