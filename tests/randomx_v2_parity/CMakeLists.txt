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
# Release-gate only: each ~2 080 MiB dataset takes minutes to allocate and
# initialize, so the ctests carry the `randomx_v2_full_parity` label and are
# excluded from the per-PR fast gate. Run both with:
#
#   ctest -L randomx_v2_full_parity
#
# The harness allocates exactly one dataset per process (bounded ~2 GiB
# peak, per-seed failure isolation; see the .cpp header), so the two seeds
# are registered as two separate ctest invocations.

monero_add_minimal_executable(randomx-v2-full-parity
  randomx_v2_full_parity.cpp)

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

set_property(TARGET randomx-v2-full-parity
  PROPERTY
    FOLDER "tests")

# Two seeds, two processes (one full dataset each). `genesis` covers the
# consensus-relevant seed (derived through the production path); `canonical`
# covers a second independent dataset and carries the frozen KAT anchor.
add_test(
  NAME    randomx_v2_full_parity_genesis
  COMMAND randomx-v2-full-parity genesis)
add_test(
  NAME    randomx_v2_full_parity_canonical
  COMMAND randomx-v2-full-parity canonical)
set_tests_properties(
  randomx_v2_full_parity_genesis
  randomx_v2_full_parity_canonical
  PROPERTIES
    LABELS "randomx_v2_full_parity")
