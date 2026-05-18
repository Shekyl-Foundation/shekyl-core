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

set(difficulty_sources
  difficulty.cpp)

set(difficulty_headers)

monero_add_minimal_executable(difficulty-tests
  ${difficulty_sources}
  ${difficulty_headers})
target_link_libraries(difficulty-tests
  PRIVATE
    cryptonote_basic
    ${EXTRA_LIBRARIES})
set_property(TARGET difficulty-tests
  PROPERTY
    FOLDER "tests")

add_test(
  NAME    difficulty
  COMMAND difficulty-tests "${CMAKE_CURRENT_SOURCE_DIR}/data.txt")
add_test(
  NAME    wide_difficulty
  COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/wide_difficulty.py" "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/gen_wide_data.py" "${CMAKE_CURRENT_BINARY_DIR}/difficulty-tests" "${CMAKE_CURRENT_BINARY_DIR}/wide_data.txt")

# ----------------------------------------------------------------------
# LWMA-1 cross-check harness (Phase 2 of docs/design/DAA_LWMA1_PLAN.md).
#
# Compares the Rust production implementation
# (`shekyl_difficulty_lwma1_next` via `libshekyl_ffi.a`) against:
#
#   - The canonical zawy12 LWMA-1 C++ reference, vendored verbatim
#     against the byte-offset anchor in
#     `docs/design/refs/zawy12_issue_3_lwma1.anchors.json`.
#   - The Shekyl hybrid reference (running-max + symmetric-clamp step
#     2/3), vendored from
#     `docs/design/refs/shekyl_lwma1_running_max_symmetric_clamp.md`.
#
# Iterates the §8.1 input corpus and asserts the cross-implementation
# relations documented in `docs/design/DAA_LWMA1.md` §3 / §8.1. Failure
# aborts the test; the gate is 100% passing before the C++ cutover.
# ----------------------------------------------------------------------
monero_add_minimal_executable(lwma1-cross-check
  lwma1_cross_check.cpp
  zawy12_lwma1_reference.h
  shekyl_lwma1_hybrid_reference.h)
target_include_directories(lwma1-cross-check
  PRIVATE
    "${CMAKE_SOURCE_DIR}/src"
    "${MONERO_GENERATED_HEADERS_DIR}")
target_link_libraries(lwma1-cross-check
  PRIVATE
    ${SHEKYL_FFI_LINK_LIBS}
    ${EXTRA_LIBRARIES})
set_property(TARGET lwma1-cross-check
  PROPERTY
    FOLDER "tests")

add_test(
  NAME    lwma1_cross_check
  COMMAND lwma1-cross-check)
