# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# shekyl-wallet-bench: Google Benchmark harness capturing the wallet2 C++
# baseline for the hardening pass (commit 1 of docs/MID_REWIRE_HARDENING.md).
#
# Opt-in: configure with -DBUILD_SHEKYL_WALLET_BENCH=ON to enable. Off by
# default because the FetchContent of Google Benchmark v1.9.1 is a cold-build
# cost that normal contributors should not pay.

find_package(benchmark QUIET)

if (benchmark_FOUND)
  message(STATUS "Google Benchmark found on the system: using system package")
else ()
  message(STATUS "Google Benchmark not found on the system: fetching v1.9.1 via FetchContent")
  include(FetchContent)
  FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG        v1.9.1
    GIT_SHALLOW    TRUE
  )
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_DOWNLOAD_DEPENDENCIES OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googlebenchmark)
endif ()

set(wallet_bench_sources
  bench_wallet2.cpp
  bench_fixtures.cpp)

set(wallet_bench_headers
  bench_fixtures.h)

monero_add_minimal_executable(shekyl-wallet-bench
  ${wallet_bench_sources}
  ${wallet_bench_headers})

target_link_libraries(shekyl-wallet-bench
  PRIVATE
    wallet
    cryptonote_core
    common
    cncrypto
    epee
    benchmark::benchmark
    ${Boost_CHRONO_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${EXTRA_LIBRARIES})

set_property(TARGET shekyl-wallet-bench
  PROPERTY
    FOLDER "tests/benchmarks")

# Not registered via add_test(); benchmarks run on a dedicated invocation
# (scripts/bench/capture_cpp_baseline.sh) and intentionally do not gate the
# normal test suite.
