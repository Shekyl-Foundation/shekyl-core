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

include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

set(common_sources
  command_line.cpp
  error.cpp
  expect.cpp
  util.cpp
  i18n.cpp
  password.cpp
  perf_timer.cpp
  threadpool.cpp
  aligned.c
  timings.cc
  combinator.cpp)

if (BACKCOMPAT)
  list(APPEND common_sources compat/glibc_compat.cpp)
endif()

set(common_headers)

monero_find_all_headers(common_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(common
  ${common_private_headers})
monero_add_library(common
  ${common_sources}
  ${common_headers}
  ${common_private_headers}
  DEPENDS generate_translations_header)

target_link_libraries(common
  PUBLIC
    cncrypto
    ${Boost_DATE_TIME_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_CHRONO_LIBRARY}
  PRIVATE
    ${OPENSSL_LIBRARIES}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${EXTRA_LIBRARIES})

# The `__cxa_throw` hook is its own library, linked only by
# `enable_stack_trace` (src/CMakeLists.txt) and the unit test of the hook.
# It was a member of `common`, and in a non-STATIC build its object
# *defines* `__cxa_throw`, so any binary that linked `common` resolved every
# C++ throw to the hook before libstdc++ was searched — `shekyld` included,
# whose remnant never asked for it (DAEMON_CONFIG_CUTOVER.md DC-Q22,
# DC-F27): each throw in the daemon wrote a `[stacktrace]` dump straight to
# stderr, past the Rust log sink. A C++ executable opts in through
# `enable_stack_trace`; a library member reaches whoever links the library.
if (STACK_TRACE)
  monero_add_library(stack_trace stack_trace.cpp)
  target_link_libraries(stack_trace
    PUBLIC
      ${LIBUNWIND_LIBRARIES})
endif()

#monero_install_headers(common
#  ${common_headers})
