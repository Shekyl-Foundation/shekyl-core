# Copyright (c) 2018-2026, The Shekyl Foundation
# Copyright (c) 2018-2026, The Shekyl Foundation
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

set(daemon_sources
  command_parser_executor.cpp
  command_server.cpp
  daemon.cpp
  main.cpp
  rpc_command_executor.cpp
)

set(daemon_headers)

monero_find_all_headers(daemon_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(daemon
  ${daemon_private_headers})
shekyl_add_executable(daemon
  ${daemon_sources}
  ${daemon_headers}
  ${daemon_private_headers})
target_link_libraries(daemon
  PRIVATE
    rpc
    blockchain_db
    cryptonote_core
    cncrypto
    common
    p2p
    cryptonote_protocol
    serialization
    ${EPEE_READLINE}
    version
    # Force-load libshekyl_daemon_rpc.a *before* the shared FFI link
    # set so every shekyl_log_* reference resolves from the daemon-rpc
    # archive's embedded shekyl-logging image (one tracing dispatcher)
    # rather than the standalone libshekyl_logging.a. See the
    # SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE comment in cmake/BuildRust.cmake
    # and the post-link nm gate below.
    ${SHEKYL_DAEMON_RPC_WHOLE_ARCHIVE}
    ${SHEKYL_FFI_LINK_LIBS}
    ${SHEKYL_DAEMON_RPC_LINK_LIBS}
    rpc
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES}
    ${Blocks})
set_property(TARGET daemon
  PROPERTY
    OUTPUT_NAME "shekyld")

# Single-tracing-dispatcher gate: the binary must contain exactly one
# tracing-core GLOBAL_DISPATCH definition. Two copies means the daemon
# linked both the daemon-rpc-embedded shekyl-logging image and the
# standalone libshekyl_logging.a — the split-image regression in which
# shekyl-daemon-rpc tracing events are silently dropped
# (V3_WALLET_DECISION_LOG.md 2026-06-10). nm runs pre-strip, so the
# symbol is visible in both debug and release link products.
if(UNIX)
  find_program(SHEKYL_NM_EXECUTABLE nm)
  if(SHEKYL_NM_EXECUTABLE)
    add_custom_command(TARGET daemon POST_BUILD
      COMMAND sh -c "count=$(${SHEKYL_NM_EXECUTABLE} \"$0\" | grep -c GLOBAL_DISPATCH || true); if [ \"$count\" -ne 1 ]; then echo \"shekyld single-dispatcher gate FAILED: $count tracing GLOBAL_DISPATCH definitions (expected 1)\" >&2; exit 1; fi" "$<TARGET_FILE:daemon>"
      VERBATIM
      COMMENT "Asserting single tracing GLOBAL_DISPATCH in shekyld")
  endif()
endif()

install(TARGETS daemon DESTINATION bin)
