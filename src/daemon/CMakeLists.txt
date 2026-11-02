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

# shekyld is a Rust binary (rust/shekyld; DAEMON_CONFIG_CUTOVER.md DC-Q19).
# What this directory builds is the C++ that remains behind its two entry
# points, `shekyl_remnant_run` and `shekyl_remnant_stop` (daemon.h): the
# console, the RPC command executor and `Daemon`. It is a static library,
# and cmake/BuildRust.cmake's `shekyl_rust_link_cxx_closure` hands this
# library and everything it links to the Rust binary's link (DC-Q23).
#
# Not `shekyl_add_executable`: there is no C++ executable here, so none
# of what that helper attaches — `STACK_TRACE` and its `--wrap=__cxa_throw`
# among them (DC-Q22: the Rust side owns the process's signals and its
# panic hook; a C++ crash handler would be a second owner, DC-F17).
set(shekyld_remnant_sources
  command_parser_executor.cpp
  command_server.cpp
  daemon.cpp
  rpc_command_executor.cpp
)

set(shekyld_remnant_headers)

monero_find_all_headers(shekyld_remnant_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(shekyld_remnant
  ${shekyld_remnant_private_headers})
monero_add_library(shekyld_remnant
  ${shekyld_remnant_sources}
  ${shekyld_remnant_headers}
  ${shekyld_remnant_private_headers})
# PUBLIC: this library is never linked by a C++ target, and the closure
# walk reads LINK_LIBRARIES and INTERFACE_LINK_LIBRARIES alike; PUBLIC
# records each item once, in one place.
#
# `${SHEKYL_FFI_LINK_LIBS}` is here for the platform tail its consumers
# need (libm, pthread, the Windows socket and crypto libraries); the walk
# drops the `shekyl_ffi` archive at its head, the Rust side being the
# rlibs already in the link. `${EXTRA_LIBRARIES}` is what
# `shekyl_add_executable` would have added to the executable.
target_link_libraries(shekyld_remnant
  PUBLIC
    rpc
    cryptonote_core
    cncrypto
    common
    p2p
    cryptonote_protocol
    serialization
    ${EPEE_READLINE}
    version
    ${SHEKYL_FFI_LINK_LIBS}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES})

# The walk runs when the top-level directory finishes configuring: every
# target the closure names exists by then, whatever the subdirectory
# order. `cmake_language(DEFER)` is CMake 3.19+; the root requires 3.22.
cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
  CALL shekyl_rust_link_cxx_closure shekyld shekyld_remnant)

# Single-tracing-dispatcher gate: the binary must contain exactly one
# tracing-core GLOBAL_DISPATCH definition. Two copies means the link took
# a second copy of the Rust side — `libshekyl_ffi.a` from a C++ archive's
# interface beside the rlibs cargo linked — the split-image regression in
# which one image's tracing events are silently dropped
# (V3_WALLET_DECISION_LOG.md 2026-06-10). The closure walk drops that
# archive; this gate is what says it did. nm runs pre-strip, so the
# symbol is visible in both debug and release link products.
#
# The command hangs off `cargo-build_shekyld`, Corrosion's build target
# for the binary: a POST_BUILD step there runs after Corrosion's own
# copy of the binary into `RUNTIME_OUTPUT_DIRECTORY`, the file
# `SHEKYLD_STAGED_BINARY` (cmake/BuildRust.cmake) names. (`shekyld`
# itself is an IMPORTED target and takes no build steps; naming it
# through `$<TARGET_FILE>` here would close a dependency cycle, which is
# why the path is spelled out.) That target belongs to the top-level
# directory, where cmake/BuildRust.cmake is included, and
# `add_custom_command(TARGET)` must be called from the target's own
# directory — hence a function, called deferred in that directory.
#
# nm selection: cross builds emit non-host object formats (the depends
# Cross-Mac builds link Mach-O on a Linux host), which the host GNU nm
# rejects with "file format not recognized" — a false 0-count. Prefer
# the toolchain's own nm (CMAKE_NM; for depends Darwin this is the
# cctools <triple>-nm), fall back to PATH nm, and try candidates until
# one can actually parse the binary. A parse failure across all
# candidates fails the build loudly — the gate never silently skips, and
# a configure that finds no nm at all stops here (rule 47).
function(shekyl_shekyld_single_dispatcher_gate)
  # Resolve each candidate through find_program so bare tool names
  # (a user-set CMAKE_NM=llvm-nm, or a name-only _CMAKE_TOOLCHAIN_PREFIX
  # from a non-depends toolchain) are looked up on PATH instead of being
  # dropped by an absolute-path-only existence check. The depends Darwin
  # toolchain sets an absolute-path prefix, which find_program also
  # accepts verbatim.
  set(_shekyl_nm_candidates)
  foreach(_cand IN ITEMS "${CMAKE_NM}" "${_CMAKE_TOOLCHAIN_PREFIX}nm" "nm")
    if(_cand STREQUAL "")
      continue()
    endif()
    unset(_shekyl_nm_resolved CACHE)
    find_program(_shekyl_nm_resolved NAMES "${_cand}")
    if(_shekyl_nm_resolved)
      list(APPEND _shekyl_nm_candidates "${_shekyl_nm_resolved}")
    endif()
  endforeach()
  unset(_shekyl_nm_resolved CACHE)
  list(REMOVE_DUPLICATES _shekyl_nm_candidates)
  if(NOT _shekyl_nm_candidates)
    message(FATAL_ERROR "shekyld single-dispatcher gate: no nm tool found")
  endif()
  add_custom_command(TARGET cargo-build_shekyld POST_BUILD
    COMMAND sh -c "bin=\"$0\"; for nm_tool in \"$@\"; do if syms=$(\"$nm_tool\" \"$bin\" 2>/dev/null); then count=$(printf '%s\\n' \"$syms\" | grep GLOBAL_DISPATCH | grep -cv '[$]got' || true); if [ \"$count\" -ne 1 ]; then echo \"shekyld single-dispatcher gate FAILED ($nm_tool): $count tracing GLOBAL_DISPATCH definitions (expected 1)\" >&2; exit 1; fi; exit 0; fi; done; echo \"shekyld single-dispatcher gate FAILED: no nm tool could parse $bin (tried: $*)\" >&2; exit 1" "${SHEKYLD_STAGED_BINARY}" ${_shekyl_nm_candidates}
    VERBATIM
    COMMENT "Asserting single tracing GLOBAL_DISPATCH in shekyld")
endfunction()
if(UNIX)
  cmake_language(DEFER DIRECTORY "${CMAKE_SOURCE_DIR}"
    CALL shekyl_shekyld_single_dispatcher_gate)
endif()

# The binary, from where Corrosion staged it. `install(TARGETS)` does not
# take an IMPORTED target; the wallet binaries install the same way.
install(PROGRAMS "$<TARGET_FILE:shekyld>" DESTINATION bin)
