# Copyright (c) 2014-2019, The Monero Project
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
# 
# Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers


# This is broken up into two parts: first we check for miniupnp, compile it if we can't
# find it, and thereafter we check for libunbound, and compile it if we can't find it.
# We always compile if we are building statically to reduce static dependency issues...
# ...except for FreeBSD, because FreeBSD is a special case that doesn't play well with
# others.

find_package(Miniupnpc REQUIRED)

message(STATUS "Using in-tree miniupnpc")
set(UPNPC_NO_INSTALL TRUE CACHE BOOL "Disable miniupnp installation" FORCE)
set(UPNPC_BUILD_SHARED OFF CACHE BOOL "Disable building shared library" FORCE)
add_subdirectory(miniupnp/miniupnpc)
set_property(TARGET libminiupnpc-static PROPERTY FOLDER "external")
set_property(TARGET libminiupnpc-static PROPERTY POSITION_INDEPENDENT_CODE ON)
if(MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(NOT MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()
if(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -D_NETBSD_SOURCE")
endif()

set(UPNP_LIBRARIES "libminiupnpc-static" PARENT_SCOPE)

find_package(Unbound)

if(NOT UNBOUND_INCLUDE_DIR)
  if(MSVC)
    message(STATUS "libunbound not found -- DNS utilities will be stubbed out (MSVC wallet-core build)")
    set(UNBOUND_INCLUDE_DIR "" PARENT_SCOPE)
    set(UNBOUND_LIBRARIES "" PARENT_SCOPE)
    set(UNBOUND_AVAILABLE OFF PARENT_SCOPE)
  else()
    die("Could not find libunbound")
  endif()
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound library")
    set(UNBOUND_AVAILABLE ON PARENT_SCOPE)
  else()
    die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()

add_subdirectory(db_drivers)
add_subdirectory(qrcodegen)
add_subdirectory(randomx EXCLUDE_FROM_ALL)

# RandomX v2 (Shekyl-Foundation fork) — out-of-tree build.
#
# Both external/randomx (v1.2.1) and external/randomx-v2 (v2.0.1)
# declare project(RandomX) and add_library(randomx ...). CMake target
# names and most CACHE variables are global within a single configure
# run, so add_subdirectory(randomx-v2) after add_subdirectory(randomx)
# above would produce a duplicate-target error. ExternalProject_Add
# builds the v2 fork in an isolated configure pass under
# ${CMAKE_BINARY_DIR}/external/randomx-v2-build/, then exposes the
# resulting static library plus its include directory through a
# Shekyl-side IMPORTED target shekyl_randomx_v2.
#
# Patching the v2 fork's CMakeLists.txt is prohibited per
# 10-shekyl-first.mdc (never contort upstream); see
# docs/design/RANDOMX_V2_PHASE1_PLAN.md §2 for the full
# target-collision analysis and disposition.
#
# No C++ component links shekyl_randomx_v2 in Phase 1. First
# consumer is Phase 2's cross-check tests in
# rust/shekyl-pow-randomx/, which compare a pure-Rust verifier's
# per-hash output against this canonical C implementation
# byte-for-byte.
if(BUILD_RANDOMX_V2_MINER_LIB)
  # Phase 1 fail-fast disposition for multi-config generators
  # (Copilot finding C-6, PR #54). On multi-config generators (MSVC's
  # "Visual Studio" generator, Xcode, "Ninja Multi-Config"), the
  # single config-agnostic INSTALL_DIR + single IMPORTED_LOCATION
  # used below would silently produce wrong-configuration artifacts
  # (Debug ↔ Release in the same build tree have the second install
  # step overwrite the first, and IMPORTED_LOCATION resolves to
  # whichever was built last regardless of which configuration the
  # consumer is linking from). Phase 1 has no consumer of
  # shekyl_randomx_v2, so the bug is latent in production; but for
  # developers who do flip the option ON under a multi-config
  # generator, the right behaviour is to refuse rather than to
  # silently produce a partially-correct artifact. The per-CONFIG
  # split lands in Phase 2 alongside the first real consumer
  # (rust/shekyl-pow-randomx/ cross-check tests); the disposition
  # is recorded in docs/FOLLOWUPS.md under "RandomX v2
  # ExternalProject_Add: per-CONFIG install path and
  # IMPORTED_LOCATION_<CONFIG> for multi-config generators".
  if(CMAKE_CONFIGURATION_TYPES)
    message(FATAL_ERROR
      "RandomX v2 (BUILD_RANDOMX_V2_MINER_LIB=ON) is not supported "
      "on multi-config generators in Phase 1. The single-config "
      "install path collides Debug ↔ Release in the same build "
      "tree. Use a single-config generator instead: -G Ninja or "
      "-G \"Unix Makefiles\" with an explicit -DCMAKE_BUILD_TYPE. "
      "Per-CONFIG wiring lands in Phase 2 alongside the first "
      "consumer. See docs/FOLLOWUPS.md and the §10 D2 disposition "
      "in docs/design/RANDOMX_V2_PHASE1_PLAN.md.")
  endif()

  include(ExternalProject)

  set(RANDOMX_V2_SRC     "${CMAKE_CURRENT_SOURCE_DIR}/randomx-v2")
  set(RANDOMX_V2_INSTALL "${CMAKE_CURRENT_BINARY_DIR}/randomx-v2-install")
  set(RANDOMX_V2_LIB
      "${RANDOMX_V2_INSTALL}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}randomx${CMAKE_STATIC_LIBRARY_SUFFIX}")

  # Base CMAKE_ARGS forwarded into the sub-build unconditionally.
  set(_RANDOMX_V2_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
    -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  )

  # Cross-compile / platform-pinning settings forwarded when the parent
  # configure defined them. Each variable is only appended when set, so
  # the sub-build doesn't see spurious -DVAR= overrides that would clear
  # its own toolchain defaults. The list tracks the standard CMake
  # cross-build knobs and matches the subset the Shekyl daemon's
  # production CI (Guix + the cross-build matrices in
  # .github/workflows/depends.yml) relies on.
  #
  # List-valued variables (CMAKE_OSX_ARCHITECTURES,
  # CMAKE_FIND_ROOT_PATH, …) contain semicolons in CMake's internal
  # representation. ExternalProject_Add's CMAKE_ARGS is itself a
  # list, so an unescaped semicolon inside a forwarded value would
  # split into multiple list elements and the sub-build would
  # receive a malformed -DVAR= argument followed by a stray bare
  # token (Copilot finding C-5, PR #54). The robust fix is to
  # declare a non-semicolon LIST_SEPARATOR on ExternalProject_Add
  # (LIST_SEPARATOR "|" below) and substitute the chosen separator
  # for ';' in each forwarded value before appending. ExternalProject
  # reverses the substitution before invoking the sub-build's
  # cmake, so the sub-build sees the original semicolons.
  foreach(_var IN ITEMS
      CMAKE_TOOLCHAIN_FILE
      CMAKE_SYSROOT
      CMAKE_FIND_ROOT_PATH
      CMAKE_OSX_ARCHITECTURES
      CMAKE_OSX_DEPLOYMENT_TARGET
      CMAKE_OSX_SYSROOT
      CMAKE_ANDROID_NDK
      CMAKE_ANDROID_ARCH_ABI
      CMAKE_SYSTEM_NAME
      CMAKE_SYSTEM_PROCESSOR
      CMAKE_C_COMPILER_LAUNCHER
      CMAKE_CXX_COMPILER_LAUNCHER)
    if(DEFINED ${_var})
      string(REPLACE ";" "|" _randomx_v2_fwd_val "${${_var}}")
      list(APPEND _RANDOMX_V2_CMAKE_ARGS
        "-D${_var}=${_randomx_v2_fwd_val}")
      unset(_randomx_v2_fwd_val)
    endif()
  endforeach()

  ExternalProject_Add(randomx_v2_external
    SOURCE_DIR        "${RANDOMX_V2_SRC}"
    PREFIX            "${CMAKE_CURRENT_BINARY_DIR}/randomx-v2-build"
    INSTALL_DIR       "${RANDOMX_V2_INSTALL}"
    LIST_SEPARATOR    "|"
    CMAKE_ARGS        ${_RANDOMX_V2_CMAKE_ARGS}
    BUILD_BYPRODUCTS  "${RANDOMX_V2_LIB}"
    UPDATE_DISCONNECTED TRUE
  )

  file(MAKE_DIRECTORY "${RANDOMX_V2_INSTALL}/include")
  add_library(shekyl_randomx_v2 STATIC IMPORTED GLOBAL)
  set_target_properties(shekyl_randomx_v2 PROPERTIES
    IMPORTED_LOCATION             "${RANDOMX_V2_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${RANDOMX_V2_INSTALL}/include"
  )
  add_dependencies(shekyl_randomx_v2 randomx_v2_external)

  message(STATUS
    "RandomX v2: building Shekyl-Foundation fork (pin aaafe71, v2.0.1) "
    "out-of-tree; target shekyl_randomx_v2 is available. No Shekyl C++ "
    "consumer links it in Phase 1; first consumer is Phase 2 cross-check "
    "tests against the canonical v2 implementation.")
endif()
