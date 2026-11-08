# Copyright (c) 2025-2026, The Shekyl Foundation
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
#

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# 3.22: raised from 3.5 for Corrosion (DAEMON_CONFIG_CUTOVER.md DC-Q23),
# which went with the last C++ archive in the daemon's link; the floor
# stays, since every policy is now at 3.22's NEW behaviour.
cmake_minimum_required(VERSION 3.22)
message(STATUS "CMake version ${CMAKE_VERSION}")

# Shekyl ships nothing on Android. Called twice because the two ways a
# configure becomes Android are visible at different moments:
#   - `-DCMAKE_SYSTEM_NAME=Android` and `-DANDROID=TRUE` are set before
#     project(), and project() would otherwise enter Platform/Android
#     and search for an NDK.
#   - A toolchain file is read during project(). Its ANDROID or system
#     name is visible only once project() returns, which is also when
#     an installed NDK would let configure succeed.
# Reopen only when a release decision names an Android product and a CI
# host that builds it. That decision deletes this macro and both calls
# in the same change as the host recipe. See docs/CHANGELOG.md, "the
# Android target is removed".
macro(shekyl_refuse_android_target)
  if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR
      "Shekyl refuses to configure for Android "
      "(CMAKE_SYSTEM_NAME='${CMAKE_SYSTEM_NAME}', ANDROID='${ANDROID}'). "
      "Shekyl ships nothing on Android. "
      "See docs/CHANGELOG.md, \"the Android target is removed\".")
  endif()
endmacro()
shekyl_refuse_android_target()

project(shekyl)

shekyl_refuse_android_target()

# ---------------------------------------------------------------------------
# 64-bit-only gate — Chore #3, v3.1.0-alpha.5 (Tripwire D).
#
# Matching Rust gates (defense-in-depth; all three must be defeated to ship a
# 32-bit build):
#   - rust/shekyl-crypto-pq/src/lib.rs   (Tripwire A, primary ML-KEM/ML-DSA consumer)
#   - rust/shekyl-tx-builder/src/lib.rs  (Tripwire C, direct fips204 consumer)
#
# This gate MUST stay above any find_package / add_subdirectory / include()
# so no probe can pre-empt it. The CI test at
# tests/cmake-gate-test/run.sh (wired from
# .github/workflows/cmake-gate-test.yml) exercises exactly that ordering
# invariant against a fake 32-bit toolchain on every PR to dev — a PR that
# moves this block below find_package(...) will fail that test.
#
# See docs/CHANGELOG.md "Retired 32-bit build targets" and
# docs/audit_trail/ "Chore #3" before touching any of these gates.
# ---------------------------------------------------------------------------
# Two checks, OR'd together, because `CMAKE_SIZEOF_VOID_P` alone is not
# sufficient as a gate predicate:
#   (a) CMAKE_SIZEOF_VOID_P is populated by the compiler probe that
#       `project(shekyl)` above just triggered. On a real 32-bit target
#       with a real 32-bit cross-compiler, the probe reports 4, so this
#       half of the predicate fires.
#   (b) CMAKE_SYSTEM_PROCESSOR is populated by the toolchain file (or
#       defaults to the host). A toolchain file that declares a 32-bit
#       CMAKE_SYSTEM_PROCESSOR — `i[3-6]86`, `x86` bare, any
#       `armv[567].*` variant (covers `armv7`, `armv7l`, `armv7-a`,
#       `armv7a`, `armv7hf`, `armv7ve`, `armv6kz`, `armv5te`, etc.; all
#       32-bit ARM profiles use `armv[5-7]` — 64-bit uses `aarch64` /
#       `arm64`), `armhf`, `armel`, `arm` bare, `mips(el)?`,
#       `powerpc`/`ppc` (32-bit; `powerpc64(le)?` deliberately excluded
#       by the `$` anchor) — is unambiguously targeting a 32-bit
#       architecture, and this half of the predicate fires regardless
#       of what the compiler probe reported. This matters operationally
#       (a gate-test CI job on a 64-bit host forcing
#       CMAKE_SYSTEM_PROCESSOR via a fake toolchain must fire without
#       needing a real 32-bit sysroot; tests/cmake-gate-test/ exercises
#       exactly this path) and defensively (a future toolchain bug or
#       misconfigured cross environment that silently reports
#       `CMAKE_SIZEOF_VOID_P=8` on a 32-bit target would slip past a
#       size-only gate).
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3-6]86|x86|armv[567].*|armhf|armel|arm|mips|mipsel|powerpc|ppc)$")
  message(FATAL_ERROR
    "Shekyl refuses to configure on non-64-bit targets "
    "(CMAKE_SIZEOF_VOID_P=${CMAKE_SIZEOF_VOID_P}, "
    "CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}). "
    "ML-KEM-768 (fips203) and ML-DSA-65 (fips204) constant-time "
    "guarantees are stated against native 64-bit arithmetic; on 32-bit "
    "targets the compiler emits libgcc helpers (__muldi3, __udivdi3, "
    "__ashldi3) with no constant-time guarantee, plus variable-latency "
    "u64 multiply on common 32-bit ARM cores. This is the threat model "
    "exploited by KyberSlash (Bernstein et al., 2024) against fielded "
    "CT implementations. The hybrid X25519+ML-KEM construction does not "
    "rescue the ML-KEM secret once it leaks via timing. Matching gates "
    "live in rust/shekyl-crypto-pq/src/lib.rs and "
    "rust/shekyl-tx-builder/src/lib.rs. See docs/CHANGELOG.md entry "
    "'Retired 32-bit build targets' before attempting to revert this gate.")
endif()

# What this project builds. There is no first-party C or C++: the three
# binaries are one cargo invocation (cmake/BuildRust.cmake), and the only
# C++ CMake can configure is the vendored RandomX v2 reference
# (external/randomx-v2), opt-in below. The C toolchain is still read:
# BuildRust hands CMAKE_C_COMPILER, CMAKE_AR and CMAKE_C_FLAGS to cargo
# whenever it names a target triple (every cross build, and native macOS
# and FreeBSD), as CC_/AR_/CFLAGS_<triple> for the C that crates compile
# and as -C link-arg for the link. The flags below exist for that.
include(CheckCCompilerFlag)

function (dir_populated_ignoring_git dir out_var)
  file(GLOB _dpi_entries LIST_DIRECTORIES true "${dir}/*")
  set(_dpi_populated FALSE)
  foreach(_dpi_e IN LISTS _dpi_entries)
    get_filename_component(_dpi_bn "${_dpi_e}" NAME)
    if(NOT _dpi_bn STREQUAL ".git")
      set(_dpi_populated TRUE)
      break()
    endif()
  endforeach()
  set(${out_var} ${_dpi_populated} PARENT_SCOPE)
endfunction ()

function (add_c_flag_if_supported flag var)
  # Prepending the flag with -Werror will only add the flag,
  # if it doesn't result in generation of a warning of using a flag unknown to the compiler.
  set(TMP "-Werror ${flag}")
  string(REGEX REPLACE "[- ]" "_" supported ${TMP}_c)
  check_c_compiler_flag(${TMP} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  message(STATUS "Setting default build type: ${CMAKE_BUILD_TYPE}")
endif()

# ARCH defines the target architecture, either by an explicit identifier or
# one of the following two keywords. By default, ARCH a value of 'native':
# target arch = host arch, binary is not portable. When ARCH is set to the
# string 'default', no -march arg is passed, which creates a binary that is
# portable across processors in the same family as host processor.  In cases
# when ARCH is not set to an explicit identifier, cmake's builtin is used
# to identify the target architecture, to direct logic in this cmake script.
# Since ARCH is a cached variable, it will not be set on first cmake invocation.
if (NOT ARCH_ID)
if (NOT ARCH OR ARCH STREQUAL "" OR ARCH STREQUAL "native" OR ARCH STREQUAL "default")
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "")
    set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif()
  set(ARCH_ID "${CMAKE_SYSTEM_PROCESSOR}")
else()
  set(ARCH_ID "${ARCH}")
endif()
endif()
string(TOLOWER "${ARCH_ID}" ARCH_ID)
string(TOLOWER "${ARCH_ID}" ARM_ID)

if (ARM_ID STREQUAL "aarch64" OR ARM_ID STREQUAL "arm64" OR ARM_ID STREQUAL "armv8-a")
  set(ARM 1)
  set(ARM8 1)
  set(ARCH "armv8-a")
endif()

if(ARCH_ID STREQUAL "ppc64le")
  set(PPC64LE 1)
  set(PPC64   0)
  set(PPC     0)
endif()

if(ARCH_ID STREQUAL "powerpc64" OR ARCH_ID STREQUAL "ppc64")
  set(PPC64LE 0)
  set(PPC64   1)
  set(PPC     0)
endif()

if(ARCH_ID STREQUAL "powerpc" OR ARCH_ID STREQUAL "ppc")
  set(PPC64LE 0)
  set(PPC64   0)
  set(PPC     1)
endif()

if(ARCH_ID STREQUAL "s390x")
  set(S390X 1)
endif()

if(ARCH_ID STREQUAL "riscv64")
set(RISCV   1)
set(RISCV64 1)
endif()

if(ARCH_ID STREQUAL "riscv32")
set(RISCV   1)
set(RISCV32 1)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "kOpenBSD.*|OpenBSD.*")
  set(OPENBSD TRUE)
endif()

function(set_default_arch)
  if (OPENBSD)
    set(ARCH default)
  else()
    set(ARCH native)
  endif()

  set(ARCH ${ARCH} CACHE STRING "CPU to build for: -march value or 'default' to not pass -march at all")
endfunction()

if (NOT (MSVC OR ARCH))
  set_default_arch()
endif()

set(PIC_FLAG "-fPIC")

if (UNIX AND NOT APPLE)
  add_c_flag_if_supported(-pthread CMAKE_C_FLAGS)
endif()

if(NOT MSVC)
  message(STATUS "Building on ${CMAKE_SYSTEM_PROCESSOR} for ${ARCH}")
  if(ARCH STREQUAL "default")
    set(ARCH_FLAG "")
  elseif(PPC64LE)
    set(ARCH_FLAG "-mcpu=power8")
  elseif(PPC64)
    set(ARCH_FLAG "-mcpu=970")
  elseif(PPC)
    set(ARCH_FLAG "-mcpu=7400")
  else()
    set(ARCH_FLAG "-march=${ARCH}")
    if(ARCH STREQUAL "native")
      check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
      if (NOT CC_SUPPORTS_MARCH_NATIVE)
        check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
        if (CC_SUPPORTS_MTUNE_NATIVE)
          set(ARCH_FLAG "-mtune=${ARCH}")
        else()
          set(ARCH_FLAG "")
        endif()
      endif()
    endif()
  endif()

  option(NO_AES "Explicitly disable AES support" ${NO_AES})

  if(NO_AES)
    message(STATUS "AES support explicitly disabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_AES")
  elseif(NOT ARM AND NOT PPC64LE AND NOT PPC64 AND NOT PPC AND NOT S390X AND NOT RISCV)
    message(STATUS "AES support enabled")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
  elseif(PPC64LE OR PPC64 OR PPC)
    message(STATUS "AES support not available on POWER")
  elseif(S390X)
    message(STATUS "AES support not available on s390x")
  elseif(RISCV)
    message(STATUS "AES support not available on RISC-V")
  elseif(ARM8)
    check_c_compiler_flag("-march=${ARCH}+crypto" ARCH_PLUS_CRYPTO)
    if(ARCH_PLUS_CRYPTO)
      message(STATUS "Crypto extensions enabled for ARMv8")
      set(ARCH_FLAG "-march=${ARCH}+crypto")
    else()
      message(STATUS "Crypto extensions unavailable on your ARMv8 device")
    endif()
  else()
    message(STATUS "AES support disabled")
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAG}")

  if(MINGW)
    set(MINGW_FLAG "${MINGW_FLAG} -DWIN32_LEAN_AND_MEAN")
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")

  if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT OPENBSD)
    set(C_SECURITY_FLAGS "${C_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
  endif()

  # warnings (duplicated in WARNINGS for non-MSVC; kept here for SECURITY_FLAGS aggregation)
  add_c_flag_if_supported(-Wformat C_SECURITY_FLAGS)
  add_c_flag_if_supported(-Wformat-security C_SECURITY_FLAGS)

  # protection against identifier-based attacks and stack reuse
  add_c_flag_if_supported(-fno-extended-identifiers C_SECURITY_FLAGS)
  add_c_flag_if_supported(-fstack-reuse=none C_SECURITY_FLAGS)

  # ARM64 branch protection (BTI / pointer authentication)
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
      add_c_flag_if_supported("-mbranch-protection=bti" C_SECURITY_FLAGS)
    else()
      add_c_flag_if_supported("-mbranch-protection=standard" C_SECURITY_FLAGS)
    endif()
  endif()

  # -fstack-protector
  if (NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
    add_c_flag_if_supported(-fstack-protector C_SECURITY_FLAGS)
    add_c_flag_if_supported(-fstack-protector-strong C_SECURITY_FLAGS)
  endif()

  # New in GCC 8.2 -- CET is x86 Linux only; macOS lacks cet.h
  if (NOT APPLE AND NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
    add_c_flag_if_supported(-fcf-protection=full C_SECURITY_FLAGS)
  endif()
  if (NOT WIN32 AND NOT OPENBSD)
    add_c_flag_if_supported(-fstack-clash-protection C_SECURITY_FLAGS)
  endif()

  # Removed in GCC 9.1 (or before ?), but still accepted, so spams the output
  if (NOT (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1))
    add_c_flag_if_supported(-mmitigate-rop C_SECURITY_FLAGS)
  endif()

  # Per-function/data sections allow the linker to strip unreferenced code,
  # reducing binary size (inspired by Monero #9898 author's findings:
  # -ffunction-sections + --gc-sections shrank Docker images by ~14 MiB).
  if(NOT MINGW)
    add_c_flag_if_supported(-ffunction-sections C_SECURITY_FLAGS)
    add_c_flag_if_supported(-fdata-sections C_SECURITY_FLAGS)
  endif()

  # Warnings, that when ignored are so severe, that they can segfault or even UB any application.
  # Treat them as errors.
  add_c_flag_if_supported(  -Werror=switch      C_SECURITY_FLAGS)
  add_c_flag_if_supported(  -Werror=return-type C_SECURITY_FLAGS)

  message(STATUS "Using C security hardening flags: ${C_SECURITY_FLAGS}")

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${PIC_FLAG} ${C_SECURITY_FLAGS}")

  if(ARM)
    message(STATUS "Setting FPU Flags for ARM Processors")

    # Cortex-A53 errata workarounds, for the C the crates compile.
    check_c_compiler_flag(-mfix-cortex-a53-835769 CC_ACCEPTS_MFIX_CORTEX_A53_835769)
    check_c_compiler_flag(-mfix-cortex-a53-843419 CC_ACCEPTS_MFIX_CORTEX_A53_843419)
    if(CC_ACCEPTS_MFIX_CORTEX_A53_835769)
      message(STATUS "Enabling Cortex-A53 workaround 835769")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-835769")
    endif()
    if(CC_ACCEPTS_MFIX_CORTEX_A53_843419)
      message(STATUS "Enabling Cortex-A53 workaround 843419")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfix-cortex-a53-843419")
    endif()
  endif()
endif()

# RandomX v2 C reference library (Shekyl-Foundation fork) miner-library
# build toggle. Production PoW is the Rust light-cache verifier
# (`shekyl-pow-randomx`); this option builds `librandomx.a`
# out-of-tree for the differential harness and Hole-1 miner KATs only.
# OFF (default): the v2 C build is not configured; daemon and other
# components are unaffected and byte-identical to a no-flag build.
# ON: external/CMakeLists.txt runs ExternalProject_Add against the
# pinned external/randomx-v2 submodule and exposes the
# shekyl_randomx_v2 IMPORTED static-library target.
# See docs/design/RANDOMX_V2_PHASE1_PLAN.md §§2.3, 3.3, 3.4.

option(BUILD_RANDOMX_V2_MINER_LIB
  "Build RandomX v2 C reference library out-of-tree (differential harness / Hole-1 only; default OFF). Production PoW is the Rust verifier."
  OFF)

# Phase 2g Rust/C differential test harness build toggle.
# OFF (default): no harness build configured; existing CMake builds
# are byte-identical to a no-flag build (preserves the Phase 1 §4.1
# daemon-byte-equivalence contract).
# ON: implies BUILD_RANDOMX_V2_MINER_LIB=ON (auto-flipped below with
# a CMake WARNING per the §5.4.2 disposition in
# RANDOMX_V2_PHASE2G_PLAN.md). The implication is unidirectional:
# the harness needs the C reference's static library; the miner-lib
# build itself does not need the harness.
#
# The harness's Cargo build runs out-of-band from CMake (per
# §5.4.3); CMake's role is exclusively building the C reference's
# librandomx.a + headers for randomx-v2-sys (R1-D2) to link
# against. No new CMake target is added in 2g.
#
# See docs/design/RANDOMX_V2_PHASE2G_PLAN.md §§3.5 (R1-D3 close),
# 5.4.1, 5.4.2, 5.4.3, and §6.6 T12 (per-PR auto-flip assertion).
option(BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS
  "Build the Phase 2g Rust/C differential test harness (implies BUILD_RANDOMX_V2_MINER_LIB=ON). Default OFF; preserves the daemon-build byte-equivalence contract when not set."
  OFF)

# §5.4.2 implication mechanism. Per R1-D3 option (c) close, enabling
# BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON unconditionally requires
# BUILD_RANDOMX_V2_MINER_LIB=ON. When the user passes
# -DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON without also passing
# -DBUILD_RANDOMX_V2_MINER_LIB=ON (or with an explicit
# -DBUILD_RANDOMX_V2_MINER_LIB=OFF), CMake auto-flips the latter to
# ON with a WARNING so the auto-flip is observable in configure logs.
# T12 (§6.6, per-PR) asserts the warning text + the resulting cache
# value mechanically.
#
# CACHE BOOL ... FORCE updates the cache value rather than just the
# current-configure-pass variable; the auto-flip persists across
# subsequent configures of the same build tree (the cached ON value
# satisfies the if-condition below on re-configure, suppressing
# repeated WARNINGs). Passing -DBUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=OFF
# on a subsequent configure leaves the cached MINER_LIB=ON in place;
# the user explicitly sets MINER_LIB=OFF to undo (deliberate
# non-sticky-reversal: the implication is one-shot at flip time,
# not a permanent coupling).
if(BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS AND NOT BUILD_RANDOMX_V2_MINER_LIB)
  message(WARNING
    "BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON requires "
    "BUILD_RANDOMX_V2_MINER_LIB=ON (the harness consumes the C "
    "reference's static library via the randomx-v2-sys sub-crate). "
    "Auto-flipping BUILD_RANDOMX_V2_MINER_LIB to ON. Pass "
    "-DBUILD_RANDOMX_V2_MINER_LIB=ON explicitly to silence this "
    "warning. See docs/design/RANDOMX_V2_PHASE2G_PLAN.md §5.4.2 "
    "and R1-D3 for the disposition.")
  set(BUILD_RANDOMX_V2_MINER_LIB ON CACHE BOOL
    "Auto-set by BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS=ON per Phase 2g §5.4.2."
    FORCE)
endif()

if(BUILD_RANDOMX_V2_MINER_LIB)
  set(_RANDOMX_V2_SRC "${CMAKE_SOURCE_DIR}/external/randomx-v2")
  if(NOT EXISTS "${_RANDOMX_V2_SRC}" OR NOT IS_DIRECTORY "${_RANDOMX_V2_SRC}")
    message(FATAL_ERROR
      "external/randomx-v2 is missing. The C reference library is opt-in "
      "(BUILD_RANDOMX_V2_MINER_LIB / BUILD_RANDOMX_V2_DIFFERENTIAL_HARNESS). "
      "Initialize with:\n  git submodule update --init external/randomx-v2\n"
      "Default daemon CMake does not need this tree.")
  endif()
  dir_populated_ignoring_git("${_RANDOMX_V2_SRC}" _RANDOMX_V2_POPULATED)
  if(NOT _RANDOMX_V2_POPULATED)
    message(FATAL_ERROR
      "external/randomx-v2 is an empty directory (not initialized). "
      "Initialize with:\n  git submodule update --init external/randomx-v2\n"
      "Worktrees inherit gitlinks but not submodule working trees. "
      "Never --exclude this path. MANUAL_SUBMODULES=1 is an escape hatch, "
      "not the happy path, and does not skip this populate check.")
  endif()
endif()

add_subdirectory(external)

include(Version) # before BuildRust: the binaries carry the version string
include(BuildRust) # the three binaries, one cargo invocation
