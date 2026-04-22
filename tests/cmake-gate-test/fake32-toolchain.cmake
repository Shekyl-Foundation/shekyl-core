# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# ---------------------------------------------------------------------------
# Fake 32-bit toolchain file — Chore #3, v3.1.0-alpha.5 (CI gate test).
#
# This file is NOT a real cross-compile toolchain; it does not reference any
# 32-bit compiler, sysroot, or library. Its only job is to convince CMake
# that CMAKE_SIZEOF_VOID_P == 4 BEFORE any find_package / add_subdirectory /
# compiler-feature detection runs, so the 64-bit-only gate at the top of
# the root CMakeLists.txt (Tripwire D) fires.
#
# The "reconstruct a real 32-bit toolchain and discard it after the gate
# test" alternative is explicitly rejected: it would require re-introducing
# 32-bit cross-compile machinery into the tree, which is exactly what
# Chore #3 retired.
#
# See tests/cmake-gate-test/run.sh for the assertion mechanics and
# .github/workflows/cmake-gate-test.yml for the CI wiring.
# ---------------------------------------------------------------------------

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR i686)

# Force CMake to observe a 32-bit void* without actually invoking any
# 32-bit compiler. CMake normally populates CMAKE_SIZEOF_VOID_P from
# compiler probes; pre-setting it in a toolchain file short-circuits the
# probe, which is what we want for a gate-ordering test (the gate MUST
# fire before any compiler/feature detection).
set(CMAKE_SIZEOF_VOID_P 4 CACHE INTERNAL "Forced 32-bit for gate test" FORCE)
set(CMAKE_C_SIZEOF_DATA_PTR 4 CACHE INTERNAL "Forced 32-bit for gate test" FORCE)
set(CMAKE_CXX_SIZEOF_DATA_PTR 4 CACHE INTERNAL "Forced 32-bit for gate test" FORCE)
