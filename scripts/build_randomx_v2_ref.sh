#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Builds the fork-pinned RandomX v2 C reference (external/randomx-v2) with
# that project's own build, and stages it in the layout randomx-v2-sys
# links against: <install>/lib/librandomx.a and <install>/include/randomx.h.
#
# The C reference is never part of a shipped binary: shekyld's PoW is the
# Rust verifier (RANDOMX_V2_RUST.md §2; scripts/ci/check_randomx_symbol_isolation.sh).
# It serves the differential harness (shekyl-randomx-differential, through
# randomx-v2-sys) and the out-of-process miner reference's KATs.
#
# One definition on purpose: the differential workflow's x86_64 and aarch64
# lanes (through .github/actions/build-randomx-v2-ref) and a developer run
# the same commands, so no lane measures a differently built oracle.
#
#   scripts/build_randomx_v2_ref.sh [<build dir> <install dir>]
#
# Without arguments, RANDOMX_V2_BUILD_DIR and RANDOMX_V2_INSTALL_DIR name the
# two directories. Then, for the harness:
#
#   export RANDOMX_V2_INSTALL_DIR=<install dir>
#   cd rust && cargo test -p shekyl-randomx-differential
#
# Requires a C/C++ compiler, CMake and Ninja (external/randomx-v2's own
# build), and the submodule: git submodule update --init external/randomx-v2

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build_dir=${1:-${RANDOMX_V2_BUILD_DIR:-}}
install_dir=${2:-${RANDOMX_V2_INSTALL_DIR:-}}
if [ -z "$build_dir" ] || [ -z "$install_dir" ]; then
  echo "usage: $0 <build dir> <install dir>  (or set RANDOMX_V2_BUILD_DIR and RANDOMX_V2_INSTALL_DIR)" >&2
  exit 2
fi
src="$root/external/randomx-v2"
if [ ! -f "$src/CMakeLists.txt" ]; then
  echo "$src is not populated: git submodule update --init external/randomx-v2" >&2
  exit 1
fi

mkdir -p "$install_dir/lib" "$install_dir/include"
cmake -G Ninja \
  -S "$src" \
  -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cmake --build "$build_dir" --target randomx
cp "$build_dir/librandomx.a" "$install_dir/lib/"
cp "$src/src/randomx.h" "$install_dir/include/"
echo "RandomX v2 reference staged in $install_dir"
