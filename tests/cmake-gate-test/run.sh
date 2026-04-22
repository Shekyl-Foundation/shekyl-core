#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Exercises the 64-bit-only CMake gate (Tripwire D, Chore #3 v3.1.0-alpha.5)
# at the top of the root CMakeLists.txt against a fake 32-bit toolchain.
# The gate MUST fire at CMAKE_SIZEOF_VOID_P detection, BEFORE any
# find_package / include / add_subdirectory runs.
#
# Exit-code convention (stated explicitly to forestall the single most
# common bug in this class of script):
#   - exit 0  → gate fired correctly (EXPECTED; CI job passes).
#   - exit 1  → gate is broken (REGRESSION; CI job fails).
#
# Matching gates (defense-in-depth; all four must be defeated to ship a
# 32-bit build):
#   - rust/shekyl-crypto-pq/src/lib.rs   (Tripwire A, primary)
#   - rust/shekyl-ffi/src/lib.rs         (Tripwire B, structural-not-observable)
#   - rust/shekyl-tx-builder/src/lib.rs  (Tripwire C, direct fips204 consumer)
#   - CMakeLists.txt                     (Tripwire D, exercised here)
#
# See docs/CHANGELOG.md entry "Retired 32-bit build targets" for the
# underlying PQC constant-time argument (KyberSlash 2024, libgcc helpers,
# variable-latency u64 multiply on 32-bit ARM cores).

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLCHAIN_FILE="$SCRIPT_DIR/fake32-toolchain.cmake"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

cd "$REPO_ROOT"

# Capture stdout and stderr separately: the gate message must land in
# stderr (CMake's FATAL_ERROR stream), and find_package chatter must
# appear in NEITHER stream (if it does, cmake progressed past the gate,
# which is the regression this test catches).
cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
  >"$BUILD_DIR/stdout.log" 2>"$BUILD_DIR/stderr.log"
rc=$?

# Assertion 1: cmake exited non-zero (gate fired).
if [ "$rc" -eq 0 ]; then
  echo "FAIL: cmake configure succeeded on a fake 32-bit toolchain; gate did not fire." >&2
  echo "--- stdout:" >&2; cat "$BUILD_DIR/stdout.log" >&2
  echo "--- stderr:" >&2; cat "$BUILD_DIR/stderr.log" >&2
  exit 1
fi

# Assertion 2: gate-specific message present in stderr. Both tokens
# required so an unrelated failure (missing compiler, malformed
# toolchain, etc.) does not satisfy the test.
if ! grep -q 'Shekyl refuses to configure on non-64-bit targets' "$BUILD_DIR/stderr.log"; then
  echo "FAIL: gate message 'Shekyl refuses to configure on non-64-bit targets' missing from stderr." >&2
  echo "--- stderr:" >&2; cat "$BUILD_DIR/stderr.log" >&2
  exit 1
fi
if ! grep -q 'KyberSlash' "$BUILD_DIR/stderr.log"; then
  echo "FAIL: KyberSlash citation missing from gate message; cannot confirm this was the correct gate firing." >&2
  echo "--- stderr:" >&2; cat "$BUILD_DIR/stderr.log" >&2
  exit 1
fi

# Assertion 3: gate fired BEFORE find_package / compiler probes. Any
# "Looking for" / "Found " / "Could NOT find" line in either stream
# means cmake progressed past the gate into probe territory, which is
# the regression this test catches (e.g. a PR that moves the gate below
# find_package(Boost)).
if grep -qE '^-- (Looking for|Found |Could NOT find)' "$BUILD_DIR/stdout.log" "$BUILD_DIR/stderr.log"; then
  echo "FAIL: cmake progressed past the gate into find_package / compiler probes." >&2
  echo "--- stdout:" >&2; cat "$BUILD_DIR/stdout.log" >&2
  echo "--- stderr:" >&2; cat "$BUILD_DIR/stderr.log" >&2
  exit 1
fi

echo "PASS: gate fired correctly on fake 32-bit toolchain."
exit 0
