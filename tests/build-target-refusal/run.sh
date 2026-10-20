#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The depends host parser matches OS families with findstring. config.sub
# spells Android as linux-android, which contains linux, so a deleted
# Android triple used to select hosts/linux.mk. This script asserts the
# refusal fires for those triples, and that a Linux triple is classified
# as linux.
#
# The goal is show-host-os. Its recipe is one echo. The refusal is a
# parse-time $(error), so it runs before any recipe. make -n is the wrong
# probe: a recipe line that starts with + still runs, and the default goal
# is install. check-sources is the wrong probe too: a zero exit there says
# the tarball cache was inspected, not which family was selected.
#
# Exit 0 when the refusal behaves. Exit 1 when it does not.
# The make invocations are not piped: a pipe would hide make's status.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPENDS="$REPO_ROOT/contrib/depends"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

classify() {
  make -C "$DEPENDS" --no-print-directory show-host-os "$@" >"$WORK/out" 2>"$WORK/err"
  classify_rc=$?
}

refuse() {
  local name="$1"
  shift
  classify "$@"
  if [ "$classify_rc" -eq 0 ]; then
    echo "FAIL: ${name}: make exited 0." >&2
    echo "--- stderr:" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  if ! grep -q 'Shekyl refuses to build for Android' "$WORK/err"; then
    echo "FAIL: ${name}: refusal missing from stderr." >&2
    echo "--- stderr:" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  if [ -s "$WORK/out" ]; then
    echo "FAIL: ${name}: a recipe printed output. The refusal runs before any recipe." >&2
    echo "--- stdout:" >&2
    cat "$WORK/out" >&2
    exit 1
  fi
  echo "PASS: ${name}."
}

allow() {
  local name="$1"
  shift
  classify "$@"
  if [ "$classify_rc" -ne 0 ]; then
    echo "FAIL: ${name}: make exited ${classify_rc}." >&2
    echo "--- stderr:" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  if [ -s "$WORK/err" ]; then
    echo "FAIL: ${name}: make wrote to stderr." >&2
    echo "--- stderr:" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  local got
  got="$(cat "$WORK/out")"
  if [ "$got" != "linux" ]; then
    echo "FAIL: ${name}: host family is '${got}', expected linux." >&2
    exit 1
  fi
  echo "PASS: ${name}."
}

refuse "aarch64-linux-android host" HOST=aarch64-linux-android
refuse "arm-linux-androideabi host" HOST=arm-linux-androideabi
refuse "android build machine" BUILD=aarch64-linux-android HOST=x86_64-pc-linux-gnu
allow "linux host" HOST=x86_64-pc-linux-gnu

echo "PASS: Android depends triples are refused and a Linux triple is classified as linux."
exit 0
