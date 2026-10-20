#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The depends host parser matches OS families with findstring. config.sub
# spells Android as linux-android, which contains linux, so a deleted
# Android triple used to select hosts/linux.mk. This script asserts the
# refusal fires for those triples and does not fire for a Linux triple.
#
# Exit 0 when the refusal behaves. Exit 1 when it does not.
# The make invocations are not piped: a pipe would hide make's status.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPENDS="$REPO_ROOT/contrib/depends"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

refuse() {
  local name="$1"
  shift
  make -C "$DEPENDS" -n "$@" >"$WORK/out" 2>"$WORK/err"
  local rc=$?
  if [ "$rc" -eq 0 ]; then
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
  echo "PASS: ${name}."
}

allow() {
  local name="$1"
  shift
  make -C "$DEPENDS" -n "$@" >"$WORK/out" 2>"$WORK/err"
  if grep -q 'Shekyl refuses to build for Android' "$WORK/err"; then
    echo "FAIL: ${name}: Linux host was refused as Android." >&2
    echo "--- stderr:" >&2
    cat "$WORK/err" >&2
    exit 1
  fi
  echo "PASS: ${name}."
}

refuse "aarch64-linux-android host" HOST=aarch64-linux-android
refuse "arm-linux-androideabi host" HOST=arm-linux-androideabi
refuse "android build machine" BUILD=aarch64-linux-android HOST=x86_64-pc-linux-gnu
allow "linux host" HOST=x86_64-pc-linux-gnu

echo "PASS: Android depends triples are refused and a Linux triple is not."
exit 0
