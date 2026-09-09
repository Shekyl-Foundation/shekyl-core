#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Every `#[ignore]` carries its reason in the attribute itself.
#
# The 2026-09-08 ignored-test disposition walk found the tree's ignored
# tests fall into decided classes (armed live-daemon gates, fixture
# regenerators, external-binary lanes, slow KATs with a named cadence) —
# and five bare `#[ignore]`s whose reasons lived only in doc comments or
# nowhere. A reason string is the disposition made machine-visible where
# `cargo test -- --list --ignored` readers and grep both find it; a bare
# attribute is an undecided dark test the next reader must re-derive.
#
# `#[ignore = "reason"]` cannot match the bare pattern, so this gate only
# fires on attributes with no reason at all.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Rule 47: assert the subject exists before asserting its property. If no
# reasoned #[ignore = ...] attribute matches anywhere, the convention (or
# this gate's pattern) has moved and the "no bare ignores" pass below
# would be vacuous.
reasoned=$(rg -c --no-messages '^\s*#\[ignore\s*=' --type rust rust/ | awk -F: '{s+=$NF} END {print s+0}')
if [ "${reasoned:-0}" -eq 0 ]; then
  echo "FATAL: found no '#[ignore = \"reason\"]' attributes at all — the pattern or the tree moved; this gate is blind" >&2
  exit 1
fi

# `^\s*#` cannot match doc-comment mentions (those start with `///`), and
# the closing `]` right after `ignore` cannot match the reasoned form.
bare=$(rg -n --no-messages '^\s*#\[ignore\]' --type rust rust/ || true)
if [ -n "$bare" ]; then
  echo "FATAL: bare #[ignore] without a reason string — record the disposition in the attribute:" >&2
  echo "$bare" >&2
  exit 1
fi

echo "OK: ${reasoned} reasoned #[ignore] attributes, zero bare"
