#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Armed #[ignore]d regtest_e2e gates against a live shekyld.
#
# Invoked from .github/workflows/build.yml after the daemon is built. The
# script locates the repo from its own path, so SHEKYLD_BIN resolves inside
# the job container (where github.workspace is the host path, not this tree).
#
# A gate belongs on ARMED only once it has been OBSERVED FAILING for the
# reason it exists. `cargo test --exact` on a moved name exits 0 with
# "0 passed", so a rename would otherwise turn a gate off silently.
#
# Enumeration is `cargo test -- --list --ignored`, the runner's own answer.
# A grep over source counts `#[ignore]` written in doc comments too
# (21 lines, 17 attributes) and would silently disagree with the runner.
#
# The undecided baseline is the load-bearing ratchet. Adding a new
# `#[ignore]`d test without arming it raises the count and fails here;
# deleting one lowers it and also fails. e2e_fcmp_spend_accepted_by_daemon
# is 76-99 s (measured 2026-09-07, four runs); it lives here because this
# job already builds shekyld, not because a second unused membership said so.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

export SHEKYLD_BIN="${SHEKYLD_BIN:-$REPO_ROOT/build/bin/shekyld}"
test -x "$SHEKYLD_BIN" || {
  echo "FATAL: no shekyld at $SHEKYLD_BIN" >&2
  exit 1
}

cd rust

ignored="$(mktemp)"
gate_log="$(mktemp)"
trap 'rm -f "$ignored" "$gate_log"' EXIT

# Redirected, not piped: a pipeline's status is the last command's, so
# `| tee` would swallow cargo's verdict.
cargo test -p shekyl-engine-core --lib -- --list --ignored >"$ignored" 2>&1

# `grep -c` exits 1 on zero matches, which `set -e` would turn into a
# bare abort with no message — and zero matches is exactly the case this
# must report, not die on (rule 47: assert your own subject).
# Checked FIRST: if the enumeration is empty every name below looks
# renamed, and the gate would blame five tests for one broken command.
regtest_ignored=$(grep -c '^engine::regtest_e2e::.*: test$' "$ignored" || true)
[ "${regtest_ignored:-0}" -gt 0 ] || {
  echo "FATAL: enumerated no regtest_e2e ignored tests — the module moved or the enumeration broke" >&2
  exit 1
}

# Declared once. The loop iterates it and the undecided count is derived
# from it, so the two cannot drift.
ARMED=(
  engine::regtest_e2e::restricted_listener_applies_request_caps_through_the_ffi_bridge
  engine::regtest_e2e::ported_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::ported_p2p_console_commands_answer_on_the_in_process_arm
  engine::regtest_e2e::native_handlers_apply_their_own_request_caps
  engine::regtest_e2e::e2e_fcmp_spend_accepted_by_daemon
)

for a in "${ARMED[@]}"; do
  grep -qx "$a: test" "$ignored" || {
    echo "FATAL: armed gate '$a' names no ignored test — it was renamed or deleted, and this gate is now off" >&2
    exit 1
  }
done

# THE DARK SET MAY NOT GROW SILENTLY. `regtest_e2e` carries 17 `#[ignore]`
# attributes; ARMED names 5, leaving 12 on which nobody has decided.
# Adding a new `#[ignore]`d test without arming it or recording why raises
# this count and fails here. Lowering it (by arming a gate, which requires
# observing it red first) is a conscious edit of this baseline.
UNDECIDED_BASELINE=12
undecided=$((regtest_ignored - ${#ARMED[@]}))
if [ "$undecided" -ne "$UNDECIDED_BASELINE" ]; then
  echo "FATAL: $undecided regtest_e2e gates are neither armed nor decided, baseline says $UNDECIDED_BASELINE." >&2
  echo "A new #[ignore]d test must be armed (observe it red first) or its baseline moved deliberately." >&2
  exit 1
fi

for t in "${ARMED[@]}"; do
  set +e
  cargo test -p shekyl-engine-core --lib "$t" \
    -- --ignored --exact --nocapture >"$gate_log" 2>&1
  status=$?
  set -e
  cat "$gate_log"
  if [ "$status" -ne 0 ]; then
    echo "FATAL: $t failed" >&2
    exit "$status"
  fi
  grep -qE '^test result: ok\. 1 passed' "$gate_log" || {
    echo "FATAL: $t selected no test — the filter or the name moved" >&2
    exit 1
  }
done
