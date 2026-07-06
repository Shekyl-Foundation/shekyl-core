#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Pending-post single-write-path enforcement — WI-3 gate 11
# (`docs/design/ARCHIVAL_BOND_WI3_DISPATCH.md` §5 gate 11, the R2-2
# enforcement half).
#
# Gate 10's crash-atomicity argument (torn seal-vs-reservation states are
# unrepresentable) RESTS on `.wallet.pending` having exactly one write path
# and one payload kind. Without enforcement that absence-of-a-second-writer
# is held by reviewer discipline alone — the armed-gate-with-no-trigger
# position the F41 `const _` guard and the F25 enumeration were built to
# escape. This script is the trigger: "grep pending-post persistence" must
# collapse to the one choke point, the way "grep token construction"
# collapses to the disclosure choke.
#
# The pinned-in-advance choke names (fixed in the design doc before the
# driver existed — the token sole-origin shape):
#
#   1. `WalletFile::save_pending_posts` (`rust/shekyl-engine-file/src/handle.rs`)
#      is the sole writer of `.wallet.pending` and the sole
#      `encode_payload(PayloadKind::PendingPostBlockPostcard, ..)` site.
#   2. The driver's locked `PendingPostStore` path — the production
#      `PendingSealStore` impl in
#      `rust/shekyl-engine-core/src/engine/pscan/start.rs` — is the sole
#      production caller of that writer.
#
# Escape hatch: a line carrying the marker `pending-post-write-allow` is
# exempt (for a genuinely-benign, reviewed use). The marker forces the
# exemption to be explicit and grep-able, per the reward-arith precedent.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Dependency precondition: rg is the load-bearing tool; a missing rg must be
# a loud failure, not a silently-green gate.
if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) not found — the gate cannot enforce its contract" >&2
  exit 1
fi

FAIL=0

HANDLE="rust/shekyl-engine-file/src/handle.rs"
PAYLOAD="rust/shekyl-engine-file/src/payload.rs"
SEAL_STORE="rust/shekyl-engine-core/src/engine/pscan/start.rs"

# Guardrail: if a pinned choke file moved or was renamed, fail loudly rather
# than let the invariants below pass vacuously on zero hits.
for f in "$HANDLE" "$PAYLOAD" "$SEAL_STORE"; do
  if [[ ! -f "$f" ]]; then
    echo "FAIL: $f not found — the pinned choke moved; update this gate, do not let it pass silently" >&2
    exit 1
  fi
done

# -- Invariant 1: sole encode site for the pending payload kind --------------
#
# `encode_payload(PayloadKind::PendingPostBlockPostcard, ..)` may appear only
# in the writer itself (handle.rs) and the payload codec's own in-file tests
# (payload.rs). A hit anywhere else is a second serialization path — exactly
# the split write gate 10's unrepresentability argument forbids.
ENCODE_PATTERN='encode_payload\(\s*PayloadKind::PendingPostBlockPostcard'
if ENCODE_STRAYS="$(rg -n "$ENCODE_PATTERN" rust/ --glob '*.rs' \
  | rg -v 'pending-post-write-allow' \
  | rg -v "^(${HANDLE}|${PAYLOAD}):")"; then
  echo "FAIL: PendingPostBlockPostcard encode site outside the pinned choke" >&2
  echo "  (sole encode site: WalletFile::save_pending_posts in $HANDLE)" >&2
  echo "$ENCODE_STRAYS" >&2
  FAIL=1
fi

# Positive control (guards the guard): the choke encode site must still
# exist under this exact spelling — a rename must fail here, not silently
# de-arm invariant 1.
if ! rg -q "$ENCODE_PATTERN" "$HANDLE"; then
  echo "FAIL: positive control — no PendingPostBlockPostcard encode site in $HANDLE" >&2
  echo "  (if save_pending_posts moved or the payload kind was renamed, update this gate)" >&2
  FAIL=1
fi

# -- Invariant 2: sole production caller of the writer -----------------------
#
# `.save_pending_posts(` may appear only in handle.rs (the definition and the
# file layer's own tests) and in the driver's production `PendingSealStore`
# impl (start.rs). A caller anywhere else is a second write path around the
# locked `PendingPostStore` — the writer-discipline breach gate 11 exists to
# catch at commit time, not at audit time.
CALLER_PATTERN='\.save_pending_posts\('
if CALLER_STRAYS="$(rg -n "$CALLER_PATTERN" rust/ --glob '*.rs' \
  | rg -v 'pending-post-write-allow' \
  | rg -v "^(${HANDLE}|${SEAL_STORE}):")"; then
  echo "FAIL: save_pending_posts caller outside the locked PendingPostStore path" >&2
  echo "  (sole production caller: the PendingSealStore impl in $SEAL_STORE)" >&2
  echo "$CALLER_STRAYS" >&2
  FAIL=1
fi

# Positive control: the production delegation must exist in start.rs.
if ! rg -q "$CALLER_PATTERN" "$SEAL_STORE"; then
  echo "FAIL: positive control — no save_pending_posts delegation in $SEAL_STORE" >&2
  echo "  (if the production PendingSealStore impl moved, update this gate)" >&2
  FAIL=1
fi

# -- Invariant 3: no raw write to the pending file ----------------------------
#
# The seal commits through `atomic_write_file(&self.pending_path, ..)` inside
# save_pending_posts — exactly once. Any other write against `pending_path`
# (a second atomic_write_file, an fs::write, a File::create) is a split write.
ATOMIC_HITS="$(rg -c 'atomic_write_file\(&self\.pending_path' "$HANDLE" || true)"
if [[ "${ATOMIC_HITS:-0}" -ne 1 ]]; then
  echo "FAIL: expected exactly one atomic_write_file(&self.pending_path) in $HANDLE, found ${ATOMIC_HITS:-0}" >&2
  FAIL=1
fi
RAW_WRITE_PATTERN='(fs::write|File::create|OpenOptions)[^\n]*pending_path'
if RAW_WRITES="$(rg -n "$RAW_WRITE_PATTERN" rust/ --glob '*.rs' \
  | rg -v 'pending-post-write-allow')"; then
  echo "FAIL: raw write against pending_path (bypasses the crash-atomic seal)" >&2
  echo "$RAW_WRITES" >&2
  FAIL=1
fi

exit "$FAIL"
