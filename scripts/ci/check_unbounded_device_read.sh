#!/usr/bin/env bash
#
# Copyright (c) 2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# Unbounded device-read gate.
#
# `std::fs::read` / `read_to_string` read to EOF. A character device under
# `/dev/` never reaches one, so "read the file" becomes "consume all memory",
# silently, until the machine notices.
#
# THIS HAS HAPPENED, AND THE TREE HAD ALREADY WARNED ABOUT IT.
# `rust/shekyl-cli/src/commands/signing.rs` names `/dev/urandom` explicitly as
# the hazard, states the failure mode ("read to EOF before any refusal --
# hanging or exhausting memory locally"), cites rule 82, and fixes it with
# `File::take(cap + 1)`. That warning was written, and then
# `fs::read("/dev/urandom")` was committed in another crate anyway: it grew to
# ~107 GB RSS on a 125 GB box, was SIGKILLed by the OOM killer (EXIT=137), took
# down the editor repeatedly, and cost four measurement sessions that were each
# misattributed to something else.
#
# A discipline that is documented at one site and violated at another is not a
# discipline. This is the enforcement.
#
# SCOPE, and what is deliberately NOT gated:
#
#   * GATED: `fs::read`/`read_to_string` on a `/dev/...` literal. Zero
#     exemptions in the tree today, so the gate starts clean.
#   * NOT GATED: non-literal paths (`fs::read(&path)`). That is the OTHER
#     hazard -- a caller-supplied path could be a FIFO or a multi-GB log -- and
#     it is real, but there are 71 such sites across 40 files, nearly all
#     reading known-bounded repo and config files. A gate needing 71 exemption
#     markers is noise, and a gate everyone marks around is worse than none.
#     For that class the discipline stays prose (`signing.rs`, rule 82): a
#     caller-supplied path wants `File::take(cap)`, not `fs::read`.
#   * NOT GATED: `/proc` literals. `/proc/self/statm` is seven numbers. Most
#     proc files are bounded; `/dev` character devices are not. Gating what is
#     actually unbounded keeps the signal honest.
#
# Escape hatch: a line carrying `device-read-allow` is exempt, forcing any
# exemption to be explicit and grep-able (the reward-arith / pending-post
# precedent).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Rule 47: the gate must assert its own subject exists. A missing `rg` must be
# a hard failure, never a silent pass over zero files searched.
if ! command -v rg >/dev/null 2>&1; then
  echo "FAIL: ripgrep (rg) is required by this gate and is not installed." >&2
  exit 1
fi

# The subject itself: if the search corpus is empty, the gate is vacuous.
CRATE_COUNT="$(rg --files rust/ --glob '*.rs' --glob '!target' --glob '!shekyl-oxide' 2>/dev/null | wc -l)"
if [ "$CRATE_COUNT" -lt 100 ]; then
  echo "FAIL: expected >=100 Rust sources to scan, found ${CRATE_COUNT}." >&2
  echo "      A gate that searches nothing passes for the wrong reason." >&2
  exit 1
fi

# Fail CLOSED on a scan error, and read the verdict UNPIPED (rule 46).
#
# `rg | grep ... || true` was wrong twice over: the `|| true` swallowed the
# whole pipeline's exit, and the pipeline's exit is grep's, not rg's — so an
# `rg` that errored (exit 2: a file it could not read) would leave HITS empty
# and the gate would certify a tree it never fully scanned. That is the
# fail-open shape this gate exists to be the opposite of.
#
# rg exit codes: 0 = match, 1 = no match (the clean pass), >=2 = error. Capture
# rg alone so its status is the verdict, then filter the allow-marker off the
# captured text — where a "nothing left" grep exit cannot mask a scan failure.
set +e
RAW="$(rg -n 'fs::read(_to_string)?\(\s*"/dev/' rust/ \
         --glob '*.rs' --glob '!target' --glob '!shekyl-oxide')"
RG_STATUS=$?
set -e
if [ "$RG_STATUS" -ge 2 ]; then
  echo "FAIL: ripgrep errored (exit ${RG_STATUS}) while scanning rust/." >&2
  echo "      The gate cannot certify a tree it could not fully read." >&2
  exit 1
fi

# The marker filter runs on captured text, not in the verdict pipe. grep exits 1
# when every line is filtered (the clean case), so `|| true` here catches THAT
# and only that — it can no longer hide an rg error, which already exited above.
HITS="$(printf '%s' "$RAW" | grep -v 'device-read-allow' || true)"

if [ -n "$HITS" ]; then
  echo "FAIL: unbounded read of a /dev character device." >&2
  echo >&2
  echo "$HITS" >&2
  echo >&2
  echo "  fs::read / read_to_string read to EOF, and a /dev character device" >&2
  echo "  never reaches one. Use a bounded read:" >&2
  echo >&2
  echo "      let mut f = std::fs::File::open(path)?;" >&2
  echo "      let mut buf = [0u8; N];" >&2
  echo "      f.read_exact(&mut buf)?;        // or File::take(cap)" >&2
  echo >&2
  echo "  See rust/shekyl-cli/src/commands/signing.rs, which documented this" >&2
  echo "  exact hazard -- naming /dev/urandom -- before it was committed anyway." >&2
  exit 1
fi

echo "device-read gate: no unbounded /dev reads (${CRATE_COUNT} sources scanned)"
