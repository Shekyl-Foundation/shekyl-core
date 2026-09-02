#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# check_engine_decomposition.sh — structural anti-drift guard for the
# `Engine` composition root (docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md).
#
# The decomposition doc's "How you'll know it worked" criteria are
# aspirations until something enforces them. Monolith re-formation is a
# drift-over-time failure: no single PR looks like "building a god-object",
# it adds one field, one generic, one 200-line method. Review does not catch
# accretion; the seven traits accreted DESPITE the Stage 1-2 modularization
# intent. This is the tripwire that makes the doc's criteria mechanical,
# in the same structural-enforcement family as check_zeroize.sh and
# check_segment_freeze_sites.sh.
#
# Ratchet semantics live in scripts/ci/engine_decomposition_ratchet.conf and
# are bidirectional: regression fails (a value grew past its ceiling) AND
# slack fails (a value shrank well below its ceiling without the baseline
# being tightened). A relaxation is therefore always a visible diff in the
# .conf — that diff is the explicit-decision gate.
#
# Exit 0 = clean. Non-zero = at least one of:
#   - Engine<...> grew past PARAMS_MAX generics
#   - Engine grew past FIELDS_CEILING top-level fields
#   - Engine pub inherent methods grew past METHODS_CEILING
#   - Engine pub inherent methods dropped >METHODS_BAND below the ceiling
#   - a baselined file regressed above its ceiling
#   - a baselined file dropped >BAND below its ceiling (tighten it)
#   - a non-baselined engine/*.rs crossed NEW_FILE_CAP (new god-file)
#   - a FILE baseline names a file that no longer exists (stale entry)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENGINE_DIR="${REPO_ROOT}/rust/shekyl-engine-core/src/engine"
MOD_RS="${ENGINE_DIR}/mod.rs"
CONF="${REPO_ROOT}/scripts/ci/engine_decomposition_ratchet.conf"

[ -f "${CONF}" ]   || { echo "FATAL: ratchet conf missing at ${CONF}"; exit 2; }
[ -f "${MOD_RS}" ] || { echo "FATAL: engine mod.rs missing at ${MOD_RS}"; exit 2; }

fail=0
note() { echo "  - $1"; }

# --- parse the conf ----------------------------------------------------------
PARAMS_MAX=0; FIELDS_CEILING=0; NEW_FILE_CAP=0; BAND=0
METHODS_CEILING=0; METHODS_BAND=0
declare -A FILE_CEIL; declare -A EXCLUDE
while read -r key a b _rest; do
  case "${key}" in
    ''|\#*)          continue ;;
    PARAMS_MAX)      PARAMS_MAX="${a}" ;;
    FIELDS_CEILING)  FIELDS_CEILING="${a}" ;;
    NEW_FILE_CAP)    NEW_FILE_CAP="${a}" ;;
    BAND)            BAND="${a}" ;;
    METHODS_CEILING) METHODS_CEILING="${a}" ;;
    METHODS_BAND)    METHODS_BAND="${a}" ;;
    FILE)            FILE_CEIL["${a}"]="${b}" ;;
    EXCLUDE)         EXCLUDE["${a}"]=1 ;;
    *)               echo "FATAL: unknown conf key '${key}'"; exit 2 ;;
  esac
done < "${CONF}"

# --- 1. Engine<...> generic parameter count (frozen) -------------------------
# Count top-level generics by counting bracket-depth-1 ':' (each param is
# `Ident: Bound`; '::' path separators and default type args sit at depth >=2).
# Robust to the multi-line P default and to a trailing comma.
params="$(awk '
  /pub struct Engine</ { on=1 }
  on {
    n=split($0, ch, "")
    for (i=1;i<=n;i++) {
      c=ch[i]
      if (c=="<") d++
      else if (c==">") { d--; if (d==0) { print cnt; exit } }
      else if (c==":" && d==1) {
        # ignore the second colon of a "::" path separator
        if (ch[i-1]!=":" && ch[i+1]!=":") cnt++
      }
    }
  }' "${MOD_RS}")"
if [ -z "${params}" ]; then
  echo "FATAL: could not parse 'pub struct Engine<...>' header in mod.rs"; exit 2
fi
if [ "${params}" -gt "${PARAMS_MAX}" ]; then
  echo "FAIL: Engine has ${params} generic parameters (max ${PARAMS_MAX})."
  note "New domains become owned services/handles, not a new Engine<...> generic (§1)."
  fail=1
fi

# --- 2. Engine top-level field count -----------------------------------------
fields="$(awk '
  /^pub struct Engine</ { inbody=1; next }
  inbody && /^}/        { exit }
  inbody && /^    [a-z_][a-z0-9_]*[[:space:]]*:/ { c++ }
  END { print c+0 }' "${MOD_RS}")"
if [ "${fields}" -gt "${FIELDS_CEILING}" ]; then
  echo "FAIL: Engine has ${fields} top-level fields (ceiling ${FIELDS_CEILING})."
  note "Group into identity / caps / runtime sub-structs (§5) rather than widening the root."
  fail=1
fi

# --- 2b. Engine pub inherent method count ------------------------------------
# Subject assertion (rule 47): the helper and a positive count must exist.
# Absence of signal is first evidence the subject is absent — do not treat
# a missing helper or a zero as "no methods, therefore under ceiling."
COUNT_PY="${REPO_ROOT}/scripts/ci/count_engine_pub_methods.py"
if [ ! -f "${COUNT_PY}" ]; then
  echo "FATAL: method-count helper missing at ${COUNT_PY}"
  note "METHODS_CEILING has no subject without scripts/ci/count_engine_pub_methods.py."
  exit 2
fi
if ! python3 "${COUNT_PY}" --self-test >/dev/null; then
  echo "FATAL: ${COUNT_PY} --self-test failed."
  note "METHODS_CEILING cannot freeze a counter that mis-attributes StakeFacade / where Engine<...> impls."
  exit 2
fi
if [ "${METHODS_CEILING}" -eq 0 ] || [ "${METHODS_BAND}" -eq 0 ]; then
  echo "FATAL: METHODS_CEILING/METHODS_BAND missing or zero in ${CONF}"
  note "The inherent-API freeze is not optional; restore both keys."
  exit 2
fi
methods="$(python3 "${COUNT_PY}" "${ENGINE_DIR}")"
if ! [[ "${methods}" =~ ^[0-9]+$ ]]; then
  echo "FATAL: ${COUNT_PY} did not print an integer (got: ${methods})"
  exit 2
fi
if [ "${methods}" -eq 0 ]; then
  echo "FATAL: method-count helper reported 0 pub inherent Engine methods."
  note "Absence of signal is evidence the counter (or Engine impls) disappeared."
  fail=1
elif [ "${methods}" -gt "${METHODS_CEILING}" ]; then
  echo "FAIL: Engine has ${methods} pub inherent methods (ceiling ${METHODS_CEILING})."
  note "New staking / fee / daemon-transport behavior lands on a façade, not Engine::."
  fail=1
elif [ "${methods}" -lt "$(( METHODS_CEILING - METHODS_BAND ))" ]; then
  echo "FAIL: Engine has ${methods} pub inherent methods, >${METHODS_BAND} under ceiling ${METHODS_CEILING} — tighten it."
  note "Lower METHODS_CEILING in engine_decomposition_ratchet.conf to lock the win in."
  fail=1
fi

# --- 3. per-file line-count ratchet + new-file cap ---------------------------
while IFS= read -r path; do
  rel="${path#"${ENGINE_DIR}/"}"
  [ -n "${EXCLUDE[$rel]:-}" ] && continue
  lines="$(wc -l < "${path}")"
  if [ -n "${FILE_CEIL[$rel]:-}" ]; then
    ceil="${FILE_CEIL[$rel]}"
    if [ "${lines}" -gt "${ceil}" ]; then
      echo "FAIL: ${rel} is ${lines} lines (ceiling ${ceil}) — regression."
      note "Split by workflow (§2) instead of growing the god-file."
      fail=1
    elif [ "${lines}" -lt "$(( ceil - BAND ))" ]; then
      echo "FAIL: ${rel} is ${lines} lines, >${BAND} under ceiling ${ceil} — tighten it."
      note "Lower its FILE line in engine_decomposition_ratchet.conf to lock the win in."
      fail=1
    fi
  elif [ "${lines}" -gt "${NEW_FILE_CAP}" ]; then
    echo "FAIL: ${rel} is ${lines} lines (>${NEW_FILE_CAP}) and is not baselined — new god-file."
    note "Carve it, or add a reviewed FILE baseline in engine_decomposition_ratchet.conf."
    fail=1
  fi
# Every engine subdirectory, not a hand-kept list. The old exclusion of
# traits/ and pscan/ was written when keys were bare basenames and
# traits/refresh.rs would have collided with refresh.rs; keys are now
# ENGINE_DIR-relative paths (`merge.rs`, `transfer/engine.rs`,
# `pscan/scan_step.rs`), so a nested file that shares a basename is simply a
# distinct key and a top-level file's key still equals its bare basename. With
# the collision gone the exclusion only bought silence: `pscan/` held four
# baselines that were never measured, so their ceilings enforced nothing in
# either direction. A `-name '*.rs'` sweep of ENGINE_DIR keeps the scanned set
# equal to the tree, so a new subdirectory is baselined-or-capped the day it
# appears rather than the day someone remembers to add an arm here.
done < <(find "${ENGINE_DIR}" -name '*.rs' | sort)

# --- 4. stale baseline entries -----------------------------------------------
# Keys are ENGINE_DIR-relative, so this resolves both top-level (`merge.rs`) and
# nested (`transfer/engine.rs`) baselines against their real on-disk location.
for key in "${!FILE_CEIL[@]}"; do
  [ -f "${ENGINE_DIR}/${key}" ] || {
    echo "FAIL: ratchet baselines ${key} but engine/${key} no longer exists — stale entry."
    note "Remove its FILE line from engine_decomposition_ratchet.conf."
    fail=1
  }
done

# --- 5. Transfer workflow ownership pin --------------------------------------
# docs/design/ENGINE_COMPOSITION_DECOMPOSITION.md §"Transfer workflow ownership"
#
# Multi-step send lives under engine/transfer/ as LocalPendingTx. Re-inflating
# those orchestration methods onto Engine / lifecycle / top-level monofiles is
# the failure mode this tripwire catches. Pure grep (no ripgrep) so this script
# stays dependency-free for CI.
#
# Invariants (semantic, not filename-brittle):
#   - engine/transfer/ exists with a module root (mod.rs)
#   - `pub struct LocalPendingTx` is defined *somewhere* under transfer/
#     (may move between transfer/*.rs on later file-splits)
#   - local_pending_tx.rs is a re-export shim from transfer, not a second
#     implementor (no local struct; `pub use` path mentions transfer + type)
TRANSFER_DIR="${ENGINE_DIR}/transfer"
TRANSFER_MOD_RS="${TRANSFER_DIR}/mod.rs"
SHIM_RS="${ENGINE_DIR}/local_pending_tx.rs"

if [ ! -d "${TRANSFER_DIR}" ] || [ ! -f "${TRANSFER_MOD_RS}" ]; then
  echo "FAIL: engine/transfer/ workflow tree is missing (expected transfer/mod.rs)."
  note "Transfer ownership is engine/transfer/ — restore it, do not move send logic onto Engine."
  fail=1
else
  # Definition may live in transfer/engine.rs today or another transfer/*.rs later.
  # Use find + per-file grep (same style as the method-def loop below) so we do
  # not depend on recursive-grep option ordering (`--include` must precede paths
  # on some greps, and a misordered flag is easy to treat as a path).
  lpt_def_hits=""
  while IFS= read -r transfer_rs; do
    if hits="$(grep -nE '^[[:space:]]*pub[[:space:]]+struct[[:space:]]+LocalPendingTx\b' "${transfer_rs}" 2>/dev/null)"; then
      while IFS= read -r hit; do
        lpt_def_hits+="${transfer_rs}:${hit}"$'\n'
      done <<<"${hits}"
    fi
  done < <(find "${TRANSFER_DIR}" -name '*.rs' | sort)
  if [ -z "${lpt_def_hits}" ]; then
    echo "FAIL: LocalPendingTx is not defined under engine/transfer/."
    note "Production transfer implementor must live under engine/transfer/ (any .rs in that tree)."
    fail=1
  fi
fi

if [ ! -f "${SHIM_RS}" ]; then
  echo "FAIL: engine/local_pending_tx.rs shim is missing."
  note "Keep the re-export shim so historical import paths keep working."
  fail=1
else
  # Reject a second implementor in the shim (struct body / type alias as home).
  if grep -nE '^[[:space:]]*(pub([[:space:]]*\([^)]*\))?[[:space:]]+)?(struct|type)[[:space:]]+LocalPendingTx\b' "${SHIM_RS}" >/dev/null; then
    echo "FAIL: local_pending_tx.rs defines LocalPendingTx (struct/type) — must re-export only."
    note "Shim must stay a re-export path, not a second implementor."
    fail=1
  fi
  # Accept equivalent re-export forms:
  #   pub use super::transfer::LocalPendingTx;
  #   pub use crate::engine::transfer::LocalPendingTx;
  #   pub use super::transfer::{LocalPendingTx, …};
  # Require both `transfer` and `LocalPendingTx` on a `pub use` line.
  if ! grep -qE '^[[:space:]]*pub[[:space:]]+use[[:space:]]+[^;]*\btransfer\b[^;]*\bLocalPendingTx\b' "${SHIM_RS}"; then
    echo "FAIL: local_pending_tx.rs does not re-export LocalPendingTx from transfer/."
    note "Shim must pub-use LocalPendingTx via a path that includes transfer (super::transfer::… or crate::…::transfer::…)."
    fail=1
  fi
fi

# Method *definitions* that belong only under transfer/. Mentions in comments
# or call sites elsewhere are fine; a second `fn build_select_sync` body is not.
TRANSFER_OWNED_FNS=(
  build_select_sync
  reanchor_consumer_held
  finalize_submit_accept
  finalize_submit_terminal
  finalize_submit_retryable
  finalize_submit_ambiguous
  finalize_submit_already_in_chain
  commit_built_sync
  signal_mempool_evicted_sync
)
while IFS= read -r path; do
  case "${path}" in
    "${ENGINE_DIR}/transfer"/*) continue ;;
  esac
  for sym in "${TRANSFER_OWNED_FNS[@]}"; do
    # Match inherent/method defs only (optional pub / pub(crate) / pub(super) / async).
    # Pattern anchors at line start so doc comments naming the symbol do not trip.
    if hits="$(grep -nE "^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+${sym}[[:space:]]*\(" "${path}" 2>/dev/null)"; then
      echo "FAIL: transfer orchestration method '${sym}' is defined outside engine/transfer/:"
      echo "${hits}" | while IFS= read -r hit; do
        echo "  ${path}:${hit}"
      done
      note "Move the body into engine/transfer/ (or delete the duplicate). See ENGINE_COMPOSITION_DECOMPOSITION.md §Transfer workflow ownership."
      fail=1
    fi
  done
done < <(find "${ENGINE_DIR}" -name '*.rs' | sort)

if [ "${fail}" -ne 0 ]; then
  echo "check_engine_decomposition: FAILED"
  exit 1
fi
echo "check_engine_decomposition: clean (params=${params}, fields=${fields}, methods=${methods})"
