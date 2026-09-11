#!/usr/bin/env bash
#
# Copyright (c) 2025-2026, The Shekyl Foundation
# All rights reserved.
# BSD-3-Clause
#
# The carrier opt-in is a DEVELOPMENT switch, not a product one
# (COVER_TRAFFIC_RESTORATION.md §3.1). Armed, a node pays a sustained
# ~42 GB/month and its traffic profile stops matching an unarmed node's.
#
# Visibility in `--help` IS the difference between the two, and it is one
# `add_arg` argument away: moving the registration from `hidden_options` to
# `visible_options` turns a measurement tool into an operator setting, changes
# nothing else, and breaks no test. That is what this gate pins.
set -uo pipefail

# Every path below is repo-relative, so anchor the working directory the way
# the sibling gates do. Without this the greps run against whatever directory
# the caller happened to be in, every file read fails, and the subject check
# reports "the flag was renamed or removed" — a diagnosis that would have a
# reader retire a live gate.
# Resolved from the SCRIPT, not from the caller's cwd. `git rev-parse
# --show-toplevel` was the first attempt and is what two siblings use, but it
# answers for wherever the caller happens to be standing — run this from
# outside any repository and it fails with "not a git repository" instead of
# checking anything. Deriving from `BASH_SOURCE` works from any directory and
# needs no git, which is what `check_network_uniformity.sh` already does.
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 2
cd "${here}/../.." || exit 2

MAIN="src/daemon/main.cpp"
DECL="src/daemon/command_line_args.h"
ARG="arg_carrier_development"
rc=0

# A MISSING FILE IS NOT A MISSING FLAG, and the two need different answers:
# one means the tree moved under the gate, the other means the subject was
# renamed or deleted. `grep` returns 2 for the first and 1 for the second and
# this used to collapse both into the second.
for f in "${MAIN}" "${DECL}"; do
  if [ ! -r "${f}" ]; then
    echo "FAIL: ${f} is missing or unreadable."
    echo "  The gate could not read its subject at all — this is a moved or"
    echo "  renamed FILE, not a renamed flag. Fix the path, do not retire."
    exit 2
  fi
done

# Rule 47: assert the SUBJECT before asserting anything about it. A renamed or
# deleted flag must fail loudly here rather than let every check below pass on
# zero matches.
if ! grep -q "daemon_args::${ARG}" "${MAIN}"; then
  echo "FAIL: '${ARG}' does not appear in ${MAIN}."
  echo "  The flag was renamed or removed. Retire this gate deliberately —"
  echo "  do not leave it passing against a subject that no longer exists."
  exit 1
fi

hidden=$(grep -c "add_arg(hidden_options, daemon_args::${ARG})" "${MAIN}" || true)
if [ "${hidden}" -ne 1 ]; then
  echo "FAIL: expected exactly 1 registration in hidden_options, found ${hidden}."
  rc=1
fi

elsewhere=$(grep -cE "add_arg\((visible_options|core_settings|all_options), daemon_args::${ARG}\)" "${MAIN}" || true)
if [ "${elsewhere}" -ne 0 ]; then
  echo "FAIL: '${ARG}' is registered in a VISIBLE option group (${elsewhere} site(s))."
  echo "  It would then appear in --help, which makes it an operator setting."
  echo "  §3.1 ruled it a development switch; if that ruling changed, change"
  echo "  the ruling first."
  rc=1
fi

# The severe regression: armed by default in every shipped build.
if ! grep -q "arg_descriptor<bool> ${ARG}" "${DECL}"; then
  echo "FAIL: '${ARG}' declaration not found in ${DECL}."
  exit 1
fi

# ONE PROCESS, NO PIPE. This is a gate verdict, and rule 46 keeps those out of
# pipes: the earlier `grep -A4 ... | grep -q ...` put the answer behind a
# consumer that exits early, so under `pipefail` a SIGPIPE on the producer
# could report a failure that did not happen. It reported correctly at this
# window size — the hazard was latent, not live — which is precisely why it
# would have survived review and bitten later.
if ! awk -v decl="arg_descriptor<bool> ${ARG}" '
      index($0, decl) { window = 5 }
      window && /, false/ { found = 1 }
      window { window-- }
      END { exit(found ? 0 : 1) }
    ' "${DECL}"; then
  echo "FAIL: '${ARG}' does not default to false."
  echo "  A default-on carrier arms cover traffic in every shipped build."
  rc=1
fi

if [ "${rc}" -eq 0 ]; then
  echo "carrier flag: hidden-only registration and default-off, both confirmed"
fi
exit "${rc}"
