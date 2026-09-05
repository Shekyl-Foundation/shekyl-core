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

MAIN="src/daemon/main.cpp"
ARG="arg_carrier_development"
rc=0

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
DECL="src/daemon/command_line_args.h"
if ! grep -q "arg_descriptor<bool> ${ARG}" "${DECL}"; then
  echo "FAIL: '${ARG}' declaration not found in ${DECL}."
  exit 1
fi
if ! grep -A4 "arg_descriptor<bool> ${ARG}" "${DECL}" | grep -q ", false"; then
  echo "FAIL: '${ARG}' does not default to false."
  echo "  A default-on carrier arms cover traffic in every shipped build."
  rc=1
fi

if [ "${rc}" -eq 0 ]; then
  echo "carrier flag: hidden-only registration and default-off, both confirmed"
fi
exit "${rc}"
