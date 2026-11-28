#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# The RandomX verifier touches the floating-point control register only
# in `fpu_rounding.rs`, through a fixed set of `asm!` blocks whose
# compiler promises are the ones that module's doc justifies
# (`docs/design/RANDOMX_ROUNDING_DECISION.md`). An undeclared or false
# promise does not reliably fail the hash pins, so this gate holds the
# shape by count:
#
# - exactly eight `asm!(` in the module: per architecture, the
#   four-operation block macro, the sqrt block, the once-per-run read
#   and the test-only write;
# - no `asm!(` anywhere else in the crate;
# - no `pure` and no `preserves_flags` option (both false: the
#   arithmetic raises exception flags);
# - no `_mm_setcsr(`, `_mm_getcsr(` or `fesetround(`: nothing sets the
#   mode for code outside a block.

set -euo pipefail

CRATE="rust/shekyl-pow-randomx/src"
FILE="${CRATE}/fpu_rounding.rs"
EXPECTED_ASM=8

if [[ ! -f "${FILE}" ]]; then
  echo "FATAL: ${FILE} not found"
  exit 1
fi

asm_count="$(grep -c 'asm!(' "${FILE}" || true)"
if [[ "${asm_count}" -ne "${EXPECTED_ASM}" ]]; then
  echo "FATAL: expected exactly ${EXPECTED_ASM} asm!( in ${FILE}; found ${asm_count}"
  exit 1
fi

elsewhere="$(grep -rln 'asm!(' "${CRATE}" | grep -v -x "${FILE}" || true)"
if [[ -n "${elsewhere}" ]]; then
  echo "FATAL: asm!( outside ${FILE}:"
  echo "${elsewhere}"
  exit 1
fi

options_count="$(grep -c 'options(' "${FILE}" || true)"
if [[ "${options_count}" -eq 0 ]]; then
  echo "FATAL: no options( in ${FILE}: the gate's subject is missing"
  exit 1
fi
false_promises="$(grep -n 'options(.*\(pure\|preserves_flags\)' "${FILE}" || true)"
if [[ -n "${false_promises}" ]]; then
  echo "FATAL: a block promises pure or preserves_flags, both false for the rounding blocks:"
  echo "${false_promises}"
  exit 1
fi

for forbidden in '_mm_setcsr(' '_mm_getcsr(' 'fesetround('; do
  hits="$(grep -rn -F "${forbidden}" "${CRATE}" || true)"
  if [[ -n "${hits}" ]]; then
    echo "FATAL: ${forbidden} is forbidden in ${CRATE}:"
    echo "${hits}"
    exit 1
  fi
done

echo "RandomX FPU rounding blocks grep clean: ${asm_count} asm!( in ${FILE}, none elsewhere, no false promise."
