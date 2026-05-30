#!/usr/bin/env bash
# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

set -euo pipefail

FILE="rust/shekyl-pow-randomx/src/fpu_rounding.rs"

if [[ ! -f "${FILE}" ]]; then
  echo "FATAL: ${FILE} not found"
  exit 1
fi

mm_setcsr_count="$(grep -c '_mm_setcsr(' "${FILE}" || true)"
asm_count="$(grep -c 'asm!(' "${FILE}" || true)"
fesetround_count="$(grep -c 'fesetround(' "${FILE}" || true)"

if [[ "${mm_setcsr_count}" -ne 1 ]]; then
  echo "FATAL: expected exactly one _mm_setcsr( in ${FILE}; found ${mm_setcsr_count}"
  exit 1
fi

if [[ "${asm_count}" -ne 2 ]]; then
  echo "FATAL: expected exactly two asm!( invocations in ${FILE}; found ${asm_count}"
  exit 1
fi

if [[ "${fesetround_count}" -ne 0 ]]; then
  echo "FATAL: fesetround( is forbidden in ${FILE}; found ${fesetround_count}"
  exit 1
fi

echo "RandomX FPU rounding primitive grep clean."
