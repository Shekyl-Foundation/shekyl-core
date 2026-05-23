# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Reproducer for the Phase 2d single-opcode reference vectors
# committed alongside this Makefile. Builds `gen` against the v2
# RandomX fork at the same pin used by phase2c/, then exposes
# `vectors` to regenerate T9-T15.
#
# Phase 2d's vectors drive `randomx::BytecodeMachine` directly per
# single instruction (not the full `randomx_vm` pipeline), so the
# fork-object list is strictly narrower than phase2c/'s — only the
# bytecode-machine + instructions + reciprocal substrate is linked.
# No argon2, no AES, no JIT, no dataset/cache substrate.
#
# This Makefile is host-portable for little-endian C++17 toolchains
# (no architecture-specific JIT pinning since the only SIMD surface
# is intrin_portable.h's __m128d primitives, which are SSE2-baseline
# on x86_64 and remain bit-identical across hosts at softfloat-default
# semantics).

FORK_ROOT := ../../../../../../../external/randomx-v2
FORK_SRC  := $(FORK_ROOT)/src

CXX      ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(FORK_SRC) -DRANDOMX_DEFAULT_FLAG_V2=128

# Minimal v2 substrate: bytecode-machine compile/execute, the
# `Instruction` getters/setters, the portable instruction helpers
# (mulh / smulh / signExtend2sCompl), and the reciprocal cache
# (IMUL_RCP compile path calls `randomx_reciprocal`).
FORK_OBJS := \
	$(FORK_SRC)/allocator.cpp \
	$(FORK_SRC)/bytecode_machine.cpp \
	$(FORK_SRC)/instruction.cpp \
	$(FORK_SRC)/instructions_portable.cpp \
	$(FORK_SRC)/reciprocal.c \
	$(FORK_SRC)/virtual_memory.c

.PHONY: all clean vectors check-fork-pin

all: gen

gen: gen.cpp $(FORK_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^

# Regenerates all committed vectors from `gen`. Outputs land in
# `../../vm/`:
#
#   T9   vm_single_int_smoke          — IADD_RS / IMULH_R / IROR_R / ISTORE
#   T10  vm_single_fp_smoke_rn        — FADD_R / FMUL_R / FDIV_M / FSQRT_R
#                                       under round-to-nearest
#   T11  vm_fp_matrix_rn              — 9-FP-opcode matrix, mode 0
#   T12  vm_fp_matrix_rd              — 9-FP-opcode matrix, mode 1
#   T13  vm_fp_matrix_ru              — 9-FP-opcode matrix, mode 2
#   T14  vm_fp_matrix_rz              — 9-FP-opcode matrix, mode 3
#   T15  vm_cfround_throttle          — CFROUND throttle + 2 unthrottled
vectors: gen
	./gen t9  > ../../vm/t9_vm_single_int_smoke.bin
	./gen t10 > ../../vm/t10_vm_single_fp_smoke_rn.bin
	./gen t11 > ../../vm/t11_vm_fp_matrix_rn.bin
	./gen t12 > ../../vm/t12_vm_fp_matrix_rd.bin
	./gen t13 > ../../vm/t13_vm_fp_matrix_ru.bin
	./gen t14 > ../../vm/t14_vm_fp_matrix_rz.bin
	./gen t15 > ../../vm/t15_vm_cfround_throttle.bin

check-fork-pin:
	@cd $(FORK_ROOT) && git rev-parse HEAD

clean:
	rm -f gen
