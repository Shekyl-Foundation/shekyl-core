# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Reproducer for the Phase 2c reference vectors committed alongside
# this Makefile. Builds `gen` against the v2 RandomX fork's reference
# at pin aaafe71 — Argon2d for cache derivation, Blake2 + Blake2Generator
# + SuperscalarHash for cache item derivation, softAes for scratchpad
# fill / final hash, and the full VM substrate (`virtual_machine.cpp`,
# `vm_interpreted.cpp`, `bytecode_machine.cpp`, `instructions_portable.cpp`,
# `dataset.cpp`, etc.) for register init, program parse, per-iteration
# scratchpad-mix + AES-mix snapshots, and the end-to-end stub-NOP hash.
#
# Pinning to `softAes=true` keeps the produced bytes instruction-set-
# independent — no AES-NI / NEON / RVV / zvkned codegen variance — and
# reproducible on any little-endian platform with a C++17 compiler.
#
# This Makefile and the surrounding `_generator/phase2c/` directory are
# committed for audit reproducibility per docs/design/RANDOMX_V2_RUST.md
# §3 and per the design plan
# `docs/design/RANDOMX_V2_PHASE2C_PLAN.md` §7 (F6 generator details) +
# §9 commit 7 (generator + T1-T8 spec-vector tests). They are NOT
# built by `cargo test`; the Rust test suite consumes the pre-committed
# `.bin` vector files via `include_bytes!`. Rebuilding the vectors
# requires a C++ toolchain and `git submodule update --init` for the
# `external/randomx-v2/` submodule.
#
# Layout note: this generator lives at
# `tests/vectors/reference/_generator/phase2c/` (one level above the
# per-subsystem layout used by aes/, argon2d/, superscalar/) because
# Phase 2c's eight reference vectors span two subsystems — T1, T2 emit
# to `../../cache/`, T3-T8 emit to `../../vm/`. The shared parent makes
# the cross-subsystem provenance auditable from a single Makefile +
# .meta.txt root, per RANDOMX_V2_PHASE2C_PLAN.md §7.

FORK_ROOT := ../../../../../../../external/randomx-v2
FORK_SRC  := $(FORK_ROOT)/src

CXX      ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(FORK_SRC) -I$(FORK_SRC)/blake2 -DRANDOMX_DEFAULT_FLAG_V2=128

# Full v2 substrate: cache derivation (argon2 + blake2 + superscalar),
# dataset item derivation, AES fill/hash (softAes for portability), VM
# substrate (virtual_machine + interpreted_light + bytecode_machine +
# instructions_portable), reciprocal cache, instructions, and the
# top-level randomx.cpp C bindings (randomx_alloc_cache,
# randomx_init_cache, randomx_create_vm, etc.).
#
# vm_compiled.cpp and assembly_generator_x86.cpp are linked because
# `randomx.cpp::randomx_create_vm` (compiled into the same translation
# unit we depend on for the cache C API) instantiates the
# `randomx::CompiledVm*` templates whose constructors call into
# `JitCompilerX86`. The interpreted-light code path doesn't call them
# at runtime, but the link references must still resolve, so we add
# the x86_64 JIT compiler sources to FORK_OBJS.
#
# This Makefile is x86_64-Linux-pinned (the v2 RandomX fork's CMakeLists
# selects per-architecture sources at configure time; we hard-pin x86_64
# here since the Shekyl substrate targets x86_64 hosts for v3 launch).
# Cross-host reproduction would need to swap to jit_compiler_a64*.cpp /
# jit_compiler_rv64*.cpp per CMakeLists.txt §§141-185.
FORK_OBJS := \
	$(FORK_SRC)/aes_hash.cpp \
	$(FORK_SRC)/allocator.cpp \
	$(FORK_SRC)/argon2_avx2.c \
	$(FORK_SRC)/argon2_core.c \
	$(FORK_SRC)/argon2_ref.c \
	$(FORK_SRC)/argon2_ssse3.c \
	$(FORK_SRC)/assembly_generator_x86.cpp \
	$(FORK_SRC)/blake2/blake2b.c \
	$(FORK_SRC)/blake2_generator.cpp \
	$(FORK_SRC)/bytecode_machine.cpp \
	$(FORK_SRC)/cpu.cpp \
	$(FORK_SRC)/dataset.cpp \
	$(FORK_SRC)/instruction.cpp \
	$(FORK_SRC)/instructions_portable.cpp \
	$(FORK_SRC)/jit_compiler_x86.cpp \
	$(FORK_SRC)/jit_compiler_x86_static.S \
	$(FORK_SRC)/randomx.cpp \
	$(FORK_SRC)/reciprocal.c \
	$(FORK_SRC)/soft_aes.cpp \
	$(FORK_SRC)/superscalar.cpp \
	$(FORK_SRC)/virtual_machine.cpp \
	$(FORK_SRC)/virtual_memory.c \
	$(FORK_SRC)/vm_compiled.cpp \
	$(FORK_SRC)/vm_compiled_light.cpp \
	$(FORK_SRC)/vm_interpreted.cpp \
	$(FORK_SRC)/vm_interpreted_light.cpp

.PHONY: all clean vectors check-fork-pin

all: gen

gen: gen.cpp $(FORK_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^

# Regenerates all committed vectors from `gen`. Outputs cross two
# subsystem directories under `../../`:
#   - T1, T2 → cache-side fingerprints                → `../../cache/`
#   - T3, T4, T5, T6, T7, T8 → VM-side fingerprints   → `../../vm/`
#
# Phase 2c scope per RANDOMX_V2_PHASE2C_PLAN.md §5.7 (F7 T1-T8 matrix):
#
#   T1  cache_derive_fingerprint    — Blake2b-256(cache.memory ‖
#                                     8 SuperscalarPrograms serialized)
#   T2  cache_derive_item_batch     — 8 × 64-byte dataset items at
#                                     item_numbers {0, 1, 1023, 1024,
#                                     524287, 524288, 2097150, 2097151}
#   T3  vm_scratchpad_init          — Blake2b-256(scratchpad bytes after
#                                     fillAes1Rx4 init from 64-byte seed)
#   T4  vm_register_init            — NativeRegisterFile snapshot after
#                                     register init from 128-byte entropy
#   T5  vm_program_parse            — 384-instruction Program parsed from
#                                     3072-byte instruction payload
#   T6  vm_spaddr_4iter             — spAddr0/1 pairs for 4 iterations
#                                     covering the readReg0/1 combinations
#   T7  vm_aesmix_4iter             — post-AES-mix register snapshot for
#                                     4 iterations under stub-NOP dispatch
#   T8  vm_compute_hash_nop         — end-to-end compute_hash output with
#                                     literal-NOP byteCode override
vectors: gen
	./gen t1 > ../../cache/t1_cache_derive_fingerprint.bin
	./gen t2 > ../../cache/t2_cache_derive_item_batch.bin
	./gen t3 > ../../vm/t3_vm_scratchpad_init.bin
	./gen t4 > ../../vm/t4_vm_register_init.bin
	./gen t5 > ../../vm/t5_vm_program_parse.bin
	./gen t6 > ../../vm/t6_vm_spaddr_4iter.bin
	./gen t7 > ../../vm/t7_vm_aesmix_4iter.bin
	./gen t8 > ../../vm/t8_vm_compute_hash_nop.bin

# Sanity check that the fork pin hasn't drifted under us. Informational;
# does not block `vectors` since the .meta.txt files record the
# expected pin and a reviewer comparing the diff will notice any
# mismatch.
check-fork-pin:
	@cd $(FORK_ROOT) && git rev-parse HEAD

clean:
	rm -f gen
