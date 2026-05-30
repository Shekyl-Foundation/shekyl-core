# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Reproducer for the SuperscalarHash reference vectors committed
# alongside this Makefile. Builds `gen` against the v2 RandomX fork's
# reference SuperscalarHash implementation at pin aaafe71 —
# `superscalar.cpp` (program generation and execution),
# `blake2_generator.cpp` (the SS-RNG), `blake2/blake2b.c` (the
# underlying hash), and `reciprocal.c` (the `IMUL_RCP` reciprocal
# computation). All emitted bytes are platform-independent: the
# generator and executor are pure scalar C++ with no SIMD codegen
# dependency, and the wire format is little-endian.
#
# This Makefile and the surrounding `_generator/` directory are
# committed for audit reproducibility per docs/design/RANDOMX_V2_RUST.md
# §3 and per the design plan
# `docs/design/RANDOMX_V2_PHASE2B_PLAN.md` §5.3 (C++ generator
# convention) + §5.4 (F4 SuperscalarHash structured 3-vector
# decomposition). They are NOT built by `cargo test`; the Rust test
# suite consumes the pre-committed `.bin` vector files via
# `include_bytes!`. Rebuilding the vectors requires a C++ toolchain
# and `git submodule update --init` for the `external/randomx-v2/`
# submodule.

FORK_ROOT := ../../../../../../../external/randomx-v2
FORK_SRC  := $(FORK_ROOT)/src

CXX      ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(FORK_SRC) -I$(FORK_SRC)/blake2

FORK_OBJS := \
	$(FORK_SRC)/superscalar.cpp \
	$(FORK_SRC)/blake2_generator.cpp \
	$(FORK_SRC)/instructions_portable.cpp \
	$(FORK_SRC)/reciprocal.c \
	$(FORK_SRC)/blake2/blake2b.c

.PHONY: all clean vectors check-fork-pin

all: gen

gen: gen.cpp $(FORK_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^

# Regenerates all committed vectors from `gen`. Output goes to the
# parent directory alongside the `.meta.txt` headers; reviewers
# verifying provenance run `make vectors` and `git diff --stat`
# against the committed files (mirroring the AES generator convention
# in the sibling `../aes/_generator/` Makefile).
#
# Phase 2b SS-hash scope (per `RANDOMX_V2_PHASE2B_PLAN.md` §5.4 / F4):
#  - Layer A — 3 program serializations covering the structured
#    seed/nonce decomposition: baseline / nonce-mixing /
#    seed-derivation. A test divergence on a specific vector
#    attributes the failure mode mechanically.
#  - Layer B — 3 executions of the same fixed input
#    `r=[0, 1, 2, 3, 4, 5, 6, 7]` through each Layer A program. Tests
#    execution parity independent of generation parity (the Rust test
#    loads the serialized program from Layer A's `.bin` and runs
#    `execute_superscalar` against it).
#  - Combined — 1 end-to-end attestation tuple (seed=shekyl-ss-test,
#    nonce=0, input=[0..8]) → output[8]. Same bytes as `exec_v3.bin`
#    but tested via the full generate→execute pipeline without
#    intermediate `.bin` serialization.
vectors: gen
	./gen prog_v1   > ../ss_program_seed_empty_nonce_0.bin
	./gen prog_v2   > ../ss_program_seed_empty_nonce_1.bin
	./gen prog_v3   > ../ss_program_seed_shekyl_nonce_0.bin
	./gen exec_v1   > ../ss_execute_seed_empty_nonce_0.bin
	./gen exec_v2   > ../ss_execute_seed_empty_nonce_1.bin
	./gen exec_v3   > ../ss_execute_seed_shekyl_nonce_0.bin
	./gen combined  > ../ss_combined_seed_shekyl_nonce_0.bin

# Sanity check that the fork pin hasn't drifted under us. Informational;
# does not block `vectors` since the .meta.txt files record the
# expected pin and a reviewer comparing the diff will notice any
# mismatch.
check-fork-pin:
	@cd $(FORK_ROOT) && git rev-parse HEAD

clean:
	rm -f gen
