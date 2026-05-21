# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Reproducer for the AES reference vectors committed alongside this
# Makefile. Builds `gen` against the v2 RandomX fork's reference AES
# implementation at pin aaafe71 — specifically `soft_aes.cpp` (the
# constant-time LUT software AES) and `aes_hash.cpp`'s
# template-`<softAes=true>` instantiations of `fillAes1Rx4`,
# `fillAes4Rx4`, and `hashAes1Rx4`. Pinning to `softAes=true` keeps
# the produced bytes instruction-set-independent — no AES-NI / NEON /
# RVV / zvkned codegen variance — and reproducible on any little-
# endian platform with a C++17 compiler.
#
# This Makefile and the surrounding `_generator/` directory are
# committed for audit reproducibility per docs/design/RANDOMX_V2_RUST.md
# §3 and per the design plan
# `docs/design/RANDOMX_V2_PHASE2B_PLAN.md` §5.3 (C++ generator
# convention). They are NOT built by `cargo test`; the Rust test suite
# consumes the pre-committed `.bin` vector files via `include_bytes!`.
# Rebuilding the vectors requires a C++ toolchain and
# `git submodule update --init` for the `external/randomx-v2/`
# submodule.

FORK_ROOT := ../../../../../../../external/randomx-v2
FORK_SRC  := $(FORK_ROOT)/src

CXX      ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(FORK_SRC) -I$(FORK_SRC)/blake2

FORK_OBJS := \
	$(FORK_SRC)/soft_aes.cpp \
	$(FORK_SRC)/aes_hash.cpp

.PHONY: all clean vectors check-fork-pin

all: gen

gen: gen.cpp $(FORK_OBJS)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -o $@ $^

# Regenerates all committed vectors from `gen`. Output goes to the
# parent directory alongside the `.meta.txt` headers; reviewers
# verifying provenance run `make vectors` and `git diff --stat`
# against the committed files (analogous to the Phase 2a Argon2d
# convention in the sibling `argon2d/_generator/` Makefile).
#
# Phase 2b scope (per `RANDOMX_V2_PHASE2B_PLAN.md` §6.1):
#  - 3 round-encrypt tuples + 3 round-decrypt tuples (smoke test
#    inputs documented in `gen.cpp`'s `ROUND_INPUT_STATES`/`_KEYS`
#    tables).
#  - Chained-pair multi-round F6 supplement (3 rounds chained for
#    each direction; intermediate states pinned).
#  - One AesGenerator1R (state writeback) and one AesGenerator4R (no
#    state writeback) vector at iters=4.
#  - Two AesHash1R vectors: uniform input and empty input (the
#    finalization-only path).
vectors: gen
	./gen round_enc                > ../round_enc.bin
	./gen round_dec                > ../round_dec.bin
	./gen chained_enc              > ../chained_enc.bin
	./gen chained_dec              > ../chained_dec.bin
	./gen gen_1r_state42_iters4    > ../gen_1r_state42_iters4.bin
	./gen gen_4r_state33_iters4    > ../gen_4r_state33_iters4.bin
	./gen hash_1r_uniform128       > ../hash_1r_uniform128.bin
	./gen hash_1r_empty            > ../hash_1r_empty.bin

# Sanity check that the fork pin hasn't drifted under us. Informational;
# does not block `vectors` since the .meta.txt files record the
# expected pin and a reviewer comparing the diff will notice any
# mismatch.
check-fork-pin:
	@cd $(FORK_ROOT) && git rev-parse HEAD

clean:
	rm -f gen
