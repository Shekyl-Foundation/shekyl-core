# Copyright (c) 2025-2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause

# Reproducer for the Argon2d reference vectors committed alongside this
# Makefile. Builds `gen` against the v2 RandomX fork's reference Argon2
# implementation at pin aaafe71 (no SSSE3/AVX2 variants; the reference
# `argon2_ref.c` keeps the produced bytes architecture-independent).
#
# This Makefile and the surrounding `_generator/` directory are
# committed for audit reproducibility per docs/design/RANDOMX_V2_RUST.md
# §3. They are NOT built by `cargo test`; the Rust test suite consumes
# the pre-committed `.bin` vector files via `include_bytes!`. Rebuilding
# the vectors requires a C toolchain and `git submodule update --init`
# for the `external/randomx-v2/` submodule.

FORK_ROOT := ../../../../../../../external/randomx-v2
FORK_SRC  := $(FORK_ROOT)/src

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
CPPFLAGS := -I$(FORK_SRC) -I$(FORK_SRC)/blake2

FORK_OBJS := \
	$(FORK_SRC)/argon2_ref.c \
	$(FORK_SRC)/argon2_core.c \
	$(FORK_SRC)/blake2/blake2b.c

.PHONY: all clean vectors check-fork-pin

all: gen

gen: gen.c $(FORK_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^

# Convenience target that regenerates all committed vectors from `gen`.
# Output goes to the parent directory alongside the `.meta.txt` headers.
# Reviewers verifying provenance run `make vectors` and `diff` against
# the committed files.
#
# Phase 2a scope: two small-parameter vectors (m=8 and m=64). The Argon2
# inner loop (`fill_block` + `blamka_round`) is identical regardless of
# m_cost; byte-for-byte agreement at small m demonstrates agreement at
# the production m=262144. The `blake` mode in `gen.c` is provided for
# Phase 2g's differential harness (full-parameter Blake2b-512 fingerprint
# against the live C reference); no committed vector uses it at Phase 2a.
vectors: gen
	./gen raw 8  3 1 "Shekyl RandomX v2 Phase 2a test key" > ../m8_t3_p1_shekyl_test_key.bin
	./gen raw 64 3 1 "Shekyl RandomX v2 Phase 2a test key" > ../m64_t3_p1_shekyl_test_key.bin

# Sanity check that the fork pin hasn't drifted under us. This target
# is informational; it does not block `vectors` since the .meta.txt
# files record the expected pin and a reviewer comparing the diff will
# notice any mismatch.
check-fork-pin:
	@cd $(FORK_ROOT) && git rev-parse HEAD

clean:
	rm -f gen
