#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# Build the cargo-checkct (BINSEC) container and lay out the verification
# workspaces for CA-1 (docs/design/CRYPTO_AUDIT.md §1). Everything lands
# under .build/ beside this script; nothing outside the repository is
# touched, and the container runs as the invoking user.
#
# Workspaces (each a cargo-checkct workspace with its own lockfile):
#   subject        crypto-bigint =0.5.5 (cb055) and dalek-ff-group =0.5.0 (dfg050)
#   subject-noslp  the same, x86_64 only, with SLP vectorisation off (see README)
#   helio          the vendored helioselene (rust/shekyl-oxide/crypto/helioselene)
#   ctl75, ctl76   crypto-bigint =0.7.5 / =0.7.6 with drivers/ctl.rs (controls)
#   ctlpre         upstream's own checkct driver against the crypto-bigint tree
#                  just before the 0.7.6 constant-time fixes (#1358's parent)
#
# Usage:  ./setup.sh            # build image, clone pins, create workspaces
#         CHECKCT_NIGHTLY=nightly-2025-12-04 ./setup.sh   # pin another nightly
#
# The nightly override installs that toolchain into .build/rustup-home with
# rust-src and the bare-metal targets; run.sh then passes the same home.
set -euo pipefail

CHECKCT_REPO=https://github.com/Ledger-Donjon/cargo-checkct
CHECKCT_COMMIT=85271e5ce9eab9ba895c62c8b5d4129810a635a0
CRYPTO_BIGINT_REPO=https://github.com/RustCrypto/crypto-bigint
# Parent of the merge of RustCrypto/crypto-bigint#1358 (the first 0.7.6
# constant-time fix); #1360 follows it. Upstream found this tree leaky.
CRYPTO_BIGINT_PREFIX=eeaabbe
IMAGE=shekyl-checkct:85271e5

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
BUILD=$HERE/.build
mkdir -p "$BUILD"

# ---- tools -----------------------------------------------------------------
if [ ! -d "$BUILD/cargo-checkct/.git" ]; then
    git clone -q "$CHECKCT_REPO" "$BUILD/cargo-checkct"
fi
git -C "$BUILD/cargo-checkct" checkout -q "$CHECKCT_COMMIT"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker build -t "$IMAGE" -f "$BUILD/cargo-checkct/Containerfile" "$BUILD/cargo-checkct"
fi

if [ ! -d "$BUILD/crypto-bigint/.git" ]; then
    git clone -q "$CRYPTO_BIGINT_REPO" "$BUILD/crypto-bigint"
fi
if [ ! -d "$BUILD/cb-pre" ]; then
    git -C "$BUILD/crypto-bigint" worktree add -q "$BUILD/cb-pre" "$CRYPTO_BIGINT_PREFIX"
fi

# ---- container wrapper ------------------------------------------------------
# The repository is mounted at /repo so path dependencies resolve the same
# way inside and outside the container.
DOCKER_ENV=(-e HOME=/tmp/h -e CARGO_HOME=/repo/docs/formal/checkct/.build/cargo-home)
if [ -n "${CHECKCT_NIGHTLY:-}" ]; then
    DOCKER_ENV+=(-e RUSTUP_HOME=/repo/docs/formal/checkct/.build/rustup-home)
fi
inctr() {
    docker run --rm -u "$(id -u):$(id -g)" "${DOCKER_ENV[@]}" \
        -v "$REPO:/repo" -w /repo/docs/formal/checkct/.build "$IMAGE" bash -c "$*"
}

if [ -n "${CHECKCT_NIGHTLY:-}" ]; then
    # With RUSTUP_HOME redirected, rustup installs the toolchain and then
    # exits 1 because it cannot place proxies in CARGO_HOME ("rustup is not
    # installed at ..."). The install itself succeeds, so the exit is
    # tolerated and the toolchain is asserted by running it (rule 47).
    inctr "rustup toolchain install $CHECKCT_NIGHTLY --profile minimal -c rust-src \
        -t riscv32imac-unknown-none-elf -t thumbv7em-none-eabihf -t thumbv6m-none-eabi || true"
    inctr "rustup run $CHECKCT_NIGHTLY rustc -vV"
fi

# ---- workspaces -------------------------------------------------------------
RAND_CORE='rand_core = "0.10"
rand_core_09 = { package = "rand_core", version = "0.9" }
rand_core_06 = { package = "rand_core", version = "0.6" }'

# mkws NAME "TARGETS" "EXTRA_X86_RUSTFLAGS" PROFILE_PANIC DRIVER:DEPS ...
#   TARGETS            space-separated rustc targets
#   EXTRA_X86_RUSTFLAGS extra -C flags for x86_64 (e.g. no-vectorize-slp), or ""
#   PROFILE_PANIC      abort | immediate-abort
#   DRIVER:DEPS        driver crate name (drivers/<name>.rs) and its Cargo deps
mkws() {
    local name=$1 targets=$2 x86extra=$3 panic=$4; shift 4
    local ws=$BUILD/$name
    rm -rf "$ws"
    mkdir -p "$ws/src"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n[workspace]\n' "$name" >"$ws/Cargo.toml"
    echo '#![no_std]' >"$ws/src/lib.rs"
    inctr "cargo checkct init -d /repo/docs/formal/checkct/.build/$name >/dev/null"
    rm -rf "$ws/checkct/driver"
    local members=()
    for spec in "$@"; do
        local drv=${spec%%:*} deps=${spec#*:}
        inctr "cargo checkct add -d /repo/docs/formal/checkct/.build/$name -n $drv >/dev/null"
        members+=("\"$drv\"")
        if [ "$drv" = ctlpre ]; then
            cp "$BUILD/crypto-bigint/checkct/driver/src/driver.rs" "$ws/checkct/$drv/src/driver.rs"
        else
            cp "$HERE/drivers/$drv.rs" "$ws/checkct/$drv/src/driver.rs"
        fi
        cat >"$ws/checkct/$drv/Cargo.toml" <<EOF
[package]
name = "$drv"
version = "0.0.0"
publish = false
edition = "2024"

[dependencies]
checkct_macros = { path = "../checkct_macros" }
$deps
$RAND_CORE
EOF
    done
    local list; list=$(IFS=,; echo "${members[*]}")
    {
        if [ "$panic" = immediate-abort ]; then echo 'cargo-features = ["panic-immediate-abort"]'; echo; fi
        echo '[workspace]'
        echo "members = [${list//,/, }]"
        echo 'resolver = "2"'
        echo
        echo '[profile.release]'
        echo 'debug = true'
        echo "panic = \"$panic\""
        # Parity with rust/Cargo.toml [profile.release]: the wallet is built
        # with overflow checks on, and the crypto crates at opt-level 3
        # (the release default here). No LTO and no target-cpu there either.
        echo 'overflow-checks = true'
    } >"$ws/checkct/Cargo.toml"
    local tlist; tlist=$(for t in $targets; do printf '"%s", ' "$t"; done)
    cat >"$ws/checkct/.cargo/config.toml" <<EOF
[build]
target = [${tlist%, }]

# Freestanding drivers linked by rust-lld; a static relocation model gives
# binsec absolute entrypoint addresses (cargo-checkct's template flags).
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "linker=rust-lld", "-C", "linker-flavor=ld.lld", "-C", "relocation-model=static"${x86extra}]

[unstable]
# dalek-ff-group 0.5.0 enables curve25519-dalek/alloc, so alloc must come
# from build-std too; the drivers name a null allocator.
build-std = ["core", "alloc", "panic_abort"]
build-std-features = ["compiler-builtins-mem"]
EOF
    if [ -n "${CHECKCT_NIGHTLY:-}" ]; then
        sed -i "s/^channel = .*/channel = \"$CHECKCT_NIGHTLY\"/" "$ws/checkct/rust-toolchain.toml"
    fi
    inctr "cd /repo/docs/formal/checkct/.build/$name/checkct && cargo generate-lockfile >/dev/null 2>&1"
}

CB055='crypto-bigint = { version = "=0.5.5", default-features = false, features = ["zeroize"] }
subtle = { version = "2", default-features = false }'
DFG050='dalek-ff-group = { version = "=0.5.0", default-features = false }
ff = { version = "0.13", default-features = false, features = ["bits"] }
subtle = { version = "2", default-features = false }'
HELIO='helioselene = { path = "/repo/rust/shekyl-oxide/crypto/helioselene", default-features = false }
ff = { version = "0.13", default-features = false, features = ["bits"] }
subtle = { version = "2", default-features = false }'

ALL3="x86_64-unknown-linux-gnu riscv32imac-unknown-none-elf thumbv7em-none-eabihf"
mkws subject       "$ALL3" "" abort "cb055:$CB055" "dfg050:$DFG050"
mkws subject-noslp "x86_64-unknown-linux-gnu" ', "-C", "no-vectorize-slp"' abort "cb055:$CB055" "dfg050:$DFG050"
mkws helio         "$ALL3" "" abort "helio:$HELIO"
# Controls mirror upstream's checkct profile (panic-immediate-abort).
CTL_TARGETS="x86_64-unknown-linux-gnu thumbv6m-none-eabi riscv32imac-unknown-none-elf"
mkws ctl75  "$CTL_TARGETS" "" immediate-abort 'ctl:crypto-bigint = { version = "=0.7.5", default-features = false }'
mkws ctl76  "$CTL_TARGETS" "" immediate-abort 'ctl:crypto-bigint = { version = "=0.7.6", default-features = false }'
mkws ctlpre "$CTL_TARGETS thumbv7em-none-eabihf" "" immediate-abort \
    'ctlpre:crypto-bigint = { path = "/repo/docs/formal/checkct/.build/cb-pre", default-features = false }'

echo "setup complete: workspaces under $BUILD"
