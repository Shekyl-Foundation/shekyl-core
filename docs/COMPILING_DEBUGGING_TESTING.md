# Compiling, debugging and testing efficiently

This document describes ways of compiling and testing Shekyl efficiently. The
intended audience is developers. Before reading it, consult "Compiling Shekyl
from source" in the main README.md.

Everything Shekyl ships is Rust: the workspace under `rust/`. CMake and the
top-level `Makefile` drive one cargo invocation (`cmake/BuildRust.cmake`)
that builds `shekyld`, `shekyl-cli` and `shekyl-wallet-rpc` and stages them
in the build directory's `bin/`. The tree holds no first-party C or C++
(`scripts/ci/check_no_first_party_c.py`). The canonical PQC format is
documented in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.

## Rust Reproducible Builds

Reproducibility of the shipped binaries is essential for release
verification.

### Requirements

- **x86_64 host only.** Rust does not produce bit-identical output across CPU architectures (see Monero #9801). Release artifacts must be built on x86_64 Linux. ARM64, RISC-V, and other architectures may produce functionally correct binaries but they will not match the deterministic reference hash.
- **Pinned toolchain and vendored snapshot.** The workspace uses `Cargo.lock`
  to pin dependency versions, and vendored `shekyl-oxide` crates under
  `rust/shekyl-oxide/` are tracked via
  `rust/shekyl-oxide/UPSTREAM_MONERO_OXIDE_COMMIT`. All `cargo build`
  invocations in CI and CMake pass `--locked` to enforce reproducibility.
- **Stable Rust.** The workspace targets stable Rust (currently 1.94.0+). Nightly features are not used.

### Verifying determinism locally

CI's determinism check (`.github/workflows/rust-audit-test.yml`) builds the
daemon twice and compares the hashes:

```bash
cd rust
cargo build --locked --release -p shekyld
sha256sum target/release/shekyld
cargo clean -p shekyld --release
cargo build --locked --release -p shekyld
sha256sum target/release/shekyld
# Both hashes must match
```

### Guix integration

Guix gained improved Rust packaging support in 2025 with Cargo.lock lockfile importing. The `guix-rustup` third-party channel provides access to pinned stable Rust toolchains. Full Guix reproducible release integration is tracked as a Phase 1a.2 deliverable. Until Guix integration is validated, release builds use the CI determinism check (build twice, diff hashes) as the reproducibility gate.

## Basic compilation

Shekyl can be compiled via the main `Makefile`, using one of several targets
listed there. The targets are presets for `CMake` calls with various options.
It is possible to extract these `CMake` calls and modify them for your
specific needs. For example, a minimal cmake command run from a new build
directory:

`cmake -S "$DIR_SRC" -DCMAKE_BUILD_TYPE=Release && make`

where the variable `DIR_SRC` is expected to store the path to the Shekyl
source code. When iterating on one crate, `cargo build -p <crate>` and
`cargo test -p <crate>` from `rust/` are faster than a full CMake build.

## Testing

The tests are cargo's. From `rust/`:

```bash
cargo test --workspace --exclude shekyl-randomx-differential
```

`shekyl-randomx-differential` compares the Rust RandomX verifier with the C
reference and needs the reference built first; its own workflow
(`.github/workflows/randomx-v2-differential.yml`) is the gate. The tests
that run against a live regtest daemon are `#[ignore]`d and armed by
`scripts/ci/run_live_daemon_gates.sh`. `tests/` at the top of the tree holds
only the CMake gate tests and the stressnet harness (`tests/README.md`).

PQC changes should come with: Rust unit tests in `rust/shekyl-crypto-pq`;
transaction serialization tests for the PQ transaction format; wallet sign
and consensus verify integration tests; malformed signature and
malformed-length rejection tests; and encoded-size regression checks for
mempool and RPC consumers.

## Running a source build with Tor

A release archive carries the pinned Tor bundle in `tor/` beside the
binaries. A source build does not, so a `shekyld` you compiled starts
clearnet-only and warns that no Tor was found. To give it one, stage the
pinned bundle into the build's `bin/tor/`:

```bash
# x86_64 Linux; use aarch64-linux-gnu on an arm64 host.
python3 scripts/release/tor_bundle.py stage --host x86_64-linux-gnu \
  --sources ~/.cache/shekyl-tor --dest build/bin/tor --licenses build/bin/tor-licenses
```

`stage` downloads the tarball named in `config/tor_pins.json` if
`--sources` does not hold it, refuses it unless its SHA-256 is the pinned
one, and extracts only the files the pin lists. The daemon then finds
`tor/tor` beside itself.

`--tor-file /path/to/tor` (or `tor-file` in the configuration file) names
where the daemon looks; nothing is read from the environment. It does not
relax what it checks. The path must name the `tor` inside a directory
that holds **exactly** the pinned files:

- **Pointing it at a full extracted Expert Bundle is refused.** That
  directory also holds `pluggable_transports/`, and the daemon refuses a
  tor directory with anything in it that is not pinned. The loader is
  pointed at that directory, so anything in it could be loaded. Stage the
  bundle as above and point the variable at the staged `tor`.
- A distribution's `tor` (`/usr/bin/tor`) is refused: it is a different
  build and its directory is not the bundle.
- There is no `PATH` lookup.

The managed tor is started with an empty environment plus, on Linux,
`LD_LIBRARY_PATH` set to its own directory. A variable exported in your
shell does not reach it.

To run without Tor on purpose, pass `--tor off`. The lifecycle tests take
any tor through `SHEKYL_TEST_TOR_BINARY`, which bypasses the pin and exists
only in test builds.

The managed tor is pinned for Linux (x86_64, aarch64), Windows (x86_64) and
macOS (x86_64, aarch64); `config/tor_pins.json` is the list. FreeBSD and
riscv64 Linux have none, because the Tor Project publishes no Expert Bundle
for them (`docs/design/TOR_BUNDLE_DISTRIBUTION.md` §5). There the daemon says
so at start. Run your own Tor and set `tor = operator` with `tor-socks`, and
`tor-onion` with `tor-onion-listen` for inbound.

## Seed node build (lean daemon)

`make release-seed` builds the binaries with `ARCH=x86-64` (portable
x86_64), so they run on any x86_64 host regardless of CPU generation (no
AVX/SSE4.x required).

```bash
make release-seed
```

The resulting binary is at `build/<platform>/release/bin/shekyld`.

Equivalent manual cmake invocation:

```bash
cmake -S . -B build/seed-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DARCH="x86-64"
cmake --build build/seed-release --target shekyl_rust_bins -- -j"$(nproc)"
```

If you previously configured the same build directory with a different `ARCH`
(for example `native`), delete that build directory before rebuilding so stale
CMake cache values cannot leak architecture-specific flags.

The binary needs no shared library beyond the C runtime.

See `shekyl-dev/docs/SEED_NODE_DEPLOYMENT.md` for full deployment instructions.

## Testnet build command cookbook

Use out-of-source builds and keep a dedicated release directory for testnet.

### 1) Configure once (fresh testnet release build dir)

```bash
cmake -S . -B build/testnet-release -DCMAKE_BUILD_TYPE=Release
```

### 2) Build the binaries

```bash
cmake --build build/testnet-release -- -j"$(nproc)"
```

`shekyl_rust_bins` is the one target that builds and stages all three
binaries; `cmake --build build/testnet-release --target help` lists the
targets. Straight from cargo, without the CMake staging copy:

```bash
cd rust && cargo build --release -p shekyld -p shekyl-cli -p shekyl-wallet-rpc
```

### 3) Fast recovery from a stale build directory

```bash
rm -rf build/testnet-release
cmake -S . -B build/testnet-release -DCMAKE_BUILD_TYPE=Release
cmake --build build/testnet-release --target shekyl_rust_bins -- -j"$(nproc)"
```

### 4) Testnet launch sanity command (runtime, not build)

```bash
./build/testnet-release/bin/shekyld --network testnet --data-dir /var/lib/shekyl-testnet
```
