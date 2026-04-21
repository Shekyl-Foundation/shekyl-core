# Shekyl Installation Guide

This guide documents how to build and run Shekyl from source using the current repository build system.

It is intentionally Shekyl-native (binary names and commands), even where legacy docs still reference `monero*`.

---

## 1) What this guide covers

- Supported platforms and practical build targets.
- Required and optional dependencies.
- Build flows using both top-level `Makefile` and direct CMake.
- Shekyl binary names and first-run verification.
- Common pitfalls (submodules, compatibility flags, RPC safety).

---

## 2) Supported platforms

### Documented by repository docs

The project README documents build/run guidance for:

- Linux and macOS
- Windows (MSYS2/MinGW)
- Raspberry Pi
- FreeBSD, OpenBSD, NetBSD, Solaris

### Practical baseline

If you are starting fresh, prefer:

- Linux (Debian/Ubuntu/Fedora/Arch)
- macOS
- Windows via MSYS2

---

## 3) Dependencies

The dependency matrix is maintained in `README.md` and includes:

- compiler/tooling: GCC, CMake, pkg-config
- core libs: Boost, OpenSSL, libunbound, libsodium
- optional libs/tools: libunwind, readline, expat, gtest, ccache, doxygen/graphviz
- optional hardware wallet stack: hidapi, libusb, protobuf/protoc, libudev

### Rust integration behavior

Rust modules are integrated via `cmake/BuildRust.cmake`:

- if `cargo` is found, Rust workspace under `rust/` is built and linked
- if `cargo` is not found, build continues with Rust modules disabled

Install Rust toolchain when you want full Rust-enabled builds:

```bash
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
```

### PQC and FCMP++ build note

Shekyl's rebooted chain design depends on Rust-based PQC and FCMP++ components.

Today:

- some Rust modules are optional at build time
- PQC implementation is still being completed
- FCMP++ Rust crates (`shekyl-fcmp`, `shekyl-address`) are required for
  consensus-valid builds

Target state for the rebooted mainnet:

- Rust toolchain will be a required dependency for consensus-valid builds
- node operators, wallet builders, and release builders should assume a
  Rust-enabled build is mandatory
- the canonical PQC design and transaction format are documented in
  `docs/POST_QUANTUM_CRYPTOGRAPHY.md`
- the FCMP++ design document will be published as `docs/FCMP_PLUS_PLUS.md`

---

## 4) Clone and prepare source

Clone recursively to include required submodules:

```bash
git clone --recursive <your-shekyl-repo-url>
cd Shekyl
```

If already cloned without submodules:

```bash
git submodule update --init --force
```

Important: CMake checks submodule state and can fail if submodules are out of sync (unless you explicitly pass `-DMANUAL_SUBMODULES=1`).

---

## 5) Build on Linux/macOS

### Quick path (recommended)

From repository root:

```bash
make
```

This builds release artifacts under a `build/.../release` path (or `build/release`, depending on builddir mode).

### Common build targets

```bash
make release-all         # release + tests enabled at build time
make release-test        # release build, then run tests
make debug               # debug build
make release-static      # static build
make coverage            # debug + coverage + tests
```

### Explicit CMake path (equivalent control)

```bash
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=ON
cmake --build build --target all
```

---

## 6) Build on Windows (MSYS2/MinGW)

Open MSYS2 MinGW shell and install toolchain + dependencies (64-bit example):

```bash
pacman -Syu
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-boost mingw-w64-x86_64-openssl \
  mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound
```

Then:

```bash
git clone --recursive <your-shekyl-repo-url>
cd Shekyl
make release-static-win64
```

> **Do not build 32-bit Shekyl.** `make release-static-win32` is
> still present in the `Makefile` but is scheduled for removal in
> V3.2 (Chore #3). Shekyl's post-quantum primitives (ML-KEM-768,
> ML-DSA-65) rely on 64-bit arithmetic for their constant-time
> guarantees; on 32-bit targets the compiler decomposes every
> `u64` operation into variable-time 32-bit sequences with
> operand-dependent carry propagation, opening a published
> timing-side-channel surface against which a Shekyl wallet's
> private key is extractable by any attacker who can measure
> operation timing. See `docs/STRUCTURAL_TODO.md` §"32-bit targets
> cannot safely run Shekyl" for the full analysis. If your
> hardware cannot run 64-bit Windows, Shekyl is not appropriate
> for your machine.

---

## 7) Shekyl binary names and locations

The current CMake targets produce:

- daemon: `shekyld`
- CLI wallet: `shekyl-cli`
- wallet RPC: `shekyl-wallet-rpc`

Typical output location:

- `<build_dir>/bin/`

For a common release flow:

- `build/release/bin/shekyld`
- `build/release/bin/shekyl-cli`
- `build/release/bin/shekyl-wallet-rpc`

Note: some legacy or upstream docs/config examples may still use older daemon/wallet names; use Shekyl names above for this repository.

---

## 8) First-run verification

From your build output directory:

```bash
./shekyld --version
./shekyld --help
./shekyl-cli --help
./shekyl-wallet-rpc --help
```

Start daemon in foreground:

```bash
./shekyld
```

Run the daemon in the background via your platform's service manager
(systemd on Linux, launchd on macOS, Task Scheduler on Windows). An
example systemd unit lives at `contrib/packaging/linux/shekyld.service`;
copy it to `/etc/systemd/system/shekyld.service` and `systemctl enable
--now shekyld`. `--detach`, `--pidfile`, and the Windows `--*-service`
flags were removed in V3.1; the daemon now only runs in the foreground
and is supervised externally. The GUI wallet embeds `shekyld` as a
Tauri sidecar and does not require a separate service unit.

If running a public remote RPC node, always use restricted mode.

---

## 9) Optional compatibility/build flags

### Better libc compatibility across older Linux systems

Use:

```bash
cmake -S . -B build -D CMAKE_BUILD_TYPE=Release -DBACKCOMPAT=ON
cmake --build build
```

### Manual submodule override (advanced only)

If you intentionally manage submodules outside CMake checks:

```bash
cmake -S . -B build -DMANUAL_SUBMODULES=1
```

### Static builds and `-fPIC`

Some static dependencies may need to be rebuilt with `-fPIC` for successful static linking.

---

## 10) Runtime safety notes

- For public node operation, use restricted RPC mode.
- On macOS, if you encounter refresh/runtime instability, try `--max-concurrency 1`.
- Keep daemon and wallet versions from the same build.
- Prefer explicit `--data-dir` and `--config-file` paths in service environments.

---

## 11) Troubleshooting

### CMake fails with submodule error

Fix:

```bash
git submodule update --init --force
```

Then rerun CMake.

### Rust components not built

If configure output indicates cargo not found, install Rust/cargo and rebuild.

### Missing dependencies

Install packages for your distro from the dependency section in `README.md`, then clean/rebuild.

### Built binaries do not run on older Linux distro

Rebuild with `-DBACKCOMPAT=ON`.

---

## 12) Related docs

- `README.md` (full dependency matrix and platform specifics)
- `Makefile` (build targets)
- `CMakeLists.txt` (build options, submodule checks, linker flags)
- `shekyl-dev/docs/SEEDS_SETUP.md` (seed bootstrap model and runtime seed/peer controls)
- `shekyl-dev/docs/SEED_NODE_DEPLOYMENT.md` (step-by-step seed node and shekyl.org caching deployment)
- `docs/POST_QUANTUM_CRYPTOGRAPHY.md` (canonical PQC spec and reboot-only transaction format)
- `docs/FCMP_PLUS_PLUS.md` (FCMP++ design document)
