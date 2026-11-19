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
- FreeBSD

A platform is supported only if CI or gitian builds it: Linux, macOS, Windows
and FreeBSD (Rick, 2026-11-17). OpenBSD, NetBSD, DragonFly BSD, illumos and
Solaris are not supported. The daemon names no arm for them, so a build for any
of them stops at the account walk's `compile_error!` in `shekyl-daemon-config`.
The daemon has no iOS or Android arm either: no CI or gitian job builds a node
for them.

### Practical baseline

If you are starting fresh, prefer:

- Linux (Debian/Ubuntu/Fedora/Arch)
- macOS
- Windows via MSYS2

---

## 3) Dependencies

The dependency matrix is maintained in `README.md` and includes:

- the Rust toolchain `rust/rust-toolchain.toml` pins, with `cargo`;
- CMake, and a C compiler for the crates whose build scripts compile C
  (no C or C++ library is linked from the system: no Boost, OpenSSL,
  libsodium or readline).

### Rust integration behavior

Every binary is Rust. `cmake/BuildRust.cmake` runs `cargo` for the
workspace under `rust/`, so a build needs the Rust toolchain:

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
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake
```

Then:

```bash
git clone --recursive <your-shekyl-repo-url>
cd Shekyl
make release-static-win64
```

> **Shekyl is 64-bit only.** 32-bit build targets
> (`release-static-win32`, `release-static-linux-i686`, and the
> corresponding `depends`
> triples) were permanently retired in v3.1.0-alpha.5 (Chore #3).
> The C++-side configure refuses non-64-bit hosts via a top-level
> `CMAKE_SIZEOF_VOID_P` gate, and the Rust workspace carries three
> independent `compile_error!` tripwires against `target_pointer_width
> != 64`. Shekyl's post-quantum primitives (ML-KEM-768 via `fips203`,
> ML-DSA-65 via `fips204`) state their constant-time guarantees
> against native 64-bit arithmetic; on 32-bit targets the compiler
> emits libgcc helpers (`__muldi3`, `__udivdi3`, `__ashldi3`) with no
> CT guarantee, plus variable-latency `u64` multiply on common
> 32-bit ARM cores — the exact threat model exploited by KyberSlash
> (Bernstein et al., 2024). See `docs/CHANGELOG.md` entry "Retired
> 32-bit build targets" and the audit-trail closure for the full
> argument. If your hardware cannot run 64-bit, Shekyl is not
> appropriate for your machine.

---

## 7) Shekyl binary names and locations

The current CMake targets produce:

- daemon: `shekyld` (a Rust binary, `rust/shekyld`, that links the C++
  core as a static library; `DAEMON_CONFIG_CUTOVER.md` DC-Q19)
- CLI wallet: `shekyl-cli` (Rust)
- wallet RPC: `shekyl-wallet-rpc` (Rust)

All three are built from the Rust workspace by `cmake/BuildRust.cmake` as
part of the ordinary CMake build — no separate `cargo` step is needed, and
`cargo` is already a build prerequisite.

**Platform note.** The wallet binaries are produced for Unix targets
(Linux, macOS). They are **not built for Windows** — `BuildRust.cmake`
skips them there, so a Windows build produces `shekyld` and the
blockchain utilities as before, and Windows release archives carry the
daemon but no wallet.

That skip is no longer because the code cannot be built: as of
2026-08-25 both `shekyl-cli` and `shekyl-wallet-rpc` compile and link for
`x86_64-pc-windows-msvc`, and their end-to-end tests pass there. What is
unverified is everything *after* compilation — the CMake cross-compile
path, staging, `install()`, and the archive layout — so the gate stays
until that is done deliberately rather than as a side effect. See
`docs/FOLLOWUPS.md`, "Rust wallet stack: no Windows support" (WP-W5).

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
(systemd on Linux, rc.d on FreeBSD, launchd on macOS, Task Scheduler on
Windows). The shipped systemd unit is the template
`contrib/packaging/linux/shekyld@.service`, one instance per network,
with `shekyl.slice` beside it. The `.deb` and the `.rpm` install both,
create the `shekyl` system account the unit runs as and `/etc/shekyl`,
and place each public network's settings file,
`/etc/shekyl/shekyld-<network>.toml`, when none is there: every option in
it is commented out, so the daemon runs on its defaults. They refuse to install where
an account named `shekyl` is already someone's login, because the daemon
would run with that login's rights, and say how to rename it. They do not
start the daemon. Set what you need in the network's file, then enable
and start that network's instance; before every start it checks the file
as the daemon's account:

```bash
sudo systemctl enable --now shekyld@testnet
```

Without a package, apply the same two declarations first, because
systemd refuses to start a unit whose account does not exist. Check first
that no login is named `shekyl` (`getent passwd shekyl`): the declaration
keeps an account that already exists, and the daemon would run as it. Then install
both units and enable the daemon; the unit runs `/usr/local/bin/shekyld`:

```bash
sudo cp contrib/packaging/linux/shekyl.sysusers /usr/lib/sysusers.d/shekyl.conf
sudo cp contrib/packaging/linux/shekyl.tmpfiles /usr/lib/tmpfiles.d/shekyl.conf
sudo systemd-sysusers shekyl.conf
sudo systemd-tmpfiles --create shekyl.conf
sudo cp contrib/packaging/linux/shekyld@.service \
  contrib/packaging/linux/shekyl.slice /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shekyld@testnet
```

The slice is the daemon's own
top-level control group, weighed 4:1 against `user.slice` under
contention, so a daemon that is syncing or verifying keeps about 80 % of
the CPU while a wallet in a user session serves archival shards beside
it (the wallet itself is never a system service). A daemon started by
hand runs in your session and has no slice, and it stops when your
session ends; the shipped unit passes `--service`, which marks the
machine's service instance.

On FreeBSD the release archive carries the daemon binary and an rc.d
script, `rc.d/shekyld` (in the tree at
`contrib/packaging/freebsd/shekyld`). The script runs
`/usr/local/bin/shekyld`, so install that binary from the archive, then
the script:

```bash
install -m 0555 shekyld /usr/local/bin/shekyld
pw useradd shekyl -d /nonexistent -s /usr/sbin/nologin -c "Shekyl daemon"
install -m 0555 rc.d/shekyld /usr/local/etc/rc.d/shekyld
sysrc shekyld_enable=YES
service shekyld start
```

`sysrc shekyld_args="--network testnet"` selects another network. The
script runs the daemon as `shekyl` with `--service`, creates
`/var/run/shekyl`, `/var/db/shekyl` and `/var/log/shekyl` before each
start, and restarts it 30 seconds after a failed exit. A clean stop
stays stopped. A refused start is a failed exit, so it is retried, and
the refusal is in syslog.

`--detach`, `--pidfile`, and the Windows `--*-service` flags were
removed in V3.1; the daemon now only runs in the foreground and is
supervised externally. The GUI wallet embeds `shekyld` as a Tauri
sidecar and does not require a separate service unit.

RPC is operator-to-operator. Restricted RPC is a view-only listener for
your own wallet, not a public remote node.

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

- RPC is operator-to-operator (a daemon you control). Restricted RPC is a
  view-only listener for *your* wallet, not a public remote node.
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
