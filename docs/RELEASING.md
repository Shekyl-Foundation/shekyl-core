# Releasing Shekyl

This document describes how to create a new Shekyl release.

## Prerequisites

- Push access to [Shekyl-Foundation/shekyl-core](https://github.com/Shekyl-Foundation/shekyl-core)
- All CI checks passing on `dev`
- Physical possession of the Shekyl Foundation release-signing hardware
  token (OpenPGP applet holding signing subkey `6914D74823DDA8DC`) and
  its Signature PIN. See `docs/SIGNING.md` for full key material and
  the signing ceremony.

### Build Dependencies

The CI workflows install all dependencies automatically. For local builds:

- **C++ toolchain**: GCC or Clang with C++17 support
- **Rust toolchain**: stable Rust via [rustup](https://rustup.rs/) (builds `libshekyl_ffi.a`)
- **CMake** >= 3.14 (required for `FetchContent`)
- **Google Test**: system `libgtest-dev` is preferred; if absent, CMake fetches GoogleTest v1.16.0 at configure time
- **Boost, OpenSSL, libunbound, libsodium** and other standard Monero-derived dependencies

## Branch Strategy

- **`dev`** -- continuous development and staging branch. All feature work,
  bug fixes, and CI improvements land here first.
- **`main`** -- protected release branch. Only receives merge commits from
  `dev` at release time. Tags are always created on `main`.

## Creating a Release

1. **Prepare the changelog on `dev`.** In `docs/CHANGELOG.md`, rename the
   `## Unreleased` section to `## [X.Y.Z] - YYYY-MM-DD` and add a fresh
   empty `## Unreleased` section above it. Commit on `dev`.

2. **Merge `dev` into `main`** with a merge commit to preserve branch
   topology and create a clear release boundary:

   ```bash
   git checkout main
   git merge --no-ff dev -m "release: merge dev for vX.Y.Z"
   ```

3. **Tag the release** on `main` with the Foundation institutional
   signing key, following the ceremony in `docs/SIGNING.md`
   (§"Release-tag signing ceremony"). The version is derived
   automatically from the tag name by CMake (see
   `cmake/GitVersion.cmake`), so there is no need to manually edit
   `src/version.cpp.in`.

   > **Version symbols:** The canonical C++ identifiers are
   > `SHEKYL_VERSION`, `SHEKYL_VERSION_TAG`, `SHEKYL_RELEASE_NAME`,
   > `SHEKYL_VERSION_FULL`, and `SHEKYL_VERSION_IS_RELEASE` (declared
   > in `src/version.h`, defined in the generated `version.cpp`).
   > Legacy `MONERO_*` macro aliases exist for backward compatibility
   > with upstream cherry-picks and will be removed after v4 RingPQC
   > stabilisation.

   Summary of the ceremony (see SIGNING.md for full checks and
   failure modes — this is a *summary*, not a substitute):

   ```bash
   # YubiKey inserted, then warm the GPG agent — DO NOT SKIP.
   # Without this, the first signing attempt fails with a
   # misleading "No secret key" error even when the card is plugged in.
   gpg --card-status

   # Sign with the Foundation release-signing subkey explicitly.
   # -u overrides git config user.signingkey for this single command,
   # so your personal commit-signing key stays configured for normal work.
   git tag -u 6914D74823DDA8DC -a -s v3.0.3-RC1 -m "Shekyl v3.0.3-RC1"

   # Verify BEFORE pushing. A wrong signer can still be undone locally.
   git verify-tag v3.0.3-RC1
   # Expected: "Good signature from 'Shekyl Foundation (Release Signing Key) ...'"
   # Expected: Primary key fingerprint F5F7 5A47 70C9 4FE1 D5A5 AE59 844E 424F 9866 4F44
   ```

   For pre-releases use a suffix: `v3.0.3-RC1`, `v3.1.0-alpha.5`,
   `v3.1.0-beta.1`, etc.

4. **Push the branch and tag.** CI triggers on tag push. Push the
   branch first so the tag commit is reachable:

   ```bash
   git push origin main
   git push origin v3.0.3-RC1
   ```

   > **Important:** The tag must point to a commit that is already on
   > the remote's `main` branch. Push the branch first, then the tag.

5. **(Optional) Bump the dev default** -- after tagging, update
   `SHEKYL_VERSION_DEFAULT` in `cmake/Version.cmake` to the next
   planned version so that un-tagged development builds show the
   correct series.

6. **Reverse-merge `main` into `dev`** so `dev` carries the release
   merge commit and its tag parent chain stays clean. Either a
   fast-forward (if `dev` hasn't moved) or a `--no-ff` reverse-merge
   PR (if it has) is acceptable.

7. **GitHub Actions takes over.** The `gitian` workflow automatically:
   - Builds reproducible, deterministic binaries for Linux (x86_64, aarch64,
     armhf, riscv64), Windows x64, macOS (x86_64, aarch64), and FreeBSD x86_64
     inside isolated Docker containers
   - Packages Linux x86_64 and aarch64 binaries as `.deb` and `.rpm`
   - Builds a Windows NSIS installer (`.exe`)
   - Creates a source archive with all submodules
   - Generates `SHA256SUMS` for all artifacts
   - Publishes everything as a GitHub Release

8. **Verify the release** at https://github.com/Shekyl-Foundation/shekyl-core/releases

## Tag Naming

- Release tags: `v3.0.3`, `v3.1.0`, `v4.0.0`
- Pre-release tags: `v3.0.3-RC1`, `v3.1.0-alpha`, `v3.1.0-beta`
- Tags containing `RC`, `alpha`, or `beta` are automatically marked as pre-releases

## Release Artifacts

Each release produces these files (all binaries are Gitian reproducible builds):

| File | Description |
|------|-------------|
| `shekyl-x86_64-linux-gnu-vX.Y.Z.tar.bz2` | Linux x86_64 binaries |
| `shekyl-aarch64-linux-gnu-vX.Y.Z.tar.bz2` | Linux ARM64 binaries |
| `shekyl-riscv64-linux-gnu-vX.Y.Z.tar.bz2` | Linux RISC-V 64-bit binaries |
| `shekyl_X.Y.Z_amd64.deb` | Debian/Ubuntu x86_64 package with systemd unit |
| `shekyl_X.Y.Z_arm64.deb` | Debian/Ubuntu ARM64 package with systemd unit |
| `shekyl-X.Y.Z-1.x86_64.rpm` | RPM x86_64 package for Fedora/RHEL/SUSE |
| `shekyl-X.Y.Z-1.aarch64.rpm` | RPM ARM64 package for Fedora/RHEL/SUSE |
| `shekyl-x86_64-w64-mingw32-vX.Y.Z.zip` | Windows x64 binaries (portable zip) |
| `shekyl-vX.Y.Z-win-x64-setup.exe` | Windows installer (NSIS) |
| `shekyl-x86_64-apple-darwin11-vX.Y.Z.tar.bz2` | macOS Intel binaries |
| `shekyl-aarch64-apple-darwin11-vX.Y.Z.tar.bz2` | macOS Apple Silicon binaries |
| `shekyl-x86_64-unknown-freebsd-vX.Y.Z.tar.bz2` | FreeBSD x86_64 binaries |
| `shekyl-vX.Y.Z-source.tar.gz` | Complete source with submodules |
| `SHA256SUMS` | Checksums for all artifacts |

## Linux Package Details

The `.deb` and `.rpm` packages are available for both x86_64 and ARM64:
- Install `shekyld`, `shekyl-cli`, and `shekyl-wallet-rpc` to `/usr/local/bin/`
- Include a systemd service unit for `shekyld`
- After install: `sudo systemctl enable --now shekyld`
- Data directory: `/var/lib/shekyl`
- Logs: systemd journal (`journalctl -u shekyld`)

## Windows Installer Details

The NSIS installer:
- Installs binaries to `Program Files\Shekyl`
- Optionally adds to system PATH
- Creates Start Menu shortcuts
- Registers a standard Windows uninstaller

## Gitian Deterministic Builds

The `gitian` workflow is the **sole release pipeline**. It runs automatically
on every tag push and produces reproducible builds for all platforms, then
packages and publishes the GitHub Release. It can also be triggered manually
via the GitHub Actions UI (`workflow_dispatch`), which allows overriding the
tag and repository URL -- useful for testing against a fork.

The pipeline has two phases:
1. **Build** -- 4 parallel Gitian jobs (Linux, Windows, macOS, FreeBSD)
   produce deterministic tarballs inside isolated Docker containers.
2. **Package & Publish** -- a lightweight job downloads the Gitian artifacts,
   creates `.deb`/`.rpm` packages and a Windows NSIS installer from the
   pre-built binaries, generates a source archive and `SHA256SUMS`, then
   publishes the GitHub Release.

Each Gitian build descriptor installs the Rust toolchain via `rustup` with
the appropriate cross-compilation targets (aarch64, RISC-V for Linux;
64-bit MinGW for Windows; Darwin targets for macOS). 32-bit targets were
permanently retired in v3.1.0-alpha.5 (Chore #3) on PQC constant-time
grounds — see `docs/CHANGELOG.md` entry "Retired 32-bit build targets".

### Re-running a Failed Gitian Build

If a tag needs to be moved (e.g. to include a last-minute fix):

```bash
git tag -d v3.0.3-RC1                              # delete local
git push origin :refs/tags/v3.0.3-RC1               # delete remote
gpg --card-status                                   # warm the agent
git tag -u 6914D74823DDA8DC -a -s v3.0.3-RC1 \
  -m "Shekyl v3.0.3-RC1"                           # recreate on HEAD, signed
git verify-tag v3.0.3-RC1                           # MUST pass before pushing
git push origin main && git push origin v3.0.3-RC1
```

Re-tagging goes through the same signing ceremony as a fresh release;
`docs/SIGNING.md` §"Release-tag signing ceremony" is the full procedure.

Or trigger manually from the Actions tab without retagging.

### Testing Against a Fork

```bash
# From the Actions tab, use "Run workflow" with:
#   tag: v3.0.3-RC1
#   repo_url: https://github.com/youruser/shekyl-core
```

## Future Platforms

- **macOS `.dmg` installer** -- native disk image with drag-to-Applications UX.
- **Linux AppImage** -- single-file portable binary for desktop distributions.
- **RISC-V 64-bit** is available via Gitian deterministic builds and may be
  promoted to the main release if demand warrants. 32-bit platforms are
  permanently out of scope on security grounds — see `docs/CHANGELOG.md`
  entry "Retired 32-bit build targets".
