# Releasing Shekyl

This document describes how to create a new Shekyl release.

## Prerequisites

- Push access to [Shekyl-Foundation/shekyl-core](https://github.com/Shekyl-Foundation/shekyl-core)
- All changes merged to `main`

### Build Dependencies

The CI workflows install all dependencies automatically. For local builds:

- **C++ toolchain**: GCC or Clang with C++14 support
- **Rust toolchain**: stable Rust via [rustup](https://rustup.rs/) (builds `libshekyl_ffi.a`)
- **CMake** >= 3.14 (required for `FetchContent`)
- **Google Test**: system `libgtest-dev` is preferred; if absent, CMake fetches GoogleTest v1.16.0 at configure time
- **Boost, OpenSSL, ZeroMQ, libunbound, libsodium** and other standard Monero-derived dependencies

## Creating a Release

1. **Tag the release** from `main`.  The version is derived automatically from
   the tag name by CMake (see `cmake/GitVersion.cmake`), so there is no need
   to manually edit `src/version.cpp.in`.

   > **Version symbols:** The canonical C++ identifiers are `SHEKYL_VERSION`,
   > `SHEKYL_VERSION_TAG`, `SHEKYL_RELEASE_NAME`, `SHEKYL_VERSION_FULL`, and
   > `SHEKYL_VERSION_IS_RELEASE` (declared in `src/version.h`, defined in the
   > generated `version.cpp`).  Legacy `MONERO_*` macro aliases exist for
   > backward compatibility with upstream cherry-picks and will be removed
   > after v4 RingPQC stabilisation.

   ```bash
   git tag -a v3.0.2 -m "Shekyl v3.0.2"
   ```

   For pre-releases use a suffix: `v3.0.2-RC1`, `v3.0.2-alpha`, etc.

2. **Push the tag to all remotes.** CI triggers on tag push, so the tag must
   reach every remote that runs workflows. Push both the branch and the tag:

   ```bash
   # Push to the foundation repo (triggers release + gitian workflows)
   git push foundation main
   git push foundation v3.0.2

   # Mirror to the development origin
   git push origin ng
   git push origin v3.0.2
   ```

   > **Important:** The tag must point to a commit that is already on the
   > remote's default branch. Push the branch first, then the tag.

3. **(Optional) Bump the dev default** -- after tagging, update
   `SHEKYL_VERSION_DEFAULT` in `cmake/Version.cmake` to the next planned
   version so that un-tagged development builds show the correct series.

4. **GitHub Actions takes over.** The `release/tagged` and `gitian` workflows
   automatically:
   - Build static Linux x86_64 binaries
   - Cross-compile Windows x64 binaries via MinGW
   - Build Gitian deterministic binaries for Linux, Windows, macOS, Android,
     and FreeBSD (each including Rust toolchain setup)
   - Package Linux as `.tar.gz`, `.deb`, and `.rpm`
   - Package Windows as `.zip` and `.exe` installer (NSIS)
   - Generate `SHA256SUMS` for all artifacts
   - Publish everything as a GitHub Release

5. **Verify the release** at https://github.com/Shekyl-Foundation/shekyl-core/releases

## Tag Naming

- Release tags: `v3.0.2`, `v3.0.3`, `v3.1.0`
- Pre-release tags: `v3.0.2-RC1`, `v3.1.0-alpha`, `v3.1.0-beta`
- Tags containing `RC`, `alpha`, or `beta` are automatically marked as pre-releases

## Release Artifacts

Each release produces these files:

| File | Description |
|------|-------------|
| `shekyl-vX.Y.Z-linux-x86_64.tar.gz` | Linux binaries (portable static build) |
| `shekyl_X.Y.Z_amd64.deb` | Debian/Ubuntu package with systemd unit |
| `shekyl-X.Y.Z.x86_64.rpm` | RPM package for Fedora/RHEL/SUSE |
| `shekyl-vX.Y.Z-win-x64.zip` | Windows binaries (portable zip) |
| `shekyl-vX.Y.Z-win-x64-setup.exe` | Windows installer (NSIS) |
| `SHA256SUMS` | Checksums for all artifacts |

## Linux Package Details

The `.deb` and `.rpm` packages:
- Install `shekyld`, `shekyl-wallet-cli`, and `shekyl-wallet-rpc` to `/usr/local/bin/`
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

The `gitian` workflow runs automatically on every tag push and produces
reproducible builds for all platforms. It can also be triggered manually via
the GitHub Actions UI (`workflow_dispatch`), which allows overriding the tag
and repository URL -- useful for testing against a fork.

Each Gitian build descriptor installs the Rust toolchain via `rustup` with
the appropriate cross-compilation targets (ARM, aarch64, RISC-V for Linux;
MinGW targets for Windows; Darwin targets for macOS).

### Re-running a Failed Gitian Build

If a tag needs to be moved (e.g. to include a last-minute fix):

```bash
git tag -d v3.0.2-RC1                              # delete local
git push foundation :refs/tags/v3.0.2-RC1           # delete remote
git tag -a v3.0.2-RC1 -m "Shekyl v3.0.2-RC1"       # recreate on HEAD
git push foundation main && git push foundation v3.0.2-RC1
```

Or trigger manually from the Actions tab without retagging.

### Testing Against a Fork

```bash
# From the Actions tab, use "Run workflow" with:
#   tag: v3.0.2-RC1
#   repo_url: https://github.com/youruser/shekyl-core
```

## Future Platforms

macOS builds and native packages (`.dmg`) are planned for a future release.
