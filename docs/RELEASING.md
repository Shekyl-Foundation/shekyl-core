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

   ```bash
   git tag -a v3.0.2 -m "Shekyl v3.0.2"
   git push foundation v3.0.2
   ```

   For pre-releases use a suffix: `v3.0.2-RC1`, `v3.0.2-alpha`, etc.

2. **(Optional) Bump the dev default** -- after tagging, update
   `SHEKYL_VERSION_DEFAULT` in `cmake/Version.cmake` to the next planned
   version so that un-tagged development builds show the correct series.

3. **GitHub Actions takes over.** The `release/tagged` and `gitian` workflows automatically:
   - Builds static Linux x86_64 binaries
   - Cross-compiles Windows x64 binaries via MinGW
   - Packages Linux as `.tar.gz`, `.deb`, and `.rpm`
   - Packages Windows as `.zip` and `.exe` installer (NSIS)
   - Generates `SHA256SUMS` for all artifacts
   - Publishes everything as a GitHub Release

4. **Verify the release** at https://github.com/Shekyl-Foundation/shekyl-core/releases

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

## Future Platforms

macOS builds and native packages (`.dmg`) are planned for a future release.
