# Versioning

This document is the authoritative versioning scheme for all Shekyl
repositories. It governs two independent version identifiers: the
**software version** (per-repo, follows SemVer) and the **protocol
version** (shared across all implementations, a single integer).

---

## Software version

Each repository versions independently using [SemVer 2.0](https://semver.org/):

```
MAJOR.MINOR.PATCH[-PRERELEASE]
```

| Component | Bumped when |
|-----------|-------------|
| MAJOR | Breaking change to the repo's external interface: RPC removal, CLI flag change, config format change, LMDB schema requiring resync, wallet file format change. |
| MINOR | Backward-compatible feature addition: new RPC endpoint, new CLI command, new wallet capability. |
| PATCH | Bug fix, performance improvement, or non-breaking internal change. |
| PRERELEASE | `alpha.N` / `beta.N` / `rc.N` (see below). |

MAJOR, MINOR, and PATCH are **not coupled across repos**. shekyl-core
may be at 3.2.7 while shekyl-gui-wallet is at 3.1.4. Each repo's version
describes that repo's artifact, nothing more.

### Pre-release stages

| Stage | Meaning | Entry condition |
|-------|---------|-----------------|
| `alpha.N` | Feature-incomplete, interfaces may change. Suitable for developer testing. | Feature branch merged to dev. |
| `beta.N` | Feature-complete, bugs expected. Suitable for stressnet and community testing. | All planned features merged; stressnet deployed. |
| `rc.N` | Release candidate. No known blocking issues. | Stressnet stable; audit findings addressed. |
| *(none)* | Stable release. | RC period elapsed without blocking findings. |

Pre-release identifiers use lowercase with dot-separated numeric
counters, per SemVer: `3.1.0-alpha.1 < 3.1.0-beta.1 < 3.1.0-rc.1 < 3.1.0`.

### Tag format

All repos use `v<software_version>`:

```
v3.1.0-alpha.1
v3.1.0-beta.2
v3.1.0-rc.1
v3.1.0
v3.2.0-alpha.1
```

Tags prior to this scheme (`v3.0.3-RC1`, `v0.4.0-beta.2`, etc.) used
inconsistent casing and separators. They are retained in git history for
archival but are non-canonical for SemVer ordering. Do not use old tags
as precedent for new tag naming.

---

## Protocol version

The protocol version is a **single integer** that identifies the
consensus rules, network handshake, and transaction format. It is
independent of any repo's software version and increments on its own
schedule.

```
protocol_version = 3
```

### Protocol version 3

FCMP++ curve tree membership proofs, hybrid Ed25519 + ML-DSA-65 spend
authorization, hybrid X25519 + ML-KEM-768 output encryption, V3.1
multisig wire format (FROST-style). Minimum transaction type:
`RCTTypeFcmpPlusPlusPqc`.

### Protocol version 4 (future)

Lattice-only threshold signatures, removing the classical Ed25519
component. Gated on NIST lattice threshold algorithm standardization.
Timeline: 12-24 months after protocol version 3 launch. See
`00-mission.mdc` for the V4 transition commitment.

### Where protocol_version lives in code

| Location | Purpose |
|----------|---------|
| `src/cryptonote_config.h` | `SHEKYL_PROTOCOL_VERSION` constant. Authoritative definition. |
| Daemon `--version` output | Prints `Shekyl vX.Y.Z (protocol 3)`. |
| `/get_info` RPC response | `protocol_version` field. |
| P2P handshake | Network peers exchange protocol versions during connection. |

---

## Compatibility declaration

Each repo declares what protocol version(s) it implements. This is the
user-facing source of truth for "can I use component X with component Y?"

| Software | Version | Protocol | Notes |
|----------|---------|----------|-------|
| shekyl-core | 3.1.0-alpha.1 | 3 | Reference implementation. |
| shekyl-gui-wallet | 3.1.0-alpha.1 | requires 3, refuses 4 | First release under aligned versioning. |

Update this table when shipping new versions. Third-party implementations
should declare their own protocol compatibility.

### Why the versions happen to match

For the initial alpha, both repos are at software version 3.1.0. This is
a coincidence of timing, not a coupling rule. The software MAJOR is 3
because the first public release ships with protocol 3 — there are no
prior stable releases to be backward-compatible with, so MAJOR starts at
3 rather than 1. Future software MAJOR bumps (breaking RPC changes,
schema migrations) will diverge from the protocol version.

---

## Version sources

### shekyl-core

| File | Field | Example |
|------|-------|---------|
| `cmake/Version.cmake` | `SHEKYL_VERSION_DEFAULT` | `"3.1.0"` |
| `cmake/GitVersion.cmake` | Tag-derived at build time | `"3.1.0-alpha.1"` |
| `src/version.cpp.in` | Configured by CMake | `SHEKYL_VERSION`, `SHEKYL_VERSION_TAG` |
| `src/cryptonote_config.h` | `SHEKYL_PROTOCOL_VERSION` | `3` |
| `rust/Cargo.toml` | `[workspace.package] version` | `"3.1.0"` |

### shekyl-gui-wallet

| File | Field | Example |
|------|-------|---------|
| `package.json` | `"version"` | `"3.1.0-alpha.1"` |
| `src-tauri/Cargo.toml` | `version` | `"3.1.0-alpha.1"` |
| `src-tauri/tauri.conf.json` | `"version"` | `"3.1.0-alpha.1"` |

### Consistency rule

All version sources within a repo must agree at tag time. CI should
assert this. Between tags, development builds use `git describe` output
and sources may temporarily diverge from the next planned version.

---

## Changelog conventions

Both repos maintain `docs/CHANGELOG.md` using
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
Unreleased changes accumulate under `## Unreleased`. When tagging a
release, the unreleased section is renamed to `## [X.Y.Z] - YYYY-MM-DD`
(or `## [X.Y.Z-alpha.N] - YYYY-MM-DD` for pre-releases).
