# shekyl-oxide (Shekyl fork)

A modern transaction library for the Shekyl protocol (forked from Monero).
Provides Rust-native types and serialization for the FCMP++ proof system,
Bulletproof+ range proofs, and the full Shekyl transaction format.

This library is usable under no-std when the `std` feature (on by default) is
disabled.

Recommended usage of the library is with `overflow-checks = true`, even for
release builds.

### Shekyl Differences from Upstream

- **FCMP++ support**: `ProofType::FcmpPlusPlusPqc` (wire value 7) with full
  serialization round-trip for the new proof type.
- **No legacy proof types**: MLSAG, Borromean, CLSAG, and legacy Bulletproofs
  have been completely removed. Only FCMP++ with Bulletproof+ is supported.
- **No legacy Monero chain**: Shekyl starts at HF1 with a fresh genesis.
  v1 (CryptoNote) transactions are rejected outright.
- **Post-quantum readiness**: `PrunableProof` includes per-input PQC
  authentication signatures (ML-DSA-65 blobs).
- **`#![deny(unsafe_code)]`**: Enforced crate-wide.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators` (on by default): Derives the generators at
  compile-time so they don't need to be derived at runtime. This is recommended
  if program size doesn't need to be kept minimal.
- `multisig`: Enables the `multisig` feature for all dependencies.
