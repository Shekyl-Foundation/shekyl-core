# Shekyl FCMP++

Implementation of
[the FCMP++ protocol composition](https://github.com/kayabaNerve/fcmp-plus-plus-paper)
for Shekyl. FCMP++ replaces per-input ring signatures (CLSAG) with a single
proof that spent outputs exist in the full UTXO set curve tree, providing
global anonymity set coverage.

This crate is the only proof system accepted by Shekyl consensus from
genesis (HF1). It is re-exported from `shekyl-oxide` as `fcmp::fcmp_pp`.

This library is usable under no-std when the `std` feature (on by default) is
disabled. `#![deny(unsafe_code)]` is enforced.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators`: Pre-computes curve generators at build time.
- `multisig`: Enables FROST-based threshold signing for FCMP++ proofs.
