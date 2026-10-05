# Shekyl FCMP++

Implementation of
[the FCMP++ protocol composition](https://github.com/kayabaNerve/fcmp-plus-plus-paper)
for Shekyl. FCMP++ replaces per-input ring signatures (CLSAG) with a single
proof that spent outputs exist in the full UTXO set curve tree; the proof is
zero-knowledge over that whole set. (Shekyl's transaction composition
identified the spent output anyway through the proof's public 4th-scalar
input until `PL-D3`, 2026-09-14, made the 4th scalar a hiding commitment
opened in-circuit — `PL-D1`, `docs/design/FCMP_SPEND_LINKABILITY.md`.)

This crate is the only proof system accepted by Shekyl consensus from
genesis (HF1). It is a first-party crate (relocated out of the vendored
`shekyl-oxide` tree in the un-vendor) and is wrapped by `shekyl-fcmp`.

This library is usable under no-std when the `std` feature (on by default) is
disabled. `#![deny(unsafe_code)]` is enforced.

### Cargo Features

- `std` (on by default): Enables `std` (and with it, more efficient internal
  implementations).
- `compile-time-generators`: Pre-computes curve generators at build time.
- `multisig`: Enables FROST-based threshold signing for FCMP++ proofs.
