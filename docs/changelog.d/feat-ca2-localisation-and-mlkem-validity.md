- **`CA-2`'s localisation runs and ML-KEM's validity gap are registered.** The dynamic constant-time crate gains three things:
  - a fat-LTO profile (`release-lto`) for timing the halves of a `HelioseleneField` square inlined;
  - `Field25519` rows whose Montgomery residue is sparse, which tell the multiplier path from `red512`;
  - rows timing `subtle`'s `ct_ne` over a 1,088-byte ML-KEM ciphertext, equal against random and against one bit flipped.

  The registration (`docs/formal/checkct/results/2026-11-21/ca2-localisation-registration.md`) names the lines, the devices, the order and the core controls. Those include RT-P4's validity comparisons on other silicon, under DOITM and a pinned clock, and the floor device's prediction.
