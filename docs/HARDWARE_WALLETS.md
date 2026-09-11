# Hardware Wallet Support

## V3 Status: Not Supported

Hardware wallet backends are not supported in Shekyl V3.

- **Trezor**: the inherited backend (`src/device_trezor/`, `tests/trezor/`,
  `cmake/CheckTrezor.cmake`) is **deleted** (2026-08-18, Phase-5 cutover).
  It was dead code under the V3 default — protobuf generation never ran and
  `protocol.cpp` carried a `#error` against accidental compilation — and
  Trezor firmware has no post-quantum support. **Reopen criterion**: Trezor
  ships firmware implementing the V4-roadmap primitives below; reintroduce
  the backend from the archive tags / Monero lineage rather than reviving
  the deleted tree wholesale, since the wallet stack it integrated against
  (`wallet2`) is also gone.
- **Ledger**: the dormant backend under `src/device/` remains in-tree,
  disabled. The CMake option `USE_HW_DEVICE` defaults to `OFF`.

### Rationale

Shekyl V3 introduces architectural changes that are incompatible with existing
hardware wallet firmware:

1. **Two-component output keys** (`O = x*G + y*T`): The output key derivation
   requires computing a scalar multiplication against the generator `T`, which
   existing Ledger and Trezor firmware does not support.

2. **KEM-derived secrets**: Output construction and scanning use a unified
   HKDF-SHA-512 derivation from a combined Montgomery DH + ML-KEM-768
   shared secret. The classical DH is **not** RFC 7748 X25519 (no scalar
   clamping); see `POST_QUANTUM_CRYPTOGRAPHY.md` §DH Semantics. Hardware
   devices would need to implement ML-KEM-768 encapsulation/decapsulation
   and unclamped Montgomery scalar multiplication, which requires firmware
   changes.

3. **ECDH removal**: The legacy `ecdhEncode`/`ecdhDecode` amount encryption
   protocol has been replaced by `enc_amounts` (direct XOR with an HKDF-derived
   amount key). The device virtual interface for ECDH encoding no longer exists.

4. **FCMP++ witness construction**: The 256-byte witness header written to the
   FCMP++ prover includes secrets (`x`, `y`, `z`, `a`) that the device would
   need to compute from the KEM shared secret. No device firmware implements
   this path.

### Build Behavior

- `USE_HW_DEVICE=OFF` (default): HIDAPI is not searched and Ledger sources are
  not compiled.

- `USE_DEVICE_LEDGER` in `src/device/device.hpp` defaults to `0` as a
  belt-and-suspenders guard even if `HAVE_HIDAPI` is somehow defined.

- The Trezor backend is deleted entirely (see above); there is no Trezor
  build arm. The `external/trezor-common` submodule was removed earlier for
  the same reason. Re-add both from the Trezor upstream if/when support
  returns (see V4 roadmap below).

### V4 Roadmap

Hardware wallet support may be revisited in V4 if there is demand and if device
manufacturers implement:

- ML-KEM-768 encapsulation/decapsulation
- Generator `T` scalar multiplication
- HKDF-SHA-512 expand with Shekyl-specific labels
- 256-byte FCMP++ witness header construction

Until then, Shekyl wallets run on general-purpose hardware only.
