# Hardware Wallet Support

## V3 Status: Not Supported

Hardware wallet backends (Ledger and Trezor) are **disabled by default** in Shekyl V3.
The CMake option `USE_HW_DEVICE` defaults to `OFF`.

### Rationale

Shekyl V3 introduces architectural changes that are incompatible with existing
hardware wallet firmware:

1. **Two-component output keys** (`O = x*G + y*T`): The output key derivation
   requires computing a scalar multiplication against the generator `T`, which
   existing Ledger and Trezor firmware does not support.

2. **KEM-derived secrets**: Output construction and scanning use a unified
   HKDF-SHA-512 derivation from a combined X25519 + ML-KEM-768 shared secret.
   Hardware devices would need to implement ML-KEM-768 encapsulation and
   decapsulation, which requires firmware changes.

3. **ECDH removal**: The legacy `ecdhEncode`/`ecdhDecode` amount encryption
   protocol has been replaced by `enc_amounts` (direct XOR with an HKDF-derived
   amount key). The device virtual interface for ECDH encoding no longer exists.

4. **FCMP++ witness construction**: The 256-byte witness header written to the
   FCMP++ prover includes secrets (`x`, `y`, `z`, `a`) that the device would
   need to compute from the KEM shared secret. No device firmware implements
   this path.

### Build Behavior

- `USE_HW_DEVICE=OFF` (default): HIDAPI is not searched, Ledger sources are not
  compiled, Trezor protobuf generation is skipped, `protocol.cpp` is excluded
  from the build.

- `USE_DEVICE_LEDGER` in `src/device/device.hpp` defaults to `0` as a
  belt-and-suspenders guard even if `HAVE_HIDAPI` is somehow defined.

- `protocol.cpp` contains a `#error` that fires if `DEVICE_TREZOR_READY` is
  defined, preventing accidental Trezor compilation without firmware support.

### V4 Roadmap

Hardware wallet support may be revisited in V4 if there is demand and if device
manufacturers implement:

- ML-KEM-768 encapsulation/decapsulation
- Generator `T` scalar multiplication
- HKDF-SHA-512 expand with Shekyl-specific labels
- 256-byte FCMP++ witness header construction

Until then, Shekyl wallets run on general-purpose hardware only.
