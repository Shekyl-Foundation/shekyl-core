# Post Quantum Cryptography (PQC)

> **Last updated:** 2026-04-10

## Purpose

This document is the canonical specification for Shekyl's post-quantum
cryptography rollout.

It defines:

- the reboot-only hybrid spend/ownership authorization model
- the hybrid signature algorithms and security goals
- the new transaction format used by the rebooted chain
- canonical serialization rules for hybrid key/signature material
- the exact payload to be signed and verified
- FFI ownership expectations between Rust and C++
- what is explicitly deferred until after signatures are stable

This document is source-of-truth for PQC-related implementation work in:

- `rust/shekyl-crypto-pq` — hybrid signatures, KEM, address encoding, per-output derivation
- `rust/shekyl-fcmp` — FCMP++ wrapper with 4-scalar PQC leaf
- `rust/shekyl-ffi` — C++ FFI bridge for all PQC and FCMP++ operations
- `src/cryptonote_basic`
- `src/cryptonote_core`
- `src/wallet`

## Reboot Assumption

Shekyl NG is treated as a rebooted chain with a new genesis block.

Implications:

- No long-term backward compatibility with legacy transaction authentication is
  required on the rebooted chain.
- We do not need a mixed old/new transaction regime after launch.
- The rebooted chain may require a single new transaction version from launch.
- Legacy chain data may still be used for snapshot/accounting purposes, but not
  as a consensus-validation obligation for the rebooted runtime.

## Security Goals

Shekyl's phase-1 PQC objective is hybrid protection of the
spend/ownership layer.

This is intentionally stronger than merely adding an extra transaction-wrapper
signature.

In scope for v3:

- make it materially harder for a future quantum attacker to steal funds
- preserve as much of the current privacy schema as practical
- augment the existing privacy machinery rather than replacing it outright

Achieved at genesis:

- FCMP++ replaces CLSAG for membership proofs; per-output PQC keys via
  hybrid KEM prevent transaction linkability
- `pqc_auths` (one entry per input) provides quantum-resistant spend authorization

The chain must remain secure if either:

- classical assumptions still hold and PQ assumptions fail, or
- PQ assumptions hold and classical assumptions fail

Therefore, spend authorization must use hybrid verification:

- Ed25519 signature must verify
- ML-DSA signature must verify
- the spend/ownership authorization path is valid only if both succeed

This is deliberately conservative. Hybrid mode increases size and complexity,
but it avoids betting the chain on a single transition-era primitive.

## Algorithm Choices

### Phase 1: Hybrid Spend/Ownership Protection

- Classical component: `Ed25519`
- PQ component: `ML-DSA-65`
- Security rule: hybrid authorization succeeds only if the classical and PQ
  components both verify

Rationale:

- Ed25519 is already familiar, compact, and easy to integrate.
- ML-DSA-65 targets NIST level 3 style security and is a reasonable transition
  choice for a public chain.
- The combination gives classical and PQ assurance during the migration period.

### Phase 2: KEM (Ships at Genesis)

KEM ships at genesis for per-output PQC key derivation. Each transaction
output receives a unique PQC keypair derived from a hybrid KEM exchange,
preventing transaction linkability.

- Classical component: unclamped Montgomery DH over Curve25519 (see
  "X25519 Binding to View Key" and "DH Semantics" below)
- PQ component: `ML-KEM-768` (NIST level 3)
- Combining rule: `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1", info = context_bytes)`
- ML-KEM ciphertexts are stored in `tx_extra` under tag `0x06`
  (`TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`), one per output (1088 bytes each).

See "Per-Output PQC Key Derivation" section below for the full flow.

### X25519 Binding to View Key

The recipient's X25519 public key is not transmitted in the address. It is
a **derived quantity**: the canonical Edwards→Montgomery image of the
Ed25519 view public key carried in the classical Bech32m segment. Any
conforming implementation MUST derive the X25519 public key via this map;
generating or transmitting an independent X25519 key produces incompatible
`combined_ss` values and breaks interoperability.

**Derivation (public side):**

```
x25519_pub = Edwards_to_Montgomery(view_pub)
           = u where u = (1 + y) / (1 - y) mod p
```

Where `y` is the y-coordinate of the compressed Edwards point `view_pub`,
and `p = 2^255 - 19`. The sign bit (bit 255 of the compressed encoding)
selects between `±x` on the Edwards curve; the Montgomery u-coordinate
depends only on `y`, so both sign variants produce the same `x25519_pub`.

**Derivation (secret side):**

```
x25519_sec = Scalar::from_bytes_mod_order(view_secret_key)
```

The Ed25519 view secret key bytes are interpreted directly as an unclamped
Montgomery scalar. No bit-clearing or bit-setting is applied. This scalar
is already reduced mod `ℓ` (the Ed25519 group order) by construction.

**Rejection rules (public side):**

A conforming implementation MUST reject the following inputs to the
Edwards→Montgomery conversion:

| Input | Reason |
|-------|--------|
| Non-canonical y (≥ p after masking sign bit) | `curve25519-dalek` silently reduces mod p; explicit canonicality check required |
| Decompression failure (y not on curve) | Not a valid Ed25519 point |
| Identity point (y = 1, maps to u = 0) | Montgomery identity; DH output is always zero regardless of scalar |
| u = 0 after conversion | Defense-in-depth; same as identity |

**Why the view key:**

The Ed25519 view public key is already present in every Shekyl address
(classical segment). Deriving X25519 from it adds zero bytes on the wire.
The derivation is the standard birational map used by age, Signal,
WireGuard, and (implicitly) Monero's own stealth-address ECDH. An observer
who knows the address can compute the X25519 public key — but they could
already read the view key, so no new information is revealed. The hybrid
property is preserved: if either X25519 or ML-KEM is secure, `combined_ss`
is secure. Forward secrecy against quantum attack comes from the ML-KEM
component, which is structurally unaffected.

**Implementation:**

- Rust: `shekyl-crypto-pq/src/montgomery.rs` (`ed25519_pk_to_x25519_pk`,
  `ed25519_sk_as_montgomery_scalar`, `is_low_order_montgomery`)
- FFI: `shekyl_view_pub_to_x25519_pub` in `shekyl-ffi`
- Test vectors: `docs/test_vectors/PQC_TEST_VECTOR_005_X25519_DERIVATION.json`

### DH Semantics

**This is not RFC 7748 X25519.** Shekyl's classical KEM component performs
Diffie-Hellman over the Montgomery curve Curve25519, but does NOT apply
RFC 7748 scalar clamping (clear bits 0, 1, 2 and 255; set bit 254).

The DH operation is:

```
shared_secret = scalar * MontgomeryPoint
```

Where `scalar` is either:
- **Sender (ephemeral):** `Scalar::from_bytes_mod_order(per_output_seed[0..32])`
- **Recipient (view key):** `Scalar::from_bytes_mod_order(view_secret_key)`

Both scalars are used as-is after `mod ℓ` reduction. Clamping is
incompatible with this design because the view secret key is an Ed25519
scalar already reduced mod `ℓ`; applying RFC 7748 clamping would mutate
it, producing a different scalar on the recipient side than the sender
used to derive the ephemeral shared secret.

**Low-order point rejection (mandatory recipient-side validation rule):**

Before performing DH, the recipient MUST reject low-order Montgomery
points on the ephemeral ciphertext input `kem_ct_x25519`:

```
if (Scalar::from(8) * MontgomeryPoint(kem_ct_x25519)).is_identity():
    reject  // CryptoError::LowOrderPoint
```

This check detects all points of order dividing 8 (the 12 low-order
points on Curve25519's Montgomery form: order 1, 2, 4, and 8). Without
this check, an attacker who publishes a low-order ephemeral point in
`tx_extra` can observe `view_scalar mod 8` (3 bits) through the
recipient's subsequent on-chain behavior. RFC 7748 clamping neutralizes
this by forcing `scalar ≡ 0 mod 8`; since Shekyl does not clamp, explicit
rejection replaces that defense.

On the sender side, the same check is applied as defense-in-depth on the
recipient's derived X25519 public key (to catch conversion bugs). This
check should never trigger for honestly-derived keys.

**Constant-time guarantee:** `curve25519-dalek`'s `Scalar * MontgomeryPoint`
is constant-time regardless of scalar value or point. The low-order check
uses `Scalar::from(8) * point` which is also constant-time.

**Rationale summary:**

| Property | RFC 7748 X25519 | Shekyl's DH |
|----------|----------------|-------------|
| Scalar source | Random 32 bytes, clamped | Ed25519 scalar, reduced mod ℓ, unclamped |
| Cofactor safety | Clamping forces scalar ≡ 0 mod 8 | Explicit low-order point rejection |
| Sender/receiver symmetry | Both clamp independently | Both use unreduced scalars; consistency follows from using the same derivation |
| Constant-time | Yes (per library) | Yes (per `curve25519-dalek`) |

## Curve Tower

FCMP++ membership proofs operate over a curve tower: Ed25519 → Helios → Selene.

The tower structure enables efficient recursive proof composition:

- **Ed25519**: The base curve for output keys, key images, and Pedersen
  commitments. All outputs in the UTXO set are points on Ed25519.
- **Helios**: An intermediate curve whose base field matches Ed25519's scalar
  field. Enables efficient arithmetic over Ed25519 scalars.
- **Selene**: A curve whose base field matches Helios's scalar field,
  completing the cycle back to Ed25519's base field.

The curve tree is a Merkle-like structure where:

- Leaves are 4-tuples of Ed25519 scalars: `{O.x, I.x, C.x, H(pqc_pk)}`
  (output key x-coordinate, key image x-coordinate, commitment x-coordinate,
  hash of PQC public key).
- Odd-level internal nodes are Helios hash commitments.
- Even-level internal nodes are Selene hash commitments.
- The root is committed in the block header as `curve_tree_root`.

The membership proof is classical (it operates over elliptic curves, not
lattice structures), but the overall scheme achieves quantum resistance through
the `H(pqc_pk)` leaf binding: even if an attacker could break the EC discrete
log problem, they cannot forge a valid per-input `pqc_auths[i]` signature without the
ML-DSA-65 secret key bound to the leaf. The FCMP++ proof demonstrates
membership; each `pqc_auths[i]` proves authorization for that input.

## Per-Output PQC Key Derivation

Each transaction output receives a unique PQC keypair to prevent transaction
linkability. KEM encapsulation is **deterministic** from the transaction key,
recipient public keys, and output index. This allows the sender to re-derive
`combined_ss` at proof time from `tx_key_secret` (stored in `m_tx_keys`)
and public data, without caching per-output shared secrets.

The derivation flow is:

1. **Sender** reads the recipient's ML-KEM-768 encapsulation key from the
   PQC segments of the Bech32m address and derives the recipient's X25519
   public key from the Ed25519 view public key in the classical segment
   (see §X25519 Binding to View Key).
2. **Derive deterministic per-output KEM seed:**
   ```
   fingerprint = SHA3-256(x25519_pk || ml_kem_ek)           // 32 bytes
   info        = fingerprint || output_index_le64            // 40 bytes
   per_output_seed = HKDF-SHA-512(
     ikm  = tx_key_secret,
     salt = "shekyl-output-kem-v1",
     info = info
   )                                                         // 64 bytes
   ```
   The first 32 bytes seed the X25519 ephemeral key; the last 32 bytes seed
   ML-KEM-768 encapsulation.
3. **Deterministic Montgomery DH** (see §DH Semantics — not RFC 7748):
   ```
   x25519_eph_scalar = Scalar::from_bytes_mod_order(per_output_seed[0..32])
   x25519_eph_pk     = x25519_eph_scalar * MONTGOMERY_BASEPOINT
   x25519_shared_secret = x25519_eph_scalar * recipient_x25519_pk
   ```
   Sender SHOULD reject `recipient_x25519_pk` if it is a low-order point
   (defense-in-depth; see §DH Semantics).
4. **Deterministic ML-KEM-768 encapsulation:**
   ```
   ml_kem_seed = per_output_seed[32..64]
   (ml_kem_shared_secret, ml_kem_ciphertext) = ML-KEM-768.EncapsFromSeed(recipient_ek, ml_kem_seed)
   ```
   `ml_kem_ciphertext` (1088 bytes) is stored in `tx_extra` tag `0x06`.
5. **Combined shared secret:**
   ```
   combined_ss = HKDF-SHA-512(
     ikm  = x25519_shared_secret || ml_kem_shared_secret,
     salt = "shekyl-kem-v1",
     info = ""
   )                                                         // 64 bytes
   ```
6. **Derive per-output secrets** from `combined_ss` (see HKDF Label Registry below).
7. **Derive per-output ML-DSA-65 keypair:**
   ```
   (pqc_pk, pqc_sk) = ML-DSA-65.KeyGen(seed = HKDF-Expand(combined_ss, "shekyl-pqc-output", 32))
   ```
8. **Commit** `H(pqc_pk)` as the 4th scalar in the curve tree leaf for this
   output.

The recipient reverses steps 3-7 using their ML-KEM-768 decapsulation key and
their Ed25519 view secret as the unclamped Montgomery scalar (see §DH
Semantics). The recipient MUST reject the sender's ephemeral X25519 public
key (`kem_ct_x25519`) if it is a low-order point, before performing DH.

For **coinbase transactions**, the miner self-encapsulates to their own
ML-KEM-768 key, ensuring per-output PQC uniqueness even for miner rewards.

### Proof Helpers

The sender can re-derive `combined_ss` at proof time without storing it:

- **`rederive_combined_ss(tx_key_secret, x25519_pk, ml_kem_ek, output_index)`**:
  Replays steps 2-5 above. Returns `(combined_ss, x25519_eph_pk, ml_kem_ct)`.
  The verifier compares `x25519_eph_pk` and `ml_kem_ct` against on-chain data
  for integrity.

- **`derive_proof_secrets(combined_ss, output_index)`**: Returns the proof
  secrets projection `ProofSecrets(ho, y, z, k_amount)`. This is the ONLY
  function that converts `combined_ss` into values that leave Rust in the
  proof path. TX proofs use all four fields; reserve proofs use `ho`, `y`,
  `k_amount` (z omitted from wire format per the HKDF binding argument).
  Does NOT return `ml_dsa_seed`, `ed25519_pqc_seed`, or `amount_tag`.

- **`derive_output_key(combined_ss, spend_key, output_index)`**: Computes
  `O = ho*G + B + y*T`. Validates `spend_key` is on the prime-order subgroup.

- **`recover_recipient_spend_pubkey(combined_ss, output_key, output_index)`**:
  Computes `B' = O - ho*G - y*T` for subaddress lookup. Validates the
  recovered point is prime-order and non-identity.

- **`decrypt_amount(combined_ss, enc_amount, amount_tag, output_index)`**:
  Decrypts the amount and verifies the `amount_tag`.

- **`compute_output_key_image(combined_ss, output_index, spend_secret, hp_of_O)`**:
  Derives `ho` internally and computes `I = x * Hp(O)` where `x = ho + b`.
  Returns both the key image and spend secret `x`. `Hp(O)` is provided by
  C++ via `hash_to_ec` (Category 2 Keccak, stays in C++).

- **`compute_output_key_image_from_ho(ho, spend_secret, hp_of_O)`**: Variant
  for the `tx_source_entry` boundary where `ho` has already been extracted.

### HKDF Label Registry

All per-output secrets are derived via HKDF-SHA-512. Three derivation contexts
exist: the KEM seed derivation (from `tx_key_secret`), the primary combined-SS
derivation (from `combined_ss`), and a secondary X25519-only derivation for
fast wallet scanning.

**KEM seed derivation (from tx_key_secret):**

| Secret | Salt | Info string | Output | Notes |
|--------|------|-------------|--------|-------|
| `per_output_seed` | `shekyl-output-kem-v1` | SHA3-256(x25519\_pk &#124;&#124; ml\_kem\_ek) &#124;&#124; index\_le64 | 64 B | First 32B = X25519 eph seed, last 32B = ML-KEM encaps seed |

- `fips203` is pinned to `=0.4.3` (exact) because `DummyRng::fill_bytes =
  unimplemented!()` pattern means a minor-version bump could panic at runtime.
- KAT vectors: `docs/test_vectors/KEM_DERIVE_V1_KAT.json`

**Primary derivation (combined shared secret):**

| Secret | Salt | Info string | Output | Reduction |
|--------|------|-------------|--------|-----------|
| `ho` (x-derivation) | `shekyl-output-derive-v1` | `shekyl-output-x` &#124;&#124; index\_le64 | 64 B | mod l (wide) |
| `y` (T-component) | `shekyl-output-derive-v1` | `shekyl-output-y` &#124;&#124; index\_le64 | 64 B | mod l (wide) |
| `z` (commitment mask) | `shekyl-output-derive-v1` | `shekyl-output-mask` &#124;&#124; index\_le64 | 64 B | mod l (wide) |
| `k_amount` | `shekyl-output-derive-v1` | `shekyl-output-amount-key` &#124;&#124; index\_le64 | 32 B | raw |
| `view_tag_combined` | `shekyl-output-derive-v1` | `shekyl-output-view-tag` &#124;&#124; index\_le64 | 1 B | first byte |
| `amount_tag` | `shekyl-output-derive-v1` | `shekyl-output-amount-tag` &#124;&#124; index\_le64 | 1 B | first byte |
| `ml_dsa_seed` | `shekyl-output-derive-v1` | `shekyl-pqc-output` &#124;&#124; index\_le64 | 32 B | raw |

**Secondary derivation (X25519 shared secret only, for fast scan):**

| Secret | Salt | Info string | Output | Reduction |
|--------|------|-------------|--------|-----------|
| `view_tag_x25519` | `shekyl-view-tag-x25519-v1` | `shekyl-view-tag` &#124;&#124; index\_le64 | 1 B | first byte |

- `index_le64` is the output index as a little-endian 8-byte integer.
- "wide reduce" means expanding 64 bytes via HKDF-Expand, then reducing
  mod Ed25519 scalar order `l` using `Scalar::from_bytes_mod_order_wide`.
- Test vectors: `docs/test_vectors/PQC_OUTPUT_SECRETS.json`
- Reference implementation: `tools/reference/derive_output_secrets.py`
- Rust implementation: `rust/shekyl-crypto-pq/src/derivation.rs`

### Security Properties of the Derivation

#### y == 0 Defense-in-Depth

The secret scalar `y` (T-component of the two-component output key `O = ho*G + B + y*T`)
must never be zero. If `y == 0`, the output key degenerates to the single-component form
`O = ho*G + B`, losing the security properties of the two-component construction.

**Defense stack:**

1. **Construction-time Rust assert** (`derivation.rs:223-224`):
   `assert!(y != [0u8; 32])` panics at output construction if HKDF produces a zero y
   scalar. This is `assert!`, not `debug_assert!` — Rust compiles it in all build
   profiles including release. Hard crash, not a debug-only check.

2. **Receiver-side independent verification**: `derive_output_secrets` is called by both
   `construct_output` (sender) and `scan_output` / `scan_output_recover` (receiver). The
   receiver independently hits the same `assert!(y != [0u8; 32])` on every scan. A
   malicious sender who bypassed their own assert (e.g., patched binary producing y=0
   outputs) would still trip the receiver's assert before the output is marked spendable.
   This is the closest thing to a "wire check" — the receiver re-derives y from the KEM
   shared secret and crashes if it's zero, preventing the degenerate output from entering
   the wallet's transfer set.

3. **Probabilistic impossibility**: `y` is derived from 64 bytes of HKDF-SHA-512 output
   reduced mod l (Ed25519 scalar order, ~2^{252.2}). The probability of the reduction
   yielding exactly zero is ~2^{-252}. This is computationally infeasible to trigger or
   exploit.

4. **Fuzz coverage**: All fuzz targets that exercise `construct_output` and
   `scan_output_recover` transitively call `derive_output_secrets`, hitting the assert
   with random inputs on both sender and receiver paths.

**Why a consensus-level y == 0 check is impossible**: `y` is a secret scalar derived from
`combined_ss`, which is only known to the sender and recipient. The on-chain output key
`O = ho*G + B + y*T` is an elliptic curve point — without the discrete log, a verifier
cannot extract `y` from `O`. The commitment `C = z*G + amount*H` does not involve `y`.
Therefore, no purely on-chain structural check for `y == 0` exists.

The consensus layer's `check_commitment_mask_valid` rejects `z == 0` and `z == 1` because
`z` controls the commitment mask which IS indirectly observable (trivial commitments are
distinguishable). The `y` scalar has no analogous on-chain observable effect. The defense
relies on both endpoints (sender and receiver) executing the same `derive_output_secrets`
code path, which is enforced by the protocol: the receiver must re-derive all secrets from
the KEM shared secret to decrypt the output.

#### Malformed KEM Ciphertext Handling

`scan_output_recover` fails closed on malformed ciphertexts through layered checks:

- **Structurally invalid** (wrong length, unparseable): Caught by length checks and
  `CipherText::try_from_bytes` → `Err(DecapsulationFailed)`.
- **Structurally valid but corrupted** (correct length, wrong content): ML-KEM-768 uses
  **implicit rejection** per FIPS 203 — `try_decaps` returns a pseudorandom shared secret
  (constant-time, no timing leak) rather than an error. This wrong SS propagates through
  HKDF and produces incorrect output secrets. Two downstream checks catch the mismatch:
  - `amount_tag` verification rejects ~99.6% (255/256) of corruptions cheaply before any
    point arithmetic. This is a **fast pre-filter**, not the soundness barrier.
  - `commitment` algebraic check `C == z*G + amount*H` is the **actual soundness barrier**.
    The wrong HKDF output produces a wrong `z` scalar and wrong `k_amount`. For the check
    to pass, the corrupted KEM ciphertext would need to produce a `combined_ss` that, after
    HKDF, yields the exact `(z, k_amount)` pair that satisfies the Pedersen commitment
    equation for the on-chain `C` — computationally infeasible.
  - `output_key` algebraic check `O == ho*G + B + y*T` (`scan_output` only) provides an
    independent second barrier using different HKDF-derived scalars (`ho`, `y`).

The 1-in-256 `amount_tag` pass-through is harmless: the commitment check closes it
unconditionally. An auditor should treat `amount_tag` as a performance optimization (avoids
two point multiplications on 255/256 of corruptions), not as a security gate.

No panics, no timing leaks, always returns `Err(CryptoError::...)`. Fuzz coverage:
`fuzz_scan_malformed_ct` exercises corrupted, truncated, and random ML-KEM ciphertexts
through the full scan path with a valid wallet KEM secret. Tests 1 and 4 preserve the
X25519 ephemeral key (ensuring the view-tag pre-filter matches) so the fuzzer reaches the
ML-KEM decapsulation and downstream algebraic checks. Test 3 corrupts the X25519 key to
separately exercise the view-tag rejection path.

#### View-Tag Pre-Filter

The X25519-only view tag (`derive_view_tag_x25519`) is a cheap O(1) pre-filter that
rejects ~255/256 of non-owned outputs before the expensive ML-KEM decapsulation. On a
view-tag match, the **full** verification chain runs without abbreviation:

1. Full ML-KEM-768 decapsulation
2. HKDF derivation of ALL output secrets (ho, y, z, k_amount, amount_tag, ml_dsa_seed)
3. Amount tag verification (probabilistic rejection)
4. Amount decryption
5. Output key / commitment algebraic verification
6. PQC keypair derivation

An attacker grinding view tags to match a victim's X25519 tag wastes only their own CPU.
Each successful tag match triggers the complete verification chain including two independent
algebraic checks. The view tag reveals no information beyond what the attacker already has
(the X25519 ephemeral key is on-chain).

**Independence of algebraic checks**: The two verification equations use different HKDF
labels and different scalar families:

- **Output key check**: `O == ho*G + B + y*T` uses `ho` (label `shekyl-output-x`) and
  `y` (label `shekyl-output-y`).
- **Commitment check**: `C == z*G + amount*H` uses `z` (label `shekyl-output-mask`) and
  `k_amount` (label `shekyl-output-amount-key`) for amount recovery.

An attacker who induced a collision on one set of HKDF labels (already computationally
infeasible against SHA-512) would gain zero advantage against the other check — the labels
produce independent pseudorandom outputs. This is not "two checks of the same thing" but
two structurally independent verification gates derived from disjoint key material.

#### Wallet Cache Version Gate (PR-wallet Requirement)

The wallet cache envelope (`cache_file_data`) currently has no pre-decryption version field.
When PR-wallet bumps the serialization version for two-component key support, old-format
wallets will decrypt successfully (same key derivation) but fail during deserialization with
a generic error.

**PR-wallet must add a plaintext `cache_format_version` to the `cache_file_data` envelope**,
checked before XChaCha20 decryption, to produce a clear error: "Wallet cache format too
old — delete cache and resync from seed."

**AAD binding (mandatory)**: The `cache_format_version` field is an unauthenticated plaintext
input. To prevent version-confusion attacks (an attacker flips the version byte on disk to
trigger a different decode path that happens to parse), the version byte MUST be included in
the XChaCha20-Poly1305 AAD (Additional Authenticated Data). On load, verify the version
before decryption, then include it in the AAD during decryption — if an attacker tampers
with the version, Poly1305 authentication fails. This is cheap to implement and prevents an
entire class of envelope manipulation bugs.

**Hard policy — no migration, resync only**: When the cache format version is too old, the
wallet refuses to load and instructs the user to delete the cache and resync from seed.
**There is no in-place migration path.** Migration code is a permanent attack surface for a
one-time problem. Since Shekyl starts at v3-from-genesis with no legacy user base carrying
forward years of wallet state, resync-from-seed is always correct and safe. PR-wallet must
not introduce migration logic. If a future hard fork requires a cache format bump, the same
delete-and-resync policy applies.

## Address Format

Shekyl uses a three-segment Bech32m encoding, where each segment stays
within Bech32m's proven checksum detection range (<1023 characters):

```
<classical_bech32m> / <pqc_a_bech32m> / <pqc_b_bech32m>
```

Example structure:
```
shekyl1<version 0x01><spend_key 32B><view_key 32B><checksum>
/skpq1<ml_kem_first_592B><checksum>
/skpq21<ml_kem_last_592B><checksum>
```

| Segment | HRP | Raw bytes | Bech32m chars (approx) |
|---|---|---|---|
| Classical | `shekyl` | 1 + 64 = 65 | ~113 |
| PQC-A | `skpq` | 592 | ~956 |
| PQC-B | `skpq2` | 592 | ~957 |
| **Total** | — | **1249** | **~2030** |

Design notes:

- The version byte (`0x01`) enables future address format upgrades (e.g.,
  compact addresses via on-chain KEM registration).
- The classical segment alone (`shekyl1...`) is sufficient for view-only
  wallets, human identification, and scanning infrastructure.
- The `/`-separated PQC segments carry the ML-KEM-768 encapsulation key
  (1184 bytes) needed for per-output PQC key derivation. The X25519 public
  key is **not** transmitted in the address; it is derived from the Ed25519
  view public key in the classical segment via the canonical
  Edwards→Montgomery map (see §X25519 Binding to View Key). This means the
  PQC segments carry ML-KEM material exclusively.
- The three-segment design ensures each individual Bech32m string stays
  within the proven error-detection range of the Bech32m checksum polynomial.
- Addresses are too long for QR codes at standard error correction levels.
  Wallets should support URI-based sharing and clipboard operations. A future
  compact address format (via on-chain KEM key registration) is planned to
  reduce the address to ~120 characters.
- Implementation: `rust/shekyl-crypto-pq/src/address.rs` (`ShekylAddress`
  type with `encode()`, `decode()`, `encode_classical_display()` methods).
  FFI: `shekyl_address_encode()`, `shekyl_address_decode()`.

## Why `tx_extra` Is Not Used

Hybrid spend/ownership material must not be stored in `tx_extra`.

Reasons:

1. `tx_extra` is already part of the serialized transaction prefix, so placing
   the signature there creates a self-reference problem.
2. Current `tx_extra` limits are too small for ML-DSA-sized payloads.
3. `tx_extra` is intended for auxiliary metadata, not primary spend/ownership
   authorization material.
4. A rebooted chain lets us adopt a cleaner structure directly instead of
   extending a path that was not designed for PQ-sized payloads.

`tx_extra` remains available for existing wallet-scanning and metadata uses,
but not for hybrid authorization material itself.

## Hybrid Model for v3

The v3 design is an augmentation strategy, not a full privacy rewrite.

The intended split is:

- existing privacy layer remains in place as much as practical
- spend/ownership authorization gains a hybrid classical + PQ layer
- transaction-level wrapper fields exist to carry and bind the hybrid
  authorization data, but they are not the main security boundary

In plain terms:

- FCMP++ replaces CLSAG entirely from genesis, providing full-chain
  membership proofs with complete UTXO-set anonymity
- `pqc_auths` remains the hybrid spend authorization layer, ensuring quantum
  resistance for ownership verification

## Ownership and Spend Authorization

Phase-1 requirement:

- hybrid keys/signatures must be tied to recipient ownership and spend
  authorization
- a detached transaction-wrapper signature alone is not sufficient

This means the PQ layer must answer the actual ownership question:

- who is authorized to spend this output?

not just the weaker authenticity question:

- who signed this serialized transaction blob?

### Practical v3 rule

For v3, Shekyl will preserve the existing privacy machinery where practical,
but the spend path must incorporate hybrid-controlled ownership material.

That is, the system must be designed so that breaking the classical side alone
is not enough to authorize a spend.

Exact binding details are still implementation work, but the design intent is
fixed:

- hybrid protection belongs to the spend/ownership layer
- transaction wrapper signatures only support that binding

### FCMP++ and PQC ownership binding

FCMP++ solves the anonymous per-input PQC ownership verification problem.
Each curve tree leaf contains 4 scalars: `{O.x, I.x, C.x, H(pqc_pk)}`.
The 4th scalar `H(pqc_pk)` is a hash of the output's PQC public key, proven
in-circuit during the FCMP++ membership proof. This binds PQC ownership to
the UTXO without revealing which output is being spent -- the full UTXO set
serves as the anonymity set.

The binding works as follows:

- When an output is created, the sender derives a per-output PQC keypair via
  hybrid KEM (X25519 + ML-KEM-768) and commits `H(pqc_pk)` as the 4th leaf
  scalar in the curve tree.
- When spending, the FCMP++ proof demonstrates that the referenced leaf
  (including its `H(pqc_pk)`) exists in the curve tree, without revealing
  which leaf.
- Each `pqc_auths[i]` entry then provides the hybrid Ed25519 + ML-DSA-65
  signature for that input, proving knowledge of the corresponding PQC secret key.
- An attacker cannot substitute a different PQC key because the in-circuit
  proof binds the leaf's `H(pqc_pk)` to the membership proof.

## Transaction Format

### Version

The rebooted chain introduces `TransactionV3` as the required user transaction
format.

High-level rule:

- user transactions on the rebooted chain use `version = 3`
- older user transaction formats are not accepted on the rebooted chain
- genesis coinbase remains a special case as usual

### Structure

`TransactionV3` keeps the existing CryptoNote-style prefix and FCMP++ body, but
adds a dedicated hybrid authorization structure outside `tx_extra`.

The FCMP++ type for user transactions is `RCTTypeFcmpPlusPlusPqc = 7`. This is
Shekyl's only non-coinbase RCT type. It replaces CLSAG ring signatures with
FCMP++ membership proofs, uses Bulletproof+ range proofs, and adds a
`referenceBlock` field to `rctSigBase` anchoring the proof to a specific curve
tree snapshot. The prunable section carries `curve_trees_tree_depth` and an
opaque `fcmp_pp_proof` blob instead of CLSAGs.

Coinbase transactions continue to use `RCTTypeNull = 0`.

Conceptually:

```text
TransactionV3 {
  prefix: TransactionPrefixV3
  rct_signatures: rctSig          // type = RCTTypeFcmpPlusPlusPqc (7)
  pqc_auths: std::vector<PqcAuthentication>   // one per input (pqc_auths.size() == vin.size())
}
```

Coinbase and block-level note:

- `pqc_auths` is required for user transactions (`vin[0] != txin_gen`) on the
  rebooted chain. Each input has its own `PqcAuthentication` entry
  (`pqc_auths.size() == vin.size()`).
- Miner transactions (coinbase) are explicitly excluded from `pqc_auths`
  serialization and verification. Coinbase KEM self-encapsulation ensures
  per-output PQC key uniqueness.
- Block construction includes a `curve_tree_root` consensus commitment in
  the block header.

Where:

```text
TransactionPrefixV3 {
  version
  unlock_time
  vin
  vout
  extra
}

PqcAuthentication {
  auth_version
  scheme_id
  flags
  hybrid_public_key
  hybrid_signature
}
```

### Field Semantics

- `auth_version`: version for the PQ authorization container
- `scheme_id`: identifies the hybrid scheme (see scheme registry below)
- `flags`: reserved for future optional features; must be zero in phase 1
- `hybrid_public_key`: canonical `HybridPublicKey` (Ed25519 pubkey || ML-DSA-65
  public key) binding spend/ownership authorization to hybrid verification
- `hybrid_signature`: dual signature over the canonical signing payload

### Scheme Registry

| `scheme_id` | Name | Status | Description |
|---|---|---|---|
| 0 | (reserved) | — | Invalid / unassigned |
| 1 | `ed25519_ml_dsa_65` | **Active (HF1)** | Single-signer hybrid spend authorization |
| 2 | `ed25519_ml_dsa_65_multisig` | **Active (HF1)** | M-of-N hybrid signature list; see `docs/PQC_MULTISIG.md` |
| 3 | `lattice_threshold_composite` | **Reserved (V4)** | Lattice-based composite threshold; see `docs/PQC_MULTISIG.md` |

For `scheme_id = 1`, the `PqcAuthentication` fields are as defined above.
For `scheme_id = 2`, the container is extended with signer count, threshold,
and arrays of keys/signatures. The canonical format is specified in
`docs/PQC_MULTISIG.md`.

## Canonical Serialization

### General Rules

Canonical encoding is mandatory. Equivalent semantic values must serialize to
exactly one byte representation.

Rules:

- all integer discriminator fields use little-endian fixed-width encoding unless
  otherwise specified
- variable-length binary blobs use `u32 length || bytes`
- no optional trailing fields in phase 1
- reserved bytes/flags must be zero
- unknown `scheme_id` values are invalid
- malformed lengths or oversized blobs are invalid

### Canonical Encoding: `HybridPublicKey`

Phase-1 encoding order:

```text
HybridPublicKey {
  u8  key_version
  u8  scheme_id
  u16 reserved
  u32 ed25519_len
  [ed25519_len] ed25519_bytes
  u32 ml_dsa_len
  [ml_dsa_len] ml_dsa_bytes
}
```

Phase-1 constraints:

- `key_version = 1`
- `scheme_id = 1` means `Ed25519 + ML-DSA-65`
- `reserved = 0`
- `ed25519_len = 32`
- `ml_dsa_len` must match the selected ML-DSA public key length exactly

### Canonical Encoding: `HybridSignature`

Phase-1 encoding order:

```text
HybridSignature {
  u8  sig_version
  u8  scheme_id
  u16 reserved
  u32 ed25519_sig_len
  [ed25519_sig_len] ed25519_sig_bytes
  u32 ml_dsa_sig_len
  [ml_dsa_sig_len] ml_dsa_sig_bytes
}
```

Phase-1 constraints:

- `sig_version = 1`
- `scheme_id = 1`
- `reserved = 0`
- `ed25519_sig_len = 64`
- `ml_dsa_sig_len` must match the selected ML-DSA signature length exactly

### Canonical Encoding: `PqcAuthentication`

```text
PqcAuthentication {
  u8  auth_version
  u8  scheme_id
  u16 flags
  HybridPublicKey ownership_key
  HybridSignature signature
}
```

Phase-1 constraints:

- `auth_version = 1`
- `scheme_id = 1`
- `flags = 0`

## Signed Payload Definition

The signature must not sign itself.

Therefore the signed payload is defined as:

```text
signed_payload =
  cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(RctSigningBody)
    || H(serialize(RctSigPrunable))
    || serialize(PqcAuthHeader)
    || H(pqc_pk_0) || H(pqc_pk_1) || ... || H(pqc_pk_{N-1})
  )
```

Where:

- `TransactionPrefixV3` is the full serialized transaction prefix, including
  `extra`
- `RctSigningBody` is the non-PQC FCMP++ body data required to bind the actual
  transaction economics, outputs, and spend semantics (see layout below)
- `H(serialize(RctSigPrunable))` is `cn_fast_hash` of the serialized prunable
  data (`fcmp_pp_proof`, `pseudoOuts`, `curve_trees_tree_depth`,
  `BulletproofPlus`), binding the signature to the FCMP++ proof
- `H(pqc_pk_i)` is `cn_fast_hash` of the `hybrid_public_key` blob for each
  input, binding each signature to all inputs' authorized PQC keys
- `PqcAuthHeader` is:

```text
PqcAuthHeader {
  auth_version
  scheme_id
  flags
  hybrid_public_key
}
```

### RctSigningBody Layout

`RctSigningBody` is the output of `rctSig.serialize_rctsig_base(ar, num_inputs, num_outputs)`.
It comprises the base (non-prunable) FCMP++ structure: type, message,
pseudoOuts/ecdhInfo as applicable, and `referenceBlock` (the block height
anchoring the FCMP++ curve tree snapshot, validated within `[tip - 100, tip - 2]`).
This is the same byte sequence used as the base RCT component in the v3
transaction hash calculation.

### Measured Sizes (Phase 1)

Measured from canonical serialization output in
`docs/PQC_TEST_VECTOR_001.json`:

- `HybridPublicKey` canonical bytes: `1996` bytes
- `HybridSignature` canonical bytes: `3385` bytes
- `PqcAuthentication` payload contribution (`u8,u8,u16` + key + signature):
  `4 + 1996 + 3385 = 5385` bytes

The measured values match the canonical field layout:

- `HybridPublicKey`: `1 + 1 + 2 + 4 + 32 + 4 + 1952 = 1996`
- `HybridSignature`: `1 + 1 + 2 + 4 + 64 + 4 + 3309 = 3385`

### Test Vectors (Phase 1)

Canonical vector material is published in:

- `docs/PQC_TEST_VECTOR_001.json`

The vector contains:

- fixed message bytes (`message_hex`)
- canonical encoded `HybridPublicKey`
- canonical encoded `HybridSignature`
- expected encoded lengths
- expected verify result (`true`)

The Rust crate validates this vector in
`rust/shekyl-crypto-pq/src/signature.rs` via
`documented_vector_verifies`, including a negative check with a tampered
message.

Importantly:

- `hybrid_signature` is excluded from the payload
- the ownership material is included in the payload to prevent substitution
- `extra` is still covered because it remains part of the prefix

## Verification Rule

For `TransactionV3`, validation succeeds only if all of the following succeed:

1. standard transaction structural checks
2. existing privacy-layer checks required for the chosen v3 scheme
3. canonical PQC field decoding
4. ownership/spend binding checks for the hybrid authorization material
5. `Ed25519.verify(signed_payload, ed25519_sig, ed25519_pub)`
6. `ML-DSA.verify(signed_payload, ml_dsa_sig, ml_dsa_pub)`

If either signature fails, the spend authorization is invalid.

## Wallet and Scanning Notes

The wallet must keep two ideas separate:

- transaction ownership/scanning data
- transaction wrapper/authentication data

Rules:

- stealth-address and tx pubkey scanning metadata can remain in `extra`
- hybrid authorization data lives in `pqc_auths`
- wallet construction must build the transaction body first, then compute the
  signed payload, then attach each input's hybrid signature in `pqc_auths[i]`
- wallet restore and scanning logic must not assume PQ keys replace one-time
  address derivation keys
- the wallet must not treat a detached hybrid signature as sufficient proof of
  spend authority on its own

PQC spend/ownership authorization works alongside the FCMP++ membership proof
layer. FCMP++ provides full-chain anonymity; `pqc_auths` provides quantum-resistant
spend authorization. Stealth addresses and one-time output derivation remain
part of the privacy stack.

## FFI Contract

Rust provides the cryptographic implementation. C++ remains the primary caller.

Phase-1 FFI must expose:

- hybrid key generation
- hybrid sign
- hybrid verify
- serialization helpers if needed by C++
- explicit free/release functions for any Rust-owned buffers

Ownership rules:

- caller-allocated input buffers are owned by the caller
- Rust-owned returned buffers must have matching free helpers
- secret-key buffers must be zeroized on drop/free
- verification APIs should prefer caller-supplied buffers and simple boolean or
  error-code returns

## Size and Bandwidth Considerations

Hybrid authorization materially increases transaction size.

Operational consequences:

- mempool pressure increases
- relay bandwidth increases
- RPC consumers must expect larger transaction payloads
- documentation and operator guidance must explicitly call this out

### v3 Privacy Boundary (Operator-Facing)

`TransactionV3` protection boundary is:

- **Protected by hybrid PQ auth**
  - per-input authorization metadata in `pqc_auths`
  - canonical payload hash over prefix + FCMP++ base + PQ auth header
  - dual verification requirement (`Ed25519 && ML-DSA-65`)
  - per-output PQC keys via hybrid KEM prevent transaction linkability
- **Classical (but full-chain anonymous)**
  - FCMP++ membership proof operates over classical elliptic curves
    (Ed25519 → Helios → Selene curve tower)
  - stealth addressing and one-time output derivation
  - full UTXO set serves as the anonymity set (no ring subset selection)
- **Quantum-resistant binding**
  - `H(pqc_pk)` in each curve tree leaf binds PQC ownership to the UTXO
  - even if EC discrete log is broken, the ML-DSA-65 authorization prevents
    unauthorized spending

Operationally: the FCMP++ EC membership proof provides full-chain anonymity
while `pqc_auths` provides quantum-resistant authorization. The combination
achieves both privacy and quantum resistance.

### v3 Rollout Notes

- `HF_VERSION_SHEKYL_NG` (`1`) gates `TransactionV3` validation behavior.
- Coinbase transactions have no `pqc_auths` entries (coinbase is not a v3 spend).
- Nodes, wallets, and indexers should budget for ~5.3KB extra auth material per
  user transaction (before other serialization overhead).
- RPC consumers should avoid rigid tx-size assumptions and update parser
  limits accordingly.

## V4 Roadmap

V3 (genesis) ships FCMP++ for full-chain membership proofs, hybrid PQ
spend authorization, and per-output PQC key derivation via KEM. The V4
roadmap focuses on incremental improvements to the cryptographic stack.

Shekyl uses a feature-driven upgrade policy: hard forks ship when the
feature is ready, not on a fixed calendar. See `docs/UPGRADE_POLICY.md`.

The V4 "lattice-based ring signature survey" originally planned under V4-A
through V4-D is **retired**. FCMP++ is the chosen anonymity primitive from
genesis, providing full-UTXO-set anonymity without ring subsets.

### V4-A: ML-KEM Algorithm Upgrades

Prerequisite: v3 mainnet stabilized; per-output KEM derivation confirmed
stable.

- Monitor NIST PQC standardization for ML-KEM parameter updates or
  replacement algorithms.
- Evaluate ML-KEM-1024 (NIST level 5) as a potential upgrade for
  higher-security deployments.
- Define migration path for address format changes if the encapsulation key
  size changes.
- Extend the `scheme_id` registry to accommodate upgraded KEM parameters.

### V4-B: Compact Address Format

Prerequisite: V4-A evaluation complete.

- Implement on-chain KEM key registration: users register their ML-KEM-768
  encapsulation key in a transaction, receiving a short registration index.
- Compact address format: `shekyl1:<version 0x02><classical 64B><registration_index>`
  (~120 characters total).
- Senders look up the full encapsulation key from the chain using the
  registration index.
- QR-code compatible at standard error correction levels.

### V4-C: Lattice Threshold Multisig

Prerequisite: V4-B or independent of address format work.

- Implement lattice-based composite threshold multisig (`scheme_id = 3`) per
  `docs/PQC_MULTISIG.md` V4 roadmap.
- DKG protocol implementation in Tauri wallet.
- Single compact on-chain signature regardless of M or N.
- Formal security review required before consensus activation.

### KEM Composition (Ships at Genesis)

The hybrid KEM combines:

- **Classical:** unclamped Montgomery DH over Curve25519 with the Ed25519
  view key (see §X25519 Binding to View Key and §DH Semantics)
- **Post-quantum:** `ML-KEM-768` (NIST level 3)
- **Combining rule:** `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1", info = context_bytes)`

The combined shared secret feeds into per-output PQC key derivation (see
§Per-Output PQC Key Derivation). ML-KEM ciphertexts (1088 bytes each) are
stored in `tx_extra` tag `0x06` (`TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`).

Implementation: `rust/shekyl-crypto-pq/src/kem.rs`

> **Invariant: `m_pqc_public_key` layout**
>
> `m_pqc_public_key` is exactly **1216 bytes**, laid out as:
>
> ```
> X25519_pub[0..32] || ML-KEM-768_ek[32..1216]
> ```
>
> `X25519_pub` is **derived, never transmitted**: it is the
> Edwards→Montgomery image of the Ed25519 view public key in the classical
> address segment. The canonical assemblers are `get_account_address_from_str`
> (address decode path) and `generate_pqc_key_material` (wallet keygen path).
> Code that splits `m_pqc_public_key` at byte 32 relies on this layout;
> runtime checks enforce `size == SHEKYL_PQC_PUBLIC_KEY_BYTES (1216)` at
> every split site.
>
> On the secret side, `m_pqc_secret_key[0..32]` is identical to
> `m_view_secret_key`. The wallet enforces this at load time and refuses to
> open on mismatch.

### Amount Encryption and Commitment Masks (HKDF Only)

All amount encryption and commitment mask derivation uses HKDF exclusively.
The legacy Keccak-based derivation path (`derivation_to_scalar` for amount
keys, `ecdhHash`/`genCommitmentMask` for commitment masks) has been fully
removed from construction, scanning, and signing paths.

- **Amount encryption**: `enc_amount = k_amount XOR d2h(amount)` where
  `k_amount` is derived via HKDF (label `shekyl-output-amount-key`).
- **Commitment masks**: `z` scalar derived via HKDF (label
  `shekyl-output-mask`). Used directly by the Rust BP+ prover.
- **Construction**: `construct_output` (Rust FFI) produces `enc_amount`,
  commitment, and `z` scalar. The C++ `construct_tx_with_tx_key` stores
  these in `v3_rct_data` and exports `z` scalars as `v3_commitment_masks`
  for the signing path.
- **Signing**: `shekyl_sign_fcmp_transaction` receives commitment masks
  directly; the C++ `proveRangeBulletproofPlus` function has been deleted.
  All BP+ proof generation occurs in Rust.
- **Scanning**: `shekyl_scan_and_recover` (Rust FFI) derives all output
  secrets from `combined_ss` via HKDF. No Keccak fallback exists.

## Deferred Scope

The following are explicitly deferred:

- PQ stealth-address redesign
- lattice-based composite threshold multisig (V4; see `docs/PQC_MULTISIG.md`)
- hardware wallet support details (targeted for v1.1)

### No Longer Deferred

- **Multisig under hybrid scheme:** V3 signature-list multisig (`scheme_id = 2`)
  is specified in `docs/PQC_MULTISIG.md` and ships with HF1. This uses the
  existing `Ed25519 + ML-DSA-65` primitives with no new cryptographic
  assumptions.

## Implementation Mapping

All Phase-1 (single-signer) and Phase-2 (multisig) items are implemented. This table serves as an index into the codebase for each layer:

| # | Layer | Status | Key files |
|---|-------|--------|-----------|
| 1 | Rust hybrid sign/verify | Done | `rust/shekyl-crypto-pq/src/signature.rs` |
| 2 | FFI ABI (keygen/sign/verify) | Done | `rust/shekyl-ffi/src/lib.rs`, `src/shekyl/shekyl_ffi.h` |
| 3 | TransactionV3 serialization | Done | `src/cryptonote_basic/cryptonote_basic.h` (`pqc_authentication`), boost serialization |
| 4 | Core verification | Done | `src/cryptonote_core/tx_pqc_verify.cpp`, `blockchain.cpp` |
| 5 | Wallet construction | Done | `src/cryptonote_core/cryptonote_tx_utils.cpp` (standard txs), `src/wallet/wallet2.cpp` (claim txs) |
| 6 | Documentation | Done | `docs/POST_QUANTUM_CRYPTOGRAPHY.md`, `docs/DOCUMENTATION_TODOS_AND_PQC.md`, `docs/CHANGELOG.md` |
| 7 | Rust multisig core (scheme_id=2) | Done | `rust/shekyl-crypto-pq/src/multisig.rs` |
| 8 | FFI scheme dispatch + multisig | Done | `rust/shekyl-ffi/src/lib.rs` (`shekyl_pqc_verify` with scheme_id, `shekyl_pqc_verify_debug`, `shekyl_pqc_multisig_group_id`) |
| 9 | Consensus verification + scheme downgrade | Done | `src/cryptonote_core/tx_pqc_verify.cpp` (size-format checks), FCMP++ `h_pqc` leaf binding (see `PQC_MULTISIG.md` Attack 1) |
| 10 | Wallet multisig coordination | Done | `src/wallet/wallet2.cpp` (group creation, file-based signing), `src/wallet/wallet2.h` |
| 11 | Fuzz testing (4 targets, 10M each) | Done | `rust/shekyl-crypto-pq/fuzz/fuzz_targets/`, `docs/PQC_TEST_VECTOR_002_MULTISIG.json` |
| 12 | FCMP++ FFI (prove/verify) | Done | `rust/shekyl-fcmp/`, `rust/shekyl-ffi/src/lib.rs` |
| 13 | Curve tree DB (grow/trim/root/path) | Done | `src/blockchain_db/`, `rust/shekyl-fcmp/` |
| 14 | Per-output KEM derivation | Done | `rust/shekyl-crypto-pq/src/kem.rs`, `rust/shekyl-crypto-pq/src/output.rs`, `rust/shekyl-crypto-pq/src/montgomery.rs`; wallet scanning via `shekyl_scan_and_recover` FFI, construction via `shekyl_construct_output` FFI; X25519 derived from Ed25519 view key via Edwards→Montgomery map |
| 15 | FCMP++ `check_tx_inputs` verification | Done (skeleton) | `src/cryptonote_core/blockchain.cpp`; see `docs/FCMP_PLUS_PLUS.md` |
| 16 | Per-input `pqc_auths` migration | Done | `src/cryptonote_basic/cryptonote_basic.h` (`pqc_authentication`), `src/cryptonote_core/tx_pqc_verify.cpp`; signing via `shekyl_sign_fcmp_transaction` FFI |
| 17 | Native Rust tx signing (`shekyl-tx-builder`) | Done | `rust/shekyl-tx-builder/` — BP+, FCMP++, PQC signing in pure Rust; CLI wallet uses `shekyl_sign_fcmp_transaction` FFI (collapsed signing), GUI uses `shekyl-wallet-rpc` `native-sign` feature |
| 18 | Proof FFI (tx proof + reserve proof) | Done | `rust/shekyl-proofs/` — outbound/inbound tx proofs, reserve proofs; `rust/shekyl-ffi/src/lib.rs` (6 proof FFI exports); `src/wallet/wallet2.cpp` callers collapsed to Rust FFI |

Notes:
- Staking and unstaking use `create_transactions_2` which routes through
  `construct_tx_with_tx_key` (PQC signing built in).
- Claim transactions use a dedicated PQC signing block in
  `create_claim_transaction`.
- Classical Monero-style multisig (secret-splitting, `make_multisig`) is
  removed from the rebooted chain. All multisig is PQC-only via
  `scheme_id = 2` — see `docs/PQC_MULTISIG.md`.
- The FCMP++ membership proof is constructed by the coordinator for multisig;
  pqc_auths provide M-of-N authorization per input.

## Open Items

The following still need final implementation confirmation, but this document
sets the intended direction:

- exact `scheme_id` registry values beyond those already assigned
  (`1 = ed25519_ml_dsa_65`, `2 = ed25519_ml_dsa_65_multisig`,
  `3 = lattice_threshold_composite` reserved for V4)

### Resolved Items

- **Rust crate for ML-DSA-65:** `fips204` crate (`ml_dsa_65` module).
- **`RctSigningBody` layout:** `rctSig.serialize_rctsig_base` output; used in
  the signing payload alongside prefix and PQ auth header.
- **Ownership binding:** `PqcAuthentication` is attached to `TransactionV3`;
  the signed payload covers prefix + RCT base + auth header (excluding the
  signature itself). Implemented in `tx_pqc_verify.cpp`.
- **Max transaction size:** Measured at 5,385 bytes per user tx for `pqc_auths`
  (see Measured Sizes above). Operator limits documented in
  `docs/V3_ROLLOUT.md` under "Payload Limit Guidance."
- **Multisig approach:** V3 uses signature-list (`scheme_id = 2`); lattice
  threshold deferred to V4. Full specification in `docs/PQC_MULTISIG.md`.

## Acceptance Criteria For This Spec

This document is complete enough to implement against when:

- `TransactionV3` field placement is no longer ambiguous
- canonical encoding is defined
- the signed payload excludes self-reference
- verification semantics require both classical and PQ success
- the design clearly places hybrid protection in the spend/ownership layer, not
  just a detached transaction-wrapper signature
- FFI ownership expectations are explicit
- deferred items are clearly listed so they do not creep into phase 1
