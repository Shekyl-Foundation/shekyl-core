# Post Quantum Cryptography (PQC)

> **Last updated:** 2026-04-03

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
- pqc_auth provides quantum-resistant spend authorization per input

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

- Classical component: `X25519`
- PQ component: `ML-KEM-768` (NIST level 3)
- Combining rule: `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1", info = context_bytes)`
- ML-KEM ciphertexts are stored in `tx_extra` under tag `0x06`
  (`TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`), one per output (1088 bytes each).

See "Per-Output PQC Key Derivation" section below for the full flow.

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
log problem, they cannot forge a valid `pqc_auth` signature without the
ML-DSA-65 secret key bound to the leaf. The FCMP++ proof demonstrates
membership; the `pqc_auth` proves authorization.

## Per-Output PQC Key Derivation

Each transaction output receives a unique PQC keypair to prevent transaction
linkability. The derivation flow is:

1. **Sender** reads the recipient's ML-KEM-768 encapsulation key from their
   address (the PQC segment of the Bech32m address).
2. **Sender** performs ML-KEM-768 encapsulation, producing:
   - `ml_kem_ciphertext` (1088 bytes, stored in `tx_extra` tag `0x06`)
   - `ml_kem_shared_secret` (32 bytes)
3. **Sender** performs X25519 ECDH with the recipient's classical view key,
   producing `x25519_shared_secret` (32 bytes).
4. **Combined shared secret:**
   ```
   combined_ss = HKDF-SHA-512(
     ikm  = x25519_shared_secret || ml_kem_shared_secret,
     salt = "shekyl-kem-v1",
     info = output_index || tx_public_key
   )
   ```
5. **Derive per-output ML-DSA-65 keypair:**
   ```
   (pqc_pk, pqc_sk) = ML-DSA-65.KeyGen(seed = HKDF-Expand(combined_ss, "shekyl-pqc-output-key", 32))
   ```
6. **Commit** `H(pqc_pk)` as the 4th scalar in the curve tree leaf for this
   output.

The recipient reverses steps 2-5 using their ML-KEM-768 decapsulation key and
X25519 secret key to recover the per-output PQC keypair.

For **coinbase transactions**, the miner self-encapsulates to their own
ML-KEM-768 key, ensuring per-output PQC uniqueness even for miner rewards.

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
  needed for per-output PQC key derivation.
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
- pqc_auth remains the hybrid spend authorization layer, ensuring quantum
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
- The `pqc_auth` field then provides the actual hybrid Ed25519 + ML-DSA-65
  signature, proving knowledge of the corresponding PQC secret key.
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

`TransactionV3` keeps the existing CryptoNote-style prefix and RingCT body, but
adds a dedicated hybrid authorization structure outside `tx_extra`.

Conceptually:

```text
TransactionV3 {
  prefix: TransactionPrefixV3
  rct_signatures: rctSig
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
    || serialize(PqcAuthHeader)
  )
```

Where:

- `TransactionPrefixV3` is the full serialized transaction prefix, including
  `extra`
- `RctSigningBody` is the non-PQC RingCT body data required to bind the actual
  transaction economics, outputs, and spend semantics (see layout below)
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
It comprises the base (non-prunable) RingCT structure: type, message,
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
- hybrid authorization data lives in `pqc_auth`
- wallet construction must build the transaction body first, then compute the
  signed payload, then attach `pqc_auth.signature`
- wallet restore and scanning logic must not assume PQ keys replace one-time
  address derivation keys
- the wallet must not treat a detached hybrid signature as sufficient proof of
  spend authority on its own

PQC spend/ownership authorization works alongside the FCMP++ membership proof
layer. FCMP++ provides full-chain anonymity; pqc_auth provides quantum-resistant
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
- ZMQ/RPC consumers must expect larger transaction payloads
- documentation and operator guidance must explicitly call this out

### v3 Privacy Boundary (Operator-Facing)

`TransactionV3` protection boundary is:

- **Protected by hybrid PQ auth**
  - per-input authorization metadata in `pqc_auths`
  - canonical payload hash over prefix + RingCT base + PQ auth header
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
while pqc_auth provides quantum-resistant authorization. The combination
achieves both privacy and quantum resistance.

### v3 Rollout Notes

- `HF_VERSION_SHEKYL_NG` (`1`) gates `TransactionV3` validation behavior.
- Coinbase transactions remain excluded from `pqc_auth`.
- Nodes, wallets, and indexers should budget for ~5.3KB extra auth material per
  user transaction (before other serialization overhead).
- RPC/ZMQ consumers should avoid rigid tx-size assumptions and update parser
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

### KEM Composition (Implemented at Genesis)

The KEM combining rule is implemented and ships at genesis:

- Classical: `X25519`
- PQ: `ML-KEM-768` (NIST level 3)
- Combining: `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1", info = context_bytes)`
- The combined shared secret feeds into per-output PQC key derivation.
- ML-KEM ciphertexts stored in `tx_extra` tag `0x06`
  (`TX_EXTRA_TAG_PQC_KEM_CIPHERTEXT`).
- Implementation: `rust/shekyl-crypto-pq/src/kem.rs`

## Deferred Scope

The following are explicitly deferred:

- PQ stealth-address redesign
- mixed legacy/reboot transaction coexistence logic
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
| 9 | Consensus verification + scheme downgrade | Done | `src/cryptonote_core/tx_pqc_verify.cpp`, `src/cryptonote_basic/tx_extra.h` (`tx_extra_pqc_ownership`) |
| 10 | Wallet multisig coordination | Done | `src/wallet/wallet2.cpp` (group creation, file-based signing), `src/wallet/wallet2.h` |
| 11 | Fuzz testing (4 targets, 10M each) | Done | `rust/shekyl-crypto-pq/fuzz/fuzz_targets/`, `docs/PQC_TEST_VECTOR_002_MULTISIG.json` |
| 12 | FCMP++ FFI (prove/verify) | Planned | `rust/shekyl-fcmp/`, `rust/shekyl-ffi/src/lib.rs` |
| 13 | Curve tree DB (grow/trim/root/path) | Planned | `src/blockchain_db/`, `rust/shekyl-fcmp/` |
| 14 | Per-output KEM derivation | Planned | `rust/shekyl-crypto-pq/src/kem.rs`, `src/cryptonote_core/cryptonote_tx_utils.cpp` |

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
- **Max transaction size:** Measured at 5,385 bytes per user tx for `pqc_auth`
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
