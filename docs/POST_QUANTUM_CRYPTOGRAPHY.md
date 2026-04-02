# Post Quantum Cryptography (PQC)

> **Last updated:** 2026-04-01

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

- `rust/shekyl-crypto-pq`
- `rust/shekyl-ffi`
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

Out of scope for v3:

- full post-quantum replacement of RingCT / CLSAG / stealth addresses
- full post-quantum private transaction system

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

### Phase 2: KEM

KEM is deferred until transaction authentication is stable.

Planned direction:

- Classical component: `X25519`
- PQ component: `ML-KEM-768`

KEM is not consensus-critical in phase 1 and must not block signature rollout.

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

- we are not trying to fully replace RingCT/CLSAG in v3
- we are trying to make spending materially safer against plausible future
  quantum attacks while keeping the current privacy architecture mostly intact

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

### Privacy-preserving v3 boundary

The current RingCT / CLSAG stack does not give us a clean way to add
consensus-time, per-input PQ ownership verification without either:

- redesigning the anonymity machinery, or
- revealing or strongly hinting which ring member is real

For v3, Shekyl explicitly chooses to preserve the current ring privacy
properties.

Therefore phase-1 implementation work includes:

- making PQ key material first-class wallet/account/address state
- carrying the upgraded address/account format through wallet and operator flows
- adding transaction-format groundwork needed for later integration

And it explicitly does not include:

- consensus-critical anonymous per-input PQ ownership proofs
- any shortcut that materially degrades ring-member ambiguity

That deeper anonymous spend-binding problem is deferred to v4 alongside the
broader post-ECC privacy redesign.

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
  pqc_auth: PqcAuthentication
}
```

Coinbase and block-level note:

- `pqc_auth` is required for user transactions (`vin[0] != txin_gen`) on the
  rebooted chain.
- Miner transactions (coinbase) are explicitly excluded from `pqc_auth`
  serialization and verification.
- Block construction itself (`block_header`, `miner_tx`, `tx_hashes`) does not
  require structural changes for v3 PQC.

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
| 1 | `ed25519_ml_dsa_65` | **Active (HF17)** | Single-signer hybrid spend authorization |
| 2 | `ed25519_ml_dsa_65_multisig` | **Active (HF17)** | M-of-N hybrid signature list; see `docs/PQC_MULTISIG.md` |
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
It comprises the base (non-prunable) RingCT structure: type, message, mixRing
(or equivalent for the RCT variant), pseudoOuts/ecdhInfo as applicable.
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

PQC spend/ownership augmentation does not itself replace RingCT, stealth
addresses, CLSAG, or one-time output derivation in phase 1.

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

`TransactionV3` phase-1 protection boundary is:

- **Protected by hybrid PQ auth**
  - authorization metadata in `pqc_auth`
  - canonical payload hash over prefix + RingCT base + PQ auth header
  - dual verification requirement (`Ed25519 && ML-DSA-65`)
- **Still classical in phase 1**
  - ring anonymity machinery (`CLSAG`, RingCT internals)
  - stealth addressing and one-time output derivation
  - broader privacy assumptions of current CryptoNote stack

Operationally: v3 raises the cost of key-compromise style spend forgery under
future quantum pressure, but it is not yet a full PQ privacy rewrite.

### v3 Rollout Notes

- `HF_VERSION_SHEKYL_NG` (`17`) gates `TransactionV3` validation behavior.
- Coinbase transactions remain excluded from `pqc_auth`.
- Nodes, wallets, and indexers should budget for ~5.3KB extra auth material per
  user transaction (before other serialization overhead).
- RPC/ZMQ consumers should avoid rigid tx-size assumptions and update parser
  limits accordingly.

## V4 Privacy Roadmap (Tentative)

V3 protects the spend/ownership authorization layer with hybrid PQ
signatures. The ring anonymity machinery (CLSAG, RingCT, stealth addresses)
remains classical. V4 addresses this gap with a phased approach.

### V4-A: Research and Specification

Target: begin after v3 mainnet stabilization (~3 months post-launch).

- Survey candidate PQ-anonymous ownership primitives:
  - Lattice-based ring signatures (e.g. extensions of Esgin et al. 2019,
    Lyubashevsky et al. 2022).
  - PQ zero-knowledge proofs for membership/range (lattice-based Bulletproofs
    analogues, PQ SNARKs/STARKs).
  - Hybrid classical+PQ ring constructions that preserve existing anonymity set
    sizes.
- Evaluate ML-KEM-768 for PQ stealth address derivation:
  - Combining rule: `shared_secret = KDF(X25519_ss || ML-KEM_ss)` using
    `HKDF-SHA-512` with a domain-separated info string.
  - Must not break one-time address unlinkability.
- Define a formal threat model update that covers:
  - Quantum adversary with selective ring-member de-anonymization capability.
  - Harvest-now-decrypt-later attacks against stealth address material.
  - Timing/size side channels introduced by PQ primitives.
- Extend the `scheme_id` registry to accommodate new hybrid schemes.
- Deliverable: published V4 specification draft in `docs/`.

### V4-B: Prototype

Target: ~6 months post-launch.

- Implement candidate primitives as non-consensus Rust crates under
  `rust/shekyl-crypto-pq-v4/`.
- Implement lattice-based composite threshold multisig prototype
  (`scheme_id = 3`) per `docs/PQC_MULTISIG.md` V4 roadmap.
- Benchmark transaction size, verification time, and memory usage against
  v3 baseline.
- Size budget target: total v4 transaction should not exceed 2x the v3 size
  for equivalent ring size.
- Deliverable: benchmark report and prototype crate with test vectors.

### V4-C: Testnet Experiment

Target: ~9-12 months post-launch.

- Feature-gate v4 transaction format behind a testnet-only hard fork version.
- Run privacy regression tests: verify that ring-member ambiguity is not
  degraded vs v3.
- Measure anonymity-network impact (Tor/I2P cell counts, burst patterns).
- Identify any consensus-rule changes required for v4 activation.
- Deliverable: testnet running v4 transactions; go/no-go report for mainnet.

### V4-D: Activation

Target: ~12-18 months post-launch (dependent on V4-C results).

- Single hard fork activation height (same pattern as HF17).
- Migration notes for wallets, indexers, and operators.
- v3 transactions remain valid; v4 is opt-in initially, mandatory after a
  grace period.

### Pre-V4 Dependency: KEM Composition

Before V4-A can finalize stealth-address PQ protection, the KEM combining
rule must be decided. The current placeholder is in `rust/shekyl-crypto-pq/src/kem.rs`.

Planned direction:

- Classical: `X25519`
- PQ: `ML-KEM-768` (NIST level 3)
- Combining: `HKDF-SHA-512(ikm = X25519_ss || ML-KEM_ss, salt = "shekyl-kem-v1", info = context_bytes)`
- The combined shared secret feeds into one-time address derivation, replacing
  the current `X25519`-only path.
- KEM must be implemented and tested in `shekyl-crypto-pq` before V4-A spec
  work begins.

## Deferred Scope

The following are explicitly deferred until after phase-1 hybrid spend/ownership
protection is stable:

- KEM in consensus-critical transaction validation
- PQ replacement of RingCT primitives
- PQ stealth-address redesign
- mixed legacy/reboot transaction coexistence logic
- lattice-based composite threshold multisig (V4; see `docs/PQC_MULTISIG.md`)
- hardware wallet support details

### No Longer Deferred

- **Multisig under hybrid scheme:** V3 signature-list multisig (`scheme_id = 2`)
  is specified in `docs/PQC_MULTISIG.md` and ships with HF17. This uses the
  existing `Ed25519 + ML-DSA-65` primitives with no new cryptographic
  assumptions.

## Implementation Mapping

All Phase-1 items are implemented. This table serves as an index into the
codebase for each layer:

| # | Layer | Status | Key files |
|---|-------|--------|-----------|
| 1 | Rust hybrid sign/verify | Done | `rust/shekyl-crypto-pq/src/signature.rs` |
| 2 | FFI ABI (keygen/sign/verify) | Done | `rust/shekyl-ffi/src/lib.rs`, `src/shekyl/shekyl_ffi.h` |
| 3 | TransactionV3 serialization | Done | `src/cryptonote_basic/cryptonote_basic.h` (`pqc_authentication`), boost serialization |
| 4 | Core verification | Done | `src/cryptonote_core/tx_pqc_verify.cpp`, `blockchain.cpp` |
| 5 | Wallet construction | Done | `src/cryptonote_core/cryptonote_tx_utils.cpp` (standard txs), `src/wallet/wallet2.cpp` (claim txs) |
| 6 | Documentation | Done | `docs/POST_QUANTUM_CRYPTOGRAPHY.md`, `docs/DOCUMENTATION_TODOS_AND_PQC.md`, `docs/CHANGELOG.md` |

Notes:
- Staking and unstaking use `create_transactions_2` which routes through
  `construct_tx_with_tx_key` (PQC signing built in).
- Claim transactions use a dedicated PQC signing block in
  `create_claim_transaction`.
- Classical Monero-style multisig (secret-splitting, `make_multisig`) is
  removed from the rebooted chain. All multisig is PQC-only via
  `scheme_id = 2` — see `docs/PQC_MULTISIG.md`.
- The CLSAG/RingCT layer always uses a single classical key for multisig
  transactions. M-of-N authorization lives entirely in the `pqc_auth` layer.

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
