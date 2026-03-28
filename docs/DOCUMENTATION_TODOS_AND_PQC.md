# Documentation TODOs and PQC Implementation Status

This document consolidates key TODOs identified across Shekyl documentation and outlines the current state and next steps for Post-Quantum Cryptography (PQC) implementation.

---

## 1) Key TODOs from Existing Documentation

### 1.1 GENESIS_TRANSPARENCY.md (formerly referenced as GENESIS_STRATEGY.md)

| Item | Description |
|------|-------------|
| **Emission Economics (TODO)** | Original Shekyl `MONEY_SUPPLY` (2^32 in atomic units with 12 decimals) yields ~0.004 coins. Needs redesign before mainnet: reduce decimals (e.g. 8), choose different supply, or redesign emission curve. Currently using upstream default supply for testnet. |
| **Snapshot / UTXO** | Locate and extract original Shekyl UTXO set; implement snapshot restoration logic (Phase 2); mainnet launch after full testing. |
| **PQC transaction format** | Post-genesis blocks use a reboot-only hybrid PQ spend/ownership format with dedicated authorization fields — defined in `POST_QUANTUM_CRYPTOGRAPHY.md`; v3 tx format, core validation, and wallet construction are implemented. |

### 1.2 DESIGN_CONCEPTS.md

| Item | Description |
|------|-------------|
| **Provisional parameters** | `tx_baseline` (50) and `FINAL_SUBSIDY_PER_MINUTE` (300,000,000) are provisionally locked after 8-scenario simulation sweep (`rust/shekyl-economics-sim`); final confirmation from testnet. |
| **Simulation scenarios** | All eight scenarios implemented and run in `rust/shekyl-economics-sim/`; results in `docs/economics_sim_results.json`. |
| **Test coverage** | Design doc calls for unit/property/integration tests for reward curve, burn formula, staker distribution, overflow boundaries, pre/post-fork sync. |

### 1.3 COMPILING_DEBUGGING_TESTING.md

| Item | Description |
|------|-------------|
| **To be done (and merged)** | References external upstream PRs: multihost parallel compilation (#7160), faster core_tests with caching (#5821), precompiled headers (#7216), unity builds (#7217). Shekyl may adopt or reimplement as needed. |

### 1.4 LEVIN_PROTOCOL.md

| Item | Description |
|------|-------------|
| **Wire data inventory** | "This document does not currently list all data being sent by the Shekyl protocol, that portion is a work-in-progress." Completing this helps anonymity and DPI analysis. |

### 1.5 ANONYMITY_NETWORKS.md

| Item | Description |
|------|-------------|
| **Future mitigations** | Random offset for peer timed sync on anonymity networks; peers that receive tx over anonymity network delay broadcast to public peers by randomized amount; careful disconnect/reconnect strategy to avoid linking. |
| **I2P/Tor stream reuse** | Document notes that rotating circuits / disconnecting occasionally should be done carefully — implementation work remains. |

### 1.6 RELEASE_CHECKLIST.md

| Item | Description |
|------|-------------|
| **Full checklist** | Security audit, code audit, Ledger/Trezor integration, fork height and announcements, wallet/exchange/pool notifications, release tagging, testnet fork and testing, reproducible builds, CLI/GUI release, announcements. All items are unchecked; use Shekyl-specific resources and project website/channels. |

### 1.7 SEEDS_SETUP.md

| Item | Description |
|------|-------------|
| **Current gaps** | Public DNS seed list empty; fallback IP seed lists are placeholders; some docs/config still use legacy naming; seed operations under-documented for end users. |
| **Runtime seed add** | Adding new seed nodes/peers at runtime via daemon command is not currently documented/implemented. |

### 1.8 CONTRIBUTING.md / README.i18n.md

| Item | Description |
|------|-------------|
| **Shekyl-specific** | CONTRIBUTING and i18n docs have been updated to reference Shekyl maintainers, project channels, and binary names (e.g. `shekyl-wallet-cli`). |

### 1.9 Other docs (ZMQ, PORTABLE_STORAGE, INSTALLATION_GUIDE, PUBLIC_NARRATIVE_FAQ)

- **ZMQ.md**: No explicit TODOs; describes current/future ZMQ status in Shekyl; note any differences from upstream if relevant.
- **PORTABLE_STORAGE.md**: No TODOs; reference doc.
- **INSTALLATION_GUIDE.md**: Shekyl-native; no critical TODOs.
- **PUBLIC_NARRATIVE_FAQ.md**: Narrative/positioning; no technical TODOs.

### 1.10 Economics and PoW modularization status

| Item | Description |
|------|-------------|
| **Economics chain-state wiring** | `tx_volume_avg` is now computed from recent chain history and passed into miner template construction, tx pool block-reward estimation, and miner reward validation. `circulating_supply` is sourced from `already_generated_coins`; `stake_ratio` is now computed from chain-state scanning of locked `txout_to_staked_key` outputs. |
| **Modular PoW schema** | PoW hashing now routes through a schema interface and registry (`IPowSchema`, RandomX schema, Cryptonight schema) while preserving historic behavior (`major_version >= RX_BLOCK_VERSION` => RandomX; older => Cryptonight variants). |
| **Follow-up TODO** | Add configuration-driven PoW activation policy and expand test coverage for schema-selection parity against legacy `get_block_longhash` behavior. |

---

## 2) What Is Documented for PQC

### 2.1 Project rules (.cursor/rules/privacy-security.mdc)

- **Priority**: Quantum resistance is priority #1; classical security #2; privacy #3.
- **Standards**: Prefer NIST PQC finalized standards: **ML-DSA**, **ML-KEM**, **SLH-DSA**.
- **Transition**: Prefer **hybrid** constructions (e.g. Ed25519 + ML-DSA) during transition.
- **Requirements**: No new crypto without quantum security evaluation; constant-time/side-channel resistance; no key material in logs or error messages.

### 2.2 Genesis strategy (docs/GENESIS_TRANSPARENCY.md)

- The rebooted chain is planned to use a single PQ-enabled transaction format from launch.
- Legacy transaction coexistence is no longer a requirement on the rebooted runtime.

### 2.3 Code: `rust/shekyl-crypto-pq`

- **Purpose**: Post-quantum primitives for Shekyl (ML-DSA, ML-KEM, hybrid signatures).
- **Design**:
  - **Signatures**: Hybrid `Ed25519 + ML-DSA-65`; both must verify.
  - **KEM**: Hybrid `X25519 + ML-KEM-768` remains deferred until a concrete protocol use is specified.
- **Types**: `HybridPublicKey`, `HybridSecretKey`, `HybridSignature`; `HybridKemPublicKey`, `HybridKemSecretKey`, `HybridCiphertext`, `SharedSecret`.
- **Status**: Hybrid signature support is implemented with canonical serialization helpers and tests. KEM remains present only as deferred future work.
- **Integration**: Signature operations are exposed via `shekyl-ffi`; wallet/core spend-binding integration in the C++ path is still in progress.

### 2.4 Gaps in PQC documentation

- Dedicated PQC design doc now exists: `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.
- Remaining work: keep the PQC spec aligned with implementation as code lands.
- Exact measured encoded sizes and a publishable vector are now documented (`docs/POST_QUANTUM_CRYPTOGRAPHY.md`, `docs/PQC_TEST_VECTOR_001.json`).
- Negative/malformed test vectors (`PQC_TEST_VECTOR_002–004`) now cover tampered ownership, wrong scheme_id, and oversized blob rejection.
- Operator-facing rollout notes now exist (`docs/V3_ROLLOUT.md`).
- Wallet scanning vs hybrid authorization coexistence is now documented in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.
- Hybrid signature vector verification is now covered in Rust unit tests (`documented_vector_verifies`).
- **RingCT / stealth addresses**: hybrid PQ spend protection is specified as an augmentation of the existing privacy primitives, but the production integration still needs implementation and review.
- **v3 boundary**: address/account PQ groundwork can land now, but anonymous per-input PQ ownership enforcement remains deferred so v3 does not regress ring privacy.

---

## 3) PQC Next Steps (Recommended)

### Phase 1: Hybrid signatures

Completed:

- dependencies selected and wired
- `HybridEd25519MlDsa` keygen/sign/verify implemented
- canonical serialization for `HybridPublicKey` and `HybridSignature` implemented
- unit tests added for success/failure and malformed serialization paths

Remaining:

- ~~extend vector set with additional malformed/negative vectors~~ **Done** — three negative vectors added:
  - `PQC_TEST_VECTOR_002_tampered_ownership.json` (corrupted Ed25519 public key byte)
  - `PQC_TEST_VECTOR_003_wrong_scheme_id.json` (scheme_id 0x01 → 0x02)
  - `PQC_TEST_VECTOR_004_oversized_blob.json` (ML-DSA length field inflated beyond blob)
  - Integration tests in `rust/shekyl-crypto-pq/tests/negative_vectors.rs`
- future KEM vectors (deferred until KEM protocol use is specified)

### Phase 2: KEM (`HybridX25519MlKem`)

Deferred:

- do not make KEM consensus-critical yet
- do not finalize dependencies or ABI until a concrete protocol use is defined
- when revived, define secret-combining/KDF rules explicitly before implementation

### Phase 3: FFI and C++ integration

Completed:

- `shekyl-ffi` now exposes hybrid keygen/sign/verify
- explicit Rust-owned buffer release helper exists
- ABI expectations are documented in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`

Completed:

- C++ transaction serialization for the reboot-only v3 format (pqc_auth in transaction)
- hybrid layer bound to spend/ownership via PqcAuthentication and signed payload
- Rust verify called from core validation (verify_transaction_pqc_auth)
- Rust sign called from wallet transaction construction when hf_version >= HF_VERSION_SHEKYL_NG
- reboot-chain transaction version rules enforced (max_tx_version, version gates)

Remaining:

- expand wallet RPC docs with claim-flow details once staker claim tx format is finalized

### Phase 4: Documentation and audit

1. **PQC design doc**
   - Canonical spec exists in `docs/POST_QUANTUM_CRYPTOGRAPHY.md`.
   - Keep it aligned with the hybrid spend/ownership model as code lands.

2. **Privacy**
   - Describe impact on RingCT and stealth addresses (if any); ensure no key material in logs; constant-time and side-channel notes.
   - Make the v3 privacy boundary explicit: no anonymous per-input PQ ownership proof is shipped yet.

3. **Test vectors**
   - Publish test vectors for hybrid sign/verify and KEM for interop and future audits.

4. **Security review**
   - Schedule review of PQC integration (crypto + integration points) before mainnet.

---

## 4) Summary Table

| Area | Key TODOs | PQC-related |
|------|-----------|-------------|
| Genesis / emission | Emission economics redesign; snapshot/UTXO; v2.0 tx format | v2.0 depends on PQC |
| Design / economics | Params provisionally locked; 8-scenario simulation complete (`shekyl-economics-sim`); test coverage expanding | — |
| Build / test | Adopt or reimplement upstream build/test improvements | — |
| Levin / wire | Complete list of data on wire | — |
| Anonymity | Timestamp offset; broadcast delay; circuit rotation | — |
| Release | Full checklist; Shekyl-specific seeds, wallets, exchanges | — |
| Seeds | Populate DNS/IP seeds; runtime seed add; Shekyl naming | — |
| Economics / PoW | Finish config-driven proof activation and staker-claim transaction grammar | Stake-ratio chain-state tracking implemented; modular PoW scaffolding implemented |
| **PQC** | **v3 complete; 4 published vectors (1 positive, 3 negative); V4 roadmap published; external audit and KEM implementation remain** | **Core of this document** |

---

## 5) References

- **Project rules**: `.cursor/rules/privacy-security.mdc`
- **Genesis**: `docs/GENESIS_TRANSPARENCY.md`
- **Design**: `docs/DESIGN_CONCEPTS.md`
- **Rust PQC crate**: `rust/shekyl-crypto-pq/` (signature.rs, kem.rs, error.rs)
- **FFI**: `rust/shekyl-ffi/src/lib.rs` (hybrid keygen/sign/verify exported)
- **Backward compatibility**: `.cursor/rules/backward-compatibility.mdc` (pre-fork blocks remain valid under original consensus)
