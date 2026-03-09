# Documentation TODOs and PQC Implementation Status

This document consolidates key TODOs identified across Shekyl documentation and outlines the current state and next steps for Post-Quantum Cryptography (PQC) implementation.

---

## 1) Key TODOs from Existing Documentation

### 1.1 GENESIS_STRATEGY.md

| Item | Description |
|------|-------------|
| **Emission Economics (TODO)** | Original Shekyl `MONEY_SUPPLY` (2^32 in atomic units with 12 decimals) yields ~0.004 coins. Needs redesign before mainnet: reduce decimals (e.g. 8), choose different supply, or redesign emission curve. Currently using upstream default supply for testnet. |
| **Snapshot / UTXO** | Locate and extract original Shekyl UTXO set; implement snapshot restoration logic (Phase 2); mainnet launch after full testing. |
| **PQC transaction format** | Post-genesis blocks are planned to use a reboot-only hybrid PQ spend/ownership format with dedicated authorization fields — defined in `POST_QUANTUM_CRYPTOGRAPHY.md`; wallet/core binding work is still in progress. |

### 1.2 DESIGN_CONCEPTS.md

| Item | Description |
|------|-------------|
| **Pending parameters** | `tx_baseline` and `FINAL_SUBSIDY_PER_MINUTE` are marked **Pending** — to be set from testnet data. |
| **Simulation scenarios** | Eight simulation scenarios are listed as required (baseline, boom-bust, stuffing attack, stake concentration, etc.) — run and validate before locking parameters. |
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

---

## 2) What Is Documented for PQC

### 2.1 Project rules (.cursor/rules/privacy-security.mdc)

- **Priority**: Quantum resistance is priority #1; classical security #2; privacy #3.
- **Standards**: Prefer NIST PQC finalized standards: **ML-DSA**, **ML-KEM**, **SLH-DSA**.
- **Transition**: Prefer **hybrid** constructions (e.g. Ed25519 + ML-DSA) during transition.
- **Requirements**: No new crypto without quantum security evaluation; constant-time/side-channel resistance; no key material in logs or error messages.

### 2.2 Genesis strategy (docs/GENESIS_STRATEGY.md)

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
- No finalized implementation write-up yet for exact crate choices, measured encoded sizes, or test vectors.
- No finalized operator-facing explanation yet for relay/mempool impact from larger hybrid signatures.
- No finalized implementation note yet for how wallet scanning metadata and hybrid spend/ownership authorization coexist.
- No **test vectors** or **interop spec** for hybrid signatures/KEM.
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

- document measured encoded sizes from real outputs
- add publishable test vectors / interop fixtures

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

Remaining:

- make the v3 transaction/account rollout explicit in operator and wallet docs
- add C++ transaction serialization for the reboot-only v3 format
- bind the hybrid layer to spend/ownership semantics rather than a detached wrapper-only signature
- call Rust verify from core validation and Rust sign from wallet transaction construction
- enforce reboot-chain transaction version rules in the relevant validation paths

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
| Design / economics | Pending params from testnet; simulation runs; test coverage | — |
| Build / test | Adopt or reimplement upstream build/test improvements | — |
| Levin / wire | Complete list of data on wire | — |
| Anonymity | Timestamp offset; broadcast delay; circuit rotation | — |
| Release | Full checklist; Shekyl-specific seeds, wallets, exchanges | — |
| Seeds | Populate DNS/IP seeds; runtime seed add; Shekyl naming | — |
| **PQC** | **Hybrid signatures and FFI are in place; wallet/core v3 spend-binding, measured sizing, test vectors, and audit remain** | **Core of this document** |

---

## 5) References

- **Project rules**: `.cursor/rules/privacy-security.mdc`
- **Genesis**: `docs/GENESIS_STRATEGY.md`
- **Design**: `docs/DESIGN_CONCEPTS.md`
- **Rust PQC crate**: `rust/shekyl-crypto-pq/` (signature.rs, kem.rs, error.rs)
- **FFI**: `rust/shekyl-ffi/src/lib.rs` (hybrid keygen/sign/verify exported)
- **Backward compatibility**: `.cursor/rules/backward-compatibility.mdc` (pre-fork blocks remain valid under original consensus)
