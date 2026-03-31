# PQC Multisig for Shekyl

> **Last updated:** 2026-03-30

## Purpose

This document specifies how multisignature spend authorization integrates with
Shekyl's post-quantum cryptography (`pqc_auth`) framework.

Multisig is implemented in two phases:

- **V3 (HF1):** Hybrid signature list — M individual hybrid signatures from
  the existing `Ed25519 + ML-DSA-65` scheme, carried in an extended
  `pqc_auth` container. Uses only proven, NIST-backed primitives.
- **V4 (future):** Lattice-based composite threshold signatures — a single
  compact on-chain signature produced by M-of-N participants via distributed
  key generation. Requires further research maturity before deployment.

## Design Principles

1. **Ship proven primitives first.** The V3 signature-list approach reuses the
   existing hybrid scheme (`scheme_id = 1`) with zero new cryptographic
   assumptions. Lattice threshold signatures are theoretically elegant but not
   yet NIST-standardized or thoroughly audited.
2. **Tolerate known costs over unmodeled risks.** The signature-list approach
   adds ~5.3 KB per additional signer. This is a known, bounded cost.
   Multisig transactions represent well under 1% of on-chain volume (Monero
   data confirms multisig usage is negligible — and on-chain
   indistinguishable from single-key spends due to secret-splitting). The
   aggregate chain growth impact is noise.
3. **Preserve ring privacy.** All multisig coordination happens off-chain.
   On-chain transactions must remain indistinguishable from single-key spends
   at the ring/CLSAG layer. The `pqc_auth` field carries authorization
   material, not privacy-layer data.
4. **Protect long-duration staked outputs.** The primary use case driving V3
   multisig is securing staked positions locked for 25,000–150,000 blocks
   (35–208 days). A single key controlling a locked position for months is a
   single point of failure. Multisig staked outputs and claim transactions
   address this directly.

## Monero Multisig Heritage

Shekyl inherits Monero's additive N-of-M scheme on Ed25519. Key properties
of the classical design:

- No single participant ever knows the full shared private key.
- The on-chain transaction looks like a normal single-key spend (secret
  splitting, not on-chain multi-signature).
- Coordination happens off-chain via the Multisig Messaging System (MMS) or
  manual data exchange.
- There is no separate multisig address type — multisig is invisible on-chain.

Monero's multisig is CLI-only, still flagged as experimental, had known bugs
until PR #8149 (mid-2022), and has no formal specification or completed
third-party audit. Usage is negligible — well under 0.1% of daily
transactions by any informed estimate.

For Shekyl, multisig is being designed with wallet GUI integration from
launch, which should improve adoption modestly — but the power-user nature
of the feature means it will never dominate transaction volume.

---

## V3: Hybrid Signature List (HF1)

### Overview

A new `scheme_id` value extends the existing `PqcAuthentication` container to
carry M hybrid signatures and M hybrid public keys. Each signer produces a
complete `Ed25519 + ML-DSA-65` hybrid signature over the same canonical
signing payload. The verifier checks all M signatures independently.

### Scheme Registry Extension

| `scheme_id` | Name | Description |
|---|---|---|
| 1 | `ed25519_ml_dsa_65` | Single-signer hybrid (existing V3) |
| 2 | `ed25519_ml_dsa_65_multisig` | M-of-N hybrid signature list (V3 multisig) |

### PqcAuthentication Structure (scheme_id = 2)

```text
PqcAuthentication {
  u8   auth_version        // 1
  u8   scheme_id           // 2
  u16  flags               // reserved, must be 0
  u8   n_total             // N (total authorized signers)
  u8   m_required          // M (threshold)
  u8   sig_count           // number of signatures present (must equal m_required)
  HybridPublicKey[n_total] ownership_keys    // all N public keys (defines the multisig group)
  HybridSignature[m_required] signatures     // M signatures from the signing subset
  u8[m_required] signer_indices              // which of the N keys produced each signature
}
```

### Canonical Serialization

```text
MultisigPqcAuth {
  u8   auth_version
  u8   scheme_id           // 2
  u16  flags               // 0
  u8   n_total
  u8   m_required
  u8   sig_count
  // ownership keys: N × HybridPublicKey (same encoding as scheme_id=1)
  for i in 0..n_total:
    HybridPublicKey[i]
  // signatures: M × HybridSignature (same encoding as scheme_id=1)
  for i in 0..m_required:
    HybridSignature[i]
  // signer indices: M bytes, each in range [0, n_total)
  for i in 0..m_required:
    u8 signer_index[i]
}
```

Constraints:

- `auth_version = 1`
- `scheme_id = 2`
- `flags = 0`
- `1 <= m_required <= n_total <= 16`
- `sig_count == m_required`
- All `signer_index` values must be unique and in range `[0, n_total)`
- `signer_index` array must be sorted ascending (canonical ordering)
- Each `HybridPublicKey` and `HybridSignature` uses the same canonical
  encoding defined in `POST_QUANTUM_CRYPTOGRAPHY.md` for `scheme_id = 1`

### Signed Payload

The signed payload is identical to single-signer V3:

```text
signed_payload =
  cn_fast_hash(
    serialize(TransactionPrefixV3)
    || serialize(RctSigningBody)
    || serialize(PqcAuthHeader)
  )
```

Where `PqcAuthHeader` for multisig includes:

```text
PqcAuthHeader {
  auth_version
  scheme_id           // 2
  flags
  n_total
  m_required
  HybridPublicKey[n_total]   // all N ownership keys
}
```

All M signers sign the same payload. The signatures themselves are excluded
from the payload (no self-reference).

### Verification Rule

For `scheme_id = 2`, validation succeeds only if ALL of the following hold:

1. Standard transaction structural checks pass.
2. Existing privacy-layer checks pass.
3. Canonical PQC field decoding succeeds.
4. `m_required <= n_total <= 16` and `sig_count == m_required`.
5. `signer_index` array is sorted ascending with no duplicates.
6. For each of the M signatures at position `i`:
   - Let `key = ownership_keys[signer_indices[i]]`
   - `Ed25519.verify(signed_payload, sig.ed25519_sig, key.ed25519_pub)` succeeds
   - `ML-DSA.verify(signed_payload, sig.ml_dsa_sig, key.ml_dsa_pub)` succeeds
7. If any individual signature fails either check, the entire spend
   authorization is invalid.

### Transaction Size Impact

Measured per-signer contribution (from V3 phase-1 measurements):

- `HybridPublicKey`: 1,996 bytes
- `HybridSignature`: 3,385 bytes

| Configuration | Keys | Signatures | Auth overhead | vs single-signer |
|---|---|---|---|---|
| Single (scheme 1) | 1,996 | 3,385 | ~5,385 | baseline |
| 2-of-3 | 5,988 | 6,770 | ~12,769 | +7,384 (~2.4x) |
| 3-of-5 | 9,980 | 10,155 | ~20,153 | +14,768 (~3.7x) |
| 5-of-7 | 13,972 | 16,925 | ~30,921 | +25,536 (~5.7x) |

At sub-0.1% of transaction volume, even the 5-of-7 case has negligible
impact on aggregate chain growth.

### Multisig Group Identity

The multisig group is defined by the ordered set of N `HybridPublicKey`
values. The group identity (for address generation and UTXO matching) is:

```text
multisig_group_id = cn_fast_hash(
  "shekyl-multisig-group-v1"
  || u8(n_total)
  || u8(m_required)
  || HybridPublicKey[0] || HybridPublicKey[1] || ... || HybridPublicKey[n_total-1]
)
```

Note: the domain separator string `"shekyl-multisig-group-v1"` is
provisional. The exact byte-level constant will be finalized in the Rust
implementation (`rust/shekyl-crypto-pq`) and published as part of the test
vector set to avoid any future collision risk with other hash-domain uses.

This deterministic group ID allows wallets to identify outputs belonging to
the multisig group during scanning.

### Staking Integration

Multisig staked outputs use the same `txout_to_staked_key` format. The
ownership key in the staking output references the multisig group identity.

Claim transactions (`txin_stake_claim`) from multisig staked outputs require
`scheme_id = 2` authorization with the same M-of-N threshold.

Lock enforcement is unchanged — the protocol-level lock applies regardless
of whether the staked output uses single-signer or multisig authorization.

### Wallet Implementation Notes

- Key generation: each participant generates their own hybrid keypair
  independently. The N public keys are exchanged out-of-band and assembled
  into the multisig group.
- Signing: the wallet constructs the complete transaction body, computes
  the canonical signing payload, and distributes it to M signers. Each
  signer produces their hybrid signature independently. The wallet collects
  M signatures and assembles the final `pqc_auth`.
- No DKG protocol is required for V3. This is a significant simplification
  over the lattice threshold approach.
- The Tauri wallet should expose multisig group creation and signing
  coordination in the GUI, especially integrated with the staking flow.

---

## V4: Lattice-Based Composite Threshold (Future)

### Motivation

The V3 signature-list approach is functional but scales linearly in
transaction size with the number of signers. For configurations beyond
3-of-5, the size overhead becomes material. A lattice-based threshold
scheme produces a single compact signature regardless of M or N.

### Core Concept

In lattice cryptography, the hardness assumption is finding short vectors
in a high-dimensional lattice (Module-LWE / SIS problems).

- Each participant's private key is a short vector `s_i` (small
  coefficients).
- The composite public key is the vector sum:
  `pk = s_1 + s_2 + ... + s_N`
- To sign, any M participants each produce a partial short vector `p_j`.
- The verifier receives the sum: `sigma = p_1 + p_2 + ... + p_M`
- Verification succeeds if `sigma` is sufficiently short AND satisfies the
  lattice equation for `pk`.

The threshold property comes from the fact that only M short vectors are
needed to reach a valid short `sigma`; fewer than M vectors fail the
equation. The remaining (N-M) vectors stay secret.

### Advantages Over Signature List

- Single compact `pqc_auth` field (~7-9 KB for any M-of-N, vs linear
  scaling).
- True threshold security (no single party can spend).
- Single-equation verification (constant time, independent of N).
- Preserves ring privacy (threshold math happens off-chain).

### Barriers (Realistic)

- **Research maturity:** Threshold lattice signatures (e.g. "Threshold
  Dilithium" variants from 2024-2026 literature) are not NIST-standardized.
  Specific scheme selection requires further survey.
- **DKG complexity:** Distributed key generation must be secure against
  malicious participants. This adds protocol steps and attack surface that
  the V3 approach avoids entirely.
- **Performance:** Lattice operations are heavier than Ed25519. Partial
  signing rounds add latency during coordination (not during on-chain
  validation).
- **Audit requirements:** A formal security review of the chosen threshold
  scheme is mandatory before consensus activation.

### Integration Plan

| `scheme_id` | Name | Target |
|---|---|---|
| 3 | `lattice_threshold_composite` | V4 (HF18+) |

The `PqcAuthentication` container carries the composite public key and
summed signature. Verification is a single lattice relation check.

### Rollout Phases

| Phase | Feature | Target |
|---|---|---|
| V4.0 | Scheme selection and Rust prototype in `rust/shekyl-crypto-pq` | Post V3 stabilization |
| V4.1 | DKG protocol implementation in Tauri wallet | +3 months |
| V4.2 | Testnet experiment with `scheme_id = 3` behind feature gate | +6 months |
| V4.3 | Security audit and mainnet activation (HF18+) | +9-12 months |

### Hybrid Fallback

During the V4 transition period, `scheme_id = 2` (signature list) remains
valid. Wallets can offer both options. `scheme_id = 3` becomes mandatory
only after a grace period following activation.

### Open Research Items

- Select a specific lattice threshold scheme from recent literature and
  evaluate against Shekyl's size/performance constraints.
- Define the DKG protocol and its security model (honest-majority vs
  dishonest-majority).
- Benchmark signing time, verification time, and tx size for realistic
  M-of-N configurations.
- Publish test vectors once the Rust prototype is complete.

---

## Use Cases

### Treasury Management

Organizations holding significant SHEKYL — development funds, community
treasuries, business operating accounts — require that no single person can
unilaterally spend. A 2-of-3 or 3-of-5 multisig ensures cooperative
authorization.

### Staking Security

Staked positions locked at the long tier (150,000 blocks / ~208 days)
represent months of illiquidity with real yield at stake. A single key
controlling that position is a single point of failure for 7 months.
Multisig staked outputs require M-of-N authorization for claim transactions
and for the eventual unlock-and-spend.

### Inheritance and Recovery

A 2-of-3 setup where the owner holds two keys and a trusted party holds one
allows normal day-to-day operation (owner uses their two keys) while
providing estate recovery if the owner is incapacitated.

### Escrow

Buyer, seller, and arbitrator each hold a key in a 2-of-3. Direct
settlement requires buyer + seller agreement. Disputes are resolved by the
arbitrator co-signing with the aggrieved party.

---

## Privacy Considerations

### On-Chain Indistinguishability

For V3 (signature list), multisig transactions are distinguishable from
single-signer transactions by their `scheme_id` and larger `pqc_auth` size.
This is a privacy trade-off accepted for V3 given negligible multisig
volume.

For V4 (lattice threshold), the composite signature is the same size
regardless of M or N, but the `scheme_id` still differs from single-signer.
True indistinguishability would require all transactions to use the same
scheme — this is a V5+ consideration if multisig adoption grows
significantly.

### Ring Privacy

Neither V3 nor V4 multisig affects the ring/CLSAG layer. The
`pqc_auth` field is authorization material, not ring-member selection data.
Anonymity set size is unchanged.

---

## Relationship to Other Documents

| Document | Relevant changes |
|---|---|
| `POST_QUANTUM_CRYPTOGRAPHY.md` | `scheme_id` registry extended; deferred scope updated; multisig no longer fully deferred |
| `V3_ROLLOUT.md` | Multisig tx size guidance added to payload limits |
| `DESIGN_CONCEPTS.md` | Staking section references multisig as operational security option |
| `STAKER_REWARD_DISBURSEMENT.md` | Claim transactions support multisig authorization |
| `RELEASE_CHECKLIST.md` | Multisig testing items to be added |

---

## References

- Monero multisig documentation: <https://docs.getmonero.org/multisignature/>
- Monero MMS guide: <https://web.getmonero.org/resources/user-guides/multisig-messaging-system.html>
- Esgin et al., "Practical Exact Proofs from Lattices" (2019)
- Lyubashevsky et al., lattice-based ring/group signature constructions (2022-2026)
- NIST PQC standards: ML-DSA (FIPS 204), ML-KEM (FIPS 203)
- Shekyl PQC spec: `docs/POST_QUANTUM_CRYPTOGRAPHY.md`
- Shekyl staker disbursement: `docs/STAKER_REWARD_DISBURSEMENT.md`
