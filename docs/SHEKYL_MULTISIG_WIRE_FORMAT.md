# Shekyl Multisig Wire Format v1

> **Status:** Normative for V3.1 conformance
>
> **Spec version:** 1
>
> **Parent spec:** `PQC_MULTISIG.md`
>
> **Reference implementation:** `rust/shekyl-wallet-core/src/multisig/v31/`

This document defines the portable binary wire format for Shekyl V3.1
multisig inter-participant communication. A third-party wallet
implementation can target this document without reading the full V3.1
multisig spec. All multi-byte integers are **little-endian** unless
stated otherwise.

---

## 1. MultisigEnvelope

The `MultisigEnvelope` is the common wrapper for all inter-participant
messages. It is the unit of transport — every relay message, P2P
message, and file-transport blob is exactly one envelope.

### 1.1 Binary Layout

```
Offset  Size     Field                   Notes
------  ----     -----                   -----
0       1        version                 Must be 0x01
1       32       group_id                cn_fast_hash of group key material
33      32       intent_hash             cn_fast_hash of SpendIntent canonical bytes
65      1        sender_index            0-indexed participant number
66      4        sig_len                 u32 LE, length of sender_sig
70      sig_len  sender_sig              Hybrid signature over signable_header
70+S    4        payload_len             u32 LE, length of encrypted_payload
74+S    P        encrypted_payload       AEAD ciphertext (see §4)
```

Where `S = sig_len` and `P = payload_len`.

**Minimum size:** 74 bytes (sig_len=0, payload_len=0). Implementations
MUST reject envelopes shorter than 74 bytes.

### 1.2 Signable Header

The `sender_sig` covers these bytes concatenated in order:

```
version || group_id || intent_hash || sender_index || encrypted_payload
```

The signature is computed over these bytes using the sender's hybrid
signing key (Ed25519 + ML-DSA-65). The signature format is the hybrid
signature defined in `POST_QUANTUM_CRYPTOGRAPHY.md`.

### 1.3 Version Negotiation

- Version `0x01` is the only defined version.
- Implementations MUST reject envelopes with `version != 0x01`.
- No silent skip: an unknown version is a hard error, not a warning.
- Future versions will be defined in updated wire format specs.

---

## 2. SpendIntent Canonical Serialization

The `SpendIntent` is the proposal message that initiates a multisig
spend. Its canonical serialization is the input to `intent_hash` and
determines cross-implementation compatibility.

### 2.1 Constants

| Name | Value | Description |
|------|-------|-------------|
| `SPEND_INTENT_VERSION` | `0x01` | Current version |
| `MAX_VALIDITY_SECS` | `86400` | Maximum validity window (24h) |
| `FCMP_REFERENCE_BLOCK_MIN_AGE` | `10` | Minimum ref block age in blocks |
| `FCMP_REFERENCE_BLOCK_MAX_AGE` | `100` | Maximum ref block age in blocks |

### 2.2 Canonical Byte Layout

Fields are serialized in declaration order. Variable-length fields use
a `u32 LE` length prefix.

```
Offset  Size     Field
------  ----     -----
0       1        version                 0x01
1       32       intent_id               Random 32 bytes
33      32       group_id                32-byte group identifier
65      1        proposer_index          0-indexed
66      4        proposer_sig_len        u32 LE
70      S        proposer_sig            Hybrid signature bytes
70+S    8        created_at              u64 LE, unix seconds
78+S    8        expires_at              u64 LE, unix seconds
86+S    8        tx_counter              u64 LE, monotonic
94+S    8        reference_block_height  u64 LE
102+S   32       reference_block_hash    32 bytes
134+S   4        recipients_count        u32 LE
138+S   ...      recipients[]            See §2.3
...     8        fee                     u64 LE, atomic units
...     4        inputs_count            u32 LE
...     ...      input_global_indices[]  Each u64 LE
...     32       kem_randomness_seed     32 bytes
...     32       chain_state_fingerprint 32 bytes
```

### 2.3 Recipient Encoding

Each recipient is:

```
4        address_len    u32 LE
A        address        Raw address bytes
8        amount         u64 LE, atomic units
```

Recipients MUST be sorted by `(address, amount)` lexicographically.
Duplicate `(address, amount)` tuples are forbidden.

### 2.4 Intent Hash

```
intent_hash = cn_fast_hash(canonical_bytes)
```

Where `cn_fast_hash` is Keccak-256 and `canonical_bytes` is the full
serialization from §2.2.

### 2.5 Signable Bytes

The `proposer_sig` covers the same layout as §2.2 but with
`proposer_sig_len` and `proposer_sig` fields omitted.

---

## 3. Message Types

The message type is carried **inside the encrypted payload** (not in
the cleartext envelope header) to prevent role-pattern leakage.

| ID | Name | Direction | Description |
|----|------|-----------|-------------|
| `0x01` | SpendIntent | proposer → all | Transaction proposal |
| `0x02` | ProverOutput | prover → all | FCMP++ proof for assigned outputs |
| `0x03` | SignatureShare | signer → all | Partial hybrid signature |
| `0x04` | Veto | any → all | Abort request with reason |
| `0x05` | ProverReceipt | prover → all | Acknowledgment of prover assignment |
| `0x06` | Heartbeat | any → all | Liveness and sync beacon |
| `0x07` | CounterProof | any → stale | Chain evidence for counter recovery |
| `0x08` | GroupStateSummary | any → all | Group state synchronization |
| `0x09` | InvariantViolation | any → all | Report of failed invariant check |
| `0x0A` | RotationIntent | reserved | Reserved for V4 |
| `0x0B` | EquivocationProof | any → all | Evidence of conflicting proofs |

Implementations MUST reject unknown message type bytes. `0x0A` is
reserved and MUST NOT be sent in V3.1.

---

## 4. AEAD Encryption

All payloads are encrypted with ChaCha20-Poly1305.

### 4.1 Key Derivation

```
message_key = HKDF-Expand(
    PRK  = group_shared_secret,       // 32 bytes
    info = intent_hash                 // 32 bytes
           || u8(message_type)         // 1 byte
           || u8(sender_index),        // 1 byte
    L    = 32
)
```

The HKDF uses SHA-256 as the hash function. `group_shared_secret` is
the 32-byte shared secret established during DKG.

### 4.2 Nonce Derivation

```
nonce = HKDF-Expand(
    PRK  = group_shared_secret,        // 32 bytes
    info = b"nonce"                     // 5 bytes, ASCII literal
           || u8(sender_index)          // 1 byte
           || u64_le(message_counter),  // 8 bytes
    L    = 12
)
```

The `message_counter` is a per-sender monotonic counter that prevents
nonce reuse. Each sender maintains their own counter independently.

### 4.3 Encryption

```
ciphertext || tag = ChaCha20-Poly1305.Encrypt(
    key       = message_key,
    nonce     = nonce,
    plaintext = DecryptedPayload,
    aad       = (none)
)
```

The `tag` is 16 bytes appended to the ciphertext. The total
`encrypted_payload` length is `plaintext_len + 16`.

### 4.4 Key Zeroization

Implementations MUST zeroize `message_key` immediately after
encryption or decryption completes.

---

## 5. DecryptedPayload

After AEAD decryption, the plaintext has this layout:

```
Offset  Size     Field
------  ----     -----
0       1        message_type    One of the IDs from §3
1       ...      body            Type-specific serialization
```

The `body` format depends on `message_type` and is defined by each
message type's specification in `PQC_MULTISIG.md`.

---

## 6. Chain State Fingerprint

The chain state fingerprint is a 32-byte hash that members must agree
on before signing. It ensures all signers see the same chain state.

### 6.1 Computation

```
preimage = reference_block_hash          // 32 bytes
        || sorted(input_global_indices)  // each u64 LE
        || sorted(input_eligible_heights)// each u64 LE
        || sorted(input_amounts)         // each u64 LE
        || sorted(input_assigned_prover_indices)  // each u8

chain_state_fingerprint = cn_fast_hash(preimage)
```

All arrays are sorted independently before concatenation.

---

## 7. File Transport

For air-gapped operation, envelopes are transported as files.

### 7.1 File Naming

Files use **random opaque filenames**: `shekyl-ms-<random64hex>.bin`.
The filename MUST NOT contain metadata (group_id, intent_hash, message
type, sender index). Metadata is carried inside the encrypted payload.

### 7.2 File Contents

The file contains exactly one `MultisigEnvelope` serialized per §1.1.
No additional framing, headers, or magic bytes.

### 7.3 Display Names

Wallet UIs SHOULD display human-readable names derived from the
decrypted metadata (e.g., "Intent 0x1a2b... from participant 3").
These display names are never written to disk.

---

## 8. Conformance

An implementation claiming V3.1 wire format conformance MUST:

1. Produce byte-identical `intent_hash` values for the same
   `SpendIntent` inputs
2. Successfully decrypt envelopes produced by any other conforming
   implementation given the same `group_shared_secret`
3. Reject envelopes with unknown version bytes (no silent skip)
4. Reject unknown `message_type` bytes (no silent skip)
5. Reject recipients that are not sorted or contain duplicates
6. Pass all canonical test vectors in `test_vectors/v3.1/`

---

## 9. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1 | 2026-04-13 | Initial release for V3.1 |
