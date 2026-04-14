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
Offset   Size     Field                   Notes
------   ----     -----                   -----
0        1        version                 Must be 0x01
1        32       group_id                cn_fast_hash of group key material
33       32       intent_hash             cn_fast_hash of SpendIntent canonical bytes
65       1        sender_index            0-indexed participant number
66       4        sig_len                 u32 LE, length of sender_sig
70       sig_len  sender_sig              Hybrid signature over signable_header
70+S     4        payload_len             u32 LE, length of encrypted_payload
74+S     P        encrypted_payload       AEAD ciphertext (see §4)
```

Where `S = sig_len` and `P = payload_len`.

**Size bounds:**
- **Minimum:** 74 bytes (sig_len=0, payload_len=0). Implementations
  MUST reject envelopes shorter than 74 bytes.
- **Maximum:** Implementations MUST reject envelopes where
  `sig_len + payload_len > 1,048,576` (1 MiB). This bounds memory
  allocation from untrusted input.
- **`sig_len`** MUST NOT exceed 8,192 bytes (hybrid signatures are
  ~3,385 bytes; the bound allows headroom for future schemes).
- **`payload_len`** MUST NOT exceed 1,048,576 bytes (1 MiB).

### 1.2 Signable Header

The `sender_sig` covers these bytes concatenated in order:

```
version || group_id || intent_hash || sender_index || payload_len || encrypted_payload
```

Note: `payload_len` (4 bytes, u32 LE) is included in the signed data
to prevent framing attacks where an attacker swaps the length prefix
while preserving the ciphertext. `sig_len` is NOT included because it
is metadata about the signature itself.

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
| `MAX_RECIPIENTS` | `16` | Maximum recipients per intent |
| `MAX_INPUTS` | `128` | Maximum inputs per intent |
| `MAX_ADDRESS_LEN` | `65536` | Maximum address byte length |

### 2.2 Canonical Byte Layout

Fields are serialized in declaration order with no padding. All
subsequent fields follow the preceding field immediately.
Variable-length fields use a `u32 LE` length prefix.

```
Offset   Size     Field
------   ----     -----
0        1        version                 0x01
1        32       intent_id               Random 32 bytes
33       32       group_id                32-byte group identifier
65       1        proposer_index          0-indexed
66       4        proposer_sig_len        u32 LE
70       S        proposer_sig            Hybrid signature bytes
```

All subsequent fields follow at `offset = 70 + S` with no padding,
concatenated in the order listed:

```
8        created_at              u64 LE, unix seconds
8        expires_at              u64 LE, unix seconds
8        tx_counter              u64 LE, monotonic
8        reference_block_height  u64 LE
32       reference_block_hash    32 bytes
4        recipients_count        u32 LE (MUST be ≤ MAX_RECIPIENTS)
...      recipients[]            See §2.3, repeated recipients_count times
8        fee                     u64 LE, atomic units
4        inputs_count            u32 LE (MUST be ≤ MAX_INPUTS)
...      input_global_indices[]  inputs_count × u64 LE (8 bytes each)
32       kem_randomness_seed     32 bytes
32       chain_state_fingerprint 32 bytes
```

Implementations MUST reject intents where `recipients_count >
MAX_RECIPIENTS` or `inputs_count > MAX_INPUTS` or `proposer_sig_len >
8192`.

### 2.3 Recipient Encoding

Each recipient is encoded as:

```
4        address_len    u32 LE (MUST be ≤ MAX_ADDRESS_LEN)
A        address        Raw address bytes (A = address_len)
8        amount         u64 LE, atomic units
```

Implementations MUST reject recipients with `address_len >
MAX_ADDRESS_LEN`.

**Sort order:** Recipients MUST be sorted by `(address, amount)` where
`address` is compared as raw bytes via unsigned byte-wise lexicographic
comparison (`memcmp` semantics: compare byte-by-byte from index 0;
shorter address sorts before longer if they share a prefix). Ties are
broken by `amount` as unsigned 64-bit integer, ascending.

Duplicate `(address, amount)` tuples are forbidden.

### 2.4 Intent Hash

```
intent_hash = cn_fast_hash(canonical_bytes)
```

Where `cn_fast_hash` is Keccak-256 and `canonical_bytes` is the full
serialization from §2.2 (including `proposer_sig_len` and
`proposer_sig`).

### 2.5 Signable Bytes

The `proposer_sig` covers the canonical serialization from §2.2 with
the `proposer_sig_len` (4 bytes) and `proposer_sig` (S bytes) fields
**skipped**: all other fields are concatenated in declaration order
with no padding and no placeholder bytes filling the gap. Concretely:

```
version || intent_id || group_id || proposer_index
|| created_at || expires_at || tx_counter || reference_block_height
|| reference_block_hash || recipients_count || recipients[]
|| fee || inputs_count || input_global_indices[]
|| kem_randomness_seed || chain_state_fingerprint
```

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
| `0x0A` | RotationIntent | reserved | Reserved for V3.2 |
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
the 32-byte shared secret established during DKG. The `info` field is
the raw concatenation of these bytes with no length prefixes or
delimiters — all three components are fixed-length (32 + 1 + 1 = 34
bytes total).

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

The `info` field is the raw concatenation with no delimiters (5 + 1 +
8 = 14 bytes total).

The `message_counter` is a per-sender monotonic counter that prevents
nonce reuse. Each sender maintains their own counter independently.

**Persistence requirements:** `message_counter` MUST be persisted
durably to non-volatile storage. It MUST survive application restarts
and OS reboots. On wallet restore from seed, the counter MUST be
seeded to a value strictly greater than any value the wallet could have
plausibly used. The recommended recovery strategy is to scan the
wallet's own past envelopes from all configured relays and set the
counter to `max_observed + 1`. If no past envelopes are found, start
at `0`. Failure to persist the counter creates a nonce-reuse window
exploitable by an attacker replaying old envelopes.

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

### 4.4 Sensitive Material Lifecycle

Implementations MUST zeroize the following values when no longer needed:

- **`message_key`**: zeroize immediately after each encrypt or decrypt
  operation completes.
- **Decrypted plaintext**: zeroize after the message body has been
  parsed and processed.
- **`group_shared_secret`**: lives for the lifetime of the wallet
  session. MUST be zeroized on wallet close, session end, or process
  exit. MUST be stored in memory pages excluded from swap/core dumps
  where the OS supports it.

Nonce bytes are not sensitive (they are derived from public
information and are implicitly disclosed by the ciphertext).

---

## 5. DecryptedPayload

After AEAD decryption, the plaintext has this layout:

```
Offset  Size     Field
------  ----     -----
0       1        message_type    One of the IDs from §3
1       ...      body            Type-specific serialization (see §5.1)
```

### 5.1 Message Body Layouts

All bodies use the same conventions: multi-byte integers are LE,
variable-length fields use `u32 LE` length prefixes, fields are
concatenated with no padding.

#### 0x01 SpendIntent

The body is the SpendIntent canonical serialization from §2.2.

#### 0x02 ProverOutput

```
1        prover_index
32       intent_hash
4        proof_count            u32 LE
         [repeated proof_count times:]
           8        input_global_index    u64 LE
           4        fcmp_proof_len        u32 LE
           ...      fcmp_proof            fcmp_proof_len bytes
           32       key_image
4        prover_sig_len         u32 LE
...      prover_sig             prover_sig_len bytes
```

#### 0x03 SignatureShare

```
1        signer_index
4        hybrid_sig_len         u32 LE
...      hybrid_sig             hybrid_sig_len bytes
32       tx_hash_commitment
32       fcmp_proof_commitment
32       bp_plus_proof_commitment
```

#### 0x04 Veto

```
1        sender_index
32       intent_hash
1        reason_code            0x01=InvariantFailed, 0x02=ProverEquivocation,
                                0x03=ChainStateMismatch, 0x04=RateLimitExceeded,
                                0x05=Manual
         [if reason_code == 0x01:]
           1        invariant_id
         [if reason_code == 0x05:]
           4        message_len       u32 LE (MUST be ≤ 1024)
           ...      message           UTF-8 text
4        sender_sig_len         u32 LE
...      sender_sig             sender_sig_len bytes
```

#### 0x05 ProverReceipt

```
1        prover_index
32       intent_hash
8        local_counter          u64 LE
4        receipt_sig_len        u32 LE
...      receipt_sig            receipt_sig_len bytes
```

#### 0x06 Heartbeat

```
1        sender_index
8        timestamp              u64 LE, unix seconds
32       last_seen_intent       intent_hash of most recent known intent
4        relay_ops_count        u32 LE (MUST be ≤ 32)
         [repeated relay_ops_count times:]
           4        op_len           u32 LE (MUST be ≤ 256)
           ...      operator_id      UTF-8 string
8        local_tx_counter       u64 LE
4        sig_len                u32 LE
...      sig                    sig_len bytes
```

#### 0x07 CounterProof

```
1        sender_index
8        advancing_to           u64 LE
32       tx_hash
8        block_height           u64 LE
32       block_hash
2        tx_position            u16 LE
4        consumed_count         u32 LE (MUST be ≤ MAX_INPUTS)
         [repeated consumed_count times:]
           32       key_image
4        output_count           u32 LE (MUST be ≤ MAX_INPUTS)
         [repeated output_count times:]
           32       output_commitment
32       intent_hash
4        sender_sig_len         u32 LE
...      sender_sig             sender_sig_len bytes
```

#### 0x08 GroupStateSummary

Body format defined in `PQC_MULTISIG.md` §13.5. Implementations that
do not need group state synchronization MAY treat this as opaque.

#### 0x09 InvariantViolation

```
1        reporter_index
32       intent_hash
1        invariant_id           I1=0x01 through I7=0x07
4        evidence_len           u32 LE (MUST be ≤ 65536)
...      evidence               evidence_len bytes (opaque)
4        reporter_sig_len       u32 LE
...      reporter_sig           reporter_sig_len bytes
```

#### 0x0A RotationIntent

Reserved for V3.2. MUST NOT be sent or accepted in V3.1.

#### 0x0B EquivocationProof

```
1        prover_index
32       intent_hash
4        proof_a_len            u32 LE
...      proof_a                ProverOutput body (§5.1 0x02 layout)
4        proof_b_len            u32 LE
...      proof_b                ProverOutput body (§5.1 0x02 layout)
```

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

All arrays are sorted independently in ascending numeric order before
concatenation. Duplicates are expected and preserved — multiple inputs
may share the same prover index, amount, or eligible height.

---

## 7. File Transport

For air-gapped operation, envelopes are transported as files.

### 7.1 File Naming

Files use **random opaque filenames**: `shekyl-ms-<random64hex>.bin`.
The 64 hex characters represent 32 bytes of randomness, which MUST be
generated from a cryptographically secure source (OS-level CSPRNG:
`/dev/urandom`, `getrandom(2)`, `BCryptGenRandom`, or equivalent).
The filename MUST NOT be generated from a userspace PRNG seeded with
predictable data.

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

1. Produce byte-identical **canonical serialization** (§2.2) for the
   same `SpendIntent` inputs. The `intent_hash` equality follows from
   serialization equality, but it is the serialization itself that is
   the interoperability requirement.
2. Successfully decrypt envelopes produced by any other conforming
   implementation given the same `group_shared_secret`.
3. Reject envelopes with unknown version bytes (no silent skip).
4. Reject unknown `message_type` bytes (no silent skip).
5. Reject recipients that are not sorted per §2.3 or contain
   duplicates.
6. Enforce all size bounds in §1.1 and §2.2 (reject oversized length
   prefixes without allocating).
7. Persist `message_counter` durably per §4.2.
8. Pass all canonical test vectors in `test_vectors/v3.1/`.

---

## 9. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1 | 2026-04-13 | Initial release for V3.1 |
| 1.1 | 2026-04-14 | Tighten ambiguities: add size bounds on all length prefixes, clarify recipient sort order as unsigned bytewise comparison, fix signable header to include payload_len, clarify signable bytes gap semantics, add message_counter persistence requirements, add message body layouts for all 11 types, fix RotationIntent target to V3.2, expand zeroization guidance, require CSPRNG for file naming, strengthen conformance requirements |
