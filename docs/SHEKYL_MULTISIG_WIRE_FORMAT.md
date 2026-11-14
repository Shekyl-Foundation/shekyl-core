# Shekyl Multisig Wire Format v2

> **Status:** normative for the ceremony file (§1, §4), the spend intent
> (§2), the message types and their bodies (§3).
>
> **Spec version:** 2.1
>
> **Parent spec:** `PQC_MULTISIG.md`
>
> **Reference implementation:** `rust/shekyl-multisig/src/envelope.rs`,
> `intent.rs`, `messages.rs`, `ceremony/files.rs`;
> `rust/shekyl-crypto-pq/src/multisig_blob.rs`,
> `multisig_envelope.rs`

This document defines the bytes Option E′ group members exchange. A
third-party wallet can target it without reading the full multisig spec.
All multi-byte integers are **little-endian** unless stated otherwise.

The only transport is files (R-9): a member writes a ceremony file and
the others receive it by any means — email, a messenger, a USB stick. The
wallet moves no bytes itself.

---

## 1. Ceremony file

One file is one message from one member. **Only its format version is in
the clear** (R-10): which group, which intent, which member and which
step are inside the ciphertext. A file shows its size and that it is a
Shekyl multisig file, and nothing else.

### 1.1 File layout

```
Offset   Size     Field             Notes
------   ----     -----             -----
0        1        format_version    0x02
1        24       nonce             random, §4.2
25       C        ciphertext        XChaCha20-Poly1305 of the plaintext (§1.2)
25+C     16       tag               Poly1305
```

A file is `plaintext_len + 41` bytes: `MIN_FILE_LEN = 3,500` for an empty
body, `MAX_FILE_LEN = MIN_FILE_LEN + MAX_BODY_LEN` for a full one. A file
outside those bounds is not a ceremony file.

### 1.2 Plaintext layout

```
Offset   Size     Field                 Notes
------   ----     -----                 -----
0        32       address_fingerprint   the group's identity (PQC_MULTISIG.md §5.3)
32       32       intent_hash           §2.4
64       1        sender_index          0-indexed member
65       1        message_type          §3
66       4        body_len              u32 LE, ≤ MAX_BODY_LEN
70       B        body                  §3.1
70+B     4        sig_len               u32 LE, exactly SENDER_SIG_LEN
74+B     3385     sender_sig            §1.3
```

| Name | Value | Meaning |
|------|-------|---------|
| `MAX_BODY_LEN` | `1,048,576` | The largest body (1 MiB) |
| `SENDER_SIG_LEN` | `3385` | One canonical hybrid signature (`POST_QUANTUM_CRYPTOGRAPHY.md`) |

The plaintext parses **exactly**: `body_len` is bounded before it is read
and must not exceed what follows; `sig_len` must equal `SENDER_SIG_LEN`;
the signature ends the plaintext, with no trailing bytes. Any other shape
is refused without allocating past the bounds.

### 1.3 Sender signature

Every member has a long-term hybrid envelope keypair (Ed25519 +
ML-DSA-65), minted by the dealer and written into the member files: the
member's own secret, and every member's public key (`PQC_MULTISIG.md`
§6.6). It derives from no spend secret and signs nothing but ceremony
files. The sender signs every plaintext field except the signature:

```
message    = frame("shekyl/multisig-envelope-v1", network_id,
                   [u64(format_version), address_fingerprint, intent_hash,
                    u64(sender_index), u64(message_type), body])          // 64 bytes
sender_sig = HybridEd25519MlDsa.sign(envelope_secret,
                                     "shekyl/multisig-envelope-scheme-v1", message)
```

`frame` is the signing envelope (`NETWORK_IDENTITY.md` §2.6): cSHAKE256
with the first string as customization over the 16-byte network id
followed by each field behind its u64-LE length, read to 64 bytes; an
integer field is its u64-LE bytes. Both strings are registered
(`CRYPTO_DOMAIN_REGISTRY.tsv`).

A member who holds the group transport secret can write a file that
opens for the group, but cannot sign it as another member: the
signature is checked under the envelope public key of the member the
file names.

### 1.4 Import

Nothing in a file names its group, so a wallet finds the group by **trial
decryption**. It checks, in this order, and refuses at the first
failure; the body reaches nothing before every check has passed:

1. `format_version` is `0x02`, and the file's length is within
   `MIN_FILE_LEN..=MAX_FILE_LEN` (§1.1); both read once, before any key is
   tried, so an unauthenticated file costs nothing per group. Version
   `0x01`, the clear-header layout, is refused by name.
2. The file opens under one of the wallet's groups' keys (§4). Under
   none: "not for this wallet".
3. The plaintext parses exactly (§1.2).
4. `address_fingerprint` is the fingerprint of the group whose key
   opened the file.
5. `sender_index < n`.
6. `sender_sig` verifies under member `sender_index`'s envelope public
   key, on this network.
7. `message_type` is assigned (§3).

---

## 2. SpendIntent Canonical Serialization

The `SpendIntent` is the proposal that starts a spend; a `Proposal` file
(§3) carries it, and that file's sender signature is the proposal's. It
is the only input a signer trusts (R-7): every signer rebuilds every
signing input from it. Its canonical serialization is the input to
`intent_hash`.

### 2.1 Constants

| Name | Value | Description |
|------|-------|-------------|
| `SPEND_INTENT_VERSION` | `0x02` | Current version |
| `MIN_MULTISIG_THRESHOLD` | `2` | The smallest `m` (R-11) |
| `MAX_RECIPIENTS` | `16` | Maximum recipients per intent: the consensus output cap (`MAX_OUTPUTS`). Change is a recipient |
| `MAX_INPUTS` | `8` | Maximum inputs per intent: the consensus cap (`MAX_FCMP_INPUTS`, CEN-I4) |
| `MAX_ADDRESS_LEN` | `65536` | Maximum address byte length |

### 2.2 Canonical Byte Layout

Fields are serialized in this order with no padding. Variable-length
fields use a `u32 LE` length prefix.

```
1        version                 0x02
32       intent_id               random 32 bytes
32       address_fingerprint     the group's identity
1        proposer_index          0-indexed
4        signers_len             u32 LE, equal to m
m        signers                 member indices, strictly ascending
1        responder_index         one of signers, not the proposer
8        created_at              u64 LE, unix seconds; display only
8        reference_block_height  u64 LE
32       reference_block_hash    32 bytes
4        recipients_count        u32 LE (MUST be ≤ MAX_RECIPIENTS)
...      recipients[]            §2.3, repeated recipients_count times
8        fee                     u64 LE, atomic units
4        inputs_count            u32 LE (1..=MAX_INPUTS)
...      input_global_indices[]  inputs_count × u64 LE
32       kem_randomness_seed     32 bytes
32       chain_state_fingerprint 32 bytes
```

A verifier with an `m`-of-`n` group refuses, each by name: a version other
than `0x02`; `m < 2` or `m > n`; `proposer_index ≥ n`; a signer count
other than `m`; signers not strictly ascending; a signer `≥ n`; a
proposer who is not a signer; a responder who is not a signer; a
responder who is the proposer; an input count outside `1..=MAX_INPUTS`;
more than `MAX_RECIPIENTS` recipients; an address longer than
`MAX_ADDRESS_LEN`; recipients out of order or repeated.

### 2.3 Recipient Encoding

Each recipient is encoded as:

```
4        address_len    u32 LE (MUST be ≤ MAX_ADDRESS_LEN)
A        address        Raw address bytes (A = address_len)
8        amount         u64 LE, atomic units
```

**Sort order:** Recipients MUST be sorted by `(address, amount)` where
`address` is compared as raw bytes via unsigned byte-wise lexicographic
comparison (`memcmp` semantics: compare byte-by-byte from index 0;
shorter address sorts before longer if they share a prefix). Ties are
broken by `amount` as unsigned 64-bit integer, ascending.

Duplicate `(address, amount)` tuples are forbidden.

### 2.4 Intent Hash

```
intent_hash = keccak256(canonical_bytes)
```

Where `keccak256` is **original-padding Keccak-256** (`0x01` padding, NOT
FIPS-202 SHA3-256's `0x06` — the two differ in one byte and fail silently),
implemented as `shekyl_crypto_hash::keccak256`, and `canonical_bytes` is
the full serialization from §2.2. Because the signer set and the
responder are in it, every file of a ceremony binds them.

### 2.5 Deadline

An intent has no wall-clock expiry (R-13). It expires when no block can
list a spend anchored at its reference block: consensus admits a
reference whose age **measured from the connecting height** is in
`[FCMP_REFERENCE_BLOCK_MIN_AGE, FCMP_REFERENCE_BLOCK_MAX_AGE]` (CEN-I11),
so the last block that can list the spend is
`reference_block_height + MAX_AGE`, and the last tip at which a member
can still submit is one below that. A reference above a member's tip is
"not yet" (the member's node is behind), never "expired".
`created_at` is shown to people and checked against nothing.

---

## 3. Message Types

The message type is carried **inside the ciphertext** (§1.2).

| ID | Name | Status | Body |
|----|------|--------|------|
| `0x01` | SpendIntent | REJECTED | Replaced by `Proposal`, which carries the intent with the proposer's first round |
| `0x02` | ProverOutput | REJECTED | Option D; E′ has no prover |
| `0x03` | SignatureShare | live | Per input, a holder's FROST share |
| `0x04` | Veto | REJECTED | Option D |
| `0x05` | ProverReceipt | REJECTED | Option D |
| `0x06` | Heartbeat | REJECTED | Option D |
| `0x07` | CounterProof | REJECTED | Option D |
| `0x08` | GroupStateSummary | REJECTED | No producer or reader |
| `0x09` | InvariantViolation | REJECTED | No producer or reader: a member that refuses an intent shows its human and sends nothing (`PQC_MULTISIG.md` §2.7) |
| `0x0A` | RotationIntent | REJECTED | Option D |
| `0x0B` | EquivocationProof | REJECTED | No producer or reader: different preprocess sets complete no SAL and use each nonce once (`PQC_MULTISIG.md` §11.4) |
| `0x0C` | Proposal | live | The intent (§2.2); per input, the proposer's preprocess and per-output key |
| `0x0D` | Commitment | live | Per input, a holder's preprocess and per-output key |
| `0x0E` | SigningSet | live | Other members' files, forwarded sealed as received |
| `0x0F` | ResponderShare | live | Per input, the responder's preprocess, share and per-output key |
| `0x10` | FinalTx | live | The `Proposal` file; per input, every signer's per-output key; the FCMP++ proof; the range proof |
| `0x11` | HybridSig | live | Per input, the signer's hybrid signature |

A REJECTED value is never reused. An import refuses any value that is
not live, after the sender signature has verified (§1.4). Which member
sends each type, and when, is `PQC_MULTISIG.md` §11.1.

### 3.1 Bodies

Every body parses **exactly**: each count and length is bounded before
it is read, every field is read in full, and no bytes may follow the
last field. A per-input list leads with its count `n` (one byte,
`1 ≤ n ≤ MAX_INPUTS` = 8) and is in the intent's input order; a
per-signer list leads with its count (one byte, at most
`MAX_MULTISIG_PARTICIPANTS` = 5). A length prefix is a `u32` LE,
at most `MAX_FILE_LEN`.

| Field | Size | Encoding |
|-------|------|----------|
| `preprocess` | 64 | A FROST SAL preprocess: two compressed Ed25519 points, decoded by the receiver's signing machine, which refuses a non-canonical, torsioned or identity point |
| `share` | 32 | A FROST SAL share: a canonical scalar, decoded by the receiver's machine |
| `key` | 1996 | A member's per-output hybrid public key, canonical (`POST_QUANTUM_CRYPTOGRAPHY.md`) |
| `signature` | 3385 | A hybrid signature, canonical |
| `file` | `u32` + len | A ceremony file (§1), sealed as its sender wrote it |

```
Proposal       = u32(len) ‖ intent (§2.2) ‖ n ‖ n × (preprocess ‖ key)
Commitment     = n ‖ n × (preprocess ‖ key)
SigningSet     = k ‖ k × file                              1 ≤ k ≤ 5
ResponderShare = n ‖ n × (preprocess ‖ share ‖ key)
SignatureShare = n ‖ n × share
FinalTx        = file (the Proposal) ‖ n ‖ m ‖ n × m × key  2 ≤ m ≤ 5
                 ‖ u32(len) ‖ FCMP++ proof ‖ u32(len) ‖ range proof
HybridSig      = n ‖ n × signature
```

In `FinalTx`, each input's `m` keys are in the intent's signer order. The
FCMP++ proof is `shekyl-fcmp`'s (SALs included); the range proof is one
Bulletproof+ over every output.

---

## 4. Seal

The ciphertext is `shekyl_crypto_pq::multisig_blob` (R-4, R-10).

### 4.1 Key

```
key = HKDF-SHA-512(
    ikm  = transport_secret,              // 32 bytes, the group transport secret
    salt = empty,                         // RFC 5869's HashLen zero salt
    info = "shekyl/multisig-blob-key-v1", // LABEL_MULTISIG_BLOB_KEY, alone
    L    = 32
)
```

One key per group. `transport_secret` is the group transport secret every
member file holds (`PQC_MULTISIG.md` §6.6), derived by the dealer under
`salt_for`.

### 4.2 Nonce

Each seal draws 24 bytes from a cryptographic RNG and writes them after
the version byte. The nonce is not derived from anything: a nonce taken
from persisted state would repeat after a wallet is restored, and a
repeated nonce under this AEAD leaks the XOR of two plaintexts and the
Poly1305 key. At 192 bits a random nonce under one key does not repeat
for any number of files a group will ever make.

### 4.3 Associated data

```
aad = format_version     // 1 byte
```

### 4.4 Sensitive material

Implementations MUST zeroize the following values when no longer needed:

- **The group key**, immediately after each seal or open.
- **The plaintext working buffer**, on seal and after the body has been
  handed on, on open. A body may carry FROST material.
- **`transport_secret` and the envelope secret**: they live for the
  wallet session and MUST be zeroized on close. MUST be stored in memory
  pages excluded from swap and core dumps where the OS supports it.

The nonce is not sensitive.

---

## 5. Chain State Fingerprint

The chain state fingerprint is a 32-byte hash members agree on before
signing.

```
preimage = reference_block_hash          // 32 bytes
        || sorted(input_global_indices)  // each u64 LE
        || sorted(input_eligible_heights)// each u64 LE
        || sorted(input_amounts)         // each u64 LE

chain_state_fingerprint = keccak256(preimage)   // §2.4 primitive
```

Each array is sorted ascending on its own before concatenation.
Duplicates are preserved.

---

## 6. File Transport

### 6.1 File Naming

Files use **random opaque filenames**: `shekyl-ms-<random64hex>.bin`.
The 64 hex characters represent 32 bytes from a cryptographically secure
source (`/dev/urandom`, `getrandom(2)`, `BCryptGenRandom`, or
equivalent). The filename MUST NOT contain metadata (group, intent hash,
message type, sender).

### 6.2 File Contents

The file is exactly one ceremony file (§1.1). No additional framing.

### 6.3 Display Names

Wallet UIs SHOULD show names derived from the opened plaintext (e.g.,
"Proposal 0x1a2b… from member 3"). These names are never written to
disk.

---

## 7. Conformance

An implementation claiming conformance MUST:

1. Produce byte-identical canonical serialization (§2.2) for the same
   `SpendIntent`, and so the same `intent_hash`
   (`docs/test_vectors/MULTISIG_INTENT_V2.json`, checked by
   `scripts/kat/multisig_intent_oracle.py`).
2. Open files produced by any other conforming implementation given the
   same transport secret, and derive the same group key (§4.1; the key
   vector in `multisig_blob.rs`'s `the_blob_key_is_pinned`).
3. Refuse a file whose version is not `0x02`, reading the byte before any
   key.
4. Run the import checks of §1.4 in order, and hand on no body that has
   not passed all of them.
5. Refuse a `message_type` that is not live (§3), and parse each body
   exactly (§3.1).
6. Refuse recipients that are not sorted per §2.3 or contain duplicates.
7. Enforce every bound in §1.2 and §2.2 without allocating past it.
8. Draw a fresh 24-byte nonce for every seal (§4.2).

---

## 8. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1 | 2026-04-13 | Initial release for V3.1 |
| 1.1 | 2026-04-14 | Size bounds on every length prefix, the recipient sort order, the signable header, a persisted message counter, body layouts for eleven types, zeroization guidance, CSPRNG file names |
| 1.2 | 2026-11-12 | The E′ seal: XChaCha20-Poly1305 under an HKDF-SHA-512 key from the group transport secret, a random 24-byte nonce, a clear 66-byte header as associated data |
| 2 | 2026-11-13 | R-6, R-9, R-10, R-12, R-13 (slice 3 PR-B): the header moves inside the ciphertext and a file shows only its version; one key per group and trial decryption on import; a sender signature under a per-member envelope key; intent version 2 with the signer set and responder, without the proposer signature or wall-clock expiry; the persisted message counter and the intent's `tx_counter` deleted (replay is the reference block's age, the per-intent held nonce and consensus key images); message types `0x0C`–`0x11`; files are the only transport |
| 2.1 | 2026-11-14 | Slice 3 PR-C: each live type's body (§3.1); `0x09` and `0x0B` REJECTED. The file format byte is unchanged |
