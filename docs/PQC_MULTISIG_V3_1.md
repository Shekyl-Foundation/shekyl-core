# PQC Multisig V3.1: Equal-Participants Model

> **Status:** DRAFT for adversarial review
> **Target:** V3.1 wallet-layer release (no consensus changes)
> **Supersedes (when accepted):** coordinator-based flow in `PQC_MULTISIG.md` §V3

---

## 1. Purpose

This document specifies an "equal-participants" multisig protocol that achieves
symmetric participation, deterministic construction, and auditable intent —
entirely within the existing V3 consensus rules (`scheme_id = 2`). No hard
fork, no new transaction types, no privacy regression.

The goal is to eliminate the coordinator role as a power center while
retaining a single participant as the FCMP++ prover (the one structural
asymmetry that cannot be removed without V4 FROST SAL).

---

## 2. Design Principles

1. **Separate authorities.** The four authorities currently conflated in
   "coordinator" — proposal, construction, signing, assembly — are split.
   Only one (FCMP++ proof construction) retains a designated holder in V3,
   and that role has no content authority.
2. **Deterministic construction.** Given a spend intent and a committed
   chain snapshot, every participant constructs byte-identical transaction
   bytes. There is no interface latitude and no "coordinator discretion."
3. **No consensus changes.** Everything shipped here is a wallet protocol on
   top of the existing `scheme_id = 2` consensus rules. If the wallet
   protocol has a bug, the worst case is a failed broadcast — not a chain
   split.
4. **On-chain indistinguishability preserved.** The resulting transaction is
   structurally identical to any other `scheme_id = 2` transaction and is
   not distinguishable from single-signer transactions beyond the already-
   known `pqc_auth` size difference.
5. **Transport-agnostic.** The protocol defines message formats, not wire
   transport. Nostr relays, direct P2P, and files are all valid carriers.

---

## 3. Threat Model

### In scope

- **Malicious proposer** proposes a spend that harms the group.
- **Malicious prover** tries to build an FCMP++ proof that pays a different
  destination than the intent specifies.
- **Malicious signer** refuses to sign, signs a different intent, or signs
  twice.
- **Malicious assembler** broadcasts a tampered transaction.
- **Malicious transport operator** (relay, P2P node) tries to drop, reorder,
  inject, or correlate messages.
- **External passive observer** tries to identify multisig groups and their
  membership from transport traffic.
- **Rollback and replay attacks** at any stage.

### Out of scope (still V4 open problems)

- M-of-N collusion (by definition, M colluding signers can spend — that is
  the authorization contract).
- Selective disclosure by M signers to an outside auditor (no
  zero-knowledge proof that a signature was *not* produced).
- Denial-of-service by the FCMP++ prover refusing to participate. In V3,
  the classical `y` is single-holder; if the holder refuses, the group is
  stuck. V4 FROST SAL removes this.
- Signer identity recovery from on-chain patterns (the `pqc_auth` blob
  reveals `n_total`, `m_required`, and N public keys — these are already
  on-chain metadata; group members are not hidden from each other).

---

## 4. Roles

Four roles, each symmetrically occupiable by any group member unless noted.

| Role | Authority | Who | Can a malicious actor in this role harm the group? |
|---|---|---|---|
| **Proposer** | Publishes a signed spend intent | Any member | No — signers veto by refusing to sign. |
| **Prover** | Constructs the FCMP++ membership proof | The member holding classical `y` (V3 only) | Cannot modify the transaction; proof binds to the signers' computed payload. Can only refuse to participate (liveness). |
| **Signer** | Produces hybrid signature over canonical payload | Any M of the N members | Cannot individually authorize; needs collusion with M−1 others. |
| **Assembler** | Collects M signatures, finalizes, broadcasts | Any member | Can only broadcast what signers produced; cannot substitute content. |

In V3, **Prover = the fixed `y`-holder**. In V4 (with FROST SAL), Prover
becomes a threshold role with no single holder.

---

## 5. Group Setup

### 5.1 Group parameters

A group is defined by:

- `n_total`: total signers, `1 ≤ n_total ≤ 7` (matches V3 consensus cap).
- `m_required`: threshold, `1 ≤ m_required ≤ n_total`.
- `hybrid_pubkeys[n_total]`: the N hybrid (Ed25519 + ML-DSA-65) public keys.
- `y_holder_index`: the index into `hybrid_pubkeys` of the prover. V3 only.
- `group_id`: deterministic hash, as in current `PQC_MULTISIG.md`:

  ```
  group_id = cn_fast_hash(
      scheme_id || n_total || m_required ||
      sort_and_concat(hybrid_pubkeys) ||
      y_holder_index
  )
  ```

### 5.2 Change address derivation

Each group derives a single dedicated change address used for all outgoing
transactions:

```
change_seed = HKDF-Expand(group_id, "shekyl-v3.1-multisig-change", 32)
change_spend_key = derive_address_from_seed(change_seed, network_type)
```

The change address is a normal V3 Bech32m address whose spend authority is
the group itself. All members can derive it identically. Funds sent to the
change address are spendable by the same multisig rules as the group's main
holdings.

### 5.3 Group state synchronization

Each member's wallet maintains local group state:

- `tx_counter`: monotonic counter of *accepted* spend intents. Starts at 0.
- `pending_intents`: set of published-but-not-yet-broadcast intents.
- `seen_intents`: history of accepted intent hashes.

Members synchronize by exchanging `GroupStateSummary` messages periodically.
Disagreement resolution rules are defined in §10.

---

## 6. Spend Intent

The spend intent is the canonical input to construction. It contains
**everything** needed to deterministically produce the transaction.

### 6.1 Schema

```
SpendIntent {
    // Versioning
    version:          u8         // = 1
    intent_id:        [u8; 32]   // random, unique per intent

    // Group binding
    group_id:         [u8; 32]

    // Proposer
    proposer_index:   u8         // index into hybrid_pubkeys
    proposer_sig:     HybridSignature  // over all preceding + all following fields

    // Temporal binding
    created_at:       u64        // Unix seconds
    expires_at:       u64        // Unix seconds; intent invalid after this
    tx_counter:       u64        // must equal group's current tx_counter
    reference_block_height: u64
    reference_block_hash:   [u8; 32]

    // Content
    recipients: [
        { address: Bech32mAddress, amount: u64 }
    ]  // sorted by (address_bytes, amount) ascending
    fee:              u64
    input_global_indices: [u64]  // global output indices to spend, sorted ascending

    // Determinism anchors
    kem_randomness_seed: [u8; 32]  // HKDF salt for deterministic KEM nonces
    // Note: change output derivation is implicit from group_id + tx_counter
}
```

### 6.2 Invariants

1. `version == 1`
2. `group_id` matches the proposer's wallet's group
3. `proposer_index < n_total`
4. `proposer_sig` verifies against `hybrid_pubkeys[proposer_index]`
5. `created_at ≤ now ≤ expires_at`
6. `expires_at - created_at ≤ 86400` (24h max validity window)
7. `tx_counter` equals the group's current expected counter
8. `reference_block_height` is within `FCMP_REFERENCE_BLOCK_MAX_AGE` of the
   current tip and `≥ FCMP_REFERENCE_BLOCK_MIN_AGE` blocks behind it
9. `reference_block_hash` matches the chain's block at
   `reference_block_height`
10. All `input_global_indices` refer to outputs:
    - owned by the group (their ownership material matches `group_id`)
    - unspent according to the member's local view
    - eligible at the reference height
11. Recipients are sorted; no duplicate address-amount tuples
12. `sum(recipients.amount) + fee == sum(input.amount)` (computed from the
    member's view of the outputs; mismatch indicates either tampering or
    state drift)
13. `kem_randomness_seed` is 32 random bytes (not predictable)

### 6.3 Intent hash

```
intent_hash = cn_fast_hash(canonical_serialize(SpendIntent))
```

`intent_hash` is the durable identifier of the intent and is referenced by
all subsequent messages.

---

## 7. Canonical Construction Algorithm

Given `SpendIntent I`, `GroupState G`, and the member's local view of chain
state, every member executes:

### 7.1 Pre-flight verification

Run all §6.2 invariants. If any fail, **reject the intent** and publish a
`Veto` (§9.4). Do not proceed.

### 7.2 Output derivation

For each output `i` (recipients + one change output, in canonical order):

```
// Deterministic KEM randomness
kem_nonce[i] = HKDF-Expand(
    I.kem_randomness_seed,
    "shekyl-v3.1-kem-nonce" || u32_le(i),
    64  // enough for X25519 + ML-KEM-768 combined
)

// Recipient public key (from the intent's recipient list, or derived
// change address for the change output)
recipient_pk[i] = parse_address(I.recipients[i].address).pqc_pubkey
                  // or group change address for the change output

// Hybrid KEM encapsulation, deterministic
(kem_ciphertext[i], shared_secret[i]) = HybridKEM.encap_deterministic(
    recipient_pk[i],
    kem_nonce[i]
)

// Derive per-output secrets
output_secrets[i] = derive_output_secrets(shared_secret[i], i)
    // produces: output_y, output_pqc_seed, commitment_mask, view_tag

// Compute output public key
output_pk[i] = derive_output_public_key(recipient_pk[i], output_secrets[i])
```

All of `kem_ciphertext[i]`, `output_pk[i]`, and the commitment masks are
therefore **pure functions of the intent**.

### 7.3 Transaction prefix

```
TransactionPrefixV3 {
    version:        3
    unlock_time:    0
    vin:            [for each input_global_indices[j]:
                       TxInFcmpPlusPlus {
                           key_image: derived_from_group(input[j]),
                           // key_offsets: empty (FCMP++ uses reference_block)
                           reference_block: I.reference_block_hash,
                       }
                    ]
    vout:           [for each output i:
                       TxOut { amount: 0, target: output_pk[i] }
                    ]
    extra:          [
                       TxExtraPubKey(ephemeral_pub), // derived from kem_nonce[0]
                       TxExtraPqcKemCiphertexts(kem_ciphertext[0..]),
                       TxExtraPqcLeafHashes(...),
                    ]
}
```

### 7.4 RCT body

```
RctSigBase {
    type: RCTTypeFcmpPlusPlusPqc (=7)
    txnFee: I.fee
    ecdhInfo: [for each i: encoded_amount(i, shared_secret[i])]
    outPk: [for each i: commitment(amount[i], commitment_mask[i])]
    pseudoOuts: [for each input j: commitment(amount[j], mask[j])]
    bp_plus: deterministic_bulletproof(outputs, blinding_from_intent)
}
```

Deterministic Bulletproof+ requires deterministic blinding:

```
bp_blinding = HKDF-Expand(I.kem_randomness_seed, "shekyl-v3.1-bp-blinding", 32)
```

This is nonstandard (Bulletproofs+ normally use fresh randomness) but safe:
the blinding does not need to be random, only uniformly distributed in the
field, and HKDF output satisfies that. Deterministic bp_plus allows every
member to reconstruct identical proof bytes.

### 7.5 Canonical signing payload

```
signing_payload = cn_fast_hash(
    serialize(TransactionPrefixV3) ||
    serialize(RctSigBase) ||
    cn_fast_hash(serialize(RctSigPrunable_skeleton)) ||
    serialize(PqcAuthHeader) ||
    H(hybrid_pubkeys[0]) || ... || H(hybrid_pubkeys[n_total-1])
)
```

Where `RctSigPrunable_skeleton` is the RCT prunable section *without* the
FCMP++ proof filled in (we use its hash because the proof comes from the
prover asynchronously; the payload must be computable before the proof
exists).

`PqcAuthHeader` contains `scheme_id=2, n_total, m_required`, and the N
ownership keys, per existing `PQC_MULTISIG.md` §V3.

### 7.6 Output of construction

Each member now holds:

- `TransactionPrefixV3` bytes (identical across members)
- `RctSigBase` bytes (identical)
- `signing_payload` (identical 32-byte hash)

The only remaining fields to fill are the FCMP++ proof and the M PQC
signatures.

---

## 8. FCMP++ Proof Construction (V3 Prover Role)

The member at `y_holder_index` runs:

```
fcmp_proof = shekyl_fcmp_prove(
    spend_key_y,
    spend_key_x,
    input_tree_paths,    // fetched from daemon at reference_block
    signing_payload,
    construction_context
)
```

The prover publishes a `ProverOutput` message (§9.2) containing the
`fcmp_proof` bytes.

### 8.1 Why the prover cannot redirect funds

The prover sees `signing_payload` and builds a proof that binds to that
hash. They cannot construct a proof over a different payload without the
other participants noticing: every signer independently computes the
payload from the intent and will verify that the proof binds to *their*
computed payload before signing.

The prover can:

- Refuse to participate (liveness attack)
- Publish a malformed proof (signers reject before signing)
- Publish a proof over a different payload (signers reject)

The prover cannot:

- Modify recipients, amounts, fees, inputs
- Substitute a different intent
- Cause signers to sign anything other than the agreed payload

### 8.2 What the prover does hold

The prover holds `y` (the classical spend key). In V3, this is the group's
single point of spend-key compromise at the classical layer. An attacker
who compromises the prover's host obtains `y` but still needs M PQC
signatures to spend. They cannot unilaterally move funds.

The prover's compromise is bounded to:

- Denial of service (refuse to prove)
- Classical-layer key leak (does not enable unilateral spend; enables
  possible long-term privacy attacks if classical ECC is broken, which
  would already be compromising the single-sig case)

V4 FROST SAL eliminates this.

---

## 9. Message Formats

All multisig messages share a common envelope:

```
MultisigEnvelope {
    version:        u8 (= 1)
    group_id:       [u8; 32]
    message_type:   u8
    intent_hash:    [u8; 32]    // binds message to a specific intent
    sender_index:   u8
    sender_sig:     HybridSignature   // over all fields above + payload
    payload:        EncryptedBlob     // see §9.5
}
```

### 9.1 `SpendIntent` (message_type = 0x01)

Payload: canonical-serialized `SpendIntent` (§6.1). Issued by the proposer.

### 9.2 `ProverOutput` (message_type = 0x02)

Payload:

```
ProverOutput {
    fcmp_proof:      [u8]    // variable-length
    prover_index:    u8
}
```

Issued by the prover after receiving and verifying the intent.

### 9.3 `SignatureShare` (message_type = 0x03)

Payload:

```
SignatureShare {
    signer_index:    u8
    hybrid_sig:      HybridSignature   // over signing_payload
    commitment_to_tx_hash: [u8; 32]   // see §9.3.1
}
```

#### 9.3.1 Commitment to tx hash

Each signer computes the final tx hash (which *includes* the prover's
FCMP++ proof) and commits to it in their signature share. This lets the
assembler detect if the prover's proof was swapped between the signing
round and assembly.

### 9.4 `Veto` (message_type = 0x04)

Payload:

```
Veto {
    vetoer_index:    u8
    reason_code:     u8
    reason_text:     string (optional, max 256 bytes)
}
```

A veto publicly records that a member declined to participate in a specific
intent. Other members treat the intent as dead once `n_total - m_required + 1`
vetoes are received (insufficient signers remain).

### 9.5 Encryption

Each message payload is encrypted to the group. The symmetric key is
derived from `group_id` and a per-message nonce:

```
message_key = HKDF-Expand(
    group_shared_secret,
    intent_hash || message_type || sender_index,
    32
)
```

Where `group_shared_secret` is a 32-byte secret established at group-setup
time and stored in each member's wallet. For V3.1, group_shared_secret is
either:

- **Simple mode (V3.1.0):** a random 32-byte value generated by the
  founding proposer and distributed to members via a one-time encrypted
  channel at group formation (each member's hybrid pubkey used as KEM
  recipient).
- **DKG mode (V3.1.1 or V4):** derived from a group DKG ceremony,
  preventing any single member from knowing the full shared secret.

AEAD construction: ChaCha20-Poly1305 with the 96-bit nonce derived as
`HKDF-Expand(group_shared_secret, "nonce" || sender_index || message_counter, 12)`.

---

## 10. Protocol Flow

### 10.1 Happy path

```
  Proposer                Prover              Other members           Assembler
     |                       |                      |                     |
     |--- SpendIntent ------>|--------------------->|                     |
     |                       | (all verify intent)  |                     |
     |                       |                      |                     |
     |                       |--- ProverOutput ---->|--------------------->|
     |                       |                      |                     |
     |                       |    (all reconstruct  |                     |
     |                       |     and verify tx    |                     |
     |                       |     matches intent)  |                     |
     |                       |                      |                     |
     |<---- SignatureShare --|<---------------------|---------------------|
     |                          ... M-1 others ...                        |
     |                                                                    |
     |                         (any with M sigs)                          |
     |                                                                    |
     |                                                          broadcasts tx
```

Any member can play Assembler. Typical implementation: the first member to
see M valid signatures in the group becomes the assembler.

### 10.2 Pre-broadcast verification (every signer)

Before producing `SignatureShare`, each signer:

1. Reconstructs the full transaction bytes from the intent (§7).
2. Verifies the `ProverOutput.fcmp_proof` against the reconstructed payload
   by calling `shekyl_fcmp_verify()`.
3. Computes the final tx hash.
4. Only then signs the `signing_payload` and publishes the share with the
   tx hash commitment.

### 10.3 Assembly verification

The assembler, upon receiving M `SignatureShare` messages:

1. Verifies all M tx hash commitments agree.
2. If they disagree, the assembler publishes a `Veto` naming the
   discrepancy and aborts. This detects prover-tampering between signing
   and assembly.
3. Otherwise, constructs the `pqc_auth` blob per `scheme_id = 2` layout,
   attaches it to the transaction, and submits to the daemon.

### 10.4 State machine

Each member tracks per-intent state:

```
states:
    PROPOSED      → intent seen, not yet verified
    VERIFIED      → intent passed §6.2 checks
    PROVER_READY  → ProverOutput received and verified
    SIGNED        → this member produced and published their signature
    ASSEMBLED     → M signatures gathered (by this member or another)
    BROADCAST     → tx appeared in mempool or on chain
    REJECTED      → intent rejected (veto threshold reached, expiry, or
                    chain rejected the broadcast)
    TIMED_OUT     → expires_at passed without reaching BROADCAST
```

On state transition, the member updates `tx_counter` only when reaching
BROADCAST (confirmed on-chain). Counters increment on observed success,
not on proposal.

### 10.5 Disagreement resolution

**Conflicting intents with same tx_counter.** If two proposers publish
conflicting intents simultaneously, each with `tx_counter = k`, members
use deterministic tiebreaking:

```
winner = intent with smaller cn_fast_hash(intent_bytes)
```

The losing intent is treated as never published. Members who already
signed the losing intent must publish a `Veto` to reset their state.

**Proposer disappears mid-flight.** Intent has `expires_at`; if not
assembled by then, all members transition to `TIMED_OUT` and discard
the intent.

**Prover disappears.** Intent times out. In V3, the group cannot progress
without the prover. Mitigated partially by `tx_counter` not advancing on
timeouts.

---

## 11. Transport Bindings

The protocol is transport-agnostic. Three bindings are defined.

### 11.1 Nostr relay binding

Each message is posted as a Nostr kind-`30000` replaceable event with:

- `d` tag: `shekyl-multisig:<hex(group_id)>:<intent_hash>:<message_type>:<sender_index>`
- Content: the `MultisigEnvelope` from §9, base64-encoded
- Signed with the sender's **secp256k1 Nostr key** (not their hybrid key)

The sender's hybrid signature inside the envelope is the cryptographic
authority; the Nostr signature is only for relay acceptance. Members
subscribe to their group's `d` tag prefix on configured relays.

Privacy properties:

- Relay operators see ciphertext and group_id hash
- Relay operators cannot read messages, cannot verify group membership,
  and cannot link group_id to on-chain addresses (group_id does not appear
  on-chain in any form)
- Groups can rotate group_id periodically (by redoing group setup) to
  further unlink relay traffic from group identity

### 11.2 Direct P2P binding

Members discover each other via DNS-SRV or static configuration and
establish mutually authenticated TLS connections using hybrid
certificates (Ed25519 + ML-DSA-65). Messages are exchanged directly.

Pros: no third parties. Cons: NAT traversal, availability requires all
signers online simultaneously.

### 11.3 File binding (airgap)

Messages are written to files. Compatible with existing Monero-style
USB-stick workflows. File name convention:

```
shekyl-multisig-<hex(group_id)>-<intent_hash>-<message_type>-<sender_index>.bin
```

---

## 12. Security Properties

### 12.1 Safety properties

| Property | Argument |
|---|---|
| No unilateral spend | Consensus requires M PQC signatures (`scheme_id = 2` rules). Any M−1 or fewer cannot authorize. |
| No silent redirect | Construction is a pure function of the intent. Every signer independently reconstructs and verifies before signing. Prover's proof binds to the same payload signers compute. |
| No replay | `intent_id` nonce + `tx_counter` binding + `expires_at` + `reference_block_hash` + observed-state tx_counter advancement. |
| No rollback past broadcast | Once broadcast and confirmed, key images appear on-chain and consensus prevents reuse. |
| Intent non-repudiation | Proposer signs intent with hybrid signature (Ed25519 + ML-DSA-65); forward-quantum-resistant. |
| Signer non-repudiation | Each signature share is hybrid-signed over the payload; binds the signer to exact transaction bytes via the tx-hash commitment. |
| Prover cannot modify tx | Proof binds to `signing_payload`, which is a function of the intent; tampering invalidates the proof. |
| Assembler cannot tamper | Assembler can only broadcast what signers signed; modifications invalidate signatures. |

### 12.2 Liveness properties

| Property | Status |
|---|---|
| Any M honest signers can advance | Yes, assuming the prover is one of them and they reach M. |
| Proposer disappearance recovery | Yes, by timeout and reproposal. |
| Signer disappearance recovery | Yes, as long as M others remain available. |
| **Prover disappearance recovery** | **No in V3.** Group is stuck until prover returns. V4 FROST SAL fixes this. |

### 12.3 Privacy properties

| Property | Argument |
|---|---|
| On-chain indistinguishability | Transactions use the standard V3 `RCTTypeFcmpPlusPlusPqc` format. The only distinguisher is the `pqc_auth` blob size (already known). |
| Transport metadata privacy | Group_id is not on-chain; relay operators cannot link transport to chain activity. Content is encrypted. |
| Member-to-member privacy | None. By design, all M signers see the full transaction. |
| Member set privacy from outsiders | Strong via Nostr (encrypted, unlinked). Weak via direct P2P (connection graph leaks). |

---

## 13. Implementation Plan

### 13.1 Crate layout

All new code in `shekyl-wallet-core/src/multisig/v31/`:

- `intent.rs` — `SpendIntent` struct, canonical serialization, signing
- `construction.rs` — `canonical_construct()` deterministic function
- `prover.rs` — V3 prover role
- `state.rs` — per-group state machine
- `transport/` — trait + Nostr, P2P, file bindings
- `messages.rs` — envelope + message types
- `tx_counter.rs` — counter management and disagreement resolution

No changes in `shekyl-core` C++. No changes in `shekyl-fcmp` (the existing
`shekyl_fcmp_prove` and `shekyl_fcmp_verify` FFIs are sufficient).

### 13.2 GUI wallet changes

- Replace `create_pqc_multisig_group` / `get_pqc_multisig_info` /
  `sign_multisig_partial` handlers with V3.1 equivalents
- Add intent creation UI (recipients, fee, review screen)
- Add intent verification UI (reconstruct + compare screen)
- Add veto/reject UI
- Multisig page gains "active intents" list with per-intent state

### 13.3 Feature flag

Enable `shekyl-wallet-rpc` crate with `--features multisig,multisig-v3.1`.
V3.1 supersedes the V3.0 coordinator flow entirely; there is no coexistence
requirement.

### 13.4 Test matrix

- 2-of-3 happy path
- 3-of-5 happy path
- Malicious proposer (bad recipients, bad fee, bad reference block)
- Malicious prover (wrong payload, malformed proof, no proof)
- Malicious signer (no sig, wrong payload, duplicate sig)
- Malicious assembler (tampered tx, dropped signatures)
- Proposer-disappearance timeout
- Simultaneous conflicting intents (tiebreaking)
- Network partition between signers and prover
- Nostr relay tampering (drop, reorder, inject)
- Group state desync recovery
- Counter manipulation (decrementing, skipping)

### 13.5 Fuzz targets

- `fuzz_spend_intent_deserialize`: malformed intent bytes
- `fuzz_construction_determinism`: same intent + chain state → same bytes
  across 10⁶ iterations with varied thread timing
- `fuzz_envelope_parser`: malformed envelopes, oversized payloads
- `fuzz_kem_randomness_determinism`: same seed → same ciphertext/secret
- `fuzz_veto_flood`: relay message storms

---

## 14. Open Questions for Review

1. **Deterministic Bulletproof+ blinding.** Is HKDF output uniform enough in
   the BP+ challenge domain to avoid soundness degradation? Needs a
   cryptographer check, or switch to a fresh-randomness BP+ produced by the
   prover and re-verified by signers (adds a trust round).

2. **`y`-holder assignment.** Who is it? Options:
   - Fixed at group setup (simpler, but fixes the liveness SPOF)
   - Rotating per-intent (spreads compromise risk but needs ceremony to
     transfer `y`, which can't happen without `y` exposure)
   - V3 reality: fixed. V4 FROST SAL: threshold.

3. **`change_spend_key` storage.** The group change address spend key must
   be reconstructable by every member. Current draft: derive from
   `group_id`. But that means every member *can* spend from the change
   address using single-sig! That's a silent escape hatch. Fix: the change
   address spend public key must be tied to the multisig group's
   `scheme_id = 2` authorization, not a derivable single-sig key. Needs
   design iteration.

4. **Tx_counter synchronization.** If a member missed a broadcast event,
   their counter is stale. Proposer using the correct counter will see
   their intent rejected by the stale member. Recovery: counter-correction
   message with chain proof. Not fully specified here.

5. **Group shared secret distribution.** Simple-mode KEM-to-each-member at
   setup means the proposer *knows* the shared secret. That leaks: after
   setup, the proposer can decrypt any future relay traffic. DKG-mode
   fixes this but adds ceremony complexity. V3.1.0 simple vs V3.1.1 DKG
   tradeoff needs decision.

6. **Relay censorship detection.** If a relay drops messages selectively
   (e.g., drops a specific signer's share), progress stalls without a clear
   error. Need a heartbeat / gossip-check mechanism across multiple relays
   or across transport bindings.

7. **Veto gaming.** A malicious member can spam vetoes to kill any intent
   they dislike, even if M honest signers would approve. Threshold for
   "intent dead" is `n_total - m_required + 1` vetoes, so a single member
   in a 2-of-3 group can veto anything. This is inherent (they could just
   refuse to sign) but the explicit veto makes the attack visible. Okay,
   but worth documenting.

---

## 15. V4 Path

V3.1 fixes the coordinator governance problem but leaves the prover as a
liveness SPOF. V4 closes the loop:

- **FROST SAL** threshold-shares classical `y` across M-of-N participants
- **Carrot-style address typing** resolves the HKDF-per-output-`y` vs
  DKG-group-key-`y` incompatibility by distinguishing multisig addresses
  at the scheme level
- **Prover role is distributed** — any M of N can collectively produce the
  FCMP++ proof
- **No single point of liveness failure**

V3.1 is designed so the V4 upgrade is a drop-in replacement of the prover
role: intents, construction, messages, transport, and state machine all
carry forward unchanged.
