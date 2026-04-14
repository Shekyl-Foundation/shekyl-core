# Multisig Operations Guide — Shekyl V3.1

> **Protocol version:** V3.1 (equal-participants, coordinator-less)
>
> **Spec:** `docs/PQC_MULTISIG.md`
>
> **Analysis:** `docs/PQC_MULTISIG_V3_1_ANALYSIS.md`

## Overview

Shekyl V3.1 multisig uses an equal-participants model where every member
has the same capabilities. There is no coordinator. Transaction
construction is deterministic, and each participant is the designated
prover for approximately 1/N of group outputs.

### Key Properties

- **M-of-N threshold signing** (e.g., 2-of-3, 3-of-5)
- **Hybrid PQC**: X25519 + ML-KEM-768 for KEM, Ed25519 + ML-DSA-65 for
  signatures
- **FCMP++ membership proofs** from genesis (no ring signatures)
- **Per-output forward privacy** via ephemeral KEM
- **Rotating prover assignment** — deterministic, hash-based
- **Multi-relay transport** for censorship resistance

---

## 1. Group Setup (DKG Ceremony)

### Prerequisites

- All N participants have Shekyl wallets with PQC key material
- Each participant knows the hybrid public keys of all others
- Communication channel exists between all participants

### Steps

1. **Exchange public keys**: Each participant exports their hybrid public
   key (hex) and shares it with all others.

2. **Create group**: In the GUI, navigate to Multisig → Setup Group.
   Enter N (total participants), M (required signatures), and all
   participant public keys.

3. **DKG execution**: The wallet runs `dkg-pedpop` to establish the
   shared group key. This requires all N participants to be online
   simultaneously.

4. **Fingerprint verification**: After DKG completes, each participant
   sees the same 3-representation fingerprint. **All participants must
   confirm their fingerprint matches** before transacting. This is the
   only human verification step — do not skip it.

5. **Loss acknowledgment**: The GUI requires explicit acknowledgment of
   the 1/N loss limitation before the group is finalized.

### Address Format

Multisig addresses use the `shekyl1m` HRP (Bech32m encoding). Due to
their size (~14KB for a 3-of-5 group), addresses are handled as files
rather than strings. The address file contains the full group public key
data.

---

## 2. Receiving Funds

Receiving works automatically once the group is set up:

1. Share the group's multisig address file with the sender.
2. The wallet scans incoming transactions and identifies outputs
   belonging to the group using KEM decapsulation.
3. Receive-time validation (invariant I7) automatically checks output
   integrity.

### Griefing Defense

The wallet limits computational resources spent on invalid outputs.
If an attacker floods the chain with fake multisig outputs, the
`GriefingTracker` bounds the per-output cost and rate-limits processing.

---

## 3. Spending Funds

### 3.1 Proposing a Transaction

Any group member can propose a spend:

1. **Create SpendIntent**: Specify recipients, amounts, and fee. The
   wallet automatically selects inputs, computes the chain state
   fingerprint, and assigns provers.

2. **Broadcast to group**: The SpendIntent is encrypted with the group's
   shared secret and sent to all members via configured relays.

3. **14-check validation**: Each receiving member validates the intent
   against structural, temporal, chain-state, and balance checks.

### 3.2 Proving

The assigned prover for each output constructs the FCMP++ membership
proof:

1. The prover generates the proof using their assigned outputs.
2. The `ProverOutput` is broadcast to all members with an FCMP++ proof
   commitment for equivocation detection.
3. All members verify the proof before signing.

### 3.3 Signing

Each of M required signers produces a `SignatureShare`:

1. Run invariant checks I1–I5 (SpendIntent validation, chain state,
   FCMP++ proof, BP+ determinism, prover assignment).
2. Sign the transaction hash with the hybrid signature scheme.
3. Broadcast the `SignatureShare` with commitments to tx_hash,
   fcmp_proof, and bp_plus_proof.

### 3.4 Assembly

Once M signatures are collected:

1. Run assembly consensus check (I6) — all M shares must commit to the
   same tx_hash, fcmp_proof, and bp_plus_proof.
2. Assemble the final transaction.
3. Broadcast to the network.

### 3.5 Confirmation

`tx_counter` advances only after observing the transaction confirmed
on-chain at N confirmations (default: 3).

---

## 4. Recovery

### Stale Counter Recovery

If a member misses a transaction, another member sends a `CounterProof`:

1. The proof contains block hash, tx position, consumed inputs, and
   resulting outputs.
2. The stale member verifies 8 rules against their local chain view.
3. If the block isn't synced yet, the member waits (does not reject).
4. If local state is inconsistent, a full wallet rescan is triggered.

### Heartbeat Monitoring

Members send heartbeats every 5 minutes to detect:

- Missing members (offline or censored)
- Intent disagreement (relay censorship)
- Relay diversity collapse (operator collusion)
- Counter divergence
- Time skew

On anomaly: retry across all relays, escalate to user, do not advance
state optimistically.

---

## 5. Relay Configuration

For censorship resistance, configure at least 3 relays operated by
distinct operators:

1. Navigate to Multisig → Relay Config in the GUI.
2. Add relay URLs with their operator IDs.
3. The UI warns if fewer than 3 distinct operators are configured.

All multisig messages are encrypted end-to-end. Relay operators see
only encrypted blobs and cannot determine message types, roles, or
transaction details.

---

## 6. Security Considerations

### 1/N Loss Limitation (V3.1)

If any single participant permanently loses their keys, approximately
1/N of group outputs become permanently unspendable. These are the
outputs for which the lost participant was the designated prover. This
is a V3.1 limitation that V4 will eliminate.

### Equivocation Detection

If a prover produces conflicting proofs for the same intent, any member
can construct an `EquivocationProof` and publish a `Veto`. This is
detected automatically by comparing `fcmp_proof_commitment` values.

### Invariant Violations

If any invariant (I1–I7) is violated, the signing process is
automatically aborted and a `ViolationAlert` is displayed in the GUI.
Investigate before retrying.

---

## 7. Message Types

The protocol defines 11 message types:

| Type | ID | Description |
|------|----|-------------|
| SpendIntent | 0x01 | Transaction proposal |
| ProverOutput | 0x02 | FCMP++ proof from assigned prover |
| SignatureShare | 0x03 | Partial signature from a signer |
| InvariantViolation | 0x04 | Report of failed invariant check |
| Veto | 0x05 | Abort request with reason |
| Heartbeat | 0x06 | Liveness and sync beacon |
| CounterProof | 0x07 | Chain evidence for counter recovery |
| EquivocationProof | 0x08 | Evidence of conflicting proofs |
| RotationIntent | 0x09 | Reserved for V4 |
| ProverReceipt | 0x0A | Acknowledgment of prover assignment |
| DkgRefresh | 0x0B | Reserved for V4 |

All messages are wrapped in a `MultisigEnvelope` with AEAD encryption.
The message type is encrypted inside the payload to prevent role-pattern
leakage.
