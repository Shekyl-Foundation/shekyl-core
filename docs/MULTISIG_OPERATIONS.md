# Multisig Operations Guide — Shekyl V3.1

> **Protocol version:** V3.1 (equal-participants, coordinator-less)
>
> **Spec:** `docs/PQC_MULTISIG.md`
>
> **Analysis:** `docs/PQC_MULTISIG_V3_1_ANALYSIS.md`
>
> **Wire format:** `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`

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
- **File-based transport** for air-gapped operation

---

## 1. Choosing Your Multisig Configuration

### Decision Framework

| Configuration | Security | Availability | Operational Complexity | Best For |
|---------------|----------|-------------|----------------------|----------|
| **2-of-2** | Both must agree | Both must be online | Low | Couples, business partners |
| **2-of-3** | Tolerates 1 compromised key | Tolerates 1 offline member | Low | Personal savings, small teams |
| **3-of-5** | Tolerates 2 compromised keys | Tolerates 2 offline members | Medium | Organization treasury |
| **5-of-7** | Tolerates 4 compromised keys | Tolerates 2 offline members | High | High-value cold storage |

**Rules of thumb:**

- If you need to spend quickly (business operations), keep M low relative
  to N. 2-of-3 means any two can spend.
- If you need maximum security (cold storage), keep M high relative to N.
  5-of-7 means a majority must agree.
- Never use 1-of-N — this is just single-sig with extra steps. If any
  one key is compromised, funds are lost.
- Availability and security trade off directly: higher M means more
  security but lower availability (more people must be online to spend).

### The 2-of-3 Sweet Spot

For most users, 2-of-3 is the right starting point:

- You can lose one key and still spend (availability).
- An attacker must compromise two keys (security).
- Only two people need to coordinate for any spend (operational
  simplicity).
- The 1/N loss limitation (§6.1) means at worst 33% of outputs are at
  risk if a participant disappears — manageable with periodic
  consolidation.

### When to Use Larger Groups

Move to 3-of-5 or higher when:

- The funds represent organizational assets where no single person should
  have unilateral control.
- The participants are geographically distributed and you want to
  tolerate multiple simultaneous outages.
- You need a formal approval process (three department heads, board
  members, etc.).

---

## 2. Group Setup (DKG Ceremony)

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

6. **Export group descriptor**: After setup, export the group descriptor
   file (Settings → Group Descriptor → Export). This single JSON file
   contains everything needed to restore the group from seeds.
   **Store it with your wallet backup.**

### Address Format

Multisig addresses use the `shekyl1m` HRP (Bech32m encoding). Due to
their size (~14KB for a 3-of-5 group), addresses are handled as files
rather than strings. The address file contains the full group public key
data.

---

## 3. Operational Playbooks

### 3.1 Household Multisig (2-of-2 or 2-of-3)

**Scenario:** A couple wants shared control over savings.

**Setup:**
1. Each partner creates a Shekyl wallet on their own device.
2. Both exchange public keys (in person — do not send over email).
3. One partner initiates group creation as 2-of-2 (both must agree) or
   2-of-3 with a third key on a separate backup device.
4. Both verify fingerprints match by reading them aloud to each other.
5. Both export group descriptors and store backups separately.

**Daily operation:**
- Either partner can propose a spend.
- The other reviews and signs via relay (if both online) or file
  transport (if one is offline).
- For the 2-of-3 variant: the backup device key is used only if one
  partner is unavailable. Store it in a safe or with a trusted person.

### 3.2 Small Organization Treasury (3-of-5)

**Scenario:** A 5-person team needs a treasury where any 3 can authorize
spending.

**Setup:**
1. Each of the 5 keyholders creates a wallet.
2. Designate a setup coordinator (any member) who collects public keys
   and initiates the DKG.
3. All 5 must be online simultaneously for DKG. Schedule a 30-minute
   window.
4. All 5 verify fingerprints — use a group video call where each reads
   their fingerprint.
5. All 5 export and back up their group descriptors independently.

**Operations:**
- Establish internal rules: "spending above X requires 24h delay for
  review" (enforced socially, not by protocol).
- Use a shared relay for day-to-day operations plus file transport for
  high-value transactions.
- Assign one member as "consolidation lead" who periodically proposes
  consolidation transactions to reduce the impact of 1/N loss.

### 3.3 Migrating from Single-Sig to Multisig

1. Set up the multisig group following the playbook for your
   configuration.
2. Send a test transaction (small amount) to the multisig address.
3. Complete the full signing flow to confirm everything works.
4. Transfer remaining funds from single-sig to multisig in batches (not
   all at once — if something is wrong, you want to catch it early).
5. Once all funds are transferred and confirmed, the single-sig wallet
   is no longer the primary. Keep it as an emergency fallback for a few
   weeks, then archive it.

---

## 4. Receiving Funds

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

## 5. Spending Funds

### 5.1 Proposing a Transaction

Any group member can propose a spend:

1. **Create SpendIntent**: Specify recipients, amounts, and fee. The
   wallet automatically selects inputs, computes the chain state
   fingerprint, and assigns provers.

2. **Broadcast to group**: The SpendIntent is encrypted with the group's
   shared secret and sent to all members via configured relays (or
   exported as a file for air-gapped operation).

3. **14-check validation**: Each receiving member validates the intent
   against structural, temporal, chain-state, and balance checks.

### 5.2 Proving

The assigned prover for each output constructs the FCMP++ membership
proof:

1. The prover generates the proof using their assigned outputs.
2. The `ProverOutput` is broadcast to all members with an FCMP++ proof
   commitment for equivocation detection.
3. All members verify the proof before signing.

### 5.3 Signing

Each of M required signers produces a `SignatureShare`:

1. Run invariant checks I1–I5 (SpendIntent validation, chain state,
   FCMP++ proof, BP+ determinism, prover assignment).
2. Sign the transaction hash with the hybrid signature scheme.
3. Broadcast the `SignatureShare` with commitments to tx_hash,
   fcmp_proof, and bp_plus_proof.

### 5.4 Assembly

Once M signatures are collected:

1. Run assembly consensus check (I6) — all M shares must commit to the
   same tx_hash, fcmp_proof, and bp_plus_proof.
2. Assemble the final transaction.
3. Broadcast to the network.

### 5.5 Confirmation

`tx_counter` advances only after observing the transaction confirmed
on-chain at N confirmations (default: 3).

---

## 6. Failure Recovery

### 6.1 A Participant Lost Their Keys

**Severity:** Medium (1/N of outputs at risk)

In V3.1, each participant is the designated prover for approximately 1/N
of group outputs. If participant P permanently loses their keys, the
outputs assigned to P as prover cannot be spent.

**What to do:**
1. Immediately propose a consolidation: spend all outputs NOT assigned
   to P into new outputs (which will be reassigned to surviving provers).
2. The consolidated outputs are safe. Only the ~1/N that were P's
   prover assignments may be permanently lost.
3. Consider creating a new group with a replacement participant and
   migrating remaining funds.

**Prevention:**
- All participants should keep encrypted backups of their seed phrases.
- Export and securely store the group descriptor file.
- For high-value groups, consider periodic consolidation to rebalance
  prover assignments.

### 6.2 Restoring a Group After Wallet Reinstall

1. Reinstall the Shekyl wallet.
2. Restore your individual wallet from seed.
3. Import the group descriptor file (Settings → Group Descriptor →
   Import).
4. The wallet rebuilds group state by scanning the chain from the
   group's creation height.
5. Verify the fingerprint matches your saved copy.

### 6.3 Suspecting a Participant's Device Is Compromised

**Severity:** High

If you suspect participant P's device is compromised:

1. **Do not sign any new intents.** Alert all other participants
   out-of-band (phone, in person).
2. Check for invariant violations in the Dashboard. A compromised
   participant might produce equivocating proofs.
3. If P's key is confirmed compromised:
   - Immediately sweep all outputs to a new group (without P) using the
     remaining M-1 honest signers (if M-1 >= threshold) or contact
     other signers to reach threshold.
   - The attacker cannot spend unilaterally unless they control M keys.
   - Urgency: funds are safe as long as the attacker controls fewer
     than M keys, but act quickly to prevent escalation.

### 6.4 Stuck Intent (Signed but Not Broadcast)

The Dashboard shows a yellow alert: "Signed intent not broadcast."

**Causes:**
- Relay was down during assembly.
- Network issue prevented broadcast.
- The assembler went offline mid-process.

**What to do:**
- If the intent hasn't expired: any member can retry the broadcast.
- If the intent expired: create a new intent for the same transaction.
  The `tx_counter` has not advanced (it only advances on-chain
  confirmation), so the new intent will work normally.

### 6.5 Transaction Counter Divergence

The Dashboard shows: "Transaction counter divergence."

**Meaning:** Your wallet missed a confirmed transaction, so your
`tx_counter` is behind the group's.

**What to do:**
1. Wait for the automatic `CounterProof` exchange. Another member will
   send you chain evidence of the transaction you missed.
2. Your wallet verifies the proof against your local chain view
   (8 verification rules).
3. If your chain isn't synced to the relevant block yet, wait for sync
   to complete — do not reject valid proofs prematurely.
4. Once verified, your counter updates and you can sign new intents.

**If CounterProof verification fails:** see §6.6.

### 6.6 CounterProof Verification Failure

The Dashboard shows a red alert: "CounterProof verification failed."

**Meaning:** A CounterProof from another participant failed one of the
8 verification rules. This could indicate:

- A malicious participant sending a fabricated proof
- A chain reorganization that invalidated the proof
- A bug in the sender's wallet

**What to do:**
1. Do not accept the counter value.
2. Contact the participant who sent the proof out-of-band.
3. If a chain reorg occurred, wait for your chain to stabilize and ask
   them to resend.
4. If you suspect malice, alert all other participants and consider
   migrating to a new group without the suspected party.
5. As a last resort, perform a full wallet rescan to rebuild state from
   the chain.

---

## 7. Relay Configuration

For censorship resistance, configure at least 3 relays operated by
distinct operators:

1. Navigate to Multisig → Settings → Relay Configuration.
2. Add relay URLs with their operator IDs.
3. The UI warns if fewer than 3 distinct operators are configured.

All multisig messages are encrypted end-to-end. Relay operators see
only encrypted blobs and cannot determine message types, roles, or
transaction details.

### File Transport as Alternative

For maximum security or air-gapped operation, use file-based transport
(Multisig → File Transport tab):

1. Export the signing request as a file.
2. Transfer it via USB drive, encrypted email, or any secure channel.
3. The recipient imports, signs, and exports the response.
4. Collect M response files and assemble.

File transport has equal status with relay transport. It is not an
"advanced" option — it is the trust anchor for security-conscious
treasuries.

---

## 8. Threat Model

### What Multisig Defends Against

| Threat | How Multisig Helps |
|--------|-------------------|
| **Single key theft** | Attacker needs M keys, not just 1 |
| **Single device compromise** | Other signers' devices are independent |
| **Coercion of one member** | M-1 others can refuse to sign |
| **Single point of failure** | Key loss doesn't destroy all funds |
| **Insider threat (below threshold)** | <M colluding insiders can't spend |
| **Relay censorship** | Multi-relay + file transport as fallback |

### What Multisig Does NOT Defend Against

| Threat | Why Not |
|--------|---------|
| **M keys compromised simultaneously** | By definition, M keys = full control |
| **Social engineering of M signers** | Protocol can't prevent humans from being tricked |
| **Protocol bugs** | Any software can have bugs; audit mitigates |
| **All relays colluding** | Messages could be delayed (not stolen); file transport is the escape hatch |
| **Quantum attack on ML-DSA-65** | V3.1 uses hybrid PQC; classical fallback exists |
| **Physical coercion of M members** | Out of scope for cryptographic protocol |

### Threat Model Worksheet

For your specific situation, answer these questions:

1. **Who are you protecting against?** (Theft, loss, insider, nation-state)
2. **How many participants can you trust to be honest?** (M-1 at minimum)
3. **What's your availability requirement?** (How quickly must you be
   able to spend?)
4. **Where are keys stored?** (Same building = correlated failure;
   distributed = more resilient)
5. **What's the recovery plan if a participant disappears?** (See §6.1)

---

## 9. Honest Limitations of V3.1

These are known limitations. They are not bugs — they are engineering
trade-offs documented for transparency.

### 9.1 1/N Prover Loss

If a participant permanently disappears, approximately 1/N of group
outputs become unspendable. This is inherent to V3.1's rotating prover
model. **Mitigation:** periodic consolidation to rebalance prover
assignments. **Future fix:** V4 will use threshold FCMP++ proving to
eliminate this limitation.

### 9.2 ML-DSA-65 Signing Latency

Hybrid signing (Ed25519 + ML-DSA-65) takes ~100ms on modern desktop CPUs.
This is imperceptible for interactive use but relevant for:
- Automated co-signer services processing many transactions.
- Constrained hardware (see §9.4).

### 9.3 Address File Size

A 3-of-5 multisig address is approximately 14KB. It cannot be
represented as a short string or QR code. Addresses are handled as
files. This is a UX trade-off for full PQC key inclusion.

### 9.4 No Hardware Wallet Support in V3.1

Current hardware wallets (Coldcard, Trezor, Ledger, Jade) do not
support ML-DSA-65. V3.1 signing requires a full desktop or laptop.
Hardware wallet support is a V3.2+ goal pending vendor engagement.
See `docs/FOLLOWUPS.md` for tracking.

### 9.5 All Participants Online for DKG

The DKG ceremony requires all N participants to be online
simultaneously. After DKG, daily operation is asynchronous.

### 9.6 No Partial Key Rotation

V3.1 does not support replacing a single participant's key without
creating a new group and migrating funds. `RotationIntent` (0x0A) is
reserved for V4.

---

## 10. Fee Impact Analysis

### How Shekyl Fees Work

Shekyl fees scale with transaction size in bytes. The base fee rate is
adaptive (see `burn.rs`), adjusting to network load. Multisig
transactions are larger than single-sig, so they cost more in absolute
terms.

### Size Comparison

| Transaction Type | Approx Size (2-in/2-out) | Fee Multiplier |
|-----------------|--------------------------|----------------|
| **Single-sig** | ~23 KB | 1.0x (baseline) |
| **2-of-3 multisig** | ~36 KB | ~1.6x |
| **3-of-5 multisig** | ~43 KB | ~1.9x |
| **5-of-7 multisig** | ~54 KB | ~2.3x |

### Where the Overhead Comes From

**Per-input overhead (authentication):**

| Config | Auth overhead | vs single-sig |
|--------|---------------|---------------|
| Single-sig | ~5,385 B | baseline |
| 2-of-3 | ~12,769 B | +7,384 B (~2.4x) |
| 3-of-5 | ~20,153 B | +14,768 B (~3.7x) |
| 5-of-7 | ~30,921 B | +25,536 B (~5.7x) |

**Per-output overhead (multisig-specific `tx_extra`):**

| N | Extra per output |
|---|-----------------|
| 2 | ~2,339 B |
| 3 | ~3,492 B |
| 5 | ~5,798 B |

### Comparison with Bitcoin

Bitcoin multisig is per-input overhead (public keys and signatures in
the witness/script). Bitcoin P2WSH 2-of-3 multisig is approximately 3x
the cost of P2WPKH single-sig. During the 2017 and 2021 fee spikes,
multisig became prohibitively expensive for small amounts.

Shekyl's overhead model differs:

1. **Per-output overhead is hidden behind FCMP++.** The verifier does
   not see per-output PQC key data; it's in `tx_extra` consumed only by
   the recipient's wallet. The chain stores it, but verification cost
   doesn't scale with N.
2. **Fee rate is adaptive, not auction-based.** Shekyl's adaptive burn
   mechanism smooths fee spikes; there is no fee-rate auction that
   creates winner-take-all dynamics.
3. **Smaller absolute multiplier.** 2-of-3 multisig is ~1.6x single-sig
   fees, compared to Bitcoin's ~3x. This is because FCMP++ proofs and
   PQC auth dominate the base transaction size, so the relative
   multisig overhead is proportionally smaller.

### Economic Viability

At current fee levels (assuming adaptive base rate):

- **Small transactions (< 1 SKL):** viable for 2-of-3 and 3-of-5.
  The fee difference between single-sig and multisig is negligible at
  normal network load.
- **Micro-transactions (< 0.01 SKL):** not recommended for any
  transaction type (single-sig or multisig). The base fee for a ~23 KB
  transaction may exceed the amount.
- **During congestion:** multisig fees will be 1.6-2.3x single-sig
  fees. The adaptive burn mechanism prevents extreme fee spikes, but
  users should expect higher fees during high-load periods.

**Conclusion:** Shekyl V3.1 multisig does not have Bitcoin's
"rich users only" problem. The fee multiplier is modest, and the
adaptive fee mechanism prevents the fee-spike dynamics that made
Bitcoin multisig unusable for small amounts.

---

## 11. Message Types

The protocol defines 11 message types (see `SHEKYL_MULTISIG_WIRE_FORMAT.md`
for binary layouts):

| Type | ID | Description |
|------|----|-------------|
| SpendIntent | 0x01 | Transaction proposal |
| ProverOutput | 0x02 | FCMP++ proof from assigned prover |
| SignatureShare | 0x03 | Partial signature from a signer |
| Veto | 0x04 | Abort request with reason |
| ProverReceipt | 0x05 | Acknowledgment of prover assignment |
| Heartbeat | 0x06 | Liveness and sync beacon |
| CounterProof | 0x07 | Chain evidence for counter recovery |
| GroupStateSummary | 0x08 | Group state synchronization |
| InvariantViolation | 0x09 | Report of failed invariant check |
| RotationIntent | 0x0A | Reserved for V4 |
| EquivocationProof | 0x0B | Evidence of conflicting proofs |

All messages are wrapped in a `MultisigEnvelope` with AEAD encryption.
The message type is encrypted inside the payload to prevent role-pattern
leakage.
