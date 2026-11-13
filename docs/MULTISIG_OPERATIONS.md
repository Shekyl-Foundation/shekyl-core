# Multisig Operations Guide — Shekyl V3.1

> **Protocol version:** V3.1 (equal-participants, coordinator-less)
>
> **Product path:** **Option E′** (`spend_auth_version = 0x02`) — dealer-mode
> FROST on `y`, plaintext `b`, **no mandatory prover / no 1/N permanent-loss
> assignment**. See `PQC_MULTISIG.md` §15.4a and
> `V3_1_MULTISIG_RUST_ENGINE.md` §0.5.
>
> **Spec:** `docs/PQC_MULTISIG.md`
>
> **Analysis:** `docs/PQC_MULTISIG_V3_1_ANALYSIS.md`
>
> **Wire format:** `docs/SHEKYL_MULTISIG_WIRE_FORMAT.md`
>
> **Historical:** Sections that still describe a rotating designated prover,
> ProverOutput / ProverReceipt, or 1/N recovery playbooks are **Option D
> scaffold** (deleted, not shipped). They remain until rewritten; do not
> treat them as E′ operational guidance.

## Overview

Shekyl V3.1 multisig (Option E′) uses an equal-participants model where
every member holds the same dealer-issued share of the group spend
secret `y` and the same plaintext view key `b`. There is no coordinator
and no privileged prover: any M of N can authorize a spend, and FCMP++
proof construction is not assigned to a single permanent loser.

### Key Properties

- **M-of-N threshold signing** (e.g., 2-of-3, 3-of-5) with FROST on `y`
- **Hybrid PQC**: X25519 + ML-KEM-768 for KEM, Ed25519 + ML-DSA-65 for
  signatures
- **FCMP++ membership proofs** from genesis (no ring signatures)
- **Per-output forward privacy** via ephemeral KEM
- **Dealer-mode setup** — owner is trusted KeyGen; no DKG in the
  default path
- **Files are the transport**: members pass sealed ceremony files by any
  means they choose; a file shows only that it is a Shekyl multisig file
- ~~Rotating prover assignment / 1/N permanent loss~~ — **Option D only;
  deleted under E′**

---

## 1. Choosing Your Multisig Configuration

### Decision Framework

| Configuration | Security | Availability | Operational Complexity | Best For |
|---------------|----------|-------------|----------------------|----------|
| **2-of-2** | Both must agree | Both must be online | Low | Couples, business partners |
| **2-of-3** | Tolerates 1 compromised key | Tolerates 1 offline member | Low | Personal savings, small teams |
| **3-of-5** | Tolerates 2 compromised keys | Tolerates 2 offline members | Medium | Organization treasury |
| **5-of-5** | All must agree | All must be online | High | High-value cold storage (max N) |

Target consensus cap: `MAX_MULTISIG_PARTICIPANTS = 5` (MSW-G;
decided — code still `= 7` until MSW-1). After MSW-1, configurations
with `n_total > 5` are unreachable.

**Rules of thumb:**

- If you need to spend quickly (business operations), keep M low relative
  to N. 2-of-3 means any two can spend.
- If you need maximum security (cold storage), keep M high relative to N.
  5-of-5 means every member must agree.
- 1-of-N groups cannot be made: the wallet, the address and consensus
  all refuse a threshold below 2. With one signer it would be a shared
  key under a multisig label, and any one compromised device would lose
  the funds.
- Availability and security trade off directly: higher M means more
  security but lower availability (more people must be online to spend).

### The 2-of-3 Sweet Spot

For most users, 2-of-3 is the right starting point:

- You can lose one key and still spend (availability).
- An attacker must compromise two keys (security).
- Only two people need to coordinate for any spend (operational
  simplicity).
- The **Option D** 1/N loss limitation (§6.1, historical) is **not**
  the E′ product path. Under E′, plan for ordinary M-of-N availability
  (enough shares online), not prover rebalancing.

### When to Use Larger Groups

Move to 3-of-5 or higher when:

- The funds represent organizational assets where no single person should
  have unilateral control.
- The participants are geographically distributed and you want to
  tolerate multiple simultaneous outages.
- You need a formal approval process (three department heads, board
  members, etc.).

---

## 2. Group Setup (Dealer Mode)

### Prerequisites

- One participant, the owner, runs the setup. The owner generates every
  key and is trusted with all of them until the member files are
  delivered (`PQC_MULTISIG.md` §5.2).
- Every participant has a Shekyl wallet to load its member file into.
- A private channel from the owner to each participant: a member file
  holds that participant's secrets.

### Steps

1. **Create group**: In the GUI, navigate to Multisig → Setup Group.
   Enter N (total participants) and M (required signatures).

2. **Key split**: The wallet generates the group's keys, splits the
   group's FROST key M-of-N, and writes one member file per participant
   (`PQC_MULTISIG.md` §6.6). No key-generation round runs, so the
   participants need not be online together.

3. **Deliver the files, then keep them**: The owner gives each
   participant its own member file over the private channel. Each
   participant stores that file before the owner deletes its extra
   copies. The file is the backup. It holds this participant's FROST
   share, the group scalar `b`, both KEM secrets and the transport
   secret, and none of those can be regenerated from a wallet seed or
   from the group descriptor (`PQC_MULTISIG.md` §6.6, §8.4).

4. **Fingerprint verification**: Each participant loads its member file
   and sees the group's 3-representation fingerprint. **All participants
   must confirm their fingerprint matches** before transacting. This is
   the only human verification step — do not skip it.

5. **The descriptor is not the backup.** The group descriptor is the
   group's public identity: the threshold, the public keys and the
   address fingerprint. It holds no share and no KEM secret, so a seed
   plus the descriptor does not restore the ability to receive or spend.
   Store the member file with the wallet backup.

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
2. One partner is the owner and creates the group as 2-of-2 (both must
   agree) or 2-of-3, with the third member file on a separate device.
3. The owner delivers each member file in person.
4. Both verify fingerprints match by reading them aloud to each other.
5. Each partner stores its member file with its own backup. The owner
   deletes its extra copies only after that.

**Daily operation:**
- Either partner can propose a spend.
- The other reviews and signs; the partners pass the ceremony files
  between their devices (§7).
- For the 2-of-3 variant: the backup device key is used only if one
  partner is unavailable. Store it in a safe or with a trusted person.

### 3.2 Small Organization Treasury (3-of-5)

**Scenario:** A 5-person team needs a treasury where any 3 can authorize
spending.

**Setup:**
1. Each of the 5 keyholders creates a wallet.
2. Designate the owner (any member), who runs the setup and delivers
   each keyholder its member file in person or over a private channel.
3. Each keyholder loads its member file; no shared online window is
   needed.
4. All 5 verify fingerprints — use a group video call where each reads
   their fingerprint.
5. Each keyholder stores its member file with its own backup. The owner
   deletes its extra copies only after every keyholder has confirmed
   that.

**Operations:**
- Establish internal rules: "spending above X requires 24h delay for
  review" (enforced socially, not by protocol).
- Agree how files travel (a shared folder, encrypted email, USB for
  high-value transactions) and a time for each signing session (§7).
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

2. **Send to the group**: The wallet writes a `Proposal` file, sealed
   under the group's key and signed with your envelope key. Pass it to
   the other signers by whatever means the group uses (§7).

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

The spend is done when the transaction is confirmed on-chain. Until its
session ends, your wallet will not commit to another proposal that spends
any of the same inputs.

---

## 6. Failure Recovery

> **Option E′ note:** permanent key loss for a participant is an
> **M-of-N threshold** problem (can the remaining members still meet
> `m_required`?), not a rotating-prover 1/N permanent-loss problem.
> §6.1 and §9.1 below still describe the **deleted Option D** playbook
> and will be rewritten; do not follow them as E′ ops guidance.

### 6.1 A Participant Lost Their Keys

> **Historical (Option D scaffold).**

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

### 6.2 Restoring a Member After Wallet Reinstall

The member file is what restores this participant. A wallet seed and
the group descriptor do not: the descriptor is public, and the share
and the KEM secrets are not derived from the seed (`PQC_MULTISIG.md`
§6.6).

1. Reinstall the Shekyl wallet.
2. Import the member file from the backup made at setup.
3. The wallet rescans the chain. Receive and spend state come back
   from the file plus the chain (`PQC_MULTISIG.md` §8.4).
4. Verify the fingerprint matches the saved copy.

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
- A ceremony file never reached the member assembling the transaction.
- Network issue prevented broadcast.
- The assembler went offline mid-process.

**What to do:**
- If the session hasn't expired (its reference block can still be used,
  §7): any member can retry the broadcast.
- If it expired: create a new intent for the same transaction. Its inputs
  are free again once the old session has ended.

---

## 7. Signing Sessions

The wallet moves no bytes over a network for multisig. Each step of a
spend is a **ceremony file** the wallet writes; members pass the files by
any means: a shared folder, encrypted email, a messenger, a USB stick.
A file is sealed under the group's key and signed by its sender, and
shows only its size and that it is a Shekyl multisig file, so the
channel needs no trust.

A spend is one session:

1. **Agree a time.** The signers who will take part are named in the
   proposal, so agree who they are and when. A session lasts about three
   hours (`PROOF_VALIDITY_HORIZON` blocks from the proposal's reference
   block); after that no block can include the transaction and the
   proposal must be made again.
2. **Pass files.** The proposer sends the proposal; each signer imports
   the files it receives, the wallet checks them, and it writes the next
   file for the others. Import files in any order: the wallet tells you
   which step each one is.
3. **Bring the safe-held device out once.** A device kept offline comes
   out for the session, takes part, and goes back. It does not need a
   network connection or a correct clock; a device without a chain view
   cannot tell whether the session has expired, and signing an expired
   proposal produces a transaction no block will include, not a loss.

Filenames are random and say nothing about the file. The wallet shows
each file's meaning after it opens it, and never writes that to disk.

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
| **A channel that drops or reads files** | Files are sealed and signed; pass them another way |

### What Multisig Does NOT Defend Against

| Threat | Why Not |
|--------|---------|
| **M keys compromised simultaneously** | By definition, M keys = full control |
| **Social engineering of M signers** | Protocol can't prevent humans from being tricked |
| **Protocol bugs** | Any software can have bugs; audit mitigates |
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

> **Historical (Option D scaffold).** Under Option E′ there is no
> rotating prover assignment and no 1/N permanent-loss lock from that
> mechanism. Key-loss risk is ordinary threshold failure (`m_required`
> cannot be met).

If a participant permanently disappears under the **deleted** Option D
model, approximately 1/N of group
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

**Why not yet:**
- ML-DSA-65 signing on Cortex-M class MCUs takes 1-5 seconds (vs ~100ms
  on desktop CPUs). Most hardware wallets run ARM Cortex-M4 at 120MHz.
- Coldcard Mk4 (480MHz Cortex-M7) is the most viable near-term target.
- The signing payload is already designed to be representable on small
  screens: "Sign intent {hash_prefix} sending {amount} SKL to
  {address_prefix}" is all the hardware wallet needs to display.
- No protocol changes are needed — the signing payload is self-contained
  and verifiable offline.

Hardware wallet support is a V3.2 goal. See `docs/FOLLOWUPS.md` for
vendor outreach recommendations and technical constraints.

### 9.5 A Trusted Owner at Setup

Setup is dealer mode: the owner generates every key and holds every
member's share until the member files are delivered. Participants who
cannot trust one owner with that wait for a key-generation ceremony
mode, which would be a later `spend_auth_version` (`PQC_MULTISIG.md`
§5.2). After setup, daily operation is asynchronous.

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

| Transaction Type | Approx Size (1-in/2-out) | Fee Multiplier |
|-----------------|--------------------------|----------------|
| **Single-sig** | ~15.6 KB | 1.0× (baseline) |
| **3-of-3 multisig** | ~26.5 KB | ~1.7× |
| **5-of-5 multisig** | ~37.3 KB | ~2.4× |

Oracle and rationale: `docs/V3_ROLLOUT.md` (vs-N-solos amortization).
Do not read auth-overhead “×N vs single-signer” as whole-tx cost.

### Where the Overhead Comes From

**Per-input overhead (authentication):**

| Config | Auth overhead | vs single-sig |
|--------|---------------|---------------|
| Single-sig | **5389** B (`pqc_auth_weight()`) | baseline |
| 2-of-3 | ~12.8 KB | ~2.4× |
| 3-of-5 | ~20.2 KB | ~3.7× |
| 5-of-5 | ~27 KB | ~5.0× |

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

Each ceremony file carries one message (see `SHEKYL_MULTISIG_WIRE_FORMAT.md`
for the layouts):

| Type | ID | Description |
|------|----|-------------|
| SignatureShare | 0x03 | A FROST signature share |
| InvariantViolation | 0x09 | Report of a failed invariant check |
| EquivocationProof | 0x0B | Two conflicting messages from one member |
| Proposal | 0x0C | The spend intent and the proposer's first round |
| Commitment | 0x0D | A holder's first round |
| SigningSet | 0x0E | The set the responder signs over |
| ResponderShare | 0x0F | The responder's round |
| FinalTx | 0x10 | The finished transaction |
| HybridSig | 0x11 | Each signer's post-quantum signatures |

The message type is inside the file's ciphertext, so nothing that
carries a file sees which step it is.
